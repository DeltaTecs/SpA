"""Execution of guided-analysis chat turns.

Each user message starts one agentic chat turn (:func:`run_turn`): the model is
given the prior conversation plus the configured MCP tools, and runs the
:class:`~llm.McpLlmClient` agentic loop — gated by the shared
:class:`~app.pentest.approver.PentestApprover` — to produce a reply. Turns run on
a daemon thread so the HTTP request returns immediately and the frontend polls.

A turn is ephemeral (never persisted to the db-api): the conversation lives only
in the browser, which replays it on the next turn.
"""

from __future__ import annotations

import logging
import threading
from typing import List, Optional, Set

from llm import ChatMessage, McpLlmClient, OperationCancelled
from llm.provider.base import BaseProvider

from ..activity import THINKING, SessionActivity
from ..agent_factory import build_provider, build_reviewer
from ..config import Settings, settings
from ..mcp_catalog import build_catalog, enumerate_catalog
from ..pentest.approver import PentestApprover, ReviewerClient
from ..schemas import StartGuidedTurnRequest
from .store import GuidedStore

logger = logging.getLogger(__name__)

#: Shared, process-wide store for guided chat turns.
store = GuidedStore()

#: Default system pretext when the request leaves ``system_prompt`` blank. The
#: frontend ships an identical editable default; this is the backend fallback.
DEFAULT_GUIDED_SYSTEM_PROMPT = (
    "You are an authorized penetration tester with access to recorded application "
    "traffic through tools. You also have access to web search and penetration "
    "testing tools. Help the user analyse the traffic and investigate potential "
    "vulnerability finding, using the available tools when useful and citing concrete "
    "evidence in your answers."
)

#: Scope line handed to the automatic reviewer when judging a tool call. The
#: shared approver uses it the same way it uses a pentest item's target summary.
_GUIDED_TARGET_SUMMARY = (
    "Interactive, user-guided security analysis chat over recorded application "
    "traffic. Judge each tool call for safety to the local machine and the remote "
    "target, and for adherence to the stated tool-use constraints."
)

#: One session per turn, so reviews use a fixed item id (the approver needs one).
_TURN_ITEM_ID = "turn"


def submit_guided_turn(request: StartGuidedTurnRequest, cfg: Settings = settings) -> str:
    """Validate the request, create the turn, and start its session.

    Raises ``ValueError`` for an invalid provider / missing key / misconfigured
    review policy — surfaced as HTTP 400 by the caller.
    """
    tool_cfg = request.tool_config

    provider = build_provider(request.provider, request.model, request.reasoning_effort, cfg)
    getattr(provider, "client", None)  # warm the lazily-built SDK client

    reviewer_client: Optional[ReviewerClient] = None
    if tool_cfg.review_mode == "automatic":
        if tool_cfg.reviewer is None:
            raise ValueError("Automatic review requires a reviewer configuration.")
        reviewer_client = build_reviewer(tool_cfg.reviewer, cfg)

    requested_tools: Set[str] = set(tool_cfg.allowed_tools)
    catalog_tools = enumerate_catalog(
        cfg, allowed=requested_tools, include_exempt=tool_cfg.exempt_db_search
    )
    allowed = catalog_tools.allowed_names
    ignored_tools = requested_tools - allowed
    if ignored_tools:
        logger.warning(
            "Ignoring unavailable or non-selectable guided tools: %s", sorted(ignored_tools)
        )
    exempt = catalog_tools.exempt_names
    needed_categories = catalog_tools.needed_categories

    job_id = store.create(
        provider=request.provider,
        model=provider.model,
        reasoning_effort=provider.reasoning_effort,
        call_budget=cfg.tavily_call_budget_per_job,
    )
    logger.info(
        "Guided turn %s: provider=%s, model=%s, review=%s, messages=%d, "
        "allowed_tools=%d, exempt=%d",
        job_id,
        provider.name,
        provider.model,
        tool_cfg.review_mode,
        len(request.messages),
        len(allowed),
        len(exempt),
    )

    threading.Thread(
        target=run_turn,
        args=(job_id, request, provider, cfg, exempt, allowed, needed_categories, reviewer_client),
        name=f"guided-{job_id[:8]}",
        daemon=True,
    ).start()
    return job_id


def run_turn(
    job_id: str,
    request: StartGuidedTurnRequest,
    provider: BaseProvider,
    cfg: Settings,
    exempt: Set[str],
    allowed: Set[str],
    needed_categories: Set[str],
    reviewer: Optional[ReviewerClient],
) -> None:
    """Run one agentic chat turn and record its reply (or error)."""
    token = store.token_for(job_id)
    if token is not None and token.is_cancelled:
        return  # turn was terminated before its session started
    store.update(job_id, status="running", activity=THINKING)
    activity = SessionActivity(lambda phrase: store.update(job_id, activity=phrase))
    try:
        # Only connect to toolsets that actually hold a selected tool.
        toolsets = [
            entry.toolset
            for entry in build_catalog(cfg, budget=store.budget_for(job_id))
            if entry.category in needed_categories
        ]
        approver = PentestApprover(
            store=store,
            job_id=job_id,
            item_id=_TURN_ITEM_ID,
            exempt_tools=exempt,
            review_mode=request.tool_config.review_mode,
            target_summary=_GUIDED_TARGET_SUMMARY,
            tool_constraints=request.tool_config.tool_constraints,
            reviewer=reviewer,
            review_auto_denied_manually=request.tool_config.review_auto_denied_manually,
            activity=activity,
        )
        client = McpLlmClient(
            provider,
            toolsets,
            max_iterations=request.max_iterations,
            allowed_tools=allowed,
            approver=approver,
            cancel_token=token,
            activity=activity,
        )
        run_result = client.run_messages(_build_messages(request))
        store.update(
            job_id,
            status="done",
            content=run_result.output,
            iterations=run_result.iterations,
            stopped_on_limit=run_result.stopped_on_limit,
            activity=None,
        )
    except OperationCancelled:
        logger.info("Guided turn %s cancelled", job_id)
    except Exception as exc:  # noqa: BLE001 - record the failure on the turn
        logger.exception("Guided turn %s failed", job_id)
        store.update(job_id, status="error", error=str(exc), activity=None)


def _build_messages(request: StartGuidedTurnRequest) -> List[ChatMessage]:
    """Seed the agentic loop with the system pretext and the conversation so far."""
    system = (request.system_prompt or "").strip() or DEFAULT_GUIDED_SYSTEM_PROMPT
    messages: List[ChatMessage] = [ChatMessage(role="system", content=system)]
    for message in request.messages:
        messages.append(ChatMessage(role=message.role, content=message.content))
    return messages
