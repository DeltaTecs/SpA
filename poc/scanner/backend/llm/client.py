"""The MCP / LLM orchestrator.

:class:`McpLlmClient` ties together the three inputs of a run:

* a **prompt** (and optional system message),
* one or more **MCP toolsets** (:class:`llm.mcp.toolset.McpToolset`), and
* an **LLM provider** (:class:`llm.provider.base.BaseProvider`).

It runs the agentic loop: send the prompt and the available tools to the model,
execute any tool calls the model requests against the owning toolset, feed the
results back, and repeat until the model returns a final answer (or the
iteration budget is exhausted).

The client depends only on a tiny structural surface of a toolset
(``list_tool_specs()`` and ``call_tool()``), so it can be driven with fakes in
tests without any network or live MCP server.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Protocol

from .cancellation import CancellationToken
from .provider.base import BaseProvider, ChatMessage, ToolCall, ToolSpec

logger = logging.getLogger(__name__)

#: Default cap on LLM<->tool round trips, guarding against infinite loops.
DEFAULT_MAX_ITERATIONS = 10


class Toolset(Protocol):
    """Structural type the orchestrator needs from a toolset."""

    name: str

    def list_tool_specs(self) -> list[ToolSpec]:
        ...

    def call_tool(self, name: str, arguments: dict) -> str:
        ...


@dataclass(frozen=True)
class ToolDecision:
    """A toolset-agnostic approve/deny verdict for one tool call.

    ``feedback`` is surfaced to the model on a denial so it can adjust (e.g. a
    reviewer's reason or a human operator's hint).
    """

    approved: bool
    feedback: str | None = None


class ToolApprover(Protocol):
    """Optional gate consulted before each tool call is executed.

    Implementations may block (e.g. awaiting a human decision) or call out to a
    reviewer model. The orchestrator stays agnostic to the mechanism; it only
    acts on the returned :class:`ToolDecision`.
    """

    def review(self, call: ToolCall) -> ToolDecision:
        ...


class ActivityReporter(Protocol):
    """Optional sink for coarse, human-readable run activity.

    The orchestrator notifies it as a session moves between phases — waiting on
    the model vs. executing a tool — so a UI can show what a long-running session
    is currently doing. Calls must be cheap and must not raise; the orchestrator
    ignores any return value. (The approval phase is reported by the approver
    itself, which knows whether it is awaiting a human or a reviewer model.)
    """

    def on_thinking(self) -> None:
        """The run is waiting for the model to respond."""

    def on_tool_call(self, tool_name: str) -> None:
        """The run is about to execute the named tool."""


@dataclass(frozen=True)
class TranscriptStep:
    """One ordered step of an agentic run, for after-the-fact inspection.

    A run's transcript is a flat, chronological list of these. Two kinds:

    * ``kind="reasoning"`` — the model's interim text/thinking emitted *before* a
      batch of tool calls (``text`` is the assistant content, ``reasoning`` the
      extended-thinking content). This is the reasoning *between* the tools.
    * ``kind="tool_call"`` — one executed tool call: its ``arguments``, the
      owning ``toolset_name`` (so the app layer can classify it), the reviewer's
      verdict (``approved`` is ``None`` when no approver gated the call), and the
      tool ``output`` fed back to the model.

    The structure is provider- and app-neutral and trivially JSON-serialisable.
    """

    kind: str
    text: str | None = None
    reasoning: str | None = None
    call_id: str | None = None
    tool_name: str | None = None
    toolset_name: str | None = None
    arguments: dict | None = None
    output: str | None = None
    approved: bool | None = None
    review_feedback: str | None = None


@dataclass(frozen=True)
class _CallOutcome:
    """Result of handling one tool call: its output plus the reviewer's verdict."""

    output: str
    decision: ToolDecision | None = None


@dataclass(frozen=True)
class RunResult:
    """The outcome of :meth:`McpLlmClient.run`."""

    output: str
    iterations: int
    tool_calls: list[ToolCall] = field(default_factory=list)
    stopped_on_limit: bool = False
    #: Chronological transcript of reasoning + tool steps (see :class:`TranscriptStep`).
    transcript: list[TranscriptStep] = field(default_factory=list)


class McpLlmClient:
    """Runs a prompt against a set of MCP toolsets using an LLM provider."""

    def __init__(
        self,
        provider: BaseProvider,
        toolsets: list[Toolset] | None = None,
        *,
        max_iterations: int = DEFAULT_MAX_ITERATIONS,
        allowed_tools: set[str] | None = None,
        approver: ToolApprover | None = None,
        cancel_token: CancellationToken | None = None,
        activity: ActivityReporter | None = None,
    ) -> None:
        self.provider = provider
        self.toolsets = list(toolsets or [])
        self.max_iterations = max_iterations
        # When set, only these tool names are advertised to the model; everything
        # else the toolsets expose is hidden. ``None`` means "expose all".
        self.allowed_tools = set(allowed_tools) if allowed_tools is not None else None
        # Optional pre-execution gate (human approval / reviewer model).
        self.approver = approver
        # Optional cooperative cancellation, polled between turns and tool calls.
        self.cancel_token = cancel_token
        # Optional progress sink for surfacing the current phase to a UI.
        self.activity = activity
        logger.info(
            "McpLlmClient ready (provider=%s, toolsets=%d, max_iterations=%d, "
            "allowed_tools=%s, approver=%s, cancellable=%s)",
            provider.name,
            len(self.toolsets),
            max_iterations,
            "all" if self.allowed_tools is None else len(self.allowed_tools),
            "yes" if approver is not None else "no",
            "yes" if cancel_token is not None else "no",
        )

    def run(self, prompt: str, *, system: str | None = None) -> RunResult:
        """Execute the agentic loop for a single prompt and return the result.

        Convenience wrapper around :meth:`run_messages` that seeds the loop with
        an optional system message followed by the user prompt.
        """
        messages: list[ChatMessage] = []
        if system:
            messages.append(ChatMessage(role="system", content=system))
        messages.append(ChatMessage(role="user", content=prompt))
        return self.run_messages(messages)

    def run_messages(self, messages: list[ChatMessage]) -> RunResult:
        """Execute the agentic loop over a seeded conversation and return the result.

        ``messages`` is the full prior conversation (e.g. ``[system?, user,
        assistant, user, ...]``). The list is copied before being mutated, so the
        caller's list is left untouched and can be reused for the next turn.
        """

        tool_specs, dispatch = self._collect_tools()
        logger.info("Starting run with %d aggregated tool(s)", len(tool_specs))

        messages = list(messages)
        executed_calls: list[ToolCall] = []
        transcript: list[TranscriptStep] = []

        for iteration in range(1, self.max_iterations + 1):
            self._check_cancelled()
            logger.info("Iteration %d/%d", iteration, self.max_iterations)
            if self.activity is not None:
                self.activity.on_thinking()
            result = self.provider.chat(messages, tool_specs or None)

            if not result.tool_calls:
                output = result.content or ""
                logger.info("Run complete after %d iteration(s)", iteration)
                return RunResult(
                    output=output,
                    iterations=iteration,
                    tool_calls=executed_calls,
                    transcript=transcript,
                )

            # Record the assistant's interim reasoning (the text it emits alongside a
            # batch of tool calls), then the assistant turn itself, then each call.
            self._record_reasoning(transcript, result)
            messages.append(
                ChatMessage(
                    role="assistant",
                    content=result.content,
                    reasoning_content=result.reasoning_content,
                    tool_calls=result.tool_calls,
                )
            )
            for call in result.tool_calls:
                self._check_cancelled()
                executed_calls.append(call)
                outcome = self._handle_call(call, dispatch)
                transcript.append(self._tool_step(call, dispatch, outcome))
                messages.append(
                    ChatMessage(
                        role="tool",
                        content=outcome.output,
                        tool_call_id=call.id,
                        name=call.name,
                    )
                )

        logger.warning(
            "Reached max_iterations=%d without a final answer; returning last content.",
            self.max_iterations,
        )
        last_content = next(
            (m.content for m in reversed(messages) if m.role == "assistant" and m.content),
            "",
        )
        return RunResult(
            output=last_content or "",
            iterations=self.max_iterations,
            tool_calls=executed_calls,
            stopped_on_limit=True,
            transcript=transcript,
        )

    # -- helpers ------------------------------------------------------------

    def _check_cancelled(self) -> None:
        """Stop the run if cancellation was requested (no-op without a token)."""
        if self.cancel_token is not None:
            self.cancel_token.raise_if_cancelled()

    def _collect_tools(self) -> tuple[list[ToolSpec], dict[str, Toolset]]:
        """Aggregate tool specs across toolsets and map tool name -> owner.

        On a duplicate tool name the first toolset wins and the conflict is
        logged, so the model never sees two tools with the same name.
        """

        specs: list[ToolSpec] = []
        dispatch: dict[str, Toolset] = {}
        for toolset in self.toolsets:
            for spec in toolset.list_tool_specs():
                if self.allowed_tools is not None and spec.name not in self.allowed_tools:
                    continue
                if spec.name in dispatch:
                    logger.warning(
                        "Duplicate tool name '%s' from toolset '%s' ignored (already provided by '%s')",
                        spec.name,
                        toolset.name,
                        dispatch[spec.name].name,
                    )
                    continue
                dispatch[spec.name] = toolset
                specs.append(spec)
        return specs, dispatch

    @staticmethod
    def _record_reasoning(transcript: list[TranscriptStep], result) -> None:
        """Append a reasoning step for an assistant turn's interim text, if any."""
        text = (result.content or "").strip()
        reasoning = (result.reasoning_content or "").strip()
        if text or reasoning:
            transcript.append(
                TranscriptStep(
                    kind="reasoning",
                    text=result.content or None,
                    reasoning=result.reasoning_content or None,
                )
            )

    @staticmethod
    def _tool_step(
        call: ToolCall, dispatch: dict[str, Toolset], outcome: "_CallOutcome"
    ) -> TranscriptStep:
        """Build the transcript step for one executed tool call."""
        owner = dispatch.get(call.name)
        decision = outcome.decision
        return TranscriptStep(
            kind="tool_call",
            call_id=call.id,
            tool_name=call.name,
            toolset_name=owner.name if owner is not None else None,
            arguments=call.arguments,
            output=outcome.output,
            approved=decision.approved if decision is not None else None,
            review_feedback=decision.feedback if decision is not None else None,
        )

    def _handle_call(self, call: ToolCall, dispatch: dict[str, Toolset]) -> _CallOutcome:
        """Gate a tool call through the optional approver, then dispatch it.

        Returns the tool output together with the reviewer's :class:`ToolDecision`
        (``None`` when no approver gated the call). On a denial the tool is not
        executed; the reviewer's/operator's feedback is returned to the model as
        the tool result so it can adjust within its remaining iteration budget.
        """

        if self.approver is not None:
            decision = self.approver.review(call)
            if not decision.approved:
                feedback = decision.feedback or "no reason provided"
                logger.info("Tool call '%s' denied by approver: %s", call.name, feedback)
                return _CallOutcome(
                    f"DENIED by reviewer: {feedback}. "
                    "Do not retry this exact call; adjust your approach.",
                    decision,
                )
            if self.activity is not None:
                self.activity.on_tool_call(call.name)
            return _CallOutcome(self._dispatch(call, dispatch), decision)
        if self.activity is not None:
            self.activity.on_tool_call(call.name)
        return _CallOutcome(self._dispatch(call, dispatch), None)

    def _dispatch(self, call: ToolCall, dispatch: dict[str, Toolset]) -> str:
        """Execute a single tool call, returning text (errors are returned, not raised).

        Tool failures are surfaced back to the model as an error string so it can
        recover or report, rather than aborting the whole run.
        """

        toolset = dispatch.get(call.name)
        if toolset is None:
            logger.warning("Model requested unknown tool '%s'", call.name)
            return f"Error: unknown tool '{call.name}'."

        try:
            return toolset.call_tool(call.name, call.arguments)
        except Exception as exc:  # noqa: BLE001 - report failure back to the model
            logger.exception("Tool '%s' raised; reporting error to model", call.name)
            return f"Error executing tool '{call.name}': {exc}"
