"""The :class:`AnalysisTask` contract and shared toolset assembly.

An analysis task is a self-contained unit of LLM work over a single
:class:`~app.schemas.Exchange`: it owns its prompts, the toolsets the model may
use, its result schema and the parser that turns the model's text into a typed
:class:`~app.schemas.TaskResult`. The job runner is task-agnostic — it only ever
calls the methods declared here — so adding a new analysis is a matter of
implementing this contract and registering it (see :mod:`app.tasks.registry`).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List, Literal, Mapping

from llm import CallBudget, McpToolset

from ..config import Settings
from ..schemas import Exchange, TaskResult
from ..toolsets import build_tavily_toolset

PromptPartScope = Literal["system", "user"]
PromptOverrideMap = Mapping[str, str]


@dataclass(frozen=True)
class TaskPromptPart:
    """One editable prompt block exposed by an analysis task."""

    id: str
    title: str
    scope: PromptPartScope
    content: str
    description: str = ""


def build_default_toolsets(
    settings: Settings, *, budget: CallBudget | None = None
) -> List[object]:
    """The default toolset bundle: packet-db (always) + Tavily web search (if set).

    A fresh packet-db :class:`McpToolset` is built per call so each concurrent
    worker owns its own connections. Tavily is only included when
    ``TAVILY_API_KEY`` was configured, and is assembled with cost controls
    (caching, parameter clamping, optional per-job ``budget``) via
    :func:`app.toolsets.build_tavily_toolset`.
    """
    toolsets: List[object] = [
        McpToolset(settings.mcp_packet_db_url, name="packet-db", timeout=settings.mcp_timeout)
    ]
    if settings.tavily_url:
        toolsets.append(build_tavily_toolset(settings, budget=budget))
    return toolsets


class AnalysisTask(ABC):
    """Base class every analysis task type implements."""

    #: Stable identifier used in the API and the task registry.
    task_type: str = "base"
    #: Human-readable label/description for the UI task picker.
    title: str = ""
    description: str = ""
    #: Bumped when the result payload shape changes, so consumers can adapt.
    result_version: int = 1

    def prompt_parts(self) -> List[TaskPromptPart]:
        """Editable prompt blocks for this task, in UI/render order."""
        return []

    def normalize_prompt_overrides(
        self, prompt_overrides: PromptOverrideMap | None
    ) -> Dict[str, str]:
        """Validate and copy prompt overrides before a job is submitted."""
        overrides = dict(prompt_overrides or {})
        if not overrides:
            return overrides

        known_ids = {part.id for part in self.prompt_parts()}
        unknown_ids = sorted(set(overrides) - known_ids)
        if unknown_ids:
            known = ", ".join(sorted(known_ids)) or "<none>"
            unknown = ", ".join(unknown_ids)
            raise ValueError(f"Unknown prompt part(s): {unknown}. Available: {known}.")
        return overrides

    @abstractmethod
    def build_system_prompt(self) -> str:
        """The system message framing the model's role and output contract."""

    def build_system_prompt_for_run(
        self, prompt_overrides: PromptOverrideMap | None = None
    ) -> str:
        """Build the system prompt for one run, applying optional overrides."""
        self.normalize_prompt_overrides(prompt_overrides)
        return self.build_system_prompt()

    @abstractmethod
    def build_user_prompt(self, exchange: Exchange) -> str:
        """Render the per-exchange instruction. The only exchange-coupled method."""

    def build_user_prompt_for_run(
        self, exchange: Exchange, prompt_overrides: PromptOverrideMap | None = None
    ) -> str:
        """Build the user prompt for one run, applying optional overrides."""
        self.normalize_prompt_overrides(prompt_overrides)
        return self.build_user_prompt(exchange)

    def select_toolsets(
        self, settings: Settings, *, budget: CallBudget | None = None
    ) -> List[object]:
        """Toolsets exposed to the model for this task (override to add/restrict).

        ``budget`` is an optional per-job ceiling threaded into any billable
        toolset (e.g. Tavily web search); ``None`` means unlimited.
        """
        return build_default_toolsets(settings, budget=budget)

    @abstractmethod
    def parse_output(self, raw: str) -> TaskResult:
        """Parse the model's final text into a typed, versioned result."""
