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
from typing import List

from llm import McpToolset

from ..config import Settings
from ..schemas import Exchange, TaskResult


def build_default_toolsets(settings: Settings) -> List[object]:
    """The default toolset bundle: packet-db (always) + Tavily web search (if set).

    A fresh :class:`McpToolset` is built per call so each concurrent worker owns
    its own connections. Tavily is only included when ``TAVILY_API_KEY`` was
    configured; otherwise the model still has the packet tools.
    """
    toolsets: List[object] = [
        McpToolset(settings.mcp_packet_db_url, name="packet-db", timeout=settings.mcp_timeout)
    ]
    if settings.tavily_url:
        toolsets.append(
            McpToolset(settings.tavily_url, name="tavily", timeout=settings.mcp_timeout)
        )
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

    @abstractmethod
    def build_system_prompt(self) -> str:
        """The system message framing the model's role and output contract."""

    @abstractmethod
    def build_user_prompt(self, exchange: Exchange) -> str:
        """Render the per-exchange instruction. The only exchange-coupled method."""

    def select_toolsets(self, settings: Settings) -> List[object]:
        """Toolsets exposed to the model for this task (override to add/restrict)."""
        return build_default_toolsets(settings)

    @abstractmethod
    def parse_output(self, raw: str) -> TaskResult:
        """Parse the model's final text into a typed, versioned result."""
