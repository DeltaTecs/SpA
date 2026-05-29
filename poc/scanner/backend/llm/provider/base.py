"""Provider-neutral value objects and the abstract provider contract.

All LLM providers (OpenAI, DeepSeek, local) speak in terms of the small set of
dataclasses defined here, so the orchestrator (:mod:`llm.client`) and the MCP
layer never depend on any vendor-specific request/response shapes.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ToolSpec:
    """A tool advertised to the LLM, in provider-neutral JSON-schema form.

    ``parameters`` is a JSON Schema object describing the tool's arguments
    (this is exactly what MCP returns as ``inputSchema``).
    """

    name: str
    description: str
    parameters: dict


@dataclass(frozen=True)
class ToolCall:
    """A single tool invocation requested by the model."""

    id: str
    name: str
    arguments: dict


@dataclass
class ChatMessage:
    """One entry in the conversation transcript.

    ``role`` is one of ``"system"``, ``"user"``, ``"assistant"`` or ``"tool"``.
    Assistant messages may carry ``tool_calls``; ``tool`` messages must set
    ``tool_call_id`` (and usually ``name``) to link a result to its request.
    """

    role: str
    content: str | None = None
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str | None = None
    name: str | None = None


@dataclass(frozen=True)
class ChatResult:
    """The model's response to a :meth:`BaseProvider.chat` call.

    Either ``content`` (a final textual answer) or ``tool_calls`` (work the
    model wants executed before it can answer) — or both — may be present.
    """

    content: str | None = None
    tool_calls: list[ToolCall] = field(default_factory=list)


class BaseProvider(ABC):
    """Abstract base every LLM provider inherits from.

    Concrete providers receive their credentials and endpoint configuration via
    the constructor (the factory supplies ``api_key``; see
    :mod:`llm.provider.factory`). Local providers may be constructed without an
    API key.
    """

    #: Human-readable provider name, set by subclasses (e.g. ``"openai"``).
    name: str = "base"

    def __init__(
        self,
        *,
        api_key: str | None,
        model: str,
        base_url: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = base_url
        self.timeout = timeout
        logger.info(
            "Initialised %s provider (model=%s, base_url=%s, api_key=%s)",
            self.name,
            self.model,
            self.base_url or "<default>",
            "set" if api_key else "none",
        )

    @abstractmethod
    def chat(
        self,
        messages: list[ChatMessage],
        tools: list[ToolSpec] | None = None,
    ) -> ChatResult:
        """Send the conversation (and available tools) and return the response."""

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"{type(self).__name__}(model={self.model!r}, base_url={self.base_url!r})"
