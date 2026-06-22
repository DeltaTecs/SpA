"""Pydantic request/response models for the scanner backend HTTP surface.

These are intentionally self-contained (the backend shares no code with the
db-api): ``Exchange`` mirrors the db-api shape, since the frontend fetches
exchanges from the db-api and posts the selected/edited ones here.
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator


# --- exchanges (mirrors the db-api exchanges schema) -------------------------


class Endpoint(BaseModel):
    ip: Optional[str] = None
    port: Optional[int] = None


class HttpExchangeInfo(BaseModel):
    method: Optional[str] = None
    scheme: Optional[str] = None
    path: Optional[str] = None
    endpoint_path: Optional[str] = None
    param_names: List[str] = Field(default_factory=list)
    status_code: Optional[int] = None
    host: Optional[str] = None


class Exchange(BaseModel):
    """One data exchange to analyse. Only ``id`` is required; the rest is the
    (possibly user-edited) detail the frontend fetched from the db-api."""

    id: str
    kind: Literal["conversation", "http_pair"] = "conversation"
    transport: Optional[str] = None
    local: Optional[Endpoint] = None
    remote: Optional[Endpoint] = None
    representative_packet_ids: List[int] = Field(default_factory=list)
    packet_count: int = 0
    payload_bytes: int = 0
    protocols: List[str] = Field(default_factory=list)
    http: Optional[HttpExchangeInfo] = None
    dedup_key: Optional[str] = None


# --- providers & tasks -------------------------------------------------------


ReasoningEffort = Literal["low", "medium", "high", "max"]


class ProviderOption(BaseModel):
    type: str
    requires_key: bool
    default_model: Optional[str] = None
    model_options: List[str] = Field(default_factory=list)
    reasoning_effort_options: List[ReasoningEffort] = Field(default_factory=list)


class ProviderList(BaseModel):
    providers: List[ProviderOption]


PromptPartScope = Literal["system", "user"]
MAX_PROMPT_PART_CHARS = 12000
MAX_PROMPT_OVERRIDES = 20
MAX_PROMPT_PART_ID_CHARS = 80


class PromptPartInfo(BaseModel):
    id: str = Field(..., min_length=1, max_length=MAX_PROMPT_PART_ID_CHARS)
    title: str
    scope: PromptPartScope
    content: str = Field(..., max_length=MAX_PROMPT_PART_CHARS)
    description: str = ""


class TaskTypeInfo(BaseModel):
    task_type: str
    title: str
    description: str
    result_version: int
    prompt_parts: List[PromptPartInfo] = Field(default_factory=list)


class TaskTypeList(BaseModel):
    tasks: List[TaskTypeInfo]


# --- jobs --------------------------------------------------------------------


class StartJobRequest(BaseModel):
    recording_id: int
    provider: str
    model: Optional[str] = None
    reasoning_effort: Optional[ReasoningEffort] = None
    task_type: str = "vulnerability_checks"
    max_iterations: int = Field(10, ge=1, le=50)
    exchanges: List[Exchange] = Field(default_factory=list)
    prompt_overrides: Dict[str, str] = Field(default_factory=dict)

    @field_validator("prompt_overrides")
    @classmethod
    def validate_prompt_overrides(cls, value: Dict[str, str]) -> Dict[str, str]:
        if len(value) > MAX_PROMPT_OVERRIDES:
            raise ValueError(f"At most {MAX_PROMPT_OVERRIDES} prompt overrides are allowed.")
        for key, content in value.items():
            if not key or len(key) > MAX_PROMPT_PART_ID_CHARS:
                raise ValueError(
                    "Prompt override ids must be non-empty and at most 80 characters."
                )
            if len(content) > MAX_PROMPT_PART_CHARS:
                raise ValueError(
                    f"Prompt override '{key}' exceeds {MAX_PROMPT_PART_CHARS} characters."
                )
        return value


class StartJobResponse(BaseModel):
    job_id: str


class TaskResult(BaseModel):
    """Generic, versioned envelope for any analysis task's structured output.

    ``payload`` is task-specific (for ``vulnerability_checks`` it is
    ``{"checks": [...]}``). The job/store/transport never inspect it, so new task
    types can ship their own payload shape and frontend renderer.
    """

    task_type: str
    result_version: int
    payload: Dict[str, Any] = Field(default_factory=dict)


class VulnerabilityCheck(BaseModel):
    """One suggested vulnerability check (the ``vulnerability_checks`` payload)."""

    title: str = "(untitled)"
    description: str = ""
    rationale: str = ""
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    technique: Optional[str] = None
    references: List[str] = Field(default_factory=list)


TaskStatus = Literal["pending", "running", "done", "error", "cancelled"]
JobLifecycle = Literal["running", "done", "error", "cancelled"]


class ExchangeTaskStatus(BaseModel):
    exchange_id: str
    status: TaskStatus
    result: Optional[TaskResult] = None
    error: Optional[str] = None
    iterations: Optional[int] = None
    stopped_on_limit: Optional[bool] = None
    #: Human-readable current phase while running (None when not running).
    activity: Optional[str] = None


class JobStatus(BaseModel):
    job_id: str
    status: JobLifecycle
    provider: str
    model: Optional[str] = None
    reasoning_effort: Optional[ReasoningEffort] = None
    task_type: str
    tasks: List[ExchangeTaskStatus] = Field(default_factory=list)


# --- MCP tool catalogue ------------------------------------------------------


ToolCategory = Literal["db", "search", "bash", "hexstrike"]


class McpToolInfo(BaseModel):
    name: str
    description: str = ""


class McpToolsetInfo(BaseModel):
    name: str
    category: ToolCategory
    tools: List[McpToolInfo] = Field(default_factory=list)


class McpToolsResponse(BaseModel):
    toolsets: List[McpToolsetInfo] = Field(default_factory=list)


# --- pentest -----------------------------------------------------------------


ReviewMode = Literal["manual", "automatic"]
PentestVerdict = Literal["confirmed", "inconclusive", "not_exploitable"]
MAX_TOOL_CONSTRAINTS_CHARS = 4000
MAX_PENTEST_ITEMS = 100


class ReviewerConfig(BaseModel):
    """LLM that judges tool calls in automatic review mode."""

    provider: str
    model: Optional[str] = None
    reasoning_effort: Optional[ReasoningEffort] = None
    max_iterations: int = Field(2, ge=1, le=20)


class ToolConfig(BaseModel):
    """How the model's MCP tool use is governed during a pentest job."""

    #: When true, db + web-search tools run without approval (read-only/low risk).
    exempt_db_search: bool = True
    #: Tool names the model is allowed to see/use. Empty means "expose none".
    allowed_tools: List[str] = Field(default_factory=list)
    #: Free-text constraints (e.g. rate limiting) honoured by the agent and
    #: enforced by the automatic reviewer.
    tool_constraints: str = Field("", max_length=MAX_TOOL_CONSTRAINTS_CHARS)
    review_mode: ReviewMode = "manual"
    reviewer: Optional[ReviewerConfig] = None
    #: In automatic mode, route auto-denied calls to manual review as well.
    review_auto_denied_manually: bool = False


class PentestItem(BaseModel):
    """One plan item to investigate: a single check plus its exchange context."""

    id: str
    exchange: Exchange
    check: VulnerabilityCheck


class StartPentestJobRequest(BaseModel):
    recording_id: int
    provider: str
    model: Optional[str] = None
    reasoning_effort: Optional[ReasoningEffort] = None
    max_iterations: int = Field(10, ge=1, le=50)
    items: List[PentestItem] = Field(default_factory=list)
    concurrent: bool = False
    tool_config: ToolConfig = Field(default_factory=ToolConfig)
    #: Persist the finished job snapshot to the db-api. Disabled by callers (e.g.
    #: the Analysis Queue) that manage their own session-only result lifecycle.
    persist: bool = True

    @field_validator("items")
    @classmethod
    def validate_items(cls, value: List[PentestItem]) -> List[PentestItem]:
        if not value:
            raise ValueError("At least one item is required to start a pentest job.")
        if len(value) > MAX_PENTEST_ITEMS:
            raise ValueError(f"At most {MAX_PENTEST_ITEMS} items are allowed.")
        return value


class StartPentestJobResponse(BaseModel):
    job_id: str


class PendingReview(BaseModel):
    """A tool call awaiting a human decision (manual or escalated auto-deny)."""

    review_id: str
    item_id: str
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    auto_reason: Optional[str] = None
    created_at: float


class PentestItemStatus(BaseModel):
    item_id: str
    title: str
    status: TaskStatus
    result: Optional[TaskResult] = None
    error: Optional[str] = None
    iterations: Optional[int] = None
    stopped_on_limit: Optional[bool] = None
    #: Human-readable current phase while running (None when not running).
    activity: Optional[str] = None
    pending_reviews: List[PendingReview] = Field(default_factory=list)


class PentestJobStatus(BaseModel):
    job_id: str
    status: JobLifecycle
    provider: str
    model: Optional[str] = None
    reasoning_effort: Optional[ReasoningEffort] = None
    items: List[PentestItemStatus] = Field(default_factory=list)


class ReviewDecisionRequest(BaseModel):
    approved: bool
    hint: str = Field("", max_length=MAX_TOOL_CONSTRAINTS_CHARS)


# --- tool-use transcript -----------------------------------------------------

#: Like ``ToolCategory`` but with ``"other"`` for a toolset we don't recognise.
TranscriptToolCategory = Literal["db", "search", "bash", "hexstrike", "other"]


class TranscriptStep(BaseModel):
    """One step of a recorded agentic run (see :class:`llm.TranscriptStep`).

    ``kind="reasoning"`` carries the model's interim ``text`` / ``reasoning``
    between tool calls. ``kind="tool_call"`` carries one executed call: its
    ``arguments``, the owning ``toolset_name`` and coarse ``category``, the
    reviewer's verdict (``approved`` is null when no approver gated the call, with
    ``review_feedback``), and the tool ``output`` fed back to the model.
    """

    kind: Literal["reasoning", "tool_call"]
    text: Optional[str] = None
    reasoning: Optional[str] = None
    call_id: Optional[str] = None
    tool_name: Optional[str] = None
    toolset_name: Optional[str] = None
    category: Optional[TranscriptToolCategory] = None
    arguments: Optional[Dict[str, Any]] = None
    output: Optional[str] = None
    approved: Optional[bool] = None
    review_feedback: Optional[str] = None


class TranscriptResponse(BaseModel):
    """A recorded tool-use transcript for one analysis item or guided turn."""

    item_id: Optional[str] = None
    steps: List[TranscriptStep] = Field(default_factory=list)


# --- exploit -----------------------------------------------------------------


ExploitVerdict = Literal["exploited", "not_exploitable", "inconclusive"]


class ExploitFinding(BaseModel):
    """The carried-over analysis result an exploit item starts from.

    Populated from a completed Analysis Queue report (the ``pentest`` task
    payload). All fields are optional so a partial finding is still accepted.
    """

    verdict: str = ""
    summary: str = ""
    evidence: List[str] = Field(default_factory=list)


class ExploitItem(BaseModel):
    """One issue to exploit: a check, its exchange context, and the prior finding."""

    id: str
    exchange: Exchange
    check: VulnerabilityCheck
    finding: ExploitFinding = Field(default_factory=ExploitFinding)


class StartExploitJobRequest(BaseModel):
    recording_id: int
    provider: str
    model: Optional[str] = None
    reasoning_effort: Optional[ReasoningEffort] = None
    max_iterations: int = Field(10, ge=1, le=50)
    items: List[ExploitItem] = Field(default_factory=list)
    concurrent: bool = False
    tool_config: ToolConfig = Field(default_factory=ToolConfig)
    #: Persist the finished job snapshot to the db-api. Disabled by callers (e.g.
    #: the Exploit Queue) that manage their own session-only result lifecycle.
    persist: bool = False

    @field_validator("items")
    @classmethod
    def validate_items(cls, value: List[ExploitItem]) -> List[ExploitItem]:
        if not value:
            raise ValueError("At least one item is required to start an exploit job.")
        if len(value) > MAX_PENTEST_ITEMS:
            raise ValueError(f"At most {MAX_PENTEST_ITEMS} items are allowed.")
        return value


class StartExploitJobResponse(BaseModel):
    job_id: str


# --- guided analysis (interactive chat) --------------------------------------


MAX_GUIDED_MESSAGES = 200
MAX_GUIDED_MESSAGE_CHARS = 20000
MAX_GUIDED_SYSTEM_PROMPT_CHARS = 12000


class GuidedChatMessage(BaseModel):
    """One turn of the guided-analysis conversation (final content only; the
    intermediate tool-call rounds within a turn are not echoed back as history)."""

    role: Literal["user", "assistant"]
    content: str = Field(..., max_length=MAX_GUIDED_MESSAGE_CHARS)


class StartGuidedTurnRequest(BaseModel):
    """Run one agentic chat turn over the supplied conversation.

    ``messages`` is the full prior conversation including the new user message
    (which must be last). A blank ``system_prompt`` defers to the runner's
    default pretext.
    """

    provider: str
    model: Optional[str] = None
    reasoning_effort: Optional[ReasoningEffort] = None
    max_iterations: int = Field(10, ge=1, le=50)
    system_prompt: str = Field("", max_length=MAX_GUIDED_SYSTEM_PROMPT_CHARS)
    messages: List[GuidedChatMessage] = Field(default_factory=list)
    tool_config: ToolConfig = Field(default_factory=ToolConfig)

    @field_validator("messages")
    @classmethod
    def validate_messages(cls, value: List[GuidedChatMessage]) -> List[GuidedChatMessage]:
        if not value:
            raise ValueError("At least one message is required to start a guided turn.")
        if len(value) > MAX_GUIDED_MESSAGES:
            raise ValueError(f"At most {MAX_GUIDED_MESSAGES} messages are allowed.")
        if value[-1].role != "user":
            raise ValueError("The final message must be from the user.")
        return value


class StartGuidedTurnResponse(BaseModel):
    job_id: str


class GuidedTurnStatus(BaseModel):
    """Status and result of one agentic chat turn (poll until terminal)."""

    job_id: str
    status: JobLifecycle
    #: The assistant's final reply once the turn is done (None while running).
    content: Optional[str] = None
    error: Optional[str] = None
    iterations: Optional[int] = None
    stopped_on_limit: Optional[bool] = None
    #: Human-readable current phase while running (None when not running).
    activity: Optional[str] = None
    pending_reviews: List[PendingReview] = Field(default_factory=list)


# --- termination -------------------------------------------------------------


class ToolTerminationInfo(BaseModel):
    """The result of asking one MCP server to kill its tool processes."""

    name: str
    category: ToolCategory
    ok: bool
    detail: str = ""


class TerminationResult(BaseModel):
    """Response to a job-cancel request: the job was cancelled and the per-server
    outcome of killing MCP tool processes."""

    job_id: str
    cancelled: bool
    tools: List[ToolTerminationInfo] = Field(default_factory=list)
