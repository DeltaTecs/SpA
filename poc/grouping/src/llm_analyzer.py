"""LLM adapter for read-only analysis and structured grouping decisions."""

from __future__ import annotations

import json
import logging
from typing import Any, List, Optional, Sequence

try:
    from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
    from langchain_ollama import ChatOllama
except ImportError as e:
    raise ImportError(
        "langchain packages are required. "
        "Install with: pip install langchain langchain-ollama langchain-community"
    ) from e

try:
    from langchain_google_genai import ChatGoogleGenerativeAI
except ImportError:
    ChatGoogleGenerativeAI = None

try:
    from langchain_openai import ChatOpenAI
except ImportError:
    ChatOpenAI = None

from grouping_models import ContextSummary, EventCandidate, PacketDecision
from prompts import (
    build_assignment_system_prompt,
    build_candidate_system_prompt,
    build_summary_system_prompt,
)


logger = logging.getLogger(__name__)


class PacketAnalyzer:
    """Drive LLM-based packet classification via read-only tool calling."""

    def __init__(
        self,
        model: str = "qwen3:8b",
        ollama_host: str = "http://localhost:11434",
        provider: str = "ollama",
        api_key: Optional[str] = None,
    ):
        self.model_name = model
        self.ollama_host = ollama_host
        self.provider = provider
        self.api_key = api_key
        self.llm = None

    def initialize(self):
        """Instantiate the selected chat model provider."""
        if self.provider == "gemini":
            if ChatGoogleGenerativeAI is None:
                raise ImportError(
                    "langchain-google-genai is required for Gemini. "
                    "Install with: pip install langchain-google-genai"
                )
            if not self.api_key:
                raise ValueError("--api-key is required when using --provider gemini")
            logger.info("Initializing Gemini with model: %s", self.model_name)
            self.llm = ChatGoogleGenerativeAI(
                model=self.model_name,
                google_api_key=self.api_key,
                temperature=0.1,
            )
        elif self.provider == "openai":
            if ChatOpenAI is None:
                raise ImportError(
                    "langchain-openai is required for OpenAI. "
                    "Install with: pip install langchain-openai"
                )
            if not self.api_key:
                raise ValueError("--api-key is required when using --provider openai")
            logger.info("Initializing OpenAI with model: %s", self.model_name)
            self.llm = ChatOpenAI(
                model=self.model_name,
                api_key=self.api_key,
                temperature=0.1,
            )
        else:
            logger.info("Initializing ChatOllama with model: %s", self.model_name)
            self.llm = ChatOllama(
                model=self.model_name,
                base_url=self.ollama_host,
                temperature=0.1,
            )
        logger.info("LLM initialized successfully")

    def summarize_context(
        self,
        *,
        summary_id: str,
        kind: str,
        label: str,
        packet_ids: Sequence[int],
        context_text: str,
        user_context: str = "",
        has_app_details: bool = False,
        has_user_actions: bool = False,
    ) -> ContextSummary:
        """Summarize a conversation, HTTP stream, or time window."""

        # Pass-1 summaries compress large packet contexts before candidate
        # generation and per-packet assignment.
        prompt_parts: List[str] = []
        if user_context:
            prompt_parts.append(user_context)
        prompt_parts.append(
            f"Summary id: {summary_id}\n"
            f"Context kind: {kind}\n"
            f"Label: {label}\n"
            f"Packet IDs: {list(packet_ids)}\n\n"
            f"{context_text}"
        )

        messages = [
            SystemMessage(
                content=build_summary_system_prompt(
                    has_app_details=has_app_details,
                    has_user_actions=has_user_actions,
                )
            ),
            HumanMessage(content="\n\n".join(prompt_parts)),
        ]

        try:
            response = self.llm.invoke(messages)
            text = _content_to_text(response.content).strip()
        except Exception as e:
            logger.error("LLM summary failed for %s: %s", summary_id, e)
            text = ""

        if not text:
            # Keep the pipeline moving if the model refuses or fails to answer.
            text = f"{label}; packets {', '.join(str(pid) for pid in packet_ids)}"

        return ContextSummary(
            summary_id=summary_id,
            kind=kind,
            label=label,
            packet_ids=list(packet_ids),
            text=text,
        )

    def propose_event_candidates(
        self,
        *,
        summaries: Sequence[ContextSummary],
        user_context: str = "",
        has_app_details: bool = False,
        has_user_actions: bool = False,
    ) -> List[EventCandidate]:
        """Ask the LLM to propose event candidates from pass-1 summaries."""

        # Candidate creation is non-persistent. The orchestrator creates a DB
        # event only after a later packet decision selects the candidate.
        prompt_parts: List[str] = []
        if user_context:
            prompt_parts.append(user_context)
        prompt_parts.append("\n\n".join(summary.compact() for summary in summaries))

        messages = [
            SystemMessage(
                content=build_candidate_system_prompt(
                    has_app_details=has_app_details,
                    has_user_actions=has_user_actions,
                )
            ),
            HumanMessage(content="\n\n".join(prompt_parts)),
        ]

        try:
            response = self.llm.invoke(messages)
            raw_candidates = _parse_json_list(_content_to_text(response.content))
        except Exception as e:
            logger.error("LLM event candidate generation failed: %s", e)
            raw_candidates = []

        candidates: List[EventCandidate] = []
        seen_descriptions: set[str] = set()
        for raw in raw_candidates:
            if not isinstance(raw, dict):
                continue
            description = str(raw.get("description") or "").strip()
            if not description:
                continue
            normalized = description.casefold()
            if normalized in seen_descriptions:
                continue
            seen_descriptions.add(normalized)

            source_summary_ids = [
                str(item)
                for item in raw.get("source_summary_ids", [])
                if str(item).strip()
            ]
            packet_ids = _int_list(raw.get("packet_ids", []))
            rationale = str(raw.get("rationale") or "").strip()
            candidates.append(
                EventCandidate(
                    candidate_id=f"candidate_{len(candidates) + 1}",
                    description=description,
                    source_summary_ids=source_summary_ids,
                    packet_ids=packet_ids,
                    rationale=rationale,
                )
            )

        if candidates:
            return candidates

        # Fallback candidates preserve useful summary structure when candidate
        # JSON is unavailable.
        return [
            EventCandidate(
                candidate_id=f"candidate_{idx + 1}",
                description=summary.label,
                source_summary_ids=[summary.summary_id],
                packet_ids=summary.packet_ids,
                rationale="Fallback candidate derived from a pass-1 summary.",
            )
            for idx, summary in enumerate(summaries[:20])
        ]

    def decide_packet_assignment(
        self,
        *,
        packet_id: int,
        packet_info_text: str,
        tools: list,
        summaries: Sequence[ContextSummary],
        candidates: Sequence[EventCandidate],
        existing_events_text: str,
        recording_id: int,
        user_context: str = "",
        has_app_details: bool = False,
        has_user_actions: bool = False,
        max_rounds: int = 10,
    ) -> Optional[PacketDecision]:
        """Return a structured decision without mutating the database."""

        llm_with_tools = self.llm.bind_tools(tools)
        logger.info(">>> Inspecting packet_id=%d for structured assignment", packet_id)

        # The prompt includes only relevant summaries/candidates to keep each
        # assignment decision bounded.
        prompt_parts: List[str] = []
        if user_context:
            prompt_parts.append(user_context)

        prompt_parts.extend(
            [
                f"Current recording_id: {recording_id}",
                "=== Current Packet ===\n"
                f"Classify packet_id={packet_id}.\n\n{packet_info_text}",
                "=== Existing Persisted Events ===\n" + existing_events_text,
                "=== Pass 1 Summaries ===\n"
                + "\n\n".join(summary.compact() for summary in summaries),
                "=== Pass 2 Event Candidates ===\n"
                + "\n\n".join(candidate.compact() for candidate in candidates),
                "Return the JSON decision object now. You may call read-only "
                "tools first if more evidence is needed.",
            ]
        )

        messages = [
            SystemMessage(
                content=build_assignment_system_prompt(
                    has_app_details=has_app_details,
                    has_user_actions=has_user_actions,
                )
            ),
            HumanMessage(content="\n\n".join(prompt_parts)),
        ]

        response_text = self._run_tool_conversation(
            llm_with_tools,
            messages,
            tools,
            packet_id=packet_id,
            max_rounds=max_rounds,
        )
        if response_text is None:
            return None

        try:
            return PacketDecision.from_dict(_parse_json_object(response_text))
        except Exception as e:
            logger.error(
                "Could not parse structured decision for packet %d: %s; raw=%r",
                packet_id,
                e,
                response_text[:500],
            )
            return None

    def analyze_packet(
        self,
        packet_id: int,
        packet_info_text: str,
        tools: list,
        *,
        max_rounds: int = 10,
        user_context: str = "",
        has_app_details: bool = False,
        has_user_actions: bool = False,
    ) -> Optional[str]:
        """Backward-compatible read-only packet analysis entrypoint."""

        # Retained for callers that still expect free-form analysis, but the
        # bound tool list still has no mutating tools.
        llm_with_tools = self.llm.bind_tools(tools)
        messages = [
            SystemMessage(
                content=build_assignment_system_prompt(
                    has_app_details=has_app_details,
                    has_user_actions=has_user_actions,
                )
            ),
            HumanMessage(
                content=(
                    f"{user_context}\n\n" if user_context else ""
                )
                + f"Analyze packet_id={packet_id} without persisting anything.\n\n"
                + packet_info_text,
            ),
        ]
        return self._run_tool_conversation(
            llm_with_tools,
            messages,
            tools,
            packet_id=packet_id,
            max_rounds=max_rounds,
        )

    def _run_tool_conversation(
        self,
        llm_with_tools,
        messages: list,
        tools: list,
        *,
        packet_id: int,
        max_rounds: int,
    ) -> Optional[str]:
        """Run a bounded read-only tool-calling loop."""
        for round_num in range(max_rounds):
            try:
                response = llm_with_tools.invoke(messages)
            except Exception as e:
                logger.error("LLM invocation failed (round %d): %s", round_num, e)
                return None

            messages.append(response)
            if not getattr(response, "tool_calls", None):
                return _content_to_text(response.content)

            for tool_call in response.tool_calls:
                tool_name = tool_call["name"]
                tool_args = tool_call["args"]
                logger.debug("  Tool call: %s(%s)", tool_name, tool_args)

                result = "(tool not found)"
                for tool in tools:
                    if tool.name == tool_name:
                        try:
                            result = tool.invoke(tool_args)
                        except Exception as e:
                            result = f"Error: {e}"
                        break

                messages.append(
                    ToolMessage(content=str(result), tool_call_id=tool_call["id"])
                )

        logger.warning("Max tool-call rounds reached for packet %d", packet_id)
        return _content_to_text(messages[-1].content) if messages else None


def _content_to_text(content: Any) -> str:
    """Normalize provider-specific LangChain content into plain text."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: List[str] = []
        for item in content:
            if isinstance(item, dict):
                parts.append(str(item.get("text") or item.get("content") or item))
            else:
                parts.append(str(item))
        return "\n".join(parts)
    return str(content)


def _parse_json_object(text: str) -> dict:
    """Parse the assignment decision JSON object from model output."""
    value = _parse_json_value(text, "{", "}")
    if not isinstance(value, dict):
        raise ValueError("expected JSON object")
    return value


def _parse_json_list(text: str) -> list:
    """Parse the candidate JSON array from model output."""
    value = _parse_json_value(text, "[", "]")
    if not isinstance(value, list):
        raise ValueError("expected JSON array")
    return value


def _parse_json_value(text: str, start_char: str, end_char: str) -> Any:
    """Accept raw JSON or a single fenced/explained JSON payload."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:].strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    start = cleaned.find(start_char)
    end = cleaned.rfind(end_char)
    if start == -1 or end == -1 or end <= start:
        raise ValueError("no JSON payload found")
    return json.loads(cleaned[start : end + 1])


def _int_list(raw: Any) -> List[int]:
    """Best-effort integer list coercion for model-supplied packet IDs."""
    if not isinstance(raw, list):
        return []
    values: List[int] = []
    for item in raw:
        try:
            values.append(int(item))
        except (TypeError, ValueError):
            continue
    return values
