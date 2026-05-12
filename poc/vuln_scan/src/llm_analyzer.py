from __future__ import annotations

import json
import logging
from typing import Any, Optional, Sequence

try:
    from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
    from langchain_ollama import ChatOllama
except ImportError as exc:
    raise ImportError(
        "langchain packages are required. "
        "Install with: pip install langchain langchain-ollama langchain-community"
    ) from exc

try:
    from langchain_google_genai import ChatGoogleGenerativeAI
except ImportError:
    ChatGoogleGenerativeAI = None

try:
    from langchain_openai import ChatOpenAI
except ImportError:
    ChatOpenAI = None

from prompts import build_phase_one_system_prompt
from scanner_models import ScanSummary


logger = logging.getLogger(__name__)


class ScannerAnalyzer:
    """Run the phase-one vulnerability triage prompt with read-only tools."""

    def __init__(
        self,
        model: str = "qwen3:8b",
        ollama_host: str = "http://localhost:11434",
        provider: str = "ollama",
        api_key: Optional[str] = None,
        api_base_url: Optional[str] = None,
    ):
        self.model_name = model
        self.ollama_host = ollama_host
        self.provider = provider
        self.api_key = api_key
        self.api_base_url = api_base_url
        self.llm = None

    def initialize(self) -> None:
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
        elif self.provider in ("openai", "deepseek"):
            if ChatOpenAI is None:
                raise ImportError(
                    "langchain-openai is required for OpenAI-compatible providers. "
                    "Install with: pip install langchain-openai"
                )
            if not self.api_key:
                raise ValueError(f"--api-key is required when using --provider {self.provider}")
            base_url = self.api_base_url
            if self.provider == "deepseek" and not base_url:
                base_url = "https://api.deepseek.com"
            provider_label = "DeepSeek" if self.provider == "deepseek" else "OpenAI"
            logger.info("Initializing %s with model: %s", provider_label, self.model_name)
            kwargs = {
                "model": self.model_name,
                "api_key": self.api_key,
                "temperature": 0.1,
            }
            if base_url:
                kwargs["base_url"] = base_url
            self.llm = ChatOpenAI(**kwargs)
        else:
            logger.info("Initializing ChatOllama with model: %s", self.model_name)
            self.llm = ChatOllama(
                model=self.model_name,
                base_url=self.ollama_host,
                temperature=0.1,
            )
        logger.info("LLM initialized successfully")

    def summarize_event(
        self,
        *,
        event_id: int,
        recording_id: Optional[int],
        event_context: str,
        tools: Sequence[Any],
        user_context: str = "",
        has_app_details: bool = False,
        has_user_actions: bool = False,
        max_rounds: int = 12,
    ) -> ScanSummary:
        if self.llm is None:
            raise RuntimeError("Analyzer is not initialized")

        llm_with_tools = self.llm.bind_tools(list(tools))
        prompt_parts = []
        if user_context:
            prompt_parts.append(user_context)
        prompt_parts.append(
            "=== Target Event ===\n"
            f"event_id: {event_id}\n"
            f"recording_id: {recording_id if recording_id is not None else 'null'}"
        )
        prompt_parts.append(event_context)

        messages = [
            SystemMessage(
                content=build_phase_one_system_prompt(
                    has_app_details=has_app_details,
                    has_user_actions=has_user_actions,
                )
            ),
            HumanMessage(content="\n\n".join(prompt_parts)),
        ]

        response_text = self._run_tool_conversation(
            llm_with_tools,
            messages,
            list(tools),
            event_id=event_id,
            max_rounds=max_rounds,
        )
        if response_text is None:
            response_text = ""

        try:
            raw = _parse_json_object(response_text)
            return ScanSummary.from_dict(
                raw,
                event_id=event_id,
                recording_id=recording_id,
            )
        except Exception as exc:
            logger.warning("Could not parse phase-one JSON summary: %s", exc)
            return ScanSummary(
                event_id=event_id,
                recording_id=recording_id,
                most_interesting_packet_id=None,
                packet_content="",
                event_summary=response_text.strip() or "(LLM returned no summary)",
                suspected_trigger="",
                entrypoint_rationale="",
            )

    def _run_tool_conversation(
        self,
        llm_with_tools,
        messages: list,
        tools: list,
        *,
        event_id: int,
        max_rounds: int,
    ) -> Optional[str]:
        for round_num in range(max_rounds):
            try:
                response = llm_with_tools.invoke(messages)
            except Exception as exc:
                logger.error("LLM invocation failed (round %d): %s", round_num, exc)
                return None

            messages.append(response)
            if not getattr(response, "tool_calls", None):
                return _content_to_text(response.content)

            for tool_call in response.tool_calls:
                tool_name = tool_call["name"]
                tool_args = tool_call["args"]
                logger.debug("Tool call: %s(%s)", tool_name, tool_args)

                result = "(tool not found)"
                for tool in tools:
                    if tool.name == tool_name:
                        try:
                            result = tool.invoke(tool_args)
                        except Exception as exc:
                            result = f"Error: {exc}"
                        break

                messages.append(
                    ToolMessage(content=str(result), tool_call_id=tool_call["id"])
                )

        logger.warning("Max tool-call rounds reached for event %d", event_id)
        return _content_to_text(messages[-1].content) if messages else None


def _content_to_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict):
                parts.append(str(item.get("text") or item.get("content") or item))
            else:
                parts.append(str(item))
        return "\n".join(parts)
    return str(content)


def _parse_json_object(text: str) -> dict[str, Any]:
    value = _parse_json_value(text)
    if not isinstance(value, dict):
        raise ValueError("expected JSON object")
    return value


def _parse_json_value(text: str) -> Any:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:].strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    decoder = json.JSONDecoder()
    for idx, char in enumerate(cleaned):
        if char not in "{[":
            continue
        try:
            value, _ = decoder.raw_decode(cleaned[idx:])
        except json.JSONDecodeError:
            continue
        return value
    raise ValueError("no JSON payload found")
