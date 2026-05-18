from __future__ import annotations

import json
import logging
from typing import Any, Callable, Dict, List, Optional, Sequence

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

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

from prompts import (
    build_phase_one_system_prompt,
    build_phase_two_system_prompt,
)
from scan_logger import ScanRunLogger
from scanner_models import ScanSummary


logger = logging.getLogger(__name__)


class ScannerAnalyzer:
    """Run scanner LLM prompts with MCP-backed tools."""

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
        self.deepseek_client = None

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
        elif self.provider == "deepseek":
            if OpenAI is None:
                raise ImportError(
                    "openai is required for DeepSeek. "
                    "Install with: pip install openai"
                )
            if not self.api_key:
                raise ValueError("--api-key is required when using --provider deepseek")
            base_url = self.api_base_url or "https://api.deepseek.com"
            logger.info(
                "Initializing DeepSeek with model: %s (thinking mode enabled)",
                self.model_name,
            )
            self.deepseek_client = OpenAI(api_key=self.api_key, base_url=base_url)
            self.llm = self.deepseek_client
        elif self.provider == "openai":
            if ChatOpenAI is None:
                raise ImportError(
                    "langchain-openai is required for OpenAI-compatible providers. "
                    "Install with: pip install langchain-openai"
                )
            if not self.api_key:
                raise ValueError("--api-key is required when using --provider openai")
            base_url = self.api_base_url
            logger.info("Initializing OpenAI with model: %s", self.model_name)
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
        tool_catalog: str = "",
        user_context: str = "",
        has_app_details: bool = False,
        has_user_actions: bool = False,
        max_rounds: int = 12,
        on_progress: Optional[Callable[[str], None]] = None,
        scan_logger: Optional[ScanRunLogger] = None,
    ) -> ScanSummary:
        if self.llm is None:
            raise RuntimeError("Analyzer is not initialized")

        prompt_parts = []
        if user_context:
            prompt_parts.append(user_context)
        prompt_parts.append(
            "=== Target Event ===\n"
            f"event_id: {event_id}\n"
            f"recording_id: {recording_id if recording_id is not None else 'null'}"
        )
        prompt_parts.append(event_context)
        if tool_catalog:
            prompt_parts.append(tool_catalog)

        system_prompt = build_phase_one_system_prompt(
            has_app_details=has_app_details,
            has_user_actions=has_user_actions,
        )
        human_prompt = "\n\n".join(prompt_parts)

        if scan_logger is not None:
            scan_logger.section("LLM PHASE 1 PROMPT")
            scan_logger.log_llm_request("system_prompt", system_prompt)
            scan_logger.log_llm_request("human_prompt", human_prompt)

        response_text = self._invoke_with_tools(
            system_prompt=system_prompt,
            human_prompt=human_prompt,
            tools=list(tools),
            event_id=event_id,
            max_rounds=max_rounds,
            on_progress=on_progress,
            scan_logger=scan_logger,
        )
        if response_text is None:
            response_text = ""

        if scan_logger is not None:
            scan_logger.section("LLM PHASE 1 FINAL RESPONSE")
            scan_logger.log_llm_response("final_summary_text", response_text)

        try:
            raw = _parse_json_object(response_text)
            return ScanSummary.from_dict(
                raw,
                event_id=event_id,
                recording_id=recording_id,
            )
        except Exception as exc:
            logger.warning("Could not parse phase-one JSON summary: %s", exc)
            if scan_logger is not None:
                scan_logger.warning(
                    "Could not parse phase-one JSON summary: %s", exc
                )
            return ScanSummary(
                event_id=event_id,
                recording_id=recording_id,
                most_interesting_packet_id=None,
                packet_content="",
                event_summary=response_text.strip() or "(LLM returned no summary)",
                suspected_trigger="",
                entrypoint_rationale="",
            )

    def analyze_vulnerabilities(
        self,
        *,
        event_id: int,
        recording_id: Optional[int],
        analysis_types: Sequence[str],
        constraints: str,
        event_context: str,
        tools: Sequence[Any],
        external_context: str = "",
        prescan_markdown: str = "",
        prior_reports_markdown: str = "",
        tool_catalog: str = "",
        has_app_details: bool = False,
        has_user_actions: bool = False,
        max_rounds: int = 24,
        on_progress: Optional[Callable[[str], None]] = None,
        scan_logger: Optional[ScanRunLogger] = None,
    ) -> str:
        if self.llm is None:
            raise RuntimeError("Analyzer is not initialized")

        system_prompt = build_phase_two_system_prompt(
            analysis_types=list(analysis_types),
            has_app_details=has_app_details,
            has_user_actions=has_user_actions,
            has_prescan=bool(prescan_markdown.strip()),
            has_prior_reports=bool(prior_reports_markdown.strip()),
        )

        prompt_parts: list[str] = []
        if external_context:
            prompt_parts.append(external_context)
        if constraints.strip():
            prompt_parts.append(
                "=== Analysis Constraints ===\n"
                f"{constraints.strip()}\n"
                "=== End Analysis Constraints ==="
            )
        if prescan_markdown.strip():
            prompt_parts.append(
                "=== Event Summary ===\n"
                f"{prescan_markdown.strip()}\n"
                "=== End Event Summary ==="
            )
        if prior_reports_markdown.strip():
            prompt_parts.append(
                "=== Prior Scan Reports ===\n"
                f"{prior_reports_markdown.strip()}\n"
                "=== End Prior Scan Reports ==="
            )
        prompt_parts.append(
            "=== Target Event ===\n"
            f"event_id: {event_id}\n"
            f"recording_id: {recording_id if recording_id is not None else 'null'}"
        )
        prompt_parts.append(event_context)
        if tool_catalog:
            prompt_parts.append(tool_catalog)

        human_prompt = "\n\n".join(prompt_parts)
        if on_progress:
            on_progress("Prompt prepared; invoking LLM vulnerability analysis.")

        if scan_logger is not None:
            scan_logger.section("LLM PHASE 2 PROMPT")
            scan_logger.log_llm_request("system_prompt", system_prompt)
            scan_logger.log_llm_request("human_prompt", human_prompt)

        response_text = self._invoke_with_tools(
            system_prompt=system_prompt,
            human_prompt=human_prompt,
            tools=list(tools),
            event_id=event_id,
            max_rounds=max_rounds,
            on_progress=on_progress,
            scan_logger=scan_logger,
        )
        if scan_logger is not None:
            scan_logger.section("LLM PHASE 2 FINAL RESPONSE")
            scan_logger.log_llm_response("final_analysis_text", response_text or "")
        return (response_text or "").strip() or "(LLM returned no analysis)"

    def _invoke_with_tools(
        self,
        *,
        system_prompt: str,
        human_prompt: str,
        tools: list,
        event_id: int,
        max_rounds: int,
        on_progress: Optional[Callable[[str], None]] = None,
        scan_logger: Optional[ScanRunLogger] = None,
    ) -> Optional[str]:
        if self.provider == "deepseek":
            return self._run_deepseek_tool_conversation(
                system_prompt=system_prompt,
                human_prompt=human_prompt,
                tools=tools,
                event_id=event_id,
                max_rounds=max_rounds,
                on_progress=on_progress,
                scan_logger=scan_logger,
            )

        llm_with_tools = self.llm.bind_tools(tools)
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=human_prompt),
        ]
        return self._run_tool_conversation(
            llm_with_tools,
            messages,
            tools,
            event_id=event_id,
            max_rounds=max_rounds,
            on_progress=on_progress,
            scan_logger=scan_logger,
        )

    def _run_tool_conversation(
        self,
        llm_with_tools,
        messages: list,
        tools: list,
        *,
        event_id: int,
        max_rounds: int,
        on_progress: Optional[Callable[[str], None]] = None,
        scan_logger: Optional[ScanRunLogger] = None,
    ) -> Optional[str]:
        for round_num in range(max_rounds):
            try:
                response = llm_with_tools.invoke(messages)
            except Exception as exc:
                logger.error("LLM invocation failed (round %d): %s", round_num, exc)
                if scan_logger is not None:
                    scan_logger.error(
                        "LLM invocation failed (round %d): %s", round_num, exc
                    )
                return None

            tool_calls = getattr(response, "tool_calls", None) or []
            messages.append(response)
            if scan_logger is not None:
                scan_logger.log_llm_response(
                    f"round_{round_num}",
                    {
                        "content": _content_to_text(response.content),
                        "tool_calls": [
                            {"name": call.get("name"), "args": call.get("args")}
                            for call in tool_calls
                        ],
                    },
                )
            if not tool_calls:
                return _content_to_text(response.content)

            for tool_call in tool_calls:
                tool_name = tool_call["name"]
                tool_args = tool_call["args"]
                logger.debug("Tool call: %s(%s)", tool_name, tool_args)
                if on_progress:
                    on_progress(f"LLM requested tool {tool_name}.")
                if scan_logger is not None:
                    scan_logger.log_tool_request(tool_name, tool_args, source="llm")

                result = "(tool not found)"
                for tool in tools:
                    if tool.name == tool_name:
                        try:
                            result = tool.invoke(tool_args)
                        except Exception as exc:
                            result = f"Error: {exc}"
                        break
                if scan_logger is not None:
                    scan_logger.log_tool_response(tool_name, result)

                messages.append(
                    ToolMessage(content=str(result), tool_call_id=tool_call["id"])
                )
            _emit_tool_results_received(on_progress, len(tool_calls))

        logger.warning("Max tool-call rounds reached for event %d", event_id)
        if scan_logger is not None:
            scan_logger.warning(
                "Max tool-call rounds reached for event %d", event_id
            )
        return _content_to_text(messages[-1].content) if messages else None

    def _run_deepseek_tool_conversation(
        self,
        *,
        system_prompt: str,
        human_prompt: str,
        tools: list,
        event_id: int,
        max_rounds: int,
        on_progress: Optional[Callable[[str], None]] = None,
        scan_logger: Optional[ScanRunLogger] = None,
    ) -> Optional[str]:
        """Run DeepSeek V4 thinking mode while preserving reasoning_content."""
        if self.deepseek_client is None:
            raise RuntimeError("DeepSeek client is not initialized")

        tool_specs = [_openai_tool_spec(tool) for tool in tools]
        tool_by_name = {tool.name: tool for tool in tools}
        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": human_prompt},
        ]

        for round_num in range(max_rounds):
            try:
                response = self.deepseek_client.chat.completions.create(
                    model=self.model_name,
                    messages=messages,
                    tools=tool_specs,
                    reasoning_effort="high",
                    extra_body={"thinking": {"type": "enabled"}},
                )
            except Exception as exc:
                logger.error("DeepSeek invocation failed (round %d): %s", round_num, exc)
                if scan_logger is not None:
                    scan_logger.error(
                        "DeepSeek invocation failed (round %d): %s", round_num, exc
                    )
                return None

            message = response.choices[0].message
            assistant_message = _openai_message_dict(message)
            messages.append(assistant_message)

            if scan_logger is not None:
                scan_logger.log_llm_response(
                    f"deepseek_round_{round_num}",
                    {
                        "content": getattr(message, "content", "") or "",
                        "reasoning_content": assistant_message.get(
                            "reasoning_content"
                        ),
                        "tool_calls": [
                            {
                                "name": getattr(call.function, "name", None),
                                "arguments": getattr(call.function, "arguments", None),
                            }
                            for call in (getattr(message, "tool_calls", None) or [])
                        ],
                    },
                )

            tool_calls = list(getattr(message, "tool_calls", None) or [])
            if not tool_calls:
                return str(getattr(message, "content", "") or "")

            for tool_call in tool_calls:
                tool_name = tool_call.function.name
                tool_args_text = tool_call.function.arguments or "{}"
                try:
                    tool_args = json.loads(tool_args_text)
                except json.JSONDecodeError:
                    tool_args = {}
                logger.debug("Tool call: %s(%s)", tool_name, tool_args)
                if on_progress:
                    on_progress(f"LLM requested tool {tool_name}.")
                if scan_logger is not None:
                    scan_logger.log_tool_request(tool_name, tool_args, source="llm")

                tool = tool_by_name.get(tool_name)
                if tool is None:
                    result = "(tool not found)"
                else:
                    try:
                        result = tool.invoke(tool_args)
                    except Exception as exc:
                        result = f"Error: {exc}"

                if scan_logger is not None:
                    scan_logger.log_tool_response(tool_name, result)

                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": str(result),
                    }
                )
            _emit_tool_results_received(on_progress, len(tool_calls))

        logger.warning("Max DeepSeek tool-call rounds reached for event %d", event_id)
        if scan_logger is not None:
            scan_logger.warning(
                "Max DeepSeek tool-call rounds reached for event %d", event_id
            )
        last = messages[-1].get("content") if messages else None
        return str(last or "")


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


def _emit_tool_results_received(
    on_progress: Optional[Callable[[str], None]],
    tool_count: int,
) -> None:
    if on_progress is None or tool_count <= 0:
        return
    if tool_count == 1:
        on_progress("MCP tool result received; invoking LLM.")
        return
    on_progress(f"{tool_count} MCP tool results received; invoking LLM.")


def _openai_tool_spec(tool: Any) -> Dict[str, Any]:
    """Convert a LangChain StructuredTool to OpenAI function-tool schema."""
    if getattr(tool, "args_schema", None) is not None:
        parameters = tool.args_schema.model_json_schema()
    else:
        parameters = {
            "type": "object",
            "properties": getattr(tool, "args", {}) or {},
            "required": [],
        }

    parameters = json.loads(json.dumps(parameters))
    parameters.pop("title", None)
    description = str(getattr(tool, "description", "") or "").strip()

    return {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": description,
            "parameters": parameters,
        },
    }


def _openai_message_dict(message: Any) -> Dict[str, Any]:
    """Preserve DeepSeek's reasoning_content on assistant tool-call turns."""
    if hasattr(message, "model_dump"):
        data = message.model_dump(mode="json", exclude_none=True)
    else:
        data = {
            "role": "assistant",
            "content": getattr(message, "content", "") or "",
        }

    data["role"] = "assistant"
    if "content" not in data:
        data["content"] = getattr(message, "content", "") or ""

    reasoning_content = getattr(message, "reasoning_content", None)
    if reasoning_content is None and getattr(message, "model_extra", None):
        reasoning_content = message.model_extra.get("reasoning_content")
    if reasoning_content is not None:
        data["reasoning_content"] = reasoning_content

    return data


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
