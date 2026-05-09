"""Small LangChain adapter for per-packet purpose analysis."""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

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

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

from prompts import build_packet_purpose_system_prompt


logger = logging.getLogger(__name__)


class PacketAnalyzer:
    """Initialize a chat model and run a bounded read-only tool loop."""

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
        """Instantiate the selected LangChain chat model."""

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
            return

        if self.provider == "deepseek":
            if OpenAI is None:
                raise ImportError(
                    "openai is required for DeepSeek thinking mode. "
                    "Install with: pip install openai"
                )
            if not self.api_key:
                raise ValueError("--api-key is required when using --provider deepseek")
            base_url = self.api_base_url or "https://api.deepseek.com"
            logger.info("Initializing DeepSeek with model: %s", self.model_name)
            self.deepseek_client = OpenAI(api_key=self.api_key, base_url=base_url)
            return

        if self.provider == "openai":
            if ChatOpenAI is None:
                raise ImportError(
                    "langchain-openai is required for OpenAI-compatible providers. "
                    "Install with: pip install langchain-openai"
                )
            if not self.api_key:
                raise ValueError(
                    f"--api-key is required when using --provider {self.provider}"
                )
            logger.info("Initializing OpenAI with model: %s", self.model_name)
            kwargs = {
                "model": self.model_name,
                "api_key": self.api_key,
                "temperature": 0.1,
            }
            if self.api_base_url:
                kwargs["base_url"] = self.api_base_url
            self.llm = ChatOpenAI(**kwargs)
            return

        logger.info("Initializing ChatOllama with model: %s", self.model_name)
        self.llm = ChatOllama(
            model=self.model_name,
            base_url=self.ollama_host,
            temperature=0.1,
        )

    def analyze_packet_purpose(
        self,
        *,
        packet_id: int,
        packet_info_text: str,
        tools: list,
        recording_id: int,
        user_context: str = "",
        has_app_details: bool = False,
        has_user_actions: bool = False,
        max_rounds: int = 6,
    ) -> str:
        """Return a concise purpose note for one packet."""

        if self.llm is None and self.deepseek_client is None:
            raise RuntimeError("LLM is not initialized")

        system_prompt = build_packet_purpose_system_prompt(
            has_app_details=has_app_details,
            has_user_actions=has_user_actions,
        )
        human_prompt = _packet_prompt(
            packet_id=packet_id,
            packet_info_text=packet_info_text,
            recording_id=recording_id,
            user_context=user_context,
        )

        if self.provider == "deepseek":
            result = self._run_deepseek_tool_conversation(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": human_prompt},
                ],
                tools=tools,
                packet_id=packet_id,
                max_rounds=max_rounds,
            )
            return (
                result
                or "Purpose: unknown\nEvidence: no model response\nUncertainty: high"
            )

        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=human_prompt),
        ]

        llm_with_tools = self.llm.bind_tools(tools) if tools else self.llm
        result = self._run_tool_conversation(
            llm_with_tools,
            messages,
            tools,
            packet_id=packet_id,
            max_rounds=max_rounds,
        )
        return result or "Purpose: unknown\nEvidence: no model response\nUncertainty: high"

    def analyze_packet(
        self,
        packet_id: int,
        packet_info_text: str,
        tools: list,
        **kwargs: Any,
    ) -> str:
        """Compatibility wrapper for old callers."""

        return self.analyze_packet_purpose(
            packet_id=packet_id,
            packet_info_text=packet_info_text,
            tools=tools,
            recording_id=int(kwargs.get("recording_id", 0)),
            user_context=str(kwargs.get("user_context") or ""),
            has_app_details=bool(kwargs.get("has_app_details", False)),
            has_user_actions=bool(kwargs.get("has_user_actions", False)),
            max_rounds=int(kwargs.get("max_rounds", 6)),
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
        """Let the model call read-only tools, then return the final text."""

        for _ in range(max_rounds):
            try:
                response = llm_with_tools.invoke(messages)
            except Exception as exc:
                logger.error("LLM invocation failed for packet %d: %s", packet_id, exc)
                return None

            messages.append(response)
            tool_calls = getattr(response, "tool_calls", None)
            if not tool_calls:
                return _strip_model_reasoning(_content_to_text(response.content))

            for tool_call in tool_calls:
                tool_name = tool_call["name"]
                tool_args = tool_call["args"]
                logger.debug(
                    "Packet %d tool call: %s(%s)",
                    packet_id,
                    tool_name,
                    tool_args,
                )
                messages.append(
                    ToolMessage(
                        content=_call_tool(tools, tool_name, tool_args),
                        tool_call_id=tool_call["id"],
                    )
                )

        logger.warning("Max tool-call rounds reached for packet %d", packet_id)
        return None

    def _run_deepseek_tool_conversation(
        self,
        *,
        messages: list,
        tools: list,
        packet_id: int,
        max_rounds: int,
    ) -> Optional[str]:
        """Run DeepSeek thinking mode while preserving reasoning_content."""

        openai_tools = [_to_openai_tool(tool) for tool in tools]
        for _ in range(max_rounds):
            try:
                kwargs: Dict[str, Any] = {
                    "model": self.model_name,
                    "messages": messages,
                    "reasoning_effort": "high",
                    "extra_body": {"thinking": {"type": "enabled"}},
                }
                if openai_tools:
                    kwargs["tools"] = openai_tools
                response = self.deepseek_client.chat.completions.create(**kwargs)
            except Exception as exc:
                logger.error(
                    "DeepSeek invocation failed for packet %d: %s",
                    packet_id,
                    exc,
                )
                return None

            assistant_message = _completion_message_dict(response)
            messages.append(assistant_message)
            tool_calls = assistant_message.get("tool_calls") or []
            if not tool_calls:
                return _strip_model_reasoning(
                    str(assistant_message.get("content") or "")
                )

            for tool_call in tool_calls:
                tool_name, tool_args = _tool_call_name_args(tool_call)
                logger.debug(
                    "Packet %d DeepSeek tool call: %s(%s)",
                    packet_id,
                    tool_name,
                    tool_args,
                )
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_call["id"],
                        "content": _call_tool(tools, tool_name, tool_args),
                    }
                )

        logger.warning("Max DeepSeek tool-call rounds reached for packet %d", packet_id)
        return None


def _packet_prompt(
    *,
    packet_id: int,
    packet_info_text: str,
    recording_id: int,
    user_context: str,
) -> str:
    """Build the human prompt for the current packet."""

    parts: List[str] = [f"Recording ID: {recording_id}"]
    if user_context:
        parts.append(user_context)
    parts.append(f"Analyze packet_id={packet_id}.\n\n{packet_info_text}")
    return "\n\n".join(parts)


def _call_tool(tools: list, tool_name: str, tool_args: dict) -> str:
    """Invoke one LangChain tool by name."""

    for tool in tools:
        if tool.name == tool_name:
            try:
                return str(tool.invoke(tool_args))
            except Exception as exc:
                return f"Error: {exc}"
    return f"Error: tool {tool_name} not found"


def _to_openai_tool(tool: Any) -> Dict[str, Any]:
    """Convert a LangChain tool into an OpenAI-compatible tool schema."""

    schema = _tool_parameters_schema(tool)
    return {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": getattr(tool, "description", "") or "",
            "parameters": schema,
        },
    }


def _tool_parameters_schema(tool: Any) -> Dict[str, Any]:
    """Return the JSON schema object expected by OpenAI-compatible tools."""

    args_schema = getattr(tool, "args_schema", None)
    if args_schema is not None:
        if hasattr(args_schema, "model_json_schema"):
            schema = args_schema.model_json_schema()
        elif hasattr(args_schema, "schema"):
            schema = args_schema.schema()
        else:
            schema = {}
        return {
            "type": "object",
            "properties": schema.get("properties", {}),
            "required": schema.get("required", []),
        }

    args = getattr(tool, "args", None)
    if isinstance(args, dict):
        return {"type": "object", "properties": args, "required": []}

    return {"type": "object", "properties": {}, "required": []}


def _completion_message_dict(response: Any) -> Dict[str, Any]:
    """Extract the raw assistant message, including DeepSeek reasoning_content."""

    if hasattr(response, "model_dump"):
        dumped = response.model_dump(exclude_none=True)
        raw = dumped["choices"][0]["message"]
    else:
        raw = response["choices"][0]["message"]

    message = {
        key: raw[key]
        for key in ("role", "content", "reasoning_content", "tool_calls")
        if key in raw and raw[key] is not None
    }
    message.setdefault("role", "assistant")

    # DeepSeek requires reasoning_content to be sent back after tool calls.
    reasoning = message.get("reasoning_content")
    if reasoning is None:
        raw_message = response.choices[0].message
        reasoning = getattr(raw_message, "reasoning_content", None)
        if reasoning is not None:
            message["reasoning_content"] = reasoning

    return message


def _tool_call_name_args(tool_call: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
    """Parse one OpenAI-compatible tool call into a name and argument dict."""

    function = tool_call.get("function") or {}
    name = str(function.get("name") or "")
    raw_args = function.get("arguments") or "{}"
    if isinstance(raw_args, dict):
        return name, raw_args
    try:
        parsed = json.loads(raw_args)
    except json.JSONDecodeError:
        parsed = {}
    return name, parsed


def _content_to_text(content: Any) -> str:
    """Normalize provider-specific message content into plain text."""

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


def _strip_model_reasoning(text: str) -> str:
    """Drop provider reasoning blocks and keep the visible answer."""

    return re.sub(
        r"<think>.*?</think>\s*",
        "",
        text,
        flags=re.DOTALL | re.IGNORECASE,
    ).strip()
