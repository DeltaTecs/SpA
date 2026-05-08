from __future__ import annotations

import logging
from typing import List, Optional

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

from prompts import build_system_prompt


logger = logging.getLogger(__name__)


class PacketAnalyzer:
    """Drive LLM-based packet classification via tool calling."""

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
        """Run one tool-calling conversation for a single packet."""

        llm_with_tools = self.llm.bind_tools(tools)

        logger.info(
            ">>> Inspecting packet_id=%d - sending to LLM for classification",
            packet_id,
        )

        user_prompt_parts: List[str] = []
        if user_context:
            user_prompt_parts.append(user_context)
        user_prompt_parts.append(
            f"Classify the following packet (packet_id={packet_id}).\n\n"
            f"{packet_info_text}\n\n"
            "Use the tools to inspect surrounding packets or retrieve "
            "full payloads if you need more context. Then assign the "
            "packet to an existing or new event."
        )

        messages = [
            SystemMessage(
                content=build_system_prompt(
                    has_app_details=has_app_details,
                    has_user_actions=has_user_actions,
                )
            ),
            HumanMessage(content="\n\n".join(user_prompt_parts)),
        ]

        for round_num in range(max_rounds):
            try:
                response = llm_with_tools.invoke(messages)
            except Exception as e:
                logger.error("LLM invocation failed (round %d): %s", round_num, e)
                return None

            messages.append(response)
            if not getattr(response, "tool_calls", None):
                return response.content

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
        return messages[-1].content if messages else None
