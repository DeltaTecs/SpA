"""Runtime settings for the scanner backend, sourced from the environment.

The backend wraps the standalone ``llm`` package and exposes it over HTTP. It
never touches the database directly: packet detail reaches the model through the
packet-db MCP server, and web search through Tavily's remote MCP server.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from dotenv import load_dotenv

load_dotenv()  # Allows local runs outside docker-compose.


def _optional(name: str) -> Optional[str]:
    value = os.environ.get(name)
    value = value.strip() if value else ""
    return value or None


@dataclass(frozen=True)
class Settings:
    """Backend configuration. See ``from_env`` for the environment variables."""

    mcp_packet_db_url: str
    tavily_url: Optional[str]
    hexstrike_bash_url: Optional[str]
    hexstrike_tools_url: Optional[str]
    openai_api_key: Optional[str]
    deepseek_api_key: Optional[str]
    #: Base URL of the db-api. When set, finished scans are persisted there
    #: (the db-api owns all DB access); when unset, persistence is disabled.
    db_api_url: Optional[str]
    max_concurrency: int
    default_max_iterations: int
    mcp_timeout: float
    llm_timeout: float

    @staticmethod
    def from_env() -> "Settings":
        tavily_key = _optional("TAVILY_API_KEY")
        tavily_url = (
            f"https://mcp.tavily.com/mcp/?tavilyApiKey={tavily_key}" if tavily_key else None
        )
        return Settings(
            mcp_packet_db_url=os.environ.get(
                "MCP_PACKET_DB_URL", "http://mcp-packet-db:8765/mcp"
            ),
            tavily_url=tavily_url,
            hexstrike_bash_url=_optional("HEXSTRIKE_BASH_MCP_URL"),
            hexstrike_tools_url=_optional("HEXSTRIKE_TOOLS_MCP_URL"),
            openai_api_key=_optional("OPENAI_API_KEY"),
            deepseek_api_key=_optional("DEEPSEEK_API_KEY"),
            db_api_url=_optional("DB_API_URL"),
            max_concurrency=int(os.environ.get("PLAN_MAX_CONCURRENCY", "4")),
            default_max_iterations=int(os.environ.get("PLAN_MAX_ITERATIONS", "10")),
            mcp_timeout=float(os.environ.get("PLAN_MCP_TIMEOUT", "60")),
            llm_timeout=float(os.environ.get("PLAN_LLM_TIMEOUT", "120")),
        )

    def api_key_for(self, provider_type: str) -> Optional[str]:
        """Return the configured API key for a keyed provider, else ``None``."""
        return {
            "openai": self.openai_api_key,
            "deepseek": self.deepseek_api_key,
        }.get((provider_type or "").lower())


settings = Settings.from_env()
