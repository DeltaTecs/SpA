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


def _flag(name: str, default: bool) -> bool:
    """Parse a boolean env var; unset/blank falls back to ``default``."""
    value = _optional(name)
    if value is None:
        return default
    return value.lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    """Backend configuration. See ``from_env`` for the environment variables."""

    mcp_packet_db_url: str
    tavily_url: Optional[str]
    hexstrike_bash_url: Optional[str]
    hexstrike_tools_url: Optional[str]
    hexstrike_tools_admin_token: Optional[str]
    openai_api_key: Optional[str]
    deepseek_api_key: Optional[str]
    #: Base URL of the db-api. When set, finished scans are persisted there
    #: (the db-api owns all DB access); when unset, persistence is disabled.
    db_api_url: Optional[str]
    max_concurrency: int
    default_max_iterations: int
    mcp_timeout: float
    llm_timeout: float

    # --- Tavily cost controls (web-search MCP) -------------------------------
    # Defaults here are the *safe* values used when a Settings is constructed
    # directly (e.g. in tests): caching on but in-memory only, conservative
    # parameters, unlimited budget. ``from_env`` applies the production defaults
    # (notably a persistent SQLite cache path).
    tavily_cache_enabled: bool = True
    #: Local SQLite file for the persistent cache tier; ``None`` = memory only.
    tavily_cache_path: Optional[str] = None
    tavily_cache_ttl_seconds: float = 604800.0  # 7 days
    tavily_cache_max_entries: int = 1000
    #: Forced search depth (``basic`` = 1 credit vs ``advanced`` = 2).
    tavily_search_depth: str = "basic"
    #: Cap on ``max_results`` per search (<= 0 disables the cap).
    tavily_max_results: int = 5
    tavily_allow_extract: bool = True
    tavily_allow_crawl: bool = False
    tavily_include_raw_content: bool = False
    #: Max billable Tavily calls per job (<= 0 = unlimited).
    tavily_call_budget_per_job: int = 0

    @staticmethod
    def from_env() -> "Settings":
        tavily_key = _optional("TAVILY_API_KEY")
        tavily_url = (
            f"https://mcp.tavily.com/mcp/?tavilyApiKey={tavily_key}" if tavily_key else None
        )
        hexstrike_tools_url = _optional("HEXSTRIKE_TOOLS_MCP_URL")
        hexstrike_tools_admin_token = _optional("HEXSTRIKE_TOOLS_ADMIN_TOKEN")
        if hexstrike_tools_url and not hexstrike_tools_admin_token:
            raise ValueError(
                "HEXSTRIKE_TOOLS_ADMIN_TOKEN must be configured when "
                "HEXSTRIKE_TOOLS_MCP_URL is set"
            )
        return Settings(
            mcp_packet_db_url=os.environ.get(
                "MCP_PACKET_DB_URL", "http://mcp-packet-db:8765/mcp"
            ),
            tavily_url=tavily_url,
            hexstrike_bash_url=_optional("HEXSTRIKE_BASH_MCP_URL"),
            hexstrike_tools_url=hexstrike_tools_url,
            hexstrike_tools_admin_token=hexstrike_tools_admin_token,
            openai_api_key=_optional("OPENAI_API_KEY"),
            deepseek_api_key=_optional("DEEPSEEK_API_KEY"),
            db_api_url=_optional("DB_API_URL"),
            max_concurrency=int(os.environ.get("PLAN_MAX_CONCURRENCY", "4")),
            default_max_iterations=int(os.environ.get("PLAN_MAX_ITERATIONS", "10")),
            mcp_timeout=float(os.environ.get("PLAN_MCP_TIMEOUT", "60")),
            llm_timeout=float(os.environ.get("PLAN_LLM_TIMEOUT", "120")),
            tavily_cache_enabled=_flag("TAVILY_CACHE_ENABLED", True),
            # Unset -> persistent local SQLite; explicit empty string -> memory only.
            tavily_cache_path=os.environ.get(
                "TAVILY_CACHE_PATH", ".cache/tavily.sqlite"
            ).strip()
            or None,
            tavily_cache_ttl_seconds=float(
                os.environ.get("TAVILY_CACHE_TTL_SECONDS", "604800")
            ),
            tavily_cache_max_entries=int(
                os.environ.get("TAVILY_CACHE_MAX_ENTRIES", "1000")
            ),
            tavily_search_depth=os.environ.get("TAVILY_SEARCH_DEPTH", "basic").strip()
            or "basic",
            tavily_max_results=int(os.environ.get("TAVILY_MAX_RESULTS", "5")),
            tavily_allow_extract=_flag("TAVILY_ALLOW_EXTRACT", True),
            tavily_allow_crawl=_flag("TAVILY_ALLOW_CRAWL", False),
            tavily_include_raw_content=_flag("TAVILY_INCLUDE_RAW_CONTENT", False),
            tavily_call_budget_per_job=int(
                os.environ.get("TAVILY_CALL_BUDGET_PER_JOB", "0")
            ),
        )

    def api_key_for(self, provider_type: str) -> Optional[str]:
        """Return the configured API key for a keyed provider, else ``None``."""
        return {
            "openai": self.openai_api_key,
            "deepseek": self.deepseek_api_key,
        }.get((provider_type or "").lower())


settings = Settings.from_env()
