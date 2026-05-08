#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Command-line entrypoint for packet grouping.

The CLI lives here to preserve the original executable name. The actual
recording loop stays in analysis_runner so it can be reused without argparse.
"""
from __future__ import annotations

import argparse
import logging
import sys
from typing import List, Optional

from logging_setup import configure_logging
from user_context import (
    UserAction,
    format_user_context,
    load_app_details,
    parse_intend_file,
    recent_user_actions,
)


logger = logging.getLogger(__name__)

_LAZY_EXPORTS = {
    "PacketAnalyzer": ("llm_analyzer", "PacketAnalyzer"),
    "ToolTracker": ("packet_tools", "ToolTracker"),
    "build_langchain_tools": ("packet_tools", "build_langchain_tools"),
    "run_analysis": ("analysis_runner", "run_analysis"),
}

__all__ = [
    "PacketAnalyzer",
    "ToolTracker",
    "UserAction",
    "build_langchain_tools",
    "format_user_context",
    "load_app_details",
    "main",
    "parse_intend_file",
    "recent_user_actions",
    "run_analysis",
]


def __getattr__(name: str):
    if name not in _LAZY_EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    module_name, attr_name = _LAZY_EXPORTS[name]
    module = __import__(module_name, fromlist=[attr_name])
    value = getattr(module, attr_name)
    globals()[name] = value
    return value


def main():
    configure_logging()

    parser = argparse.ArgumentParser(
        description="Analyze network packets and group them into application events using LLM + MCP"
    )
    parser.add_argument(
        "-r",
        "--recording-id",
        type=int,
        required=True,
        help="Recording ID to analyze",
    )
    parser.add_argument(
        "--mcp-url",
        default="http://localhost:8765",
        help="MCP packet-db server URL (default: http://localhost:8765)",
    )
    parser.add_argument(
        "--provider",
        choices=["ollama", "gemini", "openai"],
        default="ollama",
        help="LLM provider to use (default: ollama)",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="API key for the chosen provider (required for gemini/openai)",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Model name (default depends on provider)",
    )
    parser.add_argument(
        "--ollama-host",
        default="http://localhost:11434",
        help="Ollama server URL (only used with --provider ollama)",
    )
    parser.add_argument(
        "--app-details",
        default=None,
        help="Path to app_details.txt describing the application and its behaviour",
    )
    parser.add_argument(
        "--user-intend",
        default=None,
        help="Path to user_intend.txt with timestamped user actions (MM:SS description)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v for DEBUG)",
    )

    args = parser.parse_args()

    if args.verbose >= 1:
        logging.getLogger().setLevel(logging.DEBUG)

    app_details: Optional[str] = None
    user_actions: Optional[List[UserAction]] = None

    if args.app_details:
        app_details = load_app_details(args.app_details)
    if args.user_intend:
        user_actions = parse_intend_file(args.user_intend)

    if args.model is None:
        defaults = {
            "gemini": "gemini-2.0-flash",
            "openai": "gpt-4o-mini",
            "ollama": "qwen3:8b",
        }
        args.model = defaults.get(args.provider, "qwen3:8b")

    from analysis_runner import run_analysis
    from llm_analyzer import PacketAnalyzer
    from mcp_client import MCPClient

    mcp_client = MCPClient(base_url=args.mcp_url)
    analyzer = PacketAnalyzer(
        model=args.model,
        ollama_host=args.ollama_host,
        provider=args.provider,
        api_key=args.api_key,
    )

    try:
        analyzer.initialize()
        run_analysis(
            mcp_client,
            analyzer,
            args.recording_id,
            app_details=app_details,
            user_actions=user_actions,
        )
    except Exception as e:
        logger.error("Analysis failed: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
