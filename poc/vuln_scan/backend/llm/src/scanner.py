#!/usr/bin/env python3
from __future__ import annotations

import argparse
import logging
import sys
from typing import List, Optional

from analysis_runner import run_phase_one_summary
from llm_analyzer import ScannerAnalyzer
from logging_setup import configure_logging
from mcp_client import MCPClient
from user_context import UserAction, load_app_details, parse_intend_file


logger = logging.getLogger(__name__)


def main() -> None:
    configure_logging()

    parser = argparse.ArgumentParser(
        description=(
            "Create a phase-one vulnerability assessment summary for a database event "
            "using an LLM and read-only packet MCP tools."
        )
    )
    parser.add_argument(
        "-e",
        "--event-id",
        type=int,
        required=True,
        help="Event ID to summarize",
    )
    parser.add_argument(
        "--mcp-url",
        default="http://localhost:8765",
        help="MCP packet-db server URL (default: http://localhost:8765)",
    )
    parser.add_argument(
        "--provider",
        choices=["ollama", "gemini", "openai", "deepseek"],
        default="ollama",
        help="LLM provider to use (default: ollama)",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="API key for the chosen provider (required for gemini/openai/deepseek)",
    )
    parser.add_argument(
        "--api-base-url",
        default=None,
        help="Override API base URL for OpenAI-compatible providers",
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
        "--output",
        default=None,
        help="Optional path for the generated Markdown summary",
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

    if args.model is None:
        defaults = {
            "gemini": "gemini-2.0-flash",
            "openai": "gpt-4o-mini",
            "deepseek": "deepseek-v4-flash",
            "ollama": "qwen3:8b",
        }
        args.model = defaults.get(args.provider, "qwen3:8b")

    app_details: Optional[str] = None
    user_actions: Optional[List[UserAction]] = None
    if args.app_details:
        app_details = load_app_details(args.app_details)
    if args.user_intend:
        user_actions = parse_intend_file(args.user_intend)

    try:
        mcp_client = MCPClient(base_url=args.mcp_url)
        analyzer = ScannerAnalyzer(
            model=args.model,
            ollama_host=args.ollama_host,
            provider=args.provider,
            api_key=args.api_key,
            api_base_url=args.api_base_url,
        )
        analyzer.initialize()
        run_phase_one_summary(
            mcp_client=mcp_client,
            analyzer=analyzer,
            event_id=args.event_id,
            app_details=app_details,
            user_actions=user_actions,
            output_path=args.output,
        )
    except Exception as exc:
        logger.error("Scanner phase 1 failed: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
