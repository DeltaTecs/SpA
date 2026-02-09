#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Ensure we can import from src/ when running from repo checkout
HERE = Path(__file__).resolve()
PROJECT_ROOT = HERE.parents[1]
SRC_DIR = PROJECT_ROOT / "src"
sys.path.insert(0, str(SRC_DIR))

from packet_db_server.server import packet_info, packet_payload_hexdump  # noqa: E402


def _print_json(title: str, obj) -> None:
    print("=" * 80)
    print(title)
    print("=" * 80)
    print(json.dumps(obj, indent=2, sort_keys=False))
    print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Test helper: print MCP tool outputs for a given packet_id (direct function call)."
    )
    parser.add_argument("packet_id", type=int, help="packet_id from the database")
    parser.add_argument(
        "--full-payload",
        action="store_true",
        help="Also print the full cleartext payload hexdump (can be large).",
    )
    parser.add_argument(
        "--db-host",
        default=os.environ.get("DB_HOST"),
        help="Override DB_HOST (default: env DB_HOST)",
    )
    parser.add_argument(
        "--db-port",
        default=os.environ.get("DB_PORT"),
        help="Override DB_PORT (default: env DB_PORT)",
    )
    parser.add_argument(
        "--db-name",
        default=os.environ.get("DB_NAME"),
        help="Override DB_NAME (default: env DB_NAME)",
    )
    parser.add_argument(
        "--db-user",
        default=os.environ.get("DB_USER"),
        help="Override DB_USER (default: env DB_USER)",
    )
    parser.add_argument(
        "--db-password",
        default=os.environ.get("DB_PASSWORD"),
        help="Override DB_PASSWORD (default: env DB_PASSWORD)",
    )

    args = parser.parse_args()

    # Only set env overrides when explicitly provided.
    if args.db_host is not None:
        os.environ["DB_HOST"] = str(args.db_host)
    if args.db_port is not None:
        os.environ["DB_PORT"] = str(args.db_port)
    if args.db_name is not None:
        os.environ["DB_NAME"] = str(args.db_name)
    if args.db_user is not None:
        os.environ["DB_USER"] = str(args.db_user)
    if args.db_password is not None:
        os.environ["DB_PASSWORD"] = str(args.db_password)

    info = packet_info(args.packet_id)
    _print_json(f"packet_info(packet_id={args.packet_id})", info)

    if args.full_payload:
        payload = packet_payload_hexdump(args.packet_id)
        _print_json(f"packet_payload_hexdump(packet_id={args.packet_id})", payload)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
