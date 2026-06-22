"""Test suite for the LLM / MCP client module.

Adds ``poc/scanner/backend`` to ``sys.path`` so ``import llm`` resolves when the
suite is run via ``python -m unittest discover``.
"""

from __future__ import annotations

import sys
from pathlib import Path

_BACKEND_DIR = Path(__file__).resolve().parents[2]
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))
