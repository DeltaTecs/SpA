"""LLM-backed "smart" approver for phase-two MCP tool calls.

The smart approver lets a dedicated LLM decide whether a non-database MCP tool
call may run without a human in the loop. It approves a call only when the call

* satisfies every constraint the user stated in the UI,
* poses no risk to the local machine, and
* does not exploit a remote target beyond what is needed to prove a
  vulnerability.

Anything the reviewer rejects (or cannot evaluate) is handed back for manual
approval, so rejecting is always the safe default.

When the run enables "suggest improvement", the approver is also given the
Tavily search/extract tools and may attach a minor improvement suggestion (for
example an extra flag) to its decision; that suggestion travels back to the
analysis LLM as part of the feedback for a rejected call.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional, Sequence

from llm_analyzer import ScannerAnalyzer
from scan_logger import ScanRunLogger


logger = logging.getLogger(__name__)


class SmartToolApprover:
    """Review individual MCP tool calls with a configurable reviewer LLM."""

    def __init__(
        self,
        *,
        analyzer: ScannerAnalyzer,
        constraints: str,
        analysis_types: Sequence[str],
        event_id: int,
        suggestion_tools: Optional[Sequence[Any]] = None,
        cancel_callback: Optional[Callable[[], bool]] = None,
        scan_logger: Optional[ScanRunLogger] = None,
    ) -> None:
        self._analyzer = analyzer
        self._constraints = constraints
        self._analysis_types = list(analysis_types)
        self._event_id = event_id
        # Tavily search/extract tools the reviewer may use to research a minor
        # improvement to a call. Empty unless "suggest improvement" is enabled.
        self._suggestion_tools = list(suggestion_tools or [])
        self._cancel_callback = cancel_callback
        self._scan_logger = scan_logger

    def review(self, tool_call: dict[str, Any]) -> dict[str, Any]:
        """Return a decision dict ``{approved, reasoning, error}`` for a call.

        This never raises: any failure is reported as a non-approving decision
        with ``error`` set, which callers treat as "fall back to manual".
        """
        try:
            return self._analyzer.evaluate_tool_approval(
                tool_call=tool_call,
                constraints=self._constraints,
                analysis_types=self._analysis_types,
                event_id=self._event_id,
                suggestion_tools=self._suggestion_tools,
                cancel_callback=self._cancel_callback,
                scan_logger=self._scan_logger,
            )
        except Exception as exc:  # noqa: BLE001 - reviewer must not crash the run
            logger.error("Smart approval evaluation failed: %s", exc)
            if self._scan_logger is not None:
                self._scan_logger.error(
                    "Smart approval evaluation failed: %s", exc
                )
            return {
                "approved": False,
                "reasoning": f"Smart approver could not evaluate the call: {exc}",
                "suggestion": "",
                "error": True,
            }
