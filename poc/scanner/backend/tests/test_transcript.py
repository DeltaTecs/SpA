"""Tests for serializing/classifying an agentic run's transcript."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from llm import TranscriptStep  # noqa: E402

from app.transcript import serialize_step, serialize_transcript  # noqa: E402


class TestSerializeTranscript(unittest.TestCase):
    def test_reasoning_step_round_trips(self):
        step = TranscriptStep(kind="reasoning", text="thinking", reasoning="deep")
        self.assertEqual(
            serialize_step(step),
            {"kind": "reasoning", "text": "thinking", "reasoning": "deep"},
        )

    def test_tool_call_is_classified_and_preserves_fields(self):
        step = TranscriptStep(
            kind="tool_call",
            call_id="c1",
            tool_name="list_packets",
            toolset_name="packet-db",
            arguments={"recording_id": 1},
            output="rows",
            approved=True,
            review_feedback="ok",
        )
        out = serialize_step(step)
        self.assertEqual(out["category"], "db")
        self.assertEqual(out["tool_name"], "list_packets")
        self.assertEqual(out["arguments"], {"recording_id": 1})
        self.assertEqual(out["output"], "rows")
        self.assertTrue(out["approved"])
        self.assertEqual(out["review_feedback"], "ok")

    def test_categories_for_each_toolset(self):
        cases = {
            "packet-db": "db",
            "tavily": "search",
            "hexstrike-bash": "bash",
            "hexstrike-tools": "hexstrike",
            "something-else": "other",
            None: "other",
        }
        for toolset_name, expected in cases.items():
            step = TranscriptStep(kind="tool_call", toolset_name=toolset_name)
            self.assertEqual(serialize_step(step)["category"], expected, toolset_name)

    def test_serialize_transcript_preserves_order(self):
        steps = [
            TranscriptStep(kind="reasoning", text="a"),
            TranscriptStep(kind="tool_call", toolset_name="hexstrike-bash", tool_name="run"),
        ]
        out = serialize_transcript(steps)
        self.assertEqual([s["kind"] for s in out], ["reasoning", "tool_call"])
        self.assertEqual(out[1]["category"], "bash")


if __name__ == "__main__":
    unittest.main()
