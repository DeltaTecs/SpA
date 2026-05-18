from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional


TERMINAL_STATUSES = {"completed", "failed"}


class PrescanRun:
    def __init__(
        self,
        *,
        event_id: int,
        provider: str,
        model: str,
    ):
        self.run_id = uuid.uuid4().hex
        self.event_id = event_id
        self.provider = provider
        self.model = model
        self.status = "queued"
        self.progress: list[dict[str, Any]] = []
        self.result_markdown = ""
        self.summary: Optional[dict[str, Any]] = None
        self.recording_id: Optional[int] = None
        self.error: Optional[str] = None
        self.created_at = time.time()
        self.updated_at = self.created_at
        self._lock = threading.RLock()

    def add_progress(self, message: str) -> None:
        with self._lock:
            self.progress.append({"timestamp": time.time(), "message": message})
            self.updated_at = time.time()

    def start(self) -> None:
        with self._lock:
            self.status = "running"
            self.updated_at = time.time()
            self.progress.append({"timestamp": time.time(), "message": "Pre-scan started."})

    def complete(self, *, result_markdown: str, summary: dict[str, Any], recording_id: Optional[int]) -> None:
        with self._lock:
            self.status = "completed"
            self.result_markdown = result_markdown
            self.summary = summary
            self.recording_id = recording_id
            self.progress.append({"timestamp": time.time(), "message": "Pre-scan completed."})
            self.updated_at = time.time()

    def fail(self, error: str) -> None:
        with self._lock:
            self.status = "failed"
            self.error = error
            self.progress.append({"timestamp": time.time(), "message": f"Pre-scan failed: {error}"})
            self.updated_at = time.time()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "run_id": self.run_id,
                "event_id": self.event_id,
                "provider": self.provider,
                "model": self.model,
                "status": self.status,
                "progress": list(self.progress),
                "result_markdown": self.result_markdown,
                "summary": self.summary,
                "recording_id": self.recording_id,
                "error": self.error,
                "created_at": self.created_at,
                "updated_at": self.updated_at,
            }


class PrescanSessionStore:
    def __init__(self) -> None:
        self._runs: dict[str, PrescanRun] = {}
        self._lock = threading.RLock()

    def create(self, *, event_id: int, provider: str, model: str) -> PrescanRun:
        run = PrescanRun(event_id=event_id, provider=provider, model=model)
        with self._lock:
            self._runs[run.run_id] = run
        return run

    def get(self, run_id: str) -> Optional[PrescanRun]:
        with self._lock:
            return self._runs.get(run_id)
