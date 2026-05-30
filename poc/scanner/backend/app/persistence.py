"""Persist finished scan snapshots to the db-api for durable storage.

The scanner backend itself holds no DB logic (see :mod:`app.config`): when a job
reaches a terminal state its final snapshot is POSTed to the db-api, which owns
all Postgres access. Persistence is *best-effort* — any failure is logged and
swallowed so it never affects the result returned to the user — and a no-op when
``DB_API_URL`` is unset, so the backend stays usable standalone.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import httpx

from .config import Settings

logger = logging.getLogger(__name__)

#: Generous timeout: snapshots can be large, but persistence runs off the
#: request path so a slow db-api never blocks the user.
_TIMEOUT = 15.0


def persist_scan(
    settings: Settings,
    *,
    recording_id: int,
    scan_type: str,
    provider: Optional[str],
    model: Optional[str],
    payload: Dict[str, Any],
) -> None:
    """Best-effort POST of a finished scan snapshot to the db-api. Never raises."""
    base_url = settings.db_api_url
    if not base_url:
        logger.debug(
            "DB_API_URL unset; skipping persistence of %s scan (recording=%s).",
            scan_type,
            recording_id,
        )
        return
    url = f"{base_url.rstrip('/')}/recordings/{recording_id}/scans"
    body = {"scan_type": scan_type, "provider": provider, "model": model, "payload": payload}
    try:
        response = httpx.post(url, json=body, timeout=_TIMEOUT)
        response.raise_for_status()
        logger.info("Persisted %s scan for recording %s.", scan_type, recording_id)
    except Exception as exc:  # noqa: BLE001 - persistence must never break a scan
        logger.warning(
            "Could not persist %s scan for recording %s: %s", scan_type, recording_id, exc
        )
