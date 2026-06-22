from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()  # Allows local runs outside docker-compose.


@dataclass(frozen=True)
class Settings:
    """Frontend server settings, sourced from the environment.

    The frontend never talks to Postgres directly; it forwards ``/api/*`` to the
    packet database API (``DB_API_URL``), ``/api/plan/*`` to the scanner backend
    (``BACKEND_URL``), and serves the built React SPA from ``FRONTEND_STATIC_DIR``.
    """

    db_api_url: str
    backend_url: str
    static_dir: str
    proxy_timeout: float

    @staticmethod
    def from_env() -> "Settings":
        default_static = str(Path(__file__).resolve().parent / "static")
        return Settings(
            db_api_url=os.environ.get("DB_API_URL", "http://db-api:8000").rstrip("/"),
            backend_url=os.environ.get("BACKEND_URL", "http://scanner-backend:8000").rstrip("/"),
            static_dir=os.environ.get("FRONTEND_STATIC_DIR", default_static),
            proxy_timeout=float(os.environ.get("PROXY_TIMEOUT", "30")),
        )
