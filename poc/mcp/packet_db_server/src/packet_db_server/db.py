from __future__ import annotations

import os
import time
from typing import Optional

from .config import DbConfig

try:
    import psycopg2
except ImportError as e:  # pragma: no cover
    raise RuntimeError("psycopg2-binary is required") from e


def connect_db():
    dsn = os.environ.get("DB_DSN")
    if dsn:
        return psycopg2.connect(dsn)

    cfg = DbConfig.from_env()
    return psycopg2.connect(
        host=cfg.host,
        port=cfg.port,
        dbname=cfg.name,
        user=cfg.user,
        password=cfg.password,
    )


def retry_connect_db(max_attempts: int = 30, sleep_seconds: float = 1.0):
    last_exc: Optional[Exception] = None
    for _ in range(max_attempts):
        try:
            conn = connect_db()
            conn.autocommit = True
            return conn
        except Exception as e:  # noqa: BLE001
            last_exc = e
            time.sleep(sleep_seconds)
    raise RuntimeError(f"Could not connect to DB after {max_attempts} attempts: {last_exc}")
