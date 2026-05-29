from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Iterator, Optional

import psycopg2
from psycopg2.extras import RealDictCursor

from .config import DbConfig


def _connect():
    cfg = DbConfig.from_env()
    if cfg.dsn:
        return psycopg2.connect(cfg.dsn)
    return psycopg2.connect(
        host=cfg.host,
        port=cfg.port,
        dbname=cfg.name,
        user=cfg.user,
        password=cfg.password,
    )


def _connect_with_retry(max_attempts: int = 30, sleep_seconds: float = 1.0):
    """Connect, retrying briefly so the API tolerates a slow-starting database."""
    last_exc: Optional[Exception] = None
    for _ in range(max_attempts):
        try:
            return _connect()
        except Exception as exc:  # noqa: BLE001 - retried below
            last_exc = exc
            time.sleep(sleep_seconds)
    raise RuntimeError(
        f"Could not connect to the database after {max_attempts} attempts: {last_exc}"
    )


@contextmanager
def connection() -> Iterator:
    """Yield a connection, committing on success and rolling back on error.

    Commit/rollback handling lives here so the same helper serves read
    queries today and additional data-changing queries later.
    """
    conn = _connect_with_retry()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextmanager
def dict_cursor() -> Iterator:
    """Yield a ``RealDictCursor`` so rows arrive as plain dictionaries."""
    with connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            yield cursor
