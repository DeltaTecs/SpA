from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from dotenv import load_dotenv


load_dotenv()  # Allows local runs outside docker-compose.


@dataclass(frozen=True)
class DbConfig:
    """Database connection settings, sourced from the environment.

    A full ``DB_DSN`` takes precedence; otherwise the individual
    ``DB_*`` variables are used (matching the rest of the compose stack).
    """

    dsn: Optional[str]
    host: str
    port: int
    name: str
    user: str
    password: str

    @staticmethod
    def from_env() -> "DbConfig":
        return DbConfig(
            dsn=os.environ.get("DB_DSN") or None,
            host=os.environ.get("DB_HOST", "db"),
            port=int(os.environ.get("DB_PORT", "5432")),
            name=os.environ.get("DB_NAME", "main"),
            user=os.environ.get("DB_USER", "dbuser"),
            password=os.environ.get("DB_PASSWORD", "dbuser"),
        )
