"""Thread-safe, file-backed configuration for the HTTP proxy.

A single :class:`ConfigStore` instance is shared between the forward proxy and
the configuration API. It keeps the active :class:`ProxyConfig` in memory and
mirrors every change to a JSON file so settings survive a container restart.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# --- defaults ---------------------------------------------------------------
DEFAULT_USER_AGENT = "SpA-HTTP-Proxy/1.0"
DEFAULT_RATE_LIMIT_PER_MINUTE = 60
DEFAULT_RATE_LIMIT_BURST = 10

# --- validation bounds ------------------------------------------------------
MAX_USER_AGENT_LENGTH = 512
MAX_COUNT = 1_000_000

# Field names that callers are allowed to set. Anything else in an update
# payload is ignored so the API stays forward-compatible.
FIELD_NAMES = ("user_agent", "rate_limit_per_minute", "rate_limit_burst")


def _coerce_str(name: str, value: object) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _coerce_int(name: str, value: object) -> int:
    """Accept JSON integers, integral floats and numeric strings."""
    if isinstance(value, bool):  # bool is a subclass of int - reject explicitly
        raise ValueError(f"{name} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    raise ValueError(f"{name} must be an integer")


def _validate_user_agent(value: str) -> None:
    if not value.strip():
        raise ValueError("user_agent must not be empty")
    if len(value) > MAX_USER_AGENT_LENGTH:
        raise ValueError(f"user_agent must be at most {MAX_USER_AGENT_LENGTH} characters")
    # The value is written verbatim into an HTTP header; control characters
    # (notably CR/LF) would allow header injection.
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise ValueError("user_agent must not contain control characters")


def _validate_count(name: str, value: int, minimum: int) -> None:
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    if value > MAX_COUNT:
        raise ValueError(f"{name} must be <= {MAX_COUNT}")


@dataclass(frozen=True)
class ProxyConfig:
    """Immutable snapshot of the operator-tunable proxy settings.

    Attributes:
        user_agent: Value forced into the ``User-Agent`` header of every
            forwarded HTTP request.
        rate_limit_per_minute: Maximum forwarded requests per minute;
            ``0`` disables rate limiting entirely.
        rate_limit_burst: Number of requests allowed to burst before the
            steady per-minute rate is enforced.
    """

    user_agent: str = DEFAULT_USER_AGENT
    rate_limit_per_minute: int = DEFAULT_RATE_LIMIT_PER_MINUTE
    rate_limit_burst: int = DEFAULT_RATE_LIMIT_BURST

    def __post_init__(self) -> None:
        _validate_user_agent(self.user_agent)
        _validate_count("rate_limit_per_minute", self.rate_limit_per_minute, minimum=0)
        _validate_count("rate_limit_burst", self.rate_limit_burst, minimum=1)

    def to_dict(self) -> dict:
        return {
            "user_agent": self.user_agent,
            "rate_limit_per_minute": self.rate_limit_per_minute,
            "rate_limit_burst": self.rate_limit_burst,
        }

    def merged_with(self, changes: dict) -> "ProxyConfig":
        """Return a new validated config with ``changes`` applied on top.

        Only keys in :data:`FIELD_NAMES` are considered; unknown keys and
        ``None`` values are ignored, which makes partial updates safe. Raises
        :class:`ValueError` if any supplied value fails coercion or validation.
        """
        values = self.to_dict()
        for name in FIELD_NAMES:
            if changes.get(name) is not None:
                values[name] = changes[name]
        return ProxyConfig(
            user_agent=_coerce_str("user_agent", values["user_agent"]),
            rate_limit_per_minute=_coerce_int(
                "rate_limit_per_minute", values["rate_limit_per_minute"]
            ),
            rate_limit_burst=_coerce_int("rate_limit_burst", values["rate_limit_burst"]),
        )

    @classmethod
    def from_dict(cls, data: dict) -> "ProxyConfig":
        """Build a config from a (possibly partial) dict, filling in defaults."""
        return cls().merged_with(data or {})


class ConfigStore:
    """Holds the active :class:`ProxyConfig` and persists it to a JSON file."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.RLock()
        self._config = self._load()

    @property
    def path(self) -> str:
        return self._path

    def get(self) -> ProxyConfig:
        """Return the current configuration (a thread-safe immutable snapshot)."""
        with self._lock:
            return self._config

    def update_from(self, changes: dict) -> ProxyConfig:
        """Apply ``changes``, persist the result and return the new config.

        Raises :class:`ValueError` if the update is invalid, leaving the
        previously active configuration untouched.
        """
        with self._lock:
            new_config = self._config.merged_with(changes)
            self._persist(new_config)
            self._config = new_config
        logger.info("Proxy configuration updated: %s", new_config.to_dict())
        return new_config

    # --- persistence --------------------------------------------------------
    def _load(self) -> ProxyConfig:
        if os.path.exists(self._path):
            try:
                with open(self._path, "r", encoding="utf-8") as handle:
                    config = ProxyConfig.from_dict(json.load(handle))
                logger.info("Loaded proxy configuration from %s", self._path)
                return config
            except (OSError, ValueError) as exc:
                logger.warning(
                    "Ignoring invalid configuration at %s (%s); using defaults",
                    self._path,
                    exc,
                )
        config = ProxyConfig()
        try:
            self._persist(config)
        except OSError as exc:
            logger.warning("Could not write default configuration to %s: %s", self._path, exc)
        return config

    def _persist(self, config: ProxyConfig) -> None:
        """Atomically write ``config`` to disk (write-temp-then-rename)."""
        directory = os.path.dirname(self._path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        tmp_path = f"{self._path}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(config.to_dict(), handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp_path, self._path)
