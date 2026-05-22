"""mitmproxy addon for the SpA HTTP proxy.

mitmdump loads this file in a separate Python process. The addon therefore
reads the same persisted JSON configuration as the API and reloads it when the
file changes.
"""
from __future__ import annotations

import logging
import os

from proxyserver.config import ConfigStore
from proxyserver.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_FILE = "/data/proxy_config.json"


class UserAgentProxyAddon:
    """Applies operator-controlled proxy policy to each outbound request."""

    def __init__(self, config_path: str) -> None:
        self._config_path = config_path
        self._config_store: ConfigStore | None = None
        self._rate_limiter: RateLimiter | None = None

    def request(self, flow) -> None:
        """mitmproxy hook: runs before a request is sent upstream."""
        config_store, rate_limiter = self._runtime()
        rate_limiter.acquire()
        config = config_store.get()
        flow.request.headers["User-Agent"] = config.user_agent
        logger.info(
            "http_proxy_call client=%s method=%s target=%r status=forwarding",
            self._client_label(flow),
            flow.request.method,
            flow.request.pretty_url,
        )

    def _rate_settings(self) -> tuple[float, int]:
        config_store, _ = self._runtime()
        config = config_store.get()
        return config.requests_per_second(), config.rate_limit_burst

    def _runtime(self) -> tuple[ConfigStore, RateLimiter]:
        if self._config_store is None or self._rate_limiter is None:
            self._config_store = ConfigStore(self._config_path, reload_on_read=True)
            self._rate_limiter = RateLimiter(self._rate_settings)
        return self._config_store, self._rate_limiter

    @staticmethod
    def _client_label(flow) -> str:
        client = getattr(flow, "client_conn", None)
        address = getattr(client, "peername", None)
        if isinstance(address, tuple) and len(address) >= 2:
            return f"{address[0]}:{address[1]}"
        return "-"


addons = [
    UserAgentProxyAddon(os.environ.get("PROXY_CONFIG_FILE", DEFAULT_CONFIG_FILE)),
]
