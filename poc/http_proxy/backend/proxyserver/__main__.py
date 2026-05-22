"""Entry point: runs the forward proxy and the configuration API together.

Both servers share one :class:`~proxyserver.config.ConfigStore`, so a change
made through the API is visible to the proxy on its very next request.
"""
from __future__ import annotations

import logging
import os
import signal
import sys
import threading
from http.server import ThreadingHTTPServer

from .config import ConfigStore
from .config_api import ConfigAPIHandler
from .forward_proxy import ForwardProxyHandler
from .rate_limiter import RateLimiter

logger = logging.getLogger("proxyserver")


def _configure_logging() -> None:
    level_name = os.environ.get("LOG_LEVEL", "INFO").strip().upper()
    # The wider project uses a non-standard "VERBOSE" level; map it to DEBUG.
    level = logging.DEBUG if level_name == "VERBOSE" else getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        stream=sys.stdout,
    )


def _env_str(name: str, default: str) -> str:
    return os.environ.get(name, "").strip() or default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        logger.warning("Invalid %s=%r; falling back to %s", name, raw, default)
        return default


def main() -> None:
    _configure_logging()

    config_path = _env_str("PROXY_CONFIG_FILE", "/data/proxy_config.json")
    proxy_host = _env_str("PROXY_HOST", "0.0.0.0")
    proxy_port = _env_int("PROXY_PORT", 8899)
    config_host = _env_str("CONFIG_API_HOST", "0.0.0.0")
    config_port = _env_int("CONFIG_API_PORT", 8890)

    config_store = ConfigStore(config_path)

    def rate_settings():
        current = config_store.get()
        return current.requests_per_second(), current.rate_limit_burst

    rate_limiter = RateLimiter(rate_settings)

    # ThreadingHTTPServer handles each connection in its own daemon thread.
    proxy_server = ThreadingHTTPServer((proxy_host, proxy_port), ForwardProxyHandler)
    proxy_server.config_store = config_store
    proxy_server.rate_limiter = rate_limiter

    config_server = ThreadingHTTPServer((config_host, config_port), ConfigAPIHandler)
    config_server.config_store = config_store

    servers = (proxy_server, config_server)

    def request_shutdown(signum, _frame) -> None:
        logger.info("Received signal %s; shutting down", signum)
        # shutdown() blocks until serve_forever() returns and therefore must
        # not run on a serve_forever() thread - hand it to fresh threads.
        for server in servers:
            threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, request_shutdown)
    signal.signal(signal.SIGINT, request_shutdown)

    config_thread = threading.Thread(
        target=config_server.serve_forever, name="config-api", daemon=True
    )
    config_thread.start()

    logger.info("Forward proxy listening on %s:%s", proxy_host, proxy_port)
    logger.info("Configuration API listening on %s:%s", config_host, config_port)
    logger.info("Configuration file: %s", config_path)
    logger.info("Active configuration: %s", config_store.get().to_dict())

    try:
        proxy_server.serve_forever()
    finally:
        config_server.shutdown()
        proxy_server.server_close()
        config_server.server_close()
        logger.info("Shutdown complete")


if __name__ == "__main__":
    main()
