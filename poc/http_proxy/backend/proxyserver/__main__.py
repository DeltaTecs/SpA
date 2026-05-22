"""Entry point: runs mitmproxy and the configuration API together.

The API writes the active proxy policy to disk. The mitmproxy addon runs in the
``mitmdump`` process and reloads that policy before forwarding requests.
"""
from __future__ import annotations

import logging
import os
import signal
import shutil
import subprocess
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

from .config import ConfigStore
from .config_api import ConfigAPIHandler

logger = logging.getLogger("proxyserver")

MITMPROXY_SHUTDOWN_TIMEOUT_SECONDS = 10.0


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


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    logger.warning("Invalid %s=%r; falling back to %s", name, raw, default)
    return default


def _mitmdump_command(proxy_host: str, proxy_port: int, conf_dir: str) -> list[str]:
    executable = shutil.which("mitmdump")
    if executable is None:
        raise RuntimeError("mitmdump is not installed or is not on PATH")

    addon_path = Path(__file__).with_name("mitm_addon.py")
    command = [
        executable,
        "--mode",
        "regular",
        "--listen-host",
        proxy_host,
        "--listen-port",
        str(proxy_port),
        "--confdir",
        conf_dir,
        "--set",
        "block_global=false",
        "-s",
        str(addon_path),
    ]
    if _env_bool("MITMPROXY_SSL_INSECURE", False):
        command.extend(["--set", "ssl_insecure=true"])
    return command


def _mitmdump_environment() -> dict[str, str]:
    env = os.environ.copy()
    app_root = str(Path(__file__).resolve().parents[1])
    current_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        app_root
        if not current_pythonpath
        else f"{app_root}{os.pathsep}{current_pythonpath}"
    )
    return env


def _terminate_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    logger.info("Stopping mitmproxy")
    process.terminate()
    try:
        process.wait(timeout=MITMPROXY_SHUTDOWN_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        logger.warning("mitmproxy did not stop in time; killing it")
        process.kill()
        process.wait(timeout=MITMPROXY_SHUTDOWN_TIMEOUT_SECONDS)


def main() -> None:
    _configure_logging()

    config_path = _env_str("PROXY_CONFIG_FILE", "/data/proxy_config.json")
    proxy_host = _env_str("PROXY_HOST", "0.0.0.0")
    proxy_port = _env_int("PROXY_PORT", 8899)
    config_host = _env_str("CONFIG_API_HOST", "0.0.0.0")
    config_port = _env_int("CONFIG_API_PORT", 8890)
    mitmproxy_conf_dir = _env_str("MITMPROXY_CONF_DIR", "/mitmproxy")

    config_store = ConfigStore(config_path)

    config_server = ThreadingHTTPServer((config_host, config_port), ConfigAPIHandler)
    config_server.config_store = config_store

    os.makedirs(mitmproxy_conf_dir, exist_ok=True)
    mitmproxy_process: subprocess.Popen | None = None

    def request_shutdown(signum, _frame) -> None:
        logger.info("Received signal %s; shutting down", signum)
        # shutdown() blocks until serve_forever() returns and therefore must
        # not run on a serve_forever() thread - hand it to fresh threads.
        threading.Thread(target=config_server.shutdown, daemon=True).start()
        if mitmproxy_process is not None:
            threading.Thread(
                target=_terminate_process,
                args=(mitmproxy_process,),
                daemon=True,
            ).start()

    signal.signal(signal.SIGTERM, request_shutdown)
    signal.signal(signal.SIGINT, request_shutdown)

    config_thread = threading.Thread(
        target=config_server.serve_forever, name="config-api", daemon=True
    )
    config_thread.start()

    command = _mitmdump_command(proxy_host, proxy_port, mitmproxy_conf_dir)
    logger.info("Starting mitmproxy: %s", " ".join(command))
    mitmproxy_process = subprocess.Popen(command, env=_mitmdump_environment())

    logger.info("HTTPS-capable forward proxy listening on %s:%s", proxy_host, proxy_port)
    logger.info("Configuration API listening on %s:%s", config_host, config_port)
    logger.info("Configuration file: %s", config_path)
    logger.info("mitmproxy certificate directory: %s", mitmproxy_conf_dir)
    logger.info("Active configuration: %s", config_store.get().to_dict())

    try:
        return_code = mitmproxy_process.wait()
        if return_code != 0:
            logger.error("mitmproxy exited with status %s", return_code)
            raise SystemExit(return_code)
    finally:
        config_server.shutdown()
        if mitmproxy_process is not None:
            _terminate_process(mitmproxy_process)
        config_server.server_close()
        logger.info("Shutdown complete")


if __name__ == "__main__":
    main()
