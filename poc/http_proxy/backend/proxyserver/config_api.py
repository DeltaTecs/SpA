"""REST API for reading and updating the proxy configuration.

The web frontend talks to this API. Endpoints are served both at the root and
under an ``/api`` prefix, so the handler works whether or not a reverse proxy
strips the prefix:

    GET  /config   -> current configuration as JSON
    PUT  /config   -> apply a (partial) configuration update; returns the
                      resulting configuration
    POST /config   -> alias of PUT
    GET  /health   -> liveness probe
"""
from __future__ import annotations

import json
import logging
from http.server import BaseHTTPRequestHandler

logger = logging.getLogger(__name__)

MAX_BODY = 64 * 1024  # configuration payloads are tiny; reject anything larger
CONFIG_PATHS = ("/config", "/api/config")
HEALTH_PATHS = ("/health", "/api/health")


class ConfigAPIHandler(BaseHTTPRequestHandler):
    """Handles a single configuration-API request.

    The owning :class:`~http.server.ThreadingHTTPServer` is expected to expose
    a ``config_store`` attribute (wired up in :mod:`proxyserver.__main__`).
    """

    server_version = "SpA-HTTP-Proxy-Config"
    protocol_version = "HTTP/1.1"  # every response carries an explicit length

    @property
    def _config_store(self):
        return self.server.config_store

    # --- routing ------------------------------------------------------------
    def do_GET(self) -> None:
        if self.path in HEALTH_PATHS:
            self._send_json(200, {"status": "ok"})
        elif self.path in CONFIG_PATHS:
            self._send_json(200, self._config_store.get().to_dict())
        else:
            self._send_json(404, {"error": "Not found"})

    def do_PUT(self) -> None:
        self._apply_update()

    def do_POST(self) -> None:
        self._apply_update()

    def do_OPTIONS(self) -> None:
        # CORS preflight support for direct (cross-origin) API access.
        self.send_response(204)
        self._send_cors_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()

    # --- configuration update ----------------------------------------------
    def _apply_update(self) -> None:
        if self.path not in CONFIG_PATHS:
            self._send_json(404, {"error": "Not found"})
            return
        payload = self._read_json_body()
        if payload is None:
            return  # error already reported to the client
        try:
            updated = self._config_store.update_from(payload)
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        self._send_json(200, updated.to_dict())

    def _read_json_body(self) -> dict | None:
        """Parse and validate the JSON request body, or report an error."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._send_json(400, {"error": "Invalid Content-Length header"})
            return None
        if length <= 0:
            self._send_json(400, {"error": "Request body is required"})
            return None
        if length > MAX_BODY:
            self._send_json(413, {"error": "Request body too large"})
            return None
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            self._send_json(400, {"error": f"Invalid JSON body: {exc}"})
            return None
        if not isinstance(data, dict):
            self._send_json(400, {"error": "JSON body must be an object"})
            return None
        return data

    # --- helpers ------------------------------------------------------------
    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self._send_cors_headers()
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except OSError:
            pass  # client already disconnected

    def _send_cors_headers(self) -> None:
        # The bundled web UI is served same-origin through nginx; permissive
        # CORS only matters when the API is called directly during development.
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, PUT, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - signature fixed by base class
        logger.debug("%s - %s", self.address_string(), format % args)
