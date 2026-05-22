"""The forward HTTP proxy request handler.

Plain ``http://`` requests are parsed, re-headed with the configured
User-Agent and forwarded upstream. ``CONNECT`` requests (used by clients for
``https://`` targets) are tunnelled verbatim: their payload is end-to-end
encrypted, so the User-Agent cannot be rewritten, but the tunnel is still
rate-limited like any other forwarded request.
"""
from __future__ import annotations

import http.client
import json
import logging
import select
import socket
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

# Headers scoped to a single transport hop; they must not be forwarded.
HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "proxy-connection",
    }
)

UPSTREAM_TIMEOUT = 30.0       # seconds to connect to / read from upstream
TUNNEL_IDLE_TIMEOUT = 120.0   # seconds a CONNECT tunnel may sit idle
STREAM_CHUNK_SIZE = 65536     # bytes per relay chunk
MAX_REQUEST_BODY = 64 * 1024 * 1024  # cap buffered request bodies at 64 MiB


class ForwardProxyHandler(BaseHTTPRequestHandler):
    """Handles a single proxied connection.

    The owning :class:`~http.server.ThreadingHTTPServer` is expected to expose
    ``config_store`` and ``rate_limiter`` attributes, which are wired up in
    :mod:`proxyserver.__main__`.
    """

    server_version = "SpA-HTTP-Proxy"
    # One request per connection keeps body relaying simple and unambiguous:
    # the client reads the response until the connection is closed.
    protocol_version = "HTTP/1.0"

    # --- dependency accessors ----------------------------------------------
    @property
    def _config_store(self):
        return self.server.config_store

    @property
    def _rate_limiter(self):
        return self.server.rate_limiter

    # --- HTTP method dispatch ----------------------------------------------
    # Every standard method that carries an absolute URI is forwarded the
    # same way; CONNECT is special-cased below.
    def do_GET(self):
        self._forward()

    def do_POST(self):
        self._forward()

    def do_PUT(self):
        self._forward()

    def do_DELETE(self):
        self._forward()

    def do_HEAD(self):
        self._forward()

    def do_OPTIONS(self):
        self._forward()

    def do_PATCH(self):
        self._forward()

    # --- plain HTTP forwarding ---------------------------------------------
    def _forward(self) -> None:
        parsed = urlsplit(self.path)
        try:
            hostname = parsed.hostname
            port = parsed.port or 80
        except ValueError:
            self._send_error_page(400, "Malformed host or port in request URI")
            return

        if parsed.scheme.lower() != "http" or not hostname:
            self._send_error_page(
                400,
                "This proxy only forwards absolute http:// URLs; "
                "use the CONNECT method for https:// targets.",
            )
            return

        # Throttle before opening any upstream socket.
        self._rate_limiter.acquire()

        body = self._read_request_body()
        if body is None:
            return  # error already reported to the client

        target_path = parsed.path or "/"
        if parsed.query:
            target_path = f"{target_path}?{parsed.query}"

        connection = http.client.HTTPConnection(hostname, port, timeout=UPSTREAM_TIMEOUT)
        try:
            connection.request(
                self.command, target_path, body=body, headers=self._upstream_headers()
            )
            response = connection.getresponse()
            self._relay_response(response)
            logger.info("%s %s -> %s", self.command, self.path, response.status)
        except (OSError, http.client.HTTPException) as exc:
            logger.warning("Upstream request %s %s failed: %s", self.command, self.path, exc)
            # Only a clean error page is possible while no response bytes have
            # been written yet; otherwise just drop the corrupted connection.
            if not getattr(self, "_response_started", False):
                self._send_error_page(502, f"Upstream request failed: {exc}")
        finally:
            connection.close()

    def _read_request_body(self) -> bytes | None:
        """Return the request body bytes (``b""`` if none) or ``None`` on error."""
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            return b""
        try:
            length = int(raw_length)
            if length < 0:
                raise ValueError
        except ValueError:
            self._send_error_page(400, "Invalid Content-Length header")
            return None
        if length > MAX_REQUEST_BODY:
            self._send_error_page(413, "Request body too large")
            return None
        return self.rfile.read(length)

    def _upstream_headers(self) -> dict:
        """Build the header set for the upstream request.

        Hop-by-hop headers are dropped and the ``User-Agent`` is replaced with
        the operator-configured value.
        """
        headers = {}
        for name, value in self.headers.items():
            lowered = name.lower()
            if lowered in HOP_BY_HOP_HEADERS or lowered == "user-agent":
                continue
            headers[name] = value
        headers["User-Agent"] = self._config_store.get().user_agent
        headers["Connection"] = "close"
        return headers

    def _relay_response(self, response: http.client.HTTPResponse) -> None:
        """Stream an upstream response back to the client."""
        self._response_started = True
        self.send_response_only(response.status, response.reason)
        for name, value in response.getheaders():
            # Content-Length is dropped: the de-chunked body is streamed and
            # the client reads until the connection closes (HTTP/1.0).
            if name.lower() in HOP_BY_HOP_HEADERS or name.lower() == "content-length":
                continue
            self.send_header(name, value)
        self.send_header("Connection", "close")
        self.end_headers()

        if self.command == "HEAD":
            return
        while True:
            chunk = response.read(STREAM_CHUNK_SIZE)
            if not chunk:
                break
            self.wfile.write(chunk)

    # --- CONNECT tunnelling -------------------------------------------------
    def do_CONNECT(self) -> None:
        # A tunnel owns the connection for its whole lifetime.
        self.close_connection = True

        host, separator, raw_port = self.path.rpartition(":")
        if not separator or not host:
            self._send_error_page(400, "Malformed CONNECT target")
            return
        # Strip the brackets of an IPv6 literal so socket APIs accept it.
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        try:
            port = int(raw_port)
        except ValueError:
            self._send_error_page(400, "Malformed CONNECT target port")
            return

        # A tunnel counts as one forwarded request for rate-limiting purposes.
        self._rate_limiter.acquire()

        try:
            upstream = socket.create_connection((host, port), timeout=UPSTREAM_TIMEOUT)
        except OSError as exc:
            logger.warning("CONNECT to %s:%s failed: %s", host, port, exc)
            self._send_error_page(502, f"Cannot reach {host}:{port}: {exc}")
            return

        logger.info("CONNECT %s:%s established", host, port)
        self._response_started = True
        self.send_response_only(200, "Connection established")
        self.end_headers()
        try:
            self._tunnel(self.connection, upstream)
        finally:
            upstream.close()

    @staticmethod
    def _tunnel(client_sock: socket.socket, upstream_sock: socket.socket) -> None:
        """Relay bytes between client and upstream until either side closes."""
        client_sock.setblocking(True)
        upstream_sock.setblocking(True)
        endpoints = [client_sock, upstream_sock]
        while True:
            readable, _, errored = select.select(
                endpoints, [], endpoints, TUNNEL_IDLE_TIMEOUT
            )
            if errored or not readable:
                return  # socket error or idle timeout
            for source in readable:
                destination = upstream_sock if source is client_sock else client_sock
                try:
                    data = source.recv(STREAM_CHUNK_SIZE)
                    if not data:
                        return  # peer closed the connection
                    destination.sendall(data)
                except OSError:
                    return

    # --- helpers ------------------------------------------------------------
    def _send_error_page(self, status: int, message: str) -> None:
        """Send a small JSON error response, tolerating an already-closed client."""
        body = json.dumps({"error": message}).encode("utf-8")
        try:
            self._response_started = True
            self.send_response_only(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass  # client already disconnected

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - signature fixed by base class
        # Route the base class's request logging through the module logger.
        logger.debug("%s - %s", self.address_string(), format % args)
