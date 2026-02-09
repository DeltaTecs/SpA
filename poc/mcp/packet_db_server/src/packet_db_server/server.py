from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from dotenv import load_dotenv

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError as e:  # pragma: no cover
    raise RuntimeError("psycopg2-binary is required") from e

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as e:  # pragma: no cover
    raise RuntimeError("mcp package is required") from e


load_dotenv()  # allows local runs outside docker-compose


@dataclass(frozen=True)
class DbConfig:
    host: str
    port: int
    name: str
    user: str
    password: str

    @staticmethod
    def from_env() -> "DbConfig":
        dsn = os.environ.get("DB_DSN")
        if dsn:
            # If DB_DSN is set, psycopg2 can use it directly. We still need placeholders here.
            return DbConfig(host="", port=0, name="", user="", password="")

        return DbConfig(
            host=os.environ.get("DB_HOST", "localhost"),
            port=int(os.environ.get("DB_PORT", "5432")),
            name=os.environ.get("DB_NAME", "main"),
            user=os.environ.get("DB_USER", "appuser"),
            password=os.environ.get("DB_PASSWORD", "appuser_password"),
        )


def _connect_db():
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


def _retry_connect_db(max_attempts: int = 30, sleep_seconds: float = 1.0):
    last_exc: Optional[Exception] = None
    for _ in range(max_attempts):
        try:
            conn = _connect_db()
            conn.autocommit = True
            return conn
        except Exception as e:  # noqa: BLE001
            last_exc = e
            time.sleep(sleep_seconds)
    raise RuntimeError(f"Could not connect to DB after {max_attempts} attempts: {last_exc}")


def _bytes_from_bytea(value: Any) -> Optional[bytes]:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, memoryview):
        return bytes(value)
    # psycopg2 sometimes returns bytearray
    if isinstance(value, bytearray):
        return bytes(value)
    raise TypeError(f"Unexpected bytea type: {type(value)}")


def hexdump(data: bytes, *, width: int = 16, max_bytes: Optional[int] = None) -> str:
    original_len = len(data)
    if max_bytes is not None:
        data = data[:max_bytes]

    lines: List[str] = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = hex_part.ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:08x}  {hex_part}  |{ascii_part}|")

    if max_bytes is not None and original_len > len(data):
        lines.append(f"... ({original_len - len(data)} more bytes)")

    return "\n".join(lines) if lines else "(empty)"


def _protocol_names_for_ids(cursor, protocol_ids: Sequence[int]) -> List[str]:
    if not protocol_ids:
        return []

    cursor.execute(
        """
        SELECT u.ord, p.name
        FROM unnest(%s::bigint[]) WITH ORDINALITY AS u(protocol_id, ord)
        JOIN protocol p ON p.protocol_id = u.protocol_id
        ORDER BY u.ord ASC
        """,
        (list(protocol_ids),),
    )
    rows = cursor.fetchall() or []
    if not rows:
        return []

    first = rows[0]
    # RealDictCursor returns dict-like rows.
    if isinstance(first, dict):
        return [r.get("name") for r in rows if r.get("name") is not None]

    # Default cursor returns tuples.
    return [row[1] for row in rows]


def _get_headers(cursor, packet_id: int) -> Dict[str, Any]:
    headers: Dict[str, Any] = {"ip": None, "tcp": None, "udp": None, "http": []}

    cursor.execute(
        """
        SELECT ih.src_addr, ih.dst_addr
        FROM ip_header_information ih
        JOIN packet_header_information phi ON ih.header_information_id = phi.header_information_id
        WHERE phi.packet_id = %s
        """,
        (packet_id,),
    )
    row = cursor.fetchone()
    headers["ip"] = dict(row) if row else None

    cursor.execute(
        """
        SELECT th.src_port, th.dst_port, th.length
        FROM tcp_header_information th
        JOIN packet_header_information phi ON th.header_information_id = phi.header_information_id
        WHERE phi.packet_id = %s
        """,
        (packet_id,),
    )
    row = cursor.fetchone()
    headers["tcp"] = dict(row) if row else None

    cursor.execute(
        """
        SELECT uh.src_port, uh.dst_port, uh.length
        FROM udp_header_information uh
        JOIN packet_header_information phi ON uh.header_information_id = phi.header_information_id
        WHERE phi.packet_id = %s
        """,
        (packet_id,),
    )
    row = cursor.fetchone()
    headers["udp"] = dict(row) if row else None

    cursor.execute(
        """
        SELECT hh.header_information_id, hh.text_header, hh.stream_id, hh.version
        FROM http_header_information hh
        JOIN packet_header_information phi ON hh.header_information_id = phi.header_information_id
        WHERE phi.packet_id = %s
        ORDER BY hh.header_information_id ASC
        """,
        (packet_id,),
    )
    http_rows = cursor.fetchall() or []
    headers["http"] = [dict(r) for r in http_rows]

    return headers


def _guess_app_protocol(protocol_layers: Sequence[str], http_headers: Sequence[Dict[str, Any]]) -> str:
    layers_lower = {p.lower() for p in protocol_layers}

    if http_headers:
        return "http"
    if "websocket" in layers_lower:
        return "websocket"
    if "http" in layers_lower:
        return "http"

    return "unknown"


def _format_endpoint(ip: Optional[str], port: Optional[Any]) -> str:
    if ip is None and port is None:
        return "?"
    if port is None or port == "?":
        return str(ip) if ip is not None else "?"
    return f"{ip}:{port}"


def _format_packet_info_text(
    *,
    packet_id: int,
    timestamp: Optional[int],
    conversation_id: Optional[int],
    headers: Dict[str, Any],
    app_protocol: str,
    payload_bytes: Optional[bytes],
    payload_preview_bytes: int = 256,
) -> str:
    ip = headers.get("ip") or {}
    tcp = headers.get("tcp")
    udp = headers.get("udp")
    http_headers = headers.get("http") or []

    src_ip = ip.get("src_addr")
    dst_ip = ip.get("dst_addr")
    src_port = (tcp or udp or {}).get("src_port")
    dst_port = (tcp or udp or {}).get("dst_port")

    transport = "unknown"
    if tcp:
        transport = "TCP"
    elif udp:
        transport = "UDP"

    lines: List[str] = []
    lines.append(f"{_format_endpoint(src_ip, src_port)} -> {_format_endpoint(dst_ip, dst_port)} {transport}")
    if timestamp is not None:
        lines.append(f"timestamp: {timestamp} ms since epoch")
    if conversation_id is not None:
        lines.append(f"conversation_id: {conversation_id}")

    app_protocol_disp = {
        "http": "HTTP",
        "websocket": "WebSocket",
        "unknown": "unknown",
    }.get(app_protocol.lower(), app_protocol)
    lines.append(f"app protocol: {app_protocol_disp}")

    if http_headers:
        # Always include HTTP header text(s) if associated.
        rendered_headers: List[str] = []
        for h in http_headers:
            text = h.get("text_header")
            if text is None:
                rendered_headers.append("(null)")
            else:
                rendered_headers.append(str(text))

        lines.append("http header: {")
        if len(rendered_headers) == 1:
            lines.append(rendered_headers[0])
        else:
            lines.append("\n---\n".join(rendered_headers))
        lines.append("}")

    if payload_bytes:
        preview = hexdump(payload_bytes, max_bytes=payload_preview_bytes)
        lines.append(f"app payload (first {payload_preview_bytes} bytes): {{")
        lines.append(preview)
        lines.append("}")
    else:
        lines.append("app payload (first 256 bytes): (empty)")

    return "\n".join(lines)


mcp = FastMCP("packet-db")


@mcp.tool()
def packet_info(packet_id: int) -> str:
    """Return flow + protocol + (preview) payload info for a packet (human-readable text)."""

    with _retry_connect_db() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT
                    packet_id,
                    recording_id,
                    conversation_id,
                    from_local,
                    timestamp,
                    number,
                    protocol_ids,
                    clear_application_payload
                FROM packet
                WHERE packet_id = %s
                """,
                (packet_id,),
            )
            pkt = cursor.fetchone()
            if not pkt:
                return f"packet_id {packet_id} not found"

            protocol_ids = pkt.get("protocol_ids") or []
            protocol_layers = _protocol_names_for_ids(cursor, protocol_ids)
            headers = _get_headers(cursor, packet_id)

            payload_bytes = _bytes_from_bytea(pkt.get("clear_application_payload"))
            http_headers = headers.get("http") or []
            app_protocol = _guess_app_protocol(protocol_layers, http_headers)

            return _format_packet_info_text(
                packet_id=packet_id,
                timestamp=pkt.get("timestamp"),
                conversation_id=pkt.get("conversation_id"),
                headers=headers,
                app_protocol=app_protocol,
                payload_bytes=payload_bytes,
                payload_preview_bytes=256,
            )


@mcp.tool()
def packet_payload_hexdump(packet_id: int) -> str:
    """Return full cleartext application payload as hex+ASCII hexdump (human-readable text)."""

    with _retry_connect_db() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT packet_id, clear_application_payload
                FROM packet
                WHERE packet_id = %s
                """,
                (packet_id,),
            )
            row = cursor.fetchone()
            if not row:
                return f"packet_id {packet_id} not found"

            payload_bytes = _bytes_from_bytea(row.get("clear_application_payload"))
            if not payload_bytes:
                return "(empty)"

            return hexdump(payload_bytes)


def main() -> None:
    transport = os.environ.get("MCP_TRANSPORT", "sse").lower()
    host = os.environ.get("MCP_HOST", "0.0.0.0")
    port = int(os.environ.get("MCP_PORT", "8765"))

    # FastMCP supports multiple transports depending on the installed mcp version.
    # Prefer SSE for dockerized usage.
    if transport == "stdio":
        mcp.run()
        return

    # Start SSE in a version-tolerant way.
    # Different `mcp` versions expose different `FastMCP.run()` signatures.
    import inspect

    run_sig = inspect.signature(mcp.run)
    run_params = run_sig.parameters

    kwargs: Dict[str, Any] = {}
    if "transport" in run_params:
        kwargs["transport"] = "sse"
    if "host" in run_params:
        kwargs["host"] = host
    if "port" in run_params:
        kwargs["port"] = port

    if kwargs:
        mcp.run(**kwargs)
        return

    # Fallback for very old versions.
    run_sse = getattr(mcp, "run_sse", None)
    if run_sse:
        run_sse(host=host, port=port)
        return

    # As a last resort, run stdio (works for clients that spawn the process).
    mcp.run()


if __name__ == "__main__":
    main()
