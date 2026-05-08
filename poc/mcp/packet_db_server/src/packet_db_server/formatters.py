from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence


def bytes_from_bytea(value: Any) -> Optional[bytes]:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, memoryview):
        return bytes(value)
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


def guess_app_protocol(protocol_layers: Sequence[str], http_headers: Sequence[Dict[str, Any]]) -> str:
    layers_lower = {p.lower() for p in protocol_layers}

    if http_headers:
        return "http"
    if "websocket" in layers_lower:
        return "websocket"
    if "http" in layers_lower:
        return "http"

    return "unknown"


def format_endpoint(ip: Optional[str], port: Optional[Any]) -> str:
    if ip is None and port is None:
        return "?"
    if port is None or port == "?":
        return str(ip) if ip is not None else "?"
    return f"{ip}:{port}"


def format_packet_info_text(
    *,
    packet_id: int,
    recording_id: Optional[int],
    number: Optional[int],
    timestamp: Optional[int],
    recording_start_timestamp: Optional[int],
    conversation_id: Optional[int],
    from_local: Optional[bool],
    protocol_layers: Sequence[str],
    headers: Dict[str, Any],
    app_protocol: str,
    entropy: Optional[float],
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

    if from_local is True:
        direction = "outbound"
    elif from_local is False:
        direction = "inbound"
    else:
        direction = "unknown"

    payload_len = len(payload_bytes) if payload_bytes else 0
    timestamp_offset = None
    if timestamp is not None and recording_start_timestamp is not None:
        timestamp_offset = timestamp - recording_start_timestamp

    lines: List[str] = [
        f"packet_id: {packet_id}",
    ]
    if recording_id is not None:
        lines.append(f"recording_id: {recording_id}")
    if number is not None:
        lines.append(f"packet number: {number}")
    lines.append(f"{format_endpoint(src_ip, src_port)} -> {format_endpoint(dst_ip, dst_port)} {transport}")
    if timestamp is not None:
        lines.append(f"timestamp: {timestamp} ms since epoch")
    if timestamp_offset is not None:
        lines.append(f"timestamp offset: {timestamp_offset} ms since recording start")
    if conversation_id is not None:
        lines.append(f"conversation_id: {conversation_id}")
    lines.append(f"direction: {direction}")
    lines.append(f"from_local: {from_local}")
    lines.append(f"protocol stack: {' > '.join(protocol_layers) if protocol_layers else 'unknown'}")
    lines.append(f"entropy: {entropy:.4f}" if entropy is not None else "entropy: unknown")
    lines.append(f"payload length: {payload_len} bytes")
    if tcp and tcp.get("length") is not None:
        lines.append(f"tcp payload length: {tcp.get('length')} bytes")
    if udp and udp.get("length") is not None:
        lines.append(f"udp length: {udp.get('length')} bytes")

    app_protocol_disp = {
        "http": "HTTP",
        "websocket": "WebSocket",
        "unknown": "unknown",
    }.get(app_protocol.lower(), app_protocol)
    lines.append(f"app protocol: {app_protocol_disp}")

    if http_headers:
        # Keep raw HTTP header text intact; the analyst prompt relies on it.
        rendered_headers: List[str] = []
        for header in http_headers:
            text = header.get("text_header")
            rendered_headers.append("(null)" if text is None else str(text))

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
