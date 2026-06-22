"""Shared rendering of an :class:`~app.schemas.Exchange` into prompt text.

Both the planning task and the pentest task summarise the same exchange shape for
the model, so the rendering lives here to avoid divergence.
"""

from __future__ import annotations

from typing import List

from ..schemas import Exchange


def build_exchange_summary(exchange: Exchange) -> str:
    """Render the exchange as a compact bullet list for a prompt."""
    lines: List[str] = []
    lines.append(f"- kind: {exchange.kind}")
    if exchange.transport:
        lines.append(f"- transport: {exchange.transport}")
    if exchange.remote:
        lines.append(f"- remote endpoint: {exchange.remote.ip}:{exchange.remote.port}")
    if exchange.protocols:
        lines.append(f"- protocol stack: {', '.join(exchange.protocols)}")
    lines.append(f"- clear payload bytes: {exchange.payload_bytes}")

    if exchange.http:
        http = exchange.http
        lines.append(f"- HTTP method: {http.method}")
        lines.append(f"- HTTP endpoint: {http.endpoint_path or http.path}")
        if http.host:
            lines.append(f"- HTTP host: {http.host}")
        if http.param_names:
            lines.append(f"- query parameters: {', '.join(http.param_names)}")
        if http.status_code is not None:
            lines.append(f"- response status: {http.status_code}")

    if exchange.representative_packet_ids:
        ids = ", ".join(str(pid) for pid in exchange.representative_packet_ids)
        lines.append(f"- representative packet ids (inspect with the packet tools): {ids}")

    return "\n".join(lines)
