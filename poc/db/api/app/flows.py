"""Stable grouping keys for network flows.

A *flow key* is a normalized transport 5-tuple (protocol + both endpoints) that
is identical for both directions of a TCP/UDP exchange, so the two halves of a
conversation group together. An *association key* extends the flow key with an
HTTP/2 stream id when present, so multiplexed streams within one flow stay
distinct.

These helpers are pure (no DB, no I/O) and live here so both the packet
enrichment in :mod:`app.packets.repository` and the exchange compilation in
:mod:`app.exchanges` share one definition.
"""

from __future__ import annotations

from typing import Optional


def format_endpoint(ip_address: str, port: int) -> str:
    return f"[{ip_address}]:{port}"


def flow_key(
    transport_protocol: Optional[str],
    src_ip: Optional[str],
    src_port: Optional[int],
    dst_ip: Optional[str],
    dst_port: Optional[int],
) -> Optional[str]:
    """Return a normalized TCP/UDP 5-tuple key, or ``None`` if incomplete.

    Endpoint order is normalized so both directions of an exchange map to the
    same key.
    """
    if (
        transport_protocol is None
        or not src_ip
        or not dst_ip
        or src_port is None
        or dst_port is None
    ):
        return None

    protocol = transport_protocol.upper()
    first = (src_ip, int(src_port))
    second = (dst_ip, int(dst_port))
    if first > second:
        first, second = second, first

    return (
        f"flow:{protocol}|"
        f"{format_endpoint(first[0], first[1])}|"
        f"{format_endpoint(second[0], second[1])}"
    )


def association_key(
    packet_id: int,
    transport_protocol: Optional[str],
    src_ip: Optional[str],
    src_port: Optional[int],
    dst_ip: Optional[str],
    dst_port: Optional[int],
    stream_id: Optional[int],
) -> str:
    """Stable grouping key for a single packet.

    Packets in the same transport flow share a key. When an HTTP stream id is
    present the key is split further so multiplexed streams within one flow stay
    distinct. Packets without a complete IP/port tuple fall back to their own id
    instead of being grouped accidentally.
    """
    base = flow_key(transport_protocol, src_ip, src_port, dst_ip, dst_port)
    if base is None:
        base = f"pkt:{packet_id}"
    if stream_id is not None:
        base += f"|stream:{stream_id}"
    return base
