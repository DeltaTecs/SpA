"""Compile a recording's packets into *interesting data exchanges*.

Two kinds of exchange are produced:

* **conversation** — a distinct transport 5-tuple flow that carries clear
  application payload but **no HTTP** (e.g. a decrypted TLS app-data stream).
* **http_pair** — an HTTP request paired with its response, deduplicated so that
  repeating requests collapse: one exchange per
  ``(method, endpoint path, distinct set of query-param names)``. A distinct
  endpoint *or* a distinct param-name set yields a distinct exchange.

Everything here is a pure function over :class:`EnrichedPacket` values (no DB,
no I/O), so the grouping/dedup/pairing logic is unit-testable in isolation. The
repository layer is responsible for turning DB rows into ``EnrichedPacket``s.

Limitation: only query-string parameter names are considered. Request *body*
parameters are not available (only header text is stored/parsed).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..flows import flow_key
from ..http_parsing import (
    HttpRequestInfo,
    parse_http_header,
    query_param_names,
    split_path_segments,
)

#: Cap on representative packet ids attached to a conversation exchange.
_MAX_REPRESENTATIVE_PACKETS = 5

Endpoint = Tuple[Optional[str], Optional[int]]


@dataclass(frozen=True)
class EnrichedPacket:
    """A packet with the header fields needed to compile exchanges.

    Mirrors the enriched columns produced by the packet repository, decoupled
    from the raw DB row so the grouping logic stays DB-agnostic.
    """

    packet_id: int
    from_local: Optional[bool] = None
    timestamp: Optional[int] = None
    number: Optional[int] = None
    transport: Optional[str] = None
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    http_text: Optional[str] = None
    stream_id: Optional[int] = None
    http_count: int = 0
    payload_length: int = 0
    protocols: Tuple[str, ...] = field(default_factory=tuple)


def compile_exchanges(packets: List[EnrichedPacket]) -> List[Dict[str, Any]]:
    """Compile both exchange kinds, HTTP pairs first, each sorted by payload size."""
    http_exchanges, http_flow_keys = compile_http_pairs(packets)
    conversation_exchanges = compile_conversations(packets, http_flow_keys)

    http_exchanges.sort(key=lambda e: (-e["payload_bytes"], e["id"]))
    conversation_exchanges.sort(key=lambda e: (-e["payload_bytes"], e["id"]))
    return http_exchanges + conversation_exchanges


def compile_http_pairs(
    packets: List[EnrichedPacket],
) -> Tuple[List[Dict[str, Any]], set]:
    """Compile deduplicated HTTP request/response exchanges.

    Returns the exchanges plus the set of transport flow keys (no stream suffix)
    that carried HTTP, so conversations can exclude those flows.
    """
    requests: List[Tuple[EnrichedPacket, HttpRequestInfo]] = []
    responses_by_assoc: Dict[str, List[Tuple[EnrichedPacket, HttpRequestInfo]]] = defaultdict(list)
    http_flow_keys: set = set()

    for packet in packets:
        if not packet.http_count:
            continue
        key = flow_key(
            packet.transport, packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port
        )
        if key is not None:
            http_flow_keys.add(key)

        info = parse_http_header(packet.http_text)
        if info.is_request and info.path is not None:
            requests.append((packet, info))
        elif info.is_response:
            assoc = _association(packet)
            if assoc is not None:
                responses_by_assoc[assoc].append((packet, info))

    for candidates in responses_by_assoc.values():
        candidates.sort(key=lambda pair: _sort_key(pair[0]))

    # Group requests by dedup key, preserving first-seen order.
    groups: Dict[str, List[Tuple[EnrichedPacket, HttpRequestInfo]]] = {}
    order: List[str] = []
    for packet, info in requests:
        key = _http_dedup_key(info)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append((packet, info))

    exchanges: List[Dict[str, Any]] = []
    for dedup_key in order:
        members = sorted(groups[dedup_key], key=lambda pair: _sort_key(pair[0]))
        rep_packet, rep_info = members[0]
        local, remote = _packet_endpoints(rep_packet)

        representative_ids = [rep_packet.packet_id]
        status_code: Optional[int] = None
        response = _nearest_following_response(rep_packet, responses_by_assoc)
        if response is not None:
            response_packet, response_info = response
            representative_ids.append(response_packet.packet_id)
            status_code = response_info.status_code

        exchanges.append(
            {
                "id": dedup_key,
                "dedup_key": dedup_key,
                "kind": "http_pair",
                "transport": rep_packet.transport,
                "local": _endpoint(local),
                "remote": _endpoint(remote),
                "representative_packet_ids": representative_ids,
                "packet_count": len(members),
                "payload_bytes": sum(packet.payload_length for packet, _ in members),
                "protocols": _union_protocols(packet for packet, _ in members),
                "http": {
                    "method": rep_info.method,
                    "path": rep_info.path,
                    "endpoint_path": _endpoint_path(rep_info.path),
                    "param_names": query_param_names(rep_info.path),
                    "status_code": status_code,
                    "host": rep_info.host,
                },
            }
        )
    return exchanges, http_flow_keys


def compile_conversations(
    packets: List[EnrichedPacket], http_flow_keys: set
) -> List[Dict[str, Any]]:
    """Group non-HTTP, payload-bearing packets into per-flow conversations."""
    groups: Dict[str, List[EnrichedPacket]] = defaultdict(list)
    for packet in packets:
        if packet.payload_length <= 0 or packet.http_count:
            continue
        key = flow_key(
            packet.transport, packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port
        )
        if key is None or key in http_flow_keys:
            continue
        groups[key].append(packet)

    exchanges: List[Dict[str, Any]] = []
    for key, members in groups.items():
        members = sorted(members, key=_sort_key)
        local, remote = _flow_endpoints(members)
        exchanges.append(
            {
                "id": f"conv:{key}",
                "dedup_key": f"conv:{key}",
                "kind": "conversation",
                "transport": members[0].transport,
                "local": _endpoint(local),
                "remote": _endpoint(remote),
                "representative_packet_ids": [
                    packet.packet_id for packet in members[:_MAX_REPRESENTATIVE_PACKETS]
                ],
                "packet_count": len(members),
                "payload_bytes": sum(packet.payload_length for packet in members),
                "protocols": _union_protocols(members),
                "http": None,
            }
        )
    return exchanges


# -- helpers ------------------------------------------------------------------


def _sort_key(packet: EnrichedPacket) -> Tuple[int, int, int]:
    return (
        packet.timestamp if packet.timestamp is not None else 0,
        packet.number if packet.number is not None else 0,
        packet.packet_id,
    )


def _association(packet: EnrichedPacket) -> Optional[str]:
    """Flow key extended with the HTTP stream id, used to pair request/response."""
    key = flow_key(
        packet.transport, packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port
    )
    if key is None:
        return None
    if packet.stream_id is not None:
        return f"{key}|stream:{packet.stream_id}"
    return key


def _nearest_following_response(
    request: EnrichedPacket,
    responses_by_assoc: Dict[str, List[Tuple[EnrichedPacket, HttpRequestInfo]]],
) -> Optional[Tuple[EnrichedPacket, HttpRequestInfo]]:
    """The earliest response in the same flow/stream that follows ``request``."""
    assoc = _association(request)
    if assoc is None:
        return None
    request_key = _sort_key(request)
    for candidate in responses_by_assoc.get(assoc, []):  # sorted ascending
        if _sort_key(candidate[0]) >= request_key:
            return candidate
    return None


def _http_dedup_key(info: HttpRequestInfo) -> str:
    method = (info.method or "?").upper()
    params = ",".join(query_param_names(info.path))
    return f"http:{method}|{_endpoint_path(info.path)}|{params}"


def _endpoint_path(path: Optional[str]) -> str:
    segments = split_path_segments(path)
    return "/" + "/".join(segments) if segments else "/"


def _packet_endpoints(packet: EnrichedPacket) -> Tuple[Endpoint, Endpoint]:
    """Return (local, remote) using the packet's direction (peer = the far side)."""
    if packet.from_local is False:
        return (packet.dst_ip, packet.dst_port), (packet.src_ip, packet.src_port)
    # Outbound or unknown: treat source as local, destination as remote.
    return (packet.src_ip, packet.src_port), (packet.dst_ip, packet.dst_port)


def _flow_endpoints(packets: List[EnrichedPacket]) -> Tuple[Endpoint, Endpoint]:
    """Resolve (local, remote) for a flow using whatever direction info exists."""
    local: Optional[Endpoint] = None
    for packet in packets:
        if packet.from_local is True:
            local = (packet.src_ip, packet.src_port)
            break
        if packet.from_local is False:
            local = (packet.dst_ip, packet.dst_port)
            break

    seen: List[Endpoint] = []
    for packet in packets:
        for endpoint in ((packet.src_ip, packet.src_port), (packet.dst_ip, packet.dst_port)):
            if endpoint not in seen:
                seen.append(endpoint)

    if local is None:
        ordered = sorted(seen, key=lambda e: (e[0] or "", e[1] or 0))
        first = ordered[0] if ordered else (None, None)
        second = ordered[1] if len(ordered) > 1 else (None, None)
        return first, second

    remote = next((endpoint for endpoint in seen if endpoint != local), (None, None))
    return local, remote


def _endpoint(endpoint: Endpoint) -> Optional[Dict[str, Any]]:
    ip, port = endpoint
    if ip is None and port is None:
        return None
    return {"ip": ip, "port": port}


def _union_protocols(packets) -> List[str]:
    """Distinct protocol labels across packets, preserving first-seen order."""
    seen: List[str] = []
    for packet in packets:
        for protocol in packet.protocols:
            if protocol not in seen:
                seen.append(protocol)
    return seen
