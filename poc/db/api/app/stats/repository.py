from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from ..db import dict_cursor
from ..http_parsing import parse_http_header, split_path_segments

logger = logging.getLogger(__name__)

#: Payload entropy is bits-per-byte, so it falls in [0, 8]. We render it as a
#: fixed 16-bucket histogram (each bar 0.5 bits wide) regardless of the data so
#: the dashboard axis is stable.
_ENTROPY_MIN = 0.0
_ENTROPY_MAX = 8.0
_ENTROPY_BUCKETS = 16
_ENTROPY_WIDTH = (_ENTROPY_MAX - _ENTROPY_MIN) / _ENTROPY_BUCKETS

_NETWORK_PROTOCOLS = {"ip", "ipv6"}
_ENCRYPTED_PROTOCOLS = {"tls", "quic", "dtls"}
_PROTOCOL_DISPLAY_NAMES = {
    "ip": "IP",
    "ipv6": "IPv6",
    "tcp": "TCP",
    "udp": "UDP",
    "dns": "DNS",
    "tls": "TLS",
    "quic": "QUIC",
    "dtls": "DTLS",
    "http": "HTTP",
    "websocket": "WebSocket",
    "other": "Other",
    "stun": "STUN",
    "turn": "TURN",
    "rtp": "RTP",
    "rtcp": "RTCP",
}
_PROTOCOL_SEGMENTS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("Transport", ("udp", "tcp")),
    ("Secure/name resolution", ("tls", "quic", "dtls", "dns")),
    ("Application data", ("http", "websocket", "other")),
)

_REMOTE_IP_CTES = """
WITH recording_packets AS (
    SELECT packet_id, from_local
    FROM packet
    WHERE recording_id = %s
),
packet_ips AS (
    SELECT DISTINCT ON (rp.packet_id)
        rp.packet_id,
        rp.from_local,
        ih.src_addr,
        ih.dst_addr
    FROM recording_packets rp
    JOIN packet_header_information phi ON phi.packet_id = rp.packet_id
    JOIN ip_header_information ih
      ON ih.header_information_id = phi.header_information_id
    ORDER BY rp.packet_id, phi.header_information_id
),
local_ip_candidates AS (
    SELECT
        CASE
            WHEN from_local IS TRUE THEN src_addr
            WHEN from_local IS FALSE THEN dst_addr
        END AS ip
    FROM packet_ips
    WHERE from_local IS NOT NULL
),
local_ips AS (
    SELECT DISTINCT ip
    FROM local_ip_candidates
    WHERE ip IS NOT NULL
),
packet_remotes AS (
    SELECT
        packet_id,
        CASE
            WHEN from_local IS TRUE THEN dst_addr
            WHEN from_local IS FALSE THEN src_addr
            ELSE COALESCE(dst_addr, src_addr)
        END AS remote_ip
    FROM packet_ips
)
"""


class StatsRepository:
    """Read-only aggregation queries over a recording's packets."""

    def list_recordings(self) -> List[Dict[str, Any]]:
        """Return every recording with its packet count, lowest id first."""
        with dict_cursor() as cursor:
            cursor.execute(
                """
                SELECT r.recording_id, r.name, COUNT(p.packet_id) AS packet_count
                FROM recording r
                LEFT JOIN packet p ON p.recording_id = r.recording_id
                GROUP BY r.recording_id, r.name
                ORDER BY r.recording_id ASC
                """
            )
            return [dict(row) for row in cursor.fetchall() or []]

    def recording_stats(
        self, recording_id: int, *, top_ips: int = 50
    ) -> Dict[str, Any]:
        """Compute the full dashboard statistics payload for one recording."""
        started = time.perf_counter()
        with dict_cursor() as cursor:
            packet_count = self._packet_count(cursor, recording_id)
            protocol_counts = self._protocol_counts(cursor, recording_id)
            protocol_distribution = _protocol_distribution_from_counts(protocol_counts)
            protocol_segments = _protocol_segments_from_counts(
                protocol_counts,
                self._other_application_count(cursor, recording_id),
            )
            direction = self._direction(cursor, recording_id)
            entropy_histogram = self._entropy_histogram(cursor, recording_id)
            remote_ips = self._remote_ips(cursor, recording_id, top_ips)
            endpoint_tree = self._endpoint_tree(cursor, recording_id)

        elapsed_ms = (time.perf_counter() - started) * 1000
        logger.info(
            "Computed stats for recording %s: %d packets, %d protocols, "
            "%d remote ips, %d endpoint roots in %.1f ms",
            recording_id,
            packet_count,
            len(protocol_distribution),
            len(remote_ips),
            len(endpoint_tree),
            elapsed_ms,
        )
        return {
            "recording_id": recording_id,
            "packet_count": packet_count,
            "protocol_distribution": protocol_distribution,
            "protocol_segments": protocol_segments,
            "direction": direction,
            "entropy_histogram": entropy_histogram,
            "remote_ips": remote_ips,
            "endpoint_tree": endpoint_tree,
        }

    # --- individual aggregations -------------------------------------------------

    def _packet_count(self, cursor, recording_id: int) -> int:
        cursor.execute(
            "SELECT COUNT(*) AS c FROM packet WHERE recording_id = %s", (recording_id,)
        )
        return int(cursor.fetchone()["c"])

    def _protocol_counts(self, cursor, recording_id: int) -> Dict[str, int]:
        cursor.execute(
            """
            SELECT LOWER(pr.name) AS name, COUNT(DISTINCT p.packet_id) AS count
            FROM packet p
            CROSS JOIN LATERAL unnest(p.protocol_ids) AS pid
            JOIN protocol pr ON pr.protocol_id = pid
            WHERE p.recording_id = %s
            GROUP BY LOWER(pr.name)
            """,
            (recording_id,),
        )
        return {r["name"]: int(r["count"]) for r in cursor.fetchall() or []}

    def _other_application_count(self, cursor, recording_id: int) -> int:
        """Count clear payload packets whose stack stops at TLS/QUIC/DTLS."""
        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM packet p
            JOIN protocol final_pr
              ON final_pr.protocol_id = p.protocol_ids[array_length(p.protocol_ids, 1)]
            WHERE p.recording_id = %s
              AND LOWER(final_pr.name) = ANY(%s)
              AND COALESCE(OCTET_LENGTH(p.clear_application_payload), 0) > 0
            """,
            (recording_id, list(_ENCRYPTED_PROTOCOLS)),
        )
        return int(cursor.fetchone()["count"])

    def _direction(self, cursor, recording_id: int) -> Dict[str, int]:
        cursor.execute(
            """
            SELECT from_local, COUNT(*) AS count
            FROM packet WHERE recording_id = %s GROUP BY from_local
            """,
            (recording_id,),
        )
        counts = {"incoming": 0, "outgoing": 0, "unknown": 0}
        for row in cursor.fetchall() or []:
            from_local = row["from_local"]
            key = (
                "outgoing"
                if from_local is True
                else "incoming"
                if from_local is False
                else "unknown"
            )
            counts[key] += int(row["count"])
        return counts

    def _entropy_histogram(self, cursor, recording_id: int) -> List[Dict[str, Any]]:
        cursor.execute(
            """
            SELECT width_bucket(entropy, %s, %s, %s) AS bucket, COUNT(*) AS count
            FROM packet
            WHERE recording_id = %s AND entropy IS NOT NULL
            GROUP BY bucket
            ORDER BY bucket
            """,
            (_ENTROPY_MIN, _ENTROPY_MAX, _ENTROPY_BUCKETS, recording_id),
        )
        # width_bucket yields 1.._ENTROPY_BUCKETS, with 0 for < min and N+1 for
        # >= max. Fold the top overflow (entropy == 8.0 exactly) into the last bar.
        raw: Dict[int, int] = {}
        for row in cursor.fetchall() or []:
            bucket = int(row["bucket"])
            bucket = min(max(bucket, 1), _ENTROPY_BUCKETS)
            raw[bucket] = raw.get(bucket, 0) + int(row["count"])
        return _entropy_buckets(raw)

    def _remote_ips(
        self, cursor, recording_id: int, top_ips: int
    ) -> List[Dict[str, Any]]:
        cursor.execute(
            _REMOTE_IP_CTES
            + """
            SELECT remote_ip, COUNT(*) AS count
            FROM packet_remotes
            WHERE remote_ip IS NOT NULL
              AND NOT EXISTS (
                  SELECT 1
                  FROM local_ips
                  WHERE local_ips.ip = packet_remotes.remote_ip
              )
            GROUP BY remote_ip
            ORDER BY count DESC, remote_ip ASC
            LIMIT %s
            """,
            (recording_id, top_ips),
        )
        return [
            {"ip": r["remote_ip"], "count": int(r["count"])}
            for r in cursor.fetchall() or []
        ]

    def _endpoint_tree(self, cursor, recording_id: int) -> List[Dict[str, Any]]:
        cursor.execute(
            _REMOTE_IP_CTES
            + """
            SELECT
                pr.remote_ip,
                hh.text_header
            FROM recording_packets rp
            JOIN packet_header_information phi_h ON phi_h.packet_id = rp.packet_id
            JOIN http_header_information hh
              ON hh.header_information_id = phi_h.header_information_id
            LEFT JOIN packet_remotes pr ON pr.packet_id = rp.packet_id
            WHERE pr.remote_ip IS NULL
               OR NOT EXISTS (
                   SELECT 1
                   FROM local_ips
                   WHERE local_ips.ip = pr.remote_ip
               )
            """,
            (recording_id,),
        )
        rows = [(r["remote_ip"], r["text_header"]) for r in cursor.fetchall() or []]
        return build_endpoint_tree(rows)


def _entropy_buckets(raw: Dict[int, int]) -> List[Dict[str, Any]]:
    """Materialise all fixed entropy buckets (zero-filled) from a sparse map."""
    buckets: List[Dict[str, Any]] = []
    for i in range(1, _ENTROPY_BUCKETS + 1):
        buckets.append(
            {
                "bucket": i,
                "range_start": round((i - 1) * _ENTROPY_WIDTH, 4),
                "range_end": round(i * _ENTROPY_WIDTH, 4),
                "count": raw.get(i, 0),
            }
        )
    return buckets


def _protocol_distribution_from_counts(
    protocol_counts: Dict[str, int],
) -> List[Dict[str, Any]]:
    """Return the flat protocol distribution, excluding network-layer labels."""
    result = [
        {"name": _protocol_display_name(name), "count": count}
        for name, count in protocol_counts.items()
        if name not in _NETWORK_PROTOCOLS
    ]
    result.sort(key=lambda row: (-row["count"], row["name"]))
    return result


def _protocol_segments_from_counts(
    protocol_counts: Dict[str, int],
    other_application_count: int,
) -> List[Dict[str, Any]]:
    """Build the three dashboard protocol comparison groups."""
    counts = {**protocol_counts, "other": other_application_count}
    return [
        {
            "name": segment_name,
            "protocols": [
                {
                    "name": _protocol_display_name(protocol_name),
                    "count": counts.get(protocol_name, 0),
                }
                for protocol_name in protocol_names
            ],
        }
        for segment_name, protocol_names in _PROTOCOL_SEGMENTS
    ]


def _protocol_display_name(protocol_name: str) -> str:
    return _PROTOCOL_DISPLAY_NAMES.get(protocol_name, protocol_name.upper())


def build_endpoint_tree(rows: List[Tuple[Optional[str], Optional[str]]]) -> List[Dict[str, Any]]:
    """Build a remote-IP -> host -> path tree from (remote_ip, text_header) rows.

    Pure function (no DB), so it is straightforward to unit test. Each HTTP
    request contributes one count to its IP, host and every path segment along
    its route. Non-request headers (responses, unparseable) are skipped.
    """
    ip_nodes: Dict[str, Dict[str, Any]] = {}

    for remote_ip, text_header in rows:
        info = parse_http_header(text_header)
        if not info.is_usable:
            continue

        ip_key = remote_ip or "unknown"
        host_key = info.host or "(no host)"

        ip_node = ip_nodes.setdefault(
            ip_key, {"name": ip_key, "type": "ip", "count": 0, "children": {}}
        )
        ip_node["count"] += 1

        host_node = ip_node["children"].setdefault(
            host_key, {"name": host_key, "type": "host", "count": 0, "children": {}}
        )
        host_node["count"] += 1

        segments = split_path_segments(info.path)
        if not segments:
            segments = ["/"]

        cursor = host_node["children"]
        for seg in segments:
            label = seg if seg == "/" else "/" + seg
            node = cursor.setdefault(
                seg, {"name": label, "type": "path", "count": 0, "children": {}}
            )
            node["count"] += 1
            cursor = node["children"]

    return _children_to_list(ip_nodes)


def _children_to_list(children: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convert the dict-keyed tree into sorted child lists (count desc, name asc)."""
    result = [
        {
            "name": node["name"],
            "type": node["type"],
            "count": node["count"],
            "children": _children_to_list(node["children"]),
        }
        for node in children.values()
    ]
    result.sort(key=lambda n: (-n["count"], n["name"]))
    return result
