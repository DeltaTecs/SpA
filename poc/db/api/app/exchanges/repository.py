from __future__ import annotations

from typing import Any, Dict, List

from ..db import dict_cursor
from ..packets.repository import _PACKET_ENRICH_JOINS, _PACKET_ENRICH_SELECT_COLUMNS
from .grouping import EnrichedPacket, compile_exchanges


class ExchangeRepository:
    """Compiles a recording's packets into interesting data exchanges.

    The enrichment SQL (peer ip/ports, transport, HTTP header text/stream id) is
    shared with :class:`app.packets.repository.PacketRepository`; the grouping,
    dedup and pairing logic lives in the pure :mod:`app.exchanges.grouping` module.
    """

    def list_exchanges(self, recording_id: int) -> List[Dict[str, Any]]:
        with dict_cursor() as cursor:
            cursor.execute(
                f"""
                SELECT
                    {_PACKET_ENRICH_SELECT_COLUMNS}
                FROM packet p
                {_PACKET_ENRICH_JOINS}
                WHERE p.recording_id = %s
                ORDER BY p.timestamp ASC NULLS LAST, p.number ASC, p.packet_id ASC
                """,
                (recording_id,),
            )
            packets = [_to_enriched(dict(row)) for row in cursor.fetchall() or []]
        return compile_exchanges(packets)


def _to_enriched(row: Dict[str, Any]) -> EnrichedPacket:
    return EnrichedPacket(
        packet_id=row["packet_id"],
        from_local=row.get("from_local"),
        timestamp=row.get("timestamp"),
        number=row.get("number"),
        transport=row.get("transport_protocol"),
        src_ip=row.get("ip_src"),
        src_port=row.get("port_src"),
        dst_ip=row.get("ip_dst"),
        dst_port=row.get("port_dst"),
        http_text=row.get("http_text"),
        stream_id=row.get("http_stream_id"),
        http_count=row.get("http_count") or 0,
        payload_length=row.get("payload_length") or 0,
        protocols=tuple(row.get("protocols") or ()),
    )
