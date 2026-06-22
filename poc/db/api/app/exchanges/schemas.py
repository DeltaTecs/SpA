from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field


class Endpoint(BaseModel):
    ip: Optional[str] = None
    port: Optional[int] = None


class HttpExchangeInfo(BaseModel):
    """The HTTP shape of an ``http_pair`` exchange.

    Only query-string parameter names are captured; request *body* parameters
    are not available from the stored header text.
    """

    method: Optional[str] = None
    scheme: Optional[str] = None
    path: Optional[str] = Field(None, description="Request path as captured, incl. query string.")
    endpoint_path: Optional[str] = Field(
        None, description="Path with query/fragment stripped (used for dedup)."
    )
    param_names: List[str] = Field(
        default_factory=list, description="Sorted distinct query-parameter names."
    )
    status_code: Optional[int] = None
    host: Optional[str] = None


class Exchange(BaseModel):
    """One interesting data exchange compiled from a recording's packets."""

    id: str = Field(description="Stable identity (equals dedup_key).")
    kind: Literal["conversation", "http_pair"]
    transport: Optional[str] = Field(None, description="Transport protocol, e.g. TCP/UDP.")
    local: Optional[Endpoint] = None
    remote: Optional[Endpoint] = None
    representative_packet_ids: List[int] = Field(
        default_factory=list,
        description="A few packet ids to inspect (request+response, or flow samples).",
    )
    packet_count: int = Field(0, description="Raw packets collapsed into this exchange.")
    payload_bytes: int = Field(0, description="Total clear application payload bytes.")
    protocols: List[str] = Field(default_factory=list)
    http: Optional[HttpExchangeInfo] = None
    dedup_key: str = Field(description="The key this exchange was grouped under.")


class ExchangeList(BaseModel):
    recording_id: int
    items: List[Exchange]
