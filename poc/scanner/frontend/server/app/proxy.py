"""Reverse proxy that forwards ``/api/*`` requests to the packet database API.

Keeping the SPA same-origin (it calls ``/api/...``) avoids any CORS dependency
and gives us a single place to log outbound calls and, later, to inject
attack-orchestration endpoints alongside the passthrough.
"""

from __future__ import annotations

import logging

import httpx
from fastapi import APIRouter, Request, Response

logger = logging.getLogger(__name__)

# Headers that must not be copied verbatim between hops.
_HOP_BY_HOP = {
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
}

_PROXY_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]


def build_proxy_router() -> APIRouter:
    """Build the catch-all router that proxies to ``app.state.http_client``."""

    router = APIRouter()

    @router.api_route("/{path:path}", methods=_PROXY_METHODS)
    async def proxy(path: str, request: Request) -> Response:
        client: httpx.AsyncClient = request.app.state.http_client
        upstream_path = "/" + path
        body = await request.body()
        fwd_headers = {
            k: v for k, v in request.headers.items() if k.lower() not in _HOP_BY_HOP
        }

        try:
            upstream = await client.request(
                request.method,
                upstream_path,
                params=request.query_params.multi_items(),
                content=body,
                headers=fwd_headers,
            )
        except httpx.RequestError as exc:
            logger.error(
                "Proxy to db-api failed for %s %s: %s", request.method, upstream_path, exc
            )
            return Response(
                content=b'{"detail":"upstream db-api unavailable"}',
                status_code=502,
                media_type="application/json",
            )

        logger.debug(
            "Proxied %s %s -> %s (%d bytes)",
            request.method,
            upstream_path,
            upstream.status_code,
            len(upstream.content),
        )
        # httpx has already decoded the body, so drop encoding/length headers.
        resp_headers = {
            k: v
            for k, v in upstream.headers.items()
            if k.lower() not in _HOP_BY_HOP and k.lower() != "content-encoding"
        }
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            headers=resp_headers,
            media_type=upstream.headers.get("content-type"),
        )

    return router
