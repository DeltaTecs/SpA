"""Reverse proxy that forwards SPA ``/api/*`` requests to an upstream service.

Keeping the SPA same-origin (it calls ``/api/...``) avoids any CORS dependency
and gives us a single place to log outbound calls. One router instance forwards
to one upstream ``httpx.AsyncClient`` (named via ``client_attr``), so the app can
mount several: ``/api/plan/*`` to the scanner backend and ``/api/*`` to the db-api.
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


def build_proxy_router(client_attr: str = "http_client") -> APIRouter:
    """Build a catch-all router proxying to ``app.state.<client_attr>``.

    FastAPI strips the router's mount ``prefix`` from ``path``, so a router
    mounted at ``/api/plan`` forwards the remainder (e.g. ``/jobs``) to its
    upstream base URL.
    """

    router = APIRouter()

    @router.api_route("/{path:path}", methods=_PROXY_METHODS)
    async def proxy(path: str, request: Request) -> Response:
        client: httpx.AsyncClient = getattr(request.app.state, client_attr)
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
                "Proxy to %s failed for %s %s: %s",
                client_attr,
                request.method,
                upstream_path,
                exc,
            )
            return Response(
                content=b'{"detail":"upstream service unavailable"}',
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
