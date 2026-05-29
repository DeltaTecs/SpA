"""Scanner frontend server.

Responsibilities:
- serve the built React SPA (with client-side-routing fallback to index.html),
- proxy ``/api/*`` to the packet database API,
- log to ``poc/logs/scanner-frontend.log``.

It deliberately holds no database logic; all data comes from the db-api.
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse

from .config import Settings
from .logging_config import configure_logging
from .proxy import build_proxy_router

settings = Settings.from_env()
_log_file = configure_logging()
logger = logging.getLogger(__name__)

_STATIC_DIR = Path(settings.static_dir)
_INDEX_FILE = _STATIC_DIR / "index.html"


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "Starting scanner frontend (db_api_url=%s, static_dir=%s, logs=%s)",
        settings.db_api_url,
        settings.static_dir,
        _log_file,
    )
    if not _INDEX_FILE.is_file():
        logger.warning(
            "SPA build not found at %s; serving API proxy only (dev mode). "
            "Run the Vite dev server, or build the SPA into this directory.",
            _STATIC_DIR,
        )
    app.state.http_client = httpx.AsyncClient(
        base_url=settings.db_api_url, timeout=settings.proxy_timeout
    )
    try:
        yield
    finally:
        await app.state.http_client.aclose()
        logger.info("Scanner frontend stopped")


app = FastAPI(title="Scanner Frontend", version="0.1.0", lifespan=lifespan)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = (time.perf_counter() - start) * 1000
    logger.info(
        "%s %s -> %s (%.1f ms)",
        request.method,
        request.url.path,
        response.status_code,
        elapsed_ms,
    )
    return response


@app.get("/health", tags=["health"])
async def health() -> dict:
    return {"status": "ok"}


# All data access is proxied to the db-api under /api/*.
app.include_router(build_proxy_router(), prefix="/api")


def _safe_static_file(rel_path: str) -> Path | None:
    """Resolve ``rel_path`` under the static dir, guarding against traversal."""
    if not rel_path:
        return None
    candidate = (_STATIC_DIR / rel_path).resolve()
    try:
        candidate.relative_to(_STATIC_DIR.resolve())
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    """Serve a built static asset if it exists, else the SPA entry point.

    The index.html fallback lets the client-side router own paths like
    ``/explorer`` and ``/attack``.
    """
    asset = _safe_static_file(full_path)
    if asset is not None:
        return FileResponse(asset)
    if _INDEX_FILE.is_file():
        return FileResponse(_INDEX_FILE)
    return JSONResponse(
        {"detail": "SPA not built. Use the Vite dev server during development."},
        status_code=404,
    )
