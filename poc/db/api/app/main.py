from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import DbConfig
from .logging_config import configure_logging
from .packets.router import router as packets_router
from .stats.router import router as stats_router


_log_file = configure_logging()
logger = logging.getLogger(__name__)
logger.info(
    "Starting Packet Database API (db_host=%s, db_name=%s, logs=%s)",
    DbConfig.from_env().host,
    DbConfig.from_env().name,
    _log_file,
)

app = FastAPI(title="Packet Database API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", tags=["health"])
def health() -> dict:
    return {"status": "ok"}


app.include_router(packets_router)
app.include_router(stats_router)
