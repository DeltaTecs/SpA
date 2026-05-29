from __future__ import annotations

import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .packets.router import router as packets_router


def _configure_logging() -> None:
    # The compose stack uses LOG_LEVEL=VERBOSE; map it onto stdlib levels.
    raw_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    level = logging.DEBUG if raw_level in {"VERBOSE", "DEBUG"} else logging.INFO
    logging.basicConfig(level=level)


_configure_logging()

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
