from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import events, logs, onboarding, parsers, security, stats
from app.api.v1.analyzer import router as analyzer_router
from app.api.v1.blockchain import router as blockchain_router
from app.core.config import settings
from app.core.logging import setup_logging
from app.database.init_db import init_db

setup_logging()

app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "ULPF is NOT a SIEM. It is an intelligent preprocessing and "
        "normalization layer that sits before a SIEM/analytics/ML platform, "
        "converting heterogeneous security logs into a common, "
        "analytics-ready universal schema while preserving the original "
        "raw log for forensic traceability."
    ),
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup() -> None:
    init_db()


app.include_router(logs.router, prefix=settings.API_V1_PREFIX)
app.include_router(events.router, prefix=settings.API_V1_PREFIX)
app.include_router(parsers.router, prefix=settings.API_V1_PREFIX)
app.include_router(onboarding.router, prefix=settings.API_V1_PREFIX)
app.include_router(stats.router, prefix=settings.API_V1_PREFIX)
app.include_router(security.router, prefix=settings.API_V1_PREFIX)
app.include_router(analyzer_router, prefix=settings.API_V1_PREFIX)
app.include_router(blockchain_router, prefix="/api/v1")


@app.get("/")
def root() -> dict:
    return {
        "app": settings.APP_NAME,
        "docs": "/docs",
        "note": "ULPF is a preprocessing/normalization layer, not a SIEM.",
    }
