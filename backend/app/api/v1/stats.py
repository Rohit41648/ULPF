from __future__ import annotations

from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database import models
from app.database.session import get_db
from app.schemas.api import HealthResponse, StatsResponse

router = APIRouter(tags=["stats"])


@router.get("/stats", response_model=StatsResponse)
def get_stats(db: Session = Depends(get_db)) -> dict:
    total_logs = db.query(func.count(models.RawLog.id)).scalar() or 0
    processed_events = db.query(func.count(models.NormalizedEvent.id)).scalar() or 0
    supported_formats = db.query(func.count(models.Parser.id)).filter(models.Parser.status == "active").scalar() or 0

    avg_conf = db.query(func.avg(models.NormalizedEvent.confidence)).scalar()
    unknown_pending = (
        db.query(func.count(models.ProcessingRun.id))
        .filter(models.ProcessingRun.status == "FAILED", models.ProcessingRun.detected_format == "unknown")
        .scalar()
        or 0
    )

    events = db.query(models.NormalizedEvent).all()
    by_format = Counter(e.format or "unknown" for e in events)
    by_vendor = Counter(e.vendor or "unknown" for e in events)
    by_severity = Counter(e.severity or "unknown" for e in events)
    by_status = Counter(e.processing_status for e in events)

    # Integrity hash verification stats
    integrity_verified = (
        db.query(func.count(models.RawLog.id))
        .filter(models.RawLog.integrity_status == "VERIFIED")
        .scalar() or 0
    )
    integrity_tampered = (
        db.query(func.count(models.RawLog.id))
        .filter(models.RawLog.integrity_status == "TAMPERED")
        .scalar() or 0
    )
    integrity_no_hash = (
        db.query(func.count(models.RawLog.id))
        .filter(models.RawLog.integrity_status == "NO_HASH")
        .scalar() or 0
    )

    return {
        "total_logs": total_logs,
        "processed_events": processed_events,
        "supported_formats": supported_formats,
        "average_confidence": round(float(avg_conf), 3) if avg_conf else 0.0,
        "unknown_sources_pending": unknown_pending,
        "events_by_format": dict(by_format),
        "events_by_vendor": dict(by_vendor),
        "events_by_severity": dict(by_severity),
        "processing_status_breakdown": dict(by_status),
        "integrity_verified": integrity_verified,
        "integrity_tampered": integrity_tampered,
        "integrity_no_hash": integrity_no_hash,
    }


@router.get("/health", response_model=HealthResponse)
def health_check(db: Session = Depends(get_db)) -> dict:
    db_status = "ok"
    try:
        db.execute(func.now() if not settings.DATABASE_URL.startswith("sqlite") else func.abs(1))
    except Exception:
        db_status = "unreachable"
    return {"status": "ok", "app_name": settings.APP_NAME, "database": db_status}
