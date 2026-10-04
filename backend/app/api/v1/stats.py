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

    # Blockchain ledger integrity audit
    corrupted_raw_log_ids = set()
    blockchain_tampered = 0
    try:
        from app.api.v1.blockchain import ledger
        audit = ledger.verify_chain_detailed()
        corrupted_indices = set(audit.get("corrupted_blocks", []))
        blockchain_tampered = len(corrupted_indices)
        if corrupted_indices:
            for b in ledger.get_blocks():
                if b.get("index") in corrupted_indices and b.get("raw_log_id"):
                    corrupted_raw_log_ids.add(b["raw_log_id"])
            if corrupted_raw_log_ids:
                db.query(models.RawLog).filter(
                    models.RawLog.id.in_(corrupted_raw_log_ids),
                    models.RawLog.integrity_status != "TAMPERED",
                ).update({"integrity_status": "TAMPERED"}, synchronize_session=False)
                db.commit()
    except Exception:
        pass

    # Integrity verification stats (including upload transit and blockchain audits)
    integrity_tampered = (
        db.query(func.count(models.RawLog.id))
        .filter(models.RawLog.integrity_status == "TAMPERED")
        .scalar() or 0
    )
    if blockchain_tampered > integrity_tampered:
        integrity_tampered = blockchain_tampered

    integrity_verified = (
        db.query(func.count(models.RawLog.id))
        .filter(models.RawLog.integrity_status == "VERIFIED")
        .scalar() or 0
    )
    integrity_no_hash = (
        db.query(func.count(models.RawLog.id))
        .filter(
            (models.RawLog.integrity_status == "NO_HASH")
            | (models.RawLog.integrity_status.is_(None))
        )
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
        "blockchain_tampered": blockchain_tampered,
        "blockchain_valid": blockchain_tampered == 0,
    }


@router.get("/health", response_model=HealthResponse)
def health_check(db: Session = Depends(get_db)) -> dict:
    db_status = "ok"
    try:
        db.execute(func.now() if not settings.DATABASE_URL.startswith("sqlite") else func.abs(1))
    except Exception:
        db_status = "unreachable"

    # Engine Status: Local ML Classifier
    ml_status = {"status": "offline", "model": "RandomForestClassifier", "offline": True}
    try:
        from app.onboarding.ml_provider import local_ml_engine
        ml_status = {
            "status": "active" if local_ml_engine.is_available() else "idle",
            "model": "RandomForestClassifier (13 schema classes)",
            "offline": True,
            "classes_count": 14,
            "training_samples": 40,
        }
    except Exception as e:
        ml_status["error"] = str(e)

    # Engine Status: Blockchain Ledger
    blockchain_status = {"status": "inactive"}
    try:
        from app.api.v1.blockchain import ledger
        audit = ledger.verify_chain_detailed()
        is_valid = audit["valid"]
        blockchain_status = {
            "status": "healthy" if is_valid else "compromised",
            "total_blocks": len(ledger.get_blocks()),
            "algorithm": "SHA-256 Merkle Chain",
            "chain_valid": is_valid,
            "corrupted_blocks": audit.get("corrupted_blocks", []),
            "tampered_count": len(audit.get("corrupted_blocks", [])),
        }
    except Exception as e:
        blockchain_status["error"] = str(e)

    # Engine Status: Cryptographic Key Management
    crypto_status = {"status": "active", "cipher": "AES-256-GCM"}
    try:
        from app.security.crypto import get_aes_key_hex, DEFAULT_AES_KEY_PATH
        path = settings.ENCRYPTION_KEY_PATH or str(DEFAULT_AES_KEY_PATH)
        key_hex = get_aes_key_hex(path)
        crypto_status = {
            "status": "active" if settings.ENCRYPTION_ENABLED else "disabled",
            "cipher": "AES-256-GCM (A256GCM)",
            "has_key": bool(key_hex),
        }
    except Exception as e:
        crypto_status["error"] = str(e)

    return {
        "status": "ok",
        "app_name": settings.APP_NAME,
        "database": db_status,
        "ml_engine": ml_status,
        "blockchain": blockchain_status,
        "crypto": crypto_status,
    }


