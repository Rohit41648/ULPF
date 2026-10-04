from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.config import settings
from app.security.crypto import decrypt_and_verify, decrypt_with_config
from app.database import models
from app.database.session import get_db
from app.schemas.api import (
    BatchProcessRequest,
    SecureBatchProcessRequest,
    EncryptedEnvelope,
    IngestLogRequest,
    IntegrityResult,
    ProcessLogRequest,
    ProcessLogResponse,
    RawLogOut,
)
from app.services.log_processing_service import log_processing_service

router = APIRouter(prefix="/logs", tags=["logs"])


def _check_size(raw_log: str) -> None:
    if len(raw_log.encode("utf-8")) > settings.MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Log exceeds maximum allowed size.")


def _check_batch_size(raw_logs: list[str]) -> None:
    if len(raw_logs) > settings.MAX_BATCH_LOGS:
        raise HTTPException(413, detail=f"Batch contains more than {settings.MAX_BATCH_LOGS} log lines.")
    total_bytes = sum(len(line.encode("utf-8")) for line in raw_logs)
    if total_bytes > settings.MAX_BATCH_BYTES:
        raise HTTPException(413, detail="Uploaded log file exceeds the maximum allowed batch size.")
    for line in raw_logs:
        _check_size(line)


@router.post("/ingest", response_model=RawLogOut)
def ingest_log(payload: IngestLogRequest, db: Session = Depends(get_db)) -> models.RawLog:
    """Store a raw log without processing it yet (pure preservation step)."""
    _check_size(payload.raw_log)
    return log_processing_service.ingest_raw_log(db, payload.raw_log, payload.source_hint)


@router.post("/process", response_model=ProcessLogResponse)
def process_log(payload: ProcessLogRequest, db: Session = Depends(get_db)) -> dict:
    """Ingest + immediately run the detect -> parse -> normalize -> validate pipeline."""
    _check_size(payload.raw_log)
    result = log_processing_service.ingest_and_process(db, payload.raw_log, payload.source_hint)
    message = None
    if result["status"] == "UNKNOWN_FORMAT":
        message = "No known or generated parser matched this log. Use /onboarding/analyze to onboard it."
    return {"status": result["status"], "raw_log": result["raw_log"], "event": result["event"], "message": message}


@router.post("/process/batch", response_model=list[ProcessLogResponse])
def process_batch(payload: BatchProcessRequest, db: Session = Depends(get_db)) -> list[dict]:
    _check_batch_size(payload.raw_logs)
    responses = []
    for raw_log in payload.raw_logs:
        _check_size(raw_log)
        result = log_processing_service.ingest_and_process(db, raw_log, payload.source_hint)
        message = None
        if result["status"] == "UNKNOWN_FORMAT":
            message = "No known or generated parser matched this log."
        responses.append({"status": result["status"], "raw_log": result["raw_log"], "event": result["event"], "message": message})
    return responses


@router.post("/secure-process-batch", response_model=list[ProcessLogResponse])
def secure_process_batch(payload: EncryptedEnvelope, db: Session = Depends(get_db)) -> list[dict]:
    """Decrypt an AES-256-GCM encrypted batch, verify integrity hash, then process."""
    if not settings.ENCRYPTION_ENABLED:
        raise HTTPException(status_code=404, detail="Application-layer encryption is disabled.")
    try:
        data, integrity = decrypt_and_verify(payload.model_dump(), settings.ENCRYPTION_KEY_PATH)
        request = SecureBatchProcessRequest.model_validate(data)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Unable to decrypt secure log batch: {exc}") from exc

    integrity_result = IntegrityResult(**integrity)
    _check_batch_size(request.raw_logs)
    responses = []
    for raw_log in request.raw_logs:
        result = log_processing_service.ingest_and_process(
            db, raw_log, request.source_hint,
            integrity_status=integrity["integrity_status"],
        )
        message = None
        if result["status"] == "UNKNOWN_FORMAT":
            message = "No known or generated parser matched this line."
        responses.append({
            "status": result["status"],
            "raw_log": result["raw_log"],
            "event": result["event"],
            "message": message,
            "integrity": integrity_result,
        })
    return responses


@router.get("", response_model=list[RawLogOut])
def list_logs(
    db: Session = Depends(get_db),
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[models.RawLog]:
    return (
        db.query(models.RawLog)
        .order_by(models.RawLog.ingested_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.get("/{log_id}", response_model=RawLogOut)
def get_log(log_id: str, db: Session = Depends(get_db)) -> models.RawLog:
    raw_log = db.query(models.RawLog).filter(models.RawLog.id == log_id).first()
    if not raw_log:
        raise HTTPException(status_code=404, detail="Raw log not found.")
    return raw_log


@router.post("/secure-process", response_model=ProcessLogResponse)
def secure_process_log(payload: EncryptedEnvelope, db: Session = Depends(get_db)) -> dict:
    """Decrypt an AES-256-GCM encrypted log, verify integrity hash, then process."""
    if not settings.ENCRYPTION_ENABLED:
        raise HTTPException(status_code=404, detail="Application-layer encryption is disabled.")
    try:
        data, integrity = decrypt_and_verify(payload.model_dump(), settings.ENCRYPTION_KEY_PATH)
        request = ProcessLogRequest.model_validate(data)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Unable to decrypt secure log payload: {exc}") from exc

    _check_size(request.raw_log)
    result = log_processing_service.ingest_and_process(
        db, request.raw_log, request.source_hint,
        integrity_status=integrity["integrity_status"],
    )
    message = None
    if result["status"] == "UNKNOWN_FORMAT":
        message = "No known or generated parser matched this log. Use /onboarding/analyze to onboard it."
    return {
        "status": result["status"],
        "raw_log": result["raw_log"],
        "event": result["event"],
        "message": message,
        "integrity": IntegrityResult(**integrity),
    }
