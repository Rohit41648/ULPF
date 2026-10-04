from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import models
from app.database.session import get_db
from app.onboarding.parser_generation_service import parser_generation_service
from app.services.log_processing_service import log_processing_service
from app.parsers.registry import parser_registry
from app.core.config import settings
from app.security.crypto import decrypt_with_config
from app.schemas.api import (
    OnboardingAnalyzeRequest,
    EncryptedEnvelope,
    OnboardingAnalyzeResponse,
    OnboardingCreateParserRequest,
    OnboardingCreateParserResponse,
)

router = APIRouter(prefix="/onboarding", tags=["onboarding"])


@router.post("/analyze", response_model=OnboardingAnalyzeResponse)
def analyze_unknown_log(payload: OnboardingAnalyzeRequest) -> dict:
    """Step 1 of onboarding: confirm no known parser matches, then run the
    heuristic (optionally LLM-assisted) field discovery engine."""
    if parser_registry.find_matching_parser(payload.raw_log):
        raise HTTPException(
            status_code=400,
            detail="This log already matches a known deterministic parser; onboarding is not needed.",
        )
    mapping = parser_generation_service.suggest_mapping(payload.raw_log)
    return {**mapping, "raw_log": payload.raw_log}


@router.post("/analyze-secure", response_model=OnboardingAnalyzeResponse)
def analyze_unknown_log_secure(payload: EncryptedEnvelope) -> dict:
    """Decrypt a sender-encrypted onboarding request at the receiving side."""
    if not settings.ENCRYPTION_ENABLED:
        raise HTTPException(status_code=404, detail="Application-layer encryption is disabled.")
    try:
        data = decrypt_with_config(payload.model_dump(), settings.ENCRYPTION_KEY_PATH)
        request = OnboardingAnalyzeRequest.model_validate(data)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Unable to decrypt secure onboarding payload: {exc}") from exc

    if parser_registry.find_matching_parser(request.raw_log):
        raise HTTPException(
            status_code=400,
            detail="This log already matches a known deterministic parser; onboarding is not needed.",
        )
    mapping = parser_generation_service.suggest_mapping(request.raw_log)
    return {**mapping, "raw_log": request.raw_log}


@router.post("/create-parser", response_model=OnboardingCreateParserResponse)
def create_parser(payload: OnboardingCreateParserRequest, db: Session = Depends(get_db)) -> dict:
    """Step 2 of onboarding: human has reviewed/edited the suggested mapping
    and approves it -> persist as an ai_generated parser for future logs."""
    existing = db.query(models.Parser).filter(models.Parser.name == payload.parser_name).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Parser '{payload.parser_name}' already exists.")

    config = parser_generation_service.generate_parser(
        payload.raw_log, payload.parser_name, payload.approved_fields,
    )

    row = models.Parser(
        name=payload.parser_name,
        vendor="Unknown",
        format="custom",
        version="1.0",
        status="active",
        source_type="ml_generated",
        config=config,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    # Process the original raw log through the newly created parser
    # so the event is recorded and appears on the Events page
    log_processing_service.ingest_and_process(db, payload.raw_log)

    return {"parser": row, "config": config}


@router.post("/create-parser-secure", response_model=OnboardingCreateParserResponse)
def create_parser_secure(payload: EncryptedEnvelope, db: Session = Depends(get_db)) -> dict:
    """Decrypt an encrypted parser-approval request before persistence."""
    if not settings.ENCRYPTION_ENABLED:
        raise HTTPException(status_code=404, detail="Application-layer encryption is disabled.")
    try:
        data = decrypt_with_config(payload.model_dump(), settings.ENCRYPTION_KEY_PATH)
        request = OnboardingCreateParserRequest.model_validate(data)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Unable to decrypt secure parser payload: {exc}") from exc

    existing = db.query(models.Parser).filter(models.Parser.name == request.parser_name).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Parser '{request.parser_name}' already exists.")

    config = parser_generation_service.generate_parser(
        request.raw_log, request.parser_name, request.approved_fields,
    )
    row = models.Parser(
        name=request.parser_name,
        vendor="Unknown",
        format="custom",
        version="1.0",
        status="active",
        source_type="ml_generated",
        config=config,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    # Process the original raw log through the newly created parser
    log_processing_service.ingest_and_process(db, request.raw_log)

    return {"parser": row, "config": config}
