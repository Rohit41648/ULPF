"""
Unified Log Analyzer API
=========================
Single entry point for analyzing logs — auto-detects known vs unknown formats,
runs the appropriate pipeline, and returns comprehensive analysis results.

Replaces the separate Process Logs + Unknown Source Onboarding pages.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database import models
from app.database.session import get_db
from app.detection.format_detector import FormatDetector
from app.normalization.universal_event_mapper import FIELD_MAP
from app.onboarding.generated_parser import GeneratedParser
from app.onboarding.parser_generation_service import parser_generation_service
from app.parsers.base import BaseLogParser
from app.parsers.registry import parser_registry
from app.security.crypto import decrypt_and_verify
from app.services.log_processing_service import log_processing_service
from app.schemas.api import (
    AnalyzerResult,
    AnalyzerBatchResult,
    ApproveActionRequest,
    EncryptedEnvelope,
    FieldAnalysis,
    IntegrityResult,
    NormalizedEventOut,
    ParserCandidate,
    RawLogOut,
    SecureBatchProcessRequest,
)

router = APIRouter(prefix="/analyzer", tags=["analyzer"])

_detector = FormatDetector()


# ── Field mapping to Universal Schema ────────────────────────────────────

_FIELD_TO_SCHEMA = {
    "timestamp": "timestamp",
    "hostname": "host.hostname",
    "username": "user.username",
    "source_ip": "network.source_ip",
    "source_port": "network.source_port",
    "destination_ip": "network.destination_ip",
    "destination_port": "network.destination_port",
    "protocol": "network.protocol",
    "event_action": "event.action",
    "event_type": "event.type",
    "severity": "event.severity",
    "http_method": "http.method",
    "http_path": "http.path",
    "http_status_code": "http.status_code",
    "http_user_agent": "http.user_agent",
}

_TYPE_HINTS = {
    "source_port": "integer",
    "destination_port": "integer",
    "http_status_code": "integer",
    "timestamp": "datetime",
    "confidence": "float",
}


def _infer_data_type(field: str, value: Any) -> str:
    if field in _TYPE_HINTS:
        return _TYPE_HINTS[field]
    if value is None:
        return "string"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "float"
    return "string"


# ── Find parser (in-memory + DB-stored AI-generated) ────────────────────

def _find_matching_parser(raw_log: str, db: Session | None = None) -> BaseLogParser | None:
    """Check DB-stored AI-generated (custom) parsers first — they are more
    specific because the user explicitly created them — then fall back to
    built-in deterministic parsers."""
    # Custom / AI-generated parsers take priority
    if db is not None:
        generated_rows = (
            db.query(models.Parser)
            .filter(models.Parser.source_type == "ai_generated", models.Parser.status == "active")
            .all()
        )
        for row in generated_rows:
            candidate = GeneratedParser(row.config or {})
            if candidate.detect(raw_log):
                return candidate

    # Fall back to built-in deterministic parsers
    parser = parser_registry.find_matching_parser(raw_log)
    if parser:
        return parser

    return None


# ── Known-format analysis ────────────────────────────────────────────────

def _analyze_known(
    raw_log: str,
    db: Session,
    integrity_status: str | None = None,
) -> AnalyzerResult:
    """Analyze a log that matches a known parser. Process it and return detailed results."""
    parser = _find_matching_parser(raw_log, db)
    if not parser:
        raise ValueError("Expected a known parser match")

    # Parse to get extracted fields
    fields_dict = parser.parse(raw_log)
    conf = parser.confidence(fields_dict)

    # Build field analysis
    field_analyses = []
    for field_name, value in fields_dict.items():
        if field_name.startswith("ext_"):
            mapped = f"extensions.{field_name}"
        else:
            mapped = _FIELD_TO_SCHEMA.get(field_name, f"extensions.{field_name}")
        field_analyses.append(FieldAnalysis(
            field=field_name,
            value=str(value) if value is not None else None,
            mapped_to=mapped,
            confidence=conf,
            source="deterministic_parser",
            data_type=_infer_data_type(field_name, value),
            status="matched",
        ))

    # Actually process the log
    result = log_processing_service.ingest_and_process(
        db, raw_log, integrity_status=integrity_status,
    )

    # Look up parser in DB
    parser_row = db.query(models.Parser).filter(models.Parser.name == parser.name).first()

    return AnalyzerResult(
        format_status="KNOWN",
        raw_log=raw_log,
        parser_name=parser.name,
        parser_version=parser.version,
        parser_source_type="deterministic" if parser_row and parser_row.source_type == "deterministic" else "ai_generated",
        detected_format=parser.format,
        detected_vendor=parser.vendor,
        confidence=conf,
        fields=field_analyses,
        event=NormalizedEventOut.model_validate(result["event"], from_attributes=True) if result.get("event") else None,
        raw_log_record=RawLogOut.model_validate(result["raw_log"], from_attributes=True) if result.get("raw_log") else None,
    )


# ── Unknown-format analysis ──────────────────────────────────────────────

def _compute_parser_candidates(
    raw_log: str,
    discovered_fields: set[str],
    db: Session | None = None,
) -> list[ParserCandidate]:
    """Compare an unknown log against ALL parsers (in-memory deterministic +
    DB-stored AI-generated) to find candidates."""
    candidates = []

    # Collect all parsers: in-memory + DB-stored AI-generated
    all_parsers: list[BaseLogParser] = list(parser_registry.list_parsers())
    seen_names = {p.name for p in all_parsers}

    if db is not None:
        generated_rows = (
            db.query(models.Parser)
            .filter(models.Parser.source_type == "ai_generated", models.Parser.status == "active")
            .all()
        )
        for row in generated_rows:
            if row.name not in seen_names:
                all_parsers.append(GeneratedParser(row.config or {}))
                seen_names.add(row.name)

    for parser in all_parsers:
        expected = set(getattr(parser, "expected_fields", []))
        if not expected:
            continue

        matched = discovered_fields & expected
        unmatched = discovered_fields - expected
        match_pct = (len(matched) / max(len(expected), len(discovered_fields), 1)) * 100

        recommendation = ""
        if match_pct >= 70:
            new_count = len(unmatched)
            recommendation = f"Strong candidate — extend with {new_count} new field{'s' if new_count != 1 else ''}"
        elif match_pct >= 40:
            recommendation = "Partial match — review field mapping carefully"
        else:
            recommendation = "Low overlap — consider creating a new parser"

        candidates.append(ParserCandidate(
            parser_name=parser.name,
            parser_format=parser.format,
            vendor=parser.vendor,
            match_percentage=round(match_pct, 1),
            matched_fields=sorted(matched),
            unmatched_fields=sorted(unmatched),
            recommendation=recommendation,
        ))

    candidates.sort(key=lambda c: c.match_percentage, reverse=True)
    return candidates


def _analyze_unknown(raw_log: str, db: Session | None = None) -> AnalyzerResult:
    """Analyze a log that doesn't match any known parser."""
    # Run heuristic + optional LLM analysis
    mapping = parser_generation_service.suggest_mapping(raw_log)

    # Build field analysis from suggestions
    field_analyses = []
    discovered_fields = set()
    for f in mapping.get("fields", []):
        field_name = f["field"]
        discovered_fields.add(field_name)
        mapped_to = _FIELD_TO_SCHEMA.get(field_name, f"extensions.{field_name}")
        field_analyses.append(FieldAnalysis(
            field=field_name,
            value=f.get("value"),
            mapped_to=mapped_to,
            confidence=f.get("confidence", 0.0),
            source=f.get("source", "unknown"),
            data_type=_infer_data_type(field_name, f.get("value")),
            status="new",
        ))

    # Compute parser candidates (includes DB-stored AI-generated parsers)
    candidates = _compute_parser_candidates(raw_log, discovered_fields, db=db)

    # Format detection info
    detection = _detector.detect(raw_log)

    return AnalyzerResult(
        format_status="UNKNOWN",
        raw_log=raw_log,
        detected_format=detection.format if detection.format != "unknown" else None,
        detected_vendor=detection.vendor,
        confidence=mapping.get("overall_confidence", 0.0),
        fields=field_analyses,
        parser_candidates=candidates,
    )


# ── API endpoints ────────────────────────────────────────────────────────

@router.post("/analyze", response_model=AnalyzerResult)
def analyze_log(
    payload: dict[str, str],
    db: Session = Depends(get_db),
) -> AnalyzerResult:
    """Analyze a single log line — auto-detects known vs unknown format."""
    raw_log = payload.get("raw_log", "").strip()
    if not raw_log:
        raise HTTPException(400, detail="raw_log is required")

    parser = _find_matching_parser(raw_log, db)
    if parser:
        return _analyze_known(raw_log, db)
    else:
        return _analyze_unknown(raw_log, db=db)


@router.post("/analyze-secure", response_model=AnalyzerResult)
def analyze_log_secure(
    payload: EncryptedEnvelope,
    db: Session = Depends(get_db),
) -> AnalyzerResult:
    """Decrypt an AES-256-GCM envelope, verify integrity, then analyze."""
    if not settings.ENCRYPTION_ENABLED:
        raise HTTPException(404, detail="Application-layer encryption is disabled.")
    try:
        data, integrity = decrypt_and_verify(payload.model_dump(), settings.ENCRYPTION_KEY_PATH)
    except Exception as exc:
        raise HTTPException(400, detail=f"Unable to decrypt: {exc}") from exc

    raw_log = data.get("raw_log", "").strip()
    if not raw_log:
        raise HTTPException(400, detail="raw_log is required in decrypted payload")

    parser = _find_matching_parser(raw_log, db)
    if parser:
        result = _analyze_known(raw_log, db, integrity_status=integrity["integrity_status"])
    else:
        result = _analyze_unknown(raw_log, db=db)

    result.integrity = IntegrityResult(**integrity)
    return result


@router.post("/analyze-batch-secure", response_model=AnalyzerBatchResult)
def analyze_batch_secure(
    payload: EncryptedEnvelope,
    db: Session = Depends(get_db),
) -> AnalyzerBatchResult:
    """Decrypt an encrypted batch, verify integrity, then analyze each line.

    For unknown logs: instead of analyzing each line in isolation, all unknown
    lines have their fields unioned.  A single set of parser candidates is
    computed against the combined field set so the user can create / extend
    a parser that covers the whole file, not just one sample.
    """
    if not settings.ENCRYPTION_ENABLED:
        raise HTTPException(404, detail="Application-layer encryption is disabled.")
    try:
        data, integrity = decrypt_and_verify(payload.model_dump(), settings.ENCRYPTION_KEY_PATH)
        batch = SecureBatchProcessRequest.model_validate(data)
    except Exception as exc:
        raise HTTPException(400, detail=f"Unable to decrypt batch: {exc}") from exc

    integrity_result = IntegrityResult(**integrity)
    results: list[AnalyzerResult] = []
    summary = {"total": 0, "known": 0, "unknown": 0}

    # ── First pass: separate known from unknown ──────────────────────────
    unknown_logs: list[str] = []

    for raw_log_line in batch.raw_logs:
        raw_log_line = raw_log_line.strip()
        if not raw_log_line:
            continue
        summary["total"] += 1

        parser = _find_matching_parser(raw_log_line, db)
        if parser:
            r = _analyze_known(raw_log_line, db, integrity_status=integrity["integrity_status"])
            r.integrity = integrity_result
            results.append(r)
            summary["known"] += 1
        else:
            unknown_logs.append(raw_log_line)
            summary["unknown"] += 1

    # ── Second pass: union all unknown logs into a single analysis ───────
    if unknown_logs:
        # Analyse each unknown line to extract its fields
        all_field_analyses: dict[str, FieldAnalysis] = {}  # field_name -> best FieldAnalysis
        all_discovered_fields: set[str] = set()
        confidence_sum = 0.0

        for ulog in unknown_logs:
            mapping = parser_generation_service.suggest_mapping(ulog)
            confidence_sum += mapping.get("overall_confidence", 0.0)
            for f in mapping.get("fields", []):
                field_name = f["field"]
                all_discovered_fields.add(field_name)
                # Keep the field analysis with the highest confidence
                existing = all_field_analyses.get(field_name)
                new_conf = f.get("confidence", 0.0)
                if existing is None or new_conf > existing.confidence:
                    mapped_to = _FIELD_TO_SCHEMA.get(field_name, f"extensions.{field_name}")
                    all_field_analyses[field_name] = FieldAnalysis(
                        field=field_name,
                        value=f.get("value"),
                        mapped_to=mapped_to,
                        confidence=new_conf,
                        source=f.get("source", "unknown"),
                        data_type=_infer_data_type(field_name, f.get("value")),
                        status="new",
                    )

        # Compute parser candidates using the UNION of all discovered fields
        candidates = _compute_parser_candidates(
            unknown_logs[0], all_discovered_fields, db=db,
        )

        avg_confidence = round(confidence_sum / len(unknown_logs), 2) if unknown_logs else 0.0

        # Build one unified AnalyzerResult for the unknown portion
        detection = _detector.detect(unknown_logs[0])
        unified_unknown = AnalyzerResult(
            format_status="UNKNOWN",
            raw_log=unknown_logs[0],  # representative sample
            detected_format=detection.format if detection.format != "unknown" else None,
            detected_vendor=detection.vendor,
            confidence=avg_confidence,
            fields=list(all_field_analyses.values()),
            parser_candidates=candidates,
            integrity=integrity_result,
            unknown_raw_logs=unknown_logs,
        )
        results.append(unified_unknown)

    return AnalyzerBatchResult(
        results=results,
        summary=summary,
        integrity=integrity_result,
    )


@router.post("/approve")
def approve_action(
    payload: ApproveActionRequest,
    db: Session = Depends(get_db),
) -> dict:
    """Human approval: extend an existing parser or create a new one."""
    if payload.action == "extend_parser":
        # Find existing parser
        existing = db.query(models.Parser).filter(models.Parser.name == payload.parser_name).first()
        if not existing:
            raise HTTPException(404, detail=f"Parser '{payload.parser_name}' not found.")

        # Merge new fields into existing config
        current_config = existing.config or {}
        current_fields = current_config.get("fields", {})
        current_details = current_config.get("field_details", [])

        for f in payload.approved_fields:
            field_name = f["field"]
            current_fields[field_name] = f.get("raw_token") or f.get("value", "")
            # Add to details if not already present
            if not any(d.get("field") == field_name for d in current_details):
                current_details.append(f)

        current_config["fields"] = current_fields
        current_config["field_details"] = current_details
        existing.config = current_config
        # Force SQLAlchemy to detect the change
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(existing, "config")
        db.commit()
        db.refresh(existing)

        return {
            "action": "extended",
            "parser_name": existing.name,
            "parser_id": existing.id,
            "message": f"Extended parser '{existing.name}' with {len(payload.approved_fields)} new fields.",
        }

    elif payload.action == "create_parser":
        # Check if name already exists
        existing = db.query(models.Parser).filter(models.Parser.name == payload.parser_name).first()
        if existing:
            raise HTTPException(409, detail=f"Parser '{payload.parser_name}' already exists.")

        config = parser_generation_service.generate_parser(
            payload.raw_log, payload.parser_name, payload.approved_fields,
        )

        row = models.Parser(
            name=payload.parser_name,
            vendor=None,
            format="custom",
            version="1.0",
            status="active",
            source_type="ai_generated",
            config=config,
        )
        db.add(row)
        db.commit()
        db.refresh(row)

        return {
            "action": "created",
            "parser_name": row.name,
            "parser_id": row.id,
            "message": f"Created new parser '{row.name}' with {len(payload.approved_fields)} fields.",
        }

    else:
        raise HTTPException(400, detail=f"Unknown action '{payload.action}'. Use 'extend_parser' or 'create_parser'.")
