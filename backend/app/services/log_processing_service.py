"""
LogProcessingService
======================
Implements the two pipelines from the architecture doc:

KNOWN FORMAT:
  raw log -> format detection -> deterministic parser -> normalize -> validate -> store

UNKNOWN FORMAT:
  raw log -> format detection -> no parser matches -> caller is told to use
  the onboarding endpoints (/onboarding/analyze, /onboarding/create-parser)

This module is the single place that touches the database for
ingestion/processing, keeping API route handlers thin.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.database import models
from app.onboarding.generated_parser import GeneratedParser
from app.parsers.base import BaseLogParser
from app.parsers.registry import parser_registry
from app.schemas.universal_event import UniversalEvent
from app.validation.validator import validate_event
from app.blockchain.ledger import BlockchainLedger


class NoParserAvailable(Exception):
    """Raised when no deterministic or generated parser can handle a log."""

    def __init__(self, raw_log_id: str):
        self.raw_log_id = raw_log_id
        super().__init__(f"No parser available for raw_log_id={raw_log_id}")


class LogProcessingService:
    def __init__(self):
        self.blockchain = BlockchainLedger()
    def ingest_raw_log(
        self,
        db: Session,
        raw_content: str,
        source_hint: str | None = None,
        integrity_status: str | None = None,
    ) -> models.RawLog:
        raw_log = models.RawLog(
            raw_content=raw_content,
            source_hint=source_hint,
            integrity_status=integrity_status,
        )
        db.add(raw_log)
        db.commit()
        db.refresh(raw_log)
        return raw_log

    def _find_parser(self, db: Session, raw_content: str) -> BaseLogParser | None:
        parser = parser_registry.find_matching_parser(raw_content)
        if parser:
            return parser

        # fall back to DB-stored AI-generated parsers
        generated_rows = (
            db.query(models.Parser)
            .filter(models.Parser.source_type == "ai_generated", models.Parser.status == "active")
            .all()
        )
        for row in generated_rows:
            candidate = GeneratedParser(row.config or {})
            if candidate.detect(raw_content):
                return candidate
        return None

    def process_raw_log(self, db: Session, raw_log: models.RawLog) -> models.NormalizedEvent:
        parser = self._find_parser(db, raw_log.raw_content)
        if parser is None:
            db.add(models.ProcessingRun(
                raw_log_id=raw_log.id, status="FAILED", detected_format="unknown",
                message="No deterministic or generated parser matched this log.",
            ))
            db.commit()
            raise NoParserAvailable(raw_log.id)

        raw_log.detected_format = parser.format
        raw_log.detected_vendor = parser.vendor

        event: UniversalEvent = parser.normalize(raw_log.raw_content, raw_log.id)
        validation = validate_event(event)

        parser_row = db.query(models.Parser).filter(models.Parser.name == parser.name).first()

        normalized_event = models.NormalizedEvent(
            raw_log_id=raw_log.id,
            parser_id=parser_row.id if parser_row else None,
            event_data=event.model_dump(mode="json"),
            event_type=event.event.type,
            severity=event.event.severity,
            vendor=event.source.vendor,
            format=event.source.format,
            source_ip=event.network.source_ip,
            confidence=event.parser.confidence,
            processing_status=validation.status,
            validation_warnings=validation.warnings,
            validation_errors=validation.errors,
        )
        db.add(normalized_event)

        if parser_row:
            parser_row.events_processed = (parser_row.events_processed or 0) + 1

        db.add(models.ProcessingRun(
            raw_log_id=raw_log.id, event_id=None, status=validation.status,
            detected_format=parser.format, parser_used=parser.name,
            message="; ".join(validation.warnings + validation.errors) or "Processed successfully.",
        ))
        db.commit()
        db.refresh(normalized_event)
                # Create blockchain integrity proof
        blockchain_block = self.blockchain.add_event(
            event_id=event.event_id,
            raw_log_id=raw_log.id,
            event_data=event.model_dump(mode="json"),
            raw_log=raw_log.raw_content,
            parser_id=parser.name,
        )
        return normalized_event

    def ingest_and_process(
        self,
        db: Session,
        raw_content: str,
        source_hint: str | None = None,
        integrity_status: str | None = None,
    ) -> dict[str, Any]:
        raw_log = self.ingest_raw_log(db, raw_content, source_hint, integrity_status)
        try:
            event = self.process_raw_log(db, raw_log)
            return {"raw_log": raw_log, "event": event, "status": event.processing_status}
        except NoParserAvailable:
            return {"raw_log": raw_log, "event": None, "status": "UNKNOWN_FORMAT"}


log_processing_service = LogProcessingService()
