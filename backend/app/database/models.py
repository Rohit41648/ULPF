from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


def _uuid() -> str:
    return uuid.uuid4().hex


def _now() -> datetime:
    return datetime.now(timezone.utc)


class RawLog(Base):
    __tablename__ = "raw_logs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    raw_content: Mapped[str] = mapped_column(Text, nullable=False)
    detected_format: Mapped[str | None] = mapped_column(String, nullable=True)
    detected_vendor: Mapped[str | None] = mapped_column(String, nullable=True)
    source_hint: Mapped[str | None] = mapped_column(String, nullable=True)  # e.g. upload filename
    integrity_status: Mapped[str | None] = mapped_column(
        String, nullable=True, default=None
    )  # VERIFIED | TAMPERED | NO_HASH — set for encrypted uploads
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    events: Mapped[list["NormalizedEvent"]] = relationship(back_populates="raw_log")


class Parser(Base):
    __tablename__ = "parsers"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    vendor: Mapped[str | None] = mapped_column(String, nullable=True)
    format: Mapped[str | None] = mapped_column(String, nullable=True)
    version: Mapped[str] = mapped_column(String, default="1.0")
    status: Mapped[str] = mapped_column(String, default="active")  # active | generated | disabled
    source_type: Mapped[str] = mapped_column(String, default="deterministic")  # deterministic | ai_generated
    config: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # generated field mapping, if any
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    events_processed: Mapped[int] = mapped_column(Integer, default=0)

    events: Mapped[list["NormalizedEvent"]] = relationship(back_populates="parser")


class NormalizedEvent(Base):
    __tablename__ = "normalized_events"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    raw_log_id: Mapped[str] = mapped_column(String, ForeignKey("raw_logs.id"), nullable=False)
    parser_id: Mapped[str | None] = mapped_column(String, ForeignKey("parsers.id"), nullable=True)

    event_data: Mapped[dict] = mapped_column(JSON, nullable=False)  # full UniversalEvent as JSON
    event_type: Mapped[str | None] = mapped_column(String, nullable=True)
    severity: Mapped[str | None] = mapped_column(String, nullable=True)
    vendor: Mapped[str | None] = mapped_column(String, nullable=True)
    format: Mapped[str | None] = mapped_column(String, nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)

    processing_status: Mapped[str] = mapped_column(String, default="SUCCESS")  # SUCCESS|WARNING|FAILED
    validation_warnings: Mapped[list | None] = mapped_column(JSON, nullable=True)
    validation_errors: Mapped[list | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    raw_log: Mapped["RawLog"] = relationship(back_populates="events")
    parser: Mapped["Parser | None"] = relationship(back_populates="events")


class ProcessingRun(Base):
    """One row per ingest/process call — used for /stats and audit history."""

    __tablename__ = "processing_runs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    raw_log_id: Mapped[str | None] = mapped_column(String, ForeignKey("raw_logs.id"), nullable=True)
    event_id: Mapped[str | None] = mapped_column(String, ForeignKey("normalized_events.id"), nullable=True)
    status: Mapped[str] = mapped_column(String, default="SUCCESS")
    detected_format: Mapped[str | None] = mapped_column(String, nullable=True)
    parser_used: Mapped[str | None] = mapped_column(String, nullable=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
