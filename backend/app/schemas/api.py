from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel


class IngestLogRequest(BaseModel):
    raw_log: str
    source_hint: Optional[str] = None


class ProcessLogRequest(BaseModel):
    raw_log: str
    source_hint: Optional[str] = None


class BatchProcessRequest(BaseModel):
    raw_logs: list[str]
    source_hint: Optional[str] = None


class SecureBatchProcessRequest(BaseModel):
    raw_logs: list[str]
    source_hint: Optional[str] = None


class RawLogOut(BaseModel):
    id: str
    raw_content: str
    detected_format: Optional[str] = None
    detected_vendor: Optional[str] = None
    source_hint: Optional[str] = None
    integrity_status: Optional[str] = None  # VERIFIED | TAMPERED | NO_HASH
    ingested_at: datetime

    model_config = {"from_attributes": True}


class NormalizedEventOut(BaseModel):
    id: str
    raw_log_id: str
    parser_id: Optional[str] = None
    event_data: dict[str, Any]
    event_type: Optional[str] = None
    severity: Optional[str] = None
    vendor: Optional[str] = None
    format: Optional[str] = None
    source_ip: Optional[str] = None
    confidence: Optional[float] = None
    processing_status: str
    validation_warnings: Optional[list[str]] = None
    validation_errors: Optional[list[str]] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class IntegrityResult(BaseModel):
    """Result of the SHA-256 integrity hash verification."""
    integrity_verified: bool
    integrity_hash_sent: Optional[str] = None
    integrity_hash_computed: str
    integrity_status: str  # VERIFIED | TAMPERED | NO_HASH


class ProcessLogResponse(BaseModel):
    status: str  # SUCCESS | WARNING | FAILED | UNKNOWN_FORMAT
    raw_log: RawLogOut
    event: Optional[NormalizedEventOut] = None
    message: Optional[str] = None
    integrity: Optional[IntegrityResult] = None  # present for encrypted uploads


class ParserOut(BaseModel):
    id: str
    name: str
    vendor: Optional[str] = None
    format: Optional[str] = None
    version: str
    status: str
    source_type: str
    created_at: datetime
    events_processed: int

    model_config = {"from_attributes": True}


class TraceabilityOut(BaseModel):
    raw_log: RawLogOut
    event: NormalizedEventOut
    parser: Optional[ParserOut] = None


class EncryptedEnvelope(BaseModel):
    """AES-256-GCM encrypted envelope (no RSA key wrapping)."""
    version: int = 1
    algorithm: str  # A256GCM
    iv: str
    ciphertext: str
    integrity_hash: Optional[str] = None  # SHA-256 hex digest of plaintext


class OnboardingAnalyzeRequest(BaseModel):
    raw_log: str


class FieldSuggestionOut(BaseModel):
    field: str
    value: Optional[str] = None
    confidence: float
    source: str
    raw_token: Optional[str] = None


class OnboardingAnalyzeResponse(BaseModel):
    overall_confidence: float
    fields: list[FieldSuggestionOut]
    raw_log: str


class OnboardingCreateParserRequest(BaseModel):
    raw_log: str
    parser_name: str
    approved_fields: list[dict[str, Any]]


class OnboardingCreateParserResponse(BaseModel):
    parser: ParserOut
    config: dict[str, Any]


# ─── Log Analyzer schemas ───────────────────────────────────────────────

class FieldAnalysis(BaseModel):
    """One field from the analysis — whether matched by a known parser or
    discovered by heuristics/AI for an unknown log."""
    field: str
    value: Optional[str] = None
    mapped_to: Optional[str] = None  # Universal Schema target (e.g. "network.source_ip")
    confidence: float = 0.0
    source: str = "unknown"  # regex | key_value | positional | llm_assisted
    data_type: str = "string"
    status: str = "matched"  # matched | unmatched | new


class ParserCandidate(BaseModel):
    """An existing parser evaluated as a potential match for an unknown log."""
    parser_name: str
    parser_format: Optional[str] = None
    vendor: Optional[str] = None
    match_percentage: float = 0.0
    matched_fields: list[str] = []
    unmatched_fields: list[str] = []
    recommendation: str = ""  # e.g. "Best candidate — extend with 2 new fields"


class AnalyzerResult(BaseModel):
    """Full analysis result for a single log line."""
    format_status: str  # "KNOWN" | "UNKNOWN"
    raw_log: str

    # Known-format details
    parser_name: Optional[str] = None
    parser_version: Optional[str] = None
    parser_source_type: Optional[str] = None  # deterministic | ai_generated
    detected_format: Optional[str] = None
    detected_vendor: Optional[str] = None
    confidence: float = 0.0

    # Field analysis
    fields: list[FieldAnalysis] = []

    # Normalized event (for known formats that were processed)
    event: Optional[NormalizedEventOut] = None
    raw_log_record: Optional[RawLogOut] = None

    # Unknown-format: parser candidates
    parser_candidates: list[ParserCandidate] = []

    # Batch unknown: all raw log lines that were unrecognised (for unified display)
    unknown_raw_logs: list[str] = []

    # Integrity
    integrity: Optional[IntegrityResult] = None


class AnalyzerBatchResult(BaseModel):
    results: list[AnalyzerResult]
    summary: dict[str, int]
    integrity: Optional[IntegrityResult] = None


class ApproveActionRequest(BaseModel):
    """Human approval for unknown log handling."""
    action: str  # "extend_parser" | "create_parser"
    raw_log: str
    parser_name: str  # existing parser to extend, or new parser name
    approved_fields: list[dict[str, Any]]


# ─── Stats & Health ──────────────────────────────────────────────────────

class StatsResponse(BaseModel):
    total_logs: int
    processed_events: int
    supported_formats: int
    average_confidence: float
    unknown_sources_pending: int
    events_by_format: dict[str, int]
    events_by_vendor: dict[str, int]
    events_by_severity: dict[str, int]
    processing_status_breakdown: dict[str, int]
    integrity_verified: int = 0
    integrity_tampered: int = 0
    integrity_no_hash: int = 0


class HealthResponse(BaseModel):
    status: str
    app_name: str
    database: str
