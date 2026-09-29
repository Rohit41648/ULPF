"""
Universal Security Event Schema (ULPF)
========================================
Vendor-neutral schema that every parser normalizes into. Extra/unknown
fields are preserved under `extensions` rather than dropped, so no
source-specific information is ever lost in normalization.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, ConfigDict


class SourceInfo(BaseModel):
    vendor: Optional[str] = None
    product: Optional[str] = None
    format: Optional[str] = None  # syslog | cef | json | csv | apache_access | custom


class EventInfo(BaseModel):
    type: Optional[str] = None       # e.g. network_connection, authentication, http_request
    action: Optional[str] = None     # e.g. allowed, denied, login_success
    severity: Optional[str] = None   # low | medium | high | critical


class NetworkInfo(BaseModel):
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None


class UserInfo(BaseModel):
    username: Optional[str] = None


class HttpInfo(BaseModel):
    method: Optional[str] = None
    path: Optional[str] = None
    status_code: Optional[int] = None
    user_agent: Optional[str] = None


class HostInfo(BaseModel):
    hostname: Optional[str] = None


class ParserInfo(BaseModel):
    name: Optional[str] = None
    version: Optional[str] = None
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)


class TraceabilityInfo(BaseModel):
    raw_log_id: str
    parser_id: Optional[str] = None
    ingested_at: datetime


class UniversalEvent(BaseModel):
    """The common schema every log source, known or unknown, is mapped into."""

    model_config = ConfigDict(extra="forbid")

    event_id: str
    timestamp: Optional[datetime] = None

    source: SourceInfo = Field(default_factory=SourceInfo)
    event: EventInfo = Field(default_factory=EventInfo)
    network: NetworkInfo = Field(default_factory=NetworkInfo)
    user: UserInfo = Field(default_factory=UserInfo)
    http: HttpInfo = Field(default_factory=HttpInfo)
    host: HostInfo = Field(default_factory=HostInfo)
    parser: ParserInfo = Field(default_factory=ParserInfo)
    traceability: TraceabilityInfo

    # Fields that don't map cleanly into the fixed taxonomy above are kept
    # here, so normalization is additive/lossless rather than lossy.
    extensions: dict[str, Any] = Field(default_factory=dict)


class ProcessingStatus:
    SUCCESS = "SUCCESS"
    WARNING = "WARNING"
    FAILED = "FAILED"


class ValidationResult(BaseModel):
    status: str  # SUCCESS | WARNING | FAILED
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
