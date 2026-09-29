"""
BaseLogParser — the interface every deterministic parser implements, plus
the ParserRegistry used to plug new parsers in without touching core code.
"""
from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from app.schemas.universal_event import (
    EventInfo,
    HostInfo,
    HttpInfo,
    NetworkInfo,
    ParserInfo,
    SourceInfo,
    TraceabilityInfo,
    UniversalEvent,
    UserInfo,
)


class BaseLogParser(ABC):
    """Contract: detect() -> can this parser handle the line; parse() ->
    intermediate field dict; normalize() -> UniversalEvent."""

    name: str = "base_parser"
    version: str = "1.0"
    vendor: str | None = None
    product: str | None = None
    format: str = "unknown"

    @abstractmethod
    def detect(self, raw_log: str) -> bool:
        """Return True if this parser can handle the given raw log line."""

    @abstractmethod
    def parse(self, raw_log: str) -> dict[str, Any]:
        """Extract raw fields into an intermediate dict. May raise ValueError."""

    def confidence(self, fields: dict[str, Any]) -> float:
        """Deterministic confidence heuristic: fraction of the parser's
        expected fields that were successfully extracted, scaled into a
        0.85-0.99 band so known/deterministic parsers always score above
        the unknown-source heuristic engine."""
        expected = getattr(self, "expected_fields", None) or list(fields.keys())
        if not expected:
            return 0.9
        found = sum(1 for f in expected if fields.get(f) not in (None, ""))
        ratio = found / len(expected)
        return round(0.85 + ratio * 0.14, 2)

    def normalize(self, raw_log: str, raw_log_id: str) -> UniversalEvent:
        fields = self.parse(raw_log)
        conf = self.confidence(fields)

        return UniversalEvent(
            event_id=f"ULPF-{uuid.uuid4().hex[:12]}",
            timestamp=fields.get("timestamp"),
            source=SourceInfo(vendor=self.vendor, product=self.product, format=self.format),
            event=EventInfo(
                type=fields.get("event_type"),
                action=fields.get("event_action"),
                severity=fields.get("severity"),
            ),
            network=NetworkInfo(
                source_ip=fields.get("source_ip"),
                source_port=fields.get("source_port"),
                destination_ip=fields.get("destination_ip"),
                destination_port=fields.get("destination_port"),
                protocol=fields.get("protocol"),
            ),
            user=UserInfo(username=fields.get("username")),
            http=HttpInfo(
                method=fields.get("http_method"),
                path=fields.get("http_path"),
                status_code=fields.get("http_status_code"),
                user_agent=fields.get("http_user_agent"),
            ),
            host=HostInfo(hostname=fields.get("hostname")),
            parser=ParserInfo(name=self.name, version=self.version, confidence=conf),
            traceability=TraceabilityInfo(
                raw_log_id=raw_log_id,
                parser_id=f"{self.name}-v{self.version}",
                ingested_at=datetime.now(timezone.utc),
            ),
            extensions={k: v for k, v in fields.items() if k.startswith("ext_")},
        )


class ParserRegistry:
    """Simple in-memory plugin registry. Swap for a DB-backed registry
    later without changing calling code."""

    def __init__(self) -> None:
        self._parsers: dict[str, BaseLogParser] = {}

    def register_parser(self, parser: BaseLogParser) -> None:
        self._parsers[parser.name] = parser

    def get_parser(self, name: str) -> BaseLogParser | None:
        return self._parsers.get(name)

    def list_parsers(self) -> list[BaseLogParser]:
        return list(self._parsers.values())

    def find_matching_parser(self, raw_log: str) -> BaseLogParser | None:
        for parser in self._parsers.values():
            try:
                if parser.detect(raw_log):
                    return parser
            except Exception:
                continue
        return None
