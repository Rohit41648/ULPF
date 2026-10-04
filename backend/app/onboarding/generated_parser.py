"""
GeneratedParser
================
Wraps a human-approved field mapping (produced by
`ParserGenerationService.generate_parser`) as a real `BaseLogParser`, so
logs 2..N from a newly onboarded source are parsed deterministically —
only the *first* sample needed the heuristic/AI-assisted path.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from app.onboarding.heuristics import _ALLCAPS_ACTION_RE, _IP_RE, _TIMESTAMP_PATTERNS
from app.parsers.base import BaseLogParser


class GeneratedParser(BaseLogParser):
    format = "custom"

    def __init__(self, config: dict[str, Any]):
        self.name = config["parser_name"]
        self.version = "1.0"
        self.vendor = config.get("vendor") or "Unknown"
        self.product = "auto-generated"
        self._field_details = {f["field"]: f for f in config.get("field_details", [])}
        self.expected_fields = list(self._field_details.keys())

        self._kv_key_by_field: dict[str, str] = {}
        for f, detail in self._field_details.items():
            if detail.get("source") == "key_value":
                token = detail.get("raw_token", "")
                if "=" in token:
                    self._kv_key_by_field[f] = token.split("=", 1)[0]

    def detect(self, raw_log: str) -> bool:
        # A generated parser matches if the same key=value keys it was
        # trained on are present in the candidate line.
        if not self._kv_key_by_field:
            return False
        return all(f"{key}=" in raw_log for key in self._kv_key_by_field.values())

    def parse(self, raw_log: str) -> dict[str, Any]:
        fields: dict[str, Any] = {}

        for field, key in self._kv_key_by_field.items():
            m = re.search(rf"\b{re.escape(key)}=([^\s]+)", raw_log)
            if m:
                fields[field] = m.group(1)

        if "timestamp" in self._field_details and "timestamp" not in self._kv_key_by_field:
            fields["timestamp"] = self._extract_timestamp(raw_log)

        if "source_ip" in self._field_details and "source_ip" not in self._kv_key_by_field:
            m = _IP_RE.search(raw_log)
            if m:
                fields["source_ip"] = m.group(0)

        if "event_action" in self._field_details and "event_action" not in self._kv_key_by_field:
            m = _ALLCAPS_ACTION_RE.search(raw_log)
            if m:
                fields["event_action"] = m.group(0)

        fields.setdefault("event_type", "custom_source_event")
        return fields

    @staticmethod
    def _extract_timestamp(raw_log: str) -> datetime | None:
        for pattern, fmt in _TIMESTAMP_PATTERNS:
            m = pattern.search(raw_log)
            if not m:
                continue
            text = m.group(0)
            try:
                if fmt == "%b %d %H:%M:%S":
                    return datetime.strptime(f"{datetime.now().year} {text}", f"%Y {fmt}")
                return datetime.strptime(text, fmt)
            except ValueError:
                continue
        return None
