"""
Deterministic heuristic field-discovery engine for unknown log sources.

Supports:
- timestamps
- IP addresses
- key=value fields
- ALL_CAPS actions
- pipe-delimited unknown log formats
- positional hostname detection
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


_TIMESTAMP_PATTERNS = [
    (
        re.compile(r"\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}"),
        "%Y/%m/%d %H:%M:%S",
    ),
    (
        re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"),
        "%Y-%m-%dT%H:%M:%S",
    ),
    (
        re.compile(r"\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"),
        "%b %d %H:%M:%S",
    ),
]

_IP_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

_KV_RE = re.compile(
    r"(\w[\w.-]*)=([^\s|]+)"
)

_ALLCAPS_ACTION_RE = re.compile(
    r"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b"
)

_KV_KEY_HINTS = {
    "username": {"user", "username", "usr", "account", "principal"},
    "source_ip": {
        "src",
        "srcip",
        "source_ip",
        "ip",
        "client_ip",
        "remote",
        "origin_addr",
    },
    "destination_ip": {
        "dst",
        "dstip",
        "destination_ip",
        "server_ip",
        "destination_addr",
    },
    "event_action": {
        "action",
        "act",
        "event",
        "verb",
        "operation",
        "command",
        "method",
    },
    "hostname": {
        "host",
        "hostname",
        "device",
        "devname",
    },
    "http_path": {
        "uri",
        "path",
        "resource",
        "resource_uri",
        "object",
        "destination",
    },
    "http_status_code": {
        "code",
        "status_code",
        "http_code",
        "response",
    },
}


@dataclass
class FieldSuggestion:
    field: str
    value: str | None
    confidence: float
    source: str
    raw_token: str = ""


@dataclass
class AnalysisResult:
    raw_log: str
    suggestions: list[FieldSuggestion] = field(default_factory=list)
    overall_confidence: float = 0.0


class HeuristicFieldDiscovery:
    """
    Analyzes an unknown log line and proposes a field mapping
    that a human can review and approve.
    """

    def analyze(self, raw_log: str) -> AnalysisResult:

        # ---------------------------------------------------------
        # NEW: Detect pipe-delimited unknown log format
        # ---------------------------------------------------------
        pipe_suggestions = self._parse_pipe_log(raw_log)

        if pipe_suggestions:
            overall = round(
                sum(s.confidence for s in pipe_suggestions)
                / len(pipe_suggestions),
                2,
            )

            return AnalysisResult(
                raw_log=raw_log,
                suggestions=pipe_suggestions,
                overall_confidence=overall,
            )

        # ---------------------------------------------------------
        # Existing generic heuristic processing
        # ---------------------------------------------------------

        suggestions: list[FieldSuggestion] = []
        claimed_spans: list[tuple[int, int]] = []

        # 1. Timestamp
        ts_suggestion = self._find_timestamp(raw_log)

        if ts_suggestion:
            suggestions.append(ts_suggestion)

        # 2. key=value pairs
        kv_suggestions, kv_spans = self._find_kv_pairs(raw_log)

        suggestions.extend(kv_suggestions)
        claimed_spans.extend(kv_spans)

        mapped_fields = {s.field for s in suggestions}

        # 3. Bare IP address
        if "source_ip" not in mapped_fields:

            ip_suggestion = self._find_bare_ip(
                raw_log,
                claimed_spans,
            )

            if ip_suggestion:
                suggestions.append(ip_suggestion)

        # 4. ALL_CAPS action
        if "event_action" not in mapped_fields:

            action_suggestion = self._find_allcaps_action(
                raw_log
            )

            if action_suggestion:
                suggestions.append(action_suggestion)

        # 5. Hostname
        if "hostname" not in {s.field for s in suggestions}:

            host_suggestion = self._find_hostname(
                raw_log,
                ts_suggestion,
            )

            if host_suggestion:
                suggestions.append(host_suggestion)

        overall = (
            round(
                sum(s.confidence for s in suggestions)
                / len(suggestions),
                2,
            )
            if suggestions
            else 0.0
        )

        return AnalysisResult(
            raw_log=raw_log,
            suggestions=suggestions,
            overall_confidence=overall,
        )

    # =============================================================
    # PIPE-DELIMITED UNKNOWN LOG PARSER
    # =============================================================

    def _parse_pipe_log(
        self,
        raw_log: str,
    ) -> list[FieldSuggestion]:

        suggestions: list[FieldSuggestion] = []

        if not raw_log or "|" not in raw_log:
            return suggestions

        parts = [
            part.strip()
            for part in raw_log.split("|")
            if part.strip()
        ]

        if not parts:
            return suggestions

        # ---------------------------------------------------------
        # First field = timestamp
        # ---------------------------------------------------------

        timestamp_match = re.search(
            r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\b",
            parts[0],
        )

        if timestamp_match:

            suggestions.append(
                FieldSuggestion(
                    field="timestamp",
                    value=timestamp_match.group(0),
                    confidence=0.95,
                    source="regex",
                    raw_token=timestamp_match.group(0),
                )
            )

        # ---------------------------------------------------------
        # Second field = hostname
        # ---------------------------------------------------------

        if len(parts) >= 2:

            hostname = parts[1]

            if re.match(
                r"^[A-Za-z0-9._-]+$",
                hostname,
            ):

                suggestions.append(
                    FieldSuggestion(
                        field="hostname",
                        value=hostname,
                        confidence=0.90,
                        source="positional",
                        raw_token=hostname,
                    )
                )

        # ---------------------------------------------------------
        # key=value fields
        # ---------------------------------------------------------

        key_map = {

            # User
            "principal": "username",
            "user": "username",
            "username": "username",

            # Source IP
            "src": "source_ip",
            "source": "source_ip",
            "source_ip": "source_ip",
            "remote": "source_ip",
            "origin_addr": "source_ip",

            # Destination IP
            "dst": "destination_ip",
            "destination_ip": "destination_ip",
            "destination_addr": "destination_ip",

            # Action
            "verb": "event_action",
            "action": "event_action",
            "operation": "event_action",
            "command": "event_action",

            # Path
            "uri": "http_path",
            "path": "http_path",
            "resource": "http_path",
            "resource_uri": "http_path",
            "object": "http_path",

            # HTTP status
            "code": "http_status_code",
            "status_code": "http_status_code",
            "http_code": "http_status_code",
            "response": "http_status_code",
        }

        seen_fields: set[str] = {
            suggestion.field
            for suggestion in suggestions
        }

        for part in parts:

            match = re.match(
                r"^([A-Za-z_][A-Za-z0-9_]*)=(.+)$",
                part,
            )

            if not match:
                continue

            key = match.group(1).lower()
            value = match.group(2).strip()

            field_name = key_map.get(key)

            if not field_name:
                continue

            # Avoid duplicate fields
            if field_name in seen_fields:
                continue

            suggestions.append(
                FieldSuggestion(
                    field=field_name,
                    value=value,
                    confidence=0.93,
                    source="key_value",
                    raw_token=part,
                )
            )

            seen_fields.add(field_name)

        return suggestions

    # =============================================================
    # GENERIC HEURISTICS
    # =============================================================

    def _find_timestamp(
        self,
        raw_log: str,
    ) -> FieldSuggestion | None:

        for pattern, _fmt in _TIMESTAMP_PATTERNS:

            match = pattern.search(raw_log)

            if match:

                return FieldSuggestion(
                    field="timestamp",
                    value=match.group(0),
                    confidence=0.90,
                    source="regex",
                    raw_token=match.group(0),
                )

        return None

    def _find_kv_pairs(
        self,
        raw_log: str,
    ) -> tuple[
        list[FieldSuggestion],
        list[tuple[int, int]],
    ]:

        suggestions: list[FieldSuggestion] = []
        spans: list[tuple[int, int]] = []

        seen_fields: set[str] = set()

        for match in _KV_RE.finditer(raw_log):

            key = match.group(1).lower()
            value = match.group(2)

            for target_field, hints in _KV_KEY_HINTS.items():

                if (
                    key in hints
                    and target_field not in seen_fields
                ):

                    suggestions.append(
                        FieldSuggestion(
                            field=target_field,
                            value=value,
                            confidence=0.93,
                            source="key_value",
                            raw_token=match.group(0),
                        )
                    )

                    seen_fields.add(target_field)
                    spans.append(match.span())

        return suggestions, spans

    def _find_bare_ip(
        self,
        raw_log: str,
        claimed_spans: list[tuple[int, int]],
    ) -> FieldSuggestion | None:

        for match in _IP_RE.finditer(raw_log):

            if any(
                start <= match.start() < end
                for start, end in claimed_spans
            ):
                continue

            return FieldSuggestion(
                field="source_ip",
                value=match.group(0),
                confidence=0.75,
                source="regex",
                raw_token=match.group(0),
            )

        return None

    def _find_allcaps_action(
        self,
        raw_log: str,
    ) -> FieldSuggestion | None:

        match = _ALLCAPS_ACTION_RE.search(raw_log)

        if match:

            return FieldSuggestion(
                field="event_action",
                value=match.group(0),
                confidence=0.70,
                source="regex",
                raw_token=match.group(0),
            )

        return None

    def _find_hostname(
        self,
        raw_log: str,
        ts_suggestion: FieldSuggestion | None,
    ) -> FieldSuggestion | None:

        remainder = raw_log

        if ts_suggestion:

            index = raw_log.find(
                ts_suggestion.raw_token
            )

            if index != -1:

                remainder = raw_log[
                    index
                    + len(ts_suggestion.raw_token):
                ]

        for token in remainder.split():

            if _IP_RE.match(token):
                continue

            if "=" in token:
                continue

            if re.match(
                r"^[A-Za-z][\w-]{2,}$",
                token,
            ):

                return FieldSuggestion(
                    field="hostname",
                    value=token,
                    confidence=0.65,
                    source="positional",
                    raw_token=token,
                )

        return None