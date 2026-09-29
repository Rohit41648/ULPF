"""Apache Common/Combined Log Format parser.

Example:
192.168.1.50 - - [11/Sep/2026:10:42:12 +0000] "GET /login HTTP/1.1" 200 1245 "-" "curl/8.0"
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from app.parsers.base import BaseLogParser

_APACHE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<httpver>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?:\s+"[^"]*"\s+"(?P<agent>[^"]*)")?'
)


class ApacheAccessParser(BaseLogParser):
    name = "apache_access_v1"
    version = "1.0"
    vendor = "Apache"
    product = "HTTP Server"
    format = "apache_access"
    expected_fields = ["timestamp", "source_ip", "http_method", "http_path", "http_status_code"]

    def detect(self, raw_log: str) -> bool:
        return bool(_APACHE_RE.match(raw_log))

    def parse(self, raw_log: str) -> dict[str, Any]:
        m = _APACHE_RE.match(raw_log)
        if not m:
            raise ValueError("Apache access log pattern not matched")

        status = int(m.group("status"))
        severity = "high" if status >= 500 else "medium" if status >= 400 else "low"

        return {
            "timestamp": self._parse_timestamp(m.group("ts")),
            "source_ip": m.group("ip"),
            "http_method": m.group("method"),
            "http_path": m.group("path"),
            "http_status_code": status,
            "http_user_agent": m.group("agent"),
            "event_type": "http_request",
            "event_action": "request",
            "severity": severity,
            "ext_response_size": None if m.group("size") == "-" else int(m.group("size")),
        }

    @staticmethod
    def _parse_timestamp(ts: str) -> datetime | None:
        try:
            return datetime.strptime(ts.split(" ")[0], "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            return None
