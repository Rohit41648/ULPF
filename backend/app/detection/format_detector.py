"""
Deterministic format detection engine.

Uses syntax patterns / regex / known prefixes / field signatures — no ML —
to keep detection of KNOWN formats fast and explainable. This module is
intentionally modular (one `_detect_*` method per format) so an ML-based
classifier can be slotted in later for the unknown-source path without
touching this deterministic core.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass


@dataclass
class DetectionResult:
    format: str            # syslog | cef | json | apache_access | linux_syslog | unknown
    vendor: str | None
    confidence: float
    reason: str


_CEF_RE = re.compile(r"CEF:\d+\|")
_SYSLOG_HEADER_RE = re.compile(r"^<\d+>")
_CISCO_ASA_RE = re.compile(r"%ASA-\d-\d+")
_FORTIGATE_KV_RE = re.compile(r"\bdevname=|\bsrcip=|\bdstip=")
_APACHE_RE = re.compile(
    r'^(\S+) \S+ \S+ \[[^\]]+\] "(\S+) (\S+) [^"]+" (\d{3}) (\d+|-)'
)
_LINUX_SYSLOG_RE = re.compile(
    r"^\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+\[?\d*\]?:"
)


class FormatDetector:
    """Runs a small ordered battery of deterministic checks."""

    def detect(self, raw_log: str) -> DetectionResult:
        raw_log = raw_log.strip()

        result = self._detect_json(raw_log)
        if result:
            return result

        result = self._detect_cisco_syslog(raw_log)
        if result:
            return result

        result = self._detect_fortigate(raw_log)
        if result:
            return result

        result = self._detect_cef(raw_log)
        if result:
            return result

        result = self._detect_apache(raw_log)
        if result:
            return result

        result = self._detect_linux_syslog(raw_log)
        if result:
            return result

        return DetectionResult(
            format="unknown",
            vendor=None,
            confidence=0.0,
            reason="No deterministic signature matched any known format.",
        )

    # -- individual detectors -------------------------------------------------

    def _detect_json(self, raw_log: str) -> DetectionResult | None:
        if not (raw_log.startswith("{") and raw_log.endswith("}")):
            return None
        try:
            payload = json.loads(raw_log)
        except (json.JSONDecodeError, ValueError):
            return None
        vendor = None
        confidence = 0.75
        reason = "Valid JSON payload detected."
        if "EventID" in payload and "Computer" in payload:
            vendor = "Microsoft"
            confidence = 0.97
            reason = "JSON with EventID + Computer matches Windows Event Log signature."
        return DetectionResult(format="windows_json", vendor=vendor, confidence=confidence, reason=reason)

    def _detect_cisco_syslog(self, raw_log: str) -> DetectionResult | None:
        if _CISCO_ASA_RE.search(raw_log):
            return DetectionResult(
                format="syslog",
                vendor="Cisco",
                confidence=0.97,
                reason="Detected RFC-style syslog header and Cisco ASA (%ASA-n-nnnnnn) signature.",
            )
        return None

    def _detect_fortigate(self, raw_log: str) -> DetectionResult | None:
        hits = len(_FORTIGATE_KV_RE.findall(raw_log))
        if hits >= 2:
            return DetectionResult(
                format="kv_syslog",
                vendor="Fortinet",
                confidence=0.93,
                reason="Detected Fortigate key=value syslog fields (devname/srcip/dstip).",
            )
        return None

    def _detect_cef(self, raw_log: str) -> DetectionResult | None:
        if _CEF_RE.search(raw_log):
            vendor = None
            parts = raw_log.split("|")
            if len(parts) > 1:
                vendor = parts[1] or None
            return DetectionResult(
                format="cef",
                vendor=vendor,
                confidence=0.95,
                reason="Detected CEF:<version>| header.",
            )
        return None

    def _detect_apache(self, raw_log: str) -> DetectionResult | None:
        if _APACHE_RE.match(raw_log):
            return DetectionResult(
                format="apache_access",
                vendor="Apache",
                confidence=0.96,
                reason="Matched Common/Combined Log Format pattern (ip - - [ts] \"METHOD path\" status size).",
            )
        return None

    def _detect_linux_syslog(self, raw_log: str) -> DetectionResult | None:
        if _LINUX_SYSLOG_RE.match(raw_log):
            return DetectionResult(
                format="linux_syslog",
                vendor="Linux",
                confidence=0.9,
                reason="Matched 'Mon DD HH:MM:SS host process[pid]:' syslog pattern.",
            )
        return None
