"""Cisco ASA syslog parser — deterministic, regex-based.

Handles the two most common ASA message families used in the MVP demo:
  - %ASA-6-302013 (Built ... connection ... for <zone>:<ip>/<port> to <zone>:<ip>/<port>)
  - %ASA-6-106023 (Deny <proto> src <zone>:<ip>/<port> dst <zone>:<ip>/<port> by access-group "<acl>")
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from app.parsers.base import BaseLogParser

_HEADER_RE = re.compile(
    r"(?:<\d+>)?(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+%ASA-(?P<level>\d)-(?P<msgid>\d+):"
)
_BUILT_RE = re.compile(
    r"Built (?P<direction>\w+) (?P<proto>\w+) connection .* for (?:\S+:)?(?P<src_ip>[\d.]+)/(?P<src_port>\d+)"
    r"(?:\s*\(\S+\))?\s+to\s+(?:\S+:)?(?P<dst_ip>[\d.]+)/(?P<dst_port>\d+)"
)
_DENY_RE = re.compile(
    r"Deny (?P<proto>\w+) src (?:\S+:)?(?P<src_ip>[\d.]+)/(?P<src_port>\d+)\s+dst\s+(?:\S+:)?(?P<dst_ip>[\d.]+)/(?P<dst_port>\d+)"
    r"(?:.*by access-group \"(?P<acl>[^\"]+)\")?"
)


class CiscoSyslogParser(BaseLogParser):
    name = "cisco_syslog_v1"
    version = "1.0"
    vendor = "Cisco"
    product = "ASA"
    format = "syslog"
    expected_fields = [
        "timestamp", "hostname", "protocol", "source_ip", "source_port",
        "destination_ip", "destination_port", "event_action",
    ]

    def detect(self, raw_log: str) -> bool:
        return bool(_HEADER_RE.search(raw_log))

    def parse(self, raw_log: str) -> dict[str, Any]:
        header = _HEADER_RE.search(raw_log)
        if not header:
            raise ValueError("Cisco ASA syslog header not found")

        fields: dict[str, Any] = {
            "hostname": header.group("host"),
            "timestamp": self._parse_timestamp(header.group("ts")),
            "ext_msg_id": f"ASA-{header.group('level')}-{header.group('msgid')}",
        }

        built = _BUILT_RE.search(raw_log)
        deny = _DENY_RE.search(raw_log)

        if built:
            fields.update(
                protocol=built.group("proto").upper(),
                source_ip=built.group("src_ip"),
                source_port=int(built.group("src_port")),
                destination_ip=built.group("dst_ip"),
                destination_port=int(built.group("dst_port")),
                event_action="allowed",
                event_type="network_connection",
                severity="low",
            )
        elif deny:
            fields.update(
                protocol=deny.group("proto").upper(),
                source_ip=deny.group("src_ip"),
                source_port=int(deny.group("src_port")),
                destination_ip=deny.group("dst_ip"),
                destination_port=int(deny.group("dst_port")),
                event_action="denied",
                event_type="network_connection",
                severity="medium",
                ext_acl=deny.group("acl"),
            )

        return fields

    @staticmethod
    def _parse_timestamp(ts: str) -> datetime:
        year = datetime.now().year
        return datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S")
