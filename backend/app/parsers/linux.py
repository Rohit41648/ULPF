"""Linux syslog/auth log parser (sshd-focused for the MVP demo set).

Example:
Sep 11 10:40:12 server01 sshd[1234]: Accepted password for admin
from 192.168.1.20 port 54321 ssh2
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from app.parsers.base import BaseLogParser

_HEADER_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<process>\w+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
_SSH_AUTH_RE = re.compile(
    r"(?P<result>Accepted|Failed) (?P<method>\w+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)(?:\s+(?P<proto>\w+))?"
)


class LinuxSyslogParser(BaseLogParser):
    name = "linux_syslog_v1"
    version = "1.0"
    vendor = "Linux"
    product = "syslog"
    format = "linux_syslog"
    expected_fields = ["timestamp", "hostname", "username", "source_ip", "event_action"]

    def detect(self, raw_log: str) -> bool:
        return bool(_HEADER_RE.match(raw_log))

    def parse(self, raw_log: str) -> dict[str, Any]:
        header = _HEADER_RE.match(raw_log)
        if not header:
            raise ValueError("Linux syslog header not found")

        fields: dict[str, Any] = {
            "hostname": header.group("host"),
            "timestamp": self._parse_timestamp(header.group("ts")),
            "ext_process": header.group("process"),
            "ext_pid": header.group("pid"),
            "event_type": "authentication",
        }

        auth = _SSH_AUTH_RE.search(header.group("msg"))
        if auth:
            fields.update(
                username=auth.group("user"),
                source_ip=auth.group("ip"),
                source_port=int(auth.group("port")),
                protocol=(auth.group("proto") or "ssh").upper(),
                event_action="login_success" if auth.group("result") == "Accepted" else "login_failed",
                severity="low" if auth.group("result") == "Accepted" else "high",
            )
        return fields

    @staticmethod
    def _parse_timestamp(ts: str) -> datetime:
        year = datetime.now().year
        return datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S")
