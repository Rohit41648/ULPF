"""Fortigate parser — key=value style syslog (also common as a CEF payload).

Example:
date=2026-09-11 time=10:35:22 devname="FG01" srcip=10.0.0.5 dstip=8.8.8.8
srcport=51322 dstport=443 proto=6 action="accept" user="jdoe"
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from app.parsers.base import BaseLogParser

_KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')
_PROTO_MAP = {"6": "TCP", "17": "UDP", "1": "ICMP"}


class FortigateParser(BaseLogParser):
    name = "fortigate_kv_v1"
    version = "1.0"
    vendor = "Fortinet"
    product = "FortiGate"
    format = "kv_syslog"
    expected_fields = [
        "timestamp", "hostname", "source_ip", "destination_ip",
        "destination_port", "protocol", "event_action",
    ]

    def detect(self, raw_log: str) -> bool:
        hits = len(re.findall(r"\bdevname=|\bsrcip=|\bdstip=", raw_log))
        return hits >= 2

    def parse(self, raw_log: str) -> dict[str, Any]:
        kv: dict[str, str] = {}
        for match in _KV_RE.finditer(raw_log):
            key = match.group(1)
            value = match.group(2) if match.group(2) is not None else match.group(3)
            kv[key] = value

        timestamp = None
        if "date" in kv and "time" in kv:
            try:
                timestamp = datetime.strptime(f"{kv['date']} {kv['time']}", "%Y-%m-%d %H:%M:%S")
            except ValueError:
                timestamp = None

        action = kv.get("action")
        severity = "medium" if action in ("deny", "block") else "low"

        return {
            "timestamp": timestamp,
            "hostname": kv.get("devname"),
            "source_ip": kv.get("srcip"),
            "source_port": int(kv["srcport"]) if kv.get("srcport", "").isdigit() else None,
            "destination_ip": kv.get("dstip"),
            "destination_port": int(kv["dstport"]) if kv.get("dstport", "").isdigit() else None,
            "protocol": _PROTO_MAP.get(kv.get("proto", ""), kv.get("proto")),
            "event_action": action,
            "event_type": "network_connection",
            "severity": severity,
            "username": kv.get("user"),
            "ext_policy_id": kv.get("policyid"),
        }
