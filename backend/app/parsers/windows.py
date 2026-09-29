"""Windows Event Log (JSON-exported) parser.

Example:
{"EventID": 4624, "Computer": "WIN-SERVER", "User": "Administrator",
 "IpAddress": "10.0.0.15", "TimeCreated": "2026-09-11T10:45:00Z"}
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from app.parsers.base import BaseLogParser

# Common security-relevant Windows Event IDs
_EVENT_ACTIONS = {
    4624: ("login_success", "authentication", "low"),
    4625: ("login_failed", "authentication", "high"),
    4634: ("logoff", "authentication", "low"),
    4720: ("account_created", "account_management", "medium"),
    4688: ("process_created", "process", "low"),
}


class WindowsJsonParser(BaseLogParser):
    name = "windows_json_v1"
    version = "1.0"
    vendor = "Microsoft"
    product = "Windows Event Log"
    format = "windows_json"
    expected_fields = ["timestamp", "hostname", "username", "source_ip", "event_action"]

    def detect(self, raw_log: str) -> bool:
        try:
            payload = json.loads(raw_log)
        except (json.JSONDecodeError, ValueError):
            return False
        return isinstance(payload, dict) and "EventID" in payload and "Computer" in payload

    def parse(self, raw_log: str) -> dict[str, Any]:
        payload = json.loads(raw_log)
        event_id = int(payload.get("EventID"))
        action, event_type, severity = _EVENT_ACTIONS.get(event_id, (f"event_{event_id}", "windows_event", "low"))

        timestamp = None
        if payload.get("TimeCreated"):
            try:
                timestamp = datetime.fromisoformat(payload["TimeCreated"].replace("Z", "+00:00"))
            except ValueError:
                timestamp = None

        return {
            "timestamp": timestamp,
            "hostname": payload.get("Computer"),
            "username": payload.get("User"),
            "source_ip": payload.get("IpAddress"),
            "event_action": action,
            "event_type": event_type,
            "severity": severity,
            "ext_event_id": event_id,
            "ext_logon_type": payload.get("LogonType"),
        }
