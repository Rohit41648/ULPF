import sqlite3
import json

DEFAULT_CONFIGS = {
    "apache_access_v1": {
        "parser_name": "apache_access_v1",
        "format": "apache_access",
        "fields": {
            "timestamp": "%d/%b/%Y:%H:%M:%S",
            "source_ip": "client_ip",
            "http_method": "method",
            "http_path": "path",
            "http_status_code": "status",
            "http_user_agent": "agent",
            "ext_response_size": "size",
        },
    },
    "cisco_syslog_v1": {
        "parser_name": "cisco_syslog_v1",
        "format": "syslog",
        "fields": {
            "timestamp": "%b %d %H:%M:%S",
            "hostname": "host",
            "protocol": "proto",
            "source_ip": "src_ip",
            "source_port": "src_port",
            "destination_ip": "dst_ip",
            "destination_port": "dst_port",
            "event_action": "Built|Deny",
        },
    },
    "fortigate_kv_v1": {
        "parser_name": "fortigate_kv_v1",
        "format": "kv_syslog",
        "fields": {
            "timestamp": "date=... time=...",
            "hostname": "devname",
            "source_ip": "srcip",
            "destination_ip": "dstip",
            "destination_port": "dstport",
            "protocol": "proto",
            "event_action": "action",
        },
    },
    "linux_syslog_v1": {
        "parser_name": "linux_syslog_v1",
        "format": "linux_syslog",
        "fields": {
            "timestamp": "%b %d %H:%M:%S",
            "hostname": "host",
            "username": "user",
            "source_ip": "from <ip>",
            "event_action": "Accepted|Failed",
        },
    },
    "windows_json_v1": {
        "parser_name": "windows_json_v1",
        "format": "windows_json",
        "fields": {
            "timestamp": "TimeCreated",
            "hostname": "Computer",
            "username": "User",
            "source_ip": "IpAddress",
            "event_action": "EventID",
        },
    },
}

def seed_configs():
    conn = sqlite3.connect("ulpf.db")
    c = conn.cursor()
    rows = c.execute("SELECT id, name, source_type, config FROM parsers").fetchall()
    updated = 0
    for pid, name, stype, cfg in rows:
        if cfg is None or cfg == "":
            default_cfg = DEFAULT_CONFIGS.get(name, {
                "parser_name": name,
                "fields": {
                    "timestamp": "timestamp",
                    "event_type": "event_type",
                    "source_ip": "source_ip",
                }
            })
            c.execute("UPDATE parsers SET config = ? WHERE id = ?", (json.dumps(default_cfg), pid))
            updated += 1
            print(f"Updated config for parser: {name} (ID: {pid})")

    conn.commit()
    conn.close()
    print(f"Total parsers updated: {updated}")

if __name__ == "__main__":
    seed_configs()
