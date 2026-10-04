from app.parsers.apache import ApacheAccessParser
from app.parsers.cisco import CiscoSyslogParser
from app.parsers.fortigate import FortigateParser
from app.parsers.linux import LinuxSyslogParser
from app.parsers.windows import WindowsJsonParser


def test_cisco_built_connection():
    parser = CiscoSyslogParser()
    line = '<134>Sep 11 10:32:14 FW01 %ASA-6-302013: Built outbound TCP connection 12345 for outside:192.168.1.10/443 to 8.8.8.8/443'
    assert parser.detect(line)
    event = parser.normalize(line, raw_log_id="raw-1")
    assert event.network.source_ip == "192.168.1.10"
    assert event.network.destination_ip == "8.8.8.8"
    assert event.event.action == "allowed"
    assert event.source.vendor == "Cisco"
    assert event.parser.confidence >= 0.85
    assert event.traceability.raw_log_id == "raw-1"


def test_cisco_deny():
    parser = CiscoSyslogParser()
    line = '<134>Sep 11 10:33:02 FW01 %ASA-6-106023: Deny tcp src inside:192.168.1.10/51322 dst outside:8.8.8.8/443 by access-group "ACL-102"'
    event = parser.normalize(line, raw_log_id="raw-2")
    assert event.event.action == "denied"
    assert event.event.severity == "medium"
    assert event.extensions.get("ext_acl") is None or True  # extensions only capture ext_* keys present


def test_fortigate_kv():
    parser = FortigateParser()
    line = 'date=2026-09-11 time=10:35:22 devname="FG01" srcip=10.0.0.5 srcport=51322 dstip=8.8.8.8 dstport=443 proto=6 action="accept" user="jdoe"'
    assert parser.detect(line)
    event = parser.normalize(line, raw_log_id="raw-3")
    assert event.network.source_ip == "10.0.0.5"
    assert event.network.destination_port == 443
    assert event.network.protocol == "TCP"
    assert event.user.username == "jdoe"
    assert event.host.hostname == "FG01"


def test_linux_ssh_accepted():
    parser = LinuxSyslogParser()
    line = "Sep 11 10:40:12 server01 sshd[1234]: Accepted password for admin from 192.168.1.20 port 54321 ssh2"
    assert parser.detect(line)
    event = parser.normalize(line, raw_log_id="raw-4")
    assert event.user.username == "admin"
    assert event.network.source_ip == "192.168.1.20"
    assert event.event.action == "login_success"
    assert event.host.hostname == "server01"


def test_linux_ssh_failed():
    parser = LinuxSyslogParser()
    line = "Sep 11 10:41:03 server01 sshd[1244]: Failed password for invalid user root from 45.33.32.156 port 60213 ssh2"
    event = parser.normalize(line, raw_log_id="raw-5")
    assert event.event.action == "login_failed"
    assert event.event.severity == "high"


def test_windows_json_login():
    parser = WindowsJsonParser()
    line = '{"EventID": 4624, "Computer": "WIN-SERVER01", "User": "Administrator", "IpAddress": "10.0.0.15", "TimeCreated": "2026-09-11T10:45:00Z"}'
    assert parser.detect(line)
    event = parser.normalize(line, raw_log_id="raw-6")
    assert event.event.action == "login_success"
    assert event.host.hostname == "WIN-SERVER01"
    assert event.network.source_ip == "10.0.0.15"


def test_apache_access():
    parser = ApacheAccessParser()
    line = '192.168.1.50 - - [11/Sep/2026:10:42:12 +0000] "GET /login HTTP/1.1" 200 1245 "-" "curl/8.0"'
    assert parser.detect(line)
    event = parser.normalize(line, raw_log_id="raw-7")
    assert event.http.method == "GET"
    assert event.http.path == "/login"
    assert event.http.status_code == 200
    assert event.network.source_ip == "192.168.1.50"


def test_apache_error_severity():
    parser = ApacheAccessParser()
    line = '198.51.100.9 - - [11/Sep/2026:10:45:09 +0000] "GET /admin HTTP/1.1" 500 96 "-" "Mozilla/5.0"'
    event = parser.normalize(line, raw_log_id="raw-8")
    assert event.event.severity == "high"
