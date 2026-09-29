from app.detection.format_detector import FormatDetector

detector = FormatDetector()


def test_detects_cisco_syslog():
    line = '<134>Sep 11 10:32:14 FW01 %ASA-6-302013: Built outbound TCP connection 12345 for outside:192.168.1.10/443 to 8.8.8.8/443'
    result = detector.detect(line)
    assert result.format == "syslog"
    assert result.vendor == "Cisco"
    assert result.confidence > 0.9


def test_detects_fortigate_kv():
    line = 'date=2026-09-11 time=10:35:22 devname="FG01" srcip=10.0.0.5 dstip=8.8.8.8 action="accept"'
    result = detector.detect(line)
    assert result.format == "kv_syslog"
    assert result.vendor == "Fortinet"


def test_detects_windows_json():
    line = '{"EventID": 4624, "Computer": "WIN-SERVER", "User": "Administrator", "IpAddress": "10.0.0.15"}'
    result = detector.detect(line)
    assert result.format == "windows_json"
    assert result.vendor == "Microsoft"


def test_detects_apache_access():
    line = '192.168.1.50 - - [11/Sep/2026:10:42:12 +0000] "GET /login HTTP/1.1" 200 1245 "-" "curl/8.0"'
    result = detector.detect(line)
    assert result.format == "apache_access"


def test_detects_linux_syslog():
    line = "Sep 11 10:40:12 server01 sshd[1234]: Accepted password for admin from 192.168.1.20 port 54321 ssh2"
    result = detector.detect(line)
    assert result.format == "linux_syslog"


def test_unknown_format_returns_zero_confidence():
    line = "2026/09/11 10:51:23 AUTH-SRV LOGIN_SUCCESS user=admin src=10.20.4.15"
    result = detector.detect(line)
    assert result.format == "unknown"
    assert result.confidence == 0.0
