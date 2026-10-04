from app.parsers.cisco import CiscoSyslogParser
from app.validation.validator import validate_event


def test_valid_event_passes_validation():
    parser = CiscoSyslogParser()
    line = '<134>Sep 11 10:32:14 FW01 %ASA-6-302013: Built outbound TCP connection 12345 for outside:192.168.1.10/443 to 8.8.8.8/443'
    event = parser.normalize(line, raw_log_id="raw-1")
    result = validate_event(event)
    assert result.status in ("SUCCESS", "WARNING")
    assert result.errors == []


def test_invalid_ip_is_caught():
    parser = CiscoSyslogParser()
    line = '<134>Sep 11 10:32:14 FW01 %ASA-6-302013: Built outbound TCP connection 12345 for outside:192.168.1.10/443 to 8.8.8.8/443'
    event = parser.normalize(line, raw_log_id="raw-1")
    event.network.destination_ip = "999.999.999.999"
    result = validate_event(event)
    assert result.status == "FAILED"
    assert any("destination_ip" in e for e in result.errors)


def test_missing_timestamp_produces_warning():
    parser = CiscoSyslogParser()
    line = '<134>Sep 11 10:32:14 FW01 %ASA-6-302013: Built outbound TCP connection 12345 for outside:192.168.1.10/443 to 8.8.8.8/443'
    event = parser.normalize(line, raw_log_id="raw-1")
    event.timestamp = None
    result = validate_event(event)
    assert result.status in ("WARNING", "SUCCESS")
    assert any("Timestamp" in w for w in result.warnings)
