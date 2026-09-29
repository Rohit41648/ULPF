def test_trace_links_raw_log_and_normalized_event(client):
    line = '<134>Sep 11 10:32:14 FW01 %ASA-6-302013: Built outbound TCP connection 12345 for outside:192.168.1.10/443 to 8.8.8.8/443'
    resp = client.post("/api/v1/logs/process", json={"raw_log": line})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] in ("SUCCESS", "WARNING")
    event_id = body["event"]["id"]
    raw_log_id = body["raw_log"]["id"]

    trace_resp = client.get(f"/api/v1/events/{event_id}/trace")
    assert trace_resp.status_code == 200
    trace = trace_resp.json()
    assert trace["raw_log"]["id"] == raw_log_id
    assert trace["raw_log"]["raw_content"] == line
    assert trace["event"]["id"] == event_id
    assert trace["parser"]["name"] == "cisco_syslog_v1"
