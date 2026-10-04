def test_health(client):
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_parser_registry_seeded(client):
    resp = client.get("/api/v1/parsers")
    assert resp.status_code == 200
    names = {p["name"] for p in resp.json()}
    assert {"cisco_syslog_v1", "fortigate_kv_v1", "linux_syslog_v1", "windows_json_v1", "apache_access_v1"} <= names


def test_ingest_then_list_logs(client):
    line = "Sep 11 10:40:12 server01 sshd[1234]: Accepted password for admin from 192.168.1.20 port 54321 ssh2"
    ingest = client.post("/api/v1/logs/ingest", json={"raw_log": line, "source_hint": "manual-test"})
    assert ingest.status_code == 200
    list_resp = client.get("/api/v1/logs")
    assert list_resp.status_code == 200
    assert len(list_resp.json()) >= 1


def test_batch_process_mixed_sources(client):
    logs = [
        '<134>Sep 11 10:32:14 FW01 %ASA-6-302013: Built outbound TCP connection 12345 for outside:192.168.1.10/443 to 8.8.8.8/443',
        '192.168.1.50 - - [11/Sep/2026:10:42:12 +0000] "GET /login HTTP/1.1" 200 1245 "-" "curl/8.0"',
    ]
    resp = client.post("/api/v1/logs/process/batch", json={"raw_logs": logs})
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 2
    assert all(r["status"] in ("SUCCESS", "WARNING") for r in results)


def test_stats_reflect_processed_events(client):
    client.post("/api/v1/logs/process", json={
        "raw_log": '<134>Sep 11 10:32:14 FW01 %ASA-6-302013: Built outbound TCP connection 12345 for outside:192.168.1.10/443 to 8.8.8.8/443'
    })
    resp = client.get("/api/v1/stats")
    assert resp.status_code == 200
    body = resp.json()
    assert body["processed_events"] >= 1
    assert body["supported_formats"] >= 5


def test_update_and_delete_parser(client):
    # Create an ML-generated parser
    sample = "2026/09/11 10:51:23 AUTH-SRV LOGIN_SUCCESS user=admin src=10.20.4.15"
    create_resp = client.post("/api/v1/onboarding/create-parser", json={
        "raw_log": sample,
        "parser_name": "temp_parser_to_edit",
        "approved_fields": [{"field": "username", "value": "admin", "raw_token": "user=admin"}],
    })
    assert create_resp.status_code == 200
    parser_id = create_resp.json()["parser"]["id"]

    # Test updating parser name and status
    patch_resp = client.patch(f"/api/v1/parsers/{parser_id}", json={
        "name": "renamed_parser",
        "status": "disabled",
    })
    assert patch_resp.status_code == 200
    assert patch_resp.json()["name"] == "renamed_parser"
    assert patch_resp.json()["status"] == "disabled"

    # Test re-enabling
    enable_resp = client.patch(f"/api/v1/parsers/{parser_id}", json={"status": "active"})
    assert enable_resp.status_code == 200
    assert enable_resp.json()["status"] == "active"

    # Test deleting parser
    del_resp = client.delete(f"/api/v1/parsers/{parser_id}")
    assert del_resp.status_code == 200
    assert del_resp.json()["success"] is True

    # Verify parser is deleted
    get_resp = client.get(f"/api/v1/parsers/{parser_id}")
    assert get_resp.status_code == 404


def test_update_and_delete_event(client):
    # Process a log to create an event
    process_resp = client.post("/api/v1/logs/process", json={
        "raw_log": '<134>Sep 11 10:32:14 FW01 %ASA-6-302013: Built outbound TCP connection 12345 for outside:192.168.1.10/443 to 8.8.8.8/443'
    })
    assert process_resp.status_code == 200
    event_id = process_resp.json()["event"]["id"]

    # Test updating event type and severity
    patch_resp = client.patch(f"/api/v1/events/{event_id}", json={
        "event_type": "security_alert",
        "severity": "critical",
    })
    assert patch_resp.status_code == 200
    assert patch_resp.json()["event_type"] == "security_alert"
    assert patch_resp.json()["severity"] == "critical"
    assert patch_resp.json()["event_data"]["event"]["type"] == "security_alert"

    # Test bulk delete
    bulk_resp = client.post("/api/v1/events/bulk-delete", json={"event_ids": [event_id]})
    assert bulk_resp.status_code == 200
    assert bulk_resp.json()["deleted_count"] == 1

    # Verify event is deleted
    get_resp = client.get(f"/api/v1/events/{event_id}")
    assert get_resp.status_code == 404


def test_health_engine_status(client):
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["database"] == "ok"
    assert data["ml_engine"]["status"] == "active"
    assert data["ml_engine"]["offline"] is True
    assert data["blockchain"]["status"] == "healthy"
    assert data["crypto"]["status"] == "active"


def test_parser_test_sandbox(client):
    parsers = client.get("/api/v1/parsers").json()
    apache_parser = next(p for p in parsers if "apache" in p["name"])
    log = '192.168.1.50 - - [11/Sep/2026:10:42:12 +0000] "GET /login HTTP/1.1" 200 1245 "-" "curl/8.0"'
    resp = client.post(f"/api/v1/parsers/{apache_parser['id']}/test", json={"raw_log": log})
    assert resp.status_code == 200
    data = resp.json()
    assert data["matched"] is True
    assert data["confidence"] > 0.8
    assert len(data["fields"]) > 0


