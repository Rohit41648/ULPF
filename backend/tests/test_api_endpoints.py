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
