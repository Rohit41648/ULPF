UNKNOWN_LOG_1 = "2026/09/11 10:51:23 AUTH-SRV LOGIN_SUCCESS user=admin src=10.20.4.15"
UNKNOWN_LOG_2 = "2026/09/11 10:52:07 AUTH-SRV LOGIN_FAILED user=root src=45.33.32.156"


def test_analyze_known_log_is_rejected(client):
    known = '<134>Sep 11 10:32:14 FW01 %ASA-6-302013: Built outbound TCP connection 12345 for outside:192.168.1.10/443 to 8.8.8.8/443'
    resp = client.post("/api/v1/onboarding/analyze", json={"raw_log": known})
    assert resp.status_code == 400


def test_analyze_unknown_log_suggests_fields(client):
    resp = client.post("/api/v1/onboarding/analyze", json={"raw_log": UNKNOWN_LOG_1})
    assert resp.status_code == 200
    body = resp.json()
    field_names = {f["field"] for f in body["fields"]}
    assert "username" in field_names
    assert "source_ip" in field_names
    assert body["overall_confidence"] > 0


def test_full_onboarding_flow_then_process_second_log(client):
    # Step 0: confirm it's genuinely unrecognized first
    process_resp = client.post("/api/v1/logs/process", json={"raw_log": UNKNOWN_LOG_1})
    assert process_resp.json()["status"] == "UNKNOWN_FORMAT"

    # Step 1: analyze
    analyze_resp = client.post("/api/v1/onboarding/analyze", json={"raw_log": UNKNOWN_LOG_1})
    fields = analyze_resp.json()["fields"]

    # Step 2: human approves suggested mapping as-is, creates parser
    create_resp = client.post(
        "/api/v1/onboarding/create-parser",
        json={"raw_log": UNKNOWN_LOG_1, "parser_name": "auth_server_v1", "approved_fields": fields},
    )
    assert create_resp.status_code == 200
    assert create_resp.json()["parser"]["source_type"] in ("ml_generated", "ai_generated")

    # Step 3: process a SECOND, different log from the same unknown source
    # using the newly generated parser — no more manual onboarding needed.
    second_resp = client.post("/api/v1/logs/process", json={"raw_log": UNKNOWN_LOG_2})
    second_body = second_resp.json()
    assert second_body["status"] in ("SUCCESS", "WARNING")
    assert second_body["event"]["vendor"] is None  # auto-generated parser, no vendor claimed
    event_data = second_body["event"]["event_data"]
    assert event_data["user"]["username"] == "root"
    assert event_data["network"]["source_ip"] == "45.33.32.156"


def test_duplicate_parser_name_conflicts(client):
    analyze_resp = client.post("/api/v1/onboarding/analyze", json={"raw_log": UNKNOWN_LOG_1})
    fields = analyze_resp.json()["fields"]
    payload = {"raw_log": UNKNOWN_LOG_1, "parser_name": "dup_parser", "approved_fields": fields}
    first = client.post("/api/v1/onboarding/create-parser", json=payload)
    assert first.status_code == 200
    second = client.post("/api/v1/onboarding/create-parser", json=payload)
    assert second.status_code == 409
