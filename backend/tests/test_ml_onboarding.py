from unittest.mock import patch

from app.onboarding.ml_provider import LocalMLEngine, extract_token_features, local_ml_engine
from app.onboarding.parser_generation_service import ParserGenerationService

UNKNOWN_LOG = "2026/09/11 10:51:23 AUTH-SRV LOGIN_SUCCESS user=admin src=10.20.4.15"


def test_feature_extraction():
    """Test that morphological and contextual features are extracted accurately."""
    feats_ip = extract_token_features("192.168.1.100", prev_token="src=", next_token="dst=", key_name="src")
    assert feats_ip["is_ipv4"] is True
    assert feats_ip["key_is_src"] is True

    feats_user = extract_token_features("admin", prev_token="user=", key_name="user")
    assert feats_user["key_is_user"] is True

    feats_action = extract_token_features("LOGIN_SUCCESS", prev_token="AUTH-SRV")
    assert feats_action["is_all_caps"] is True
    assert feats_action["is_action_like"] is True


def test_local_ml_engine_inference():
    """Test that the local ML engine discovers fields offline with calibrated confidence."""
    engine = LocalMLEngine()
    suggestions = engine.infer_fields(UNKNOWN_LOG)
    assert len(suggestions) > 0

    field_map = {s["field"]: s for s in suggestions}
    assert "hostname" in field_map
    assert field_map["hostname"]["value"] == "AUTH-SRV"
    assert field_map["hostname"]["source"] == "local_ml"
    assert 0.0 < field_map["hostname"]["confidence"] <= 1.0


def test_local_ml_suggestions_merged_in_service():
    """Test that parser generation service merges local ML fields with heuristics."""
    service = ParserGenerationService()
    result = service.analyze_unknown_log(UNKNOWN_LOG)

    fields = {s.field: s for s in result.suggestions}
    # Heuristics detect username as key_value
    assert "username" in fields
    assert fields["username"].value == "admin"
    assert fields["username"].source == "key_value"

    # ML detects hostname
    assert "hostname" in fields
    assert fields["hostname"].value == "AUTH-SRV"


def test_local_ml_engine_feedback_recording():
    """Test that human approval feedback is recorded for active learning."""
    engine = LocalMLEngine()
    initial_feedback_count = len(engine._feedback_samples)

    engine.record_feedback(
        UNKNOWN_LOG,
        [
            {"field": "hostname", "value": "AUTH-SRV"},
            {"field": "username", "value": "admin"},
        ],
    )
    assert len(engine._feedback_samples) == initial_feedback_count + 2
