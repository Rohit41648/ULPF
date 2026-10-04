from unittest.mock import patch

from app.onboarding.parser_generation_service import ParserGenerationService

UNKNOWN_LOG = "2026/09/11 10:51:23 AUTH-SRV LOGIN_SUCCESS user=admin src=10.20.4.15"


def test_llm_not_called_when_unavailable():
    """With no LLM_API_KEY configured, results should be heuristic-only."""
    service = ParserGenerationService()
    with patch("app.onboarding.llm_provider.is_available", return_value=False):
        result = service.analyze_unknown_log(UNKNOWN_LOG)
    assert all(s.source != "llm_assisted" for s in result.suggestions)
    assert len(result.suggestions) > 0  # heuristics still ran


def test_llm_suggestions_merged_without_overriding_heuristics():
    """When the LLM is available, it should only ADD fields the heuristic
    engine missed — never override an existing heuristic suggestion."""
    service = ParserGenerationService()
    fake_llm_output = [
        # duplicate of a field the heuristic engine already found
        {"field": "username", "value": "someone_else", "confidence": 0.8, "source": "llm_assisted", "raw_token": "someone_else"},
        # a genuinely new field the heuristic engine can't find
        {"field": "hostname", "value": "AUTH-SRV", "confidence": 0.8, "source": "llm_assisted", "raw_token": "AUTH-SRV"},
    ]
    with patch("app.onboarding.llm_provider.is_available", return_value=True), \
         patch("app.onboarding.llm_provider.suggest_fields_via_llm", return_value=fake_llm_output):
        result = service.analyze_unknown_log(UNKNOWN_LOG)

    by_field = {s.field: s for s in result.suggestions}
    # heuristic's own "admin" value must win over the LLM's "someone_else"
    assert by_field["username"].value == "admin"
    assert by_field["username"].source == "key_value"


def test_llm_call_failure_returns_empty_not_raises():
    """suggest_fields_via_llm() itself must swallow any failure (bad key,
    no network in an air-gapped env, malformed response) and return an
    empty list rather than propagating an exception."""
    from app.onboarding import llm_provider

    with patch.object(llm_provider.settings, "LLM_API_KEY", "fake-key"), \
         patch.object(llm_provider.settings, "LLM_PROVIDER", "gemini"), \
         patch("google.genai.Client", side_effect=Exception("network unreachable")):
        result = llm_provider.suggest_fields_via_llm(UNKNOWN_LOG)

    assert result == []


def test_onboarding_api_still_works_when_llm_configured_but_unreachable(client):
    """End-to-end: even with LLM_API_KEY set, if Gemini is unreachable the
    /onboarding/analyze endpoint must still return heuristic suggestions
    successfully, never a 500."""
    from app.onboarding import llm_provider

    with patch.object(llm_provider.settings, "LLM_API_KEY", "fake-key"), \
         patch.object(llm_provider.settings, "LLM_PROVIDER", "gemini"), \
         patch("google.genai.Client", side_effect=Exception("network unreachable")):
        resp = client.post("/api/v1/onboarding/analyze", json={"raw_log": UNKNOWN_LOG})

    assert resp.status_code == 200
    field_names = {f["field"] for f in resp.json()["fields"]}
    assert "username" in field_names  # heuristic result still came through
