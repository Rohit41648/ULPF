"""
Optional LLM provider for unknown-source onboarding.

This module is only ever called if `LLM_API_KEY` is set and
`LLM_PROVIDER=gemini` — the heuristic engine in `heuristics.py` is the
guaranteed, always-on fallback, so ULPF keeps working (including in
air-gapped deployments) with this module entirely unused.

Design choices, worth explaining if asked:
  - The LLM is asked for a *fixed* set of allowed field names — the same
    ones the heuristic engine produces — so its output merges cleanly into
    the same suggestion list the UI already renders.
  - LLM suggestions are capped at a fixed, modest confidence (0.8) rather
    than trusting a self-reported confidence score, because LLM confidence
    self-assessments aren't calibrated and we don't want them silently
    outranking a heuristic's key=value match (0.93).
  - Any failure (missing key, network error in an air-gapped environment,
    malformed JSON back from the model) is caught and simply yields no
    extra suggestions — it never raises, and never blocks the heuristic
    path.
"""
from __future__ import annotations

import json
import logging

from app.core.config import settings

logger = logging.getLogger(__name__)

_ALLOWED_FIELDS = [
    "timestamp", "hostname", "username", "source_ip", "destination_ip",
    "event_action", "http_method", "http_path", "http_status_code",
]

_LLM_CONFIDENCE_CAP = 0.8

_PROMPT_TEMPLATE = """You are analyzing ONE line of a security log from an \
unrecognized source, to help a log-normalization tool propose a field \
mapping for human review.

Identify which of these fields are present in the log line, and the exact \
substring for each: {fields}

Raw log line:
{raw_log}

Respond with ONLY a JSON array (no markdown, no commentary), where each \
element is {{"field": "<one of the allowed field names>", "value": "<exact \
substring from the log>"}}. Only include fields you can find explicitly in \
the log. If none are found, respond with []."""


def is_available() -> bool:
    return bool(settings.LLM_API_KEY) and (settings.LLM_PROVIDER or "").lower() == "gemini"


def suggest_fields_via_llm(raw_log: str) -> list[dict]:
    """Returns a list of {field, value, confidence, source} dicts, or an
    empty list on any failure. Never raises."""
    if not is_available():
        return []

    try:
        from google import genai  # imported lazily so the dependency is
        # only required when someone actually opts into LLM assistance.

        client = genai.Client(api_key=settings.LLM_API_KEY)
        prompt = _PROMPT_TEMPLATE.format(fields=", ".join(_ALLOWED_FIELDS), raw_log=raw_log)

        response = client.models.generate_content(
            model=settings.LLM_MODEL or "gemini-2.0-flash",
            contents=prompt,
        )
        text = (response.text or "").strip()
        text = text.removeprefix("```json").removeprefix("```").removesuffix("```").strip()

        raw_items = json.loads(text)
        if not isinstance(raw_items, list):
            return []

        suggestions = []
        for item in raw_items:
            field = item.get("field")
            value = item.get("value")
            if field in _ALLOWED_FIELDS and value:
                suggestions.append({
                    "field": field,
                    "value": value,
                    "confidence": _LLM_CONFIDENCE_CAP,
                    "source": "llm_assisted",
                    "raw_token": value,
                })
        return suggestions

    except Exception as exc:  # noqa: BLE001 - deliberately broad: any
        # failure here must degrade to "no LLM suggestions", never crash
        # the onboarding request.
        logger.warning("LLM-assisted field discovery failed, continuing with heuristics only: %s", exc)
        return []
