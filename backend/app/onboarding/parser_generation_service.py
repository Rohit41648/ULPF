"""
ParserGenerationService
========================
Orchestrates the AI-assisted unknown-source onboarding flow:

    analyze_unknown_log()  -> AnalysisResult (what we found, and how)
    suggest_mapping()      -> dict field -> {value, confidence, source}
    generate_parser()      -> a storable parser config (used to build a
                               GeneratedParser instance for future logs)

If LLM_API_KEY is configured, `analyze_unknown_log` can optionally be
augmented by an LLM provider for richer field inference; the heuristic
engine (`HeuristicFieldDiscovery`) always runs and is the guaranteed
fallback, so the feature works with zero external dependencies.
"""
from __future__ import annotations

from typing import Any

from app.onboarding import llm_provider
from app.onboarding.heuristics import AnalysisResult, HeuristicFieldDiscovery


class ParserGenerationService:
    def __init__(self) -> None:
        self._engine = HeuristicFieldDiscovery()

    def analyze_unknown_log(self, raw_log: str) -> AnalysisResult:
        """Runs the guaranteed heuristic engine first, then — only if
        LLM_API_KEY + LLM_PROVIDER=gemini are configured — asks Gemini to
        fill in any fields the heuristics missed. Heuristic suggestions are
        never overridden by the LLM; the LLM only adds fields that are
        still missing, since key=value/regex matches are more explainable
        and get to stay authoritative."""
        result = self._engine.analyze(raw_log)

        if llm_provider.is_available():
            print("DEBUG: LLM IS AVAILABLE IN PARSER_GENERATION_SERVICE")
            already_found = {s.field for s in result.suggestions}
            llm_suggestions = llm_provider.suggest_fields_via_llm(raw_log)
            print("DEBUG: LLM RETURNED:", llm_suggestions)
            for item in llm_suggestions:
                if item["field"] not in already_found:
                    from app.onboarding.heuristics import FieldSuggestion
                    result.suggestions.append(FieldSuggestion(
                        field=item["field"], value=item["value"],
                        confidence=item["confidence"], source=item["source"],
                        raw_token=item["raw_token"],
                    ))
                    already_found.add(item["field"])
            if result.suggestions:
                result.overall_confidence = round(
                    sum(s.confidence for s in result.suggestions) / len(result.suggestions), 2
                )

        with open("parser_service_debug.txt", "w") as f:
            f.write(f"is_available: {llm_provider.is_available()}\n")
            f.write(f"API_KEY: {llm_provider.settings.LLM_API_KEY[:5] if llm_provider.settings.LLM_API_KEY else None}\n")
            f.write(f"PROVIDER: {llm_provider.settings.LLM_PROVIDER}\n")
            f.write(f"suggestions: {result.suggestions}")

        return result

    def suggest_mapping(self, raw_log: str) -> dict[str, Any]:
        result = self.analyze_unknown_log(raw_log)
        return {
            "overall_confidence": result.overall_confidence,
            "fields": [
                {
                    "field": s.field,
                    "value": s.value,
                    "confidence": s.confidence,
                    "source": s.source,
                    "raw_token": s.raw_token,
                }
                for s in result.suggestions
            ],
        }

    def generate_parser(self, raw_log: str, parser_name: str, approved_fields: list[dict[str, Any]]) -> dict[str, Any]:
        """Builds a storable parser config from human-approved field
        suggestions. `approved_fields` is the (optionally edited) list the
        user confirmed in the UI, in the same shape `suggest_mapping` returns."""
        field_map: dict[str, str] = {}
        for f in approved_fields:
            field_map[f["field"]] = f.get("raw_token") or f.get("value", "")

        return {
            "parser_name": parser_name,
            "format": "custom",
            "source_sample": raw_log,
            "fields": field_map,
            "field_details": approved_fields,
        }


parser_generation_service = ParserGenerationService()
