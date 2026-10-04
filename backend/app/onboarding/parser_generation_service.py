"""
ParserGenerationService
========================
Orchestrates the AI/ML-assisted unknown-source onboarding flow:

    analyze_unknown_log()  -> AnalysisResult (what we found, and how)
    suggest_mapping()      -> dict field -> {value, confidence, source}
    generate_parser()      -> a storable parser config (used to build a
                               GeneratedParser instance for future logs)

Runs the deterministic heuristic engine (`HeuristicFieldDiscovery`) first,
then augments any missing fields using the local scikit-learn ML engine
(`LocalMLEngine`) — 100% offline, air-gap compliant, sub-millisecond latency.
"""
from __future__ import annotations

from typing import Any

from app.onboarding.heuristics import AnalysisResult, FieldSuggestion, HeuristicFieldDiscovery
from app.onboarding.ml_provider import local_ml_engine


class ParserGenerationService:
    def __init__(self) -> None:
        self._engine = HeuristicFieldDiscovery()

    def analyze_unknown_log(self, raw_log: str) -> AnalysisResult:
        """Runs the guaranteed heuristic engine first, then asks the local ML
        classifier to discover any fields the heuristics missed. Heuristic
        suggestions are never overridden by ML; ML only adds fields that are
        still missing, keeping deterministic rules authoritative."""
        result = self._engine.analyze(raw_log)

        if local_ml_engine.is_available():
            already_found = {s.field for s in result.suggestions}
            ml_suggestions = local_ml_engine.infer_fields(raw_log)
            for item in ml_suggestions:
                if item["field"] not in already_found:
                    result.suggestions.append(FieldSuggestion(
                        field=item["field"],
                        value=item["value"],
                        confidence=item["confidence"],
                        source=item["source"],
                        raw_token=item["raw_token"],
                    ))
                    already_found.add(item["field"])

            if result.suggestions:
                result.overall_confidence = round(
                    sum(s.confidence for s in result.suggestions) / len(result.suggestions), 2
                )

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
        suggestions, and records human feedback into the local ML engine."""
        field_map: dict[str, str] = {}
        for f in approved_fields:
            field_map[f["field"]] = f.get("raw_token") or f.get("value", "")

        # Active Learning: feed confirmed fields back to the local ML model
        if local_ml_engine.is_available():
            local_ml_engine.record_feedback(raw_log, approved_fields)

        return {
            "parser_name": parser_name,
            "format": "custom",
            "source_sample": raw_log,
            "fields": field_map,
            "field_details": approved_fields,
        }


parser_generation_service = ParserGenerationService()
