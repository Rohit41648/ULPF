# ULPF — Architecture Document

**SIH 2026 · PS 156 · Universal Log Pre-processing Framework**

## 1. Purpose

ULPF sits between heterogeneous perimeter/security log sources and
downstream SIEM, data-lake, and ML systems. It ingests logs in any format,
preserves them losslessly, normalizes them into one vendor-neutral schema,
and keeps every normalized event traceable back to its exact raw source. It
is explicitly **not** a SIEM — it produces analytics-ready, normalized data
for one to consume.

## 2. Two pipelines, one schema

**Known format** (deterministic, fast, explainable):

```
Raw log → Format detection → Deterministic parser → Field extraction →
Universal schema mapping → Validation → Storage → Dashboard / API
```

**Unknown format** (human-in-the-loop, AI-assisted):

```
Raw log → Format detection → no parser matches → heuristic + local ML
field discovery (scikit-learn RandomForest token classifier) → suggested
mapping + calibrated confidence → human approval → parser generated →
stored → future logs from this source now follow the deterministic path
```

Both pipelines converge on the same output: a `UniversalEvent`. The known
path is 100% deterministic; the unknown path uses local in-house ML with zero
external cloud calls.

## 3. Universal Event Schema (UES)

A single Pydantic model with a fixed taxonomy (`source`, `event`, `network`,
`user`, `http`, `host`, `parser`, `traceability`) plus an open `extensions`
map for anything that doesn't fit the taxonomy. This makes normalization
**additive, never lossy**: a field a parser can't classify is preserved
under `extensions` rather than discarded. `traceability.raw_log_id` and
`traceability.parser_id` are mandatory on every event, giving unconditional
raw ↔ normalized linkage.

## 4. Format detection

A deterministic `FormatDetector` runs an ordered battery of signature checks
(JSON validity + key shape, `%ASA-n-nnnnnn` for Cisco, CEF header, Fortigate
key=value density, Apache combined-log regex, Linux syslog header) before
falling back to "unknown." No ML sits on this hot path — detection stays
fast, explainable, and testable with plain unit tests.

## 5. Parser architecture

Every parser implements `BaseLogParser`: `detect()`, `parse()`,
`normalize()`. A `ParserRegistry` holds all deterministic parsers; adding a
sixth known source is one new class plus one registry line — no change to
the detection, validation, storage, or API layers. Confidence per event is
computed deterministically as the fraction of a parser's expected fields
that were successfully extracted, scaled into a realistic band — never a
random number.

## 6. Unknown-source onboarding

`ParserGenerationService` wraps a `HeuristicFieldDiscovery` engine that finds
timestamps, key=value pairs (with a small hint table: `user`/`username` →
username, `src`/`srcip` → source IP, etc.), bare IPs, `ALL_CAPS_ACTION`
tokens, and a positional hostname guess — each suggestion carries its own
confidence based on *how* it was found (explicit key=value pairs score
highest; positional guesses score lowest). A human reviews, edits, and
approves the mapping in the UI; only then is a `GeneratedParser` persisted
and registered, so it can deterministically parse every subsequent log from
that source.

To achieve 100% air-gap compliance and zero external dependencies, this step is
augmented by an in-house machine learning token classifier (`app/onboarding/ml_provider.py`)
built with `scikit-learn` (`RandomForestClassifier` + `DictVectorizer`). The local ML engine
extracts morphological and contextual token features to infer missing fields
(`username`, `hostname`, `source_ip`, `destination_ip`, `event_action`, `http_method`,
`http_status_code`, etc.) with calibrated probabilities via `predict_proba`. When an operator
approves or edits field mappings in the UI, feedback is recorded for Active Learning to
incrementally retrain the model. Heuristic suggestions (exact regex / key=value) remain
authoritative and are never overridden. The entire pipeline runs completely offline with
sub-millisecond latency (< 2ms) and zero data leakage.

## 7. Data model

Four tables: `raw_logs` (immutable, written before any parsing),
`normalized_events` (JSONB `event_data`, FK to `raw_logs` and `parsers`),
`parsers` (deterministic + AI-generated, with `events_processed` counters),
`processing_runs` (an audit trail of every ingest/process call, including
failures, for `/stats` and debugging). PostgreSQL is the default in
production; SQLite is a zero-setup local-dev fallback behind the same
SQLAlchemy models.

## 8. API and UI

FastAPI exposes ingest/process/batch, log and event listing, the
raw↔parser↔normalized trace endpoint, the parser registry, the two-step
onboarding endpoints (`analyze`, `create-parser`), and `/stats`/`/health`.
Swagger/OpenAPI docs are generated automatically. The React dashboard
mirrors this 1:1: Overview (metrics + charts), Process Logs (paste a log,
watch it move through Ingested → Format Detected → Parsed → Normalized →
Validated → Stored), Events, Parser Registry, Unknown Source Onboarding
(the AI-suggestion / human-approval / parser-creation flow made visually
explicit), and Traceability (a three-panel raw ↔ parser ↔ normalized view).

## 9. Deployment and scaling path

The MVP runs as three containers (`frontend`, `backend`, `postgres`) via
`docker compose up --build`, with no external network calls required —
satisfying the air-gapped deployment requirement. The architecture leaves
explicit seams for scale: `LogProcessingService` is the single point where a
Kafka/Redpanda producer would replace direct DB writes for high-throughput
ingestion, and `normalized_events` is structured so a secondary
OpenSearch/Elasticsearch sink can be added for full-text search and
SIEM-style dashboards without touching the parsing or normalization layers.

## 10. Why this design meets the evaluation criteria

| Requirement | How ULPF satisfies it |
|---|---|
| Lossless raw preservation | `raw_logs` written before parsing; raw content never mutated |
| Source-specific extraction | Five deterministic parsers, one per vendor/format |
| Common taxonomy | Fixed Universal Event Schema + open `extensions` |
| Traceability | Mandatory `raw_log_id` + `parser_id` on every event |
| Plug-and-play onboarding | `ParserRegistry` for known sources; AI-assisted flow for unknown ones |
| Reduced parser effort | One sample log → working parser in under a minute, no code |
| Air-gapped deployment | All components self-hosted; zero required external calls |
| Containerized | Dockerfiles + docker-compose for the full stack |
| AI/ML-ready | Normalized, flat schema is directly usable as ML features |
