# ULPF — Universal Log Pre-processing Framework

**SIH 2026 · Problem Statement 156**

> ULPF is **not** a SIEM. It is an intelligent preprocessing and normalization
> layer that sits *before* a SIEM, analytics platform, or ML system — turning
> heterogeneous security logs into a common, analytics-ready universal schema
> while preserving the original raw log for forensic traceability.

## 1. Problem statement

Enterprises generate logs from firewalls, servers, cloud services, operating
systems, applications, and IoT devices, in formats ranging from Syslog and
JSON to XML, CSV, CEF, and LEEF. Before a SIEM or ML system can use this data,
someone has to write a vendor-specific parser for every source — expensive,
slow, and hard to scale. ULPF replaces that per-vendor effort with a single
extensible framework.

## 2. Architecture

```
KNOWN FORMAT                          UNKNOWN FORMAT
Raw Log                               Raw Log
  |                                     |
Format Detection  ----------------------+
  |                                     |
Deterministic Parser              No suitable parser
  |                                     |
Field Extraction                  AI/ML-assisted field discovery
  |                                     |
Universal Schema Mapping          Suggested field mapping + confidence
  |                                     |
Validation                        Human approval
  |                                     |
Storage  <-------------------------  Generate parser configuration
  |                                     |
Dashboard / API                   Store parser -> process future logs
                                   deterministically from then on
```

Every raw log is written to `raw_logs` **before** any parsing happens, so
nothing is ever lost even if normalization fails. Every normalized event
carries a `traceability` block linking it back to its exact `raw_log_id` and
the exact `parser_id`/version that produced it.

## 3. Features

- Deterministic format detection (regex/signature-based, no ML on the known path)
- Five built-in parsers: Cisco ASA syslog, Fortigate key=value syslog, Linux
  auth/syslog, Windows Event Log (JSON), Apache access log
- Vendor-neutral **Universal Event Schema** (Pydantic), extensible via an
  `extensions` field so nothing is dropped in normalization
- Full raw-log preservation + raw ↔ normalized traceability
- Deterministic confidence scoring (not random) for every parsed event
- **AI-assisted unknown-source onboarding**: heuristic field discovery →
  human review/approval → generated parser → deterministic reuse on future
  logs from that source (no LLM required; an LLM hook exists as an optional
  enhancement)
- Plugin/registry architecture — a new deterministic parser is one class + one
  registry line, with zero changes to the pipeline
- FastAPI REST API with full Swagger/OpenAPI docs
- React + Vite + Tailwind + Chart.js SOC-style dashboard
- Dockerized; `docker compose up --build` runs the whole stack
- Architected so Kafka and OpenSearch/Elasticsearch can be added later
  without changing the parsing/normalization core

## 4. Tech stack

| Layer | Technology |
|---|---|
| Backend | Python, FastAPI, Pydantic, SQLAlchemy |
| Database | PostgreSQL (SQLite fallback for zero-setup local dev) |
| Frontend | React, Vite, Tailwind CSS, Chart.js |
| Deployment | Docker, Docker Compose |
| Future scale | Kafka/Redpanda, OpenSearch/Elasticsearch (planned, not required for MVP) |

## 5. Project structure

```
ulpf/
├── backend/
│   ├── app/
│   │   ├── main.py                 FastAPI app + router wiring
│   │   ├── core/                   config, logging
│   │   ├── database/               SQLAlchemy models, session, init/seed
│   │   ├── schemas/                Universal Event Schema + API models
│   │   ├── detection/              deterministic format detector
│   │   ├── parsers/                BaseLogParser, 5 parsers, registry
│   │   ├── validation/             event validator
│   │   ├── onboarding/             heuristic engine, ParserGenerationService,
│   │   │                           GeneratedParser
│   │   ├── services/               LogProcessingService (orchestration)
│   │   └── api/v1/                 logs, events, parsers, onboarding, stats
│   ├── tests/                      27 pytest tests
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── pages/                  Overview, ProcessLogs, Events,
│   │   │                           ParserRegistry, Onboarding, Traceability
│   │   ├── components/             MetricCard, StatusChip
│   │   └── services/api.js         typed fetch wrapper over the REST API
│   └── Dockerfile
├── data/                           sample logs: cisco, fortigate, linux,
│                                   windows, apache, unknown
├── docs/architecture.md            2-page architecture document
├── docker-compose.yml
└── .env.example
```

## 6. Local setup (without Docker)

**Backend:**
```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
# Swagger UI at http://localhost:8000/docs
```
By default the backend uses a local SQLite file (`ulpf.db`) — zero setup
required. Set `DATABASE_URL` to point at Postgres instead when needed.

**Frontend:**
```bash
cd frontend
npm install
cp .env.example .env   # adjust VITE_API_BASE_URL if needed
npm run dev
# App at http://localhost:5173
```

## 7. Docker setup

```bash
cp .env.example .env   # optional, defaults work out of the box
docker compose up --build
```
- Frontend: http://localhost:8080
- Backend + Swagger: http://localhost:8000/docs
- Postgres: localhost:5432

Kafka and OpenSearch are intentionally **not** part of the default compose
file — see the commented services at the bottom of `docker-compose.yml` for
how they'd be added once volume justifies streaming ingestion.

## 8. Environment variables

See `.env.example` (root, for Docker) and `frontend/.env.example`. No secrets
are hardcoded anywhere; `LLM_API_KEY` is optional and the app is fully
functional without it.

## 9. API documentation

Full interactive docs are auto-generated by FastAPI at `/docs` (Swagger) and
`/redoc`. Key endpoints:

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/logs/ingest` | Store a raw log without processing |
| POST | `/api/v1/logs/process` | Ingest + run the full pipeline |
| POST | `/api/v1/logs/process/batch` | Process multiple raw logs |
| GET | `/api/v1/logs`, `/api/v1/logs/{id}` | List / fetch raw logs |
| GET | `/api/v1/events`, `/api/v1/events/{id}` | List / fetch normalized events |
| GET | `/api/v1/events/{id}/trace` | Raw ↔ parser ↔ normalized traceability |
| GET | `/api/v1/parsers`, `/api/v1/parsers/{id}` | Parser registry |
| POST | `/api/v1/onboarding/analyze` | Heuristic field discovery for an unknown log |
| POST | `/api/v1/onboarding/create-parser` | Persist a human-approved mapping as a parser |
| GET | `/api/v1/stats` | Dashboard metrics |
| GET | `/api/v1/health` | Health check |

## 10. Supported formats (MVP)

Cisco ASA syslog · Fortigate key=value syslog · Linux auth/syslog ·
Windows Event Log (JSON) · Apache Common/Combined access log · plus any
custom source onboarded through the AI-assisted flow.

## 11. Universal Event Schema

```json
{
  "event_id": "ULPF-...",
  "timestamp": "...",
  "source": { "vendor": "Cisco", "product": "ASA", "format": "syslog" },
  "event": { "type": "network_connection", "action": "allowed", "severity": "low" },
  "network": { "source_ip": "192.168.1.10", "source_port": 443,
               "destination_ip": "8.8.8.8", "destination_port": 443, "protocol": "TCP" },
  "user": { "username": null },
  "http": { "method": null, "path": null, "status_code": null, "user_agent": null },
  "host": { "hostname": "FW01" },
  "parser": { "name": "cisco_syslog_v1", "version": "1.0", "confidence": 0.98 },
  "traceability": { "raw_log_id": "RAW-...", "parser_id": "cisco_syslog_v1-v1.0", "ingested_at": "..." },
  "extensions": {}
}
```
Fields that don't map onto the fixed taxonomy are kept under `extensions`
rather than dropped — normalization is additive, never lossy.

## 12. Unknown-source onboarding

1. `POST /onboarding/analyze` — runs a deterministic heuristic engine
   (timestamp / IP / key=value / ALL_CAPS-action detection) over one sample
   line and proposes a field mapping with a confidence score per field.
2. A human reviews/edits the mapping in the UI.
3. `POST /onboarding/create-parser` — persists the approved mapping as an
   `ai_generated` parser.
4. Every subsequent log from that source is parsed **deterministically** by
   the generated parser — no further AI assistance needed.

If `LLM_API_KEY` is set and `LLM_PROVIDER=gemini`, step 1 is extended with a
real Gemini call that fills in any fields the heuristic engine missed —
**heuristic suggestions are never overridden**, the LLM only adds fields
that are still missing. Without a key configured (or if Gemini is
unreachable, e.g. in an air-gapped deployment), the heuristic engine alone
is the complete, working fallback — the LLM call fails safe and simply
contributes nothing rather than breaking onboarding.

```bash
# .env
LLM_API_KEY=your-gemini-api-key
LLM_PROVIDER=gemini
LLM_MODEL=gemini-3.6-flash   # optional
```

## 13. Example API requests

```bash
# Process a known Cisco log
curl -X POST localhost:8000/api/v1/logs/process \
  -H 'Content-Type: application/json' \
  -d '{"raw_log": "<134>Sep 11 10:32:14 FW01 %ASA-6-302013: Built outbound TCP connection 12345 for outside:192.168.1.10/443 to 8.8.8.8/443"}'

# Analyze an unknown source
curl -X POST localhost:8000/api/v1/onboarding/analyze \
  -H 'Content-Type: application/json' \
  -d '{"raw_log": "2026/09/11 10:51:23 AUTH-SRV LOGIN_SUCCESS user=admin src=10.20.4.15"}'
```

## 14. Application-layer encryption

ULPF supports encrypted browser-to-backend payloads using hybrid cryptography:
AES-256-GCM encrypts each request and RSA-OAEP-3072 protects the per-request AES key.
The browser uses only the receiver public key; the backend private key decrypts the payload.
Generate the local receiver key pair with `python backend/scripts/generate_crypto_keys.py`.
See `docs/SECURITY_ENCRYPTION.md` for the full flow and production guidance.

## 15. Testing

```bash
cd backend
pytest -q
```
27 tests covering: format detection, all five parsers, universal-schema
validation, raw ↔ normalized traceability, and the full unknown-source
onboarding flow (analyze → approve → create parser → auto-parse a second log).

## 15. Future scalability

- Swap SQLite/Postgres writes for a Kafka/Redpanda topic ahead of the
  processing service for high-throughput ingestion (billions of events/day)
- Add OpenSearch/Elasticsearch as a secondary sink for full-text search and
  SIEM-style dashboards, alongside Postgres for relational/audit queries
- Swap the heuristic-only onboarding engine for an optional LLM-backed one
  (the `ParserGenerationService` abstraction is already in place for this)
- Add Parquet/Iceberg export from the raw store for large-scale data-lake
  and ML training use cases
- Extend the parser registry beyond perimeter devices to servers, cloud,
  identity, and endpoint sources — no core pipeline changes required

## 16. Air-gap and container notes

Every component (Postgres, FastAPI, the React build served via nginx) is
self-hostable with no external API calls required at runtime, satisfying
air-gapped deployment. `LLM_API_KEY` is the only optional external
dependency and the system is fully functional without it.


## Log file upload / batch processing

The Process Logs page supports uploading `.txt`, `.log`, and `.csv` files. Each non-empty line is processed as an individual log event. The browser encrypts the complete batch with AES-256-GCM and protects the per-request AES key with the receiver RSA-OAEP public key before sending it to `POST /api/v1/logs/secure-process-batch`. The backend decrypts the batch, applies the existing deterministic/generated parsers, and returns per-line statuses plus a summary in the UI.

The local demo limits uploads to 5 MB and 10,000 non-empty lines. Unknown lines remain marked `UNKNOWN_FORMAT` and can be onboarded through the Unknown Source Onboarding workflow.
