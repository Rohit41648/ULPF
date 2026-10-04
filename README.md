# ULPF — Universal Log Pre-processing Framework

**SIH 2026 · Problem Statement 156**

> ULPF is **not** a SIEM. It is an intelligent preprocessing and normalization
> layer that sits *before* a SIEM, analytics platform, or ML system — turning
> heterogeneous security logs into a common, analytics-ready universal schema
> while preserving the original raw log for forensic traceability.

---

## 1. Problem Statement

Enterprises generate logs from firewalls, servers, cloud services, operating
systems, applications, and IoT devices, in formats ranging from Syslog and
JSON to XML, CSV, CEF, and LEEF. Before a SIEM or ML system can use this data,
someone has to write a vendor-specific parser for every source — expensive,
slow, and hard to scale. ULPF replaces that per-vendor effort with a single
extensible framework.

---

## 2. Architecture

```
KNOWN FORMAT                          UNKNOWN FORMAT
Raw Log                               Raw Log
  │                                     │
Format Detection  ──────────────────────┤
  │                                     │
Deterministic Parser              No suitable parser
  │                                     │
Field Extraction                  AI/ML-assisted field discovery
  │                                     │
Universal Schema Mapping          Suggested field mapping + confidence
  │                                     │
Validation                        Human approval
  │                                     │
Blockchain Integrity Proof        Generate parser configuration
  │                                     │
Storage  ◄─────────────────────── Store parser → process future logs
  │                                  deterministically from then on
Dashboard / API
```

Every raw log is written to `raw_logs` **before** any parsing happens, so
nothing is ever lost even if normalization fails. Every normalized event
carries a `traceability` block linking it back to its exact `raw_log_id` and
the exact `parser_id`/version that produced it.

---

## 3. Features

### Core Pipeline
- **Deterministic format detection** — regex/signature-based, no ML on the known path
- **Five built-in parsers**: Cisco ASA syslog, Fortigate key=value syslog, Linux auth/syslog, Windows Event Log (JSON), Apache access log
- **Vendor-neutral Universal Event Schema** (Pydantic), extensible via an `extensions` field so nothing is dropped in normalization
- **Full raw-log preservation** + raw ↔ normalized traceability
- **Deterministic confidence scoring** (not random) for every parsed event
- **Plugin/registry architecture** — a new deterministic parser is one class + one registry line, with zero changes to the pipeline

### AI/ML-Assisted Unknown-Source Onboarding
- Heuristic field discovery (timestamp / IP / key=value / ALL_CAPS-action / pipe-delimited formats)
- **100% Local ML Backend** — deterministic heuristics augmented by an in-house `scikit-learn` Random Forest token classifier with calibrated probability scoring
- **Zero External APIs** — completely self-contained, air-gapped, and sub-millisecond execution (< 2ms) with zero cloud data leakage
- **Active Learning feedback loop** — human approval actions in the UI incrementally refine the local model
- **Batch union analysis** — when a file contains multiple unknown-format logs, their discovered fields are unioned and a single set of parser candidates is computed, so the user can create/extend a parser covering the entire batch

### Security & Integrity
- **AES-256-GCM application-layer encryption** — the browser encrypts every payload before sending; the backend decrypts server-side
- **SHA-256 integrity verification** — a hash is computed before encryption and verified after decryption to detect in-transit tampering
- **Blockchain integrity ledger** — every processed event is recorded in a private SHA-256 hash-chain; each block links to the previous block's hash, enabling tamper-evident audit trails

### Frontend Dashboard
- **Overview** — real-time metrics, format/vendor/severity breakdowns, confidence gauges
- **Log Analyzer** — unified analysis page: paste a log or upload a file; auto-detects known vs unknown; shows parser details, field mapping, parser candidates, and human approval actions
- **Events** — browse normalized events
- **Parser Registry** — view all registered parsers (deterministic + AI-generated)
- **Traceability** — raw ↔ normalized ↔ parser audit trail per event

### Deployment
- Dockerized; `docker compose up --build` runs the whole stack
- SQLite fallback for zero-setup local development
- Architected so Kafka and OpenSearch/Elasticsearch can be added later without changing the parsing/normalization core

---

## 4. Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, FastAPI, Pydantic, SQLAlchemy |
| Database | PostgreSQL (SQLite fallback for zero-setup local dev) |
| Frontend | React, Vite, Tailwind CSS, Chart.js |
| Encryption | AES-256-GCM (Web Crypto API + `cryptography` library) |
| Integrity | SHA-256 hash verification + blockchain hash-chain ledger |
| Deployment | Docker, Docker Compose |
| Future scale | Kafka/Redpanda, OpenSearch/Elasticsearch (planned, not required for MVP) |

---

## 5. Project Structure

```
ulpf/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                        FastAPI app + router wiring
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   └── v1/
│   │   │       ├── __init__.py
│   │   │       ├── analyzer.py            unified log analysis (known + unknown)
│   │   │       ├── blockchain.py          blockchain status & verification
│   │   │       ├── events.py              normalized event CRUD
│   │   │       ├── logs.py                raw log ingest & secure processing
│   │   │       ├── onboarding.py          unknown-source onboarding endpoints
│   │   │       ├── parsers.py             parser registry listing
│   │   │       ├── security.py            encryption key exchange
│   │   │       └── stats.py               dashboard metrics
│   │   ├── blockchain/
│   │   │   ├── __init__.py
│   │   │   └── ledger.py                  private SHA-256 hash-chain ledger
│   │   ├── core/
│   │   │   ├── __init__.py
│   │   │   ├── config.py                  settings & environment variables
│   │   │   └── logging.py                 logging configuration
│   │   ├── database/
│   │   │   ├── __init__.py
│   │   │   ├── init_db.py                 DB initialization & seed data
│   │   │   ├── models.py                  SQLAlchemy ORM models
│   │   │   └── session.py                 DB session / engine setup
│   │   ├── detection/
│   │   │   ├── __init__.py
│   │   │   └── format_detector.py         deterministic format detection
│   │   ├── normalization/
│   │   │   ├── __init__.py
│   │   │   └── universal_event_mapper.py  maps parsed fields → universal schema
│   │   ├── onboarding/
│   │   │   ├── __init__.py
│   │   │   ├── generated_parser.py        runtime-generated parser class
│   │   │   ├── heuristics.py              heuristic field discovery engine
│   │   │   ├── ml_provider.py             local scikit-learn ML token classifier
│   │   │   └── parser_generation_service.py  creates parsers from approved fields
│   │   ├── parsers/
│   │   │   ├── __init__.py
│   │   │   ├── base.py                    BaseLogParser abstract class
│   │   │   ├── registry.py               parser registry (lookup by format)
│   │   │   ├── apache.py                  Apache access log parser
│   │   │   ├── cisco.py                   Cisco ASA syslog parser
│   │   │   ├── fortigate.py              Fortigate key=value parser
│   │   │   ├── linux.py                   Linux auth/syslog parser
│   │   │   └── windows.py                Windows Event Log (JSON) parser
│   │   ├── schemas/
│   │   │   ├── __init__.py
│   │   │   ├── api.py                     API request/response models
│   │   │   └── universal_event.py         Universal Event Schema (Pydantic)
│   │   ├── security/
│   │   │   ├── __init__.py
│   │   │   └── crypto.py                  AES-256-GCM encrypt/decrypt + SHA-256
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   └── log_processing_service.py  pipeline orchestration service
│   │   └── validation/
│   │       ├── __init__.py
│   │       └── validator.py               event schema validator
│   ├── data/
│   │   └── blockchain/
│   │       └── ledger.json                blockchain ledger storage
│   ├── keys/
│   │   └── aes_secret.key                 AES-256 key (gitignored)
│   ├── scripts/
│   │   └── generate_crypto_keys.py        key generation utility
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── conftest.py                    pytest fixtures & config
│   │   ├── test_api_endpoints.py          API endpoint tests
│   │   ├── test_format_detector.py        format detection tests
│   │   ├── test_llm_onboarding.py         LLM onboarding tests
│   │   ├── test_onboarding.py             heuristic onboarding tests
│   │   ├── test_parsers.py                parser unit tests
│   │   ├── test_schema_validation.py      schema validation tests
│   │   └── test_traceability.py           traceability tests
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── App.jsx                        root component + routing
│   │   ├── main.jsx                       Vite entry point
│   │   ├── index.css                      global styles
│   │   ├── pages/
│   │   │   ├── Overview.jsx               dashboard with metrics & charts
│   │   │   ├── LogAnalyzer.jsx            unified log analysis (paste/upload)
│   │   │   ├── ProcessLogs.jsx            secure log processing page
│   │   │   ├── EventsPage.jsx             browse normalized events
│   │   │   ├── ParserRegistry.jsx         view registered parsers
│   │   │   ├── Traceability.jsx           raw ↔ normalized audit trail
│   │   │   └── Onboarding.jsx             unknown-source onboarding UI
│   │   ├── components/
│   │   │   ├── MetricCard.jsx             reusable metric display card
│   │   │   └── StatusChip.jsx             status indicator chip
│   │   └── services/
│   │       ├── api.js                     typed fetch wrapper over the REST API
│   │       └── secureCrypto.js            AES-256-GCM encryption + SHA-256 hashing
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js
│   ├── tailwind.config.js
│   ├── postcss.config.js
│   ├── nginx.conf                         production nginx config
│   └── Dockerfile
├── data/                                  sample logs
│   ├── apache/                            Apache access log samples
│   ├── cisco/                             Cisco ASA syslog samples
│   ├── fortigate/                         Fortigate key=value samples
│   ├── linux/                             Linux auth/syslog samples
│   ├── windows/                           Windows Event Log samples
│   └── unknown/                           unknown-format samples
├── docs/
│   ├── architecture.md                    architecture document
│   └── SECURITY_ENCRYPTION.md             encryption flow documentation
├── LogNexus03_Architecture.docx
├── docker-compose.yml
├── .env.example
└── .gitignore
```

---

## 6. Local Setup (Without Docker)

### Backend

```bash
cd backend
python -m venv .venv
# On macOS/Linux:
source .venv/bin/activate
# On Windows:
.venv\Scripts\activate

pip install -r requirements.txt

# Generate the AES-256 encryption key (run once)
python -m scripts.generate_crypto_keys

# Start the server
uvicorn app.main:app --reload --env-file .env
# Swagger UI at http://localhost:8000/docs
```

By default the backend uses a local SQLite file (`ulpf.db`) — zero setup
required. Set `DATABASE_URL` to point at Postgres instead when needed.

### Frontend

```bash
cd frontend
npm install
npm run dev
# App at http://localhost:5173
```

---

## 7. Docker Setup

```bash
cp .env.example .env   # optional, defaults work out of the box
docker compose up --build
```

| Service | URL |
|---|---|
| Frontend | http://localhost:8080 |
| Backend + Swagger | http://localhost:8000/docs |
| Postgres | localhost:5432 |

Kafka and OpenSearch are intentionally **not** part of the default compose
file — see the commented services at the bottom of `docker-compose.yml` for
how they'd be added once volume justifies streaming ingestion.

---

## 8. Environment Variables

See [`.env.example`](.env.example). No secrets are hardcoded anywhere.

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./ulpf.db` | Database connection string |
| `CORS_ORIGINS` | `http://localhost:5173` | Comma-separated allowed origins |
| `ENCRYPTION_ENABLED` | `true` | Enable AES-256-GCM payload encryption |
| `ENCRYPTION_KEY_PATH` | `backend/keys/aes_secret.key` | Path to the AES key file |
| `ENABLE_LOCAL_ML` | `true` | Enable local scikit-learn ML token classifier for unknown onboarding |
| `ML_CONFIDENCE_THRESHOLD` | `0.65` | Minimum confidence score threshold for local ML field inference |
| `VITE_API_BASE_URL` | `http://localhost:8000/api/v1` | Frontend API base URL |

---

## 9. API Documentation

Full interactive docs are auto-generated by FastAPI at `/docs` (Swagger) and
`/redoc`. Key endpoints:

### Log Processing

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/logs/ingest` | Store a raw log without processing |
| POST | `/api/v1/logs/secure-process` | AES-encrypted single log ingest + process |
| POST | `/api/v1/logs/secure-process-batch` | AES-encrypted batch processing |
| GET | `/api/v1/logs` | List raw logs |
| GET | `/api/v1/logs/{id}` | Fetch a single raw log |

### Unified Log Analyzer

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/analyzer/analyze` | Analyze a single log (auto-detect known/unknown) |
| POST | `/api/v1/analyzer/analyze-secure` | AES-encrypted single log analysis |
| POST | `/api/v1/analyzer/analyze-batch-secure` | AES-encrypted batch analysis with union of unknown fields |
| POST | `/api/v1/analyzer/approve` | Human approval: extend existing parser or create new one |

### Events & Traceability

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/events` | List normalized events |
| GET | `/api/v1/events/{id}` | Fetch a single normalized event |
| GET | `/api/v1/events/{id}/trace` | Raw ↔ parser ↔ normalized traceability |

### Parsers

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/parsers` | List all parsers (deterministic + AI-generated) |
| GET | `/api/v1/parsers/{id}` | Fetch a single parser |

### Blockchain Integrity

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/blockchain/status` | Chain validity + block count |
| GET | `/api/v1/blockchain/blocks` | Full blockchain data |
| GET | `/api/v1/blockchain/verify/{event_id}` | Verify a specific event against the chain |

### Security & Infrastructure

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/security/encryption-key` | Fetch the shared AES key (must be over HTTPS in production) |
| GET | `/api/v1/stats` | Dashboard metrics |
| GET | `/api/v1/health` | Health check |

---

## 10. Supported Formats (MVP)

| Format | Vendor | Detection Method |
|---|---|---|
| Syslog (RFC) | Cisco ASA | `%ASA-n-nnnnnn` signature |
| Key=value syslog | Fortinet (Fortigate) | `devname=`, `srcip=`, `dstip=` keys |
| Linux syslog | Linux | `Mon DD HH:MM:SS host process[pid]:` pattern |
| JSON event log | Microsoft (Windows) | `EventID` + `Computer` keys |
| Common/Combined Log | Apache | IP - - [timestamp] "METHOD path" status pattern |
| Custom (pipe-delimited, key=value, etc.) | Any | AI-assisted onboarding → generated parser |

---

## 11. Universal Event Schema

```json
{
  "event_id": "ULPF-...",
  "timestamp": "...",
  "source": { "vendor": "Cisco", "product": "ASA", "format": "syslog" },
  "event": { "type": "network_connection", "action": "allowed", "severity": "low" },
  "network": {
    "source_ip": "192.168.1.10", "source_port": 443,
    "destination_ip": "8.8.8.8", "destination_port": 443,
    "protocol": "TCP"
  },
  "user": { "username": null },
  "http": { "method": null, "path": null, "status_code": null, "user_agent": null },
  "host": { "hostname": "FW01" },
  "parser": { "name": "cisco_syslog_v1", "version": "1.0", "confidence": 0.98 },
  "traceability": {
    "raw_log_id": "RAW-...",
    "parser_id": "cisco_syslog_v1-v1.0",
    "ingested_at": "..."
  },
  "extensions": {}
}
```

Fields that don't map onto the fixed taxonomy are kept under `extensions`
rather than dropped — normalization is additive, never lossy.

---

## 12. Unknown-Source Onboarding

### Single Log Analysis

1. **Analyze** — `POST /analyzer/analyze` runs a deterministic heuristic engine
   (timestamp / IP / key=value / ALL_CAPS-action / pipe-delimited format detection)
   over the log and proposes a field mapping with a per-field confidence score.
2. **Review** — The user reviews/edits the discovered fields and sees existing
   parser candidates ranked by field-overlap percentage.
3. **Approve** — `POST /analyzer/approve` with `action: "create_parser"` or
   `action: "extend_parser"` persists the approved mapping.
4. **Reuse** — Every subsequent log from that source is parsed
   **deterministically** by the generated parser — no further AI assistance
   needed. The parser is immediately recognized on the next analysis.

### Batch File Analysis

When a file contains multiple unknown-format logs, ULPF **unions** all
discovered fields across every unknown line and computes a single set of
parser candidates against the combined field set. This means:

- The user sees one unified analysis covering the whole file
- They can create/extend a parser that handles **all** the log variants in that file
- Known-format lines in the same file are still processed individually

### Local ML Field Inference Engine

ULPF features a **100% offline, self-hosted Machine Learning field inference engine**
built on `scikit-learn` (`RandomForestClassifier` + `DictVectorizer`). When an unknown
log source is analyzed:

1. **Heuristics first** — exact regex signatures and key=value pairs are extracted with
   maximum authority and explainability.
2. **Local ML augmentation** — unmatched tokens are processed through morphological and
   contextual feature extraction (token lengths, IP signatures, timestamp patterns, casing,
   neighboring word clues, positional context).
3. **Calibrated probabilities** — the local model predicts target schema fields
   (`username`, `hostname`, `source_ip`, `destination_ip`, `event_action`, `http_method`,
   `http_status_code`, etc.) with mathematically calibrated confidence scores via `predict_proba`.
4. **Active Learning feedback** — when human operators approve or customize field mappings
   in the UI, feedback is recorded to incrementally retrain the local model weights.
5. **Zero Cloud Dependencies** — no third-party APIs (Gemini, OpenAI, etc.), no internet
   connectivity required, sub-millisecond execution (< 2ms), and zero data-leakage risk.

```bash
# .env
ENABLE_LOCAL_ML=true
ML_CONFIDENCE_THRESHOLD=0.65
```

---

## 13. Application-Layer Encryption

ULPF encrypts browser-to-backend payloads using **AES-256-GCM**:

```
Browser                                   Backend
  │                                         │
  ├─ GET /security/encryption-key ─────────►│ (served over HTTPS/TLS)
  │◄─── { key_hex: "..." } ────────────────┤
  │                                         │
  ├─ SHA-256 hash of plaintext              │
  ├─ AES-256-GCM encrypt (random IV)       │
  ├─ POST { iv, ciphertext, hash } ───────►│
  │                                         ├─ AES-256-GCM decrypt
  │                                         ├─ SHA-256 re-hash
  │                                         ├─ Compare hashes → VERIFIED / TAMPERED
  │                                         ├─ Process log(s)
  │◄──── { result, integrity_status } ─────┤
```

- **Key exchange** is secured by HTTPS/TLS (no RSA key wrapping)
- The shared AES-256 key is generated once with `python -m scripts.generate_crypto_keys`
- SHA-256 integrity hash detects any in-transit tampering even if the attacker can decrypt

Generate the AES key:
```bash
cd backend
python -m scripts.generate_crypto_keys
```

See [`docs/SECURITY_ENCRYPTION.md`](docs/SECURITY_ENCRYPTION.md) for the full
flow and production guidance.

---

## 14. Blockchain Integrity Ledger

Every successfully processed event is recorded in a **private SHA-256 hash-chain**
stored at `data/blockchain/ledger.json`:

- Each block stores: `event_hash`, `raw_log_hash`, `parser_id`, and `previous_hash`
- The chain starts with a genesis block
- Verification endpoint: `GET /api/v1/blockchain/verify/{event_id}` re-hashes
  the event and raw log from the database and compares against the stored block
- Chain integrity: `GET /api/v1/blockchain/status` validates every block's
  `previous_hash` linkage

This provides a tamper-evident audit trail — if any stored event or raw log is
modified after processing, the blockchain verification will detect the mismatch.

---

## 15. Example API Requests

```bash
# Process a known Cisco log (encrypted)
curl -X POST localhost:8000/api/v1/logs/secure-process \
  -H 'Content-Type: application/json' \
  -d '{ ... encrypted envelope ... }'

# Analyze an unknown source (plaintext, for testing)
curl -X POST localhost:8000/api/v1/analyzer/analyze \
  -H 'Content-Type: application/json' \
  -d '{"raw_log": "2026/09/11 10:51:23 AUTH-SRV LOGIN_SUCCESS user=admin src=10.20.4.15"}'

# Create a parser from approved fields
curl -X POST localhost:8000/api/v1/analyzer/approve \
  -H 'Content-Type: application/json' \
  -d '{
    "action": "create_parser",
    "raw_log": "2026/09/11 10:51:23 AUTH-SRV LOGIN_SUCCESS user=admin src=10.20.4.15",
    "parser_name": "auth_kv_v1",
    "approved_fields": [...]
  }'

# Check blockchain integrity
curl localhost:8000/api/v1/blockchain/status

# Verify a specific event against the chain
curl localhost:8000/api/v1/blockchain/verify/ULPF-abc123def456
```

---

## 16. Testing

```bash
cd backend
pytest -q
```

Test suite covers: format detection, all five deterministic parsers,
universal-schema validation, raw ↔ normalized traceability, LLM onboarding,
API endpoints, and the full unknown-source onboarding flow (analyze → approve
→ create parser → auto-parse a second log).

---

## 17. Future Scalability

- Swap SQLite/Postgres writes for a Kafka/Redpanda topic ahead of the
  processing service for high-throughput ingestion (billions of events/day)
- Add OpenSearch/Elasticsearch as a secondary sink for full-text search and
  SIEM-style dashboards, alongside Postgres for relational/audit queries
- Extend the parser registry beyond perimeter devices to servers, cloud,
  identity, and endpoint sources — no core pipeline changes required
- Add Parquet/Iceberg export from the raw store for large-scale data-lake
  and ML training use cases

---

## 18. Air-Gap and Container Notes

Every component (Postgres, FastAPI, the React build served via nginx, and the local
scikit-learn ML engine) is 100% self-hostable with **zero external API calls** required at
runtime, strictly satisfying air-gapped deployment and enterprise SOC data privacy requirements.
No external API keys or third-party cloud services are required.
