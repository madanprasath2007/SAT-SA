# SAT-SA — Architecture Documentation
**Supervisory Analytics Tool for SOC Assessment**
_Air-Gapped Supervisory Analytics Platform · NCIIPC / NTRO Compliant_

> All diagrams are accurate to the implemented code. Each `.mmd` file in `docs/diagrams/`
> is a self-contained Mermaid source renderable by any Mermaid-compatible viewer
> (GitHub, mermaid.live, VS Code Mermaid Preview extension).

---

## Overview

SAT-SA is a **multi-CSE supervisory oversight platform** — not a SOC tool.
It receives periodic telemetry exports from Cyber Security Entities (CSEs),
processes them through five analytics engines, and surfaces supervisory findings
to NCIIPC/NTRO supervisors. Fully offline (air-gapped); optional local Ollama LLM.

---

## Diagram 1 — System Architecture

**Source**: [`docs/diagrams/01_system_architecture.mmd`](diagrams/01_system_architecture.mmd)

All components run on a single Docker Compose host. No internet egress at runtime.
DuckDB is an embedded file — no separate DB server. Ollama is optional (`--profile ai`);
MockLLM is the always-available deterministic fallback.

Key system boundaries:
- **React Frontend** (port 5173) — 12 pages, Axios API client, role switcher pill
- **FastAPI Backend** (port 8000) — 11 routers, all business logic and pipeline
- **DuckDB** — single embedded file, 20 tables, all storage
- **Ollama** (port 11434) — optional LLM container; profiles `ai` or `llm`

---

## Diagram 2 — End-to-End Workflow

**Source**: [`docs/diagrams/02_workflow.mmd`](diagrams/02_workflow.mmd)

The platform has 8 phases from upload to export:

1. **Ingest** — `POST /api/ingest/{cse_id}/{data_type}` triggers 5-stage pipeline
2. **Analytics** — `POST /api/analytics/run` runs all 5 engines (idempotent)
3. **Risk Scoring** — composite 0–100 score written per CSE (INSERT OR REPLACE)
4. **Threat Intel** — manual bundle import with SHA-256 verification
5. **Traceback** — NetworkX clustering + LLM narrative + evidence verifier
6. **Dashboard** — supervisor views findings, peer benchmarks, attack path graph
7. **Human Review** — VALID / FALSE_POSITIVE / NEEDS_MORE_DATA decisions
8. **Feedback Loop** — FP rates → tuning proposals → supervisor approval (DB-only; YAML unchanged)

Pipeline is sequential per file. Rejected rows are stored but do not block valid rows.
Engine runs are idempotent — DELETE + INSERT per (engine, CSE) scope.

---

## Diagram 3 — Threat Intelligence Flow

**Source**: [`docs/diagrams/03_threat_intel_flow.mmd`](diagrams/03_threat_intel_flow.mmd)

CTI is imported offline via `POST /api/threat-intel/import` (bundle.json + manifest.json).
SHA-256 checksum is verified before any DB write. CRLF normalisation attempted on mismatch.
`ChecksumMismatchError` raises HTTP 400.

Auto-seed: `GET /api/threat-intel/status` seeds from `data/threat_intel/sample_bundle/`
if `threat_intel_iocs` is empty.

Runtime IOC usage:

| Consumer | Mechanism |
|---|---|
| Risk Scoring | SQL JOIN `alerts ON source_ip = ioc_value OR dest_ip = ioc_value` |
| Attack Traceback | `get_threat_intel_lookup()` enriches graph IP nodes with actor/family labels |
| Peer Benchmarks | `ioc_count` per CSE shown in benchmark comparison table |
| PDF Report | `matched_iocs` section lists correlated threat actors |

**No TAXII/MISP/live feed client exists in the codebase. Import is manual only.**

---

## Diagram 4 — Sequence Diagram (Full Supervisory Session)

**Source**: [`docs/diagrams/04_sequence_diagram.mmd`](diagrams/04_sequence_diagram.mmd)

Covers the full actor sequence:
Supervisor → Upload → Analytics Run → Traceback → Review → Feedback Approval

LLM interaction detail:
- Prompt contains: real alert IDs from the candidate incident + last 5 supervisor review decisions
- `verify_llm_claims()` strips any `evidence_id` not found in `alerts` table
- OllamaLLM falls back to MockLLM on HTTP failure or connection timeout
- MockLLM is always available and produces deterministic JSON

---

## Diagram 5 — Attack Traceback Internals

**Source**: [`docs/diagrams/05_attack_traceback.mmd`](diagrams/05_attack_traceback.mmd)

### Graph Construction (`correlate.py`)

NetworkX MultiDiGraph node types:

| Node prefix | Represents | Example |
|---|---|---|
| `alert:` | Individual alert event | `alert:ALT-001` |
| `ip:` | Source/dest IP (CTI-enriched if IOC matched) | `ip:192.168.1.50` |
| `asset:` | Asset from `alerts.asset_id` | `asset:SRV-01` |
| `user:` | Analyst from `alerts.analyst_id` | `user:analyst-3` |

Edge types: `inbound_traffic`, `outbound_traffic`, `impacts_asset`, `handled_by`, `sequence`

### Incident Clustering (`path.py`)

`cluster_candidate_incidents()` steps:
1. Build undirected version of the MultiDiGraph
2. Remove user/asset bridge nodes (they link unrelated incidents)
3. `nx.connected_components()` — each component is one candidate incident
4. Sort: IOC match count DESC, then alert count DESC

### Stage Confidence Formula

```
stage_confidence = min(0.98, avg_severity_weight * (1.15 if ioc_match else 1.0))

severity weights: CRITICAL=1.0, HIGH=0.85, MEDIUM=0.70, LOW=0.50

overall_confidence = avg(stage_confidences)
  + 0.10  if any CTI IOC matched
  + 0.08  if >= 4 stages detected
  + 0.05  if >= 2 impacted assets
  capped at 0.99
```

### Evidence Verifier

`verify_llm_claims()` in `llm/verifier.py`: every `evidence_id` in LLM JSON output
is checked against the `alerts` table. Unverified IDs are stripped before the report
is persisted. This is the anti-hallucination guardrail — the traceback report only
contains IDs that exist in real case data.

---

## Diagram 6 — Database Entity-Relationship

**Source**: [`docs/diagrams/06_database_er.mmd`](diagrams/06_database_er.mmd)

18 tables in a single DuckDB file. No FK enforcement at DB level.
All referential integrity is application-enforced.

### Key design notes

| Item | Detail |
|---|---|
| `cases.linked_alert_ids` | VARCHAR comma-list; queried via `LIKE '%' || alert_id || '%'`. Fragile — substring false-positives; no index. |
| `findings.evidence` | TEXT column storing arbitrary JSON. No DB-level JSON type enforcement. |
| `risk_scores` | 1:1 with `cses`; uses INSERT OR REPLACE — only latest score kept per CSE. |
| `telemetry_baseline` | Defined in `models.py`; never populated at runtime. Blackout detection designed but not wired. |
| `traceback_reports.graph_json` | Stores full React Flow `{nodes, edges}` as TEXT. |

### Relationship summary

```
cses (root)
 +--< ingest_batches
 +--< alerts --< escalations
 |         \--< findings --< reviews
 +--< cases --< investigations
 +--< assets
 +--< entities
 +-- risk_scores (1:1, INSERT OR REPLACE)
 +--< traceback_reports

users --< audit_logs
threat_intel_bundles --< threat_intel_iocs
feedback_logs (standalone)
rejects (references batch_id)
```

---

## Diagram 7 — Frontend Component Map

**Source**: [`docs/diagrams/07_frontend_map.mmd`](diagrams/07_frontend_map.mmd)

React Router v6. All routes nested under `Layout.tsx` (sidebar + header shell with Outlet).

| Route | Page Component | Primary API calls |
|---|---|---|
| `/` | OverallRiskView | `getRiskScores`, `getKPIs`, `getPeerBenchmarks`, `runAnalytics` |
| `/cse-analysis` | CseAnalysisView | `getRiskScoreBreakdown`, `getFindings`, `getTracebackReport` |
| `/attack-path` | AttackPathView | `triggerTraceback`, `getTracebackGraph` |
| `/findings` | KeyFindingsView | `getFindings`, `getDrilldown`, `getFindingById` |
| `/peer-comparison` | PeerComparisonView | `getPeerBenchmarks` |
| `/drilldown` | DrilldownView | `getDrilldown`, `getTracebackReport` |
| `/reviews` | ReviewQueueView | `getReviewQueue`, `submitReview`, `getReviewHistory` |
| `/feedback` | FeedbackLogView | `getFeedbackStats`, `getSuggestions`, approve/reject |
| `/export` | ExportReportsView | PDF URL, CSV URL, `getAuditLogs` |
| `/admin` | AdminAuditView | `getAuditLogs`, `getSystemStatus`, `switchRole` |
| `/upload` | UploadPage | `ingestFile`, `getCseStats`, `getIngestStatus` |
| `/normalization` | NormalizationPage | `getNormalizationPreview`, `getRejects` |

**State management**: Local React state per page; no Redux/Zustand/Context.

**API client** (`api.ts`): Single Axios instance, `baseURL http://localhost:8000/api`.
JWT injected via request interceptor from `localStorage.satsa_token`.
All 35+ endpoints are fully typed with TypeScript interfaces.

**React Flow** (`AttackPathView`): uses `react-flow-renderer` to render `{nodes, edges}`
from `GET /api/traceback/{finding_id}/graph`.

---

## Diagram 8 — Deployment

**Source**: [`docs/diagrams/08_deployment.mmd`](diagrams/08_deployment.mmd)

### Docker Compose services

| Service | Image | Port | Profile | Restart |
|---|---|---|---|---|
| `satsa-backend` | `./backend/Dockerfile` | 8000:8000 | always | unless-stopped |
| `satsa-frontend` | `./frontend/Dockerfile` | 5173:80 | always | unless-stopped |
| `satsa-ollama` | `ollama/ollama:latest` | 11434:11434 | `ai`, `llm` | unless-stopped |
| `satsa-seed` | `./backend/Dockerfile` | — | `seed` | no (one-shot) |

Frontend depends on backend health check: `GET /api/health` — 10s interval, 5s timeout, 3 retries.

### Environment variables (`.env.example`)

| Variable | Default | Purpose |
|---|---|---|
| `DB_PATH` | `./data/sat_sa.duckdb` | DuckDB file path, mounted as `/app/data` volume |
| `JWT_SECRET_KEY` | `satsa_airgap_secret_...` | JWT signing key — **must be rotated for production** |
| `LLM_BACKEND` | `mock` | `mock` or `ollama` |
| `OLLAMA_HOST` | `http://localhost:11434` | In Compose use `http://ollama:11434` |
| `OLLAMA_MODEL` | `mistral:latest` | Any model pre-loaded into the Ollama volume |
| `ENVIRONMENT` | `air_gapped_on_prem` | Surfaced in `/api/admin/system-status` |
| `CLASSIFICATION_LEVEL` | `RESTRICTED` | Surfaced in `/api/admin/system-status` |

### Running without Docker

```bash
# Backend
cd backend && pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000

# Frontend
cd frontend && npm install && npm run dev
```

---

## Architecture Decisions and Rationale

| Decision | Rationale |
|---|---|
| **DuckDB over PostgreSQL** | Single embedded file — no server process, air-gapped friendly, OLAP-optimised for aggregation queries all 5 engines rely on |
| **MockLLM always available** | Prevents failure if Ollama absent or model not downloaded; deterministic output enables reproducible testing |
| **5-stage sequential pipeline** | Each stage produces clean output for the next; rejects stored without blocking; idempotent re-runs safe |
| **Engine registry pattern** | `@register_engine` + `get_all_engines()` — add/remove engines without modifying orchestrator |
| **Feedback never auto-applies to YAML** | Supervisory control principle — human must manually apply rule changes; prevents automated drift in a regulated context |
| **JWT dev fallback to Supervisor role** | Frictionless offline dev and demo; all dashboard features accessible without auth config |
| **Evidence verifier post-LLM** | Anti-hallucination guardrail — every claimed `evidence_id` checked against `alerts` table before persisting |
| **INSERT OR REPLACE on risk_scores** | Score is a derived aggregate — only latest calculation relevant; history preserved in `findings` |
| **ReportLab for PDF** | No cloud rendering dependency; fully offline, no headless browser |

---

## Known Architectural Gaps

| # | Gap | Impact |
|---|---|---|
| 1 | `audit_logs` not hash-chained | README claims cryptographic tamper-evidence; actual is append-only INSERT with no SHA-256 chain between rows |
| 2 | Feedback approval does not modify YAML | `feedback_logs.status = APPROVED` is DB-only; rule files unchanged without manual operator action |
| 3 | `telemetry_baseline` never populated | Blackout detection capability designed but not wired into `NegativeSpaceEngine.run()` |
| 4 | Dead router `routers/reviews.py` | 11 KB of code; never mounted in `main.py`; `routers/review.py` is the active router |
| 5 | No per-finding PDF export | `api.ts:getFindingPdfReportUrl()` references `/api/export/pdf/finding/:id`; route does not exist in `export.py` |
| 6 | STIX 2.1 not implemented | Documentation claims STIX 2.1 input; only CSV and JSON are supported by the pipeline |
| 7 | `cases.linked_alert_ids` design | VARCHAR comma-list queried via `LIKE` — substring false-positive risk; no index |
| 8 | No online CTI pull | No TAXII/MISP client; CTI updates require manual file transfer and bundle import |