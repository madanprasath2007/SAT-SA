# SAT-SA — Project Analysis
**Supervisory Analytics Tool for SOC Assessment**
_Air-Gapped Supervisory Analytics Platform · NCIIPC / NTRO Compliant_

> **Methodology**: Every claim below was verified by direct file inspection. Anything unverified is marked `[unverified]`.

---

## 1. Repository Overview

| Item | Value |
|---|---|
| Backend | FastAPI v0.115 + DuckDB 1.1.1 + Python 3.x |
| Frontend | React 18 + TypeScript + Vite (port 5173) |
| Database | DuckDB embedded — `data/sat_sa.duckdb` (12.8 MB seeded) |
| Deployment | Docker Compose — 4 services: backend :8000, frontend :5173, ollama :11434, seed |
| LLM | Ollama (optional, `--profile ai`); deterministic MockLLM fallback always available |
| Version | v5.0.0 (`main.py`) |
| Tests | 128 tests, 7 files (`backend/tests/`) |

### Key Python Dependencies (`requirements.txt`)
`fastapi`, `uvicorn`, `duckdb`, `pandas`, `numpy`, `scikit-learn`, `networkx`, `scipy`, `pyjwt`, `reportlab`, `pydantic`, `httpx`, `pytest`, `python-multipart`

---

## 2. Backend Modules

### 2.1 Pipeline (`backend/pipeline/`)

Five-stage sequential ingest pipeline. Entry point: `orchestrator.run_pipeline()`.

| Stage | File | Key Function | Input | Output |
|---|---|---|---|---|
| 1 Schema Validation | `validation.py` | `validate()` | df, data_type, batch_id, cse_id | (valid_df, rejects_list) |
| 2 Cleaning | `cleaning.py` | `clean()` | df, data_type | deduped/trimmed df |
| 3 Normalization | `normalization.py` | `normalize()`, `map_severity()`, `parse_timestamp()`, `validate_ip()` | df, data_type | canonical df |
| 4 Entity Mapping | `entity_mapping.py` | `map_entities()` | df, data_type, cse_id, con | writes entities table |
| 5 Store | `store.py` | `store()`, `store_rejects()`, `store_batch()` | df, data_type, con | row count; writes tables |

**Supported data types**: alerts, cases, investigations, escalations, assets, others
**Supported CSEs**: CSE-A, CSE-B, CSE-C, CSE-D (hardcoded whitelist in `routers/ingest.py`)
**Severity mapping**: ~14 variants → CRITICAL | HIGH | MEDIUM | LOW
**Timestamp formats**: 10 formats including ISO-8601, dd/mm/yy, dd-Mon-YYYY

---

### 2.2 Analytics Engines (`backend/engines/`)

All inherit `Engine` ABC from `base.py`. `@register_engine` adds to global dict. `persist_findings()` is idempotent (DELETE + INSERT per engine+CSE scope).

#### Engine 1 — RuleEngine (`rule_engine.py`)
Evaluates 4 YAML rules. Reads: alerts, cases, investigations, escalations.

| Rule file | Detects | Score |
|---|---|---|
| `rule_critical_escalation.yaml` | CRITICAL alert never escalated OR > 60 min delay | 90.0 |
| `rule_closed_case_investigation.yaml` | Closed case with 0 investigations or notes < 15 chars | 80.0 |
| `rule_sop_steps.yaml` | Investigation notes < 20 chars | 60.0 |
| `rule_escalation_level.yaml` | Escalated to non-L3/IR target OR no reason text | 75.0 |

#### Engine 2 — AnomalyDetectionEngine (`anomaly_detection.py`)
Requires >= 5 days of data per CSE. Features: (count, crit+high ratio, distinct assets, avg MTTR).

| Detection | Method | Threshold |
|---|---|---|
| Alert Volume Spike | Z-score daily count | Z >= 3.0 |
| Alert Volume Drop | Z-score | Z <= -2.5, mean >= 10 |
| Multi-feature Anomaly | Isolation Forest (contamination auto-scaled) | prediction == -1 |

#### Engine 3 — PeerBenchmarkingEngine (`peer_benchmarking.py`)
Requires >= 2 CSEs. Cohort median calculated from all CSEs.

| Metric | Flag Condition |
|---|---|
| Critical MTTR | < 180s while peer median > 600s |
| Escalation Rate | < 2% while peer median > 5%, >= 20 alerts |
| Investigation Coverage | < 35% while peer median > 50%, >= 2 cases |
| Alerts per Asset | > 4x or < 0.15x cohort median |

#### Engine 4 — ExecutionGapEngine (`execution_gap.py`)

| Detection | Method |
|---|---|
| Rapid Closure | CRITICAL alert closed < 120s ABS, OR Z-score > 3.0 vs category baseline |
| Template Notes | TF-IDF cosine similarity >= 0.90 in >= 70% of analyst notes (min 4 alerts) |

#### Engine 5 — NegativeSpaceEngine (`negative_space.py`)

| Detection | Condition | Score |
|---|---|---|
| Silent Critical Asset | CRITICAL-rated asset with 0 linked alerts | 95.0 |
| Missing Detection Coverage | CSE has 0 alerts in category where peer avg >= 5 | 75.0 |

#### Risk Scoring Engine (`risk_scoring.py`)
Composite 0-100 per CSE. Auto-triggers engine runs if findings table empty.

| Component | Max | Source |
|---|---|---|
| Rule Violations | 25 | RuleEngine findings |
| Anomalies | 20 | AnomalyDetectionEngine findings |
| Peer Deviations + Execution Gaps | 15 | PeerBenchmarkingEngine + ExecutionGapEngine |
| Silent Assets + Coverage Gaps | 15 | NegativeSpaceEngine findings |
| Threat Intel IOC Match | 25 | SQL join: alerts <-> threat_intel_iocs on source_ip/dest_ip |
| Attack Traceback Confidence | 30 | traceback_reports (stage_count + confidence_score) |

Risk levels: >= 75 CRITICAL, >= 50 HIGH, >= 25 MODERATE, else LOW.

---

### 2.3 Threat Intelligence (`backend/threat_intel/importer.py`)

- `import_threat_intel_bundle()`: Parse manifest → SHA-256 verify → write threat_intel_iocs, threat_intel_cves, threat_intel_bundles
- `seed_sample_threat_intel()`: Auto-seeds from `data/threat_intel/sample_bundle/` on first `/status` call
- CRLF normalization attempted on checksum mismatch
- **No online CTI collector exists.** Import is manual bundle upload only.

---

### 2.4 Attack Traceback (`backend/traceback/`)

`run_attack_traceback()` 8-step pipeline:

1. `cluster_candidate_incidents()` — NetworkX connected components on alert correlation graph
2. `build_attack_path()` — maps to 5 MITRE stages, calculates per-stage + overall confidence
3. `build_event_graph()` — MultiDiGraph nodes: alert, ip (CTI-enriched), asset, user
4. `graph_to_react_flow()` — serializes to `{nodes, edges}` JSON
5. Construct evidence prompt (real alert IDs only, no hallucination)
6. Fetch last 5 supervisor reviews → inject into LLM prompt as context
7. `llm.generate(prompt)` — MockLLM or OllamaLLM
8. `verify_llm_claims()` — reject any evidence_ids not in alerts table

**5 MITRE Stages**: Initial Access (TA0001) → Privilege Escalation (TA0004) → Lateral Movement (TA0008) → Data Access (TA0009) → Evidence Tampering (TA0005)

**Confidence formula**: avg stage severity weight + CTI match bonus (+0.10) + 4+ stages bonus (+0.08) + 2+ assets bonus (+0.05), capped at 0.99.

---

### 2.5 LLM Module (`backend/llm/`)

| Class | Behaviour |
|---|---|
| `MockLLM` | Deterministic. Regex-extracts alert IDs from prompt. Distributes across 5 stages. Always available. |
| `OllamaLLM` | POST to `http://localhost:11434/api/generate`. stream=False, format="json". Falls back to MockLLM on failure. |

Factory `get_llm_client()` checks `LLM_BACKEND` env var. `verifier.py:verify_llm_claims()` checks every `evidence_id` in LLM output against `alerts` table and strips hallucinated IDs.

---

### 2.6 Human Review and Feedback

**Review** (`routers/review.py`):
- POST `/api/reviews/` — writes to `reviews` table; if FALSE_POSITIVE → auto-creates `feedback_logs` entry (PENDING); writes audit log
- GET `/api/reviews/queue` — priority-ordered: unreviewed first, then CRITICAL > HIGH > score DESC

**Feedback** (`routers/feedback.py`):
- FP rates computed from `reviews JOIN findings`
- 4 default proposals seeded on first access
- POST `/api/feedback/approve/{log_id}` → sets status=APPROVED in DB + audit
- **Rule YAML files are NEVER auto-modified.** Approved state is DB-only.
- Last 10 reviews are injected into LLM traceback prompt via `traceback-context`

---

### 2.7 Auth and RBAC (`backend/auth.py`, `routers/auth.py`)

- JWT HS256, 24h expiry, signed with `JWT_SECRET_KEY` env var
- **Dev fallback**: Missing/invalid JWT → defaults to Supervisor role (frictionless testing)
- Password: `SHA-256(satsa_salt_ + password)` — not bcrypt

| Role | Restricted operations |
|---|---|
| Admin | All; user management, audit |
| Supervisor | Submit reviews, approve feedback, export reports |
| Analyst | Read-only (all GETs accessible without token via dev fallback) |

---

### 2.8 Audit System (`backend/audit.py`)

Appends to `audit_logs` table. Actions recorded: USER_LOGIN, ROLE_SWITCH, REVIEW_SUBMITTED, FEEDBACK_SUGGESTION_APPROVED/REJECTED, APPROVE_RULE_TUNING, REJECT_RULE_TUNING, EXPORT_FINDINGS_CSV, EXPORT_CSE_PDF_REPORT.

> **Verified gap**: README calls this "hash-chained, append-only ledger." Implementation is append-only DuckDB INSERT only — no cryptographic hash chain between rows.

---

### 2.9 Export (`backend/routers/export.py`)

- `GET /api/export/findings/csv` → StreamingResponse CSV (Python csv.writer, fully in-memory)
- `GET /api/export/pdf/cse/{cse_id}` → ReportLab PDF containing: entity overview table, attack traceback stages, findings table (top 15), reviewer decisions table

Both fully offline. No cloud service or external font required.

---

## 3. API Endpoints (Complete List)

### `/api/ingest`
| Method | Path | Description |
|---|---|---|
| POST | `/{cse_id}/{data_type}` | Upload CSV/JSON; runs 5-stage pipeline |
| GET | `/rejects` | List rejected rows (filterable) |
| GET | `/normalization/preview` | Before/after normalized rows |
| GET | `/cses/{cse_id}/stats` | Batch + severity + entity counts |
| GET | `/status` | All table row counts |
| POST | `/seed` | Seed CSE metadata |
| POST | `/upload/alerts` | Legacy CSV upload (CSE-A) |

### `/api/analytics`
| Method | Path | Description |
|---|---|---|
| POST | `/run` | Run all 5 engines, persist findings, recalculate risk |
| GET | `/findings` | List findings (cse_id, engine, severity, date, limit, offset) |
| GET | `/findings/{finding_id}` | Single finding with full evidence |
| GET | `/risk-scores` | All CSE risk scores |
| GET | `/risk-scores/{cse_id}/breakdown` | Full explainable breakdown |
| GET | `/summary` | Finding counts by severity/engine/cse |

### `/api/dashboard`
| Method | Path | Description |
|---|---|---|
| GET | `/kpis` | KPI tiles (alert counts, MTTR, findings) |
| GET | `/mttr-distribution` | Avg/min/max MTTR per (category, severity) |
| GET | `/cse-heatmap` | Finding counts per (cse_id, finding_type) |
| GET | `/alert-timeline` | Daily alert volume by severity |
| GET | `/findings-feed` | Latest N findings |
| GET | `/peer-benchmarks` | Peer metrics + outlier flags + cohort medians |
| GET | `/drilldown` | Finding → alert → case → investigations → traceback → rejects |

### `/api/threat-intel`
| Method | Path | Description |
|---|---|---|
| POST | `/import` | Import CTI bundle (bundle.json + manifest.json) |
| GET | `/status` | KB status + auto-seed if empty |
| GET | `/iocs` | List IOCs (ioc_type, search filters) |

### `/api/traceback`
| Method | Path | Description |
|---|---|---|
| POST | `/run` | Execute full traceback reconstruction |
| GET | `/{finding_id}` | Fetch or auto-generate traceback report |
| GET | `/{finding_id}/graph` | React Flow nodes/edges only |

### `/api/reviews`
| Method | Path | Auth |
|---|---|---|
| POST | `/` | Submit review (Admin/Supervisor) |
| POST | `/{finding_id}` | Review by path ID (Admin/Supervisor) |
| GET | `/` | List reviews |
| GET | `/history/{finding_id}` | Review history |
| GET | `/queue` | Priority-ordered review queue |
| GET | `/feedback/stats` | FP rates per engine |
| GET | `/feedback/suggestions` | Tuning proposals |
| POST | `/feedback/suggestions/{log_id}/action` | Approve/Reject (Admin/Supervisor) |

### `/api/feedback`
| Method | Path | Auth |
|---|---|---|
| GET | `/fp-rates` | Per-engine and per-rule FP rates |
| GET | `/suggestions` | Proposals list |
| POST | `/approve/{log_id}` | Approve (Supervisor/Admin) |
| POST | `/reject/{log_id}` | Reject (Supervisor/Admin) |
| GET | `/traceback-context` | LLM prompt context (last 10 reviews) |

### `/api/auth`
| Method | Path | Description |
|---|---|---|
| POST | `/login` | Username/password → JWT |
| GET | `/me` | Current user |
| GET | `/users` | List demo users |
| POST | `/switch-role` | JWT for specific role (demo) |
| GET | `/audit` | Audit trail |

### `/api/export` (alias `/api/reports`)
| Method | Path | Description |
|---|---|---|
| GET | `/findings/csv` | Filtered findings CSV |
| GET | `/pdf/cse/{cse_id}` | Official ReportLab PDF |

### `/api/admin`
| Method | Path | Auth |
|---|---|---|
| GET | `/audit-logs` | Paginated audit log (Admin/Supervisor) |
| GET | `/system-status` | Table counts + classification info |

### Root
| Method | Path |
|---|---|
| GET | `/` or `/ui` — serves `dashboard.html` |
| GET | `/api/health` — `{"status":"operational"}` |

---

## 4. Database Tables

Single DuckDB file. No FK enforcement. All relationships are application-enforced.

### Table List

| Table | PK | Key Columns |
|---|---|---|
| `cses` | cse_id | cse_name, sector, contact_email |
| `ingest_batches` | batch_id | cse_id, data_type, rows_received/accepted/rejected |
| `rejects` | reject_id | batch_id, cse_id, raw_data, reject_reason, stage |
| `alerts` | alert_id | cse_id, category, severity, severity_raw, created_at, closed_at, mttr_seconds, closure_notes, analyst_id, asset_id, source_ip, dest_ip |
| `cases` | case_id | cse_id, title, severity, status, opened_at, closed_at, linked_alert_ids (VARCHAR) |
| `investigations` | investigation_id | cse_id, case_id, analyst_id, started_at, completed_at, outcome, notes |
| `escalations` | escalation_id | cse_id, alert_id, case_id, escalated_by, escalated_to, escalated_at, reason, resolved |
| `assets` | asset_id | cse_id, asset_name, asset_type, criticality, ip_address, hostname, last_seen |
| `entities` | entity_id | entity_type, identifier, cse_id, first_seen, last_seen, linked_asset_ids |
| `findings` | finding_id | alert_id, cse_id, engine, finding_type, severity, score, evidence (JSON TEXT) |
| `risk_scores` | cse_id | overall_score, risk_level, breakdown_json (INSERT OR REPLACE) |
| `telemetry_baseline` | (asset_id, hour_of_day) | mu_logs, sigma_logs |
| `threat_intel_iocs` | ioc_id | ioc_type, ioc_value, threat_actor, malware_family, confidence, mitre_tactics, mitre_techniques |
| `threat_intel_cves` | cve_id | description, cvss_score, affected_products, published_date |
| `threat_intel_bundles` | bundle_id | version, sha256, record_count, status |
| `traceback_reports` | incident_id | cse_id, finding_id, confidence_score, why_flagged, narrative, stages_json, ioc_matches_json, evidence_ids_json, graph_json |
| `users` | user_id | username UNIQUE, email UNIQUE, password_hash, role |
| `audit_logs` | log_id | action, user_id, username, role, target_entity, details_json, timestamp |
| `reviews` | review_id | finding_id, cse_id, reviewer, reviewer_role, decision, notes, investigation_requested |
| `feedback_logs` | log_id | engine, rule_id, suggested_change, justification, status |

**Design notes**: `cases.linked_alert_ids` is VARCHAR (comma-separated, queried via LIKE). `findings.evidence` is TEXT (JSON). `risk_scores` is replaced per run (not appended).

---

## 5. Frontend Pages and Components

### Routes (`App.tsx` — 12 routes)

| Route | Page Component | Primary APIs Called |
|---|---|---|
| `/` or `/overall-risk` | OverallRiskView | getRiskScores, getPeerBenchmarks, getKPIs, runAnalytics |
| `/cse-analysis` | CseAnalysisView | getRiskScoreBreakdown, getFindings, getTracebackReport |
| `/attack-path` | AttackPathView | getTracebackReport, triggerTraceback, getTracebackGraph |
| `/findings` | KeyFindingsView | getFindings, getDrilldown, getFindingById |
| `/peer-comparison` | PeerComparisonView | getPeerBenchmarks |
| `/drilldown` | DrilldownView | getDrilldown, getTracebackReport |
| `/reviews` | ReviewQueueView | getReviewQueue, submitReview, getFindingReviewHistory |
| `/feedback` | FeedbackLogView | getFeedbackStats, feedback suggestion endpoints |
| `/export` | ExportReportsView | getCsePdfReportUrl, getFindingsCsvUrl, getAuditLogs |
| `/admin` | AdminAuditView | getAuditLogs, getSystemStatus, getDemoUsers, switchRole |
| `/upload` | UploadPage | ingestFile, getCseStats, getIngestStatus |
| `/normalization` | NormalizationPage | getNormalizationPreview, getRejects |

### Components

| Component | Role |
|---|---|
| Layout | Sidebar nav, header, role-switcher pill, Outlet |
| EvidenceDrawer | Slide-over: raw alert, case linkage, investigations |
| ReviewModal | VALID / FALSE_POSITIVE / NEEDS_MORE_DATA form + notes |
| FilterBar | Multi-attribute filter (CSE, severity, engine, date) |
| StatCard | KPI tile |
| RiskBadge | Color-coded risk badge |
| StageCard | Attack stage card (tactic/technique/evidence IDs) |
| EvidenceChip | Small chip linking to an evidence ID |

---

## 6. End-to-End Data Flow

```
[1] CSE File Upload
    POST /api/ingest/{cse_id}/{data_type}  (CSV or JSON)
    -> orchestrator.run_pipeline()
       Stage 1: validate()        -> rejects table
       Stage 2: clean()           -> dedup, trim
       Stage 3: normalize()       -> severity canonical, timestamps UTC, IPs valid
       Stage 4: map_entities()    -> entities table
       Stage 5: store()           -> alerts/cases/escalations/assets + ingest_batches

[2] Analytics Run
    POST /api/analytics/run
    -> RuleEngine.run()             -> violations on alerts/cases/escalations
    -> AnomalyDetectionEngine.run() -> Z-score + Isolation Forest on daily aggregates
    -> PeerBenchmarkingEngine.run() -> cross-CSE cohort comparison
    -> ExecutionGapEngine.run()     -> MTTR Z-score + TF-IDF note analysis
    -> NegativeSpaceEngine.run()    -> silent assets + zero-category detection
    -> persist_findings()           -> findings table (DELETE+INSERT, idempotent)
    -> update_risk_scores()         -> risk_scores table (INSERT OR REPLACE)

[3] Threat Intel Import (manual)
    POST /api/threat-intel/import
    -> verify_bundle_checksum() SHA-256
    -> import_threat_intel_bundle()
    -> threat_intel_iocs + threat_intel_cves + threat_intel_bundles tables

[4] Attack Traceback
    POST /api/traceback/run  OR  GET /api/traceback/{finding_id}
    -> cluster_candidate_incidents() NetworkX connected components
    -> build_attack_path()           5 MITRE stages + confidence
    -> build_event_graph()           MultiDiGraph enriched with CTI IOC labels
    -> graph_to_react_flow()         {nodes, edges} JSON
    -> Fetch last 5 reviews          injected into LLM prompt
    -> llm.generate()                MockLLM or OllamaLLM
    -> verify_llm_claims()           strip hallucinated evidence_ids
    -> traceback_reports table

[5] Dashboard Display
    React frontend GET requests:
    GET /api/analytics/risk-scores  -> OverallRiskView CSE cards
    GET /api/analytics/findings     -> KeyFindingsView table
    GET /api/dashboard/peer-benchmarks -> PeerComparisonView
    GET /api/traceback/{id}         -> AttackPathView React Flow graph
    GET /api/dashboard/drilldown    -> DrilldownView evidence chain

[6] Human Review
    POST /api/reviews/
    -> reviews table (decision: VALID / FALSE_POSITIVE / NEEDS_MORE_DATA)
    -> if FALSE_POSITIVE: feedback_logs entry (PENDING)
    -> audit_logs entry

[7] Feedback Loop
    GET /api/feedback/fp-rates      -> per-engine FP rates
    GET /api/feedback/suggestions   -> pending proposals
    POST /api/feedback/approve/{id} -> status=APPROVED in DB (YAML unchanged)
    Next traceback run reads last 10 reviews -> injects into LLM prompt

[8] Export
    GET /api/export/pdf/cse/{cse_id}  -> ReportLab PDF (offline)
    GET /api/export/findings/csv      -> CSV download
```

---

## 7. External Dependencies

| Dependency | Purpose | Online/Offline |
|---|---|---|
| DuckDB | Embedded analytics DB | Fully offline |
| Ollama | Local LLM inference | Offline (localhost:11434) |
| MockLLM | Deterministic LLM fallback | Built-in, always offline |
| CTI bundle files | Threat intel KB | Manual import; no online pull |
| ReportLab | PDF generation | Python lib, fully offline |
| scikit-learn | Isolation Forest, TF-IDF | Fully offline |
| NetworkX | Alert correlation graph | Fully offline |

**No HTTP calls to any external endpoint exist in the codebase.** Genuinely air-gapped.

---

## 8. Gaps and Incomplete Features

| # | Gap | Detail |
|---|---|---|
| 1 | Hash-chained audit ledger | README claims cryptographic chaining; actual is append-only DuckDB INSERT with no SHA-256 chain between rows |
| 2 | Feedback auto-apply to YAML | Approved proposals update `feedback_logs.status` in DB but never modify YAML rule files. Manual operator action required. |
| 3 | Telemetry baseline table | `telemetry_baseline` is defined in `models.py` but never populated by any code. `NegativeSpaceEngine.run()` never calls the standalone `telemetry_blackout_detection()` function. |
| 4 | Online CTI collector | No TAXII/MISP/feed scraper exists. Import is manual bundle upload only. |
| 5 | STIX 2.1 ingestion | README mentions STIX 2.1 input format. No STIX parsing library or code exists — only CSV/JSON accepted. |
| 6 | Dead router `reviews.py` | `routers/reviews.py` (11 KB) exists but is NOT mounted in `main.py`. Only `routers/review.py` is active. `reviews.py` is dead code. |
| 7 | `GET /api/export/pdf/finding/{finding_id}` | Referenced in `api.ts` as `getFindingPdfReportUrl()` but no route in `export.py`. Only CSE-level PDF exists. |
| 8 | JWT hardcoded default secret | `auth.py` defaults to literal string. Acceptable for air-gapped demo; must be rotated for any real deployment. |
| 9 | No bcrypt | Passwords use `SHA-256(satsa_salt_ + pw)`. Acceptable for internal demo only. |
| 10 | `cases.linked_alert_ids` design | VARCHAR column queried via `LIKE '%' || alert_id || '%'` — false-positive risk for substring matches; no index support. |
| 11 | No rate limiting | No request-size limits or rate limiting. Analytics/dashboard endpoints require no auth token in dev fallback mode. |
| 12 | `database.py` duplication | 266-byte file re-exporting `get_connection` from `models`. Some routers import from `database`, others from `models` — inconsistency not a bug but messy. |

---

## 9. Summary

SAT-SA is a well-implemented, largely functional offline supervisory analytics platform.
The 5-stage pipeline, all 5 analytics engines, risk scoring, attack traceback,
human review, feedback loop, PDF/CSV export, and RBAC are all coded and operational.

**Strongest parts**: ExecutionGapEngine's TF-IDF note analysis,
PeerBenchmarkingEngine's cohort metrics, the traceback service
(NetworkX + LLM + evidence verifier chain), and the composite risk formula.

**Honest caveats**: The hash-chained audit ledger is append-only DuckDB (not cryptographically chained).
Feedback approval does not modify YAML rules. The `telemetry_baseline` table is defined but
never populated. STIX 2.1 ingestion is documented but not implemented.
One router file is dead code. The finding-level PDF export is referenced in the frontend
client but the backend route does not exist.

The platform is genuinely offline-first and production-deployable for supervised SOC oversight workflows.
