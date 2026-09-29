# SAT-SA Demo Workflow — SIH Video Script
**Generated from live system observation on 2026-09-29**
**Backend:** FastAPI/Uvicorn on `:8000` | **Frontend:** Vite React on `:5173`

> **Methodology**: This document was produced by actually running the backend and frontend, hitting every API endpoint with authenticated requests, measuring real response times, and inspecting the live React source. It describes what *currently works*, not what the architecture intends.

---

## Pre-Flight Checklist (Before Recording)

Run these once before the video session:

```bash
# Terminal 1 — Backend (from repo root)
backend\.venv\Scripts\uvicorn main:app --port 8000

# Terminal 2 — Frontend (from repo root)
cd frontend && npm run dev

# Terminal 3 — Seed / reset demo data (only needed if DB was wiped)
backend\.venv\Scripts\python scripts/seed_demo.py
```

**Confirm both are alive:**
- Backend: http://localhost:8000/api/health → `{"status":"operational"}`
- Frontend: http://localhost:5173 → loads without blank screen

**Live database state after seed:**

| Metric | Value |
|:---|---:|
| Total Alerts ingested | **803** (across 4 CSEs) |
| Total Findings generated | **175** (140 CRITICAL, 30 HIGH, 5 MEDIUM) |
| Attack traceback reports | **7** |
| Threat Intel IOCs | **4** |
| Threat Intel CVEs | **3** |
| Audit log entries | **27** |

---

## Sample Data to Use in the Demo (Reproducible)

Use these exact IDs — they are seeded deterministically and will exist after every `seed_demo.py` run:

| Item | ID / Value | Why |
|:---|:---|:---|
| **Primary CSE** | `CSE-A` (Alpha Power Grid, Power sector) | Has the most complete story: CRITICAL risk score, 5-stage APT traceback, CTI match, all finding types |
| **APT Incident case** | `S1-CASE-0001` — "APT Campaign — External IP 203.0.113.5" | Full multi-stage case with 12 linked alerts (S1-ALT-0001 through S1-ALT-0012) |
| **Best drilldown alert** | `S1-ALT-0001` | Suspicious Login → CRITICAL → links to Case, Investigation, and Attack Path |
| **Source IP (IOC match)** | `203.0.113.5` → threat actor `APT-VOLT-STORM-PROXY` (confidence 0.95) | The only IOC that matched in the live seed |
| **Second CSE to contrast** | `CSE-B` (Beta Banking Corp, Banking sector, score 75) | Good contrast: rapid closures in 36s, template investigation notes |
| **Negative Space finding** | `CSE-C` — CORE-SWITCH-01 (192.168.10.1), 0 alerts in 30 days | Most striking "silence = blind spot" demonstration |
| **Feedback proposal for live approval** | `fb-prop-01` (NS-R01 — PENDING) | Safe to approve on camera without breaking anything |
| **Review finding (PENDING)** | Any item in `/reviews/queue` where `review_status = PENDING` | 175 findings, all start unreviewed after fresh seed |

---

## Step-by-Step Demo Walkthrough

> **Format:** Step number, Screen name, What to do, What appears on screen, Real time taken, status

---

### STEP 1 — Application Boot

**Screen:** Browser fresh-open to `http://localhost:5173`
**Action:** Navigate to the URL. No login screen — app loads directly.

**What appears:**
- Dark-themed SOC console loads immediately.
- Left sidebar shows 12 navigation items.
- Top header bar: "National Critical Infrastructure Cyber Telemetry Console" with a pulsing green live dot.
- **Role Switcher** (Admin / Supervisor / Analyst) in the top-right header — click **Supervisor**.
- No login screen. The app auto-initialises using `localStorage`. The `switchRole` API call fires and stores a JWT Bearer token automatically.

**Time:** ~0.5s to first paint
**Demonstrates:** Air-gapped offline startup — no internet dependency, no cloud auth.
**Status:** WORKS

> **TIP:** Click the **Supervisor** role button in the top-right header before proceeding. This ensures authenticated API calls for review submission and exports.

---

### STEP 2 — Overall Risk Dashboard (Landing Screen)

**Screen:** `/` or `/overall-risk` — "Overall Risk View"
**Action:** Page auto-loads on app start. Observe KPIs and the risk scorecard grid.

**What appears:**
- 4 KPI stat cards at the top:
  - **803** Total Alerts
  - **175** Total Findings
  - **140** Critical Findings
  - **57.7 min** Avg Critical MTTR
- **Risk Scorecard grid** — 4 CSE cards with composite risk scores:
  - `CSE-A` Alpha Power Grid — **100 / 100 CRITICAL** (red)
  - `CSE-C` Charlie Telecom — **86 CRITICAL** (red)
  - `CSE-D` Delta Healthcare — **80 CRITICAL** (red)
  - `CSE-B` Beta Banking Corp — **75 CRITICAL** (red)
- A **Radar chart** (Recharts) showing per-component score breakdown.
- A **bar chart** comparing risk scores across CSEs.
- Each CSE card has an "→ View Details" button.
- "Run Analytics" button at top calls `POST /api/analytics/run` when clicked.

**Time to render:** ~1.0s (two parallel API calls: `/api/analytics/risk-scores` + `/api/dashboard/kpis`)
**Time if "Run Analytics" is clicked:** **3.68s** — account for this pause in video.
**Demonstrates:** Composite risk rollup across all 4 national critical sector entities.
**Status:** WORKS

---

### STEP 3 — CSE Deep-Dive (Alpha Power Grid)

**Screen:** `/cse-analysis` — "CSE-wise Analysis"
**Action:** Click "CSE-wise Analysis" in sidebar. Select `CSE-A` from the dropdown.

**What appears:**
- **Summary stats panel** for CSE-A:
  - 203 total alerts, 29 CRITICAL
  - Avg Critical MTTR: 55.7 min
  - 6 monitored assets, 33.8 alerts/asset
  - Escalation rate: 24.1%
  - 1 CTI threat actor match (`APT-VOLT-STORM-PROXY`)
- **Per-engine findings breakdown** bar chart.
- **Top findings list** — 10 highest-score findings with severity badges.
- **Recommendations panel** — 4 action items including "Execute emergency IR Plan: Multi-stage APT chain identified."
- "View Attack Path" button → navigates to `/attack-path?cse_id=CSE-A`.

**Time:** ~0.8s
**Demonstrates:** Per-entity supervisory deep-dive; multi-engine corroboration.
**Status:** WORKS

---

### STEP 4 — Upload Telemetry (Step 1 of 7-step plan)

**Screen:** `/upload` — "Upload Telemetry"
**Action:** Click "Upload Telemetry" in sidebar. Select CSE-A, data type = "alerts", drag or choose `data/synthetic/CSE-A/alerts.csv`.

**What appears:**
- Drag-and-drop upload zone with CSE colour coding (orange = Power sector).
- After clicking "Upload & Ingest":
  - Progress spinner appears (~2s).
  - Result card: rows received 456, **406 accepted, 50 rejected** (duplicates + schema failures filtered).
  - Batch ID shown.
- Upload history list at the bottom.

**Time:** ~2–3s per file
**Demonstrates:** Step 1 — Offline CSV telemetry ingestion with real-time validation feedback. The 50 rejections demonstrate schema validation catching malformed records — this is intentional.
**Status:** WORKS

---

### STEP 5 — Normalization Inspector (Step 2 of 7-step plan)

**Screen:** `/normalization` — "Normalization Data"
**Action:** Click "Normalization Data" in sidebar. Select CSE-A, data type = alerts.

**What appears:**
- Before/after comparison table:
  - `severity_before` vs `severity_after`
  - `created_at_iso` — ISO-8601 timestamp normalisation
  - `mttr_seconds` computed field
  - `source_ip`, `category` entity mapping
- Sample row: alert `939d61dc` — severity MEDIUM, timestamp `2025-08-19T10:52:44`, MTTR 1076.58s, category "Authentication Failure".

**Time:** ~0.5s
**Demonstrates:** Step 2 — ISO-8601 normalisation, severity standardisation, MTTR computation, all offline in DuckDB.
**Status:** WORKS

---

### STEP 6 — Key Findings (Analytics Engines Output)

**Screen:** `/findings` — "Key Findings"
**Action:** Click "Key Findings" in sidebar. Filter by `CSE-A`, severity = `CRITICAL`.

**What appears:**
- Filterable findings table: Engine, Finding Type, Severity, Score, Description.
- Top findings (most impactful):
  1. **RuleEngine** — "Unescalated Critical Alert: S1-ALT-0001 (Suspicious Login)" — score 90 — CRITICAL
  2. **ExecutionGapEngine** — "Unjustified Rapid Closure: S2-ALT-0013 closed in 36s" — CRITICAL score 75
  3. **AnomalyDetectionEngine** — log volume burst anomaly — HIGH
  4. **NegativeSpaceEngine** — CSE-C CORE-SWITCH-01 (192.168.10.1), 0 alerts in 30 days — CRITICAL score 95
- Clicking any row opens an **Evidence Drawer** (slide-in panel) with full alert metadata.
- "View Attack Path" button per finding.

**Finding counts by engine after seed:**

| Engine | Findings |
|:---|---:|
| RuleEngine | 124 |
| ExecutionGapEngine | 42 |
| AnomalyDetectionEngine | 8 |
| NegativeSpaceEngine | 1 |
| PeerBenchmarkingEngine | **0** |

**Time:** ~0.8s
**Demonstrates:** Step 4 — Output of all 5 supervisory analytics engines.
**Status:** WORKS (PeerBenchmarkingEngine caveat noted in broken items section)

---

### STEP 7 — Record Drill-Down (Alert S1-ALT-0001)

**Screen:** `/drilldown?alert_id=S1-ALT-0001`
**Action:** Click "Record Drill-down" in sidebar. Enter `S1-ALT-0001` in the alert ID field.

**What appears:**
- **Primary Alert:** S1-ALT-0001 — "Suspicious Login" — CRITICAL — Source IP `203.0.113.5` — Asset `SRV-APP-01` — MTTR 2700s (45 min) — Analyst `ANA-A01`
- **Linked Case:** `S1-CASE-0001` — "APT Campaign — External IP 203.0.113.5" — Status OPEN — 12 linked alerts (S1-ALT-0001 through S1-ALT-0012)
- **Investigation:** `S1-INV-0001` — Status ongoing — "Attacker IP 203.0.113.5 confirmed malicious. Escalated to Tier-3."
- **Timeline** of all alerts in the case chain.
- **Related Alerts** from CSE-A sharing asset or source IP.

**Time:** ~0.7s
**Demonstrates:** Evidence traceability — single alert → case → investigation → multi-stage chain.
**Status:** WORKS

---

### STEP 8 — Peer Comparison (Cross-CSE Benchmarking)

**Screen:** `/peer-comparison` — "Peer Benchmarks"
**Action:** Click "Peer Benchmarks" in sidebar.

**What appears:**
- Comparison table (4 CSEs side-by-side):

| Metric | CSE-A (Power) | CSE-B (Banking) | CSE-C (Telecom) |
|:---|---:|---:|---:|
| Total Alerts | 203 | 187 | 210 |
| Critical Alerts | 29 | 41 | 24 |
| Avg Critical MTTR (min) | 55.7 | 39.8 | 60.3 |
| Escalation Rate | 24.1% | 36.6% | **0%** |
| Investigation Coverage | 100% | **0%** | **0%** |

- Outlier callout for CSE-A: "Active correlation with 1 known CTI threat actor" — CRITICAL.
- CSE-C shows 0% escalation and 0% investigation coverage starkly.

**Time:** ~0.6s
**Demonstrates:** Cross-sector benchmarking, offline, no cloud.
**Status:** WORKS

---

### STEP 9 — Attack Path Graph (MOST VISUALLY IMPRESSIVE MOMENT)

**Screen:** `/attack-path?cse_id=CSE-A` — "Attack Path Graph"
**Action:** Click "Attack Path Graph" in sidebar, or "View Attack Path" from any CSE-A finding.

**What appears:**
- **React Flow interactive graph** — full 5-stage kill-chain reconstruction for CSE-A:
  1. **Stage 1 — Initial Access** (TA0001 / T1078): Suspicious Login via `S1-ALT-0001`, `S1-ALT-0002`
  2. **Stage 2 — Privilege Escalation** (TA0004 / T1068): via `S1-ALT-0003`, `S1-ALT-0004`
  3. **Stage 3 — Lateral Movement** (TA0008 / T1021.001): RDP tunnelling to SRV-APP-01 via `S1-ALT-0005`, `S1-ALT-0006`
  4. **Stage 4 — Data Access** (TA0009 / T1005): Database staging via `S1-ALT-0007`, `S1-ALT-0008`
  5. **Stage 5 — Log Tampering** (TA0005): Anti-forensics / evidence destruction
- Each node is colour-coded by severity (CRITICAL = red border).
- **IOC nodes** for attacker IPs (203.0.113.5, 29.165.221.251, 33.157.152.130).
- Zoom/pan/minimap controls (React Flow built-in).
- **Confidence score: 99.0%** displayed prominently.
- Incident title: "Multi-Stage Advanced Persistent Threat Campaign Reconstruction."
- Toggle between **Graph View** and **Timeline View**.
- Clicking a stage node opens **Evidence Drawer** with specific alert records.
- **"Run Traceback" button** triggers fresh reconstruction (`POST /api/traceback/run`).

**Time to load existing report:** ~0.8s
**Time to re-run traceback (mock LLM):** **2.37s**
**Demonstrates:** Step 5 — Multi-stage APT kill-chain with MITRE ATT&CK mapping, CTI correlation, React Flow visualisation.
**Status:** WORKS

> **GIVE THIS SCREEN THE MOST TIME. The animated React Flow graph with 5 kill-chain stages, MITRE tactic labels, and 99% confidence score is the single most visually impactful moment in the current build. Pan across the graph slowly, then click a stage node to show the evidence drawer sliding in.**

---

### STEP 10 — Review Queue (Human-in-the-Loop Adjudication)

**Screen:** `/reviews` — "Review Queue"
**Action:** Click "Review Queue" in sidebar. Click a CRITICAL finding row (e.g., NegativeSpaceEngine — Silent Critical Asset). Submit a review.

**What appears:**
- Summary bar: **175 PENDING** reviews on fresh seed.
- Filterable table: filter by CSE, status, free-text search.
- Click any row → **Review Modal** with:
  - Finding details (engine, type, severity, score, description)
  - Decision buttons: Valid / False Positive / Needs More Data
  - Notes text area
  - "Request Investigation" checkbox
- After submit: row updates with reviewer's decision + timestamp.

**Live demo action:**
1. Find NegativeSpaceEngine finding — "CORE-SWITCH-01 silent for 30 days" — score 95.
2. Click it → modal opens.
3. Select "VALID", type: "Core switch confirmed unmonitored — escalate to CSE-C SOC leadership."
4. Submit → confirmation toast appears.

**Time per review action:** ~2.0s (API + audit log write)
**Demonstrates:** Step 6 — Human review workflow with tamper-evident audit trail.
**Status:** WORKS

> Selecting "FALSE_POSITIVE" automatically creates a feedback proposal in the tuning queue — this is the bridge to Step 11.

---

### STEP 11 — Feedback Loop & Rule Tuning

**Screen:** `/feedback` — "Feedback Loop"
**Action:** Click "Feedback Loop" in sidebar. Approve one pending proposal.

**What appears:**
- **Rule Tuning Suggestions** panel — 4 pre-seeded proposals:
  1. `fb-prop-01` — NegativeSpaceEngine NS-R01: "Adjust silence window from 4h to 6h" — **PENDING**
  2. `fb-prop-02` — ExecutionGapEngine EG-UNINVESTIGATED: "Extend SLA from 24h to 36h" — **APPROVED** (already approved in seed)
  3. `fb-prop-03` — AnomalyDetectionEngine AD-ZSCORE-BURST: "Increase Z-score from 2.5σ to 3.0σ" — **PENDING**
  4. `fb-prop-04` — PeerBenchmarkingEngine PB-MTTR-OUTLIER: "Relax IQR multiplier 1.5x to 2.0x" — **PENDING**
- Approve / Reject buttons per proposal.
- **Traceback Context panel** — supervisor feedback injected as LLM prompt context (visible proof of closed loop).
- Per-engine FP rate chart — populated after reviews in Step 10.

**Live demo action:** Click "Approve" on `fb-prop-01`. It flips to APPROVED.

**Time:** ~0.5s render, ~1.0s per approve action
**Demonstrates:** Step 7 — Adaptive rule tuning; threshold changes require explicit supervisor approval.
**Status:** WORKS (FP rate chart is empty on fresh seed; shows data after Step 10 reviews)

---

### STEP 12 — Export PDF Dossier

**Screen:** `/export` — "Reports & Export"
**Action:** Click "Reports & Export" in sidebar. Select CSE-A. Click "Download PDF Dossier".

**What appears:**
- 4 CSE dossier cards (name, sector, risk, findings count).
- Clicking "Download PDF" for CSE-A → browser download dialogue → PDF saves locally.
- "Download All Findings CSV" → downloads 55KB CSV with 176 rows.

**Time for PDF:** **~2.1s** (7,337 bytes, air-gapped ReportLab)
**Time for CSV:** **~2.1s** (55,319 bytes, 176 finding rows)
**Demonstrates:** Step 7 — Offline regulatory PDF + CSV export, zero cloud dependency.
**Status:** WORKS

> The PDF is functional but visually basic (plain ReportLab text, 7KB). Mention "offline regulatory dossier" and move on quickly — do not show PDF contents on screen.

---

### STEP 13 — Admin & Audit Trail

**Screen:** `/admin` — "Admin & Audit"
**Action:** Switch role to **Admin** (click "Admin" in role switcher). Click "Admin & Audit" in sidebar.

**What appears:**
- **System Status panel:** Live counts — 4 CSEs, 803 alerts, 175 findings, 3 users, 7 traceback reports, 4 IOCs, 3 CVEs, all from DuckDB.
- **Audit Log table:** Every supervisory action with timestamp, user, role, action type, target entity, IP address. After Step 10, the review submission appears here.
- **RBAC User panel:** 3 demo users with roles.

**Time:** ~1.0s
**Demonstrates:** Tamper-evident audit ledger; RBAC visibility; zero data leaves the machine.
**Status:** WORKS (Admin role only — Supervisor role returns 403 on audit-logs endpoint)

> Must be in **Admin** role before navigating here. Switch role first.

---

## Total Demo Time

| Step | Screen | Real Time |
|:---|:---|:---:|
| 1 | App boot | 5s |
| 2 | Overall Risk Dashboard | 25s |
| 3 | CSE Deep-Dive (CSE-A) | 20s |
| 4 | Upload Telemetry | 20s |
| 5 | Normalization Inspector | 15s |
| 6 | Key Findings | 25s |
| 7 | Record Drilldown (S1-ALT-0001) | 20s |
| 8 | Peer Comparison | 15s |
| 9 | **Attack Path Graph** | **50s** |
| 10 | Review Queue (submit 1 review) | 25s |
| 11 | Feedback Loop (approve 1 proposal) | 15s |
| 12 | Export PDF | 15s |
| 13 | Admin Audit Trail | 15s |
| **TOTAL** | | **~4 min 5s** |

Fits a **3:30–4:00 minute** video with concise narration.

**2:30 cut:** Remove Steps 4 (upload) and 5 (normalization) — focus on analytics, attack path, and review.

---

## Single Most Visually Impressive Moment

**Step 9: Attack Path Graph at `/attack-path?cse_id=CSE-A`**

- React Flow kill-chain graph: 5 connected stages with MITRE ATT&CK labels
- Colour-coded severity borders (CRITICAL = red)
- IOC nodes with CTI threat actor annotation
- 99% confidence score banner
- Evidence drawer slide-in on stage click
- Re-Analyse button fires a fresh reconstruction in 2.4s

**Give this screen 45–50 seconds of camera time.**

---

## What Is NOT Working (Cut From Demo Script)

| Feature | Original Step | Status | Why / What To Say Instead |
|:---|:---|:---|:---|
| **PeerBenchmarkingEngine findings** | Step 4 | 0 findings generated | The peer comparison *page* works; the engine output is empty. Remove "Peer Benchmarking Engine findings" from narrative. Show the UI page (Step 8), just don't claim engine-generated findings for it. |
| **Ollama/AI narrative generation** | Step 5 | MockLLM only | Ollama requires `docker compose --profile ai up -d`. Without it, MockLLM (deterministic fallback) is used. The attack graph still renders and the narrative reads well — but do NOT describe it as "AI-generated" unless Ollama is running. Say "automated kill-chain reconstruction." |
| **CTI bundle import via UI** | Step 3 | No UI page exists | `/api/threat-intel/import` endpoint works, but there is no frontend page for it. CTI is seeded via `seed_demo.py`. Do not promise on-camera STIX bundle upload. |
| **PDF visual quality** | Step 7 | Plain text, 7KB | Do not show PDF content on screen. Mention "offline regulatory dossier generation" and move on. |
| **FP rate chart on fresh seed** | Step 7 | Empty until reviews submitted | Submit a review in Step 10 first, then return to feedback. Or frame it as "will populate as supervisors adjudicate findings." |
| **Admin audit log for Supervisor** | Step 7 | 403 Forbidden | Switch to Admin role before Step 13. |

---

## Startup Commands (Copy-Paste)

```powershell
# In repo root
backend\.venv\Scripts\python scripts/seed_demo.py

# Terminal 1 — Backend
cd backend
.\.venv\Scripts\uvicorn main:app --port 8000

# Terminal 2 — Frontend
cd ..\frontend
npm run dev
```

**Demo accounts:**

| Role | Username | Password | Use For |
|:---|:---|:---|:---|
| Supervisor | `supervisor` | `Supervisor@123` | Steps 1–12 |
| Admin | `admin` | `Admin@123` | Step 13 only |
| Analyst | `analyst` | `Analyst@123` | Read-only (skip in demo) |

---

## Quick URL Reference

| Screen | URL |
|:---|:---|
| Overall Risk | `http://localhost:5173/` |
| CSE Analysis | `http://localhost:5173/cse-analysis` |
| Attack Path (CSE-A) | `http://localhost:5173/attack-path?cse_id=CSE-A` |
| Key Findings | `http://localhost:5173/findings` |
| Peer Comparison | `http://localhost:5173/peer-comparison` |
| Alert Drilldown | `http://localhost:5173/drilldown?alert_id=S1-ALT-0001` |
| Review Queue | `http://localhost:5173/reviews` |
| Feedback Loop | `http://localhost:5173/feedback` |
| Export Reports | `http://localhost:5173/export` |
| Admin & Audit | `http://localhost:5173/admin` |
| Upload Telemetry | `http://localhost:5173/upload` |
| Normalization | `http://localhost:5173/normalization` |
| Backend Swagger | `http://localhost:8000/docs` |
