"""
Execution-Gap Engine
Detects gamed MTTR, rapid-closure anomalies, and copy-paste / template closure notes.
Exposes ExecutionGapEngine class inheriting from Engine base contract.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
import uuid

import duckdb
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from .base import Engine, Finding, register_engine

# ── Thresholds ──────────────────────────────────────────────────────────────
RAPID_CLOSURE_ZSCORE_THRESHOLD = 3.0
RAPID_CLOSURE_ABS_SECONDS = 120       # < 120s on a CRITICAL alert is flagged as suspicious rapid closure
TEMPLATE_NOTE_SIM_THRESHOLD = 0.90   # cosine similarity
TEMPLATE_NOTE_MIN_FRACTION = 0.70    # 70% of an analyst's notes must be similar


def zscore_mttr_anomalies(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Flags alerts where the analyst closed them suspiciously fast compared
    to category baselines or under absolute rapid closure SLA.
    """
    findings = []
    # Group by (category, severity)
    groups: Dict[str, List[float]] = {}
    for a in alerts:
        if a.get("mttr_seconds") is None:
            continue
        key = f"{a['category']}|{a['severity']}"
        groups.setdefault(key, []).append(float(a["mttr_seconds"]))

    for a in alerts:
        if a.get("mttr_seconds") is None:
            continue
        key = f"{a['category']}|{a['severity']}"
        times = groups[key]
        t = float(a["mttr_seconds"])

        mu = float(np.mean(times)) if len(times) >= 5 else 1800.0
        sigma = float(np.std(times)) if len(times) >= 5 and np.std(times) > 0 else 600.0
        zscore = (mu - t) / sigma

        flagged = False
        reason = ""
        sev = a.get("severity", "").upper()
        if sev == "CRITICAL" and t < RAPID_CLOSURE_ABS_SECONDS:
            flagged = True
            reason = f"CRITICAL alert closed in {t:.0f}s (< {RAPID_CLOSURE_ABS_SECONDS}s threshold without formal triage)"
        elif zscore > RAPID_CLOSURE_ZSCORE_THRESHOLD and len(times) >= 5:
            flagged = True
            reason = f"Rapid closure anomaly: Z-score={zscore:.2f} (threshold {RAPID_CLOSURE_ZSCORE_THRESHOLD}), μ={mu:.0f}s σ={sigma:.0f}s, actual={t:.0f}s"

        if flagged:
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "alert_id": a["alert_id"],
                "cse_id": a["cse_id"],
                "engine": "ExecutionGapEngine",
                "finding_type": "Execution Gap: Unjustified Rapid Closure",
                "severity": "CRITICAL" if sev == "CRITICAL" else "HIGH",
                "description": reason,
                "score": round(max(zscore, 75.0), 2),
                "evidence": {
                    "alert_id": a["alert_id"],
                    "category": a.get("category"),
                    "severity": a.get("severity"),
                    "mttr_seconds": t,
                    "analyst_id": a.get("analyst_id"),
                    "asset_id": a.get("asset_id"),
                    "closure_notes": a.get("closure_notes"),
                },
                "created_at": datetime.utcnow().isoformat(),
            })
    return findings


def template_note_anomalies(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Groups closure notes by analyst_id, computes pairwise cosine similarity
    of TF-IDF vectors, and flags analysts using templated copy-paste closure justifications.
    """
    findings = []
    analyst_notes: Dict[str, List[Dict]] = {}
    for a in alerts:
        note = (a.get("closure_notes") or "").strip()
        if not note or len(note) < 10:
            continue
        analyst_notes.setdefault(a["analyst_id"], []).append(a)

    for analyst_id, analyst_alerts in analyst_notes.items():
        if len(analyst_alerts) < 4:
            continue
        notes = [a["closure_notes"] for a in analyst_alerts]
        try:
            vect = TfidfVectorizer(min_df=1, stop_words="english").fit_transform(notes)
            sim_matrix = cosine_similarity(vect)
        except Exception:
            continue

        n = len(notes)
        high_sim_count = 0
        total_pairs = 0
        for i in range(n):
            for j in range(i + 1, n):
                total_pairs += 1
                if sim_matrix[i, j] >= TEMPLATE_NOTE_SIM_THRESHOLD:
                    high_sim_count += 1

        if total_pairs == 0:
            continue
        fraction = high_sim_count / total_pairs
        if fraction >= TEMPLATE_NOTE_MIN_FRACTION:
            sample_note = notes[0][:120]
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "alert_id": analyst_alerts[0]["alert_id"],
                "cse_id": analyst_alerts[0]["cse_id"],
                "engine": "ExecutionGapEngine",
                "finding_type": "Execution Gap: Superficial/Template Investigation",
                "severity": "HIGH",
                "description": (
                    f"Analyst {analyst_id}: {fraction*100:.1f}% of {n} closure notes "
                    f"match identical template phrasing (similarity ≥ {TEMPLATE_NOTE_SIM_THRESHOLD}). "
                    f"Sample: \"{sample_note}\""
                ),
                "score": round(fraction * 100, 1),
                "evidence": {
                    "analyst_id": analyst_id,
                    "case_count": n,
                    "similarity_fraction": round(fraction, 3),
                    "sample_note": sample_note,
                },
                "created_at": datetime.utcnow().isoformat(),
            })
    return findings


def run_execution_gap_engine(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings = []
    findings.extend(zscore_mttr_anomalies(alerts))
    findings.extend(template_note_anomalies(alerts))
    return findings


@register_engine
class ExecutionGapEngine(Engine):
    name = "ExecutionGapEngine"
    description = "Detects rapid closure anomalies, superficial triage, and template-based alert dismissals."

    def run(self, db: duckdb.DuckDBPyConnection, cse_id: Optional[str] = None) -> List[Finding]:
        query = """
            SELECT alert_id, cse_id, category, severity,
                   mttr_seconds, closure_notes, analyst_id, asset_id,
                   source_ip, dest_ip, created_at, closed_at
            FROM alerts
        """
        params = []
        if cse_id:
            query += " WHERE cse_id = ?"
            params.append(cse_id)

        rows = db.execute(query, params).fetchall()
        cols = [
            "alert_id", "cse_id", "category", "severity", "mttr_seconds",
            "closure_notes", "analyst_id", "asset_id", "source_ip", "dest_ip",
            "created_at", "closed_at"
        ]
        alerts = [dict(zip(cols, r)) for r in rows]

        raw_findings = run_execution_gap_engine(alerts)
        out = []
        for rf in raw_findings:
            out.append(Finding(
                finding_id=rf.get("finding_id", str(uuid.uuid4())),
                cse_id=rf["cse_id"],
                engine=self.name,
                finding_type=rf["finding_type"],
                severity=rf["severity"],
                description=rf["description"],
                alert_id=rf.get("alert_id"),
                score=float(rf.get("score") or 0.0),
                evidence=rf.get("evidence"),
                created_at=rf.get("created_at", datetime.utcnow().isoformat()),
            ))
        return out
