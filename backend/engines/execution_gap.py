"""
Execution-Gap Engine
Detects gamed MTTR, rapid-closure anomalies, and copy-paste closure notes.
"""

import uuid
from datetime import datetime
from typing import List, Dict, Any

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# ── Z-score threshold for MTTR anomaly ──────────────────────────────────────
RAPID_CLOSURE_ZSCORE_THRESHOLD = 3.0
RAPID_CLOSURE_ABS_SECONDS = 30        # < 30 s on a CRITICAL alert is always flagged
TEMPLATE_NOTE_SIM_THRESHOLD = 0.92   # cosine similarity
TEMPLATE_NOTE_MIN_FRACTION = 0.80    # 80 % of an analyst's notes must be similar


def zscore_mttr_anomalies(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Flags alerts where the analyst closed them suspiciously fast compared
    to the per-category mean/std of closure times.
    Returns a list of finding dicts.
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
        if len(times) < 5:
            continue  # not enough peers to compute a meaningful baseline
        mu = np.mean(times)
        sigma = np.std(times) if np.std(times) > 0 else 1.0
        t = float(a["mttr_seconds"])
        zscore = (mu - t) / sigma

        flagged = False
        reason = ""
        if a["severity"].upper() == "CRITICAL" and t < RAPID_CLOSURE_ABS_SECONDS:
            flagged = True
            reason = f"CRITICAL alert closed in {t:.0f}s (< 30 s absolute threshold)"
        elif zscore > RAPID_CLOSURE_ZSCORE_THRESHOLD:
            flagged = True
            reason = f"Z-score={zscore:.2f} (threshold {RAPID_CLOSURE_ZSCORE_THRESHOLD}), μ={mu:.0f}s σ={sigma:.0f}s, actual={t:.0f}s"

        if flagged:
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "alert_id": a["alert_id"],
                "cse_id": a["cse_id"],
                "engine": "ExecutionGapEngine",
                "finding_type": "Execution Gap: Unjustified Rapid Closure",
                "severity": "HIGH",
                "description": reason,
                "score": round(zscore, 3),
                "created_at": datetime.utcnow().isoformat(),
            })
    return findings


def template_note_anomalies(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Groups closure notes by analyst_id, computes pairwise cosine similarity
    of TF-IDF vectors, and flags analysts whose notes are > 92% similar
    across > 80% of their cases.
    """
    findings = []
    # Group by analyst
    analyst_notes: Dict[str, List[Dict]] = {}
    for a in alerts:
        note = (a.get("closure_notes") or "").strip()
        if not note or len(note) < 10:
            continue
        analyst_notes.setdefault(a["analyst_id"], []).append(a)

    for analyst_id, analyst_alerts in analyst_notes.items():
        if len(analyst_alerts) < 5:
            continue
        notes = [a["closure_notes"] for a in analyst_alerts]
        try:
            vect = TfidfVectorizer(min_df=1, stop_words="english").fit_transform(notes)
        except ValueError:
            continue
        sim_matrix = cosine_similarity(vect)

        # Count pairs above threshold
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
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "alert_id": analyst_alerts[0]["alert_id"],
                "cse_id": analyst_alerts[0]["cse_id"],
                "engine": "ExecutionGapEngine",
                "finding_type": "Execution Gap: Superficial/Template Investigation",
                "severity": "MEDIUM",
                "description": (
                    f"Analyst {analyst_id}: {fraction*100:.1f}% of {n} closure notes "
                    f"have cosine similarity ≥ {TEMPLATE_NOTE_SIM_THRESHOLD} "
                    f"(threshold: {TEMPLATE_NOTE_MIN_FRACTION*100:.0f}%)"
                ),
                "score": round(fraction, 3),
                "created_at": datetime.utcnow().isoformat(),
            })
    return findings


def run_execution_gap_engine(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings = []
    findings.extend(zscore_mttr_anomalies(alerts))
    findings.extend(template_note_anomalies(alerts))
    return findings
