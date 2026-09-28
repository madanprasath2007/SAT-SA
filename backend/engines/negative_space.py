"""
Negative-Space Engine
Detects telemetry blackouts and zero-alert category anomalies.
"""

import uuid
from datetime import datetime
from typing import List, Dict, Any

import numpy as np

BLACKOUT_ZSCORE_THRESHOLD = -2.5     # z < -2.5 during business hours
ZERO_ALERT_PEER_MIN_AVG = 50         # peers must average > 50 alerts for comparison


def telemetry_blackout_detection(
    telemetry_obs: List[Dict[str, Any]],
    baselines: Dict[str, Dict[int, Dict[str, float]]],
) -> List[Dict[str, Any]]:
    """
    telemetry_obs: list of {asset_id, cse_id, hour_of_day, log_count}
    baselines:     {asset_id: {hour_of_day: {mu, sigma}}}

    Flags observations where Z-score < -2.5 during business hours (8-20).
    """
    findings = []
    for obs in telemetry_obs:
        asset_id = obs["asset_id"]
        hour = int(obs["hour_of_day"])
        if not (8 <= hour <= 20):
            continue  # only flag during business hours
        if asset_id not in baselines:
            continue
        if hour not in baselines[asset_id]:
            continue
        mu = baselines[asset_id][hour]["mu"]
        sigma = baselines[asset_id][hour]["sigma"]
        if sigma == 0:
            sigma = 1.0
        v_actual = float(obs["log_count"])
        z = (v_actual - mu) / sigma
        if z < BLACKOUT_ZSCORE_THRESHOLD:
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "alert_id": None,
                "cse_id": obs.get("cse_id"),
                "engine": "NegativeSpaceEngine",
                "finding_type": "Negative Space: Critical Asset Telemetry Blackout",
                "severity": "CRITICAL",
                "description": (
                    f"Asset {asset_id} at hour {hour:02d}:00 — "
                    f"observed {v_actual:.0f} logs, baseline μ={mu:.1f} σ={sigma:.1f}, "
                    f"Z={z:.2f} (threshold {BLACKOUT_ZSCORE_THRESHOLD})"
                ),
                "score": round(z, 3),
                "created_at": datetime.utcnow().isoformat(),
            })
    return findings


def zero_alert_category_anomalies(
    cse_alert_counts: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    cse_alert_counts: list of {cse_id, category, alert_count (over 30 days)}

    For each category, computes peer average. Flags CSEs with 0 alerts
    when the peer average exceeds ZERO_ALERT_PEER_MIN_AVG.
    """
    findings = []
    # Group by category
    categories: Dict[str, List[Dict]] = {}
    for row in cse_alert_counts:
        categories.setdefault(row["category"], []).append(row)

    for category, rows in categories.items():
        counts = [r["alert_count"] for r in rows]
        peer_avg = float(np.mean(counts))
        if peer_avg < ZERO_ALERT_PEER_MIN_AVG:
            continue
        for row in rows:
            if row["alert_count"] == 0:
                findings.append({
                    "finding_id": str(uuid.uuid4()),
                    "alert_id": None,
                    "cse_id": row["cse_id"],
                    "engine": "NegativeSpaceEngine",
                    "finding_type": "Negative Space: Missing Detection Coverage",
                    "severity": "HIGH",
                    "description": (
                        f"CSE {row['cse_id']} reported 0 alerts in category "
                        f"'{category}' over 30 days. "
                        f"Peer average: {peer_avg:.0f} alerts."
                    ),
                    "score": 0.0,
                    "created_at": datetime.utcnow().isoformat(),
                })
    return findings


def run_negative_space_engine(
    telemetry_obs: List[Dict[str, Any]],
    baselines: Dict[str, Dict[int, Dict[str, float]]],
    cse_alert_counts: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    findings = []
    findings.extend(telemetry_blackout_detection(telemetry_obs, baselines))
    findings.extend(zero_alert_category_anomalies(cse_alert_counts))
    return findings
