"""
Negative-Space Engine
Detects telemetry blackouts, silent critical assets with zero visibility,
and missing threat detection category coverage.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
import uuid

import duckdb
import numpy as np

from .base import Engine, Finding, register_engine

BLACKOUT_ZSCORE_THRESHOLD = -2.5     # z < -2.5 during business hours
ZERO_ALERT_PEER_MIN_AVG = 5.0        # peers must average >= 5 alerts for category coverage check


def telemetry_blackout_detection(
    telemetry_obs: List[Dict[str, Any]],
    baselines: Dict[str, Dict[int, Dict[str, float]]],
) -> List[Dict[str, Any]]:
    findings = []
    for obs in telemetry_obs:
        asset_id = obs["asset_id"]
        hour = int(obs["hour_of_day"])
        if not (8 <= hour <= 20):
            continue  # only flag during business hours
        if asset_id not in baselines or hour not in baselines[asset_id]:
            continue
        mu = baselines[asset_id][hour]["mu"]
        sigma = baselines[asset_id][hour]["sigma"] or 1.0
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
                "score": round(abs(z) * 10, 2),
                "evidence": {
                    "asset_id": asset_id,
                    "hour_of_day": hour,
                    "observed_logs": v_actual,
                    "baseline_mean": mu,
                    "baseline_std": sigma,
                    "z_score": round(z, 2),
                },
                "created_at": datetime.utcnow().isoformat(),
            })
    return findings


def zero_alert_category_anomalies(
    cse_alert_counts: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    findings = []
    categories: Dict[str, List[Dict]] = {}
    for row in cse_alert_counts:
        categories.setdefault(row["category"], []).append(row)

    for category, rows in categories.items():
        counts = [r["alert_count"] for r in rows]
        peer_avg = float(np.mean(counts)) if counts else 0.0
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
                        f"'{category}' over 30 days. Peer average: {peer_avg:.1f} alerts. "
                        f"Indicates disabled detection rule or blind spot in log pipeline."
                    ),
                    "score": 75.0,
                    "evidence": {
                        "category": category,
                        "observed_count": 0,
                        "peer_average": round(peer_avg, 2),
                    },
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


@register_engine
class NegativeSpaceEngine(Engine):
    name = "NegativeSpaceEngine"
    description = "Identifies invisible attack surfaces, silent critical assets, and zero-alert category blind spots."

    def run(self, db: duckdb.DuckDBPyConnection, cse_id: Optional[str] = None) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Silent Critical Assets (Planted S3 Scenario & core negative space rule)
        query = """
            SELECT a.asset_id, a.cse_id, a.asset_name, a.asset_type, a.criticality,
                   COALESCE(a.ip_address, '') as ip_address,
                   COALESCE(a.hostname, '') as hostname,
                   COUNT(alt.alert_id) as alert_count
            FROM assets a
            LEFT JOIN alerts alt ON a.asset_id = alt.asset_id
            WHERE a.criticality = 'CRITICAL'
        """
        params = []
        if cse_id:
            query += " AND a.cse_id = ?"
            params.append(cse_id)

        query += " GROUP BY a.asset_id, a.cse_id, a.asset_name, a.asset_type, a.criticality, a.ip_address, a.hostname"
        rows = db.execute(query, params).fetchall()

        for r in rows:
            asset_id, cid, aname, atype, crit, ip, host, alert_cnt = r
            if alert_cnt == 0:
                findings.append(Finding(
                    cse_id=cid,
                    engine=self.name,
                    finding_type="Negative Space: Silent Critical Asset",
                    severity="CRITICAL",
                    description=(
                        f"Critical asset {asset_id} ('{aname}', type: {atype}, IP: {ip or 'N/A'}) "
                        f"has recorded 0 security alerts across the entire 30-day supervisory period. "
                        f"Unmonitored high-criticality asset poses unmitigated compromise risk."
                    ),
                    score=95.0,
                    evidence={
                        "asset_id": asset_id,
                        "asset_name": aname,
                        "asset_type": atype,
                        "criticality": crit,
                        "ip_address": ip,
                        "hostname": host,
                        "alerts_observed": 0,
                    },
                ))

        # 2. Missing Detection Category Coverage across CSEs
        # Gather all distinct categories in alerts
        cats = db.execute("SELECT DISTINCT category FROM alerts WHERE category IS NOT NULL").fetchall()
        all_categories = [c[0] for c in cats]

        all_cses = [cse_id] if cse_id else [
            r[0] for r in db.execute("SELECT DISTINCT cse_id FROM cses").fetchall()
        ]

        if len(all_cses) >= 2 and all_categories:
            # Build matrix of counts
            counts_query = """
                SELECT cse_id, category, COUNT(*) as cnt
                FROM alerts
                WHERE category IS NOT NULL
                GROUP BY cse_id, category
            """
            c_rows = db.execute(counts_query).fetchall()
            counts_map = {(r[0], r[1]): r[2] for r in c_rows}

            for cat in all_categories:
                counts_for_cat = [counts_map.get((c, cat), 0) for c in all_cses]
                peer_avg = float(np.mean(counts_for_cat))
                if peer_avg >= ZERO_ALERT_PEER_MIN_AVG:
                    for cid in all_cses:
                        if counts_map.get((cid, cat), 0) == 0:
                            findings.append(Finding(
                                cse_id=cid,
                                engine=self.name,
                                finding_type="Negative Space: Missing Detection Coverage",
                                severity="HIGH",
                                description=(
                                    f"CSE {cid} reported 0 alerts in threat category '{cat}' over 30 days. "
                                    f"Peer cohort averaged {peer_avg:.1f} alerts. High risk of telemetry blind spot."
                                ),
                                score=75.0,
                                evidence={
                                    "category": cat,
                                    "observed_count": 0,
                                    "peer_average": round(peer_avg, 2),
                                },
                            ))

        return findings
