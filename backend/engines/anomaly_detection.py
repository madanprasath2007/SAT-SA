"""
Anomaly Detection Engine
Detects temporal alert spikes/drops using statistical Z-scores and multi-feature
behavioral anomalies using Isolation Forest (alert volume, severity mix, asset breadth, MTTR).
Provides plain-language supervisor explanations.
"""

from datetime import datetime
from typing import Dict, List, Optional
import duckdb
import numpy as np
from sklearn.ensemble import IsolationForest

from .base import Engine, Finding, register_engine


@register_engine
class AnomalyDetectionEngine(Engine):
    name = "AnomalyDetectionEngine"
    description = "Detects statistical alert volume spikes, sensor drops, and multi-dimensional behavioral deviations."

    Z_SPIKE_THRESHOLD = 3.0
    Z_DROP_THRESHOLD = -2.5

    def run(self, db: duckdb.DuckDBPyConnection, cse_id: Optional[str] = None) -> List[Finding]:
        findings: List[Finding] = []

        # Get list of target CSEs
        if cse_id:
            cses = [cse_id]
        else:
            rows = db.execute("SELECT DISTINCT cse_id FROM alerts ORDER BY cse_id").fetchall()
            cses = [r[0] for r in rows if r[0]]

        for cse in cses:
            findings.extend(self._analyze_cse_anomalies(db, cse))

        return findings

    def _analyze_cse_anomalies(self, db: duckdb.DuckDBPyConnection, cse: str) -> List[Finding]:
        findings: List[Finding] = []

        # Daily aggregations
        query = """
            SELECT
                CAST(created_at AS DATE) as day,
                COUNT(*) as alert_count,
                SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as crit_count,
                SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high_count,
                COUNT(DISTINCT asset_id) as asset_count,
                COALESCE(AVG(mttr_seconds), 0.0) as avg_mttr
            FROM alerts
            WHERE cse_id = ? AND created_at IS NOT NULL
            GROUP BY day
            ORDER BY day
        """
        rows = db.execute(query, [cse]).fetchall()
        if len(rows) < 5:
            # Insufficient days to compute standard statistics
            return findings

        days = [str(r[0]) for r in rows]
        counts = np.array([float(r[1]) for r in rows])
        crits = np.array([float(r[2]) for r in rows])
        highs = np.array([float(r[3]) for r in rows])
        assets = np.array([float(r[4]) for r in rows])
        mttrs = np.array([float(r[5]) for r in rows])

        mean_cnt = float(np.mean(counts))
        std_cnt = float(np.std(counts))
        if std_cnt == 0.0:
            std_cnt = 1.0

        # Multi-feature matrix for Isolation Forest
        crit_ratios = np.divide(crits + highs, counts, out=np.zeros_like(counts), where=counts != 0)
        X = np.column_stack([counts, crit_ratios, assets, mttrs])

        # Isolation Forest detection
        try:
            contamination = max(0.02, min(0.15, 2.0 / len(rows)))
            iso = IsolationForest(contamination=contamination, random_state=42)
            iso_preds = iso.fit_predict(X)
            iso_scores = -iso.score_samples(X)  # Higher means more anomalous
        except Exception:
            iso_preds = np.zeros(len(rows))
            iso_scores = np.zeros(len(rows))

        for idx, day in enumerate(days):
            cnt = counts[idx]
            z_score = (cnt - mean_cnt) / std_cnt
            is_iso_anom = (iso_preds[idx] == -1)

            # Check 1: Volume Spike
            if z_score >= self.Z_SPIKE_THRESHOLD:
                sev = "CRITICAL" if z_score >= 5.0 else "HIGH"
                desc = (
                    f"Alert Volume Spike on {day}: CSE {cse} recorded {int(cnt)} alerts "
                    f"(30-day baseline mean: μ={mean_cnt:.1f}, σ={std_cnt:.1f}, Z=+{z_score:.2f}). "
                    f"High-priority ratio: {crit_ratios[idx]*100:.0f}%, impacting {int(assets[idx])} distinct assets. "
                    f"Indicates surge in adversary activity or automated scanning burst."
                )
                findings.append(Finding(
                    cse_id=cse,
                    engine=self.name,
                    finding_type="Anomaly: Alert Volume Spike",
                    severity=sev,
                    description=desc,
                    score=round(float(z_score), 2),
                    evidence={
                        "day": day,
                        "observed_count": int(cnt),
                        "baseline_mean": round(mean_cnt, 2),
                        "baseline_std": round(std_cnt, 2),
                        "z_score": round(float(z_score), 2),
                        "critical_high_ratio": round(float(crit_ratios[idx]), 3),
                        "impacted_assets": int(assets[idx]),
                        "isolation_forest_flag": bool(is_iso_anom),
                    },
                ))

            # Check 2: Volume Drop / Blackout
            elif z_score <= self.Z_DROP_THRESHOLD and mean_cnt >= 10:
                findings.append(Finding(
                    cse_id=cse,
                    engine=self.name,
                    finding_type="Anomaly: Alert Volume Drop",
                    severity="HIGH",
                    description=(
                        f"Alert Volume Drop on {day}: CSE {cse} recorded only {int(cnt)} alerts "
                        f"(baseline mean: μ={mean_cnt:.1f}, σ={std_cnt:.1f}, Z={z_score:.2f}). "
                        f"Abrupt drop may signal sensor failure, network partition, or log pipeline outage."
                    ),
                    score=round(abs(float(z_score)), 2),
                    evidence={
                        "day": day,
                        "observed_count": int(cnt),
                        "baseline_mean": round(mean_cnt, 2),
                        "baseline_std": round(std_cnt, 2),
                        "z_score": round(float(z_score), 2),
                    },
                ))

            # Check 3: Multi-feature Isolation Forest Anomaly (if not already flagged as simple spike)
            elif is_iso_anom and z_score < self.Z_SPIKE_THRESHOLD:
                findings.append(Finding(
                    cse_id=cse,
                    engine=self.name,
                    finding_type="Anomaly: Multi-Feature SOC Behavioral Deviation",
                    severity="MEDIUM",
                    description=(
                        f"Unusual SOC Operational Pattern on {day}: CSE {cse} exhibited anomalous "
                        f"correlation across alert volume ({int(cnt)}), critical ratio ({crit_ratios[idx]*100:.0f}%), "
                        f"and asset diversity ({int(assets[idx])} assets). Isolation Forest anomaly score: {iso_scores[idx]:.3f}."
                    ),
                    score=round(float(iso_scores[idx]) * 10, 2),
                    evidence={
                        "day": day,
                        "observed_count": int(cnt),
                        "critical_high_ratio": round(float(crit_ratios[idx]), 3),
                        "impacted_assets": int(assets[idx]),
                        "avg_mttr_seconds": round(float(mttrs[idx]), 1),
                        "anomaly_score": round(float(iso_scores[idx]), 4),
                    },
                ))

        return findings
