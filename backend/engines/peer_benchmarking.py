"""
Peer Benchmarking Engine
Compares CSEs against cohort and sector peers across four core operational metrics:
1. Alerts per monitored asset (normalization by infrastructure size)
2. Mean Time to Close (MTTR) on high-severity alerts (identifying closure anomalies)
3. Escalation rate (identifying under-reporting and failure to escalate)
4. Investigation coverage (% of opened cases with formal investigation records)
Flags statistical outliers with evidence links.
"""

from typing import Dict, List, Optional
import duckdb
import numpy as np

from .base import Engine, Finding, register_engine


@register_engine
class PeerBenchmarkingEngine(Engine):
    name = "PeerBenchmarkingEngine"
    description = "Benchmarks CSE operational efficiency and escalation rates against sector cohorts to identify supervisory outliers."

    def run(self, db: duckdb.DuckDBPyConnection, cse_id: Optional[str] = None) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Fetch all CSEs and their sectors
        cses_data = db.execute("SELECT cse_id, cse_name, sector FROM cses").fetchall()
        if not cses_data:
            # Fallback to distinct cse_ids in alerts
            rows = db.execute("SELECT DISTINCT cse_id FROM alerts").fetchall()
            cses_data = [(r[0], r[0], "general") for r in rows if r[0]]

        if len(cses_data) < 2:
            return findings

        # 2. Gather metrics per CSE
        metrics: Dict[str, Dict] = {}
        for cid, cname, sector in cses_data:
            # Alert count
            alert_cnt = db.execute("SELECT COUNT(*) FROM alerts WHERE cse_id = ?", [cid]).fetchone()[0]
            # Asset count
            asset_cnt = db.execute("SELECT COUNT(*) FROM assets WHERE cse_id = ?", [cid]).fetchone()[0]
            if asset_cnt == 0:
                asset_cnt = db.execute("SELECT COUNT(DISTINCT asset_id) FROM alerts WHERE cse_id = ?", [cid]).fetchone()[0]
            asset_cnt = max(asset_cnt, 1)

            # MTTR on Critical / High
            mttr_res = db.execute("""
                SELECT AVG(mttr_seconds) FROM alerts
                WHERE cse_id = ? AND severity IN ('CRITICAL', 'HIGH') AND mttr_seconds IS NOT NULL
            """, [cid]).fetchone()[0]
            avg_mttr = float(mttr_res) if mttr_res is not None else 0.0

            # Escalation count
            esc_cnt = db.execute("SELECT COUNT(*) FROM escalations WHERE cse_id = ?", [cid]).fetchone()[0]
            esc_rate = (esc_cnt / max(alert_cnt, 1)) * 100.0

            # Case & Investigation count
            case_cnt = db.execute("SELECT COUNT(*) FROM cases WHERE cse_id = ?", [cid]).fetchone()[0]
            inv_cnt = db.execute("""
                SELECT COUNT(DISTINCT case_id) FROM investigations WHERE cse_id = ?
            """, [cid]).fetchone()[0]
            inv_cov = (inv_cnt / max(case_cnt, 1)) * 100.0 if case_cnt > 0 else 100.0

            metrics[cid] = {
                "cse_id": cid,
                "cse_name": cname,
                "sector": sector,
                "alert_count": alert_cnt,
                "asset_count": asset_cnt,
                "alerts_per_asset": round(alert_cnt / asset_cnt, 2),
                "critical_mttr_seconds": round(avg_mttr, 1),
                "escalation_rate_pct": round(esc_rate, 2),
                "investigation_coverage_pct": round(inv_cov, 2),
                "case_count": case_cnt,
                "escalation_count": esc_cnt,
            }

        # 3. Calculate cohort baselines
        all_cids = list(metrics.keys())
        mttrs = [m["critical_mttr_seconds"] for m in metrics.values() if m["critical_mttr_seconds"] > 0]
        esc_rates = [m["escalation_rate_pct"] for m in metrics.values()]
        inv_covs = [m["investigation_coverage_pct"] for m in metrics.values() if m["case_count"] > 0]
        alerts_per_assets = [m["alerts_per_asset"] for m in metrics.values()]

        median_mttr = float(np.median(mttrs)) if mttrs else 1800.0
        mean_mttr = float(np.mean(mttrs)) if mttrs else 1800.0
        median_esc = float(np.median(esc_rates)) if esc_rates else 15.0
        mean_esc = float(np.mean(esc_rates)) if esc_rates else 15.0
        median_inv = float(np.median(inv_covs)) if inv_covs else 80.0

        # Filter target CSEs if cse_id specified
        target_cids = [cse_id] if cse_id else all_cids

        # 4. Outlier analysis
        for cid in target_cids:
            if cid not in metrics:
                continue
            m = metrics[cid]

            # Metric A: Abnormally fast MTTR (Metric gaming / triage skipping)
            # Flag if critical MTTR < 150 seconds while peer median > 600s
            if m["critical_mttr_seconds"] > 0 and m["critical_mttr_seconds"] < 180 and median_mttr > 600:
                findings.append(Finding(
                    cse_id=cid,
                    engine=self.name,
                    finding_type="Peer Benchmark Outlier: Abnormally Fast Closure MTTR",
                    severity="HIGH",
                    description=(
                        f"CSE {cid} ({m['cse_name']}) reports Critical/High MTTR of {m['critical_mttr_seconds']:.0f}s "
                        f"({m['critical_mttr_seconds']/60:.1f} min), drastically below the supervisory peer median "
                        f"of {median_mttr:.0f}s ({median_mttr/60:.1f} min). Indicates perfunctory triage or SLA metric gaming."
                    ),
                    score=85.0,
                    evidence={
                        "metric": "critical_mttr_seconds",
                        "cse_value": m["critical_mttr_seconds"],
                        "peer_median": round(median_mttr, 1),
                        "peer_mean": round(mean_mttr, 1),
                        "sector": m["sector"],
                    },
                ))

            # Metric B: Under-escalation (Zero or near-zero escalation rate)
            # E.g. CSE-D has 0 escalations while peers average ~15%
            if m["escalation_rate_pct"] < 2.0 and median_esc > 5.0 and m["alert_count"] >= 20:
                findings.append(Finding(
                    cse_id=cid,
                    engine=self.name,
                    finding_type="Peer Benchmark Outlier: Low Escalation Rate",
                    severity="HIGH",
                    description=(
                        f"CSE {cid} ({m['cse_name']}) has an escalation rate of {m['escalation_rate_pct']:.1f}% "
                        f"({m['escalation_count']} escalations across {m['alert_count']} alerts), "
                        f"severely trailing the peer cohort median of {median_esc:.1f}%. "
                        f"Indicates institutional reluctance to escalate security incidents."
                    ),
                    score=80.0,
                    evidence={
                        "metric": "escalation_rate_pct",
                        "cse_value": m["escalation_rate_pct"],
                        "peer_median": round(median_esc, 2),
                        "peer_mean": round(mean_esc, 2),
                        "total_alerts": m["alert_count"],
                        "escalation_count": m["escalation_count"],
                    },
                ))

            # Metric C: Low Investigation Coverage
            # E.g. Case investigations < 30% while peer median > 60%
            if m["case_count"] >= 2 and m["investigation_coverage_pct"] < 35.0 and median_inv > 50.0:
                findings.append(Finding(
                    cse_id=cid,
                    engine=self.name,
                    finding_type="Peer Benchmark Outlier: Deficient Investigation Coverage",
                    severity="HIGH",
                    description=(
                        f"CSE {cid} formally investigated only {m['investigation_coverage_pct']:.1f}% of opened security cases "
                        f"(peer median: {median_inv:.1f}%). Violates supervisory expectation of forensic depth."
                    ),
                    score=75.0,
                    evidence={
                        "metric": "investigation_coverage_pct",
                        "cse_value": m["investigation_coverage_pct"],
                        "peer_median": round(median_inv, 2),
                        "case_count": m["case_count"],
                    },
                ))

            # Metric D: Alerts per asset imbalance
            if len(alerts_per_assets) >= 3:
                apa = m["alerts_per_asset"]
                apa_med = float(np.median(alerts_per_assets))
                if apa > 0 and apa_med > 0 and (apa > 4.0 * apa_med or apa < 0.15 * apa_med):
                    typ = "Excessive Alert Density" if apa > apa_med else "Unusually Sparse Telemetry"
                    sev = "MEDIUM"
                    findings.append(Finding(
                        cse_id=cid,
                        engine=self.name,
                        finding_type=f"Peer Benchmark Outlier: {typ}",
                        severity=sev,
                        description=(
                            f"CSE {cid} averages {apa:.1f} alerts/monitored asset (cohort median: {apa_med:.1f}). "
                            f"{'Potential alert fatigue or tuning failure' if apa > apa_med else 'Potential logging blind spot'}."
                        ),
                        score=60.0,
                        evidence={
                            "metric": "alerts_per_asset",
                            "cse_value": apa,
                            "cohort_median": apa_med,
                            "asset_count": m["asset_count"],
                            "alert_count": m["alert_count"],
                        },
                    ))

        return findings
