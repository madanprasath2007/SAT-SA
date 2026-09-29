"""
Composite Risk Scoring Engine v2
Calculates a supervisory risk score (0–100) per CSE combining:
1. Base supervisory findings (rules, anomalies, peer gaps, silent assets)
2. Threat Intelligence IOC correlation (matches against verified CTI feeds)
3. Attack Traceback confidence & multi-stage progression

Documented in docs/scoring.md.
"""

from datetime import datetime
import json
from typing import Any, Dict, List, Optional
import duckdb


def calculate_cse_risk(
    db: duckdb.DuckDBPyConnection, cse_id: str
) -> Dict[str, Any]:
    # 1. Fetch CSE info
    cse_row = db.execute("SELECT cse_id, cse_name, sector FROM cses WHERE cse_id = ?", [cse_id]).fetchone()
    cse_name = cse_row[1] if cse_row else cse_id
    sector = cse_row[2] if cse_row else "general"

    # 2. Fetch all findings for this CSE (auto-evaluate engines if findings have not been computed yet)
    rows = db.execute("""
        SELECT finding_id, engine, finding_type, severity, description, score, evidence, created_at
        FROM findings
        WHERE cse_id = ?
        ORDER BY score DESC, created_at DESC
    """, [cse_id]).fetchall()

    if not rows:
        try:
            from .base import get_all_engines, persist_findings
            engines = get_all_engines()
            auto_findings = []
            for eng in engines:
                try:
                    auto_findings.extend(eng.run(db, cse_id=cse_id))
                except Exception:
                    pass
            if auto_findings:
                persist_findings(db, auto_findings, cse_id=cse_id)
                rows = db.execute("""
                    SELECT finding_id, engine, finding_type, severity, description, score, evidence, created_at
                    FROM findings
                    WHERE cse_id = ?
                    ORDER BY score DESC, created_at DESC
                """, [cse_id]).fetchall()
        except Exception:
            pass

    cols = ["finding_id", "engine", "finding_type", "severity", "description", "score", "evidence", "created_at"]
    findings = []
    for r in rows:
        item = dict(zip(cols, r))
        if item.get("created_at") is not None:
            item["created_at"] = str(item["created_at"])
        findings.append(item)

    # Component 1: Rule Violations (Max 25 in v2)
    rule_findings = [f for f in findings if f["engine"] == "RuleEngine"]
    rv_crit = sum(1 for f in rule_findings if f["severity"] == "CRITICAL")
    rv_high = sum(1 for f in rule_findings if f["severity"] == "HIGH")
    rv_med = sum(1 for f in rule_findings if f["severity"] == "MEDIUM")
    rv_low = sum(1 for f in rule_findings if f["severity"] == "LOW")
    raw_rv_score = (rv_crit * 10.0) + (rv_high * 5.0) + (rv_med * 2.5) + (rv_low * 1.0)
    rule_score = min(25.0, raw_rv_score)

    # Component 2: Anomalies (Max 20 in v2)
    anom_findings = [f for f in findings if f["engine"] == "AnomalyDetectionEngine"]
    anom_crit = sum(1 for f in anom_findings if f["severity"] == "CRITICAL")
    anom_high = sum(1 for f in anom_findings if f["severity"] == "HIGH")
    anom_med = sum(1 for f in anom_findings if f["severity"] == "MEDIUM")
    raw_anom_score = (anom_crit * 12.0) + (anom_high * 7.0) + (anom_med * 3.0)
    anomaly_score = min(20.0, raw_anom_score)

    # Component 3: Peer Benchmark Deviations & Execution Gaps (Max 15 in v2)
    peer_eg_findings = [f for f in findings if f["engine"] in ("PeerBenchmarkingEngine", "ExecutionGapEngine")]
    peg_crit = sum(1 for f in peer_eg_findings if f["severity"] == "CRITICAL")
    peg_high = sum(1 for f in peer_eg_findings if f["severity"] == "HIGH")
    peg_med = sum(1 for f in peer_eg_findings if f["severity"] == "MEDIUM")
    raw_peer_score = (peg_crit * 10.0) + (peg_high * 6.0) + (peg_med * 3.0)
    peer_score = min(15.0, raw_peer_score)

    # Component 4: Silent Assets & Negative Space (Max 15 in v2)
    neg_findings = [f for f in findings if f["engine"] == "NegativeSpaceEngine"]
    silent_assets_count = sum(1 for f in neg_findings if "Silent Critical Asset" in f["finding_type"])
    coverage_gaps_count = sum(1 for f in neg_findings if "Missing Detection Coverage" in f["finding_type"] or "Blackout" in f["finding_type"])
    raw_silent_score = (silent_assets_count * 15.0) + (coverage_gaps_count * 5.0)
    silent_score = min(15.0, raw_silent_score)

    # ── Phase 3 / v2: Threat Intelligence Match Component (Max 25 pts) ────────
    matched_iocs = []
    try:
        ioc_rows = db.execute("""
            SELECT DISTINCT t.ioc_value, t.threat_actor, t.confidence, t.description
            FROM threat_intel_iocs t
            JOIN alerts a ON (a.source_ip = t.ioc_value OR a.dest_ip = t.ioc_value)
            WHERE a.cse_id = ?
        """, [cse_id]).fetchall()
        for r in ioc_rows:
            matched_iocs.append({
                "ioc_value": r[0],
                "threat_actor": r[1],
                "confidence": float(r[2] or 0.8),
                "description": r[3],
            })
    except Exception:
        pass

    ti_score = 0.0
    if matched_iocs:
        # Base 15 pts for any CTI match, plus confidence scaling up to 25 pts
        ti_score = min(25.0, 15.0 + sum(ioc["confidence"] * 10.0 for ioc in matched_iocs))

    # ── Phase 3 / v2: Attack Traceback Confidence & Multi-Stage Attack (Max 30 pts)
    traceback_score = 0.0
    traceback_meta = {}
    try:
        tb_row = db.execute("""
            SELECT confidence_score, stages_json, why_flagged
            FROM traceback_reports
            WHERE cse_id = ?
            ORDER BY created_at DESC LIMIT 1
        """, [cse_id]).fetchone()

        if tb_row:
            tb_conf = float(tb_row[0] or 0.0)
            stages = json.loads(tb_row[1]) if tb_row[1] else []
            stage_count = len(stages)

            # Traceback contribution: base confidence + stage completeness bonus
            stage_bonus = 10.0 if stage_count >= 4 else (stage_count * 2.0)
            traceback_score = min(30.0, (tb_conf / 100.0) * 20.0 + stage_bonus)
            traceback_meta = {
                "confidence_score": tb_conf,
                "stages_count": stage_count,
                "why_flagged": tb_row[2],
            }
        else:
            # Check if alerts contain multi-stage attack signatures even before formal report run
            # e.g., CSE-A S1 attack categories
            cat_count = db.execute("""
                SELECT COUNT(DISTINCT category) FROM alerts
                WHERE cse_id = ? AND category IN ('Suspicious Login', 'Privilege Escalation', 'Lateral Movement', 'File Access', 'Log Tampering')
            """, [cse_id]).fetchone()[0]
            if cat_count >= 4:
                traceback_score = 25.0
                traceback_meta = {"stages_detected": cat_count, "multi_stage_attack_detected": True}
    except Exception:
        pass

    # Total Composite Score (0–100)
    # Weights: base components (max 75) + Threat Intel (max 25) + Traceback (max 30) capped at 100
    subtotal = rule_score + anomaly_score + peer_score + silent_score + ti_score + traceback_score
    total_score = round(min(100.0, subtotal), 1)

    if total_score >= 75.0:
        risk_level = "CRITICAL"
    elif total_score >= 50.0:
        risk_level = "HIGH"
    elif total_score >= 25.0:
        risk_level = "MODERATE"
    else:
        risk_level = "LOW"

    # Actionable supervisory recommendations
    recs = []
    if matched_iocs:
        recs.append(f"CRITICAL: Active adversary presence detected. Block confirmed CTI indicator(s): {', '.join([ioc['ioc_value'] for ioc in matched_iocs])} at boundary firewalls.")
    if traceback_score >= 20.0:
        recs.append("Execute emergency Incident Response Plan: Multi-stage APT attack chain identified with lateral movement. Isolate compromised subnets.")
    if silent_assets_count > 0:
        recs.append("Conduct an immediate audit of silent critical assets. Re-verify EDR sensor health and syslog ingestion forwarding.")
    if rv_crit > 0:
        recs.append("Mandate emergency review of unescalated critical alerts. Verify SOC Tier 2/3 paging escalation pathways.")
    if anom_crit > 0 or anom_high > 0:
        recs.append("Investigate high-volume alert spike timestamps for coordinated multi-stage adversary campaigns or data exfiltration.")
    if any("Rapid Closure" in f["finding_type"] for f in peer_eg_findings):
        recs.append("Audit analyst closure practices; verify closure justifications to eliminate SLA gaming and perfunctory triage.")
    if not recs:
        recs.append("Maintain routine supervisory surveillance. All operational benchmarks within acceptable tolerances.")

    breakdown = {
        "cse_id": cse_id,
        "cse_name": cse_name,
        "sector": sector,
        "overall_score": total_score,
        "risk_level": risk_level,
        "version": "2.0.0",
        "calculated_at": datetime.utcnow().isoformat(),
        "components": {
            "rule_violations": {
                "score": round(rule_score, 1),
                "max": 25.0,
                "finding_count": len(rule_findings),
                "breakdown": {"critical": rv_crit, "high": rv_high, "medium": rv_med, "low": rv_low},
            },
            "anomalies": {
                "score": round(anomaly_score, 1),
                "max": 20.0,
                "finding_count": len(anom_findings),
                "breakdown": {"critical": anom_crit, "high": anom_high, "medium": anom_med},
            },
            "peer_deviations": {
                "score": round(peer_score, 1),
                "max": 15.0,
                "finding_count": len(peer_eg_findings),
                "breakdown": {"critical": peg_crit, "high": peg_high, "medium": peg_med},
            },
            "silent_assets": {
                "score": round(silent_score, 1),
                "max": 15.0,
                "finding_count": len(neg_findings),
                "silent_critical_assets": silent_assets_count,
                "coverage_gaps": coverage_gaps_count,
            },
            "threat_intelligence": {
                "score": round(ti_score, 1),
                "max": 25.0,
                "matched_iocs": matched_iocs,
                "match_count": len(matched_iocs),
            },
            "attack_traceback": {
                "score": round(traceback_score, 1),
                "max": 30.0,
                "meta": traceback_meta,
            },
        },
        "total_findings": len(findings),
        "top_findings": findings[:5],
        "recommendations": recs,
    }

    return breakdown


def update_risk_scores(
    db: duckdb.DuckDBPyConnection, cse_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    if cse_id:
        cses = [cse_id]
    else:
        rows = db.execute("SELECT DISTINCT cse_id FROM cses").fetchall()
        cses = [r[0] for r in rows if r[0]]
        if not cses:
            rows = db.execute("SELECT DISTINCT cse_id FROM alerts").fetchall()
            cses = [r[0] for r in rows if r[0]]

    results = []
    for cid in cses:
        b = calculate_cse_risk(db, cid)
        db.execute("""
            INSERT OR REPLACE INTO risk_scores (cse_id, overall_score, risk_level, breakdown_json, calculated_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, [cid, b["overall_score"], b["risk_level"], json.dumps(b, default=str)])
        results.append(b)

    return results
