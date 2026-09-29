"""
Dashboard Router — Step 5 of SAT-SA pipeline.
Provides aggregated metrics for the React supervisor dashboard.
"""

from fastapi import APIRouter
from models import get_connection

router = APIRouter()


@router.get("/kpis")
def get_kpis():
    con = get_connection()
    total_alerts   = con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    total_findings = con.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    critical_findings = con.execute(
        "SELECT COUNT(*) FROM findings WHERE severity='CRITICAL'"
    ).fetchone()[0]
    high_findings = con.execute(
        "SELECT COUNT(*) FROM findings WHERE severity='HIGH'"
    ).fetchone()[0]
    cse_count = con.execute("SELECT COUNT(DISTINCT cse_id) FROM alerts").fetchone()[0]
    avg_mttr = con.execute(
        "SELECT AVG(mttr_seconds) FROM alerts WHERE severity='CRITICAL'"
    ).fetchone()[0] or 0
    con.close()
    return {
        "data": {
            "total_alerts":      total_alerts,
            "total_findings":    total_findings,
            "critical_findings": critical_findings,
            "high_findings":     high_findings,
            "cse_count":         cse_count,
            "avg_critical_mttr_minutes": round(avg_mttr / 60, 1),
        }
    }


@router.get("/mttr-distribution")
def mttr_distribution():
    con = get_connection()
    rows = con.execute("""
        SELECT category, severity,
               AVG(mttr_seconds)/60 as avg_mttr_min,
               MIN(mttr_seconds)/60 as min_mttr_min,
               MAX(mttr_seconds)/60 as max_mttr_min,
               COUNT(*) as alert_count
        FROM alerts
        GROUP BY category, severity
        ORDER BY category, severity
    """).fetchall()
    cols = ["category","severity","avg_mttr_min","min_mttr_min","max_mttr_min","alert_count"]
    con.close()
    return {"data": [dict(zip(cols, r)) for r in rows]}


@router.get("/cse-heatmap")
def cse_heatmap():
    """Finding counts per CSE per finding type — for risk heatmap."""
    con = get_connection()
    rows = con.execute("""
        SELECT cse_id, finding_type, COUNT(*) as count
        FROM findings
        GROUP BY cse_id, finding_type
        ORDER BY cse_id, count DESC
    """).fetchall()
    cols = ["cse_id","finding_type","count"]
    con.close()
    return {"data": [dict(zip(cols, r)) for r in rows]}


@router.get("/alert-timeline")
def alert_timeline():
    """Daily alert counts over the last 30 days by severity."""
    con = get_connection()
    rows = con.execute("""
        SELECT CAST(created_at AS DATE) as day, severity, COUNT(*) as count
        FROM alerts
        GROUP BY day, severity
        ORDER BY day
    """).fetchall()
    cols = ["day","severity","count"]
    con.close()
    return {"data": [dict(zip(cols, r)) for r in rows]}


@router.get("/findings-feed")
def findings_feed(limit: int = 20):
    """Latest findings for the live feed panel."""
    con = get_connection()
    rows = con.execute(f"""
        SELECT finding_id, cse_id, engine, finding_type, severity, description, score, created_at
        FROM findings
        ORDER BY created_at DESC
        LIMIT {limit}
    """).fetchall()
    cols = ["finding_id","cse_id","engine","finding_type","severity","description","score","created_at"]
    con.close()
    return {"data": [dict(zip(cols, r)) for r in rows]}


@router.get("/peer-benchmarks")
def get_peer_benchmarks():
    """
    Returns comparative benchmark metrics and outlier flags across all CSEs
    covering MTTR, escalation rates, investigation coverage, and volume per asset.
    """
    import numpy as np
    con = get_connection()

    cses_rows = con.execute("SELECT cse_id, cse_name, sector FROM cses ORDER BY cse_id").fetchall()
    if not cses_rows:
        # Fallback to distinct cses in alerts
        cses_rows = con.execute("SELECT DISTINCT cse_id, cse_id, 'Energy' FROM alerts ORDER BY cse_id").fetchall()

    benchmarks = []
    all_mttrs = []
    all_esc_rates = []
    all_inv_covs = []

    for cse_id, cse_name, sector in cses_rows:
        # Total alerts
        total_alerts = con.execute("SELECT COUNT(*) FROM alerts WHERE cse_id = ?", [cse_id]).fetchone()[0]
        # Critical alerts
        crit_alerts = con.execute("SELECT COUNT(*) FROM alerts WHERE cse_id = ? AND severity = 'CRITICAL'", [cse_id]).fetchone()[0]
        # Critical MTTR avg in seconds
        avg_crit_mttr = con.execute("SELECT AVG(mttr_seconds) FROM alerts WHERE cse_id = ? AND severity = 'CRITICAL'", [cse_id]).fetchone()[0] or 0.0

        # Monitored assets
        monitored_assets = con.execute("SELECT COUNT(DISTINCT asset_id) FROM alerts WHERE cse_id = ?", [cse_id]).fetchone()[0] or 1

        # Cases count
        cases_count = con.execute("SELECT COUNT(*) FROM cases WHERE cse_id = ?", [cse_id]).fetchone()[0]

        # Escalated critical alerts count
        # An alert is considered escalated if linked to a case or has escalation notes
        esc_cases = con.execute("""
            SELECT COUNT(DISTINCT a.alert_id)
            FROM alerts a
            JOIN cases c ON (c.cse_id = a.cse_id AND c.linked_alert_ids LIKE '%' || a.alert_id || '%')
            WHERE a.cse_id = ? AND a.severity = 'CRITICAL'
        """, [cse_id]).fetchone()[0]
        esc_rate = round((esc_cases / crit_alerts * 100.0), 1) if crit_alerts > 0 else 0.0

        # Investigation coverage (cases with at least one investigation)
        inv_cases = con.execute("""
            SELECT COUNT(DISTINCT case_id) FROM investigations WHERE cse_id = ?
        """, [cse_id]).fetchone()[0]
        inv_coverage = round((inv_cases / cases_count * 100.0), 1) if cases_count > 0 else 0.0

        # Findings count & severity breakdown
        finding_counts = con.execute("""
            SELECT severity, COUNT(*) FROM findings WHERE cse_id = ? GROUP BY severity
        """, [cse_id]).fetchall()
        sev_map = dict(finding_counts)

        # Matched CTI IOCs
        ioc_count = con.execute("""
            SELECT COUNT(DISTINCT t.ioc_value)
            FROM threat_intel_iocs t
            JOIN alerts a ON (a.source_ip = t.ioc_value OR a.dest_ip = t.ioc_value)
            WHERE a.cse_id = ?
        """, [cse_id]).fetchone()[0]

        benchmarks.append({
            "cse_id": cse_id,
            "cse_name": cse_name,
            "sector": sector or "Critical Infrastructure",
            "total_alerts": total_alerts,
            "critical_alerts": crit_alerts,
            "avg_critical_mttr": round(avg_crit_mttr, 1),
            "avg_critical_mttr_min": round(avg_crit_mttr / 60.0, 1),
            "monitored_assets": monitored_assets,
            "alerts_per_asset": round(total_alerts / monitored_assets, 1),
            "cases_count": cases_count,
            "escalation_rate": esc_rate,
            "investigation_coverage": inv_coverage,
            "ioc_count": ioc_count,
            "findings_critical": sev_map.get("CRITICAL", 0),
            "findings_high": sev_map.get("HIGH", 0),
            "findings_medium": sev_map.get("MEDIUM", 0),
            "findings_low": sev_map.get("LOW", 0),
            "total_findings": sum(sev_map.values()),
            "outliers": [],
        })

        if avg_crit_mttr > 0: all_mttrs.append(avg_crit_mttr)
        all_esc_rates.append(esc_rate)
        all_inv_covs.append(inv_coverage)

    # Calculate cohort medians
    median_mttr = float(np.median(all_mttrs)) if all_mttrs else 600.0
    median_esc = float(np.median(all_esc_rates)) if all_esc_rates else 20.0
    median_inv = float(np.median(all_inv_covs)) if all_inv_covs else 50.0

    # Tag outliers per benchmark rules
    for b in benchmarks:
        outliers = []
        if b["avg_critical_mttr"] > 0 and b["avg_critical_mttr"] < 120.0 and median_mttr > 300.0:
            outliers.append({
                "metric": "MTTR",
                "type": "gamed_rapid_closure",
                "description": f"Critical MTTR ({b['avg_critical_mttr_min']}m) suspiciously fast vs cohort median ({round(median_mttr/60, 1)}m) — indicates metric gaming.",
                "severity": "CRITICAL",
            })
        if b["critical_alerts"] >= 5 and b["escalation_rate"] < 2.0:
            outliers.append({
                "metric": "Escalation Rate",
                "type": "under_escalation",
                "description": f"Escalation rate ({b['escalation_rate']}%) near zero vs cohort median ({median_esc}%) — unescalated critical risk.",
                "severity": "CRITICAL",
            })
        if b["cases_count"] >= 3 and b["investigation_coverage"] < 35.0:
            outliers.append({
                "metric": "Investigation Coverage",
                "type": "uninvestigated_cases",
                "description": f"Case investigation coverage ({b['investigation_coverage']}%) below acceptable threshold (35%) vs cohort median ({median_inv}%).",
                "severity": "HIGH",
            })
        if b["ioc_count"] > 0:
            outliers.append({
                "metric": "Threat Intel Match",
                "type": "cti_match",
                "description": f"Active correlation with {b['ioc_count']} known CTI threat actor / campaign indicator(s).",
                "severity": "CRITICAL",
            })
        b["outliers"] = outliers

    con.close()
    return {
        "data": {
            "benchmarks": benchmarks,
            "medians": {
                "critical_mttr_seconds": round(median_mttr, 1),
                "critical_mttr_min": round(median_mttr / 60.0, 1),
                "escalation_rate": round(median_esc, 1),
                "investigation_coverage": round(median_inv, 1),
            }
        }
    }


@router.get("/drilldown")
def get_drilldown_data(
    finding_id: str = None,
    alert_id: str = None,
    case_id: str = None,
    cse_id: str = None,
    limit: int = 50,
):
    """
    Unified drill-down endpoint providing raw records, linked alerts, cases,
    investigation notes, and chronological context around any finding or record ID.
    """
    import json
    con = get_connection()

    result = {
        "finding": None,
        "primary_alert": None,
        "linked_case": None,
        "investigations": [],
        "related_alerts": [],
        "timeline": [],
        "rejects": [],
        "traceback": None,
    }

    target_cse = cse_id
    target_alert_id = alert_id

    # 1. If finding_id is provided, fetch finding record
    if finding_id:
        f_row = con.execute("""
            SELECT finding_id, alert_id, cse_id, engine, finding_type, severity, description, score, evidence, created_at
            FROM findings WHERE finding_id = ?
        """, [finding_id]).fetchone()
        if f_row:
            cols = ["finding_id", "alert_id", "cse_id", "engine", "finding_type", "severity", "description", "score", "evidence", "created_at"]
            d = dict(zip(cols, f_row))
            d["created_at"] = str(d["created_at"])
            if d.get("evidence"):
                try: d["evidence"] = json.loads(d["evidence"])
                except Exception: pass
            result["finding"] = d
            target_cse = d["cse_id"]
            if d.get("alert_id"):
                target_alert_id = d["alert_id"]
            elif isinstance(d.get("evidence"), dict):
                ev = d["evidence"]
                target_alert_id = ev.get("alert_id") or (ev.get("alert_ids", [None])[0] if isinstance(ev.get("alert_ids"), list) else None)

    # 2. If target_alert_id is known, fetch primary alert
    if target_alert_id:
        a_row = con.execute("""
            SELECT alert_id, cse_id, batch_id, category, severity, severity_raw, created_at, closed_at,
                   mttr_seconds, closure_notes, analyst_id, asset_id, source_ip, dest_ip, status
            FROM alerts WHERE alert_id = ?
        """, [target_alert_id]).fetchone()
        if a_row:
            a_cols = ["alert_id", "cse_id", "batch_id", "category", "severity", "severity_raw", "created_at", "closed_at",
                      "mttr_seconds", "closure_notes", "analyst_id", "asset_id", "source_ip", "dest_ip", "status"]
            a_dict = dict(zip(a_cols, a_row))
            for k in ["created_at", "closed_at"]:
                if a_dict.get(k): a_dict[k] = str(a_dict[k])
            result["primary_alert"] = a_dict
            target_cse = a_dict["cse_id"]

            # Check if this alert is linked to a case
            c_row = con.execute("""
                SELECT case_id, cse_id, batch_id, title, severity, status, opened_at, closed_at, analyst_id, linked_alert_ids
                FROM cases
                WHERE cse_id = ? AND linked_alert_ids LIKE '%' || ? || '%'
                LIMIT 1
            """, [target_cse, target_alert_id]).fetchone()
            if c_row:
                c_cols = ["case_id", "cse_id", "batch_id", "title", "severity", "status", "opened_at", "closed_at", "analyst_id", "linked_alert_ids"]
                c_dict = dict(zip(c_cols, c_row))
                for k in ["opened_at", "closed_at"]:
                    if c_dict.get(k): c_dict[k] = str(c_dict[k])
                result["linked_case"] = c_dict
                case_id = c_dict["case_id"]

    # 3. If case_id is known, fetch case and its investigations
    if case_id and not result["linked_case"]:
        c_row = con.execute("""
            SELECT case_id, cse_id, batch_id, title, severity, status, opened_at, closed_at, analyst_id, linked_alert_ids
            FROM cases WHERE case_id = ?
        """, [case_id]).fetchone()
        if c_row:
            c_cols = ["case_id", "cse_id", "batch_id", "title", "severity", "status", "opened_at", "closed_at", "analyst_id", "linked_alert_ids"]
            c_dict = dict(zip(c_cols, c_row))
            for k in ["opened_at", "closed_at"]:
                if c_dict.get(k): c_dict[k] = str(c_dict[k])
            result["linked_case"] = c_dict
            target_cse = c_dict["cse_id"]

    if case_id:
        inv_rows = con.execute("""
            SELECT investigation_id, cse_id, case_id, analyst_id, started_at, completed_at, outcome, notes
            FROM investigations WHERE case_id = ?
        """, [case_id]).fetchall()
        inv_cols = ["investigation_id", "cse_id", "case_id", "analyst_id", "started_at", "completed_at", "outcome", "notes"]
        for r in inv_rows:
            inv_dict = dict(zip(inv_cols, r))
            inv_dict["status"] = inv_dict.get("outcome")
            for k in ["started_at", "completed_at"]:
                if inv_dict.get(k): inv_dict[k] = str(inv_dict[k])
            result["investigations"].append(inv_dict)


    # 4. Fetch related raw alerts for the CSE or asset / source_ip
    filter_clause = "WHERE 1=1"
    f_params = []
    if target_cse:
        filter_clause += " AND cse_id = ?"
        f_params.append(target_cse)

    # If primary alert exists, also pull related alerts matching asset or source IP
    if result["primary_alert"]:
        p = result["primary_alert"]
        if p.get("source_ip"):
            f_rows = con.execute(f"""
                SELECT alert_id, cse_id, category, severity, created_at, closed_at, mttr_seconds, closure_notes, asset_id, source_ip, dest_ip, analyst_id
                FROM alerts
                WHERE (cse_id = ? AND (source_ip = ? OR asset_id = ?)) AND alert_id != ?
                ORDER BY created_at DESC LIMIT {limit}
            """, [target_cse, p["source_ip"], p.get("asset_id", ""), p["alert_id"]]).fetchall()
        else:
            f_rows = con.execute(f"""
                SELECT alert_id, cse_id, category, severity, created_at, closed_at, mttr_seconds, closure_notes, asset_id, source_ip, dest_ip, analyst_id
                FROM alerts
                WHERE cse_id = ? AND alert_id != ?
                ORDER BY created_at DESC LIMIT {limit}
            """, [target_cse, p["alert_id"]]).fetchall()
    else:
        f_rows = con.execute(f"""
            SELECT alert_id, cse_id, category, severity, created_at, closed_at, mttr_seconds, closure_notes, asset_id, source_ip, dest_ip, analyst_id
            FROM alerts
            {filter_clause}
            ORDER BY created_at DESC LIMIT {limit}
        """, f_params).fetchall()

    rel_cols = ["alert_id", "cse_id", "category", "severity", "created_at", "closed_at", "mttr_seconds", "closure_notes", "asset_id", "source_ip", "dest_ip", "analyst_id"]
    for r in f_rows:
        rd = dict(zip(rel_cols, r))
        for k in ["created_at", "closed_at"]:
            if rd.get(k): rd[k] = str(rd[k])
        result["related_alerts"].append(rd)

    # 5. Fetch traceback summary if applicable
    if target_cse:
        tb_row = con.execute("""
            SELECT incident_id, cse_id, title, confidence_score, why_flagged, narrative, stages_json, ioc_matches_json
            FROM traceback_reports
            WHERE cse_id = ?
            ORDER BY created_at DESC LIMIT 1
        """, [target_cse]).fetchone()
        if tb_row:
            result["traceback"] = {
                "incident_id": tb_row[0],
                "cse_id": tb_row[1],
                "title": tb_row[2],
                "confidence_score": tb_row[3],
                "why_flagged": tb_row[4],
                "narrative": tb_row[5],
                "stages": json.loads(tb_row[6]) if tb_row[6] else [],
                "matched_iocs": json.loads(tb_row[7]) if tb_row[7] else [],
            }

        # Also get recent data-quality rejects for this CSE
        rej_rows = con.execute("""
            SELECT reject_id, cse_id, data_type, row_index, raw_data, reject_reason, stage, rejected_at
            FROM rejects
            WHERE cse_id = ?
            ORDER BY rejected_at DESC LIMIT 10
        """, [target_cse]).fetchall()
        rej_cols = ["reject_id", "cse_id", "data_type", "row_index", "raw_data", "reject_reason", "stage", "rejected_at"]
        for r in rej_rows:
            rej_d = dict(zip(rej_cols, r))
            rej_d["rejected_at"] = str(rej_d["rejected_at"])
            result["rejects"].append(rej_d)

    con.close()
    return {"data": result}
