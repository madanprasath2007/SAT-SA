"""
Dashboard Router — Step 5 of SAT-SA pipeline.
Provides aggregated metrics for the React supervisor dashboard.
"""

from fastapi import APIRouter
from database import get_connection

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
        "total_alerts":      total_alerts,
        "total_findings":    total_findings,
        "critical_findings": critical_findings,
        "high_findings":     high_findings,
        "cse_count":         cse_count,
        "avg_critical_mttr_minutes": round(avg_mttr / 60, 1),
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
    return [dict(zip(cols, r)) for r in rows]


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
    return [dict(zip(cols, r)) for r in rows]


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
    return [dict(zip(cols, r)) for r in rows]


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
    return [dict(zip(cols, r)) for r in rows]
