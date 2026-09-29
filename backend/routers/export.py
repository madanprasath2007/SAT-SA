"""
Export & Regulatory Reporting Router (Phase 5)
Provides:
- CSV export of supervisory findings with filters
- Official PDF supervisory assessment reports for CSEs and individual findings
  using ReportLab with air-gapped generation.
"""

import csv
from datetime import datetime
import io
import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import StreamingResponse

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from models import get_connection
from auth import get_current_user
from audit import log_audit

router = APIRouter()


@router.get("/findings/csv")
def export_findings_csv(
    cse_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    engine: Optional[str] = Query(None),
    user: Dict[str, Any] = Depends(get_current_user),
):
    """Generates and downloads a CSV export of supervisory findings."""
    con = get_connection()
    query = """
        SELECT finding_id, alert_id, cse_id, engine, finding_type, severity, score, description, created_at
        FROM findings WHERE 1=1
    """
    params = []
    if cse_id:
        query += " AND cse_id = ?"
        params.append(cse_id)
    if severity:
        query += " AND severity = ?"
        params.append(severity.upper())
    if engine:
        query += " AND engine = ?"
        params.append(engine)

    query += " ORDER BY created_at DESC"
    rows = con.execute(query, params).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Finding ID", "Alert ID", "CSE ID", "Engine", "Finding Type", "Severity", "Score", "Description", "Created At"])

    for r in rows:
        writer.writerow(list(r))

    log_audit(
        con,
        action="EXPORT_FINDINGS_CSV",
        user=user,
        target_entity=cse_id or "ALL",
        details={"record_count": len(rows)},
    )
    con.close()

    output.seek(0)
    filename = f"sat_sa_findings_{cse_id or 'all'}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/pdf/cse/{cse_id}")
def export_cse_pdf_report(
    cse_id: str,
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Generates an official SAT-SA Supervisory Assessment PDF report for a CSE.
    Contains executive summary, composite risk score, attack traceback stages,
    findings table, and reviewer decisions.
    """
    con = get_connection()

    # 1. Fetch CSE info
    cse_row = con.execute("SELECT cse_id, cse_name, sector, contact_email FROM cses WHERE cse_id = ?", [cse_id]).fetchone()
    cse_name = cse_row[1] if cse_row else cse_id
    sector = cse_row[2] if cse_row else "Critical Infrastructure"

    # 2. Fetch risk score breakdown
    risk_row = con.execute("SELECT overall_score, risk_level, breakdown_json FROM risk_scores WHERE cse_id = ?", [cse_id]).fetchone()
    score = risk_row[0] if risk_row else 50.0
    level = risk_row[1] if risk_row else "HIGH"
    breakdown = json.loads(risk_row[2]) if risk_row and risk_row[2] else {}

    # 3. Fetch top findings
    f_rows = con.execute("""
        SELECT finding_id, engine, finding_type, severity, score, description
        FROM findings WHERE cse_id = ?
        ORDER BY score DESC LIMIT 15
    """, [cse_id]).fetchall()

    # 4. Fetch traceback report if available
    tb_row = con.execute("""
        SELECT incident_id, title, confidence_score, why_flagged, narrative, stages_json, ioc_matches_json
        FROM traceback_reports WHERE cse_id = ?
        ORDER BY created_at DESC LIMIT 1
    """, [cse_id]).fetchone()

    # 5. Fetch reviewer decisions
    rev_rows = con.execute("""
        SELECT finding_id, reviewer, decision, notes, created_at
        FROM reviews WHERE cse_id = ?
        ORDER BY created_at DESC LIMIT 10
    """, [cse_id]).fetchall()

    log_audit(
        con,
        action="EXPORT_CSE_PDF_REPORT",
        user=user,
        target_entity=cse_id,
        details={"score": score, "level": level},
    )
    con.close()

    # Build PDF with ReportLab
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a"),
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#475569"),
    )
    h2_style = ParagraphStyle(
        "DocH2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#0891b2"),
        spaceBefore=14,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "DocBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1e293b"),
    )
    bold_body = ParagraphStyle(
        "DocBodyBold",
        parent=body_style,
        fontName="Helvetica-Bold",
    )

    story = []

    # Title & Metadata Header
    story.append(Paragraph("SAT-SA — Supervisory SOC Assessment Report", title_style))
    story.append(Paragraph(f"National Supervisory Assessment · NCIIPC / NTRO Compliant · Generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", subtitle_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#0891b2"), spaceAfter=12))

    # Entity Overview Table
    entity_data = [
        [Paragraph("Designated Entity:", bold_body), Paragraph(f"{cse_name} ({cse_id})", body_style),
         Paragraph("Sector:", bold_body), Paragraph(sector.capitalize(), body_style)],
        [Paragraph("Composite Risk Score:", bold_body), Paragraph(f"<b>{score:.1f} / 100</b> ({level})", body_style),
         Paragraph("Assessor Session:", bold_body), Paragraph(f"{user.get('full_name')} ({user.get('role')})", body_style)],
    ]
    entity_table = Table(entity_data, colWidths=[110, 155, 100, 165])
    entity_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(entity_table)
    story.append(Spacer(1, 14))

    # Traceback Section if present
    if tb_row:
        story.append(Paragraph("Adversary Kill-Chain & Attack Path Reconstruction", h2_style))
        story.append(Paragraph(f"<b>Incident:</b> {tb_row[1]} &nbsp;|&nbsp; <b>Confidence:</b> {tb_row[2]:.1f}%", body_style))
        story.append(Spacer(1, 4))
        if tb_row[3]:
            story.append(Paragraph(f"<b>Adversary Trigger:</b> {tb_row[3]}", body_style))
            story.append(Spacer(1, 4))
        if tb_row[4]:
            story.append(Paragraph(f"<b>Reconstruction Narrative:</b> {tb_row[4]}", body_style))
            story.append(Spacer(1, 8))

        stages = json.loads(tb_row[5]) if tb_row[5] else []
        if stages:
            stage_table_data = [["Stage", "Tactic / MITRE", "Claim & Evidence", "Confidence"]]
            for s in stages:
                eids = ", ".join(s.get("evidence_ids", [])[:3])
                stage_table_data.append([
                    f"{s.get('stage_number')}. {s.get('stage_name')}",
                    f"{s.get('tactic')} ({s.get('technique')})",
                    Paragraph(f"{s.get('claim')}<br/><font color='#0891b2'>Evidence: {eids}</font>", body_style),
                    f"{int(s.get('confidence', 0.9)*100)}%",
                ])

            stage_table = Table(stage_table_data, colWidths=[120, 110, 240, 60])
            stage_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(stage_table)
            story.append(Spacer(1, 14))

    # Findings Table
    story.append(Paragraph("Key Supervisory Findings", h2_style))
    f_table_data = [["Finding ID", "Engine", "Type", "Severity", "Score", "Description"]]
    for f in f_rows:
        f_table_data.append([
            f[0][:12],
            f[1].replace("Engine", ""),
            f[2],
            f[3],
            str(f[4]),
            Paragraph(f[5], body_style),
        ])

    f_table = Table(f_table_data, colWidths=[65, 80, 110, 55, 35, 185])
    f_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0891b2")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(f_table)
    story.append(Spacer(1, 14))

    # Reviewer Decisions Section
    if rev_rows:
        story.append(Paragraph("Human Reviewer Decisions & Oversight Actions", h2_style))
        r_table_data = [["Finding ID", "Reviewer", "Decision", "Notes", "Timestamp"]]
        for r in rev_rows:
            r_table_data.append([
                r[0][:12],
                r[1],
                r[2],
                Paragraph(r[3] or "—", body_style),
                str(r[4])[:19],
            ])
        r_table = Table(r_table_data, colWidths=[70, 95, 85, 180, 100])
        r_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(r_table)

    doc.build(story)
    buf.seek(0)

    filename = f"sat_sa_report_{cse_id}_{datetime.utcnow().strftime('%Y%m%d')}.pdf"
    return StreamingResponse(
        buf,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
