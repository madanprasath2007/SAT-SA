"""
Rule Engine
Evaluates editable YAML rules in backend/rules/*.yaml against DuckDB tables.
Detects compliance violations, unescalated critical alerts, missing investigation notes,
and SOP adherence gaps.
"""

import glob
import os
from typing import Dict, List, Optional
import yaml
import duckdb

from .base import Engine, Finding, register_engine

RULES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "rules"))


@register_engine
class RuleEngine(Engine):
    name = "RuleEngine"
    description = "Evaluates declarative compliance and supervisory rules against normalized SOC records."

    def __init__(self, rules_dir: Optional[str] = None):
        self.rules_dir = rules_dir or RULES_DIR

    def load_rules(self) -> List[Dict]:
        rules = []
        pattern = os.path.join(self.rules_dir, "*.yaml")
        for fpath in sorted(glob.glob(pattern)):
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    cfg = yaml.safe_load(f)
                    if cfg and cfg.get("enabled", True):
                        cfg["_file"] = os.path.basename(fpath)
                        rules.append(cfg)
            except Exception as e:
                print(f"[RuleEngine] Error loading {fpath}: {e}")
        return rules

    def run(self, db: duckdb.DuckDBPyConnection, cse_id: Optional[str] = None) -> List[Finding]:
        rules = self.load_rules()
        findings: List[Finding] = []

        for rule in rules:
            rule_id = rule.get("id")
            if rule_id == "critical_alert_escalation":
                findings.extend(self._eval_critical_escalation(db, rule, cse_id))
            elif rule_id == "closed_case_investigation_notes":
                findings.extend(self._eval_closed_case_investigations(db, rule, cse_id))
            elif rule_id == "sop_steps_present":
                findings.extend(self._eval_sop_steps(db, rule, cse_id))
            elif rule_id == "escalation_level_severity_match":
                findings.extend(self._eval_escalation_level(db, rule, cse_id))

        return findings

    def _eval_critical_escalation(
        self, db: duckdb.DuckDBPyConnection, rule: Dict, cse_id: Optional[str] = None
    ) -> List[Finding]:
        findings = []
        max_minutes = rule.get("parameters", {}).get("max_minutes", 60)

        # Alerts with severity CRITICAL that were never escalated or escalated late
        query = """
            SELECT a.alert_id, a.cse_id, a.category, a.created_at,
                   e.escalation_id, e.escalated_at,
                   date_diff('minute', a.created_at, e.escalated_at) as diff_min
            FROM alerts a
            LEFT JOIN escalations e ON a.alert_id = e.alert_id
            WHERE a.severity = 'CRITICAL'
        """
        params = []
        if cse_id:
            query += " AND a.cse_id = ?"
            params.append(cse_id)

        rows = db.execute(query, params).fetchall()

        for row in rows:
            alert_id, cse, category, created_at, esc_id, esc_at, diff_min = row
            is_violation = False
            desc = ""

            if esc_id is None:
                is_violation = True
                desc = (
                    f"CRITICAL alert {alert_id} ({category}) was never escalated to incident response. "
                    f"Mandatory escalation required within {max_minutes} minutes."
                )
            elif diff_min is not None and diff_min > max_minutes:
                is_violation = True
                desc = (
                    f"CRITICAL alert {alert_id} ({category}) escalation was delayed by {int(diff_min)} minutes "
                    f"(SLA limit: {max_minutes} min)."
                )

            if is_violation:
                findings.append(Finding(
                    cse_id=cse,
                    engine=self.name,
                    finding_type=rule.get("name", "Rule Violation: Unescalated Critical Alert"),
                    severity=rule.get("severity", "CRITICAL"),
                    description=desc,
                    alert_id=alert_id,
                    score=float(rule.get("threshold_score", 90.0)),
                    evidence={
                        "rule_id": rule.get("id"),
                        "alert_id": alert_id,
                        "category": category,
                        "created_at": str(created_at),
                        "escalated": esc_id is not None,
                        "delay_minutes": diff_min,
                        "sla_limit_minutes": max_minutes,
                    },
                ))

        return findings

    def _eval_closed_case_investigations(
        self, db: duckdb.DuckDBPyConnection, rule: Dict, cse_id: Optional[str] = None
    ) -> List[Finding]:
        findings = []
        min_length = rule.get("parameters", {}).get("min_note_length", 15)

        # Closed cases without investigation notes or no investigation at all
        query = """
            SELECT c.case_id, c.cse_id, c.title, c.severity, c.closed_at,
                   COUNT(i.investigation_id) as inv_count,
                   MAX(LENGTH(COALESCE(TRIM(i.notes), ''))) as max_notes_len
            FROM cases c
            LEFT JOIN investigations i ON c.case_id = i.case_id
            WHERE LOWER(c.status) = 'closed'
        """
        params = []
        if cse_id:
            query += " AND c.cse_id = ?"
            params.append(cse_id)

        query += " GROUP BY c.case_id, c.cse_id, c.title, c.severity, c.closed_at"

        rows = db.execute(query, params).fetchall()

        for row in rows:
            case_id, cse, title, severity, closed_at, inv_count, max_notes_len = row
            notes_len = max_notes_len or 0

            if inv_count == 0 or notes_len < min_length:
                reason = "no linked investigation record" if inv_count == 0 else f"substantive notes absent (len: {notes_len} chars)"
                findings.append(Finding(
                    cse_id=cse,
                    engine=self.name,
                    finding_type=rule.get("name", "Rule Violation: Closed Case Lacks Investigation Notes"),
                    severity=rule.get("severity", "HIGH"),
                    description=f"Case {case_id} ('{title}') was marked closed with {reason}.",
                    score=float(rule.get("threshold_score", 80.0)),
                    evidence={
                        "rule_id": rule.get("id"),
                        "case_id": case_id,
                        "title": title,
                        "severity": severity,
                        "closed_at": str(closed_at),
                        "investigation_count": inv_count,
                        "notes_length": notes_len,
                    },
                ))

        return findings

    def _eval_sop_steps(
        self, db: duckdb.DuckDBPyConnection, rule: Dict, cse_id: Optional[str] = None
    ) -> List[Finding]:
        findings = []
        min_chars = rule.get("parameters", {}).get("min_chars", 20)

        query = """
            SELECT i.investigation_id, i.case_id, i.cse_id, i.analyst_id, i.outcome, i.notes
            FROM investigations i
            WHERE i.outcome IS NOT NULL
        """
        params = []
        if cse_id:
            query += " AND i.cse_id = ?"
            params.append(cse_id)

        rows = db.execute(query, params).fetchall()

        for row in rows:
            inv_id, case_id, cse, analyst, outcome, notes = row
            text = (notes or "").strip()
            if len(text) < min_chars:
                findings.append(Finding(
                    cse_id=cse,
                    engine=self.name,
                    finding_type=rule.get("name", "Rule Violation: Investigation Missing Mandatory SOP Steps"),
                    severity=rule.get("severity", "MEDIUM"),
                    description=(
                        f"Investigation {inv_id} for case {case_id} (Analyst: {analyst}) closed with outcome "
                        f"'{outcome}' but failed SOP documentation standard ({len(text)} chars vs minimum {min_chars})."
                    ),
                    score=float(rule.get("threshold_score", 60.0)),
                    evidence={
                        "rule_id": rule.get("id"),
                        "investigation_id": inv_id,
                        "case_id": case_id,
                        "analyst_id": analyst,
                        "outcome": outcome,
                        "notes_length": len(text),
                    },
                ))

        return findings

    def _eval_escalation_level(
        self, db: duckdb.DuckDBPyConnection, rule: Dict, cse_id: Optional[str] = None
    ) -> List[Finding]:
        findings = []
        allowed = rule.get("parameters", {}).get("critical_allowed_targets", ["L3", "Tier 3", "SOC Lead", "IR Team"])
        require_reason = rule.get("parameters", {}).get("require_reason", True)

        query = """
            SELECT e.escalation_id, e.cse_id, e.alert_id, e.case_id,
                   e.escalated_by, e.escalated_to, e.reason,
                   a.severity as alert_severity
            FROM escalations e
            LEFT JOIN alerts a ON e.alert_id = a.alert_id
            WHERE a.severity IN ('CRITICAL', 'HIGH')
        """
        params = []
        if cse_id:
            query += " AND e.cse_id = ?"
            params.append(cse_id)

        rows = db.execute(query, params).fetchall()

        for row in rows:
            esc_id, cse, alert_id, case_id, esc_by, esc_to, reason, alert_sev = row
            reason_str = (reason or "").strip()

            target_ok = any(t.lower() in (esc_to or "").lower() for t in allowed)
            reason_ok = not require_reason or len(reason_str) > 5

            if not target_ok or not reason_ok:
                issues = []
                if not target_ok:
                    issues.append(f"escalated to non-senior target '{esc_to}' (required: {', '.join(allowed)})")
                if not reason_ok:
                    issues.append("missing escalation justification reason")

                findings.append(Finding(
                    cse_id=cse,
                    engine=self.name,
                    finding_type=rule.get("name", "Rule Violation: Escalation Level Mismatches Alert Severity"),
                    severity=rule.get("severity", "HIGH"),
                    description=f"{alert_sev} alert {alert_id} escalation issue: {'; '.join(issues)}.",
                    alert_id=alert_id,
                    score=float(rule.get("threshold_score", 75.0)),
                    evidence={
                        "rule_id": rule.get("id"),
                        "escalation_id": esc_id,
                        "alert_id": alert_id,
                        "case_id": case_id,
                        "alert_severity": alert_sev,
                        "escalated_to": esc_to,
                        "reason": reason_str,
                    },
                ))

        return findings
