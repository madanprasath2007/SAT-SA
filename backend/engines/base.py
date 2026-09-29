"""
Supervisory Analytics Layer — Base Engine & Finding Contract
All 5 supervisory engines inherit from Engine and produce evidence-linked Findings.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime
import json
from typing import Dict, List, Optional, Type, Union
import uuid

import duckdb


@dataclass
class Finding:
    """
    Standard supervisory finding produced by any of the 5 analytics engines.
    Evidence pointers link the finding directly to source alerts, cases, assets,
    or quantitative metrics for supervisor auditability.
    """
    cse_id: str
    engine: str
    finding_type: str
    severity: str                         # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    alert_id: Optional[str] = None
    score: float = 0.0
    evidence: Optional[Union[Dict, List, str]] = None
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        d = asdict(self)
        if isinstance(d["evidence"], (dict, list)):
            d["evidence_json"] = json.dumps(d["evidence"])
        elif d["evidence"] is None:
            d["evidence_json"] = None
        else:
            d["evidence_json"] = str(d["evidence"])
        return d


class Engine(ABC):
    """Abstract base class for all supervisory analytics engines."""
    name: str = "BaseEngine"
    description: str = "Base Engine"

    @abstractmethod
    def run(self, db: duckdb.DuckDBPyConnection, cse_id: Optional[str] = None) -> List[Finding]:
        """
        Execute engine analysis against DuckDB normalized tables.
        If cse_id is provided, limit analysis to that CSE; otherwise analyze all.
        Returns list of Finding objects.
        """
        pass


# ── Engine Registry ──────────────────────────────────────────────────────────

_REGISTRY: Dict[str, Engine] = {}


def register_engine(engine_instance_or_cls: Union[Engine, Type[Engine]]):
    """Register an engine instance or class in the global registry."""
    if isinstance(engine_instance_or_cls, type):
        inst = engine_instance_or_cls()
    else:
        inst = engine_instance_or_cls
    _REGISTRY[inst.name] = inst
    return engine_instance_or_cls


def get_engine(name: str) -> Optional[Engine]:
    return _REGISTRY.get(name)


def get_all_engines() -> List[Engine]:
    return list(_REGISTRY.values())


def clear_registry():
    _REGISTRY.clear()


# ── Persistence & Idempotency ────────────────────────────────────────────────

def persist_findings(
    con: duckdb.DuckDBPyConnection,
    findings: List[Finding],
    cse_id: Optional[str] = None,
    engine_names: Optional[List[str]] = None,
) -> int:
    """
    Persist findings into the DuckDB `findings` table.
    Idempotent: removes prior findings matching the (cse_id, engine) scope before inserting.
    """
    if engine_names is None:
        # Determine engines present in findings or all registered
        engine_names = list(set([f.engine for f in findings] + list(_REGISTRY.keys())))

    for eng_name in engine_names:
        if cse_id:
            con.execute("DELETE FROM findings WHERE cse_id = ? AND engine = ?", [cse_id, eng_name])
        else:
            con.execute("DELETE FROM findings WHERE engine = ?", [eng_name])

    count = 0
    for f in findings:
        f_dict = f.to_dict()
        con.execute(
            """
            INSERT OR REPLACE INTO findings
                (finding_id, alert_id, cse_id, engine, finding_type, severity, description, score, evidence, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                f_dict["finding_id"],
                f_dict.get("alert_id"),
                f_dict["cse_id"],
                f_dict["engine"],
                f_dict["finding_type"],
                f_dict["severity"],
                f_dict["description"],
                float(f_dict.get("score") or 0.0),
                f_dict.get("evidence_json"),
                f_dict.get("created_at"),
            ]
        )
        count += 1

    return count
