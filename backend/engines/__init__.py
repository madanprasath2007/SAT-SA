"""
Supervisory Analytics Engines Package
Exports the 5 supervisory analytics engines and base abstractions.
"""

from .base import (
    Engine,
    Finding,
    register_engine,
    get_engine,
    get_all_engines,
    persist_findings,
    clear_registry,
)
from .rule_engine import RuleEngine
from .anomaly_detection import AnomalyDetectionEngine
from .peer_benchmarking import PeerBenchmarkingEngine
from .execution_gap import ExecutionGapEngine
from .negative_space import NegativeSpaceEngine
from .risk_scoring import calculate_cse_risk, update_risk_scores

__all__ = [
    "Engine",
    "Finding",
    "register_engine",
    "get_engine",
    "get_all_engines",
    "persist_findings",
    "clear_registry",
    "RuleEngine",
    "AnomalyDetectionEngine",
    "PeerBenchmarkingEngine",
    "ExecutionGapEngine",
    "NegativeSpaceEngine",
    "calculate_cse_risk",
    "update_risk_scores",
]
