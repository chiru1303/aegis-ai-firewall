"""
Aegis AI Firewall - Parallel Decision Orchestrator Package
Enforces 3 Invariants and 8 Architectural Corrections:
- Strict detector contracts
- Process/Thread Pool for CPU-bound ML inference
- 3-tier confidence gate (detector confidence != risk score != decision confidence)
- Escalation to Laya mmBERT and Open-Jev
- Bounded session context
"""
from .decision_schema import DetectorContractResult, OrchestratedDecision, DetectorStatus
from .confidence_gate import ConfidenceGate, GateOutcome
from .ml_executor import MLExecutorPool, get_ml_executor_pool
from .bounded_context import BoundedSessionContext, build_bounded_context
from .arbitration import ArbitrationRouter
from .fusion import EvidenceFusionEngine
from .orchestrator import ParallelDecisionOrchestrator

__all__ = [
    "DetectorContractResult",
    "OrchestratedDecision",
    "DetectorStatus",
    "ConfidenceGate",
    "GateOutcome",
    "MLExecutorPool",
    "get_ml_executor_pool",
    "BoundedSessionContext",
    "build_bounded_context",
    "ArbitrationRouter",
    "EvidenceFusionEngine",
    "ParallelDecisionOrchestrator",
]
