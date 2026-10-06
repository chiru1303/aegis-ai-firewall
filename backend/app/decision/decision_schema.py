"""
Aegis AI Firewall - Strict Detector Contract & Decision Schema
Enforces Invariant 3: Detector failure cannot silently become security approval.
Explicit status and error tracking for all detectors.
"""
from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class DetectorStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    TIMED_OUT = "TIMED_OUT"


class DetectorContractResult(BaseModel):
    """
    Standardized contract required from every detector across all tiers (0, 1, 2).
    """
    detector_id: str
    detector_version: str = "1.0.0"
    tier: int = Field(ge=0, le=2)  # 0=deterministic, 1=ML binary/multi, 2=typed escalation
    signal_type: str = "unknown"
    is_malicious: bool = False

    # 3 Separate concepts (Correction 1):
    detector_confidence: float = Field(default=0.0, ge=0.0, le=1.0)  # How sure is this detector?
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)           # How severe is the finding?

    attack_types: List[str] = Field(default_factory=list)
    evidence_snippets: List[str] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    latency_ms: float = 0.0
    status: DetectorStatus = DetectorStatus.SUCCESS
    error_message: Optional[str] = None


class OrchestratedDecision(BaseModel):
    """
    Synthesized decision returned by the Parallel Decision Orchestrator.
    """
    request_id: str
    decision: str  # ALLOW, SANITIZE, BLOCK, REQUIRE_REVIEW, QUARANTINE
    risk_score: float
    risk_level: str

    # Explicit separation of confidences:
    detector_confidence: float  # Mean confidence of reporting detectors
    decision_confidence: float  # Confidence in the final ALLOW/BLOCK decision

    gate_outcome: str  # FAST_BLOCK, FAST_ALLOW, ESCALATED_DECISION, DEGRADED_FAILSAFE_BLOCK
    attack_types: List[str] = Field(default_factory=list)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    degraded_mode: bool = False
    detector_failures: List[str] = Field(default_factory=list)
    detector_results: List[DetectorContractResult] = Field(default_factory=list)
    latency_ms: float = 0.0
