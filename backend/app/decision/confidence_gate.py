"""
Aegis AI Firewall - 3-Tier Confidence Gate
Enforces Correction 1:
Separates:
1. Detector confidence = How confident is this detector in its observation?
2. Risk score = How dangerous is the overall payload?
3. Decision confidence = How confident are we in the final ALLOW/BLOCK decision?

Fast-Allow is strictly narrower and safer than Fast-Block.
Disagreement or boundary ambiguity escalates to Tier 2 (Laya mmBERT / Open-Jev).
"""
from enum import Enum
from typing import List, Dict, Any, Tuple
from app.decision.decision_schema import DetectorContractResult, DetectorStatus
from app.core.logging import get_logger

logger = get_logger(__name__)


class GateOutcome(str, Enum):
    FAST_BLOCK = "FAST_BLOCK"
    FAST_ALLOW = "FAST_ALLOW"
    ESCALATE = "ESCALATE"
    FAILSAFE_BLOCK = "FAILSAFE_BLOCK"


class ConfidenceGate:
    """
    Evaluates detector agreement and calibrated risk to choose between fast paths
    and Tier 2 arbitration escalation.
    """

    FAST_ALLOW_MAX_RISK = 0.15
    FAST_ALLOW_MIN_DECISION_CONF = 0.85

    FAST_BLOCK_MIN_RISK = 0.75
    FAST_BLOCK_MIN_DECISION_CONF = 0.70

    def evaluate_gate(
        self,
        tier0_results: List[DetectorContractResult],
        tier1_results: List[DetectorContractResult],
        source_trust: str = "UNTRUSTED",
        mandatory_block_detected: bool = False,
    ) -> Tuple[GateOutcome, float, float, float, List[str]]:
        """
        Evaluate confidence gate:
        Returns (GateOutcome, fused_risk_score, avg_detector_conf, decision_confidence, reasons)
        """
        reasons = []

        # 1. Mandatory Security Violations -> Immediate Fast-Block
        if mandatory_block_detected:
            reasons.append("Mandatory platform security violation detected.")
            return GateOutcome.FAST_BLOCK, 1.0, 1.0, 1.0, reasons

        # 2. Check for detector failures (Invariant 3: Failure cannot silently become approval)
        failed_detectors = [
            d.detector_id for d in (tier0_results + tier1_results)
            if d.status == DetectorStatus.FAILED
        ]
        if failed_detectors and source_trust in ["UNTRUSTED", "MALICIOUS"]:
            # If critical detectors failed on untrusted input, fail safe
            reasons.append(f"Failsafe triggered: Detectors failed during untrusted ingestion: {failed_detectors}")
            return GateOutcome.FAILSAFE_BLOCK, 0.85, 0.5, 0.90, reasons

        # 3. Calculate separate metrics:
        # a. Mean Detector Confidence
        all_results = [d for d in (tier0_results + tier1_results) if d.status == DetectorStatus.SUCCESS]
        if not all_results:
            reasons.append("No active detector results available.")
            return GateOutcome.FAILSAFE_BLOCK, 0.9, 0.1, 0.9, reasons

        mean_detector_conf = sum(d.detector_confidence for d in all_results) / len(all_results)

        # b. Fused Risk Score
        # Tier 0 deterministic detections have higher priority for presence of threats
        t0_detected = [d for d in tier0_results if d.is_malicious]
        t1_detected = [d for d in tier1_results if d.is_malicious]

        t0_max_risk = max([d.risk_score for d in tier0_results], default=0.0)
        t1_max_risk = max([d.risk_score for d in tier1_results], default=0.0)

        # Base fused risk
        fused_risk = max(t0_max_risk * 0.95, t1_max_risk)
        if t0_detected and t1_detected:
            # Multi-tier confirmation boost
            fused_risk = min(1.0, fused_risk * 1.15)

        # c. Decision Confidence (How confident in final decision?)
        # Measure agreement across ML and rules
        total_evals = len(all_results)
        malicious_count = len([d for d in all_results if d.is_malicious])
        agreement_ratio = malicious_count / total_evals if total_evals > 0 else 0.0

        # High agreement near 0 or near 1 indicates high decision confidence
        distance_from_uncertainty = abs(agreement_ratio - 0.5) * 2.0  # 0.0 (50/50 split) to 1.0 (unanimous)

        # Factor in distance to risk threshold (0.50 boundary)
        boundary_distance = abs(fused_risk - 0.50) * 2.0  # 0.0 (exactly 0.50) to 1.0 (0.0 or 1.0)

        decision_confidence = (distance_from_uncertainty * 0.5) + (boundary_distance * 0.5)
        decision_confidence = max(0.1, min(1.0, decision_confidence))

        # 4. Fast-Block Gate Evaluation
        if fused_risk >= self.FAST_BLOCK_MIN_RISK and decision_confidence >= self.FAST_BLOCK_MIN_DECISION_CONF:
            reasons.append(
                f"Fast-Block approved: Risk {fused_risk:.2f} >= {self.FAST_BLOCK_MIN_RISK} "
                f"with decision confidence {decision_confidence:.2f}."
            )
            return GateOutcome.FAST_BLOCK, fused_risk, mean_detector_conf, decision_confidence, reasons

        # 5. Fast-Allow Gate Evaluation (Must be STRICTER than Fast-Block)
        if (
            fused_risk <= self.FAST_ALLOW_MAX_RISK
            and decision_confidence >= self.FAST_ALLOW_MIN_DECISION_CONF
            and len(t0_detected) == 0
            and len(t1_detected) == 0
            and source_trust != "MALICIOUS"
        ):
            reasons.append(
                f"Fast-Allow approved: Unanimous benign consensus. Risk {fused_risk:.2f} <= {self.FAST_ALLOW_MAX_RISK}, "
                f"decision confidence {decision_confidence:.2f}."
            )
            return GateOutcome.FAST_ALLOW, fused_risk, mean_detector_conf, decision_confidence, reasons

        # 6. Ambiguity or Disagreement -> Escalate to Tier 2
        reasons.append(
            f"Escalation required: Borderline or cross-detector disagreement "
            f"(Risk: {fused_risk:.2f}, Decision Conf: {decision_confidence:.2f}, "
            f"T0 Malicious: {len(t0_detected)}, T1 Malicious: {len(t1_detected)})."
        )
        return GateOutcome.ESCALATE, fused_risk, mean_detector_conf, decision_confidence, reasons
