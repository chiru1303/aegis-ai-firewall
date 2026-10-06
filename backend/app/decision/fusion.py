"""
Aegis AI Firewall - Multi-Detector Evidence Fusion
Combines disparate signals from deterministic rules, ML classifiers, and session state.
"""
from typing import List, Dict, Any, Tuple
from app.decision.decision_schema import DetectorContractResult, DetectorStatus
from app.models.schemas import AttackType
from app.core.logging import get_logger

logger = get_logger(__name__)


class EvidenceFusionEngine:
    """Combines evidence across detection tiers into unified assessment."""

    ATTACK_TYPE_ALIASES = {
        "INSTRUCTION_OVERRIDE": AttackType.INSTRUCTION_OVERRIDE,
        "ROLE_CHANGE": AttackType.ROLE_CHANGE,
        "ROLE_MANIPULATION": AttackType.ROLE_CHANGE,
        "SECRET_EXTRACTION": AttackType.SECRET_EXTRACTION,
        "CREDENTIAL_THEFT": AttackType.CREDENTIAL_THEFT,
        "CREDENTIAL_DETECTOR": AttackType.CREDENTIAL_THEFT,
        "TOOL_ABUSE": AttackType.TOOL_ABUSE,
        "CONTEXT_POISONING": AttackType.CONTEXT_POISONING,
        "MULTI_STEP_JAILBREAK": AttackType.MULTI_STEP_JAILBREAK,
        "ENCODED_INSTRUCTION": AttackType.ENCODED_INSTRUCTION,
        "OBFUSCATION": AttackType.ENCODED_INSTRUCTION,
        "INDIRECT_PROMPT_INJECTION": AttackType.INDIRECT_PROMPT_INJECTION,
        "INDIRECT_INJECTION": AttackType.INDIRECT_PROMPT_INJECTION,
    }

    def fuse_evidence(
        self,
        results: List[DetectorContractResult],
        trajectory_risk: float = 0.0,
        obfuscation_score: float = 0.0,
        source_trust: str = "UNTRUSTED",
    ) -> Tuple[float, List[Dict[str, Any]], Dict[str, float]]:
        """
        Fuse detector outputs into:
        (fused_risk_score, attack_types_list, component_scores)
        """
        active_results = [r for r in results if r.status == DetectorStatus.SUCCESS]

        # 1. Group by attack types and keep maximum confidence per attack type
        attack_map: Dict[str, float] = {}
        for r in active_results:
            if r.is_malicious:
                for at in r.attack_types:
                    clean = at.strip().upper().replace(" ", "_")
                    enum_val = self.ATTACK_TYPE_ALIASES.get(clean, clean)
                    val_str = enum_val.value if hasattr(enum_val, "value") else str(enum_val)
                    if val_str not in attack_map or r.detector_confidence > attack_map[val_str]:
                        attack_map[val_str] = r.detector_confidence

        # 2. Component scores
        t0_scores = [r.risk_score for r in active_results if r.tier == 0 and r.is_malicious]
        t1_scores = [r.risk_score for r in active_results if r.tier == 1 and r.is_malicious]
        t2_scores = [r.risk_score for r in active_results if r.tier == 2 and r.is_malicious]

        t0_max = max(t0_scores, default=0.0)
        t1_max = max(t1_scores, default=0.0)
        t2_max = max(t2_scores, default=0.0)

        component_scores = {
            "tier0_rules": t0_max,
            "tier1_ml": t1_max,
            "tier2_escalation": t2_max,
            "trajectory": trajectory_risk,
            "obfuscation": obfuscation_score,
        }

        # 3. Weighted multi-factor combination
        # Tier 0 (exact deterministic signals) is highest priority when present
        raw_score = (
            t0_max * 0.35 +
            t1_max * 0.25 +
            t2_max * 0.20 +
            trajectory_risk * 0.10 +
            obfuscation_score * 0.10
        )

        # 4. Boosting factors
        boost = 1.0
        if len(attack_map) > 1:
            boost *= 1.15  # Multi-vector attack
        if obfuscation_score > 0.2:
            boost *= 1.10  # Deliberate obfuscation attempt
        if source_trust in ["UNTRUSTED", "MALICIOUS"]:
            boost *= 1.08  # Untrusted ingress source

        fused_score = min(1.0, max(t0_max * 0.95, t2_max * 0.95, raw_score * boost))

        attack_types_list = [
            {"type": at_name, "confidence": round(conf, 4)}
            for at_name, conf in attack_map.items()
        ]

        return round(fused_score, 4), attack_types_list, component_scores
