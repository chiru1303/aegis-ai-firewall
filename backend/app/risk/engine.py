import math
from typing import List, Dict, Any, Optional
from pydantic import BaseModel

class DetectorResult(BaseModel):
    detector_type: str
    confidence: float
    attack_types: List[str]
    evidence: Dict[str, Any]

class RiskAssessment(BaseModel):
    risk_score: float
    risk_level: str
    confidence: float
    attack_types: List[Dict[str, Any]]
    evidence: List[Dict[str, Any]]
    component_scores: Dict[str, float]
    boosting_factors: List[str]
    explanation: str

class RiskEngine:
    def __init__(self):
        self.weights = {
            "rule": 0.30,
            "ml": 0.25,
            "obfuscation": 0.15,
            "provenance": 0.10,
            "context": 0.10,
            "trajectory": 0.05,
            "tool": 0.05
        }

    def _sigmoid(self, x: float) -> float:
        return 1 / (1 + math.exp(-10 * (x - 0.5)))

    async def assess_risk(self, results: List[DetectorResult], source_trust: str = "UNTRUSTED") -> RiskAssessment:
        categories = {k: [] for k in self.weights.keys()}
        for r in results:
            if r.detector_type in categories:
                categories[r.detector_type].append(r)

        component_scores = {}
        for cat, cats_results in categories.items():
            if cats_results:
                component_scores[cat] = max(r.confidence for r in cats_results)
            else:
                component_scores[cat] = 0.0

        base_score = sum(component_scores.get(cat, 0.0) * weight for cat, weight in self.weights.items())
        scaled_score = self._sigmoid(base_score)

        boosting_factors = []
        all_attacks = set()
        for r in results:
            all_attacks.update(r.attack_types)

        if len(all_attacks) > 1:
            scaled_score *= 1.2
            boosting_factors.append("Multiple attack types detected")

        if source_trust in ["UNTRUSTED", "MALICIOUS"]:
            scaled_score *= 1.1
            boosting_factors.append("Untrusted source")

        if component_scores.get("obfuscation", 0.0) > 0.5:
            scaled_score *= 1.15
            boosting_factors.append("Obfuscation detected")

        final_score = min(1.0, scaled_score)

        if final_score < 0.20:
            level = "LOW"
        elif final_score < 0.50:
            level = "MEDIUM"
        elif final_score < 0.80:
            level = "HIGH"
        else:
            level = "CRITICAL"

        valid_scores = [v for v in component_scores.values() if v > 0]
        overall_confidence = sum(valid_scores) / len(valid_scores) if valid_scores else 0.0

        attack_list = [{"type": a, "confidence": max([r.confidence for r in results if a in r.attack_types] + [0.0])} for a in all_attacks]
        evidence = [r.evidence for r in results]

        explanation = f"Risk score is {final_score:.2f} ({level})."
        if boosting_factors:
            explanation += f" Boosted by: {', '.join(boosting_factors)}."

        return RiskAssessment(
            risk_score=final_score,
            risk_level=level,
            confidence=overall_confidence,
            attack_types=attack_list,
            evidence=evidence,
            component_scores=component_scores,
            boosting_factors=boosting_factors,
            explanation=explanation
        )
