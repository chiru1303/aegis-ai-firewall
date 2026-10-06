"""
Ensemble Decision Pipeline
Orchestrates:
1. Tier 0: Rules & Normalization (executed upstream)
2. Tier 1: Wolf Defender v2 (0.3B ONNX) + ProtectAI DeBERTa v2
3. Tier 2: Laya Multilingual (322M mmBERT typed decisions)
4. Tier 3: Open-Jev-2B (Jev-style structured decisions for ambiguous cases)
5. LightGBM: Feature-based independent detector
"""
from typing import Dict, Any, List, Optional
from .lightgbm_classifier import LightGBMClassifier
from .wolf_defender import WolfDefenderClassifier
from .deberta_classifier import DeBERTaClassifier
from .laya_decision import LayaDecisionModel
from .open_jev_decision import OpenJevDecisionModel
from app.core.logging import get_logger

logger = get_logger(__name__)


class EnsembleClassifier:
    """
    Ensemble classifier that coordinates multi-tier AI evaluation without generative LLMs.
    """

    def __init__(self):
        self.lgb = LightGBMClassifier()
        self.wolf = WolfDefenderClassifier()
        self.deberta = DeBERTaClassifier()
        self.laya = LayaDecisionModel()
        self.open_jev = OpenJevDecisionModel()

    async def initialize(self) -> None:
        """Initialize all sub-classifiers."""
        await self.lgb.initialize()
        await self.wolf.initialize()
        await self.deberta.initialize()
        await self.laya.initialize()
        await self.open_jev.initialize()

    async def predict(
        self,
        content: str,
        normalized_content: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute cascading ensemble:
        1. Fast ML check: Wolf Defender + LightGBM
        2. Disagreement / Ambiguity check -> DeBERTa + Laya
        3. High Ambiguity -> Open-Jev
        """
        text = normalized_content or content

        # Step 1: Run Primary ML (Wolf Defender & LightGBM)
        wolf_res = await self.wolf.predict(text)
        lgb_res = await self.lgb.predict(text)

        scores = [lgb_res.get("confidence", 0.0)]
        preds = [lgb_res.get("is_malicious", False)]

        if wolf_res.get("status") == "ok":
            scores.append(wolf_res.get("confidence", 0.0))
            preds.append(wolf_res.get("is_malicious", False))

        # Check for ambiguity: agreement between Wolf and LightGBM
        is_ambiguous = len(set(preds)) > 1 or (0.35 <= max(scores) <= 0.65)

        deb_res = None
        laya_res = None
        jev_res = None

        # Step 2: Tier 1 ensemble escalation with DeBERTa if ambiguous or requested
        if is_ambiguous or wolf_res.get("status") != "ok":
            deb_res = await self.deberta.predict(text)
            if deb_res.get("status") == "ok":
                scores.append(deb_res.get("confidence", 0.0))
                preds.append(deb_res.get("is_malicious", False))

        # Step 3: Tier 2 Typed Decision with Laya
        laya_res = await self.laya.decide(text, context)
        if laya_res.get("is_malicious"):
            preds.append(True)
            scores.append(laya_res.get("confidence", 0.9))
        else:
            preds.append(False)
            scores.append(laya_res.get("confidence", 0.9))

        # Step 4: Tier 3 Escalation with Open-Jev if unresolved ambiguity remains
        malicious_count = sum(preds)
        total_evaluators = len(preds)
        agreement_ratio = malicious_count / total_evaluators if total_evaluators > 0 else 0

        if 0.3 < agreement_ratio < 0.7:
            # Unsettled decision: escalate to Open-Jev
            jev_res = await self.open_jev.evaluate_ambiguity(
                text,
                {"scores": scores, "preds": preds, "context": context}
            )
            if jev_res.get("is_malicious"):
                preds.append(True)
                scores.append(jev_res.get("confidence", 0.95))
            else:
                preds.append(False)
                scores.append(jev_res.get("confidence", 0.95))

        # Final consensus
        final_malicious_count = sum(preds)
        final_total = len(preds)
        is_malicious = final_malicious_count >= (final_total / 2)
        confidence = sum(scores) / len(scores) if scores else 0.5

        # Boost confidence when multiple models strongly agree
        if final_malicious_count == final_total or final_malicious_count == 0:
            confidence = min(1.0, confidence * 1.15)

        return {
            "is_malicious": is_malicious,
            "confidence": round(confidence, 4),
            "agreement_ratio": round(final_malicious_count / final_total, 2) if final_total > 0 else 0.0,
            "escalated_to_open_jev": jev_res is not None,
            "details": {
                "lightgbm": lgb_res,
                "wolf_defender": wolf_res,
                "deberta": deb_res,
                "laya": laya_res,
                "open_jev": jev_res
            }
        }
