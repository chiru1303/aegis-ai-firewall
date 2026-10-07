"""
Aegis AI Firewall - Arbitration & Escalation Router
Invoked when Confidence Gate cannot achieve high-confidence Fast-Allow or Fast-Block.
Coordinates Tier 2 escalation:
1. Laya mmBERT typed decision model
2. Open-Jev structured arbiter
Executes CPU-bound inference via the dedicated MLExecutorPool worker threads.
"""
import time
from typing import List, Dict, Any, Optional
from app.decision.decision_schema import DetectorContractResult, DetectorStatus
from app.decision.ml_executor import get_ml_executor_pool
from app.classifiers.laya_decision import LayaDecisionModel
from app.classifiers.open_jev_decision import OpenJevDecisionModel
from app.core.logging import get_logger

logger = get_logger(__name__)


class ArbitrationRouter:
    """Escalation router managing Tier 2 and Tier 3 deep decision models."""

    def __init__(self):
        self.laya = LayaDecisionModel()
        self.open_jev = OpenJevDecisionModel()
        self.ml_pool = get_ml_executor_pool()
        self._initialized = False

    async def initialize(self):
        if not self._initialized:
            try:
                await self.laya.initialize()
                await self.open_jev.initialize()
                self._initialized = True
                logger.info("ArbitrationRouter models initialized.")
            except Exception as e:
                logger.warning(f"ArbitrationRouter initialization warning: {e}")

    async def arbitrate(
        self,
        text: str,
        prior_results: List[DetectorContractResult],
        bounded_context: Optional[str] = None,
    ) -> List[DetectorContractResult]:
        """
        Execute arbitration escalation. Runs models on thread pool to protect event loop.
        """
        await self.initialize()
        escalation_results: List[DetectorContractResult] = []

        context_dict = {"bounded_context": bounded_context} if bounded_context else {}

        # 1. Escalate to Laya mmBERT
        t_start = time.perf_counter()
        try:
            # Run model decide through thread pool
            laya_res = await self.ml_pool.run_inference(self._run_laya_sync, text, context_dict)
            laya_ms = (time.perf_counter() - t_start) * 1000

            is_mal = bool(laya_res.get("is_malicious", False))
            conf = float(laya_res.get("confidence", 0.5))
            primary_attack = laya_res.get("primary_attack") or ("INSTRUCTION_OVERRIDE" if is_mal else "")

            escalation_results.append(
                DetectorContractResult(
                    detector_id="laya_mmbert_tier2",
                    detector_version="1.0.0",
                    tier=2,
                    signal_type="typed_semantic_analysis",
                    is_malicious=is_mal,
                    detector_confidence=conf,
                    risk_score=conf if is_mal else (1.0 - conf) * 0.2,
                    attack_types=[primary_attack] if primary_attack else [],
                    evidence_snippets=[f"Laya verdict: {laya_res.get('reasoning', 'Typed decision evaluated')}"],
                    latency_ms=round(laya_ms, 2),
                    status=DetectorStatus.SUCCESS,
                )
            )
        except Exception as e:
            logger.error(f"Laya escalation error: {e}")
            escalation_results.append(
                DetectorContractResult(
                    detector_id="laya_mmbert_tier2",
                    tier=2,
                    status=DetectorStatus.FAILED,
                    error_message=str(e),
                )
            )

        # 2. Check if Open-Jev escalation is warranted
        # Trigger Open-Jev if Laya is uncertain or directly contradicts Tier 1
        needs_jev = False
        t1_malicious = any(r.is_malicious for r in prior_results if r.tier == 1)
        laya_malicious = any(r.is_malicious for r in escalation_results if r.detector_id == "laya_mmbert_tier2")

        if t1_malicious != laya_malicious:
            needs_jev = True  # Contradiction between Tier 1 ML and Tier 2 Laya
        elif any(0.40 <= r.detector_confidence <= 0.60 for r in escalation_results):
            needs_jev = True  # Boundary ambiguity

        if needs_jev:
            t_start = time.perf_counter()
            try:
                jev_res = await self.ml_pool.run_inference(
                    self._run_open_jev_sync, text, {"context": bounded_context}
                )
                jev_ms = (time.perf_counter() - t_start) * 1000

                is_mal = bool(jev_res.get("is_malicious", False))
                conf = float(jev_res.get("confidence", 0.5))
                attack_category = str(jev_res.get("category") or "").upper()
                if not attack_category or attack_category == "NONE":
                    attack_category = "INSTRUCTION_OVERRIDE"

                escalation_results.append(
                    DetectorContractResult(
                        detector_id="open_jev_tier3",
                        detector_version="1.0.0",
                        tier=2,
                        signal_type="structured_arbitration",
                        is_malicious=is_mal,
                        detector_confidence=conf,
                        risk_score=conf if is_mal else (1.0 - conf) * 0.15,
                        attack_types=[attack_category] if is_mal else [],
                        evidence_snippets=[
                            f"Open-Jev ({jev_res.get('status', 'unknown source')}): "
                            f"{jev_res.get('explanation', 'Arbitration completed')}"
                        ],
                        latency_ms=round(jev_ms, 2),
                        status=DetectorStatus.SUCCESS,
                    )
                )
            except Exception as e:
                logger.error(f"Open-Jev escalation error: {e}")
                escalation_results.append(
                    DetectorContractResult(
                        detector_id="open_jev_tier3",
                        tier=2,
                        status=DetectorStatus.FAILED,
                        error_message=str(e),
                    )
                )

        return escalation_results

    def _run_laya_sync(self, text: str, context: dict) -> dict:
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(self.laya.decide(text, context))
        finally:
            loop.close()

    def _run_open_jev_sync(self, text: str, context: dict) -> dict:
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(self.open_jev.evaluate_ambiguity(text, context))
        finally:
            loop.close()
