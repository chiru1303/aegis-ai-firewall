"""
Aegis AI Firewall - Parallel Decision Orchestrator
Enforces:
1. Invariant 1: Server-derived trust (client trust claims strictly ignored).
2. Invariant 2: Deterministic policy engine is the absolute final authority.
3. Invariant 3: Detector failure cannot silently become security approval (failsafe defaults).
4. Correction 1: Fused decision confidence gate (detector confidence != risk score != decision confidence).
5. Correction 2: ThreadPool executor for ML inference (ASGI event loop never blocked).
6. Correction 6: Bounded session context (no token explosions).
"""
import time
import asyncio
from typing import List, Dict, Any, Optional
from app.decision.decision_schema import (
    DetectorContractResult, OrchestratedDecision, DetectorStatus
)
from app.decision.confidence_gate import ConfidenceGate, GateOutcome
from app.decision.ml_executor import get_ml_executor_pool
from app.decision.bounded_context import build_bounded_context
from app.decision.arbitration import ArbitrationRouter
from app.decision.fusion import EvidenceFusionEngine
from app.detectors import registry as detector_registry, normalizer_engine
from app.classifiers.lightgbm_classifier import LightGBMClassifier
from app.classifiers.deberta_classifier import DeBERTaClassifier
from app.classifiers.wolf_defender import WolfDefenderClassifier
from app.core.logging import get_logger

logger = get_logger(__name__)


class ParallelDecisionOrchestrator:
    """
    Production-grade parallel orchestrator executing Tier 0 deterministic rules,
    Tier 1 ML models, Confidence Gate, and Tier 2 arbitration escalation.
    """

    def __init__(self):
        self.confidence_gate = ConfidenceGate()
        self.evidence_fusion = EvidenceFusionEngine()
        self.arbitration_router = ArbitrationRouter()
        self.ml_pool = get_ml_executor_pool()

        # Tier 1 ML Models
        self.lgb_classifier = LightGBMClassifier()
        self.deberta_classifier = DeBERTaClassifier()
        self.wolf_classifier = WolfDefenderClassifier()
        self._initialized = False
        self._init_lock = asyncio.Lock()

    async def initialize(self):
        """Warm up models and thread pool."""
        async with self._init_lock:
            await self._initialize_models()

    async def _initialize_models(self):
        if not self._initialized:
            try:
                await self.lgb_classifier.initialize()
                await self.deberta_classifier.initialize()
                await self.wolf_classifier.initialize()
                await self.arbitration_router.initialize()
                self._initialized = True
                logger.info("ParallelDecisionOrchestrator initialized successfully.")
            except Exception as e:
                logger.warning(f"ParallelDecisionOrchestrator model init notice: {e}")

    async def execute_pipeline(
        self,
        content: str,
        source_type: str,
        origin: str,
        authoritative_trust: str,
        session_id: Optional[str] = None,
        session_engine: Optional[Any] = None,
        trace_id: Optional[str] = None,
        request_id: Optional[str] = None,
        tenant_id: str = "tenant_default",
        application_id: Optional[str] = None,
        record_session_event: bool = True,
    ) -> OrchestratedDecision:
        """
        Full zero-trust parallel execution path.
        """
        start_time = time.perf_counter()
        req_id = request_id or f"req_{int(time.time()*1000)}"
        await self.initialize()

        # 1. Normalization & Obfuscation Extraction
        norm_result = normalizer_engine.normalize(content)
        normalized_content = norm_result.normalized
        decoded_variants = norm_result.decoded_variants
        obfuscation_score = norm_result.anomaly_score

        # 2. Build Bounded Context for Session Trajectory (Correction 6)
        bounded_context = await build_bounded_context(session_id, session_engine, tenant_id=tenant_id, application_id=application_id)
        trajectory_risk = bounded_context.accumulated_risk if bounded_context else 0.0

        detector_results: List[DetectorContractResult] = []
        detector_failures: List[str] = []

        # 3. Schedule Tier 0 Deterministic Rules and Tier 1 ML concurrently
        metadata = {
            "source_type": source_type,
            "origin": origin,
            "trust_level": authoritative_trust,
            "session_id": session_id,
            "bounded_context": bounded_context.bounded_summary_text if bounded_context else "",
            "session_state": bounded_context.current_state if bounded_context else "NORMAL",
            "trajectory_risk": bounded_context.accumulated_risk if bounded_context else 0.0,
            "session_event_count": bounded_context.event_count if bounded_context else 0,
        }

        # Run Tier 0 in parallel
        tier0_task = self._run_tier0(content, normalized_content, decoded_variants, metadata)

        # Run Tier 1 ML in parallel using MLExecutorPool worker threads (Correction 2)
        tier1_task = self._run_tier1_parallel(content, normalized_content, metadata)

        # Await both tiers
        t0_results, t1_results = await asyncio.gather(tier0_task, tier1_task)
        detector_results.extend(t0_results)
        detector_results.extend(t1_results)

        # Track any failed detectors
        for r in detector_results:
            if r.status == DetectorStatus.FAILED:
                detector_failures.append(r.detector_id)

        # 4. Check Mandatory Security Blocks (e.g. Credential theft, secret exfiltration)
        mandatory_violation = False
        for r in detector_results:
            if r.is_malicious:
                for at in r.attack_types:
                    if at in ["CREDENTIAL_THEFT", "SECRET_EXTRACTION", "credential_detector", "secret_extraction"]:
                        mandatory_violation = True
                        break

        # 5. Evaluate Confidence Gate (Correction 1)
        gate_outcome, fused_risk, mean_det_conf, decision_conf, gate_reasons = (
            self.confidence_gate.evaluate_gate(
                t0_results,
                t1_results,
                source_trust=authoritative_trust,
                mandatory_block_detected=mandatory_violation,
            )
        )

        escalated_results: List[DetectorContractResult] = []

        # 6. Arbitration Escalation Path (If Gate dictates ESCALATE)
        if gate_outcome == GateOutcome.ESCALATE:
            logger.info(f"Escalating request {req_id} to Tier 2 deep evaluation.")
            escalated_results = await self.arbitration_router.arbitrate(
                text=normalized_content or content,
                prior_results=detector_results,
                bounded_context=bounded_context.bounded_summary_text if bounded_context else None,
            )
            detector_results.extend(escalated_results)

            for r in escalated_results:
                if r.status == DetectorStatus.FAILED:
                    detector_failures.append(r.detector_id)

            # Clear an isolated ML alarm only when the independent Tier 2 review
            # confidently finds no injection and no deterministic rule matched.
            # Keep the adjudication in metadata for audit, but do not let a lone
            # model vote inflate risk or appear as a confirmed attack.
            tier2_successes = [r for r in escalated_results if r.status == DetectorStatus.SUCCESS]
            tier2_clear = bool(tier2_successes) and all(
                not r.is_malicious and r.detector_confidence >= 0.80 for r in tier2_successes
            )
            deterministic_findings = [r for r in t0_results if r.is_malicious]
            learned_findings = [r for r in t1_results if r.is_malicious]
            if tier2_clear and not deterministic_findings and len(learned_findings) == 1:
                lone_finding = learned_findings[0]
                lone_finding.metadata = {
                    **lone_finding.metadata,
                    "initial_model_verdict": "suspicious",
                    "adjudication": "not_confirmed_by_independent_review",
                }
                lone_finding.is_malicious = False
                lone_finding.risk_score = 0.0
                lone_finding.attack_types = []
                lone_finding.evidence_snippets = []

        # 7. Final Evidence Fusion
        final_risk_score, attack_types_list, component_scores = (
            self.evidence_fusion.fuse_evidence(
                results=detector_results,
                trajectory_risk=trajectory_risk,
                obfuscation_score=obfuscation_score,
                source_trust=authoritative_trust,
            )
        )

        # 8. Determine Risk Level
        if final_risk_score >= 0.80:
            risk_level = "CRITICAL"
        elif final_risk_score >= 0.50:
            risk_level = "HIGH"
        elif final_risk_score >= 0.20:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # 9. Formulate Decision
        # Invariant 3: If failsafe triggered, force BLOCK
        if bounded_context and bounded_context.current_state == "QUARANTINE":
            decision = "QUARANTINE"
            outcome_label = "SESSION_QUARANTINE"
        elif gate_outcome == GateOutcome.FAILSAFE_BLOCK:
            decision = "BLOCK"
            outcome_label = "DEGRADED_FAILSAFE_BLOCK"
        elif mandatory_violation or gate_outcome == GateOutcome.FAST_BLOCK or final_risk_score >= 0.75:
            decision = "BLOCK"
            outcome_label = "FAST_BLOCK" if gate_outcome == GateOutcome.FAST_BLOCK else "ESCALATED_BLOCK"
        elif gate_outcome == GateOutcome.FAST_ALLOW and final_risk_score <= 0.15:
            decision = "ALLOW"
            outcome_label = "FAST_ALLOW"
        elif risk_level == "MEDIUM":
            decision = "SANITIZE"
            outcome_label = "ESCALATED_SANITIZE"
        elif risk_level == "HIGH":
            decision = "REQUIRE_REVIEW"
            outcome_label = "ESCALATED_REVIEW"
        else:
            decision = "ALLOW"
            outcome_label = "ESCALATED_ALLOW"

        # 10. Compile structured evidence
        evidence_records = []
        for r in detector_results:
            if r.is_malicious or r.risk_score > 0.1:
                evidence_records.append({
                    "detector": r.detector_id,
                    "tier": r.tier,
                    "confidence": r.detector_confidence,
                    "risk_score": r.risk_score,
                    "snippets": r.evidence_snippets[:3],
                    "status": r.status.value,
                })

        total_latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

        all_findings = []
        for r in detector_results:
            if hasattr(r, "findings") and r.findings:
                all_findings.extend(r.findings)

        if session_id and session_engine and record_session_event:
            await session_engine.process_event(session_id, content,
                {"automatic": True, "risk_score": final_risk_score}, tenant_id, application_id)
        return OrchestratedDecision(
            request_id=req_id,
            decision=decision,
            risk_score=final_risk_score,
            risk_level=risk_level,
            detector_confidence=round(mean_det_conf, 4),
            decision_confidence=round(decision_conf, 4),
            gate_outcome=outcome_label,
            attack_types=[at["type"] for at in attack_types_list],
            evidence=evidence_records,
            findings=all_findings,
            degraded_mode=len(detector_failures) > 0,
            detector_failures=detector_failures,
            detector_results=detector_results,
            latency_ms=total_latency_ms,
        )

    async def _run_tier0(
        self, content: str, normalized: str, decoded: List[str], metadata: dict
    ) -> List[DetectorContractResult]:
        """Execute all Tier 0 rule detectors concurrently."""
        t_start = time.perf_counter()
        try:
            t0_raw = await detector_registry.run_tier(0, content, normalized, decoded, metadata)
            results = []
            for r in t0_raw:
                ms = round((time.perf_counter() - t_start) * 1000, 2)
                raw_findings = [
                    f.__dict__ if hasattr(f, "__dict__") else dict(f)
                    for f in getattr(r, "findings", [])
                ]
                results.append(
                    DetectorContractResult(
                        detector_id=r.detector_name,
                        detector_version="1.0.0",
                        tier=0,
                        signal_type="deterministic_rule",
                        is_malicious=r.detected,
                        detector_confidence=r.confidence,
                        risk_score=r.confidence if r.detected else 0.0,
                        attack_types=r.attack_types,
                        evidence_snippets=r.matched_signals[:5],
                        findings=raw_findings,
                        latency_ms=ms,
                        status=DetectorStatus.SUCCESS,
                    )
                )
            return results
        except Exception as e:
            logger.error(f"Tier 0 execution failure: {e}")
            return [
                DetectorContractResult(
                    detector_id="tier0_rules_engine",
                    tier=0,
                    status=DetectorStatus.FAILED,
                    error_message=str(e),
                )
            ]

    async def _run_tier1_parallel(
        self, content: str, normalized: str, metadata: dict
    ) -> List[DetectorContractResult]:
        """
        Execute Tier 1 ML classifiers in parallel on dedicated thread pool (Correction 2).
        """
        text = normalized or content

        async def run_lgb() -> DetectorContractResult:
            t0 = time.perf_counter()
            try:
                res = await self.ml_pool.run_inference(self._run_lgb_sync, text, metadata)
                ms = (time.perf_counter() - t0) * 1000
                is_mal = bool(res.get("is_malicious", False))
                conf = float(res.get("confidence", 0.0))
                return DetectorContractResult(
                    detector_id="lightgbm_tier1",
                    tier=1,
                    signal_type="feature_gradient_boosting",
                    is_malicious=is_mal,
                    detector_confidence=conf,
                    risk_score=conf if is_mal else 0.0,
                    attack_types=["INSTRUCTION_OVERRIDE"] if is_mal else [],
                    evidence_snippets=[f"LightGBM model score: {conf:.2f}"] if is_mal else [],
                    latency_ms=round(ms, 2),
                    status=DetectorStatus.SUCCESS,
                )
            except Exception as e:
                logger.warning(f"LightGBM inference error: {e}")
                return DetectorContractResult(
                    detector_id="lightgbm_tier1",
                    tier=1,
                    status=DetectorStatus.FAILED,
                    error_message=str(e),
                )

        async def run_deberta() -> DetectorContractResult:
            t0 = time.perf_counter()
            try:
                res = await self.ml_pool.run_inference(self._run_deberta_sync, text)
                ms = (time.perf_counter() - t0) * 1000
                if res.get("status") == "unavailable":
                    return DetectorContractResult(
                        detector_id="deberta_onnx_tier1",
                        tier=1,
                        signal_type="transformer_embedding",
                        latency_ms=round(ms, 2),
                        status=DetectorStatus.SKIPPED,
                    )
                if res.get("status") == "error":
                    return DetectorContractResult(
                        detector_id="deberta_onnx_tier1",
                        tier=1,
                        status=DetectorStatus.FAILED,
                        error_message=str(res.get("error", "DeBERTa inference failed"))[:240],
                    )
                is_mal = bool(res.get("is_malicious", False))
                conf = float(res.get("confidence", 0.0))
                return DetectorContractResult(
                    detector_id="deberta_onnx_tier1",
                    tier=1,
                    signal_type="transformer_embedding",
                    is_malicious=is_mal,
                    detector_confidence=conf,
                    risk_score=conf if is_mal else 0.0,
                    attack_types=["INSTRUCTION_OVERRIDE"] if is_mal else [],
                    evidence_snippets=[f"DeBERTa injection score: {conf:.2f}"] if is_mal else [],
                    latency_ms=round(ms, 2),
                    status=DetectorStatus.SUCCESS,
                )
            except Exception as e:
                logger.warning(f"DeBERTa inference error: {e}")
                return DetectorContractResult(
                    detector_id="deberta_onnx_tier1",
                    tier=1,
                    status=DetectorStatus.FAILED,
                    error_message=str(e),
                )

        async def run_wolf() -> DetectorContractResult:
            t0 = time.perf_counter()
            try:
                res = await self.ml_pool.run_inference(self._run_wolf_sync, text)
                ms = (time.perf_counter() - t0) * 1000
                if res.get("status") == "ok":
                    is_mal = bool(res.get("is_malicious", False))
                    conf = float(res.get("confidence", 0.0))
                    return DetectorContractResult(
                        detector_id="wolf_defender_tier1",
                        tier=1,
                        signal_type="onnx_classifier",
                        is_malicious=is_mal,
                        detector_confidence=conf,
                        risk_score=conf if is_mal else 0.0,
                        attack_types=["INSTRUCTION_OVERRIDE"] if is_mal else [],
                        evidence_snippets=["Wolf Defender v2 detected pattern"] if is_mal else [],
                        latency_ms=round(ms, 2),
                        status=DetectorStatus.SUCCESS,
                    )
                return DetectorContractResult(
                    detector_id="wolf_defender_tier1",
                    tier=1,
                    status=DetectorStatus.SKIPPED,
                )
            except Exception as e:
                return DetectorContractResult(
                    detector_id="wolf_defender_tier1",
                    tier=1,
                    status=DetectorStatus.FAILED,
                    error_message=str(e),
                )

        t1_results = await asyncio.gather(run_lgb(), run_deberta(), run_wolf())
        return list(t1_results)

    def _run_lgb_sync(self, text: str, metadata: dict) -> dict:
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(self.lgb_classifier.predict(text, metadata))
        finally:
            loop.close()

    def _run_deberta_sync(self, text: str) -> dict:
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(self.deberta_classifier.predict(text))
        finally:
            loop.close()

    def _run_wolf_sync(self, text: str) -> dict:
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(self.wolf_classifier.predict(text))
        finally:
            loop.close()


shared_orchestrator = ParallelDecisionOrchestrator()
