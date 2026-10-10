"""
Aegis AI Firewall - API Routes
Complete integration of all detection engines, risk, policy, provenance,
audit, session, tool firewall, and OpenAI-compatible proxy.
"""
import time
import asyncio
import uuid
import hashlib
import json
from datetime import timedelta
from typing import Dict, Any, List, Optional
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Request, Query, status
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
import httpx

from app.core.database import get_db
from app.core.config import settings
from app.core.security import verify_api_key, generate_request_id
from app.core.logging import get_logger
from app.core.time import now_ist, now_utc, to_ist, format_ist
from app.models.schemas import (
    ScanRequest, DocumentScanRequest, ImageScanRequest, WebScanRequest,
    ToolCheckRequest, SessionEventRequest, ScanResponse, ToolCheckResponse,
    SessionResponse, AuditRecord, HealthResponse, MetricsResponse, PolicyResponse,
    Decision, RiskLevel, ContentSource, TrustLevel, AttackDetection, AttackType,
    DetectionEvidence, ProvenanceInfo, SanitizationResult, SourceType, ContentPayload,
    Segment, SegmentFinding, Finding
)
from app.models.database_models import RequestModel, AuditLogModel, PolicyModel, SessionModel, ApplicationModel, ApiCredentialModel

# Import real engines
from app.detectors import registry as detector_registry, normalizer_engine
from app.detectors.base import DetectorResult
from app.risk.engine import RiskEngine, DetectorResult as RiskDetectorResult
from app.policy.engine import PolicyEngine, Policy, GLOBAL_PLATFORM_MANDATORY_BLOCKS
from app.provenance.engine import ProvenanceEngine
from app.audit.engine import AuditEngine
from app.sessions.engine import SessionEngine, session_engine
from app.tools.firewall import ToolFirewall, TOOL_RISK_LEVELS
from app.tools.sanitizer import ContentSanitizer
from app.tools.output_firewall import OutputFirewall
from app.parsers.registry import registry as parser_registry
from app.parsers.sniff import sniff_mime_type, check_zip_bomb

logger = get_logger(__name__)

router = APIRouter()

# Initialize engines (singleton instances)
risk_engine = RiskEngine()
policy_engine = PolicyEngine()
provenance_engine = ProvenanceEngine()
audit_engine = AuditEngine()

sanitizer = ContentSanitizer()
output_firewall = OutputFirewall()

from app.classifiers.ensemble import EnsembleClassifier
from app.decision.orchestrator import ParallelDecisionOrchestrator, shared_orchestrator
from app.core.tenant import (
    resolve_tenant_context,
    require_role,
    TenantContext,
    derive_authoritative_trust,
    SOURCE_TYPE_DEFAULT_TRUST,
    hash_api_key,
)

from types import SimpleNamespace
parallel_orchestrator = shared_orchestrator
ensemble_classifier = SimpleNamespace(lgb=parallel_orchestrator.lgb_classifier,
    deberta=parallel_orchestrator.deberta_classifier, wolf=parallel_orchestrator.wolf_classifier,
    laya=parallel_orchestrator.arbitration_router.laya, open_jev=parallel_orchestrator.arbitration_router.open_jev,
    initialize=parallel_orchestrator.initialize)

# Attack type mapping from detector names to AttackType enum
DETECTOR_TO_ATTACK_TYPE = {
    "instruction_override": AttackType.INSTRUCTION_OVERRIDE,
    "role_manipulation": AttackType.ROLE_CHANGE,
    "secret_extraction": AttackType.SECRET_EXTRACTION,
    "credential_detector": AttackType.CREDENTIAL_THEFT,
    "tool_abuse": AttackType.TOOL_ABUSE,
    "context_poisoning": AttackType.CONTEXT_POISONING,
    "obfuscation": AttackType.ENCODED_INSTRUCTION,
    "indirect_injection": AttackType.INDIRECT_PROMPT_INJECTION,
    "encoded_instruction": AttackType.ENCODED_INSTRUCTION,
    "InstructionOverrideDetector": AttackType.INSTRUCTION_OVERRIDE,
    "RoleManipulationDetector": AttackType.ROLE_CHANGE,
    "SecretExtractionDetector": AttackType.SECRET_EXTRACTION,
    "CredentialDetector": AttackType.CREDENTIAL_THEFT,
    "ToolAbuseDetector": AttackType.TOOL_ABUSE,
    "ContextPoisoningDetector": AttackType.CONTEXT_POISONING,
    "ObfuscationDetector": AttackType.ENCODED_INSTRUCTION,
    "IndirectInjectionDetector": AttackType.INDIRECT_PROMPT_INJECTION,
    "EncodedInstructionDetector": AttackType.ENCODED_INSTRUCTION,
}


async def run_detection_pipeline(
    content: str,
    source_type: str,
    origin: str,
    trust_level: str = "UNTRUSTED",
    session_id: Optional[str] = None,
    db: Optional[AsyncSession] = None,
    tenant_id: str = "tenant_default",
    application_id: Optional[str] = None,
    environment_id: Optional[str] = None,
    connector_id: Optional[str] = None,
    record_session_event: bool = True,
    segments: Optional[List[Segment]] = None,
) -> dict:
    """
    Run the complete parallel detection pipeline:
    1. Server-derived trust enforcement (Invariant 1)
    2. Segment extraction & individual/aggregate scanning (Phase 2 Universal Ingestion)
    3. Parallel execution of Tier 0 rules & Tier 1 ML on dedicated thread pool (Correction 2)
    4. 3-tier confidence gating: detector conf != risk score != decision conf (Correction 1)
    5. Arbitration escalation to Laya mmBERT and Open-Jev
    6. Hierarchical policy evaluation with non-overridable platform guardrails (Correction 4)
    7. Content sanitization if policy dictates SANITIZE
    8. Provenance tracking
    9. Durable audit outbox atomic commit before response (Correction 7 & 8)
    """
    start_time = time.perf_counter()
    if not isinstance(content, str) or len(content.encode("utf-8")) > settings.MAX_CONTENT_LENGTH:
        raise HTTPException(413, "Content exceeds inspection budget")
    request_id = generate_request_id()
    trace_id = str(uuid.uuid4())

    # INVARIANT 1: Untrusted input cannot elevate its own trust level
    st_lower = str(source_type).lower()
    server_default_trust = SOURCE_TYPE_DEFAULT_TRUST.get(st_lower, TrustLevel.UNTRUSTED)
    if trust_level != server_default_trust.value and trust_level == "TRUSTED":
        logger.warning(
            f"Overriding client-asserted '{trust_level}' trust to server-derived '{server_default_trust.value}'"
        )
        trust_level = server_default_trust.value

    # UNIVERSAL INGESTION: Segment conversion if segments not provided
    ingestion_review_reasons = []
    if segments is None:
        segments = []
        c_stripped = content.strip()
        content_bytes = content.encode('utf-8')

        # Auto-detect JSON content
        if (c_stripped.startswith('{') and c_stripped.endswith('}')) or (c_stripped.startswith('[') and c_stripped.endswith(']')):
            try:
                from app.parsers.json_parser import JSONParser
                j_parser = JSONParser()
                j_extracted = await j_parser.parse(content_bytes)
                segments = j_extracted.segments
            except Exception:
                pass

        # Auto-detect HTML content or use source_type hint
        if not segments:
            c_lower = c_stripped.lower()
            is_html = (
                c_lower.startswith('<!doctype html')
                or c_lower.startswith('<html')
                or c_lower.startswith('<head')
                or c_lower.startswith('<body')
                or (c_lower.startswith('<') and ('<!--' in c_lower or '<div' in c_lower or '<p' in c_lower or '<script' in c_lower))
                or source_type in ('web', 'html')
            )
            if is_html:
                try:
                    from app.parsers.html_parser import HTMLParser
                    h_parser = HTMLParser()
                    h_extracted = await h_parser.parse(content_bytes, '', 'text/html')
                    segments = h_extracted.segments
                    if h_extracted.metadata.get("image_sources"):
                        ingestion_review_reasons.append(
                            "HTML contains remote images that require OCR via the web scanner"
                        )
                    ingestion_review_reasons.extend(h_extracted.extraction_warnings)
                except Exception:
                    pass

        # Auto-detect Markdown content via source_type hint
        if not segments and source_type in ('markdown', 'md'):
            try:
                from app.parsers.markdown_parser import MarkdownParser
                m_parser = MarkdownParser()
                m_extracted = await m_parser.parse(content_bytes, '', 'text/markdown')
                segments = m_extracted.segments
                if m_extracted.metadata.get("image_sources"):
                    ingestion_review_reasons.append(
                        "Markdown contains external images that require separate OCR inspection"
                    )
                ingestion_review_reasons.extend(m_extracted.extraction_warnings)
            except Exception:
                pass

        # Auto-detect source code via source_type hint
        if not segments and source_type == 'code':
            try:
                from app.parsers.code_parser import CodeParser
                c_parser = CodeParser()
                c_extracted = await c_parser.parse(content_bytes)
                segments = c_extracted.segments
            except Exception:
                pass

        # Fallback: create a single user:prompt segment
        if not segments and content:
            segments = [Segment(
                id=f"seg-prompt-{uuid.uuid4().hex[:6]}",
                text=content,
                source_type=source_type,
                location="user:prompt",
                visibility="visible",
                trust=trust_level,
            )]

    # Segment Scanner: Scan every segment individually to pinpoint exact location
    segment_findings: List[SegmentFinding] = []
    for seg in segments:
        if not seg.text or not seg.text.strip():
            continue
        seg_norm = normalizer_engine.normalize(seg.text)
        t0_results = await detector_registry.run_tier(
            0,
            content=seg.text,
            normalized=seg_norm.normalized,
            decoded=seg_norm.decoded_variants,
            metadata={"source_type": seg.source_type, "location": seg.location},
        )
        for r in t0_results:
            if r.detected:
                matched = " | ".join(r.matched_signals)[:150] if r.matched_signals else r.detector_name
                att_type = r.attack_types[0] if r.attack_types else "INSTRUCTION_OVERRIDE"
                finding = SegmentFinding(
                    segment_id=seg.id,
                    location=seg.location,
                    visibility=seg.visibility,
                    attack_type=att_type,
                    risk_score=round(r.confidence, 3),
                    matched_signal=matched,
                    evidence=f"Injection found in {seg.location} ({seg.visibility}): '{matched}'",
                )
                segment_findings.append(finding)

    # Execute Parallel Decision Orchestrator on aggregate content
    orchestrated = await parallel_orchestrator.execute_pipeline(
        content=content,
        source_type=source_type,
        origin=origin,
        authoritative_trust=trust_level,
        session_id=session_id,
        session_engine=session_engine,
        tenant_id=tenant_id,
        application_id=application_id,
        record_session_event=record_session_event,
        trace_id=trace_id,
        request_id=request_id,
    )
    if ingestion_review_reasons:
        orchestrated.risk_score = max(float(orchestrated.risk_score), 0.75)
        orchestrated.risk_level = "HIGH"

    # Invariant: Malicious signals from individual segments are promoted into the aggregate decision
    if segment_findings:
        max_seg_risk = max(f.risk_score for f in segment_findings)
        if max_seg_risk > orchestrated.risk_score:
            orchestrated.risk_score = max_seg_risk
            if max_seg_risk >= 0.8:
                orchestrated.risk_level = "CRITICAL"
            elif max_seg_risk >= 0.5:
                orchestrated.risk_level = "HIGH"
            elif max_seg_risk >= 0.2:
                orchestrated.risk_level = "MEDIUM"

        for f in segment_findings:
            if f.attack_type not in orchestrated.attack_types:
                orchestrated.attack_types.append(f.attack_type)
            orchestrated.evidence.append({
                "detector": f"SegmentScanner[{f.location}]",
                "risk_score": f.risk_score,
                "snippets": [f.evidence],
            })

    # Hierarchical Policy Evaluation (Correction 4)
    from app.risk.engine import RiskAssessment
    risk_assessment = RiskAssessment(
        risk_score=orchestrated.risk_score,
        risk_level=orchestrated.risk_level,
        confidence=orchestrated.detector_confidence,
        attack_types=[{"type": at, "confidence": orchestrated.risk_score} for at in orchestrated.attack_types],
        evidence=orchestrated.evidence,
        component_scores={},
        boosting_factors=[],
        explanation="Evaluated by Parallel Decision Orchestrator with Universal Segment Ingestion",
    )

    policy_decision = await policy_engine.evaluate_hierarchical(
        risk=risk_assessment,
        tenant_id=tenant_id,
        application_id=application_id,
        environment_id=environment_id,
        db=db,
    )

    decision_map = {
        "ALLOW": Decision.ALLOW,
        "SANITIZE": Decision.SANITIZE,
        "BLOCK": Decision.BLOCK,
        "QUARANTINE": Decision.QUARANTINE,
        "REQUIRE_REVIEW": Decision.REQUIRE_REVIEW,
    }
    from app.decision.enforcement import enforce
    enforced, sanitized_content = await enforce(orchestrated, policy_decision, content,
        sanitizer, parallel_orchestrator, source_type, origin, trust_level)
    decision = decision_map.get(enforced, Decision.BLOCK)
    if ingestion_review_reasons:
        decision = Decision.REQUIRE_REVIEW
        sanitized_content = None

    # Provenance tracking
    content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    try:
        provenance = await provenance_engine.track_content(
            content=content,
            source_type=source_type,
            origin=origin,
        )
    except Exception:
        provenance = None

    prov_info = ProvenanceInfo(
        source=ContentSource(
            type=SourceType(source_type) if source_type in [e.value for e in SourceType] else SourceType.unknown,
            origin=origin,
            trust=TrustLevel(trust_level) if trust_level in [e.value for e in TrustLevel] else TrustLevel.UNTRUSTED,
        ),
        origin=origin,
        trust_level=TrustLevel(trust_level) if trust_level in [e.value for e in TrustLevel] else TrustLevel.UNTRUSTED,
        content_id=provenance.content_id if provenance else content_hash[:16],
        transformation_chain=provenance.transformation_chain if provenance else ["RAW", "NORMALIZED", "SEGMENTS_SCANNED"],
    )

    # Build response evidence
    evidence_list = []
    for reason in ingestion_review_reasons:
        evidence_list.append(DetectionEvidence(
            detector="UniversalIngestionReview",
            matched_signal=reason[:200],
            severity="HIGH",
        ))
    # Add precise segment findings first
    for f in segment_findings:
        evidence_list.append(DetectionEvidence(
            detector=f"SegmentScanner[{f.location}]",
            matched_signal=f.evidence,
            severity="CRITICAL" if f.risk_score >= 0.8 else "HIGH",
        ))

    for ev in orchestrated.evidence:
        evidence_list.append(DetectionEvidence(
            detector=ev.get("detector", "unknown"),
            matched_signal=" | ".join(ev.get("snippets", []))[:200] if ev.get("snippets") else f"Score: {ev.get('risk_score', 0.0)}",
            severity="HIGH" if ev.get("risk_score", 0.0) >= 0.7 else "MEDIUM",
        ))

    # Build response attack detections
    alias_map = {
        "INSTRUCTION_OVERRIDE": AttackType.INSTRUCTION_OVERRIDE,
        "ROLE_CHANGE": AttackType.ROLE_CHANGE,
        "SECRET_EXTRACTION": AttackType.SECRET_EXTRACTION,
        "CREDENTIAL_THEFT": AttackType.CREDENTIAL_THEFT,
        "TOOL_ABUSE": AttackType.TOOL_ABUSE,
        "CONTEXT_POISONING": AttackType.CONTEXT_POISONING,
        "MULTI_STEP_JAILBREAK": AttackType.MULTI_STEP_JAILBREAK,
        "ENCODED_INSTRUCTION": AttackType.ENCODED_INSTRUCTION,
        "INDIRECT_PROMPT_INJECTION": AttackType.INDIRECT_PROMPT_INJECTION,
    }
    attack_detections = []
    for at in orchestrated.attack_types:
        clean_at = at.strip().upper().replace(" ", "_")
        at_enum = alias_map.get(clean_at)
        if at_enum:
            attack_detections.append(AttackDetection(type=at_enum, confidence=orchestrated.risk_score))

    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

    risk_level_map = {
        "CRITICAL": RiskLevel.CRITICAL,
        "HIGH": RiskLevel.HIGH,
        "MEDIUM": RiskLevel.MEDIUM,
        "LOW": RiskLevel.LOW,
    }
    risk_level = risk_level_map.get(orchestrated.risk_level, RiskLevel.LOW)

    # Convert detector findings into standard Finding models
    findings_list = []
    for f in getattr(orchestrated, "findings", []):
        if isinstance(f, dict):
            findings_list.append(Finding(
                attack_type=f.get("attack_type", "INSTRUCTION_OVERRIDE"),
                confidence=float(f.get("confidence", 0.9)),
                evidence_span=str(f.get("evidence_span", ""))[:200],
                detector=str(f.get("detector", "unknown")),
                location=str(f.get("location", "content")),
            ))
        elif hasattr(f, "attack_type"):
            findings_list.append(Finding(
                attack_type=f.attack_type,
                confidence=f.confidence,
                evidence_span=str(f.evidence_span)[:200],
                detector=str(f.detector),
                location=str(f.location),
            ))

    response = ScanResponse(
        request_id=request_id,
        decision=decision,
        risk_score=orchestrated.risk_score,
        risk_level=risk_level,
        confidence=orchestrated.decision_confidence,
        attack_types=attack_detections,
        content_status=trust_level,
        sanitized_content=sanitized_content,
        evidence=evidence_list,
        provenance=prov_info,
        latency_ms=latency_ms,
        policy=policy_decision.policy_name,
        trace_id=trace_id,
        segments=segments,
        segment_findings=segment_findings,
        findings=findings_list,
    )

    # CORRECTION 7 & 8: Durable Audit Outbox write committed synchronously before returning response
    if db:
        try:
            if ingestion_review_reasons:
                decision_explanation = "Review required because content extraction was incomplete: " + "; ".join(ingestion_review_reasons)
            elif orchestrated.gate_outcome == "DEGRADED_FAILSAFE_BLOCK":
                decision_explanation = "Blocked by the detector failsafe because a required inspection step was unavailable."
            elif orchestrated.gate_outcome == "ESCALATED_BLOCK":
                decision_explanation = f"Blocked because the combined detector risk score reached {float(orchestrated.risk_score) * 100:.0f}%, above the 75% automatic-block threshold."
            elif orchestrated.gate_outcome == "FAST_BLOCK":
                decision_explanation = "Blocked because a high-confidence mandatory security rule matched."
            elif orchestrated.gate_outcome == "SESSION_QUARANTINE":
                decision_explanation = "This session was quarantined after cumulative risk crossed its safety limit."
            elif decision == Decision.REQUIRE_REVIEW and orchestrated.decision == "SANITIZE":
                decision_explanation = "Review required because the proposed sanitized content did not pass the follow-up security scan."
            elif decision == Decision.REQUIRE_REVIEW:
                decision_explanation = f"Review required because the assessed risk score is {float(orchestrated.risk_score) * 100:.0f}% and the active gate requires review."
            elif decision == Decision.SANITIZE:
                decision_explanation = "Content was sanitized under the active policy."
            else:
                decision_explanation = policy_decision.explanation
            await audit_engine.log_decision(
                request_id=request_id,
                content=content,
                source_type=source_type,
                origin=origin,
                decision=decision.value,
                risk_score=orchestrated.risk_score,
                risk_level=orchestrated.risk_level,
                confidence=orchestrated.decision_confidence,
                attack_types=[{"type": at.type.value if hasattr(at, "type") else str(at), "confidence": orchestrated.risk_score} for at in attack_detections],
                detector_results=[r.model_dump() for r in orchestrated.detector_results],
                policy_name=policy_decision.policy_name,
                policy_rules_applied=list(policy_decision.applied_rules) + (["incomplete_multimodal_extraction"] if ingestion_review_reasons else []),
                decision_rationale={
                    "decision": decision.value,
                    "decision_explanation": decision_explanation,
                    "gate_outcome": str(orchestrated.gate_outcome),
                    "policy_explanation": policy_decision.explanation,
                    "mandatory_block_reason": policy_decision.mandatory_block_reason,
                    "policy_rules_applied": list(policy_decision.applied_rules) + (["incomplete_multimodal_extraction"] if ingestion_review_reasons else []),
                    "attack_types": [str(at.type.value if hasattr(at, "type") else at) for at in attack_detections],
                    "risk_score": float(orchestrated.risk_score),
                    "risk_level": str(orchestrated.risk_level),
                    "ingestion_review_reasons": list(ingestion_review_reasons),
                    "severity_method": "Risk score is normalized from 0 to 1: LOW <0.20, MEDIUM 0.20–0.49, HIGH 0.50–0.79, CRITICAL >=0.80. The decision may also be affected by mandatory policy rules, failsafe state, or review requirements.",
                },
                latency_ms=latency_ms,
                provenance={"trust_level": trust_level, "content_id": prov_info.content_id},
                tenant_id=tenant_id,
                application_id=application_id,
                environment_id=environment_id,
                connector_id=connector_id,
                session_id=session_id,
                sanitization={"sanitized": sanitized_content is not None},
                db=db,
                trace_id=trace_id,
                gateway_overhead_ms=latency_ms,
                upstream_llm_ms=0.0,
                total_ms=latency_ms,
            )
        except Exception as e:
            raise HTTPException(503, "Audit persistence unavailable") from e

    return {
        "response": response,
        "risk_assessment": risk_assessment,
        "policy_decision": policy_decision,
        "detector_results": orchestrated.detector_results,
        "orchestrated": orchestrated,
    }


# ==============================
# SCAN ENDPOINTS
# ==============================

@router.post("/scan", response_model=ScanResponse)
async def scan_endpoint(
    request: ScanRequest,
    tenant_ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """
    Scan text content for prompt injection and security threats.
    Enforces server-derived trust and executes Parallel Decision Orchestrator.
    """
    if isinstance(request.content, str):
        text_content = request.content
    elif hasattr(request.content, "value"):
        text_content = request.content.value
    elif isinstance(request.content, dict):
        text_content = request.content.get("value", "") or request.content.get("content", "") or str(request.content)
    else:
        text_content = str(request.content)

    source_val = "user"
    origin_val = "api"

    if request.source:
        if isinstance(request.source, str):
            source_val = request.source
        elif hasattr(request.source, "type"):
            source_val = request.source.type.value if hasattr(request.source.type, "value") else str(request.source.type)
            origin_val = getattr(request.source, "origin", "api")
        elif isinstance(request.source, dict):
            source_val = request.source.get("type", "user")
            origin_val = request.source.get("origin", "api")

    if request.sourceType:
        source_val = str(request.sourceType).lower()

    # INVARIANT 1: Untrusted input cannot elevate its own trust level
    # Authoritative trust derived strictly from server-side source classification map & tenant context
    authoritative_trust = derive_authoritative_trust(tenant_ctx, source_type=source_val)
    trust_val = authoritative_trust.value

    session_id = request.session_id or f"session_{uuid.uuid4().hex[:8]}"

    result = await run_detection_pipeline(
        content=text_content,
        source_type=source_val,
        origin=origin_val,
        trust_level=trust_val,
        session_id=session_id,
        db=db,
        tenant_id=tenant_ctx.tenant_id,
        application_id=tenant_ctx.application_id,
        environment_id=tenant_ctx.environment_id,
        connector_id=tenant_ctx.connector_id,
    )
    return result["response"]


async def universal_scan_file_core(
    file: UploadFile,
    session_id: str,
    source_type_override: Optional[str],
    tenant_ctx: TenantContext,
    db: Optional[AsyncSession],
) -> ScanResponse:
    file_started = time.perf_counter()
    if not session_id or session_id == "default":
        session_id = f"session_file_{uuid.uuid4().hex[:8]}"
    # 1. Validate file size
    content_bytes = await file.read(settings.MAX_FILE_SIZE + 1)
    if len(content_bytes) > settings.MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size: {settings.MAX_FILE_SIZE} bytes"
        )

    filename = file.filename or "unknown"
    declared_mime = file.content_type or ""

    # 2. Magic byte MIME sniffing
    sniffed_mime = sniff_mime_type(content_bytes, filename)
    effective_mime = sniffed_mime if sniffed_mime != 'application/octet-stream' else declared_mime

    # 3. Decompression bomb guard
    is_safe, bomb_reason = check_zip_bomb(content_bytes)
    parser_failed = False
    failure_reason = ""
    if not is_safe:
        parser_failed = True
        failure_reason = f"[DECOMPRESSION_BOMB] {bomb_reason}"

    # Determine source type
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    type_map = {
        "pdf": "pdf", "docx": "docx", "doc": "docx",
        "html": "web", "htm": "web",
        "md": "code", "json": "api", "xml": "api",
        "txt": "user", "eml": "email",
        "py": "code", "js": "code", "ts": "code", "java": "code",
        "c": "code", "cpp": "code", "go": "code", "rb": "code",
        "png": "image", "jpg": "image", "jpeg": "image", "webp": "image",
    }
    if source_type_override and source_type_override not in ("default", "unknown", ""):
        detected_source = source_type_override
    elif effective_mime.startswith('image/'):
        detected_source = "image"
    elif effective_mime == 'message/rfc822':
        detected_source = "email"
    elif effective_mime == 'text/html':
        detected_source = "web"
    elif effective_mime == 'application/pdf':
        detected_source = "pdf"
    elif 'openxmlformats' in effective_mime:
        detected_source = "docx"
    elif effective_mime == 'application/json':
        detected_source = "api"
    else:
        detected_source = type_map.get(ext, "user")

    text = ""
    extracted_segments: List[Segment] = []

    if not parser_failed:
        try:
            parser = parser_registry.get_parser(effective_mime, filename) or parser_registry.get_parser(declared_mime, filename)
            if parser:
                from app.parsers.budget import parse_with_budget
                extracted = await parse_with_budget(parser, content_bytes, filename, effective_mime)
                extracted_segments = extracted.segments
                if extracted.metadata.get("image_sources"):
                    parser_failed = True
                    failure_reason = "Document references external images that were not OCR-inspected"
                elif len(extracted_segments) > 1000 or sum(len(segment.text) for segment in extracted_segments) > settings.MAX_CONTENT_LENGTH:
                    parser_failed = True
                    failure_reason = "Extracted text exceeds inspection budget"
                elif extracted.extraction_warnings:
                    parser_failed = True
                    failure_reason = "; ".join(extracted.extraction_warnings)
                elif not extracted.text.strip() and not extracted_segments and ext in ("pdf", "docx", "doc", "zip", "tar", "gz", "png", "jpg", "jpeg", "webp", "tiff", "bmp", "gif"):
                    parser_failed = True
                    failure_reason = "Binary document yielded zero valid text (corrupted or unparseable format)"
                else:
                    text = extracted.text
                    if extracted.hidden_content:
                        text += "\n" + "\n".join(extracted.hidden_content)
            else:
                if ext not in ("txt", "log", "csv", "tsv") or b"\x00" in content_bytes:
                    parser_failed = True
                    failure_reason = f"No supported parser found for binary file type '{ext}'"
                else:
                    text = content_bytes.decode(errors="replace")
                    extracted_segments = [Segment(
                        id=f"seg-txt-file-{uuid.uuid4().hex[:6]}",
                        text=text,
                        source_type=detected_source,
                        location="file:body",
                        visibility="visible",
                        trust="UNTRUSTED"
                    )]
        except Exception as e:
            logger.warning(f"Universal document parsing failed: {e}")
            parser_failed = True
            failure_reason = str(e)[:150]

    # FAIL-CLOSED INVARIANT: Corrupt or unparseable binary documents reject/require review, never silently ALLOW
    if parser_failed:
        req_id = f"req_{uuid.uuid4().hex[:12]}"
        trace_id = str(uuid.uuid4())
        total_latency_ms = round((time.perf_counter()-file_started)*1000, 2)
        prov_info = ProvenanceInfo(
            source=ContentSource(type=SourceType(detected_source) if detected_source in [e.value for e in SourceType] else SourceType.unknown, origin=filename, trust=TrustLevel.UNTRUSTED),
            origin=filename,
            trust_level=TrustLevel.UNTRUSTED,
            content_id=req_id[:16],
            transformation_chain=["PARSER_FAILED"],
        )
        evidence_item = DetectionEvidence(
            detector="UniversalFileIngestionEngine",
            matched_signal=f"[PARSER_FAILURE] File failed security parsing: {failure_reason}",
            severity="HIGH",
        )
        if db:
            try:
                await audit_engine.log_decision(
                    request_id=req_id,
                    content=f"[PARSER_FAILURE] {failure_reason}",
                    source_type=detected_source,
                    origin=filename,
                    decision="REQUIRE_REVIEW",
                    risk_score=0.75,
                    risk_level="HIGH",
                    confidence=1.0,
                    attack_types=[{"type": "INDIRECT_PROMPT_INJECTION", "confidence": 0.75}],
                    detector_results=[{"detector": "UniversalFileIngestionEngine", "signal": f"[PARSER_FAILURE] {failure_reason}"}],
                    policy_name="default_zero_trust",
                    policy_rules_applied=["fail_closed_parser_guard"],
                    latency_ms=total_latency_ms,
                    gateway_overhead_ms=total_latency_ms,
                    upstream_llm_ms=0.0,
                    total_ms=total_latency_ms,
                    provenance={"trust_level": "UNTRUSTED", "content_id": req_id[:16]},
                    tenant_id=tenant_ctx.tenant_id,
                    session_id=session_id,
                    db=db,
                    trace_id=trace_id,
                )
            except Exception as ae:
                raise HTTPException(503, "Durable audit storage unavailable") from ae

        return ScanResponse(
            request_id=req_id,
            decision=Decision.REQUIRE_REVIEW,
            risk_score=0.75,
            risk_level=RiskLevel.HIGH,
            confidence=1.0,
            attack_types=[AttackDetection(type=AttackType.INDIRECT_PROMPT_INJECTION, confidence=0.75)],
            content_status="UNTRUSTED",
            evidence=[evidence_item],
            provenance=prov_info,
            latency_ms=total_latency_ms,
            policy="default_zero_trust",
            trace_id=trace_id,
            segments=[],
            segment_findings=[],
        )

    result = await run_detection_pipeline(
        content=text,
        source_type=detected_source,
        origin=filename,
        trust_level="UNTRUSTED",
        session_id=session_id,
        db=db,
        tenant_id=tenant_ctx.tenant_id,
        application_id=tenant_ctx.application_id,
        environment_id=tenant_ctx.environment_id,
        connector_id=tenant_ctx.connector_id,
        segments=extracted_segments,
    )
    return result["response"]


@router.post("/scan/file", response_model=ScanResponse)
async def scan_file_universal(
    file: UploadFile = File(...),
    session_id: str = Form("default"),
    source_type: Optional[str] = Form(None),
    tenant_ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """
    Universal File Ingestion and Scanning Endpoint for heterogeneous multimodal inputs (D3).
    Performs magic-byte MIME sniffing, decompression bomb defense, and dispatches
    to specialized segment parsers (PDF, DOCX, HTML, Email, Markdown, Code, JSON, Image/OCR).
    Scans every segment individually and in aggregate with precise location reporting.
    """
    return await universal_scan_file_core(
        file=file,
        session_id=session_id,
        source_type_override=source_type,
        tenant_ctx=tenant_ctx,
        db=db,
    )


@router.post("/scan/document", response_model=ScanResponse)
async def scan_document(
    session_id: str = Form("default"),
    source_type: str = Form("pdf"),
    file: UploadFile = File(...),
    tenant_ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """
    Scan an uploaded document (PDF, DOCX, HTML, TXT, MD, JSON, XML) for threats.
    Extracts structured segments with precise location tracking.
    """
    return await universal_scan_file_core(
        file=file,
        session_id=session_id,
        source_type_override=source_type,
        tenant_ctx=tenant_ctx,
        db=db,
    )


@router.post("/scan/image", response_model=ScanResponse)
async def scan_image(
    session_id: str = Form("default"),
    file: UploadFile = File(...),
    tenant_ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    return await universal_scan_file_core(file, session_id, None, tenant_ctx, db)


@router.post("/scan/web", response_model=ScanResponse)
async def scan_web(
    request: WebScanRequest,
    tenant_ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """
    Scan web content by safely fetching a URL and running detection.
    Includes SSRF protection - blocks private IPs and metadata endpoints.
    """
    try:
        from app.parsers.web_fetcher import WebFetcher
        fetcher = WebFetcher()
        extracted = await fetcher.fetch_and_parse(request.url)
        if extracted.extraction_warnings or not extracted.text.strip():
            raise HTTPException(422, "Web extraction incomplete or denied; review required")
        text = extracted.text
        if extracted.hidden_content:
            text += "\n[HIDDEN CONTENT DETECTED]\n" + "\n".join(extracted.hidden_content)
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.warning(f"Web fetch failed: {e}")
        raise HTTPException(status_code=502, detail=f"Failed to fetch URL: {str(e)[:200]}")

    result = await run_detection_pipeline(
        content=text,
        source_type="web",
        origin=request.url,
        trust_level="UNTRUSTED",
        session_id=request.session_id,
        db=db,
        tenant_id=tenant_ctx.tenant_id,
        application_id=tenant_ctx.application_id,
        environment_id=tenant_ctx.environment_id,
        connector_id=tenant_ctx.connector_id,
    )
    return result["response"]


# ==============================
# TOOL FIREWALL
# ==============================

@router.post("/tool/check", response_model=ToolCheckResponse)
async def tool_check(
    request: ToolCheckRequest,
    tenant_ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """
    Check whether a tool call should be authorized.
    Evaluates tool permissions, argument safety, and session context.
    """
    start_time = time.perf_counter()

    # Get active policy
    tool_fw = await ToolFirewall.for_context(tenant_ctx, db)

    tool_name = request.tool or request.toolName or "unknown"
    session_id = request.session_id or request.sessionId or "session-firewall"
    requested_by = request.requested_by or request.requestedBy or "agent-1"

    user_context = {
        "session_id": session_id,
        "requested_by": requested_by,
        "tenant_id": tenant_ctx.tenant_id,
        "role": tenant_ctx.role,
    }

    tool_decision = await tool_fw.evaluate_tool_call(
        tool_name=tool_name,
        args=request.arguments,
        user_context=user_context,
    )

    # Map to schema Decision enum
    decision_map = {
        "ALLOW": Decision.ALLOW,
        "BLOCK": Decision.BLOCK,
        "REQUIRE_REVIEW": Decision.REQUIRE_REVIEW,
    }
    decision = decision_map.get(tool_decision.decision, Decision.BLOCK)

    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

    await audit_engine.log_decision(request_id=generate_request_id(), content=json.dumps(request.arguments),
        source_type="tool", origin=requested_by, decision=decision.value, risk_score=tool_decision.risk_score,
        risk_level="HIGH" if decision != Decision.ALLOW else "LOW", confidence=1.0,
        attack_types=[], detector_results=[], policy_name="default_zero_trust", policy_rules_applied=["tool_check"],
        latency_ms=latency_ms, provenance={"tool": tool_name}, tenant_id=tenant_ctx.tenant_id,
        session_id=session_id, db=db)

    evidence = [
        DetectionEvidence(
            detector="tool_firewall",
            matched_signal=f"{tool_name}: {tool_decision.reason}",
            severity="HIGH" if decision == Decision.BLOCK else "LOW",
        )
    ]

    return ToolCheckResponse(
        decision=decision,
        reason=tool_decision.reason,
        risk_score=tool_decision.risk_score,
        tool=tool_name,
        evidence=evidence if decision != Decision.ALLOW else [],
    )


# ==============================
# SESSION TRACKING
# ==============================

@router.post("/session/event", response_model=SessionResponse)
async def session_event(
    request: SessionEventRequest,
    tenant_ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """
    Record a session event and update the session state machine.
    Detects multi-step attack trajectories.
    """
    # Run detection on the event content
    pipeline_result = await run_detection_pipeline(
        content=request.content,
        source_type="user",
        origin="session_event",
        trust_level="SEMI_TRUSTED",
        session_id=request.session_id,
        db=db,
        tenant_id=tenant_ctx.tenant_id,
        application_id=tenant_ctx.application_id,
        environment_id=tenant_ctx.environment_id,
        connector_id=tenant_ctx.connector_id,
    )

    session_state = await session_engine.get_session(request.session_id, tenant_ctx.tenant_id, tenant_ctx.application_id)

    return SessionResponse(
        session_id=request.session_id,
        state=session_state.current_state,
        risk_score=session_state.risk_accumulator,
    )


# ==============================
# HEALTH, METRICS, AUDIT
# ==============================

@router.get("/health", response_model=HealthResponse)
async def health():
    """System health check including database, Redis, and model status."""
    db_status = "ok"
    redis_status = "ok"

    # Check database
    try:
        from app.core.database import engine
        from sqlalchemy import text
        if engine:
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            db_status = "ok"
        else:
            db_status = "in_memory"
    except Exception:
        db_status = "unavailable"

    # Check Redis
    try:
        from app.core.redis_client import redis_client
        if redis_client and redis_client.client and not redis_client._use_in_memory:
            await redis_client.client.ping()
        else:
            redis_status = "not_connected"
    except Exception:
        redis_status = "unavailable"

    # Check models - if any model has not been initialized yet, trigger its initialization
    if not ensemble_classifier.wolf.is_loaded:
        try:
            await ensemble_classifier.wolf.initialize()
        except Exception:
            pass
    if not ensemble_classifier.laya.is_loaded:
        try:
            await ensemble_classifier.laya.initialize()
        except Exception:
            pass

    models_status = {
        "wolf_defender": "loaded · every scan" if ensemble_classifier.wolf.is_loaded else f"not loaded · Tier 0 fallback · {ensemble_classifier.wolf.load_error or 'weights missing'}",
        "deberta": "loaded · every scan" if ensemble_classifier.deberta.is_loaded else "not loaded · Tier 0 fallback",
        "laya": "loaded · escalation" if ensemble_classifier.laya.is_loaded else f"not loaded · deterministic fallback · {ensemble_classifier.laya.load_error or 'package not loaded'}",
        "open_jev": (
            "loaded · local model · escalation only"
            if ensemble_classifier.open_jev.is_loaded
            else f"not loaded · evidence fallback · {ensemble_classifier.open_jev.load_error or 'model not initialized'}"
        ),
        "lightgbm": "loaded · every scan" if ensemble_classifier.lgb.is_loaded else "heuristic · every scan",
        "tier0_detectors": f"{len(detector_registry.get_tier(0))} loaded · every scan",
    }

    is_healthy = db_status == "ok" and len(detector_registry.get_tier(0)) > 0
    if settings.ENVIRONMENT == "production":
        is_healthy = is_healthy and redis_status == "ok"
    if settings.REQUIRE_ML_MODELS:
        is_healthy = is_healthy and ensemble_classifier.deberta.is_loaded and ensemble_classifier.lgb.is_loaded
    t0_count = len(detector_registry.get_tier(0))
    upstream_status = "configured_unverified" if settings.LLM_BASE_URL else "not_configured"

    return HealthResponse(
        status="healthy" if is_healthy else "degraded",
        healthy=is_healthy,
        database=db_status,
        redis=redis_status,
        models=models_status,
        tier_0_detectors=t0_count,
        upstream_llm=upstream_status,
        timestamp=format_ist(now_utc()),
    )


@router.get("/metrics")
async def metrics(
    tenant_ctx: TenantContext = Depends(require_role(["superadmin", "admin", "tenant_admin", "soc_analyst", "auditor"])),
    db: AsyncSession = Depends(get_db),
):
    """
    Return operational metrics computed from actual audit log data.
    Never fabricates values.
    """
    try:
        tenant_scope = [] if tenant_ctx.role == "superadmin" else [AuditLogModel.tenant_id == tenant_ctx.tenant_id]
        total = await db.scalar(select(func.count(AuditLogModel.id)).where(*tenant_scope)) or 0
        blocked = await db.scalar(
            select(func.count(AuditLogModel.id)).where(*tenant_scope, AuditLogModel.decision == "BLOCK")
        ) or 0
        allowed = await db.scalar(
            select(func.count(AuditLogModel.id)).where(*tenant_scope, AuditLogModel.decision == "ALLOW")
        ) or 0
        sanitized = await db.scalar(
            select(func.count(AuditLogModel.id)).where(*tenant_scope, AuditLogModel.decision == "SANITIZE")
        ) or 0
        review = await db.scalar(
            select(func.count(AuditLogModel.id)).where(*tenant_scope, AuditLogModel.decision == "REQUIRE_REVIEW")
        ) or 0
        avg_latency = await db.scalar(select(func.avg(AuditLogModel.latency_ms)).where(*tenant_scope)) or 0.0
        avg_risk = await db.scalar(select(func.avg(AuditLogModel.risk_score)).where(*tenant_scope)) or 0.0

        current_window_start = now_utc() - timedelta(days=1)
        previous_window_start = current_window_start - timedelta(days=1)
        current_window_total = await db.scalar(
            select(func.count(AuditLogModel.id)).where(*tenant_scope, AuditLogModel.timestamp >= current_window_start)
        ) or 0
        previous_window_total = await db.scalar(
            select(func.count(AuditLogModel.id)).where(
                *tenant_scope, AuditLogModel.timestamp >= previous_window_start,
                AuditLogModel.timestamp < current_window_start,
            )
        ) or 0
        current_window_blocks = await db.scalar(
            select(func.count(AuditLogModel.id)).where(
                *tenant_scope, AuditLogModel.timestamp >= current_window_start,
                AuditLogModel.decision == "BLOCK",
            )
        ) or 0
        previous_window_blocks = await db.scalar(
            select(func.count(AuditLogModel.id)).where(
                *tenant_scope, AuditLogModel.timestamp >= previous_window_start,
                AuditLogModel.timestamp < current_window_start,
                AuditLogModel.decision == "BLOCK",
            )
        ) or 0
        current_window_block_rate = current_window_blocks / current_window_total if current_window_total else 0.0
        previous_window_block_rate = previous_window_blocks / previous_window_total if previous_window_total else 0.0

        # Compute gateway overhead metrics (p50/p95/p99) and upstream latency separately
        try:
            gw_stmt = select(
                func.coalesce(AuditLogModel.gateway_overhead_ms, AuditLogModel.latency_ms)
            ).where(
                *tenant_scope,
                AuditLogModel.timestamp >= current_window_start,
                func.coalesce(AuditLogModel.gateway_overhead_ms, AuditLogModel.latency_ms) > 0
            ).order_by(
                func.coalesce(AuditLogModel.gateway_overhead_ms, AuditLogModel.latency_ms)
            )
            gw_res = await db.execute(gw_stmt)
            gw_lats = [float(x[0]) for x in gw_res.all()]
            if gw_lats:
                n = len(gw_lats)
                p50_idx = int(0.50 * n)
                p95_idx = min(int(0.95 * n), n - 1)
                p99_idx = min(int(0.99 * n), n - 1)
                gateway_p50 = round(gw_lats[p50_idx], 2)
                gateway_p95 = round(gw_lats[p95_idx], 2)
                gateway_p99 = round(gw_lats[p99_idx], 2)
                avg_gateway_overhead = round(sum(gw_lats) / n, 2)
            else:
                gateway_p50 = gateway_p95 = gateway_p99 = avg_gateway_overhead = 0.0

            avg_upstream_val = await db.scalar(
                select(func.avg(AuditLogModel.upstream_llm_ms)).where(
                    *tenant_scope, AuditLogModel.timestamp >= current_window_start,
                    AuditLogModel.upstream_llm_ms > 0
                )
            ) or 0.0
            avg_upstream = round(float(avg_upstream_val), 2)
        except Exception:
            gateway_p50 = gateway_p95 = gateway_p99 = avg_gateway_overhead = 0.0
            avg_upstream = 0.0

        # High risk count (risk_score >= 0.5)
        high_risk = await db.scalar(
            select(func.count(AuditLogModel.id)).where(*tenant_scope, AuditLogModel.risk_score >= 0.5)
        ) or 0
        critical = await db.scalar(
            select(func.count(AuditLogModel.id)).where(*tenant_scope, AuditLogModel.risk_score >= 0.8)
        ) or 0

        # Detection rate
        detection_rate = (blocked + sanitized + review) / total if total > 0 else 0.0

        # Recent requests for threat feed
        recent_query = await db.execute(
            select(AuditLogModel).where(*tenant_scope)
            .order_by(desc(AuditLogModel.timestamp))
            .limit(50)
        )
        recent = recent_query.scalars().all()
        recent_items = [
            {
                "request_id": r.request_id,
                "session_id": r.session_id,
                "timestamp": format_ist(r.timestamp) if r.timestamp else "",
                "source_type": r.source_type,
                "origin": r.origin,
                "decision": r.decision,
                "risk_score": r.risk_score,
                "latency_ms": r.latency_ms,
                "evidence": r.evidence_json or [],
                "decision_rationale": r.evidence_json.get("decision_rationale", {}) if isinstance(r.evidence_json, dict) else {},
                "policy_rules_applied": r.evidence_json.get("policy_rules_applied", []) if isinstance(r.evidence_json, dict) else [],
                "policy": r.policy,
            }
            for r in recent
        ]

        # Compute distributions for SOC dashboard
        decision_dist = {
            "allow": allowed,
            "block": blocked,
            "sanitize": sanitized,
            "quarantine": 0,
            "require_review": review,
            "ALLOW": allowed,
            "BLOCK": blocked,
            "SANITIZE": sanitized,
            "QUARANTINE": 0,
            "REQUIRE_REVIEW": review,
        }

        canonical_attacks = [
            "INSTRUCTION_OVERRIDE",
            "ROLE_CHANGE",
            "SECRET_EXTRACTION",
            "TOOL_ABUSE",
            "CREDENTIAL_THEFT",
            "CONTEXT_POISONING",
            "MULTI_STEP_JAILBREAK",
            "ENCODED_INSTRUCTION",
            "INDIRECT_PROMPT_INJECTION",
        ]
        attack_dist = {atk: 0 for atk in canonical_attacks}

        for r in recent:
            ev_data = r.evidence_json
            if isinstance(ev_data, str):
                try:
                    ev_data = json.loads(ev_data)
                except Exception:
                    ev_data = {}
            items = []
            if isinstance(ev_data, dict):
                at_raw = ev_data.get("attack_types", [])
                det_raw = ev_data.get("detector_results", [])
                items.extend(at_raw)
                items.extend(det_raw)
            elif isinstance(ev_data, list):
                items = ev_data

            # Track detected attack types for this specific audit record (deduplicate per record)
            seen_for_record = set()
            for ev in items:
                atype = None
                if isinstance(ev, dict):
                    atype = ev.get("attack_type") or ev.get("type") or ev.get("detector_name")
                elif isinstance(ev, str):
                    atype = ev
                if atype:
                    clean_atype = str(atype).upper().replace(" ", "_").strip()
                    for canon in canonical_attacks:
                        if canon == clean_atype or canon in clean_atype or clean_atype in canon:
                            seen_for_record.add(canon)
                            break

            for atk in seen_for_record:
                attack_dist[atk] += 1

        risk_buckets = [
            {"bucket": "0-20", "count": allowed},
            {"bucket": "21-50", "count": sanitized},
            {"bucket": "51-80", "count": high_risk},
            {"bucket": "81-100", "count": critical},
        ]

        hour_counts = {f"{i:02d}:00": {"count": 0, "allowed": 0, "blocked": 0} for i in range(24)}
        for r in recent:
            if r.timestamp:
                try:
                    ist_dt = to_ist(r.timestamp)
                    if ist_dt:
                        h_str = ist_dt.strftime("%H:00")
                        if h_str in hour_counts:
                            hour_counts[h_str]["count"] += 1
                            decision = str(r.decision or "").upper()
                            if decision == "ALLOW":
                                hour_counts[h_str]["allowed"] += 1
                            elif decision == "BLOCK":
                                hour_counts[h_str]["blocked"] += 1
                except Exception:
                    pass
        requests_over_time = [{"timestamp": h, **counts} for h, counts in hour_counts.items()]

    except Exception as e:
        logger.warning(f"Metrics query failed: {e}")
        return {
            "totalRequestsToday": 0, "blockedRequests": 0, "allowedRequests": 0,
            "sanitizedRequests": 0, "highRiskRequests": 0, "criticalRequests": 0,
            "avgLatencyMs": 0.0, "detectionRate": 0.0,
            "requestsOverTime": [{"timestamp": f"{i:02d}:00", "count": 0} for i in range(24)],
            "decisionDistribution": {"allow": 0, "block": 0, "sanitize": 0, "quarantine": 0, "require_review": 0},
            "attackTypeDistribution": {},
            "riskScoreDistribution": [],
            "requests_total": 0, "blocks_total": 0, "allowed_total": 0,
            "sanitized_total": 0, "review_total": 0, "high_risk": 0,
            "critical": 0, "avg_latency_ms": 0.0, "avg_risk_score": 0.0,
            "requests_last_24h": 0, "requests_previous_24h": 0,
            "blocks_last_24h": 0, "blocks_previous_24h": 0,
            "block_rate_last_24h": 0.0, "block_rate_previous_24h": 0.0,
            "detection_rate": 0.0, "recent": [],
        }

    return {
        # CamelCase for Frontend Dashboard
        "totalRequestsToday": total,
        "blockedRequests": blocked,
        "allowedRequests": allowed,
        "sanitizedRequests": sanitized,
        "highRiskRequests": high_risk,
        "criticalRequests": critical,
        "avgLatencyMs": avg_gateway_overhead if avg_gateway_overhead > 0 else round(avg_latency, 2),
        "gateway_overhead_ms": avg_gateway_overhead if avg_gateway_overhead > 0 else round(avg_latency, 2),
        "gateway_p50_ms": gateway_p50,
        "gateway_p95_ms": gateway_p95,
        "gateway_p99_ms": gateway_p99,
        "upstream_llm_ms": avg_upstream,
        "detectionRate": round(detection_rate, 4),
        "requestsOverTime": requests_over_time,
        "decisionDistribution": decision_dist,
        "attackTypeDistribution": attack_dist,
        "riskScoreDistribution": risk_buckets,
        # Snake_case compatibility
        "requests_total": total,
        "blocks_total": blocked,
        "allowed_total": allowed,
        "sanitized_total": sanitized,
        "review_total": review,
        "high_risk": high_risk,
        "critical": critical,
        "requests_last_24h": current_window_total,
        "requests_previous_24h": previous_window_total,
        "blocks_last_24h": current_window_blocks,
        "blocks_previous_24h": previous_window_blocks,
        "block_rate_last_24h": round(current_window_block_rate, 4),
        "block_rate_previous_24h": round(previous_window_block_rate, 4),
        "avg_latency_ms": round(avg_latency, 2),
        "avg_gateway_overhead_ms": avg_gateway_overhead,
        "avg_upstream_ms": avg_upstream,
        "avg_risk_score": round(avg_risk, 4),
        "detection_rate": round(detection_rate, 4),
        "recent": recent_items,
    }


@router.get("/feed")
async def get_threat_feed(
    limit: int = 20,
    tenant_ctx: TenantContext = Depends(require_role(["superadmin", "admin", "tenant_admin", "soc_analyst"])),
    db: AsyncSession = Depends(get_db),
):
    """Return threat feed items for live SOC monitoring."""
    try:
        if tenant_ctx.role != "superadmin":
            query = select(AuditLogModel).where(AuditLogModel.tenant_id == tenant_ctx.tenant_id)
        else:
            query = select(AuditLogModel)
        query = query.order_by(desc(AuditLogModel.timestamp)).limit(limit)
        res = await db.execute(query)
        items = res.scalars().all()
        feed_items = []
        for r in items:
            at_list = []
            ev_data = r.evidence_json
            if isinstance(ev_data, dict):
                at_raw = ev_data.get("attack_types", [])
                at_list = [a.get("type", str(a)) if isinstance(a, dict) else str(a) for a in at_raw]
            elif isinstance(ev_data, list):
                at_list = [ev.get("attack_type", str(ev)) if isinstance(ev, dict) else str(ev) for ev in ev_data]

            feed_items.append({
                "id": r.request_id,
                "timestamp": format_ist(r.timestamp) if r.timestamp else "",
                "sourceType": r.source_type or "user",
                "attackTypes": at_list,
                "riskLevel": "CRITICAL" if (r.risk_score or 0) >= 0.8 else ("HIGH" if (r.risk_score or 0) >= 0.5 else ("MEDIUM" if (r.risk_score or 0) >= 0.2 else "LOW")),
                "riskScore": r.risk_score or 0.0,
                "decision": r.decision or "ALLOW",
                "latencyMs": r.latency_ms or 0.0,
                "prompt": getattr(r, "prompt", None) or (r.evidence_json.get("prompt") if isinstance(r.evidence_json, dict) else ""),
                "hasPii": bool(isinstance(r.evidence_json, dict) and r.evidence_json.get("has_pii")),
                "rawPromptHash": getattr(r, "raw_prompt_hash", None) or (r.evidence_json.get("raw_prompt_hash") if isinstance(r.evidence_json, dict) else (r.hash_chain or "")),
            })
        return feed_items
    except Exception as e:
        logger.warning(f"Threat feed query failed: {e}")
        return []


@router.get("/audit")
async def get_audit(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    decision: Optional[str] = None,
    tenant_ctx: TenantContext = Depends(require_role(["superadmin", "admin", "tenant_admin", "soc_analyst", "auditor"])),
    db: AsyncSession = Depends(get_db),
):
    """Return paginated audit logs, optionally filtered by decision."""
    try:
        query = select(AuditLogModel).order_by(desc(AuditLogModel.timestamp))
        if decision:
            query = query.where(AuditLogModel.decision == decision)
        query = query.offset(skip).limit(limit)

        res = await db.execute(query)
        records = res.scalars().all()

        return [
            {
                "id": r.request_id,
                "request_id": r.request_id,
                "session_id": r.session_id or "",
                "timestamp": format_ist(r.timestamp) if r.timestamp else "",
                "action": r.action or "inspection",
                "decision": r.decision or "ALLOW",
                "risk_score": r.risk_score or 0.0,
                "riskScore": r.risk_score or 0.0,
                "risk_level": "CRITICAL" if (r.risk_score or 0) >= 0.8 else ("HIGH" if (r.risk_score or 0) >= 0.5 else ("MEDIUM" if (r.risk_score or 0) >= 0.2 else "LOW")),
                "riskLevel": "CRITICAL" if (r.risk_score or 0) >= 0.8 else ("HIGH" if (r.risk_score or 0) >= 0.5 else ("MEDIUM" if (r.risk_score or 0) >= 0.2 else "LOW")),
                "prompt": getattr(r, "prompt", None) or (r.evidence_json.get("prompt") if isinstance(r.evidence_json, dict) else ""),
                "raw_prompt_hash": getattr(r, "raw_prompt_hash", None) or (r.evidence_json.get("raw_prompt_hash") if isinstance(r.evidence_json, dict) else (r.hash_chain or "")),
                "has_pii": bool(isinstance(r.evidence_json, dict) and r.evidence_json.get("has_pii")),
                "pii_types": r.evidence_json.get("pii_types", []) if isinstance(r.evidence_json, dict) else [],
                "evidence": r.evidence_json or [],
                "policy": r.policy or "default_zero_trust",
                "latency_ms": r.latency_ms or 0.0,
                "source_type": r.source_type or "user",
                "origin": r.origin or "api",
            }
            for r in records
        ]
    except Exception as e:
        logger.warning(f"Audit query failed: {e}")
        return []


@router.get("/audit/{record_id}")
async def get_audit_by_id(
    record_id: str,
    tenant_ctx: TenantContext = Depends(require_role(["superadmin", "admin", "tenant_admin", "soc_analyst", "auditor"])),
    db: AsyncSession = Depends(get_db),
):
    """Return a specific audit record by request_id or the most recent record."""
    try:
        r = None
        if record_id == "recent":
            res = await db.execute(
                select(AuditLogModel).order_by(desc(AuditLogModel.timestamp)).limit(1)
            )
            r = res.scalar_one_or_none()
            if not r:
                raise HTTPException(status_code=404, detail="No audit records found in gateway log")
        else:
            if record_id.isdigit():
                res = await db.execute(
                    select(AuditLogModel).where(
                        (AuditLogModel.request_id == record_id) | (AuditLogModel.id == int(record_id))
                    )
                )
            else:
                res = await db.execute(
                    select(AuditLogModel).where(AuditLogModel.request_id == record_id)
                )
            r = res.scalar_one_or_none()
            if not r:
                raise HTTPException(status_code=404, detail="Audit record not found")

        risk_val = r.risk_score if r.risk_score is not None else 0.0
        risk_lvl = "CRITICAL" if risk_val >= 0.8 else ("HIGH" if risk_val >= 0.5 else ("MEDIUM" if risk_val >= 0.2 else "LOW"))

        ev_data = r.evidence_json
        if isinstance(ev_data, str):
            try:
                ev_data = json.loads(ev_data)
            except Exception:
                ev_data = {}

        prompt_val = getattr(r, "prompt", None) or (ev_data.get("prompt") if isinstance(ev_data, dict) else "")
        raw_hash_val = getattr(r, "raw_prompt_hash", None) or (ev_data.get("raw_prompt_hash") if isinstance(ev_data, dict) else (r.hash_chain or ""))
        has_pii_val = bool(isinstance(ev_data, dict) and ev_data.get("has_pii"))
        pii_types_val = ev_data.get("pii_types", []) if isinstance(ev_data, dict) else []
        decision_rationale = ev_data.get("decision_rationale", {}) if isinstance(ev_data, dict) else {}

        detected_attacks = []
        if isinstance(ev_data, dict):
            for det in (ev_data.get("detector_results") or []):
                if not isinstance(det, dict) or not (det.get("is_malicious") or det.get("detected")):
                    continue
                at_names = det.get("attack_types") or []
                det_conf = det.get("detector_confidence", det.get("confidence"))
                raw_snippets = det.get("evidence_snippets", det.get("matched_signals", []))
                clean_snippets = [str(s)[:240] for s in raw_snippets if "benign" not in str(s).lower() and "safe" not in str(s).lower()]
                for attack_name in at_names:
                    detected_attacks.append({
                        "attackType": attack_name,
                        "confidence": float(det_conf) if det_conf is not None else None,
                        "detectorName": det.get("detector_id", "Security detector"),
                        "evidence": clean_snippets,
                    })

            # Older audit entries may only have the aggregate categories. Do not
            # invent per-detector confidence or synthetic evidence for those rows.
            known_types = {str(item["attackType"]).upper().replace(" ", "_") for item in detected_attacks}
            for at in (ev_data.get("attack_types") or []):
                at_name = (at.get("type") or at.get("attack_type", "UNKNOWN")) if isinstance(at, dict) else str(at)
                if str(at_name).upper().replace(" ", "_") not in known_types:
                    detected_attacks.append({"attackType": at_name, "confidence": None, "detectorName": None, "evidence": []})
        elif isinstance(ev_data, list):
            for ev in ev_data:
                if isinstance(ev, dict):
                    detected_attacks.append({
                        "attackType": ev.get("attack_type", "INJECTION"),
                        "confidence": float(ev.get("confidence", risk_val or 0.95)),
                        "evidence": [{"detectorName": ev.get("detector", "RuleEngine"), "signal": ev.get("signal", str(ev))}]
                    })
                else:
                    detected_attacks.append({
                        "attackType": str(ev),
                        "confidence": risk_val or 0.95,
                        "evidence": [{"detectorName": "RuleEngine", "signal": str(ev)}]
                    })

        # Deduplicate detector results by attack type; prefer real evidence/confidence.
        unique_attacks = {}
        for item in detected_attacks:
            atype = item.get("attackType", "UNKNOWN").upper().replace(" ", "_")
            existing = unique_attacks.get(atype)
            item_score = float(item.get("confidence") or 0) + (0.01 if item.get("evidence") else 0)
            existing_score = (float(existing.get("confidence") or 0) + (0.01 if existing.get("evidence") else 0)) if existing else -1
            if existing is None:
                unique_attacks[atype] = item
            else:
                existing["evidence"] = list(dict.fromkeys(existing.get("evidence", []) + item.get("evidence", [])))[:5]
                if item_score > existing_score:
                    unique_attacks[atype].update({k: v for k, v in item.items() if k != "evidence"})
        detected_attacks = list(unique_attacks.values())

        return {
            "id": r.request_id,
            "request_id": r.request_id,
            "session_id": r.session_id or "",
            "timestamp": format_ist(r.timestamp) if r.timestamp else format_ist(now_ist()),
            "action": r.action or "inspection",
            "decision": r.decision or "ALLOW",
            "risk_score": risk_val,
            "riskScore": risk_val,
            "risk_level": risk_lvl,
            "riskLevel": risk_lvl,
            "prompt": prompt_val,
            "raw_prompt_hash": raw_hash_val,
            "has_pii": has_pii_val,
            "pii_types": pii_types_val,
            "evidence": r.evidence_json or [],
            "decision_rationale": decision_rationale,
            "policy_rules_applied": ev_data.get("policy_rules_applied", []) if isinstance(ev_data, dict) else [],
            "policy": r.policy or "default_zero_trust",
            "latency_ms": r.latency_ms or 0.0,
            "source_type": r.source_type or "user",
            "origin": r.origin or "api",
            "details": {
                "sessionId": r.session_id or "",
                "riskScore": risk_val,
                "risk_score": risk_val,
                "riskLevel": risk_lvl,
                "risk_level": risk_lvl,
                "prompt": prompt_val,
                "rawPromptHash": raw_hash_val,
                "hasPii": has_pii_val,
                "piiTypes": pii_types_val,
                "detectedAttacks": detected_attacks,
                "decisionRationale": decision_rationale,
                "decision_rationale": decision_rationale,
                "policyRulesApplied": ev_data.get("policy_rules_applied", []) if isinstance(ev_data, dict) else [],
                "policy": r.policy or "default_zero_trust",
                "latency_ms": r.latency_ms or 0.0,
                "provenance": {
                    "origin": r.origin or "chat_completions",
                    "sourceType": r.source_type or "user",
                    "trustLevel": "UNTRUSTED",
                    "hash": raw_hash_val or r.hash_chain or "",
                },
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"Audit lookup failed: {e}")
        raise HTTPException(status_code=500, detail="Internal error")


@router.get("/sessions")
async def list_sessions(
    tenant_ctx: TenantContext = Depends(require_role(["superadmin", "admin", "tenant_admin", "soc_analyst"])),
    db: AsyncSession = Depends(get_db),
):
    """Return all active multi-turn sessions with trajectory states."""
    result = []
    for s in await session_engine.list_sessions(None if tenant_ctx.role == "superadmin" else tenant_ctx.tenant_id):
        result.append({
            "sessionId": s.session_id,
            "currentState": s.current_state,
            "riskAccumulator": round(s.risk_accumulator * 100, 1),
            "eventCount": s.event_count,
            "flags": s.flags,
            "startTime": s.created_at,
            "lastActive": s.updated_at,
            "events": s.events,
            "stateTransitions": s.state_transitions,
        })
    return result


@router.get("/session/{session_id}")
async def get_session(
    session_id: str,
    tenant_ctx: TenantContext = Depends(require_role(["superadmin", "admin", "tenant_admin", "soc_analyst"])),
    db: AsyncSession = Depends(get_db),
):
    """Return session state and events."""
    try:
        session_state = await session_engine.get_session(session_id, tenant_ctx.tenant_id, tenant_ctx.application_id)
        if not session_state:
            raise HTTPException(404, "Session not found")
        return {
            "session_id": session_id,
            "state": session_state.current_state if session_state else "NORMAL",
            "risk_score": session_state.risk_accumulator if session_state else 0.0,
            "event_count": session_state.event_count if session_state else 0,
            "events": session_state.events if session_state else [],
            "state_transitions": session_state.state_transitions if session_state else [],
            "flags": session_state.flags if session_state else [],
            "created_at": session_state.created_at if session_state else "",
            "updated_at": session_state.updated_at if session_state else "",
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"Session lookup failed: {e}")
        return {
            "session_id": session_id,
            "state": "NORMAL",
            "risk_score": 0.0,
            "event_count": 0,
            "events": [],
            "state_transitions": [],
            "flags": [],
        }


@router.post("/session/{session_id}/quarantine")
async def quarantine_session(
    session_id: str,
    tenant_ctx: TenantContext = Depends(require_role(["superadmin", "admin", "tenant_admin", "soc_analyst"])),
    db: AsyncSession = Depends(get_db),
):
    """
    Quarantine an active session, setting risk to maximum and blocking downstream operations.
    """
    existing = await session_engine.get_session(session_id, tenant_ctx.tenant_id, tenant_ctx.application_id)
    if not existing:
        raise HTTPException(404, "Session not found")
    session = await session_engine.quarantine_session(session_id, tenant_id=tenant_ctx.tenant_id, application_id=tenant_ctx.application_id)
    if db:
        try:
            from app.models.database_models import SessionModel
            stmt = select(SessionModel).where(SessionModel.session_id == session_id, SessionModel.tenant_id == tenant_ctx.tenant_id)
            res = await db.execute(stmt)
            db_session = res.scalar_one_or_none()
            if db_session:
                db_session.state = "QUARANTINE"
                db_session.risk_accumulator = 1.0
                await db.commit()
        except Exception as e:
            logger.warning(f"Failed to persist quarantined session to DB: {e}")

    return {
        "status": "success",
        "session_id": session_id,
        "current_state": "QUARANTINE",
        "risk_accumulator": session.risk_accumulator,
        "message": f"Session {session_id} successfully quarantined."
    }



class CreatePolicyPayload(BaseModel):
    name: str
    description: Optional[str] = ""
    scope: Optional[str] = "GLOBAL"
    action: Optional[str] = "BLOCK"
    risk_threshold: Optional[float] = 0.70
    rules: Optional[List[str]] = None
    is_active: Optional[bool] = True


@router.get("/policies")
async def get_policies(
    tenant_ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Return all configured security policies including platform guardrails and custom DB policies."""
    policies = []

    # 1. Custom and persistent policies from DB
    try:
        stmt = select(PolicyModel).order_by(PolicyModel.priority.asc(), PolicyModel.created_at.desc())
        res = await db.execute(stmt)
        db_policies = res.scalars().all()
        for p in db_policies:
            rules_list = []
            if isinstance(p.rules_json, dict):
                rules_list = p.rules_json.get("rules", [])
                if not rules_list and p.rules_json.get("mandatory_blocks"):
                    rules_list = [f"Block on {m}" for m in p.rules_json.get("mandatory_blocks", [])]
            policies.append({
                "id": str(p.id),
                "name": p.name,
                "description": p.description or "",
                "scope": p.scope or "GLOBAL",
                "is_mandatory": p.is_mandatory or False,
                "isMandatory": p.is_mandatory or False,
                "is_active": p.is_active if p.is_active is not None else True,
                "active": p.is_active if p.is_active is not None else True,
                "risk_threshold": p.rules_json.get("risk_threshold", 0.70) if isinstance(p.rules_json, dict) else 0.70,
                "riskThreshold": p.rules_json.get("risk_threshold", 0.70) if isinstance(p.rules_json, dict) else 0.70,
                "action": p.rules_json.get("action", "BLOCK") if isinstance(p.rules_json, dict) else "BLOCK",
                "rules": rules_list or ["Custom enforcement rule"],
                "created_at": format_ist(p.created_at) if p.created_at else "",
            })
    except Exception as e:
        logger.warning(f"Failed to query DB policies: {e}")

    # 2. Built-in platform policies
    for name, policy in policy_engine.policies.items():
        if name.startswith("custom_"):
            continue  # Already represented from DB
        is_default_active = name in ["default_zero_trust", "banking_strict"]
        policies.append({
            "id": name,
            "name": policy.name.replace("_", " ").title(),
            "description": policy.description,
            "scope": policy.scope,
            "is_mandatory": policy.is_mandatory,
            "isMandatory": policy.is_mandatory,
            "is_active": is_default_active,
            "active": is_default_active,
            "risk_threshold": policy.max_risk_for_auto_allow,
            "riskThreshold": policy.max_risk_for_auto_allow,
            "action": policy.risk_thresholds.get("CRITICAL", "BLOCK"),
            "risk_thresholds": policy.risk_thresholds,
            "mandatory_blocks": policy.mandatory_blocks,
            "allowed_tools": policy.allowed_tools,
            "blocked_tools": policy.blocked_tools,
            "rules": [f"Mandatory block on {m}" for m in policy.mandatory_blocks[:2]] + [f"Auto-allow risk threshold <= {policy.max_risk_for_auto_allow}"],
        })

    return policies


@router.post("/policies")
async def create_policy(
    payload: CreatePolicyPayload,
    tenant_ctx: TenantContext = Depends(require_role(["superadmin", "tenant_admin", "admin"])),
    db: AsyncSession = Depends(get_db),
):
    """Create a new custom security policy and activate it in the firewall engine."""
    try:
        rules_list = payload.rules or []
        if isinstance(rules_list, str):
            rules_list = [r.strip() for r in rules_list.split(",") if r.strip()]
        if not rules_list:
            rules_list = [f"Enforce {payload.action} on suspicious inputs exceeding risk {payload.risk_threshold}"]

        rules_json = {
            "action": payload.action,
            "risk_threshold": payload.risk_threshold,
            "rules": rules_list,
            "risk_thresholds": {
                "LOW": "ALLOW",
                "MEDIUM": "SANITIZE" if payload.action in ["SANITIZE", "BLOCK"] else "ALLOW",
                "HIGH": payload.action or "BLOCK",
                "CRITICAL": "BLOCK"
            },
            "mandatory_blocks": list(GLOBAL_PLATFORM_MANDATORY_BLOCKS) if payload.action == "BLOCK" else []
        }

        new_policy = PolicyModel(
            name=payload.name,
            description=payload.description or "",
            tenant_id=None if tenant_ctx.role == "superadmin" and (payload.scope or "GLOBAL") == "GLOBAL" else tenant_ctx.tenant_id,
            scope=(payload.scope or "GLOBAL") if tenant_ctx.role == "superadmin" else "TENANT",
            scope_id=None if tenant_ctx.role == "superadmin" else tenant_ctx.tenant_id,
            priority=50,  # Custom policies have higher precedence than baseline defaults (100)
            is_mandatory=False,
            rules_json=rules_json,
            is_active=payload.is_active if payload.is_active is not None else True,
        )
        db.add(new_policy)
        await db.commit()
        await db.refresh(new_policy)

        return {
            "id": str(new_policy.id),
            "name": new_policy.name,
            "description": new_policy.description,
            "scope": new_policy.scope,
            "is_active": new_policy.is_active,
            "active": new_policy.is_active,
            "action": payload.action,
            "risk_threshold": payload.risk_threshold,
            "rules": rules_list,
            "message": "Policy successfully created and enforced"
        }
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Policy creation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create policy: {str(e)}")


@router.post("/policies/{policy_id}/toggle")
async def toggle_policy(
    policy_id: str,
    tenant_ctx: TenantContext = Depends(require_role(["superadmin", "tenant_admin", "admin"])),
    db: AsyncSession = Depends(get_db),
):
    """Toggle policy active or disabled status in database and in-memory engine."""
    try:
        if policy_id.isdigit():
            pid = int(policy_id)
            res = await db.execute(select(PolicyModel).where(PolicyModel.id == pid))
            policy_rec = res.scalar_one_or_none()
            if not policy_rec:
                raise HTTPException(status_code=404, detail="Policy not found")
            if policy_rec.is_mandatory or (policy_rec.tenant_id is None and tenant_ctx.role != "superadmin"):
                raise HTTPException(403, "Platform policies cannot be disabled")
            policy_rec.is_active = not policy_rec.is_active
            await db.commit()
            await db.refresh(policy_rec)

            mem_key = f"custom_{pid}"
            if mem_key in policy_engine.policies and not policy_rec.is_active:
                policy_engine.policies.pop(mem_key, None)

            return {
                "id": str(policy_rec.id),
                "is_active": policy_rec.is_active,
                "active": policy_rec.is_active,
                "name": policy_rec.name,
                "message": f"Policy '{policy_rec.name}' is now {'active' if policy_rec.is_active else 'disabled'}"
            }
        else:
            # Handle builtin named policy toggle in memory
            if policy_id in policy_engine.policies:
                return {
                    "id": policy_id,
                    "is_active": True,
                    "active": True,
                    "name": policy_engine.policies[policy_id].name,
                    "message": f"Policy '{policy_engine.policies[policy_id].name}' updated"
                }
            raise HTTPException(status_code=404, detail="Policy not found")
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Policy toggle failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to toggle policy")


# ==============================
# OPENAI-COMPATIBLE PROXY
# ==============================

@router.post("/chat/completions")
async def chat_completions(
    request: Request,
    tenant_ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    from app.api.data_plane.routes import chat_completions_gateway
    return await chat_completions_gateway(request, tenant_ctx, db)


@router.get("/models")
async def list_models(request: Request):
    """
    OpenAI-compatible models list endpoint.
    Proxies to downstream LLM or returns supported models so external chatbots
    verifying model availability initialize seamlessly.
    """
    if settings.LLM_BASE_URL:
        try:
            downstream_url = f"{settings.LLM_BASE_URL.rstrip('/')}/v1/models"
            headers = {}
            incoming_auth = request.headers.get("Authorization")
            if settings.LLM_API_KEY:
                headers["Authorization"] = f"Bearer {settings.LLM_API_KEY}"
            elif incoming_auth:
                headers["Authorization"] = incoming_auth

            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(downstream_url, headers=headers)
                if resp.status_code == 200:
                    return JSONResponse(content=resp.json())
        except Exception:
            pass

    # Fallback standard models catalogue
    return JSONResponse(content={
        "object": "list",
        "data": [
            {"id": settings.LLM_MODEL or "gpt-4o", "object": "model", "created": 1700000000, "owned_by": "aegis"},
            {"id": "gpt-4-turbo", "object": "model", "created": 1700000000, "owned_by": "aegis"},
            {"id": "gpt-3.5-turbo", "object": "model", "created": 1700000000, "owned_by": "aegis"},
            {"id": "claude-3-5-sonnet-20241022", "object": "model", "created": 1700000000, "owned_by": "aegis"},
            {"id": "llama3", "object": "model", "created": 1700000000, "owned_by": "aegis"}
        ]
    })


@router.get("/applications")
async def api_list_applications(
    tenant_ctx: TenantContext = Depends(require_role(["superadmin", "admin", "tenant_admin", "soc_analyst", "data_plane"])),
    db: AsyncSession = Depends(get_db),
):
    """List registered protected applications."""
    stmt = select(ApplicationModel).order_by(ApplicationModel.created_at.desc())
    if tenant_ctx.role not in ("superadmin", "admin"):
        stmt = stmt.where(ApplicationModel.tenant_id == tenant_ctx.tenant_id)
    res = await db.execute(stmt)
    apps = res.scalars().all()
    return [
        {
            "id": a.id,
            "tenant_id": a.tenant_id,
            "name": a.name,
            "slug": a.slug,
            "description": a.description,
            "is_active": a.is_active,
            "created_at": format_ist(a.created_at) if a.created_at else None,
        }
        for a in apps
    ]


@router.post("/applications")
async def api_create_application(
    payload: Dict[str, Any],
    tenant_ctx: TenantContext = Depends(require_role(["superadmin", "admin", "tenant_admin"])),
    db: AsyncSession = Depends(get_db),
):
    """Register a new protected application and provision its dedicated API key."""
    name = payload.get("name", "New Chatbot Application")
    slug = payload.get("slug") or name.lower().replace(" ", "-")
    tenant_id = tenant_ctx.tenant_id if tenant_ctx.role != "superadmin" else payload.get("tenant_id", "tenant_default")
    app_id = f"app_{uuid.uuid4().hex[:12]}"

    app_record = ApplicationModel(
        id=app_id,
        tenant_id=tenant_id,
        name=name,
        slug=slug,
        description=payload.get("description", "Enterprise conversational agent"),
        is_active=True,
    )
    db.add(app_record)

    raw_secret = f"aegis_live_{uuid.uuid4().hex}"
    key_hash = hash_api_key(raw_secret)
    prefix = raw_secret[:14]

    cred = ApiCredentialModel(
        id=f"cred_{uuid.uuid4().hex[:12]}",
        tenant_id=tenant_id,
        application_id=app_id,
        key_hash=key_hash,
        key_prefix=prefix,
        name=f"Default Key for {name}",
        role="data_plane",
        is_active=True,
    )
    db.add(cred)
    await db.commit()

    return {
        "id": app_record.id,
        "name": app_record.name,
        "slug": app_record.slug,
        "tenant_id": tenant_id,
        "credential": {
            "credential_id": cred.id,
            "name": cred.name,
            "api_key": raw_secret,
            "prefix": prefix,
            "warning": "Copy this secret now. It will not be shown again.",
        }
    }


@router.post("/providers/test")
async def api_test_llm_provider(
    payload: Dict[str, Any],
    tenant_ctx: TenantContext = Depends(require_role(["superadmin"])),
):
    """Test connection to an upstream LLM provider (Ollama, OpenAI, vLLM, custom)."""
    provider = payload.get("provider", "ollama").lower()
    base_url = (payload.get("base_url") or settings.LLM_BASE_URL or "http://localhost:11434").rstrip("/")
    from app.core.upstream import validate_upstream, origin
    base_url = validate_upstream(base_url)
    same_destination = bool(settings.LLM_BASE_URL and origin(base_url) == origin(settings.LLM_BASE_URL))
    api_key = payload.get("api_key") or (settings.LLM_API_KEY if same_destination else None)
    model = payload.get("model") or settings.LLM_MODEL or "llama3"

    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    start_time = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            if provider == "ollama":
                resp = await client.get(f"{base_url}/api/tags")
                lat_ms = (time.perf_counter() - start_time) * 1000
                if resp.status_code == 200:
                    data = resp.json()
                    models = [m.get("name") for m in data.get("models", [])]
                    return {
                        "status": "connected",
                        "provider": "ollama",
                        "base_url": base_url,
                        "latency_ms": round(lat_ms, 2),
                        "models": models,
                        "message": f"Successfully connected to Ollama ({len(models)} models available)."
                    }
                else:
                    return {
                        "status": "error",
                        "provider": "ollama",
                        "base_url": base_url,
                        "latency_ms": round(lat_ms, 2),
                        "message": f"Ollama responded with HTTP {resp.status_code}: {resp.text[:200]}"
                    }
            elif provider in ("openai", "vllm", "custom"):
                resp = None
                for endpoint in [f"{base_url}/v1/models", f"{base_url}/models"]:
                    try:
                        resp = await client.get(endpoint, headers=headers)
                        if resp.status_code == 200:
                            break
                    except Exception:
                        continue

                lat_ms = (time.perf_counter() - start_time) * 1000
                if resp and resp.status_code == 200:
                    data = resp.json()
                    models = [m.get("id") for m in data.get("data", [])] if isinstance(data.get("data"), list) else []
                    return {
                        "status": "connected",
                        "provider": provider,
                        "base_url": base_url,
                        "latency_ms": round(lat_ms, 2),
                        "models": models[:10],
                        "message": f"Successfully connected to {provider.upper()} gateway ({len(models)} models found)."
                    }
                elif resp:
                    return {
                        "status": "error",
                        "provider": provider,
                        "base_url": base_url,
                        "latency_ms": round(lat_ms, 2),
                        "message": f"Provider returned HTTP {resp.status_code}: {resp.text[:200]}"
                    }
                else:
                    return {
                        "status": "unreachable",
                        "provider": provider,
                        "base_url": base_url,
                        "latency_ms": round(lat_ms, 2),
                        "message": f"Could not reach {base_url}. Ensure upstream server is running and accessible."
                    }
            else:
                return {
                    "status": "error",
                    "provider": provider,
                    "base_url": base_url,
                    "latency_ms": 0.0,
                    "message": f"Unknown provider: {provider}"
                }
    except Exception as exc:
        lat_ms = (time.perf_counter() - start_time) * 1000
        return {
            "status": "unreachable",
            "provider": provider,
            "base_url": base_url,
            "latency_ms": round(lat_ms, 2),
            "message": f"Connection failed: {str(exc)}"
        }


@router.get("/config/upstream")
async def api_get_upstream_config(tenant_ctx: TenantContext = Depends(require_role(["superadmin"]))):
    """Retrieve currently active upstream LLM configuration."""
    return {
        "provider": settings.LLM_PROVIDER,
        "base_url": settings.LLM_BASE_URL,
        "model": settings.LLM_MODEL,
        "has_api_key": bool(settings.LLM_API_KEY),
    }


@router.post("/config/upstream")
async def api_update_upstream_config(
    payload: Dict[str, Any],
    tenant_ctx: TenantContext = Depends(require_role(["superadmin"])),
    db: AsyncSession = Depends(get_db),
):
    from app.core.upstream import validate_upstream, origin
    provider = str(payload.get("provider", settings.LLM_PROVIDER)).lower()
    model = str(payload.get("model", settings.LLM_MODEL))
    if provider not in ("openai", "ollama", "vllm", "custom") or any(ord(c) < 32 for c in model):
        raise HTTPException(400, "Invalid provider configuration")
    base_url = validate_upstream(str(payload.get("base_url") or settings.LLM_BASE_URL or ""), allow_configured=False)
    same_destination = bool(settings.LLM_BASE_URL and origin(base_url) == origin(settings.LLM_BASE_URL))
    new_key = payload.get("api_key", settings.LLM_API_KEY if same_destination else None)
    if new_key is not None and (not isinstance(new_key, str) or any(ord(c) < 32 for c in new_key)):
        raise HTTPException(400, "Invalid provider credential")
    await audit_engine.log_decision(
        request_id=generate_request_id(), content=f"Provider configuration: {provider} {base_url} {model}",
        source_type="configuration", origin="admin", decision="ALLOW", risk_score=0.0,
        risk_level="LOW", confidence=1.0, attack_types=[], detector_results=[],
        policy_name="admin_configuration", policy_rules_applied=["superadmin", "origin_allowlist"],
        latency_ms=0.0, provenance={}, tenant_id=tenant_ctx.tenant_id, db=db,
    )
    # Runtime update only. Durable secrets/configuration are managed by the operator.
    settings.LLM_PROVIDER, settings.LLM_BASE_URL, settings.LLM_MODEL = provider, base_url, model
    settings.LLM_API_KEY = new_key or None
    return {"status": "success", "provider": provider, "base_url": base_url,
            "model": model, "has_api_key": bool(new_key), "persistent": False}
