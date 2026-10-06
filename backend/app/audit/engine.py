"""
Aegis AI Firewall - Durable Audit & Outbox Engine
Enforces:
1. Correction 7 & 8: Request -> Decision -> DB transaction (decision record + audit outbox)
   strictly committed before returning any response.
2. Hash chaining: SHA-256 tamper-evident integrity chaining across consecutive audit entries.
3. Strict zero-trust privacy: Credentials and raw secrets are redacted before persistence.
"""
import uuid
import hashlib
import json
import re
import asyncio
from collections import deque
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from app.core.logging import get_logger
from app.core.time import now_utc, format_ist
from app.core.config import settings
from app.core.pii import process_prompt_for_audit

logger = get_logger(__name__)


class AuditEntry(BaseModel):
    audit_id: str
    request_id: str
    tenant_id: str = "tenant_default"
    session_id: Optional[str] = None
    timestamp: str
    source_type: str
    origin: str
    content_hash: str
    decision: str
    risk_score: float
    risk_level: str
    confidence: float
    attack_types: List[Dict[str, Any]]
    detector_results: List[Dict[str, Any]]
    policy_name: str
    policy_rules_applied: List[str]
    latency_ms: float
    gateway_overhead_ms: float = 0.0
    upstream_llm_ms: float = 0.0
    total_ms: float = 0.0
    sanitization: Optional[Dict[str, Any]] = None
    tool_decision: Optional[Dict[str, Any]] = None
    provenance: Dict[str, Any]
    redacted: bool
    hash_chain: Optional[str] = None
    prompt: Optional[str] = None  # PII/secret masked prompt for forensic review
    raw_prompt_hash: Optional[str] = None  # SHA-256 hash of original raw prompt
    has_pii: bool = False
    pii_types: List[str] = []


class AuditEngine:
    _write_lock = asyncio.Lock()
    def __init__(self):
        self.logs = deque(maxlen=1000)
        self._last_hash: str = "0" * 64

    def _hash_content(self, content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def redact_content(self, content: str) -> tuple[str, bool]:
        """Redact sensitive keys, passwords, and tokens before audit persistence."""
        redacted = False
        cred_pattern = re.compile(
            r'(?i)(password|secret|key|token|bearer|authorization)[\s:=]+["\']?([a-zA-Z0-9_\-\.\/]{6,})["\']?'
        )
        new_content, count = cred_pattern.subn(r'\1 = [REDACTED:CREDENTIAL]', content)
        if count > 0:
            redacted = True
        return new_content, redacted

    def _compute_hash_chain(
        self, prev_hash: str, request_id: str, decision: str, risk_score: float, timestamp: str
    ) -> str:
        payload = f"{prev_hash}|{request_id}|{decision}|{risk_score:.4f}|{timestamp}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    async def log_decision(self, *args, **kwargs):
        async with self._write_lock:
            db = kwargs.get("db")
            if settings.ENVIRONMENT == "production" and (db is None or not hasattr(db, "bind")):
                raise RuntimeError("Durable audit storage is required")
            if db is not None and hasattr(db, "bind") and db.bind.dialect.name == "postgresql":
                from sqlalchemy import text
                await db.execute(text("SELECT pg_advisory_xact_lock(714902311)"))
            return await self._log_decision(*args, **kwargs)

    async def _log_decision(
        self,
        request_id: str,
        content: str,
        source_type: str,
        origin: str,
        decision: str,
        risk_score: float,
        risk_level: str,
        confidence: float,
        attack_types: List[Dict[str, Any]],
        detector_results: List[Dict[str, Any]],
        policy_name: str,
        policy_rules_applied: List[str],
        latency_ms: float,
        provenance: Dict[str, Any],
        tenant_id: str = "tenant_default",
        application_id: Optional[str] = None,
        environment_id: Optional[str] = None,
        connector_id: Optional[str] = None,
        session_id: Optional[str] = None,
        sanitization: Optional[Dict[str, Any]] = None,
        tool_decision: Optional[Dict[str, Any]] = None,
        db: Optional[AsyncSession] = None,
        trace_id: Optional[str] = None,
        gateway_overhead_ms: Optional[float] = None,
        upstream_llm_ms: Optional[float] = None,
        total_ms: Optional[float] = None,
    ) -> AuditEntry:
        """
        Record decision synchronously into durable DB transaction + outbox before response.
        """
        _, redacted = self.redact_content(content)
        prompt_data = process_prompt_for_audit(content)
        masked_prompt = prompt_data["masked_prompt"]
        raw_prompt_hash = prompt_data["raw_prompt_hash"]
        has_pii = prompt_data["has_pii"]
        pii_types = prompt_data["pii_types"]
        total_redacted = redacted or has_pii

        gw_overhead = gateway_overhead_ms if gateway_overhead_ms is not None else latency_ms
        up_llm = upstream_llm_ms if upstream_llm_ms is not None else 0.0
        tot_time = total_ms if total_ms is not None else latency_ms

        current_dt = now_utc()
        ts_now = format_ist(current_dt)
        content_sha = raw_prompt_hash or self._hash_content(content)

        # 1. Compute tamper-evident hash chain
        prev_hash = self._last_hash
        if db:
            prev_hash = "0" * 64
            try:
                from app.models.database_models import AuditLogModel
                stmt = select(AuditLogModel.hash_chain).order_by(AuditLogModel.id.desc()).limit(1).execution_options(platform_query=True)
                res = await db.execute(stmt)
                last_db_hash = res.scalar_one_or_none()
                if last_db_hash:
                    prev_hash = last_db_hash
            except Exception:
                if settings.ENVIRONMENT == "production":
                    raise RuntimeError("Cannot read the durable audit chain")

        current_hash = ""

        normalized_detector_results = []
        for r in (detector_results or []):
            if isinstance(r, dict):
                normalized_detector_results.append(r)
            elif hasattr(r, "model_dump"):
                normalized_detector_results.append(r.model_dump())
            elif hasattr(r, "__dict__"):
                normalized_detector_results.append(r.__dict__)
            else:
                normalized_detector_results.append({"name": str(r)})

        normalized_attack_types = []
        for at in (attack_types or []):
            if isinstance(at, dict):
                normalized_attack_types.append(at)
            elif hasattr(at, "model_dump"):
                normalized_attack_types.append(at.model_dump())
            elif hasattr(at, "type"):
                normalized_attack_types.append({"type": str(at.type), "confidence": getattr(at, "confidence", 1.0)})
            else:
                normalized_attack_types.append({"type": str(at), "confidence": 1.0})

        def scrub(value):
            if isinstance(value, str):
                return process_prompt_for_audit(value)["masked_prompt"]
            if isinstance(value, dict):
                return {k: scrub(v) for k, v in value.items()}
            if isinstance(value, list):
                return [scrub(v) for v in value]
            return value

        normalized_detector_results = scrub(normalized_detector_results)
        provenance = scrub(provenance)
        entry = AuditEntry(
            audit_id=str(uuid.uuid4()),
            request_id=request_id,
            tenant_id=tenant_id,
            session_id=session_id,
            timestamp=ts_now,
            source_type=source_type,
            origin=origin,
            content_hash=content_sha,
            decision=decision,
            risk_score=risk_score,
            risk_level=risk_level,
            confidence=confidence,
            attack_types=normalized_attack_types,
            detector_results=normalized_detector_results,
            policy_name=policy_name,
            policy_rules_applied=policy_rules_applied,
            latency_ms=latency_ms,
            gateway_overhead_ms=gw_overhead,
            upstream_llm_ms=up_llm,
            total_ms=tot_time,
            sanitization=sanitization,
            tool_decision=tool_decision,
            provenance=provenance,
            redacted=total_redacted,
            hash_chain=current_hash,
            prompt=masked_prompt,
            raw_prompt_hash=raw_prompt_hash,
            has_pii=has_pii,
            pii_types=pii_types,
        )

        # 2. Durable Outbox Transaction
        if db:
            try:
                from app.models.database_models import RequestModel, AuditLogModel, AuditOutboxModel

                # A. Audit Log record
                audit_record = AuditLogModel(
                    request_id=request_id,
                    tenant_id=tenant_id,
                    session_id=session_id,
                    timestamp=current_dt,
                    action="scan",
                    decision=decision,
                    risk_score=risk_score,
                    evidence_json={
                        "confidence": confidence,
                        "attack_types": normalized_attack_types,
                        "detector_results": normalized_detector_results[:10],
                        "redacted": total_redacted,
                        "has_pii": has_pii,
                        "pii_types": pii_types,
                        "prompt": masked_prompt,
                        "raw_prompt_hash": raw_prompt_hash,
                        "policy_rules_applied": scrub(policy_rules_applied),
                        "provenance": provenance,
                        "tool_decision": scrub(tool_decision),
                        "sanitization": scrub(sanitization),
                    },
                    policy=policy_name,
                    latency_ms=latency_ms,
                    gateway_overhead_ms=gw_overhead,
                    upstream_llm_ms=up_llm,
                    total_ms=tot_time,
                    source_type=source_type,
                    origin=origin,
                    hash_chain=current_hash,
                    prompt=masked_prompt,
                    raw_prompt_hash=raw_prompt_hash,
                )
                document = self.record_document(audit_record)
                current_hash = hashlib.sha256((prev_hash + "|" + json.dumps(document, sort_keys=True, separators=(",", ":"))).encode()).hexdigest()
                audit_record.hash_chain = current_hash
                audit_record.evidence_json = {**audit_record.evidence_json, "_chain_version": 2, "_previous_hash": prev_hash}
                entry.hash_chain = current_hash

                # B. Request record
                request_record = RequestModel(
                    request_id=request_id,
                    tenant_id=tenant_id,
                    application_id=application_id,
                    environment_id=environment_id,
                    connector_id=connector_id,
                    session_id=session_id,
                    timestamp=current_dt,
                    source_type=source_type,
                    origin=origin,
                    trust_level=provenance.get("trust_level", "UNTRUSTED"),
                    content_hash=content_sha,
                    content_type="text",
                    decision=decision,
                    risk_score=risk_score,
                    risk_level=risk_level,
                    confidence=confidence,
                    attack_types_json=normalized_attack_types,
                    policy=policy_name,
                    latency_ms=latency_ms,
                    gateway_overhead_ms=gw_overhead,
                    upstream_llm_ms=up_llm,
                    total_ms=tot_time,
                    trace_id=trace_id or request_id,
                    prompt=masked_prompt,
                    raw_prompt_hash=raw_prompt_hash,
                )

                # C. Durable Outbox event
                outbox_record = AuditOutboxModel(
                    event_id=f"evt_{uuid.uuid4().hex}",
                    tenant_id=tenant_id,
                    event_type="DECISION_RECORDED" if decision == "ALLOW" else "SECURITY_VIOLATION_BLOCKED",
                    payload_json={
                        "request_id": request_id,
                        "decision": decision,
                        "risk_score": risk_score,
                        "risk_level": risk_level,
                        "policy": policy_name,
                        "source_type": source_type,
                        "hash_chain": current_hash,
                        "timestamp": ts_now,
                    },
                    status="PENDING",
                    retry_count=0,
                )

                db.add_all([audit_record, request_record, outbox_record])
                # Critical: commit transaction to enforce durability before returning response
                await db.commit()
                self._last_hash = current_hash
                self.logs.append(entry)
                logger.debug(f"Durable audit transaction committed for request {request_id}")

            except Exception as e:
                logger.error(f"Failed to commit durable audit transaction: {e}")
                try:
                    await db.rollback()
                except Exception:
                    pass
                # Fail-safe invariant: We log the failure explicitly
                raise RuntimeError(f"Audit durability failure: {e}")

        else:
            current_hash = hashlib.sha256((prev_hash + "|" + entry.model_dump_json(exclude={"hash_chain"})).encode()).hexdigest()
            entry.hash_chain = current_hash
            self._last_hash = current_hash
            self.logs.append(entry)
        return entry

    @staticmethod
    def record_document(record):
        evidence = {k: v for k, v in (record.evidence_json or {}).items() if not k.startswith("_chain") and k != "_previous_hash"}
        return {"request_id": record.request_id, "tenant_id": record.tenant_id, "session_id": record.session_id,
                "timestamp": format_ist(record.timestamp), "action": record.action, "decision": record.decision,
                "risk_score": float(record.risk_score or 0), "evidence": evidence, "policy": record.policy,
                "latency_ms": float(record.latency_ms or 0), "source_type": record.source_type, "origin": record.origin,
                "prompt": record.prompt, "raw_prompt_hash": record.raw_prompt_hash,
                "gateway_overhead_ms": float(record.gateway_overhead_ms or 0), "upstream_llm_ms": float(record.upstream_llm_ms or 0),
                "total_ms": float(record.total_ms or 0)}

    async def verify_chain(self, db, expected_head=None):
        """Recompute persisted records; legacy entries are identified, never certified."""
        from app.models.database_models import AuditLogModel
        previous, checked, legacy = "0" * 64, 0, 0
        result = await db.stream_scalars(select(AuditLogModel).order_by(AuditLogModel.id).execution_options(platform_query=True))
        async for record in result:
            evidence = record.evidence_json or {}
            if not isinstance(evidence, dict) or evidence.get("_chain_version") != 2:
                legacy += 1
                previous = record.hash_chain or "0" * 64
                continue
            expected = hashlib.sha256((previous + "|" + json.dumps(self.record_document(record), sort_keys=True, separators=(",", ":"))).encode()).hexdigest()
            if evidence.get("_previous_hash") != previous or record.hash_chain != expected:
                return {"valid": False, "checked": checked, "legacy_unverified": legacy, "first_invalid_id": record.id}
            previous = record.hash_chain
            checked += 1
        return {"valid": expected_head is None or expected_head == previous, "checked": checked,
                "legacy_unverified": legacy, "head": previous, "externally_anchored": expected_head is not None}
