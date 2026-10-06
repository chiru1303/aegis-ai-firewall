"""
Aegis AI Firewall - Control Plane Administration Router
Handles:
1. Multi-tenant administration (Tenants, Applications, Connectors)
2. API Key Credential lifecycle (generation, hashing, revocation)
3. Hierarchical policy management (Global -> Tenant -> App -> Env)
4. Tamper-evident Audit trail queries with SHA-256 hash-chain verification
5. Live SOC Threat Feed and Session Trajectory state inspection
6. System health, diagnostics, and metrics reporting
"""
import uuid
import hashlib
import time
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
import httpx

from app.core.database import get_db, _has_async_driver
from app.core.config import settings
from app.core.tenant import resolve_tenant_context, hash_api_key, TenantContext, require_role
from app.core.logging import get_logger
from app.core.time import format_ist
from app.models.database_models import (
    TenantModel, ApplicationModel, ConnectorModel, ApiCredentialModel,
    PolicyModel, AuditLogModel, RequestModel, SessionModel, AuditOutboxModel
)
from app.models.schemas import (
    HealthResponse, MetricsResponse, PolicyResponse, AuditRecord
)
from app.decision.ml_executor import get_ml_executor_pool

logger = get_logger(__name__)

router = APIRouter()


@router.delete("/credentials/{credential_id}")
async def revoke_api_credential(credential_id: str, ctx: TenantContext = Depends(require_role(["superadmin", "tenant_admin"])), db: AsyncSession = Depends(get_db)):
    credential = (await db.execute(select(ApiCredentialModel).where(ApiCredentialModel.id == credential_id))).scalar_one_or_none()
    if credential is None or (ctx.role != "superadmin" and credential.tenant_id != ctx.tenant_id):
        raise HTTPException(404, "Credential not found")
    if credential_id == "cred_master_default":
        raise HTTPException(422, "Rotate the bootstrap key through deployment configuration")
    credential.is_active = False
    await db.commit()
    return {"status": "revoked"}


@router.get("/audit/verify")
async def verify_audit_chain(expected_head: Optional[str] = Query(None, min_length=64, max_length=64), ctx: TenantContext = Depends(require_role(["superadmin"])), db: AsyncSession = Depends(get_db)):
    from app.api.routes import audit_engine
    return await audit_engine.verify_chain(db, expected_head)


# -------------------------------------------------------------------------
# 1. Health & Diagnostics
# -------------------------------------------------------------------------
@router.get("/health", response_model=HealthResponse)
async def get_system_health(db: AsyncSession = Depends(get_db)):
    """System health diagnostics across models, database, and thread pool."""
    from app.api.routes import health
    return await health()


# -------------------------------------------------------------------------
# 2. SOC Operational Metrics
# -------------------------------------------------------------------------
@router.get("/metrics")
async def get_system_metrics(
    tenant_ctx: TenantContext = Depends(require_role(["superadmin", "admin", "tenant_admin", "soc_analyst", "auditor"])),
    db: AsyncSession = Depends(get_db),
):
    """Aggregated metrics for the security operations dashboard."""
    try:
        # Total requests
        total_stmt = select(func.count(RequestModel.id))
        if tenant_ctx.role != "superadmin":
            total_stmt = total_stmt.where(RequestModel.tenant_id == tenant_ctx.tenant_id)
        total_res = await db.execute(total_stmt)
        total_reqs = total_res.scalar() or 0

        # Total blocks
        blocks_stmt = select(func.count(RequestModel.id)).where(RequestModel.decision == "BLOCK")
        if tenant_ctx.role != "superadmin":
            blocks_stmt = blocks_stmt.where(RequestModel.tenant_id == tenant_ctx.tenant_id)
        blocks_res = await db.execute(blocks_stmt)
        total_blocks = blocks_res.scalar() or 0

        # Total allowed
        allowed_stmt = select(func.count(RequestModel.id)).where(RequestModel.decision == "ALLOW")
        if tenant_ctx.role != "superadmin":
            allowed_stmt = allowed_stmt.where(RequestModel.tenant_id == tenant_ctx.tenant_id)
        allowed_res = await db.execute(allowed_stmt)
        total_allowed = allowed_res.scalar() or 0

        # Total sanitized
        sanitized_stmt = select(func.count(RequestModel.id)).where(RequestModel.decision == "SANITIZE")
        if tenant_ctx.role != "superadmin":
            sanitized_stmt = sanitized_stmt.where(RequestModel.tenant_id == tenant_ctx.tenant_id)
        sanitized_res = await db.execute(sanitized_stmt)
        total_sanitized = sanitized_res.scalar() or 0

        # Average latency
        lat_stmt = select(func.avg(RequestModel.latency_ms))
        if tenant_ctx.role != "superadmin":
            lat_stmt = lat_stmt.where(RequestModel.tenant_id == tenant_ctx.tenant_id)
        lat_res = await db.execute(lat_stmt)
        avg_lat = lat_res.scalar() or 0.0

        return {
            "requests_today": total_reqs,
            "requests_total": total_reqs,
            "blocked": total_blocks,
            "blocks_total": total_blocks,
            "allowed": total_allowed,
            "sanitized": total_sanitized,
            "high_risk": total_blocks,
            "critical": total_blocks,
            "avg_latency_ms": round(float(avg_lat), 2),
            "detection_rate": round(total_blocks / total_reqs * 100, 1) if total_reqs > 0 else 0.0,
            "requests_by_hour": [],
            "decision_distribution": {
                "ALLOW": total_allowed,
                "BLOCK": total_blocks,
                "SANITIZE": total_sanitized,
            },
            "attack_types_distribution": {},
            "risk_score_distribution": [],
        }
    except Exception as e:
        logger.debug(f"Metrics aggregation fallback: {e}")
        return {
            "requests_today": 0,
            "requests_total": 0,
            "blocked": 0,
            "blocks_total": 0,
            "allowed": 0,
            "sanitized": 0,
            "high_risk": 0,
            "critical": 0,
            "avg_latency_ms": 0.0,
            "detection_rate": 0.0,
            "requests_by_hour": [],
            "decision_distribution": {"ALLOW": 0, "BLOCK": 0, "SANITIZE": 0},
            "attack_types_distribution": {},
            "risk_score_distribution": [],
        }


# -------------------------------------------------------------------------
# 3. Live Threat Feed & Auditing
# -------------------------------------------------------------------------
@router.get("/feed")
async def get_threat_feed(
    limit: int = Query(20, ge=1, le=100),
    tenant_ctx: TenantContext = Depends(require_role(["superadmin", "admin", "tenant_admin", "soc_analyst"])),
    db: AsyncSession = Depends(get_db),
):
    """Real-time live threat feed queryable by SOC dashboard."""
    try:
        stmt = select(RequestModel).order_by(RequestModel.id.desc()).limit(limit)
        if tenant_ctx.role != "superadmin":
            stmt = stmt.where(RequestModel.tenant_id == tenant_ctx.tenant_id)
        res = await db.execute(stmt)
        items = res.scalars().all()

        return [
            {
                "id": str(r.id),
                "request_id": r.request_id,
                "timestamp": format_ist(r.timestamp) if r.timestamp else "",
                "source": r.source_type or "user",
                "attack_types": r.attack_types_json or [],
                "risk_score": r.risk_score or 0.0,
                "riskScore": r.risk_score or 0.0,
                "decision": r.decision or "ALLOW",
                "latency_ms": r.latency_ms or 0.0,
                "origin": r.origin or "api",
                "policy": r.policy or "default_zero_trust",
                "prompt": getattr(r, "prompt", None) or "",
                "raw_prompt_hash": getattr(r, "raw_prompt_hash", None) or "",
            }
            for r in items
        ]
    except Exception as e:
        logger.debug(f"Feed query exception: {e}")
        return []


@router.get("/audit")
async def get_audit_logs(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    tenant_ctx: TenantContext = Depends(require_role(["superadmin", "admin", "tenant_admin", "soc_analyst", "auditor"])),
    db: AsyncSession = Depends(get_db),
):
    """Retrieve immutable audit trail with SHA-256 hash chaining."""
    try:
        stmt = (
            select(AuditLogModel)
            .order_by(AuditLogModel.id.desc())
            .offset(offset)
            .limit(limit)
        )
        if tenant_ctx.role != "superadmin":
            stmt = stmt.where(AuditLogModel.tenant_id == tenant_ctx.tenant_id)
        res = await db.execute(stmt)
        logs = res.scalars().all()

        return [
            {
                "id": l.id,
                "request_id": l.request_id,
                "tenant_id": l.tenant_id,
                "session_id": l.session_id,
                "timestamp": format_ist(l.timestamp) if l.timestamp else "",
                "action": l.action,
                "decision": l.decision,
                "risk_score": l.risk_score,
                "riskScore": l.risk_score,
                "prompt": getattr(l, "prompt", None) or (l.evidence_json.get("prompt") if isinstance(l.evidence_json, dict) else ""),
                "raw_prompt_hash": getattr(l, "raw_prompt_hash", None) or (l.evidence_json.get("raw_prompt_hash") if isinstance(l.evidence_json, dict) else ""),
                "has_pii": bool(isinstance(l.evidence_json, dict) and l.evidence_json.get("has_pii")),
                "pii_types": l.evidence_json.get("pii_types", []) if isinstance(l.evidence_json, dict) else [],
                "evidence": l.evidence_json,
                "policy": l.policy,
                "latency_ms": l.latency_ms,
                "source_type": l.source_type,
                "origin": l.origin,
                "hash_chain": l.hash_chain,
            }
            for l in logs
        ]
    except Exception as e:
        logger.debug(f"Audit log query exception: {e}")
        return []


# -------------------------------------------------------------------------
# 4. Multi-Tenant Organization Management
# -------------------------------------------------------------------------
@router.get("/tenants")
async def list_tenants(
    tenant_ctx: TenantContext = Depends(require_role(["superadmin", "admin"])),
    db: AsyncSession = Depends(get_db),
):
    """List registered tenants."""
    stmt = select(TenantModel).order_by(TenantModel.created_at.desc())
    if tenant_ctx.role != "superadmin":
        stmt = stmt.where(TenantModel.id == tenant_ctx.tenant_id)
    res = await db.execute(stmt)
    tenants = res.scalars().all()
    return [
        {
            "id": t.id,
            "name": t.name,
            "slug": t.slug,
            "tier": t.tier,
            "is_active": t.is_active,
            "created_at": format_ist(t.created_at) if t.created_at else None,
        }
        for t in tenants
    ]


@router.post("/tenants")
async def create_tenant(
    payload: Dict[str, Any],
    tenant_ctx: TenantContext = Depends(require_role(["superadmin"])),
    db: AsyncSession = Depends(get_db),
):
    """Create a new tenant with dedicated isolation boundary. Requires superadmin role."""
    slug = payload.get("slug") or payload.get("name", "").lower().replace(" ", "-")
    tenant_id = f"tenant_{uuid.uuid4().hex[:12]}"

    tenant = TenantModel(
        id=tenant_id,
        name=payload.get("name", "Unnamed Tenant"),
        slug=slug,
        tier=payload.get("tier", "standard"),
        is_active=True,
    )
    db.add(tenant)
    await db.commit()
    return {"id": tenant.id, "slug": tenant.slug, "status": "created"}


# -------------------------------------------------------------------------
# 5. Connector Management (Authoritative Trust Mapping)
# -------------------------------------------------------------------------
@router.get("/connectors")
async def list_connectors(
    tenant_ctx: TenantContext = Depends(require_role(["superadmin", "admin", "tenant_admin"])),
    db: AsyncSession = Depends(get_db),
):
    """List connectors and their server-derived trust levels."""
    stmt = select(ConnectorModel).order_by(ConnectorModel.created_at.desc())
    if tenant_ctx.role != "superadmin":
        stmt = stmt.where(ConnectorModel.tenant_id == tenant_ctx.tenant_id)
    res = await db.execute(stmt)
    connectors = res.scalars().all()
    return [
        {
            "id": c.id,
            "tenant_id": c.tenant_id,
            "name": c.name,
            "connector_type": c.connector_type,
            "default_trust_level": c.default_trust_level,
            "auth_type": c.auth_type,
        }
        for c in connectors
    ]


@router.post("/connectors")
async def create_connector(
    payload: Dict[str, Any],
    tenant_ctx: TenantContext = Depends(require_role(["superadmin", "tenant_admin"])),
    db: AsyncSession = Depends(get_db),
):
    """Create a new ingress connector with authoritative trust policy."""
    tenant_id = tenant_ctx.tenant_id if tenant_ctx.role != "superadmin" else payload.get("tenant_id", "tenant_default")
    connector = ConnectorModel(
        id=f"conn_{uuid.uuid4().hex[:12]}",
        tenant_id=tenant_id,
        name=payload.get("name", "Ingress Connector"),
        connector_type=payload.get("connector_type", "api_gateway"),
        default_trust_level=payload.get("default_trust_level", "UNTRUSTED"),
        auth_type=payload.get("auth_type", "api_key"),
        config_json=payload.get("config", {}),
    )
    db.add(connector)
    await db.commit()
    return {"id": connector.id, "name": connector.name, "trust_level": connector.default_trust_level}


# -------------------------------------------------------------------------
# 6. API Key Credential Management (Secure Hash Storage)
# -------------------------------------------------------------------------
@router.post("/credentials")
async def create_api_credential(
    payload: Dict[str, Any],
    tenant_ctx: TenantContext = Depends(require_role(["superadmin", "tenant_admin"])),
    db: AsyncSession = Depends(get_db),
):
    """
    Generate a new API Key.
    The secret key is shown ONCE. Only its SHA-256 hash is retained on disk.
    Enforces tenant boundaries and prevents non-superadmin privilege escalation.
    """
    requested_role = payload.get("role", "data_plane")
    if requested_role == "superadmin" and tenant_ctx.role != "superadmin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Only superadmin can provision superadmin credentials.",
        )

    tenant_id = tenant_ctx.tenant_id if tenant_ctx.role != "superadmin" else payload.get("tenant_id", "tenant_default")

    if requested_role not in {"superadmin", "tenant_admin", "admin", "soc_analyst", "auditor", "data_plane"}:
        raise HTTPException(422, "Unknown credential role")
    tenant = (await db.execute(select(TenantModel).where(TenantModel.id == tenant_id))).scalar_one_or_none()
    if not tenant or not tenant.is_active:
        raise HTTPException(404, "Active tenant not found")
    for field, model in (("application_id", ApplicationModel), ("connector_id", ConnectorModel)):
        if payload.get(field):
            item = (await db.execute(select(model).where(model.id == payload[field], model.tenant_id == tenant_id))).scalar_one_or_none()
            if item is None:
                raise HTTPException(404, f"Owned {field} not found")

    raw_secret = f"aegis_live_{uuid.uuid4().hex}"
    key_hash = hash_api_key(raw_secret)
    prefix = raw_secret[:14]

    cred = ApiCredentialModel(
        id=f"cred_{uuid.uuid4().hex[:12]}",
        tenant_id=tenant_id,
        application_id=payload.get("application_id"),
        environment_id=payload.get("environment_id"),
        connector_id=payload.get("connector_id"),
        key_hash=key_hash,
        key_prefix=prefix,
        name=payload.get("name", "Generated API Key"),
        role=requested_role,
        is_active=True,
    )
    db.add(cred)
    await db.commit()

    return {
        "credential_id": cred.id,
        "name": cred.name,
        "role": cred.role,
        "api_key": raw_secret,  # Displayed once
        "prefix": prefix,
        "warning": "Copy this secret now. It will not be shown again.",
    }


# -------------------------------------------------------------------------
# 7. Hierarchical Policy Management
# -------------------------------------------------------------------------
@router.get("/policies")
async def list_policies(
    tenant_ctx: TenantContext = Depends(require_role(["superadmin", "admin", "soc_analyst", "data_plane"])),
    db: AsyncSession = Depends(get_db),
):
    """List active security policies."""
    stmt = select(PolicyModel).order_by(PolicyModel.priority.asc())
    res = await db.execute(stmt)
    policies = res.scalars().all()
    if not policies:
        # Fallback to default
        return [
            {
                "id": "1",
                "name": "default_zero_trust",
                "scope": "GLOBAL",
                "priority": 10,
                "is_mandatory": True,
                "is_active": True,
            }
        ]
    return [
        {
            "id": str(p.id),
            "name": p.name,
            "description": p.description,
            "scope": p.scope,
            "scope_id": p.scope_id,
            "priority": p.priority,
            "is_mandatory": p.is_mandatory,
            "is_active": p.is_active,
            "rules": p.rules_json,
        }
        for p in policies
    ]


# -------------------------------------------------------------------------
# 8. Protected Applications Management
# -------------------------------------------------------------------------
@router.get("/applications")
async def list_applications(
    tenant_ctx: TenantContext = Depends(require_role(["superadmin", "admin", "tenant_admin", "soc_analyst", "data_plane"])),
    db: AsyncSession = Depends(get_db),
):
    """List registered protected applications."""
    stmt = select(ApplicationModel).order_by(ApplicationModel.created_at.desc())
    if tenant_ctx.role != "superadmin":
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
async def create_application(
    payload: Dict[str, Any],
    tenant_ctx: TenantContext = Depends(require_role(["superadmin", "admin", "tenant_admin", "data_plane"])),
    db: AsyncSession = Depends(get_db),
):
    """
    Register a new protected application and provision its dedicated API key.
    """
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

    # Automatically provision credential
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


# -------------------------------------------------------------------------
# 9. Upstream Provider Connectivity Validation
# -------------------------------------------------------------------------
@router.post("/providers/test")
async def test_llm_provider(
    payload: Dict[str, Any],
    tenant_ctx: TenantContext = Depends(require_role(["superadmin"])),
):
    """
    Test connection to an upstream LLM provider (Ollama, OpenAI, vLLM, custom).
    Validates responsiveness, measures connection latency, and returns model list if available.
    """
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
