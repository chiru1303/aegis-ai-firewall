"""
Aegis AI Firewall - Tenant & Server-Derived Trust Resolution
Enforces Non-Negotiable Invariants:
1. Invariant 1: Untrusted input cannot elevate its own trust level.
2. Server-derived trust: Trust is derived authoritatively from server-configured Connector/Identity policies.
3. Strict Authentication: Unauthenticated requests cannot assume default superadmin credentials.
"""
from dataclasses import dataclass
from typing import Optional, Dict, Any, List
import hashlib
import hmac
from fastapi import Request, Header, HTTPException, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.config import settings
from app.core.database import get_db
from app.core.logging import get_logger
from app.models.schemas import TrustLevel, SourceType
from app.core.browser_session import COOKIE_NAME, read_session
from datetime import datetime, timezone

logger = get_logger(__name__)


@dataclass
class TenantContext:
    tenant_id: str
    tenant_name: str
    application_id: Optional[str] = None
    environment_id: Optional[str] = None
    connector_id: Optional[str] = None
    role: str = "data_plane"
    authoritative_trust_level: TrustLevel = TrustLevel.UNTRUSTED
    credential_id: Optional[str] = None
    credential_name: Optional[str] = None


def bind_context(db, ctx):
    if hasattr(db, "info"):
        db.info["tenant_id"] = ctx.tenant_id
        db.info["role"] = ctx.role
    return ctx


# Default fallback trust map based on server-verified connector types and source types
SOURCE_TYPE_DEFAULT_TRUST: Dict[str, TrustLevel] = {
    "system": TrustLevel.TRUSTED,
    "database": TrustLevel.SEMI_TRUSTED,
    "api": TrustLevel.SEMI_TRUSTED,
    "user": TrustLevel.UNTRUSTED,
    "web": TrustLevel.UNTRUSTED,
    "pdf": TrustLevel.UNTRUSTED,
    "docx": TrustLevel.UNTRUSTED,
    "email": TrustLevel.UNTRUSTED,
    "ocr": TrustLevel.UNTRUSTED,
    "code": TrustLevel.UNTRUSTED,
    "image": TrustLevel.UNTRUSTED,
    "unknown": TrustLevel.UNTRUSTED,
}


def hash_api_key(key: str) -> str:
    """Return SHA-256 hash of API key for secure lookups."""
    return hashlib.sha256(key.strip().encode("utf-8")).hexdigest()


async def resolve_tenant_context(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    db: AsyncSession = Depends(get_db),
) -> TenantContext:
    """
    Authenticate caller via API key and derive the authoritative TenantContext.
    Ensures that trust level is strictly determined by server-side policy and identity.
    VULN-01 FIX: Never assign default superadmin privileges to unauthenticated requests.
    VULN-08 FIX: Use constant-time comparison for API key verification.
    """
    raw_key = None
    if x_api_key:
        raw_key = x_api_key.strip()
    elif authorization and authorization.lower().startswith("bearer "):
        raw_key = authorization[7:].strip()

    # If API authentication is disabled (explicit test/dev setting), allow a dev context
    if not settings.ENABLE_API_AUTH and not raw_key:
        return TenantContext(
            tenant_id="tenant_default",
            tenant_name="Default Bootstrap Tenant",
            application_id="app_default",
            environment_id="env_dev",
            role="data_plane",
            authoritative_trust_level=TrustLevel.UNTRUSTED,
            credential_name="dev_unauthenticated_test",
        )

    session_hash = read_session(request.cookies.get(COOKIE_NAME, "")) if not raw_key else None
    # A browser session is revalidated against the live credential on every request.
    if not raw_key and not session_hash:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API credential. Provide 'Authorization: Bearer <key>' or 'X-API-Key'.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    hashed_key = hash_api_key(raw_key) if raw_key else session_hash

    # 1. DB lookup for API credential
    try:
        from app.models.database_models import ApiCredentialModel, ConnectorModel, TenantModel
        stmt = (
            select(ApiCredentialModel, ConnectorModel, TenantModel)
            .outerjoin(ConnectorModel, ApiCredentialModel.connector_id == ConnectorModel.id)
            .outerjoin(TenantModel, ApiCredentialModel.tenant_id == TenantModel.id)
            .where(ApiCredentialModel.key_hash == hashed_key)
            .where(ApiCredentialModel.is_active.is_(True))
        )
        res = await db.execute(stmt)
        record = res.first()

        if record:
            cred, connector, tenant = record
            if cred.id == "cred_master_default" and cred.key_hash != hash_api_key(settings.API_KEY):
                raise HTTPException(401, "Bootstrap credential rotated")
            if tenant and not tenant.is_active:
                raise HTTPException(401, "Tenant is disabled")
            if cred.expires_at:
                expires = cred.expires_at.replace(tzinfo=timezone.utc) if cred.expires_at.tzinfo is None else cred.expires_at
                if expires <= datetime.now(timezone.utc):
                    raise HTTPException(401, "Credential expired")
            trust_lvl = TrustLevel.UNTRUSTED
            if connector and connector.default_trust_level:
                try:
                    trust_lvl = TrustLevel(connector.default_trust_level)
                except ValueError:
                    trust_lvl = TrustLevel.UNTRUSTED

            return bind_context(db, TenantContext(
                tenant_id=cred.tenant_id,
                tenant_name=tenant.name if tenant else "Default Tenant",
                application_id=cred.application_id,
                environment_id=cred.environment_id,
                connector_id=cred.connector_id,
                role=cred.role,
                authoritative_trust_level=trust_lvl,
                credential_id=cred.id,
                credential_name=cred.name,
            ))
    except HTTPException:
        raise
    except Exception as e:
        logger.debug(f"DB lookup during tenant context resolution: {e}")

    # 2. Timing-safe comparison against master system key
    if settings.API_KEY and hmac.compare_digest(hashed_key, hash_api_key(settings.API_KEY)):
        return bind_context(db, TenantContext(
            tenant_id="tenant_default",
            tenant_name="Default System Tenant",
            application_id="app_default",
            environment_id="env_production",
            connector_id="conn_api_gateway",
            role="superadmin",
            authoritative_trust_level=TrustLevel.UNTRUSTED,
            credential_name="master_system_key",
        ))

    # 3. Reject unauthorized access
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or deactivated API credential",
        headers={"WWW-Authenticate": "ApiKey"},
    )


def require_role(allowed_roles: List[str]):
    """
    Role-Based Access Control (RBAC) dependency.
    Ensures that only callers with appropriate roles can access privileged endpoints.
    """
    async def role_checker(
        tenant_ctx: TenantContext = Depends(resolve_tenant_context)
    ) -> TenantContext:
        if tenant_ctx.role == "superadmin" or tenant_ctx.role in allowed_roles:
            return tenant_ctx
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: Insufficient privileges. Required role in {allowed_roles}, caller has '{tenant_ctx.role}'.",
        )
    return role_checker


def derive_authoritative_trust(
    tenant_ctx: TenantContext,
    source_type: Optional[str] = None,
    client_claimed_trust: Optional[str] = None,
) -> TrustLevel:
    """
    CRITICAL INVARIANT 1: Untrusted input cannot elevate its own trust level.
    The client-supplied 'trustLevel' is strictly ignored and overridden.
    Trust is derived from:
    1. Tenant connector default trust level
    2. Server-side source type classification map
    The least trusted privilege is enforced.
    """
    if client_claimed_trust and client_claimed_trust != tenant_ctx.authoritative_trust_level.value:
        logger.warning(
            f"Client attempted to assert trust level '{client_claimed_trust}'. "
            f"Overridden by authoritative server trust: '{tenant_ctx.authoritative_trust_level.value}'"
        )

    # Base trust from connector
    base_trust = tenant_ctx.authoritative_trust_level

    # Refine by verified source type
    if source_type:
        st = source_type.lower()
        type_trust = SOURCE_TYPE_DEFAULT_TRUST.get(st, TrustLevel.UNTRUSTED)
        priority = {
            TrustLevel.MALICIOUS: 0,
            TrustLevel.UNTRUSTED: 1,
            TrustLevel.SEMI_TRUSTED: 2,
            TrustLevel.TRUSTED: 3,
        }
        if priority.get(type_trust, 1) < priority.get(base_trust, 1):
            return type_trust

    return base_trust
