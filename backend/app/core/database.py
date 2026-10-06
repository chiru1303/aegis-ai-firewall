"""
Database initialization with resilient fallback.
Supports asyncpg (PostgreSQL in Docker/Production), aiosqlite (Local),
and an in-memory fallback async session if DB driver packages are not present.
"""
from typing import AsyncGenerator
from sqlalchemy.orm import declarative_base
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

Base = declarative_base()
import app.core.tenant_queries

_engine = None
_async_session_maker = None
_has_async_driver = False

try:
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
    # Test if driver is available
    if "postgresql" in settings.DATABASE_URL:
        import asyncpg
    elif "sqlite" in settings.DATABASE_URL:
        import aiosqlite

    _engine = create_async_engine(
        settings.DATABASE_URL,
        echo=settings.DEBUG,
        future=True
    )
    _async_session_maker = async_sessionmaker(
        _engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False
    )
    _has_async_driver = True
    engine = _engine
    logger.info("Database engine initialized")
except Exception as e:
    logger.warning(f"Async DB driver not available ({e}). Using resilient in-memory session engine.")
    _has_async_driver = False
    engine = None


class InMemoryAsyncSession:
    """In-memory async session fallback when asyncpg/aiosqlite is not installed locally."""
    def __init__(self):
        self._items = []

    def add(self, item):
        self._items.append(item)

    async def commit(self):
        pass

    async def rollback(self):
        pass

    async def scalar(self, stmt):
        return 0

    async def execute(self, stmt):
        class DummyResult:
            def scalars(self):
                class DummyScalars:
                    def all(self):
                        return []
                    def one_or_none(self):
                        return None
                return DummyScalars()
            def scalar_one_or_none(self):
                return None
        return DummyResult()

    async def close(self):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


async def get_db() -> AsyncGenerator:
    """FastAPI dependency for database session."""
    if _has_async_driver and _async_session_maker:
        async with _async_session_maker() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
    else:
        session = InMemoryAsyncSession()
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    """Create all tables and seed default tenant, connector, credential, and global policy if empty."""
    if _has_async_driver and _engine:
        try:
            import app.models.database_models as db_models
            async with _engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
                # Auto-migrate: ensure prompt and raw_prompt_hash columns exist
                from sqlalchemy import text
                for tbl, col, col_type in [
                    ("audit_logs", "prompt", "TEXT"),
                    ("audit_logs", "raw_prompt_hash", "VARCHAR(64)"),
                    ("requests", "prompt", "TEXT"),
                    ("requests", "raw_prompt_hash", "VARCHAR(64)"),
                    ("audit_logs", "gateway_overhead_ms", "FLOAT DEFAULT 0.0"),
                    ("audit_logs", "upstream_llm_ms", "FLOAT DEFAULT 0.0"),
                    ("audit_logs", "total_ms", "FLOAT DEFAULT 0.0"),
                    ("requests", "gateway_overhead_ms", "FLOAT DEFAULT 0.0"),
                    ("requests", "upstream_llm_ms", "FLOAT DEFAULT 0.0"),
                    ("requests", "total_ms", "FLOAT DEFAULT 0.0"),
                ]:
                    from sqlalchemy import inspect
                    existing = await conn.run_sync(lambda sync_conn: {c["name"] for c in inspect(sync_conn).get_columns(tbl)})
                    if col not in existing:
                        await conn.execute(text(f"ALTER TABLE {tbl} ADD COLUMN {col} {col_type}"))
            logger.info("Database tables created/verified successfully.")

            # Seed default tenant and master credential if not present
            async with _async_session_maker() as session:
                from sqlalchemy import select
                import hashlib
                res = await session.execute(select(db_models.TenantModel).limit(1))
                if not res.first():
                    default_tenant = db_models.TenantModel(
                        id="tenant_default",
                        name="Default Organization",
                        slug="default-org",
                        tier="enterprise",
                        is_active=True
                    )
                    default_app = db_models.ApplicationModel(
                        id="app_default",
                        tenant_id="tenant_default",
                        name="Aegis AI Gateway",
                        slug="aegis-gateway",
                        is_active=True
                    )
                    default_env = db_models.EnvironmentModel(
                        id="env_production",
                        application_id="app_default",
                        name="production",
                        is_active=True
                    )
                    default_connector = db_models.ConnectorModel(
                        id="conn_api_gateway",
                        tenant_id="tenant_default",
                        name="Standard Ingress API Gateway",
                        connector_type="api_gateway",
                        default_trust_level="UNTRUSTED",
                        auth_type="api_key"
                    )
                    master_hash = hashlib.sha256(settings.API_KEY.strip().encode("utf-8")).hexdigest()
                    default_cred = db_models.ApiCredentialModel(
                        id="cred_master_default",
                        tenant_id="tenant_default",
                        application_id="app_default",
                        environment_id="env_production",
                        connector_id="conn_api_gateway",
                        key_hash=master_hash,
                        key_prefix=settings.API_KEY[:8] if len(settings.API_KEY) >= 8 else "master_key",
                        name="Master Development & Ingestion Key",
                        role="superadmin",
                        is_active=True
                    )
                    global_policy = db_models.PolicyModel(
                        name="default_zero_trust",
                        description="Global mandatory zero-trust guardrails",
                        scope="GLOBAL",
                        priority=10,
                        is_mandatory=True,
                        rules_json={
                            "mandatory_blocks": [
                                "credential_exfiltration",
                                "unauthorized_secret_extraction",
                                "unauthorized_high_risk_tool",
                                "attempted_privilege_escalation",
                                "known_malicious_encoded_instruction"
                            ],
                            "max_risk_for_auto_allow": 0.19,
                            "sanitize_on_medium": True
                        },
                        is_active=True
                    )
                    session.add_all([default_tenant, default_app, default_env, default_connector, default_cred, global_policy])
                    await session.commit()
                    logger.info("Bootstrap tenant, application, connector, credentials, and policies seeded.")
        except Exception as e:
            if settings.ENVIRONMENT == "production":
                raise
            logger.warning(f"Database init_db warning: {e}")
    else:
        logger.info("Operating in driver-free memory mode; skipping schema creation.")


async def close_db():
    """Dispose of database engine connections."""
    if _has_async_driver and _engine:
        try:
            await _engine.dispose()
        except Exception:
            pass
