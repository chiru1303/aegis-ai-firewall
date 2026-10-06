"""
Aegis AI Firewall - Main Application Entry Point
FastAPI application with lifespan management for database, Redis, ML models,
and detector initialization.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
import time

from app.core.config import settings
from app.core.database import init_db, close_db
from app.core.logging import setup_logging, get_logger
from app.core.security import SecurityHeadersMiddleware

setup_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle: initialize resources on startup, clean up on shutdown."""
    if settings.ENVIRONMENT == "production":
        if not settings.ENABLE_RATE_LIMITING or "*" in settings.CORS_ORIGINS:
            raise RuntimeError("Production requires rate limiting and explicit browser origins")
        if not settings.ENABLE_API_AUTH or len(settings.API_KEY) < 32 or settings.API_KEY in ("secret-key-change-me", "aegis-dev-key-change-in-production"):
            raise RuntimeError("Production requires authentication and a strong unique API_KEY")
        if len(settings.DASHBOARD_PASSWORD) < 12 or settings.DASHBOARD_PASSWORD == "admin123":
            raise RuntimeError("Production requires a unique dashboard password of at least 12 characters")
        if not settings.COOKIE_SECURE:
            raise RuntimeError("Production browser sessions require COOKIE_SECURE=true")
        if not settings.DATABASE_URL.startswith("postgresql"):
            raise RuntimeError("Production requires PostgreSQL for durable audit serialization")
        if settings.OUTPUT_SECURITY_MODE != "FULL_BUFFER":
            raise RuntimeError("Only FULL_BUFFER output security is supported")
        if settings.LLM_BASE_URL:
            from app.core.upstream import validate_upstream
            validate_upstream(settings.LLM_BASE_URL)
    logger.info("=" * 60)
    logger.info("  Aegis AI Firewall - Starting Up")
    logger.info("  Zero-Trust Prompt Injection & Agent Security Gateway")
    logger.info("=" * 60)

    # Initialize database
    try:
        await init_db()
        logger.info("[OK] Database initialized")
    except Exception as e:
        if settings.ENVIRONMENT == "production":
            raise
        logger.warning(f"[WARN] Database initialization failed: {e}")
        logger.warning("  -> Running in degraded mode without persistent storage")

    # Initialize Redis
    try:
        from app.core.redis_client import redis_client
        await redis_client.connect()
        if settings.ENVIRONMENT == "production" and redis_client._use_in_memory:
            raise RuntimeError("Production requires shared Redis storage")
        logger.info("[OK] Redis connected")
    except Exception as e:
        if settings.ENVIRONMENT == "production":
            raise
        logger.warning(f"[WARN] Redis not available: {e}")
        logger.warning("  -> Session tracking will use in-memory fallback")

    # Initialize detector registry (Tier 0 - deterministic)
    try:
        from app.detectors import registry
        tier0_count = len(registry.get_tier(0))
        logger.info(f"[OK] Tier 0 detectors loaded: {tier0_count} detectors")
        for d in registry.get_all():
            logger.info(f"     -> {d.name} (Tier {d.tier})")
    except Exception as e:
        logger.error(f"[ERR] Detector registry failed: {e}")

    # Initialize Multi-Tier AI Stack (Tier 1: DeBERTa, LightGBM; Tier 2: Laya; Tier 3: Open-Jev)
    try:
        from app.api.routes import ensemble_classifier
        await ensemble_classifier.initialize()
        logger.info(f"[OK] Wolf Defender: {'loaded' if ensemble_classifier.wolf.is_loaded else 'not loaded'}")
        logger.info(f"[OK] ProtectAI DeBERTa: {'loaded' if ensemble_classifier.deberta.is_loaded else 'not loaded'}")
        logger.info(f"[OK] LightGBM Classifier: {'loaded' if ensemble_classifier.lgb.is_loaded else 'not loaded'}")
        logger.info(f"[OK] Laya Multilingual: {'loaded' if ensemble_classifier.laya.is_loaded else 'not loaded'}")
        logger.info(f"[OK] Open-Jev Arbitrator: {'loaded' if ensemble_classifier.open_jev.is_loaded else 'not loaded'}")
    except Exception as e:
        logger.warning(f"[--] Ensemble initialization exception: {e}")

    if settings.REQUIRE_ML_MODELS:
        if not ensemble_classifier.deberta.is_loaded or not ensemble_classifier.lgb.is_loaded:
            raise RuntimeError("Required ML models are unavailable; readiness denied")

    # Check default secret key
    if settings.API_KEY == "secret-key-change-me" and not settings.DEBUG:
        logger.warning("[SECURITY] Master API_KEY is set to default 'secret-key-change-me'. Override in production via .env or environment variable.")

    # Log configuration
    logger.info(f"[CFG] LLM Provider: {settings.LLM_PROVIDER}")
    logger.info(f"[CFG] LLM Base URL: {settings.LLM_BASE_URL or 'not configured'}")
    logger.info(f"[CFG] API Auth: {'enabled' if settings.ENABLE_API_AUTH else 'disabled'}")
    logger.info(f"[CFG] Rate Limiting: {'enabled' if settings.ENABLE_RATE_LIMITING else 'disabled'}")
    logger.info("")
    logger.info("Aegis AI Firewall is ready to protect.")
    logger.info("=" * 60)

    yield

    # Shutdown
    try:
        from app.decision.ml_executor import get_ml_executor_pool
        get_ml_executor_pool().shutdown(wait=False)
    except Exception:
        pass
    try:
        await close_db()
    except Exception:
        pass
    try:
        from app.core.redis_client import redis_client
        await redis_client.disconnect()
    except Exception:
        pass
    logger.info("Shutdown complete.")


app = FastAPI(
    title=settings.APP_NAME,
    description="Zero-Trust Prompt Injection & Agent Security Gateway",
    version=settings.VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS Middleware: Disallow credentials if wildcard origin is configured
cors_allow_credentials = True
if "*" in settings.CORS_ORIGINS:
    cors_allow_credentials = False
    logger.warning("Wildcard '*' in CORS_ORIGINS; disabling allow_credentials for security compliance.")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=cors_allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security Headers
app.add_middleware(SecurityHeadersMiddleware)
from app.core.ingress import IngressMiddleware
app.add_middleware(IngressMiddleware)

# Request timing middleware
@app.middleware("http")
async def add_timing_header(request: Request, call_next):
    start_time = time.perf_counter()
    response = await call_next(request)
    process_time = (time.perf_counter() - start_time) * 1000
    response.headers["X-Process-Time-Ms"] = f"{process_time:.2f}"
    response.headers["X-Powered-By"] = "Aegis AI Firewall"
    return response

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": "An unexpected error occurred. Check server logs.",
        }
    )

# Import routers: Split Data Plane & Control Plane, plus unified API
from app.api.data_plane.routes import router as data_plane_router
from app.api.control_plane.routes import router as control_plane_router
from app.api.routes import router as unified_router

# Mount Data Plane (Zero-Trust Ingestion Gateway)
app.include_router(data_plane_router, prefix="/v1", tags=["Data Plane Gateway"])

# Mount Control Plane (Admin, Multi-Tenancy, Policies, Audit)
app.include_router(control_plane_router, prefix="/admin", tags=["Control Plane Admin"])

# Mount Unified API under /api/v1 (Ensuring 100% backward compatibility for dashboard and clients)
app.include_router(unified_router, prefix="/api/v1", tags=["Aegis Unified Security API"])
from app.api.auth import router as auth_router
app.include_router(auth_router, prefix="/api/v1/auth", tags=["Browser authentication"])



@app.get("/", tags=["Root"])
async def root():
    return {
        "name": settings.APP_NAME,
        "version": settings.VERSION,
        "description": "Zero-Trust Prompt Injection & Agent Security Gateway",
        "docs": "/docs",
        "health": "/api/v1/health",
        "philosophy": "Inspect untrusted content and enforce authorization at model and tool boundaries.",
    }


@app.get("/ready", tags=["Health"])
async def ready():
    from app.api.routes import health
    result = await health()
    return JSONResponse({"ready": result.healthy}, status_code=200 if result.healthy else 503)


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
