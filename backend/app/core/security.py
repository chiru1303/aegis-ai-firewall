from fastapi import Request, Depends, HTTPException, status
from fastapi.security import APIKeyHeader
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
import uuid
import time
from app.core.config import settings
from app.core.redis_client import get_redis, RedisClient
from app.core.logging import get_logger

logger = get_logger(__name__)

API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

async def verify_api_key(api_key: str = Depends(api_key_header)):
    if not settings.ENABLE_API_AUTH:
        return True
    if api_key != settings.API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key"
        )
    return api_key

def generate_request_id() -> str:
    return f"req_{uuid.uuid4().hex}"

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"
        return response

class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if not settings.ENABLE_RATE_LIMITING:
            return await call_next(request)

        try:
            client_ip = request.client.host if request.client else "unknown"
            from app.core.redis_client import redis_client

            if redis_client and redis_client.client:
                key = f"rate_limit:{client_ip}"
                current = await redis_client.incr(key)
                if current == 1:
                    await redis_client.expire(key, settings.RATE_LIMIT_WINDOW)

                if current > settings.RATE_LIMIT_REQUESTS:
                    return Response("Rate limit exceeded", status_code=status.HTTP_429_TOO_MANY_REQUESTS)
        except Exception:
            # If Redis is unavailable, allow the request through
            pass

        return await call_next(request)
