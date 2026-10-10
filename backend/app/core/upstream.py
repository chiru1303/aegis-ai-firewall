"""Server-controlled provider origins and credential destination binding."""
from urllib.parse import urlsplit
from fastapi import HTTPException
from app.core.config import settings


def origin(url: str) -> str:
    if any(ord(c) < 32 for c in url):
        raise HTTPException(400, "Invalid provider URL")
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError()
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return f"{parsed.scheme}://{parsed.hostname.lower()}:{port}"
    except ValueError:
        raise HTTPException(400, "Provider must be an HTTP(S) URL without credentials or query parameters")


# Default trusted origins for common providers in development or when not explicitly overridden
DEFAULT_UPSTREAM_ORIGINS = [
    "http://localhost:11434",
    "http://127.0.0.1:11434",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "https://api.openai.com",
    "https://api.anthropic.com",
    "https://api.groq.com",
]


def validate_upstream(url: str, *, allow_configured: bool = True) -> str:
    target = origin(url)
    allowed = {origin(item) for item in settings.UPSTREAM_ALLOWED_ORIGINS}
    if allow_configured and settings.LLM_BASE_URL:
        allowed.add(origin(settings.LLM_BASE_URL))
    # In development or if no explicit allowlist is configured, permit standard local and provider endpoints
    if settings.ENVIRONMENT != "production" or not settings.UPSTREAM_ALLOWED_ORIGINS:
        allowed.update({origin(item) for item in DEFAULT_UPSTREAM_ORIGINS})
    if target not in allowed:
        raise HTTPException(403, "Provider origin is not in the server allowlist")
    if settings.ENVIRONMENT == "production" and urlsplit(url).scheme != "https":
        raise HTTPException(400, "Production providers require HTTPS")
    return url.rstrip("/")
