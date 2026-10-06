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


def validate_upstream(url: str, *, allow_configured: bool = True) -> str:
    target = origin(url)
    allowed = {origin(item) for item in settings.UPSTREAM_ALLOWED_ORIGINS}
    if allow_configured and settings.LLM_BASE_URL:
        allowed.add(origin(settings.LLM_BASE_URL))
    if target not in allowed:
        raise HTTPException(403, "Provider origin is not in the server allowlist")
    if settings.ENVIRONMENT == "production" and urlsplit(url).scheme != "https":
        raise HTTPException(400, "Production providers require HTTPS")
    return url.rstrip("/")
