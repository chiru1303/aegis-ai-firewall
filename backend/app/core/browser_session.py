"""Signed, expiring browser sessions carry a credential hash, never a raw API key."""
import base64
import hashlib
import hmac
import json
import time
from app.core.config import settings

COOKIE_NAME = "aegis_session"


def issue_session(key_hash: str) -> str:
    payload = base64.urlsafe_b64encode(json.dumps({
        "key_hash": key_hash, "expires": int(time.time()) + settings.SESSION_TTL_SECONDS,
    }, separators=(",", ":")).encode()).decode()
    signature = hmac.new(settings.API_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{signature}"


def read_session(token: str) -> str | None:
    try:
        payload, signature = token.rsplit(".", 1)
        expected = hmac.new(settings.API_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        claims = json.loads(base64.urlsafe_b64decode(payload))
        if claims["expires"] <= time.time():
            return None
        return claims["key_hash"]
    except (ValueError, KeyError, TypeError, UnicodeError):
        return None
