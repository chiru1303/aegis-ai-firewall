"""Bound request bodies before parsing; rate limits apply even without the proxy."""
import hashlib
import time
from collections import OrderedDict
from starlette.responses import JSONResponse
from app.core.config import settings
from app.core.browser_session import COOKIE_NAME


class IngressMiddleware:
    def __init__(self, app):
        self.app = app
        self.counters = OrderedDict()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        cookie_auth = f"{COOKIE_NAME}=" in headers.get("cookie", "")
        if cookie_auth and scope["method"] not in ("GET", "HEAD", "OPTIONS"):
            if headers.get("origin") not in settings.CORS_ORIGINS:
                return await JSONResponse({"detail": "Untrusted browser origin"}, 403)(scope, receive, send)
        if settings.ENABLE_RATE_LIMITING and scope["path"] not in ("/", "/ready", "/api/v1/health", "/admin/health"):
            ip = (scope.get("client") or ("unknown",))[0]
            credential = headers.get("x-api-key") or headers.get("authorization") or headers.get("cookie", "")
            identities = [f"ip:{ip}"]
            if credential:
                identities.append(hashlib.sha256(credential.encode()).hexdigest())
            try:
                from app.core.redis_client import redis_client
                for identity in identities:
                    key = f"aegis:limit:{identity}"
                    if redis_client.client and not redis_client._use_in_memory:
                        count = await redis_client.client.eval(
                            "local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],ARGV[1]) end; return n",
                            1, key, settings.RATE_LIMIT_WINDOW)
                    elif settings.ENVIRONMENT == "production":
                        raise RuntimeError("Rate limit store unavailable")
                    else:
                        now = time.monotonic()
                        count, expires = self.counters.get(key, (0, now + settings.RATE_LIMIT_WINDOW))
                        if expires <= now:
                            count, expires = 0, now + settings.RATE_LIMIT_WINDOW
                        count += 1
                        self.counters[key] = (count, expires)
                        self.counters.move_to_end(key)
                        while len(self.counters) > 10000:
                            self.counters.popitem(last=False)
                    if count > settings.RATE_LIMIT_REQUESTS:
                        return await JSONResponse({"detail": "Request limit exceeded"}, 429,
                            headers={"Retry-After": str(settings.RATE_LIMIT_WINDOW)})(scope, receive, send)
            except Exception:
                return await JSONResponse({"detail": "Security rate limiter unavailable"}, 503)(scope, receive, send)
        limit = settings.MAX_FILE_SIZE + 1024 * 1024 if "multipart/form-data" in headers.get("content-type", "") else settings.MAX_CONTENT_LENGTH
        body = bytearray()
        while True:
            event = await receive()
            if event["type"] == "http.disconnect":
                return
            body.extend(event.get("body", b""))
            if len(body) > limit:
                return await JSONResponse({"detail": "Request body too large"}, 413)(scope, receive, send)
            if not event.get("more_body", False):
                break
        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)
