"""
Redis client wrapper with in-memory TTL dictionary fallback.
Allows running seamlessly in local environments without Redis installed/running,
while connecting to real Redis in production/Docker.
"""
import json
import time
from typing import Optional, Any, Dict
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

_HAS_REDIS = False
try:
    import redis.asyncio as redis
    _HAS_REDIS = True
except ImportError:
    _HAS_REDIS = False


class InMemoryCache:
    """In-memory key-value store with expiration for standalone/offline execution."""
    def __init__(self):
        self._data: Dict[str, Any] = {}
        self._expires: Dict[str, float] = {}

    def _purge_expired(self, key: str):
        if key in self._expires and time.time() > self._expires[key]:
            self._data.pop(key, None)
            self._expires.pop(key, None)

    async def get(self, key: str) -> Optional[str]:
        self._purge_expired(key)
        val = self._data.get(key)
        return str(val) if val is not None else None

    async def set(self, key: str, value: str, ex: Optional[int] = None):
        for old in list(self._expires):
            self._purge_expired(old)
        while len(self._data) >= 10000 and key not in self._data:
            oldest = next(iter(self._data))
            self._data.pop(oldest, None)
            self._expires.pop(oldest, None)
        self._data[key] = value
        if ex:
            self._expires[key] = time.time() + ex

    async def delete(self, key: str):
        self._data.pop(key, None)
        self._expires.pop(key, None)

    async def incr(self, key: str) -> int:
        self._purge_expired(key)
        current = int(self._data.get(key, 0)) + 1
        self._data[key] = current
        return current

    async def expire(self, key: str, seconds: int):
        self._expires[key] = time.time() + seconds

    async def ping(self):
        return True


class RedisClient:
    def __init__(self):
        self.pool = None
        self.client = None
        self._use_in_memory = not _HAS_REDIS

    async def connect(self):
        if _HAS_REDIS:
            try:
                self.pool = redis.ConnectionPool.from_url(
                    settings.REDIS_URL,
                    decode_responses=True
                )
                self.client = redis.Redis(connection_pool=self.pool)
                await self.client.ping()
                self._use_in_memory = False
                logger.info("Connected to Redis")
                return
            except Exception as e:
                if settings.ENVIRONMENT == "production":
                    raise RuntimeError("Shared Redis storage unavailable") from e
                logger.warning(f"Could not connect to Redis: {e}. Using in-memory cache.")

        self._use_in_memory = True
        self.client = InMemoryCache()
        logger.info("Operating with in-memory cache fallback.")

    async def disconnect(self):
        if self.pool and not self._use_in_memory:
            await self.pool.disconnect()

    async def get(self, key: str) -> Optional[str]:
        if not self.client:
            if settings.ENVIRONMENT == "production":
                raise RuntimeError("Shared Redis storage unavailable")
            self.client = InMemoryCache()
            self._use_in_memory = True
        return await self.client.get(key)

    async def set(self, key: str, value: str, expire: Optional[int] = None):
        if not self.client:
            if settings.ENVIRONMENT == "production":
                raise RuntimeError("Shared Redis storage unavailable")
            self.client = InMemoryCache()
            self._use_in_memory = True
        await self.client.set(key, value, ex=expire)

    async def delete(self, key: str):
        if self.client:
            await self.client.delete(key)

    async def incr(self, key: str) -> int:
        if not self.client:
            if settings.ENVIRONMENT == "production":
                raise RuntimeError("Shared Redis storage unavailable")
            self.client = InMemoryCache()
            self._use_in_memory = True
        return await self.client.incr(key)

    async def expire(self, key: str, seconds: int):
        if self.client:
            await self.client.expire(key, seconds)

    async def get_json(self, key: str) -> Any:
        val = await self.get(key)
        if val:
            try:
                return json.loads(val)
            except Exception:
                if settings.ENVIRONMENT == "production":
                    raise RuntimeError("Security state is corrupt")
                return None
        return None

    async def set_json(self, key: str, value: Any, expire: Optional[int] = None):
        await self.set(key, json.dumps(value), expire)


redis_client = RedisClient()


async def get_redis() -> RedisClient:
    return redis_client
