import hashlib
import json
import logging
from typing import Optional

from starlette.responses import JSONResponse, Response

from ..core.config import neurawallConfig
from ..core.models import RequestContext

logger = logging.getLogger("neurawall.cache")


class SmartCache:
    """
    Redis-backed GET cache.
    AI hook: in future, the AI detector's anomaly score can
    inform TTL — suspicious IPs get shorter cache windows.
    """

    def __init__(self, config: neurawallConfig):
        self.config = config
        self._client = None
        self._connect()

    def _connect(self):
        try:
            import redis.asyncio as aioredis
            self._client = aioredis.from_url(
                self.config.redis_url or "redis://localhost:6379",
                encoding="utf-8",
                decode_responses=True,
            )
            logger.info("neurawall cache connected to Redis")
        except ImportError:
            logger.warning("redis package not installed — cache disabled. Run: pip install redis")
        except Exception as e:
            logger.warning(f"Redis connection failed: {e} — cache disabled")

    def _cache_key(self, ctx: RequestContext) -> str:
        raw = f"{ctx.method}:{ctx.path}:{json.dumps(dict(sorted(ctx.headers.items())))}"
        return "neurawall:" + hashlib.sha256(raw.encode()).hexdigest()[:24]

    async def get(self, ctx: RequestContext) -> Optional[Response]:
        if not self._client:
            return None
        try:
            key = self._cache_key(ctx)
            data = await self._client.get(key)
            if data:
                payload = json.loads(data)
                logger.debug(f"[{ctx.request_id}] Cache HIT {key}")
                return JSONResponse(content=payload["body"], headers=payload["headers"])
        except Exception as e:
            logger.debug(f"Cache get error: {e}")
        return None

    async def set(self, ctx: RequestContext, response: Response, ttl: int = 60):
        if not self._client:
            return
        try:
            key = self._cache_key(ctx)
            # TTL shortened for suspicious requests
            effective_ttl = max(5, int(ttl * (1 - ctx.anomaly_score)))
            body = b""
            async for chunk in response.body_iterator:
                body += chunk
            payload = json.dumps({
                "body": json.loads(body),
                "headers": dict(response.headers),
            })
            await self._client.setex(key, effective_ttl, payload)
            logger.debug(f"[{ctx.request_id}] Cache SET {key} TTL={effective_ttl}s")
        except Exception as e:
            logger.debug(f"Cache set error: {e}")
