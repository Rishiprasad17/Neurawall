import asyncio
import json
import logging
import time
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from .config import neurawallConfig
from .models import RequestContext

logger = logging.getLogger("neurawall")

ALWAYS_SKIP = {"/dashboard", "/dashboard/events", "/favicon.ico", "/docs", "/redoc", "/openapi.json"}


class neurawallMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, config: neurawallConfig = None):
        super().__init__(app)
        self.config = config or neurawallConfig()
        self._setup_phases()

    def _setup_phases(self):
        if self.config.ai_enabled:
            from ..ai.detector import AnomalyDetector
            self.ai_detector = AnomalyDetector(self.config)
        else:
            self.ai_detector = None

        if self.config.security_enabled:
            from ..security.hardening import SecurityHardener
            self.security = SecurityHardener(self.config)
        else:
            self.security = None

        if self.config.cache_enabled:
            from ..performance.cache import SmartCache
            self.cache = SmartCache(self.config)
        else:
            self.cache = None

        if self.config.quantum_enabled:
            from ..quantum.layer import QuantumLayer
            self.quantum = QuantumLayer(self.config)
        else:
            self.quantum = None

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path

        # Skip dashboard + static paths entirely
        if path in ALWAYS_SKIP or path in self.config.excluded_paths:
            return await call_next(request)

        ctx = await self._build_context(request)
        start = time.perf_counter()

        # --- Phase 3: Rule-based security (instant, 0ms) ---
        if self.security:
            block = await self.security.check(request, ctx)
            if block:
                ctx.latency_ms = (time.perf_counter() - start) * 1000
                self._log(ctx)
                return self._blocked_response(ctx)

        # --- Phase 5: Quantum ---
        if self.quantum:
            await self.quantum.pre_request(ctx)

        # --- Phase 4: Cache ---
        if self.cache and request.method == "GET":
            cached = await self.cache.get(ctx)
            if cached:
                ctx.cache_hit = True
                ctx.latency_ms = (time.perf_counter() - start) * 1000
                self._log(ctx)
                return cached

        # --- Forward request IMMEDIATELY — don't wait for AI ---
        response = await call_next(request)

        ctx.latency_ms = (time.perf_counter() - start) * 1000

        # --- Phase 2: AI scoring runs in background (non-blocking) ---
        if self.ai_detector and request.method in ("POST", "PUT", "PATCH"):
            asyncio.create_task(
                self._score_and_log(ctx)
            )
        else:
            self._log(ctx)

        # --- Phase 3: Response signing ---
        if self.security:
            response = await self.security.sign_response(response, ctx)

        return response

    async def _score_and_log(self, ctx: RequestContext):
        """
        Runs AI scoring AFTER the response is sent.
        Fast requests are never delayed by Mistral.
        High scores are flagged in logs for review.
        """
        try:
            score = await self.ai_detector.score(ctx)
            ctx.anomaly_score = score

            if score >= self.config.anomaly_threshold:
                ctx.block_reason = f"AI flagged post-hoc: score {score:.2f} — review request {ctx.request_id}"
                logger.warning(
                    f"[THREAT DETECTED] {ctx.method} {ctx.path} "
                    f"score={score:.2f} ip={ctx.client_ip} id={ctx.request_id}"
                )
        except Exception as e:
            logger.debug(f"Background AI scoring error: {e}")
        finally:
            self._log(ctx)

    async def _build_context(self, request: Request) -> RequestContext:
        body = None
        if request.method in ("POST", "PUT", "PATCH"):
            body = await request.body()
        return RequestContext(
            method=request.method,
            path=request.url.path,
            headers=dict(request.headers),
            body=body,
            client_ip=request.client.host if request.client else "unknown",
        )

    def _blocked_response(self, ctx: RequestContext) -> JSONResponse:
        return JSONResponse(
            status_code=403,
            content={
                "error": "Request blocked by neurawall",
                "reason": ctx.block_reason,
                "request_id": ctx.request_id,
            },
        )

    def _log(self, ctx: RequestContext):
        if self.config.log_requests:
            level = logging.WARNING if ctx.blocked else logging.INFO
            logger.log(level, json.dumps(ctx.to_log()))
