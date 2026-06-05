"""
middleware.py - Neurawall Core Middleware
Solution 2: Smart pre-screening
Solution 3: Streaming inference
Phase 3: Adaptive learning
"""
import asyncio
import json
import logging
import re
import time
import uuid
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from .config import NeurawallConfig
from .models import RequestContext

logger = logging.getLogger("guardrail.middleware")

PRESCREEN_PATTERNS = [
    re.compile(r"(admin|password|credential|secret|token|api.{0,1}key)", re.IGNORECASE),
    re.compile(r"(export|dump|extract|download).{0,20}(data|user|customer|record)", re.IGNORECASE),
    re.compile(r"(show|reveal|display|give|send).{0,20}(password|credential|secret|key)", re.IGNORECASE),
    re.compile(r"(bypass|circumvent|override|ignore).{0,20}(security|auth|restrict|filter)", re.IGNORECASE),
    re.compile(r"(pretend|act as|behave as).{0,20}(no restriction|unrestrict|admin)", re.IGNORECASE),
    re.compile(r"(security audit|penetration test|pentest).{0,30}(show|access|reveal)", re.IGNORECASE),
    re.compile(r"(for testing|test purpose).{0,20}(disable|bypass|ignore|show)", re.IGNORECASE),
    re.compile(r"(all user|all customer|all record|entire database)", re.IGNORECASE),
    re.compile(r"(send to|email to|forward to).{0,30}@", re.IGNORECASE),
    re.compile(r"(http|https|ftp)://(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254)", re.IGNORECASE),
    re.compile(r"(http|https)://10\.\d+\.\d+\.\d+", re.IGNORECASE),
    re.compile(r"(http|https)://192\.168\.\d+\.\d+", re.IGNORECASE),
    re.compile(r"file:///", re.IGNORECASE),
    re.compile(r"gopher://", re.IGNORECASE),
    re.compile(r"\{\{.{1,50}\}\}", re.IGNORECASE),
    re.compile(r"\$\{.{1,50}\}", re.IGNORECASE),
    re.compile(r"#\{.{1,50}\}", re.IGNORECASE),
    re.compile(r"<!ENTITY", re.IGNORECASE),
    re.compile(r"quantity\s*=\s*-\d+", re.IGNORECASE),
    re.compile(r"price\s*=\s*-\d+", re.IGNORECASE),
    re.compile(r"amount\s*=\s*-\d+", re.IGNORECASE),
    re.compile(r"(.)\1{20,}"),
    re.compile(r"(login as|sign in as|access as).{0,20}(admin|root|other user)", re.IGNORECASE),
    re.compile(r"(impersonate|masquerade).{0,20}(user|admin|account)", re.IGNORECASE),
]


def prescreen(body_text):
    if len(body_text) > 2000:
        return True, "unusually large body"
    for pattern in PRESCREEN_PATTERNS:
        if pattern.search(body_text):
            return True, f"pre-screen: {pattern.pattern[:40]}"
    return False, ""


class IPReputationTracker:
    def __init__(self):
        self._history = defaultdict(list)
        self._blocked_ips = set()
        self._window_seconds = 300

    def record(self, ip, score):
        now = time.time()
        self._history[ip].append((now, score))
        self._history[ip] = [(t, s) for t, s in self._history[ip] if now - t < self._window_seconds]
        recent = self._history[ip]
        if len(recent) >= 3:
            avg = sum(s for _, s in recent[-3:]) / 3
            if avg >= 0.75:
                self._blocked_ips.add(ip)
                logger.warning(f"IP {ip} auto-blocked: avg={avg:.2f}")

    def is_suspicious(self, ip):
        recent = [(t, s) for t, s in self._history.get(ip, []) if time.time() - t < 300]
        if not recent:
            return False
        return sum(s for _, s in recent) / len(recent) >= 0.5

    def is_blocked(self, ip):
        return ip in self._blocked_ips

    def get_stats(self):
        return {"tracked_ips": len(self._history), "blocked_ips": len(self._blocked_ips)}


class AdaptiveLearningCollector:
    def __init__(self, data_dir="training_data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        self._buffer = []
        self._session_file = self.data_dir / f"session_{int(time.time())}.jsonl"

    def collect(self, ctx, label, confidence="high"):
        if not ctx.body:
            return
        try:
            body_text = ctx.body.decode("utf-8", errors="replace")[:500]
        except Exception:
            return
        sample = {
            "timestamp": datetime.now().isoformat(),
            "method": ctx.method,
            "path": ctx.path,
            "body": body_text,
            "label": label,
            "confidence": confidence,
            "anomaly_score": ctx.anomaly_score,
            "block_reason": ctx.block_reason,
            "source": "neurawall_production",
        }
        self._buffer.append(sample)
        if len(self._buffer) >= 50:
            self._flush()

    def _flush(self):
        if not self._buffer:
            return
        try:
            with open(self._session_file, "a", encoding="utf-8") as f:
                for s in self._buffer:
                    f.write(json.dumps(s) + "\n")
            self._buffer.clear()
        except Exception as e:
            logger.error(f"Flush error: {e}")


_reputation_tracker = IPReputationTracker()
_learning_collector = None


class NeurawallMiddleware(BaseHTTPMiddleware):

    def __init__(self, app, config=None):
        super().__init__(app)
        self.config = config or NeurawallConfig()
        self._setup()

    def _setup(self):
        global _learning_collector

        if self.config.ai_enabled:
            try:
                from ..ai.detector import AIDetector
                self._ai = AIDetector(self.config)
            except Exception as e:
                logger.warning(f"AI init failed: {e}")
                self._ai = None
        else:
            self._ai = None

        if getattr(self.config, "adaptive_learning", True):
            _learning_collector = AdaptiveLearningCollector(
                getattr(self.config, "training_data_dir", "training_data")
            )

        if self.config.security_enabled:
            try:
                from ..security.hardening import SecurityHardener
                self._hardener = SecurityHardener(self.config)
            except Exception as e:
                logger.warning(f"Hardener init failed: {e}")
                self._hardener = None
        else:
            self._hardener = None

        logger.info(
            f"Neurawall ready | security={self.config.security_enabled} | "
            f"ai={self.config.ai_enabled} | streaming=True | prescreening=True"
        )

    async def dispatch(self, request, call_next):
        start = time.perf_counter()

        ctx = RequestContext(
            request_id=str(uuid.uuid4()),
            method=request.method,
            path=str(request.url.path),
            headers=dict(request.headers),
            client_ip=request.client.host if request.client else "unknown",
            timestamp=time.time(),
        )

        try:
            ctx.body = await request.body()
        except Exception:
            ctx.body = b""

        # Block known bad IPs
        if _reputation_tracker.is_blocked(ctx.client_ip):
            if _learning_collector:
                _learning_collector.collect(ctx, "attack", "high")
            return self._block_response("IP blocked — repeat offender", ctx, "ip_reputation")

        # Rule-based security
        if self._hardener:
            blocked = await self._hardener.check(request, ctx)
            if blocked:
                ctx.latency_ms = (time.perf_counter() - start) * 1000
                if _learning_collector:
                    _learning_collector.collect(ctx, "attack", "high")
                self._log_event(ctx)
                return self._block_response(ctx.block_reason, ctx, "rules")

        # Pre-screen check
        body_text = ""
        if ctx.body:
            body_text = ctx.body.decode("utf-8", errors="replace")

        is_suspicious, prescreen_reason = prescreen(body_text)
        ip_suspicious = _reputation_tracker.is_suspicious(ctx.client_ip)

        # Streaming AI for suspicious traffic
        if self._ai and (is_suspicious or ip_suspicious):
            logger.info(f"[{ctx.request_id}] Sync AI: prescreen={is_suspicious} ip_history={ip_suspicious}")

            ai_task = asyncio.create_task(self._ai.score(ctx))
            response_task = asyncio.create_task(self._get_response(call_next, request))

            try:
                score = await asyncio.wait_for(asyncio.shield(ai_task), timeout=60.0)
            except asyncio.TimeoutError:
                score = None
                logger.warning(f"[{ctx.request_id}] AI timeout — passing through")

            if score is not None:
                ctx.anomaly_score = score
                _reputation_tracker.record(ctx.client_ip, score)

                if score >= self.config.anomaly_threshold:
                    response_task.cancel()
                    ctx.blocked = True
                    ctx.block_reason = f"AI detected threat (score={score:.2f})"
                    ctx.latency_ms = (time.perf_counter() - start) * 1000
                    if _learning_collector:
                        _learning_collector.collect(ctx, "attack", "medium")
                    self._log_event(ctx)
                    return self._block_response(ctx.block_reason, ctx, "ai_sync")

            try:
                response = await response_task
            except asyncio.CancelledError:
                response = Response(status_code=500)

        else:
            response = await call_next(request)
            if self._ai:
                asyncio.create_task(self._async_score(ctx))

        ctx.latency_ms = (time.perf_counter() - start) * 1000

        import random
        if _learning_collector and not ctx.blocked and random.random() < 0.05:
            _learning_collector.collect(ctx, "clean", "high")

        self._log_event(ctx)
        return response

    async def _get_response(self, call_next, request):
        return await call_next(request)

    async def _async_score(self, ctx):
        try:
            score = await self._ai.score(ctx)
            if score is not None:
                ctx.anomaly_score = score
                _reputation_tracker.record(ctx.client_ip, score)
                if score >= self.config.anomaly_threshold:
                    logger.warning(f"[{ctx.request_id}] AI flagged async: score={score:.2f}")
                    if _learning_collector:
                        _learning_collector.collect(ctx, "attack", "medium")
        except Exception as e:
            logger.debug(f"Async AI error: {e}")

    def _block_response(self, reason, ctx, block_type):
        return Response(
            content=json.dumps({
                "error": "Request blocked by Neurawall",
                "reason": reason,
                "request_id": ctx.request_id,
            }),
            status_code=403,
            media_type="application/json",
            headers={"X-Neurawall-Block": block_type},
        )

    def _log_event(self, ctx):
        logger.info(json.dumps({
            "request_id": ctx.request_id,
            "method": ctx.method,
            "path": ctx.path,
            "client_ip": ctx.client_ip,
            "latency_ms": round(getattr(ctx, "latency_ms", 0), 2),
            "blocked": ctx.blocked,
            "block_reason": ctx.block_reason,
            "anomaly_score": round(ctx.anomaly_score, 3),
            "timestamp": datetime.now().isoformat(),
        }))


GuardrailMiddleware = NeurawallMiddleware
