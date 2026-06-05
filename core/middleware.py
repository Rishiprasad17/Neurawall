"""
middleware.py — Neurawall Core Middleware
Solution 2: Smart pre-screening — only suspicious traffic gets sync AI
Solution 3: Streaming inference — AI scores while response generates
Phase 3:    Adaptive learning — auto-collects training data
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

# ------------------------------------------------------------------ #
# PRE-SCREEN PATTERNS — Solution 2
# Fast 1ms check to identify suspicious requests before full AI scoring
# ------------------------------------------------------------------ #
PRESCREEN_PATTERNS = [
    # Social engineering
    re.compile(r"(admin|password|credential|secret|token|api.?key)", re.I),
    re.compile(r"(export|dump|extract|download).{0,20}(data|user|customer|record)", re.I),
    re.compile(r"(show|reveal|display|give).{0,20}(password|credential|secret)", re.I),
    re.compile(r"(bypass|circumvent|override|ignore).{0,20}(security|auth|restrict)", re.I),
    re.compile(r"(pretend|act as|behave as).{0,20}(no restriction|unrestrict|admin)", re.I),
    re.compile(r"(security audit|penetration test|pentest).{0,30}(show|access|reveal)", re.I),
    re.compile(r"(for testing|test purpose).{0,20}(disable|bypass|ignore)", re.I),
    # Unusual patterns
    re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]"),  # control characters
    re.compile(r"(.)\1{20,}"),                        # repeated chars (fuzzing)
    re.compile(r"(base64|hex|rot13|encode|decode).{0,20}(execute|eval|run)", re.I),
    re.compile(r"(curl|wget|fetch|http).{0,20}(evil|attack|malware|shell)", re.I),
]


def prescreen(body_text: str) -> tuple:
    """
    Fast 1ms pre-screen.
    Returns (is_suspicious, reason)
    """
    if len(body_text) > 2000:
        return True, "unusually large body"

    for pattern in PRESCREEN_PATTERNS:
        if pattern.search(body_text):
            return True, f"pre-screen pattern: {pattern.pattern[:40]}"

    return False, ""


# ------------------------------------------------------------------ #
# IP REPUTATION TRACKER
# ------------------------------------------------------------------ #
class IPReputationTracker:
    def __init__(self):
        self._history: dict = defaultdict(list)
        self._blocked_ips: set = set()
        self._window_seconds = 300

    def record(self, ip: str, score: float):
        now = time.time()
        self._history[ip].append((now, score))
        self._history[ip] = [
            (t, s) for t, s in self._history[ip]
            if now - t < self._window_seconds
        ]
        recent = self._history[ip]
        if len(recent) >= 3:
            avg = sum(s for _, s in recent[-3:]) / 3
            if avg >= 0.75:
                self._blocked_ips.add(ip)
                logger.warning(f"IP {ip} auto-blocked: avg score {avg:.2f}")

    def is_suspicious(self, ip: str) -> bool:
        recent = self._history.get(ip, [])
        if not recent:
            return False
        now = time.time()
        recent_5min = [(t, s) for t, s in recent if now - t < 300]
        if not recent_5min:
            return False
        avg = sum(s for _, s in recent_5min) / len(recent_5min)
        return avg >= 0.5

    def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked_ips

    def get_stats(self) -> dict:
        return {
            "tracked_ips": len(self._history),
            "blocked_ips": len(self._blocked_ips),
            "blocked_list": list(self._blocked_ips)[:10],
        }


# ------------------------------------------------------------------ #
# ADAPTIVE LEARNING COLLECTOR — Phase 3
# ------------------------------------------------------------------ #
class AdaptiveLearningCollector:
    def __init__(self, data_dir: str = "training_data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        self._buffer = []
        self._buffer_size = 50
        self._session_file = self.data_dir / f"session_{int(time.time())}.jsonl"

    def collect(self, ctx: RequestContext, label: str, confidence: str = "high"):
        if not ctx.body:
            return
        try:
            body_text = ctx.body.decode("utf-8", errors="replace")[:500]
        except Exception:
            return

        sample = {
            "timestamp":     datetime.now().isoformat(),
            "method":        ctx.method,
            "path":          ctx.path,
            "body":          body_text,
            "label":         label,
            "confidence":    confidence,
            "anomaly_score": ctx.anomaly_score,
            "block_reason":  ctx.block_reason,
            "source":        "neurawall_production",
        }
        self._buffer.append(sample)
        if len(self._buffer) >= self._buffer_size:
            self._flush()

    def _flush(self):
        if not self._buffer:
            return
        try:
            with open(self._session_file, "a", encoding="utf-8") as f:
                for sample in self._buffer:
                    f.write(json.dumps(sample) + "\n")
            self._buffer.clear()
        except Exception as e:
            logger.error(f"Failed to flush training data: {e}")

    def get_stats(self) -> dict:
        try:
            files = list(self.data_dir.glob("*.jsonl"))
            total = sum(sum(1 for _ in open(f, encoding="utf-8")) for f in files)
            return {"total_samples": total, "session_files": len(files)}
        except Exception:
            return {"total_samples": 0}


# ------------------------------------------------------------------ #
# GLOBALS
# ------------------------------------------------------------------ #
_reputation_tracker  = IPReputationTracker()
_learning_collector: Optional[AdaptiveLearningCollector] = None


# ------------------------------------------------------------------ #
# MAIN MIDDLEWARE
# ------------------------------------------------------------------ #
class NeurawallMiddleware(BaseHTTPMiddleware):

    def __init__(self, app: ASGIApp, config: Optional[NeurawallConfig] = None):
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
                logger.warning(f"AI detector failed: {e}")
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
                logger.warning(f"Security hardener failed: {e}")
                self._hardener = None
        else:
            self._hardener = None

        logger.info(
            f"Neurawall ready | security={self.config.security_enabled} | "
            f"ai={self.config.ai_enabled} | streaming=True | prescreening=True"
        )

    async def dispatch(self, request: Request, call_next):
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

        # ── Block known bad IPs ───────────────────────────────────
        if _reputation_tracker.is_blocked(ctx.client_ip):
            if _learning_collector:
                _learning_collector.collect(ctx, "attack", "high")
            return self._block_response("IP blocked — repeat offender",
                                        ctx, "ip_reputation")

        # ── Rule-based security ───────────────────────────────────
        if self._hardener:
            blocked = await self._hardener.check(request, ctx)
            if blocked:
                ctx.latency_ms = (time.perf_counter() - start) * 1000
                if _learning_collector:
                    _learning_collector.collect(ctx, "attack", "high")
                self._log_event(ctx)
                return self._block_response(ctx.block_reason, ctx, "rules")

        # ── Solution 2: Pre-screen ────────────────────────────────
        body_text = ""
        if ctx.body:
            body_text = ctx.body.decode("utf-8", errors="replace")

        is_suspicious, prescreen_reason = prescreen(body_text)
        ip_suspicious = _reputation_tracker.is_suspicious(ctx.client_ip)

        # ── Solution 3: Streaming AI for suspicious traffic ───────
        if self._ai and (is_suspicious or ip_suspicious):
            logger.info(
                f"[{ctx.request_id}] Sync AI: "
                f"prescreen={is_suspicious} ip_history={ip_suspicious}"
            )

            # Run AI and response generation simultaneously
            ai_task       = asyncio.create_task(self._ai.score(ctx))
            response_task = asyncio.create_task(self._get_response(call_next, request))

            # Wait for AI first with timeout
            try:
                score = await asyncio.wait_for(
                    asyncio.shield(ai_task), timeout=60.0
                )
            except asyncio.TimeoutError:
                score = None
                logger.warning(f"[{ctx.request_id}] AI timeout — passing through")

            if score is not None:
                ctx.anomaly_score = score
                _reputation_tracker.record(ctx.client_ip, score)

                if score >= self.config.anomaly_threshold:
                    # Cancel response — block the request
                    response_task.cancel()
                    ctx.blocked     = True
                    ctx.block_reason = f"AI detected threat (score={score:.2f})"
                    ctx.latency_ms  = (time.perf_counter() - start) * 1000

                    if _learning_collector:
                        _learning_collector.collect(ctx, "attack", "medium")

                    self._log_event(ctx)
                    return self._block_response(ctx.block_reason, ctx, "ai_sync")

            # AI cleared or timed out — return the response
            try:
                response = await response_task
            except asyncio.CancelledError:
                response = Response(status_code=500)

        else:
            # ── Normal traffic: async AI ──────────────────────────
            response = await call_next(request)
            if self._ai:
                asyncio.create_task(self._async_score(ctx))

        ctx.latency_ms = (time.perf_counter() - start) * 1000

        # Collect 5% of clean traffic for adaptive learning
        if _learning_collector and not ctx.blocked:
            import random
            if random.random() < 0.05:
                _learning_collector.collect(ctx, "clean", "high")

        self._log_event(ctx)
        return response

    async def _get_response(self, call_next, request):
        """Wrapper to get response — used in streaming mode."""
        return await call_next(request)

    async def _async_score(self, ctx: RequestContext):
        """Async AI scoring — zero latency impact."""
        try:
            score = await self._ai.score(ctx)
            if score is not None:
                ctx.anomaly_score = score
                _reputation_tracker.record(ctx.client_ip, score)
                if score >= self.config.anomaly_threshold:
                    logger.warning(
                        f"[{ctx.request_id}] AI flagged async: "
                        f"score={score:.2f} ip={ctx.client_ip}"
                    )
                    if _learning_collector:
                        _learning_collector.collect(ctx, "attack", "medium")
        except Exception as e:
            logger.debug(f"Async AI error: {e}")

    def _block_response(self, reason: str, ctx: RequestContext,
                        block_type: str) -> Response:
        return Response(
            content=json.dumps({
                "error":      "Request blocked by Neurawall",
                "reason":     reason,
                "request_id": ctx.request_id,
            }),
            status_code=403,
            media_type="application/json",
            headers={"X-Neurawall-Block": block_type},
        )

    def _log_event(self, ctx: RequestContext):
        logger.info(json.dumps({
            "request_id":    ctx.request_id,
            "method":        ctx.method,
            "path":          ctx.path,
            "client_ip":     ctx.client_ip,
            "latency_ms":    round(getattr(ctx, "latency_ms", 0), 2),
            "blocked":       ctx.blocked,
            "block_reason":  ctx.block_reason,
            "anomaly_score": round(ctx.anomaly_score, 3),
            "timestamp":     datetime.now().isoformat(),
        }))


# Backwards compatible alias
GuardrailMiddleware = NeurawallMiddleware

