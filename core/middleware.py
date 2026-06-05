"""
middleware.py — Neurawall Core Middleware
Phase 1: Real-time AI blocking for flagged IPs
Phase 2: Async scoring for normal traffic
Phase 3: Adaptive learning — auto-collect training data
"""
import asyncio
import json
import logging
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
# IP REPUTATION TRACKER — Phase 1
# Tracks anomaly history per IP for real-time blocking decisions
# ------------------------------------------------------------------ #
class IPReputationTracker:
    def __init__(self):
        # ip -> list of (timestamp, score) tuples
        self._history: dict = defaultdict(list)
        self._blocked_ips: set = set()
        self._window_seconds = 300  # 5 minute window

    def record(self, ip: str, score: float):
        now = time.time()
        self._history[ip].append((now, score))
        # Clean old entries
        self._history[ip] = [
            (t, s) for t, s in self._history[ip]
            if now - t < self._window_seconds
        ]
        # Auto-block IPs with consistently high scores
        recent = self._history[ip]
        if len(recent) >= 3:
            avg = sum(s for _, s in recent[-3:]) / 3
            if avg >= 0.75:
                self._blocked_ips.add(ip)
                logger.warning(f"IP {ip} auto-blocked: avg score {avg:.2f}")

    def is_suspicious(self, ip: str) -> bool:
        """IP has history of suspicious requests — use sync AI."""
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

    def unblock(self, ip: str):
        self._blocked_ips.discard(ip)
        self._history.pop(ip, None)

    def get_stats(self) -> dict:
        return {
            "tracked_ips": len(self._history),
            "blocked_ips": len(self._blocked_ips),
            "blocked_list": list(self._blocked_ips)[:10],
        }


# ------------------------------------------------------------------ #
# ADAPTIVE LEARNING COLLECTOR — Phase 3
# Auto-collects training data from blocked/flagged requests
# ------------------------------------------------------------------ #
class AdaptiveLearningCollector:
    def __init__(self, data_dir: str = "training_data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        self._buffer = []
        self._buffer_size = 50  # flush every 50 samples
        self._session_file = self.data_dir / f"session_{int(time.time())}.jsonl"
        logger.info(f"Adaptive learning: saving to {self._session_file}")

    def collect(self, ctx: RequestContext, label: str, confidence: str = "high"):
        """
        Collect a labelled training sample.
        label: 'attack' or 'clean'
        confidence: 'high' (rule-blocked), 'medium' (AI-flagged), 'low' (uncertain)
        """
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
            "ai_attack_type": getattr(ctx, "ai_attack_type", None),
            "source": "neurawall_production",
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
            logger.info(f"Adaptive learning: flushed {len(self._buffer)} samples")
            self._buffer.clear()
        except Exception as e:
            logger.error(f"Failed to flush training data: {e}")

    def flush_all(self):
        self._flush()

    def get_stats(self) -> dict:
        try:
            files = list(self.data_dir.glob("*.jsonl"))
            total = sum(
                sum(1 for _ in open(f, encoding="utf-8"))
                for f in files
            )
            attacks = 0
            clean = 0
            for f in files:
                for line in open(f, encoding="utf-8"):
                    try:
                        d = json.loads(line)
                        if d.get("label") == "attack":
                            attacks += 1
                        else:
                            clean += 1
                    except Exception:
                        pass
            return {
                "total_samples": total,
                "attack_samples": attacks,
                "clean_samples": clean,
                "session_files": len(files),
                "buffer_size": len(self._buffer),
            }
        except Exception:
            return {"total_samples": 0}


# ------------------------------------------------------------------ #
# GLOBAL INSTANCES
# ------------------------------------------------------------------ #
_reputation_tracker = IPReputationTracker()
_learning_collector: Optional[AdaptiveLearningCollector] = None


def get_reputation_tracker() -> IPReputationTracker:
    return _reputation_tracker


def get_learning_collector() -> Optional[AdaptiveLearningCollector]:
    return _learning_collector


# ------------------------------------------------------------------ #
# MAIN MIDDLEWARE
# ------------------------------------------------------------------ #
class NeurawallMiddleware(BaseHTTPMiddleware):
    # Backwards compatible alias
    GuardrailMiddleware = None

    def __init__(self, app: ASGIApp, config: Optional[NeurawallConfig] = None):
        super().__init__(app)
        self.config = config or NeurawallConfig()
        self._setup()

    def _setup(self):
        global _learning_collector

        # Phase 2 — AI detector
        if self.config.ai_enabled:
            try:
                from ..ai.detector import AIDetector
                self._ai = AIDetector(self.config)
            except Exception as e:
                logger.warning(f"AI detector failed to init: {e}")
                self._ai = None
        else:
            self._ai = None

        # Phase 3 — Adaptive learning
        if getattr(self.config, "adaptive_learning", True):
            _learning_collector = AdaptiveLearningCollector(
                getattr(self.config, "training_data_dir", "training_data")
            )

        # Phase 3 — Security hardener
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
            f"Neurawall ready | "
            f"security={self.config.security_enabled} | "
            f"ai={self.config.ai_enabled} | "
            f"adaptive_learning=True"
        )

    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter()

        # Build context
        ctx = RequestContext(
            request_id=str(uuid.uuid4()),
            method=request.method,
            path=str(request.url.path),
            headers=dict(request.headers),
            client_ip=request.client.host if request.client else "unknown",
            timestamp=time.time(),
        )

        # Read body
        try:
            ctx.body = await request.body()
        except Exception:
            ctx.body = b""

        # ── Phase 1: Check IP reputation ─────────────────────────
        tracker = _reputation_tracker
        if tracker.is_blocked(ctx.client_ip):
            logger.warning(f"[{ctx.request_id}] Blocked IP: {ctx.client_ip}")
            if _learning_collector:
                _learning_collector.collect(ctx, "attack", "high")
            return Response(
                content='{"error":"IP blocked","reason":"Repeat offender"}',
                status_code=403,
                media_type="application/json",
                headers={"X-Neurawall-Block": "ip_reputation"},
            )

        # ── Phase 2: Rule-based security ─────────────────────────
        if self._hardener:
            blocked = await self._hardener.check(request, ctx)
            if blocked:
                latency = (time.perf_counter() - start) * 1000
                ctx.latency_ms = latency

                # Collect for adaptive learning
                if _learning_collector:
                    _learning_collector.collect(ctx, "attack", "high")

                # Log structured event
                self._log_event(ctx)

                return Response(
                    content=json.dumps({
                        "error": "Request blocked by Neurawall",
                        "reason": ctx.block_reason,
                        "request_id": ctx.request_id,
                    }),
                    status_code=403,
                    media_type="application/json",
                    headers={"X-Neurawall-Block": "rules"},
                )

        # ── Phase 1: Synchronous AI for suspicious IPs ───────────
        if self._ai and tracker.is_suspicious(ctx.client_ip):
            try:
                score = await asyncio.wait_for(
                    self._ai.score(ctx), timeout=20.0
                )
                if score is not None:
                    ctx.anomaly_score = score
                    tracker.record(ctx.client_ip, score)

                    if score >= self.config.anomaly_threshold:
                        ctx.blocked = True
                        ctx.block_reason = f"AI detected threat (score={score:.2f})"

                        if _learning_collector:
                            _learning_collector.collect(ctx, "attack", "medium")

                        self._log_event(ctx)
                        return Response(
                            content=json.dumps({
                                "error": "Request blocked by Neurawall AI",
                                "reason": ctx.block_reason,
                                "request_id": ctx.request_id,
                                "anomaly_score": score,
                            }),
                            status_code=403,
                            media_type="application/json",
                            headers={"X-Neurawall-Block": "ai_sync"},
                        )
            except asyncio.TimeoutError:
                logger.warning(f"Sync AI timeout for {ctx.client_ip}")

        # ── Forward request ───────────────────────────────────────
        response = await call_next(request)
        latency = (time.perf_counter() - start) * 1000
        ctx.latency_ms = latency

        # ── Phase 2: Async AI scoring (all traffic) ───────────────
        if self._ai:
            asyncio.create_task(self._async_score(ctx))

        # Collect clean traffic samples for training (1 in 20)
        if _learning_collector and not ctx.blocked:
            import random
            if random.random() < 0.05:  # 5% of clean traffic
                _learning_collector.collect(ctx, "clean", "high")

        self._log_event(ctx)
        return response

    async def _async_score(self, ctx: RequestContext):
        """Async AI scoring — runs after response, zero latency impact."""
        try:
            score = await self._ai.score(ctx)
            if score is not None:
                ctx.anomaly_score = score
                _reputation_tracker.record(ctx.client_ip, score)

                if score >= self.config.anomaly_threshold:
                    logger.warning(
                        f"[{ctx.request_id}] AI flagged (async): "
                        f"score={score:.2f} ip={ctx.client_ip}"
                    )
                    # Collect for adaptive learning
                    if _learning_collector:
                        _learning_collector.collect(ctx, "attack", "medium")
        except Exception as e:
            logger.debug(f"Async AI scoring error: {e}")

    def _log_event(self, ctx: RequestContext):
        log_data = {
            "request_id":   ctx.request_id,
            "method":       ctx.method,
            "path":         ctx.path,
            "client_ip":    ctx.client_ip,
            "latency_ms":   round(getattr(ctx, "latency_ms", 0), 2),
            "blocked":      ctx.blocked,
            "block_reason": ctx.block_reason,
            "anomaly_score": round(ctx.anomaly_score, 3),
            "timestamp":    datetime.now().isoformat(),
        }
        logger.info(json.dumps(log_data))


# Backwards compatible alias
GuardrailMiddleware = NeurawallMiddleware
