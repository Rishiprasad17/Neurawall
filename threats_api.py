"""
threats_api.py — Neurawall Threat Report API
Adds /threats endpoint to any FastAPI app using Neurawall.

Usage:
    from neurawall.threats import add_threats_api
    add_threats_api(app)

Then access:
    GET /threats           — last hour summary
    GET /threats?hours=24  — last 24 hours
    GET /threats/live      — last 10 blocked requests
"""

import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse

# Global threat store — keeps last 1000 events in memory
_threat_events = deque(maxlen=1000)
_stats = {
    "total_requests":  0,
    "total_blocked":   0,
    "ai_blocks":       0,
    "rule_blocks":     0,
    "ip_blocks":       0,
    "start_time":      time.time(),
}


def record_threat(event: dict):
    """Called by middleware for every blocked request."""
    event["timestamp"] = time.time()
    _threat_events.appendleft(event)
    _stats["total_blocked"] += 1
    block_type = event.get("block_type", "rules")
    if block_type == "ai_sync":
        _stats["ai_blocks"] += 1
    elif block_type == "ip_reputation":
        _stats["ip_blocks"] += 1
    else:
        _stats["rule_blocks"] += 1


def record_request():
    """Called by middleware for every request."""
    _stats["total_requests"] += 1


def add_threats_api(app: FastAPI):
    """Add /threats endpoints to your FastAPI app."""

    @app.get("/threats")
    async def threats_summary(hours: int = Query(default=1, ge=1, le=168)):
        """
        Get threat summary for the last N hours.
        Default: last 1 hour. Max: 168 hours (1 week).
        """
        cutoff = time.time() - (hours * 3600)
        recent = [e for e in _threat_events if e.get("timestamp", 0) > cutoff]

        # Count by category
        by_category = defaultdict(int)
        by_ip        = defaultdict(int)
        by_type      = defaultdict(int)
        scores       = []

        for event in recent:
            cat = event.get("block_reason", "Unknown")
            # Clean up reason to category
            if "SQL" in cat:          cat = "SQL Injection"
            elif "XSS" in cat:        cat = "XSS"
            elif "Command" in cat:    cat = "Command Injection"
            elif "Path" in cat:       cat = "Path Traversal"
            elif "Prompt" in cat:     cat = "Prompt Injection"
            elif "AI detected" in cat: cat = "Semantic Attack"
            elif "Rate" in cat:       cat = "Rate Limit"
            elif "IP" in cat:         cat = "Repeat Offender"

            by_category[cat] += 1
            by_ip[event.get("client_ip", "unknown")] += 1
            by_type[event.get("block_type", "rules")] += 1

            score = event.get("anomaly_score", 0)
            if score > 0:
                scores.append(score)

        # Top attacking IPs
        top_ips = sorted(by_ip.items(), key=lambda x: x[1], reverse=True)[:10]

        # Uptime
        uptime_seconds = int(time.time() - _stats["start_time"])
        uptime = str(timedelta(seconds=uptime_seconds))

        return JSONResponse({
            "period_hours":    hours,
            "generated_at":    datetime.now().isoformat(),
            "uptime":          uptime,
            "summary": {
                "total_requests":  _stats["total_requests"],
                "total_blocked":   len(recent),
                "rule_blocks":     by_type.get("rules", 0),
                "ai_blocks":       by_type.get("ai_sync", 0),
                "ip_blocks":       by_type.get("ip_reputation", 0),
                "block_rate_pct":  round(
                    len(recent) / max(_stats["total_requests"], 1) * 100, 2
                ),
                "avg_ai_score":    round(
                    sum(scores) / len(scores), 3
                ) if scores else 0,
            },
            "by_attack_type":  dict(sorted(
                by_category.items(), key=lambda x: x[1], reverse=True
            )),
            "top_attacking_ips": [
                {"ip": ip, "attempts": count}
                for ip, count in top_ips
            ],
            "threat_level": _get_threat_level(len(recent)),
        })

    @app.get("/threats/live")
    async def threats_live(limit: int = Query(default=10, ge=1, le=100)):
        """Get the last N blocked requests in real time."""
        recent = list(_threat_events)[:limit]
        return JSONResponse({
            "count": len(recent),
            "events": [
                {
                    "time":         datetime.fromtimestamp(
                        e.get("timestamp", 0)
                    ).strftime("%H:%M:%S"),
                    "ip":           e.get("client_ip", "unknown"),
                    "reason":       e.get("block_reason", ""),
                    "block_type":   e.get("block_type", "rules"),
                    "ai_score":     e.get("anomaly_score", 0),
                    "path":         e.get("path", "/"),
                    "method":       e.get("method", "POST"),
                }
                for e in recent
            ],
        })

    @app.get("/threats/stats")
    async def threats_stats():
        """Get all-time statistics."""
        uptime_seconds = int(time.time() - _stats["start_time"])
        return JSONResponse({
            "all_time": {
                "total_requests":  _stats["total_requests"],
                "total_blocked":   _stats["total_blocked"],
                "rule_blocks":     _stats["rule_blocks"],
                "ai_blocks":       _stats["ai_blocks"],
                "ip_blocks":       _stats["ip_blocks"],
                "block_rate_pct":  round(
                    _stats["total_blocked"] /
                    max(_stats["total_requests"], 1) * 100, 2
                ),
            },
            "uptime_seconds": uptime_seconds,
            "model": "neurawall-phi3",
            "version": "0.3.0",
        })


def _get_threat_level(blocked_last_hour: int) -> str:
    if blocked_last_hour == 0:    return "SAFE"
    if blocked_last_hour < 5:     return "LOW"
    if blocked_last_hour < 20:    return "MEDIUM"
    if blocked_last_hour < 100:   return "HIGH"
    return "CRITICAL"
