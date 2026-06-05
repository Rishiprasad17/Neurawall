"""
example_app.py — Neurawall quick start

Run:
    uvicorn example_app:app --reload  (from C:\guardrail folder)

Dashboard:
    http://127.0.0.1:8000/dashboard
"""
import os
import logging

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from guardrail import NeurawallMiddleware as GuardrailMiddleware, NeurawallConfig as GuardrailConfig
from guardrail.dashboard import add_dashboard

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(name)s | %(message)s")

config = GuardrailConfig(
    # Phase 1 — always on
    log_requests=True,
    max_latency_ms=3000,

    # Phase 2 — AI (local Ollama)
    ai_enabled=True,
    ai_backend="ollama",
    ollama_model="phi3:medium",
    anomaly_threshold=0.75,

    # Phase 3 — Security
    security_enabled=True,
    rate_limit_rpm=2000,
    block_prompt_injection=True,
    enable_hmac_signing=False,

    # Phase 4 — Cache (needs Redis)
    cache_enabled=False,

    # Phase 5 — Quantum
    quantum_enabled=False,

    debug=True,
)

app = FastAPI(title="Neurawall Demo")
app.add_middleware(GuardrailMiddleware, config=config)
add_dashboard(app)


@app.get("/health")
async def health():
    return {"status": "ok", "protected_by": "neurawall"}


@app.get("/hello")
async def hello():
    return {"message": "This request passed Neurawall security checks"}


@app.post("/data")
async def receive_data(payload: dict):
    return {"received": payload, "clean": True}


@app.get("/metrics")
async def metrics():
    return {
        "neurawall_version": "0.2.0",
        "phases": {
            "core":     True,
            "ai":       config.ai_enabled,
            "security": config.security_enabled,
            "cache":    config.cache_enabled,
            "quantum":  config.quantum_enabled,
        }
    }


