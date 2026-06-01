# Guardrail

**AI-powered HTTP security middleware for FastAPI.**  
Fast. Precise. Quantum-ready.

## Install

```bash
pip install -r requirements.txt
```

## Quickstart

```python
from fastapi import FastAPI
from guardrail import GuardrailMiddleware, GuardrailConfig

app = FastAPI()

config = GuardrailConfig(
    ai_enabled=True,
    anthropic_api_key="your-key-here",
    security_enabled=True,
    rate_limit_rpm=60,
)

app.add_middleware(GuardrailMiddleware, config=config)
```

## Phases

| Phase | Feature | Status |
|-------|---------|--------|
| 1 | Core HTTP interceptor, logging, latency tracking | ✅ Ready |
| 2 | AI anomaly detection (Anthropic API) | ✅ Ready |
| 3 | Rate limiting, prompt injection guard, HMAC signing | ✅ Ready |
| 4 | Redis smart cache, AI-weighted TTL | ✅ Ready |
| 5 | Post-quantum crypto (Kyber), QML scoring | 🔬 Stub (install deps) |

## Run the demo

```bash
export ANTHROPIC_API_KEY=your-key-here
uvicorn guardrail.example_app:app --reload
```

## Test

```bash
pytest guardrail/tests/ -v
```

## Phase 5 — Quantum (when ready)

```bash
pip install open-quantum-safe pennylane
```

Then enable in config:
```python
config = GuardrailConfig(
    quantum_enabled=True,
    post_quantum_crypto=True,
    qml_anomaly_model=True,
)
```

## Roadmap

- [ ] OpenTelemetry metrics export
- [ ] Dashboard UI (FastAPI + HTMX)
- [ ] Publish to PyPI as `guardrail-ai`
- [ ] CRYSTALS-Dilithium response signing
- [ ] Full QML threat model (PennyLane)
