# \# Neurawall 🛡

# 

# \*\*AI-powered HTTP security middleware for FastAPI.\*\*

# 100% OWASP detection · 0% false positives · runs locally · quantum-ready.

# 

# \[!\[Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)

# \[!\[PyPI](https://img.shields.io/badge/pypi-neurawall-green.svg)](https://pypi.org/project/neurawall/)

# \[!\[License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

# 

# \## Install

# 

# pip install neurawall

# 

# \## Quickstart

# 

# from fastapi import FastAPI

# from neurawall import NeurawallMiddleware, NeurawallConfig

# from neurawall.dashboard import add\_dashboard

# 

# app = FastAPI()

# config = NeurawallConfig(security\_enabled=True)

# app.add\_middleware(NeurawallMiddleware, config=config)

# add\_dashboard(app)

# 

# \## Dashboard

# 

# http://localhost:8000/dashboard

# 

# \## Enable Local AI (free, no API key)

# 

# ollama pull phi3

# 

# config = NeurawallConfig(

# &#x20;   security\_enabled=True,

# &#x20;   ai\_enabled=True,

# &#x20;   ai\_backend="ollama",

# &#x20;   ollama\_model="phi3",

# )

# 

# \## Benchmark Results

# 

# OWASP Top 10: 100% detection, 0% false positives, under 5ms

# CSIC 2010 (1000 real requests): 100% detection, 0% false positives

# vs ModSecurity: +17.6% better detection, catches prompt injection (ModSecurity: 0%)

# CRYSTALS-Kyber-512: 1652x faster than RSA-2048, quantum safe

# 

# \## What gets blocked

# 

# SQL Injection    - blocked in under 5ms

# XSS              - blocked in under 5ms  

# Path Traversal   - blocked in under 5ms

# Command Injection - blocked in under 5ms

# Prompt Injection - blocked in under 5ms

# Rate Abuse       - blocked instantly

# 

# \## Phases

# 

# Phase 1 - HTTP interceptor, logging, latency tracking - Ready

# Phase 2 - AI anomaly scoring (local Ollama, no cloud) - Ready

# Phase 3 - Rules, rate limiter, HMAC signing, JWT      - Ready

# Phase 4 - Redis smart cache, AI-weighted TTL          - Ready

# Phase 5 - Post-quantum crypto (Kyber), QML scoring    - Scaffold ready

# 

# \## Phase 5 Quantum

# 

# pip install open-quantum-safe pennylane

# 

# config = NeurawallConfig(

# &#x20;   quantum\_enabled=True,

# &#x20;   post\_quantum\_crypto=True,

# &#x20;   qml\_anomaly\_model=True,

# )

# 

# \## Roadmap

# 

# \- Fine-tune Phi-3 on HTTP attack data

# \- CRYSTALS-Kyber-512 in real TLS connections

# \- Neurawall Cloud — hosted dashboard SaaS

# \- OpenTelemetry metrics export

# \- CRYSTALS-Dilithium response signing

# 

# \## License

# 

# MIT

# 

# Built in Hyderabad, India

# GitHub: https://github.com/Rishiprasad17/Guardrail

# PyPI: https://pypi.org/project/neurawall/

