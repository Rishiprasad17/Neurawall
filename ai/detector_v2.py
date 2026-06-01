import json
import logging
from typing import Optional

import httpx

from ..core.config import neurawallConfig
from ..core.models import RequestContext

logger = logging.getLogger("neurawall.ai")

SYSTEM_PROMPT = """You are a security analyst for an HTTP middleware system.
Analyze the incoming request and return a JSON object with exactly this shape:
{
  "anomaly_score": <float 0.0 to 1.0>,
  "reason": "<one sentence explanation>",
  "flags": ["<flag1>", "<flag2>"]
}

Score guide:
0.0–0.3  = normal traffic
0.3–0.6  = suspicious, worth logging
0.6–0.75 = likely malicious
0.75–1.0 = block immediately

Common attack flags: sql_injection, prompt_injection, path_traversal,
xss_attempt, unusual_headers, oversized_payload, rate_abuse, bot_pattern.

Return ONLY valid JSON. No preamble, no markdown."""


class AnomalyDetector:
    """
    Supports three AI backends — switch via config.ai_backend:

      "anthropic" — Anthropic API (cloud, needs API key)
      "ollama"    — Local Ollama (free, no key needed)
                    Install: curl -fsSL https://ollama.ai/install.sh | sh
                    Then:    ollama pull mistral
      "lmstudio"  — LM Studio local server (free, no key needed)
                    Download: https://lmstudio.ai — start local server on port 1234

    Recommended: start with "ollama", fine-tune your own model later.
    """

    def __init__(self, config: neurawallConfig):
        self.config = config
        self.backend = getattr(config, "ai_backend", "anthropic")
        logger.info(f"AI detector using backend: {self.backend}")

    async def score(self, ctx: RequestContext) -> float:
        try:
            summary = self._summarise(ctx)

            if self.backend == "ollama":
                result = await self._call_ollama(summary)
            elif self.backend == "lmstudio":
                result = await self._call_lmstudio(summary)
            else:
                result = await self._call_anthropic(summary)

            score = float(result.get("anomaly_score", 0.0))
            flags = result.get("flags", [])
            reason = result.get("reason", "")

            if flags:
                logger.info(
                    f"[{ctx.request_id}] flags={flags} score={score:.2f} | {reason}"
                )

            if self.config.qml_anomaly_model:
                from ..quantum.layer import QMLScorer
                score = await QMLScorer.refine(score, ctx)

            return min(max(score, 0.0), 1.0)

        except Exception as e:
            logger.warning(f"AI scoring failed ({e}), defaulting to 0.0")
            return 0.0

    # ------------------------------------------------------------------ #
    #  Backend: Ollama (local, free, no key)
    # ------------------------------------------------------------------ #
    async def _call_ollama(self, request_summary: str) -> dict:
        """
        Requires Ollama running locally.
        Install:  curl -fsSL https://ollama.ai/install.sh | sh
        Pull model: ollama pull mistral   (or phi3, llama3, gemma2)
        """
        model = getattr(self.config, "ollama_model", "mistral")
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                "http://localhost:11434/api/chat",
                json={
                    "model": model,
                    "stream": False,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user",   "content": f"Analyze this request:\n{request_summary}"},
                    ],
                },
            )
            resp.raise_for_status()
            text = resp.json()["message"]["content"]
            return self._parse_json(text)

    # ------------------------------------------------------------------ #
    #  Backend: LM Studio (local, free, no key)
    # ------------------------------------------------------------------ #
    async def _call_lmstudio(self, request_summary: str) -> dict:
        """
        Requires LM Studio running with local server enabled (port 1234).
        Download: https://lmstudio.ai
        """
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                "http://localhost:1234/v1/chat/completions",
                json={
                    "model": "local-model",   # LM Studio ignores this, uses loaded model
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user",   "content": f"Analyze this request:\n{request_summary}"},
                    ],
                    "temperature": 0.1,
                },
            )
            resp.raise_for_status()
            text = resp.json()["choices"][0]["message"]["content"]
            return self._parse_json(text)

    # ------------------------------------------------------------------ #
    #  Backend: Anthropic (cloud)
    # ------------------------------------------------------------------ #
    async def _call_anthropic(self, request_summary: str) -> dict:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.config.anthropic_api_key or "",
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": self.config.ai_model,
                    "max_tokens": 256,
                    "system": SYSTEM_PROMPT,
                    "messages": [
                        {"role": "user", "content": f"Analyze this request:\n{request_summary}"}
                    ],
                },
            )
            resp.raise_for_status()
            text = resp.json()["content"][0]["text"]
            return self._parse_json(text)

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #
    def _summarise(self, ctx: RequestContext) -> str:
        body_preview = ""
        if ctx.body:
            try:
                body_preview = ctx.body[:500].decode("utf-8", errors="replace")
            except Exception:
                body_preview = "<binary>"

        sensitive_headers = {
            k: v for k, v in ctx.headers.items()
            if k.lower() in ("user-agent", "authorization", "x-forwarded-for", "content-type")
        }

        return json.dumps({
            "method": ctx.method,
            "path": ctx.path,
            "client_ip": ctx.client_ip,
            "headers": sensitive_headers,
            "body_preview": body_preview,
        })

    def _parse_json(self, text: str) -> dict:
        # Strip markdown fences if model adds them
        clean = text.strip().replace("```json", "").replace("```", "").strip()
        return json.loads(clean)
