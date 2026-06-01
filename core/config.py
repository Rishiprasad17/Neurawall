from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class GuardrailConfig:
    # --- Phase 1: Core ---
    log_requests: bool = True
    max_latency_ms: int = 5000          # warn if request exceeds this
    max_retries: int = 3
    retry_backoff_factor: float = 0.5

    # --- Phase 2: AI ---
    ai_enabled: bool = False
    ai_backend: str = "ollama"          # "ollama" | "lmstudio" | "anthropic"
    anthropic_api_key: Optional[str] = None
    ai_model: str = "claude-sonnet-4-20250514"
    ollama_model: str = "mistral"       # mistral | phi3 | llama3 | gemma2
    anomaly_threshold: float = 0.75     # 0–1, above = block
    validate_payloads: bool = True

    # --- Phase 3: Security ---
    security_enabled: bool = False
    jwt_secret: Optional[str] = None
    enable_hmac_signing: bool = False
    hmac_secret: Optional[str] = None
    block_prompt_injection: bool = True
    rate_limit_rpm: int = 100           # requests per minute per IP

    # --- Phase 4: Performance ---
    cache_enabled: bool = False
    redis_url: Optional[str] = None
    prefetch_enabled: bool = False
    batch_enabled: bool = False

    # --- Phase 5: Quantum ---
    quantum_enabled: bool = False
    post_quantum_crypto: bool = False   # CRYSTALS-Kyber key exchange
    qml_anomaly_model: bool = False     # quantum ML threat scoring

    # --- General ---
    excluded_paths: List[str] = field(default_factory=lambda: ["/health", "/metrics"])
    debug: bool = False
