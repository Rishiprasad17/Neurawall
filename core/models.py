import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class RequestContext:
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    method: str = ""
    path: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[bytes] = None
    client_ip: str = ""
    timestamp: float = field(default_factory=time.time)

    # Populated by middleware phases
    anomaly_score: float = 0.0
    blocked: bool = False
    block_reason: str = ""
    cache_hit: bool = False
    latency_ms: float = 0.0

    def to_log(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "method": self.method,
            "path": self.path,
            "client_ip": self.client_ip,
            "anomaly_score": round(self.anomaly_score, 3),
            "blocked": self.blocked,
            "block_reason": self.block_reason,
            "cache_hit": self.cache_hit,
            "latency_ms": round(self.latency_ms, 2),
        }


