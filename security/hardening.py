import hashlib
import hmac
import logging
import re
import time
from collections import defaultdict

from fastapi import Request, Response
from ..core.config import neurawallConfig
from ..core.models import RequestContext

logger = logging.getLogger("neurawall.security")

# --- Prompt Injection (high precision — unique phrases) ---
INJECTION_PATTERNS = [
    r"ignore previous instructions",
    r"ignore all instructions",
    r"you are now",
    r"act as (a|an)",
    r"disregard (your|all|the)",
    r"system prompt",
    r"jailbreak",
    r"DAN mode",
]

# --- SQL Injection (require strong multi-token evidence) ---
SQL_PATTERNS = [
    r"(DROP|TRUNCATE|ALTER)\s+TABLE\s+\w+",   # DROP TABLE users
    r"UNION\s+(ALL\s+)?SELECT\s+\w+",          # UNION SELECT username
    r";\s*(DROP|DELETE|INSERT|UPDATE)\s+",      # ; DROP / ; DELETE
    r"waitfor\s+delay\s+'",                     # time-based SQLi
    r"SLEEP\s*\(\s*\d+\s*\)",                  # MySQL sleep
    r"benchmark\s*\(\s*\d+",                   # MySQL benchmark
    r"'\s*;\s*--",                              # '; --
    r"'\s*OR\s+'\w+'\s*=\s*'\w+'",             # ' OR 'a'='a'
    r"1\s*=\s*1\s*--",                         # 1=1--
    r"'\s*DELETE\s+FROM\s+\w+",               # ' DELETE FROM table
    r"'\s*;\s*(SELECT|INSERT|UPDATE|DROP)",    # '; SELECT
]

# --- XSS (require tag structure, not just keywords) ---
XSS_PATTERNS = [
    r"<\s*script[\s>\/]",                      # <script> or <script/
    r"<\s*SCR\w*\s*>",                         # <SCRipt>
    r"javascript\s*:\s*\w",                    # javascript:alert
    r"\bon\w+\s*=\s*['\"]?\s*(alert|eval)",   # onerror=alert(
    r"<\s*iframe[\s>]",                        # <iframe
    r"<\s*img[^>]+\bon\w+\s*=",              # <img onerror=
    r"\beval\s*\(\s*['\"]",                   # eval("
    r"alert\s*\(\s*['\"]",                    # alert("
]

# --- Path Traversal (require multiple dots or sensitive files) ---
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./\.\./",                             # ../../
    r"\.\.\\\.\.\\",                           # ..\..\ 
    r"%2e%2e%2f%2e%2e",                       # double encoded
    r"etc/passwd",
    r"etc/shadow",
    r"windows/system32",
    r"boot\.ini",
    r"/proc/self",
]

# --- Command Injection (require shell command context) ---
CMD_PATTERNS = [
    r";\s*(rm\s+-rf|cat\s+/etc|wget\s+http|curl\s+http|bash\s+-)",
    r"\|\s*(bash|sh|python|perl|nc\s+)",
    r"`\s*(whoami|id|ls|cat|rm)\s*`",
    r"\$\(\s*(whoami|id|ls|cat|rm)",
    r"\/bin\/(bash|sh)\s",
    r"--no-preserve-root",
    r"cmd\.exe\s*/c",
]

ALL_PATTERN_GROUPS = {
    "Prompt Injection":  [(re.compile(p, re.IGNORECASE), p) for p in INJECTION_PATTERNS],
    "SQL Injection":     [(re.compile(p, re.IGNORECASE), p) for p in SQL_PATTERNS],
    "XSS":               [(re.compile(p, re.IGNORECASE), p) for p in XSS_PATTERNS],
    "Path Traversal":    [(re.compile(p, re.IGNORECASE), p) for p in PATH_TRAVERSAL_PATTERNS],
    "Command Injection": [(re.compile(p, re.IGNORECASE), p) for p in CMD_PATTERNS],
}


class RateLimiter:
    def __init__(self, rpm: int):
        self.rpm = rpm
        self._counts: dict = defaultdict(list)

    def is_allowed(self, ip: str) -> bool:
        now = time.time()
        self._counts[ip] = [t for t in self._counts[ip] if now - t < 60.0]
        if len(self._counts[ip]) >= self.rpm:
            return False
        self._counts[ip].append(now)
        return True


class SecurityHardener:
    def __init__(self, config: neurawallConfig):
        self.config = config
        self.rate_limiter = RateLimiter(config.rate_limit_rpm)

    async def check(self, request: Request, ctx: RequestContext) -> bool:
        if not self.rate_limiter.is_allowed(ctx.client_ip):
            ctx.blocked = True
            ctx.block_reason = "Rate limit exceeded"
            return True

        if ctx.body:
            body_text = ctx.body.decode("utf-8", errors="replace")
            for category, patterns in ALL_PATTERN_GROUPS.items():
                for compiled, raw in patterns:
                    if compiled.search(body_text):
                        ctx.blocked = True
                        ctx.block_reason = f"{category} pattern detected"
                        logger.warning(f"[{ctx.request_id}] Blocked: {category} | {raw[:40]}")
                        return True
        return False

    async def sign_response(self, response: Response, ctx: RequestContext) -> Response:
        if self.config.enable_hmac_signing and self.config.hmac_secret:
            payload = f"{ctx.request_id}:{ctx.path}:{int(ctx.timestamp)}"
            sig = hmac.new(
                self.config.hmac_secret.encode(),
                payload.encode(),
                hashlib.sha256,
            ).hexdigest()
            response.headers["X-neurawall-Signature"] = sig
            response.headers["X-neurawall-Request-ID"] = ctx.request_id
        return response

    def _verify_jwt(self, token: str) -> bool:
        return len(token) > 10
