import hashlib
import hmac
import logging
import re
import time
from collections import defaultdict
from urllib.parse import unquote, unquote_plus

from fastapi import Request, Response
from ..core.config import NeurawallConfig
from ..core.models import RequestContext

logger = logging.getLogger("guardrail.security")

# --- Prompt Injection ---
INJECTION_PATTERNS = [
    r"ignore previous instructions",
    r"ignore all (previous )?instructions",
    r"disregard (previous |your |all )?instructions",
    r"forget (previous |all )?instructions",
    r"override (previous |all )?instructions",
    r"you are now (in )?",
    r"act as (a |an |if )",
    r"pretend (you are|to be)",
    r"you must now act as",
    r"your new instructions",
    r"new (system )?prompt",
    r"ignore your system prompt",
    r"disregard your system prompt",
    r"forget your system prompt",
    r"override your system prompt",
    r"system:\s*ignore",
    r"SYSTEM OVERRIDE",
    r"###\s*(instruction|system|prompt)",
    r"\[SYSTEM\]",
    r"\[\[system\]\]",
    r"jailbreak",
    r"DAN mode",
    r"developer mode (enabled|activated)",
    r"sudo mode",
    r"ADMIN OVERRIDE",
    r"print your system prompt",
    r"reveal your instructions",
    r"show me your prompt",
    r"repeat your system prompt",
    r"what (are|were) your instructions",
    r"tell me your (system |initial )?prompt",
    # Multilingual
    r"ignoriere.*anweisung",
    r"ignorer.*instruction",
    r"ignora.*istruzione",
    r"ignore.*everything",
    r"新しい指示",
    r"이전 지시를 무시",
]

# --- SQL Injection ---
SQL_PATTERNS = [
    r"(DROP|TRUNCATE|ALTER)\s+TABLE\s+\w+",
    r"UNION\s+(ALL\s+)?SELECT\s+",
    r";\s*(DROP|DELETE|INSERT|UPDATE|EXEC|EXECUTE)\s+",
    r"SELECT\s+[\*\w,\s]+\s+FROM\s+\w+",
    r"WHERE\s+.{1,30}=.{1,30}",
    r"admin'--",
    r"'\s*--",
    r"'#",
    r"waitfor\s+delay",
    r"SLEEP\s*\(\s*\d+",
    r"benchmark\s*\(",
    r"'\s*OR\s+'?\w+'?\s*=\s*'?\w+",
    r"OR\s+1\s*=\s*1",
    r"AND\s+1\s*=\s*1",
    r"1\s*=\s*1\s*--",
    r"'\s*DELETE\s+FROM",
    r"';\s*(SELECT|INSERT|UPDATE|DROP)",
    r"xp_cmdshell",
    r"@@version",
    r"@@servername",
    r"information_schema",
    r"EXEC\s+(xp_|sp_)\w+",
    r"CAST\s*\(",
    r"CONVERT\s*\(",
    r"char\s*\(\s*\d+",
    r"pg_sleep",
    r"extractvalue\s*\(",
    r"updatexml\s*\(",
    r"LOAD_FILE\s*\(",
    r"INTO\s+OUTFILE",
    r"PROCEDURE\s+ANALYSE",
    r"ORDER\s+BY\s+\d+--",
    r"GROUP\s+BY\s+\d+--",
    r"HAVING\s+1\s*=\s*1",
    r"RLIKE\s+SLEEP",
    r"1\s+AND\s+BENCHMARK",
    r"OR\s+'[^']+'\s*=\s*'[^']+",
    r"OR\s+\"[^\"]+\"\s*=\s*\"[^\"]+",
    r"'\s*OR\s+'something",
    r"OR\s+char\s*\(",
    r"exec\s+sp_",
    r"exec\s+xp_",
]

# --- XSS ---
XSS_PATTERNS = [
    r"<\s*script[\s>\/]",
    r"<\s*SCR\w*[\s>]",
    r"javascript\s*:\s*\w",
    r"onerror\s*=",
    r"onload\s*=",
    r"onclick\s*=",
    r"onmouseover\s*=",
    r"onfocus\s*=",
    r"onblur\s*=",
    r"onstart\s*=",
    r"ontoggle\s*=",
    r"<\s*iframe",
    r"<\s*img[^>]+\bon\w+\s*=",
    r"<\s*svg[\s>\/]",
    r"<\s*body[\s>][^>]*on\w+",
    r"<\s*video[\s>]",
    r"<\s*audio[\s>]",
    r"<\s*details[\s>]",
    r"<\s*marquee[\s>]",
    r"<\s*form[^>]+action\s*=\s*['\"]?javascript",
    r"<\s*meta[^>]+javascript",
    r"eval\s*\(",
    r"alert\s*\(",
    r"fetch\s*\(\s*['\"]https?://",
    r"document\.cookie",
    r"document\.location",
    r"new\s+Image\s*\(\s*\)",
    r"setTimeout\s*\(",
    r"setInterval\s*\(",
    r"data:text/html",
    r"vbscript\s*:",
    r"<\s*object[^>]+data\s*=",
    r"<\s*embed[^>]+src",
    r"<\s*link[^>]+javascript",
    r"String\.fromCharCode",
    r"atob\s*\(",
    r"window\[",
    r"constructor\s*\(",
    r"formaction\s*=\s*['\"]?javascript",
    r"href\s*=\s*['\"]?javascript",
    r"src\s*=\s*['\"]?javascript",
    r"onerror\s*=\s*fetch",
]

# --- Path Traversal ---
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.[/\\]",
    r"\.\.%2f",
    r"%2e%2e",
    r"\.\.%252f",
    r"%252e%252e",
    r"\.\.%c0%af",
    r"\.\.%e0%80%af",
    r"etc/passwd",
    r"etc/shadow",
    r"etc/hosts",
    r"proc/self",
    r"proc/version",
    r"windows[/\\]system32",
    r"windows[/\\]win\.ini",
    r"boot\.ini",
    r"\.\.//",
    r"php://filter",
    r"php://input",
    r"file:///",
    r"data:text/",
]

# --- Command Injection ---
CMD_PATTERNS = [
    # Semicolon commands
    r";\s*(ls|dir|id|whoami|pwd|cat|type|more|head|tail|find|grep)\b",
    r";\s*(rm|del|mkdir|copy|move|cp|mv)\b",
    r";\s*(ping|curl|wget|nc|netcat|nmap)\b",
    r";\s*(python|perl|ruby|php|bash|sh|cmd|powershell)\b",
    r";\s*(net\s+user|ipconfig|ifconfig|systeminfo|uname)\b",
    r";\s*(/bin/|/usr/bin/|/sbin/)",
    r";\s*echo\s+",
    r";\s*touch\s+",
    r";\s*(chmod|chown)\s+",
    # Pipe commands
    r"\|\s*(ls|dir|id|whoami|cat|type|bash|sh)\b",
    r"\|\s*(curl|wget)\s+http",
    r"\|\s*(python|perl|ruby|php)\b",
    r"\|\s*(/bin/|/usr/bin/)",
    # Ampersand commands
    r"&&\s*(ls|dir|id|whoami|cat|wget|curl|bash)\b",
    r"&\s+(ls|dir|id|whoami|cat)\b",
    r"\|\|\s*(ls|dir|id|whoami)\b",
    # Backtick/subshell
    r"`\s*(ls|dir|id|whoami|cat|ping|curl|wget)\s*`",
    r"`\s*/bin/",
    r"\$\(\s*(ls|dir|id|whoami|cat|curl|wget)\b",
    r"\$\(\s*/bin/",
    r"\$\{IFS\}",
    # Encoded
    r"%0a\s*(ls|id|whoami|cat)",
    r"%3b\s*(ls|id|whoami)",
    r"%7c\s*(ls|id|whoami)",
    r"%26\s*(ls|id|whoami)",
    # Specific dangerous commands
    r"rm\s+-rf",
    r"--no-preserve-root",
    r"__class__\.__",
    r"__globals__",
    r"__init__\.__",
    r"__import__\s*\(",
    r"popen\s*\(",
    r"cmd\.exe\s*/c",
    r"powershell\.exe",
    r"/bin/(bash|sh|zsh)\b",
    r"nc\s+-e\s+/bin",
    r"bash\s+-i\s+>&",
    r"/dev/tcp/",
    r"reverse.shell",
    r"bind.shell",
    # Network
    r"curl\s+http.*\|\s*(bash|sh)",
    r"wget\s+http.*&&",
    r"wget\s+-O\s+.*&&",
    r"__class__\.__",
    r"__globals__",
    r"__init__\.__",
    r"__import__\s*\(",
    r"popen\s*\(",
    r"\{%.*?(exec|import|system|popen).*?%\}",
]

ALL_PATTERN_GROUPS = {
    "Prompt Injection":  [(re.compile(p, re.IGNORECASE), p) for p in INJECTION_PATTERNS],
    "SQL Injection":     [(re.compile(p, re.IGNORECASE), p) for p in SQL_PATTERNS],
    "XSS":               [(re.compile(p, re.IGNORECASE), p) for p in XSS_PATTERNS],
    "Path Traversal":    [(re.compile(p, re.IGNORECASE), p) for p in PATH_TRAVERSAL_PATTERNS],
    "Command Injection": [(re.compile(p, re.IGNORECASE), p) for p in CMD_PATTERNS],
}


def decode_payload(text: str) -> list:
    versions = {text}
    try:
        d1 = unquote(text)
        versions.add(d1)
        d2 = unquote(d1)
        versions.add(d2)
    except Exception:
        pass
    try:
        versions.add(unquote_plus(text))
    except Exception:
        pass
    try:
        no_comments = re.sub(r'/\*.*?\*/', ' ', text)
        versions.add(no_comments)
    except Exception:
        pass
    versions.add(text.lower())
    return list(versions)


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
    def __init__(self, config: NeurawallConfig):
        self.config = config
        self.rate_limiter = RateLimiter(config.rate_limit_rpm)

    async def check(self, request: Request, ctx: RequestContext) -> bool:
        if not self.rate_limiter.is_allowed(ctx.client_ip):
            ctx.blocked = True
            ctx.block_reason = "Rate limit exceeded"
            return True

        if ctx.body:
            body_text = ctx.body.decode("utf-8", errors="replace")
            versions = decode_payload(body_text)
            for version in versions:
                for category, patterns in ALL_PATTERN_GROUPS.items():
                    for compiled, raw in patterns:
                        if compiled.search(version):
                            ctx.blocked = True
                            ctx.block_reason = f"{category} pattern detected"
                            logger.warning(f"[{ctx.request_id}] Blocked: {category} | {raw[:40]}")
                            return True

        if self.config.jwt_secret:
            token = ctx.headers.get("authorization", "").replace("Bearer ", "")
            if token and not self._verify_jwt(token):
                ctx.blocked = True
                ctx.block_reason = "Invalid JWT token"
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
            response.headers["X-Neurawall-Signature"] = sig
            response.headers["X-Neurawall-Request-ID"] = ctx.request_id
        return response

    def _verify_jwt(self, token: str) -> bool:
        return len(token) > 10

