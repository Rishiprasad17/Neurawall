"""
neurawall_universal.py — Neurawall for FastAPI, Django, and Flask

Install:
    pip install neurawall

FastAPI usage:
    from neurawall import NeurawallMiddleware, NeurawallConfig
    app.add_middleware(NeurawallMiddleware, config=NeurawallConfig())

Django usage:
    # settings.py
    MIDDLEWARE = ['neurawall.django.NeurawallDjangoMiddleware'] + MIDDLEWARE
    NEURAWALL_CONFIG = {'security_enabled': True, 'ai_enabled': True}

Flask usage:
    from neurawall.flask import init_neurawall
    init_neurawall(app, security_enabled=True, ai_enabled=True)
"""

# ================================================================== #
# DJANGO MIDDLEWARE
# ================================================================== #

class NeurawallDjangoMiddleware:
    """
    Neurawall middleware for Django.

    Add to settings.py:
        MIDDLEWARE = [
            'neurawall.django.NeurawallDjangoMiddleware',
            ... your existing middleware ...
        ]

        NEURAWALL_CONFIG = {
            'security_enabled': True,
            'ai_enabled': True,
            'ai_backend': 'ollama',
            'ollama_model': 'neurawall-phi3',
            'rate_limit_rpm': 60,
            'anomaly_threshold': 0.75,
        }
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self._setup()

    def _setup(self):
        import logging
        self.logger = logging.getLogger("neurawall.django")

        try:
            from django.conf import settings
            cfg = getattr(settings, "NEURAWALL_CONFIG", {})
        except Exception:
            cfg = {}

        from guardrail.core.config import NeurawallConfig
        self.config = NeurawallConfig(
            security_enabled=cfg.get("security_enabled", True),
            ai_enabled=cfg.get("ai_enabled", False),
            ai_backend=cfg.get("ai_backend", "ollama"),
            ollama_model=cfg.get("ollama_model", "neurawall-phi3"),
            rate_limit_rpm=cfg.get("rate_limit_rpm", 60),
            anomaly_threshold=cfg.get("anomaly_threshold", 0.75),
        )

        from guardrail.security.hardening import SecurityHardener
        self.hardener = SecurityHardener(self.config)
        self.logger.info("Neurawall Django middleware ready")

    def __call__(self, request):
        import json
        from guardrail.core.models import RequestContext
        import uuid, time

        # Build context
        body = b""
        try:
            body = request.body
        except Exception:
            pass

        ctx = RequestContext(
            request_id=str(uuid.uuid4()),
            method=request.method,
            path=request.path,
            headers=dict(request.headers),
            client_ip=self._get_ip(request),
            timestamp=time.time(),
            body=body,
        )

        # Check security synchronously
        blocked = self._check_sync(ctx)
        if blocked:
            from django.http import JsonResponse
            return JsonResponse({
                "error": "Request blocked by Neurawall",
                "reason": ctx.block_reason,
                "request_id": ctx.request_id,
            }, status=403)

        response = self.get_response(request)
        return response

    def _check_sync(self, ctx):
        """Synchronous security check for Django."""
        import re, time
        from collections import defaultdict

        if not ctx.body:
            return False

        body_text = ctx.body.decode("utf-8", errors="replace")

        # Import and run pattern matching
        from guardrail.security.hardening import ALL_PATTERN_GROUPS, decode_payload
        versions = decode_payload(body_text)
        for version in versions:
            for category, patterns in ALL_PATTERN_GROUPS.items():
                for compiled, raw in patterns:
                    if compiled.search(version):
                        ctx.blocked = True
                        ctx.block_reason = f"{category} pattern detected"
                        return True
        return False

    def _get_ip(self, request):
        x_forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded:
            return x_forwarded.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "unknown")


# ================================================================== #
# FLASK MIDDLEWARE
# ================================================================== #

def init_neurawall(app, **config_kwargs):
    """
    Initialize Neurawall for Flask.

    Usage:
        from flask import Flask
        from neurawall.flask import init_neurawall

        app = Flask(__name__)
        init_neurawall(app,
            security_enabled=True,
            ai_enabled=True,
            ollama_model='neurawall-phi3',
        )
    """
    import logging
    import json
    import uuid
    import time

    logger = logging.getLogger("neurawall.flask")

    from guardrail.core.config import NeurawallConfig
    config = NeurawallConfig(**config_kwargs)

    from guardrail.security.hardening import SecurityHardener
    hardener = SecurityHardener(config)

    logger.info("Neurawall Flask middleware ready")

    @app.before_request
    def neurawall_check():
        from flask import request, jsonify, g
        from guardrail.core.models import RequestContext
        from guardrail.security.hardening import ALL_PATTERN_GROUPS, decode_payload

        body = b""
        try:
            body = request.get_data()
        except Exception:
            pass

        ctx = RequestContext(
            request_id=str(uuid.uuid4()),
            method=request.method,
            path=request.path,
            headers=dict(request.headers),
            client_ip=request.remote_addr or "unknown",
            timestamp=time.time(),
            body=body,
        )

        # Pattern matching
        if body:
            body_text = body.decode("utf-8", errors="replace")
            versions = decode_payload(body_text)
            for version in versions:
                for category, patterns in ALL_PATTERN_GROUPS.items():
                    for compiled, raw in patterns:
                        if compiled.search(version):
                            response = jsonify({
                                "error": "Request blocked by Neurawall",
                                "reason": f"{category} pattern detected",
                                "request_id": ctx.request_id,
                            })
                            response.status_code = 403
                            logger.warning(
                                f"[{ctx.request_id}] Blocked: {category} "
                                f"ip={ctx.client_ip}"
                            )
                            return response

        # Store context for after_request
        g.neurawall_ctx = ctx

    return app


# ================================================================== #
# USAGE EXAMPLES
# ================================================================== #

FASTAPI_EXAMPLE = '''
# FastAPI — existing way (unchanged)
from fastapi import FastAPI
from neurawall import NeurawallMiddleware, NeurawallConfig
from neurawall.dashboard import add_dashboard

app = FastAPI()
config = NeurawallConfig(
    security_enabled=True,
    ai_enabled=True,
    ollama_model="neurawall-phi3",
)
app.add_middleware(NeurawallMiddleware, config=config)
add_dashboard(app)
'''

DJANGO_EXAMPLE = '''
# Django — settings.py
MIDDLEWARE = [
    "guardrail.django.NeurawallDjangoMiddleware",
    "django.middleware.security.SecurityMiddleware",
    # ... rest of your middleware
]

NEURAWALL_CONFIG = {
    "security_enabled": True,
    "ai_enabled": True,
    "ai_backend": "ollama",
    "ollama_model": "neurawall-phi3",
    "rate_limit_rpm": 60,
}
'''

FLASK_EXAMPLE = '''
# Flask — app.py
from flask import Flask
from guardrail.flask import init_neurawall

app = Flask(__name__)
init_neurawall(app,
    security_enabled=True,
    ai_enabled=True,
    ai_backend="ollama",
    ollama_model="neurawall-phi3",
)

@app.route("/hello")
def hello():
    return {"message": "Protected by Neurawall"}
'''

if __name__ == "__main__":
    print("Neurawall Universal Integration")
    print("================================")
    print("\nFastAPI:", FASTAPI_EXAMPLE)
    print("\nDjango:", DJANGO_EXAMPLE)
    print("\nFlask:", FLASK_EXAMPLE)
