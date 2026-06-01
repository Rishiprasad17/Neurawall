# guardrail — AI-powered HTTP security middleware
__version__ = "0.1.0"
__author__ = "Your Name"

from .core.middleware import GuardrailMiddleware
from .core.config import GuardrailConfig

__all__ = ["GuardrailMiddleware", "GuardrailConfig"]
