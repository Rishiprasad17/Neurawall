from .core.middleware import NeurawallMiddleware
from .core.config import NeurawallConfig
GuardrailMiddleware = NeurawallMiddleware
GuardrailConfig = NeurawallConfig
__version__ = '0.2.0'
__all__ = ['NeurawallMiddleware', 'NeurawallConfig', 'GuardrailMiddleware', 'GuardrailConfig']
