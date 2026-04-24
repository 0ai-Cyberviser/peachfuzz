"""CactusFuzz authorized adversarial fuzzing edition."""
from .agent import CactusDecision, CactusFuzzAgent
from .scope import AuthorizationScope, ScopeError

__all__ = ["CactusDecision", "CactusFuzzAgent", "AuthorizationScope", "ScopeError"]
__version__ = "0.1.0"
