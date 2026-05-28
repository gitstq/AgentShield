"""AgentShield core module."""

from agentshield.core.policy import Policy, PolicySet
from agentshield.core.context import ExecutionContext
from agentshield.core.exceptions import (
    PolicyError,
    PolicyLoadError,
    PolicyEvaluationError,
    GuardError,
    GuardViolationError,
    AuditError,
)


def __getattr__(name):
    """Lazy import for PolicyEngine to avoid circular imports."""
    if name == "PolicyEngine":
        from agentshield.core.engine import PolicyEngine
        return PolicyEngine
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "PolicyEngine",
    "Policy",
    "PolicySet",
    "ExecutionContext",
    "PolicyError",
    "PolicyLoadError",
    "PolicyEvaluationError",
    "GuardError",
    "GuardViolationError",
    "AuditError",
]
