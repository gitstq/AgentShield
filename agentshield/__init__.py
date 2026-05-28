"""AgentShield - A lightweight AI Agent policy governance engine."""

__version__ = "1.0.0"
__author__ = "AgentShield Team"

from agentshield.core.engine import PolicyEngine
from agentshield.core.policy import Policy, PolicySet
from agentshield.core.context import ExecutionContext
from agentshield.core.exceptions import (
    PolicyError,
    GuardViolationError,
    AuditError,
    PolicyLoadError,
)
from agentshield.templates.builtin import get_builtin_template, list_builtin_templates
from agentshield.audit.logger import AuditLogger
from agentshield.decorators import shield, guard, audit, PolicyContext

__all__ = [
    "PolicyEngine",
    "Policy",
    "PolicySet",
    "ExecutionContext",
    "PolicyError",
    "GuardViolationError",
    "AuditError",
    "PolicyLoadError",
    "get_builtin_template",
    "list_builtin_templates",
    "AuditLogger",
    "shield",
    "guard",
    "audit",
    "PolicyContext",
]
