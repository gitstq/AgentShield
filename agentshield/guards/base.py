"""Base guard class and result type for AgentShield.

All guards inherit from BaseGuard and implement the check() method to
determine whether an action should be allowed or denied.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from agentshield.core.engine import PolicyEngine


@dataclass
class GuardResult:
    """Result of a guard check.

    Attributes:
        allowed: Whether the action is allowed.
        reason: Human-readable explanation for the decision.
        details: Optional dictionary with additional context.
        enforce: Whether to raise an exception on denial.
            If False, the denial is logged but execution continues.
    """

    allowed: bool
    reason: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    enforce: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Serialize this result to a dictionary.

        Returns:
            A dictionary representation of this result.
        """
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "details": self.details,
            "enforce": self.enforce,
        }

    def __repr__(self) -> str:
        return f"GuardResult(allowed={self.allowed!r}, reason={self.reason!r})"


class BaseGuard(ABC):
    """Abstract base class for all guards.

    Guards are responsible for checking whether specific actions should be
    allowed or denied based on their domain-specific rules.

    Attributes:
        name: Unique name for this guard.
        description: Human-readable description.
        enforce_mode: Whether to raise exceptions on denial.
        enabled: Whether this guard is active.
        engine: Reference to the parent PolicyEngine.
    """

    def __init__(
        self,
        name: str = "base",
        description: str = "",
        enforce_mode: bool = True,
        enabled: bool = True,
    ):
        self.name = name
        self.description = description
        self.enforce_mode = enforce_mode
        self.enabled = enabled
        self.engine: Optional["PolicyEngine"] = None

    @abstractmethod
    def check(
        self,
        action: str,
        resource: str,
        context: Dict[str, Any],
    ) -> GuardResult:
        """Check whether the given action on the resource is allowed.

        Args:
            action: The action being performed (e.g., "file:read").
            resource: The resource being accessed (e.g., "/etc/passwd").
            context: Additional context for the evaluation.

        Returns:
            A GuardResult indicating whether the action is allowed.
        """
        pass

    def enforce(
        self,
        action: str,
        resource: str,
        context: Dict[str, Any],
    ) -> GuardResult:
        """Check and enforce the guard decision.

        If enforce_mode is True and the action is denied, this method
        raises GuardViolationError. Otherwise, it returns the result.

        Args:
            action: The action being performed.
            resource: The resource being accessed.
            context: Additional context for the evaluation.

        Returns:
            A GuardResult indicating whether the action is allowed.

        Raises:
            GuardViolationError: If enforce_mode is True and the action is denied.
        """
        if not self.enabled:
            return GuardResult(
                allowed=True,
                reason=f"Guard '{self.name}' is disabled",
            )

        result = self.check(action, resource, context)
        result.enforce = self.enforce_mode
        return result

    def configure(self, **kwargs: Any) -> None:
        """Configure the guard with additional settings.

        Subclasses should override this to accept their own configuration.

        Args:
            **kwargs: Configuration key-value pairs.
        """
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize this guard to a dictionary.

        Returns:
            A dictionary representation of this guard.
        """
        return {
            "name": self.name,
            "description": self.description,
            "enforce_mode": self.enforce_mode,
            "enabled": self.enabled,
        }

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(name={self.name!r}, "
            f"enforce_mode={self.enforce_mode!r}, enabled={self.enabled!r})"
        )
