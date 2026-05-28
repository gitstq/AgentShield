"""Custom exceptions for AgentShield."""


class AgentShieldError(Exception):
    """Base exception for all AgentShield errors.

    Attributes:
        message: Human-readable error description.
        details: Optional dictionary with additional context.
    """

    def __init__(self, message: str, details: dict = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} | details={self.details}"
        return self.message


class PolicyError(AgentShieldError):
    """Base exception for policy-related errors."""


class PolicyLoadError(PolicyError):
    """Raised when a policy file cannot be loaded or parsed.

    Attributes:
        file_path: Path to the policy file that failed to load.
    """

    def __init__(self, message: str, file_path: str = "", details: dict = None):
        super().__init__(message, details)
        self.file_path = file_path

    def __str__(self) -> str:
        base = super().__str__()
        if self.file_path:
            return f"{base} | file={self.file_path}"
        return base


class PolicyEvaluationError(PolicyError):
    """Raised when policy evaluation encounters an unexpected condition.

    Attributes:
        policy_name: Name of the policy that caused the error.
        action: The action being evaluated.
        resource: The resource being accessed.
    """

    def __init__(
        self,
        message: str,
        policy_name: str = "",
        action: str = "",
        resource: str = "",
        details: dict = None,
    ):
        super().__init__(message, details)
        self.policy_name = policy_name
        self.action = action
        self.resource = resource


class GuardError(AgentShieldError):
    """Base exception for guard-related errors."""


class GuardViolationError(GuardError):
    """Raised when a guard detects a policy violation.

    Attributes:
        guard_name: Name of the guard that detected the violation.
        action: The action that was blocked.
        resource: The resource that was being accessed.
        policy_name: Name of the violated policy.
    """

    def __init__(
        self,
        message: str,
        guard_name: str = "",
        action: str = "",
        resource: str = "",
        policy_name: str = "",
        details: dict = None,
    ):
        super().__init__(message, details)
        self.guard_name = guard_name
        self.action = action
        self.resource = resource
        self.policy_name = policy_name


class AuditError(AgentShieldError):
    """Raised when audit logging encounters an error."""


class TemplateError(AgentShieldError):
    """Raised when a policy template cannot be loaded or applied."""


class DashboardError(AgentShieldError):
    """Raised when the dashboard encounters an error."""
