"""Decorators for AgentShield.

Provides convenient decorators for applying policy governance to functions,
including @shield, @guard, and @audit decorators, as well as a context
manager for policy enforcement.
"""

import functools
from typing import Any, Callable, List, Optional

from agentshield.core.context import ExecutionContext
from agentshield.core.engine import PolicyEngine
from agentshield.core.exceptions import GuardViolationError
from agentshield.core.policy import Effect, PolicySet
from agentshield.templates.builtin import BuiltinTemplates


# Global default engine instance
_default_engine: Optional[PolicyEngine] = None


def _get_default_engine() -> PolicyEngine:
    """Get or create the default global PolicyEngine.

    Returns:
        The default PolicyEngine instance.
    """
    global _default_engine
    if _default_engine is None:
        _default_engine = PolicyEngine()
        _default_engine.load_policy_set(BuiltinTemplates.balanced())
    return _default_engine


def set_default_engine(engine: PolicyEngine) -> None:
    """Set the global default PolicyEngine.

    Args:
        engine: The PolicyEngine to use as default.
    """
    global _default_engine
    _default_engine = engine


def shield(
    policy: Optional[str] = None,
    engine: Optional[PolicyEngine] = None,
    action: str = "",
    resource: str = "",
    agent_id: str = "",
) -> Callable:
    """Decorator to apply policy governance to a function.

    Wraps a function so that all calls are evaluated against the
    specified policy template.

    Args:
        policy: Policy template name (strict, balanced, permissive, owasp_top10).
        engine: Optional PolicyEngine instance. If None, uses the default.
        action: Action string for policy evaluation. If empty, uses "function:{name}".
        resource: Resource string for policy evaluation. If empty, uses the function name.
        agent_id: Agent identifier. If empty, uses "default_agent".

    Returns:
        A decorator function.

    Example::

        @shield(policy="strict")
        def read_file(path: str) -> str:
            with open(path) as f:
                return f.read()
    """

    def decorator(func: Callable) -> Callable:
        _engine = engine or _get_default_engine()

        # Load the policy template if it's a named template
        if isinstance(policy, str) and policy:
            try:
                template = BuiltinTemplates.get_template(policy)
                _engine.load_policy_set(template)
            except ValueError:
                pass  # Use existing engine policies

        _action = action or f"function:{func.__name__}"
        _resource = resource or func.__name__
        _agent_id = agent_id or "default_agent"

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            ctx = ExecutionContext(
                action=_action,
                resource=_resource,
                agent_id=_agent_id,
                metadata={
                    "function": func.__name__,
                    "args_count": len(args),
                    "kwargs_keys": list(kwargs.keys()),
                },
            )

            try:
                allowed = _engine.evaluate(_action, _resource, ctx)
            except GuardViolationError:
                raise PermissionError(
                    f"Policy denied execution of function '{func.__name__}' "
                    f"(action={_action}, resource={_resource})"
                )

            if not allowed:
                raise PermissionError(
                    f"Policy denied execution of function '{func.__name__}' "
                    f"(action={_action}, resource={_resource})"
                )

            return func(*args, **kwargs)

        return wrapper

    return decorator


def guard(
    guard_name: str,
    engine: Optional[PolicyEngine] = None,
    action: str = "",
    resource: str = "",
) -> Callable:
    """Decorator to apply a specific guard to a function.

    Args:
        guard_name: Name of the guard to apply.
        engine: Optional PolicyEngine instance.
        action: Action string for guard evaluation.
        resource: Resource string for guard evaluation.

    Returns:
        A decorator function.

    Example::

        @guard("file")
        def read_config(path: str) -> dict:
            ...
    """

    def decorator(func: Callable) -> Callable:
        _engine = engine or _get_default_engine()
        _action = action or f"function:{func.__name__}"
        _resource = resource or func.__name__

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            ctx = ExecutionContext(
                action=_action,
                resource=_resource,
                metadata={
                    "function": func.__name__,
                    "guard_name": guard_name,
                },
            )

            try:
                _engine.evaluate(_action, _resource, ctx, guard_names=[guard_name])
            except GuardViolationError:
                raise PermissionError(
                    f"Guard '{guard_name}' denied execution of function '{func.__name__}'"
                )

            return func(*args, **kwargs)

        return wrapper

    return decorator


def audit(
    action: str = "",
    resource: str = "",
    agent_id: str = "",
    engine: Optional[PolicyEngine] = None,
) -> Callable:
    """Decorator to add audit logging to a function.

    Logs every function call to the audit logger without enforcing
    any policy decisions.

    Args:
        action: Action string for audit logging.
        resource: Resource string for audit logging.
        agent_id: Agent identifier for audit logging.
        engine: Optional PolicyEngine instance.

    Returns:
        A decorator function.

    Example::

        @audit(action="custom_action", resource="my_function")
        def my_function():
            ...
    """

    def decorator(func: Callable) -> Callable:
        _engine = engine or _get_default_engine()
        _action = action or f"audit:{func.__name__}"
        _resource = resource or func.__name__
        _agent_id = agent_id or "default_agent"

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            ctx = ExecutionContext(
                action=_action,
                resource=_resource,
                agent_id=_agent_id,
                metadata={
                    "function": func.__name__,
                    "args_count": len(args),
                    "kwargs_keys": list(kwargs.keys()),
                },
            )

            _engine.audit_logger.log(
                agent_id=_agent_id,
                action=_action,
                resource=_resource,
                decision="allowed",
                details={
                    "function": func.__name__,
                    "type": "audit_decorator",
                },
                request_id=ctx.request_id,
            )

            return func(*args, **kwargs)

        return wrapper

    return decorator


class PolicyContext:
    """Context manager for applying policy governance to a block of code.

    Sets the execution context for the duration of the block and
    evaluates policy decisions.

    Args:
        policy: Policy template name or PolicySet.
        action: Action string for policy evaluation.
        resource: Resource string for policy evaluation.
        agent_id: Agent identifier.
        engine: Optional PolicyEngine instance.

    Example::

        with PolicyContext(policy="strict", action="file:read", resource="/tmp/data"):
            # Code here runs under strict policy
            data = open("/tmp/data").read()
    """

    def __init__(
        self,
        policy: str = "balanced",
        action: str = "",
        resource: str = "",
        agent_id: str = "",
        engine: Optional[PolicyEngine] = None,
    ):
        self._engine = engine or _get_default_engine()
        self._action = action
        self._resource = resource
        self._agent_id = agent_id or "default_agent"
        self._context: Optional[ExecutionContext] = None
        self._previous_context: Optional[ExecutionContext] = None

        # Load policy template if it's a named template
        if isinstance(policy, str):
            try:
                template = BuiltinTemplates.get_template(policy)
                self._engine.load_policy_set(template)
            except ValueError:
                pass
        elif isinstance(policy, PolicySet):
            self._engine.load_policy_set(policy)

    def __enter__(self) -> "PolicyContext":
        """Enter the policy context.

        Returns:
            This PolicyContext instance.
        """
        self._context = ExecutionContext(
            action=self._action,
            resource=self._resource,
            agent_id=self._agent_id,
        )
        self._previous_context = ExecutionContext.get_current()
        ExecutionContext.set_current(self._context)

        # Evaluate the policy
        if self._action and self._resource:
            effect = self._engine.check(self._action, self._resource, self._context)
            if effect != Effect.ALLOW:
                self.__exit__(None, None, None)
                raise PermissionError(
                    f"Policy denied: action={self._action}, resource={self._resource}"
                )

        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit the policy context, restoring the previous context."""
        ExecutionContext.set_current(self._previous_context)
