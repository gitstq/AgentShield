"""Policy engine core for AgentShield.

The PolicyEngine is the central component that loads policies, registers guards,
evaluates policy decisions, and manages the audit trail.
"""

import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Type

from agentshield.audit.logger import AuditLogger
from agentshield.core.context import ExecutionContext
from agentshield.core.exceptions import (
    GuardViolationError,
    PolicyEvaluationError,
    PolicyLoadError,
)
from agentshield.core.policy import Effect, Policy, PolicySet, parse_yaml_policy_file
from agentshield.guards.base import BaseGuard


class PolicyEngine:
    """Central policy evaluation engine.

    The PolicyEngine loads policies, manages guards, and evaluates whether
    actions are allowed or denied. It is thread-safe and supports policy
    hot-reloading.

    Attributes:
        policy_set: The current set of policies.
        guards: Registered guard instances.
        audit_logger: The audit logger for recording decisions.
        default_effect: The default effect when no policy matches.
    """

    def __init__(
        self,
        policy_set: Optional[PolicySet] = None,
        audit_logger: Optional[AuditLogger] = None,
        default_effect: Effect = Effect.DENY,
    ):
        self._lock = threading.RLock()
        self.policy_set = policy_set or PolicySet(name="default")
        self.guards: Dict[str, BaseGuard] = {}
        self.audit_logger = audit_logger or AuditLogger()
        self.default_effect = default_effect
        self._policy_file: Optional[str] = None
        self._policy_mtime: float = 0.0
        self._hot_reload: bool = False
        self._reload_interval: float = 5.0
        self._reload_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def load_policy_file(self, file_path: str) -> None:
        """Load policies from a YAML file.

        Args:
            file_path: Path to the YAML policy file.

        Raises:
            PolicyLoadError: If the file cannot be loaded.
        """
        with self._lock:
            policy_set = parse_yaml_policy_file(file_path)
            self.policy_set = policy_set
            self._policy_file = file_path
            self._policy_mtime = os.path.getmtime(file_path)

    def load_policy_set(self, policy_set: PolicySet) -> None:
        """Load a PolicySet directly.

        Args:
            policy_set: The PolicySet to use.
        """
        with self._lock:
            self.policy_set = policy_set
            self._policy_file = None
            self._policy_mtime = 0.0

    def add_policy(self, policy: Policy) -> None:
        """Add a single policy to the current policy set.

        Args:
            policy: The Policy to add.
        """
        with self._lock:
            self.policy_set.add_policy(policy)

    def remove_policy(self, name: str) -> bool:
        """Remove a policy by name.

        Args:
            name: Name of the policy to remove.

        Returns:
            True if the policy was found and removed.
        """
        with self._lock:
            return self.policy_set.remove_policy(name)

    def register_guard(self, name: str, guard: BaseGuard) -> None:
        """Register a guard instance.

        Args:
            name: Unique name for the guard.
            guard: The guard instance.
        """
        with self._lock:
            guard.engine = self
            self.guards[name] = guard

    def unregister_guard(self, name: str) -> bool:
        """Unregister a guard by name.

        Args:
            name: Name of the guard to unregister.

        Returns:
            True if the guard was found and removed.
        """
        with self._lock:
            if name in self.guards:
                del self.guards[name]
                return True
            return False

    def get_guard(self, name: str) -> Optional[BaseGuard]:
        """Get a registered guard by name.

        Args:
            name: Name of the guard.

        Returns:
            The guard instance, or None if not found.
        """
        with self._lock:
            return self.guards.get(name)

    def evaluate(
        self,
        action: str,
        resource: str,
        context: Optional[ExecutionContext] = None,
        guard_names: Optional[List[str]] = None,
    ) -> bool:
        """Evaluate whether an action is allowed.

        Checks both policy rules and registered guards. Deny overrides allow.

        Args:
            action: The action being performed (e.g., "file:read").
            resource: The resource being accessed (e.g., "/etc/passwd").
            context: Optional execution context for evaluation.
            guard_names: Optional list of specific guards to check.
                If None, all registered guards are checked.

        Returns:
            True if the action is allowed, False if denied.

        Raises:
            GuardViolationError: If enforce_mode is enabled on a guard.
        """
        eval_context = context.get_evaluation_context() if context else {}

        # Check policy set
        with self._lock:
            effect = self.policy_set.evaluate(action, resource, eval_context)

        if effect is None:
            effect = self.default_effect

        # Check guards
        guards_to_check = self.guards.values()
        if guard_names is not None:
            guards_to_check = [
                self.guards[name]
                for name in guard_names
                if name in self.guards
            ]

        for guard in guards_to_check:
            guard_result = guard.check(action, resource, eval_context)
            if guard_result is not None and not guard_result.allowed:
                if guard_result.enforce:
                    self._log_decision(
                        context=context,
                        action=action,
                        resource=resource,
                        decision="denied",
                        guard_name=guard.name,
                        details=guard_result.details,
                    )
                    raise GuardViolationError(
                        message=f"Guard '{guard.name}' denied action '{action}' on '{resource}'",
                        guard_name=guard.name,
                        action=action,
                        resource=resource,
                        details=guard_result.details,
                    )
                effect = Effect.DENY

        allowed = effect == Effect.ALLOW
        self._log_decision(
            context=context,
            action=action,
            resource=resource,
            decision="allowed" if allowed else "denied",
            details={"effect": effect.value},
        )

        return allowed

    def check(
        self,
        action: str,
        resource: str,
        context: Optional[ExecutionContext] = None,
    ) -> Effect:
        """Check policy decision without raising exceptions.

        Unlike evaluate(), this method never raises GuardViolationError.
        It returns the policy decision directly.

        Args:
            action: The action being performed.
            resource: The resource being accessed.
            context: Optional execution context.

        Returns:
            Effect.ALLOW if allowed, Effect.DENY if denied.
        """
        try:
            allowed = self.evaluate(action, resource, context)
            return Effect.ALLOW if allowed else Effect.DENY
        except GuardViolationError:
            return Effect.DENY

    def _log_decision(
        self,
        context: Optional[ExecutionContext],
        action: str,
        resource: str,
        decision: str,
        guard_name: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log a policy decision to the audit logger.

        Args:
            context: The execution context.
            action: The action that was evaluated.
            resource: The resource that was accessed.
            decision: The decision made ("allowed" or "denied").
            guard_name: Optional name of the guard that made the decision.
            details: Optional additional details.
        """
        if self.audit_logger:
            self.audit_logger.log(
                agent_id=context.agent_id if context else "unknown",
                action=action,
                resource=resource,
                decision=decision,
                guard_name=guard_name,
                details=details,
                request_id=context.request_id if context else "",
            )

    def enable_hot_reload(self, interval: float = 5.0) -> None:
        """Enable policy hot-reload from the loaded file.

        The engine will periodically check the policy file for changes
        and reload it automatically.

        Args:
            interval: Check interval in seconds.
        """
        if self._policy_file is None:
            raise PolicyLoadError("No policy file loaded; cannot enable hot reload")

        self._hot_reload = True
        self._reload_interval = interval
        self._stop_event.clear()
        self._reload_thread = threading.Thread(
            target=self._reload_loop,
            daemon=True,
            name="agentshield-hot-reload",
        )
        self._reload_thread.start()

    def disable_hot_reload(self) -> None:
        """Disable policy hot-reload."""
        self._hot_reload = False
        self._stop_event.set()
        if self._reload_thread and self._reload_thread.is_alive():
            self._reload_thread.join(timeout=10.0)
        self._reload_thread = None

    def _reload_loop(self) -> None:
        """Background loop for hot-reloading policies."""
        while not self._stop_event.is_set():
            self._stop_event.wait(self._reload_interval)
            if self._stop_event.is_set():
                break
            self._try_reload()

    def _try_reload(self) -> None:
        """Attempt to reload the policy file if it has changed."""
        if self._policy_file is None:
            return
        try:
            current_mtime = os.path.getmtime(self._policy_file)
            if current_mtime > self._policy_mtime:
                with self._lock:
                    policy_set = parse_yaml_policy_file(self._policy_file)
                    self.policy_set = policy_set
                    self._policy_mtime = current_mtime
        except (OSError, PolicyLoadError):
            pass  # Silently ignore reload errors; will retry next interval

    def get_policies_summary(self) -> List[Dict[str, Any]]:
        """Get a summary of all loaded policies.

        Returns:
            List of policy summary dictionaries.
        """
        with self._lock:
            return [
                {
                    "name": p.name,
                    "description": p.description,
                    "effect": p.effect.value,
                    "actions": p.actions,
                    "resources": p.resources,
                    "priority": p.priority,
                    "enabled": p.enabled,
                    "tags": p.tags,
                }
                for p in self.policy_set.policies
            ]

    def get_guards_summary(self) -> List[Dict[str, Any]]:
        """Get a summary of all registered guards.

        Returns:
            List of guard summary dictionaries.
        """
        with self._lock:
            return [
                {
                    "name": guard.name,
                    "description": guard.description,
                    "enforce_mode": guard.enforce_mode,
                }
                for guard in self.guards.values()
            ]

    def shutdown(self) -> None:
        """Shut down the engine, stopping hot-reload and flushing audit logs."""
        self.disable_hot_reload()
        if self.audit_logger:
            self.audit_logger.flush()

    def __repr__(self) -> str:
        return (
            f"PolicyEngine(policies={len(self.policy_set)}, "
            f"guards={len(self.guards)}, "
            f"default_effect={self.default_effect.value!r})"
        )
