"""Policy model, parser, and condition evaluators for AgentShield.

This module defines the Policy and PolicySet classes, YAML policy parsing,
and built-in condition evaluators for matching resources and actions.
"""

import copy
import fnmatch
import os
import re
from enum import Enum
from typing import Any, Dict, List, Optional, Set

try:
    import yaml
except ImportError:
    yaml = None

from agentshield.core.exceptions import PolicyLoadError


class Effect(Enum):
    """Policy effect: allow or deny."""

    ALLOW = "allow"
    DENY = "deny"

    def __str__(self) -> str:
        return self.value


class ConditionOperator(Enum):
    """Supported condition operators."""

    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    REGEX_MATCH = "regex_match"
    REGEX_NOT_MATCH = "regex_not_match"
    GLOB_MATCH = "glob_match"
    GLOB_NOT_MATCH = "glob_not_match"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    GREATER_THAN_OR_EQUAL = "greater_than_or_equal"
    LESS_THAN_OR_EQUAL = "less_than_or_equal"
    IN = "in"
    NOT_IN = "not_in"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"


class Condition:
    """A single condition for policy evaluation.

    Conditions compare a field value against an expected value using
    a specified operator.

    Attributes:
        field: The field name to evaluate (e.g., "path", "domain", "method").
        operator: The comparison operator.
        value: The expected value to compare against.
    """

    def __init__(self, field: str, operator: ConditionOperator, value: Any):
        self.field = field
        self.operator = operator
        self.value = value

    def evaluate(self, context: Dict[str, Any]) -> bool:
        """Evaluate this condition against the given context.

        Args:
            context: A dictionary of field names to values.

        Returns:
            True if the condition is satisfied, False otherwise.

        Raises:
            PolicyEvaluationError: If the evaluation encounters an error.
        """
        actual = context.get(self.field)

        try:
            if self.operator == ConditionOperator.EQUALS:
                return actual == self.value
            elif self.operator == ConditionOperator.NOT_EQUALS:
                return actual != self.value
            elif self.operator == ConditionOperator.CONTAINS:
                return self.value in str(actual) if actual is not None else False
            elif self.operator == ConditionOperator.NOT_CONTAINS:
                return self.value not in str(actual) if actual is not None else True
            elif self.operator == ConditionOperator.REGEX_MATCH:
                if actual is None:
                    return False
                return bool(re.search(str(self.value), str(actual)))
            elif self.operator == ConditionOperator.REGEX_NOT_MATCH:
                if actual is None:
                    return True
                return not bool(re.search(str(self.value), str(actual)))
            elif self.operator == ConditionOperator.GLOB_MATCH:
                if actual is None:
                    return False
                return fnmatch.fnmatch(str(actual), str(self.value))
            elif self.operator == ConditionOperator.GLOB_NOT_MATCH:
                if actual is None:
                    return True
                return not fnmatch.fnmatch(str(actual), str(self.value))
            elif self.operator == ConditionOperator.GREATER_THAN:
                if actual is None:
                    return False
                return float(actual) > float(self.value)
            elif self.operator == ConditionOperator.LESS_THAN:
                if actual is None:
                    return False
                return float(actual) < float(self.value)
            elif self.operator == ConditionOperator.GREATER_THAN_OR_EQUAL:
                if actual is None:
                    return False
                return float(actual) >= float(self.value)
            elif self.operator == ConditionOperator.LESS_THAN_OR_EQUAL:
                if actual is None:
                    return False
                return float(actual) <= float(self.value)
            elif self.operator == ConditionOperator.IN:
                return actual in self.value if isinstance(self.value, (list, set)) else False
            elif self.operator == ConditionOperator.NOT_IN:
                return actual not in self.value if isinstance(self.value, (list, set)) else True
            elif self.operator == ConditionOperator.EXISTS:
                return self.field in context and context[self.field] is not None
            elif self.operator == ConditionOperator.NOT_EXISTS:
                return self.field not in context or context[self.field] is None
            else:
                return False
        except (ValueError, TypeError) as e:
            return False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Condition":
        """Create a Condition from a dictionary.

        Args:
            data: Dictionary with keys 'field', 'operator', and 'value'.

        Returns:
            A Condition instance.

        Raises:
            PolicyLoadError: If the data is malformed.
        """
        field = data.get("field", "")
        operator_str = data.get("operator", "equals")
        value = data.get("value")

        if not field:
            raise PolicyLoadError("Condition must have a 'field' key")

        try:
            operator = ConditionOperator(operator_str)
        except ValueError:
            raise PolicyLoadError(
                f"Unknown condition operator: {operator_str}",
                details={"valid_operators": [op.value for op in ConditionOperator]},
            )

        return cls(field=field, operator=operator, value=value)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize this condition to a dictionary.

        Returns:
            A dictionary representation of this condition.
        """
        return {
            "field": self.field,
            "operator": self.operator.value,
            "value": self.value,
        }

    def __repr__(self) -> str:
        return f"Condition(field={self.field!r}, operator={self.operator.value!r}, value={self.value!r})"


class Policy:
    """A single policy rule.

    A policy defines whether an action on a resource is allowed or denied,
    optionally with conditions that must be satisfied.

    Attributes:
        name: Unique policy name.
        description: Human-readable description.
        effect: ALLOW or DENY.
        actions: List of action patterns (supports glob).
        resources: List of resource patterns (supports glob).
        conditions: List of Condition objects that must all be satisfied.
        priority: Higher priority policies are evaluated first.
        enabled: Whether this policy is active.
        tags: Optional tags for categorization.
    """

    def __init__(
        self,
        name: str,
        effect: Effect,
        actions: Optional[List[str]] = None,
        resources: Optional[List[str]] = None,
        conditions: Optional[List[Condition]] = None,
        description: str = "",
        priority: int = 0,
        enabled: bool = True,
        tags: Optional[List[str]] = None,
    ):
        self.name = name
        self.description = description
        self.effect = effect
        self.actions = actions or ["*"]
        self.resources = resources or ["*"]
        self.conditions = conditions or []
        self.priority = priority
        self.enabled = enabled
        self.tags = tags or []

    def matches_action(self, action: str) -> bool:
        """Check if the given action matches any of this policy's action patterns.

        Args:
            action: The action string to check.

        Returns:
            True if the action matches any pattern.
        """
        return any(fnmatch.fnmatch(action, pattern) for pattern in self.actions)

    def matches_resource(self, resource: str) -> bool:
        """Check if the given resource matches any of this policy's resource patterns.

        Args:
            resource: The resource string to check.

        Returns:
            True if the resource matches any pattern.
        """
        return any(fnmatch.fnmatch(resource, pattern) for pattern in self.resources)

    def evaluate_conditions(self, context: Dict[str, Any]) -> bool:
        """Evaluate all conditions against the given context.

        All conditions must be satisfied (AND logic).

        Args:
            context: A dictionary of field names to values.

        Returns:
            True if all conditions are satisfied or no conditions exist.
        """
        if not self.conditions:
            return True
        return all(condition.evaluate(context) for condition in self.conditions)

    def matches(self, action: str, resource: str, context: Optional[Dict[str, Any]] = None) -> bool:
        """Check if this policy applies to the given action, resource, and context.

        Args:
            action: The action being performed.
            resource: The resource being accessed.
            context: Optional context dictionary for condition evaluation.

        Returns:
            True if the policy matches and all conditions are satisfied.
        """
        if not self.enabled:
            return False
        if not self.matches_action(action):
            return False
        if not self.matches_resource(resource):
            return False
        eval_context = dict(context or {})
        eval_context["action"] = action
        eval_context["resource"] = resource
        return self.evaluate_conditions(eval_context)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize this policy to a dictionary.

        Returns:
            A dictionary representation of this policy.
        """
        return {
            "name": self.name,
            "description": self.description,
            "effect": self.effect.value,
            "actions": self.actions,
            "resources": self.resources,
            "conditions": [c.to_dict() for c in self.conditions],
            "priority": self.priority,
            "enabled": self.enabled,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Policy":
        """Create a Policy from a dictionary.

        Args:
            data: Dictionary with policy configuration.

        Returns:
            A Policy instance.

        Raises:
            PolicyLoadError: If the data is malformed.
        """
        name = data.get("name", "")
        if not name:
            raise PolicyLoadError("Policy must have a 'name' key")

        effect_str = data.get("effect", "deny")
        try:
            effect = Effect(effect_str)
        except ValueError:
            raise PolicyLoadError(
                f"Unknown effect: {effect_str}. Must be 'allow' or 'deny'.",
                details={"policy_name": name},
            )

        conditions_data = data.get("conditions", [])
        conditions = [Condition.from_dict(cd) for cd in conditions_data]

        return cls(
            name=name,
            effect=effect,
            actions=data.get("actions", ["*"]),
            resources=data.get("resources", ["*"]),
            conditions=conditions,
            description=data.get("description", ""),
            priority=data.get("priority", 0),
            enabled=data.get("enabled", True),
            tags=data.get("tags", []),
        )

    def __repr__(self) -> str:
        return (
            f"Policy(name={self.name!r}, effect={self.effect.value!r}, "
            f"priority={self.priority!r}, enabled={self.enabled!r})"
        )


class PolicySet:
    """A collection of policies with evaluation semantics.

    PolicySet supports deny-override precedence: if any matching policy
    denies an action, the action is denied regardless of allow policies.

    Attributes:
        name: Name of this policy set.
        description: Human-readable description.
        policies: List of Policy objects.
    """

    def __init__(
        self,
        name: str = "default",
        description: str = "",
        policies: Optional[List[Policy]] = None,
    ):
        self.name = name
        self.description = description
        self.policies: List[Policy] = list(policies or [])

    def add_policy(self, policy: Policy) -> None:
        """Add a policy to this set.

        Args:
            policy: The Policy to add.
        """
        self.policies.append(policy)

    def remove_policy(self, name: str) -> bool:
        """Remove a policy by name.

        Args:
            name: Name of the policy to remove.

        Returns:
            True if the policy was found and removed, False otherwise.
        """
        for i, p in enumerate(self.policies):
            if p.name == name:
                self.policies.pop(i)
                return True
        return False

    def get_policy(self, name: str) -> Optional[Policy]:
        """Get a policy by name.

        Args:
            name: Name of the policy to find.

        Returns:
            The Policy if found, None otherwise.
        """
        for p in self.policies:
            if p.name == name:
                return p
        return None

    def evaluate(
        self,
        action: str,
        resource: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[Effect]:
        """Evaluate all policies and return the decision.

        Policies are sorted by priority (highest first). Deny overrides allow:
        if any matching deny policy is found, the action is denied.

        Args:
            action: The action being performed.
            resource: The resource being accessed.
            context: Optional context for condition evaluation.

        Returns:
            Effect.ALLOW if allowed, Effect.DENY if denied, None if no policy matches.
        """
        sorted_policies = sorted(
            [p for p in self.policies if p.enabled],
            key=lambda p: p.priority,
            reverse=True,
        )

        matched_policies = []
        for policy in sorted_policies:
            if policy.matches(action, resource, context):
                matched_policies.append(policy)

        if not matched_policies:
            return None

        # Deny overrides allow
        for policy in matched_policies:
            if policy.effect == Effect.DENY:
                return Effect.DENY

        return Effect.ALLOW

    def get_matching_policies(
        self,
        action: str,
        resource: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Policy]:
        """Get all policies that match the given action and resource.

        Args:
            action: The action being performed.
            resource: The resource being accessed.
            context: Optional context for condition evaluation.

        Returns:
            List of matching Policy objects, sorted by priority (highest first).
        """
        sorted_policies = sorted(
            [p for p in self.policies if p.enabled],
            key=lambda p: p.priority,
            reverse=True,
        )
        return [
            p for p in sorted_policies if p.matches(action, resource, context)
        ]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize this policy set to a dictionary.

        Returns:
            A dictionary representation of this policy set.
        """
        return {
            "name": self.name,
            "description": self.description,
            "policies": [p.to_dict() for p in self.policies],
        }

    def __len__(self) -> int:
        return len(self.policies)

    def __iter__(self):
        return iter(self.policies)

    def __repr__(self) -> str:
        return f"PolicySet(name={self.name!r}, policies={len(self.policies)})"


def parse_yaml_policy_file(file_path: str) -> PolicySet:
    """Parse a YAML policy file into a PolicySet.

    The YAML file should have the following structure::

        name: my_policy_set
        description: My policy set
        policies:
          - name: deny_etc_access
            effect: deny
            actions: ["file:read", "file:write"]
            resources: ["/etc/*"]
            priority: 100

    Args:
        file_path: Path to the YAML policy file.

    Returns:
        A PolicySet parsed from the file.

    Raises:
        PolicyLoadError: If the file cannot be read or parsed.
    """
    if yaml is None:
        raise PolicyLoadError(
            "PyYAML is required to parse YAML policy files. "
            "Install it with: pip install pyyaml"
        )

    if not os.path.exists(file_path):
        raise PolicyLoadError(
            f"Policy file not found: {file_path}",
            file_path=file_path,
        )

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise PolicyLoadError(
            f"Failed to parse YAML: {e}",
            file_path=file_path,
        )
    except IOError as e:
        raise PolicyLoadError(
            f"Failed to read file: {e}",
            file_path=file_path,
        )

    if not isinstance(data, dict):
        raise PolicyLoadError(
            "Policy file must contain a YAML mapping at the top level",
            file_path=file_path,
        )

    return parse_yaml_policy_data(data, file_path=file_path)


def parse_yaml_policy_data(data: Dict[str, Any], file_path: str = "") -> PolicySet:
    """Parse YAML policy data (already loaded) into a PolicySet.

    Args:
        data: Dictionary of policy data.
        file_path: Optional file path for error reporting.

    Returns:
        A PolicySet parsed from the data.

    Raises:
        PolicyLoadError: If the data is malformed.
    """
    name = data.get("name", "unnamed")
    description = data.get("description", "")
    policies_data = data.get("policies", [])

    if not isinstance(policies_data, list):
        raise PolicyLoadError(
            "'policies' must be a list",
            file_path=file_path,
        )

    policies = []
    for i, pdata in enumerate(policies_data):
        if not isinstance(pdata, dict):
            raise PolicyLoadError(
                f"Policy at index {i} must be a mapping",
                file_path=file_path,
            )
        try:
            policy = Policy.from_dict(pdata)
            policies.append(policy)
        except PolicyLoadError as e:
            raise PolicyLoadError(
                f"Error in policy at index {i}: {e}",
                file_path=file_path,
            )

    return PolicySet(
        name=name,
        description=description,
        policies=policies,
    )


def parse_yaml_string(yaml_string: str) -> PolicySet:
    """Parse a YAML string into a PolicySet.

    Args:
        yaml_string: YAML-formatted string.

    Returns:
        A PolicySet parsed from the string.

    Raises:
        PolicyLoadError: If the string cannot be parsed.
    """
    if yaml is None:
        raise PolicyLoadError(
            "PyYAML is required to parse YAML policy files. "
            "Install it with: pip install pyyaml"
        )

    try:
        data = yaml.safe_load(yaml_string)
    except yaml.YAMLError as e:
        raise PolicyLoadError(f"Failed to parse YAML string: {e}")

    if not isinstance(data, dict):
        raise PolicyLoadError("YAML string must contain a mapping at the top level")

    return parse_yaml_policy_data(data)
