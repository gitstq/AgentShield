"""Tests for the PolicyEngine and Policy model."""

import os
import sys
import tempfile
import threading
import unittest

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentshield.core.engine import PolicyEngine
from agentshield.core.exceptions import (
    GuardViolationError,
    PolicyLoadError,
    PolicyEvaluationError,
)
from agentshield.core.policy import (
    Condition,
    ConditionOperator,
    Effect,
    Policy,
    PolicySet,
    parse_yaml_string,
)
from agentshield.core.context import ExecutionContext
from agentshield.audit.logger import AuditLogger


class TestCondition(unittest.TestCase):
    """Tests for the Condition class."""

    def test_equals_operator(self):
        """Test the equals condition operator."""
        cond = Condition("method", ConditionOperator.EQUALS, "GET")
        self.assertTrue(cond.evaluate({"method": "GET"}))
        self.assertFalse(cond.evaluate({"method": "POST"}))
        self.assertFalse(cond.evaluate({}))

    def test_not_equals_operator(self):
        """Test the not_equals condition operator."""
        cond = Condition("method", ConditionOperator.NOT_EQUALS, "GET")
        self.assertFalse(cond.evaluate({"method": "GET"}))
        self.assertTrue(cond.evaluate({"method": "POST"}))

    def test_contains_operator(self):
        """Test the contains condition operator."""
        cond = Condition("path", ConditionOperator.CONTAINS, "etc")
        self.assertTrue(cond.evaluate({"path": "/etc/passwd"}))
        self.assertFalse(cond.evaluate({"path": "/tmp/data"}))

    def test_regex_match_operator(self):
        """Test the regex_match condition operator."""
        cond = Condition("path", ConditionOperator.REGEX_MATCH, r"^/etc/.*")
        self.assertTrue(cond.evaluate({"path": "/etc/passwd"}))
        self.assertFalse(cond.evaluate({"path": "/tmp/data"}))

    def test_glob_match_operator(self):
        """Test the glob_match condition operator."""
        cond = Condition("path", ConditionOperator.GLOB_MATCH, "/etc/*")
        self.assertTrue(cond.evaluate({"path": "/etc/passwd"}))
        self.assertFalse(cond.evaluate({"path": "/tmp/data"}))

    def test_greater_than_operator(self):
        """Test the greater_than condition operator."""
        cond = Condition("size", ConditionOperator.GREATER_THAN, 100)
        self.assertTrue(cond.evaluate({"size": 200}))
        self.assertFalse(cond.evaluate({"size": 50}))

    def test_less_than_operator(self):
        """Test the less_than condition operator."""
        cond = Condition("size", ConditionOperator.LESS_THAN, 100)
        self.assertTrue(cond.evaluate({"size": 50}))
        self.assertFalse(cond.evaluate({"size": 200}))

    def test_in_operator(self):
        """Test the in condition operator."""
        cond = Condition("method", ConditionOperator.IN, ["GET", "POST"])
        self.assertTrue(cond.evaluate({"method": "GET"}))
        self.assertTrue(cond.evaluate({"method": "POST"}))
        self.assertFalse(cond.evaluate({"method": "DELETE"}))

    def test_exists_operator(self):
        """Test the exists condition operator."""
        cond = Condition("path", ConditionOperator.EXISTS, None)
        self.assertTrue(cond.evaluate({"path": "/etc/passwd"}))
        self.assertFalse(cond.evaluate({"method": "GET"}))

    def test_not_exists_operator(self):
        """Test the not_exists condition operator."""
        cond = Condition("path", ConditionOperator.NOT_EXISTS, None)
        self.assertFalse(cond.evaluate({"path": "/etc/passwd"}))
        self.assertTrue(cond.evaluate({"method": "GET"}))

    def test_from_dict(self):
        """Test creating a Condition from a dictionary."""
        data = {"field": "method", "operator": "equals", "value": "GET"}
        cond = Condition.from_dict(data)
        self.assertEqual(cond.field, "method")
        self.assertEqual(cond.operator, ConditionOperator.EQUALS)
        self.assertEqual(cond.value, "GET")

    def test_from_dict_missing_field(self):
        """Test that from_dict raises on missing field."""
        with self.assertRaises(PolicyLoadError):
            Condition.from_dict({"operator": "equals", "value": "GET"})

    def test_from_dict_unknown_operator(self):
        """Test that from_dict raises on unknown operator."""
        with self.assertRaises(PolicyLoadError):
            Condition.from_dict({"field": "x", "operator": "unknown_op", "value": "y"})

    def test_to_dict(self):
        """Test serializing a Condition to a dictionary."""
        cond = Condition("method", ConditionOperator.EQUALS, "GET")
        d = cond.to_dict()
        self.assertEqual(d["field"], "method")
        self.assertEqual(d["operator"], "equals")
        self.assertEqual(d["value"], "GET")


class TestPolicy(unittest.TestCase):
    """Tests for the Policy class."""

    def test_create_policy(self):
        """Test basic policy creation."""
        p = Policy(
            name="test_policy",
            effect=Effect.DENY,
            actions=["file:read"],
            resources=["/etc/*"],
        )
        self.assertEqual(p.name, "test_policy")
        self.assertEqual(p.effect, Effect.DENY)
        self.assertEqual(p.actions, ["file:read"])
        self.assertEqual(p.resources, ["/etc/*"])
        self.assertTrue(p.enabled)

    def test_matches_action(self):
        """Test action matching with glob patterns."""
        p = Policy(name="test", effect=Effect.DENY, actions=["file:*"])
        self.assertTrue(p.matches_action("file:read"))
        self.assertTrue(p.matches_action("file:write"))
        self.assertFalse(p.matches_action("http:request"))

    def test_matches_resource(self):
        """Test resource matching with glob patterns."""
        p = Policy(name="test", effect=Effect.DENY, resources=["/etc/*"])
        self.assertTrue(p.matches_resource("/etc/passwd"))
        self.assertFalse(p.matches_resource("/tmp/data"))

    def test_evaluate_conditions_empty(self):
        """Test that empty conditions always pass."""
        p = Policy(name="test", effect=Effect.DENY)
        self.assertTrue(p.evaluate_conditions({}))

    def test_evaluate_conditions_with_conditions(self):
        """Test condition evaluation."""
        conditions = [
            Condition("method", ConditionOperator.EQUALS, "GET"),
        ]
        p = Policy(name="test", effect=Effect.DENY, conditions=conditions)
        self.assertTrue(p.evaluate_conditions({"method": "GET"}))
        self.assertFalse(p.evaluate_conditions({"method": "POST"}))

    def test_matches_full(self):
        """Test full policy matching."""
        p = Policy(
            name="test",
            effect=Effect.DENY,
            actions=["file:read"],
            resources=["/etc/*"],
        )
        self.assertTrue(p.matches("file:read", "/etc/passwd"))
        self.assertFalse(p.matches("file:read", "/tmp/data"))
        self.assertFalse(p.matches("http:request", "/etc/passwd"))

    def test_disabled_policy(self):
        """Test that disabled policies don't match."""
        p = Policy(
            name="test",
            effect=Effect.DENY,
            actions=["file:read"],
            resources=["/etc/*"],
            enabled=False,
        )
        self.assertFalse(p.matches("file:read", "/etc/passwd"))

    def test_from_dict(self):
        """Test creating a Policy from a dictionary."""
        data = {
            "name": "test_policy",
            "effect": "deny",
            "actions": ["file:read"],
            "resources": ["/etc/*"],
            "description": "Test policy",
            "priority": 50,
        }
        p = Policy.from_dict(data)
        self.assertEqual(p.name, "test_policy")
        self.assertEqual(p.effect, Effect.DENY)
        self.assertEqual(p.priority, 50)

    def test_from_dict_missing_name(self):
        """Test that from_dict raises on missing name."""
        with self.assertRaises(PolicyLoadError):
            Policy.from_dict({"effect": "deny"})

    def test_to_dict(self):
        """Test serializing a Policy to a dictionary."""
        p = Policy(name="test", effect=Effect.ALLOW, actions=["file:read"])
        d = p.to_dict()
        self.assertEqual(d["name"], "test")
        self.assertEqual(d["effect"], "allow")
        self.assertEqual(d["actions"], ["file:read"])


class TestPolicySet(unittest.TestCase):
    """Tests for the PolicySet class."""

    def test_create_policy_set(self):
        """Test basic PolicySet creation."""
        ps = PolicySet(name="test_set")
        self.assertEqual(ps.name, "test_set")
        self.assertEqual(len(ps), 0)

    def test_add_and_remove_policy(self):
        """Test adding and removing policies."""
        ps = PolicySet()
        p = Policy(name="test", effect=Effect.DENY)
        ps.add_policy(p)
        self.assertEqual(len(ps), 1)
        self.assertTrue(ps.remove_policy("test"))
        self.assertEqual(len(ps), 0)

    def test_remove_nonexistent_policy(self):
        """Test removing a policy that doesn't exist."""
        ps = PolicySet()
        self.assertFalse(ps.remove_policy("nonexistent"))

    def test_get_policy(self):
        """Test getting a policy by name."""
        ps = PolicySet()
        p = Policy(name="test", effect=Effect.DENY)
        ps.add_policy(p)
        self.assertEqual(ps.get_policy("test"), p)
        self.assertIsNone(ps.get_policy("nonexistent"))

    def test_evaluate_deny_overrides_allow(self):
        """Test that deny overrides allow."""
        ps = PolicySet()
        ps.add_policy(Policy(
            name="allow_all",
            effect=Effect.ALLOW,
            actions=["*"],
            resources=["*"],
            priority=0,
        ))
        ps.add_policy(Policy(
            name="deny_etc",
            effect=Effect.DENY,
            actions=["file:read"],
            resources=["/etc/*"],
            priority=100,
        ))
        result = ps.evaluate("file:read", "/etc/passwd")
        self.assertEqual(result, Effect.DENY)

    def test_evaluate_allow_when_no_deny(self):
        """Test that allow works when no deny matches."""
        ps = PolicySet()
        ps.add_policy(Policy(
            name="allow_tmp",
            effect=Effect.ALLOW,
            actions=["file:read"],
            resources=["/tmp/*"],
            priority=0,
        ))
        result = ps.evaluate("file:read", "/tmp/data")
        self.assertEqual(result, Effect.ALLOW)

    def test_evaluate_no_match(self):
        """Test that no match returns None."""
        ps = PolicySet()
        ps.add_policy(Policy(
            name="deny_etc",
            effect=Effect.DENY,
            actions=["file:read"],
            resources=["/etc/*"],
        ))
        result = ps.evaluate("file:read", "/tmp/data")
        self.assertIsNone(result)

    def test_evaluate_with_conditions(self):
        """Test evaluation with conditions."""
        ps = PolicySet()
        ps.add_policy(Policy(
            name="deny_get",
            effect=Effect.DENY,
            actions=["http:get"],
            resources=["*"],
            conditions=[
                Condition("domain", ConditionOperator.EQUALS, "internal.corp"),
            ],
        ))
        # Should deny when condition matches
        result = ps.evaluate("http:get", "https://internal.corp/api", {"domain": "internal.corp"})
        self.assertEqual(result, Effect.DENY)
        # Should not match when condition doesn't match
        result = ps.evaluate("http:get", "https://example.com/api", {"domain": "example.com"})
        self.assertIsNone(result)

    def test_get_matching_policies(self):
        """Test getting matching policies."""
        ps = PolicySet()
        ps.add_policy(Policy(name="p1", effect=Effect.ALLOW, actions=["file:read"], resources=["/tmp/*"]))
        ps.add_policy(Policy(name="p2", effect=Effect.DENY, actions=["file:read"], resources=["/etc/*"]))
        matching = ps.get_matching_policies("file:read", "/tmp/data")
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0].name, "p1")

    def test_to_dict(self):
        """Test serializing a PolicySet."""
        ps = PolicySet(name="test")
        ps.add_policy(Policy(name="p1", effect=Effect.ALLOW))
        d = ps.to_dict()
        self.assertEqual(d["name"], "test")
        self.assertEqual(len(d["policies"]), 1)


class TestParseYaml(unittest.TestCase):
    """Tests for YAML policy parsing."""

    def test_parse_yaml_string(self):
        """Test parsing a YAML string."""
        yaml_str = """
name: test_set
description: Test policy set
policies:
  - name: deny_etc
    effect: deny
    actions: ["file:read"]
    resources: ["/etc/*"]
    priority: 100
  - name: allow_tmp
    effect: allow
    actions: ["file:read"]
    resources: ["/tmp/*"]
    priority: 10
"""
        ps = parse_yaml_string(yaml_str)
        self.assertEqual(ps.name, "test_set")
        self.assertEqual(len(ps), 2)
        self.assertEqual(ps.policies[0].name, "deny_etc")
        self.assertEqual(ps.policies[1].name, "allow_tmp")

    def test_parse_yaml_with_conditions(self):
        """Test parsing YAML with conditions."""
        yaml_str = """
name: test
policies:
  - name: conditional_deny
    effect: deny
    actions: ["http:get"]
    resources: ["*"]
    conditions:
      - field: domain
        operator: equals
        value: internal.corp
"""
        ps = parse_yaml_string(yaml_str)
        self.assertEqual(len(ps), 1)
        self.assertEqual(len(ps.policies[0].conditions), 1)


class TestPolicyEngine(unittest.TestCase):
    """Tests for the PolicyEngine class."""

    def setUp(self):
        """Set up test fixtures."""
        self.engine = PolicyEngine()
        self.audit = AuditLogger()
        self.engine.audit_logger = self.audit

    def tearDown(self):
        """Clean up test fixtures."""
        self.engine.shutdown()

    def test_create_engine(self):
        """Test basic engine creation."""
        self.assertIsNotNone(self.engine)
        self.assertEqual(len(self.engine.policy_set), 0)

    def test_load_policy_set(self):
        """Test loading a PolicySet."""
        ps = PolicySet(name="test")
        ps.add_policy(Policy(name="p1", effect=Effect.ALLOW, actions=["file:read"], resources=["/tmp/*"]))
        self.engine.load_policy_set(ps)
        self.assertEqual(self.engine.policy_set.name, "test")
        self.assertEqual(len(self.engine.policy_set), 1)

    def test_evaluate_allow(self):
        """Test that evaluate returns True for allowed actions."""
        self.engine.add_policy(Policy(
            name="allow_tmp",
            effect=Effect.ALLOW,
            actions=["file:read"],
            resources=["/tmp/*"],
        ))
        result = self.engine.evaluate("file:read", "/tmp/data")
        self.assertTrue(result)

    def test_evaluate_deny(self):
        """Test that evaluate returns False for denied actions."""
        self.engine.add_policy(Policy(
            name="deny_etc",
            effect=Effect.DENY,
            actions=["file:read"],
            resources=["/etc/*"],
        ))
        result = self.engine.evaluate("file:read", "/etc/passwd")
        self.assertFalse(result)

    def test_evaluate_default_deny(self):
        """Test that default effect is deny when no policy matches."""
        result = self.engine.evaluate("file:read", "/some/path")
        self.assertFalse(result)

    def test_evaluate_with_context(self):
        """Test evaluation with execution context."""
        self.engine.add_policy(Policy(
            name="allow_specific_agent",
            effect=Effect.ALLOW,
            actions=["file:read"],
            resources=["*"],
            conditions=[
                Condition("agent_id", ConditionOperator.EQUALS, "trusted_agent"),
            ],
        ))
        ctx = ExecutionContext(action="file:read", resource="/etc/passwd", agent_id="trusted_agent")
        result = self.engine.evaluate("file:read", "/etc/passwd", ctx)
        self.assertTrue(result)

    def test_check_method(self):
        """Test the check method (non-exception)."""
        self.engine.add_policy(Policy(
            name="deny_all",
            effect=Effect.DENY,
            actions=["*"],
            resources=["*"],
        ))
        result = self.engine.check("file:read", "/etc/passwd")
        self.assertEqual(result, Effect.DENY)

    def test_register_guard(self):
        """Test guard registration."""
        from agentshield.guards.file_guard import FileGuard
        guard = FileGuard()
        self.engine.register_guard("file", guard)
        self.assertIsNotNone(self.engine.get_guard("file"))
        self.assertEqual(len(self.engine.guards), 1)

    def test_unregister_guard(self):
        """Test guard unregistration."""
        from agentshield.guards.file_guard import FileGuard
        guard = FileGuard()
        self.engine.register_guard("file", guard)
        self.assertTrue(self.engine.unregister_guard("file"))
        self.assertIsNone(self.engine.get_guard("file"))

    def test_evaluate_with_guard(self):
        """Test evaluation with a registered guard."""
        from agentshield.guards.file_guard import FileGuard
        guard = FileGuard(
            denied_paths=["/etc/*"],
            allow_by_default=True,
        )
        self.engine.register_guard("file", guard)
        self.engine.add_policy(Policy(
            name="allow_all",
            effect=Effect.ALLOW,
            actions=["*"],
            resources=["*"],
        ))
        # Guard should deny /etc/passwd
        with self.assertRaises(GuardViolationError):
            self.engine.evaluate("file:read", "/etc/passwd")

    def test_get_policies_summary(self):
        """Test getting policies summary."""
        self.engine.add_policy(Policy(name="p1", effect=Effect.ALLOW))
        summary = self.engine.get_policies_summary()
        self.assertEqual(len(summary), 1)
        self.assertEqual(summary[0]["name"], "p1")

    def test_get_guards_summary(self):
        """Test getting guards summary."""
        from agentshield.guards.file_guard import FileGuard
        self.engine.register_guard("file", FileGuard())
        summary = self.engine.get_guards_summary()
        self.assertEqual(len(summary), 1)

    def test_thread_safety(self):
        """Test that the engine is thread-safe."""
        self.engine.add_policy(Policy(
            name="allow_tmp",
            effect=Effect.ALLOW,
            actions=["file:read"],
            resources=["/tmp/*"],
        ))

        results = []
        errors = []

        def evaluate():
            try:
                for _ in range(100):
                    result = self.engine.evaluate("file:read", "/tmp/data")
                    results.append(result)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=evaluate) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0)
        self.assertTrue(all(r is True for r in results))

    def test_load_policy_file(self):
        """Test loading policies from a YAML file."""
        yaml_content = """
name: file_test
policies:
  - name: allow_tmp
    effect: allow
    actions: ["file:read"]
    resources: ["/tmp/*"]
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            temp_path = f.name

        try:
            self.engine.load_policy_file(temp_path)
            self.assertEqual(self.engine.policy_set.name, "file_test")
            self.assertEqual(len(self.engine.policy_set), 1)
        finally:
            os.unlink(temp_path)


class TestExecutionContext(unittest.TestCase):
    """Tests for the ExecutionContext class."""

    def test_create_context(self):
        """Test basic context creation."""
        ctx = ExecutionContext(
            action="file:read",
            resource="/tmp/data",
            agent_id="test_agent",
        )
        self.assertEqual(ctx.action, "file:read")
        self.assertEqual(ctx.resource, "/tmp/data")
        self.assertEqual(ctx.agent_id, "test_agent")
        self.assertIsNotNone(ctx.request_id)

    def test_to_dict(self):
        """Test serializing context to dict."""
        ctx = ExecutionContext(action="test", resource="res")
        d = ctx.to_dict()
        self.assertEqual(d["action"], "test")
        self.assertEqual(d["resource"], "res")

    def test_get_evaluation_context(self):
        """Test getting evaluation context."""
        ctx = ExecutionContext(
            action="file:read",
            resource="/tmp/data",
            agent_id="agent1",
            metadata={"method": "GET"},
        )
        eval_ctx = ctx.get_evaluation_context()
        self.assertEqual(eval_ctx["action"], "file:read")
        self.assertEqual(eval_ctx["resource"], "/tmp/data")
        self.assertEqual(eval_ctx["agent_id"], "agent1")
        self.assertEqual(eval_ctx["method"], "GET")

    def test_create_child(self):
        """Test creating a child context."""
        parent = ExecutionContext(action="file:read", resource="/tmp/data", agent_id="agent1")
        child = parent.create_child(resource="/tmp/other")
        self.assertEqual(child.action, "file:read")
        self.assertEqual(child.resource, "/tmp/other")
        self.assertEqual(child.agent_id, "agent1")
        self.assertEqual(child.parent_id, parent.request_id)

    def test_context_manager(self):
        """Test context manager support."""
        ctx = ExecutionContext(action="test")
        with ctx as c:
            self.assertEqual(ExecutionContext.get_current(), ctx)
        self.assertIsNone(ExecutionContext.get_current())

    def test_nested_context_manager(self):
        """Test nested context manager support."""
        outer = ExecutionContext(action="outer")
        inner = ExecutionContext(action="inner")
        with outer:
            self.assertEqual(ExecutionContext.get_current(), outer)
            with inner:
                self.assertEqual(ExecutionContext.get_current(), inner)
            self.assertEqual(ExecutionContext.get_current(), outer)
        self.assertIsNone(ExecutionContext.get_current())


if __name__ == "__main__":
    unittest.main()
