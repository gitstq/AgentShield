"""Tests for the decorator API."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentshield.core.engine import PolicyEngine
from agentshield.core.policy import Effect, Policy, PolicySet
from agentshield.core.context import ExecutionContext
from agentshield.decorators import (
    PolicyContext,
    audit,
    guard,
    shield,
    set_default_engine,
)
from agentshield.guards.file_guard import FileGuard


class TestShieldDecorator(unittest.TestCase):
    """Tests for the @shield decorator."""

    def setUp(self):
        self.engine = PolicyEngine()
        self.engine.add_policy(Policy(
            name="allow_functions",
            effect=Effect.ALLOW,
            actions=["function:*"],
            resources=["*"],
        ))
        set_default_engine(self.engine)

    def tearDown(self):
        self.engine.shutdown()

    def test_shield_allows(self):
        """Test that @shield allows execution when policy permits."""
        @shield(engine=self.engine)
        def my_function():
            return "success"

        result = my_function()
        self.assertEqual(result, "success")

    def test_shield_denies(self):
        """Test that @shield raises PermissionError when policy denies."""
        engine = PolicyEngine(default_effect=Effect.DENY)
        engine.add_policy(Policy(
            name="deny_all",
            effect=Effect.DENY,
            actions=["*"],
            resources=["*"],
        ))

        @shield(engine=engine)
        def blocked_function():
            return "should not reach"

        with self.assertRaises(PermissionError):
            blocked_function()

    def test_shield_preserves_function_name(self):
        """Test that @shield preserves function metadata."""
        @shield(engine=self.engine)
        def my_function():
            """My docstring."""
            pass

        self.assertEqual(my_function.__name__, "my_function")
        self.assertEqual(my_function.__doc__, "My docstring.")

    def test_shield_with_guard_violation(self):
        """Test that @shield handles guard violations."""
        engine = PolicyEngine()
        engine.add_policy(Policy(
            name="allow_all",
            effect=Effect.ALLOW,
            actions=["*"],
            resources=["*"],
        ))
        file_guard = FileGuard(
            denied_paths=["/etc/*"],
            allow_by_default=True,
        )
        engine.register_guard("file", file_guard)

        @shield(policy="balanced", engine=engine, action="file:read", resource="/etc/passwd")
        def blocked_function():
            return "should not reach"

        with self.assertRaises(PermissionError):
            blocked_function()

    def test_shield_custom_action_resource(self):
        """Test @shield with custom action and resource."""
        engine = PolicyEngine()
        engine.add_policy(Policy(
            name="allow_custom",
            effect=Effect.ALLOW,
            actions=["custom:action"],
            resources=["custom_resource"],
        ))

        @shield(engine=engine, action="custom:action", resource="custom_resource")
        def my_function():
            return "success"

        result = my_function()
        self.assertEqual(result, "success")


class TestGuardDecorator(unittest.TestCase):
    """Tests for the @guard decorator."""

    def setUp(self):
        self.engine = PolicyEngine()
        self.engine.add_policy(Policy(
            name="allow_all",
            effect=Effect.ALLOW,
            actions=["*"],
            resources=["*"],
        ))
        file_guard = FileGuard(
            denied_paths=["/etc/*"],
            allowed_paths=["/tmp/*"],
            allow_by_default=True,
        )
        self.engine.register_guard("file", file_guard)
        set_default_engine(self.engine)

    def tearDown(self):
        self.engine.shutdown()

    def test_guard_allows(self):
        """Test that @guard allows when guard permits."""
        @guard("file", engine=self.engine, action="file:read", resource="/tmp/data")
        def read_file():
            return "success"

        result = read_file()
        self.assertEqual(result, "success")

    def test_guard_denies(self):
        """Test that @guard raises PermissionError when guard denies."""
        @guard("file", engine=self.engine, action="file:read", resource="/etc/passwd")
        def read_file():
            return "should not reach"

        with self.assertRaises(PermissionError):
            read_file()

    def test_guard_preserves_name(self):
        """Test that @guard preserves function metadata."""
        @guard("file", engine=self.engine, action="file:read", resource="/tmp/data")
        def my_func():
            pass

        self.assertEqual(my_func.__name__, "my_func")


class TestAuditDecorator(unittest.TestCase):
    """Tests for the @audit decorator."""

    def setUp(self):
        self.engine = PolicyEngine()
        set_default_engine(self.engine)

    def tearDown(self):
        self.engine.shutdown()

    def test_audit_logs_call(self):
        """Test that @audit logs function calls."""
        @audit(action="custom_action", resource="my_func", engine=self.engine)
        def my_func():
            return "result"

        my_func()
        entries = self.engine.audit_logger.get_entries(action="custom_action")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["decision"], "allowed")

    def test_audit_preserves_result(self):
        """Test that @audit doesn't affect function return value."""
        @audit(engine=self.engine)
        def add(a, b):
            return a + b

        result = add(2, 3)
        self.assertEqual(result, 5)

    def test_audit_preserves_name(self):
        """Test that @audit preserves function metadata."""
        @audit(engine=self.engine)
        def my_func():
            """Docstring."""
            pass

        self.assertEqual(my_func.__name__, "my_func")
        self.assertEqual(my_func.__doc__, "Docstring.")


class TestPolicyContext(unittest.TestCase):
    """Tests for the PolicyContext context manager."""

    def setUp(self):
        self.engine = PolicyEngine()
        self.engine.add_policy(Policy(
            name="allow_all",
            effect=Effect.ALLOW,
            actions=["*"],
            resources=["*"],
        ))
        set_default_engine(self.engine)

    def tearDown(self):
        self.engine.shutdown()

    def test_context_manager_allows(self):
        """Test that PolicyContext allows when policy permits."""
        with PolicyContext(
            policy="balanced",
            action="file:read",
            resource="/tmp/data",
            engine=self.engine,
        ):
            ctx = ExecutionContext.get_current()
            self.assertIsNotNone(ctx)

    def test_context_manager_denies(self):
        """Test that PolicyContext raises PermissionError when policy denies."""
        engine = PolicyEngine(default_effect=Effect.DENY)

        with self.assertRaises(PermissionError):
            with PolicyContext(
                policy="strict",
                action="file:read",
                resource="/etc/passwd",
                engine=engine,
            ):
                pass

    def test_context_manager_restores(self):
        """Test that PolicyContext restores previous context."""
        outer = ExecutionContext(action="outer", resource="outer")
        with outer:
            self.assertEqual(ExecutionContext.get_current(), outer)
            with PolicyContext(
                policy="permissive",
                action="inner",
                resource="inner",
                engine=self.engine,
            ):
                ctx = ExecutionContext.get_current()
                self.assertIsNotNone(ctx)
            self.assertEqual(ExecutionContext.get_current(), outer)

    def test_context_with_policy_set(self):
        """Test PolicyContext with a PolicySet."""
        ps = PolicySet()
        ps.add_policy(Policy(
            name="allow_all",
            effect=Effect.ALLOW,
            actions=["*"],
            resources=["*"],
        ))
        with PolicyContext(
            policy=ps,
            action="test",
            resource="test",
            engine=self.engine,
        ):
            ctx = ExecutionContext.get_current()
            self.assertIsNotNone(ctx)


if __name__ == "__main__":
    unittest.main()
