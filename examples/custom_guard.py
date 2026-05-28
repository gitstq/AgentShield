"""Custom guard example for AgentShield.

This example demonstrates how to create a custom guard by extending
the BaseGuard class. The example implements a ContentFilterGuard that
blocks content containing specific keywords or phrases.
"""

import re
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import Any, Dict, List, Set

from agentshield.core.engine import PolicyEngine
from agentshield.core.context import ExecutionContext
from agentshield.guards.base import BaseGuard, GuardResult
from agentshield.core.policy import Effect, Policy


class ContentFilterGuard(BaseGuard):
    """Custom guard that filters content based on keywords and patterns.

    This guard demonstrates how to create a custom guard by extending
    BaseGuard. It blocks content containing forbidden keywords and
    optionally checks content length.

    Attributes:
        forbidden_keywords: Set of keywords that trigger blocking.
        forbidden_patterns: List of compiled regex patterns.
        max_content_length: Maximum allowed content length.
        case_sensitive: Whether keyword matching is case-sensitive.
    """

    def __init__(
        self,
        name: str = "content_filter",
        description: str = "Filters content based on keywords and patterns",
        enforce_mode: bool = True,
        enabled: bool = True,
        forbidden_keywords: List[str] = None,
        forbidden_patterns: List[str] = None,
        max_content_length: int = 100000,
        case_sensitive: bool = False,
    ):
        super().__init__(
            name=name,
            description=description,
            enforce_mode=enforce_mode,
            enabled=enabled,
        )
        self.forbidden_keywords: Set[str] = set(forbidden_keywords or [])
        self._case_sensitive = case_sensitive
        self.max_content_length = max_content_length

        # Compile regex patterns
        self._patterns: List[re.Pattern] = []
        for pattern_str in forbidden_patterns or []:
            try:
                self._patterns.append(re.compile(pattern_str))
            except re.error:
                pass

    def _check_keywords(self, content: str) -> List[str]:
        """Check content for forbidden keywords.

        Args:
            content: The content to check.

        Returns:
            List of matched forbidden keywords.
        """
        matched = []
        check_content = content if self._case_sensitive else content.lower()
        for keyword in self.forbidden_keywords:
            check_keyword = keyword if self._case_sensitive else keyword.lower()
            if check_keyword in check_content:
                matched.append(keyword)
        return matched

    def _check_patterns(self, content: str) -> List[str]:
        """Check content for forbidden patterns.

        Args:
            content: The content to check.

        Returns:
            List of matched pattern strings.
        """
        matched = []
        for pattern in self._patterns:
            match = pattern.search(content)
            if match:
                matched.append(match.group(0))
        return matched

    def check(
        self,
        action: str,
        resource: str,
        context: Dict[str, Any],
    ) -> GuardResult:
        """Check whether content passes the filter.

        Args:
            action: The action (e.g., "content:write", "content:publish").
            resource: The content or a resource identifier.
            context: Additional context (may contain "content" key).

        Returns:
            GuardResult indicating whether the content is allowed.
        """
        # Only handle content-related actions
        if not action.startswith("content:"):
            return GuardResult(
                allowed=True,
                reason=f"Guard '{self.name}' does not handle action '{action}'",
            )

        content = context.get("content", resource)

        # Check content length
        if len(content) > self.max_content_length:
            return GuardResult(
                allowed=False,
                reason=f"Content exceeds maximum length of {self.max_content_length}",
                details={
                    "guard": self.name,
                    "content_length": len(content),
                    "max_length": self.max_content_length,
                },
            )

        # Check keywords
        matched_keywords = self._check_keywords(content)
        if matched_keywords:
            return GuardResult(
                allowed=False,
                reason=f"Content contains forbidden keywords: {matched_keywords}",
                details={
                    "guard": self.name,
                    "matched_keywords": matched_keywords,
                },
            )

        # Check patterns
        matched_patterns = self._check_patterns(content)
        if matched_patterns:
            return GuardResult(
                allowed=False,
                reason=f"Content matches forbidden patterns: {matched_patterns}",
                details={
                    "guard": self.name,
                    "matched_patterns": matched_patterns,
                },
            )

        return GuardResult(
            allowed=True,
            reason="Content filter check passed",
            details={"guard": self.name},
        )

    def add_keyword(self, keyword: str) -> None:
        """Add a forbidden keyword.

        Args:
            keyword: The keyword to add.
        """
        self.forbidden_keywords.add(keyword)

    def remove_keyword(self, keyword: str) -> bool:
        """Remove a forbidden keyword.

        Args:
            keyword: The keyword to remove.

        Returns:
            True if the keyword was found and removed.
        """
        if keyword in self.forbidden_keywords:
            self.forbidden_keywords.discard(keyword)
            return True
        return False

    def add_pattern(self, pattern: str) -> None:
        """Add a forbidden regex pattern.

        Args:
            pattern: The regex pattern string.

        Raises:
            ValueError: If the pattern is invalid.
        """
        try:
            compiled = re.compile(pattern)
            self._patterns.append(compiled)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}")

    def to_dict(self) -> Dict[str, Any]:
        """Serialize this guard to a dictionary.

        Returns:
            A dictionary representation of this guard.
        """
        result = super().to_dict()
        result.update({
            "forbidden_keywords": sorted(self.forbidden_keywords),
            "pattern_count": len(self._patterns),
            "max_content_length": self.max_content_length,
            "case_sensitive": self._case_sensitive,
        })
        return result


class RateLimitGuard(BaseGuard):
    """Custom guard that enforces per-action rate limits.

    Demonstrates a stateful guard that tracks request rates.

    Attributes:
        max_requests: Maximum requests per window.
        window_seconds: Time window in seconds.
    """

    def __init__(
        self,
        name: str = "rate_limit",
        description: str = "Enforces per-action rate limits",
        enforce_mode: bool = True,
        enabled: bool = True,
        max_requests: int = 10,
        window_seconds: float = 60.0,
    ):
        super().__init__(
            name=name,
            description=description,
            enforce_mode=enforce_mode,
            enabled=enabled,
        )
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._request_log: Dict[str, List[float]] = {}

    def check(
        self,
        action: str,
        resource: str,
        context: Dict[str, Any],
    ) -> GuardResult:
        """Check whether the action is within rate limits.

        Args:
            action: The action to check.
            resource: The resource being accessed.
            context: Additional context.

        Returns:
            GuardResult indicating whether the action is within limits.
        """
        import time

        current_time = time.time()
        key = action

        if key not in self._request_log:
            self._request_log[key] = []

        # Clean old entries
        cutoff = current_time - self.window_seconds
        self._request_log[key] = [
            t for t in self._request_log[key] if t > cutoff
        ]

        count = len(self._request_log[key])
        if count >= self.max_requests:
            return GuardResult(
                allowed=False,
                reason=f"Rate limit exceeded for '{action}': {count}/{self.max_requests}",
                details={
                    "guard": self.name,
                    "action": action,
                    "request_count": count,
                    "max_requests": self.max_requests,
                    "window_seconds": self.window_seconds,
                },
            )

        self._request_log[key].append(current_time)
        return GuardResult(
            allowed=True,
            reason=f"Rate limit OK: {count + 1}/{self.max_requests}",
            details={
                "guard": self.name,
                "action": action,
                "request_count": count + 1,
            },
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize this guard to a dictionary."""
        result = super().to_dict()
        result.update({
            "max_requests": self.max_requests,
            "window_seconds": self.window_seconds,
        })
        return result


def main():
    """Run custom guard examples."""
    print("=" * 60)
    print("AgentShield - Custom Guard Example")
    print("=" * 60)

    # ---- Example 1: ContentFilterGuard ----
    print("\n--- Example 1: ContentFilterGuard ---")
    engine = PolicyEngine()
    engine.add_policy(Policy(
        name="allow_all",
        effect=Effect.ALLOW,
        actions=["*"],
        resources=["*"],
    ))

    content_guard = ContentFilterGuard(
        forbidden_keywords=["spam", "scam", "phishing", "malware"],
        forbidden_patterns=[
            r"click\s+here\s+to\s+win",
            r"free\s+money",
            r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b.*\b(password|credential)\b",
        ],
        max_content_length=5000,
    )
    engine.register_guard("content", content_guard)

    content_tests = [
        "This is a normal message about Python programming.",
        "Congratulations! Click here to win free money now!",
        "Check out this spam recipe for dinner.",
        "Hello, please send your password to verify your account.",
        "A" * 6000,  # Too long
    ]

    for content in content_tests:
        ctx = ExecutionContext(
            action="content:publish",
            resource=content[:50],
            agent_id="demo_agent",
            metadata={"content": content},
        )
        result = engine.check("content:publish", content[:50], ctx)
        status = "ALLOWED" if result == Effect.ALLOW else "BLOCKED"
        display = content[:40] + "..." if len(content) > 40 else content
        print(f"  [{status:7s}] {display}")

    # ---- Example 2: RateLimitGuard ----
    print("\n--- Example 2: RateLimitGuard ---")
    engine2 = PolicyEngine()
    engine2.add_policy(Policy(
        name="allow_all",
        effect=Effect.ALLOW,
        actions=["*"],
        resources=["*"],
    ))

    rate_guard = RateLimitGuard(max_requests=3, window_seconds=60.0)
    engine2.register_guard("rate", rate_guard)

    for i in range(5):
        ctx = ExecutionContext(
            action="api:call",
            resource=f"/endpoint/{i}",
            agent_id="demo_agent",
        )
        result = engine2.check("api:call", f"/endpoint/{i}", ctx)
        status = "ALLOWED" if result == Effect.ALLOW else "BLOCKED"
        print(f"  [{status:7s}] Request {i + 1}/5")

    # ---- Example 3: Dynamic Configuration ----
    print("\n--- Example 3: Dynamic Guard Configuration ---")
    content_guard.add_keyword("blocked_word")
    content_guard.remove_keyword("spam")

    # After removing "spam", spam-related content should be allowed
    ctx = ExecutionContext(
        action="content:publish",
        resource="spam recipe",
        agent_id="demo_agent",
        metadata={"content": "Check out this spam recipe for dinner."},
    )
    result = engine.check("content:publish", "spam recipe", ctx)
    status = "ALLOWED" if result == Effect.ALLOW else "BLOCKED"
    print(f"  [{status:7s}] 'spam recipe' (after removing 'spam' keyword)")

    # After adding "blocked_word", it should be blocked
    ctx = ExecutionContext(
        action="content:publish",
        resource="test content",
        agent_id="demo_agent",
        metadata={"content": "This contains a blocked_word here."},
    )
    result = engine.check("content:publish", "test content", ctx)
    status = "ALLOWED" if result == Effect.ALLOW else "BLOCKED"
    print(f"  [{status:7s}] 'blocked_word' (after adding keyword)")

    # Clean up
    engine.shutdown()
    engine2.shutdown()
    print("\n" + "=" * 60)
    print("Custom guard examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
