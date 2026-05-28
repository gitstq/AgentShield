"""Execution context for AgentShield policy evaluation.

The ExecutionContext holds information about the current agent operation,
including the agent identity, action, resource, and any additional metadata.
"""

import threading
import time
import uuid
from typing import Any, Dict, Optional


class ExecutionContext:
    """Context for a single policy evaluation.

    Holds all relevant information about the operation being evaluated,
    including agent identity, action details, and timing information.

    Attributes:
        agent_id: Identifier for the AI agent making the request.
        action: The action being performed (e.g., "file:read", "http:request").
        resource: The resource being accessed (e.g., "/etc/passwd", "https://example.com").
        metadata: Additional context data for condition evaluation.
        request_id: Unique identifier for this evaluation request.
        timestamp: Unix timestamp when this context was created.
        parent_id: Optional parent context ID for nested evaluations.
    """

    _current_context = threading.local()

    def __init__(
        self,
        action: str = "",
        resource: str = "",
        agent_id: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
        parent_id: Optional[str] = None,
    ):
        self.agent_id = agent_id or "default_agent"
        self.action = action
        self.resource = resource
        self.metadata = metadata or {}
        self.request_id = request_id or str(uuid.uuid4())
        self.timestamp = time.time()
        self.parent_id = parent_id

    def to_dict(self) -> Dict[str, Any]:
        """Serialize this context to a dictionary.

        Returns:
            A dictionary representation of this context.
        """
        return {
            "agent_id": self.agent_id,
            "action": self.action,
            "resource": self.resource,
            "metadata": self.metadata,
            "request_id": self.request_id,
            "timestamp": self.timestamp,
            "parent_id": self.parent_id,
        }

    def get_evaluation_context(self) -> Dict[str, Any]:
        """Get the full context dictionary for condition evaluation.

        Merges action, resource, agent_id, and all metadata into a single
        dictionary that can be used by Condition evaluators.

        Returns:
            A merged dictionary for condition evaluation.
        """
        ctx = {
            "action": self.action,
            "resource": self.resource,
            "agent_id": self.agent_id,
            "request_id": self.request_id,
            "timestamp": self.timestamp,
        }
        ctx.update(self.metadata)
        return ctx

    def create_child(self, action: str = "", resource: str = "", **kwargs: Any) -> "ExecutionContext":
        """Create a child context for nested evaluations.

        Args:
            action: Override action for the child context.
            resource: Override resource for the child context.
            **kwargs: Additional metadata for the child context.

        Returns:
            A new ExecutionContext with this context as parent.
        """
        child_metadata = dict(self.metadata)
        child_metadata.update(kwargs)
        return ExecutionContext(
            action=action or self.action,
            resource=resource or self.resource,
            agent_id=self.agent_id,
            metadata=child_metadata,
            parent_id=self.request_id,
        )

    @classmethod
    def get_current(cls) -> Optional["ExecutionContext"]:
        """Get the current thread-local execution context.

        Returns:
            The current ExecutionContext, or None if not set.
        """
        return getattr(cls._current_context, "context", None)

    @classmethod
    def set_current(cls, context: Optional["ExecutionContext"]) -> None:
        """Set the current thread-local execution context.

        Args:
            context: The ExecutionContext to set, or None to clear.
        """
        cls._current_context.context = context

    def __enter__(self) -> "ExecutionContext":
        """Enter context manager, setting this as the current context.

        Returns:
            This ExecutionContext.
        """
        self._previous_context = ExecutionContext.get_current()
        ExecutionContext.set_current(self)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit context manager, restoring the previous context."""
        ExecutionContext.set_current(self._previous_context)

    def __repr__(self) -> str:
        return (
            f"ExecutionContext(agent_id={self.agent_id!r}, action={self.action!r}, "
            f"resource={self.resource!r}, request_id={self.request_id!r})"
        )
