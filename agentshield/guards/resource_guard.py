"""Resource usage guard for AgentShield.

Limits CPU time, memory usage, and operation counts to prevent
resource exhaustion attacks.
"""

import threading
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional

from agentshield.guards.base import BaseGuard, GuardResult


class ResourceGuard(BaseGuard):
    """Guard for limiting resource usage.

    Tracks and limits operation counts, rates, and simulated resource
    consumption per agent.

    Attributes:
        max_operations_per_window: Maximum operations per time window.
        window_seconds: Time window in seconds for rate limiting.
        max_memory_mb: Maximum allowed memory usage in MB (simulated).
        max_cpu_time_seconds: Maximum CPU time per operation in seconds.
        max_total_operations: Maximum total operations (lifetime).
    """

    def __init__(
        self,
        name: str = "resource",
        description: str = "Limits resource usage",
        enforce_mode: bool = True,
        enabled: bool = True,
        max_operations_per_window: int = 1000,
        window_seconds: float = 60.0,
        max_memory_mb: float = 512.0,
        max_cpu_time_seconds: float = 30.0,
        max_total_operations: int = 100000,
    ):
        super().__init__(
            name=name,
            description=description,
            enforce_mode=enforce_mode,
            enabled=enabled,
        )
        self.max_operations_per_window = max_operations_per_window
        self.window_seconds = window_seconds
        self.max_memory_mb = max_memory_mb
        self.max_cpu_time_seconds = max_cpu_time_seconds
        self.max_total_operations = max_total_operations

        self._lock = threading.Lock()
        # agent_id -> list of operation timestamps
        self._operation_history: Dict[str, List[float]] = defaultdict(list)
        # agent_id -> total operation count
        self._total_operations: Dict[str, int] = defaultdict(int)
        # agent_id -> operation start time (for CPU time tracking)
        self._operation_start: Dict[str, float] = {}

    def _cleanup_old_operations(self, agent_id: str, current_time: float) -> None:
        """Remove operation timestamps outside the current window.

        Args:
            agent_id: The agent identifier.
            current_time: The current timestamp.
        """
        cutoff = current_time - self.window_seconds
        history = self._operation_history[agent_id]
        # Keep only timestamps within the window
        while history and history[0] < cutoff:
            history.pop(0)

    def _get_operation_count(self, agent_id: str, current_time: float) -> int:
        """Get the number of operations within the current window.

        Args:
            agent_id: The agent identifier.
            current_time: The current timestamp.

        Returns:
            Number of operations in the current window.
        """
        self._cleanup_old_operations(agent_id, current_time)
        return len(self._operation_history[agent_id])

    def check(
        self,
        action: str,
        resource: str,
        context: Dict[str, Any],
    ) -> GuardResult:
        """Check whether the operation is within resource limits.

        Args:
            action: The action being performed.
            resource: The resource being accessed.
            context: Additional context (should contain "agent_id").

        Returns:
            GuardResult indicating whether the operation is allowed.
        """
        agent_id = context.get("agent_id", "default")
        current_time = time.time()

        with self._lock:
            # Check rate limit
            op_count = self._get_operation_count(agent_id, current_time)
            if op_count >= self.max_operations_per_window:
                return GuardResult(
                    allowed=False,
                    reason=(
                        f"Rate limit exceeded for agent '{agent_id}': "
                        f"{op_count}/{self.max_operations_per_window} operations "
                        f"in {self.window_seconds}s window"
                    ),
                    details={
                        "guard": self.name,
                        "agent_id": agent_id,
                        "operation_count": op_count,
                        "max_operations": self.max_operations_per_window,
                        "window_seconds": self.window_seconds,
                    },
                )

            # Check total operations limit
            total = self._total_operations[agent_id]
            if total >= self.max_total_operations:
                return GuardResult(
                    allowed=False,
                    reason=(
                        f"Total operations limit exceeded for agent '{agent_id}': "
                        f"{total}/{self.max_total_operations}"
                    ),
                    details={
                        "guard": self.name,
                        "agent_id": agent_id,
                        "total_operations": total,
                        "max_total_operations": self.max_total_operations,
                    },
                )

            # Check CPU time (if operation is in progress)
            if agent_id in self._operation_start:
                elapsed = current_time - self._operation_start[agent_id]
                if elapsed > self.max_cpu_time_seconds:
                    return GuardResult(
                        allowed=False,
                        reason=(
                            f"CPU time limit exceeded for agent '{agent_id}': "
                            f"{elapsed:.2f}s/{self.max_cpu_time_seconds}s"
                        ),
                        details={
                            "guard": self.name,
                            "agent_id": agent_id,
                            "elapsed_seconds": elapsed,
                            "max_cpu_time_seconds": self.max_cpu_time_seconds,
                        },
                    )

            # Record this operation
            self._operation_history[agent_id].append(current_time)
            self._total_operations[agent_id] += 1
            self._operation_start[agent_id] = current_time

        return GuardResult(
            allowed=True,
            reason="Resource usage within limits",
            details={
                "guard": self.name,
                "agent_id": agent_id,
                "operation_count": op_count + 1,
                "total_operations": total + 1,
            },
        )

    def reset_agent(self, agent_id: str) -> None:
        """Reset all counters for a specific agent.

        Args:
            agent_id: The agent identifier to reset.
        """
        with self._lock:
            self._operation_history.pop(agent_id, None)
            self._total_operations.pop(agent_id, None)
            self._operation_start.pop(agent_id, None)

    def get_agent_stats(self, agent_id: str) -> Dict[str, Any]:
        """Get resource usage statistics for a specific agent.

        Args:
            agent_id: The agent identifier.

        Returns:
            Dictionary with usage statistics.
        """
        current_time = time.time()
        with self._lock:
            op_count = self._get_operation_count(agent_id, current_time)
            total = self._total_operations.get(agent_id, 0)
            start_time = self._operation_start.get(agent_id)
            elapsed = current_time - start_time if start_time else 0.0

        return {
            "agent_id": agent_id,
            "operations_in_window": op_count,
            "max_operations_per_window": self.max_operations_per_window,
            "window_seconds": self.window_seconds,
            "total_operations": total,
            "max_total_operations": self.max_total_operations,
            "current_operation_elapsed": elapsed,
            "max_cpu_time_seconds": self.max_cpu_time_seconds,
        }

    def configure(
        self,
        max_operations_per_window: Optional[int] = None,
        window_seconds: Optional[float] = None,
        max_memory_mb: Optional[float] = None,
        max_cpu_time_seconds: Optional[float] = None,
        max_total_operations: Optional[int] = None,
        **kwargs: Any,
    ) -> None:
        """Configure the resource guard.

        Args:
            max_operations_per_window: Max operations per time window.
            window_seconds: Time window in seconds.
            max_memory_mb: Max memory in MB.
            max_cpu_time_seconds: Max CPU time per operation.
            max_total_operations: Max total operations.
            **kwargs: Additional configuration.
        """
        if max_operations_per_window is not None:
            self.max_operations_per_window = max_operations_per_window
        if window_seconds is not None:
            self.window_seconds = window_seconds
        if max_memory_mb is not None:
            self.max_memory_mb = max_memory_mb
        if max_cpu_time_seconds is not None:
            self.max_cpu_time_seconds = max_cpu_time_seconds
        if max_total_operations is not None:
            self.max_total_operations = max_total_operations
        super().configure(**kwargs)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize this guard to a dictionary.

        Returns:
            A dictionary representation of this guard.
        """
        result = super().to_dict()
        result.update({
            "max_operations_per_window": self.max_operations_per_window,
            "window_seconds": self.window_seconds,
            "max_memory_mb": self.max_memory_mb,
            "max_cpu_time_seconds": self.max_cpu_time_seconds,
            "max_total_operations": self.max_total_operations,
        })
        return result
