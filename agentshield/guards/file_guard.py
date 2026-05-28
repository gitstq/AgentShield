"""File system access guard for AgentShield.

Controls file read, write, and delete operations based on path patterns.
Supports allow/deny lists with glob matching.
"""

import fnmatch
import os
from typing import Any, Dict, List, Optional, Set

from agentshield.guards.base import BaseGuard, GuardResult


class FileGuard(BaseGuard):
    """Guard for controlling file system access.

    Uses path pattern matching to determine whether file operations
    are allowed. Supports separate rules for read, write, and delete operations.

    Attributes:
        denied_paths: Set of glob patterns for denied paths.
        allowed_paths: Set of glob patterns for allowed paths.
        denied_read_paths: Set of glob patterns specifically denied for reading.
        allowed_read_paths: Set of glob patterns specifically allowed for reading.
        denied_write_paths: Set of glob patterns specifically denied for writing.
        allowed_write_paths: Set of glob patterns specifically allowed for writing.
        denied_delete_paths: Set of glob patterns specifically denied for deletion.
        allowed_delete_paths: Set of glob patterns specifically allowed for deletion.
        allow_by_default: If True, allow all paths not explicitly denied.
            If False, deny all paths not explicitly allowed.
    """

    def __init__(
        self,
        name: str = "file",
        description: str = "Controls file system access",
        enforce_mode: bool = True,
        enabled: bool = True,
        denied_paths: Optional[List[str]] = None,
        allowed_paths: Optional[List[str]] = None,
        denied_read_paths: Optional[List[str]] = None,
        allowed_read_paths: Optional[List[str]] = None,
        denied_write_paths: Optional[List[str]] = None,
        allowed_write_paths: Optional[List[str]] = None,
        denied_delete_paths: Optional[List[str]] = None,
        allowed_delete_paths: Optional[List[str]] = None,
        allow_by_default: bool = False,
    ):
        super().__init__(
            name=name,
            description=description,
            enforce_mode=enforce_mode,
            enabled=enabled,
        )
        self.denied_paths: Set[str] = set(denied_paths or [])
        self.allowed_paths: Set[str] = set(allowed_paths or [])
        self.denied_read_paths: Set[str] = set(denied_read_paths or [])
        self.allowed_read_paths: Set[str] = set(allowed_read_paths or [])
        self.denied_write_paths: Set[str] = set(denied_write_paths or [])
        self.allowed_write_paths: Set[str] = set(allowed_write_paths or [])
        self.denied_delete_paths: Set[str] = set(denied_delete_paths or [])
        self.allowed_delete_paths: Set[str] = set(allowed_delete_paths or [])
        self.allow_by_default = allow_by_default

    def _resolve_path(self, path: str) -> str:
        """Resolve a file path to its absolute form.

        Args:
            path: The file path to resolve.

        Returns:
            The absolute path.
        """
        return os.path.abspath(os.path.expanduser(path))

    def _matches_any(self, path: str, patterns: Set[str]) -> bool:
        """Check if a path matches any of the given glob patterns.

        Args:
            path: The file path to check.
            patterns: Set of glob patterns.

        Returns:
            True if the path matches any pattern.
        """
        return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)

    def _is_path_denied(self, path: str, operation: str = "") -> bool:
        """Check if a path is denied for the given operation.

        Checks operation-specific denied paths first, then general denied paths.

        Args:
            path: The file path to check.
            operation: The operation type ("read", "write", "delete", or "").

        Returns:
            True if the path is denied.
        """
        resolved = self._resolve_path(path)

        # Check operation-specific denied paths
        if operation == "read" and self._matches_any(resolved, self.denied_read_paths):
            return True
        if operation == "write" and self._matches_any(resolved, self.denied_write_paths):
            return True
        if operation == "delete" and self._matches_any(resolved, self.denied_delete_paths):
            return True

        # Check general denied paths
        if self._matches_any(resolved, self.denied_paths):
            return True

        return False

    def _is_path_allowed(self, path: str, operation: str = "") -> bool:
        """Check if a path is explicitly allowed for the given operation.

        Checks operation-specific allowed paths first, then general allowed paths.

        Args:
            path: The file path to check.
            operation: The operation type ("read", "write", "delete", or "").

        Returns:
            True if the path is explicitly allowed.
        """
        resolved = self._resolve_path(path)

        # Check operation-specific allowed paths
        if operation == "read" and self._matches_any(resolved, self.allowed_read_paths):
            return True
        if operation == "write" and self._matches_any(resolved, self.allowed_write_paths):
            return True
        if operation == "delete" and self._matches_any(resolved, self.allowed_delete_paths):
            return True

        # Check general allowed paths
        if self._matches_any(resolved, self.allowed_paths):
            return True

        return False

    def check(
        self,
        action: str,
        resource: str,
        context: Dict[str, Any],
    ) -> GuardResult:
        """Check whether a file operation is allowed.

        Args:
            action: The action (e.g., "file:read", "file:write", "file:delete").
            resource: The file path.
            context: Additional context.

        Returns:
            GuardResult indicating whether the action is allowed.
        """
        # Only handle file-related actions
        if not action.startswith("file:"):
            return GuardResult(
                allowed=True,
                reason=f"Guard '{self.name}' does not handle action '{action}'",
            )

        operation = action.split(":", 1)[1] if ":" in action else ""

        # Check deny list first (deny takes precedence)
        if self._is_path_denied(resource, operation):
            return GuardResult(
                allowed=False,
                reason=f"Path '{resource}' is denied for operation '{operation}'",
                details={
                    "guard": self.name,
                    "action": action,
                    "resource": resource,
                    "operation": operation,
                },
            )

        # Check allow list
        if self._is_path_allowed(resource, operation):
            return GuardResult(
                allowed=True,
                reason=f"Path '{resource}' is allowed for operation '{operation}'",
                details={
                    "guard": self.name,
                    "action": action,
                    "resource": resource,
                    "operation": operation,
                },
            )

        # Fall back to default
        if self.allow_by_default:
            return GuardResult(
                allowed=True,
                reason=f"Path '{resource}' allowed by default",
                details={
                    "guard": self.name,
                    "action": action,
                    "resource": resource,
                    "operation": operation,
                },
            )
        else:
            return GuardResult(
                allowed=False,
                reason=f"Path '{resource}' not in allow list for operation '{operation}'",
                details={
                    "guard": self.name,
                    "action": action,
                    "resource": resource,
                    "operation": operation,
                },
            )

    def configure(
        self,
        denied_paths: Optional[List[str]] = None,
        allowed_paths: Optional[List[str]] = None,
        denied_read_paths: Optional[List[str]] = None,
        allowed_read_paths: Optional[List[str]] = None,
        denied_write_paths: Optional[List[str]] = None,
        allowed_write_paths: Optional[List[str]] = None,
        denied_delete_paths: Optional[List[str]] = None,
        allowed_delete_paths: Optional[List[str]] = None,
        allow_by_default: Optional[bool] = None,
        **kwargs: Any,
    ) -> None:
        """Configure the file guard.

        Args:
            denied_paths: Glob patterns for denied paths.
            allowed_paths: Glob patterns for allowed paths.
            denied_read_paths: Glob patterns for read-denied paths.
            allowed_read_paths: Glob patterns for read-allowed paths.
            denied_write_paths: Glob patterns for write-denied paths.
            allowed_write_paths: Glob patterns for write-allowed paths.
            denied_delete_paths: Glob patterns for delete-denied paths.
            allowed_delete_paths: Glob patterns for delete-allowed paths.
            allow_by_default: Default allow behavior.
            **kwargs: Additional configuration.
        """
        if denied_paths is not None:
            self.denied_paths = set(denied_paths)
        if allowed_paths is not None:
            self.allowed_paths = set(allowed_paths)
        if denied_read_paths is not None:
            self.denied_read_paths = set(denied_read_paths)
        if allowed_read_paths is not None:
            self.allowed_read_paths = set(allowed_read_paths)
        if denied_write_paths is not None:
            self.denied_write_paths = set(denied_write_paths)
        if allowed_write_paths is not None:
            self.allowed_write_paths = set(allowed_write_paths)
        if denied_delete_paths is not None:
            self.denied_delete_paths = set(denied_delete_paths)
        if allowed_delete_paths is not None:
            self.allowed_delete_paths = set(allowed_delete_paths)
        if allow_by_default is not None:
            self.allow_by_default = allow_by_default
        super().configure(**kwargs)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize this guard to a dictionary.

        Returns:
            A dictionary representation of this guard.
        """
        result = super().to_dict()
        result.update({
            "denied_paths": sorted(self.denied_paths),
            "allowed_paths": sorted(self.allowed_paths),
            "denied_read_paths": sorted(self.denied_read_paths),
            "allowed_read_paths": sorted(self.allowed_read_paths),
            "denied_write_paths": sorted(self.denied_write_paths),
            "allowed_write_paths": sorted(self.allowed_write_paths),
            "denied_delete_paths": sorted(self.denied_delete_paths),
            "allowed_delete_paths": sorted(self.allowed_delete_paths),
            "allow_by_default": self.allow_by_default,
        })
        return result
