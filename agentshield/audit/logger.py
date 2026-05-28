"""Audit logger for AgentShield.

Provides structured JSON logging for all policy decisions,
with in-memory buffering, file persistence, and configurable
flush intervals.
"""

import json
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from agentshield.audit.exporter import AuditExporter
from agentshield.audit.formatter import AuditFormatter
from agentshield.core.exceptions import AuditError


class AuditLogger:
    """Structured audit logger for policy decisions.

    Records all policy evaluation results with structured data including
    timestamps, agent IDs, actions, resources, decisions, and details.

    Supports in-memory buffering with configurable size and automatic
    flushing to file.

    Attributes:
        buffer_size: Maximum number of entries in the in-memory buffer.
        flush_interval: Automatic flush interval in seconds (0 = disabled).
        log_file: Optional file path for persistent logging.
    """

    def __init__(
        self,
        buffer_size: int = 10000,
        flush_interval: float = 0.0,
        log_file: Optional[str] = None,
    ):
        self.buffer_size = buffer_size
        self.flush_interval = flush_interval
        self.log_file = log_file

        self._lock = threading.Lock()
        self._buffer: List[Dict[str, Any]] = []
        self._all_entries: List[Dict[str, Any]] = []
        self._formatter = AuditFormatter()
        self._exporter = AuditExporter(self._formatter)
        self._callbacks: List[Callable[[Dict[str, Any]], None]] = []
        self._flush_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._last_flush_time = time.time()

        # Ensure log directory exists
        if self.log_file:
            log_dir = os.path.dirname(self.log_file)
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)

        # Start auto-flush thread if configured
        if self.flush_interval > 0:
            self._start_auto_flush()

    def log(
        self,
        agent_id: str = "",
        action: str = "",
        resource: str = "",
        decision: str = "",
        guard_name: str = "",
        policy_name: str = "",
        details: Optional[Dict[str, Any]] = None,
        request_id: str = "",
    ) -> Dict[str, Any]:
        """Record an audit log entry.

        Args:
            agent_id: Identifier for the AI agent.
            action: The action that was evaluated.
            resource: The resource that was accessed.
            decision: The decision made ("allowed" or "denied").
            guard_name: Optional name of the guard.
            policy_name: Optional name of the policy.
            details: Optional additional details.
            request_id: Optional request identifier.

        Returns:
            The created log entry dictionary.
        """
        entry = {
            "timestamp": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ"
            ),
            "request_id": request_id,
            "agent_id": agent_id,
            "action": action,
            "resource": resource,
            "decision": decision,
            "guard_name": guard_name,
            "policy_name": policy_name,
            "details": details or {},
        }

        with self._lock:
            self._buffer.append(entry)
            self._all_entries.append(entry)

            # Trim buffer if it exceeds the maximum size
            if len(self._buffer) > self.buffer_size:
                self._buffer = self._buffer[-self.buffer_size:]

            # Trim all_entries to prevent unbounded growth (keep last 100k)
            if len(self._all_entries) > 100000:
                self._all_entries = self._all_entries[-100000:]

        # Notify callbacks
        for callback in self._callbacks:
            try:
                callback(entry)
            except Exception:
                pass  # Callback errors should not affect logging

        return entry

    def get_entries(
        self,
        limit: int = 100,
        offset: int = 0,
        agent_id: Optional[str] = None,
        decision: Optional[str] = None,
        action: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get audit log entries with optional filtering.

        Args:
            limit: Maximum number of entries to return.
            offset: Number of entries to skip.
            agent_id: Filter by agent ID.
            decision: Filter by decision ("allowed" or "denied").
            action: Filter by action.

        Returns:
            List of matching audit log entries.
        """
        with self._lock:
            entries = list(self._all_entries)

        # Apply filters
        if agent_id is not None:
            entries = [e for e in entries if e.get("agent_id") == agent_id]
        if decision is not None:
            entries = [e for e in entries if e.get("decision") == decision]
        if action is not None:
            entries = [e for e in entries if e.get("action") == action]

        # Apply pagination
        return entries[offset:offset + limit]

    def get_recent_entries(self, count: int = 100) -> List[Dict[str, Any]]:
        """Get the most recent audit log entries.

        Args:
            count: Maximum number of entries to return.

        Returns:
            List of the most recent audit log entries.
        """
        with self._lock:
            return list(self._buffer[-count:])

    def get_stats(self) -> Dict[str, Any]:
        """Get audit log statistics.

        Returns:
            Dictionary with statistics about the audit log.
        """
        with self._lock:
            total = len(self._all_entries)
            buffer_len = len(self._buffer)

            allowed = sum(
                1 for e in self._all_entries if e.get("decision") == "allowed"
            )
            denied = sum(
                1 for e in self._all_entries if e.get("decision") == "denied"
            )

            # Count unique agents
            agents = set(e.get("agent_id", "") for e in self._all_entries)

            # Count unique actions
            actions = set(e.get("action", "") for e in self._all_entries)

        return {
            "total_entries": total,
            "buffer_size": buffer_len,
            "max_buffer_size": self.buffer_size,
            "allowed_count": allowed,
            "denied_count": denied,
            "unique_agents": len(agents),
            "unique_actions": len(actions),
        }

    def clear(self) -> None:
        """Clear all audit log entries from memory."""
        with self._lock:
            self._buffer.clear()
            self._all_entries.clear()

    def flush(self) -> None:
        """Flush the in-memory buffer to the log file.

        If no log file is configured, this method is a no-op.
        """
        if not self.log_file:
            return

        with self._lock:
            entries = list(self._buffer)

        if not entries:
            return

        try:
            self._exporter.export_to_json_file(
                entries,
                self.log_file,
                pretty_print=False,
            )
        except (IOError, OSError) as e:
            raise AuditError(f"Failed to flush audit log to '{self.log_file}': {e}")

        self._last_flush_time = time.time()

    def add_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Add a callback to be called for each new log entry.

        Args:
            callback: A function that accepts a log entry dictionary.
        """
        self._callbacks.append(callback)

    def remove_callback(self, callback: Callable[[Dict[str, Any]], None]) -> bool:
        """Remove a previously added callback.

        Args:
            callback: The callback function to remove.

        Returns:
            True if the callback was found and removed.
        """
        try:
            self._callbacks.remove(callback)
            return True
        except ValueError:
            return False

    def export_json(self, pretty_print: bool = False) -> str:
        """Export all entries as a JSON string.

        Args:
            pretty_print: Whether to use pretty-printing.

        Returns:
            A JSON-formatted string of all entries.
        """
        with self._lock:
            entries = list(self._all_entries)
        return self._exporter.export_to_json_string(entries, pretty_print=pretty_print)

    def export_csv(self) -> str:
        """Export all entries as a CSV string.

        Returns:
            A CSV-formatted string of all entries.
        """
        with self._lock:
            entries = list(self._all_entries)
        return self._exporter.export_to_csv_string(entries)

    def export_to_file(self, file_path: str, pretty_print: bool = False) -> None:
        """Export all entries to a file.

        Args:
            file_path: Path to the output file (.json or .csv).
            pretty_print: Whether to use pretty-printing (JSON only).
        """
        with self._lock:
            entries = list(self._all_entries)
        self._exporter.export_to_file(entries, file_path, pretty_print=pretty_print)

    def _start_auto_flush(self) -> None:
        """Start the automatic flush background thread."""
        self._stop_event.clear()
        self._flush_thread = threading.Thread(
            target=self._auto_flush_loop,
            daemon=True,
            name="agentshield-audit-flush",
        )
        self._flush_thread.start()

    def _auto_flush_loop(self) -> None:
        """Background loop for automatic flushing."""
        while not self._stop_event.is_set():
            self._stop_event.wait(self.flush_interval)
            if self._stop_event.is_set():
                break
            try:
                self.flush()
            except AuditError:
                pass  # Silently ignore flush errors

    def shutdown(self) -> None:
        """Shut down the audit logger, flushing any remaining entries."""
        self._stop_event.set()
        if self._flush_thread and self._flush_thread.is_alive():
            self._flush_thread.join(timeout=5.0)
        self._flush_thread = None
        self.flush()

    def __len__(self) -> int:
        with self._lock:
            return len(self._all_entries)

    def __repr__(self) -> str:
        return (
            f"AuditLogger(entries={len(self)}, "
            f"buffer_size={self.buffer_size}, "
            f"log_file={self.log_file!r})"
        )
