"""Audit log formatter for AgentShield.

Provides formatting utilities for audit log entries,
supporting JSON, text, and CSV output formats.
"""

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class AuditFormatter:
    """Formatter for audit log entries.

    Supports multiple output formats including JSON, text, and CSV.

    Attributes:
        include_timestamp: Whether to include timestamps in formatted output.
        timestamp_format: strftime format string for timestamps.
        pretty_print: Whether to use pretty-printing for JSON output.
    """

    def __init__(
        self,
        include_timestamp: bool = True,
        timestamp_format: str = "%Y-%m-%dT%H:%M:%S.%fZ",
        pretty_print: bool = False,
    ):
        self.include_timestamp = include_timestamp
        self.timestamp_format = timestamp_format
        self.pretty_print = pretty_print

    def format_json(self, entry: Dict[str, Any]) -> str:
        """Format a single audit log entry as JSON.

        Args:
            entry: The audit log entry dictionary.

        Returns:
            A JSON-formatted string.
        """
        if self.include_timestamp and "timestamp" not in entry:
            entry["timestamp"] = datetime.now(timezone.utc).strftime(
                self.timestamp_format
            )

        if self.pretty_print:
            return json.dumps(entry, indent=2, ensure_ascii=False, default=str)
        else:
            return json.dumps(entry, ensure_ascii=False, default=str)

    def format_text(self, entry: Dict[str, Any]) -> str:
        """Format a single audit log entry as human-readable text.

        Args:
            entry: The audit log entry dictionary.

        Returns:
            A formatted text string.
        """
        timestamp = entry.get("timestamp", "N/A")
        agent_id = entry.get("agent_id", "N/A")
        action = entry.get("action", "N/A")
        resource = entry.get("resource", "N/A")
        decision = entry.get("decision", "N/A")
        guard_name = entry.get("guard_name", "")
        details = entry.get("details", {})

        parts = [f"[{timestamp}]"]

        if agent_id != "N/A":
            parts.append(f"agent={agent_id}")

        parts.append(f"action={action}")
        parts.append(f"resource={resource}")
        parts.append(f"decision={decision}")

        if guard_name:
            parts.append(f"guard={guard_name}")

        if details:
            detail_str = " ".join(
                f"{k}={v}" for k, v in details.items() if v is not None
            )
            if detail_str:
                parts.append(detail_str)

        return " | ".join(parts)

    def format_csv_row(self, entry: Dict[str, Any]) -> List[str]:
        """Format a single audit log entry as a CSV row.

        Args:
            entry: The audit log entry dictionary.

        Returns:
            A list of string values for CSV output.
        """
        return [
            entry.get("timestamp", ""),
            entry.get("request_id", ""),
            entry.get("agent_id", ""),
            entry.get("action", ""),
            entry.get("resource", ""),
            entry.get("decision", ""),
            entry.get("guard_name", ""),
            entry.get("policy_name", ""),
            json.dumps(entry.get("details", {}), ensure_ascii=False, default=str),
        ]

    @staticmethod
    def get_csv_header() -> List[str]:
        """Get the CSV header row.

        Returns:
            List of column header strings.
        """
        return [
            "timestamp",
            "request_id",
            "agent_id",
            "action",
            "resource",
            "decision",
            "guard_name",
            "policy_name",
            "details",
        ]

    def format_entries_json(self, entries: List[Dict[str, Any]]) -> str:
        """Format multiple audit log entries as a JSON array.

        Args:
            entries: List of audit log entry dictionaries.

        Returns:
            A JSON array string.
        """
        formatted = []
        for entry in entries:
            e = dict(entry)
            if self.include_timestamp and "timestamp" not in e:
                e["timestamp"] = datetime.now(timezone.utc).strftime(
                    self.timestamp_format
                )
            formatted.append(e)

        if self.pretty_print:
            return json.dumps(formatted, indent=2, ensure_ascii=False, default=str)
        else:
            return json.dumps(formatted, ensure_ascii=False, default=str)

    def format_entries_csv(self, entries: List[Dict[str, Any]]) -> str:
        """Format multiple audit log entries as CSV.

        Args:
            entries: List of audit log entry dictionaries.

        Returns:
            A CSV-formatted string with header row.
        """
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(self.get_csv_header())
        for entry in entries:
            writer.writerow(self.format_csv_row(entry))
        return output.getvalue()
