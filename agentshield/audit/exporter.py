"""Audit log exporter for AgentShield.

Provides export functionality for audit logs to JSON and CSV files.
"""

import csv
import io
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from agentshield.audit.formatter import AuditFormatter


class AuditExporter:
    """Exporter for audit log entries.

    Exports audit logs to JSON and CSV formats, supporting both
    file-based and string-based output.

    Attributes:
        formatter: The formatter used for output.
    """

    def __init__(self, formatter: Optional[AuditFormatter] = None):
        self.formatter = formatter or AuditFormatter()

    def export_to_json_string(
        self,
        entries: List[Dict[str, Any]],
        pretty_print: bool = False,
    ) -> str:
        """Export audit log entries to a JSON string.

        Args:
            entries: List of audit log entry dictionaries.
            pretty_print: Whether to use pretty-printing.

        Returns:
            A JSON-formatted string.
        """
        original_pretty = self.formatter.pretty_print
        self.formatter.pretty_print = pretty_print
        try:
            return self.formatter.format_entries_json(entries)
        finally:
            self.formatter.pretty_print = original_pretty

    def export_to_csv_string(self, entries: List[Dict[str, Any]]) -> str:
        """Export audit log entries to a CSV string.

        Args:
            entries: List of audit log entry dictionaries.

        Returns:
            A CSV-formatted string with header row.
        """
        return self.formatter.format_entries_csv(entries)

    def export_to_json_file(
        self,
        entries: List[Dict[str, Any]],
        file_path: str,
        pretty_print: bool = False,
    ) -> None:
        """Export audit log entries to a JSON file.

        Args:
            entries: List of audit log entry dictionaries.
            file_path: Path to the output file.
            pretty_print: Whether to use pretty-printing.
        """
        directory = os.path.dirname(file_path)
        if directory:
            os.makedirs(directory, exist_ok=True)

        content = self.export_to_json_string(entries, pretty_print=pretty_print)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)

    def export_to_csv_file(
        self,
        entries: List[Dict[str, Any]],
        file_path: str,
    ) -> None:
        """Export audit log entries to a CSV file.

        Args:
            entries: List of audit log entry dictionaries.
            file_path: Path to the output file.
        """
        directory = os.path.dirname(file_path)
        if directory:
            os.makedirs(directory, exist_ok=True)

        content = self.export_to_csv_string(entries)
        with open(file_path, "w", encoding="utf-8", newline="") as f:
            f.write(content)

    def export_to_file(
        self,
        entries: List[Dict[str, Any]],
        file_path: str,
        pretty_print: bool = False,
    ) -> None:
        """Export audit log entries to a file, auto-detecting format from extension.

        Args:
            entries: List of audit log entry dictionaries.
            file_path: Path to the output file.
            pretty_print: Whether to use pretty-printing (JSON only).
        """
        ext = os.path.splitext(file_path)[1].lower()
        if ext == ".json":
            self.export_to_json_file(entries, file_path, pretty_print=pretty_print)
        elif ext == ".csv":
            self.export_to_csv_file(entries, file_path)
        else:
            raise ValueError(
                f"Unsupported file format: '{ext}'. Supported formats: .json, .csv"
            )
