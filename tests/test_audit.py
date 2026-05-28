"""Tests for the audit system."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentshield.audit.logger import AuditLogger
from agentshield.audit.formatter import AuditFormatter
from agentshield.audit.exporter import AuditExporter
from agentshield.core.exceptions import AuditError


class TestAuditFormatter(unittest.TestCase):
    """Tests for the AuditFormatter class."""

    def setUp(self):
        self.formatter = AuditFormatter()

    def test_format_json(self):
        """Test JSON formatting."""
        entry = {
            "agent_id": "agent1",
            "action": "file:read",
            "resource": "/tmp/data",
            "decision": "allowed",
        }
        result = self.formatter.format_json(entry)
        parsed = json.loads(result)
        self.assertEqual(parsed["agent_id"], "agent1")
        self.assertEqual(parsed["decision"], "allowed")
        self.assertIn("timestamp", parsed)

    def test_format_json_pretty(self):
        """Test pretty-printed JSON formatting."""
        formatter = AuditFormatter(pretty_print=True)
        entry = {"agent_id": "agent1", "decision": "allowed"}
        result = formatter.format_json(entry)
        self.assertIn("\n", result)

    def test_format_text(self):
        """Test text formatting."""
        entry = {
            "timestamp": "2024-01-01T00:00:00Z",
            "agent_id": "agent1",
            "action": "file:read",
            "resource": "/tmp/data",
            "decision": "allowed",
        }
        result = self.formatter.format_text(entry)
        self.assertIn("agent=agent1", result)
        self.assertIn("action=file:read", result)
        self.assertIn("decision=allowed", result)

    def test_format_csv_row(self):
        """Test CSV row formatting."""
        entry = {
            "timestamp": "2024-01-01T00:00:00Z",
            "agent_id": "agent1",
            "action": "file:read",
            "resource": "/tmp/data",
            "decision": "allowed",
        }
        row = self.formatter.format_csv_row(entry)
        self.assertEqual(len(row), 9)
        self.assertEqual(row[2], "agent1")

    def test_get_csv_header(self):
        """Test CSV header."""
        header = AuditFormatter.get_csv_header()
        self.assertEqual(len(header), 9)
        self.assertEqual(header[0], "timestamp")

    def test_format_entries_json(self):
        """Test formatting multiple entries as JSON."""
        entries = [
            {"agent_id": "agent1", "decision": "allowed"},
            {"agent_id": "agent2", "decision": "denied"},
        ]
        result = self.formatter.format_entries_json(entries)
        parsed = json.loads(result)
        self.assertEqual(len(parsed), 2)

    def test_format_entries_csv(self):
        """Test formatting multiple entries as CSV."""
        entries = [
            {"agent_id": "agent1", "decision": "allowed"},
            {"agent_id": "agent2", "decision": "denied"},
        ]
        result = self.formatter.format_entries_csv(entries)
        lines = result.strip().split("\n")
        self.assertEqual(len(lines), 3)  # header + 2 rows


class TestAuditExporter(unittest.TestCase):
    """Tests for the AuditExporter class."""

    def setUp(self):
        self.exporter = AuditExporter()
        self.entries = [
            {
                "timestamp": "2024-01-01T00:00:00Z",
                "agent_id": "agent1",
                "action": "file:read",
                "resource": "/tmp/data",
                "decision": "allowed",
                "details": {},
            },
            {
                "timestamp": "2024-01-01T00:00:01Z",
                "agent_id": "agent2",
                "action": "file:write",
                "resource": "/etc/config",
                "decision": "denied",
                "details": {"reason": "policy"},
            },
        ]

    def test_export_json_string(self):
        """Test exporting to JSON string."""
        result = self.exporter.export_to_json_string(self.entries)
        parsed = json.loads(result)
        self.assertEqual(len(parsed), 2)

    def test_export_json_string_pretty(self):
        """Test exporting to pretty-printed JSON string."""
        result = self.exporter.export_to_json_string(self.entries, pretty_print=True)
        self.assertIn("\n", result)

    def test_export_csv_string(self):
        """Test exporting to CSV string."""
        result = self.exporter.export_to_csv_string(self.entries)
        lines = result.strip().split("\n")
        self.assertEqual(len(lines), 3)

    def test_export_json_file(self):
        """Test exporting to a JSON file."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            temp_path = f.name
        try:
            self.exporter.export_to_json_file(self.entries, temp_path)
            with open(temp_path, "r") as f:
                data = json.load(f)
            self.assertEqual(len(data), 2)
        finally:
            os.unlink(temp_path)

    def test_export_csv_file(self):
        """Test exporting to a CSV file."""
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            temp_path = f.name
        try:
            self.exporter.export_to_csv_file(self.entries, temp_path)
            with open(temp_path, "r") as f:
                lines = f.readlines()
            self.assertEqual(len(lines), 3)
        finally:
            os.unlink(temp_path)

    def test_export_to_file_json(self):
        """Test auto-detect format for JSON."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            temp_path = f.name
        try:
            self.exporter.export_to_file(self.entries, temp_path)
            with open(temp_path, "r") as f:
                data = json.load(f)
            self.assertEqual(len(data), 2)
        finally:
            os.unlink(temp_path)

    def test_export_to_file_csv(self):
        """Test auto-detect format for CSV."""
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            temp_path = f.name
        try:
            self.exporter.export_to_file(self.entries, temp_path)
            with open(temp_path, "r") as f:
                lines = f.readlines()
            self.assertEqual(len(lines), 3)
        finally:
            os.unlink(temp_path)

    def test_export_to_file_unsupported(self):
        """Test that unsupported formats raise ValueError."""
        with self.assertRaises(ValueError):
            self.exporter.export_to_file(self.entries, "/tmp/test.txt")


class TestAuditLogger(unittest.TestCase):
    """Tests for the AuditLogger class."""

    def setUp(self):
        self.logger = AuditLogger(buffer_size=100)

    def tearDown(self):
        self.logger.shutdown()

    def test_log_entry(self):
        """Test logging a single entry."""
        entry = self.logger.log(
            agent_id="agent1",
            action="file:read",
            resource="/tmp/data",
            decision="allowed",
        )
        self.assertEqual(entry["agent_id"], "agent1")
        self.assertEqual(entry["decision"], "allowed")
        self.assertIn("timestamp", entry)

    def test_log_multiple_entries(self):
        """Test logging multiple entries."""
        for i in range(10):
            self.logger.log(agent_id=f"agent{i}", action="test", decision="allowed")
        self.assertEqual(len(self.logger), 10)

    def test_get_entries(self):
        """Test getting entries."""
        for i in range(5):
            self.logger.log(agent_id="agent1", action="test", decision="allowed")
        for i in range(3):
            self.logger.log(agent_id="agent2", action="test", decision="denied")

        entries = self.logger.get_entries()
        self.assertEqual(len(entries), 8)

    def test_get_entries_with_filter(self):
        """Test getting entries with filters."""
        for i in range(5):
            self.logger.log(agent_id="agent1", action="test", decision="allowed")
        for i in range(3):
            self.logger.log(agent_id="agent2", action="test", decision="denied")

        allowed = self.logger.get_entries(decision="allowed")
        self.assertEqual(len(allowed), 5)

        agent1 = self.logger.get_entries(agent_id="agent1")
        self.assertEqual(len(agent1), 5)

    def test_get_entries_pagination(self):
        """Test entry pagination."""
        for i in range(20):
            self.logger.log(agent_id="agent1", action="test", decision="allowed")

        page1 = self.logger.get_entries(limit=5, offset=0)
        page2 = self.logger.get_entries(limit=5, offset=5)
        self.assertEqual(len(page1), 5)
        self.assertEqual(len(page2), 5)
        self.assertNotEqual(page1[0]["timestamp"], page2[0]["timestamp"])

    def test_get_recent_entries(self):
        """Test getting recent entries."""
        for i in range(20):
            self.logger.log(agent_id=f"agent{i}", action="test", decision="allowed")

        recent = self.logger.get_recent_entries(count=5)
        self.assertEqual(len(recent), 5)

    def test_get_stats(self):
        """Test getting statistics."""
        for _ in range(7):
            self.logger.log(agent_id="agent1", action="test", decision="allowed")
        for _ in range(3):
            self.logger.log(agent_id="agent2", action="test", decision="denied")

        stats = self.logger.get_stats()
        self.assertEqual(stats["total_entries"], 10)
        self.assertEqual(stats["allowed_count"], 7)
        self.assertEqual(stats["denied_count"], 3)
        self.assertEqual(stats["unique_agents"], 2)

    def test_clear(self):
        """Test clearing entries."""
        for _ in range(10):
            self.logger.log(agent_id="agent1", action="test", decision="allowed")
        self.logger.clear()
        self.assertEqual(len(self.logger), 0)

    def test_buffer_trim(self):
        """Test that buffer is trimmed when exceeding max size."""
        logger = AuditLogger(buffer_size=5)
        for i in range(10):
            logger.log(agent_id="agent1", action="test", decision="allowed")
        # Buffer should be trimmed to 5
        self.assertEqual(len(logger._buffer), 5)
        # All entries should still be in _all_entries
        self.assertEqual(len(logger), 10)
        logger.shutdown()

    def test_callback(self):
        """Test callback notification."""
        received = []

        def on_log(entry):
            received.append(entry)

        self.logger.add_callback(on_log)
        self.logger.log(agent_id="agent1", action="test", decision="allowed")
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]["agent_id"], "agent1")

    def test_remove_callback(self):
        """Test removing a callback."""
        received = []

        def on_log(entry):
            received.append(entry)

        self.logger.add_callback(on_log)
        self.logger.remove_callback(on_log)
        self.logger.log(agent_id="agent1", action="test", decision="allowed")
        self.assertEqual(len(received), 0)

    def test_callback_error_doesnt_break(self):
        """Test that callback errors don't break logging."""

        def bad_callback(entry):
            raise RuntimeError("callback error")

        self.logger.add_callback(bad_callback)
        entry = self.logger.log(agent_id="agent1", action="test", decision="allowed")
        self.assertIsNotNone(entry)

    def test_export_json(self):
        """Test JSON export."""
        self.logger.log(agent_id="agent1", action="test", decision="allowed")
        result = self.logger.export_json()
        parsed = json.loads(result)
        self.assertEqual(len(parsed), 1)

    def test_export_csv(self):
        """Test CSV export."""
        self.logger.log(agent_id="agent1", action="test", decision="allowed")
        result = self.logger.export_csv()
        lines = result.strip().split("\n")
        self.assertEqual(len(lines), 2)

    def test_flush_to_file(self):
        """Test flushing to a file."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            temp_path = f.name
        try:
            logger = AuditLogger(log_file=temp_path)
            logger.log(agent_id="agent1", action="test", decision="allowed")
            logger.flush()
            with open(temp_path, "r") as f:
                data = json.load(f)
            self.assertEqual(len(data), 1)
            logger.shutdown()
        finally:
            os.unlink(temp_path)

    def test_len(self):
        """Test __len__."""
        self.assertEqual(len(self.logger), 0)
        self.logger.log(agent_id="agent1", action="test", decision="allowed")
        self.assertEqual(len(self.logger), 1)

    def test_repr(self):
        """Test __repr__."""
        r = repr(self.logger)
        self.assertIn("AuditLogger", r)


if __name__ == "__main__":
    unittest.main()
