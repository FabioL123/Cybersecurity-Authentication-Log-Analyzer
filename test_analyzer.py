Original path: cybersecurity-auth-log-analyzer/tests/test_analyzer.py
Note: this PDF displays the file's text. It is not a runnable replacement for the original .py, .sql, .yml, or configuration file.
import tempfile
import unittest
from pathlib import Path
from src.analyzer import parse_log
class AnalyzerTests(unittest.TestCase):
 def test_counts_failed_and_successful_events(self):
 sample = """Oct 11 10:02:11 host sshd[1]: Failed password for invalid user admin from 192.0.2.10
port 51000 ssh2
Oct 11 10:03:01 host sshd[2]: Accepted publickey for analyst from 198.51.100.22 port 52000 ssh2
Oct 11 10:04:05 host sshd[3]: Failed password for test from 192.0.2.10 port 53000 ssh2
not a matching line
"""
 with tempfile.TemporaryDirectory() as temp_dir:
 path = Path(temp_dir) / "auth.log"
 path.write_text(sample, encoding="utf-8")
 report = parse_log(path)
 self.assertEqual(report["lines_read"], 4)
 self.assertEqual(report["failed_login_count"], 2)
 self.assertEqual(report["successful_login_count"], 1)
 self.assertEqual(report["failed_attempts_by_source_ip"]["192.0.2.10"], 2)
 self.assertEqual(len(report["events"]), 3)
 def test_empty_file(self):
 with tempfile.TemporaryDirectory() as temp_dir:
 path = Path(temp_dir) / "empty.log"
 path.write_text("", encoding="utf-8")
 report = parse_log(path)
 self.assertEqual(report["lines_read"], 0)
 self.assertEqual(report["failed_login_count"], 0)
 self.assertEqual(report["events"], [])
if __name__ == "__main__":
 unittest.main()
