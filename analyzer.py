Original path: cybersecurity-auth-log-analyzer/src/analyzer.py
Note: this PDF displays the file's text. It is not a runnable replacement for the original .py, .sql, .yml, or configuration file.
#!/usr/bin/env python3
"""Summarize failed SSH-style authentication events from a supplied text log."""
from __future__ import annotations
import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
# Matches common OpenSSH messages, for example:
# Oct 11 10:02:11 host sshd[123]: Failed password for invalid user admin from 192.0.2.10 port 51000 ssh2
FAILED_RE = re.compile(
 r"(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
 r"(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+Failed password for (?:invalid user )?"
 r"(?P<username>\S+) from (?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]+) port (?P<port>\d+)"
)
ACCEPTED_RE = re.compile(
 r"(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
 r"(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+Accepted (?:password|publickey) for "
 r"(?P<username>\S+) from (?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]+) port (?P<port>\d+)"
)
def parse_log(path: Path) -> dict[str, Any]:
 failed_by_ip: Counter[str] = Counter()
 failed_by_user: Counter[str] = Counter()
 accepted_by_ip: Counter[str] = Counter()
 events: list[dict[str, Any]] = []
 lines_read = 0
 with path.open("r", encoding="utf-8", errors="replace") as handle:
 for line_number, line in enumerate(handle, start=1):
 lines_read += 1
 match = FAILED_RE.search(line)
 if match:
 record = match.groupdict()
 failed_by_ip[record["ip"]] += 1
 failed_by_user[record["username"]] += 1
 events.append({"line": line_number, "event": "failed_login", **record})
 continue
 match = ACCEPTED_RE.search(line)
 if match:
 events.append({"line": line_number, "event": "successful_login", **match.groupdict()})
 accepted_by_ip[match.group("ip")] += 1
 return {
 "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
 "source_file": path.name,
 "lines_read": lines_read,
 "failed_login_count": sum(failed_by_ip.values()),
 "successful_login_count": sum(accepted_by_ip.values()),
 "failed_attempts_by_source_ip": dict(failed_by_ip.most_common()),
 "failed_attempts_by_username": dict(failed_by_user.most_common()),
 "events": events,
 }
def main() -> int:
 parser = argparse.ArgumentParser(description=__doc__)
 parser.add_argument("log_file", type=Path, help="path to a log file you are authorized to analyze")
 parser.add_argument("--output", type=Path, default=Path("auth_log_report.json"), help="report output
path")
 parser.add_argument("--threshold", type=int, default=5, help="flag source IPs with at least this
many failed attempts")
 args = parser.parse_args()
 if args.threshold < 1:
 parser.error("--threshold must be at least 1")
 if not args.log_file.is_file():
 parser.error(f"log file does not exist: {args.log_file}")
 report = parse_log(args.log_file)
 report["threshold"] = args.threshold
 report["source_ips_over_threshold"] = {
 ip: count for ip, count in report["failed_attempts_by_source_ip"].items() if count >= args.
threshold
 }
 args.output.parent.mkdir(parents=True, exist_ok=True)
 args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
 print(f"Lines read: {report['lines_read']}")
 print(f"Failed logins: {report['failed_login_count']}")
 print(f"Successful logins: {report['successful_login_count']}")
 print(f"Source IPs at/above threshold ({args.threshold}): {len(report[
'source_ips_over_threshold'])}")
 print(f"Report saved to: {args.output}")
 return 0
if __name__ == "__main__":
 raise SystemExit(main())
