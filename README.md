Original path: cybersecurity-auth-log-analyzer/README.md
Note: this PDF displays the file's text. It is not a runnable replacement for the original .py, .sql, .yml, or configuration file.
# Cybersecurity Authentication Log Analyzer
A defensive Python tool for analyzing Linux/OpenSSH-style authentication logs. It identifies failed and
successful login events, summarizes failed attempts by source IP and username, and writes a JSON report
that highlights IPs meeting a configurable failure threshold.
## Requirements
- Python 3.10+
- No third-party packages required
## Run against the included synthetic sample
From this folder:
```bash
python -m src.analyzer sample_data/auth.log --output reports/auth_log_report.json --threshold 3
```
## Run tests
```bash
python -m unittest discover -s tests -v
```
## Example output
The included sample has 10 log lines, 8 failed-login events, and 2 successful-login events. With `--
threshold 3`, the report flags `203.0.113.7` (5 failures). These IP ranges are reserved for
documentation and the sample data is synthetic.
## What it demonstrates
- Regular expressions and log parsing
- Event classification and aggregation
- JSON reporting and threshold-based triage
- Unit testing and command-line argument validation
## Scope and limitations
This is a learning project, not a full SIEM or intrusion detector. It recognizes common OpenSSH passwordfailure and accepted-login message formats; other Linux distributions, locales, and authentication
methods may require additional parsers. Analyze only logs you are authorized to access. A repeated
failure count is an investigation signal, not proof of malicious activity.
