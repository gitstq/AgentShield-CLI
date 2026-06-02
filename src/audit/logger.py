#!/usr/bin/env python3
"""
Audit Logger - Record and manage execution audit logs
审计日志 - 记录和管理执行审计日志
"""

import os
import json
from pathlib import Path
from datetime import datetime
from typing import Optional


class AuditLogger:
    """Record and manage AgentShield audit logs."""

    def __init__(self):
        self.config_dir = Path(os.path.expanduser("~")) / ".agentshield"
        self.audit_dir = self.config_dir / "audit"
        self.audit_dir.mkdir(parents=True, exist_ok=True)

    def log_execution(self, config, result):
        """Log a sandbox execution event."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "session_id": result.session_id,
            "event": "execution",
            "command": config.command,
            "policy": config.policy_name,
            "exit_code": result.exit_code,
            "duration": round(result.duration, 3),
            "timed_out": result.timed_out,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "files_created": len(result.files_created),
            "files_modified": len(result.files_modified),
            "files_deleted": len(result.files_deleted),
            "policy_violations": len(result.policy_violations),
            "stdout_lines": len(result.stdout.split("\n")) if result.stdout else 0,
            "stderr_lines": len(result.stderr.split("\n")) if result.stderr else 0,
        }

        self._append_entry(entry)

    def log_policy_violation(self, session_id: str, violation: dict):
        """Log a policy violation event."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "session_id": session_id,
            "event": "policy_violation",
            "severity": violation.get("severity", "warn"),
            "rule": violation.get("rule", "unknown"),
            "message": violation.get("message", ""),
        }
        self._append_entry(entry)

    def log_system_event(self, event_type: str, message: str, details: dict = None):
        """Log a system event."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "event": f"system.{event_type}",
            "message": message,
            "details": details or {},
        }
        self._append_entry(entry)

    def _append_entry(self, entry: dict):
        """Append an entry to the audit log file."""
        # Daily log file
        today = datetime.now().strftime("%Y-%m-%d")
        log_file = self.audit_dir / f"audit-{today}.jsonl"

        with open(log_file, "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def get_entries(self, limit: int = 50, severity: str = None,
                    session_id: str = None, since: str = None) -> list:
        """Get audit log entries with optional filtering."""
        entries = []

        # Read all log files
        for log_file in sorted(self.audit_dir.glob("audit-*.jsonl"), reverse=True):
            try:
                with open(log_file) as f:
                    for line in f:
                        try:
                            entry = json.loads(line.strip())
                            entries.append(entry)
                        except json.JSONDecodeError:
                            continue
            except IOError:
                continue

        # Apply filters
        if severity:
            entries = [e for e in entries if e.get("severity") == severity]

        if session_id:
            entries = [e for e in entries if e.get("session_id") == session_id]

        if since:
            try:
                since_dt = datetime.fromisoformat(since)
                entries = [
                    e for e in entries
                    if datetime.fromisoformat(e["timestamp"]) >= since_dt
                ]
            except ValueError:
                pass

        return entries[:limit]

    def clear_logs(self):
        """Clear all audit logs."""
        for log_file in self.audit_dir.glob("audit-*.jsonl"):
            log_file.unlink()

    def handle(self, args) -> int:
        """Handle CLI audit commands."""
        if args.clear:
            self.clear_logs()
            print("✅ Audit logs cleared")
            return 0

        entries = self.get_entries(
            limit=args.limit,
            severity=args.filter,
            session_id=args.session,
            since=args.since,
        )

        if not entries:
            print("📋 No audit entries found")
            return 0

        if args.format == "json":
            print(json.dumps(entries, indent=2, ensure_ascii=False))
        elif args.format == "csv":
            self._print_csv(entries)
        else:
            self._print_table(entries)

        # Export if requested
        if args.export:
            self._export(entries, args.export)

        return 0

    def _print_table(self, entries: list):
        """Print entries as a formatted table."""
        print(f"\n📋 AgentShield Audit Log ({len(entries)} entries)\n")
        print(f"{'Time':<20} {'Session':<10} {'Event':<20} {'Severity':<10} {'Details'}")
        print(f"{'─'*20} {'─'*10} {'─'*20} {'─'*10} {'─'*30}")

        for entry in entries:
            timestamp = entry.get("timestamp", "")[:19]
            session = entry.get("session_id", "-")[:8]
            event = entry.get("event", "-")[:20]
            severity = entry.get("severity", "-")[:10]

            # Build details string
            details_parts = []
            if entry.get("command"):
                details_parts.append(f"cmd: {entry['command'][:30]}")
            if entry.get("message"):
                details_parts.append(entry["message"][:30])
            if entry.get("risk_score") is not None:
                details_parts.append(f"risk: {entry['risk_score']}")
            details = " | ".join(details_parts)[:40]

            print(f"{timestamp:<20} {session:<10} {event:<20} {severity:<10} {details}")

        print()

    def _print_csv(self, entries: list):
        """Print entries as CSV."""
        import csv
        import io
        if not entries:
            return

        writer = csv.writer(sys.stdout)
        headers = list(entries[0].keys())
        writer.writerow(headers)
        for entry in entries:
            writer.writerow([entry.get(h, "") for h in headers])

    def _export(self, entries: list, filepath: str):
        """Export entries to a file."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        suffix = path.suffix.lower()
        if suffix == ".json":
            with open(path, "w") as f:
                json.dump(entries, f, indent=2, ensure_ascii=False)
        elif suffix == ".html":
            self._export_html(entries, path)
        elif suffix == ".md":
            self._export_markdown(entries, path)
        else:
            with open(path, "w") as f:
                json.dump(entries, f, indent=2, ensure_ascii=False)

        print(f"✅ Audit log exported to: {path}")

    def _export_html(self, entries: list, path: Path):
        """Export audit log as HTML report."""
        html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AgentShield Audit Report</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 20px; background: #0d1117; color: #c9d1d9; }
h1 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
table { border-collapse: collapse; width: 100%; margin-top: 20px; }
th, td { border: 1px solid #30363d; padding: 8px 12px; text-align: left; }
th { background: #161b22; color: #58a6ff; }
tr:hover { background: #161b22; }
.severity-critical { color: #f85149; font-weight: bold; }
.severity-error { color: #f85149; }
.severity-warn { color: #d29922; }
.severity-info { color: #58a6ff; }
.risk-high { background: #3d1f1f; }
.risk-medium { background: #3d2e1f; }
.risk-low { background: #1f3d1f; }
</style>
</head>
<body>
<h1>🛡️ AgentShield Audit Report</h1>
<p>Generated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
<p>Total entries: """ + str(len(entries)) + """</p>
<table>
<tr><th>Time</th><th>Session</th><th>Event</th><th>Severity</th><th>Details</th></tr>
"""
        for entry in entries:
            severity = entry.get("severity", "info")
            risk = entry.get("risk_score", 0)
            risk_class = "risk-high" if risk >= 70 else "risk-medium" if risk >= 40 else "risk-low"
            html += f"""<tr class="{risk_class}">
<td>{entry.get('timestamp', '')[:19]}</td>
<td>{entry.get('session_id', '-')[:8]}</td>
<td>{entry.get('event', '-')}</td>
<td class="severity-{severity}">{severity}</td>
<td>{entry.get('command', entry.get('message', ''))[:50]}</td>
</tr>
"""
        html += "</table></body></html>"

        with open(path, "w") as f:
            f.write(html)

    def _export_markdown(self, entries: list, path: Path):
        """Export audit log as Markdown."""
        md = f"# 🛡️ AgentShield Audit Report\n\n"
        md += f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        md += f"**Total Entries**: {len(entries)}\n\n"
        md += "| Time | Session | Event | Severity | Details |\n"
        md += "|------|---------|-------|----------|--------|\n"

        for entry in entries:
            timestamp = entry.get("timestamp", "")[:19]
            session = entry.get("session_id", "-")[:8]
            event = entry.get("event", "-")
            severity = entry.get("severity", "-")
            details = entry.get("command", entry.get("message", ""))[:50]
            md += f"| {timestamp} | {session} | {event} | {severity} | {details} |\n"

        with open(path, "w") as f:
            f.write(md)


# Need sys for CSV export
import sys
