#!/usr/bin/env python3
"""
Report Generator - Generate execution reports in multiple formats
报告生成器 - 生成多格式执行报告
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List


class ReportGenerator:
    """Generate execution reports in multiple formats."""

    def __init__(self):
        self.config_dir = Path(os.path.expanduser("~")) / ".agentshield"

    def generate(self, entries: List[Dict], output_path: str, format: str = "auto") -> str:
        """Generate a report from audit entries."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        if format == "auto":
            suffix = path.suffix.lower()
            format = suffix.lstrip(".")

        if format == "json":
            return self._generate_json(entries, path)
        elif format == "html":
            return self._generate_html(entries, path)
        elif format == "md":
            return self._generate_markdown(entries, path)
        else:
            return self._generate_json(entries, path)

    def _generate_json(self, entries: List[Dict], path: Path) -> str:
        """Generate JSON report."""
        report = {
            "report_type": "AgentShield Audit Report",
            "generated_at": datetime.now().isoformat(),
            "total_entries": len(entries),
            "summary": self._compute_summary(entries),
            "entries": entries,
        }

        with open(path, "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        return str(path)

    def _generate_html(self, entries: List[Dict], path: Path) -> str:
        """Generate HTML report with styling."""
        summary = self._compute_summary(entries)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AgentShield Security Report</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }}
.container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
.header {{ text-align: center; padding: 30px; border-bottom: 1px solid #30363d; margin-bottom: 30px; }}
.header h1 {{ color: #58a6ff; font-size: 2em; margin-bottom: 10px; }}
.header .meta {{ color: #8b949e; }}
.summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }}
.card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }}
.card h3 {{ color: #8b949e; font-size: 0.9em; margin-bottom: 5px; }}
.card .value {{ font-size: 1.8em; font-weight: bold; }}
.card.green .value {{ color: #3fb950; }}
.card.yellow .value {{ color: #d29922; }}
.card.red .value {{ color: #f85149; }}
.card.blue .value {{ color: #58a6ff; }}
table {{ width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; }}
th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #30363d; }}
th {{ background: #21262d; color: #58a6ff; font-weight: 600; }}
tr:hover {{ background: #1c2128; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.85em; }}
.badge-low {{ background: #1f3d1f; color: #3fb950; }}
.badge-medium {{ background: #3d2e1f; color: #d29922; }}
.badge-high {{ background: #3d1f1f; color: #f85149; }}
.footer {{ text-align: center; padding: 20px; color: #8b949e; border-top: 1px solid #30363d; margin-top: 30px; }}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>🛡️ AgentShield Security Report</h1>
<div class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Total Entries: {len(entries)}</div>
</div>

<div class="summary">
<div class="card blue">
<h3>Total Executions</h3>
<div class="value">{summary['total']}</div>
</div>
<div class="card green">
<h3>Success Rate</h3>
<div class="value">{summary['success_rate']}%</div>
</div>
<div class="card yellow">
<h3>Avg Risk Score</h3>
<div class="value">{summary['avg_risk']}</div>
</div>
<div class="card {'red' if summary['high_risk'] > 0 else 'green'}">
<h3>High Risk</h3>
<div class="value">{summary['high_risk']}</div>
</div>
</div>

<table>
<tr><th>Time</th><th>Session</th><th>Command</th><th>Exit</th><th>Risk</th><th>Duration</th></tr>
"""
        for entry in entries:
            risk = entry.get("risk_score", 0)
            risk_level = entry.get("risk_level", "low")
            badge_class = f"badge-{risk_level}"
            html += f"""<tr>
<td>{entry.get('timestamp', '')[:19]}</td>
<td><code>{entry.get('session_id', '-')[:8]}</code></td>
<td>{entry.get('command', '-')[:40]}</td>
<td>{entry.get('exit_code', '-')}</td>
<td><span class="badge {badge_class}">{risk} ({risk_level})</span></td>
<td>{entry.get('duration', 0)}s</td>
</tr>
"""
        html += """</table>
<div class="footer">
<p>🛡️ Generated by AgentShield-CLI v1.0.0 | Zero Dependencies, Cross-Platform</p>
</div>
</div>
</body>
</html>"""

        with open(path, "w") as f:
            f.write(html)

        return str(path)

    def _generate_markdown(self, entries: List[Dict], path: Path) -> str:
        """Generate Markdown report."""
        summary = self._compute_summary(entries)

        md = f"""# 🛡️ AgentShield Security Report

> Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Total Entries: {len(entries)}

## 📊 Summary

| Metric | Value |
|--------|-------|
| Total Executions | {summary['total']} |
| Success Rate | {summary['success_rate']}% |
| Average Risk Score | {summary['avg_risk']} |
| High Risk Count | {summary['high_risk']} |
| Average Duration | {summary['avg_duration']}s |

## 📜 Execution Details

| Time | Session | Command | Exit | Risk | Duration |
|------|---------|---------|------|------|----------|
"""
        for entry in entries:
            risk = entry.get("risk_score", 0)
            risk_level = entry.get("risk_level", "low")
            risk_icon = "🔴" if risk >= 70 else "🟡" if risk >= 40 else "🟢"
            md += f"| {entry.get('timestamp', '')[:19]} | {entry.get('session_id', '-')[:8]} | {entry.get('command', '-')[:30]} | {entry.get('exit_code', '-')} | {risk_icon} {risk} ({risk_level}) | {entry.get('duration', 0)}s |\n"

        md += f"\n---\n*🛡️ Generated by AgentShield-CLI v1.0.0*\n"

        with open(path, "w") as f:
            f.write(md)

        return str(path)

    def _compute_summary(self, entries: List[Dict]) -> Dict[str, Any]:
        """Compute summary statistics from entries."""
        if not entries:
            return {
                "total": 0,
                "success_rate": 0,
                "avg_risk": 0,
                "high_risk": 0,
                "avg_duration": 0,
            }

        total = len(entries)
        successes = sum(1 for e in entries if e.get("exit_code") == 0)
        risks = [e.get("risk_score", 0) for e in entries]
        durations = [e.get("duration", 0) for e in entries]
        high_risk = sum(1 for r in risks if r >= 70)

        return {
            "total": total,
            "success_rate": round(successes / total * 100, 1) if total else 0,
            "avg_risk": round(sum(risks) / len(risks), 1) if risks else 0,
            "high_risk": high_risk,
            "avg_duration": round(sum(durations) / len(durations), 3) if durations else 0,
        }
