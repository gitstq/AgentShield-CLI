#!/usr/bin/env python3
"""
History Manager - Track and manage execution history
历史管理器 - 跟踪和管理执行历史
"""

import os
import json
from pathlib import Path
from datetime import datetime


class HistoryManager:
    """Track and manage sandbox execution history."""

    def __init__(self):
        self.config_dir = Path(os.path.expanduser("~")) / ".agentshield"
        self.history_dir = self.config_dir / "history"
        self.history_file = self.history_dir / "executions.json"
        self.history_dir.mkdir(parents=True, exist_ok=True)

    def record(self, config, result):
        """Record an execution to history."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "session_id": result.session_id,
            "command": config.command,
            "policy": config.policy_name,
            "exit_code": result.exit_code,
            "duration": round(result.duration, 3),
            "timed_out": result.timed_out,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "cwd": config.cwd,
            "network_mode": config.network_mode,
            "memory_limit_mb": config.memory_limit,
        }

        data = self._load_data()
        data["executions"].append(entry)

        # Keep only last 1000 entries
        if len(data["executions"]) > 1000:
            data["executions"] = data["executions"][-1000:]

        data["total_count"] = len(data["executions"])

        with open(self.history_file, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _load_data(self) -> dict:
        """Load history data from file."""
        if self.history_file.exists():
            try:
                with open(self.history_file) as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return {"executions": [], "total_count": 0}

    def get_history(self, limit: int = 20) -> list:
        """Get recent execution history."""
        data = self._load_data()
        return list(reversed(data["executions"][-limit:]))

    def handle(self, args) -> int:
        """Handle CLI history commands."""
        entries = self.get_history(limit=args.limit)

        if not entries:
            print("📜 No execution history found")
            print("   Run 'agentshield run <command>' to start")
            return 0

        if args.format == "json":
            print(json.dumps(entries, indent=2, ensure_ascii=False))
            return 0

        # Table format
        print(f"\n📜 Execution History (last {len(entries)} runs)\n")
        print(f"{'#':<4} {'Time':<20} {'Session':<10} {'Exit':<6} {'Risk':<8} {'Duration':<10} {'Command'}")
        print(f"{'─'*4} {'─'*20} {'─'*10} {'─'*6} {'─'*8} {'─'*10} {'─'*30}")

        for i, entry in enumerate(entries, 1):
            timestamp = entry.get("timestamp", "")[:19]
            session = entry.get("session_id", "-")[:8]
            exit_code = str(entry.get("exit_code", "-"))
            risk = f"{entry.get('risk_score', 0)} ({entry.get('risk_level', '-')})"
            duration = f"{entry.get('duration', 0)}s"
            command = entry.get("command", "-")[:35]

            # Color indicators
            risk_score = entry.get("risk_score", 0)
            risk_icon = "🔴" if risk_score >= 70 else "🟡" if risk_score >= 40 else "🟢"
            exit_icon = "✅" if entry.get("exit_code") == 0 else "❌"

            print(f"{i:<4} {timestamp:<20} {session:<10} {exit_icon}{exit_code:<5} {risk_icon}{risk:<8} {duration:<10} {command}")

        print()
        return 0
