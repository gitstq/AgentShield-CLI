#!/usr/bin/env python3
"""
TUI Dashboard - Terminal UI for real-time monitoring
TUI仪表盘 - 实时监控终端界面
"""

import sys
import os
import time
import json
from pathlib import Path
from datetime import datetime


def launch_dashboard() -> int:
    """Launch the TUI dashboard."""
    # Check for curses support
    try:
        import curses
    except ImportError:
        print("❌ TUI dashboard requires 'curses' module")
        print("   On Linux/macOS: curses is built-in")
        print("   On Windows: pip install windows-curses")
        return 1

    try:
        curses.wrapper(_dashboard_loop)
    except KeyboardInterrupt:
        pass

    return 0


def _dashboard_loop(stdscr):
    """Main TUI dashboard loop."""
    # Initialize curses
    curses.curs_set(0)
    stdscr.nodelay(1)
    stdscr.timeout(500)

    # Colors
    curses.start_color()
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)
    curses.init_pair(4, curses.COLOR_CYAN, curses.COLOR_BLACK)
    curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLACK)
    curses.init_pair(6, curses.COLOR_MAGENTA, curses.COLOR_BLACK)

    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()

        # Header
        _draw_header(stdscr, w)

        # System info
        _draw_system_info(stdscr, w)

        # Recent executions
        _draw_recent_executions(stdscr, h, w)

        # Policy info
        _draw_policy_info(stdscr, h, w)

        # Footer
        _draw_footer(stdscr, h, w)

        stdscr.refresh()

        # Handle input
        try:
            key = stdscr.getch()
            if key == ord('q') or key == ord('Q') or key == 27:  # q, Q, ESC
                break
            elif key == ord('r') or key == ord('R'):
                pass  # Refresh (already auto-refreshing)
        except:
            break

        time.sleep(0.5)


def _draw_header(stdscr, w):
    """Draw dashboard header."""
    title = "🛡️  AgentShield-CLI Dashboard"
    version = "v1.0.0"
    time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    stdscr.addstr(0, 2, title, curses.color_pair(4) | curses.A_BOLD)
    stdscr.addstr(0, w - len(version) - 2, version, curses.color_pair(5))
    stdscr.addstr(1, 2, time_str, curses.color_pair(5))

    # Separator
    stdscr.addstr(2, 0, "─" * w, curses.color_pair(5))


def _draw_system_info(stdscr, w):
    """Draw system information panel."""
    y = 3
    stdscr.addstr(y, 2, "🖥️  System", curses.color_pair(4) | curses.A_BOLD)

    import platform
    info_lines = [
        f"Platform: {platform.system()} {platform.release()} ({platform.machine()})",
        f"Python: {platform.python_version()}",
    ]

    for i, line in enumerate(info_lines):
        stdscr.addstr(y + 1 + i, 4, line, curses.color_pair(5))

    # Separator
    stdscr.addstr(y + len(info_lines) + 1, 0, "─" * w, curses.color_pair(5))


def _draw_recent_executions(stdscr, h, w):
    """Draw recent execution history."""
    y = 8
    stdscr.addstr(y, 2, "📜 Recent Executions", curses.color_pair(4) | curses.A_BOLD)

    # Load history
    config_dir = Path(os.path.expanduser("~")) / ".agentshield"
    history_file = config_dir / "history" / "executions.json"

    entries = []
    if history_file.exists():
        try:
            with open(history_file) as f:
                data = json.load(f)
            entries = list(reversed(data.get("executions", [])[-8:]))
        except (json.JSONDecodeError, IOError):
            pass

    if not entries:
        stdscr.addstr(y + 1, 4, "No executions recorded yet", curses.color_pair(5))
        stdscr.addstr(y + 2, 4, "Run 'agentshield run <command>' to start", curses.color_pair(5))
        return

    # Table header
    header = f"{'Time':<18} {'Session':<9} {'Exit':<5} {'Risk':<10} {'Command'}"
    stdscr.addstr(y + 1, 4, header, curses.color_pair(6))

    for i, entry in enumerate(entries[:min(8, h - y - 5)]):
        timestamp = entry.get("timestamp", "")[:19]
        session = entry.get("session_id", "-")[:8]
        exit_code = str(entry.get("exit_code", "-"))
        risk = f"{entry.get('risk_score', 0)} ({entry.get('risk_level', '-')})"
        command = entry.get("command", "-")[:w - 55]

        risk_score = entry.get("risk_score", 0)
        if risk_score >= 70:
            color = curses.color_pair(3)
        elif risk_score >= 40:
            color = curses.color_pair(2)
        else:
            color = curses.color_pair(1)

        line = f"{timestamp:<18} {session:<9} {exit_code:<5} {risk:<10} {command}"
        stdscr.addstr(y + 2 + i, 4, line[:w-6], color)

    # Separator
    sep_y = y + min(len(entries) + 2, 10)
    if sep_y < h - 4:
        stdscr.addstr(sep_y, 0, "─" * w, curses.color_pair(5))


def _draw_policy_info(stdscr, h, w):
    """Draw current policy information."""
    y = min(h - 4, 18)
    stdscr.addstr(y, 2, "📜 Active Policy: default", curses.color_pair(4) | curses.A_BOLD)

    policy_info = "Network: restricted | Memory: 512MB | Timeout: 60s"
    stdscr.addstr(y + 1, 4, policy_info, curses.color_pair(5))


def _draw_footer(stdscr, h, w):
    """Draw footer with controls."""
    footer = "Press [Q] to quit | Auto-refresh: 500ms"
    stdscr.addstr(h - 1, 2, footer, curses.color_pair(5))
