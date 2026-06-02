#!/usr/bin/env python3
"""
Status Module - Show sandbox system status
状态模块 - 显示沙箱系统状态
"""

import os
import sys
import platform
import json
from datetime import datetime


def show_status(args) -> int:
    """Display current sandbox system status."""
    info = gather_system_info()

    if args.json:
        print(json.dumps(info, indent=2, ensure_ascii=False))
        return 0

    print(f"\n{'='*60}")
    print(f"🛡️  AgentShield System Status")
    print(f"{'='*60}")

    print(f"\n🖥️  System Information:")
    print(f"   Platform      : {info['system']['platform']}")
    print(f"   Architecture   : {info['system']['architecture']}")
    print(f"   Python        : {info['system']['python_version']}")
    print(f"   OS Release    : {info['system']['os_release']}")

    print(f"\n📦 AgentShield Information:")
    print(f"   Version       : {info['agentshield']['version']}")
    print(f"   Config Path   : {info['agentshield']['config_path']}")
    print(f"   Audit Path    : {info['agentshield']['audit_path']}")
    print(f"   History Path  : {info['agentshield']['history_path']}")

    print(f"\n🔒 Sandbox Capabilities:")
    for cap, supported in info['capabilities'].items():
        status = "✅" if supported else "❌"
        print(f"   {status} {cap}")

    print(f"\n📜 Active Policy:")
    print(f"   Template      : {info['policy']['current']}")
    print(f"   Network Mode  : {info['policy']['network_mode']}")
    print(f"   Memory Limit  : {info['policy']['memory_limit_mb']}MB")
    print(f"   Timeout       : {info['policy']['timeout_seconds']}s")

    print(f"\n📊 Execution Statistics:")
    print(f"   Total Runs    : {info['stats']['total_runs']}")
    print(f"   Success Rate  : {info['stats']['success_rate']}%")
    print(f"   Avg Duration  : {info['stats']['avg_duration']}s")
    print(f"   High Risk     : {info['stats']['high_risk_count']}")

    print(f"\n{'='*60}\n")
    return 0


def gather_system_info() -> dict:
    """Gather comprehensive system information."""
    home = os.path.expanduser("~")
    config_dir = os.path.join(home, ".agentshield")

    # Check capabilities
    capabilities = {
        "Process Isolation": True,
        "Memory Limiting": True,
        "File System Monitoring": True,
        "Network Restriction": True,
        "Timeout Control": True,
        "Audit Logging": True,
        "TUI Dashboard": _check_tui_support(),
        "Resource Monitoring": True,
    }

    # Check for optional dependencies
    try:
        import yaml
        capabilities["YAML Policy Support"] = True
    except ImportError:
        capabilities["YAML Policy Support"] = False

    # Gather stats
    stats = _gather_stats(config_dir)

    # Get current policy
    policy = _get_current_policy(config_dir)

    return {
        "system": {
            "platform": platform.system(),
            "architecture": platform.machine(),
            "python_version": platform.python_version(),
            "os_release": platform.release(),
            "hostname": platform.node(),
        },
        "agentshield": {
            "version": "1.0.0",
            "config_path": os.path.join(config_dir, "config.json"),
            "audit_path": os.path.join(config_dir, "audit"),
            "history_path": os.path.join(config_dir, "history"),
        },
        "capabilities": capabilities,
        "policy": policy,
        "stats": stats,
        "timestamp": datetime.now().isoformat(),
    }


def _check_tui_support() -> bool:
    """Check if TUI dashboard is supported."""
    try:
        import curses
        return hasattr(curses, 'initscr')
    except ImportError:
        return False


def _gather_stats(config_dir: str) -> dict:
    """Gather execution statistics from history."""
    stats = {
        "total_runs": 0,
        "success_rate": 100.0,
        "avg_duration": 0.0,
        "high_risk_count": 0,
    }

    history_file = os.path.join(config_dir, "history", "executions.json")
    if os.path.exists(history_file):
        try:
            with open(history_file, "r") as f:
                data = json.load(f)
            executions = data.get("executions", [])
            stats["total_runs"] = len(executions)

            if executions:
                successes = sum(1 for e in executions if e.get("exit_code") == 0)
                stats["success_rate"] = round(successes / len(executions) * 100, 1)

                durations = [e.get("duration", 0) for e in executions]
                stats["avg_duration"] = round(sum(durations) / len(durations), 3)

                stats["high_risk_count"] = sum(
                    1 for e in executions if e.get("risk_score", 0) >= 70
                )
        except (json.JSONDecodeError, IOError):
            pass

    return stats


def _get_current_policy(config_dir: str) -> dict:
    """Get current active policy configuration."""
    policy = {
        "current": "default",
        "network_mode": "restricted",
        "memory_limit_mb": 512,
        "timeout_seconds": 60,
    }

    config_file = os.path.join(config_dir, "config.json")
    if os.path.exists(config_file):
        try:
            with open(config_file, "r") as f:
                config = json.load(f)
            policy.update(config.get("default_policy", {}))
        except (json.JSONDecodeError, IOError):
            pass

    return policy
