#!/usr/bin/env python3
"""
CLI Module - Command Line Interface for AgentShield-CLI
CLI模块 - AgentShield-CLI 命令行接口
"""

import argparse
import sys
import os


def create_parser() -> argparse.ArgumentParser:
    """Create the main argument parser."""
    parser = argparse.ArgumentParser(
        prog="agentshield",
        description="🛡️ AgentShield-CLI - Lightweight Terminal AI Agent Execution Security Sandbox Engine\n"
                    "轻量级终端AI Agent执行安全沙箱引擎",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  agentshield run "python script.py"              Run a command in sandbox
  agentshield run --policy strict "npm install"    Run with strict policy
  agentshield run --timeout 30 "node app.js"       Run with 30s timeout
  agentshield audit --format json                  View audit log in JSON
  agentshield audit --export report.html           Export audit report to HTML
  agentshield policy show                          Show current policy config
  agentshield policy init --template strict        Initialize a strict policy
  agentshield status                               Show sandbox status
  agentshield tui                                  Launch TUI dashboard
        """
    )

    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"%(prog)s v{__import__('src').__version__}"
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Available commands")

    # === run command ===
    run_parser = subparsers.add_parser(
        "run",
        help="🚀 Execute a command in the security sandbox",
        description="Execute a command in the AgentShield security sandbox with policy enforcement"
    )
    run_parser.add_argument(
        "command",
        help="The command to execute in the sandbox"
    )
    run_parser.add_argument(
        "--policy", "-p",
        default="default",
        choices=["default", "strict", "permissive", "custom"],
        help="Policy template to use (default: default)"
    )
    run_parser.add_argument(
        "--policy-file",
        help="Path to a custom YAML policy file"
    )
    run_parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=60,
        help="Execution timeout in seconds (default: 60)"
    )
    run_parser.add_argument(
        "--memory-limit",
        type=int,
        default=512,
        help="Memory limit in MB (default: 512)"
    )
    run_parser.add_argument(
        "--network",
        choices=["allow", "deny", "restricted"],
        default="restricted",
        help="Network access mode (default: restricted)"
    )
    run_parser.add_argument(
        "--cwd",
        help="Working directory for the sandboxed command"
    )
    run_parser.add_argument(
        "--env",
        action="append",
        default=[],
        help="Environment variables to pass (format: KEY=VALUE)"
    )
    run_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be executed without actually running"
    )
    run_parser.add_argument(
        "--verbose", "-V",
        action="store_true",
        help="Enable verbose output"
    )

    # === audit command ===
    audit_parser = subparsers.add_parser(
        "audit",
        help="📋 View and manage audit logs",
        description="View, filter, and export AgentShield audit logs"
    )
    audit_parser.add_argument(
        "--format", "-f",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)"
    )
    audit_parser.add_argument(
        "--export",
        help="Export audit log to file (supports .json, .html, .md)"
    )
    audit_parser.add_argument(
        "--limit", "-l",
        type=int,
        default=50,
        help="Number of entries to show (default: 50)"
    )
    audit_parser.add_argument(
        "--filter",
        help="Filter by severity: info,warn,error,critical"
    )
    audit_parser.add_argument(
        "--session",
        help="Filter by session ID"
    )
    audit_parser.add_argument(
        "--since",
        help="Show entries since timestamp (ISO format)"
    )
    audit_parser.add_argument(
        "--clear",
        action="store_true",
        help="Clear all audit logs"
    )

    # === policy command ===
    policy_parser = subparsers.add_parser(
        "policy",
        help="📜 Manage security policies",
        description="View, create, and manage AgentShield security policies"
    )
    policy_sub = policy_parser.add_subparsers(dest="policy_action")

    policy_show = policy_sub.add_parser("show", help="Show current policy configuration")
    policy_show.add_argument("--name", "-n", default="default", help="Policy name to show")

    policy_init = policy_sub.add_parser("init", help="Initialize a new policy file")
    policy_init.add_argument(
        "--template",
        choices=["default", "strict", "permissive"],
        default="default",
        help="Policy template to use"
    )
    policy_init.add_argument(
        "--output", "-o",
        default="agentshield-policy.yaml",
        help="Output file path"
    )

    policy_validate = policy_sub.add_parser("validate", help="Validate a policy file")
    policy_validate.add_argument("file", help="Policy file to validate")

    policy_list = policy_sub.add_parser("list", help="List available policy templates")

    # === status command ===
    status_parser = subparsers.add_parser(
        "status",
        help="📊 Show sandbox system status",
        description="Display current sandbox configuration, resource usage, and system info"
    )
    status_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format"
    )

    # === tui command ===
    tui_parser = subparsers.add_parser(
        "tui",
        help="🖥️ Launch TUI dashboard",
        description="Launch the terminal UI dashboard for real-time monitoring"
    )

    # === config command ===
    config_parser = subparsers.add_parser(
        "config",
        help="⚙️ Manage AgentShield configuration",
        description="View and modify AgentShield global configuration"
    )
    config_sub = config_parser.add_subparsers(dest="config_action")
    config_show = config_sub.add_parser("show", help="Show current configuration")
    config_set = config_sub.add_parser("set", help="Set a configuration value")
    config_set.add_argument("key", help="Configuration key")
    config_set.add_argument("value", help="Configuration value")
    config_reset = config_sub.add_parser("reset", help="Reset configuration to defaults")

    # === history command ===
    history_parser = subparsers.add_parser(
        "history",
        help="📜 View execution history",
        description="View past sandbox execution history and results"
    )
    history_parser.add_argument(
        "--limit", "-l",
        type=int,
        default=20,
        help="Number of entries to show"
    )
    history_parser.add_argument(
        "--format", "-f",
        choices=["table", "json"],
        default="table",
        help="Output format"
    )

    # === scan command (NEW) ===
    scan_parser = subparsers.add_parser(
        "scan",
        help="🔍 Scan AI Agent Skill files for security vulnerabilities",
        description="Security scanner for AI Agent skills, MCP tools, and code files"
    )
    scan_parser.add_argument(
        "path",
        help="Path to file or directory to scan"
    )
    scan_parser.add_argument(
        "--format",
        choices=["terminal", "json", "markdown", "sarif"],
        default="terminal",
        help="Output format (default: terminal)"
    )
    scan_parser.add_argument(
        "--output", "-o",
        help="Output file path (default: print to terminal)"
    )
    scan_parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="Do not scan subdirectories"
    )
    scan_parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Only show issues at or above this severity level"
    )

    return parser


def main() -> int:
    """Main entry point for CLI."""
    parser = create_parser()
    args = parser.parse_args()

    if not args.subcommand:
        parser.print_help()
        return 0

    try:
        if args.subcommand == "run":
            from src.core.runner import run_command
            return run_command(args)

        elif args.subcommand == "audit":
            from src.audit.manager import AuditManager
            manager = AuditManager()
            return manager.handle(args)

        elif args.subcommand == "policy":
            from src.policy.manager import PolicyManager
            manager = PolicyManager()
            return manager.handle(args)

        elif args.subcommand == "status":
            from src.core.status import show_status
            return show_status(args)

        elif args.subcommand == "tui":
            from src.tui.dashboard import launch_dashboard
            return launch_dashboard()

        elif args.subcommand == "config":
            from src.core.config import ConfigManager
            manager = ConfigManager()
            return manager.handle(args)

        elif args.subcommand == "history":
            from src.audit.history import HistoryManager
            manager = HistoryManager()
            return manager.handle(args)

        elif args.subcommand == "scan":
            from src.core.scanner import run_scan
            return run_scan(args)

        else:
            parser.print_help()
            return 1

    except KeyboardInterrupt:
        print("\n⚠️  Operation cancelled by user")
        return 130
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        if os.environ.get("AGENTSHIELD_DEBUG"):
            import traceback
            traceback.print_exc()
        return 1
