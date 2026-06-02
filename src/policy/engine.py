#!/usr/bin/env python3
"""
Policy Engine - Declarative YAML/JSON security policy management
策略引擎 - 声明式安全策略管理
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime


# Built-in policy templates
POLICY_TEMPLATES = {
    "default": {
        "name": "default",
        "description": "Balanced security policy for general development tasks",
        "network": {
            "mode": "restricted",
            "allowed_hosts": [],
            "blocked_hosts": [],
            "allowed_ports": [80, 443, 8080, 3000, 5000, 8000, 8888],
            "blocked_ports": [],
        },
        "filesystem": {
            "mode": "restricted",
            "allowed_paths": [],
            "blocked_paths": [
                "/etc/shadow",
                "/etc/passwd",
                "/etc/sudoers",
                "~/.ssh",
                "~/.gnupg",
                "~/.aws",
                "~/.config/gcloud",
            ],
            "max_file_size_mb": 100,
            "max_total_size_mb": 500,
            "allow_symlinks": False,
        },
        "process": {
            "max_processes": 10,
            "allowed_commands": [],
            "blocked_commands": ["rm -rf /", "mkfs", "dd if=", ":(){ :|:& };:"],
            "allow_fork": True,
            "allow_exec": True,
        },
        "environment": {
            "blocked_vars": ["AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "PRIVATE_KEY"],
            "allowed_vars": [],
        },
        "resources": {
            "memory_limit_mb": 512,
            "cpu_limit_percent": 80,
            "timeout_seconds": 60,
            "max_output_size_kb": 1024,
        },
    },
    "strict": {
        "name": "strict",
        "description": "Maximum security policy for untrusted code execution",
        "network": {
            "mode": "deny",
            "allowed_hosts": [],
            "blocked_hosts": ["*"],
            "allowed_ports": [],
            "blocked_ports": [],
        },
        "filesystem": {
            "mode": "deny",
            "allowed_paths": [],
            "blocked_paths": ["*"],
            "max_file_size_mb": 10,
            "max_total_size_mb": 50,
            "allow_symlinks": False,
        },
        "process": {
            "max_processes": 1,
            "allowed_commands": [],
            "blocked_commands": ["*"],
            "allow_fork": False,
            "allow_exec": False,
        },
        "environment": {
            "blocked_vars": ["*"],
            "allowed_vars": ["PATH", "HOME", "AGENTSHIELD_*"],
        },
        "resources": {
            "memory_limit_mb": 128,
            "cpu_limit_percent": 50,
            "timeout_seconds": 30,
            "max_output_size_kb": 256,
        },
    },
    "permissive": {
        "name": "permissive",
        "description": "Relaxed policy for trusted code with monitoring only",
        "network": {
            "mode": "allow",
            "allowed_hosts": [],
            "blocked_hosts": [],
            "allowed_ports": [],
            "blocked_ports": [],
        },
        "filesystem": {
            "mode": "allow",
            "allowed_paths": [],
            "blocked_paths": [
                "/etc/shadow",
                "~/.ssh/id_rsa",
                "~/.ssh/id_ed25519",
            ],
            "max_file_size_mb": 1000,
            "max_total_size_mb": 5000,
            "allow_symlinks": True,
        },
        "process": {
            "max_processes": 50,
            "allowed_commands": [],
            "blocked_commands": ["rm -rf /"],
            "allow_fork": True,
            "allow_exec": True,
        },
        "environment": {
            "blocked_vars": [],
            "allowed_vars": [],
        },
        "resources": {
            "memory_limit_mb": 2048,
            "cpu_limit_percent": 100,
            "timeout_seconds": 300,
            "max_output_size_kb": 10240,
        },
    },
}


class PolicyViolation:
    """Represents a single policy violation."""

    def __init__(self, rule: str, severity: str, message: str, details: dict = None):
        self.rule = rule
        self.severity = severity  # info, warn, error, critical
        self.message = message
        self.details = details or {}
        self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp,
        }


class PolicyEvaluator:
    """Evaluate actions against security policies."""

    def __init__(self, policy: dict):
        self.policy = policy

    def check_command(self, command: str) -> List[PolicyViolation]:
        """Check if a command violates any policy rules."""
        violations = []

        # Check blocked commands
        blocked = self.policy.get("process", {}).get("blocked_commands", [])
        for pattern in blocked:
            if pattern == "*":
                violations.append(PolicyViolation(
                    "process.blocked_commands",
                    "critical",
                    f"All commands are blocked in strict mode"
                ))
                break
            if pattern.lower() in command.lower():
                violations.append(PolicyViolation(
                    "process.blocked_commands",
                    "critical",
                    f"Command matches blocked pattern: {pattern}"
                ))

        # Check environment variables
        blocked_vars = self.policy.get("environment", {}).get("blocked_vars", [])
        if "*" not in blocked_vars:
            for var in blocked_vars:
                if var in os.environ:
                    violations.append(PolicyViolation(
                        "environment.blocked_vars",
                        "warn",
                        f"Blocked environment variable present: {var}"
                    ))

        return violations

    def check_file_access(self, filepath: str, mode: str = "read") -> List[PolicyViolation]:
        """Check if file access violates policy."""
        violations = []
        expanded = os.path.expanduser(filepath)

        blocked = self.policy.get("filesystem", {}).get("blocked_paths", [])
        for pattern in blocked:
            expanded_pattern = os.path.expanduser(pattern)
            if pattern == "*" or expanded.startswith(expanded_pattern):
                violations.append(PolicyViolation(
                    "filesystem.blocked_paths",
                    "error",
                    f"Access to blocked path: {filepath} (pattern: {pattern})"
                ))
                break

        return violations

    def check_network(self, host: str, port: int) -> List[PolicyViolation]:
        """Check if network access violates policy."""
        violations = []
        network_mode = self.policy.get("network", {}).get("mode", "restricted")

        if network_mode == "deny":
            violations.append(PolicyViolation(
                "network.mode",
                "error",
                f"Network access denied (mode: {network_mode})"
            ))
            return violations

        if network_mode == "restricted":
            allowed_ports = self.policy.get("network", {}).get("allowed_ports", [])
            if allowed_ports and port not in allowed_ports:
                violations.append(PolicyViolation(
                    "network.ports",
                    "warn",
                    f"Port {port} not in allowed list: {allowed_ports}"
                ))

        return violations

    def evaluate_execution(self, command: str) -> List[PolicyViolation]:
        """Full pre-execution policy evaluation."""
        violations = []
        violations.extend(self.check_command(command))
        return violations


class PolicyManager:
    """Manage security policies."""

    def __init__(self):
        self.config_dir = Path(os.path.expanduser("~")) / ".agentshield"
        self.policies_dir = self.config_dir / "policies"

    def handle(self, args) -> int:
        """Handle CLI policy commands."""
        if args.policy_action == "show":
            return self._show_policy(args.name)
        elif args.policy_action == "init":
            return self._init_policy(args.template, args.output)
        elif args.policy_action == "validate":
            return self._validate_policy(args.file)
        elif args.policy_action == "list":
            return self._list_policies()
        else:
            print("Usage: agentshield policy <show|init|validate|list>")
            return 1

    def _show_policy(self, name: str) -> int:
        """Show a policy configuration."""
        if name in POLICY_TEMPLATES:
            policy = POLICY_TEMPLATES[name]
        else:
            # Try to load from file
            policy_file = self.policies_dir / f"{name}.json"
            if policy_file.exists():
                with open(policy_file) as f:
                    policy = json.load(f)
            else:
                print(f"❌ Policy '{name}' not found")
                return 1

        print(f"\n📜 Policy: {policy['name']}")
        print(f"   Description: {policy.get('description', 'N/A')}")
        print(f"\n{json.dumps(policy, indent=2, ensure_ascii=False)}\n")
        return 0

    def _init_policy(self, template: str, output: str) -> int:
        """Initialize a new policy file from template."""
        if template not in POLICY_TEMPLATES:
            print(f"❌ Unknown template: {template}")
            print(f"   Available: {', '.join(POLICY_TEMPLATES.keys())}")
            return 1

        policy = dict(POLICY_TEMPLATES[template])
        policy["name"] = os.path.splitext(os.path.basename(output))[0]
        policy["created_at"] = datetime.now().isoformat()

        self.policies_dir.mkdir(parents=True, exist_ok=True)
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(policy, f, indent=2, ensure_ascii=False)

        print(f"✅ Policy created: {output_path}")
        print(f"   Template: {template}")
        print(f"   Name: {policy['name']}")
        return 0

    def _validate_policy(self, filepath: str) -> int:
        """Validate a policy file."""
        path = Path(filepath)
        if not path.exists():
            print(f"❌ File not found: {filepath}")
            return 1

        try:
            with open(path) as f:
                policy = json.load(f)
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON: {e}")
            return 1

        # Validate required fields
        required = ["name", "network", "filesystem", "process", "resources"]
        missing = [f for f in required if f not in policy]
        if missing:
            print(f"❌ Missing required fields: {', '.join(missing)}")
            return 1

        # Validate network mode
        net_mode = policy.get("network", {}).get("mode", "")
        if net_mode not in ("allow", "deny", "restricted"):
            print(f"❌ Invalid network mode: {net_mode}")
            return 1

        # Validate filesystem mode
        fs_mode = policy.get("filesystem", {}).get("mode", "")
        if fs_mode not in ("allow", "deny", "restricted"):
            print(f"❌ Invalid filesystem mode: {fs_mode}")
            return 1

        print(f"✅ Policy '{policy['name']}' is valid")
        return 0

    def _list_policies(self) -> int:
        """List available policy templates."""
        print(f"\n📜 Available Policy Templates:\n")
        for name, policy in POLICY_TEMPLATES.items():
            print(f"  📋 {name}")
            print(f"     {policy.get('description', 'N/A')}")
            net = policy.get("network", {}).get("mode", "N/A")
            mem = policy.get("resources", {}).get("memory_limit_mb", "N/A")
            timeout = policy.get("resources", {}).get("timeout_seconds", "N/A")
            print(f"     Network: {net} | Memory: {mem}MB | Timeout: {timeout}s")
            print()

        # List custom policies
        if self.policies_dir.exists():
            custom = list(self.policies_dir.glob("*.json"))
            if custom:
                print(f"  📁 Custom Policies:")
                for f in custom:
                    print(f"     - {f.stem}")
                print()

        return 0

    def get_policy(self, name: str = "default") -> dict:
        """Get a policy by name."""
        if name in POLICY_TEMPLATES:
            return dict(POLICY_TEMPLATES[name])

        # Try custom policy
        policy_file = self.policies_dir / f"{name}.json"
        if policy_file.exists():
            with open(policy_file) as f:
                return json.load(f)

        return dict(POLICY_TEMPLATES["default"])
