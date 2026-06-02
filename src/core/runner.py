#!/usr/bin/env python3
"""
Runner Module - Execute commands in the security sandbox
运行模块 - 在安全沙箱中执行命令
"""

import subprocess
import sys
import os
import time
import signal
import resource
import tempfile
import shutil
import uuid
import json
from pathlib import Path
from typing import Optional, Dict, Any, List


class SandboxConfig:
    """Sandbox execution configuration."""

    def __init__(self, args):
        self.command = args.command
        self.policy_name = args.policy
        self.policy_file = args.policy_file
        self.timeout = args.timeout
        self.memory_limit = args.memory_limit  # MB
        self.network_mode = args.network
        self.cwd = args.cwd or os.getcwd()
        self.env_vars = {}
        self.dry_run = args.dry_run
        self.verbose = args.verbose
        self.session_id = str(uuid.uuid4())[:8]

        # Parse environment variables
        for env_str in args.env:
            if "=" in env_str:
                key, value = env_str.split("=", 1)
                self.env_vars[key] = value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "command": self.command,
            "policy": self.policy_name,
            "timeout": self.timeout,
            "memory_limit_mb": self.memory_limit,
            "network_mode": self.network_mode,
            "cwd": self.cwd,
            "env_vars": self.env_vars,
            "dry_run": self.dry_run,
        }


class ExecutionResult:
    """Result of a sandbox execution."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.exit_code: int = -1
        self.stdout: str = ""
        self.stderr: str = ""
        self.start_time: float = 0
        self.end_time: float = 0
        self.duration: float = 0
        self.timed_out: bool = False
        self.memory_peak_mb: float = 0
        self.files_created: List[str] = []
        self.files_modified: List[str] = []
        self.files_deleted: List[str] = []
        self.network_connections: List[Dict] = []
        self.policy_violations: List[Dict] = []
        self.risk_score: int = 0  # 0-100
        self.risk_level: str = "low"

    def compute_risk_score(self):
        """Compute risk score based on execution behavior."""
        score = 0

        # Network activity
        if self.network_connections:
            score += min(len(self.network_connections) * 5, 30)

        # File system activity
        file_ops = len(self.files_created) + len(self.files_modified) + len(self.files_deleted)
        score += min(file_ops * 2, 25)

        # Policy violations
        score += min(len(self.policy_violations) * 15, 30)

        # Memory usage
        if self.memory_peak_mb > 256:
            score += 5
        if self.memory_peak_mb > 512:
            score += 10

        # Duration
        if self.duration > 30:
            score += 5

        self.risk_score = min(score, 100)
        if self.risk_score >= 70:
            self.risk_level = "high"
        elif self.risk_score >= 40:
            self.risk_level = "medium"
        else:
            self.risk_level = "low"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "exit_code": self.exit_code,
            "duration_seconds": round(self.duration, 3),
            "timed_out": self.timed_out,
            "memory_peak_mb": round(self.memory_peak_mb, 2),
            "files_created": self.files_created,
            "files_modified": self.files_modified,
            "files_deleted": self.files_deleted,
            "network_connections": self.network_connections,
            "policy_violations": self.policy_violations,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "stdout_preview": self.stdout[:500] if self.stdout else "",
            "stderr_preview": self.stderr[:500] if self.stderr else "",
        }


class SandboxExecutor:
    """Execute commands in an isolated sandbox environment."""

    def __init__(self, config: SandboxConfig):
        self.config = config
        self.result = ExecutionResult(config.session_id)
        self._process: Optional[subprocess.Popen] = None
        self._temp_dir: Optional[str] = None
        self._file_snapshot_before: Dict[str, float] = {}

    def _setup_sandbox(self):
        """Set up the sandbox environment."""
        # Create a temporary working directory for sandbox isolation
        self._temp_dir = tempfile.mkdtemp(prefix=f"agentshield_{self.config.session_id}_")

        # Snapshot current directory files for change detection
        self._file_snapshot_before = self._scan_directory(self.config.cwd)

    def _scan_directory(self, path: str) -> Dict[str, float]:
        """Scan directory and return file modification times."""
        snapshot = {}
        try:
            for root, dirs, files in os.walk(path):
                # Skip hidden directories and common exclusions
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in {
                    'node_modules', '__pycache__', '.git', 'venv', '.venv',
                    'target', 'build', 'dist', '.next', '.cache'
                }]
                for f in files:
                    filepath = os.path.join(root, f)
                    try:
                        snapshot[filepath] = os.path.getmtime(filepath)
                    except (OSError, PermissionError):
                        pass
        except (OSError, PermissionError):
            pass
        return snapshot

    def _detect_file_changes(self):
        """Detect file changes after execution."""
        snapshot_after = self._scan_directory(self.config.cwd)

        # New files
        self.result.files_created = [
            f for f in snapshot_after if f not in self._file_snapshot_before
        ]

        # Modified files
        self.result.files_modified = [
            f for f in self._file_snapshot_before
            if f in snapshot_after and snapshot_after[f] != self._file_snapshot_before[f]
        ]

        # Deleted files
        self.result.files_deleted = [
            f for f in self._file_snapshot_before if f not in snapshot_after
        ]

    def _build_environment(self) -> Dict[str, str]:
        """Build sandboxed environment variables."""
        env = os.environ.copy()

        # Inject AgentShield markers
        env["AGENTSHIELD_SESSION"] = self.config.session_id
        env["AGENTSHIELD_SANDBOX"] = "1"
        env["AGENTSHIELD_POLICY"] = self.config.policy_name

        # Apply user-specified env vars
        env.update(self.config.env_vars)

        # Network restriction via environment
        if self.config.network_mode == "deny":
            env["AGENTSHIELD_NETWORK"] = "deny"
            # Block common network-related env vars
            for key in list(env.keys()):
                if any(n in key.upper() for n in ["PROXY", "HTTP_PROXY", "HTTPS_PROXY"]):
                    del env[key]

        return env

    def _enforce_memory_limit(self):
        """Set memory limit for the current process tree."""
        limit_bytes = self.config.memory_limit * 1024 * 1024
        try:
            resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))
        except (ValueError, OSError):
            pass  # May not be supported on all platforms

    def _timeout_handler(self, signum, frame):
        """Handle execution timeout."""
        if self._process:
            self._process.terminate()
            self.result.timed_out = True

    def execute(self) -> ExecutionResult:
        """Execute the command in the sandbox."""
        self.result.start_time = time.time()

        if self.config.dry_run:
            return self._dry_run()

        self._setup_sandbox()

        try:
            env = self._build_environment()

            # Parse command into list
            import shlex
            cmd_parts = shlex.split(self.config.command)

            if self.config.verbose:
                print(f"🔧 Session: {self.config.session_id}")
                print(f"🔧 Policy: {self.config.policy_name}")
                print(f"🔧 Timeout: {self.config.timeout}s")
                print(f"🔧 Memory Limit: {self.config.memory_limit}MB")
                print(f"🔧 Network: {self.config.network_mode}")
                print(f"🔧 CWD: {self.config.cwd}")
                print(f"🔧 Command: {self.config.command}")
                print()

            # Start process
            self._process = subprocess.Popen(
                cmd_parts,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.config.cwd,
                env=env,
                preexec_fn=self._enforce_memory_limit if hasattr(os, 'fork') else None,
            )

            # Set up timeout
            if self.config.timeout > 0:
                signal.signal(signal.SIGALRM, self._timeout_handler)
                signal.alarm(self.config.timeout)

            # Wait for completion
            stdout, stderr = self._process.communicate()
            self.result.exit_code = self._process.returncode
            self.result.stdout = stdout.decode("utf-8", errors="replace")
            self.result.stderr = stderr.decode("utf-8", errors="replace")

            # Cancel timeout alarm
            if self.config.timeout > 0:
                signal.alarm(0)

            # Detect file changes
            self._detect_file_changes()

            # Compute risk score
            self.result.compute_risk_score()

        except subprocess.TimeoutExpired:
            self.result.timed_out = True
            if self._process:
                self._process.kill()
                self._process.wait()
            self.result.exit_code = -1
            self.result.stderr = f"Execution timed out after {self.config.timeout}s"

        except FileNotFoundError:
            self.result.exit_code = 127
            self.result.stderr = f"Command not found: {self.config.command.split()[0] if self.config.command else 'unknown'}"

        except PermissionError:
            self.result.exit_code = 126
            self.result.stderr = "Permission denied"

        except Exception as e:
            self.result.exit_code = -1
            self.result.stderr = str(e)

        finally:
            self.result.end_time = time.time()
            self.result.duration = self.result.end_time - self.result.start_time

            # Cleanup temp directory
            if self._temp_dir and os.path.exists(self._temp_dir):
                shutil.rmtree(self._temp_dir, ignore_errors=True)

        return self.result

    def _dry_run(self) -> ExecutionResult:
        """Simulate execution without actually running."""
        self.result.exit_code = 0
        self.result.stdout = f"[DRY RUN] Would execute: {self.config.command}"
        self.result.end_time = time.time()
        self.result.duration = self.result.end_time - self.result.start_time
        self.result.compute_risk_score()
        return self.result


def run_command(args) -> int:
    """Run a command in the sandbox (CLI handler)."""
    config = SandboxConfig(args)
    executor = SandboxExecutor(config)
    result = executor.execute()

    # Display results
    _display_result(result, config.verbose)

    # Save to audit log
    try:
        from src.audit.logger import AuditLogger
        logger = AuditLogger()
        logger.log_execution(config, result)
    except Exception:
        pass  # Don't fail if audit logging fails

    # Save to history
    try:
        from src.audit.history import HistoryManager
        history = HistoryManager()
        history.record(config, result)
    except Exception:
        pass

    return result.exit_code if not result.timed_out else 124


def _display_result(result: ExecutionResult, verbose: bool = False):
    """Display execution result in terminal."""
    # Risk level indicators
    risk_icons = {"low": "🟢", "medium": "🟡", "high": "🔴"}
    risk_icon = risk_icons.get(result.risk_level, "⚪")

    print(f"\n{'='*60}")
    print(f"🛡️  AgentShield Execution Report")
    print(f"{'='*60}")
    print(f"  Session ID    : {result.session_id}")
    print(f"  Duration      : {result.duration:.3f}s")
    print(f"  Exit Code     : {result.exit_code}")
    print(f"  Risk Score    : {risk_icon} {result.risk_score}/100 ({result.risk_level})")

    if result.timed_out:
        print(f"  ⚠️  TIMEOUT    : Execution exceeded time limit")

    # File activity summary
    total_file_ops = len(result.files_created) + len(result.files_modified) + len(result.files_deleted)
    if total_file_ops > 0:
        print(f"\n  📁 File Activity ({total_file_ops} operations):")
        if result.files_created:
            print(f"     ✅ Created  : {len(result.files_created)}")
            if verbose:
                for f in result.files_created[:10]:
                    print(f"        + {f}")
        if result.files_modified:
            print(f"     ✏️  Modified : {len(result.files_modified)}")
            if verbose:
                for f in result.files_modified[:10]:
                    print(f"        ~ {f}")
        if result.files_deleted:
            print(f"     🗑️  Deleted  : {len(result.files_deleted)}")
            if verbose:
                for f in result.files_deleted[:10]:
                    print(f"        - {f}")

    # Policy violations
    if result.policy_violations:
        print(f"\n  ⚠️  Policy Violations ({len(result.policy_violations)}):")
        for v in result.policy_violations:
            print(f"     - [{v.get('severity', 'warn')}] {v.get('message', 'Unknown violation')}")

    # Stdout preview
    if result.stdout and verbose:
        print(f"\n  📤 stdout:")
        for line in result.stdout.split("\n")[:20]:
            print(f"     {line}")
        if len(result.stdout.split("\n")) > 20:
            print(f"     ... ({len(result.stdout.split(chr(10)))} lines total)")

    # Stderr
    if result.stderr:
        print(f"\n  📥 stderr:")
        for line in result.stderr.split("\n")[:10]:
            print(f"     {line}")

    print(f"\n{'='*60}")
