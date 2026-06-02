#!/usr/bin/env python3
"""
Tests for AgentShield-CLI
AgentShield-CLI 测试套件
"""

import unittest
import sys
import os
import json
import tempfile
import shutil
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestPolicyEngine(unittest.TestCase):
    """Test policy engine functionality."""

    def setUp(self):
        from src.policy.engine import POLICY_TEMPLATES
        self.default_policy = POLICY_TEMPLATES["default"]
        self.strict_policy = POLICY_TEMPLATES["strict"]

    def test_default_policy_has_required_fields(self):
        """Test default policy has all required fields."""
        required = ["name", "network", "filesystem", "process", "resources"]
        for field in required:
            self.assertIn(field, self.default_policy)

    def test_strict_policy_blocks_all_network(self):
        """Test strict policy denies all network access."""
        self.assertEqual(self.strict_policy["network"]["mode"], "deny")

    def test_strict_policy_blocks_all_commands(self):
        """Test strict policy blocks all commands."""
        self.assertIn("*", self.strict_policy["process"]["blocked_commands"])

    def test_policy_evaluator_detects_blocked_commands(self):
        """Test policy evaluator detects blocked command patterns."""
        from src.policy.engine import PolicyEvaluator
        evaluator = PolicyEvaluator(self.default_policy)
        violations = evaluator.check_command("rm -rf /")
        self.assertTrue(len(violations) > 0)

    def test_policy_evaluator_allows_safe_command(self):
        """Test policy evaluator allows safe commands."""
        from src.policy.engine import PolicyEvaluator
        evaluator = PolicyEvaluator(self.default_policy)
        violations = evaluator.check_command("python hello.py")
        self.assertEqual(len(violations), 0)

    def test_strict_evaluator_blocks_everything(self):
        """Test strict evaluator blocks all commands."""
        from src.policy.engine import PolicyEvaluator
        evaluator = PolicyEvaluator(self.strict_policy)
        violations = evaluator.check_command("python hello.py")
        self.assertTrue(len(violations) > 0)

    def test_network_check_deny_mode(self):
        """Test network check in deny mode."""
        from src.policy.engine import PolicyEvaluator
        evaluator = PolicyEvaluator(self.strict_policy)
        violations = evaluator.check_network("example.com", 443)
        self.assertTrue(len(violations) > 0)
        self.assertEqual(violations[0].severity, "error")


class TestSandboxEnvironment(unittest.TestCase):
    """Test sandbox environment functionality."""

    def test_create_and_cleanup(self):
        """Test sandbox creation and cleanup."""
        from src.sandbox.environment import SandboxEnvironment
        sandbox = SandboxEnvironment("test-session")
        work_dir = sandbox.create()
        self.assertTrue(os.path.exists(work_dir))
        sandbox.cleanup()
        self.assertFalse(os.path.exists(sandbox.base_dir))

    def test_context_manager(self):
        """Test sandbox as context manager."""
        from src.sandbox.environment import SandboxEnvironment
        with SandboxEnvironment("test-session") as sandbox:
            self.assertTrue(os.path.exists(sandbox.work_dir))
        self.assertFalse(os.path.exists(sandbox.base_dir))

    def test_isolated_env(self):
        """Test isolated environment variables."""
        from src.sandbox.environment import SandboxEnvironment
        with SandboxEnvironment("test-session") as sandbox:
            env = sandbox.get_isolated_env()
            self.assertEqual(env.get("AGENTSHIELD_SANDBOX"), "1")
            self.assertEqual(env.get("AGENTSHIELD_SESSION"), "test-session")


class TestExecutionResult(unittest.TestCase):
    """Test execution result functionality."""

    def test_risk_score_low(self):
        """Test low risk score computation."""
        from src.core.runner import ExecutionResult
        result = ExecutionResult("test")
        result.compute_risk_score()
        self.assertEqual(result.risk_level, "low")
        self.assertEqual(result.risk_score, 0)

    def test_risk_score_high_with_violations(self):
        """Test high risk score with many violations."""
        from src.core.runner import ExecutionResult
        result = ExecutionResult("test")
        result.policy_violations = [
            {"severity": "critical", "message": "test"} for _ in range(5)
        ]
        result.network_connections = [{"host": "evil.com"} for _ in range(5)]
        result.files_created = [f"file_{i}.txt" for i in range(10)]
        result.files_modified = [f"file_{i}.txt" for i in range(10)]
        result.compute_risk_score()
        # 30 (violations capped) + 25 (network capped) + 25 (file ops) = 80
        self.assertGreaterEqual(result.risk_score, 70)
        self.assertEqual(result.risk_level, "high")

    def test_result_to_dict(self):
        """Test result serialization."""
        from src.core.runner import ExecutionResult
        result = ExecutionResult("test123")
        result.exit_code = 0
        result.duration = 1.5
        d = result.to_dict()
        self.assertEqual(d["session_id"], "test123")
        self.assertEqual(d["exit_code"], 0)


class TestConfigManager(unittest.TestCase):
    """Test configuration management."""

    def test_default_config(self):
        """Test default configuration values."""
        from src.core.config import ConfigManager
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ConfigManager()
            # Override config dir for testing
            manager.config_dir = Path(tmpdir) / ".agentshield"
            manager.config_file = manager.config_dir / "config.json"
            manager._config = None

            config = manager.config
            self.assertIn("version", config)
            self.assertIn("default_policy", config)
            self.assertIn("audit", config)

    def test_set_and_get(self):
        """Test setting and getting config values."""
        from src.core.config import ConfigManager
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ConfigManager()
            manager.config_dir = Path(tmpdir) / ".agentshield"
            manager.config_file = manager.config_dir / "config.json"
            manager._config = None

            manager.set("default_policy.timeout_seconds", 120)
            self.assertEqual(manager.get("default_policy.timeout_seconds"), 120)

    def test_reset(self):
        """Test configuration reset."""
        from src.core.config import ConfigManager
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ConfigManager()
            # Set paths BEFORE any operations to ensure correct file I/O
            test_dir = Path(tmpdir) / ".agentshield"
            test_file = test_dir / "config.json"
            manager.config_dir = test_dir
            manager.config_file = test_file
            manager._config = None  # Force reload from new path

            # Now set a value - it will save to test_file
            manager.set("default_policy.timeout_seconds", 999)
            # Reset should write defaults to test_file
            manager.reset()
            # Force reload from test_file
            manager._config = None
            self.assertEqual(manager.get("default_policy.timeout_seconds"), 60)


class TestAuditLogger(unittest.TestCase):
    """Test audit logging functionality."""

    def test_log_and_retrieve(self):
        """Test logging and retrieving entries."""
        from src.audit.logger import AuditLogger
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger()
            logger.audit_dir = Path(tmpdir) / "audit"
            logger.audit_dir.mkdir(parents=True, exist_ok=True)

            # Create mock config and result
            class MockConfig:
                command = "echo hello"
                policy_name = "default"

            class MockResult:
                session_id = "test123"
                exit_code = 0
                duration = 0.5
                timed_out = False
                risk_score = 10
                risk_level = "low"
                files_created = []
                files_modified = []
                files_deleted = []
                policy_violations = []
                stdout = "hello\n"
                stderr = ""

            logger.log_execution(MockConfig(), MockResult())
            entries = logger.get_entries(limit=10)
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["session_id"], "test123")

    def test_clear_logs(self):
        """Test clearing audit logs."""
        from src.audit.logger import AuditLogger
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger()
            logger.audit_dir = Path(tmpdir) / "audit"
            logger.audit_dir.mkdir(parents=True, exist_ok=True)

            # Create a dummy log file
            log_file = logger.audit_dir / "audit-2026-01-01.jsonl"
            log_file.write_text('{"test": true}\n')

            logger.clear_logs()
            self.assertEqual(len(list(logger.audit_dir.glob("*.jsonl"))), 0)


class TestReportGenerator(unittest.TestCase):
    """Test report generation."""

    def test_json_report(self):
        """Test JSON report generation."""
        from src.report.generator import ReportGenerator
        with tempfile.TemporaryDirectory() as tmpdir:
            generator = ReportGenerator()
            entries = [
                {
                    "timestamp": "2026-06-02T12:00:00",
                    "session_id": "abc12345",
                    "command": "echo test",
                    "exit_code": 0,
                    "duration": 0.1,
                    "risk_score": 5,
                    "risk_level": "low",
                }
            ]
            output = os.path.join(tmpdir, "report.json")
            result = generator.generate(entries, output, format="json")
            self.assertTrue(os.path.exists(result))

            with open(result) as f:
                data = json.load(f)
            self.assertEqual(data["total_entries"], 1)

    def test_html_report(self):
        """Test HTML report generation."""
        from src.report.generator import ReportGenerator
        with tempfile.TemporaryDirectory() as tmpdir:
            generator = ReportGenerator()
            entries = [
                {
                    "timestamp": "2026-06-02T12:00:00",
                    "session_id": "abc12345",
                    "command": "echo test",
                    "exit_code": 0,
                    "duration": 0.1,
                    "risk_score": 5,
                    "risk_level": "low",
                }
            ]
            output = os.path.join(tmpdir, "report.html")
            result = generator.generate(entries, output, format="html")
            self.assertTrue(os.path.exists(result))

            with open(result) as f:
                content = f.read()
            self.assertIn("AgentShield", content)
            self.assertIn("<html", content)

    def test_markdown_report(self):
        """Test Markdown report generation."""
        from src.report.generator import ReportGenerator
        with tempfile.TemporaryDirectory() as tmpdir:
            generator = ReportGenerator()
            entries = [
                {
                    "timestamp": "2026-06-02T12:00:00",
                    "session_id": "abc12345",
                    "command": "echo test",
                    "exit_code": 0,
                    "duration": 0.1,
                    "risk_score": 5,
                    "risk_level": "low",
                }
            ]
            output = os.path.join(tmpdir, "report.md")
            result = generator.generate(entries, output, format="md")
            self.assertTrue(os.path.exists(result))

            with open(result) as f:
                content = f.read()
            self.assertIn("AgentShield", content)
            self.assertIn("#", content)


class TestCLIParsing(unittest.TestCase):
    """Test CLI argument parsing."""

    def test_run_command_parsing(self):
        """Test run command argument parsing."""
        from src.core.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(["run", "python app.py", "--timeout", "30", "--policy", "strict"])
        self.assertEqual(args.subcommand, "run")
        self.assertEqual(args.command, "python app.py")
        self.assertEqual(args.timeout, 30)
        self.assertEqual(args.policy, "strict")

    def test_audit_command_parsing(self):
        """Test audit command argument parsing."""
        from src.core.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(["audit", "--format", "json", "--limit", "10"])
        self.assertEqual(args.format, "json")
        self.assertEqual(args.limit, 10)

    def test_policy_command_parsing(self):
        """Test policy command argument parsing."""
        from src.core.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(["policy", "list"])
        self.assertEqual(args.policy_action, "list")


if __name__ == "__main__":
    unittest.main(verbosity=2)
