#!/usr/bin/env python3
"""
Config Module - Manage AgentShield configuration
配置模块 - 管理AgentShield全局配置
"""

import os
import json
import copy
from pathlib import Path


DEFAULT_CONFIG = {
    "version": "1.0.0",
    "default_policy": {
        "name": "default",
        "network_mode": "restricted",
        "memory_limit_mb": 512,
        "timeout_seconds": 60,
        "max_file_ops": 1000,
        "allowed_paths": [],
        "blocked_paths": [],
    },
    "audit": {
        "enabled": True,
        "max_entries": 10000,
        "auto_export": False,
        "export_format": "json",
    },
    "sandbox": {
        "temp_dir": "",
        "auto_cleanup": True,
        "preserve_on_error": False,
    },
    "tui": {
        "refresh_rate_ms": 500,
        "max_log_lines": 1000,
    },
}


class ConfigManager:
    """Manage AgentShield global configuration."""

    def __init__(self):
        self.config_dir = Path(os.path.expanduser("~")) / ".agentshield"
        self.config_file = self.config_dir / "config.json"
        self._config = None

    @property
    def config(self) -> dict:
        """Get current configuration, loading from file if needed."""
        if self._config is None:
            self._load()
        return self._config

    def _load(self):
        """Load configuration from file."""
        if self.config_file.exists():
            try:
                with open(self.config_file, "r") as f:
                    self._config = json.load(f)
                # Merge with defaults for any missing keys
                self._config = self._merge_defaults(self._config)
            except (json.JSONDecodeError, IOError):
                self._config = copy.deepcopy(DEFAULT_CONFIG)
        else:
            self._config = copy.deepcopy(DEFAULT_CONFIG)

    def _merge_defaults(self, config: dict) -> dict:
        """Merge config with defaults to ensure all keys exist."""
        merged = dict(DEFAULT_CONFIG)
        for key, value in config.items():
            if isinstance(value, dict) and key in merged:
                merged[key] = {**merged[key], **value}
            else:
                merged[key] = value
        return merged

    def save(self):
        """Save current configuration to file."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        with open(self.config_file, "w") as f:
            json.dump(self.config, f, indent=2, ensure_ascii=False)

    def get(self, key_path: str, default=None):
        """Get a config value by dot-separated key path."""
        keys = key_path.split(".")
        value = self.config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value

    def set(self, key_path: str, value):
        """Set a config value by dot-separated key path."""
        keys = key_path.split(".")
        config = self.config
        for key in keys[:-1]:
            if key not in config or not isinstance(config[key], dict):
                config[key] = {}
            config = config[key]
        config[keys[-1]] = value
        self.save()

    def reset(self):
        """Reset configuration to defaults."""
        self._config = copy.deepcopy(DEFAULT_CONFIG)
        self.save()

    def ensure_dirs(self):
        """Ensure all required directories exist."""
        dirs = [
            self.config_dir,
            self.config_dir / "audit",
            self.config_dir / "history",
            self.config_dir / "policies",
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)

    def handle(self, args) -> int:
        """Handle CLI config commands."""
        self.ensure_dirs()

        if args.config_action == "show":
            return self._show_config()
        elif args.config_action == "set":
            return self._set_config(args.key, args.value)
        elif args.config_action == "reset":
            return self._reset_config()
        else:
            print("Usage: agentshield config <show|set|reset>")
            return 1

    def _show_config(self) -> int:
        """Display current configuration."""
        import json as j
        print(f"\n⚙️  AgentShield Configuration")
        print(f"   Config File: {self.config_file}")
        print(f"\n{j.dumps(self.config, indent=2, ensure_ascii=False)}\n")
        return 0

    def _set_config(self, key: str, value: str) -> int:
        """Set a configuration value."""
        # Try to parse value as JSON for complex types
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            parsed = value

        self.set(key, parsed)
        print(f"✅ Set {key} = {parsed}")
        return 0

    def _reset_config(self) -> int:
        """Reset configuration to defaults."""
        self.reset()
        print("✅ Configuration reset to defaults")
        return 0
