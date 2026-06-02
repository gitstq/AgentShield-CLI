#!/usr/bin/env python3
"""
Sandbox Module - Core sandbox isolation mechanisms
沙箱模块 - 核心沙箱隔离机制
"""

import os
import sys
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional


class SandboxEnvironment:
    """Create and manage isolated sandbox environments."""

    def __init__(self, session_id: str, base_dir: Optional[str] = None):
        self.session_id = session_id
        self.base_dir = base_dir or tempfile.mkdtemp(prefix=f"agentshield_{session_id}_")
        self.work_dir = os.path.join(self.base_dir, "work")
        self.temp_dir = os.path.join(self.base_dir, "tmp")
        self._created = False

    def create(self) -> str:
        """Create the sandbox directory structure."""
        os.makedirs(self.work_dir, exist_ok=True)
        os.makedirs(self.temp_dir, exist_ok=True)
        self._created = True
        return self.work_dir

    def cleanup(self):
        """Remove the sandbox directory and all contents."""
        if self.base_dir and os.path.exists(self.base_dir):
            shutil.rmtree(self.base_dir, ignore_errors=True)
        self._created = False

    def get_isolated_env(self, parent_env: Dict = None) -> Dict[str, str]:
        """Get an isolated environment variable set."""
        env = parent_env or os.environ.copy()

        # Override temp directories
        env["TMPDIR"] = self.temp_dir
        env["TEMP"] = self.temp_dir
        env["TMP"] = self.temp_dir

        # Add sandbox markers
        env["AGENTSHIELD_SANDBOX"] = "1"
        env["AGENTSHIELD_SESSION"] = self.session_id
        env["AGENTSHIELD_WORK_DIR"] = self.work_dir

        return env

    def list_files(self) -> List[str]:
        """List all files created in the sandbox."""
        files = []
        if os.path.exists(self.work_dir):
            for root, dirs, filenames in os.walk(self.work_dir):
                for f in filenames:
                    files.append(os.path.join(root, f))
        return files

    def get_file_changes(self) -> Dict[str, str]:
        """Get summary of file changes in the sandbox."""
        return {
            "total_files": len(self.list_files()),
            "work_dir": self.work_dir,
            "total_size_bytes": self._get_total_size(),
        }

    def _get_total_size(self) -> int:
        """Get total size of files in the sandbox."""
        total = 0
        if os.path.exists(self.work_dir):
            for root, dirs, filenames in os.walk(self.work_dir):
                for f in filenames:
                    filepath = os.path.join(root, f)
                    try:
                        total += os.path.getsize(filepath)
                    except OSError:
                        pass
        return total

    def __enter__(self):
        self.create()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        return False
