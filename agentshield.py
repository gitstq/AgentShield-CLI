#!/usr/bin/env python3
"""
AgentShield-CLI Entry Point
AgentShield-CLI 主入口
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.core.cli import main

if __name__ == "__main__":
    sys.exit(main())
