#!/usr/bin/env python3
"""
Resource Monitor - Track resource usage during execution
资源监控器 - 跟踪执行期间的资源使用情况
"""

import os
import time
import threading
from typing import Dict, Optional


class ResourceMonitor:
    """Monitor resource usage of a process."""

    def __init__(self, pid: Optional[int] = None, interval: float = 0.5):
        self.pid = pid or os.getpid()
        self.interval = interval
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._samples: list = []
        self.peak_memory_mb: float = 0
        self.avg_cpu_percent: float = 0

    def start(self):
        """Start resource monitoring."""
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop resource monitoring."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)

    def _monitor_loop(self):
        """Main monitoring loop."""
        while self._running:
            sample = self._take_sample()
            if sample:
                self._samples.append(sample)
                if sample["memory_mb"] > self.peak_memory_mb:
                    self.peak_memory_mb = sample["memory_mb"]
            time.sleep(self.interval)

    def _take_sample(self) -> Optional[Dict]:
        """Take a single resource usage sample."""
        try:
            # Try to read from /proc on Linux
            if os.path.exists("/proc/self/status"):
                return self._read_proc_status()
            # Fallback: use resource module
            return self._resource_fallback()
        except (OSError, PermissionError):
            return None

    def _read_proc_status(self) -> Dict:
        """Read process status from /proc filesystem (Linux)."""
        status_file = f"/proc/{self.pid}/status"
        memory_mb = 0

        try:
            with open(status_file) as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        # VmRSS is in kB
                        memory_kb = int(line.split()[1])
                        memory_mb = memory_kb / 1024
                        break
        except (OSError, PermissionError, ValueError):
            pass

        return {
            "memory_mb": round(memory_mb, 2),
            "timestamp": time.time(),
        }

    def _resource_fallback(self) -> Dict:
        """Fallback resource measurement using resource module."""
        import resource
        usage = resource.getrusage(resource.RUSAGE_SELF)
        memory_mb = usage.ru_maxrss / 1024  # Convert from kB to MB

        return {
            "memory_mb": round(memory_mb, 2),
            "timestamp": time.time(),
        }

    def get_stats(self) -> Dict:
        """Get monitoring statistics."""
        return {
            "peak_memory_mb": round(self.peak_memory_mb, 2),
            "sample_count": len(self._samples),
            "duration_seconds": len(self._samples) * self.interval,
        }
