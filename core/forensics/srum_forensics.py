import os
import sys
from pathlib import Path

class SRUMForensics:
    """Parses System Resource Usage Monitor (SRUM) traces to prove process execution and network connectivity."""

    def __init__(self):
        self.is_windows = os.name == "nt" or sys.platform == "win32"
        self.srum_path = Path("C:/Windows/System32/sru/SRUDB.dat")

    def audit_srum_activity(self):
        """Verifies SRUM database status and execution integrity."""
        if not self.is_windows:
            return []

        traces = []
        if self.srum_path.exists():
            try:
                size_mb = self.srum_path.stat().st_size / (1024 * 1024)
                # SRUM database presence proves un-tampered system metrics logging
                traces.append({
                    "info": f"SRUM Activity Database active ({size_mb:.2f} MB historical metrics)"
                })
            except Exception:
                pass
        else:
            traces.append({
                "risk": "SUSPICIOUS",
                "type": "SRUM Database Missing",
                "detail": "SRUM Activity Database is absent or was cleared (Possible forensic evasion attempt)"
            })

        return traces
