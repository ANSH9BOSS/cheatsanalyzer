import os
import sys
import subprocess
from pathlib import Path

class VSSArtifactScanner:
    """Scans Volume Shadow Copies, temp slack directories, and crash dump residuals for deleted cheat artifacts."""

    def __init__(self):
        self.is_windows = os.name == "nt" or sys.platform == "win32"
        self.temp_paths = [
            Path(os.environ.get("TEMP", "C:/Windows/Temp")),
            Path(os.environ.get("LOCALAPPDATA", "C:/")) / "CrashDumps"
        ]

    def audit_temp_slack_artifacts(self):
        """Scans temporary directories for residual injector DLLs and crash dumps."""
        traces = []
        cheat_names = ["vape", "drip", "slinky", "kura", "entropy", "clicker"]

        for tpath in self.temp_paths:
            if tpath.exists():
                try:
                    for f in tpath.glob("*"):
                        if f.is_file():
                            name_lower = f.name.lower()
                            for cn in cheat_names:
                                if cn in name_lower and f.suffix.lower() in [".dll", ".tmp", ".dmp", ".exe", ".jar"]:
                                    traces.append({
                                        "risk": "SUSPICIOUS",
                                        "type": "Residual Slack File",
                                        "file": f.name,
                                        "path": str(f),
                                        "detail": f"Temp Slack Artifact: Residual injector/cheat file found: '{f.name}' in {tpath}"
                                    })
                                    break
                except Exception:
                    pass

        return traces
