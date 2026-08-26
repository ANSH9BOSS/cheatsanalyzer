import os
import sys
from pathlib import Path

class PCAForensics:
    """Parses Windows Program Compatibility Assistant (PCA) execution logs (PcaAppLaunchDic.txt)."""

    def __init__(self):
        self.is_windows = os.name == "nt" or sys.platform == "win32"
        self.cheat_keywords = [
            "vape", "drip", "slinky", "autoclick", "clicker", "cleaner",
            "kura", "karma", "spearmint", "entropy", "doomsday", "destruct",
            "cheatengine", "processhacker", "mango", "itami"
        ]

    def audit_pca_launch_history(self):
        """Scans Windows PCA launch dictionary files for past execution records."""
        if not self.is_windows:
            return []

        pca_files = [
            Path("C:/Windows/appcompat/Programs/PcaAppLaunchDic.txt"),
            Path("C:/Windows/appcompat/Programs/PcaGeneral.txt"),
            Path("C:/Windows/appcompat/Programs/Amcache.hve")
        ]

        traces = []
        for p_file in pca_files:
            if p_file.exists() and p_file.suffix == ".txt":
                try:
                    with open(p_file, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line_lower = line.lower()
                            for kw in self.cheat_keywords:
                                if kw in line_lower and ".exe" in line_lower:
                                    path_str = line.strip().split("|")[0].strip()
                                    traces.append({
                                        "risk": "DANGEROUS",
                                        "type": "PCA Execution History",
                                        "path": path_str,
                                        "detail": f"Windows PCA Log: Executable was executed on this machine: '{path_str}'"
                                    })
                                    break
                except Exception:
                    pass

        # Deduplicate
        unique = []
        seen = set()
        for t in traces:
            if t["path"] not in seen:
                seen.add(t["path"])
                unique.append(t)

        return unique
