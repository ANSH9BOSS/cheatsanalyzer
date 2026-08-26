import os
import sys
import subprocess
from pathlib import Path

class USNJournalParser:
    """Parses NTFS USN Change Journal ($UsnJrnl) to detect deleted, renamed, or self-destructed cheat files."""

    def __init__(self):
        self.is_windows = os.name == "nt" or sys.platform == "win32"
        self.target_keywords = [
            "vape", "drip", "slinky", "autoclick", "clicker", "cleaner",
            "kura", "karma", "spearmint", "entropy", "doomsday", "destruct",
            "selfdestruct", "journal", "history_cleaner", "bypass"
        ]

    def audit_deleted_files_journal(self, max_records=200):
        """Queries the NTFS USN Journal for deleted (.jar, .exe, .bat, .dll) files."""
        if not self.is_windows:
            return []

        traces = []
        try:
            # Query recent USN records on C:
            cmd = ["fsutil", "usn", "readjournal", "c:", "csv"]
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                universal_newlines=True,
                errors="ignore"
            )
            count = 0

            for line in proc.stdout:
                if count >= max_records:
                    break
                line_lower = line.lower()
                for kw in self.target_keywords:
                    if kw in line_lower and any(ext in line_lower for ext in [".exe", ".jar", ".dll", ".bat", ".vbs"]):
                        parts = line.strip().split(",")
                        file_name = parts[0] if parts else line.strip()
                        traces.append({
                            "risk": "CRITICAL",
                            "type": "USN Journal Deleted Artifact",
                            "file": file_name,
                            "raw_record": line.strip()[:100],
                            "detail": f"NTFS USN Journal Forensic Evidence: Deleted/Renamed cheat artifact logged: '{file_name}'"
                        })
                        count += 1
                        break
            proc.kill()
        except Exception:
            pass

        # Deduplicate by filename
        unique = []
        seen = set()
        for t in traces:
            if t["file"] not in seen:
                seen.add(t["file"])
                unique.append(t)

        return unique
