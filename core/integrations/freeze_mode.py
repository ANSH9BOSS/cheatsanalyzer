import time
import threading
import psutil

class TournamentFreezeMonitor:
    """Monitors process spawning in the background during active screenshares to detect self-destruct cleaner attempts."""

    def __init__(self, on_violation_callback=None):
        self.is_monitoring = False
        self.on_violation = on_violation_callback
        self.suspicious_processes = [
            "cleaner.bat", "selfdestruct.exe", "fsutil.exe", "wevtutil.exe",
            "cipher.exe", "sdelete.exe", "processhacker.exe", "cheatengine.exe"
        ]

    def start_monitoring(self):
        self.is_monitoring = True
        threading.Thread(target=self._monitor_loop, daemon=True).start()

    def stop_monitoring(self):
        self.is_monitoring = False

    def _monitor_loop(self):
        known_pids = set(psutil.pids())
        while self.is_monitoring:
            time.sleep(1.0)
            current_pids = set(psutil.pids())
            new_pids = current_pids - known_pids
            for pid in new_pids:
                try:
                    proc = psutil.Process(pid)
                    name_lower = proc.name().lower()
                    for sp in self.suspicious_processes:
                        if sp in name_lower:
                            violation_text = f"CRITICAL: Cleaner/Self-Destruct process spawned during audit: '{proc.name()}' (PID: {pid})"
                            if self.on_violation:
                                self.on_violation(violation_text)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            known_pids = current_pids
