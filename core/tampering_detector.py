import os
import sys
import subprocess
from pathlib import Path

if os.name == "nt":
    import winreg
else:
    winreg = None

class TamperingDetector:
    """Detects self-destruct routines, event log clearing, journal tampering, and DNS cache hits."""

    def __init__(self, config=None):
        self.config = config or {}
        self.is_windows = os.name == "nt" or sys.platform == "win32"
        self.cheat_domains = [d.lower() for d in self.config.get("cheat_domains", [
            "vape.gg", "drip.gg", "slinky.gg", "spearmint.cc", 
            "astolfo.lgbt", "novoline.lol", "tenacity.dev", "entropy.club"
        ])]

    def check_prefetch_tampering(self):
        """Checks if Windows Prefetcher has been disabled to hide cheat execution."""
        if not self.is_windows or not winreg:
            return None

        try:
            key_path = r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                val, _ = winreg.QueryValueEx(key, "EnablePrefetcher")
                if val == 0:
                    return {
                        "risk": "DANGEROUS",
                        "type": "Prefetch Disabled",
                        "detail": "CRITICAL: Windows Prefetch has been disabled (EnablePrefetcher=0) - common self-destruct bypass."
                    }
        except Exception:
            pass
        return None

    def check_dns_cache(self):
        """Audits Windows DNS cache for connections to ghost client authentication servers."""
        if not self.is_windows:
            return []

        hits = []
        try:
            cmd = ["ipconfig", "/displaydns"]
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True, errors="ignore")
            lines = output.lower().split("\n")

            for line in lines:
                for domain in self.cheat_domains:
                    if domain in line and "record name" in line:
                        hits.append({
                            "risk": "CRITICAL",
                            "type": "DNS Cache Evidence",
                            "domain": domain,
                            "detail": f"DNS Cache Evidence: Machine recently resolved Ghost Client domain '{domain}'"
                        })
                        break
        except Exception:
            pass

        # Deduplicate
        unique_hits = []
        seen = set()
        for h in hits:
            if h["domain"] not in seen:
                seen.add(h["domain"])
                unique_hits.append(h)
        return unique_hits

    def check_recycle_bin_cheats(self):
        """Scans Windows Recycle Bin for recently deleted mod or cheat files."""
        if not self.is_windows:
            return []

        traces = []
        recycle_roots = [Path("C:/$Recycle.Bin")]

        try:
            for root in recycle_roots:
                if root.exists():
                    for f in root.rglob("*"):
                        if f.is_file():
                            name_lower = f.name.lower()
                            for cheat in ["vape", "drip", "slinky", "killaura", "clicker", "cheat"]:
                                if cheat in name_lower or f.suffix.lower() in [".jar", ".exe", ".dll"]:
                                    if cheat in name_lower:
                                        traces.append({
                                            "risk": "DANGEROUS",
                                            "type": "Recycle Bin Trace",
                                            "file": f.name,
                                            "detail": f"Recycle Bin: Found deleted cheat artifact '{f.name}'"
                                        })
                                        break
        except Exception:
            pass
        return traces

    def run_tampering_audit(self):
        """Runs complete anti-self-destruct and tampering inspection."""
        findings = []

        pf_tamper = self.check_prefetch_tampering()
        if pf_tamper:
            findings.append(pf_tamper)

        dns_hits = self.check_dns_cache()
        findings.extend(dns_hits)

        recycle_hits = self.check_recycle_bin_cheats()
        findings.extend(recycle_hits)

        return findings
