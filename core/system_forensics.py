import os
import sys
import glob
from pathlib import Path

if os.name == "nt":
    import winreg
else:
    winreg = None

class SystemForensics:
    """Forensic auditor for USB devices, BAM execution traces, Prefetch, and Shimcache."""

    def __init__(self, config=None):
        self.config = config or {}
        self.is_windows = os.name == "nt" or sys.platform == "win32"

    def audit_usbstor_devices(self):
        """Audits HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR for connected USB drives."""
        if not self.is_windows or not winreg:
            return []

        devices = []
        try:
            key_path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as usbstor_key:
                num_subkeys = winreg.QueryInfoKey(usbstor_key)[0]
                for i in range(num_subkeys):
                    dev_type = winreg.EnumKey(usbstor_key, i)
                    with winreg.OpenKey(usbstor_key, dev_type) as dev_key:
                        num_instances = winreg.QueryInfoKey(dev_key)[0]
                        for j in range(num_instances):
                            instance_id = winreg.EnumKey(dev_key, j)
                            with winreg.OpenKey(dev_key, instance_id) as inst_key:
                                try:
                                    friendly_name = winreg.QueryValueEx(inst_key, "FriendlyName")[0]
                                except FileNotFoundError:
                                    friendly_name = dev_type

                                devices.append({
                                    "device_type": dev_type,
                                    "instance_id": instance_id,
                                    "friendly_name": friendly_name
                                })
        except Exception:
            pass

        return devices

    def audit_bam_execution_traces(self):
        """Audits Background Activity Moderator (BAM) execution logs from registry."""
        if not self.is_windows or not winreg:
            return []

        traces = []
        cheat_keywords = ["autoclick", "clicker", "vape", "drip", "slinky", "injector", "bypass", "cleaner", "kura", "entropy", "ghost"]
        try:
            base_path = r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_path) as user_settings_key:
                num_users = winreg.QueryInfoKey(user_settings_key)[0]
                for i in range(num_users):
                    user_sid = winreg.EnumKey(user_settings_key, i)
                    with winreg.OpenKey(user_settings_key, user_sid) as sid_key:
                        num_values = winreg.QueryInfoKey(sid_key)[1]
                        for j in range(num_values):
                            val_name, val_data, _ = winreg.EnumValue(sid_key, j)
                            val_lower = val_name.lower()
                            
                            # Check for USB/Removable drives (e.g., \Device\HarddiskVolume or typical cheat paths)
                            for kw in cheat_keywords:
                                if kw in val_lower:
                                    traces.append({
                                        "risk": "DANGEROUS",
                                        "type": "BAM Execution Trace",
                                        "path": val_name,
                                        "detail": f"BAM forensic evidence: Known cheat/autoclicker executable executed: '{val_name}'"
                                    })
                                    break
        except Exception:
            pass

        return traces

    def audit_prefetch_files(self):
        """Scans Windows Prefetch directory for cheat executable launch traces."""
        if not self.is_windows:
            return []

        prefetch_dir = Path("C:/Windows/Prefetch")
        if not prefetch_dir.exists():
            return []

        traces = []
        suspicious_pf = [
            "autoclick", "clicker", "vape", "drip", "slinky", "entropy", 
            "cheatengine", "processhacker", "cleaner", "fsutil", "journal"
        ]

        try:
            for pf_file in prefetch_dir.glob("*.pf"):
                pf_name = pf_file.name.lower()
                for kw in suspicious_pf:
                    if kw in pf_name:
                        traces.append({
                            "risk": "SUSPICIOUS",
                            "type": "Prefetch Evidence",
                            "file": pf_file.name,
                            "path": str(pf_file),
                            "detail": f"Windows Prefetch evidence: Program executed on system: '{pf_file.name}'"
                        })
                        break
        except PermissionError:
            # Prefetch requires administrator permission in some environments
            pass
        except Exception:
            pass

        return traces

    def audit_muicache(self):
        """Scans MUICache registry entries for executed applications."""
        if not self.is_windows or not winreg:
            return []

        traces = []
        try:
            mui_path = r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, mui_path) as mui_key:
                num_values = winreg.QueryInfoKey(mui_key)[1]
                for i in range(num_values):
                    val_name, val_data, _ = winreg.EnumValue(mui_key, i)
                    val_lower = val_name.lower()
                    for cheat in ["vape", "drip", "slinky", "autoclicker", "kura", "raven", "entropy"]:
                        if cheat in val_lower:
                            traces.append({
                                "risk": "DANGEROUS",
                                "type": "MUICache Trace",
                                "path": val_name,
                                "name": str(val_data),
                                "detail": f"MUICache execution trace: '{val_name}' ({val_data})"
                            })
        except Exception:
            pass

        return traces

    def run_full_forensics_audit(self):
        """Executes complete system & USB forensic audit."""
        results = {
            "usb_devices": self.audit_usbstor_devices(),
            "bam_traces": self.audit_bam_execution_traces(),
            "prefetch_traces": self.audit_prefetch_files(),
            "muicache_traces": self.audit_muicache(),
            "all_threats": []
        }

        results["all_threats"].extend(results["bam_traces"])
        results["all_threats"].extend(results["prefetch_traces"])
        results["all_threats"].extend(results["muicache_traces"])
        return results
