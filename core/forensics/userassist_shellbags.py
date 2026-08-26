import os
import sys
import codecs

if os.name == "nt":
    import winreg
else:
    winreg = None

class UserAssistExplorer:
    """Decodes Windows Explorer UserAssist ROT-13 registry keys to extract execution frequency and timestamps."""

    def __init__(self):
        self.is_windows = os.name == "nt" or sys.platform == "win32"
        self.cheat_keywords = [
            "vape", "drip", "slinky", "autoclick", "clicker", "cleaner",
            "kura", "karma", "spearmint", "entropy", "doomsday", "destruct"
        ]

    def audit_userassist_rot13(self):
        """Scans and decodes UserAssist registry entries."""
        if not self.is_windows or not winreg:
            return []

        traces = []
        base_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, base_path) as ua_key:
                num_guids = winreg.QueryInfoKey(ua_key)[0]
                for i in range(num_guids):
                    guid = winreg.EnumKey(ua_key, i)
                    count_path = f"{base_path}\\{guid}\\Count"
                    try:
                        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, count_path) as count_key:
                            num_values = winreg.QueryInfoKey(count_key)[1]
                            for j in range(num_values):
                                val_name, _, _ = winreg.EnumValue(count_key, j)
                                # Decode ROT13 obfuscated executable path
                                decoded_path = codecs.decode(val_name, "rot_13")
                                decoded_lower = decoded_path.lower()

                                for kw in self.cheat_keywords:
                                    if kw in decoded_lower and ".exe" in decoded_lower:
                                        traces.append({
                                            "risk": "DANGEROUS",
                                            "type": "UserAssist Execution Record",
                                            "path": decoded_path,
                                            "detail": f"Windows UserAssist Forensic Record: Application launched: '{decoded_path}'"
                                        })
                                        break
                    except Exception:
                        pass
        except Exception:
            pass

        return traces
