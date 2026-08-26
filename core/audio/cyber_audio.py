import os
import sys
import threading
import subprocess

class CyberVoiceAlerts:
    """Sci-Fi synthesized voice announcements for forensic events and scan completions."""

    def __init__(self, enabled=True):
        self.enabled = enabled
        self.is_windows = os.name == "nt" or sys.platform == "win32"

    def speak(self, text):
        """Asynchronously synthesizes speech using Windows native speech engine."""
        if not self.enabled or not self.is_windows:
            return

        def _speak_thread():
            try:
                # Clean text for safe PowerShell passing
                clean_text = text.replace('"', '').replace("'", "")
                ps_cmd = f'Add-Type -AssemblyName System.Speech; (New-Object System.Speech.Synthesis.SpeechSynthesizer).Speak("{clean_text}");'
                subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps_cmd],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=0x08000000 if os.name == "nt" else 0
                )
            except Exception:
                pass

        threading.Thread(target=_speak_thread, daemon=True).start()
