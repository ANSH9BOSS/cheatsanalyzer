import os
import json
import urllib.request

class ThreatCloudSync:
    """Synchronizes dynamic zero-day cheat signatures and ghost client tokens from Cloud Threat Intelligence."""

    def __init__(self, config):
        self.config = config
        self.api_url = os.environ.get("ANSH9BOSS_API_URL", "https://ansh9boss.vercel.app")

    def sync_signatures(self):
        """Fetches dynamic signatures and updates config in-memory."""
        url = f"{self.api_url}/api/rules"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "ANSH9BOSS-Sentinel/3.0"}
            )
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                for key in ["known_cheats", "known_packages", "cheat_strings", "memory_signatures", "cheat_domains"]:
                    if key in data and isinstance(data[key], list):
                        existing = set(self.config.get(key, []))
                        existing.update(data[key])
                        self.config[key] = list(existing)
                return True, f"Threat Cloud Synced: v{data.get('version', '3.0')}"
        except Exception:
            return False, "Offline fallback: using local threat database"
