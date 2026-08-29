import os
import json
import urllib.request
import urllib.error
from datetime import datetime

DEFAULT_WEBHOOK = "https://discord.com/api/webhooks/1543109814593519658/VeKGdUanLyJCR5-N86Ma0EcD4q5VR18MiDGJOEyMiF0t5HNVd_dQS3Qxcgvkzjkpo1hN"

class DiscordStaffAlerts:
    """Dispatches real-time forensic screenshare alert embeds and dossier reports to server staff Discord channels."""

    def __init__(self, webhook_url=None):
        self.webhook_url = webhook_url or os.environ.get("ANSH9BOSS_DISCORD_WEBHOOK", DEFAULT_WEBHOOK)

    def send_audit_alert(self, scan_results, player_ign="Player", output_file=None):
        """Sends rich formatted Discord embed alert to staff webhook."""
        if not self.webhook_url:
            return False, "No Discord Webhook URL configured"

        highest_risk = scan_results.get("highest_risk", "CLEAN")
        threat_score = scan_results.get("threat_score", 0)
        total_mods = scan_results.get("total_mods", 0)
        flagged_mods = scan_results.get("flagged_mods", 0)
        ram_hits = len(scan_results.get("ram_hits", []))
        forensic_hits = len(scan_results.get("forensic_hits", [])) + len(scan_results.get("tampering_hits", []))

        # Color: Green (0x00E676) | Yellow (0xFFD600) | Red (0xFF1744)
        color = 0x00E676 if highest_risk == "CLEAN" else (0xFFD600 if highest_risk == "SUSPICIOUS" else 0xFF1744)

        embed = {
            "title": f"🛡️ ANSH9BOSS Forensic Screenshare Audit — {player_ign}",
            "description": f"**Final Audit Verdict:** `{highest_risk}`\n**Threat Confidence Index:** `{threat_score}%`",
            "color": color,
            "fields": [
                {"name": "📦 Scanned Mods", "value": f"`{total_mods}` Total / `{flagged_mods}` Flagged", "inline": True},
                {"name": "🧠 RAM Memory Hooks", "value": f"`{ram_hits}` Injections", "inline": True},
                {"name": "🛡️ Forensic / USB Traces", "value": f"`{forensic_hits}` Traces", "inline": True},
            ],
            "footer": {
                "text": f"ANSH9BOSS Forensic Suite v3.0 • {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}"
            }
        }

        payload = {
            "username": "ANSH9BOSS Anti-Cheat Sentinel",
            "avatar_url": "https://raw.githubusercontent.com/ANSH9BOSS/cheatsanalyzer/main/web/static/logo.png",
            "embeds": [embed]
        }

        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "ANSH9BOSS-Sentinel/3.0"
                }
            )
            with urllib.request.urlopen(req, timeout=4) as resp:
                return True, "Alert sent successfully to Discord staff channel"
        except Exception as e:
            return False, f"Failed to send Discord alert: {str(e)}"
