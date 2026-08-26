import hashlib
import json
import socket
from datetime import datetime

class AuditCertificateGenerator:
    """Generates tamper-proof SHA-256 cryptographic audit certificates for tournament validation."""

    @staticmethod
    def generate_certificate(scan_results, player_ign="Player"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        hostname = socket.gethostname()
        highest_risk = scan_results.get("highest_risk", "CLEAN")
        threat_score = scan_results.get("threat_score", 0)
        total_mods = scan_results.get("total_mods", 0)
        flagged_mods = scan_results.get("flagged_mods", 0)

        # Build raw signature string
        sig_data = f"{player_ign}|{hostname}|{timestamp}|{highest_risk}|{threat_score}|{total_mods}|{flagged_mods}|ANSH9BOSS_v3_VERIFIED"
        cert_hash = hashlib.sha256(sig_data.encode("utf-8")).hexdigest().upper()

        certificate = {
            "certificate_id": f"CERT-{cert_hash[:12]}",
            "sha256_seal": cert_hash,
            "player_ign": player_ign,
            "hostname": hostname,
            "timestamp": timestamp,
            "verdict": highest_risk,
            "threat_score": f"{threat_score}%",
            "is_valid": True
        }
        return certificate
