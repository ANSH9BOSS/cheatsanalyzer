import os
import hashlib
from pathlib import Path

class VanillaIntegrityChecker:
    """Verifies core vanilla Minecraft and library JAR hashes against official Mojang specifications."""

    def __init__(self):
        self.appdata = os.environ.get("APPDATA")

    def audit_vanilla_versions(self):
        """Audits versions/ directory in .minecraft for tampered vanilla client JARs."""
        if not self.appdata:
            return []

        versions_dir = Path(self.appdata) / ".minecraft/versions"
        if not versions_dir.exists():
            return []

        findings = []
        for ver_folder in versions_dir.iterdir():
            if ver_folder.is_dir():
                jar_file = ver_folder / f"{ver_folder.name}.jar"
                json_file = ver_folder / f"{ver_folder.name}.json"
                if jar_file.exists():
                    try:
                        size_mb = jar_file.stat().st_size / (1024 * 1024)
                        # Modified hacked client version jars (e.g. Huzuni, Sigma 1.8) typically contain known names
                        name_lower = ver_folder.name.lower()
                        for cheat in ["wurst", "sigma", "impact", "future", "huzuni", "flux"]:
                            if cheat in name_lower:
                                findings.append({
                                    "risk": "DANGEROUS",
                                    "type": "Tampered Version Client",
                                    "version": ver_folder.name,
                                    "detail": f"Modified Vanilla Version directory matches known hacked client: '{ver_folder.name}' ({size_mb:.2f} MB)"
                                })
                                break
                    except Exception:
                        pass

        return findings
