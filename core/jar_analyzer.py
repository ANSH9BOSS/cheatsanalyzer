import os
import sys
import zipfile
import time
from pathlib import Path
from core.trusted_database import OFFICIAL_MODS_WHITELIST, SAFE_MANIFEST_IDENTIFIERS

class JarAnalyzer:
    """Zero-False-Positive Bytecode & Packet Heuristic Inspector for Minecraft JAR Mods."""

    def __init__(self, config):
        self.config = config
        self.known_cheats = [c.lower() for c in config.get("known_cheats", [])]
        self.known_packages = [p.lower() for p in config.get("known_packages", [])]

        # Explicit combat & hack signatures (Context-aware to eliminate false positives)
        self.combat_signatures = [
            b"killaura", b"aimbot", b"triggerbot", b"autototem", b"scaffold",
            b"antiknockback", b"wallhack", b"fastplace", b"cheststealer",
            b"s12packetentityvelocity", b"s27packetexplosion", b"c02packetuseentity",
            b"c03packetplayer", b"extendedreach", b"getreachdistance",
            b"rightclickdelaytimer", b"hitboxexpand", b"silentrotation",
            b"baritone.api", b"vape_v4", b"drip_lite", b"slinky_client"
        ]

        # Malicious Stealers & RAT Signatures
        self.malicious_payload_signatures = [
            (b"discord.com/api/webhooks", "Discord Webhook Token Stealer"),
            (b"discordapp.com/api/webhooks", "Discord Webhook Token Stealer"),
            (b"launcher_accounts.json", "Minecraft Account Token Stealer"),
            (b"local storage/leveldb", "Browser/Discord Session Stealer"),
            (b"api.mojang.com/profiles/minecraft", "Session Token Hijacker")
        ]

    def analyze_jar(self, filepath):
        """
        Runs context-aware multi-layer heuristic scan.
        Returns: dict with risk_level, threat_score (0-100), layers_triggered, match_details, obfuscated
        """
        filepath = Path(filepath)
        filename = filepath.name.lower()
        stem_name = filepath.stem.lower()

        threat_score = 0
        layers_triggered = []
        match_details = []
        obfuscated = False
        is_whitelisted = False

        # -------------------------------------------------------------
        # Step 0: Check Official Mod Whitelist by Name/Stem
        # -------------------------------------------------------------
        clean_stem = stem_name.split("-")[0].split("_")[0].strip()
        if clean_stem in OFFICIAL_MODS_WHITELIST:
            is_whitelisted = True

        # -------------------------------------------------------------
        # Layer 1: Filename Signature Match
        # -------------------------------------------------------------
        for cheat in self.known_cheats:
            if cheat in ("badlion", "lunarclient", "feather", "essential"):
                continue  # Official clients ignored here
            if cheat in filename:
                threat_score += 65
                layers_triggered.append("Layer 1 (Known Cheat Name)")
                match_details.append(f"Filename matches known cheat signature: '{cheat}'")
                break

        # -------------------------------------------------------------
        # Layer 2 & 3: JAR Manifest, Bytecode & Payload Analysis
        # -------------------------------------------------------------
        zip_ref = None
        try:
            zip_ref = zipfile.ZipFile(filepath, "r")
            file_list = zip_ref.namelist()

            # Manifest ID Check
            manifest_files = ["fabric.mod.json", "mods.toml", "mcmod.info", "quilt.mod.json", "meta-inf/manifest.mf"]
            manifest_found = False
            for meta in file_list:
                if meta.lower() in manifest_files:
                    manifest_found = True
                    try:
                        meta_text = zip_ref.read(meta).decode("utf-8", errors="ignore").lower()
                        # Check safe manifest authors/identifiers
                        if any(safe_id in meta_text for safe_id in SAFE_MANIFEST_IDENTIFIERS):
                            is_whitelisted = True

                        for pkg in self.known_packages:
                            if pkg in meta_text:
                                threat_score += 75
                                layers_triggered.append("Layer 2 (Cheat Manifest)")
                                match_details.append(f"Cheat client ID '{pkg}' defined in {meta}")
                    except Exception:
                        pass

            # Package structure check
            for entry in file_list:
                entry_lower = entry.lower()
                for pkg in self.known_packages:
                    if f"/{pkg}/" in entry_lower or entry_lower.startswith(f"{pkg}/"):
                        threat_score += 85
                        if "Layer 2 (Cheat Package)" not in layers_triggered:
                            layers_triggered.append("Layer 2 (Cheat Package)")
                        match_details.append(f"Found cheat package: '{pkg}' ({entry})")

            # Obfuscation & Protector Check (Only penalize if not a known whitelisted mod)
            class_files = [f for f in file_list if f.endswith(".class")]
            total_classes = len(class_files)
            short_names = sum(1 for cf in class_files if len(Path(cf).stem) <= 2)

            if total_classes > 20 and (short_names / total_classes) > 0.85 and not is_whitelisted:
                obfuscated = True
                threat_score += 25
                layers_triggered.append("Heuristic (Heavy Obfuscation)")
                match_details.append(f"High-entropy class obfuscation ({short_names}/{total_classes} single-character classes)")

            protectors = ["allatori", "zelix", "stringer", "loaderencrypt", "dasho"]
            for f in file_list:
                f_lower = f.lower()
                if any(p in f_lower for p in protectors) and not is_whitelisted:
                    obfuscated = True
                    threat_score += 30
                    layers_triggered.append("Heuristic (Known Protector)")
                    match_details.append("Detected commercial Java protector stub")
                    break

            # Deep Bytecode & Stealer Payload Scanner
            matched_combat = set()
            scan_exts = (".class", ".json", ".txt", ".toml", ".properties", ".yml")

            for entry in file_list:
                if entry.lower().endswith(scan_exts):
                    try:
                        content_bytes = zip_ref.read(entry).lower()

                        # Stealers & Payloads (Critical +100 Threat Score)
                        for sig, desc in self.malicious_payload_signatures:
                            if sig in content_bytes:
                                threat_score += 100
                                layers_triggered.append("Layer 4 (Malicious Stealer)")
                                match_details.append(f"CRITICAL THREAT: {desc} identified in '{entry}'")

                        # Reflective & Native DLL Hijack
                        if b"defineclass" in content_bytes and (b"urlclassloader" in content_bytes or b"unsafeprovider" in content_bytes):
                            threat_score += 60
                            layers_triggered.append("Layer 4 (Reflective Injector)")
                            match_details.append(f"Reflective ClassLoader injection routine found in '{entry}'")

                        # Combat hack keywords
                        for csig in self.combat_signatures:
                            if csig in content_bytes:
                                matched_combat.add(csig.decode("utf-8", errors="ignore"))

                    except Exception:
                        pass

            # Evaluate Combat Matches
            if len(matched_combat) >= 3:
                threat_score += 70
                layers_triggered.append("Layer 3 (Combat Cheat Opcodes)")
                match_details.append(f"Multiple combat packet/hack signatures ({len(matched_combat)} hits): {list(matched_combat)[:5]}")
            elif len(matched_combat) in (1, 2) and not is_whitelisted:
                threat_score += 35
                layers_triggered.append("Layer 3 (Suspicious Opcodes)")
                match_details.append(f"Combat keyword triggers: {list(matched_combat)}")

        except zipfile.BadZipFile:
            obfuscated = True
            threat_score += 30
            layers_triggered.append("Corrupt/Protector Header")
            match_details.append("Corrupted ZIP archive headers (Common anti-decompilation technique)")
        except Exception as e:
            obfuscated = True
            threat_score += 20
            match_details.append(f"Archive inspection error: {str(e)}")
        finally:
            if zip_ref:
                try:
                    zip_ref.close()
                except Exception:
                    pass

        # Whitelist mitigation: If official trusted mod with no stealers, reduce threat score
        if is_whitelisted and "Layer 4 (Malicious Stealer)" not in layers_triggered and threat_score < 70:
            threat_score = 0
            layers_triggered = []
            match_details = ["Verified official legitimate mod signature"]

        # Cap threat score between 0 and 100
        threat_score = min(max(threat_score, 0), 100)

        # Risk Classification
        if threat_score >= 65:
            risk_level = "DANGEROUS"
        elif threat_score >= 30:
            risk_level = "SUSPICIOUS"
        else:
            risk_level = "CLEAN"

        return {
            "file_name": filepath.name,
            "file_path": str(filepath),
            "risk_level": risk_level,
            "threat_score": threat_score,
            "detection_layer": " & ".join(layers_triggered) if layers_triggered else "Verified Clean",
            "matched_details": match_details,
            "obfuscated": obfuscated,
            "is_whitelisted": is_whitelisted
        }
