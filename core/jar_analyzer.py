import os
import sys
import zipfile
import time
from pathlib import Path

class JarAnalyzer:
    """Multi-layer static bytecode & manifest inspector for Minecraft JAR mods."""

    def __init__(self, config):
        self.config = config
        self.known_cheats = [c.lower() for c in config.get("known_cheats", [])]
        self.known_packages = [p.lower() for p in config.get("known_packages", [])]
        self.cheat_strings = [s.lower() for s in config.get("cheat_strings", [])]

    @staticmethod
    def check_recent_modification(filepath):
        try:
            mtime = os.path.getmtime(filepath)
            ctime = os.path.getctime(filepath) if os.name == "nt" else mtime
            latest = max(mtime, ctime)
            hours_diff = (time.time() - latest) / 3600
            return hours_diff <= 24
        except Exception:
            return False

    def analyze_jar(self, filepath):
        """
        Runs comprehensive multi-layer inspection on a single JAR file.
        Returns: dict with risk_level, layers_triggered, match_details, obfuscated, is_recent
        """
        filepath = Path(filepath)
        filename = filepath.name.lower()

        risk_level = "CLEAN"
        layers_triggered = []
        match_details = []
        obfuscated = False
        is_recent = self.check_recent_modification(filepath)

        # -------------------------------------------------------------
        # Layer 1: Filename Signature Match
        # -------------------------------------------------------------
        for cheat in self.known_cheats:
            if cheat == "badlion":
                if "badlion" in filename and "official" not in filename and "original" not in filename:
                    if risk_level != "DANGEROUS":
                        risk_level = "SUSPICIOUS"
                    layers_triggered.append("Layer 1 (Filename)")
                    match_details.append("Filename contains 'badlion' (Modified verification required)")
            elif cheat in filename:
                risk_level = "DANGEROUS"
                layers_triggered.append("Layer 1 (Filename)")
                match_details.append(f"Filename matches known cheat: '{cheat}'")
                break

        # -------------------------------------------------------------
        # Layer 2 & 3: JAR Package, Manifest & Bytecode String Analysis
        # -------------------------------------------------------------
        zip_ref = None
        try:
            zip_ref = zipfile.ZipFile(filepath, "r")
            file_list = zip_ref.namelist()

            class_files = [f for f in file_list if f.endswith(".class")]
            total_classes = len(class_files)

            # Obfuscation Heuristic 1: Excessive short class names (a.class, b.class)
            short_names = sum(1 for cf in class_files if len(Path(cf).stem) <= 2)
            if total_classes > 15 and (short_names / total_classes) > 0.80:
                obfuscated = True

            # Obfuscation Heuristic 2: Known protectors in filenames/paths
            protectors = ["yguard", "allatori", "zelix", "proguard", "stringer", "loaderencrypt", "dasho", "param"]
            for f in file_list:
                f_lower = f.lower()
                if any(p in f_lower for p in protectors):
                    obfuscated = True
                    break

            if obfuscated:
                if risk_level != "DANGEROUS":
                    risk_level = "SUSPICIOUS"
                layers_triggered.append("Obfuscation Detector")
                match_details.append("Detected heavy bytecode protector / abnormal obfuscation structure")

            # Layer 2: Package Structure & Manifest Metadata
            manifest_files = ["meta-inf/manifest.mf", "fabric.mod.json", "mods.toml", "mcmod.info", "quilt.mod.json"]
            for entry in file_list:
                entry_lower = entry.lower()
                for pkg in self.known_packages:
                    if f"/{pkg}/" in entry_lower or entry_lower.startswith(f"{pkg}/"):
                        risk_level = "DANGEROUS"
                        if "Layer 2 (Package)" not in layers_triggered:
                            layers_triggered.append("Layer 2 (Package)")
                        match_details.append(f"Found cheat package signature: '{pkg}' ({entry})")

            for meta_file in file_list:
                if meta_file.lower() in manifest_files:
                    try:
                        meta_content = zip_ref.read(meta_file).decode("utf-8", errors="ignore").lower()
                        for pkg in self.known_packages:
                            if pkg in meta_content:
                                risk_level = "DANGEROUS"
                                if "Layer 2 (Manifest)" not in layers_triggered:
                                    layers_triggered.append("Layer 2 (Manifest)")
                                match_details.append(f"Cheat package identifier '{pkg}' defined in {meta_file}")
                    except Exception:
                        pass

            # Layer 3: Deep Bytecode & Constant Pool String Scanner
            matched_strings = set()
            scan_exts = (".class", ".json", ".txt", ".toml", ".properties", ".yml", ".cfg")

            for entry in file_list:
                if entry.lower().endswith(scan_exts):
                    try:
                        content_bytes = zip_ref.read(entry).lower()

                        for cheat_str in self.cheat_strings:
                            if cheat_str.encode("utf-8") in content_bytes:
                                matched_strings.add(cheat_str)

                        # Layer 4: Stealers, Reflective Loaders & Malicious Payloads
                        if b"discord.com/api/webhooks" in content_bytes or b"discordapp.com/api/webhooks" in content_bytes:
                            risk_level = "DANGEROUS"
                            if "Layer 4 (Discord Webhook Grabber)" not in layers_triggered:
                                layers_triggered.append("Layer 4 (Discord Webhook Grabber)")
                            match_details.append(f"CRITICAL: Malicious Discord Token/Webhook Grabber in '{entry}'")

                        if b"runtime.getruntime().exec" in content_bytes or b"processbuilder" in content_bytes:
                            if risk_level != "DANGEROUS":
                                risk_level = "SUSPICIOUS"
                            if "Layer 4 (Native Execution)" not in layers_triggered:
                                layers_triggered.append("Layer 4 (Native Execution)")
                            match_details.append(f"Native Process Execution detected in '{entry}'")

                        if b"defineclass" in content_bytes and (b"urlclassloader" in content_bytes or b"unsafeprovider" in content_bytes):
                            risk_level = "DANGEROUS"
                            if "Layer 4 (Reflective Injector)" not in layers_triggered:
                                layers_triggered.append("Layer 4 (Reflective Injector)")
                            match_details.append(f"Reflective ClassLoader / Unsafe Injection payload in '{entry}'")

                        if b".dll" in content_bytes and (b"loadlibrary" in content_bytes or b"system.load" in content_bytes):
                            if risk_level != "DANGEROUS":
                                risk_level = "SUSPICIOUS"
                            if "Layer 4 (Native DLL Drop)" not in layers_triggered:
                                layers_triggered.append("Layer 4 (Native DLL Drop)")
                            match_details.append(f"Native DLL loading/extraction detected in '{entry}'")

                    except Exception:
                        pass

            if len(matched_strings) >= 3:
                risk_level = "DANGEROUS"
                layers_triggered.append("Layer 3 (Bytecode Strings)")
                match_details.append(f"Dangerous cheat keywords ({len(matched_strings)} hits): {list(matched_strings)}")
            elif len(matched_strings) in (1, 2):
                if risk_level != "DANGEROUS":
                    risk_level = "SUSPICIOUS"
                layers_triggered.append("Layer 3 (Bytecode Strings)")
                match_details.append(f"Suspicious cheat keywords ({len(matched_strings)} hits): {list(matched_strings)}")

        except zipfile.BadZipFile:
            obfuscated = True
            risk_level = "SUSPICIOUS"
            layers_triggered.append("Corrupt/Protector Header")
            match_details.append("ZIP header corrupted or blocked by anti-decompilation protector")
        except Exception as e:
            obfuscated = True
            risk_level = "SUSPICIOUS"
            layers_triggered.append("Read Error")
            match_details.append(f"Failed to read archive: {str(e)}")
        finally:
            if zip_ref:
                try:
                    zip_ref.close()
                except Exception:
                    pass

        if is_recent and risk_level != "CLEAN":
            layers_triggered.append("Recent File Trace")
            match_details.append("File was created/modified within the last 24 hours (Potential live injection)")

        return {
            "file_name": filepath.name,
            "file_path": str(filepath),
            "risk_level": risk_level,
            "detection_layer": " & ".join(layers_triggered) if layers_triggered else "Clean Inspection",
            "matched_details": match_details,
            "obfuscated": obfuscated,
            "is_recent": is_recent
        }
