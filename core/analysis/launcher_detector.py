import os
import sys
from pathlib import Path
import psutil

class MinecraftLauncherDetector:
    """Automatically detects all Minecraft launcher mod directories and running game instances across the system."""

    def __init__(self):
        self.appdata = os.environ.get("APPDATA")
        self.localappdata = os.environ.get("LOCALAPPDATA")
        self.userprofile = os.environ.get("USERPROFILE")

    def find_active_game_mod_dirs(self):
        """Finds the active mods folder from running Minecraft JVM processes by inspecting --gameDir."""
        active_dirs = []
        try:
            for proc in psutil.process_iter(["pid", "name", "cmdline", "cwd"]):
                try:
                    name = (proc.info.get("name") or "").lower()
                    if "java" in name or "minecraft" in name:
                        cmdline = proc.info.get("cmdline") or []
                        # Look for --gameDir argument
                        for i, arg in enumerate(cmdline):
                            if arg == "--gameDir" and i + 1 < len(cmdline):
                                gdir = Path(cmdline[i + 1])
                                mdir = gdir / "mods"
                                if mdir.exists():
                                    active_dirs.append({
                                        "name": f"Active Game (PID {proc.info['pid']})",
                                        "path": str(mdir.resolve())
                                    })
                                elif gdir.exists():
                                    active_dirs.append({
                                        "name": f"Active Game (PID {proc.info['pid']})",
                                        "path": str(gdir.resolve())
                                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass
        return active_dirs

    def get_all_launcher_search_paths(self):
        """Returns a list of all potential Minecraft mod folder locations across popular launchers."""
        candidates = []

        # 1. Active running games
        candidates.extend(self.find_active_game_mod_dirs())

        # 2. Standard .minecraft
        if self.appdata:
            mc_mods = Path(self.appdata) / ".minecraft/mods"
            if mc_mods.exists():
                candidates.append({"name": "Standard (.minecraft/mods)", "path": str(mc_mods.resolve())})

            # Versions mods
            mc_ver = Path(self.appdata) / ".minecraft/versions"
            if mc_ver.exists():
                for vf in mc_ver.glob("*/mods"):
                    if vf.is_dir():
                        candidates.append({"name": f".minecraft (Version: {vf.parent.name})", "path": str(vf.resolve())})

            # Prism Launcher
            prism = Path(self.appdata) / "PrismLauncher/instances"
            if prism.exists():
                for inst in prism.glob("*/.minecraft/mods"):
                    if inst.is_dir():
                        candidates.append({"name": f"Prism ({inst.parent.parent.name})", "path": str(inst.resolve())})
                for inst in prism.glob("*/mods"):
                    if inst.is_dir():
                        candidates.append({"name": f"Prism ({inst.parent.name})", "path": str(inst.resolve())})

            # Modrinth App
            modrinth = Path(self.appdata) / "com.modrinth.theseus/profiles"
            if modrinth.exists():
                for prof in modrinth.glob("*/mods"):
                    if prof.is_dir():
                        candidates.append({"name": f"Modrinth App ({prof.parent.name})", "path": str(prof.resolve())})

            # Feather Client
            feather = Path(self.appdata) / ".feather/user-mods"
            if feather.exists():
                candidates.append({"name": "Feather Client (user-mods)", "path": str(feather.resolve())})

            # Technic Launcher
            technic = Path(self.appdata) / ".technic/modpacks"
            if technic.exists():
                for tp in technic.glob("*/mods"):
                    if tp.is_dir():
                        candidates.append({"name": f"Technic ({tp.parent.name})", "path": str(tp.resolve())})

            # ATLauncher
            atlauncher = Path(self.appdata) / "ATLauncher/instances"
            if atlauncher.exists():
                for at in atlauncher.glob("*/mods"):
                    if at.is_dir():
                        candidates.append({"name": f"ATLauncher ({at.parent.name})", "path": str(at.resolve())})

        # 3. CurseForge
        if self.userprofile:
            cf = Path(self.userprofile) / "curseforge/minecraft/Instances"
            if cf.exists():
                for ci in cf.glob("*/mods"):
                    if ci.is_dir():
                        candidates.append({"name": f"CurseForge ({ci.parent.name})", "path": str(ci.resolve())})

        # 4. Local workspace test_mods/ / mods/
        for local_dir in ["test_mods", "mods"]:
            lp = Path(local_dir).resolve()
            if lp.exists() and lp.is_dir():
                candidates.append({"name": f"Local Workspace ({local_dir})", "path": str(lp)})

        # Deduplicate by path
        unique = []
        seen = set()
        for c in candidates:
            p = str(Path(c["path"]).resolve())
            if p not in seen:
                seen.add(p)
                unique.append(c)

        return unique

    def discover_all_mod_files(self, selected_path=None):
        """Discovers all .jar files from the selected path or automatically from all detected launchers."""
        all_jars = []

        if selected_path and Path(selected_path).exists():
            sp = Path(selected_path)
            if sp.is_file() and sp.suffix == ".jar":
                all_jars.append(sp.resolve())
            elif sp.is_dir():
                all_jars.extend([f.resolve() for f in sp.rglob("*.jar")])
        else:
            search_paths = self.get_all_launcher_search_paths()
            for sp_info in search_paths:
                p = Path(sp_info["path"])
                if p.exists() and p.is_dir():
                    all_jars.extend([f.resolve() for f in p.rglob("*.jar")])

        # Deduplicate
        return list(set(all_jars))
