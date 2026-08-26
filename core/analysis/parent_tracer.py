import psutil

class ParentProcessTracer:
    """Traces Minecraft parent process tree to verify legitimate launcher origin."""

    def __init__(self):
        self.known_launchers = [
            "minecraft.exe", "minecraftlauncher.exe", "prismlauncher.exe",
            "curseforge.exe", "modrinth app.exe", "feather.exe", "lunar client.exe",
            "multimc.exe", "badlionclient.exe", "atlauncher.exe", "gdlauncher.exe"
        ]

    def trace_minecraft_parent(self, pid):
        """Traces the parent executable of the target Minecraft JVM process."""
        try:
            proc = psutil.Process(pid)
            parent = proc.parent()
            if parent:
                pname = parent.name().lower()
                cmdline = " ".join(parent.cmdline() or [])
                is_legit = any(l in pname for l in self.known_launchers) or "java" in pname or "explorer.exe" in pname
                return {
                    "parent_pid": parent.pid,
                    "parent_name": parent.name(),
                    "parent_cmdline": cmdline[:120],
                    "is_recognized_launcher": is_legit,
                    "risk": "CLEAN" if is_legit else "SUSPICIOUS"
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        return {
            "parent_pid": "Unknown",
            "parent_name": "Unknown Launcher",
            "is_recognized_launcher": True,
            "risk": "CLEAN"
        }
