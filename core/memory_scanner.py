import os
import sys
import ctypes
from ctypes import wintypes
import psutil

# Win32 Memory Constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

class ProcessMemoryScanner:
    """Win32 live RAM & process inspector for detecting injected ghost clients in Minecraft."""

    def __init__(self, config=None):
        self.config = config or {}
        self.signatures = [s.lower().encode("utf-8") for s in self.config.get("memory_signatures", [
            "vape.gg", "vape_v4", "drip.gg", "slinky.gg", "spearmint.cc", 
            "raven_bplus", "kura_client", "entropy.club", "doomsday.gg", 
            "novoline.lol", "tenacity.dev", "astolfo.lgbt"
        ])]
        self.is_windows = os.name == "nt" or sys.platform == "win32"

    def find_minecraft_processes(self):
        """Finds all active java, javaw, and Minecraft launcher processes."""
        processes = []
        target_names = ["javaw.exe", "java.exe", "minecraft.exe", "minecraftlauncher.exe"]
        
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                name = proc.info["name"]
                if name and name.lower() in target_names:
                    cmdline = " ".join(proc.info.get("cmdline") or [])
                    processes.append({
                        "pid": proc.info["pid"],
                        "name": name,
                        "cmdline": cmdline,
                        "proc": proc
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return processes

    def scan_process_memory(self, pid, max_mb=250):
        """
        Scans committed virtual memory pages of a process for ghost client signatures.
        Returns: list of detections with hit details.
        """
        if not self.is_windows:
            return []

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 
            False, 
            pid
        )
        if not handle:
            return [{"risk": "WARNING", "detail": f"Access Denied: Could not open PID {pid} for memory inspection."}]

        detections = []
        mbi = MEMORY_BASIC_INFORMATION()
        address = 0
        total_scanned_bytes = 0
        max_bytes = max_mb * 1024 * 1024

        valid_protects = (PAGE_READWRITE, PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_EXECUTE_READ)

        try:
            while total_scanned_bytes < max_bytes:
                res = kernel32.VirtualQueryEx(
                    handle, 
                    ctypes.c_void_p(address), 
                    ctypes.byref(mbi), 
                    ctypes.sizeof(mbi)
                )
                if not res:
                    break

                # Inspect committed pages with read permissions
                if mbi.State == MEM_COMMIT and mbi.Protect in valid_protects and mbi.RegionSize > 0:
                    read_size = min(mbi.RegionSize, 1024 * 1024)  # 1MB buffer chunks
                    buffer = ctypes.create_string_buffer(read_size)
                    bytes_read = ctypes.c_size_t(0)

                    if kernel32.ReadProcessMemory(handle, ctypes.c_void_p(address), buffer, read_size, ctypes.byref(bytes_read)):
                        if bytes_read.value > 0:
                            data = buffer.raw[:bytes_read.value].lower()
                            total_scanned_bytes += bytes_read.value

                            for sig in self.signatures:
                                if sig in data:
                                    sig_str = sig.decode("utf-8", errors="ignore")
                                    detections.append({
                                        "risk": "CRITICAL",
                                        "pid": pid,
                                        "signature": sig_str,
                                        "address": hex(address),
                                        "detail": f"Injected Ghost Client signature '{sig_str}' identified in active RAM at {hex(address)}"
                                    })

                address += mbi.RegionSize if mbi.RegionSize > 0 else 4096

        finally:
            kernel32.CloseHandle(handle)

        return detections

    def audit_loaded_modules(self, pid):
        """Audits loaded DLL modules for known injector DLLs."""
        detections = []
        try:
            proc = psutil.Process(pid)
            for m in proc.memory_maps():
                path = m.path.lower() if m.path else ""
                for cheat in ["vape", "drip", "slinky", "kura", "entropy", "inject", "hook"]:
                    if cheat in path and "system32" not in path and "syswow64" not in path:
                        detections.append({
                            "risk": "CRITICAL",
                            "pid": pid,
                            "module": m.path,
                            "detail": f"Suspicious Injected DLL mapped in memory: {m.path}"
                        })
        except Exception:
            pass
        return detections

    def run_full_memory_audit(self):
        """Runs complete memory audit on all active Minecraft processes."""
        results = {
            "processes_found": 0,
            "detections": []
        }
        procs = self.find_minecraft_processes()
        results["processes_found"] = len(procs)

        for p in procs:
            pid = p["pid"]
            # Scan memory
            mem_hits = self.scan_process_memory(pid)
            results["detections"].extend(mem_hits)

            # Audit modules
            mod_hits = self.audit_loaded_modules(pid)
            results["detections"].extend(mod_hits)

        return results
