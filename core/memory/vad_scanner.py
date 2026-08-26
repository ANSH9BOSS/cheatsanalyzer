import os
import sys
import ctypes
from ctypes import wintypes
import psutil

class VADScanner:
    """Detects non-image executable memory pages (Manual Mapped DLLs, shellcode stubs, and reflective loaders)."""

    def __init__(self):
        self.is_windows = os.name == "nt" or sys.platform == "win32"

    def scan_unlinked_executable_memory(self, pid):
        """
        Walks Virtual Address Descriptors looking for private committed executable memory.
        Private RX/RWX memory indicates manual-mapped DLLs or shellcode.
        """
        if not self.is_windows:
            return []

        kernel32 = ctypes.windll.kernel32
        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010
        MEM_COMMIT = 0x1000
        MEM_PRIVATE = 0x20000
        PAGE_EXECUTE = 0x10
        PAGE_EXECUTE_READ = 0x20
        PAGE_EXECUTE_READWRITE = 0x40

        handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not handle:
            return []

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

        mbi = MEMORY_BASIC_INFORMATION()
        address = 0
        unlinked_pages = []

        try:
            while True:
                res = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
                if not res:
                    break

                # Detect Private Committed Executable Memory
                if mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE:
                    if mbi.Protect in (PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE):
                        # Verify if size is substantial (e.g. > 16KB typically allocated for injected DLLs)
                        if mbi.RegionSize >= 16384:
                            unlinked_pages.append({
                                "address": hex(address),
                                "size_kb": mbi.RegionSize // 1024,
                                "protect": "RWX" if mbi.Protect == PAGE_EXECUTE_READWRITE else "RX"
                            })

                address += mbi.RegionSize if mbi.RegionSize > 0 else 4096

        finally:
            kernel32.CloseHandle(handle)

        detections = []
        if len(unlinked_pages) > 2:  # Allow minimal JIT code stubs, flag abnormal private executable pages
            for page in unlinked_pages[:4]:
                detections.append({
                    "risk": "CRITICAL",
                    "type": "Manual-Mapped Injected Memory (VAD)",
                    "detail": f"VAD Memory Hunter: Non-disk-mapped executable memory ({page['protect']}) found at {page['address']} ({page['size_kb']} KB) — Signature of Manual-Mapped Ghost Client"
                })

        return detections
