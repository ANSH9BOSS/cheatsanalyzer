import os
import sys
import ctypes
from ctypes import wintypes
import psutil

class JVMTIDumper:
    """Extracts and audits loaded Java classes and in-memory class descriptors directly from JVM RAM."""

    def __init__(self, config=None):
        self.config = config or {}
        self.is_windows = os.name == "nt" or sys.platform == "win32"
        self.cheat_class_markers = [
            b"Lnet/vape/", b"Lvape/", b"Lcom/drip/", b"Ldrip/", b"Lslinky/", 
            b"Lnet/kura/", b"Lnet/karma/", b"Lnet/spearmint/", b"Lnet/augustus/",
            b"Lnet/meteorclient/", b"Lnet/wurstclient/", b"Lnet/liquidbounce/",
            b"Lcom/entropy/", b"Lcom/doomsday/", b"Lnet/novoline/", b"Lnet/tenacity/"
        ]

    def scan_jvm_loaded_classes(self, pid):
        """
        Scans committed memory for Java internal Class Descriptor tokens (e.g., 'Lnet/vape/client/').
        Returns list of in-memory injected classes found.
        """
        if not self.is_windows:
            return []

        kernel32 = ctypes.windll.kernel32
        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010
        MEM_COMMIT = 0x1000
        PAGE_READWRITE = 0x04
        PAGE_EXECUTE_READWRITE = 0x40

        handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not handle:
            return []

        injected_classes = set()
        address = 0
        max_bytes = 150 * 1024 * 1024  # 150MB scan budget
        total_scanned = 0

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

        try:
            while total_scanned < max_bytes:
                res = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
                if not res:
                    break

                if mbi.State == MEM_COMMIT and mbi.Protect in (PAGE_READWRITE, PAGE_EXECUTE_READWRITE) and mbi.RegionSize > 0:
                    read_size = min(mbi.RegionSize, 1024 * 1024)
                    buffer = ctypes.create_string_buffer(read_size)
                    bytes_read = ctypes.c_size_t(0)

                    if kernel32.ReadProcessMemory(handle, ctypes.c_void_p(address), buffer, read_size, ctypes.byref(bytes_read)):
                        if bytes_read.value > 0:
                            data = buffer.raw[:bytes_read.value]
                            total_scanned += bytes_read.value

                            for marker in self.cheat_class_markers:
                                if marker in data:
                                    idx = data.find(marker)
                                    # Extract class signature string
                                    class_name = data[idx:idx+40].split(b";")[0].decode("utf-8", errors="ignore")
                                    injected_classes.add(class_name)

                address += mbi.RegionSize if mbi.RegionSize > 0 else 4096

        finally:
            kernel32.CloseHandle(handle)

        detections = []
        for cls in injected_classes:
            detections.append({
                "risk": "CRITICAL",
                "type": "In-Memory Injected JVM Class",
                "class_descriptor": cls,
                "detail": f"Runtime In-Memory Class Dumper: Unlinked injected class detected in JVM heap: '{cls}'"
            })
        return detections
