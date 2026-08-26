import os
import sys
import ctypes
import psutil

class OverlayHookHunter:
    """Detects injected Dear ImGui click-GUIs, DirectX Present hooks, and OpenGL swap-buffer detours."""

    def __init__(self):
        self.is_windows = os.name == "nt" or sys.platform == "win32"
        self.imgui_markers = [
            b"ImGui::Begin", b"ImGui::Render", b"ImGui::CreateContext",
            b"ImGui::GetIO", b"ImFontAtlas", b"imgui.ini",
            b"wglSwapBuffers_Hook", b"D3D11PresentHook", b"D3D9EndSceneHook"
        ]

    def scan_overlay_hooks(self, pid):
        """Scans process memory for Dear ImGui rendering structures and graphics swap hooks."""
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

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", ctypes.c_ulong),
                ("RegionSize", ctypes.c_size_t),
                ("State", ctypes.c_ulong),
                ("Protect", ctypes.c_ulong),
                ("Type", ctypes.c_ulong),
            ]

        mbi = MEMORY_BASIC_INFORMATION()
        address = 0
        max_bytes = 100 * 1024 * 1024
        total_scanned = 0
        detections = []

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

                            for marker in self.imgui_markers:
                                if marker in data:
                                    marker_str = marker.decode("utf-8", errors="ignore")
                                    detections.append({
                                        "risk": "CRITICAL",
                                        "type": "Injected ImGui/DirectX Hook",
                                        "detail": f"Overlay Hook Hunter: Injected ImGui/DirectX hook token '{marker_str}' detected at {hex(address)} (Hidden Cheat Menu)"
                                    })
                                    break

                address += mbi.RegionSize if mbi.RegionSize > 0 else 4096

        finally:
            kernel32.CloseHandle(handle)

        return detections
