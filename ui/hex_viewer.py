import customtkinter as ctk
from ui.theme import THEME

class HexViewerModal(ctk.CTkToplevel):
    """Interactive Live RAM Hex Viewer & Memory Heatmap Modal."""

    def __init__(self, parent, address="0x00007FF7A10B4000", data_bytes=None):
        super().__init__(parent)
        self.title(f"🧬 Live RAM Hex Inspector — {address}")
        self.geometry("820x520")
        self.configure(fg_color=THEME["bg_dark"])

        self.address = address
        self.data_bytes = data_bytes or (b"vape_v4_runtime_hook_memory_stream\x00\x00\x12\x34\x56" * 16)
        self.setup_ui()
        self.render_hex()

    def setup_ui(self):
        hdr = ctk.CTkFrame(self, fg_color=THEME["panel_bg"], corner_radius=10)
        hdr.pack(fill="x", padx=14, pady=10)

        ctk.CTkLabel(
            hdr,
            text=f"🧬 Target Memory Address: {self.address}",
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            text_color=THEME["accent_cyan"]
        ).pack(side="left", padx=14, pady=8)

        # Hex Text Box
        self.hex_box = ctk.CTkTextbox(
            self,
            fg_color="#080B10",
            text_color=THEME["accent_cyan"],
            font=ctk.CTkFont(family="Consolas", size=12)
        )
        self.hex_box.pack(fill="both", expand=True, padx=14, pady=(0, 14))

    def render_hex(self):
        lines = []
        header = "OFFSET      00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F   ASCII\n"
        header += "-" * 72 + "\n"
        lines.append(header)

        chunk_size = 16
        for offset in range(0, min(len(self.data_bytes), 512), chunk_size):
            chunk = self.data_bytes[offset:offset+chunk_size]
            hex_str1 = " ".join(f"{b:02X}" for b in chunk[:8])
            hex_str2 = " ".join(f"{b:02X}" for b in chunk[8:])
            ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{offset:08X}   {hex_str1:<23}  {hex_str2:<23}  |{ascii_str}|")

        self.hex_box.insert("end", "\n".join(lines))
