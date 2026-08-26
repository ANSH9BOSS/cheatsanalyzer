import zipfile
from pathlib import Path
import customtkinter as ctk
from ui.theme import THEME

class DecompilerViewerModal(ctk.CTkToplevel):
    """In-GUI Java Class Decompiler & Bytecode Inspector Modal."""

    def __init__(self, parent, jar_path):
        super().__init__(parent)
        self.jar_path = Path(jar_path)
        self.title(f"🔍 Class Inspector & Decompiler — {self.jar_path.name}")
        self.geometry("900x600")
        self.configure(fg_color=THEME["bg_dark"])

        self.setup_ui()
        self.load_jar_contents()

    def setup_ui(self):
        # Header
        hdr = ctk.CTkFrame(self, fg_color=THEME["panel_bg"], corner_radius=10)
        hdr.pack(fill="x", padx=14, pady=10)

        ctk.CTkLabel(
            hdr, 
            text=f"📦 {self.jar_path.name}", 
            font=ctk.CTkFont(family=THEME["font_family"], size=16, weight="bold"),
            text_color=THEME["accent_cyan"]
        ).pack(side="left", padx=14, pady=8)

        # Body with Split Pane (Left: Class Tree / List, Right: Decompiled Source View)
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=14, pady=(0, 10))

        # Left File List
        left_pane = ctk.CTkFrame(body, fg_color=THEME["panel_bg"], width=280, corner_radius=10)
        left_pane.pack(side="left", fill="both", padx=(0, 8), expand=False)

        ctk.CTkLabel(
            left_pane,
            text="JAR CLASS STRUCTURE",
            font=ctk.CTkFont(family=THEME["font_family"], size=11, weight="bold"),
            text_color=THEME["text_secondary"]
        ).pack(anchor="w", padx=12, pady=(10, 4))

        self.class_scroll = ctk.CTkScrollableFrame(left_pane, fg_color="transparent")
        self.class_scroll.pack(fill="both", expand=True, padx=6, pady=6)

        # Right Bytecode/Text Box
        right_pane = ctk.CTkFrame(body, fg_color=THEME["panel_bg"], corner_radius=10)
        right_pane.pack(side="right", fill="both", expand=True)

        self.view_title = ctk.CTkLabel(
            right_pane,
            text="Select a class to inspect bytecode & constant pool strings",
            font=ctk.CTkFont(family=THEME["font_family"], size=12, weight="bold"),
            text_color=THEME["accent_blue"]
        )
        self.view_title.pack(anchor="w", padx=14, pady=(10, 4))

        self.code_view = ctk.CTkTextbox(
            right_pane,
            fg_color="#080B10",
            text_color=THEME["text_primary"],
            font=ctk.CTkFont(family="Consolas", size=12)
        )
        self.code_view.pack(fill="both", expand=True, padx=10, pady=10)

    def load_jar_contents(self):
        if not self.jar_path.exists():
            return

        try:
            with zipfile.ZipFile(self.jar_path, "r") as z:
                files = z.namelist()
                class_files = [f for f in files if f.endswith((".class", ".json", ".mf", ".toml"))]

                for fname in class_files[:60]:
                    btn = ctk.CTkButton(
                        self.class_scroll,
                        text=Path(fname).name,
                        font=ctk.CTkFont(family="Consolas", size=11),
                        fg_color=THEME["card_bg"],
                        hover_color=THEME["panel_hover"],
                        height=28,
                        anchor="w",
                        command=lambda f=fname: self.inspect_entry(f)
                    )
                    btn.pack(fill="x", pady=2)
        except Exception as e:
            self.code_view.insert("end", f"Failed to read JAR: {str(e)}")

    def inspect_entry(self, entry_name):
        self.view_title.configure(text=f"Viewing: {entry_name}")
        self.code_view.delete("1.0", "end")

        try:
            with zipfile.ZipFile(self.jar_path, "r") as z:
                raw_bytes = z.read(entry_name)
                # If text / json / manifest
                if entry_name.endswith((".json", ".mf", ".toml", ".txt")):
                    text_content = raw_bytes.decode("utf-8", errors="ignore")
                    self.code_view.insert("end", text_content)
                else:
                    # Parse constant pool string tokens from .class binary
                    strings = []
                    for chunk in raw_bytes.split(b"\x00"):
                        if len(chunk) >= 4:
                            try:
                                s = chunk.decode("utf-8")
                                if s.isprintable() and len(s) > 3:
                                    strings.append(s)
                            except Exception:
                                pass

                    output = f"=== CLASS BYTECODE CONSTANT POOL & STRINGS [{entry_name}] ===\n\n"
                    for idx, s in enumerate(strings[:80]):
                        # Highlight combat strings
                        warn = " [!] CHEAT TOKEN" if any(c in s.lower() for c in ["aura", "aim", "reach", "vape", "esp", "drip"]) else ""
                        output += f"[{idx+1:03d}] {s}{warn}\n"

                    self.code_view.insert("end", output)
        except Exception as e:
            self.code_view.insert("end", f"Error decompiling entry: {str(e)}")
