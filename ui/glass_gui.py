import os
import sys
import threading
import time
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox
import webbrowser

import customtkinter as ctk

from core.database import ForensicDB
from core.modrinth_verifier import ModrinthVerifier
from core.jar_analyzer import JarAnalyzer
from core.memory_scanner import ProcessMemoryScanner
from core.system_forensics import SystemForensics
from core.tampering_detector import TamperingDetector
from ui.theme import THEME
from ui.report_generator import ReportGenerator

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class GlassAnalyzerGUI(ctk.CTk):
    """Tournament-grade Glassmorphism Modern Forensic Cheat Detector GUI."""

    def __init__(self, config=None):
        super().__init__()

        self.config = config or {}
        self.db = ForensicDB()
        self.modrinth = ModrinthVerifier(self.db)
        self.jar_analyzer = JarAnalyzer(self.config)
        self.mem_scanner = ProcessMemoryScanner(self.config)
        self.system_forensics = SystemForensics(self.config)
        self.tampering_detector = TamperingDetector(self.config)

        self.scan_results = {
            "highest_risk": "STANDBY",
            "total_mods": 0,
            "flagged_mods": 0,
            "ram_hits": [],
            "forensic_hits": [],
            "tampering_hits": [],
            "mod_detections": [],
            "all_mods": []
        }
        self.is_scanning = False

        self.setup_window()
        self.build_ui()

    def setup_window(self):
        self.title("ANSH9BOSS CHEAT ANALYZER — TOURNAMENT FORENSIC SUITE")
        self.geometry("1100x740")
        self.minsize(980, 640)
        self.configure(fg_color=THEME["bg_dark"])

    def build_ui(self):
        # -------------------------------------------------------------
        # 1. Top Header Glass Bar
        # -------------------------------------------------------------
        self.header_frame = ctk.CTkFrame(
            self, 
            fg_color=THEME["panel_bg"], 
            border_color=THEME["panel_border"], 
            border_width=1, 
            corner_radius=14
        )
        self.header_frame.pack(fill="x", padx=18, pady=(16, 10))

        title_container = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        title_container.pack(side="left", padx=20, pady=12)

        self.title_label = ctk.CTkLabel(
            title_container, 
            text="⚡ ANSH9BOSS CHEAT ANALYZER", 
            font=ctk.CTkFont(family=THEME["font_family"], size=20, weight="bold"),
            text_color=THEME["accent_cyan"]
        )
        self.title_label.pack(anchor="w")

        self.sub_label = ctk.CTkLabel(
            title_container, 
            text="Tournament Grade Anti-Bypass & Process Memory Forensics • v2.0", 
            font=ctk.CTkFont(family=THEME["font_family"], size=12),
            text_color=THEME["text_secondary"]
        )
        self.sub_label.pack(anchor="w")

        # Global Status Badge
        self.status_badge = ctk.CTkLabel(
            self.header_frame, 
            text="SYSTEM READY", 
            font=ctk.CTkFont(family=THEME["font_family"], size=13, weight="bold"),
            fg_color="#1F2A38",
            text_color=THEME["accent_cyan"],
            corner_radius=20,
            padx=18,
            pady=6
        )
        self.status_badge.pack(side="right", padx=20, pady=14)

        # -------------------------------------------------------------
        # 2. Control Toolbar Buttons
        # -------------------------------------------------------------
        self.toolbar_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.toolbar_frame.pack(fill="x", padx=18, pady=(0, 10))

        self.btn_full_scan = ctk.CTkButton(
            self.toolbar_frame,
            text="▶  START FULL AUDIT",
            font=ctk.CTkFont(family=THEME["font_family"], size=13, weight="bold"),
            fg_color=THEME["accent_cyan"],
            text_color="#000000",
            hover_color=THEME["accent_blue"],
            height=38,
            corner_radius=10,
            command=self.start_full_audit_thread
        )
        self.btn_full_scan.pack(side="left", padx=(0, 8))

        self.btn_ram_scan = ctk.CTkButton(
            self.toolbar_frame,
            text="🧠  SCAN RAM ONLY",
            font=ctk.CTkFont(family=THEME["font_family"], size=13, weight="bold"),
            fg_color=THEME["card_bg"],
            border_color=THEME["panel_border"],
            border_width=1,
            text_color=THEME["text_primary"],
            hover_color=THEME["panel_hover"],
            height=38,
            corner_radius=10,
            command=self.start_ram_scan_thread
        )
        self.btn_ram_scan.pack(side="left", padx=8)

        self.btn_custom_folder = ctk.CTkButton(
            self.toolbar_frame,
            text="📁  CHOOSE FOLDER",
            font=ctk.CTkFont(family=THEME["font_family"], size=13),
            fg_color=THEME["card_bg"],
            border_color=THEME["panel_border"],
            border_width=1,
            text_color=THEME["text_primary"],
            hover_color=THEME["panel_hover"],
            height=38,
            corner_radius=10,
            command=self.choose_custom_folder
        )
        self.btn_custom_folder.pack(side="left", padx=8)

        self.btn_export = ctk.CTkButton(
            self.toolbar_frame,
            text="📄  EXPORT REPORT",
            font=ctk.CTkFont(family=THEME["font_family"], size=13, weight="bold"),
            fg_color="#1E283A",
            border_color="#304159",
            border_width=1,
            text_color=THEME["accent_cyan"],
            hover_color=THEME["panel_hover"],
            height=38,
            corner_radius=10,
            command=self.export_report
        )
        self.btn_export.pack(side="right")

        # -------------------------------------------------------------
        # 3. Middle Section: Metrics Cards & Pipeline Progress
        # -------------------------------------------------------------
        self.middle_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.middle_frame.pack(fill="x", padx=18, pady=(0, 10))

        # Metrics Card (Left)
        self.metrics_card = ctk.CTkFrame(
            self.middle_frame,
            fg_color=THEME["panel_bg"],
            border_color=THEME["panel_border"],
            border_width=1,
            corner_radius=14,
            width=360
        )
        self.metrics_card.pack(side="left", fill="both", padx=(0, 8), expand=False)

        ctk.CTkLabel(
            self.metrics_card,
            text="THREAT RADAR OVERVIEW",
            font=ctk.CTkFont(family=THEME["font_family"], size=12, weight="bold"),
            text_color=THEME["text_secondary"]
        ).pack(anchor="w", padx=16, pady=(12, 4))

        self.verdict_label = ctk.CTkLabel(
            self.metrics_card,
            text="READY TO SCAN",
            font=ctk.CTkFont(family=THEME["font_family"], size=22, weight="bold"),
            text_color=THEME["accent_cyan"]
        )
        self.verdict_label.pack(anchor="w", padx=16, pady=(0, 10))

        # Mini stats row
        self.stats_grid = ctk.CTkFrame(self.metrics_card, fg_color="transparent")
        self.stats_grid.pack(fill="x", padx=16, pady=(0, 12))

        self.stat_mods = self.create_metric_pill(self.stats_grid, "MODS SCANNED", "0", 0)
        self.stat_flagged = self.create_metric_pill(self.stats_grid, "FLAGGED THREATS", "0", 1)
        self.stat_ram = self.create_metric_pill(self.stats_grid, "RAM INJECTIONS", "0", 2)
        self.stat_forensics = self.create_metric_pill(self.stats_grid, "USB / FORENSICS", "0", 3)

        # Pipeline Progress Card (Right)
        self.pipeline_card = ctk.CTkFrame(
            self.middle_frame,
            fg_color=THEME["panel_bg"],
            border_color=THEME["panel_border"],
            border_width=1,
            corner_radius=14
        )
        self.pipeline_card.pack(side="right", fill="both", expand=True)

        ctk.CTkLabel(
            self.pipeline_card,
            text="MULTI-PHASE FORENSIC PIPELINE",
            font=ctk.CTkFont(family=THEME["font_family"], size=12, weight="bold"),
            text_color=THEME["text_secondary"]
        ).pack(anchor="w", padx=16, pady=(12, 4))

        self.progress_bar = ctk.CTkProgressBar(
            self.pipeline_card, 
            fg_color="#18202F", 
            progress_color=THEME["accent_cyan"],
            height=8
        )
        self.progress_bar.pack(fill="x", padx=16, pady=(2, 10))
        self.progress_bar.set(0)

        # Pipeline stages indicators
        self.phase_labels = {}
        phases = [
            ("P1", "Phase 1: Modrinth Cloud Hash Verification"),
            ("P2", "Phase 2: Deep Bytecode & Reflection Analysis"),
            ("P3", "Phase 3: Win32 Live Memory & Process Injection Audit"),
            ("P4", "Phase 4: USBSTOR, BAM & Prefetch Forensics"),
            ("P5", "Phase 5: Anti-Self-Destruct & DNS Cache Verification")
        ]

        for code, text in phases:
            row = ctk.CTkFrame(self.pipeline_card, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=2)
            lbl = ctk.CTkLabel(
                row, 
                text=f"○  {text}", 
                font=ctk.CTkFont(family=THEME["font_family"], size=12),
                text_color=THEME["text_muted"]
            )
            lbl.pack(side="left")
            self.phase_labels[code] = lbl

        # -------------------------------------------------------------
        # 4. Tabbed Evidence & Results Dashboard (Bottom)
        # -------------------------------------------------------------
        self.tabview = ctk.CTkTabview(
            self,
            fg_color=THEME["panel_bg"],
            segmented_button_fg_color=THEME["card_bg"],
            segmented_button_selected_color=THEME["accent_blue"],
            segmented_button_selected_hover_color=THEME["accent_cyan"],
            border_color=THEME["panel_border"],
            border_width=1,
            corner_radius=14
        )
        self.tabview.pack(fill="both", expand=True, padx=18, pady=(0, 16))

        self.tab_threats = self.tabview.add("🚨 Flagged Threats & Evidence")
        self.tab_mods = self.tabview.add("📦 Scanned Mods")
        self.tab_forensics = self.tabview.add("🛡️ System & USB Forensics")
        self.tab_log = self.tabview.add("📜 Cyber Console Log")

        # Setup scrollable logs in tabs
        self.threats_scroll = ctk.CTkScrollableFrame(self.tab_threats, fg_color="transparent")
        self.threats_scroll.pack(fill="both", expand=True, padx=8, pady=8)

        self.mods_scroll = ctk.CTkScrollableFrame(self.tab_mods, fg_color="transparent")
        self.mods_scroll.pack(fill="both", expand=True, padx=8, pady=8)

        self.forensics_scroll = ctk.CTkScrollableFrame(self.tab_forensics, fg_color="transparent")
        self.forensics_scroll.pack(fill="both", expand=True, padx=8, pady=8)

        self.console_box = ctk.CTkTextbox(
            self.tab_log,
            fg_color="#0A0D13",
            text_color=THEME["accent_cyan"],
            font=ctk.CTkFont(family="Consolas", size=12)
        )
        self.console_box.pack(fill="both", expand=True, padx=8, pady=8)
        self.log_to_console("ANSH9BOSS Cheat Analyzer v2.0 initialized. Ready for tournament screenshare audit.")

    def create_metric_pill(self, parent, label, value, col):
        frame = ctk.CTkFrame(parent, fg_color=THEME["card_bg"], corner_radius=8, height=52)
        frame.grid(row=col // 2, column=col % 2, padx=4, pady=4, sticky="nsew")
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_columnconfigure(1, weight=1)

        val_lbl = ctk.CTkLabel(
            frame, 
            text=value, 
            font=ctk.CTkFont(family=THEME["font_family"], size=16, weight="bold"),
            text_color=THEME["text_primary"]
        )
        val_lbl.pack(pady=(4, 0))

        title_lbl = ctk.CTkLabel(
            frame, 
            text=label, 
            font=ctk.CTkFont(family=THEME["font_family"], size=10),
            text_color=THEME["text_secondary"]
        )
        title_lbl.pack(pady=(0, 4))
        return val_lbl

    def log_to_console(self, text):
        timestamp = time.strftime("%H:%M:%S")
        self.console_box.insert("end", f"[{timestamp}] {text}\n")
        self.console_box.see("end")

    def update_phase(self, code, status, note=""):
        symbols = {
            "RUNNING": ("⏳", THEME["warning_yellow"]),
            "CLEAN": ("✓", THEME["success_green"]),
            "ALERT": ("⚠️", THEME["danger_red"]),
            "WAITING": ("○", THEME["text_muted"])
        }
        sym, color = symbols.get(status, ("○", THEME["text_muted"]))
        lbl = self.phase_labels.get(code)
        if lbl:
            curr_text = lbl.cget("text")
            base_name = curr_text.split(":")[-1].strip()
            lbl.configure(text=f"{sym}  Phase {code[-1]}: {base_name} {note}", text_color=color)

    def choose_custom_folder(self):
        folder = filedialog.askdirectory(title="Select Minecraft Mods Folder")
        if folder:
            self.log_to_console(f"Custom folder selected: {folder}")
            self.start_full_audit_thread(custom_path=folder)

    def start_full_audit_thread(self, custom_path=None):
        if self.is_scanning:
            return
        self.is_scanning = True
        self.btn_full_scan.configure(state="disabled")
        self.status_badge.configure(text="AUDITING...", fg_color="#332A15", text_color=THEME["warning_yellow"])
        threading.Thread(target=self.run_full_audit, args=(custom_path,), daemon=True).start()

    def start_ram_scan_thread(self):
        if self.is_scanning:
            return
        self.is_scanning = True
        self.btn_ram_scan.configure(state="disabled")
        self.status_badge.configure(text="SCANNING RAM...", fg_color="#332A15", text_color=THEME["warning_yellow"])
        threading.Thread(target=self.run_ram_only_audit, daemon=True).start()

    def run_ram_only_audit(self):
        self.log_to_console("Initiating Win32 live RAM memory scan on active Minecraft processes...")
        self.update_phase("P3", "RUNNING")
        self.progress_bar.set(0.5)

        ram_results = self.mem_scanner.run_full_memory_audit()
        detections = ram_results.get("detections", [])

        self.scan_results["ram_hits"] = detections
        self.stat_ram.configure(text=str(len(detections)))

        if detections:
            self.update_phase("P3", "ALERT", f"({len(detections)} Threats)")
            self.log_to_console(f"CRITICAL: Found {len(detections)} live RAM injection threats!")
        else:
            self.update_phase("P3", "CLEAN", "(No Injections)")
            self.log_to_console("Win32 memory scan complete. No live JVM process hooks found.")

        self.progress_bar.set(1.0)
        self.refresh_results_ui()
        self.is_scanning = False
        self.btn_ram_scan.configure(state="normal")

    def run_full_audit(self, custom_path=None):
        self.log_to_console("Starting Complete Tournament Forensic Audit...")
        self.progress_bar.set(0.05)

        # Reset states
        for code in ["P1", "P2", "P3", "P4", "P5"]:
            self.update_phase(code, "WAITING")

        # Discover mod files
        mod_files = []
        if custom_path:
            mod_files = list(Path(custom_path).rglob("*.jar"))
        else:
            # Auto-detect Minecraft paths
            appdata = os.environ.get("APPDATA")
            if appdata:
                default_mc = Path(appdata) / ".minecraft/mods"
                if default_mc.exists():
                    mod_files.extend(list(default_mc.rglob("*.jar")))

        # Deduplicate
        mod_files = list(set([p.resolve() for p in mod_files if p.is_file()]))
        self.scan_results["total_mods"] = len(mod_files)
        self.stat_mods.configure(text=str(len(mod_files)))
        self.log_to_console(f"Discovered {len(mod_files)} mod file(s) across launcher directories.")

        # -------------------------------------------------------------
        # Phase 1 & 2: Modrinth Verification & Bytecode Analysis
        # -------------------------------------------------------------
        self.update_phase("P1", "RUNNING")
        self.update_phase("P2", "RUNNING")
        self.progress_bar.set(0.2)

        mod_detections = []
        all_mods_info = []

        for idx, mod in enumerate(mod_files):
            # Phase 1: Modrinth check
            is_clean, mod_info = self.modrinth.verify_mod(mod)
            all_mods_info.append({
                "file": mod.name,
                "path": str(mod),
                "modrinth": mod_info,
                "verified": is_clean
            })

            # Phase 2: Static Bytecode Analysis
            if not is_clean:
                jar_res = self.jar_analyzer.analyze_jar(mod)
                if jar_res["risk_level"] != "CLEAN":
                    mod_detections.append(jar_res)
                    self.log_to_console(f"FLAGGED: {mod.name} -> {jar_res['detection_layer']}")

            self.progress_bar.set(0.2 + (0.3 * ((idx + 1) / max(len(mod_files), 1))))

        self.scan_results["mod_detections"] = mod_detections
        self.scan_results["all_mods"] = all_mods_info
        self.stat_flagged.configure(text=str(len(mod_detections)))

        self.update_phase("P1", "CLEAN" if not mod_detections else "ALERT")
        self.update_phase("P2", "CLEAN" if not mod_detections else "ALERT")

        # -------------------------------------------------------------
        # Phase 3: Win32 Live Memory Audit
        # -------------------------------------------------------------
        self.update_phase("P3", "RUNNING")
        self.progress_bar.set(0.6)
        self.log_to_console("Phase 3: Auditing active JVM processes and committed memory pages...")
        ram_res = self.mem_scanner.run_full_memory_audit()
        ram_hits = ram_res.get("detections", [])
        self.scan_results["ram_hits"] = ram_hits
        self.stat_ram.configure(text=str(len(ram_hits)))

        if ram_hits:
            self.update_phase("P3", "ALERT", f"({len(ram_hits)} Hits)")
        else:
            self.update_phase("P3", "CLEAN")

        # -------------------------------------------------------------
        # Phase 4: USB & System Forensics
        # -------------------------------------------------------------
        self.update_phase("P4", "RUNNING")
        self.progress_bar.set(0.75)
        self.log_to_console("Phase 4: Inspecting USBSTOR registry, BAM activity, and Windows Prefetch...")
        sys_res = self.system_forensics.run_full_forensics_audit()
        forensic_hits = sys_res.get("all_threats", [])
        self.scan_results["forensic_hits"] = forensic_hits
        self.stat_forensics.configure(text=str(len(forensic_hits)))

        if forensic_hits:
            self.update_phase("P4", "ALERT", f"({len(forensic_hits)} Traces)")
        else:
            self.update_phase("P4", "CLEAN")

        # -------------------------------------------------------------
        # Phase 5: Anti-Self-Destruct & DNS Cache
        # -------------------------------------------------------------
        self.update_phase("P5", "RUNNING")
        self.progress_bar.set(0.9)
        self.log_to_console("Phase 5: Checking for Self-Destruct actions, Event Log wipes, and DNS cache...")
        tamper_hits = self.tampering_detector.run_tampering_audit()
        self.scan_results["tampering_hits"] = tamper_hits

        if tamper_hits:
            self.update_phase("P5", "ALERT", f"({len(tamper_hits)} Traces)")
        else:
            self.update_phase("P5", "CLEAN")

        # -------------------------------------------------------------
        # Calculate Final Verdict
        # -------------------------------------------------------------
        self.progress_bar.set(1.0)
        total_threats = len(mod_detections) + len(ram_hits) + len(forensic_hits) + len(tamper_hits)

        if len(ram_hits) > 0 or any(d.get("risk_level") == "DANGEROUS" for d in mod_detections):
            highest_risk = "DANGEROUS"
        elif total_threats > 0:
            highest_risk = "SUSPICIOUS"
        else:
            highest_risk = "CLEAN"

        self.scan_results["highest_risk"] = highest_risk

        # Save to database
        self.db.save_scan(
            total_files=len(mod_files),
            flagged_files=len(mod_detections),
            highest_risk=highest_risk,
            platform="Windows",
            detections=mod_detections,
            ram_threats=len(ram_hits),
            forensic_threats=len(forensic_hits) + len(tamper_hits)
        )

        self.log_to_console(f"Audit Complete! Final System Verdict: {highest_risk}")
        self.refresh_results_ui()
        self.is_scanning = False
        self.btn_full_scan.configure(state="normal")

    def refresh_results_ui(self):
        # Update verdict badge
        highest_risk = self.scan_results.get("highest_risk", "CLEAN")
        if highest_risk == "CLEAN":
            self.verdict_label.configure(text="CLEAN (NO CHEATS)", text_color=THEME["success_green"])
            self.status_badge.configure(text="VERIFIED CLEAN", fg_color="#103822", text_color=THEME["success_green"])
        elif highest_risk == "SUSPICIOUS":
            self.verdict_label.configure(text="SUSPICIOUS TRACES", text_color=THEME["warning_yellow"])
            self.status_badge.configure(text="FLAGGED SUSPICIOUS", fg_color="#383210", text_color=THEME["warning_yellow"])
        else:
            self.verdict_label.configure(text="CRITICAL THREATS", text_color=THEME["danger_red"])
            self.status_badge.configure(text="CRITICAL INJECTIONS", fg_color="#381016", text_color=THEME["danger_red"])

        # Populate Threats Tab
        for widget in self.threats_scroll.winfo_children():
            widget.destroy()

        all_threats = []
        for r in self.scan_results.get("ram_hits", []):
            all_threats.append(("RAM INJECTION", r.get("detail", ""), THEME["danger_red"]))
        for m in self.scan_results.get("mod_detections", []):
            details = " | ".join(m.get("matched_details", [])) if isinstance(m.get("matched_details"), list) else m.get("matched_details")
            all_threats.append((f"MOD: {m.get('file_name')}", details, THEME["danger_red"] if m.get("risk_level") == "DANGEROUS" else THEME["warning_yellow"]))
        for s in self.scan_results.get("forensic_hits", []) + self.scan_results.get("tampering_hits", []):
            all_threats.append((s.get("type", "FORENSIC"), s.get("detail", ""), THEME["warning_yellow"]))

        if not all_threats:
            lbl = ctk.CTkLabel(
                self.threats_scroll,
                text="✓ No cheat threats, injected DLLs, or self-destruct traces found.",
                font=ctk.CTkFont(family=THEME["font_family"], size=13),
                text_color=THEME["success_green"]
            )
            lbl.pack(pady=20)
        else:
            for title, desc, color in all_threats:
                card = ctk.CTkFrame(self.threats_scroll, fg_color=THEME["card_bg"], border_color=color, border_width=1, corner_radius=10)
                card.pack(fill="x", pady=4, padx=4)
                ctk.CTkLabel(card, text=title, font=ctk.CTkFont(family=THEME["font_family"], size=13, weight="bold"), text_color=color).pack(anchor="w", padx=12, pady=(8, 2))
                ctk.CTkLabel(card, text=desc, font=ctk.CTkFont(family=THEME["font_family"], size=12), text_color=THEME["text_primary"], wraplength=950, justify="left").pack(anchor="w", padx=12, pady=(0, 8))

        # Populate Scanned Mods Tab
        for widget in self.mods_scroll.winfo_children():
            widget.destroy()

        for mod in self.scan_results.get("all_mods", []):
            row = ctk.CTkFrame(self.mods_scroll, fg_color=THEME["card_bg"], corner_radius=8)
            row.pack(fill="x", pady=2, padx=4)
            status_text = "MODRINTH VERIFIED" if mod["verified"] else "UNVERIFIED"
            status_color = THEME["success_green"] if mod["verified"] else THEME["text_secondary"]

            ctk.CTkLabel(row, text=mod["file"], font=ctk.CTkFont(family=THEME["font_family"], size=12, weight="bold"), text_color=THEME["text_primary"]).pack(side="left", padx=12, pady=6)
            ctk.CTkLabel(row, text=status_text, font=ctk.CTkFont(family=THEME["font_family"], size=11, weight="bold"), text_color=status_color).pack(side="right", padx=12)

    def export_report(self):
        output_file = ReportGenerator.export_html(self.scan_results)
        self.log_to_console(f"Forensic Report generated: {output_file}")
        abs_path = Path(output_file).resolve().as_uri()
        webbrowser.open(abs_path)
        messagebox.showinfo("Report Exported", f"Forensic Screenshare Report saved and opened:\n{output_file}")

def launch_gui(config=None):
    app = GlassAnalyzerGUI(config)
    app.mainloop()
