import os
import sys
import threading
import time
import math
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

class CyberRadarCanvas(tk.Canvas):
    """Futuristic Canvas-based animated cyber radar displaying threat targets in real time."""

    def __init__(self, master, width=170, height=170, **kwargs):
        super().__init__(
            master, 
            width=width, 
            height=height, 
            bg="#0B0E14", 
            highlightthickness=0, 
            **kwargs
        )
        self.w = width
        self.h = height
        self.center_x = width // 2
        self.center_y = height // 2
        self.radius = (min(width, height) // 2) - 10
        self.angle = 0
        self.is_running = False
        self.blips = []
        self.draw_static_grid()

    def draw_static_grid(self):
        self.delete("all")
        # Radar range circles
        for r_factor in [0.33, 0.66, 1.0]:
            r = self.radius * r_factor
            self.create_oval(
                self.center_x - r, self.center_y - r,
                self.center_x + r, self.center_y + r,
                outline="#1C2738", width=1
            )
        # Crosshairs
        self.create_line(self.center_x - self.radius, self.center_y, self.center_x + self.radius, self.center_y, fill="#1C2738", width=1)
        self.create_line(self.center_x, self.center_y - self.radius, self.center_x, self.center_y + self.radius, fill="#1C2738", width=1)

    def add_blip(self, is_threat=False):
        dist = (0.2 + 0.7 * (time.time() % 1.0)) * self.radius
        theta = (time.time() * 3.5) % (2 * math.pi)
        bx = self.center_x + dist * math.cos(theta)
        by = self.center_y + dist * math.sin(theta)
        color = THEME["danger_red"] if is_threat else THEME["accent_cyan"]
        self.blips.append({"x": bx, "y": by, "color": color, "alpha": 1.0})

    def start_animation(self):
        if not self.is_running:
            self.is_running = True
            self.animate()

    def stop_animation(self):
        self.is_running = False
        self.draw_static_grid()

    def animate(self):
        if not self.is_running:
            return
        self.draw_static_grid()

        # Draw sweeping beam
        rad = math.radians(self.angle)
        end_x = self.center_x + self.radius * math.cos(rad)
        end_y = self.center_y + self.radius * math.sin(rad)
        self.create_line(self.center_x, self.center_y, end_x, end_y, fill=THEME["accent_cyan"], width=2)

        # Draw blips
        remaining_blips = []
        for b in self.blips:
            r = 3
            self.create_oval(b["x"] - r, b["y"] - r, b["x"] + r, b["y"] + r, fill=b["color"], outline="")
            b["alpha"] -= 0.05
            if b["alpha"] > 0:
                remaining_blips.append(b)
        self.blips = remaining_blips

        self.angle = (self.angle + 6) % 360
        self.after(30, self.animate)


class GlassAnalyzerGUI(ctk.CTk):
    """Revolutionary Next-Gen Tournament Forensic Cheat Detector Interface."""

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
            "threat_score": 0,
            "total_mods": 0,
            "flagged_mods": 0,
            "ram_hits": [],
            "forensic_hits": [],
            "tampering_hits": [],
            "mod_detections": [],
            "all_mods": []
        }
        self.is_scanning = False
        self.current_filter = "ALL"

        self.setup_window()
        self.build_ui()

    def setup_window(self):
        self.title("⚡ ANSH9BOSS CHEAT ANALYZER — NEXT-GEN TOURNAMENT FORENSIC SUITE")
        self.geometry("1160x780")
        self.minsize(1020, 680)
        self.configure(fg_color=THEME["bg_dark"])

    def build_ui(self):
        # =============================================================
        # 1. Top Glass Header & Cyber Controls
        # =============================================================
        self.header_frame = ctk.CTkFrame(
            self, 
            fg_color=THEME["panel_bg"], 
            border_color=THEME["panel_border"], 
            border_width=1, 
            corner_radius=14
        )
        self.header_frame.pack(fill="x", padx=16, pady=(14, 8))

        title_container = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        title_container.pack(side="left", padx=18, pady=10)

        self.title_label = ctk.CTkLabel(
            title_container, 
            text="⚡ ANSH9BOSS CHEAT ANALYZER v2.0", 
            font=ctk.CTkFont(family=THEME["font_family"], size=21, weight="bold"),
            text_color=THEME["accent_cyan"]
        )
        self.title_label.pack(anchor="w")

        self.sub_label = ctk.CTkLabel(
            title_container, 
            text="AI-Assisted Zero-False-Positive Bytecode Inspector & Process Memory Forensics", 
            font=ctk.CTkFont(family=THEME["font_family"], size=12),
            text_color=THEME["text_secondary"]
        )
        self.sub_label.pack(anchor="w")

        # Top Control Buttons
        btn_box = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        btn_box.pack(side="right", padx=18, pady=10)

        self.btn_full_scan = ctk.CTkButton(
            btn_box,
            text="▶  START FULL AUDIT",
            font=ctk.CTkFont(family=THEME["font_family"], size=13, weight="bold"),
            fg_color=THEME["accent_cyan"],
            text_color="#000000",
            hover_color=THEME["accent_blue"],
            height=36,
            corner_radius=8,
            command=self.start_full_audit_thread
        )
        self.btn_full_scan.pack(side="left", padx=4)

        self.btn_ram_scan = ctk.CTkButton(
            btn_box,
            text="🧠 RAM SCAN",
            font=ctk.CTkFont(family=THEME["font_family"], size=12, weight="bold"),
            fg_color=THEME["card_bg"],
            border_color=THEME["panel_border"],
            border_width=1,
            text_color=THEME["text_primary"],
            hover_color=THEME["panel_hover"],
            height=36,
            corner_radius=8,
            command=self.start_ram_scan_thread
        )
        self.btn_ram_scan.pack(side="left", padx=4)

        self.btn_custom_folder = ctk.CTkButton(
            btn_box,
            text="📁 BROWSE FOLDER",
            font=ctk.CTkFont(family=THEME["font_family"], size=12),
            fg_color=THEME["card_bg"],
            border_color=THEME["panel_border"],
            border_width=1,
            text_color=THEME["text_primary"],
            hover_color=THEME["panel_hover"],
            height=36,
            corner_radius=8,
            command=self.choose_custom_folder
        )
        self.btn_custom_folder.pack(side="left", padx=4)

        self.btn_export = ctk.CTkButton(
            btn_box,
            text="📄 EXPORT DOSSIER",
            font=ctk.CTkFont(family=THEME["font_family"], size=12, weight="bold"),
            fg_color="#1E283A",
            border_color="#304159",
            border_width=1,
            text_color=THEME["accent_cyan"],
            hover_color=THEME["panel_hover"],
            height=36,
            corner_radius=8,
            command=self.export_report
        )
        self.btn_export.pack(side="left", padx=4)

        # =============================================================
        # 2. Middle Section: Animated Radar HUD & Multi-Phase Pipeline
        # =============================================================
        self.middle_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.middle_frame.pack(fill="x", padx=16, pady=(0, 8))

        # Left Card: Radar & Threat Verdict
        self.radar_card = ctk.CTkFrame(
            self.middle_frame,
            fg_color=THEME["panel_bg"],
            border_color=THEME["panel_border"],
            border_width=1,
            corner_radius=14,
            width=400
        )
        self.radar_card.pack(side="left", fill="both", padx=(0, 8), expand=False)

        radar_top = ctk.CTkFrame(self.radar_card, fg_color="transparent")
        radar_top.pack(fill="x", padx=14, pady=10)

        # Embedded Radar Canvas
        self.radar = CyberRadarCanvas(radar_top, width=130, height=130)
        self.radar.pack(side="left", padx=(0, 12))

        # Verdict Column
        verdict_col = ctk.CTkFrame(radar_top, fg_color="transparent")
        verdict_col.pack(side="left", fill="both", expand=True)

        ctk.CTkLabel(
            verdict_col,
            text="SYSTEM VERDICT",
            font=ctk.CTkFont(family=THEME["font_family"], size=11, weight="bold"),
            text_color=THEME["text_secondary"]
        ).pack(anchor="w")

        self.verdict_label = ctk.CTkLabel(
            verdict_col,
            text="STANDBY",
            font=ctk.CTkFont(family=THEME["font_family"], size=20, weight="bold"),
            text_color=THEME["accent_cyan"]
        )
        self.verdict_label.pack(anchor="w", pady=(0, 4))

        self.threat_index_label = ctk.CTkLabel(
            verdict_col,
            text="Threat Index: 0%",
            font=ctk.CTkFont(family=THEME["font_family"], size=12, weight="bold"),
            text_color=THEME["success_green"]
        )
        self.threat_index_label.pack(anchor="w")

        # Mini Metrics Pills
        self.stats_grid = ctk.CTkFrame(self.radar_card, fg_color="transparent")
        self.stats_grid.pack(fill="x", padx=14, pady=(0, 10))

        self.stat_mods = self.create_metric_pill(self.stats_grid, "TOTAL MODS", "0", 0)
        self.stat_flagged = self.create_metric_pill(self.stats_grid, "FLAGGED HACKS", "0", 1)
        self.stat_ram = self.create_metric_pill(self.stats_grid, "RAM HOOKS", "0", 2)
        self.stat_forensics = self.create_metric_pill(self.stats_grid, "FORENSIC TRACES", "0", 3)

        # Right Card: Multi-Phase Forensic Pipeline
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
            text="MULTI-PHASE FORENSIC INVESTIGATION PIPELINE",
            font=ctk.CTkFont(family=THEME["font_family"], size=12, weight="bold"),
            text_color=THEME["text_secondary"]
        ).pack(anchor="w", padx=16, pady=(10, 4))

        self.progress_bar = ctk.CTkProgressBar(
            self.pipeline_card, 
            fg_color="#18202F", 
            progress_color=THEME["accent_cyan"],
            height=6
        )
        self.progress_bar.pack(fill="x", padx=16, pady=(2, 8))
        self.progress_bar.set(0)

        self.phase_labels = {}
        phases = [
            ("P1", "Phase 1: Modrinth Cloud SHA-1 Hash Authentication"),
            ("P2", "Phase 2: Context-Aware Bytecode & Packet Heuristic Inspection"),
            ("P3", "Phase 3: Win32 Live Memory & Process Injection Audit"),
            ("P4", "Phase 4: USBSTOR Devices & BAM Execution Log Extraction"),
            ("P5", "Phase 5: Anti-Self-Destruct, Prefetch & DNS Cache Verification")
        ]

        for code, text in phases:
            row = ctk.CTkFrame(self.pipeline_card, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=1)
            lbl = ctk.CTkLabel(
                row, 
                text=f"○  {text}", 
                font=ctk.CTkFont(family=THEME["font_family"], size=12),
                text_color=THEME["text_muted"]
            )
            lbl.pack(side="left")
            self.phase_labels[code] = lbl

        # =============================================================
        # 3. Interactive Mod Explorer & Forensic Evidence Tabs (Bottom)
        # =============================================================
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
        self.tabview.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        self.tab_threats = self.tabview.add("🚨 Flagged Threats & Payloads")
        self.tab_mods = self.tabview.add("📦 Interactive Mod Explorer")
        self.tab_forensics = self.tabview.add("🛡️ USB & Windows Forensics")
        self.tab_log = self.tabview.add("📜 Live Cyber Console")

        # Tab 1: Threats View
        self.threats_scroll = ctk.CTkScrollableFrame(self.tab_threats, fg_color="transparent")
        self.threats_scroll.pack(fill="both", expand=True, padx=6, pady=6)

        # Tab 2: Mod Explorer with Search & Filter
        mod_controls = ctk.CTkFrame(self.tab_mods, fg_color="transparent")
        mod_controls.pack(fill="x", padx=6, pady=(0, 6))

        self.search_entry = ctk.CTkEntry(
            mod_controls,
            placeholder_text="🔍 Search mods by name, package, or hash...",
            font=ctk.CTkFont(family=THEME["font_family"], size=12),
            fg_color=THEME["card_bg"],
            border_color=THEME["panel_border"],
            height=32
        )
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.search_entry.bind("<KeyRelease>", lambda e: self.filter_mods_list())

        self.filter_seg = ctk.CTkSegmentedButton(
            mod_controls,
            values=["ALL", "CLEAN", "FLAGGED"],
            command=self.set_mod_filter,
            height=30
        )
        self.filter_seg.set("ALL")
        self.filter_seg.pack(side="right")

        self.mods_scroll = ctk.CTkScrollableFrame(self.tab_mods, fg_color="transparent")
        self.mods_scroll.pack(fill="both", expand=True, padx=6, pady=6)

        # Tab 3: System Forensics
        self.forensics_scroll = ctk.CTkScrollableFrame(self.tab_forensics, fg_color="transparent")
        self.forensics_scroll.pack(fill="both", expand=True, padx=6, pady=6)

        # Tab 4: Console Log
        self.console_box = ctk.CTkTextbox(
            self.tab_log,
            fg_color="#080B10",
            text_color=THEME["accent_cyan"],
            font=ctk.CTkFont(family="Consolas", size=12)
        )
        self.console_box.pack(fill="both", expand=True, padx=6, pady=6)
        self.log_to_console("ANSH9BOSS Next-Gen Forensic Suite v2.0 initialized. Ready for tournament screenshare audit.")

    def create_metric_pill(self, parent, label, value, col):
        frame = ctk.CTkFrame(parent, fg_color=THEME["card_bg"], corner_radius=8, height=48)
        frame.grid(row=col // 2, column=col % 2, padx=3, pady=3, sticky="nsew")
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_columnconfigure(1, weight=1)

        val_lbl = ctk.CTkLabel(
            frame, 
            text=value, 
            font=ctk.CTkFont(family=THEME["font_family"], size=15, weight="bold"),
            text_color=THEME["text_primary"]
        )
        val_lbl.pack(pady=(3, 0))

        title_lbl = ctk.CTkLabel(
            frame, 
            text=label, 
            font=ctk.CTkFont(family=THEME["font_family"], size=9),
            text_color=THEME["text_secondary"]
        )
        title_lbl.pack(pady=(0, 3))
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

    def set_mod_filter(self, val):
        self.current_filter = val
        self.filter_mods_list()

    def choose_custom_folder(self):
        folder = filedialog.askdirectory(title="Select Minecraft Mods Folder")
        if folder:
            self.log_to_console(f"Custom folder selected: {folder}")
            self.start_full_audit_thread(custom_path=folder)

    def start_full_audit_thread(self, custom_path=None):
        if self.is_scanning:
            return
        self.is_scanning = True
        self.radar.start_animation()
        self.btn_full_scan.configure(state="disabled")
        self.verdict_label.configure(text="AUDITING...", text_color=THEME["warning_yellow"])
        threading.Thread(target=self.run_full_audit, args=(custom_path,), daemon=True).start()

    def start_ram_scan_thread(self):
        if self.is_scanning:
            return
        self.is_scanning = True
        self.radar.start_animation()
        self.btn_ram_scan.configure(state="disabled")
        threading.Thread(target=self.run_ram_only_audit, daemon=True).start()

    def run_ram_only_audit(self):
        self.log_to_console("Initiating deep Win32 RAM inspection on live Minecraft / javaw.exe processes...")
        self.update_phase("P3", "RUNNING")
        self.progress_bar.set(0.5)

        ram_results = self.mem_scanner.run_full_memory_audit()
        detections = ram_results.get("detections", [])

        self.scan_results["ram_hits"] = detections
        self.stat_ram.configure(text=str(len(detections)))

        for _ in detections:
            self.radar.add_blip(is_threat=True)

        if detections:
            self.update_phase("P3", "ALERT", f"({len(detections)} Threats)")
            self.log_to_console(f"CRITICAL THREAT: Found {len(detections)} live RAM injection hooks!")
        else:
            self.update_phase("P3", "CLEAN", "(Clean Memory)")
            self.log_to_console("RAM Audit Complete: No injected DLLs or ghost client signatures found.")

        self.progress_bar.set(1.0)
        self.refresh_results_ui()
        self.is_scanning = False
        self.radar.stop_animation()
        self.btn_ram_scan.configure(state="normal")

    def run_full_audit(self, custom_path=None):
        self.log_to_console("Starting Complete Tournament Forensic Investigation...")
        self.progress_bar.set(0.05)

        for code in ["P1", "P2", "P3", "P4", "P5"]:
            self.update_phase(code, "WAITING")

        mod_files = []
        if custom_path:
            mod_files = list(Path(custom_path).rglob("*.jar"))
        else:
            appdata = os.environ.get("APPDATA")
            if appdata:
                default_mc = Path(appdata) / ".minecraft/mods"
                if default_mc.exists():
                    mod_files.extend(list(default_mc.rglob("*.jar")))

        mod_files = list(set([p.resolve() for p in mod_files if p.is_file()]))
        self.scan_results["total_mods"] = len(mod_files)
        self.stat_mods.configure(text=str(len(mod_files)))
        self.log_to_console(f"Discovered {len(mod_files)} mod file(s) across launcher instances.")

        # Phase 1 & 2: Mod Scanning
        self.update_phase("P1", "RUNNING")
        self.update_phase("P2", "RUNNING")
        self.progress_bar.set(0.2)

        mod_detections = []
        all_mods_info = []
        max_threat_score = 0

        for idx, mod in enumerate(mod_files):
            is_clean, mod_info = self.modrinth.verify_mod(mod)
            jar_res = self.jar_analyzer.analyze_jar(mod)

            if is_clean:
                jar_res["risk_level"] = "CLEAN"
                jar_res["threat_score"] = 0
                jar_res["detection_layer"] = "Modrinth Verified Clean"

            all_mods_info.append({
                "file": mod.name,
                "path": str(mod),
                "verified": is_clean,
                "modrinth": mod_info,
                "jar_res": jar_res,
                "threat_score": jar_res.get("threat_score", 0)
            })

            if jar_res["risk_level"] != "CLEAN":
                mod_detections.append(jar_res)
                max_threat_score = max(max_threat_score, jar_res.get("threat_score", 0))
                self.radar.add_blip(is_threat=True)
                self.log_to_console(f"FLAGGED: {mod.name} [Threat Index: {jar_res['threat_score']}%] -> {jar_res['detection_layer']}")
            else:
                self.radar.add_blip(is_threat=False)

            self.progress_bar.set(0.2 + (0.35 * ((idx + 1) / max(len(mod_files), 1))))

        self.scan_results["mod_detections"] = mod_detections
        self.scan_results["all_mods"] = all_mods_info
        self.stat_flagged.configure(text=str(len(mod_detections)))

        self.update_phase("P1", "CLEAN" if not mod_detections else "ALERT")
        self.update_phase("P2", "CLEAN" if not mod_detections else "ALERT")

        # Phase 3: Live RAM Audit
        self.update_phase("P3", "RUNNING")
        self.progress_bar.set(0.65)
        self.log_to_console("Phase 3: Auditing committed JVM memory pages and non-disk mapped DLLs...")
        ram_res = self.mem_scanner.run_full_memory_audit()
        ram_hits = ram_res.get("detections", [])
        self.scan_results["ram_hits"] = ram_hits
        self.stat_ram.configure(text=str(len(ram_hits)))

        if ram_hits:
            max_threat_score = max(max_threat_score, 100)
            self.update_phase("P3", "ALERT", f"({len(ram_hits)} Hits)")
        else:
            self.update_phase("P3", "CLEAN")

        # Phase 4: USB & System Forensics
        self.update_phase("P4", "RUNNING")
        self.progress_bar.set(0.8)
        self.log_to_console("Phase 4: Scanning USBSTOR registry, BAM execution history, and Prefetch...")
        sys_res = self.system_forensics.run_full_forensics_audit()
        forensic_hits = sys_res.get("all_threats", [])
        self.scan_results["forensic_hits"] = forensic_hits
        self.stat_forensics.configure(text=str(len(forensic_hits)))

        if forensic_hits:
            max_threat_score = max(max_threat_score, 45)
            self.update_phase("P4", "ALERT", f"({len(forensic_hits)} Traces)")
        else:
            self.update_phase("P4", "CLEAN")

        # Phase 5: Anti-Self-Destruct
        self.update_phase("P5", "RUNNING")
        self.progress_bar.set(0.95)
        self.log_to_console("Phase 5: Verifying Prefetch integrity, Event Logs, and DNS Cache...")
        tamper_hits = self.tampering_detector.run_tampering_audit()
        self.scan_results["tampering_hits"] = tamper_hits

        if tamper_hits:
            max_threat_score = max(max_threat_score, 75)
            self.update_phase("P5", "ALERT", f"({len(tamper_hits)} Traces)")
        else:
            self.update_phase("P5", "CLEAN")

        # Final Verdict Calculation
        self.progress_bar.set(1.0)
        self.scan_results["threat_score"] = max_threat_score

        if max_threat_score >= 65:
            highest_risk = "DANGEROUS"
        elif max_threat_score >= 30:
            highest_risk = "SUSPICIOUS"
        else:
            highest_risk = "CLEAN"

        self.scan_results["highest_risk"] = highest_risk

        self.db.save_scan(
            total_files=len(mod_files),
            flagged_files=len(mod_detections),
            highest_risk=highest_risk,
            platform="Windows",
            detections=mod_detections,
            ram_threats=len(ram_hits),
            forensic_threats=len(forensic_hits) + len(tamper_hits)
        )

        self.log_to_console(f"Audit Complete! Overall Threat Index: {max_threat_score}% | Verdict: {highest_risk}")
        self.refresh_results_ui()
        self.is_scanning = False
        self.radar.stop_animation()
        self.btn_full_scan.configure(state="normal")

    def refresh_results_ui(self):
        highest_risk = self.scan_results.get("highest_risk", "CLEAN")
        threat_score = self.scan_results.get("threat_score", 0)

        if highest_risk == "CLEAN":
            self.verdict_label.configure(text="VERIFIED CLEAN", text_color=THEME["success_green"])
            self.threat_index_label.configure(text=f"Threat Index: {threat_score}% (Safe)", text_color=THEME["success_green"])
        elif highest_risk == "SUSPICIOUS":
            self.verdict_label.configure(text="SUSPICIOUS TRACES", text_color=THEME["warning_yellow"])
            self.threat_index_label.configure(text=f"Threat Index: {threat_score}% (Flagged)", text_color=THEME["warning_yellow"])
        else:
            self.verdict_label.configure(text="CRITICAL THREAT", text_color=THEME["danger_red"])
            self.threat_index_label.configure(text=f"Threat Index: {threat_score}% (Punish/Ban)", text_color=THEME["danger_red"])

        # Threats Tab
        for widget in self.threats_scroll.winfo_children():
            widget.destroy()

        all_threats = []
        for r in self.scan_results.get("ram_hits", []):
            all_threats.append(("RAM PROCESS HOOK", r.get("detail", ""), 100, THEME["danger_red"]))
        for m in self.scan_results.get("mod_detections", []):
            details = " | ".join(m.get("matched_details", [])) if isinstance(m.get("matched_details"), list) else m.get("matched_details")
            score = m.get("threat_score", 50)
            color = THEME["danger_red"] if score >= 65 else THEME["warning_yellow"]
            all_threats.append((f"HACK MOD: {m.get('file_name')} ({score}% Threat)", details, score, color))
        for s in self.scan_results.get("forensic_hits", []) + self.scan_results.get("tampering_hits", []):
            all_threats.append((s.get("type", "FORENSIC TRACE"), s.get("detail", ""), 45, THEME["warning_yellow"]))

        if not all_threats:
            lbl = ctk.CTkLabel(
                self.threats_scroll,
                text="✓ No combat hacks, memory hooks, or self-destruct routines identified.",
                font=ctk.CTkFont(family=THEME["font_family"], size=13),
                text_color=THEME["success_green"]
            )
            lbl.pack(pady=20)
        else:
            for title, desc, score, color in all_threats:
                card = ctk.CTkFrame(self.threats_scroll, fg_color=THEME["card_bg"], border_color=color, border_width=1, corner_radius=10)
                card.pack(fill="x", pady=4, padx=4)
                ctk.CTkLabel(card, text=title, font=ctk.CTkFont(family=THEME["font_family"], size=13, weight="bold"), text_color=color).pack(anchor="w", padx=12, pady=(8, 2))
                ctk.CTkLabel(card, text=desc, font=ctk.CTkFont(family=THEME["font_family"], size=12), text_color=THEME["text_primary"], wraplength=980, justify="left").pack(anchor="w", padx=12, pady=(0, 8))

        # Mod Explorer Tab
        self.filter_mods_list()

    def filter_mods_list(self):
        query = self.search_entry.get().strip().lower()
        for widget in self.mods_scroll.winfo_children():
            widget.destroy()

        for mod in self.scan_results.get("all_mods", []):
            fname = mod["file"].lower()
            jar_res = mod.get("jar_res", {})
            risk = jar_res.get("risk_level", "CLEAN")

            # Search filter
            if query and query not in fname and query not in mod.get("path", "").lower():
                continue

            # Segmented button filter
            if self.current_filter == "CLEAN" and risk != "CLEAN":
                continue
            if self.current_filter == "FLAGGED" and risk == "CLEAN":
                continue

            score = jar_res.get("threat_score", 0)
            status_color = THEME["success_green"] if risk == "CLEAN" else (THEME["warning_yellow"] if risk == "SUSPICIOUS" else THEME["danger_red"])
            status_text = f"THREAT: {score}%" if risk != "CLEAN" else ("MODRINTH AUTHENTIC" if mod["verified"] else "SAFE")

            row = ctk.CTkFrame(self.mods_scroll, fg_color=THEME["card_bg"], corner_radius=8)
            row.pack(fill="x", pady=2, padx=4)

            ctk.CTkLabel(row, text=mod["file"], font=ctk.CTkFont(family=THEME["font_family"], size=12, weight="bold"), text_color=THEME["text_primary"]).pack(side="left", padx=12, pady=6)
            ctk.CTkLabel(row, text=status_text, font=ctk.CTkFont(family=THEME["font_family"], size=11, weight="bold"), text_color=status_color).pack(side="right", padx=12)

    def export_report(self):
        output_file = ReportGenerator.export_html(self.scan_results)
        self.log_to_console(f"Forensic Dossier saved: {output_file}")
        abs_path = Path(output_file).resolve().as_uri()
        webbrowser.open(abs_path)
        messagebox.showinfo("Dossier Exported", f"Forensic Screenshare Dossier saved and opened in browser:\n{output_file}")

def launch_gui(config=None):
    app = GlassAnalyzerGUI(config)
    app.mainloop()
