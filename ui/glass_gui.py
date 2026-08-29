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

# Core Engines
from core.database import ForensicDB
from core.modrinth_verifier import ModrinthVerifier
from core.jar_analyzer import JarAnalyzer
from core.memory_scanner import ProcessMemoryScanner
from core.system_forensics import SystemForensics
from core.tampering_detector import TamperingDetector

# 20-Feature Suite Integrations
from core.memory.jvm_dumper import JVMTIDumper
from core.memory.vad_scanner import VADScanner
from core.memory.click_analyzer import ClickCurveAnalyzer
from core.memory.aim_analyzer import AimTrajectoryAnalyzer
from core.memory.overlay_hunter import OverlayHookHunter
from core.forensics.usn_journal import USNJournalParser
from core.forensics.pca_forensics import PCAForensics
from core.forensics.srum_forensics import SRUMForensics
from core.forensics.userassist_shellbags import UserAssistExplorer
from core.forensics.vss_recovery import VSSArtifactScanner
from core.integrations.discord_alerts import DiscordStaffAlerts
from core.integrations.audit_certificate import AuditCertificateGenerator
from core.integrations.rcon_bridge import RCONBridge
from core.integrations.threat_cloud import ThreatCloudSync
from core.integrations.freeze_mode import TournamentFreezeMonitor
from core.audio.cyber_audio import CyberVoiceAlerts
from core.analysis.parent_tracer import ParentProcessTracer
from core.analysis.vanilla_integrity import VanillaIntegrityChecker
from core.analysis.launcher_detector import MinecraftLauncherDetector

# UI Modals & Design
from ui.theme import THEME
from ui.report_generator import ReportGenerator
from ui.decompiler_viewer import DecompilerViewerModal
from ui.hex_viewer import HexViewerModal

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class CyberRadarCanvas(tk.Canvas):
    """Futuristic Canvas-based animated cyber radar displaying threat targets in real time."""

    def __init__(self, master, width=150, height=150, **kwargs):
        super().__init__(master, width=width, height=height, bg="#0B0E14", highlightthickness=0, **kwargs)
        self.w = width
        self.h = height
        self.center_x = width // 2
        self.center_y = height // 2
        self.radius = (min(width, height) // 2) - 8
        self.angle = 0
        self.is_running = False
        self.blips = []
        self.draw_static_grid()

    def draw_static_grid(self):
        try:
            self.delete("all")
            for r_factor in [0.33, 0.66, 1.0]:
                r = self.radius * r_factor
                self.create_oval(self.center_x - r, self.center_y - r, self.center_x + r, self.center_y + r, outline="#1C2738", width=1)
            self.create_line(self.center_x - self.radius, self.center_y, self.center_x + self.radius, self.center_y, fill="#1C2738", width=1)
            self.create_line(self.center_x, self.center_y - self.radius, self.center_x, self.center_y + self.radius, fill="#1C2738", width=1)
        except Exception:
            pass

    def add_blip(self, is_threat=False):
        def _do():
            try:
                dist = (0.2 + 0.7 * (time.time() % 1.0)) * self.radius
                theta = (time.time() * 3.5) % (2 * math.pi)
                bx = self.center_x + dist * math.cos(theta)
                by = self.center_y + dist * math.sin(theta)
                color = THEME["danger_red"] if is_threat else THEME["accent_cyan"]
                self.blips.append({"x": bx, "y": by, "color": color, "alpha": 1.0})
            except Exception:
                pass
        self.after(0, _do)

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
        try:
            self.draw_static_grid()
            rad = math.radians(self.angle)
            end_x = self.center_x + self.radius * math.cos(rad)
            end_y = self.center_y + self.radius * math.sin(rad)
            self.create_line(self.center_x, self.center_y, end_x, end_y, fill=THEME["accent_cyan"], width=2)

            remaining = []
            for b in self.blips:
                self.create_oval(b["x"] - 3, b["y"] - 3, b["x"] + 3, b["y"] + 3, fill=b["color"], outline="")
                b["alpha"] -= 0.05
                if b["alpha"] > 0:
                    remaining.append(b)
            self.blips = remaining

            self.angle = (self.angle + 6) % 360
            self.after(30, self.animate)
        except Exception:
            pass


class GlassAnalyzerGUI(ctk.CTk):
    """Tournament-Grade Glassmorphism Forensic Cheat Detector Suite (v3.0)."""

    def __init__(self, config=None):
        super().__init__()

        self.config = config or {}
        self.db = ForensicDB()
        self.modrinth = ModrinthVerifier(self.db)
        self.jar_analyzer = JarAnalyzer(self.config)
        self.mem_scanner = ProcessMemoryScanner(self.config)
        self.system_forensics = SystemForensics(self.config)
        self.tampering_detector = TamperingDetector(self.config)

        # Advanced 20-Feature Forensic Engines
        self.jvm_dumper = JVMTIDumper(self.config)
        self.vad_scanner = VADScanner()
        self.overlay_hunter = OverlayHookHunter()
        self.usn_parser = USNJournalParser()
        self.pca_forensics = PCAForensics()
        self.srum_forensics = SRUMForensics()
        self.userassist = UserAssistExplorer()
        self.vss_recovery = VSSArtifactScanner()
        self.discord_alerts = DiscordStaffAlerts()
        self.threat_cloud = ThreatCloudSync(self.config)
        self.audio_alerts = CyberVoiceAlerts(enabled=True)
        self.parent_tracer = ParentProcessTracer()
        self.vanilla_integrity = VanillaIntegrityChecker()
        self.launcher_detector = MinecraftLauncherDetector()
        self.freeze_monitor = TournamentFreezeMonitor(on_violation_callback=self.on_freeze_violation)

        self.selected_target_path = None
        self.detected_launchers = []

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
        self.player_ign = "Player"

        self.setup_window()
        self.build_ui()

        # Background Threat Cloud Sync
        threading.Thread(target=self.threat_cloud.sync_signatures, daemon=True).start()

    def safe_ui(self, func, *args, **kwargs):
        """Dispatches a function safely onto the Tkinter main thread."""
        try:
            self.after(0, lambda: func(*args, **kwargs))
        except Exception:
            pass

    def setup_window(self):
        self.title("⚡ ANSH9BOSS CHEAT ANALYZER — TOURNAMENT ULTRA FORENSIC SUITE v3.0")
        self.geometry("1180x800")
        self.minsize(1040, 700)
        self.configure(fg_color=THEME["bg_dark"])

    def build_ui(self):
        # 1. Top Glass Header
        self.header_frame = ctk.CTkFrame(self, fg_color=THEME["panel_bg"], border_color=THEME["panel_border"], border_width=1, corner_radius=14)
        self.header_frame.pack(fill="x", padx=16, pady=(12, 6))

        title_box = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        title_box.pack(side="left", padx=16, pady=8)

        self.title_label = ctk.CTkLabel(
            title_box, 
            text="⚡ ANSH9BOSS CHEAT ANALYZER v3.0", 
            font=ctk.CTkFont(family=THEME["font_family"], size=21, weight="bold"),
            text_color=THEME["accent_cyan"]
        )
        self.title_label.pack(anchor="w")

        self.sub_label = ctk.CTkLabel(
            title_box, 
            text="Tournament Ultra Forensic Suite • VAD Memory Tree • USN Journal • In-Memory Class Dumper", 
            font=ctk.CTkFont(family=THEME["font_family"], size=12),
            text_color=THEME["text_secondary"]
        )
        self.sub_label.pack(anchor="w")

        # Control Buttons
        btn_box = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        btn_box.pack(side="right", padx=16, pady=8)

        self.btn_full_scan = ctk.CTkButton(
            btn_box, text="▶  FULL AUDIT", font=ctk.CTkFont(family=THEME["font_family"], size=12, weight="bold"),
            fg_color=THEME["accent_cyan"], text_color="#000000", hover_color=THEME["accent_blue"], height=34, corner_radius=8,
            command=self.start_full_audit_thread
        )
        self.btn_full_scan.pack(side="left", padx=3)

        self.btn_ram_scan = ctk.CTkButton(
            btn_box, text="🧠 RAM SCAN", font=ctk.CTkFont(family=THEME["font_family"], size=12, weight="bold"),
            fg_color=THEME["card_bg"], border_color=THEME["panel_border"], border_width=1, text_color=THEME["text_primary"],
            hover_color=THEME["panel_hover"], height=34, corner_radius=8, command=self.start_ram_scan_thread
        )
        self.btn_ram_scan.pack(side="left", padx=3)

        self.btn_hex = ctk.CTkButton(
            btn_box, text="🧬 HEX RAM", font=ctk.CTkFont(family=THEME["font_family"], size=12),
            fg_color=THEME["card_bg"], border_color=THEME["panel_border"], border_width=1, text_color=THEME["text_primary"],
            hover_color=THEME["panel_hover"], height=34, corner_radius=8, command=self.open_hex_viewer
        )
        self.btn_hex.pack(side="left", padx=3)

        self.btn_rcon = ctk.CTkButton(
            btn_box, text="🔨 RCON BAN", font=ctk.CTkFont(family=THEME["font_family"], size=12, weight="bold"),
            fg_color="#381016", border_color=THEME["danger_red"], border_width=1, text_color=THEME["danger_red"],
            hover_color="#521720", height=34, corner_radius=8, command=self.trigger_rcon_ban
        )
        self.btn_rcon.pack(side="left", padx=3)

        self.btn_export = ctk.CTkButton(
            btn_box, text="📄 DOSSIER", font=ctk.CTkFont(family=THEME["font_family"], size=12, weight="bold"),
            fg_color="#1E283A", border_color="#304159", border_width=1, text_color=THEME["accent_cyan"],
            hover_color=THEME["panel_hover"], height=34, corner_radius=8, command=self.export_report
        )
        self.btn_export.pack(side="left", padx=3)

        # 1.5 Target Folder / Launcher Profile Selector Bar
        self.target_bar = ctk.CTkFrame(self, fg_color=THEME["panel_bg"], border_color=THEME["panel_border"], border_width=1, corner_radius=10)
        self.target_bar.pack(fill="x", padx=16, pady=(0, 6))

        ctk.CTkLabel(
            self.target_bar,
            text="🎯 TARGET:",
            font=ctk.CTkFont(family=THEME["font_family"], size=11, weight="bold"),
            text_color=THEME["accent_cyan"]
        ).pack(side="left", padx=(12, 6), pady=6)

        self.detected_launchers = self.launcher_detector.get_all_launcher_search_paths()
        dropdown_values = ["⚡ Auto-Detect All Minecraft Launchers & Active Games (Default)"] + [f"{l['name']} ➔ {l['path']}" for l in self.detected_launchers]

        self.target_dropdown = ctk.CTkOptionMenu(
            self.target_bar,
            values=dropdown_values,
            command=self.on_target_selected,
            fg_color=THEME["card_bg"],
            button_color=THEME["accent_blue"],
            button_hover_color=THEME["accent_cyan"],
            text_color=THEME["text_primary"],
            dropdown_fg_color=THEME["panel_bg"],
            height=28,
            width=580
        )
        self.target_dropdown.pack(side="left", padx=4, pady=6)

        btn_browse = ctk.CTkButton(
            self.target_bar,
            text="📁 Custom Folder...",
            font=ctk.CTkFont(family=THEME["font_family"], size=11),
            fg_color=THEME["card_bg"],
            hover_color=THEME["panel_hover"],
            height=28,
            width=130,
            command=self.choose_custom_folder
        )
        btn_browse.pack(side="left", padx=4, pady=6)

        btn_refresh_launchers = ctk.CTkButton(
            self.target_bar,
            text="🔄 Rescan",
            font=ctk.CTkFont(family=THEME["font_family"], size=11),
            fg_color=THEME["card_bg"],
            hover_color=THEME["panel_hover"],
            height=28,
            width=80,
            command=self.refresh_launchers_list
        )
        btn_refresh_launchers.pack(side="left", padx=4, pady=6)

        # 2. Middle Section: Radar HUD & Multi-Phase Pipeline
        self.middle_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.middle_frame.pack(fill="x", padx=16, pady=(0, 6))

        # Left Radar Card
        self.radar_card = ctk.CTkFrame(self.middle_frame, fg_color=THEME["panel_bg"], border_color=THEME["panel_border"], border_width=1, corner_radius=14, width=390)
        self.radar_card.pack(side="left", fill="both", padx=(0, 6), expand=False)

        radar_top = ctk.CTkFrame(self.radar_card, fg_color="transparent")
        radar_top.pack(fill="x", padx=12, pady=8)

        self.radar = CyberRadarCanvas(radar_top, width=120, height=120)
        self.radar.pack(side="left", padx=(0, 10))

        verdict_col = ctk.CTkFrame(radar_top, fg_color="transparent")
        verdict_col.pack(side="left", fill="both", expand=True)

        ctk.CTkLabel(verdict_col, text="VERDICT STATUS", font=ctk.CTkFont(family=THEME["font_family"], size=11, weight="bold"), text_color=THEME["text_secondary"]).pack(anchor="w")
        self.verdict_label = ctk.CTkLabel(verdict_col, text="STANDBY", font=ctk.CTkFont(family=THEME["font_family"], size=19, weight="bold"), text_color=THEME["accent_cyan"])
        self.verdict_label.pack(anchor="w", pady=(0, 2))

        self.threat_index_label = ctk.CTkLabel(verdict_col, text="Threat Index: 0%", font=ctk.CTkFont(family=THEME["font_family"], size=12, weight="bold"), text_color=THEME["success_green"])
        self.threat_index_label.pack(anchor="w")

        # Stats Grid
        self.stats_grid = ctk.CTkFrame(self.radar_card, fg_color="transparent")
        self.stats_grid.pack(fill="x", padx=12, pady=(0, 8))
        self.stat_mods = self.create_metric_pill(self.stats_grid, "TOTAL MODS", "0", 0)
        self.stat_flagged = self.create_metric_pill(self.stats_grid, "HACKS DETECTED", "0", 1)
        self.stat_ram = self.create_metric_pill(self.stats_grid, "RAM VAD HOOKS", "0", 2)
        self.stat_forensics = self.create_metric_pill(self.stats_grid, "USN / FORENSICS", "0", 3)

        # Right Pipeline Card
        self.pipeline_card = ctk.CTkFrame(self.middle_frame, fg_color=THEME["panel_bg"], border_color=THEME["panel_border"], border_width=1, corner_radius=14)
        self.pipeline_card.pack(side="right", fill="both", expand=True)

        ctk.CTkLabel(self.pipeline_card, text="20-PHASE TOURNAMENT FORENSIC INVESTIGATION PIPELINE", font=ctk.CTkFont(family=THEME["font_family"], size=12, weight="bold"), text_color=THEME["text_secondary"]).pack(anchor="w", padx=14, pady=(8, 2))
        self.progress_bar = ctk.CTkProgressBar(self.pipeline_card, fg_color="#18202F", progress_color=THEME["accent_cyan"], height=6)
        self.progress_bar.pack(fill="x", padx=14, pady=(2, 6))
        self.progress_bar.set(0)

        self.phase_labels = {}
        phases = [
            ("P1", "Phase 1: Modrinth Cloud & CurseForge SHA Hash Authentication"),
            ("P2", "Phase 2: Context-Aware Bytecode & Packet Heuristic Inspection"),
            ("P3", "Phase 3: VAD Tree, In-Memory Class Dumper & ImGui Hook Audit"),
            ("P4", "Phase 4: NTFS USN Journal, PCA, BAM & UserAssist Forensic Scan"),
            ("P5", "Phase 5: Anti-Self-Destruct, DNS Domain Traces & Launcher Origin")
        ]

        for code, text in phases:
            row = ctk.CTkFrame(self.pipeline_card, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=1)
            lbl = ctk.CTkLabel(row, text=f"○  {text}", font=ctk.CTkFont(family=THEME["font_family"], size=11), text_color=THEME["text_muted"])
            lbl.pack(side="left")
            self.phase_labels[code] = lbl

        # 3. Bottom Tabview
        self.tabview = ctk.CTkTabview(
            self, fg_color=THEME["panel_bg"], segmented_button_fg_color=THEME["card_bg"],
            segmented_button_selected_color=THEME["accent_blue"], segmented_button_selected_hover_color=THEME["accent_cyan"],
            border_color=THEME["panel_border"], border_width=1, corner_radius=14
        )
        self.tabview.pack(fill="both", expand=True, padx=16, pady=(0, 10))

        self.tab_threats = self.tabview.add("🚨 Flagged Threats & Memory Hooks")
        self.tab_mods = self.tabview.add("📦 Interactive Mod Explorer (Decompiler)")
        self.tab_forensics = self.tabview.add("🛡️ USN Journal & System Forensics")
        self.tab_integrations = self.tabview.add("🌐 Cloud, Discord & RCON Bridge")
        self.tab_log = self.tabview.add("📜 Live Cyber Console")

        # Scrollable views
        self.threats_scroll = ctk.CTkScrollableFrame(self.tab_threats, fg_color="transparent")
        self.threats_scroll.pack(fill="both", expand=True, padx=6, pady=6)

        # Mod Explorer with search & decompiler launch
        mod_ctrl = ctk.CTkFrame(self.tab_mods, fg_color="transparent")
        mod_ctrl.pack(fill="x", padx=6, pady=(0, 6))

        self.search_entry = ctk.CTkEntry(mod_ctrl, placeholder_text="🔍 Search mods (Click mod to open In-GUI Decompiler)...", height=32, fg_color=THEME["card_bg"])
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.search_entry.bind("<KeyRelease>", lambda e: self.filter_mods_list())

        self.filter_seg = ctk.CTkSegmentedButton(mod_ctrl, values=["ALL", "CLEAN", "FLAGGED"], command=lambda v: self.filter_mods_list(), height=30)
        self.filter_seg.set("ALL")
        self.filter_seg.pack(side="right")

        self.mods_scroll = ctk.CTkScrollableFrame(self.tab_mods, fg_color="transparent")
        self.mods_scroll.pack(fill="both", expand=True, padx=6, pady=6)

        self.forensics_scroll = ctk.CTkScrollableFrame(self.tab_forensics, fg_color="transparent")
        self.forensics_scroll.pack(fill="both", expand=True, padx=6, pady=6)

        # Integrations Tab
        self.setup_integrations_tab()

        # Cyber Console
        self.console_box = ctk.CTkTextbox(self.tab_log, fg_color="#080B10", text_color=THEME["accent_cyan"], font=ctk.CTkFont(family="Consolas", size=12))
        self.console_box.pack(fill="both", expand=True, padx=6, pady=6)
        self.log_to_console("ANSH9BOSS Tournament Ultra Forensic Suite v3.0 loaded with 20 advanced modules.")

    def setup_integrations_tab(self):
        integ_frame = ctk.CTkFrame(self.tab_integrations, fg_color="transparent")
        integ_frame.pack(fill="both", expand=True, padx=14, pady=10)

        ctk.CTkLabel(integ_frame, text="🤖 DISCORD WEBHOOK STAFF ALERTS", font=ctk.CTkFont(family=THEME["font_family"], size=13, weight="bold"), text_color=THEME["accent_cyan"]).pack(anchor="w", pady=(0, 4))
        self.webhook_entry = ctk.CTkEntry(integ_frame, placeholder_text="Enter Discord Webhook URL (https://discord.com/api/webhooks/...)", height=32, fg_color=THEME["card_bg"])
        default_wh = self.config.get("discord_webhook", "https://discord.com/api/webhooks/1543109814593519658/VeKGdUanLyJCR5-N86Ma0EcD4q5VR18MiDGJOEyMiF0t5HNVd_dQS3Qxcgvkzjkpo1hN")
        self.webhook_entry.insert(0, default_wh)
        self.webhook_entry.pack(fill="x", pady=(0, 12))

        btn_test_webhook = ctk.CTkButton(integ_frame, text="📢 Send Test Staff Alert to Discord", height=32, fg_color=THEME["card_bg"], command=self.send_discord_alert_manual)
        btn_test_webhook.pack(anchor="w", pady=(0, 16))

        ctk.CTkLabel(integ_frame, text="🔨 RCON SERVER BAN / PUNISH ENFORCEMENT", font=ctk.CTkFont(family=THEME["font_family"], size=13, weight="bold"), text_color=THEME["accent_cyan"]).pack(anchor="w", pady=(0, 4))
        
        rcon_row = ctk.CTkFrame(integ_frame, fg_color="transparent")
        rcon_row.pack(fill="x", pady=(0, 10))

        self.rcon_ip_entry = ctk.CTkEntry(rcon_row, placeholder_text="Server IP (127.0.0.1)", width=180, fg_color=THEME["card_bg"])
        self.rcon_ip_entry.pack(side="left", padx=(0, 8))
        self.rcon_pass_entry = ctk.CTkEntry(rcon_row, placeholder_text="RCON Password", show="*", width=180, fg_color=THEME["card_bg"])
        self.rcon_pass_entry.pack(side="left", padx=(0, 8))

    def create_metric_pill(self, parent, label, value, col):
        frame = ctk.CTkFrame(parent, fg_color=THEME["card_bg"], corner_radius=8, height=44)
        frame.grid(row=col // 2, column=col % 2, padx=3, pady=3, sticky="nsew")
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_columnconfigure(1, weight=1)

        val_lbl = ctk.CTkLabel(frame, text=value, font=ctk.CTkFont(family=THEME["font_family"], size=15, weight="bold"), text_color=THEME["text_primary"])
        val_lbl.pack(pady=(2, 0))
        title_lbl = ctk.CTkLabel(frame, text=label, font=ctk.CTkFont(family=THEME["font_family"], size=9), text_color=THEME["text_secondary"])
        title_lbl.pack(pady=(0, 2))
        return val_lbl

    def log_to_console(self, text):
        def _do():
            try:
                timestamp = time.strftime("%H:%M:%S")
                self.console_box.insert("end", f"[{timestamp}] {text}\n")
                self.console_box.see("end")
            except Exception:
                pass
        self.after(0, _do)

    def update_phase(self, code, status, note=""):
        def _do():
            try:
                symbols = {"RUNNING": ("⏳", THEME["warning_yellow"]), "CLEAN": ("✓", THEME["success_green"]), "ALERT": ("⚠️", THEME["danger_red"]), "WAITING": ("○", THEME["text_muted"])}
                sym, color = symbols.get(status, ("○", THEME["text_muted"]))
                lbl = self.phase_labels.get(code)
                if lbl and lbl.winfo_exists():
                    curr_text = lbl.cget("text")
                    base_name = curr_text.split(":")[-1].strip()
                    lbl.configure(text=f"{sym}  Phase {code[-1]}: {base_name} {note}", text_color=color)
            except Exception:
                pass
        self.after(0, _do)

    def set_progress(self, val):
        def _do():
            try:
                if self.progress_bar.winfo_exists():
                    self.progress_bar.set(val)
            except Exception:
                pass
        self.after(0, _do)

    def set_stat(self, widget, val):
        def _do():
            try:
                if widget.winfo_exists():
                    widget.configure(text=str(val))
            except Exception:
                pass
        self.after(0, _do)

    def on_freeze_violation(self, text):
        self.log_to_console(f"🚨 FREEZE VIOLATION: {text}")
        self.audio_alerts.speak("Warning. Self destruct cleaner process detected.")

    def on_target_selected(self, choice):
        if choice.startswith("⚡"):
            self.selected_target_path = None
            self.log_to_console("Target set to: Auto-Detect All Minecraft Launchers & Active Games")
        else:
            for l in self.detected_launchers:
                if choice.startswith(l["name"]):
                    self.selected_target_path = l["path"]
                    self.log_to_console(f"Target profile selected: {l['name']} ({l['path']})")
                    break

    def refresh_launchers_list(self):
        self.detected_launchers = self.launcher_detector.get_all_launcher_search_paths()
        dropdown_values = ["⚡ Auto-Detect All Minecraft Launchers & Active Games (Default)"] + [f"{l['name']} ➔ {l['path']}" for l in self.detected_launchers]
        self.target_dropdown.configure(values=dropdown_values)
        self.target_dropdown.set(dropdown_values[0])
        self.selected_target_path = None
        self.log_to_console(f"Discovered {len(self.detected_launchers)} Minecraft launcher/profile directories on this system.")

    def choose_custom_folder(self):
        folder = filedialog.askdirectory(title="Select Custom Minecraft Mods Folder")
        if folder:
            self.selected_target_path = folder
            self.target_dropdown.set(f"Custom ➔ {folder}")
            self.log_to_console(f"Target directory set to custom folder: {folder}")

    def open_hex_viewer(self, address="0x00007FF7A10B4000", data=None):
        try:
            HexViewerModal(self, address, data)
        except Exception as e:
            self.log_to_console(f"Error opening Hex Viewer: {e}")

    def open_decompiler(self, jar_path):
        try:
            DecompilerViewerModal(self, jar_path)
        except Exception as e:
            self.log_to_console(f"Error opening Decompiler: {e}")

    def trigger_rcon_ban(self):
        ip = self.rcon_ip_entry.get().strip() or "127.0.0.1"
        pw = self.rcon_pass_entry.get().strip()
        if not pw:
            messagebox.showwarning("RCON Config", "Please enter your Server RCON Password in the Cloud & Integrations tab.")
            return

        rcon = RCONBridge(host=ip, password=pw)
        cmd = f"ban {self.player_ign} Cheating / Injected Ghost Client [ANSH9BOSS-Audit]"
        success, msg = rcon.send_command(cmd)
        if success:
            messagebox.showinfo("RCON Ban Executed", f"Server Response:\n{msg}")
        else:
            messagebox.showerror("RCON Error", msg)

    def send_discord_alert_manual(self):
        webhook = self.webhook_entry.get().strip()
        if not webhook:
            messagebox.showwarning("Discord Webhook", "Please enter a valid Discord Webhook URL.")
            return
        self.discord_alerts.webhook_url = webhook
        success, msg = self.discord_alerts.send_audit_alert(self.scan_results, self.player_ign)
        if success:
            messagebox.showinfo("Discord Alert", "Staff alert embed dispatched successfully!")
        else:
            messagebox.showerror("Discord Alert Error", msg)

    def start_full_audit_thread(self, custom_path=None):
        if self.is_scanning:
            return
        self.is_scanning = True
        self.radar.start_animation()
        self.btn_full_scan.configure(state="disabled")
        self.btn_ram_scan.configure(state="disabled")
        self.verdict_label.configure(text="AUDITING...", text_color=THEME["warning_yellow"])
        self.audio_alerts.speak("Initiating comprehensive forensic audit.")
        self.freeze_monitor.start_monitoring()
        threading.Thread(target=self.run_full_audit, args=(custom_path,), daemon=True).start()

    def start_ram_scan_thread(self):
        if self.is_scanning:
            return
        self.is_scanning = True
        self.radar.start_animation()
        self.btn_full_scan.configure(state="disabled")
        self.btn_ram_scan.configure(state="disabled")
        threading.Thread(target=self.run_ram_only_audit, daemon=True).start()

    def run_ram_only_audit(self):
        self.log_to_console("Scanning committed JVM RAM, VAD memory tree, and ImGui hooks...")
        self.update_phase("P3", "RUNNING")
        self.set_progress(0.5)

        ram_results = self.mem_scanner.run_full_memory_audit()
        detections = ram_results.get("detections", [])

        # VAD Scanner & JVMTI Dumper
        procs = self.mem_scanner.find_minecraft_processes()
        for p in procs:
            vad_hits = self.vad_scanner.scan_unlinked_executable_memory(p["pid"])
            jvm_hits = self.jvm_dumper.scan_jvm_loaded_classes(p["pid"])
            overlay_hits = self.overlay_hunter.scan_overlay_hooks(p["pid"])
            detections.extend(vad_hits + jvm_hits + overlay_hits)

        self.scan_results["ram_hits"] = detections
        self.set_stat(self.stat_ram, len(detections))

        if detections:
            self.update_phase("P3", "ALERT", f"({len(detections)} Hits)")
            self.audio_alerts.speak("Threat detected in process memory.")
        else:
            self.update_phase("P3", "CLEAN", "(Clean RAM)")
            self.audio_alerts.speak("Process memory audit clean.")

        self.set_progress(1.0)
        self.finish_scan_ui("CLEAN" if not detections else "DANGEROUS", 100 if detections else 0)

    def run_full_audit(self, custom_path=None):
        self.log_to_console("Starting 20-Phase Tournament Forensic Investigation...")
        self.set_progress(0.05)

        for code in ["P1", "P2", "P3", "P4", "P5"]:
            self.update_phase(code, "WAITING")

        target_path = custom_path or self.selected_target_path
        mod_files = self.launcher_detector.discover_all_mod_files(target_path)
        self.scan_results["total_mods"] = len(mod_files)
        self.set_stat(self.stat_mods, len(mod_files))
        self.log_to_console(f"Discovered {len(mod_files)} mod JARs across Minecraft launcher profiles to analyze.")

        # Phase 1 & 2: Mod Scanning
        self.update_phase("P1", "RUNNING")
        self.update_phase("P2", "RUNNING")
        self.set_progress(0.2)

        mod_detections = []
        all_mods_info = []
        max_threat_score = 0

        # Batch verify all mods in parallel
        modrinth_results = self.modrinth.verify_batch_mods(mod_files)

        for idx, mod in enumerate(mod_files):
            is_clean, mod_info = modrinth_results.get(mod, (False, {}))
            jar_res = self.jar_analyzer.analyze_jar(mod)

            if is_clean:
                jar_res["risk_level"] = "CLEAN"
                jar_res["threat_score"] = 0
                jar_res["detection_layer"] = "Modrinth Verified Clean"

            all_mods_info.append({
                "file": mod.name, "path": str(mod), "verified": is_clean,
                "modrinth": mod_info, "jar_res": jar_res, "threat_score": jar_res.get("threat_score", 0)
            })

            if jar_res["risk_level"] != "CLEAN":
                mod_detections.append(jar_res)
                max_threat_score = max(max_threat_score, jar_res.get("threat_score", 0))
                self.radar.add_blip(is_threat=True)
                self.log_to_console(f"FLAGGED: {mod.name} [Threat Index: {jar_res['threat_score']}%] -> {jar_res['detection_layer']}")
            else:
                self.radar.add_blip(is_threat=False)

            self.set_progress(0.2 + (0.35 * ((idx + 1) / max(len(mod_files), 1))))

        self.scan_results["mod_detections"] = mod_detections
        self.scan_results["all_mods"] = all_mods_info
        self.set_stat(self.stat_flagged, len(mod_detections))
        self.update_phase("P1", "CLEAN" if not mod_detections else "ALERT")
        self.update_phase("P2", "CLEAN" if not mod_detections else "ALERT")

        # Phase 3: Live RAM & VAD & JVMTI Dumper
        self.update_phase("P3", "RUNNING")
        self.set_progress(0.65)
        self.log_to_console("Phase 3: Auditing VAD private memory, loaded JVMTI classes, and Present hooks...")
        ram_res = self.mem_scanner.run_full_memory_audit()
        ram_hits = ram_res.get("detections", [])

        procs = self.mem_scanner.find_minecraft_processes()
        for p in procs:
            ram_hits.extend(self.vad_scanner.scan_unlinked_executable_memory(p["pid"]))
            ram_hits.extend(self.jvm_dumper.scan_jvm_loaded_classes(p["pid"]))
            ram_hits.extend(self.overlay_hunter.scan_overlay_hooks(p["pid"]))

        self.scan_results["ram_hits"] = ram_hits
        self.set_stat(self.stat_ram, len(ram_hits))
        if ram_hits:
            max_threat_score = max(max_threat_score, 100)
            self.update_phase("P3", "ALERT", f"({len(ram_hits)} Hits)")
        else:
            self.update_phase("P3", "CLEAN")

        # Phase 4: NTFS USN Journal, PCA, BAM & UserAssist
        self.update_phase("P4", "RUNNING")
        self.set_progress(0.8)
        self.log_to_console("Phase 4: Extracting raw NTFS USN Journal, PCA logs, BAM, and UserAssist ROT13...")
        sys_res = self.system_forensics.run_full_forensics_audit()
        forensic_hits = sys_res.get("all_threats", [])
        forensic_hits.extend(self.usn_parser.audit_deleted_files_journal())
        forensic_hits.extend(self.pca_forensics.audit_pca_launch_history())
        forensic_hits.extend(self.userassist.audit_userassist_rot13())
        forensic_hits.extend(self.vss_recovery.audit_temp_slack_artifacts())

        self.scan_results["forensic_hits"] = forensic_hits
        self.set_stat(self.stat_forensics, len(forensic_hits))
        if forensic_hits:
            max_threat_score = max(max_threat_score, 50)
            self.update_phase("P4", "ALERT", f"({len(forensic_hits)} Traces)")
        else:
            self.update_phase("P4", "CLEAN")

        # Phase 5: Anti-Self-Destruct & Parent Launcher Origin
        self.update_phase("P5", "RUNNING")
        self.set_progress(0.95)
        self.log_to_console("Phase 5: Verifying Prefetch integrity, DNS Cache, and Launcher Parent PID...")
        tamper_hits = self.tampering_detector.run_tampering_audit()
        tamper_hits.extend(self.vanilla_integrity.audit_vanilla_versions())

        for p in procs:
            ptrace = self.parent_tracer.trace_minecraft_parent(p["pid"])
            if ptrace.get("risk") != "CLEAN":
                tamper_hits.append({"risk": "SUSPICIOUS", "type": "Unrecognized Launcher Origin", "detail": f"Process spawned by non-standard parent: '{ptrace['parent_name']}'"})

        self.scan_results["tampering_hits"] = tamper_hits
        if tamper_hits:
            max_threat_score = max(max_threat_score, 75)
            self.update_phase("P5", "ALERT", f"({len(tamper_hits)} Traces)")
        else:
            self.update_phase("P5", "CLEAN")

        # Final Verdict Calculation
        self.set_progress(1.0)
        self.scan_results["threat_score"] = max_threat_score
        highest_risk = "DANGEROUS" if max_threat_score >= 65 else ("SUSPICIOUS" if max_threat_score >= 30 else "CLEAN")
        self.scan_results["highest_risk"] = highest_risk

        self.db.save_scan(
            total_files=len(mod_files), flagged_files=len(mod_detections), highest_risk=highest_risk,
            platform="Windows", detections=mod_detections, ram_threats=len(ram_hits), forensic_threats=len(forensic_hits) + len(tamper_hits)
        )

        self.log_to_console(f"Audit Complete! Threat Index: {max_threat_score}% | Final Verdict: {highest_risk}")
        if highest_risk == "CLEAN":
            self.audio_alerts.speak("Audit complete. Player verified clean.")
        else:
            self.audio_alerts.speak(f"Audit complete. Warning: {highest_risk} threat detected.")

        # Dispatch automatic Discord Alert if configured
        webhook = self.webhook_entry.get().strip()
        if webhook:
            self.discord_alerts.webhook_url = webhook
            self.discord_alerts.send_audit_alert(self.scan_results, self.player_ign)

        self.finish_scan_ui(highest_risk, max_threat_score)

    def finish_scan_ui(self, highest_risk, threat_score):
        def _do():
            try:
                self.refresh_results_ui()
                self.freeze_monitor.stop_monitoring()
                self.is_scanning = False
                self.radar.stop_animation()
                self.btn_full_scan.configure(state="normal")
                self.btn_ram_scan.configure(state="normal")
            except Exception:
                pass
        self.after(0, _do)

    def refresh_results_ui(self):
        def _do():
            try:
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

                # Threats Tab - Thread-safe clearing
                for widget in list(self.threats_scroll.winfo_children()):
                    try:
                        widget.pack_forget()
                        widget.destroy()
                    except Exception:
                        pass

                all_threats = []
                for r in self.scan_results.get("ram_hits", []):
                    all_threats.append(("RAM VAD / INJECTION HOOK", r.get("detail", ""), THEME["danger_red"]))
                for m in self.scan_results.get("mod_detections", []):
                    details = " | ".join(m.get("matched_details", [])) if isinstance(m.get("matched_details"), list) else m.get("matched_details")
                    score = m.get("threat_score", 50)
                    color = THEME["danger_red"] if score >= 65 else THEME["warning_yellow"]
                    all_threats.append((f"HACK MOD: {m.get('file_name')} ({score}% Threat)", details, color))
                for s in self.scan_results.get("forensic_hits", []) + self.scan_results.get("tampering_hits", []):
                    all_threats.append((s.get("type", "FORENSIC RECORD"), s.get("detail", ""), THEME["warning_yellow"]))

                if not all_threats:
                    lbl = ctk.CTkLabel(self.threats_scroll, text="✓ Zero cheat threats, VAD memory injections, or USN journal traces found.", font=ctk.CTkFont(family=THEME["font_family"], size=13), text_color=THEME["success_green"])
                    lbl.pack(pady=20)
                else:
                    for title, desc, color in all_threats:
                        card = ctk.CTkFrame(self.threats_scroll, fg_color=THEME["card_bg"], border_color=color, border_width=1, corner_radius=10)
                        card.pack(fill="x", pady=4, padx=4)
                        ctk.CTkLabel(card, text=title, font=ctk.CTkFont(family=THEME["font_family"], size=13, weight="bold"), text_color=color).pack(anchor="w", padx=12, pady=(8, 2))
                        ctk.CTkLabel(card, text=desc, font=ctk.CTkFont(family=THEME["font_family"], size=12), text_color=THEME["text_primary"], wraplength=980, justify="left").pack(anchor="w", padx=12, pady=(0, 8))

                # Mod Explorer Tab
                self.filter_mods_list()
            except Exception:
                pass
        self.after(0, _do)

    def filter_mods_list(self):
        def _do():
            try:
                query = self.search_entry.get().strip().lower()
                for widget in list(self.mods_scroll.winfo_children()):
                    try:
                        widget.pack_forget()
                        widget.destroy()
                    except Exception:
                        pass

                for mod in self.scan_results.get("all_mods", []):
                    fname = mod["file"].lower()
                    jar_res = mod.get("jar_res", {})
                    risk = jar_res.get("risk_level", "CLEAN")

                    if query and query not in fname and query not in mod.get("path", "").lower():
                        continue
                    if self.filter_seg.get() == "CLEAN" and risk != "CLEAN":
                        continue
                    if self.filter_seg.get() == "FLAGGED" and risk == "CLEAN":
                        continue

                    score = jar_res.get("threat_score", 0)
                    status_color = THEME["success_green"] if risk == "CLEAN" else (THEME["warning_yellow"] if risk == "SUSPICIOUS" else THEME["danger_red"])
                    status_text = f"THREAT: {score}%" if risk != "CLEAN" else ("MODRINTH AUTHENTIC" if mod["verified"] else "SAFE")

                    row = ctk.CTkFrame(self.mods_scroll, fg_color=THEME["card_bg"], corner_radius=8)
                    row.pack(fill="x", pady=2, padx=4)

                    # Clickable name opens In-GUI Decompiler
                    btn_decompile = ctk.CTkButton(
                        row, text=f"🔍 {mod['file']}", font=ctk.CTkFont(family=THEME["font_family"], size=12, weight="bold"),
                        fg_color="transparent", text_color=THEME["text_primary"], hover_color=THEME["panel_hover"], anchor="w",
                        command=lambda p=mod["path"]: self.open_decompiler(p)
                    )
                    btn_decompile.pack(side="left", padx=8, pady=4)
                    ctk.CTkLabel(row, text=status_text, font=ctk.CTkFont(family=THEME["font_family"], size=11, weight="bold"), text_color=status_color).pack(side="right", padx=12)
            except Exception:
                pass
        self.after(0, _do)

    def export_report(self):
        try:
            output_file = ReportGenerator.export_html(self.scan_results, player_ign=self.player_ign)
            self.log_to_console(f"Forensic Dossier saved: {output_file}")
            abs_path = Path(output_file).resolve().as_uri()
            webbrowser.open(abs_path)
            messagebox.showinfo("Dossier Exported", f"Signed Forensic Screenshare Dossier saved and opened in browser:\n{output_file}")
        except Exception as e:
            self.log_to_console(f"Error exporting dossier: {e}")

def launch_gui(config=None):
    app = GlassAnalyzerGUI(config)
    app.mainloop()
