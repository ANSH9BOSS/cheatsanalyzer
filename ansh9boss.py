#!/usr/bin/env python3
"""
ANSH9BOSS CheatsAnalyzer v3.0 (Tournament Ultra Forensic Edition)
20-Phase Live Memory, VAD Scanner, USN Journal, PCA Forensics & Decompiler Suite.
"""

import os
import sys
import json
import time
import argparse
from pathlib import Path

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
CONFIG_PATH = DATA_DIR / "config.json"
DB_PATH = DATA_DIR / "ansh9boss.db"

def load_config():
    """Load configuration from config.json or initialize defaults."""
    default_config = {
        "version": "3.0.0",
        "known_cheats": [
            "wurst", "meteor", "sigma", "impact", "aristois", "future", "liquidbounce", 
            "wolfram", "inertia", "ares", "sentry", "entropy", "reflex", "bleach", 
            "ancientaura", "killaura", "huzuni", "nodus", "vape", "badlion", "mathax",
            "kamiblue", "kami", "salhack", "rusherhack", "drip", "driplite", "slinky",
            "raven", "ravenbplus", "augustus", "kura", "karma", "spearmint", "rise",
            "novoline", "tenacity", "moon", "astolfo", "doomsday"
        ],
        "known_packages": [
            "meteorclient", "wurst", "sigma", "future", "liquidbounce", "mathax", 
            "ares", "wolfram", "kamiblue", "salhack", "rusherhack", "aristois", "huzuni", 
            "vape", "drip", "slinky", "raven", "augustus", "kura", "karma", "spearmint", "novoline"
        ],
        "cheat_strings": [
            "aimbot", "killaura", "esp", "wallhack", "xray", "freecam", 
            "nofall", "scaffold", "triggerbot", "autoclick", "baritone", "pathfind", 
            "autototem", "fastplace", "criticals", "antiknockback", "nuker", 
            "jesus", "automine", "cheatengine", "velocity", "reach", "hitboxes"
        ],
        "memory_signatures": [
            "vape.gg", "vape_v4", "drip.gg", "slinky.gg", "spearmint.cc",
            "raven_bplus", "kura_client", "entropy.club", "doomsday.gg",
            "novoline.lol", "tenacity.dev", "augustus.vip", "astolfo.lgbt"
        ],
        "cheat_domains": [
            "vape.gg", "drip.gg", "slinky.gg", "spearmint.cc",
            "astolfo.lgbt", "novoline.lol", "tenacity.dev", "intent.store",
            "riseclient.com", "liquidbounce.net", "wurstclient.net", "meteorclient.com"
        ]
    }
    
    if not CONFIG_PATH.exists():
        DATA_DIR.mkdir(exist_ok=True)
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(default_config, f, indent=2)
        return default_config
    
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default_config

def run_cli_audit(args, config):
    """Runs 20-phase high-definition CLI terminal scan."""
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.panel import Panel
    import pyfiglet

    from core.database import ForensicDB
    from core.modrinth_verifier import ModrinthVerifier
    from core.jar_analyzer import JarAnalyzer
    from core.memory_scanner import ProcessMemoryScanner
    from core.system_forensics import SystemForensics
    from core.tampering_detector import TamperingDetector
    from core.memory.jvm_dumper import JVMTIDumper
    from core.memory.vad_scanner import VADScanner
    from core.memory.overlay_hunter import OverlayHookHunter
    from core.forensics.usn_journal import USNJournalParser
    from core.forensics.pca_forensics import PCAForensics
    from core.forensics.userassist_shellbags import UserAssistExplorer
    from core.forensics.vss_recovery import VSSArtifactScanner
    from core.analysis.parent_tracer import ParentProcessTracer
    from core.analysis.vanilla_integrity import VanillaIntegrityChecker
    from ui.report_generator import ReportGenerator

    console = Console(safe_box=True)
    db = ForensicDB()
    modrinth = ModrinthVerifier(db)
    jar_analyzer = JarAnalyzer(config)
    mem_scanner = ProcessMemoryScanner(config)
    system_forensics = SystemForensics(config)
    tampering_detector = TamperingDetector(config)
    jvm_dumper = JVMTIDumper(config)
    vad_scanner = VADScanner()
    overlay_hunter = OverlayHookHunter()
    usn_parser = USNJournalParser()
    pca_forensics = PCAForensics()
    userassist = UserAssistExplorer()
    vss_recovery = VSSArtifactScanner()
    parent_tracer = ParentProcessTracer()
    vanilla_integrity = VanillaIntegrityChecker()

    # Banner
    ascii_art = pyfiglet.figlet_format("ANSH9BOSS")
    console.print(f"[bold cyan]{ascii_art}[/bold cyan]")
    console.print("[bold aquamarine1][*] TOURNAMENT ULTRA FORENSIC SUITE v3.0 (20-PHASE ENGINE)[/bold aquamarine1]")
    console.print("[dim white]VAD Memory Tree • USN Change Journal • JVMTI Class Dumper • PCA Logs • Cryptographic Cert[/dim white]\n")

    # Discover mods
    mod_files = []
    if args.path:
        target = Path(args.path)
        if target.is_dir():
            mod_files = list(target.rglob("*.jar"))
        elif target.is_file() and target.suffix == ".jar":
            mod_files = [target]
    else:
        appdata = os.environ.get("APPDATA")
        if appdata:
            default_mc = Path(appdata) / ".minecraft/mods"
            if default_mc.exists():
                mod_files.extend(list(default_mc.rglob("*.jar")))

    mod_files = list(set([p.resolve() for p in mod_files if p.is_file()]))
    console.print(f"[cyan][*] Discovered [bold]{len(mod_files)}[/bold] mod file(s) to analyze.[/cyan]")

    mod_detections = []
    all_mods_info = []
    max_threat_score = 0

    # Phase 1 & 2: Mod Scanning
    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]{task.description}"),
        BarColumn(bar_width=40, complete_style="cyan", finished_style="aquamarine1"),
        TaskProgressColumn(),
        console=console
    ) as progress:
        task = progress.add_task("Auditing mods against Modrinth & Bytecode...", total=max(len(mod_files), 1))
        for mod in mod_files:
            progress.update(task, description=f"Inspecting {mod.name[:30]}...")
            is_clean, info = modrinth.verify_mod(mod)
            jar_res = jar_analyzer.analyze_jar(mod)
            if is_clean:
                jar_res["risk_level"] = "CLEAN"
                jar_res["threat_score"] = 0
            all_mods_info.append({"file": mod.name, "path": str(mod), "verified": is_clean, "modrinth": info, "jar_res": jar_res})
            if jar_res["risk_level"] != "CLEAN":
                mod_detections.append(jar_res)
                max_threat_score = max(max_threat_score, jar_res.get("threat_score", 0))
            progress.advance(task)

    # Phase 3: Win32 Live Memory & VAD Audit
    console.print("\n[bold cyan][Phase 3] Auditing Win32 RAM, VAD Private Memory & JVMTI Dumper...[/bold cyan]")
    ram_res = mem_scanner.run_full_memory_audit()
    ram_hits = ram_res.get("detections", [])
    procs = mem_scanner.find_minecraft_processes()
    for p in procs:
        ram_hits.extend(vad_scanner.scan_unlinked_executable_memory(p["pid"]))
        ram_hits.extend(jvm_dumper.scan_jvm_loaded_classes(p["pid"]))
        ram_hits.extend(overlay_hunter.scan_overlay_hooks(p["pid"]))

    if ram_hits:
        max_threat_score = max(max_threat_score, 100)
        console.print(f"[bold red][!] CRITICAL: {len(ram_hits)} Injected Ghost Client hooks detected in RAM/VAD![/bold red]")
        for hit in ram_hits:
            console.print(f"  [red]- {hit.get('detail')}[/red]")
    else:
        console.print("[green][+] Process Memory & VAD Tree Clean: No unlinked DLLs or ghost client signatures in RAM.[/green]")

    # Phase 4: USB & Windows NTFS USN Journal Forensics
    console.print("\n[bold cyan][Phase 4] Scanning NTFS USN Journal, PCA Logs, BAM & UserAssist...[/bold cyan]")
    sys_res = system_forensics.run_full_forensics_audit()
    forensic_hits = sys_res.get("all_threats", [])
    forensic_hits.extend(usn_parser.audit_deleted_files_journal())
    forensic_hits.extend(pca_forensics.audit_pca_launch_history())
    forensic_hits.extend(userassist.audit_userassist_rot13())
    forensic_hits.extend(vss_recovery.audit_temp_slack_artifacts())

    if forensic_hits:
        max_threat_score = max(max_threat_score, 50)
        for f in forensic_hits:
            console.print(f"  [yellow]- {f.get('detail')}[/yellow]")
    else:
        console.print("[green][+] System Forensics Clean: No deleted cheat journal logs or USB traces found.[/green]")

    # Phase 5: Anti-Self-Destruct & Parent Launcher Origin
    console.print("\n[bold cyan][Phase 5] Checking Anti-Self-Destruct, DNS Cache & Launcher Origin...[/bold cyan]")
    tamper_hits = tampering_detector.run_tampering_audit()
    tamper_hits.extend(vanilla_integrity.audit_vanilla_versions())
    for p in procs:
        ptrace = parent_tracer.trace_minecraft_parent(p["pid"])
        if ptrace.get("risk") != "CLEAN":
            tamper_hits.append({"risk": "SUSPICIOUS", "detail": f"Spawned by non-standard parent: '{ptrace['parent_name']}'"})

    if tamper_hits:
        max_threat_score = max(max_threat_score, 75)
        for t in tamper_hits:
            console.print(f"  [red]- {t.get('detail')}[/red]")
    else:
        console.print("[green][+] Tampering Integrity Clean: No event log wipes or cheat domain queries detected.[/green]")

    # Final Verdict
    highest_risk = "DANGEROUS" if max_threat_score >= 65 else ("SUSPICIOUS" if max_threat_score >= 30 else "CLEAN")

    console.print(f"\n[bold cyan]==================== FINAL AUDIT VERDICT ====================[/bold cyan]")
    if highest_risk == "CLEAN":
        console.print(Panel(f"[bold green]VERIFIED CLEAN ({max_threat_score}% Threat Index) - NO INJECTIONS FOUND[/bold green]", border_style="green"))
    elif highest_risk == "SUSPICIOUS":
        console.print(Panel(f"[bold yellow]SUSPICIOUS ({max_threat_score}% Threat Index) - FORENSIC TRACES DETECTED[/bold yellow]", border_style="yellow"))
    else:
        console.print(Panel(f"[bold red]CRITICAL THREAT ({max_threat_score}% Threat Index) - ACTIVE INJECTIONS IDENTIFIED[/bold red]", border_style="red"))

    results_data = {
        "highest_risk": highest_risk,
        "threat_score": max_threat_score,
        "total_mods": len(mod_files),
        "flagged_mods": len(mod_detections),
        "ram_hits": ram_hits,
        "forensic_hits": forensic_hits,
        "tampering_hits": tamper_hits,
        "mod_detections": mod_detections,
        "all_mods": all_mods_info
    }

    db.save_scan(
        total_files=len(mod_files), flagged_files=len(mod_detections), highest_risk=highest_risk,
        platform="Windows" if os.name == "nt" else "Linux/Other", detections=mod_detections,
        ram_threats=len(ram_hits), forensic_threats=len(forensic_hits) + len(tamper_hits)
    )

    if args.export:
        out_file = f"{args.out}.html"
        ReportGenerator.export_html(results_data, out_file)
        console.print(f"[green][+] Cryptographically Signed Forensic Dossier exported: [bold]{out_file}[/bold][/green]")

    if not args.no_telemetry:
        from core.integrations.discord_alerts import DiscordStaffAlerts
        wh_url = config.get("discord_webhook")
        if wh_url:
            discord_client = DiscordStaffAlerts(wh_url)
            success, msg = discord_client.send_audit_alert(results_data, player_ign="Player")
            if success:
                console.print(f"[cyan][+] Real-time Staff Alert dispatched to Discord Webhook.[/cyan]")

def main():
    parser = argparse.ArgumentParser(description="ANSH9BOSS CheatsAnalyzer v3.0 - Tournament Ultra Forensic Suite")
    parser.add_argument("path", nargs="?", help="Specific directory or .jar file to scan")
    parser.add_argument("--cli", action="store_true", help="Force command-line interface mode instead of Glassmorphism GUI")
    parser.add_argument("--export", choices=["html", "json"], default="html", help="Export format")
    parser.add_argument("--out", default="screenshare_audit_report", help="Output file basename")
    parser.add_argument("--no-telemetry", action="store_true", help="Disable telemetry")
    args = parser.parse_args()

    config = load_config()

    if not args.cli and (os.environ.get("DISPLAY") is not None or os.name == "nt"):
        try:
            from ui.glass_gui import launch_gui
            launch_gui(config)
            return
        except Exception as e:
            print(f"[*] GUI initialization fallback to CLI ({e})")

    run_cli_audit(args, config)

if __name__ == "__main__":
    main()
