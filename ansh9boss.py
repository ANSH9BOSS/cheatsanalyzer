#!/usr/bin/env python3
"""
ANSH9BOSS CheatsAnalyzer v2.0
Tournament-grade Minecraft Hacks & Forensic Cheat Detector Suite.
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

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
CONFIG_PATH = DATA_DIR / "config.json"
DB_PATH = DATA_DIR / "ansh9boss.db"

def load_config():
    """Load configuration from config.json or initialize defaults."""
    default_config = {
        "version": "2.0.0",
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
    """Runs high-definition CLI terminal scan across all 5 forensic phases."""
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.panel import Panel
    from rich import box
    import pyfiglet

    from core.database import ForensicDB
    from core.modrinth_verifier import ModrinthVerifier
    from core.jar_analyzer import JarAnalyzer
    from core.memory_scanner import ProcessMemoryScanner
    from core.system_forensics import SystemForensics
    from core.tampering_detector import TamperingDetector
    from ui.report_generator import ReportGenerator

    console = Console(safe_box=True)
    db = ForensicDB()
    modrinth = ModrinthVerifier(db)
    jar_analyzer = JarAnalyzer(config)
    mem_scanner = ProcessMemoryScanner(config)
    system_forensics = SystemForensics(config)
    tampering_detector = TamperingDetector(config)

    # Banner
    ascii_art = pyfiglet.figlet_format("ANSH9BOSS")
    console.print(f"[bold cyan]{ascii_art}[/bold cyan]")
    console.print("[bold aquamarine1][*] TOURNAMENT-GRADE MINECRAFT CHEAT & PROCESS FORENSIC SUITE v2.0[/bold aquamarine1]")
    console.print("[dim white]Multi-Phase RAM Injection | USB Forensics | BAM Logs | Modrinth Cloud Hash Verification[/dim white]\n")

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

    # Phase 1 & 2: Mod Scanning
    mod_detections = []
    all_mods_info = []

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
            all_mods_info.append({"file": mod.name, "path": str(mod), "verified": is_clean, "modrinth": info})
            if not is_clean:
                jar_res = jar_analyzer.analyze_jar(mod)
                if jar_res["risk_level"] != "CLEAN":
                    mod_detections.append(jar_res)
            progress.advance(task)

    # Phase 3: Win32 Live Memory Audit
    console.print("\n[bold cyan][Phase 3] Auditing Win32 Live Process Memory (javaw.exe / Minecraft)...[/bold cyan]")
    ram_res = mem_scanner.run_full_memory_audit()
    ram_hits = ram_res.get("detections", [])
    if ram_hits:
        console.print(f"[bold red][!] CRITICAL: {len(ram_hits)} Injected Ghost Client memory hooks detected in RAM![/bold red]")
        for hit in ram_hits:
            console.print(f"  [red]- {hit.get('detail')}[/red]")
    else:
        console.print("[green][+] Process Memory Clean: No unlinked DLLs or ghost client signatures in active RAM.[/green]")

    # Phase 4: USB & System Forensics
    console.print("\n[bold cyan][Phase 4] Scanning USBSTOR Devices, BAM Execution & Prefetch Traces...[/bold cyan]")
    sys_res = system_forensics.run_full_forensics_audit()
    forensic_hits = sys_res.get("all_threats", [])
    if forensic_hits:
        for f in forensic_hits:
            console.print(f"  [yellow]- {f.get('detail')}[/yellow]")
    else:
        console.print("[green][+] System Forensics Clean: No unauthorized USB injection traces found.[/green]")

    # Phase 5: Anti-Self-Destruct
    console.print("\n[bold cyan][Phase 5] Checking Anti-Self-Destruct, Prefetch Integrity & DNS Cache...[/bold cyan]")
    tamper_hits = tampering_detector.run_tampering_audit()
    if tamper_hits:
        for t in tamper_hits:
            console.print(f"  [red]- {t.get('detail')}[/red]")
    else:
        console.print("[green][+] Tampering Integrity Clean: No event log wipes or cheat domain DNS queries detected.[/green]")

    # Final Verdict
    if len(ram_hits) > 0 or any(d.get("risk_level") == "DANGEROUS" for d in mod_detections):
        highest_risk = "DANGEROUS"
    elif len(mod_detections) + len(forensic_hits) + len(tamper_hits) > 0:
        highest_risk = "SUSPICIOUS"
    else:
        highest_risk = "CLEAN"

    console.print(f"\n[bold cyan]==================== FINAL AUDIT VERDICT ====================[/bold cyan]")
    if highest_risk == "CLEAN":
        console.print(Panel("[bold green]VERIFIED CLEAN - NO CHEAT INJECTIONS OR THREATS FOUND[/bold green]", border_style="green"))
    elif highest_risk == "SUSPICIOUS":
        console.print(Panel("[bold yellow]SUSPICIOUS - MODIFIED PACKAGES OR FORENSIC TRACES DETECTED[/bold yellow]", border_style="yellow"))
    else:
        console.print(Panel("[bold red]CRITICAL THREAT - ACTIVE CHEAT INJECTIONS / GHOST CLIENTS IDENTIFIED[/bold red]", border_style="red"))

    results_data = {
        "highest_risk": highest_risk,
        "total_mods": len(mod_files),
        "flagged_mods": len(mod_detections),
        "ram_hits": ram_hits,
        "forensic_hits": forensic_hits,
        "tampering_hits": tamper_hits,
        "mod_detections": mod_detections,
        "all_mods": all_mods_info
    }

    # Save to database
    db.save_scan(
        total_files=len(mod_files),
        flagged_files=len(mod_detections),
        highest_risk=highest_risk,
        platform="Windows" if os.name == "nt" else "Linux/Other",
        detections=mod_detections,
        ram_threats=len(ram_hits),
        forensic_threats=len(forensic_hits) + len(tamper_hits)
    )

    # Export
    if args.export:
        if args.export == "html":
            out_file = f"{args.out}.html"
            ReportGenerator.export_html(results_data, out_file)
            console.print(f"[green][+] Forensic Report exported: [bold]{out_file}[/bold][/green]")
        elif args.export == "json":
            out_file = f"{args.out}.json"
            ReportGenerator.export_json(results_data, out_file)
            console.print(f"[green][+] JSON export saved: [bold]{out_file}[/bold][/green]")

def main():
    parser = argparse.ArgumentParser(description="ANSH9BOSS CheatsAnalyzer - Tournament Minecraft Forensic Suite")
    parser.add_argument("path", nargs="?", help="Specific directory or .jar file to scan")
    parser.add_argument("--cli", action="store_true", help="Force command-line interface mode instead of Glassmorphism GUI")
    parser.add_argument("--export", choices=["html", "json"], default="html", help="Export format")
    parser.add_argument("--out", default="screenshare_audit_report", help="Output file basename")
    parser.add_argument("--no-telemetry", action="store_true", help="Disable telemetry")
    args = parser.parse_args()

    config = load_config()

    # Launch GUI by default unless --cli is specified or running headless
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
