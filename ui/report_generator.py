import json
import os
from datetime import datetime
from pathlib import Path

class ReportGenerator:
    """Generates tournament-grade forensic HTML, JSON, and Text reports."""

    @staticmethod
    def export_html(results, output_path="screenshare_audit_report.html"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        highest_risk = results.get("highest_risk", "CLEAN")
        total_mods = results.get("total_mods", 0)
        flagged_mods = results.get("flagged_mods", 0)
        ram_hits = results.get("ram_hits", [])
        forensic_hits = results.get("forensic_hits", [])
        tampering_hits = results.get("tampering_hits", [])
        mod_detections = results.get("mod_detections", [])

        badge_color = "#00E676" if highest_risk == "CLEAN" else ("#FFD600" if highest_risk == "SUSPICIOUS" else "#FF1744")

        # HTML generation with Glassmorphism CSS
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ANSH9BOSS - Forensic Cheat Detection Report</title>
    <style>
        :root {{
            --bg: #0b0e14;
            --panel: rgba(21, 27, 38, 0.85);
            --border: rgba(33, 43, 59, 0.8);
            --accent: #00f2fe;
            --danger: #ff1744;
            --warning: #ffd600;
            --success: #00e676;
            --text: #f0f6fc;
            --muted: #8b949e;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; }}
        body {{ background-color: var(--bg); color: var(--text); padding: 40px 20px; }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        .header {{ background: var(--panel); border: 1px solid var(--border); backdrop-filter: blur(12px); border-radius: 16px; padding: 30px; margin-bottom: 25px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 8px 32px rgba(0,0,0,0.4); }}
        .header h1 {{ font-size: 26px; color: var(--accent); letter-spacing: 1px; }}
        .header p {{ color: var(--muted); font-size: 14px; margin-top: 5px; }}
        .verdict-badge {{ padding: 10px 24px; border-radius: 30px; font-weight: bold; font-size: 16px; background: {badge_color}22; color: {badge_color}; border: 1px solid {badge_color}; text-transform: uppercase; }}
        .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 15px; margin-bottom: 25px; }}
        .metric-card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 20px; backdrop-filter: blur(8px); text-align: center; }}
        .metric-card .val {{ font-size: 28px; font-weight: bold; color: var(--text); margin-top: 5px; }}
        .metric-card .label {{ font-size: 13px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }}
        .section-title {{ font-size: 20px; font-weight: 600; margin: 30px 0 15px 5px; color: var(--accent); }}
        .item-card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 18px 22px; margin-bottom: 12px; }}
        .item-card.critical {{ border-left: 4px solid var(--danger); }}
        .item-card.suspicious {{ border-left: 4px solid var(--warning); }}
        .item-card.clean {{ border-left: 4px solid var(--success); }}
        .item-title {{ font-size: 16px; font-weight: bold; display: flex; justify-content: space-between; margin-bottom: 6px; }}
        .item-desc {{ font-size: 14px; color: #c9d1d9; line-height: 1.5; }}
        .item-sub {{ font-size: 12px; color: var(--muted); margin-top: 6px; }}
        .empty-alert {{ color: var(--success); font-size: 14px; padding: 12px; background: rgba(0, 230, 118, 0.08); border-radius: 8px; border: 1px solid rgba(0, 230, 118, 0.2); }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>ANSH9BOSS CHEAT ANALYZER</h1>
                <p>Tournament Forensic Audit Report &bull; {timestamp}</p>
            </div>
            <div class="verdict-badge">{highest_risk}</div>
        </div>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="label">Total Mods Analyzed</div>
                <div class="val">{total_mods}</div>
            </div>
            <div class="metric-card">
                <div class="label">Flagged Threat Mods</div>
                <div class="val" style="color: {'#ff1744' if flagged_mods > 0 else '#00e676'}">{flagged_mods}</div>
            </div>
            <div class="metric-card">
                <div class="label">Live RAM Threat Hits</div>
                <div class="val" style="color: {'#ff1744' if len(ram_hits) > 0 else '#00e676'}">{len(ram_hits)}</div>
            </div>
            <div class="metric-card">
                <div class="label">Forensic Traces Found</div>
                <div class="val" style="color: {'#ffd600' if len(forensic_hits) > 0 else '#00e676'}">{len(forensic_hits) + len(tampering_hits)}</div>
            </div>
        </div>

        <div class="section-title">🧠 Win32 Live Memory & Process Injections</div>
        <div>
"""
        if ram_hits:
            for hit in ram_hits:
                html_content += f"""
            <div class="item-card critical">
                <div class="item-title">
                    <span>{hit.get('detail', 'Memory Hook Injection')}</span>
                    <span style="color: var(--danger);">CRITICAL INJECTION</span>
                </div>
                <div class="item-desc">Process PID: {hit.get('pid', 'N/A')} &bull; Memory Address: {hit.get('address', 'N/A')}</div>
            </div>"""
        else:
            html_content += '<div class="empty-alert">&check; No active ghost client memory signatures or unlinked DLL hooks found in JVM RAM.</div>'

        html_content += """
        </div>

        <div class="section-title">📦 Mod Files & Bytecode Inspection</div>
        <div>
"""
        if mod_detections:
            for det in mod_detections:
                risk_cls = "critical" if det.get("risk_level") == "DANGEROUS" else "suspicious"
                details = " | ".join(det.get("matched_details", [])) if isinstance(det.get("matched_details"), list) else det.get("matched_details", "")
                html_content += f"""
            <div class="item-card {risk_cls}">
                <div class="item-title">
                    <span>{det.get('file_name', 'Unknown Mod')}</span>
                    <span style="color: {'var(--danger)' if risk_cls == 'critical' else 'var(--warning)'};">{det.get('risk_level', 'SUSPICIOUS')}</span>
                </div>
                <div class="item-desc">{details}</div>
                <div class="item-sub">Triggered: {det.get('detection_layer', 'Scanner')} &bull; Path: {det.get('file_path', '')}</div>
            </div>"""
        else:
            html_content += '<div class="empty-alert">&check; All scanned mod files passed Modrinth verification and bytecode threat scanning cleanly.</div>'

        html_content += """
        </div>

        <div class="section-title">🛡️ Anti-Self-Destruct & System Forensics</div>
        <div>
"""
        all_sys = forensic_hits + tampering_hits
        if all_sys:
            for trace in all_sys:
                html_content += f"""
            <div class="item-card suspicious">
                <div class="item-title">
                    <span>{trace.get('type', 'Forensic Evidence')}</span>
                    <span style="color: var(--warning);">{trace.get('risk', 'SUSPICIOUS')}</span>
                </div>
                <div class="item-desc">{trace.get('detail', '')}</div>
            </div>"""
        else:
            html_content += '<div class="empty-alert">&check; No USB storage injection traces, BAM anomalies, or event log wipes detected.</div>'

        html_content += """
        </div>
    </div>
</body>
</html>
"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return output_path

    @staticmethod
    def export_json(results, output_path="screenshare_audit_report.json"):
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4)
        return output_path
