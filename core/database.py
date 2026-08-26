import sqlite3
import json
import os
from pathlib import Path
from datetime import datetime

class ForensicDB:
    def __init__(self, db_path=None):
        if db_path is None:
            base_dir = Path(__file__).resolve().parent.parent
            data_dir = base_dir / "data"
            data_dir.mkdir(exist_ok=True)
            self.db_path = data_dir / "ansh9boss.db"
        else:
            self.db_path = Path(db_path)
            self.db_path.parent.mkdir(exist_ok=True)
        self.init_db()

    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            total_files INTEGER,
            flagged_files INTEGER,
            highest_risk TEXT,
            platform TEXT,
            ram_threats INTEGER DEFAULT 0,
            forensic_threats INTEGER DEFAULT 0
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            file_name TEXT,
            file_path TEXT,
            risk_level TEXT,
            detection_layer TEXT,
            matched_details TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS hash_whitelist (
            sha1 TEXT PRIMARY KEY,
            project_id TEXT,
            version_title TEXT,
            is_clean INTEGER,
            checked_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """)

        conn.commit()
        conn.close()

    def save_scan(self, total_files, flagged_files, highest_risk, platform, detections, ram_threats=0, forensic_threats=0):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO scans 
                   (total_files, flagged_files, highest_risk, platform, ram_threats, forensic_threats) 
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (total_files, flagged_files, highest_risk, platform, ram_threats, forensic_threats)
            )
            scan_id = cursor.lastrowid

            for det in detections:
                details = det.get("matched_details", "")
                if isinstance(details, list):
                    details = " | ".join(details)
                cursor.execute(
                    """INSERT INTO detections 
                       (scan_id, file_name, file_path, risk_level, detection_layer, matched_details) 
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        scan_id,
                        det.get("file_name", "Unknown"),
                        det.get("file_path", ""),
                        det.get("risk_level", "SUSPICIOUS"),
                        det.get("detection_layer", "Engine"),
                        details
                    )
                )

            conn.commit()
            conn.close()
            return scan_id
        except Exception as e:
            print(f"[DB Error] Failed to save scan: {e}")
            return None

    def get_whitelist_cache(self, sha1):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT is_clean, version_title FROM hash_whitelist WHERE sha1 = ?", (sha1.lower(),))
            row = cursor.fetchone()
            conn.close()
            if row:
                return bool(row[0]), row[1]
            return None, None
        except Exception:
            return None, None

    def cache_whitelist(self, sha1, project_id, version_title, is_clean):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO hash_whitelist (sha1, project_id, version_title, is_clean) VALUES (?, ?, ?, ?)",
                (sha1.lower(), project_id, version_title, 1 if is_clean else 0)
            )
            conn.commit()
            conn.close()
        except Exception:
            pass
