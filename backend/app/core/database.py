import asyncio
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional
from backend.app.core.config import settings
from backend.app.core.logger import get_logger

logger = get_logger("database")

class DatabaseManager:
    """
    Non-blocking thread-pool SQLite persistence manager for AegisForge workbench.
    Stores scenario histories, port scans, fuzzing campaigns, and malware triage reports.
    """
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or (settings.BASE_DIR / "data" / "aegisforge.db")
        self._lock = asyncio.Lock()
        self._initialized = False

    def _sync_create_tables(self, conn: sqlite3.Connection):
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scenario_runs (
                scenario_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT NOT NULL,
                status TEXT NOT NULL,
                total_steps INTEGER NOT NULL,
                steps_json TEXT NOT NULL,
                final_summary TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                scan_duration_ms REAL NOT NULL,
                open_ports_count INTEGER NOT NULL,
                open_ports_json TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS fuzz_campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                total_cases_run INTEGER NOT NULL,
                crashes_detected INTEGER NOT NULL,
                crashes_json TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS triage_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                file_type TEXT NOT NULL,
                entropy REAL NOT NULL,
                risk_score REAL NOT NULL,
                verdict TEXT NOT NULL,
                yara_matches_count INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.commit()

    def _get_connection(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        if not self._initialized:
            self._sync_create_tables(conn)
            self._initialized = True
        return conn

    def _sync_init_db(self):
        with self._get_connection():
            pass

    async def init_db(self):
        """Initializes database schema asynchronously."""
        await asyncio.to_thread(self._sync_init_db)
        logger.info("SQLite persistence database initialized at %s", self.db_path)

    # -------------------------------------------------------------
    # Scenario Runs
    # -------------------------------------------------------------
    def _sync_save_scenario(self, scenario_dict: Dict[str, Any]):
        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO scenario_runs 
                (scenario_id, title, started_at, completed_at, status, total_steps, steps_json, final_summary)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                scenario_dict["scenario_id"],
                scenario_dict.get("scenario_title", "Purple-Team Exercise"),
                scenario_dict["started_at"],
                scenario_dict["completed_at"],
                scenario_dict["status"],
                scenario_dict["total_steps"],
                json.dumps(scenario_dict.get("steps", [])),
                scenario_dict.get("final_report_summary", "")
            ))
            conn.commit()

    async def save_scenario(self, scenario_dict: Dict[str, Any]):
        async with self._lock:
            await asyncio.to_thread(self._sync_save_scenario, scenario_dict)

    def _sync_get_scenarios(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM scenario_runs ORDER BY created_at DESC LIMIT ?", (limit,)
            )
            rows = cursor.fetchall()
            results = []
            for r in rows:
                results.append({
                    "scenario_id": r["scenario_id"],
                    "scenario_title": r["title"],
                    "started_at": r["started_at"],
                    "completed_at": r["completed_at"],
                    "status": r["status"],
                    "total_steps": r["total_steps"],
                    "steps": json.loads(r["steps_json"]),
                    "final_report_summary": r["final_summary"]
                })
            return results

    async def get_scenarios(self, limit: int = 20) -> List[Dict[str, Any]]:
        return await asyncio.to_thread(self._sync_get_scenarios, limit)

    # -------------------------------------------------------------
    # Port Scans
    # -------------------------------------------------------------
    def _sync_save_scan(self, target: str, duration_ms: float, open_ports: List[Any]):
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO scan_records (target, scan_duration_ms, open_ports_count, open_ports_json)
                VALUES (?, ?, ?, ?);
            """, (
                target,
                duration_ms,
                len(open_ports),
                json.dumps([p if isinstance(p, dict) else p.model_dump() for p in open_ports])
            ))
            conn.commit()

    async def save_scan(self, target: str, duration_ms: float, open_ports: List[Any]):
        async with self._lock:
            await asyncio.to_thread(self._sync_save_scan, target, duration_ms, open_ports)

    # -------------------------------------------------------------
    # Fuzzing Campaigns
    # -------------------------------------------------------------
    def _sync_save_fuzz(self, target: str, total_cases: int, crashes: List[Any]):
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO fuzz_campaigns (target, total_cases_run, crashes_detected, crashes_json)
                VALUES (?, ?, ?, ?);
            """, (
                target,
                total_cases,
                len(crashes),
                json.dumps([c if isinstance(c, dict) else c.model_dump() for c in crashes])
            ))
            conn.commit()

    async def save_fuzz(self, target: str, total_cases: int, crashes: List[Any]):
        async with self._lock:
            await asyncio.to_thread(self._sync_save_fuzz, target, total_cases, crashes)

    # -------------------------------------------------------------
    # Malware Triage
    # -------------------------------------------------------------
    def _sync_save_triage(self, filename: str, file_type: str, entropy: float, risk_score: float, verdict: str, yara_count: int):
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO triage_reports (filename, file_type, entropy, risk_score, verdict, yara_matches_count)
                VALUES (?, ?, ?, ?, ?, ?);
            """, (filename, file_type, entropy, risk_score, verdict, yara_count))
            conn.commit()

    async def save_triage(self, filename: str, file_type: str, entropy: float, risk_score: float, verdict: str, yara_count: int):
        async with self._lock:
            await asyncio.to_thread(self._sync_save_triage, filename, file_type, entropy, risk_score, verdict, yara_count)

db = DatabaseManager()
