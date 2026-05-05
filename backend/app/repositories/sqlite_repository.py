"""
============================================
BLACK WALL — SQLite Repository
============================================
Lightweight SQLite storage for critical alerts (level ≥ 12).
Separate from PostgreSQL to allow independent operation.

Responsibilities:
  - Store critical alerts with AI analysis
  - Deduplicate via SHA-256 hashing
  - Track email notification status
"""

import os
import sqlite3
import hashlib
import logging
from datetime import datetime, timezone
from threading import Lock

logger = logging.getLogger(__name__)

# SQLite file location — next to the backend code
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "critical_alerts.db")
DB_PATH = os.path.normpath(DB_PATH)

_db_lock = Lock()


class SQLiteRepository:
    """Thread-safe SQLite storage for critical alerts."""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path

    def init_db(self) -> None:
        """Create the critical_alerts table if it doesn't exist."""
        with _db_lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS critical_alerts (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_hash   TEXT UNIQUE,
                    description  TEXT,
                    level        INTEGER,
                    agent        TEXT,
                    timestamp    TEXT,
                    raw_log      TEXT,
                    ai_analysis  TEXT,
                    notified     INTEGER DEFAULT 0,
                    created_at   TEXT DEFAULT (datetime('now'))
                )
            """)
            conn.commit()
            conn.close()
        logger.info("✅ SQLite critical alerts DB initialized at %s", self.db_path)

    # ── Hashing & Deduplication ──

    @staticmethod
    def compute_alert_hash(description: str, agent: str, timestamp: str) -> str:
        """Generate a SHA-256 hash for deduplication."""
        content = f"{description}|{agent}|{timestamp}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def is_duplicate(self, alert_hash: str) -> bool:
        """Check if an alert with this hash already exists."""
        with _db_lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) FROM critical_alerts WHERE alert_hash = ?",
                (alert_hash,),
            )
            count = cursor.fetchone()[0]
            conn.close()
        return count > 0

    # ── CRUD Operations ──

    def save_critical_alert(self, alert_data: dict) -> bool:
        """
        Save a critical alert. Returns True if inserted, False if duplicate.
        """
        alert_hash = self.compute_alert_hash(
            alert_data.get("description", ""),
            alert_data.get("agent", ""),
            alert_data.get("timestamp", ""),
        )

        if self.is_duplicate(alert_hash):
            return False

        with _db_lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    INSERT INTO critical_alerts
                        (alert_hash, description, level, agent, timestamp,
                         raw_log, ai_analysis, notified)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert_hash,
                    alert_data.get("description", ""),
                    alert_data.get("level", 0),
                    alert_data.get("agent", ""),
                    alert_data.get("timestamp", ""),
                    alert_data.get("raw_log", ""),
                    alert_data.get("ai_analysis", None),
                    1 if alert_data.get("notified", False) else 0,
                ))
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False
            finally:
                conn.close()

    def get_critical_alerts(self, limit: int = 50) -> list[dict]:
        """Retrieve the most recent critical alerts."""
        with _db_lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM critical_alerts ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
            rows = cursor.fetchall()
            conn.close()
        return [dict(row) for row in rows]

    def get_last_notified_time(self, description: str) -> str | None:
        """Get timestamp of last email notification for this alert type."""
        with _db_lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT created_at FROM critical_alerts
                WHERE description = ? AND notified = 1
                ORDER BY created_at DESC LIMIT 1
            """, (description,))
            row = cursor.fetchone()
            conn.close()
        return row[0] if row else None

    def get_stats(self) -> dict:
        """Aggregated statistics for critical alerts."""
        with _db_lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM critical_alerts")
            total = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM critical_alerts WHERE notified = 1")
            notified = cursor.fetchone()[0]

            cursor.execute("""
                SELECT agent, COUNT(*) as cnt FROM critical_alerts
                GROUP BY agent ORDER BY cnt DESC
            """)
            by_agent = {row[0]: row[1] for row in cursor.fetchall()}

            cursor.execute("""
                SELECT level, COUNT(*) as cnt FROM critical_alerts
                GROUP BY level ORDER BY level DESC
            """)
            by_level = {row[0]: row[1] for row in cursor.fetchall()}

            cursor.execute("""
                SELECT COUNT(*) FROM critical_alerts
                WHERE ai_analysis IS NOT NULL AND ai_analysis != ''
            """)
            with_ai = cursor.fetchone()[0]

            conn.close()

        return {
            "total_critical_alerts": total,
            "total_notified": notified,
            "total_with_ai_analysis": with_ai,
            "by_agent": by_agent,
            "by_level": by_level,
        }


# ── Module-level singleton ──
sqlite_repo = SQLiteRepository()
