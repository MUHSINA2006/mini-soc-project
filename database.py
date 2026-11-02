import sqlite3
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "soc_events.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                event_type TEXT NOT NULL,
                username TEXT,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open'
            )
        """)


def add_event(
    source_ip,
    event_type,
    username="unknown",
    severity="LOW",
    description="Security event recorded"
):
    timestamp = datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    )

    with get_connection() as conn:
        cursor = conn.execute("""
            INSERT INTO security_events (
                timestamp,
                source_ip,
                event_type,
                username,
                severity,
                description
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            timestamp,
            source_ip,
            event_type,
            username,
            severity,
            description
        ))

        return cursor.lastrowid


def get_events(limit=500):
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT *
            FROM security_events
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

        return [dict(row) for row in rows]


def get_event_by_id(event_id):
    with get_connection() as conn:
        row = conn.execute("""
            SELECT *
            FROM security_events
            WHERE id = ?
        """, (event_id,)).fetchone()

        return dict(row) if row else None


def update_event_status(event_id, status):
    with get_connection() as conn:
        cursor = conn.execute("""
            UPDATE security_events
            SET status = ?
            WHERE id = ?
        """, (status, event_id))

        return cursor.rowcount > 0


def get_statistics():
    with get_connection() as conn:
        total = conn.execute("""
            SELECT COUNT(*) FROM security_events
        """).fetchone()[0]

        failed_logins = conn.execute("""
            SELECT COUNT(*)
            FROM security_events
            WHERE event_type = 'FAILED_LOGIN'
        """).fetchone()[0]

        critical = conn.execute("""
            SELECT COUNT(*)
            FROM security_events
            WHERE severity = 'CRITICAL'
        """).fetchone()[0]

        suspicious_ips = conn.execute("""
            SELECT COUNT(DISTINCT source_ip)
            FROM security_events
            WHERE severity IN ('HIGH', 'CRITICAL')
        """).fetchone()[0]

        severity_rows = conn.execute("""
            SELECT severity, COUNT(*) AS count
            FROM security_events
            GROUP BY severity
        """).fetchall()

        severity_counts = {
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0,
            "CRITICAL": 0
        }

        for row in severity_rows:
            severity_counts[row["severity"]] = row["count"]

        timeline_rows = conn.execute("""
            SELECT substr(timestamp, 1, 10) AS day,
                   COUNT(*) AS count
            FROM security_events
            GROUP BY day
            ORDER BY day DESC
            LIMIT 7
        """).fetchall()

        timeline = [
            {"day": row["day"], "count": row["count"]}
            for row in reversed(timeline_rows)
        ]

        return {
            "total_events": total,
            "failed_logins": failed_logins,
            "critical_alerts": critical,
            "suspicious_ips": suspicious_ips,
            "severity_counts": severity_counts,
            "timeline": timeline
        }


def export_events():
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT id, timestamp, source_ip, event_type,
                   username, severity, description, status
            FROM security_events
            ORDER BY id DESC
        """).fetchall()

        return [dict(row) for row in rows]