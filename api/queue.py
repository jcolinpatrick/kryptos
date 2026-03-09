"""SQLite-backed queue for novel theories awaiting evaluation."""

import hashlib
import sqlite3
import time
from datetime import datetime, timezone
from typing import Optional


import os as _os

DB_PATH = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "db", "theory_queue.sqlite")


def _get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Open a SQLite connection with WAL mode."""
    path = db_path or DB_PATH
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """Create the theories and rate_limits tables if they do not exist."""
    conn = _get_connection(db_path)
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS theories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                theory_text TEXT NOT NULL,
                ip_hash TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending'
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS rate_limits (
                ip_hash TEXT NOT NULL,
                ts REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_rate_limits_ip_ts
            ON rate_limits (ip_hash, ts)
        """)
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Rate limiting (persistent)
# ---------------------------------------------------------------------------

def record_request(ip: str, window: int, max_requests: int,
                   db_path: Optional[str] = None) -> Optional[int]:
    """Record a request and check the rate limit.

    Returns None if under the limit, or seconds until the oldest request
    in the window expires if the limit is exceeded.
    """
    ip_hash = hashlib.sha256(ip.encode()).hexdigest()
    now = time.time()
    cutoff = now - window

    conn = _get_connection(db_path)
    try:
        # Prune expired entries (all IPs, keeps table small)
        conn.execute("DELETE FROM rate_limits WHERE ts <= ?", (cutoff,))

        # Count requests in window for this IP
        row = conn.execute(
            "SELECT COUNT(*) FROM rate_limits WHERE ip_hash = ? AND ts > ?",
            (ip_hash, cutoff),
        ).fetchone()
        count = row[0]

        if count >= max_requests:
            # Find the oldest timestamp to compute retry-after
            oldest = conn.execute(
                "SELECT MIN(ts) FROM rate_limits WHERE ip_hash = ? AND ts > ?",
                (ip_hash, cutoff),
            ).fetchone()
            conn.commit()
            retry_after = int(oldest[0] - cutoff) + 1
            return max(retry_after, 1)

        # Record this request
        conn.execute(
            "INSERT INTO rate_limits (ip_hash, ts) VALUES (?, ?)",
            (ip_hash, now),
        )
        conn.commit()
        return None
    finally:
        conn.close()


def add_theory(theory_text: str, ip_address: str, db_path: Optional[str] = None) -> int:
    """Insert a new pending theory and return its queue position.

    The IP address is SHA-256 hashed before storage.
    Queue position is the count of pending theories after insertion.
    """
    ip_hash = hashlib.sha256(ip_address.encode()).hexdigest()
    now = datetime.now(timezone.utc).isoformat()

    conn = _get_connection(db_path)
    try:
        conn.execute(
            "INSERT INTO theories (theory_text, ip_hash, timestamp, status) VALUES (?, ?, ?, 'pending')",
            (theory_text, ip_hash, now),
        )
        conn.commit()

        row = conn.execute("SELECT COUNT(*) FROM theories WHERE status = 'pending'").fetchone()
        return row[0]
    finally:
        conn.close()


def get_pending(db_path: Optional[str] = None) -> list[dict]:
    """Return all pending theories ordered by submission time."""
    conn = _get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT id, theory_text, ip_hash, timestamp, status FROM theories WHERE status = 'pending' ORDER BY timestamp ASC"
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def update_status(theory_id: int, new_status: str, db_path: Optional[str] = None) -> None:
    """Update the status of a theory. Valid statuses: pending, testing, published, rejected."""
    valid = {"pending", "testing", "published", "rejected"}
    if new_status not in valid:
        raise ValueError(f"Invalid status '{new_status}'. Must be one of: {valid}")

    conn = _get_connection(db_path)
    try:
        conn.execute("UPDATE theories SET status = ? WHERE id = ?", (new_status, theory_id))
        conn.commit()
    finally:
        conn.close()
