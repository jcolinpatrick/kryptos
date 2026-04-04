"""SQLite-backed queue for novel theories awaiting evaluation."""

import hashlib
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from typing import Optional


import os as _os

DB_PATH = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))), "db", "theory_queue.sqlite")


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
                status TEXT NOT NULL DEFAULT 'pending',
                token TEXT,
                result_note TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS rate_limits (
                ip_hash TEXT NOT NULL,
                ts REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS classification_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip_hash TEXT NOT NULL,
                theory_preview TEXT NOT NULL,
                status TEXT NOT NULL,
                elimination_id TEXT,
                feasibility TEXT
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_rate_limits_ip_ts
            ON rate_limits (ip_hash, ts)
        """)
        # Migrate existing tables: add token and result_note if missing
        cols = {row[1] for row in conn.execute("PRAGMA table_info(theories)").fetchall()}
        if "token" not in cols:
            conn.execute("ALTER TABLE theories ADD COLUMN token TEXT")
        if "result_note" not in cols:
            conn.execute("ALTER TABLE theories ADD COLUMN result_note TEXT")
        # Index must be created after migration ensures column exists
        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_theories_token
            ON theories (token)
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


def add_theory(theory_text: str, ip_address: str, db_path: Optional[str] = None) -> tuple[int, str]:
    """Insert a new pending theory and return (queue_position, token).

    The IP address is SHA-256 hashed before storage.
    Queue position is the count of pending theories after insertion.
    Token is a 16-byte random hex string for status lookups.
    """
    ip_hash = hashlib.sha256(ip_address.encode()).hexdigest()
    now = datetime.now(timezone.utc).isoformat()
    token = secrets.token_hex(16)

    conn = _get_connection(db_path)
    try:
        conn.execute(
            "INSERT INTO theories (theory_text, ip_hash, timestamp, status, token) VALUES (?, ?, ?, 'pending', ?)",
            (theory_text, ip_hash, now, token),
        )
        conn.commit()

        row = conn.execute("SELECT COUNT(*) FROM theories WHERE status = 'pending'").fetchone()
        return row[0], token
    finally:
        conn.close()


def get_pending(db_path: Optional[str] = None) -> list[dict]:
    """Return all pending theories ordered by submission time."""
    conn = _get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT id, theory_text, ip_hash, timestamp, status, token FROM theories WHERE status = 'pending' ORDER BY timestamp ASC"
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def update_status(theory_id: int, new_status: str, note: str = "",
                   db_path: Optional[str] = None) -> None:
    """Update the status of a theory. Valid statuses: pending, testing, published, rejected.

    An optional note is stored in result_note (visible to the submitter via their token).
    """
    valid = {"pending", "testing", "published", "rejected"}
    if new_status not in valid:
        raise ValueError(f"Invalid status '{new_status}'. Must be one of: {valid}")

    conn = _get_connection(db_path)
    try:
        if note:
            conn.execute(
                "UPDATE theories SET status = ?, result_note = ? WHERE id = ?",
                (new_status, note, theory_id),
            )
        else:
            conn.execute("UPDATE theories SET status = ? WHERE id = ?", (new_status, theory_id))
        conn.commit()
    finally:
        conn.close()


def log_classification(
    ip_address: str,
    theory_text: str,
    status: str,
    elimination_id: Optional[str] = None,
    feasibility: Optional[str] = None,
    db_path: Optional[str] = None,
) -> None:
    """Log a classification result for analytics.

    Tracks all submissions — matched, novel, rejected — so we can measure
    how often users propose already-tested ideas (site effectiveness metric).
    """
    ip_hash = hashlib.sha256(ip_address.encode()).hexdigest()
    now = datetime.now(timezone.utc).isoformat()
    preview = theory_text[:300]

    conn = _get_connection(db_path)
    try:
        conn.execute(
            "INSERT INTO classification_log (timestamp, ip_hash, theory_preview, status, elimination_id, feasibility) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (now, ip_hash, preview, status, elimination_id or "", feasibility or ""),
        )
        conn.commit()
    finally:
        conn.close()


def get_classification_stats(db_path: Optional[str] = None) -> dict:
    """Return aggregate classification statistics.

    Returns counts by status (matched, novel, rejected) and the most
    frequently matched elimination IDs.
    """
    conn = _get_connection(db_path)
    try:
        # Overall counts by status
        rows = conn.execute(
            "SELECT status, COUNT(*) as cnt FROM classification_log GROUP BY status"
        ).fetchall()
        by_status = {row["status"]: row["cnt"] for row in rows}

        # Top matched elimination IDs
        top_matched = conn.execute(
            "SELECT elimination_id, COUNT(*) as cnt FROM classification_log "
            "WHERE status = 'matched' AND elimination_id != '' "
            "GROUP BY elimination_id ORDER BY cnt DESC LIMIT 20"
        ).fetchall()

        # Recent matched submissions (last 50)
        recent = conn.execute(
            "SELECT timestamp, theory_preview, status, elimination_id, feasibility "
            "FROM classification_log ORDER BY id DESC LIMIT 50"
        ).fetchall()

        return {
            "total": sum(by_status.values()),
            "by_status": by_status,
            "top_matched_eliminations": [
                {"elimination_id": r["elimination_id"], "count": r["cnt"]}
                for r in top_matched
            ],
            "recent": [dict(r) for r in recent],
        }
    finally:
        conn.close()


def get_by_token(token: str, db_path: Optional[str] = None) -> Optional[dict]:
    """Look up a theory by its submission token. Returns None if not found."""
    conn = _get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT id, theory_text, timestamp, status, result_note FROM theories WHERE token = ?",
            (token,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()
