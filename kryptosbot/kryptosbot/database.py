"""
Persistent storage for KryptosBot.

Tracks every hypothesis, its status, evidence, disproof records,
and agent session IDs so the system can resume across restarts.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

from .config import HypothesisStatus


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ResultsDB:
    """
    Thread-safe SQLite store for KryptosBot results.

    Each hypothesis gets a row in `hypotheses`. Detailed output and evidence
    go into `evidence`. Session bookkeeping lives in `sessions`.
    """

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self._init_schema()

    # ------------------------------------------------------------------
    # Connection helpers
    # ------------------------------------------------------------------

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(str(self.db_path), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")   # safe concurrent reads
        conn.execute("PRAGMA busy_timeout=10000")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS hypotheses (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    strategy    TEXT NOT NULL,
                    category    TEXT NOT NULL,
                    status      TEXT NOT NULL DEFAULT 'queued',
                    priority    INTEGER NOT NULL DEFAULT 5,
                    created_at  TEXT NOT NULL,
                    updated_at  TEXT NOT NULL,
                    summary     TEXT DEFAULT '',
                    score       REAL DEFAULT 0.0,
                    best_plaintext TEXT DEFAULT '',
                    tags        TEXT DEFAULT '[]',
                    worker_id   TEXT DEFAULT '',
                    session_id  TEXT DEFAULT '',
                    error       TEXT DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS evidence (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    hypothesis_id  INTEGER NOT NULL REFERENCES hypotheses(id),
                    evidence_type  TEXT NOT NULL,
                    content        TEXT NOT NULL,
                    created_at     TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    session_id  TEXT PRIMARY KEY,
                    strategy    TEXT NOT NULL,
                    worker_id   TEXT NOT NULL,
                    started_at  TEXT NOT NULL,
                    finished_at TEXT DEFAULT '',
                    status      TEXT NOT NULL DEFAULT 'running'
                );

                CREATE TABLE IF NOT EXISTS disproof_log (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    strategy       TEXT NOT NULL,
                    category       TEXT NOT NULL,
                    criteria       TEXT NOT NULL,
                    evidence       TEXT NOT NULL,
                    disproved_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_hyp_status ON hypotheses(status);
                CREATE INDEX IF NOT EXISTS idx_hyp_strategy ON hypotheses(strategy);
                CREATE INDEX IF NOT EXISTS idx_evidence_hyp ON evidence(hypothesis_id);
            """)

    # ------------------------------------------------------------------
    # Hypothesis CRUD
    # ------------------------------------------------------------------

    def create_hypothesis(
        self,
        strategy: str,
        category: str,
        priority: int = 5,
        tags: list[str] | None = None,
    ) -> int:
        """Insert a new hypothesis and return its ID."""
        now = _now_iso()
        with self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO hypotheses
                   (strategy, category, priority, tags, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (strategy, category, priority, json.dumps(tags or []), now, now),
            )
            return cur.lastrowid  # type: ignore[return-value]

    def update_hypothesis(self, hyp_id: int, **fields: Any) -> None:
        """Update arbitrary fields on a hypothesis row."""
        fields["updated_at"] = _now_iso()
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        values = list(fields.values()) + [hyp_id]
        with self._connect() as conn:
            conn.execute(
                f"UPDATE hypotheses SET {set_clause} WHERE id = ?", values
            )

    def get_hypothesis(self, hyp_id: int) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM hypotheses WHERE id = ?", (hyp_id,)
            ).fetchone()
            return dict(row) if row else None

    def get_by_status(self, status: HypothesisStatus) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM hypotheses WHERE status = ? ORDER BY priority ASC",
                (status.value,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_by_strategy(self, strategy: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM hypotheses WHERE strategy = ? ORDER BY created_at DESC",
                (strategy,),
            ).fetchall()
            return [dict(r) for r in rows]

    def is_strategy_disproved(self, strategy: str) -> bool:
        """Check if a strategy has already been conclusively disproved."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) as cnt FROM hypotheses WHERE strategy = ? AND status = ?",
                (strategy, HypothesisStatus.DISPROVED.value),
            ).fetchone()
            return row["cnt"] > 0 if row else False

    def has_completed_run(self, strategy: str) -> bool:
        """
        Check if a strategy already has a completed (non-error) run.

        A run counts as completed if its status is disproved, promising,
        or inconclusive AND it has no error recorded. This prevents
        re-dispatching strategies that already produced results.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) as cnt FROM hypotheses "
                "WHERE strategy = ? "
                "AND status IN (?, ?, ?) "
                "AND (error = '' OR error IS NULL)",
                (
                    strategy,
                    HypothesisStatus.DISPROVED.value,
                    HypothesisStatus.PROMISING.value,
                    HypothesisStatus.INCONCLUSIVE.value,
                ),
            ).fetchone()
            return row["cnt"] > 0 if row else False

    # ------------------------------------------------------------------
    # Evidence
    # ------------------------------------------------------------------

    def add_evidence(
        self, hyp_id: int, evidence_type: str, content: str
    ) -> int:
        now = _now_iso()
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO evidence (hypothesis_id, evidence_type, content, created_at) VALUES (?, ?, ?, ?)",
                (hyp_id, evidence_type, content, now),
            )
            return cur.lastrowid  # type: ignore[return-value]

    def get_evidence(self, hyp_id: int) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM evidence WHERE hypothesis_id = ? ORDER BY created_at",
                (hyp_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Disproof log
    # ------------------------------------------------------------------

    def log_disproof(
        self, strategy: str, category: str, criteria: str, evidence: str
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO disproof_log (strategy, category, criteria, evidence, disproved_at) VALUES (?, ?, ?, ?, ?)",
                (strategy, category, criteria, evidence, _now_iso()),
            )

    def get_disproof_log(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM disproof_log ORDER BY disproved_at DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Session tracking
    # ------------------------------------------------------------------

    def register_session(
        self, session_id: str, strategy: str, worker_id: str
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO sessions (session_id, strategy, worker_id, started_at, status) VALUES (?, ?, ?, ?, 'running')",
                (session_id, strategy, worker_id, _now_iso()),
            )

    def finish_session(self, session_id: str, status: str = "completed") -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE sessions SET finished_at = ?, status = ? WHERE session_id = ?",
                (_now_iso(), status, session_id),
            )

    def get_running_sessions(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM sessions WHERE status = 'running'"
            ).fetchall()
            return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def summary_report(self) -> dict[str, Any]:
        """Generate a high-level status report."""
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) as n FROM hypotheses").fetchone()["n"]
            by_status = {}
            for row in conn.execute(
                "SELECT status, COUNT(*) as n FROM hypotheses GROUP BY status"
            ):
                by_status[row["status"]] = row["n"]

            best = conn.execute(
                "SELECT strategy, score, best_plaintext FROM hypotheses "
                "WHERE status IN ('promising', 'solved') ORDER BY score DESC LIMIT 10"
            ).fetchall()

            disproved_count = conn.execute(
                "SELECT COUNT(*) as n FROM disproof_log"
            ).fetchone()["n"]

        return {
            "total_hypotheses": total,
            "by_status": by_status,
            "top_candidates": [dict(r) for r in best],
            "total_disproofs": disproved_count,
            "generated_at": _now_iso(),
        }
