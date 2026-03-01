"""KryptosBot database interface for the results SQLite database."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from kryptosbot.config import HypothesisStatus


class ResultsDB:
    """Read-only interface to kryptosbot_results.db for the monitor."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row

    def summary_report(self) -> dict:
        """Build a summary report of the current database state."""
        cur = self._conn.cursor()

        # Total hypotheses
        total = cur.execute("SELECT count(*) FROM hypotheses").fetchone()[0]

        # By status
        rows = cur.execute(
            "SELECT status, count(*) as cnt FROM hypotheses GROUP BY status"
        ).fetchall()
        by_status = {r["status"]: r["cnt"] for r in rows}

        # Total disproofs
        total_disproofs = cur.execute("SELECT count(*) FROM disproof_log").fetchone()[0]

        # Top candidates (by score descending)
        top = cur.execute(
            "SELECT strategy, score, best_plaintext FROM hypotheses "
            "WHERE status IN ('promising', 'solved', 'running') "
            "ORDER BY score DESC LIMIT 10"
        ).fetchall()
        top_candidates = [
            {
                "strategy": r["strategy"],
                "score": r["score"] or 0.0,
                "best_plaintext": r["best_plaintext"] or "",
            }
            for r in top
        ]

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_hypotheses": total,
            "by_status": by_status,
            "total_disproofs": total_disproofs,
            "top_candidates": top_candidates,
        }

    def get_running_sessions(self) -> list[dict]:
        """Get currently running sessions."""
        rows = self._conn.execute(
            "SELECT session_id, strategy, worker_id, started_at "
            "FROM sessions WHERE finished_at IS NULL"
        ).fetchall()
        return [dict(r) for r in rows]

    def get_disproof_log(self) -> list[dict]:
        """Get recent disproofs, newest first."""
        rows = self._conn.execute(
            "SELECT strategy, criteria, disproved_at "
            "FROM disproof_log ORDER BY disproved_at DESC LIMIT 20"
        ).fetchall()
        return [dict(r) for r in rows]

    def get_by_status(self, status: HypothesisStatus) -> list[dict]:
        """Get hypotheses with a given status."""
        rows = self._conn.execute(
            "SELECT strategy, score, best_plaintext FROM hypotheses WHERE status = ?",
            (status.value,),
        ).fetchall()
        return [dict(r) for r in rows]
