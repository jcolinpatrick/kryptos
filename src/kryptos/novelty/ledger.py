"""Novelty ledger — anti-repeat research memory.

Tracks every hypothesis tested, with what config, what result,
and why it was eliminated or promoted. Prevents repeating the same
search in different scripts.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from kryptos.novelty.hypothesis import (
    Hypothesis, HypothesisStatus, ResearchQuestion,
)


LEDGER_SCHEMA = """
CREATE TABLE IF NOT EXISTS hypotheses (
    hypothesis_id TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    status TEXT NOT NULL,
    transform_stack TEXT,
    research_questions TEXT,
    assumptions TEXT,
    provenance TEXT,
    triage_score REAL DEFAULT 0.0,
    triage_detail TEXT,
    test_results TEXT,
    elimination_reason TEXT,
    priority_score REAL DEFAULT 0.0,
    estimated_configs INTEGER DEFAULT 0,
    tags TEXT,
    created_at TEXT,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS rq_coverage (
    research_question TEXT PRIMARY KEY,
    total_hypotheses INTEGER DEFAULT 0,
    eliminated INTEGER DEFAULT 0,
    survived INTEGER DEFAULT 0,
    promoted INTEGER DEFAULT 0,
    last_updated TEXT
);

CREATE INDEX IF NOT EXISTS idx_hyp_status ON hypotheses(status);
CREATE INDEX IF NOT EXISTS idx_hyp_priority ON hypotheses(priority_score DESC);
CREATE INDEX IF NOT EXISTS idx_hyp_triage ON hypotheses(triage_score DESC);
"""


class NoveltyLedger:
    """Persistent research memory for hypothesis tracking."""

    def __init__(self, path: str | Path = "db/novelty_ledger.sqlite") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(LEDGER_SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.commit()
        self.conn.close()

    def record(self, hyp: Hypothesis) -> None:
        """Record or update a hypothesis in the ledger."""
        ts = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "INSERT OR REPLACE INTO hypotheses "
            "(hypothesis_id, description, status, transform_stack, "
            "research_questions, assumptions, provenance, triage_score, "
            "triage_detail, test_results, elimination_reason, priority_score, "
            "estimated_configs, tags, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                hyp.hypothesis_id,
                hyp.description,
                hyp.status.value,
                json.dumps(hyp.transform_stack),
                json.dumps([rq.value for rq in hyp.research_questions]),
                json.dumps(hyp.assumptions),
                hyp.provenance,
                hyp.triage_score,
                hyp.triage_detail,
                json.dumps(hyp.test_results),
                hyp.elimination_reason,
                hyp.priority_score,
                hyp.estimated_configs,
                json.dumps(hyp.tags),
                hyp.created_at,
                ts,
            ),
        )

    def record_batch(self, hypotheses: List[Hypothesis]) -> None:
        """Record multiple hypotheses efficiently."""
        for hyp in hypotheses:
            self.record(hyp)
        self.conn.commit()

    def update_rq_coverage(self) -> None:
        """Recompute RQ coverage statistics from current hypothesis data."""
        ts = datetime.now(timezone.utc).isoformat()

        for rq in ResearchQuestion:
            cursor = self.conn.execute(
                "SELECT status, COUNT(*) FROM hypotheses "
                "WHERE research_questions LIKE ? GROUP BY status",
                (f'%"{rq.value}"%',),
            )
            counts: dict[str, int] = dict(cursor.fetchall())

            total = sum(counts.values())
            eliminated = counts.get("eliminated", 0)
            survived = counts.get("survived", 0)
            promoted = counts.get("promoted", 0) + counts.get("testing", 0)

            self.conn.execute(
                "INSERT OR REPLACE INTO rq_coverage "
                "(research_question, total_hypotheses, eliminated, survived, promoted, last_updated) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (rq.value, total, eliminated, survived, promoted, ts),
            )

        self.conn.commit()

    def get_rq_coverage(self) -> Dict[str, Dict[str, int]]:
        """Get coverage statistics per research question."""
        cursor = self.conn.execute("SELECT * FROM rq_coverage")
        cols = [d[0] for d in cursor.description]
        return {
            row[0]: dict(zip(cols[1:], row[1:]))
            for row in cursor.fetchall()
        }

    def get_underexplored_rqs(self, min_hypotheses: int = 10) -> List[str]:
        """Find research questions with fewer than min_hypotheses tested."""
        coverage = self.get_rq_coverage()
        under = []
        for rq in ResearchQuestion:
            stats = coverage.get(rq.value, {})
            total = stats.get("total_hypotheses", 0)
            if total < min_hypotheses:
                under.append(rq.value)
        return under

    def already_tested(self, hypothesis_id: str) -> bool:
        """Check if a hypothesis has already been tested."""
        cursor = self.conn.execute(
            "SELECT status FROM hypotheses WHERE hypothesis_id = ?",
            (hypothesis_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return False
        return row[0] in ("eliminated", "survived", "breakthrough")

    def get_promoted(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get top promoted hypotheses ready for full testing."""
        cursor = self.conn.execute(
            "SELECT * FROM hypotheses WHERE status = 'promoted' "
            "ORDER BY priority_score DESC LIMIT ?",
            (limit,),
        )
        cols = [d[0] for d in cursor.description]
        return [dict(zip(cols, row)) for row in cursor.fetchall()]

    def summary(self) -> Dict[str, int]:
        """Get summary counts by status."""
        cursor = self.conn.execute(
            "SELECT status, COUNT(*) FROM hypotheses GROUP BY status"
        )
        return dict(cursor.fetchall())

    def __enter__(self) -> "NoveltyLedger":
        return self

    def __exit__(self, *args) -> None:
        self.close()
