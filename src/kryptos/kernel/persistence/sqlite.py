"""SQLite persistence for experiment results and run tracking.

Schema v2 — unified schema for all experiment types.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


SCHEMA_V2 = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    campaign TEXT NOT NULL,
    config_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'CREATED',
    started_at TEXT,
    completed_at TEXT,
    total_jobs INTEGER DEFAULT 0,
    completed_jobs INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT,
    experiment_id TEXT NOT NULL,
    config_json TEXT NOT NULL,
    score INTEGER NOT NULL,
    score_breakdown TEXT,
    bean_pass BOOLEAN DEFAULT 0,
    plaintext TEXT,
    keystream TEXT,
    intermediate TEXT,
    metadata TEXT,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS eliminations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    experiment_id TEXT NOT NULL,
    hypothesis TEXT,
    configs_tested INTEGER,
    best_score INTEGER,
    verdict TEXT NOT NULL,
    evidence TEXT,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS checkpoints (
    run_id TEXT NOT NULL,
    job_id TEXT NOT NULL,
    status TEXT NOT NULL,
    result_json TEXT,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (run_id, job_id)
);

CREATE INDEX IF NOT EXISTS idx_results_score ON results(score DESC);
CREATE INDEX IF NOT EXISTS idx_results_run ON results(run_id);
CREATE INDEX IF NOT EXISTS idx_results_exp ON results(experiment_id);
CREATE INDEX IF NOT EXISTS idx_checkpoints_run ON checkpoints(run_id);
"""


class Database:
    """SQLite database wrapper with WAL mode and schema management."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(SCHEMA_V2)
        self.conn.commit()

    def close(self) -> None:
        self.conn.commit()
        self.conn.close()

    def store_result(
        self,
        experiment_id: str,
        config: Dict[str, Any],
        score: int,
        score_breakdown: Optional[Dict] = None,
        bean_pass: bool = False,
        plaintext: str = "",
        keystream: str = "",
        intermediate: str = "",
        metadata: Optional[Dict] = None,
        run_id: Optional[str] = None,
    ) -> None:
        """Store a single experiment result."""
        self.conn.execute(
            "INSERT INTO results "
            "(run_id, experiment_id, config_json, score, score_breakdown, "
            "bean_pass, plaintext, keystream, intermediate, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_id,
                experiment_id,
                json.dumps(config, sort_keys=True),
                score,
                json.dumps(score_breakdown) if score_breakdown else None,
                bean_pass,
                plaintext,
                keystream,
                intermediate,
                json.dumps(metadata) if metadata else None,
            ),
        )

    def store_elimination(
        self,
        experiment_id: str,
        hypothesis: str,
        configs_tested: int,
        best_score: int,
        verdict: str,
        evidence: str = "",
    ) -> None:
        """Record an elimination result."""
        self.conn.execute(
            "INSERT INTO eliminations "
            "(experiment_id, hypothesis, configs_tested, best_score, verdict, evidence) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (experiment_id, hypothesis, configs_tested, best_score, verdict, evidence),
        )

    def top_results(
        self,
        limit: int = 20,
        min_score: int = 0,
        experiment_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Query top-scoring results."""
        query = "SELECT * FROM results WHERE score >= ?"
        params: list[Any] = [min_score]
        if experiment_id:
            query += " AND experiment_id = ?"
            params.append(experiment_id)
        query += " ORDER BY score DESC LIMIT ?"
        params.append(limit)

        cursor = self.conn.execute(query, params)
        cols = [d[0] for d in cursor.description]
        return [dict(zip(cols, row)) for row in cursor.fetchall()]

    def completed_job_ids(self, run_id: str) -> set[str]:
        """Get set of completed job IDs for resume support."""
        cursor = self.conn.execute(
            "SELECT job_id FROM checkpoints WHERE run_id = ? AND status = 'complete'",
            (run_id,),
        )
        return {row[0] for row in cursor.fetchall()}

    def checkpoint_job(self, run_id: str, job_id: str, result: Dict[str, Any]) -> None:
        """Record job completion for resume support."""
        self.conn.execute(
            "INSERT OR REPLACE INTO checkpoints (run_id, job_id, status, result_json) "
            "VALUES (?, ?, 'complete', ?)",
            (run_id, job_id, json.dumps(result)),
        )

    def register_run(
        self, run_id: str, campaign: str, config: Dict[str, Any], total_jobs: int,
    ) -> None:
        """Register a new sweep run."""
        ts = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "INSERT OR REPLACE INTO runs "
            "(run_id, campaign, config_json, status, started_at, total_jobs) "
            "VALUES (?, ?, ?, 'RUNNING', ?, ?)",
            (run_id, campaign, json.dumps(config), ts, total_jobs),
        )
        self.conn.commit()

    def finalize_run(self, run_id: str, status: str) -> None:
        """Mark a run as complete/failed/partial."""
        ts = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "UPDATE runs SET status = ?, completed_at = ? WHERE run_id = ?",
            (status, ts, run_id),
        )
        self.conn.commit()

    def commit(self) -> None:
        self.conn.commit()
