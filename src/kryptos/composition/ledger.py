"""Composition campaign ledger — SQLite persistence for coverage tracking.

Records campaigns, composition branches, results, and pruning decisions.
Follows the same WAL-mode SQLite pattern as kernel/persistence/sqlite.py.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from kryptos.composition.models import BranchStatus


COMPOSITION_SCHEMA = """
CREATE TABLE IF NOT EXISTS campaigns (
    campaign_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'CREATED',
    started_at TEXT,
    completed_at TEXT,
    total_branches INTEGER DEFAULT 0,
    tested_branches INTEGER DEFAULT 0,
    pruned_branches INTEGER DEFAULT 0,
    best_score INTEGER DEFAULT 0,
    notes TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS branches (
    branch_id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL,
    stack_hash TEXT NOT NULL,
    stack_json TEXT NOT NULL,
    campaign_key TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    peel_order TEXT NOT NULL,
    prune_type TEXT,
    prune_reason TEXT,
    score INTEGER DEFAULT 0,
    bean_pass BOOLEAN DEFAULT 0,
    ic_value REAL,
    plaintext TEXT,
    intermediate_text TEXT,
    score_breakdown_json TEXT,
    metadata_json TEXT,
    tested_at TEXT,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(campaign_id)
);

CREATE TABLE IF NOT EXISTS composition_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id TEXT NOT NULL,
    branch_id TEXT NOT NULL,
    stack_hash TEXT NOT NULL,
    score INTEGER NOT NULL,
    bean_pass BOOLEAN DEFAULT 0,
    ic_value REAL,
    plaintext TEXT,
    intermediate_text TEXT,
    score_breakdown_json TEXT,
    metadata_json TEXT,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(campaign_id),
    FOREIGN KEY (branch_id) REFERENCES branches(branch_id)
);

CREATE TABLE IF NOT EXISTS checkpoints (
    campaign_id TEXT NOT NULL,
    branch_id TEXT NOT NULL,
    status TEXT NOT NULL,
    result_json TEXT,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (campaign_id, branch_id)
);

CREATE INDEX IF NOT EXISTS idx_branches_campaign ON branches(campaign_id);
CREATE INDEX IF NOT EXISTS idx_branches_status ON branches(status);
CREATE INDEX IF NOT EXISTS idx_branches_score ON branches(score DESC);
CREATE INDEX IF NOT EXISTS idx_branches_key ON branches(campaign_key);
CREATE INDEX IF NOT EXISTS idx_results_score ON composition_results(score DESC);
CREATE INDEX IF NOT EXISTS idx_results_campaign ON composition_results(campaign_id);
"""


class CompositionLedger:
    """SQLite ledger for composition campaign tracking.

    Provides durable storage for:
    - Campaign metadata and policies
    - Individual branch status (open/tested/pruned)
    - Pruning reasons and classification (exact/heuristic)
    - Score results and artifacts
    - Coverage queries (what's been tested, what's open)
    """

    def __init__(self, path: str | Path = "db/composition_ledger.sqlite") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(COMPOSITION_SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.commit()
        self.conn.close()

    def __enter__(self) -> "CompositionLedger":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    # ── Campaign management ────────────────────────────────────────────

    def register_campaign(
        self,
        campaign_id: str,
        name: str,
        policy: Dict[str, Any],
        total_branches: int = 0,
    ) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "INSERT OR REPLACE INTO campaigns "
            "(campaign_id, name, policy_json, status, started_at, total_branches) "
            "VALUES (?, ?, ?, 'RUNNING', ?, ?)",
            (campaign_id, name, json.dumps(policy, sort_keys=True),
             ts, total_branches),
        )
        self.conn.commit()

    def finalize_campaign(
        self,
        campaign_id: str,
        status: str = "COMPLETE",
        notes: str = "",
    ) -> None:
        ts = datetime.now(timezone.utc).isoformat()

        # Compute summary stats from branches table
        row = self.conn.execute(
            "SELECT "
            "  SUM(CASE WHEN status = 'tested' THEN 1 ELSE 0 END), "
            "  SUM(CASE WHEN status = 'pruned' THEN 1 ELSE 0 END), "
            "  MAX(score) "
            "FROM branches WHERE campaign_id = ?",
            (campaign_id,),
        ).fetchone()

        tested = row[0] if row and row[0] else 0
        pruned = row[1] if row and row[1] else 0
        best = row[2] if row and row[2] else 0

        self.conn.execute(
            "UPDATE campaigns SET status = ?, completed_at = ?, "
            "tested_branches = ?, pruned_branches = ?, best_score = ?, notes = ? "
            "WHERE campaign_id = ?",
            (status, ts, tested, pruned, best, notes, campaign_id),
        )
        self.conn.commit()

    # ── Branch management ──────────────────────────────────────────────

    def record_branch(
        self,
        branch_id: str,
        campaign_id: str,
        stack_hash: str,
        stack_json: str,
        campaign_key: str,
        peel_order: str,
        status: str = "open",
        prune_type: Optional[str] = None,
        prune_reason: Optional[str] = None,
        score: int = 0,
        bean_pass: bool = False,
        ic_value: Optional[float] = None,
        plaintext: str = "",
        intermediate_text: str = "",
        score_breakdown: Optional[Dict] = None,
        metadata: Optional[Dict] = None,
    ) -> None:
        ts = datetime.now(timezone.utc).isoformat() if status != "open" else None
        self.conn.execute(
            "INSERT OR REPLACE INTO branches "
            "(branch_id, campaign_id, stack_hash, stack_json, campaign_key, "
            "status, peel_order, prune_type, prune_reason, "
            "score, bean_pass, ic_value, plaintext, intermediate_text, "
            "score_breakdown_json, metadata_json, tested_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                branch_id, campaign_id, stack_hash, stack_json, campaign_key,
                status, peel_order, prune_type, prune_reason,
                score, bean_pass, ic_value, plaintext, intermediate_text,
                json.dumps(score_breakdown) if score_breakdown else None,
                json.dumps(metadata) if metadata else None,
                ts,
            ),
        )

    def record_result(
        self,
        campaign_id: str,
        branch_id: str,
        stack_hash: str,
        score: int,
        bean_pass: bool = False,
        ic_value: Optional[float] = None,
        plaintext: str = "",
        intermediate_text: str = "",
        score_breakdown: Optional[Dict] = None,
        metadata: Optional[Dict] = None,
    ) -> None:
        self.conn.execute(
            "INSERT INTO composition_results "
            "(campaign_id, branch_id, stack_hash, score, bean_pass, "
            "ic_value, plaintext, intermediate_text, "
            "score_breakdown_json, metadata_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                campaign_id, branch_id, stack_hash, score, bean_pass,
                ic_value, plaintext, intermediate_text,
                json.dumps(score_breakdown) if score_breakdown else None,
                json.dumps(metadata) if metadata else None,
            ),
        )

    def checkpoint(
        self,
        campaign_id: str,
        branch_id: str,
        status: str,
        result: Optional[Dict] = None,
    ) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO checkpoints "
            "(campaign_id, branch_id, status, result_json) "
            "VALUES (?, ?, ?, ?)",
            (campaign_id, branch_id, status,
             json.dumps(result) if result else None),
        )

    def completed_branch_ids(self, campaign_id: str) -> set:
        cursor = self.conn.execute(
            "SELECT branch_id FROM checkpoints "
            "WHERE campaign_id = ? AND status = 'complete'",
            (campaign_id,),
        )
        return {row[0] for row in cursor.fetchall()}

    def commit(self) -> None:
        self.conn.commit()

    # ── Coverage queries ───────────────────────────────────────────────

    def campaign_summary(self, campaign_id: str) -> Dict[str, Any]:
        """Get summary statistics for a campaign."""
        row = self.conn.execute(
            "SELECT * FROM campaigns WHERE campaign_id = ?",
            (campaign_id,),
        ).fetchone()
        if not row:
            return {}
        cols = [d[0] for d in self.conn.execute(
            "SELECT * FROM campaigns LIMIT 0"
        ).description]
        return dict(zip(cols, row))

    def coverage_by_family(self, campaign_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get branch counts by campaign_key (family+order combination)."""
        where = "WHERE campaign_id = ?" if campaign_id else ""
        params = (campaign_id,) if campaign_id else ()
        cursor = self.conn.execute(
            f"SELECT campaign_key, status, COUNT(*) "
            f"FROM branches {where} "
            f"GROUP BY campaign_key, status "
            f"ORDER BY campaign_key",
            params,
        )
        results: list[Dict[str, Any]] = []
        for campaign_key, status, count in cursor.fetchall():
            results.append({
                "campaign_key": campaign_key,
                "status": status,
                "count": count,
            })
        return results

    def open_branches(
        self,
        campaign_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get branches that haven't been tested yet."""
        where = "WHERE status = 'open'"
        params: list = []
        if campaign_id:
            where += " AND campaign_id = ?"
            params.append(campaign_id)
        cursor = self.conn.execute(
            f"SELECT branch_id, campaign_id, stack_hash, campaign_key, peel_order "
            f"FROM branches {where} LIMIT ?",
            params + [limit],
        )
        cols = [d[0] for d in cursor.description]
        return [dict(zip(cols, row)) for row in cursor.fetchall()]

    def top_results(
        self,
        limit: int = 20,
        min_score: int = 0,
        campaign_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get top-scoring composition results."""
        where = "WHERE score >= ?"
        params: list = [min_score]
        if campaign_id:
            where += " AND campaign_id = ?"
            params.append(campaign_id)
        cursor = self.conn.execute(
            f"SELECT * FROM composition_results {where} "
            f"ORDER BY score DESC LIMIT ?",
            params + [limit],
        )
        cols = [d[0] for d in cursor.description]
        return [dict(zip(cols, row)) for row in cursor.fetchall()]

    def pruning_summary(
        self,
        campaign_id: Optional[str] = None,
    ) -> Dict[str, int]:
        """Count branches by prune_type."""
        where = "WHERE status = 'pruned'"
        params: list = []
        if campaign_id:
            where += " AND campaign_id = ?"
            params.append(campaign_id)
        cursor = self.conn.execute(
            f"SELECT prune_type, COUNT(*) FROM branches {where} "
            f"GROUP BY prune_type",
            params,
        )
        return {row[0] or "unknown": row[1] for row in cursor.fetchall()}

    def all_campaigns(self) -> List[Dict[str, Any]]:
        """List all campaigns with summary info."""
        cursor = self.conn.execute(
            "SELECT campaign_id, name, status, total_branches, "
            "tested_branches, pruned_branches, best_score, started_at "
            "FROM campaigns ORDER BY started_at DESC"
        )
        cols = [d[0] for d in cursor.description]
        return [dict(zip(cols, row)) for row in cursor.fetchall()]
