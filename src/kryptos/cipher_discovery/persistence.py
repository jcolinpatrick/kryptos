"""SQLite persistence for cipher discovery subsystem.

Uses WAL mode for concurrent access (matching repo convention).
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .schema import (
    CipherRecord, FrontierEntry, SourceRecord,
    CipherType, Taxonomy, FrontierStatus, SourceType,
)


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS cipher_records (
    record_id TEXT PRIMARY KEY,
    canonical_name TEXT NOT NULL,
    alias_names_json TEXT DEFAULT '[]',
    category TEXT DEFAULT '',
    cipher_type TEXT DEFAULT 'uncertain',
    taxonomy TEXT DEFAULT 'needs_human_review',
    cipher_family TEXT DEFAULT '',
    description TEXT DEFAULT '',
    operational_mechanics TEXT DEFAULT '',
    execution_model TEXT DEFAULT '',
    tools_required_json TEXT DEFAULT '[]',
    materials_needed_json TEXT DEFAULT '[]',
    manual_execution_type TEXT DEFAULT '',
    claimed_origin TEXT DEFAULT '',
    source_urls_json TEXT DEFAULT '[]',
    quote_snippets_json TEXT DEFAULT '[]',
    source_type TEXT DEFAULT 'unknown',
    source_title TEXT DEFAULT '',
    author TEXT DEFAULT '',
    publication_year INTEGER,
    historically_attested BOOLEAN DEFAULT 0,
    pedagogical_amateur BOOLEAN DEFAULT 0,
    bespoke BOOLEAN DEFAULT 0,
    requires_human_review BOOLEAN DEFAULT 1,
    confidence_real_system REAL DEFAULT 0.0,
    confidence_distinct_from_known REAL DEFAULT 0.0,
    confidence_relevance_to_k4 REAL DEFAULT 0.0,
    obscurity_score REAL DEFAULT 0.0,
    k4_relevance_score REAL DEFAULT 0.0,
    k4_score_breakdown_json TEXT DEFAULT '{}',
    ambiguity_flags_json TEXT DEFAULT '[]',
    extraction_notes TEXT DEFAULT '',
    unresolved_questions_json TEXT DEFAULT '[]',
    tested_in_project BOOLEAN DEFAULT 0,
    exhaustion_log_ids_json TEXT DEFAULT '[]',
    exhaustion_status TEXT DEFAULT '',
    discovered_at TEXT,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS source_records (
    source_id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    domain TEXT DEFAULT '',
    title TEXT DEFAULT '',
    fetch_status INTEGER DEFAULT 0,
    content_hash TEXT DEFAULT '',
    content_length INTEGER DEFAULT 0,
    fetched_at TEXT,
    extracted_terms_json TEXT DEFAULT '[]',
    error_message TEXT DEFAULT '',
    robots_blocked BOOLEAN DEFAULT 0
);

CREATE TABLE IF NOT EXISTS frontier_entries (
    entry_id TEXT PRIMARY KEY,
    term TEXT DEFAULT '',
    url TEXT DEFAULT '',
    status TEXT DEFAULT 'pending',
    priority INTEGER DEFAULT 0,
    depth INTEGER DEFAULT 0,
    parent_term TEXT DEFAULT '',
    discovered_terms_json TEXT DEFAULT '[]',
    notes TEXT DEFAULT '',
    created_at TEXT,
    processed_at TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS alias_mappings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alias_term TEXT NOT NULL,
    canonical_name TEXT NOT NULL,
    confidence REAL DEFAULT 0.0,
    source TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS human_review_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id_a TEXT,
    record_id_b TEXT,
    reason TEXT,
    status TEXT DEFAULT 'pending',
    resolution TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    resolved_at TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_cipher_name ON cipher_records(canonical_name);
CREATE INDEX IF NOT EXISTS idx_cipher_k4_score ON cipher_records(k4_relevance_score DESC);
CREATE INDEX IF NOT EXISTS idx_cipher_taxonomy ON cipher_records(taxonomy);
CREATE INDEX IF NOT EXISTS idx_frontier_status ON frontier_entries(status);
CREATE INDEX IF NOT EXISTS idx_frontier_priority ON frontier_entries(priority DESC);
CREATE INDEX IF NOT EXISTS idx_alias_term ON alias_mappings(alias_term);
CREATE INDEX IF NOT EXISTS idx_review_status ON human_review_queue(status);
"""


class DiscoveryDB:
    """SQLite persistence for cipher discovery."""

    def __init__(self, db_path: str = "db/cipher_discovery.sqlite"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        self.conn.executescript(SCHEMA_SQL)
        self.conn.commit()

    def close(self):
        self.conn.close()

    # ---- CipherRecord CRUD ----

    def upsert_cipher(self, rec: CipherRecord):
        """Insert or update a cipher record."""
        now = datetime.now(timezone.utc).isoformat()
        rec.updated_at = now
        self.conn.execute("""
            INSERT OR REPLACE INTO cipher_records (
                record_id, canonical_name, alias_names_json, category,
                cipher_type, taxonomy, cipher_family, description,
                operational_mechanics, execution_model, tools_required_json,
                materials_needed_json, manual_execution_type, claimed_origin,
                source_urls_json, quote_snippets_json, source_type,
                source_title, author, publication_year,
                historically_attested, pedagogical_amateur, bespoke,
                requires_human_review, confidence_real_system,
                confidence_distinct_from_known, confidence_relevance_to_k4,
                obscurity_score, k4_relevance_score, k4_score_breakdown_json,
                ambiguity_flags_json, extraction_notes, unresolved_questions_json,
                tested_in_project, exhaustion_log_ids_json, exhaustion_status,
                discovered_at, updated_at
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        """, (
            rec.record_id, rec.canonical_name,
            json.dumps(rec.alias_names), rec.category,
            rec.cipher_type.value, rec.taxonomy.value,
            rec.cipher_family, rec.description,
            rec.operational_mechanics, rec.execution_model,
            json.dumps(rec.tools_required), json.dumps(rec.materials_needed),
            rec.manual_execution_type, rec.claimed_origin,
            json.dumps(rec.source_urls), json.dumps(rec.quote_snippets),
            rec.source_type.value, rec.source_title,
            rec.author, rec.publication_year,
            rec.historically_attested, rec.pedagogical_amateur,
            rec.bespoke, rec.requires_human_review,
            rec.confidence_real_system, rec.confidence_distinct_from_known,
            rec.confidence_relevance_to_k4, rec.obscurity_score,
            rec.k4_relevance_score, json.dumps(rec.k4_score_breakdown),
            json.dumps(rec.ambiguity_flags), rec.extraction_notes,
            json.dumps(rec.unresolved_questions),
            rec.tested_in_project, json.dumps(rec.exhaustion_log_ids),
            rec.exhaustion_status, rec.discovered_at, rec.updated_at,
        ))
        self.conn.commit()

    def get_cipher(self, record_id: str) -> Optional[CipherRecord]:
        """Get a cipher record by ID."""
        row = self.conn.execute(
            "SELECT * FROM cipher_records WHERE record_id = ?", (record_id,)
        ).fetchone()
        if row is None:
            return None
        return self._row_to_cipher(row)

    def get_cipher_by_name(self, name: str) -> Optional[CipherRecord]:
        """Get a cipher record by canonical name (case-insensitive)."""
        row = self.conn.execute(
            "SELECT * FROM cipher_records WHERE LOWER(canonical_name) = LOWER(?)",
            (name,)
        ).fetchone()
        if row is None:
            return None
        return self._row_to_cipher(row)

    def get_all_ciphers(self) -> list[CipherRecord]:
        """Get all cipher records."""
        rows = self.conn.execute(
            "SELECT * FROM cipher_records ORDER BY k4_relevance_score DESC"
        ).fetchall()
        return [self._row_to_cipher(r) for r in rows]

    def get_top_ciphers(self, limit: int = 30) -> list[CipherRecord]:
        """Get top ciphers by K4 relevance score."""
        rows = self.conn.execute(
            "SELECT * FROM cipher_records ORDER BY k4_relevance_score DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [self._row_to_cipher(r) for r in rows]

    def get_untested_ciphers(self) -> list[CipherRecord]:
        """Get ciphers not yet tested in the project."""
        rows = self.conn.execute(
            "SELECT * FROM cipher_records WHERE tested_in_project = 0 "
            "ORDER BY k4_relevance_score DESC"
        ).fetchall()
        return [self._row_to_cipher(r) for r in rows]

    def search_ciphers(self, query: str) -> list[CipherRecord]:
        """Search ciphers by name/description."""
        pattern = f"%{query}%"
        rows = self.conn.execute(
            "SELECT * FROM cipher_records WHERE "
            "canonical_name LIKE ? OR description LIKE ? OR alias_names_json LIKE ? "
            "ORDER BY k4_relevance_score DESC",
            (pattern, pattern, pattern)
        ).fetchall()
        return [self._row_to_cipher(r) for r in rows]

    def count_ciphers(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) FROM cipher_records").fetchone()
        return row[0]

    def _row_to_cipher(self, row: sqlite3.Row) -> CipherRecord:
        return CipherRecord(
            record_id=row["record_id"],
            canonical_name=row["canonical_name"],
            alias_names=json.loads(row["alias_names_json"]),
            category=row["category"],
            cipher_type=CipherType(row["cipher_type"]),
            taxonomy=Taxonomy(row["taxonomy"]),
            cipher_family=row["cipher_family"],
            description=row["description"],
            operational_mechanics=row["operational_mechanics"],
            execution_model=row["execution_model"],
            tools_required=json.loads(row["tools_required_json"]),
            materials_needed=json.loads(row["materials_needed_json"]),
            manual_execution_type=row["manual_execution_type"],
            claimed_origin=row["claimed_origin"],
            source_urls=json.loads(row["source_urls_json"]),
            quote_snippets=json.loads(row["quote_snippets_json"]),
            source_type=SourceType(row["source_type"]),
            source_title=row["source_title"],
            author=row["author"],
            publication_year=row["publication_year"],
            historically_attested=bool(row["historically_attested"]),
            pedagogical_amateur=bool(row["pedagogical_amateur"]),
            bespoke=bool(row["bespoke"]),
            requires_human_review=bool(row["requires_human_review"]),
            confidence_real_system=row["confidence_real_system"],
            confidence_distinct_from_known=row["confidence_distinct_from_known"],
            confidence_relevance_to_k4=row["confidence_relevance_to_k4"],
            obscurity_score=row["obscurity_score"],
            k4_relevance_score=row["k4_relevance_score"],
            k4_score_breakdown=json.loads(row["k4_score_breakdown_json"]),
            ambiguity_flags=json.loads(row["ambiguity_flags_json"]),
            extraction_notes=row["extraction_notes"],
            unresolved_questions=json.loads(row["unresolved_questions_json"]),
            tested_in_project=bool(row["tested_in_project"]),
            exhaustion_log_ids=json.loads(row["exhaustion_log_ids_json"]),
            exhaustion_status=row["exhaustion_status"],
            discovered_at=row["discovered_at"],
            updated_at=row["updated_at"],
        )

    # ---- FrontierEntry CRUD ----

    def add_frontier_entry(self, entry: FrontierEntry):
        self.conn.execute("""
            INSERT OR IGNORE INTO frontier_entries (
                entry_id, term, url, status, priority, depth,
                parent_term, discovered_terms_json, notes,
                created_at, processed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            entry.entry_id, entry.term, entry.url,
            entry.status.value, entry.priority, entry.depth,
            entry.parent_term, json.dumps(entry.discovered_terms),
            entry.notes, entry.created_at, entry.processed_at,
        ))
        self.conn.commit()

    def get_pending_frontier(self, limit: int = 50) -> list[FrontierEntry]:
        rows = self.conn.execute(
            "SELECT * FROM frontier_entries WHERE status = 'pending' "
            "ORDER BY priority DESC LIMIT ?", (limit,)
        ).fetchall()
        return [self._row_to_frontier(r) for r in rows]

    def update_frontier_status(self, entry_id: str, status: FrontierStatus):
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "UPDATE frontier_entries SET status = ?, processed_at = ? WHERE entry_id = ?",
            (status.value, now, entry_id)
        )
        self.conn.commit()

    def _row_to_frontier(self, row: sqlite3.Row) -> FrontierEntry:
        return FrontierEntry(
            entry_id=row["entry_id"],
            term=row["term"],
            url=row["url"],
            status=FrontierStatus(row["status"]),
            priority=row["priority"],
            depth=row["depth"],
            parent_term=row["parent_term"],
            discovered_terms=json.loads(row["discovered_terms_json"]),
            notes=row["notes"],
            created_at=row["created_at"],
            processed_at=row["processed_at"],
        )

    # ---- SourceRecord CRUD ----

    def add_source(self, source: SourceRecord):
        self.conn.execute("""
            INSERT OR REPLACE INTO source_records (
                source_id, url, domain, title, fetch_status,
                content_hash, content_length, fetched_at,
                extracted_terms_json, error_message, robots_blocked
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            source.source_id, source.url, source.domain,
            source.title, source.fetch_status, source.content_hash,
            source.content_length, source.fetched_at,
            json.dumps(source.extracted_terms), source.error_message,
            source.robots_blocked,
        ))
        self.conn.commit()

    # ---- Alias mappings ----

    def add_alias_mapping(self, alias_term: str, canonical_name: str,
                          confidence: float = 1.0, source: str = ""):
        self.conn.execute("""
            INSERT INTO alias_mappings (alias_term, canonical_name, confidence, source)
            VALUES (?, ?, ?, ?)
        """, (alias_term, canonical_name, confidence, source))
        self.conn.commit()

    # ---- Human review queue ----

    def add_review_item(self, record_id_a: str, record_id_b: str, reason: str):
        self.conn.execute("""
            INSERT INTO human_review_queue (record_id_a, record_id_b, reason)
            VALUES (?, ?, ?)
        """, (record_id_a, record_id_b, reason))
        self.conn.commit()

    def get_review_queue(self, status: str = "pending") -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM human_review_queue WHERE status = ? ORDER BY id",
            (status,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ---- Stats ----

    def get_stats(self) -> dict:
        """Get pipeline statistics."""
        stats = {}
        stats["total_ciphers"] = self.conn.execute(
            "SELECT COUNT(*) FROM cipher_records"
        ).fetchone()[0]
        stats["tested_ciphers"] = self.conn.execute(
            "SELECT COUNT(*) FROM cipher_records WHERE tested_in_project = 1"
        ).fetchone()[0]
        stats["untested_ciphers"] = stats["total_ciphers"] - stats["tested_ciphers"]
        stats["frontier_pending"] = self.conn.execute(
            "SELECT COUNT(*) FROM frontier_entries WHERE status = 'pending'"
        ).fetchone()[0]
        stats["frontier_total"] = self.conn.execute(
            "SELECT COUNT(*) FROM frontier_entries"
        ).fetchone()[0]
        stats["sources_fetched"] = self.conn.execute(
            "SELECT COUNT(*) FROM source_records"
        ).fetchone()[0]
        stats["review_pending"] = self.conn.execute(
            "SELECT COUNT(*) FROM human_review_queue WHERE status = 'pending'"
        ).fetchone()[0]

        # Taxonomy breakdown
        tax_rows = self.conn.execute(
            "SELECT taxonomy, COUNT(*) as cnt FROM cipher_records GROUP BY taxonomy"
        ).fetchall()
        stats["taxonomy_breakdown"] = {r["taxonomy"]: r["cnt"] for r in tax_rows}

        return stats
