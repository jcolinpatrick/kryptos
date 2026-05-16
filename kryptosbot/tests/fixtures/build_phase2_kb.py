"""Build kryptosbot/tests/fixtures/cipher_discovery_phase2_fixture.sqlite.

Run once locally:
    PYTHONPATH=src python3 kryptosbot/tests/fixtures/build_phase2_kb.py

Re-run to regenerate (output is overwritten). Deterministic across runs
because record_id values are hard-coded.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path


HERE = Path(__file__).resolve().parent
OUT = HERE / "cipher_discovery_phase2_fixture.sqlite"


# Schema mirrors src/kryptos/cipher_discovery/persistence.py — kept inline
# to avoid coupling the test fixture to internal SQL string drift.
_SCHEMA = """
CREATE TABLE cipher_records (
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
"""


ROWS = [
    # 1) Dispatcher-testable, untested, columnar.
    dict(
        record_id="fx-swagman",
        canonical_name="Swagman Cipher",
        cipher_family="columnar",
        cipher_type="historical",
        taxonomy="historically_attested",
        operational_mechanics="N-row columnar with skew permutation per row.",
        description="A columnar transposition with row-dependent skew.",
        k4_relevance_score=42.0,
        tested_in_project=0,
        exhaustion_status="untested",
    ),
    # 2) Category-B investigative, positional.
    dict(
        record_id="fx-astrolabe",
        canonical_name="Astrolabe Cipher",
        cipher_family="positional",
        cipher_type="bespoke",
        taxonomy="historically_attested",
        operational_mechanics="Star-coordinate lookup against a brass plate.",
        description="A positional cipher using astrolabe coordinates.",
        k4_relevance_score=67.4,
        tested_in_project=0,
        exhaustion_status="untested",
    ),
    # 3) Exhausted — should be filtered out by tested_status check.
    dict(
        record_id="fx-compass-exhausted",
        canonical_name="Compass Cipher",
        cipher_family="positional",
        cipher_type="bespoke",
        taxonomy="historically_attested",
        operational_mechanics="Compass-bearing lookup.",
        description="Compass-based positional cipher.",
        k4_relevance_score=71.5,
        tested_in_project=1,
        exhaustion_status="exhausted",
    ),
    # 4) Unmapped cipher_family — should defer.
    dict(
        record_id="fx-unmapped",
        canonical_name="Mystery Cipher",
        cipher_family="entirely fictional bespoke art-cipher",
        cipher_type="bespoke",
        taxonomy="needs_human_review",
        operational_mechanics="Unspecified bespoke mechanism.",
        description="Unmapped on purpose for the fixture.",
        k4_relevance_score=30.0,
        tested_in_project=0,
        exhaustion_status="untested",
    ),
    # 5) Dispatcher-testable, polybius transposition — for ranking tests.
    dict(
        record_id="fx-adfgvx",
        canonical_name="ADFGVX Cipher",
        cipher_family="polybius transposition",
        cipher_type="historical",
        taxonomy="historically_attested",
        operational_mechanics="Polybius square then columnar transposition.",
        description="WWI-era polybius+columnar two-stage cipher.",
        k4_relevance_score=58.0,
        tested_in_project=0,
        exhaustion_status="untested",
    ),
]


def main() -> None:
    if OUT.exists():
        OUT.unlink()
    conn = sqlite3.connect(str(OUT))
    try:
        conn.executescript(_SCHEMA)
        cols = list(ROWS[0].keys())
        placeholders = ",".join("?" for _ in cols)
        sql = f"INSERT INTO cipher_records ({','.join(cols)}) VALUES ({placeholders})"
        for row in ROWS:
            conn.execute(sql, [row.get(c) for c in cols])
        conn.commit()
    finally:
        conn.close()
    print(f"wrote {OUT} with {len(ROWS)} rows")


if __name__ == "__main__":
    main()
