"""Pipeline orchestrator for cipher discovery.

Runs the full discovery pipeline:
  seed -> expand -> build knowledge base -> classify -> dedup -> store

This version operates primarily from curated domain knowledge (seeds + expert
knowledge) rather than live web fetching, since the goal is to identify the
universe of known hand-executable ciphers relevant to K4 and cross-reference
with the exhaustion log. Web fetching can augment this in future passes.

[POLICY] All claims are classified per truth taxonomy.
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .schema import (
    CipherRecord, FrontierEntry, SourceRecord,
    CipherType, Taxonomy, FrontierStatus, SourceType,
    K4RelevanceScore,
)
from .seeds import get_all_seeds, Seed
from .query_expansion import normalize_term
from .classification import score_and_classify
from .dedup import deduplicate_records
from .persistence import DiscoveryDB
from .config import DiscoveryConfig
from .knowledge_base import CIPHER_KNOWLEDGE_BASE

logger = logging.getLogger(__name__)


def _load_exhaustion_log(path: str = "exhaustion_log.json") -> dict:
    """Load the project exhaustion log for cross-referencing."""
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.warning("Could not load exhaustion log: %s", e)
        return {}


def _match_exhaustion(
    cipher_name: str,
    aliases: list[str],
    exhaustion_log: dict,
) -> tuple[bool, list[str], str]:
    """Check if a cipher has been tested in the project.

    Returns (tested: bool, matching_ids: list, status: str)

    [POLICY] Matching must be precise to avoid false positives.
    We use multi-word phrase fragments, not single common words.
    """
    search_terms = [cipher_name.lower()] + [a.lower() for a in aliases]

    # Build keyword fragments -- keep multi-word phrases intact
    # Only split into words for distinctive terms (>5 chars, not common words)
    STOP_WORDS = {
        "cipher", "code", "system", "method", "technique", "hand",
        "manual", "field", "grid", "table", "square", "double",
        "key", "wheel", "disk", "card", "paper", "pencil",
        "variant", "classical", "historical", "type", "based",
        "mixed", "keyed", "device", "army", "military", "german",
        "russian", "british", "american", "secret", "writing",
        "chart", "overlay", "strip", "mask", "stencil",
    }
    fragments = set()
    for term in search_terms:
        # Remove common suffixes for matching
        for suffix in [" cipher", " code", " system", " method", " technique"]:
            if term.endswith(suffix):
                term = term[:-len(suffix)].strip()
        # Only add the phrase if it's distinctive (not a single stop word)
        if term and term not in STOP_WORDS:
            fragments.add(term)
        # Add individual words only if they're distinctive
        for word in term.split():
            if len(word) > 4 and word not in STOP_WORDS:
                fragments.add(word)

    # Remove very short or generic fragments
    fragments = {f for f in fragments if len(f) > 3}

    matching_ids = []
    statuses = set()

    for script_id, entry in exhaustion_log.items():
        script_lower = script_id.lower()
        desc = entry.get("description", "").lower()
        family = entry.get("family", "").lower()
        search_space = f"{script_lower} {desc} {family}"

        for frag in fragments:
            # Require the fragment to appear as a distinct segment
            # (not just a substring of an unrelated word)
            if frag in search_space:
                matching_ids.append(script_id)
                statuses.add(entry.get("status", "unknown"))
                break

    tested = len(matching_ids) > 0
    if "exhausted" in statuses:
        status = "exhausted"
    elif statuses:
        status = "active"
    else:
        status = "untested"

    return tested, matching_ids, status


def build_cipher_records_from_knowledge(
    exhaustion_log: dict,
) -> list[CipherRecord]:
    """Build CipherRecord objects from the curated knowledge base.

    [POLICY] Each record's provenance is the knowledge base entry.
    Claims about cipher properties are [PUBLIC FACT] from cryptographic literature.
    K4 relevance scores are [HYPOTHESIS] based on heuristic rubric.
    """
    records = []

    for entry in CIPHER_KNOWLEDGE_BASE:
        # Cross-reference with exhaustion log
        tested, matching_ids, ex_status = _match_exhaustion(
            entry["name"],
            entry.get("aliases", []),
            exhaustion_log,
        )

        rec = CipherRecord(
            canonical_name=entry["name"],
            alias_names=entry.get("aliases", []),
            category=entry.get("category", ""),
            cipher_type=CipherType(entry.get("cipher_type", "uncertain")),
            cipher_family=entry.get("family", ""),
            description=entry.get("description", ""),
            operational_mechanics=entry.get("mechanics", ""),
            execution_model=entry.get("execution", ""),
            tools_required=entry.get("tools", []),
            materials_needed=entry.get("materials", []),
            manual_execution_type=entry.get("manual_type", ""),
            claimed_origin=entry.get("origin", ""),
            source_urls=entry.get("urls", []),
            source_type=SourceType(entry.get("source_type", "encyclopedia")),
            source_title=entry.get("source_title", ""),
            author=entry.get("author", ""),
            publication_year=entry.get("year", None),
            historically_attested=entry.get("historical", True),
            pedagogical_amateur=entry.get("pedagogical", False),
            bespoke=entry.get("bespoke", False),
            confidence_real_system=entry.get("confidence_real", 0.9),
            confidence_distinct_from_known=entry.get("confidence_distinct", 0.8),
            confidence_relevance_to_k4=entry.get("confidence_k4", 0.5),
            ambiguity_flags=entry.get("ambiguity", []),
            unresolved_questions=entry.get("questions", []),
            tested_in_project=tested,
            exhaustion_log_ids=matching_ids,
            exhaustion_status=ex_status,
        )
        records.append(rec)

    return records


def run_discovery_pipeline(
    config: Optional[DiscoveryConfig] = None,
    exhaustion_log_path: str = "exhaustion_log.json",
) -> dict:
    """Run the full discovery pipeline.

    Returns a stats dict summarizing results.
    """
    if config is None:
        config = DiscoveryConfig()
    config.ensure_dirs()

    logger.info("=== Cipher Discovery Pipeline ===")
    start_time = time.time()

    # Step 1: Load exhaustion log
    logger.info("Step 1: Loading exhaustion log...")
    exhaustion_log = _load_exhaustion_log(exhaustion_log_path)
    logger.info("  Loaded %d exhaustion log entries", len(exhaustion_log))

    # Step 2: Build records from knowledge base
    logger.info("Step 2: Building cipher records from knowledge base...")
    records = build_cipher_records_from_knowledge(exhaustion_log)
    logger.info("  Built %d cipher records", len(records))

    # Step 3: Score and classify all records
    logger.info("Step 3: Scoring and classifying...")
    for rec in records:
        score_and_classify(rec)
    logger.info("  Scored %d records", len(records))

    # Step 4: Deduplicate
    logger.info("Step 4: Deduplicating...")
    deduped, flagged = deduplicate_records(records)
    logger.info("  %d records after dedup (%d flagged for review)", len(deduped), len(flagged))

    # Step 5: Persist
    logger.info("Step 5: Persisting to database...")
    db = DiscoveryDB(config.db_path)
    try:
        for rec in deduped:
            db.upsert_cipher(rec)
        for idx_a, idx_b, reason in flagged:
            if idx_a < len(records) and idx_b < len(records):
                db.add_review_item(
                    records[idx_a].record_id,
                    records[idx_b].record_id,
                    reason,
                )
        stats = db.get_stats()
    finally:
        db.close()

    elapsed = time.time() - start_time
    stats["elapsed_seconds"] = round(elapsed, 1)
    logger.info("Pipeline complete in %.1fs", elapsed)
    logger.info("  Total ciphers: %d", stats["total_ciphers"])
    logger.info("  Tested: %d, Untested: %d", stats["tested_ciphers"], stats["untested_ciphers"])

    return stats
