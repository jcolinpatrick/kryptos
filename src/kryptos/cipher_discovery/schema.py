"""Data models for cipher discovery subsystem.

All models are stdlib dataclasses. No external dependencies.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class CipherType(Enum):
    SUBSTITUTION = "substitution"
    TRANSPOSITION = "transposition"
    MIXED = "mixed"
    FRACTIONATION = "fractionation"
    SIGNALING = "signaling"
    SPATIAL = "spatial"
    SYMBOLIC = "symbolic"
    STEGANOGRAPHIC = "steganographic"
    MECHANICAL = "mechanical"
    UNCERTAIN = "uncertain"


class Taxonomy(Enum):
    """Classification of a discovered cipher claim."""
    CONFIRMED_NAMED = "confirmed_named_manual_cipher"
    PROBABLE_POORLY_EVIDENCED = "probable_but_poorly_evidenced"
    ALIAS_OF_KNOWN = "alias_or_synonym_of_known"
    ADJACENT_SYMBOLIC = "adjacent_symbolic_system"
    SIGNALING_REPURPOSABLE = "signaling_system_repurposable_as_cipher"
    ARTISTIC_BESPOKE = "artistic_or_bespoke_encoding"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_human_review"


class FrontierStatus(Enum):
    PENDING = "pending"
    FETCHED = "fetched"
    PARSED = "parsed"
    EXPANDED = "expanded"
    REJECTED = "rejected"
    MERGED = "merged"
    NEEDS_REVIEW = "needs_review"


class SourceType(Enum):
    WEB_PAGE = "web_page"
    BOOK = "book"
    JOURNAL = "journal"
    PATENT = "patent"
    MILITARY_MANUAL = "military_manual"
    EDUCATIONAL = "educational"
    FORUM = "forum"
    ENCYCLOPEDIA = "encyclopedia"
    ARCHIVE = "archive"
    PRIMARY_SOURCE = "primary_source"
    UNKNOWN = "unknown"


@dataclass
class CipherRecord:
    """A discovered cipher system with full provenance and scoring."""
    # Identity
    canonical_name: str
    alias_names: list[str] = field(default_factory=list)
    record_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])

    # Classification
    category: str = ""  # broad category (e.g., "polyalphabetic", "transposition")
    cipher_type: CipherType = CipherType.UNCERTAIN
    taxonomy: Taxonomy = Taxonomy.NEEDS_REVIEW
    cipher_family: str = ""  # finer grouping (e.g., "Vigenere family")

    # Description
    description: str = ""
    operational_mechanics: str = ""
    execution_model: str = ""  # how the cipher is performed step-by-step
    tools_required: list[str] = field(default_factory=list)
    materials_needed: list[str] = field(default_factory=list)
    manual_execution_type: str = ""  # "paper_pencil", "tabula_recta", "grid", "wheel", etc.

    # Provenance
    claimed_origin: str = ""
    source_urls: list[str] = field(default_factory=list)
    quote_snippets: list[str] = field(default_factory=list)  # short excerpts only
    source_type: SourceType = SourceType.UNKNOWN
    source_title: str = ""
    author: str = ""
    publication_year: Optional[int] = None

    # Flags
    historically_attested: bool = False
    pedagogical_amateur: bool = False
    bespoke: bool = False
    requires_human_review: bool = True

    # Confidence scores (0.0 - 1.0)
    confidence_real_system: float = 0.0
    confidence_distinct_from_known: float = 0.0
    confidence_relevance_to_k4: float = 0.0

    # Scoring
    obscurity_score: float = 0.0  # 0 = well-known, 1.0 = extremely obscure
    k4_relevance_score: float = 0.0  # 0-100, computed by rubric
    k4_score_breakdown: dict = field(default_factory=dict)

    # Flags and notes
    ambiguity_flags: list[str] = field(default_factory=list)
    extraction_notes: str = ""
    unresolved_questions: list[str] = field(default_factory=list)

    # Exhaustion log cross-reference
    tested_in_project: bool = False
    exhaustion_log_ids: list[str] = field(default_factory=list)
    exhaustion_status: str = ""  # "exhausted", "active", "untested"

    # Timestamps
    discovered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        d = asdict(self)
        d["cipher_type"] = self.cipher_type.value
        d["taxonomy"] = self.taxonomy.value
        d["source_type"] = self.source_type.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> CipherRecord:
        d = dict(d)
        if "cipher_type" in d and isinstance(d["cipher_type"], str):
            d["cipher_type"] = CipherType(d["cipher_type"])
        if "taxonomy" in d and isinstance(d["taxonomy"], str):
            d["taxonomy"] = Taxonomy(d["taxonomy"])
        if "source_type" in d and isinstance(d["source_type"], str):
            d["source_type"] = SourceType(d["source_type"])
        return cls(**d)


@dataclass
class FrontierEntry:
    """A term or URL in the discovery queue."""
    entry_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    term: str = ""
    url: str = ""
    status: FrontierStatus = FrontierStatus.PENDING
    priority: int = 0  # higher = more important
    depth: int = 0  # expansion depth from seed
    parent_term: str = ""
    discovered_terms: list[str] = field(default_factory=list)
    notes: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    processed_at: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class SourceRecord:
    """A fetched source with metadata."""
    source_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    url: str = ""
    domain: str = ""
    title: str = ""
    fetch_status: int = 0  # HTTP status code
    content_hash: str = ""
    content_length: int = 0
    fetched_at: str = ""
    extracted_terms: list[str] = field(default_factory=list)
    error_message: str = ""
    robots_blocked: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class K4RelevanceScore:
    """Breakdown of K4 relevance scoring rubric.

    Each factor is scored 0-10, weighted, and normalized to 0-100.
    [POLICY] This is a heuristic scoring system, not a proof.
    """
    manual_executability: float = 0.0       # weight 2.0
    artist_feasibility: float = 0.0         # weight 1.5
    spatial_geometric: float = 0.0          # weight 1.5
    compass_bearing_relation: float = 0.0   # weight 2.0
    morse_signaling_relation: float = 0.0   # weight 1.5
    bespoke_hybrid: float = 0.0             # weight 1.5
    physical_aid_use: float = 0.0           # weight 1.0
    short_text_plausibility: float = 0.0    # weight 1.0
    sanborn_theme_compatibility: float = 0.0  # weight 1.5

    WEIGHTS = {
        "manual_executability": 2.0,
        "artist_feasibility": 1.5,
        "spatial_geometric": 1.5,
        "compass_bearing_relation": 2.0,
        "morse_signaling_relation": 1.5,
        "bespoke_hybrid": 1.5,
        "physical_aid_use": 1.0,
        "short_text_plausibility": 1.0,
        "sanborn_theme_compatibility": 1.5,
    }

    def compute_total(self) -> float:
        """Compute weighted total normalized to 0-100 scale."""
        raw = 0.0
        max_raw = 0.0
        for attr, weight in self.WEIGHTS.items():
            raw += getattr(self, attr) * weight
            max_raw += 10.0 * weight
        if max_raw == 0:
            return 0.0
        return (raw / max_raw) * 100.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("WEIGHTS", None)
        d["total"] = self.compute_total()
        return d
