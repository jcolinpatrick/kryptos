"""Corpus data structures with provenance tracking.

Every generated variant maintains a full chain-of-custody back to the exact
source passage, file, and normalization steps applied.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional


@dataclass
class Provenance:
    """Tracks the origin and processing history of a corpus passage."""
    source_file: str
    title: str
    author: str = ""
    gutenberg_id: Optional[int] = None
    section: str = ""
    chapter: str = ""
    line_start: int = 0
    line_end: int = 0
    original_text: str = ""
    normalization_steps: List[str] = field(default_factory=list)


@dataclass
class VariantRecord:
    """A single variant of a passage."""
    name: str
    text: str           # variant with formatting preserved
    alpha: str           # A-Z uppercase only
    alpha_length: int    # len(alpha)
    steps: List[str]     # normalization steps applied


@dataclass
class CorpusPassage:
    """A single passage with all its variant representations.

    Designed for JSONL serialization: one passage per line.
    """
    passage_id: str
    raw: str
    variants: Dict[str, Dict] = field(default_factory=dict)
    provenance: Provenance = field(
        default_factory=lambda: Provenance(source_file="", title="")
    )
    raw_alpha_length: int = 0

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, d: dict) -> CorpusPassage:
        prov_data = d.pop("provenance", {})
        prov = Provenance(**prov_data)
        return cls(provenance=prov, **d)

    @classmethod
    def from_json(cls, line: str) -> CorpusPassage:
        return cls.from_dict(json.loads(line))


@dataclass
class OffsetEntry:
    """Maps a range in a flat testing file back to a corpus passage."""
    offset_start: int
    offset_end: int
    passage_id: str
    source_file: str
    line_start: int
