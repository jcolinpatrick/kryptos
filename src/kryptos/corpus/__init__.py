"""Egyptological corpus pipeline for running-key and keystream testing.

Ingests source texts, produces parallel transliteration-aware representations,
and generates variant families for cryptanalytic testing against K4.

Modules:
    schema     — CorpusPassage / Provenance dataclasses
    normalize  — Egyptological normalization rules engine
    variants   — Controlled variant expansion
    ingest     — Source text ingestion (local + Gutenberg)
"""

from kryptos.corpus.schema import CorpusPassage, Provenance
from kryptos.corpus.normalize import EgyptNormalizer
from kryptos.corpus.variants import VariantGenerator
from kryptos.corpus.ingest import TextIngester

__all__ = [
    "CorpusPassage",
    "Provenance",
    "EgyptNormalizer",
    "VariantGenerator",
    "TextIngester",
]
