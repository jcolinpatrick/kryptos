"""Generate a Lunr.js-compatible search index from SiteElimination objects."""
from __future__ import annotations

import json
from pathlib import Path

from .data_loader import SiteElimination


def build_search_documents(eliminations: list[SiteElimination]) -> list[dict]:
    """Convert eliminations into search documents for Lunr.js indexing."""
    docs = []
    for elim in eliminations:
        doc = {
            "id": elim.slug,
            "title": elim.title,
            "description": elim.description[:500],
            "category": elim.category,
            "subcategory": elim.subcategory,
            "cipher_type": elim.cipher_type,
            "tags": " ".join(elim.tags),
            "key_model": elim.key_model,
            "transposition_family": elim.transposition_family,
            "verdict": elim.verdict,
            "best_score": str(elim.best_score),
            "configs_tested": str(elim.configs_tested),
            "experiment_id": elim.id,
        }
        docs.append(doc)
    return docs


def build_search_index(eliminations: list[SiteElimination]) -> dict:
    """Build the full search index structure for the frontend.

    Returns a dict with:
      - "fields": list of searchable field names
      - "documents": list of document dicts
      - "ref": the reference field name
    """
    documents = build_search_documents(eliminations)
    return {
        "ref": "id",
        "fields": [
            "title",
            "description",
            "category",
            "subcategory",
            "cipher_type",
            "tags",
            "key_model",
            "transposition_family",
            "verdict",
            "experiment_id",
        ],
        "documents": documents,
    }


def write_search_index(eliminations: list[SiteElimination], output_path: str) -> int:
    """Write search index JSON to disk. Returns number of documents indexed."""
    index = build_search_index(eliminations)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(index, f, separators=(",", ":"))
    return len(index["documents"])
