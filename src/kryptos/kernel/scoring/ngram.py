"""N-gram scoring for plaintext quality assessment.

Uses log-probability quadgram scoring (standard in classical cryptanalysis).
"""
from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Dict, Optional


class NgramScorer:
    """Score text using n-gram log probabilities.

    Higher scores indicate more English-like text.
    """

    def __init__(self, log_probs: Dict[str, float], n: int = 4) -> None:
        self.log_probs = log_probs
        self.n = n
        self._floor = min(log_probs.values()) if log_probs else -10.0

    def score(self, text: str) -> float:
        """Compute total log-probability score for text."""
        text = text.upper()
        total = 0.0
        for i in range(len(text) - self.n + 1):
            gram = text[i : i + self.n]
            total += self.log_probs.get(gram, self._floor)
        return total

    def score_per_char(self, text: str) -> float:
        """Compute average log-probability per character."""
        text = text.upper()
        n_grams = len(text) - self.n + 1
        if n_grams <= 0:
            return self._floor
        return self.score(text) / n_grams

    @classmethod
    def from_file(cls, path: str | Path, n: int = 4) -> "NgramScorer":
        """Load n-gram probabilities from a JSON file.

        Supports two formats:
        - Flat: {"TION": -1.234, ...}
        - Nested: {"logp": {"TION": -1.234, ...}}
        """
        with open(path) as f:
            data = json.load(f)

        if "logp" in data:
            data = data["logp"]

        return cls(data, n)


# ── Singleton loader ──────────────────────────────────────────────────────

_default_scorer: Optional[NgramScorer] = None


def get_default_scorer() -> NgramScorer:
    """Get or create the default quadgram scorer.

    Looks for quadgram data at standard locations.
    """
    global _default_scorer
    if _default_scorer is not None:
        return _default_scorer

    search_paths = [
        Path("results/anneal_step7_start8/english_quadgrams.json"),
        Path("data/english_quadgrams.json"),
        Path(__file__).parent.parent.parent.parent.parent / "results/anneal_step7_start8/english_quadgrams.json",
    ]

    for p in search_paths:
        if p.exists():
            _default_scorer = NgramScorer.from_file(p)
            return _default_scorer

    raise FileNotFoundError(
        f"Could not find quadgram file at any of: {[str(p) for p in search_paths]}"
    )
