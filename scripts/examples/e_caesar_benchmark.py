#!/usr/bin/env python3
"""
Cipher: Caesar (ROT-N)
Family: substitution
Status: exhausted
Keyspace: 0-25
Last run: 2026-03-04
Best score: N/A (benchmark-only)
"""
# Caesar solver for benchmarking: scores candidates by quadgram fitness
# (English-likeness) rather than K4-specific crib matching.  This ensures
# the correct plaintext reliably ranks #1 for any English-language input.

import sys
import os

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from kryptos.kernel.constants import ALPH, ALPH_IDX, MOD
from kryptos.kernel.scoring.ngram import get_default_scorer


_scorer = None


def _get_scorer():
    global _scorer
    if _scorer is None:
        _scorer = get_default_scorer()
    return _scorer


def caesar_decrypt(ct: str, shift: int) -> str:
    """ROT-(26-shift): subtract shift from each letter mod 26."""
    return "".join(ALPH[(ALPH_IDX[c] - shift) % MOD] for c in ct if c in ALPH_IDX)


def attack(ciphertext: str, **params) -> list[tuple[float, str, str]]:
    """Standard attack contract — scored by quadgram fitness.

    Returns list of (score, plaintext, method_description) tuples,
    sorted by score descending (highest = most English-like).
    """
    scorer = _get_scorer()
    ct = "".join(c for c in ciphertext.upper() if c in ALPH_IDX)
    results = []
    for shift in range(26):
        pt = caesar_decrypt(ct, shift)
        qg = scorer.score_per_char(pt) if len(pt) >= 4 else -10.0
        results.append((qg, pt, f"Caesar ROT-{shift}"))
    results.sort(key=lambda x: -x[0])
    return results
