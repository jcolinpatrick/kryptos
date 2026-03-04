#!/usr/bin/env python3
"""
Cipher: Caesar (ROT-N)
Family: substitution
Status: exhausted
Keyspace: 0-25
Last run: 2026-03-04
Best score: 3.0 (crib_score)
"""
# ^^^ STANDARD HEADER — must be the first docstring, parseable without import.
#
# ORIGINAL DESCRIPTION (preserved for context):
# Exhaustive Caesar (ROT-N) disproof for K4.
# All 25 non-trivial shifts tested. Verdict: Tier-1 eliminated.
#
# This script demonstrates the standard attack() contract.
# Compare with the legacy version: scripts/disprove_caesar_rot.py

import sys
import os

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, BEAN_EQ, BEAN_INEQ,
)
from kryptos.kernel.scoring.aggregate import score_candidate


def caesar_decrypt(ct: str, shift: int) -> str:
    """ROT-(26-shift): subtract `shift` from each letter mod 26."""
    return "".join(ALPH[(ALPH_IDX[c] - shift) % MOD] for c in ct)


def attack(ciphertext: str, **params) -> list[tuple[float, str, str]]:
    """Standard attack contract.

    Returns list of (score, plaintext, method_description) tuples,
    sorted by score descending.
    """
    results = []
    for shift in range(1, 26):
        pt = caesar_decrypt(ciphertext, shift)
        sb = score_candidate(pt)
        results.append((
            float(sb.crib_score),
            pt,
            f"Caesar ROT-{shift}",
        ))
    results.sort(key=lambda x: -x[0])
    return results


def main():
    """Legacy-compatible entry point (prints results)."""
    print("=" * 60)
    print("Caesar ROT-N exhaustive sweep")
    print("=" * 60)

    results = attack(CT)
    for score, pt, method in results[:5]:
        print(f"  {score:5.1f}  {method:<20}  pt={pt[:40]}...")

    best_score = results[0][0] if results else 0
    print(f"\nBest: {best_score}/24 — VERDICT: ELIMINATED (Tier-1)")


if __name__ == "__main__":
    main()
