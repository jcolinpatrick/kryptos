"""Polybius-aware scoring for Campaign V2 — RETIRED.

RETIRED 2026-04-14. This module was built for Campaign V2 and depends
on the retired null-palette / null-mask construct (claim_id:
null_palette_retired). It has ZERO live callers as of the 2026-04-14
quarantine audit (verified by grep across src/, kryptosbot/, tests/,
scripts/, ops/). It is retained for historical reproducibility only —
archived scripts that may import it will still work, but any new live
caller should be reviewed against memory/project_consensus_nulls_epistemic_status_2026_04_14.md.

A DeprecationWarning is emitted at module import time to surface any
future accidental revival in logs.

Augments the canonical crib scoring (kernel/scoring/aggregate.py) with
Polybius-specific structure checks based on the split-coordinate model:
  - Columns (mod 5) = stego layer  [retired framing]
  - Rows (mod 6) = cipher layer

The key metric is row key consistency: how many of the 24 known Beaufort
row key values does a candidate mechanism reproduce?
"""
from __future__ import annotations

import sys
import os
import warnings
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

warnings.warn(
    "kryptosbot.polybius_scorer is retired (2026-04-14). It depends on "
    "the retired null-palette / null-mask construct (claim_id: "
    "null_palette_retired). See "
    "memory/project_consensus_nulls_epistemic_status_2026_04_14.md. "
    "No live callers exist as of 2026-04-14; importing this module "
    "indicates either a regression or a historical reproducibility run.",
    DeprecationWarning,
    stacklevel=2,
)

# Allow importing kernel when run from kryptosbot/
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if os.path.join(_ROOT, "src") not in sys.path:
    sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, CRIB_POSITIONS, KRYPTOS_ALPHABET,
    BEAN_EQ, BEAN_INEQ, N_CRIBS, ALPH, ALPH_IDX,
)
# NULL_PALETTE, CONSENSUS_NULL_POSITIONS, BEAUFORT_KEYSTREAM_AT_CRIBS
# moved to kryptos.kernel.retired in framework maturation Phase 2
# (2026-04-20). This module is retired (see module docstring: "RETIRED
# 2026-04-14") and kept for historical reproducibility only; imports are
# on the retired-namespace allow-list in tests/test_retired_usage.py.
from kryptos.kernel.retired import (
    BEAUFORT_KEYSTREAM_AT_CRIBS,
    CONSENSUS_NULL_POSITIONS,
    NULL_PALETTE,
)

# ── KA Polybius grid constants ───────────────────────────────────────────

KA = KRYPTOS_ALPHABET
KA_WIDTH = 5
KA_NROWS = (len(KA) + KA_WIDTH - 1) // KA_WIDTH  # 6

KA_LETTER_TO_COORD: Dict[str, Tuple[int, int]] = {}
KA_COORD_TO_LETTER: Dict[Tuple[int, int], str] = {}
for _i, _ch in enumerate(KA):
    _r, _c = _i // KA_WIDTH, _i % KA_WIDTH
    KA_LETTER_TO_COORD[_ch] = (_r, _c)
    KA_COORD_TO_LETTER[(_r, _c)] = _ch

# ── Row key at crib positions (Beaufort A=0) ────────────────────────────
# Derived as K_r = (CT_r + PT_r) % 6 for each crib position.

CRIB_POSITIONS_ORDERED: Tuple[int, ...] = tuple(sorted(CRIB_DICT.keys()))

ROW_KEY_AT_CRIBS: Tuple[int, ...] = tuple(
    (KA_LETTER_TO_COORD[CT[pos]][0] + KA_LETTER_TO_COORD[CRIB_DICT[pos]][0]) % KA_NROWS
    for pos in CRIB_POSITIONS_ORDERED
)

COL_KEY_AT_CRIBS: Tuple[int, ...] = tuple(
    (KA_LETTER_TO_COORD[CT[pos]][1] - KA_LETTER_TO_COORD[CRIB_DICT[pos]][1]) % KA_WIDTH
    for pos in CRIB_POSITIONS_ORDERED
)

# Verify against MEMORY.md
assert ROW_KEY_AT_CRIBS == (4,4,1,4,1,5,0,0,5,4,1,2,1, 4,2,0,1,3,3,4,2,3,1,0), \
    f"Row key mismatch: {ROW_KEY_AT_CRIBS}"
assert len(CRIB_POSITIONS_ORDERED) == N_CRIBS


# ── Scoring dataclass ───────────────────────────────────────────────────

@dataclass
class PolybiusScore:
    """Extended score breakdown with Polybius-specific metrics."""
    # Standard metrics
    crib_score: int = 0
    bean_eq_passed: bool = False
    bean_ineq_passed: int = 0
    ngram_per_char: float = -10.0

    # Polybius-specific
    row_key_matches: int = 0
    row_key_mismatches: List[Tuple[int, int, int]] = field(default_factory=list)
    bean_eq_row_satisfied: bool = False
    mechanism_class: str = ""

    @property
    def is_signal(self) -> bool:
        """True only for genuine signals worth investigating."""
        return self.crib_score >= 18 and self.bean_eq_passed

    @property
    def is_promising(self) -> bool:
        """True for partial matches worth reporting to Opus."""
        return self.row_key_matches >= 10 or self.crib_score >= 10

    def summary(self) -> str:
        parts = [
            f"cribs={self.crib_score}/24",
            f"row_key={self.row_key_matches}/24",
            f"bean_eq={'Y' if self.bean_eq_passed else 'N'}",
        ]
        if self.mechanism_class:
            parts.append(f"class={self.mechanism_class}")
        return " ".join(parts)


# ── Core scoring functions ──────────────────────────────────────────────

def check_row_key_consistency(
    candidate_row_key: List[int],
) -> Tuple[int, List[Tuple[int, int, int]]]:
    """Check a 97-element mod-6 row key against known values at crib positions.

    Args:
        candidate_row_key: List of 97 ints, each in [0, 5].

    Returns:
        (match_count, mismatches) where mismatches is [(position, predicted, actual), ...].
    """
    matches = 0
    mismatches: List[Tuple[int, int, int]] = []
    for i, pos in enumerate(CRIB_POSITIONS_ORDERED):
        if pos >= len(candidate_row_key):
            mismatches.append((pos, -1, ROW_KEY_AT_CRIBS[i]))
            continue
        predicted = candidate_row_key[pos]
        actual = ROW_KEY_AT_CRIBS[i]
        if predicted == actual:
            matches += 1
        else:
            mismatches.append((pos, predicted, actual))
    return matches, mismatches


def row_key_from_plaintext(
    plaintext: str,
) -> List[int]:
    """Derive the implied mod-6 Beaufort row key from a plaintext.

    For each position i: K_r = (CT_r + PT_r) % 6
    where CT_r and PT_r are KA Polybius row coordinates.

    Returns a list of length min(len(plaintext), CT_LEN).
    Values are -1 if either character is not in KA.
    """
    n = min(len(plaintext), CT_LEN)
    row_key: List[int] = []
    for i in range(n):
        ct_ch = CT[i]
        pt_ch = plaintext[i]
        if ct_ch in KA_LETTER_TO_COORD and pt_ch in KA_LETTER_TO_COORD:
            ct_r = KA_LETTER_TO_COORD[ct_ch][0]
            pt_r = KA_LETTER_TO_COORD[pt_ch][0]
            row_key.append((ct_r + pt_r) % KA_NROWS)
        else:
            row_key.append(-1)
    return row_key


def col_key_from_plaintext(
    plaintext: str,
) -> List[int]:
    """Derive the implied mod-5 Vigenère column key from a plaintext.

    For each position i: K_c = (CT_c - PT_c) % 5
    """
    n = min(len(plaintext), CT_LEN)
    col_key: List[int] = []
    for i in range(n):
        ct_ch = CT[i]
        pt_ch = plaintext[i]
        if ct_ch in KA_LETTER_TO_COORD and pt_ch in KA_LETTER_TO_COORD:
            ct_c = KA_LETTER_TO_COORD[ct_ch][1]
            pt_c = KA_LETTER_TO_COORD[pt_ch][1]
            col_key.append((ct_c - pt_c) % KA_WIDTH)
        else:
            col_key.append(-1)
    return col_key


def count_crib_matches(plaintext: str) -> int:
    """Count how many crib positions match in a plaintext."""
    hits = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(plaintext) and plaintext[pos] == ch:
            hits += 1
    return hits


def check_bean_eq(plaintext: str) -> bool:
    """Check Bean equality constraint: keystream at pos 27 == keystream at pos 65.

    Uses Beaufort: K[i] = (CT[i] + PT[i]) mod 26 on standard alphabet.
    """
    for a, b in BEAN_EQ:
        if a >= len(plaintext) or b >= len(plaintext):
            return False
        ka = (ALPH_IDX[CT[a]] + ALPH_IDX[plaintext[a]]) % 26
        kb = (ALPH_IDX[CT[b]] + ALPH_IDX[plaintext[b]]) % 26
        if ka != kb:
            return False
    return True


def check_bean_ineq(plaintext: str) -> int:
    """Count how many of 242 Bean inequalities are satisfied.

    Uses Beaufort: K[i] = (CT[i] + PT[i]) mod 26 on standard alphabet.
    """
    passed = 0
    for a, b in BEAN_INEQ:
        if a >= len(plaintext) or b >= len(plaintext):
            continue
        ka = (ALPH_IDX[CT[a]] + ALPH_IDX[plaintext[a]]) % 26
        kb = (ALPH_IDX[CT[b]] + ALPH_IDX[plaintext[b]]) % 26
        if ka != kb:
            passed += 1
    return passed


def check_bean_eq_row(row_key: List[int]) -> bool:
    """Check Bean equality in row-key space: row_key[27] == row_key[65]."""
    for a, b in BEAN_EQ:
        if a >= len(row_key) or b >= len(row_key):
            return False
        if row_key[a] != row_key[b]:
            return False
    return True


def score_polybius_candidate(
    plaintext: str,
    mechanism_class: str = "",
) -> PolybiusScore:
    """Full Polybius-aware scoring of a plaintext candidate.

    Computes standard crib score + row key consistency + Bean constraints.
    """
    if not plaintext or not plaintext.isalpha() or not plaintext.isupper():
        return PolybiusScore(mechanism_class=mechanism_class)

    crib_score = count_crib_matches(plaintext)
    bean_eq = check_bean_eq(plaintext) if len(plaintext) >= CT_LEN else False
    bean_ineq = check_bean_ineq(plaintext) if len(plaintext) >= CT_LEN else 0

    rk = row_key_from_plaintext(plaintext)
    rk_matches, rk_mismatches = check_row_key_consistency(rk)
    bean_eq_row = check_bean_eq_row(rk) if len(rk) >= CT_LEN else False

    return PolybiusScore(
        crib_score=crib_score,
        bean_eq_passed=bean_eq,
        bean_ineq_passed=bean_ineq,
        row_key_matches=rk_matches,
        row_key_mismatches=rk_mismatches,
        bean_eq_row_satisfied=bean_eq_row,
        mechanism_class=mechanism_class,
    )
