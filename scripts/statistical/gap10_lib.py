"""Pure statistics for the GAP-10 positional-measurement program.

Prereg: docs/campaigns/gap10_positional_measurement_2026_06_11.md.
Tests: tests/test_gap10_measurement.py (TDD — written first).

All functions are deterministic given their inputs; null samplers take an
explicit random.Random instance. Component-1 randomness is over COUNTERFACTUAL
constraint systems (re-derived from resampled CT letters at crib positions),
never within the 624 Bean-valid keystreams (affine-orbit lemma: within-624
tails floor at 1/2 for equality-pattern statistics).
"""
from __future__ import annotations

import os
import sys
from collections import Counter
from typing import Iterable, Sequence

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
if os.path.join(_ROOT, "src") not in sys.path:
    sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CRIB_DICT  # noqa: E402
from kryptos.kernel.constraints.derive import derive_bean_constraints  # noqa: E402

PERIODS = tuple(range(2, 27))
POSITIONS = tuple(sorted(CRIB_DICT))
_IDENTITY_TABLE = tuple(range(26))


# ── IC (component 2) ──────────────────────────────────────────────────────

def ic(text: str) -> float:
    """Index of coincidence: sum c_a(c_a-1) / (n(n-1))."""
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def region_ic(ct: str, positions: Iterable[int]) -> float:
    return ic("".join(ct[i] for i in positions))


# ── Residue machinery (component 1) ───────────────────────────────────────

def same_residue_pair_count(positions: Sequence[int], p: int) -> int:
    """N(p): number of position pairs sharing a residue class mod p."""
    counts = Counter(pos % p for pos in positions)
    return sum(c * (c - 1) // 2 for c in counts.values())


def conflict_count(ineq: Iterable[tuple[int, int]], p: int) -> int:
    """C(p): Bean-inequality pairs that a period-p key would force equal."""
    return sum(1 for a, b in ineq if a % p == b % p)


def ineq_from_crib_letters(letters: Sequence[str]) -> tuple[tuple[int, int], ...]:
    """Re-derive the Bean inequality set for counterfactual CT crib letters.

    Only the CT characters AT crib positions feed the derivation, so the rest
    of the dummy CT is filler.
    """
    ct = ["A"] * (max(POSITIONS) + 1)
    for pos, ch in zip(POSITIONS, letters):
        ct[pos] = ch
    _eq, ineq, _lin = derive_bean_constraints(
        "".join(ct), CRIB_DICT, _IDENTITY_TABLE
    )
    return tuple(ineq)


def cp_profile(ineq: Iterable[tuple[int, int]]) -> dict[int, int]:
    """C(p) for every period in PERIODS."""
    pairs = tuple(ineq)
    return {p: conflict_count(pairs, p) for p in PERIODS}


# ── Null samplers (component 1) ───────────────────────────────────────────

_REAL_CRIB_CT: tuple[str, ...] | None = None


def _real_crib_ct() -> tuple[str, ...]:
    global _REAL_CRIB_CT
    if _REAL_CRIB_CT is None:
        from kryptos.kernel.constants import CT

        _REAL_CRIB_CT = tuple(CT[p] for p in POSITIONS)
    return _REAL_CRIB_CT


def perm_crib_letters(rng) -> list[str]:
    """N1a: permute the real multiset of CT crib letters across positions."""
    letters = list(_real_crib_ct())
    rng.shuffle(letters)
    return letters


def iid_crib_letters(rng) -> list[str]:
    """N1b: IID uniform A-Z letters at the crib positions."""
    return [chr(65 + rng.randrange(26)) for _ in POSITIONS]


# ── Boundary change statistic (component 3) ───────────────────────────────

def tv_distance(s1: str, s2: str) -> float:
    """Total-variation distance between unigram distributions."""
    c1, c2 = Counter(s1), Counter(s2)
    n1, n2 = len(s1), len(s2)
    keys = set(c1) | set(c2)
    return 0.5 * sum(abs(c1[k] / n1 - c2[k] / n2) for k in keys)


def dw_profile(ct: str, w: int) -> dict[int, float]:
    """D_w(x) = TV(CT[x-w:x], CT[x:x+w]) for valid centers x in [w, len-w]."""
    return {
        x: tv_distance(ct[x - w:x], ct[x:x + w])
        for x in range(w, len(ct) - w + 1)
    }


# ── Tail machinery ────────────────────────────────────────────────────────

def two_sided_tail(obs: float, null_vals: Sequence[float]) -> float:
    """Two-sided add-one empirical tail: 2*min(P>=, P<=), capped at 1."""
    m = len(null_vals)
    ge = sum(1 for v in null_vals if v >= obs)
    le = sum(1 for v in null_vals if v <= obs)
    p_hi = (ge + 1) / (m + 1)
    p_lo = (le + 1) / (m + 1)
    return min(1.0, 2.0 * min(p_hi, p_lo))


def one_sided_high_tail(obs: float, null_vals: Sequence[float]) -> float:
    m = len(null_vals)
    return (sum(1 for v in null_vals if v >= obs) + 1) / (m + 1)


def holm(pvals: dict, alpha: float = 0.01) -> dict:
    """Holm step-down: returns {key: (p, p_holm, reject)}."""
    items = sorted(pvals.items(), key=lambda kv: kv[1])
    n = len(items)
    out = {}
    running_max = 0.0
    rejecting = True
    for rank, (key, p) in enumerate(items):
        adj = min(1.0, (n - rank) * p)
        running_max = max(running_max, adj)
        if p > alpha / (n - rank):
            rejecting = False
        out[key] = (p, running_max, rejecting)
    return out
