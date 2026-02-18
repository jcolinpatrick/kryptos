"""Crib matching and implied key computation.

Provides functions to check plaintext candidates against known cribs,
compute implied keystream values, and check periodicity.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Dict, List, Optional, Tuple

from kryptos.kernel.constants import (
    CRIB_DICT, CRIB_ENTRIES, CRIB_POSITIONS, CT, N_CRIBS, MOD,
)
from kryptos.kernel.alphabet import Alphabet
from kryptos.kernel.transforms.vigenere import CipherVariant, KEY_RECOVERY


def crib_score(text: str) -> int:
    """Count how many of the 24 crib positions match in text."""
    return sum(
        1 for pos, ch in CRIB_DICT.items()
        if pos < len(text) and text[pos] == ch
    )


def crib_matches(text: str) -> Dict[int, bool]:
    """Return dict mapping each crib position to whether it matches."""
    return {
        pos: (pos < len(text) and text[pos] == ch)
        for pos, ch in CRIB_DICT.items()
    }


def compute_implied_keys(
    ct_text: str,
    variant: CipherVariant = CipherVariant.VIGENERE,
    pa: Optional[Alphabet] = None,
    ca: Optional[Alphabet] = None,
) -> List[Tuple[int, int]]:
    """Compute implied keystream values at each crib position.

    Returns list of (position, key_value) pairs.
    Uses standard A-Z if no alphabets provided.
    """
    fn = KEY_RECOVERY[variant]
    result: list[tuple[int, int]] = []

    if pa is not None and ca is not None:
        pa_idx = pa.index_table
        ca_idx = ca.index_table
        for pos, pt_ch in CRIB_ENTRIES:
            if pos < len(ct_text):
                c = ca_idx[ord(ct_text[pos]) - 65]
                p = pa_idx[ord(pt_ch) - 65]
                result.append((pos, fn(c, p)))
    else:
        for pos, pt_ch in CRIB_ENTRIES:
            if pos < len(ct_text):
                c = ord(ct_text[pos]) - 65
                p = ord(pt_ch) - 65
                result.append((pos, fn(c, p)))

    return result


def implied_key_dict(
    ct_text: str,
    variant: CipherVariant = CipherVariant.VIGENERE,
    pa: Optional[Alphabet] = None,
    ca: Optional[Alphabet] = None,
) -> Dict[int, int]:
    """Like compute_implied_keys but returns a dict: position -> key_value."""
    return dict(compute_implied_keys(ct_text, variant, pa, ca))


def periodicity_score(
    key_values: Dict[int, int], period: int,
) -> Tuple[int, int, int]:
    """Score how well key values fit a periodic pattern.

    Groups key values by (position % period). For each group,
    counts pairs that agree.

    Returns (agreeing_pairs, total_pairs, contradicting_groups).
    """
    groups: dict[int, list[int]] = defaultdict(list)
    for pos, val in key_values.items():
        groups[pos % period].append(val)

    agree = total = contradictions = 0
    for vals in groups.values():
        if len(vals) >= 2:
            npairs = len(vals) * (len(vals) - 1) // 2
            total += npairs
            if len(set(vals)) == 1:
                agree += npairs
            else:
                contradictions += 1
                for i in range(len(vals)):
                    for j in range(i + 1, len(vals)):
                        if vals[i] == vals[j]:
                            agree += 1
    return agree, total, contradictions


def best_periodicity(
    key_values: Dict[int, int],
    periods: range = range(3, 16),
) -> Tuple[int, int, int, int]:
    """Find the period with best agreement.

    Returns (period, agree, total, contradictions).
    """
    best = (0, 0, 0, 0)
    for p in periods:
        a, t, c = periodicity_score(key_values, p)
        if t > 0 and a > best[1]:
            best = (p, a, t, c)
    return best


def check_vimark_consistency(
    implied_keys: List[Tuple[int, int]],
    period: int,
) -> Tuple[int, int, Optional[Tuple[int, ...]]]:
    """Check Vimark consistency via majority voting by position mod period.

    Returns (n_consistent, total, primer_or_none).
    """
    groups: dict[int, list[int]] = {}
    for pos, kval in implied_keys:
        r = pos % period
        groups.setdefault(r, []).append(kval)

    consistent = 0
    primer: list[Optional[int]] = [None] * period

    for r in range(period):
        vals = groups.get(r, [])
        if not vals:
            continue
        valid = [v for v in vals if v >= 0]
        if not valid:
            continue
        cnt = Counter(valid)
        best_val, best_count = cnt.most_common(1)[0]
        consistent += best_count
        primer[r] = best_val

    is_perfect = consistent == N_CRIBS
    return (
        consistent,
        N_CRIBS,
        tuple(p if p is not None else 0 for p in primer)
        if is_perfect and all(v is not None for v in primer)
        else None,
    )
