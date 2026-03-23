"""Stego-cipher coupling constraints (CxS-1 through CxS-4).

Quantifies statistical relationships between the stego layer (null palette)
and the cipher layer (Beaufort keystream at crib positions). These are
DERIVED FACTs — deterministic consequences of the confirmed null palette
{B,G,I,K,O,W,Z} and the Beaufort keystream JLJODEGKUKKKLOCGGBGOKTRU.

Each constraint is a DerivedConstraint with an exact binomial p-value,
allowing falsifiability testing and cross-layer dependency tracking.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from math import comb
from typing import FrozenSet, List

from kryptos.kernel.constants import ALPH, KRYPTOS_ALPHABET, MOD


@dataclass
class DerivedConstraint:
    """A single derived coupling constraint between stego and cipher layers."""

    id: str
    name: str
    description: str
    observed: int | float | bool
    expected: float
    evidence: list[str]
    p_value: float
    constraint_type: str
    falsifiable: str


def _binomial_tail(n: int, k: int, p: float) -> float:
    """P(X >= k) where X ~ Binomial(n, p).

    Uses exact computation via combinatorics (no scipy needed).
    """
    total = 0.0
    for i in range(k, n + 1):
        total += comb(n, i) * (p ** i) * ((1.0 - p) ** (n - i))
    return total


def keystream_palette_enrichment(
    keystream_nums: list[int],
    palette: FrozenSet[str],
) -> DerivedConstraint:
    """CxS-1: Count keystream values mapping to palette letters.

    For each of the 24 keystream integers (A=0), convert to a letter
    and check membership in the null palette. The real K4 keystream
    has 13/24 palette hits vs 6.46 expected under random.

    Args:
        keystream_nums: List of 24 integers (A=0) representing keystream values.
        palette: Set of uppercase letters forming the null palette.

    Returns:
        DerivedConstraint with binomial tail p-value.
    """
    n = len(keystream_nums)
    palette_nums = frozenset(ALPH.index(c) for c in palette)
    hits = sum(1 for v in keystream_nums if v in palette_nums)
    p_letter = len(palette) / MOD  # 7/26
    expected = n * p_letter
    p_value = _binomial_tail(n, hits, p_letter)

    return DerivedConstraint(
        id="CxS-1",
        name="Keystream-palette enrichment",
        description=(
            f"{hits}/{n} keystream values map to palette letters "
            f"(expected {expected:.2f} under random)"
        ),
        observed=hits,
        expected=expected,
        evidence=[
            f"palette={sorted(palette)}",
            f"keystream_letters={''.join(ALPH[v] for v in keystream_nums)}",
            f"hits={hits}/{n}",
        ],
        p_value=p_value,
        constraint_type="statistical",
        falsifiable=(
            "Would be falsified if palette membership were ≤ expected "
            f"({expected:.1f}) or p > 0.05"
        ),
    )


def mod5_ka_structure(
    keystream_nums: list[int],
) -> DerivedConstraint:
    """CxS-2: Keystream values cluster at KA positions with index % 5 in {0, 3}.

    For each keystream value (integer, A=0), convert to a standard letter,
    find its index in KRYPTOS_ALPHABET, and check if that index mod 5
    is in {0, 3}. This captures the Polybius row structure of the
    KRYPTOS x SEVEN stego grid.

    Args:
        keystream_nums: List of 24 integers (A=0) representing keystream values.

    Returns:
        DerivedConstraint with binomial tail p-value.
    """
    n = len(keystream_nums)

    # Count how many of the 26 letters satisfy ka_index % 5 in {0, 3}
    qualifying_letters = 0
    for letter in ALPH:
        ka_idx = KRYPTOS_ALPHABET.index(letter)
        if ka_idx % 5 in {0, 3}:
            qualifying_letters += 1

    # Count hits in keystream
    hits = 0
    for v in keystream_nums:
        letter = ALPH[v]
        ka_idx = KRYPTOS_ALPHABET.index(letter)
        if ka_idx % 5 in {0, 3}:
            hits += 1

    p_letter = qualifying_letters / MOD
    expected = n * p_letter
    p_value = _binomial_tail(n, hits, p_letter)

    return DerivedConstraint(
        id="CxS-2",
        name="Mod-5 KA structure",
        description=(
            f"{hits}/{n} keystream values have KA index % 5 in {{0, 3}} "
            f"(expected {expected:.2f}, {qualifying_letters}/26 letters qualify)"
        ),
        observed=hits,
        expected=expected,
        evidence=[
            f"qualifying_letters={qualifying_letters}/26",
            f"hits={hits}/{n}",
            f"KA={KRYPTOS_ALPHABET}",
        ],
        p_value=p_value,
        constraint_type="statistical",
        falsifiable=(
            "Would be falsified if hits were ≤ expected "
            f"({expected:.1f}) or p > 0.05"
        ),
    )


def ap_palette_containment(
    keystream_nums: list[int],
    palette: FrozenSet[str],
) -> DerivedConstraint:
    """CxS-3: Arithmetic progression {G=6, K=10, O=14} dominates keystream.

    The AP has step 4 in standard alphabet (A=0). Count how many of the
    24 keystream values are members of this 3-element AP. Also verify
    that all 3 AP members are palette letters.

    Args:
        keystream_nums: List of 24 integers (A=0) representing keystream values.
        palette: Set of uppercase letters forming the null palette.

    Returns:
        DerivedConstraint with binomial tail p-value.
    """
    ap_set = {6, 10, 14}  # G, K, O in A=0
    ap_letters = {ALPH[v] for v in ap_set}
    n = len(keystream_nums)

    hits = sum(1 for v in keystream_nums if v in ap_set)
    all_in_palette = ap_letters <= palette

    p_letter = len(ap_set) / MOD  # 3/26
    expected = n * p_letter
    p_value = _binomial_tail(n, hits, p_letter)

    return DerivedConstraint(
        id="CxS-3",
        name="AP palette containment",
        description=(
            f"{hits}/{n} keystream values are in AP {{G,K,O}} (step 4, A=0). "
            f"All AP members in palette: {all_in_palette}. "
            f"Expected {expected:.2f} under random."
        ),
        observed=hits,
        expected=expected,
        evidence=[
            f"AP={{G=6, K=10, O=14}}, step=4",
            f"hits={hits}/{n}",
            f"all_in_palette={all_in_palette}",
            f"palette={sorted(palette)}",
        ],
        p_value=p_value,
        constraint_type="statistical",
        falsifiable=(
            "Would be falsified if AP not in palette, or if hits ≤ expected "
            f"({expected:.1f}), or p > 0.05"
        ),
    )


def dual_alphabet_structure(
    keystream_nums: list[int],
) -> DerivedConstraint:
    """CxS-4: AP {G,K,O} is arithmetic in AZ but NOT in KA.

    This demonstrates that both alphabets (standard AZ and keyword-mixed KA)
    are structurally involved: the AP is regular in AZ (step 4) but
    irregular in KA (gaps 5 and 8, since K=0, O=5, G=13 in KA).

    Args:
        keystream_nums: List of 24 integers (A=0) representing keystream values.

    Returns:
        DerivedConstraint with observed=True if dual-alphabet involvement confirmed.
    """
    # AZ positions
    az_g, az_k, az_o = ALPH.index("G"), ALPH.index("K"), ALPH.index("O")
    az_gaps = [az_k - az_g, az_o - az_k]
    az_regular = az_gaps[0] == az_gaps[1]  # Step 4: True

    # KA positions
    ka_g = KRYPTOS_ALPHABET.index("G")
    ka_k = KRYPTOS_ALPHABET.index("K")
    ka_o = KRYPTOS_ALPHABET.index("O")
    ka_gaps = [ka_o - ka_k, ka_g - ka_o]  # Sorted by KA position: K=0, O=5, G=13
    ka_regular = ka_gaps[0] == ka_gaps[1]  # Gaps 5, 8: False

    both_alphabets = az_regular and not ka_regular

    return DerivedConstraint(
        id="CxS-4",
        name="Dual-alphabet structure",
        description=(
            f"AP {{G,K,O}}: AZ regular (step {az_gaps[0]}, {az_regular}), "
            f"KA irregular (gaps {ka_gaps}, {ka_regular}). "
            f"Both alphabets involved: {both_alphabets}."
        ),
        observed=both_alphabets,
        expected=0.0,  # Not a rate — structural check
        evidence=[
            f"AZ: G={az_g}, K={az_k}, O={az_o}, gaps={az_gaps}, regular={az_regular}",
            f"KA: K={ka_k}, O={ka_o}, G={ka_g}, gaps={ka_gaps}, regular={ka_regular}",
            f"both_alphabets={both_alphabets}",
        ],
        p_value=0.0,  # Structural, not statistical
        constraint_type="structural",
        falsifiable=(
            "Would be falsified if AP were arithmetic in BOTH alphabets "
            "or in NEITHER alphabet"
        ),
    )


def propagate_all(
    keystream_nums: list[int],
    palette: FrozenSet[str],
) -> list[DerivedConstraint]:
    """Run all coupling constraints and return as a list.

    Args:
        keystream_nums: List of 24 integers (A=0) representing keystream values.
        palette: Set of uppercase letters forming the null palette.

    Returns:
        List of DerivedConstraint objects (CxS-1 through CxS-4).
    """
    return [
        keystream_palette_enrichment(keystream_nums, palette),
        mod5_ka_structure(keystream_nums),
        ap_palette_containment(keystream_nums, palette),
        dual_alphabet_structure(keystream_nums),
    ]
