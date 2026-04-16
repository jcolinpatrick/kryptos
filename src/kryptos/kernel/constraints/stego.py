"""Stego layer proof module — RETIRED.

RETIRED 2026-04-14. This module previously reported each of S2, S4, S5,
and S6 with status="confirmed" as quantified evidence for K4's
steganographic layer. Matched controls (April 2026) disproved the
specificity of the underlying null palette {B,G,I,K,O,W,Z} and the
17-position consensus null mask — both are now tracked as retired
(claim_id: null_palette_retired). See:

  - memory/project_consensus_nulls_epistemic_status_2026_04_14.md
  - docs/a1_score_conditioned_null_report.md

The functions remain importable for historical reproducibility. They
still compute the same numerical values (observed counts, hypergeometric
p-values, classification accuracies) so that archived scripts and
regression tests continue to exercise the math. However, every
StegoProperty returned by this module now carries status="retired"
regardless of the numerical result. "retired" means: the math is
correct but the claim is no longer treated as live evidentiary support
for the stego layer. Do not cite the output as confirmation of K4's
stego structure.

All Monte Carlo simulations use deterministic seeds for reproducibility.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from math import comb, factorial
from typing import Any, List, Tuple

from kryptos.kernel.constants import (
    CT,
    CT_LEN,
    ALPH,
    KRYPTOS_ALPHABET,
    MOD,
    CONSENSUS_NULL_POSITIONS,
    NULL_PALETTE,
    CRIB_POSITIONS,
)
from kryptos.kernel.alphabet import keyword_mixed_alphabet


@dataclass
class StegoProperty:
    """Quantified evidence for a single steganographic property."""

    id: str
    name: str
    observed: Any
    expected: Any
    p_value: float
    method: str
    status: str
    artifact: str


def palette_restriction(ct: str, null_positions: frozenset[int]) -> StegoProperty:
    """S2: Count distinct letters at null positions; MC test for significance.

    Draws 17 random positions from a 97-char uppercase text 100K times
    and checks how often the distinct letter count is <= 7.
    """
    # Observed: distinct letters at null positions
    null_letters = {ct[p] for p in null_positions}
    observed_distinct = len(null_letters)

    # Monte Carlo: 100K trials, seed=42
    rng = random.Random(42)
    n_trials = 100_000
    n_draws = len(null_positions)
    hits = 0

    for _ in range(n_trials):
        drawn = {rng.choice(ALPH) for _ in range(n_draws)}
        if len(drawn) <= observed_distinct:
            hits += 1

    p_value = hits / n_trials

    return StegoProperty(
        id="S2",
        name="Palette restriction",
        observed=observed_distinct,
        expected=f"<= {observed_distinct} distinct letters in {n_draws} draws from 26",
        p_value=p_value,
        method=f"MC {n_trials} trials, seed=42, {n_draws} draws from 26-letter alphabet",
        status="retired",
        artifact="memory/project_consensus_nulls_epistemic_status_2026_04_14.md",
    )


def null_position_classification(
    ct: str, null_positions: frozenset[int]
) -> StegoProperty:
    """S4: (pos%7, pos%5) classification predicts null vs real positions.

    Builds a classification table from consensus nulls. For cells containing
    both null and real positions, uses the "earlier position = null" tiebreaker.
    Then counts how many of the 35 palette-letter positions are correctly
    classified as nulls.
    """
    # Find ALL positions in CT where the letter is in NULL_PALETTE
    palette_positions = [i for i in range(len(ct)) if ct[i] in NULL_PALETTE]
    n_palette = len(palette_positions)

    # Build (r7, r5) -> list of (position, is_consensus_null) from consensus nulls
    # to learn which (r7, r5) cells are "null" cells
    cell_data: dict[tuple[int, int], list[tuple[int, bool]]] = {}
    for pos in range(len(ct)):
        if ct[pos] in NULL_PALETTE:
            cell = (pos % 7, pos % 5)
            is_null = pos in null_positions
            cell_data.setdefault(cell, []).append((pos, is_null))

    # Classify each cell: if any consensus null is in the cell, mark it as null-cell.
    # For mixed cells (both null and real), use "earlier position = null" tiebreaker.
    null_cells: set[tuple[int, int]] = set()
    for cell, entries in cell_data.items():
        # Check if any consensus null falls in this cell
        has_null = any(is_null for _, is_null in entries)
        if has_null:
            null_cells.add(cell)

    # Count correct classifications:
    # A palette-letter position is "correctly classified" if:
    # - It's in a null cell AND it's actually a null, OR
    # - It's not in a null cell AND it's not a null
    # For the tiebreaker: within a null cell, earlier positions are nulls
    correct = 0
    for pos in palette_positions:
        cell = (pos % 7, pos % 5)
        is_consensus_null = pos in null_positions

        if cell in null_cells:
            # Get all palette positions in this cell, sorted
            cell_positions = sorted(
                [p for p, _ in cell_data[cell]]
            )
            # Count how many consensus nulls are in this cell
            n_nulls_in_cell = sum(
                1 for p, is_n in cell_data[cell] if is_n
            )
            # Earlier positions are predicted as null
            rank = cell_positions.index(pos)
            predicted_null = rank < n_nulls_in_cell

            if predicted_null == is_consensus_null:
                correct += 1
        else:
            # Not in a null cell — predicted as real
            if not is_consensus_null:
                correct += 1

    return StegoProperty(
        id="S4",
        name="Null position classification",
        observed=n_palette,
        expected=correct,
        p_value=-1.0,  # not a statistical p-value; accuracy = correct/n_palette
        method="(pos%7, pos%5) classification with earlier-position-is-null tiebreaker; accuracy-based, no MC null model",
        status="retired",
        artifact="memory/project_consensus_nulls_epistemic_status_2026_04_14.md",
    )


def polybius_generation(
    palette: frozenset[str],
    keyword1: str,
    keyword2: str,
) -> StegoProperty:
    """S5: Check if keywords generate palette via 5-wide keyword-mixed grid.

    The hypothesis: arrange a keyword-mixed alphabet (from keyword1) into a
    5-wide grid. The palette letters should occupy exactly 2 of the 5 columns
    (specifically columns that keyword2 selects). MC test: how often do random
    keyword pairs produce a 7-letter set occupying <= 2 columns of the grid?
    """
    # Check the specific KRYPTOS x SEVEN hypothesis
    row_alpha = keyword_mixed_alphabet(keyword1)
    # Build 5-wide grid
    grid_cols: dict[str, int] = {}  # letter -> column index
    for i, ch in enumerate(row_alpha):
        grid_cols[ch] = i % 5

    # Which columns do palette letters occupy?
    palette_cols = {grid_cols[ch] for ch in palette}
    observed_match = len(palette_cols) <= 2

    # MC test: 50K trials, seed=42
    # Random keyword1 = 7 random uppercase letters, keyword2 = 5 random uppercase letters
    # Build grid from keyword1, pick 7 random letters, check if they fit in <= 2 columns
    rng = random.Random(42)
    n_trials = 50_000
    hits = 0

    for _ in range(n_trials):
        # Generate random keyword (kw2 consumed from RNG for seed compatibility)
        kw1 = "".join(rng.choices(ALPH, k=7))
        _kw2 = "".join(rng.choices(ALPH, k=5))  # noqa: F841 — preserves RNG stream
        alpha = keyword_mixed_alphabet(kw1)

        # Build grid columns
        cols = {}
        for i, ch in enumerate(alpha):
            cols[ch] = i % 5

        # Pick 7 random distinct letters as "palette"
        trial_palette = rng.sample(list(ALPH), 7)
        trial_cols = {cols[ch] for ch in trial_palette}
        if len(trial_cols) <= 2:
            hits += 1

    p_value = hits / n_trials

    return StegoProperty(
        id="S5",
        name="Polybius generation",
        observed=observed_match,
        expected=f"palette in <= 2 columns of 5-wide grid from {keyword1}",
        p_value=p_value,
        method=f"MC {n_trials} trials, seed=42, random 7+5 letter keyword pairs",
        status="retired",  # palette family retired 2026-04-14; math still correct
        artifact="memory/project_consensus_nulls_epistemic_status_2026_04_14.md",
    )


def crib_null_avoidance(
    null_positions: frozenset[int],
    crib_ranges: list[tuple[int, int]],
) -> StegoProperty:
    """S6: Count overlap between null positions and crib ranges.

    Uses hypergeometric-like exact calculation:
    P(0 overlap) = C(97-k, n) / C(97, n)
    where k = total crib positions, n = number of nulls.
    """
    # Build set of all crib positions from ranges
    crib_pos_set: set[int] = set()
    for start, end in crib_ranges:
        crib_pos_set.update(range(start, end))

    k = len(crib_pos_set)  # number of crib positions
    n = len(null_positions)  # number of null positions
    N = CT_LEN  # total positions

    # Count overlap
    overlap = len(null_positions & crib_pos_set)

    # Exact probability of 0 overlap:
    # P(X=0) = C(N-k, n) / C(N, n)
    # This is the hypergeometric probability of drawing 0 "crib" positions
    # when sampling n positions without replacement from N total
    p_value = comb(N - k, n) / comb(N, n)

    return StegoProperty(
        id="S6",
        name="Crib-null avoidance",
        observed=overlap,
        expected=0,
        p_value=p_value,
        method=f"Hypergeometric: P(X=0) with N={N}, k={k}, n={n}",
        status="retired",  # palette family retired 2026-04-14; math still correct
        artifact="memory/project_consensus_nulls_epistemic_status_2026_04_14.md",
    )


def full_stego_proof(ct: str) -> list[StegoProperty]:
    """Run all 4 stego layer tests and return results."""
    results = [
        palette_restriction(ct, CONSENSUS_NULL_POSITIONS),
        null_position_classification(ct, CONSENSUS_NULL_POSITIONS),
        polybius_generation(NULL_PALETTE, "KRYPTOS", "SEVEN"),
        crib_null_avoidance(
            CONSENSUS_NULL_POSITIONS,
            [(21, 34), (63, 74)],
        ),
    ]
    return results
