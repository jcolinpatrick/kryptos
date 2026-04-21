#!/usr/bin/env python3
"""
Cipher: probe -- Monte Carlo on W-bracket-the-cribs pattern
Family: exploration
Status: probe (NOT a K4 attack; do not register in exhaustion_log)
Keyspace: synthetic (uniform random positions)
Last run:
Best score: N/A

PURPOSE
-------
Test whether the observation that K4's 5 W characters appear to "bracket"
both cribs is statistically surprising or is plausibly noise.

The pattern: K4 has W at positions {20, 36, 48, 58, 74}. None fall inside
EASTNORTHEAST (21-33) or BERLINCLOCK (63-73). At least one W appears in
each of the three non-crib regions: before crib 1 (0-20), between cribs
(34-62), after crib 2 (74-96).

Two null models:
  Loose: 5 random positions, all outside both crib regions.
  Tight: 5 random positions, all outside cribs AND >=1 in each of the
         three non-crib regions.

Also: condition on K4's actual letter frequency distribution and ask
whether ANY letter (not just W) shows this pattern by chance. This is
the multiple-testing correction.
"""

import os
import sys
import random
from collections import Counter

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT


CRIB1_POS = set(range(21, 34))   # EASTNORTHEAST 21..33
CRIB2_POS = set(range(63, 74))   # BERLINCLOCK 63..73
CRIB_POS = CRIB1_POS | CRIB2_POS

REGION_A = set(range(0, 21))     # before crib 1
REGION_B = CRIB1_POS              # crib 1
REGION_C = set(range(34, 63))    # between cribs
REGION_D = CRIB2_POS              # crib 2
REGION_E = set(range(74, 97))    # after crib 2


def actual_w_positions():
    return [i for i, c in enumerate(CT) if c == "W"]


def classify(positions):
    """Return tuple (count_A, count_B, count_C, count_D, count_E)."""
    return (
        sum(1 for p in positions if p in REGION_A),
        sum(1 for p in positions if p in REGION_B),
        sum(1 for p in positions if p in REGION_C),
        sum(1 for p in positions if p in REGION_D),
        sum(1 for p in positions if p in REGION_E),
    )


def is_loose_match(positions):
    """All positions outside both cribs."""
    return all(p not in CRIB_POS for p in positions)


def is_tight_match(positions):
    """Loose match AND >=1 position in each of A, C, E."""
    a, b, c, d, e = classify(positions)
    return b == 0 and d == 0 and a >= 1 and c >= 1 and e >= 1


def monte_carlo_loose(n_w, n_trials, seed=42):
    rng = random.Random(seed)
    all_positions = list(range(CT_LEN))
    hits = 0
    for _ in range(n_trials):
        sample = rng.sample(all_positions, n_w)
        if is_loose_match(sample):
            hits += 1
    return hits / n_trials


def monte_carlo_tight(n_w, n_trials, seed=43):
    rng = random.Random(seed)
    all_positions = list(range(CT_LEN))
    hits = 0
    for _ in range(n_trials):
        sample = rng.sample(all_positions, n_w)
        if is_tight_match(sample):
            hits += 1
    return hits / n_trials


def per_letter_audit():
    """For each letter L appearing in CT, classify whether L's positions
    in K4 show the loose / tight bracket pattern. This is the
    multiple-testing audit: of 26 letters, how many show a bracket
    pattern by chance?"""
    counter = Counter(CT)
    rows = []
    for letter in sorted(counter):
        positions = [i for i, c in enumerate(CT) if c == letter]
        count = len(positions)
        loose = is_loose_match(positions)
        tight = is_tight_match(positions)
        rows.append((letter, count, loose, tight, classify(positions)))
    return rows


def main():
    print("=" * 78)
    print("W-bracket-the-cribs Monte Carlo")
    print("=" * 78)

    w_positions = actual_w_positions()
    print(f"\nActual W positions in K4: {w_positions}  (count={len(w_positions)})")
    a, b, c, d, e = classify(w_positions)
    print(f"Distribution across regions: A={a} B={b} C={c} D={d} E={e}")
    print(f"  A=before-crib-1 (0-20, size 21)")
    print(f"  B=crib 1 (21-33, size 13)")
    print(f"  C=between-cribs (34-62, size 29)")
    print(f"  D=crib 2 (63-73, size 11)")
    print(f"  E=after-crib-2 (74-96, size 23)")
    print(f"Loose match (no W in cribs): {is_loose_match(w_positions)}")
    print(f"Tight match (loose AND >=1 in A, C, E): {is_tight_match(w_positions)}")

    print("\n" + "-" * 78)
    print(f"Monte Carlo: 5 random positions in 97-char text")
    print("-" * 78)

    n_trials = 1_000_000
    p_loose = monte_carlo_loose(5, n_trials)
    p_tight = monte_carlo_tight(5, n_trials)
    print(f"  N trials: {n_trials:,}")
    print(f"  P(loose match | random) = {p_loose:.4f}  ({p_loose*100:.2f}%)")
    print(f"  P(tight match | random) = {p_tight:.4f}  ({p_tight*100:.2f}%)")

    print("\n" + "-" * 78)
    print("Per-letter audit: which K4 letters show the bracket pattern?")
    print("-" * 78)
    print(f"  {'L':<3} {'count':>5} {'loose':>6} {'tight':>6} {'(A,B,C,D,E)':<18}")
    rows = per_letter_audit()
    loose_letters = []
    tight_letters = []
    for letter, count, loose, tight, dist in rows:
        marker = ""
        if loose:
            loose_letters.append(letter)
            marker += " L"
        if tight:
            tight_letters.append(letter)
            marker += " T"
        print(f"  {letter:<3} {count:>5} {str(loose):>6} {str(tight):>6} {str(dist):<18}{marker}")

    n_distinct_letters = len(rows)
    print(f"\nLetters with LOOSE match: {loose_letters}  ({len(loose_letters)}/{n_distinct_letters})")
    print(f"Letters with TIGHT match: {tight_letters}  ({len(tight_letters)}/{n_distinct_letters})")

    print("\n" + "-" * 78)
    print("Bonferroni-style assessment")
    print("-" * 78)
    # P(any of 26 letters shows tight match) approx:
    # 1 - (1 - p_tight)^26 if independent (they're not, but useful upper bound)
    p_any_loose_independent = 1 - (1 - p_loose) ** n_distinct_letters
    p_any_tight_independent = 1 - (1 - p_tight) ** n_distinct_letters
    print(f"P(at least one of {n_distinct_letters} letters shows loose pattern, indep approx): {p_any_loose_independent:.3f}")
    print(f"P(at least one of {n_distinct_letters} letters shows tight pattern, indep approx): {p_any_tight_independent:.3f}")
    # NOTE: independence approx OVERSTATES p_any (the events are negatively
    # correlated because letters share positions). So real values are lower.

    # MC: condition on K4's letter-frequency distribution and ask how often
    # some letter has its (count) positions in a tight bracket.
    print("\n" + "-" * 78)
    print(f"Conditional MC: re-sample W positions {len(w_positions)} times, see how often any K4-letter-count would have shown tight pattern")
    print("-" * 78)
    counter = Counter(CT)
    counts_seen = sorted(set(counter.values()))
    print(f"K4 distinct letter counts: {counts_seen}")
    # For each count k, compute P(tight | k positions random)
    n_trials_sub = 200000
    print(f"  count | P(loose | random) | P(tight | random)")
    for k in counts_seen:
        if k == 0:
            continue
        p_l = monte_carlo_loose(k, n_trials_sub, seed=100 + k)
        p_t = monte_carlo_tight(k, n_trials_sub, seed=200 + k)
        print(f"  {k:>5} | {p_l:>16.4f} | {p_t:>16.4f}")


if __name__ == "__main__":
    main()
