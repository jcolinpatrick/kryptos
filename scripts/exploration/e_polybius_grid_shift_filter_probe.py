#!/usr/bin/env python3
"""
Cipher: probe -- Polybius residue-consistency filter selectivity
Family: exploration
Status: probe (NOT a K4 attack; do not register in exhaustion_log)
Keyspace: synthetic (random INT and shuffled-CT through stage-2)
Last run:
Best score: N/A (selectivity probe, not a search)

PURPOSE
-------
Empirical resolution of red-team BLOCKER 1 against the two-stage Polybius
grid-shift harness design. Red team claimed residue-consistency at
period P>=4 has near-zero discriminating power; hand analysis at P=8
counts 16 nontrivial constraints on 16 mod-5 unknowns and predicts
random survivor rate ~10^-22 per (V, K) pair.

The probe measures per-period filter selectivity two ways:
  (1) Random INT at crib positions, no stage-2 (pure filter test).
  (2) Shuffled CT at crib positions, stage-2-inverted, then filter
      (end-to-end harness arithmetic test).

If P=8 yields ~0 survivors across N=10000 trials in both, the filter
is hyper-restrictive and BLOCKER 1 is closed empirically.
If P=8 yields >>0 survivors, the red team is right and the design is
broken before any harness is written.
"""

import os
import sys
import random
import string
from collections import defaultdict
from itertools import product

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CRIB_DICT


PT_AT_CRIBS = dict(CRIB_DICT)
CRIB_POSITIONS = sorted(PT_AT_CRIBS.keys())
CT_AT_CRIBS = {p: CT[p] for p in CRIB_POSITIONS}

ALPH = string.ascii_uppercase
PRIMARY_ORDERINGS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "IQLUSION",
                     "UNDERGROUND", "SANBORN", "SCHEIDT"]
MISSING_LETTERS = ["J", "Q", "X", "Z"]
PERIODS = list(range(2, 9))
VARIANTS = ["vig", "beau", "varbeau"]


def build_grid(keyword: str, missing: str) -> tuple:
    """Return tuple of 25 letters (Polybius row-major), keyword first
    with duplicates removed, then remaining A-Z in order, M dropped."""
    seen = set()
    keyword_letters = []
    for c in keyword.upper():
        if c.isalpha() and c != missing and c not in seen:
            seen.add(c)
            keyword_letters.append(c)
    rest = [c for c in ALPH if c != missing and c not in seen]
    grid = tuple(keyword_letters + rest)
    assert len(grid) == 25, f"grid len {len(grid)} for keyword={keyword} missing={missing}"
    return grid


def grid_index(letter: str, grid: tuple) -> int:
    """Return index 0..24 of letter in grid, or -1 if not present."""
    try:
        return grid.index(letter)
    except ValueError:
        return -1


def grid_position(letter: str, grid: tuple):
    """Return (row, col) for letter in grid, or None if missing."""
    idx = grid_index(letter, grid)
    if idx < 0:
        return None
    return (idx // 5, idx % 5)


def check_residue_consistency(int_at_cribs: dict, grid: tuple, missing: str, period: int) -> bool:
    """Return True iff for every residue class mod period, all
    (PT[i], INT[i]) pairs at crib positions yield the same (dc, dr).
    Pass-through: PT=M requires INT=M; no offset constraint contributed.
    Inverse-consistency rejection: INT=M while PT!=M -> False.
    """
    buckets = defaultdict(list)
    for pos in CRIB_POSITIONS:
        buckets[pos % period].append(pos)

    for residue, positions in buckets.items():
        offsets = set()
        for pos in positions:
            pt = PT_AT_CRIBS[pos]
            int_l = int_at_cribs[pos]

            if pt == missing:
                if int_l != missing:
                    return False
                continue

            if int_l == missing:
                return False

            pt_pos = grid_position(pt, grid)
            int_pos = grid_position(int_l, grid)
            offset = ((int_pos[0] - pt_pos[0]) % 5, (int_pos[1] - pt_pos[1]) % 5)
            offsets.add(offset)
            if len(offsets) > 1:
                return False
    return True


def invert_stage2(ct_at_cribs: dict, key: str, variant: str) -> dict:
    """Stage-2 inversion at crib positions, A=0 throughout."""
    int_at = {}
    for pos, ct_letter in ct_at_cribs.items():
        ct_idx = ord(ct_letter) - 65
        k_idx = ord(key[pos % len(key)]) - 65
        if variant == "vig":          # CT = INT + K  ->  INT = CT - K
            int_idx = (ct_idx - k_idx) % 26
        elif variant == "beau":       # CT = K - INT  ->  INT = K - CT
            int_idx = (k_idx - ct_idx) % 26
        elif variant == "varbeau":    # CT = INT - K  ->  INT = CT + K
            int_idx = (ct_idx + k_idx) % 26
        else:
            raise ValueError(f"unknown variant {variant}")
        int_at[pos] = chr(int_idx + 65)
    return int_at


def random_int_at_cribs(rng: random.Random) -> dict:
    """Generate a uniformly random INT at crib positions."""
    return {p: chr(rng.randint(0, 25) + 65) for p in CRIB_POSITIONS}


def shuffle_ct(rng: random.Random) -> dict:
    """Permute CT values at crib positions."""
    chars = [CT_AT_CRIBS[p] for p in CRIB_POSITIONS]
    rng.shuffle(chars)
    return dict(zip(CRIB_POSITIONS, chars))


def constraint_count(period: int) -> int:
    """Compute the count of nontrivial residue-consistency constraints
    at this period, based on PT distinctness within each residue class.
    Pass-through positions (PT == M) contribute 0; we ignore that here
    since M in {J, Q, X, Z} never collides with crib PT."""
    buckets = defaultdict(set)
    for pos in CRIB_POSITIONS:
        buckets[pos % period].add(PT_AT_CRIBS[pos])
    return sum(max(0, len(s) - 1) for s in buckets.values())


def per_class_breakdown(period: int) -> dict:
    """Diagnostic: residue class -> distinct PT letters."""
    buckets = defaultdict(set)
    for pos in CRIB_POSITIONS:
        buckets[pos % period].add(PT_AT_CRIBS[pos])
    return dict(sorted(buckets.items()))


# ── Tests ────────────────────────────────────────────────────────────


def test1_random_int(n_trials: int, seed: int = 42):
    """Pure filter selectivity on random INT (no stage-2)."""
    print(f"\nTEST 1: Random INT, no stage-2 (N={n_trials})")
    print("=" * 78)

    counts_per_period = defaultdict(int)
    cells_per_trial = len(PRIMARY_ORDERINGS) * len(MISSING_LETTERS)

    rng = random.Random(seed)
    for trial in range(n_trials):
        int_at = random_int_at_cribs(rng)
        for ord_kw, missing, period in product(PRIMARY_ORDERINGS, MISSING_LETTERS, PERIODS):
            grid = build_grid(ord_kw, missing)
            if check_residue_consistency(int_at, grid, missing, period):
                counts_per_period[period] += 1

    total_per_period = n_trials * cells_per_trial
    print(f"Cells per trial (ORD x M): {cells_per_trial}")
    print(f"Trials per period: {total_per_period}")
    print()
    print(f"  P  | Survivors | Pass rate | Constraints | Predicted (1/25)^c")
    print(f"  -- | --------- | --------- | ----------- | ------------------")
    for p in PERIODS:
        c = counts_per_period[p]
        rate = c / total_per_period if total_per_period else 0.0
        cn = constraint_count(p)
        predicted = (1 / 25) ** cn
        print(f"  {p}  | {c:>9} | {rate:.2e} | {cn:>11} | {predicted:.2e}")


def test2_shuffled_ct(n_trials: int, seed: int = 43):
    """End-to-end selectivity: shuffled CT through stage-2 then filter."""
    print(f"\nTEST 2: Shuffled CT through stage-2 (N={n_trials} per cell)")
    print("=" * 78)

    keys = ["BERLIN", "CLOCK", "KRYPTOS", "SHADOW", "ABSCISSA",
            "PALIMPSEST", "EAST", "NORTH", "SANBORN", "SCHEIDT"]

    counts_per_period = defaultdict(int)
    cells_per_trial = len(PRIMARY_ORDERINGS) * len(MISSING_LETTERS) * len(VARIANTS) * len(keys)

    rng = random.Random(seed)
    for trial in range(n_trials):
        shuffled = shuffle_ct(rng)
        for ord_kw, missing in product(PRIMARY_ORDERINGS, MISSING_LETTERS):
            grid = build_grid(ord_kw, missing)
            for variant in VARIANTS:
                for key in keys:
                    int_at = invert_stage2(shuffled, key, variant)
                    for period in PERIODS:
                        if check_residue_consistency(int_at, grid, missing, period):
                            counts_per_period[period] += 1

    total_per_period = n_trials * cells_per_trial
    print(f"Cells per trial (ORD x M x V x K): {cells_per_trial}")
    print(f"Trials per period: {total_per_period}")
    print()
    print(f"  P  | Survivors | Pass rate | Constraints | Predicted (1/25)^c")
    print(f"  -- | --------- | --------- | ----------- | ------------------")
    for p in PERIODS:
        c = counts_per_period[p]
        rate = c / total_per_period if total_per_period else 0.0
        cn = constraint_count(p)
        predicted = (1 / 25) ** cn
        print(f"  {p}  | {c:>9} | {rate:.2e} | {cn:>11} | {predicted:.2e}")


def test3_real_ct():
    """Sanity check: filter pass on real K4 CT through stage-2."""
    print(f"\nTEST 3: Real K4 CT through stage-2 (sanity)")
    print("=" * 78)

    keys = ["BERLIN", "CLOCK", "KRYPTOS", "SHADOW", "ABSCISSA",
            "PALIMPSEST", "EAST", "NORTH", "SANBORN", "SCHEIDT"]

    counts_per_period = defaultdict(int)
    cells = len(PRIMARY_ORDERINGS) * len(MISSING_LETTERS) * len(VARIANTS) * len(keys)

    for ord_kw, missing in product(PRIMARY_ORDERINGS, MISSING_LETTERS):
        grid = build_grid(ord_kw, missing)
        for variant in VARIANTS:
            for key in keys:
                int_at = invert_stage2(CT_AT_CRIBS, key, variant)
                for period in PERIODS:
                    if check_residue_consistency(int_at, grid, missing, period):
                        counts_per_period[period] += 1

    print(f"(ORD x M x V x K) cells: {cells}")
    print()
    print(f"  P  | Survivors")
    print(f"  -- | ---------")
    for p in PERIODS:
        print(f"  {p}  | {counts_per_period[p]:>9}")


def main():
    print("Polybius residue-consistency filter selectivity probe")
    print(f"Crib positions: {len(CRIB_POSITIONS)} (PT='{''.join(PT_AT_CRIBS[p] for p in CRIB_POSITIONS)}')")
    print(f"Primary orderings: {PRIMARY_ORDERINGS}")
    print(f"Missing letters: {MISSING_LETTERS}")
    print(f"Periods: {PERIODS}")

    print("\nPer-period constraint structure:")
    print(f"  P  | Constraints | Distinct-PT per residue class")
    for p in PERIODS:
        bd = per_class_breakdown(p)
        sizes = [len(bd[r]) for r in sorted(bd.keys())]
        print(f"  {p}  | {constraint_count(p):>11} | {sizes}")

    test1_random_int(n_trials=10000)
    test2_shuffled_ct(n_trials=200)
    test3_real_ct()


if __name__ == "__main__":
    main()
