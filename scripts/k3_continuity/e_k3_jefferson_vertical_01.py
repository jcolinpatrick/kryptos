"""
Cipher: K3 Vertical Jefferson (row rotation on 14×24 code chart)
Family: k3_continuity
Status: active
Keyspace: 3^24 ≈ 282B (±1 shifts) — pruned via beam search
Last run: 2026-03-19
Best score: TBD
"""

"""
K3 Jefferson Vertical Attack
=============================
The K3 code chart is a 14×24 grid. Reading columns bottom-to-top
produces the known K3 ciphertext. The NDYAHR letters at the bottom
of column 0 are physically displaced on the sculpture.

HYPOTHESIS: If each row of the 14×24 grid can rotate independently
(like a Jefferson cipher wheel), a specific set of row offsets might
reveal a hidden vertical message in one or more columns.

APPROACH:
1. NDYAHR-guided: Apply shifts derived from displacement directions
2. Exhaustive small shifts: Try all offsets ∈ {-2,-1,0,+1,+2} on
   subsets of rows, score column reads for English
3. Beam search: Assign rows one at a time, keeping top-K candidates
   by quadgram score across all 14 columns

The key insight: with 14 columns of 24 chars each, we need 24-char
vertical strings that contain English words or high-quality n-grams.
"""

import sys
import os
import json
import itertools
from collections import defaultdict

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.scoring.ngram import get_default_scorer

# ── K3 CODE CHART (14×24, verified) ──────────────────────────────────
GRID = [
    "ILNTAYESTATHCW",  # row 0
    "BLHMHEHAROIEEH",  # row 1
    "ISIWNTHONRSLEO",  # row 2
    "OLTETYMFTEHMHD",  # row 3
    "ELAAEOAERIILUV",  # row 4
    "TSGCRIPEEPEKET",  # row 5
    "PDNADESTEWCRFR",  # row 6
    "CLRIUARBAELTMT",  # row 7
    "OUPIEHBLMTIIFT",  # row 8
    "EYTPNNTRRSHRGS",  # row 9
    "HEELEEFEAMDOMS",  # row 10
    "RRNBTWIEOTDLHL",  # row 11
    "SNMECIEYTTTDON",  # row 12
    "LTXLHTRGOHCYEH",  # row 13
    "NHWEADCEEAERNE",  # row 14
    "HCRNREYTAAADPM",  # row 15
    "OAMNNSAAUIBDDI",  # row 16
    "RISLELTMTNESRE",  # row 17
    "HAOSEOCAEDFOAF",  # row 18
    "ANNETFNTUDWAHP",  # row 19
    "YHSPITEATEEEDI",  # row 20
    "DSHRDEENOSIOTR",  # row 21
    "NYOANOHEIBRGGM",  # row 22
    "EDNRWEQWFIGEAD",  # row 23
]

COLS = 14
ROWS = 24

# NDYAHR displacement-derived shifts (corrected from scale model)
NDYAHR_SHIFTS = {
    17: -1,  # R → UP
    18: +1,  # H → RIGHT
    19: -1,  # A → UP
    20: -1,  # Y → UP
    21: +1,  # D → DOWN
    22: -1,  # N → LEFT
    23:  0,  # E → FIXED (anchor)
}


def read_columns(offsets, direction='bottom_up'):
    """Read all 14 columns with given row offsets.
    Returns list of 14 strings, each 24 chars long."""
    columns = []
    for c in range(COLS):
        col_str = ""
        for r in range(ROWS):
            ri = (ROWS - 1 - r) if direction == 'bottom_up' else r
            off = offsets[ri]
            src = ((c - off) % COLS + COLS) % COLS
            col_str += GRID[ri][src]
        columns.append(col_str)
    return columns


def score_columns(columns, qg):
    """Score all 14 columns and return (total_score, best_col, best_score, best_text)."""
    total = 0.0
    best_score = float('-inf')
    best_col = -1
    best_text = ""
    for i, col in enumerate(columns):
        s = qg.score(col)
        total += s
        if s > best_score:
            best_score = s
            best_col = i
            best_text = col
    return total, best_col, best_score, best_text


def attack_ndyahr_direct(qg):
    """Test the direct NDYAHR displacement shifts."""
    print("\n=== NDYAHR Direct Shifts ===")
    offsets = [0] * ROWS
    for row, shift in NDYAHR_SHIFTS.items():
        offsets[row] = shift

    for direction in ['bottom_up', 'top_down']:
        columns = read_columns(offsets, direction)
        total, best_col, best_score, best_text = score_columns(columns, qg)
        per_char = total / (COLS * ROWS)
        print(f"  {direction}: total={total:.1f} per_char={per_char:.3f} "
              f"best_col={best_col+1} best={best_score:.1f} text={best_text}")


def attack_ndyahr_rows_exhaustive(qg, max_shift=2):
    """Exhaustive search: vary only the 7 NDYAHR rows (17-23)."""
    ndyahr_rows = sorted(NDYAHR_SHIFTS.keys())
    shift_range = list(range(-max_shift, max_shift + 1))
    n_configs = len(shift_range) ** len(ndyahr_rows)
    print(f"\n=== NDYAHR Rows Exhaustive (±{max_shift}) ===")
    print(f"  Rows: {ndyahr_rows}")
    print(f"  Configs: {n_configs}")

    best_total = float('-inf')
    best_config = None
    best_info = None
    count = 0

    for combo in itertools.product(shift_range, repeat=len(ndyahr_rows)):
        offsets = [0] * ROWS
        for i, row in enumerate(ndyahr_rows):
            offsets[row] = combo[i]

        for direction in ['bottom_up', 'top_down']:
            columns = read_columns(offsets, direction)
            total, best_col, best_score, best_text = score_columns(columns, qg)

            if total > best_total:
                best_total = total
                best_config = {row: combo[i] for i, row in enumerate(ndyahr_rows)}
                best_info = (direction, best_col, best_score, best_text, total)

        count += 1
        if count % 10000 == 0:
            print(f"  {count}/{n_configs} tested, best_total={best_total:.1f}", flush=True)

    print(f"  BEST: total={best_info[4]:.1f} dir={best_info[0]} "
          f"best_col={best_info[1]+1} col_score={best_info[2]:.1f}")
    print(f"  Config: {best_config}")
    print(f"  Best column text: {best_info[3]}")
    return best_total, best_config


def attack_all_rows_beam(qg, max_shift=1, beam_width=500):
    """Beam search: assign offsets to rows one at a time, pruning."""
    shift_range = list(range(-max_shift, max_shift + 1))
    print(f"\n=== All Rows Beam Search (±{max_shift}, beam={beam_width}) ===")
    print(f"  Full space: {len(shift_range)}^{ROWS} = {len(shift_range)**ROWS:.2e}")

    # beam = list of (partial_offsets, score)
    beam = [([0] * 0, 0.0)]

    for row_idx in range(ROWS):
        new_beam = []
        for partial, prev_score in beam:
            for shift in shift_range:
                new_partial = partial + [shift]

                # Score: read what we can so far (partial columns)
                # We score all 14 columns but only the rows assigned so far
                col_score = 0.0
                for c in range(COLS):
                    col_chars = ""
                    for r_assigned in range(len(new_partial)):
                        ri = (ROWS - 1 - r_assigned)  # bottom-up
                        off = new_partial[ri] if ri < len(new_partial) else 0
                        src = ((c - off) % COLS + COLS) % COLS
                        col_chars += GRID[ri][src]
                    # Only score if we have enough chars for quadgrams
                    if len(col_chars) >= 4:
                        col_score += qg.score(col_chars)

                new_beam.append((new_partial, col_score))

        # Prune to beam_width
        new_beam.sort(key=lambda x: x[1], reverse=True)
        beam = new_beam[:beam_width]

        if (row_idx + 1) % 4 == 0 or row_idx == ROWS - 1:
            print(f"  Row {row_idx+1}/{ROWS}: beam_top={beam[0][1]:.1f} "
                  f"beam_bottom={beam[-1][1]:.1f}", flush=True)

    # Final scoring
    print(f"\n  Top 5 configurations:")
    for rank, (offsets_list, score) in enumerate(beam[:5]):
        columns = read_columns(offsets_list, 'bottom_up')
        total, best_col, best_score, best_text = score_columns(columns, qg)
        print(f"  #{rank+1}: total={total:.1f} best_col={best_col+1} "
              f"score={best_score:.1f} text={best_text}")
        print(f"       offsets={offsets_list}")

    return beam[0]


def attack_all_rows_exhaustive_small(qg, max_shift=1):
    """Exhaustive for all 24 rows with ±1 — 3^24 ≈ 282B.
    Too large for full enumeration. Use random sampling instead."""
    import random
    shift_range = list(range(-max_shift, max_shift + 1))
    n_total = len(shift_range) ** ROWS
    n_samples = 10_000_000  # 10M random samples
    print(f"\n=== Random Sampling (±{max_shift}, {n_samples:,} samples) ===")
    print(f"  Full space: {n_total:.2e}")

    best_total = float('-inf')
    best_offsets = None
    best_info = None

    for i in range(n_samples):
        offsets = [random.choice(shift_range) for _ in range(ROWS)]

        columns = read_columns(offsets, 'bottom_up')
        total, best_col, best_score, best_text = score_columns(columns, qg)

        if total > best_total:
            best_total = total
            best_offsets = offsets[:]
            best_info = (best_col, best_score, best_text, total)
            if i > 0:
                print(f"  NEW BEST at sample {i:,}: total={total:.1f} "
                      f"col={best_col+1} score={best_score:.1f} text={best_text[:30]}",
                      flush=True)

        if (i + 1) % 1_000_000 == 0:
            print(f"  {i+1:,}/{n_samples:,} sampled, best={best_total:.1f}", flush=True)

    print(f"\n  FINAL BEST: total={best_info[3]:.1f} col={best_info[0]+1} "
          f"score={best_info[1]:.1f}")
    print(f"  Text: {best_info[2]}")
    print(f"  Offsets: {best_offsets}")
    return best_total, best_offsets


def attack(ciphertext=None, **params):
    """Standard attack interface."""
    qg = get_default_scorer()
    results = []

    # Phase 1: NDYAHR direct
    attack_ndyahr_direct(qg)

    # Phase 2: NDYAHR rows exhaustive (±3)
    score2, config2 = attack_ndyahr_rows_exhaustive(qg, max_shift=3)
    results.append((score2, str(config2), "ndyahr_rows_exhaustive_pm3"))

    # Phase 3: Beam search all rows (±1)
    best_beam = attack_all_rows_beam(qg, max_shift=1, beam_width=1000)
    results.append((best_beam[1], str(best_beam[0]), "beam_pm1_w1000"))

    # Phase 4: Random sampling (±1)
    score4, offsets4 = attack_all_rows_exhaustive_small(qg, max_shift=1)
    results.append((score4, str(offsets4), "random_sample_10M"))

    results.sort(key=lambda x: x[0], reverse=True)
    return results


if __name__ == "__main__":
    print("K3 Jefferson Vertical Cipher Attack")
    print("=" * 60)
    print(f"Grid: {COLS}×{ROWS} = {COLS*ROWS} cells")
    print(f"Reading: columns bottom-to-top = K3 ciphertext")
    print(f"Hypothesis: row rotations reveal hidden vertical message")

    # Baseline: no rotation
    qg = get_default_scorer()
    columns_baseline = read_columns([0]*ROWS, 'bottom_up')
    total_b, col_b, score_b, text_b = score_columns(columns_baseline, qg)
    print(f"\nBaseline (no rotation): total={total_b:.1f} per_char={total_b/(COLS*ROWS):.3f}")
    print(f"  Best col {col_b+1}: {score_b:.1f} = {text_b}")

    # Run attacks
    attack()
