#!/usr/bin/env python3
"""
Cipher: two_system/yar_coupling
Family: yar
Status: active
Keyspace: ~30K configs (6 direction interpretations x 5040 col orderings x null mask)
Last run:
Best score:

E-NDYAHR-COUPLING-01: Test NDYAHR directional vectors coupled WITH consensus null mask.

Prior work tested NDYAHR directions and col-7 transposition SEPARATELY.
The 15/24 best lead uses Beaufort + col-7 transposition + null mask.
NDYAHR encodes exactly 6 of the 7 KRYPTOS columns with directional vectors.

This script tests whether NDYAHR directions, when used to modify column
read-order or read-direction in a col-7 transposition AFTER null removal,
improve on the 15/24 baseline.

Directional vectors (from ndyahr_displacement.md):
  N=West(-1,0), D=East(+1,0), Y=North(0,-1), A=North(0,-1), H=East(+1,0), R=NW(-1,-1)
  E=baseline (col 0, undisplaced)

Hypotheses tested:
  H1: Direction encodes column read order (W=6, E=1, N=3, N=4, E=2, NW=5 etc.)
  H2: Direction encodes read direction (E/W = forward/reverse, N = bottom-to-top)
  H3: Vertical component encodes column priority (up-cols first)
  H4: Compass bearing as numeric column position
  H5: Direction pairs as column swaps

Output: results/ndyahr_nullmask_coupling.json
"""
import json
import os
import sys
import time
import itertools
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT, N_CRIBS,
    CONSENSUS_NULL_POSITIONS, KRYPTOS_ALPHABET,
)
from kryptos.kernel.scoring.aggregate import score_candidate

# ── Constants ────────────────────────────────────────────────────────────

KA = KRYPTOS_ALPHABET
NULLS = sorted(CONSENSUS_NULL_POSITIONS)

# NDYAHR directional vectors: (dx, dy) where +x=right, -y=up
# Col: 0=E(baseline), 1=N(W), 2=D(E), 3=Y(N), 4=A(N), 5=H(E), 6=R(NW)
DIRECTIONS = {
    0: (0, 0),    # E - baseline
    1: (-1, 0),   # N - West
    2: (1, 0),    # D - East
    3: (0, -1),   # Y - North (up)
    4: (0, -1),   # A - North (up)
    5: (1, 0),    # H - East
    6: (-1, -1),  # R - Northwest (up-left)
}

# KRYPTOS column mapping
KW_COLS = list("KRYPTOS")  # cols 0-6


def remove_nulls(ct):
    """Remove consensus null positions, return reduced CT."""
    return "".join(ct[i] for i in range(len(ct)) if i not in CONSENSUS_NULL_POSITIONS)


def columnar_decrypt(ct_str, width, col_order, col_reverse=None):
    """Undo columnar transposition. col_order[i] = which column to read i-th.
    col_reverse[col] = True means read that column bottom-to-top."""
    n = len(ct_str)
    nrows = (n + width - 1) // width
    full_cols = n % width if n % width != 0 else width

    # Compute column lengths
    col_lens = []
    for c in range(width):
        if c < full_cols or full_cols == width:
            col_lens.append(nrows)
        else:
            col_lens.append(nrows - 1)

    # Read columns in col_order
    pos = 0
    columns = {}
    for read_idx in range(width):
        col_id = col_order[read_idx]
        clen = col_lens[col_id]
        col_data = list(ct_str[pos:pos + clen])
        if col_reverse and col_reverse.get(col_id, False):
            col_data = col_data[::-1]
        columns[col_id] = col_data
        pos += clen

    # Reconstruct plaintext row by row
    pt = []
    for r in range(nrows):
        for c in range(width):
            if r < len(columns.get(c, [])):
                pt.append(columns[c][r])
    return "".join(pt)


def decrypt_beaufort(ct_str, key):
    """Beaufort decrypt: PT = (K - CT) mod 26"""
    pt = []
    klen = len(key)
    for i, c in enumerate(ct_str):
        k = ALPH_IDX[key[i % klen]]
        ct_val = ALPH_IDX[c]
        pt.append(ALPH[(k - ct_val) % MOD])
    return "".join(pt)


def score_pt(pt):
    """Score against known cribs."""
    result = score_candidate(pt)
    return result.crib_score


# ── Hypothesis generators ────────────────────────────────────────────────

def h1_direction_orderings():
    """H1: Map directions to column read priority.
    Group cols by direction type, try all orderings within/between groups."""
    # Up cols (3,4,6 have vertical component) vs horizontal cols (1,2,5) vs baseline (0)
    up_cols = [3, 4, 6]
    horiz_cols = [1, 2, 5]
    base_cols = [0]

    orderings = []
    # Up-first, then horiz, then base
    for up_perm in itertools.permutations(up_cols):
        for h_perm in itertools.permutations(horiz_cols):
            orderings.append(list(up_perm) + list(h_perm) + base_cols)
            orderings.append(base_cols + list(up_perm) + list(h_perm))
            orderings.append(list(h_perm) + list(up_perm) + base_cols)
    return orderings


def h2_direction_reversal():
    """H2: Direction encodes forward/reverse read per column.
    W/NW = reverse, E = forward, N = bottom-to-top (reverse)."""
    configs = []

    # Interpretation 1: horizontal component determines direction
    rev1 = {0: False, 1: True, 2: False, 3: False, 4: False, 5: False, 6: True}

    # Interpretation 2: any upward component = reverse
    rev2 = {0: False, 1: False, 2: False, 3: True, 4: True, 5: False, 6: True}

    # Interpretation 3: any leftward component = reverse
    rev3 = {0: False, 1: True, 2: False, 3: False, 4: False, 5: False, 6: True}

    # Interpretation 4: non-baseline = reverse
    rev4 = {0: False, 1: True, 2: True, 3: True, 4: True, 5: True, 6: True}

    configs = [rev1, rev2, rev3, rev4]
    return configs


def h3_vertical_priority():
    """H3: Columns with upward displacement read first."""
    up = [c for c, (dx, dy) in DIRECTIONS.items() if dy < 0]  # 3,4,6
    rest = [c for c in range(7) if c not in up]
    orderings = []
    for up_perm in itertools.permutations(up):
        for rest_perm in itertools.permutations(rest):
            orderings.append(list(up_perm) + list(rest_perm))
    return orderings


def worker(args):
    """Test one configuration: col_order + optional reversal + keyword."""
    col_order, col_reverse, keyword, label = args

    ct73 = remove_nulls(CT)

    try:
        pt_trans = columnar_decrypt(ct73, 7, col_order, col_reverse)
        pt = decrypt_beaufort(pt_trans, keyword)
        sc = score_pt(pt)
    except Exception:
        return None

    if sc >= 6:
        return {
            "score": sc,
            "col_order": col_order,
            "col_reverse": {str(k): v for k, v in col_reverse.items()} if col_reverse else None,
            "keyword": keyword,
            "label": label,
            "pt_preview": pt[:50],
        }
    return None


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-NDYAHR-COUPLING-01: NDYAHR Directions + Null Mask + Col-7")
    print("=" * 70)

    ct73 = remove_nulls(CT)
    print(f"CT97: {CT}")
    print(f"CT after null removal ({len(ct73)} chars): {ct73}")
    print(f"Consensus null positions ({len(NULLS)}): {NULLS}")
    print()

    # Keywords to test
    keywords = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK",
                "EASTNORTHEAST", "STOPWATCH", "LAYERTWO", "GOLD",
                "RYPTOS", "NDYAHR", "YAR"]

    # ── H1: Direction-based orderings ────────────────────────────────────
    h1_orders = h1_direction_orderings()
    print(f"H1 direction orderings: {len(h1_orders)}")

    # ── H2: Direction-based reversal ─────────────────────────────────────
    h2_reversals = h2_direction_reversal()
    print(f"H2 reversal configs: {len(h2_reversals)}")

    # ── H3: Vertical priority orderings ──────────────────────────────────
    h3_orders = h3_vertical_priority()
    print(f"H3 vertical priority orderings: {len(h3_orders)}")

    # ── Also test all 5040 col permutations with each reversal ───────────
    all_perms = list(itertools.permutations(range(7)))
    print(f"Full permutations: {len(all_perms)}")

    # Build job list
    jobs = []

    # H1 x keywords x no reversal
    for order in h1_orders:
        for kw in keywords:
            jobs.append((order, None, kw, "H1_dir_order"))

    # H2: all 5040 perms x each reversal x top keywords
    top_kw = ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]
    for rev_config in h2_reversals:
        for perm in all_perms:
            for kw in top_kw:
                jobs.append((list(perm), rev_config, kw, "H2_reversal"))

    # H3 x keywords
    for order in h3_orders:
        for kw in keywords:
            jobs.append((order, None, kw, "H3_vert_priority"))

    # H1 x H2 combined: direction ordering WITH reversal
    for order in h1_orders[:36]:  # limit combinations
        for rev_config in h2_reversals:
            for kw in top_kw:
                jobs.append((order, rev_config, kw, "H1+H2_combined"))

    print(f"\nTotal jobs: {len(jobs):,}")

    n_workers = max(1, cpu_count() - 2)
    print(f"Workers: {n_workers}")
    print()

    results = []
    best_score = 0
    t1 = time.time()

    with Pool(n_workers) as pool:
        for i, result in enumerate(pool.imap_unordered(worker, jobs, chunksize=200)):
            if result is not None:
                results.append(result)
                if result["score"] > best_score:
                    best_score = result["score"]
                    print(f"  NEW BEST: {result['score']}/24 | {result['label']} | "
                          f"order={result['col_order']} kw={result['keyword']}")
                    print(f"    PT: {result['pt_preview']}")
            if (i + 1) % 50000 == 0:
                elapsed = time.time() - t1
                print(f"  [{i+1}/{len(jobs)}] {elapsed:.0f}s, best={best_score}/24")

    elapsed = time.time() - t0
    results.sort(key=lambda x: x["score"], reverse=True)

    print(f"\n{'=' * 70}")
    print(f"RESULTS")
    print(f"{'=' * 70}")
    print(f"Total configs tested: {len(jobs):,}")
    print(f"Results above threshold: {len(results)}")
    print(f"Best score: {best_score}/24")
    print(f"Runtime: {elapsed:.1f}s")

    if results:
        print(f"\nTOP 10:")
        for r in results[:10]:
            print(f"  {r['score']}/24 | {r['label']} | order={r['col_order']} "
                  f"kw={r['keyword']} | {r['pt_preview']}")

    # Verdict
    if best_score >= 18:
        verdict = "SIGNAL"
    elif best_score >= 10:
        verdict = "INTERESTING"
    else:
        verdict = "NOISE"

    print(f"\nVERDICT: {verdict}")

    output = {
        "experiment": "E-NDYAHR-COUPLING-01",
        "description": "NDYAHR directional vectors coupled with consensus null mask + col-7 Beaufort",
        "total_configs": len(jobs),
        "best_score": best_score,
        "verdict": verdict,
        "runtime_s": round(elapsed, 1),
        "top10": results[:10],
        "hypotheses": {
            "H1": f"{len(h1_orders)} direction-based orderings",
            "H2": f"{len(h2_reversals)} reversal configs x {len(all_perms)} perms",
            "H3": f"{len(h3_orders)} vertical-priority orderings",
        },
        "null_mask": NULLS,
    }

    out_path = os.path.join(_ROOT, "results", "ndyahr_nullmask_coupling.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nResults saved to: {out_path}")


if __name__ == "__main__":
    main()
