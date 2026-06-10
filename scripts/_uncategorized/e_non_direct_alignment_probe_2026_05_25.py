#!/usr/bin/env python3
"""Non-direct-alignment probe (alignment_model = non_direct_alignment).

Tests a SMALL, installation-motivated set of REORDERINGS of the 97 carved
characters, each followed by a bounded keyword-driven inner cipher. Cribs are
checked at the canonical PLAINTEXT positions 21-33 / 63-73; Bean is RE-DERIVED
from the reordered CT (CT_perm, CANONICAL_CRIB_DICT) for every alignment.

Novelty boundary (do NOT re-run the closed universal proof):
  - We do NOT enumerate 97! permutations.
  - We do NOT do a free period sweep over arbitrary permutations.
  - Alignment universe is a NAMED, hash-documented bounded set derived from the
    sculpture's physical/structural grammar (grid re-reads at motivated widths,
    route reads, reflections).
  - Inner cipher is a BOUNDED named keyword set x 3 variants -- not a free
    period sweep -- which keeps us off the closed "all-permutations + single
    periodic key" surface.

Output: results/non_direct_alignment_probe_2026_05_25.json
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import random
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):  # walk up to repo root
    _ROOT = os.path.dirname(_ROOT)
if os.path.join(_ROOT, "src") not in sys.path:
    sys.path.insert(0, os.path.join(_ROOT, "src"))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)  # kryptosbot lives at repo root, not under src

from kryptos.kernel.constants import CT, CRIB_DICT  # noqa: E402
from kryptos.kernel.alphabet import AZ, KA  # noqa: E402
from kryptos.kernel.transforms.vigenere import CipherVariant  # noqa: E402
from kryptos.kernel.constraints.bean import derive_bean_constraints  # noqa: E402
from kryptosbot.ct_perturbation import (  # noqa: E402
    decrypt_with_keyword,
    crib_score_for_pt,
    recover_keystream_at_cribs,
    verify_bean_against_keystream,
)

CRIB_POSITIONS = sorted(CRIB_DICT.keys())

# ---------------------------------------------------------------------------
# 1. ALIGNMENT UNIVERSE: bounded, installation-motivated permutations of 0..96
# ---------------------------------------------------------------------------
N = 97


def _grid_routes(width: int):
    """Write CT row-wise into a width-w grid (pad with -1 ghost cells), then
    read by several physically-motivated routes. Yields (name, perm) where
    perm is a length-97 reordering of source indices (ghosts dropped)."""
    rows = -(-N // width)
    grid = [[None] * width for _ in range(rows)]
    idx = 0
    for r in range(rows):
        for c in range(width):
            if idx < N:
                grid[r][c] = idx
                idx += 1

    def drop_ghosts(seq):
        return [x for x in seq if x is not None]

    # column read (classic columnar, left-to-right columns)
    col = []
    for c in range(width):
        for r in range(rows):
            col.append(grid[r][c])
    yield (f"grid{width}_colLR", drop_ghosts(col))

    # column read right-to-left
    colR = []
    for c in range(width - 1, -1, -1):
        for r in range(rows):
            colR.append(grid[r][c])
    yield (f"grid{width}_colRL", drop_ghosts(colR))

    # boustrophedon / serpentine row read (alt direction per row)
    serp = []
    for r in range(rows):
        rng = range(width) if r % 2 == 0 else range(width - 1, -1, -1)
        for c in rng:
            serp.append(grid[r][c])
    yield (f"grid{width}_serpRow", drop_ghosts(serp))

    # anti-diagonal read (top-left to bottom-right diagonals)
    diag = []
    for s in range(rows + width - 1):
        for r in range(rows):
            c = s - r
            if 0 <= c < width:
                diag.append(grid[r][c])
    yield (f"grid{width}_antidiag", drop_ghosts(diag))

    # spiral inward, clockwise from top-left
    top, bot, left, right = 0, rows - 1, 0, width - 1
    spiral = []
    while top <= bot and left <= right:
        for c in range(left, right + 1):
            spiral.append(grid[top][c])
        top += 1
        for r in range(top, bot + 1):
            spiral.append(grid[r][right])
        right -= 1
        if top <= bot:
            for c in range(right, left - 1, -1):
                spiral.append(grid[bot][c])
            bot -= 1
        if left <= right:
            for r in range(bot, top - 1, -1):
                spiral.append(grid[r][left])
            left += 1
    yield (f"grid{width}_spiralCW", drop_ghosts(spiral))


def build_alignment_universe():
    """Return ordered list of (name, perm) with perm a permutation of 0..96.
    Deterministic; de-duplicated by perm tuple."""
    aligns = []
    seen = set()

    def add(name, perm):
        assert sorted(perm) == list(range(N)), f"{name} not a permutation"
        key = tuple(perm)
        if key in seen:
            return
        seen.add(key)
        aligns.append((name, perm))

    # Identity is the DIRECT model -- include as control (so the null knows it).
    add("identity", list(range(N)))
    # Full reverse read (sculpture-as-mirror / reflected read).
    add("reverse", list(range(N - 1, -1, -1)))

    # Motivated widths: prime-near rectangles, panel widths (14,21),
    # Berlin-Clock row counts (4,11), small columnar widths.
    motivated_widths = [4, 5, 6, 7, 8, 11, 13, 14, 21, 24]
    for w in motivated_widths:
        for name, perm in _grid_routes(w):
            add(name, perm)

    return aligns


# ---------------------------------------------------------------------------
# 2. INNER CIPHER UNIVERSE: bounded named keyword set x 3 variants x 2 alphabets
# ---------------------------------------------------------------------------
# Installation/lore keywords only -- NOT a free period sweep.
KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK", "BERLINCLOCK",
    "EAST", "NORTHEAST", "SHADOW", "FORCES", "LUCID", "MEMORY",
    "INVISIBLE", "DIGETAL", "INTERPRETATU", "POSITION", "IQLUSION",
    "UNDERGROUND", "LAYERTWO", "SANBORN", "LANGLEY", "COMPASS",
    "LODESTONE", "MENGENLEHREUHR",
]
VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]
ALPHABETS = [("AZ", AZ), ("KA", KA)]


def inner_keys():
    for kw in KEYWORDS:
        for var in VARIANTS:
            for ak_name, _ in ALPHABETS:
                yield (kw, var, ak_name)


# ---------------------------------------------------------------------------
# 3. SCORING ONE (alignment, key) cell
# ---------------------------------------------------------------------------
def _alpha(ak_name):
    return AZ if ak_name == "AZ" else KA


def eval_alignment(args):
    """Evaluate ALL inner keys for one alignment. Returns best record + the
    full crib-score list for null calibration. ct_perm passed precomputed."""
    name, ct_perm = args
    # Re-derive Bean from the REORDERED ct against canonical cribs.
    bc = derive_bean_constraints(ct_perm, CRIB_DICT, alphabet=AZ)
    eq, ineq, linear = bc
    best = None
    for kw, var, ak_name in inner_keys():
        alpha = _alpha(ak_name)
        try:
            pt = decrypt_with_keyword(ct_perm, kw, var, ak_name)
        except Exception:
            continue
        cs, ct_tot = crib_score_for_pt(pt, CRIB_DICT)
        bean_passed = False
        if cs >= 12:  # only bother with Bean on non-trivial crib hits
            ks = recover_keystream_at_cribs(
                ct_perm, pt, family=var, alphabet=alpha,
                crib_positions=CRIB_POSITIONS,
            )
            bean_passed = verify_bean_against_keystream(ks, eq, ineq, linear)
        rec = (cs, bean_passed, kw, var.value, ak_name, pt)
        if best is None or cs > best[0]:
            best = rec
    return name, best


def run_universe(aligns):
    workers = max(1, cpu_count() - 2)
    with Pool(workers) as pool:
        results = pool.map(eval_alignment, aligns)
    return results


# ---------------------------------------------------------------------------
# 4. NULL CALIBRATION: same inner universe over B random permutations
# ---------------------------------------------------------------------------
def random_perm(rng):
    p = list(range(N))
    rng.shuffle(p)
    return p


def run_null(B, seed=20260525):
    rng = random.Random(seed)
    null_aligns = []
    for b in range(B):
        p = random_perm(rng)
        ctp = "".join(CT[i] for i in p)
        null_aligns.append((f"null{b}", ctp))
    # Each "alignment" here is one random permutation; we take max crib over
    # the FULL inner-key universe per perm -> that is one max-of-innerN draw.
    workers = max(1, cpu_count() - 2)
    with Pool(workers) as pool:
        results = pool.map(eval_alignment, null_aligns)
    # best crib per random perm
    return [best[0] for _, best in results if best is not None]


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    aligns_idx = build_alignment_universe()
    # materialize ct_perm strings
    aligns = [(name, "".join(CT[i] for i in perm)) for name, perm in aligns_idx]

    # universe hash: enumerated permutations (names + index tuples)
    h = hashlib.sha256()
    for name, perm in aligns_idx:
        h.update(name.encode())
        h.update(bytes(perm))
    universe_hash = h.hexdigest()

    n_align = len(aligns)
    n_keys = sum(1 for _ in inner_keys())
    universe_size = n_align * n_keys

    print(f"[universe] alignments={n_align} inner_keys={n_keys} "
          f"total_cells={universe_size}")
    print(f"[universe] sha256={universe_hash}")

    # Run real sweep
    results = run_universe(aligns)
    results_sorted = sorted(
        [(name, b) for name, b in results if b is not None],
        key=lambda r: r[1][0], reverse=True,
    )

    real_max = results_sorted[0][1][0] if results_sorted else 0
    print(f"[real] best crib_score = {real_max}")
    for name, b in results_sorted[:8]:
        cs, bean, kw, var, ak, pt = b
        print(f"  {name:20s} crib={cs:2d} bean={bean} {var}/{ak}/{kw}")

    # Null calibration
    B = 30
    null_maxes = run_null(B)
    null_maxes_sorted = sorted(null_maxes, reverse=True)
    null_max = max(null_maxes) if null_maxes else 0
    null_mean = sum(null_maxes) / len(null_maxes) if null_maxes else 0
    # p-value: fraction of null perms whose best-inner crib >= real_max.
    # Note: real universe is n_align deterministic perms; each null draw is one
    # perm's max-over-inner. We report p = P(one random perm's best >= real_max).
    ge = sum(1 for x in null_maxes if x >= real_max)
    p_one = ge / len(null_maxes) if null_maxes else 1.0
    # max-of-n_align under null (approx): expected best over n_align perms
    print(f"[null] B={B} perm-best crib: max={null_max} mean={null_mean:.2f} "
          f"dist(sorted)={null_maxes_sorted}")
    print(f"[null] P(random perm best-inner >= real_max={real_max}) = {p_one:.3f}")

    out = {
        "alignment_model": "non_direct_alignment",
        "universe_hash": universe_hash,
        "n_alignments": n_align,
        "n_inner_keys": n_keys,
        "universe_size": universe_size,
        "keywords": KEYWORDS,
        "variants": [v.value for v in VARIANTS],
        "alphabets": [a for a, _ in ALPHABETS],
        "real_best_crib": real_max,
        "real_top": [
            {"alignment": name, "crib": b[0], "bean_passed": b[1],
             "keyword": b[2], "variant": b[3], "alphabet": b[4],
             "pt": b[5]}
            for name, b in results_sorted[:12]
        ],
        "null_B": B,
        "null_perm_best_crib": null_maxes,
        "null_max": null_max,
        "null_mean": null_mean,
        "p_random_perm_ge_real": p_one,
        "any_bean_pass_at_real_best": any(b[1] for _, b in results_sorted[:12]),
    }
    outpath = os.path.join(_ROOT, "results",
                           "non_direct_alignment_probe_2026_05_25.json")
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    with open(outpath, "w") as f:
        json.dump(out, f, indent=2)
    print(f"[out] {outpath}")


if __name__ == "__main__":
    main()
