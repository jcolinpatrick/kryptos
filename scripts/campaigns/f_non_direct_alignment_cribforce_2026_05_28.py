#!/usr/bin/env python3
"""Non-direct-alignment CRIB-FORCING closure (alignment_model = non_direct_alignment).

Pre-registration: docs/campaigns/non_direct_alignment_cribforce_2026_05_28.md

Closes the cell prior work left open: crib-FORCING a periodic key over the 51
NON-identity named reorderings at the Bean-surviving periods {8,13,16,19,26}.
The 2026-05-25 probe used fixed keywords (never forced); E-FRAC-36/55 forced
only under the identity reordering.

Model: an outer layer reorders CT -> I = pi(CT); an inner periodic cipher
decrypts I IN PLACE -> PT, with cribs at canonical PLAINTEXT positions
21-33 / 63-73. We feed I to solve_periodic with an IDENTITY NullMask (no nulls),
so Bean is re-derived from the reordered CT and the cribs FORCE the key residues.

Periods {20,23,24} (5-7 free residues) exceed solve_periodic's
max_free_exhaustive=4 cap and are SA-DEFERRED (recorded, not closed).

Output: results/non_direct_alignment_cribforce_2026_05_28.json
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import sys
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
if os.path.join(_ROOT, "src") not in sys.path:
    sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CRIB_DICT  # noqa: E402
from kryptos.kernel.alphabet import AZ, KA  # noqa: E402
from kryptos.kernel.transforms.vigenere import CipherVariant  # noqa: E402
from kryptos.kernel.masking.solve import solve_periodic  # noqa: E402
from kryptos.kernel.scoring.ngram import get_default_scorer  # noqa: E402
from kryptos.kernel.scoring.e0b import CALIBRATED_SIGNAL_MAX_DISTANCE  # noqa: E402

# ── Pre-registered constants (locked before any data) ───────────────────────
N = 97
PERIODS = (8, 13, 16, 19, 26)          # Bean-surviving, free residues <= 4
DEFERRED_PERIODS = (20, 23, 24)        # free residues 7/6/5 -> SA, not closed here
VARIANTS = (CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT)
ALPHABETS = (("AZ", AZ), ("KA", KA))
NGRAM_PER_CHAR_FLOOR = -4.5            # docs/preregistered_thresholds_2026_04_08.md
E0B_MAX = CALIBRATED_SIGNAL_MAX_DISTANCE  # 2.31, GAP-03 p<=1e-6
NULL_B = 5000
NULL_SEED = 20260528
EXPECTED_REORDERING_HASH = (
    "7a9ac67336cd37e2f7be75c59d549b75618395c47a4bcd515d652232996ae6aa"
)
IDENTITY_MASK = frozenset()           # no nulls: decrypt-in-place on the reordered CT
_N_QUADGRAMS = N - 3                   # 94


# ── Alignment universe (verbatim from 2026-05-25 runner; hash-asserted) ─────
def _grid_routes(width: int):
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

    col = []
    for c in range(width):
        for r in range(rows):
            col.append(grid[r][c])
    yield (f"grid{width}_colLR", drop_ghosts(col))

    colR = []
    for c in range(width - 1, -1, -1):
        for r in range(rows):
            colR.append(grid[r][c])
    yield (f"grid{width}_colRL", drop_ghosts(colR))

    serp = []
    for r in range(rows):
        rng = range(width) if r % 2 == 0 else range(width - 1, -1, -1)
        for c in rng:
            serp.append(grid[r][c])
    yield (f"grid{width}_serpRow", drop_ghosts(serp))

    diag = []
    for s in range(rows + width - 1):
        for r in range(rows):
            c = s - r
            if 0 <= c < width:
                diag.append(grid[r][c])
    yield (f"grid{width}_antidiag", drop_ghosts(diag))

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
    aligns = []
    seen = set()

    def add(name, perm):
        assert sorted(perm) == list(range(N)), f"{name} not a permutation"
        key = tuple(perm)
        if key in seen:
            return
        seen.add(key)
        aligns.append((name, perm))

    add("identity", list(range(N)))
    add("reverse", list(range(N - 1, -1, -1)))
    for w in [4, 5, 6, 7, 8, 11, 13, 14, 21, 24]:
        for name, perm in _grid_routes(w):
            add(name, perm)
    return aligns


def reordering_hash(aligns):
    h = hashlib.sha256()
    for name, perm in aligns:
        h.update(name.encode())
        h.update(bytes(perm))
    return h.hexdigest()


# ── Core (importable, tested) ───────────────────────────────────────────────
def apply_perm(ct: str, perm) -> str:
    """Reordered intermediate I where I[j] = CT[perm[j]] (gather convention,
    matches the 2026-05-25 runner verbatim)."""
    return "".join(ct[perm[j]] for j in range(len(perm)))


def eval_reordering(ct, perm, *, periods, crib_dict, scorer,
                    alphabets=ALPHABETS, variants=VARIANTS, require_bean=True):
    """Crib-force a periodic inner over one reordering. Returns a list of
    (alphabet_name, MaskedCandidate) for every residue-consistent cell."""
    intermediate = apply_perm(ct, perm)
    out = []
    for ak_name, alpha in alphabets:
        cands = solve_periodic(
            intermediate, [IDENTITY_MASK], periods=periods, crib_dict=crib_dict,
            variants=variants, alphabet=alpha, ngram_scorer=scorer,
            require_bean=require_bean, max_free_exhaustive=4,
        )
        for c in cands:
            out.append((ak_name, c))
    return out


def best_ngram_for_perm(ct, perm, scorer):
    """Best (total) n-gram among residue-consistent + Bean-passing cells for one
    reordering, or None if no consistent cell. Used for both real + null."""
    cells = eval_reordering(ct, perm, periods=PERIODS, crib_dict=CRIB_DICT,
                            scorer=scorer)
    best = None
    for _ak, c in cells:
        if c.bean_passed and c.crib_score == 24 and c.ngram_score is not None:
            if best is None or c.ngram_score > best:
                best = c.ngram_score
    return best


# ── Multiprocessing workers ─────────────────────────────────────────────────
_SCORER = None


def _init_worker():
    global _SCORER
    _SCORER = get_default_scorer()


def _eval_named(args):
    name, perm = args
    cells = eval_reordering(CT, perm, periods=PERIODS, crib_dict=CRIB_DICT,
                            scorer=_SCORER)
    recs = []
    for ak, c in cells:
        if not (c.bean_passed and c.crib_score == 24 and c.ngram_score is not None):
            continue
        recs.append({
            "alignment": name, "alphabet": ak, "variant": c.variant.value,
            "period": c.period, "crib_score": c.crib_score,
            "bean_passed": c.bean_passed, "ngram_total": c.ngram_score,
            "ngram_per_char": c.ngram_score / _N_QUADGRAMS,
            "e0b_mean_distance": c.e0b_mean_distance, "e0b_count": c.e0b_count,
            "pt": c.plaintext,
        })
    return recs


def _eval_null(perm):
    return best_ngram_for_perm(CT, perm, _SCORER)


def main():
    aligns = build_alignment_universe()
    rh = reordering_hash(aligns)
    print(f"[universe] reorderings={len(aligns)}  reordering_sha256={rh}")
    assert rh == EXPECTED_REORDERING_HASH, (
        f"reordering universe drifted from 2026-05-25 ({rh} != "
        f"{EXPECTED_REORDERING_HASH}); refusing to run a non-comparable universe")
    print(f"[universe] periods={PERIODS} (deferred SA: {DEFERRED_PERIODS}) "
          f"variants={[v.value for v in VARIANTS]} alphabets={[a for a,_ in ALPHABETS]}")

    workers = max(1, cpu_count() - 2)

    # Real sweep over the 52 named reorderings.
    with Pool(workers, initializer=_init_worker) as pool:
        real_lists = pool.map(_eval_named, aligns)
    real = [r for sub in real_lists for r in sub]
    real.sort(key=lambda r: r["ngram_total"], reverse=True)
    n_consistent_real = len(real)
    real_best = real[0] if real else None
    print(f"[real] residue-consistent+Bean cells = {n_consistent_real}")
    if real_best:
        print(f"[real] best ngram/char = {real_best['ngram_per_char']:.3f} "
              f"({real_best['alignment']} p={real_best['period']} "
              f"{real_best['variant']}/{real_best['alphabet']})")

    # Reordering-aware null.
    rng = random.Random(NULL_SEED)
    null_perms = []
    for _ in range(NULL_B):
        p = list(range(N))
        rng.shuffle(p)
        null_perms.append(p)
    with Pool(workers, initializer=_init_worker) as pool:
        null_best = pool.map(_eval_null, null_perms)
    null_vals = [x for x in null_best if x is not None]
    null_vals.sort(reverse=True)
    n_consistent_null = len(null_vals)
    null_max = null_vals[0] if null_vals else None
    null_mean = (sum(null_vals) / len(null_vals)) if null_vals else None
    print(f"[null] B={NULL_B} consistent perms={n_consistent_null} "
          f"({100*n_consistent_null/NULL_B:.1f}%) "
          f"null_max/char={(null_max/_N_QUADGRAMS):.3f} "
          if null_max is not None else f"[null] B={NULL_B} consistent perms=0")

    # Pre-registered 4-part gate.
    promoted = []
    for r in real:
        cond2 = r["ngram_per_char"] >= NGRAM_PER_CHAR_FLOOR
        cond3 = (null_max is None) or (r["ngram_total"] > null_max)
        cond4 = (r["e0b_mean_distance"] is not None and
                 r["e0b_mean_distance"] <= E0B_MAX)
        if cond2 and cond3 and cond4:
            promoted.append(r)

    # HONEST summary (per statistical-auditor 2026-05-28): the decisive,
    # well-posed comparison is max-of-universe vs max-of-universe. A naive
    # p over all B perms is diluted by cipher-incompatible perms and mismatches
    # the order-statistic depth (real best = max over many consistent cells vs
    # one perm's best). We therefore report (a) whether the null max BEATS the
    # real best (the one honest number), and (b) p CONDITIONED on the consistent
    # null reference set, clearly labelled non-inferential.
    distinct_real_reorderings = len({r["alignment"] for r in real})
    null_beats_real = (
        null_max is not None and real_best is not None
        and null_max >= real_best["ngram_total"]
    )
    p_conditioned = None  # over consistent null perms only
    if real_best is not None and null_vals:
        ge = sum(1 for x in null_vals if x >= real_best["ngram_total"])
        p_conditioned = ge / len(null_vals)

    verdict = "CLEAN_NULL" if not promoted else "CANDIDATE_ESCALATE"
    print(f"[gate] promoted cells = {len(promoted)}  VERDICT = {verdict}")
    print(f"[honest] real best total = "
          f"{real_best['ngram_total']:.2f}" if real_best else "[honest] no real cells")
    print(f"[honest] null max total = {null_max:.2f}  "
          f"null_beats_real = {null_beats_real}  "
          f"(real best is {'BELOW' if null_beats_real else 'ABOVE'} the null max)"
          if null_max is not None else "[honest] no consistent null perms")
    print(f"[honest] distinct consistent real reorderings = "
          f"{distinct_real_reorderings} (cells={n_consistent_real})")

    out = {
        "alignment_model": "non_direct_alignment",
        "submodel": "crib_forcing_periodic_inner",
        "reordering_hash": rh,
        "periods": list(PERIODS),
        "deferred_sa_periods": list(DEFERRED_PERIODS),
        "variants": [v.value for v in VARIANTS],
        "alphabets": [a for a, _ in ALPHABETS],
        "gate": {
            "ngram_per_char_floor": NGRAM_PER_CHAR_FLOOR,
            "e0b_max": E0B_MAX,
            "beats_null_max": True,
        },
        "n_consistent_real_cells": n_consistent_real,
        "real_top": real[:12],
        "null_B": NULL_B,
        "null_seed": NULL_SEED,
        "n_consistent_null_perms": n_consistent_null,
        "null_max_total": null_max,
        "null_mean_total": null_mean,
        "null_max_per_char": (null_max / _N_QUADGRAMS) if null_max else None,
        "distinct_consistent_real_reorderings": distinct_real_reorderings,
        "null_beats_real": null_beats_real,
        "p_conditioned_on_consistent_null": p_conditioned,
        "p_note": (
            "NON-INFERENTIAL. p conditioned on consistent null perms only; "
            "the decisive comparison is null_beats_real (max-of-universe vs "
            "max-of-universe). See statistical-auditor 2026-05-28."
        ),
        "n_promoted": len(promoted),
        "promoted": promoted,
        "verdict": verdict,
    }
    outpath = os.path.join(_ROOT, "results",
                           "non_direct_alignment_cribforce_2026_05_28.json")
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    with open(outpath, "w") as f:
        json.dump(out, f, indent=2)
    print(f"[out] {outpath}")
    return verdict


if __name__ == "__main__":
    main()
