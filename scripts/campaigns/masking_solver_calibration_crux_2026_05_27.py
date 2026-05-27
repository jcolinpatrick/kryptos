#!/usr/bin/env python3
"""Scaled calibration-crux validation for the masking solver (SYNTHETIC).

Preregistration: docs/campaigns/masking_solver_calibration_crux_2026_05_27.md

Validates, on PLANTED synthetic masked challenges (no real K4):
  C1 Recovery        - solver recovers the planted (mask, variant, key) + PT.
  C2 Negative ctrl   - at scale, decoy masks (truth excluded) never clear the
                       calibrated floor; report CP prune rate.
  C3 Calibrated null - empirical null places the true solve as a right-tail
                       outlier; the order-statistic floor is monotone in |U|;
                       the parametric floor (empirical mean/std) DEMOTES the
                       true solve at a large preregistered |U|.

Nothing here is promotable. Output is a quarantined JSON + markdown report.
"""
from __future__ import annotations

import json
import math
import os
import statistics
import sys
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.alphabet import AZ, KA  # noqa: E402
from kryptos.kernel.masking.mask import (  # noqa: E402
    extract_ct, remap_crib_dict, remap_position,
)
from kryptos.kernel.masking.solve import (  # noqa: E402
    calibrated_ngram_floor,
    calibrated_ngram_floor_empirical,
    estimate_ngram_null,
    select_solves,
    solve_periodic,
)
from kryptos.kernel.scoring.ngram import get_default_scorer  # noqa: E402
from kryptos.kernel.transforms.vigenere import CipherVariant, encrypt_text  # noqa: E402

U_LADDER = [1, 8, 64, 512, 4096, 32768]
PERIODS = list(range(1, 13))
# Negative-control decoys use the fully-forced regime (cribs 0..7 cover all
# residues for p<=8), so a surviving decoy needs at most a tiny free search.
# max_free_exhaustive=2 caps any residual search at 26**2.
PERIODS_NEG = list(range(1, 9))
NEG_MAX_FREE = 2
VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]
ALPHABETS = {"AZ": AZ, "KA": KA}
N_NULL = 200_000
ALPHA = 0.01
U_DEMOTE = 10**9
SEED = 20260527

# Two planted plaintexts; >14 chars so crib indices up to 14 are valid.
PT_FREE = "DEFENDTHEEASTWALLOFTHECASTLE"        # period 6, cribs {0,1,2} -> {3,4,5} free
# Forced plant: CT' length 28 (same as free plant, so n-gram scores are
# comparable) but EIGHT nulls -> decoy space C(28,8) ~ 3.1M, covering the
# |U| ladder to 32768.  Cribs 0..7 keep periods 1..8 fully forced.
PT_FORCED = "ATTACKATDAWNXKRYPTOSCLOCKNOW"       # 28 chars
KEY_FREE = [3, 17, 8, 22, 5, 11]
KEY_FORCED = [3, 17, 8, 22]
MASK_FREE = frozenset({7, 16, 25})
MASK_FORCED = frozenset(range(28, 36))           # 8 nulls -> carved len 36
CRIBS_FREE = [0, 1, 2, 6, 7, 8, 12, 13, 14]
CRIBS_FORCED = [0, 1, 2, 3, 4, 5, 6, 7]


def build_challenge(pt, key, variant, mask_positions, crib_idx, alphabet):
    ct_prime = encrypt_text(pt, key, variant, alphabet=alphabet)
    mask = frozenset(mask_positions)
    carved_len = len(ct_prime) + len(mask)
    src = iter(ct_prime)
    carved = "".join("Q" if p in mask else next(src) for p in range(carved_len))
    nonmask = [p for p in range(carved_len) if p not in mask]
    crib_dict = {nonmask[j]: pt[j] for j in crib_idx}
    return carved, mask, crib_dict


def decoy_universe(carved_len, true_mask, crib_positions, size, rng_seed, mask_size):
    """Deterministically sample `size` crib-disjoint decoy masks distinct from
    the true mask."""
    import random
    rng = random.Random(rng_seed)
    avail = [p for p in range(carved_len) if p not in crib_positions]
    masks = set()
    attempts = 0
    while len(masks) < size and attempts < size * 50:
        attempts += 1
        m = frozenset(rng.sample(avail, mask_size))
        if m != true_mask:
            masks.add(m)
    return list(masks)


def _null_chunk(args):
    alpha_name, variant_val, n = args
    alphabet = ALPHABETS[alpha_name]
    variant = CipherVariant(variant_val)
    scorer = get_default_scorer()
    carved, true_mask, crib_dict = build_challenge(
        PT_FREE, KEY_FREE, variant, MASK_FREE, CRIBS_FREE, alphabet
    )
    ct_prime = extract_ct(carved, true_mask)
    cribs = remap_crib_dict(crib_dict, true_mask)
    return estimate_ngram_null(
        ct_prime, cribs, variant, 6, scorer, n_samples=n, seed=SEED + n, alphabet=alphabet
    )


def run_cell(alpha_name, variant):
    """All three arms for one (alphabet, variant) cell."""
    alphabet = ALPHABETS[alpha_name]
    scorer = get_default_scorer()
    res = {"alphabet": alpha_name, "variant": variant.value}

    # --- C1 recovery (free-residue plant, period 6) ---
    carved_f, mask_f, crib_f = build_challenge(
        PT_FREE, KEY_FREE, variant, MASK_FREE, CRIBS_FREE, alphabet
    )
    cands = solve_periodic(
        carved_f, [mask_f], periods=[6], crib_dict=crib_f,
        variants=[variant], alphabet=alphabet, ngram_scorer=scorer,
    )
    rec = [c for c in cands if c.plaintext == PT_FREE and tuple(c.key) == tuple(KEY_FREE)]
    res["C1_recovered"] = len(rec) == 1

    # --- C3 empirical null (parallel chunks merged by caller) handled separately ---
    # Here compute true-solve score for reference.
    res["true_solve_score"] = scorer.score(PT_FREE)
    return res


def main():
    t0 = datetime.now(timezone.utc)
    workers = max(1, (os.cpu_count() or 4) - 2)
    scorer = get_default_scorer()
    cells = [(a, v) for a in ALPHABETS for v in VARIANTS]

    # ---- Parallel empirical-null sampling (the heavy part) ----
    per_chunk = max(1, N_NULL // workers)
    null_jobs = []
    for a, v in cells:
        remaining = N_NULL
        while remaining > 0:
            take = min(per_chunk, remaining)
            null_jobs.append((a, v.value, take))
            remaining -= take
    null_by_cell = {(a, v.value): [] for a, v in cells}
    with ProcessPoolExecutor(max_workers=workers) as ex:
        for (a, vval, _), samples in zip(
            null_jobs, ex.map(_null_chunk, null_jobs)
        ):
            null_by_cell[(a, vval)].extend(samples)

    report = {
        "campaign": "masking_solver_calibration_crux",
        "date": t0.isoformat(),
        "posture": "SYNTHETIC validation; not a real-K4 attempt; not promotable",
        "prereg": "docs/campaigns/masking_solver_calibration_crux_2026_05_27.md",
        "params": {
            "U_ladder": U_LADDER, "periods": PERIODS, "periods_neg": PERIODS_NEG,
            "neg_max_free": NEG_MAX_FREE, "n_null": N_NULL,
            "alpha": ALPHA, "U_demote": U_DEMOTE, "seed": SEED, "workers": workers,
        },
        "cells": [],
        "overall": {},
    }

    c1_all = c2_all = c3a_all = c3b_all = c3c_all = True

    for a, v in cells:
        alphabet = ALPHABETS[a]
        null = null_by_cell[(a, v.value)]
        mean = statistics.fmean(null)
        sd = statistics.pstdev(null)
        true_score = scorer.score(PT_FREE)

        # C1
        cell = run_cell(a, v)
        c1 = cell["C1_recovered"]

        # C3a outlier
        z = (true_score - mean) / sd if sd > 0 else float("inf")
        c3a = z >= 5.0

        # C3b empirical floor monotone over ladder
        emp_floors = [calibrated_ngram_floor_empirical(null, n, alpha=ALPHA) for n in U_LADDER]
        c3b = all(b >= a2 for a2, b in zip(emp_floors, emp_floors[1:])) and emp_floors[-1] >= emp_floors[0]

        # C3c parametric floor demotes true solve at U_DEMOTE
        floor_small = calibrated_ngram_floor(1, null_mean=mean, null_std=sd, alpha=ALPHA)
        floor_demote = calibrated_ngram_floor(U_DEMOTE, null_mean=mean, null_std=sd, alpha=ALPHA)
        c3c = (floor_small < true_score) and (floor_demote > true_score)

        # C2 negative control at scale (fully-forced plant, period 4)
        carved_x, mask_x, crib_x = build_challenge(
            PT_FORCED, KEY_FORCED, v, MASK_FORCED, CRIBS_FORCED, alphabet
        )
        crib_positions = frozenset(crib_x)
        big = U_LADDER[-1]
        decoys = decoy_universe(
            len(carved_x), mask_x, crib_positions, big, SEED + 7, len(mask_x)
        )
        decoy_cands = solve_periodic(
            carved_x, decoys, periods=PERIODS_NEG, crib_dict=crib_x,
            variants=[v], alphabet=alphabet, ngram_scorer=scorer,
            max_free_exhaustive=NEG_MAX_FREE,
        )
        prune_rate = 1.0 - (len(decoy_cands) / max(1, len(decoys) * len(PERIODS_NEG)))
        # floor at this |U| from the canonical empirical null
        floor_big = calibrated_ngram_floor_empirical(null, len(decoys), alpha=ALPHA)
        cleared = select_solves(decoy_cands, ngram_floor=floor_big)
        max_decoy = max((c.ngram_score for c in decoy_cands), default=float("-inf"))
        c2 = (len(cleared) == 0) and (max_decoy < true_score)

        c1_all &= c1; c2_all &= c2; c3a_all &= c3a; c3b_all &= c3b; c3c_all &= c3c
        report["cells"].append({
            "alphabet": a, "variant": v.value,
            "C1_recovered": c1,
            "null_mean": round(mean, 4), "null_std": round(sd, 4),
            "true_solve_score": round(true_score, 4), "true_solve_z": round(z, 2),
            "C3a_outlier_z>=5": c3a,
            "empirical_floors_over_U": [round(f, 4) for f in emp_floors],
            "C3b_floor_monotone": c3b,
            "parametric_floor_U1": round(floor_small, 4),
            "parametric_floor_Udemote": round(floor_demote, 4),
            "C3c_demotion_at_1e9": c3c,
            "neg_control_decoys": len(decoys),
            "neg_control_survivors": len(decoy_cands),
            "neg_control_prune_rate": round(prune_rate, 6),
            "neg_control_max_decoy_score": (
                round(max_decoy, 4) if max_decoy != float("-inf") else None
            ),
            "neg_control_floor": round(floor_big, 4),
            "C2_no_false_solve": c2,
        })

    report["overall"] = {
        "C1_recovery": c1_all,
        "C2_negative_control": c2_all,
        "C3a_outlier": c3a_all,
        "C3b_floor_monotone": c3b_all,
        "C3c_demotion": c3c_all,
        "ALL_PASS": all([c1_all, c2_all, c3a_all, c3b_all, c3c_all]),
        "wall_seconds": (datetime.now(timezone.utc) - t0).total_seconds(),
    }

    outdir = os.path.join(_ROOT, "results", "masking_solver_calibration_crux")
    os.makedirs(outdir, exist_ok=True)
    stamp = t0.strftime("%Y%m%d_%H%M%S")
    outpath = os.path.join(outdir, f"calibration_crux_{stamp}.json")
    with open(outpath, "w") as f:
        json.dump(report, f, indent=2)
    print(json.dumps(report["overall"], indent=2))
    print(f"\nartifact: {outpath}")


if __name__ == "__main__":
    main()
