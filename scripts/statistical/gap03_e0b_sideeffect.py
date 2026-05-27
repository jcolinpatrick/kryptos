#!/usr/bin/env python3
"""
Cipher: GAP-03 E0b side-effect operationalization
Family: statistical
Status: active
Keyspace: calibration / candidate scoring (no search)
Last run: 2026-05-27
Best score: n/a (calibration artifact)
"""
# GAP-03 — BCL E0b side-effect operationalization
# ================================================
# Turns Bean's E0b anomaly into a FORWARD side-effect predicate the bridge can
# use, with a calibrated null. See:
#   docs/REAL_K4_EVIDENCE_ACQUISITION_PLAN.md  (GAP-03 recipe, steps 1-5)
#   docs/campaigns/gap03_e0b_operationalization_2026_05_27.md  (X/p0/Y triple)
#
# Modes:
#   --validate              reproduce Bean's p ~ 1/5520 on the disclosed cribs
#   --calibrate             build + persist the crib-pinned candidate null
#   --candidate <PLAINTEXT> score a 97-char candidate -> (statistic, p_value)
#
# This script takes ZERO K4-score input; the statistic is derived from the
# carved CT + disclosed cribs only.
from __future__ import annotations

import argparse
import json
import os
import random
import statistics
import subprocess
import sys
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from kryptos.kernel.constants import CT, CRIB_DICT  # noqa: E402
from kryptos.kernel.scoring.e0b import (  # noqa: E402
    KRYPTOS_SET, e0b_bean_pvalue, e0b_candidate_pvalue, minor_distance,
)

TARGET_P = 1.81e-4  # Bean's 1/5520
SIGNAL_GATE = 1e-6  # project SIGNAL p-value gate


def _kernel_commit():
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=_ROOT, stderr=subprocess.DEVNULL
        ).decode().strip()
    except Exception:
        return "unknown"


def crib_pinned_null_distribution(n_draws, seed):
    """Mean K-set distance over crib-pinned random plaintexts (the null Y)."""
    crib = dict(CRIB_DICT)
    n = len(CT)
    letters = [chr(65 + i) for i in range(26)]
    rng = random.Random(seed)
    out = []
    for _ in range(n_draws):
        total = cnt = 0
        for i in range(n):
            letter = crib[i] if i in crib else letters[rng.randrange(26)]
            if letter in KRYPTOS_SET:
                cnt += 1
                total += minor_distance(letter, CT[i])
        out.append(total / cnt if cnt else 0.0)
    return out


def cmd_validate(args):
    res = e0b_bean_pvalue(CT, CRIB_DICT, n_mc=args.n_mc, seed=args.seed)
    ok = 5e-5 < res.p_value < 5e-4
    print(f"E0b Bean validation (CT-permutation null, n_mc={res.n_mc}):")
    print(f"  count={res.count} obs_sum={res.obs_sum} obs_mean={res.obs_mean:.3f}")
    print(f"  p_value={res.p_value:.3e}  (1/{1/res.p_value:.0f})  target 1/5520={TARGET_P:.2e}")
    print(f"  reproduces Bean: {'YES' if ok else 'NO'}")
    return 0 if ok else 1


def cmd_calibrate(args):
    bean = e0b_bean_pvalue(CT, CRIB_DICT, n_mc=args.n_mc, seed=args.seed)
    dist = crib_pinned_null_distribution(args.n_cal, args.seed)
    mean = statistics.fmean(dist)
    sd = statistics.pstdev(dist)
    dist_sorted = sorted(dist)
    # Candidate statistic that would clear the SIGNAL gate (parametric, one-sided
    # left tail) and the honest empirical floor (cannot go below observed min).
    from statistics import NormalDist
    gate_threshold_parametric = NormalDist(mean, sd).inv_cdf(SIGNAL_GATE)
    artifact = {
        "statistic": "e0b_extended_position_mean_kset_distance",
        "description": "mean minor-distance(PT,CT) at positions where PT in {K,R,Y,P,T,O,S}",
        "null_model": "crib-pinned random plaintext (cribs held, off-crib uniform A-Z)",
        "date": datetime.now(timezone.utc).isoformat(),
        "kernel_commit": _kernel_commit(),
        "bean_validation": {
            "null_model": "CT permutation (preserves carved letter multiset)",
            "count": bean.count, "obs_sum": bean.obs_sum, "obs_mean": bean.obs_mean,
            "p_value": bean.p_value, "n_mc": bean.n_mc,
            "target_p": TARGET_P,
            "reproduces_bean": 5e-5 < bean.p_value < 5e-4,
        },
        "candidate_null": {
            "n_draws": args.n_cal, "seed": args.seed,
            "mean": round(mean, 4), "std": round(sd, 4),
            "min_observed": round(dist_sorted[0], 4),
            "q01": round(dist_sorted[len(dist_sorted) // 100], 4),
            "q05": round(dist_sorted[len(dist_sorted) // 20], 4),
            "crib_anchor_mean": 2.1,
        },
        "signal_gate": {
            "p": SIGNAL_GATE,
            "parametric_threshold_mean_dist": round(gate_threshold_parametric, 4),
            "note": "a candidate clears the SIGNAL gate iff its mean K-set distance "
                    "<= this threshold under the crib-pinned null; empirical floor "
                    "cannot extrapolate below min_observed without more draws.",
        },
    }
    outdir = os.path.join(_ROOT, "null_baselines")
    os.makedirs(outdir, exist_ok=True)
    outpath = os.path.join(outdir, "e0b_sideeffect_calibration.json")
    with open(outpath, "w") as f:
        json.dump(artifact, f, indent=2)
    print(json.dumps(artifact, indent=2))
    print(f"\nartifact: {outpath}")
    return 0


def cmd_candidate(args):
    pt = args.candidate.strip().upper()
    if len(pt) != len(CT):
        print(f"ERROR: candidate length {len(pt)} != {len(CT)}")
        return 2
    stat, p = e0b_candidate_pvalue(pt, CT, CRIB_DICT, n_mc=args.n_mc, seed=args.seed)
    print(f"E0b candidate side-effect:")
    print(f"  mean_kset_distance={stat:.3f}  p_value={p:.3e}  "
          f"(SIGNAL gate p<={SIGNAL_GATE:.0e}: {'CLEARS' if p <= SIGNAL_GATE else 'does not clear'})")
    return 0


def main():
    ap = argparse.ArgumentParser(description="GAP-03 E0b side-effect operationalization")
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--calibrate", action="store_true")
    ap.add_argument("--candidate", type=str, default=None)
    ap.add_argument("--n-mc", type=int, default=200_000)
    ap.add_argument("--n-cal", type=int, default=200_000)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    if args.validate:
        return cmd_validate(args)
    if args.calibrate:
        return cmd_calibrate(args)
    if args.candidate:
        return cmd_candidate(args)
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
