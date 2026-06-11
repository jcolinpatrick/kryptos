#!/usr/bin/env python3
"""
Cipher: statistical measurement (no decryption attempt)
Family: statistical
Status: exhausted
Keyspace: 3 components — C(p) p=2..26 (2x10k counterfactual draws), region IC (4x100k subsets), boundary TV (4 boundaries + 100k placebo 4-subsets)
Last run: 2026-06-11
Best score: n/a (measurement, MEASURED_NULL)
"""
"""E-GAP10-01: crib-bound positional mechanism measurement (GAP-10).

Pre-registration: docs/campaigns/gap10_positional_measurement_2026_06_11.md
(null models, statistics, M, seeds, and decision thresholds frozen before any
null draw was generated). Statistics library: gap10_lib.py (TDD,
tests/test_gap10_measurement.py).

Components:
  1. Bean residue-class structure, periods 2-26: C(p) = same-residue
     Bean-inequality pair count vs counterfactual-CT nulls (N1a permutation
     of real crib CT letters, N1b IID uniform). Affine-orbit trap avoided by
     construction (randomness over constraint systems, never within the 624).
  2. Gap-region IC vs composition-conditional position-subset null.
  3. Cross-boundary unigram TV change statistic vs placebo positions.
"""
import importlib.util
import json
import os
import random
import subprocess
import sys
import time
from bisect import bisect_left, bisect_right
from multiprocessing import Pool

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

_spec = importlib.util.spec_from_file_location(
    "gap10_lib", os.path.join(_ROOT, "scripts", "statistical", "gap10_lib.py"))
g10 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(g10)

from kryptos.kernel.constants import CT, CRIB_DICT  # noqa: E402

SEED = 20260611
M1 = 10_000     # component 1 draws per null family
M2 = 100_000    # component 2 subsets per region
M3 = 100_000    # component 3 placebo 4-subsets
ALPHA = 0.01
POSITIONS = sorted(CRIB_DICT)
REGIONS = {
    "R1_pre_ene_0_20": list(range(0, 21)),
    "R2_gap_34_62": list(range(34, 63)),
    "R3_post_bc_74_96": list(range(74, 97)),
    "R4_unknown_73": list(range(0, 21)) + list(range(34, 63)) + list(range(74, 97)),
}
BOUNDARIES = [21, 34, 63, 74]
W_PRIMARY = 10
W_SECONDARY = [7, 14]
OUT_DIR = os.path.join(_ROOT, "results", "gap10_measurement_2026_06_11")


# ── Component 1 workers ──────────────────────────────────────────────────

def _draw_profile(args: tuple[str, int]) -> tuple[list[int], int]:
    """One counterfactual draw -> (C(p) profile as list over PERIODS, |ineq|)."""
    kind, idx = args
    rng = random.Random(SEED * 1_000_003 + idx if kind == "perm"
                        else SEED * 2_000_003 + idx)
    letters = g10.perm_crib_letters(rng) if kind == "perm" else g10.iid_crib_letters(rng)
    ineq = g10.ineq_from_crib_letters(letters)
    prof = g10.cp_profile(ineq)
    return [prof[p] for p in g10.PERIODS], len(ineq)


def _component1(workers: int) -> dict:
    obs_ineq = g10.ineq_from_crib_letters([CT[p] for p in POSITIONS])
    obs_prof = g10.cp_profile(obs_ineq)
    out: dict = {
        "observed_C": {str(p): obs_prof[p] for p in g10.PERIODS},
        "observed_ineq_count": len(obs_ineq),
        "observed_first_order_survivors": sum(
            1 for p in g10.PERIODS if obs_prof[p] == 0),
        "N_p_geometry": {str(p): g10.same_residue_pair_count(POSITIONS, p)
                         for p in g10.PERIODS},
        "M": M1, "seed": SEED,
    }
    for kind in ("perm", "iid"):
        t0 = time.time()
        with Pool(workers) as pool:
            rows = pool.map(_draw_profile, [(kind, i) for i in range(M1)],
                            chunksize=64)
        profiles = [r[0] for r in rows]
        ineq_counts = [r[1] for r in rows]
        # per-period null arrays (sorted for fast tail ranking)
        per_period = [sorted(prof[j] for prof in profiles)
                      for j in range(len(g10.PERIODS))]

        def tail2(obs_val: float, arr: list[int]) -> float:
            m = len(arr)
            ge = m - bisect_left(arr, obs_val)
            le = bisect_right(arr, obs_val)
            return min(1.0, 2.0 * min((ge + 1) / (m + 1), (le + 1) / (m + 1)))

        pvals = {str(p): tail2(obs_prof[p], per_period[j])
                 for j, p in enumerate(g10.PERIODS)}
        holm_out = g10.holm(pvals, alpha=ALPHA)
        # joint max-statistic: min per-period tail, observed vs per-draw
        obs_min_tail = min(pvals.values())
        null_min_tails = [
            min(tail2(prof[j], per_period[j]) for j in range(len(g10.PERIODS)))
            for prof in profiles
        ]
        p_joint = (sum(1 for t in null_min_tails if t <= obs_min_tail) + 1) / (M1 + 1)
        survivors = [sum(1 for j in range(len(g10.PERIODS)) if prof[j] == 0)
                     for prof in profiles]
        out[kind] = {
            "p_two_sided": pvals,
            "holm": {k: {"p": v[0], "p_holm": v[1], "reject": v[2]}
                     for k, v in holm_out.items()},
            "joint_min_tail_obs": obs_min_tail,
            "joint_p": p_joint,
            "null_C_mean": {str(p): sum(prof[j] for prof in profiles) / M1
                            for j, p in enumerate(g10.PERIODS)},
            "null_ineq_count_mean": sum(ineq_counts) / M1,
            "null_first_order_survivor_mean": sum(survivors) / M1,
            "null_survivor_ge_observed_frac":
                sum(1 for s in survivors if s <= out["observed_first_order_survivors"]) / M1,
            "wall_sec": time.time() - t0,
        }
    return out


# ── Component 2 ──────────────────────────────────────────────────────────

def _component2() -> dict:
    out: dict = {"M": M2, "seed": SEED, "regions": {}}
    for j, (name, region) in enumerate(REGIONS.items()):
        rng = random.Random(SEED * 3_000_017 + j)
        n = len(region)
        obs = g10.region_ic(CT, region)
        null_vals = []
        idx_all = list(range(len(CT)))
        for _ in range(M2):
            null_vals.append(g10.region_ic(CT, rng.sample(idx_all, n)))
        mean = sum(null_vals) / M2
        var = sum((v - mean) ** 2 for v in null_vals) / (M2 - 1)
        out["regions"][name] = {
            "n": n,
            "observed_ic": obs,
            "null_mean": mean,
            "null_sd": var ** 0.5,
            "p_two_sided": g10.two_sided_tail(obs, null_vals),
        }
    pvals = {k: v["p_two_sided"] for k, v in out["regions"].items()}
    out["holm"] = {k: {"p": v[0], "p_holm": v[1], "reject": v[2]}
                   for k, v in g10.holm(pvals, alpha=ALPHA).items()}
    return out


# ── Component 3 ──────────────────────────────────────────────────────────

def _component3() -> dict:
    out: dict = {"M": M3, "seed": SEED, "windows": {}}
    for w in [W_PRIMARY] + W_SECONDARY:
        prof = g10.dw_profile(CT, w=w)
        centers = sorted(prof)
        values = [prof[x] for x in centers]
        n_x = len(centers)
        ranks = {}  # one-sided high: fraction of centers with D >= D(b)
        for b in BOUNDARIES:
            ranks[str(b)] = sum(1 for v in values if v >= prof[b]) / n_x
        # joint: mean rank of boundaries vs random 4-subsets of centers
        rank_of = {x: sum(1 for v in values if v >= prof[x]) / n_x
                   for x in centers}
        obs_mean_rank = sum(rank_of[b] for b in BOUNDARIES) / 4
        rng = random.Random(SEED * 4_000_037 + w)
        null_means = [
            sum(rank_of[x] for x in rng.sample(centers, 4)) / 4
            for _ in range(M3)
        ]
        p_joint = (sum(1 for m in null_means if m <= obs_mean_rank) + 1) / (M3 + 1)
        entry = {
            "boundary_D": {str(b): prof[b] for b in BOUNDARIES},
            "boundary_rank_p": ranks,
            "joint_mean_rank_obs": obs_mean_rank,
            "joint_p": p_joint,
            "n_centers": n_x,
            "tier": "primary" if w == W_PRIMARY else "secondary_exploratory",
        }
        if w == W_PRIMARY:
            entry["holm"] = {k: {"p": v[0], "p_holm": v[1], "reject": v[2]}
                             for k, v in g10.holm(ranks, alpha=ALPHA).items()}
        out["windows"][f"w{w}"] = entry
    return out


# ── Main ─────────────────────────────────────────────────────────────────

def main() -> int:
    os.makedirs(OUT_DIR, exist_ok=True)
    workers = max(1, (os.cpu_count() or 2) - 2)
    git_head = subprocess.run(["git", "rev-parse", "HEAD"],
                              capture_output=True, text=True,
                              cwd=_ROOT).stdout.strip()
    summary: dict = {
        "campaign_id": "e_gap10_01_positional_measurement",
        "prereg": "docs/campaigns/gap10_positional_measurement_2026_06_11.md",
        "git_head": git_head,
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "alpha": ALPHA,
    }
    print("[1/3] Bean residue-class structure (2x10k counterfactual draws)…",
          flush=True)
    summary["component1_residue"] = _component1(workers)
    print("[2/3] Gap-region IC permutation null (4x100k subsets)…", flush=True)
    summary["component2_region_ic"] = _component2()
    print("[3/3] Cross-boundary change tests…", flush=True)
    summary["component3_boundary"] = _component3()

    # Frozen decision rules: evidence candidate = any PRIMARY Holm reject.
    candidates = []
    c1 = summary["component1_residue"]["perm"]
    candidates += [f"C1 period {k}" for k, v in c1["holm"].items() if v["reject"]]
    if c1["joint_p"] <= ALPHA:
        candidates.append("C1 joint min-tail")
    c2 = summary["component2_region_ic"]
    candidates += [f"C2 {k}" for k, v in c2["holm"].items() if v["reject"]]
    c3 = summary["component3_boundary"]["windows"][f"w{W_PRIMARY}"]
    candidates += [f"C3 boundary {k}" for k, v in c3["holm"].items() if v["reject"]]
    if c3["joint_p"] <= ALPHA:
        candidates.append("C3 joint mean-rank")
    summary["evidence_candidates"] = candidates
    summary["verdict"] = ("EVIDENCE_CANDIDATES_REQUIRE_INVESTIGATION"
                          if candidates else "MEASURED_NULL")
    summary["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    path = os.path.join(OUT_DIR, "summary.json")
    with open(path, "w") as f:
        json.dump(summary, f, indent=1)
    print(f"VERDICT: {summary['verdict']}", flush=True)
    if candidates:
        for c in candidates:
            print(f"  candidate: {c}", flush=True)
    print(f"summary -> {path}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
