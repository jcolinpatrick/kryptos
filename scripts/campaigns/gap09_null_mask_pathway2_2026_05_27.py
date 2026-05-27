#!/usr/bin/env python3
"""GAP-09 pathway-2: score-independent null-mask construction + supportive tests.

Preregistration: docs/campaigns/gap09_null_mask_pathway2_2026_05_27.md

Derives masks from FROZEN score-independent rules (R1-R5; R6 data-blocked) using
ZERO K4-score input, then runs the two RUNNABLE supportive tests:
  T1 width-21 repeated-vertical-bigram REDUCTION vs an MC null (the stego-artifact
     signature: a true null mask should erase the width-21 anomaly it created).
  T3 the validated masking solver via the known-answer gate (does any score-free
     mask yield a crib-consistent decryption above the n-gram noise floor).

T2 (anomaly co-location, the CLOSURE bar) is NOT runnable: no K4-relative
independent observable positions exist (YAR is K3-internal; ?-marks / line breaks
unmeasured). So this run CANNOT close GAP-09; it characterizes the masks only.
Nothing promotable without operator sign-off.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import statistics
import sys
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.alphabet import AZ, KA  # noqa: E402
from kryptos.kernel.constants import CRIB_DICT, CRIB_POSITIONS, CT  # noqa: E402
from kryptos.kernel.masking.mask import extract_ct, remap_crib_dict  # noqa: E402
from kryptos.kernel.scoring.ngram import get_default_scorer  # noqa: E402
from kryptos.admissibility.mask_campaign_gate import (  # noqa: E402
    ReadinessFact, run_guarded_mask_search,
)
from kryptos.admissibility.mask_hypothesis import MaskHypothesis, MaskUniverse  # noqa: E402

VOWELS = set("AEIOU")
VOWELS_Y = set("AEIOUY")
MC_TRIALS = 20000
SEED = 20260527
W21 = 21

# Known-answer gate: GREEN as re-verified 2026-05-27 (self_test 3/3, doctor PASS).
READINESS = ReadinessFact(
    readiness_gate="GREEN", block_k4_campaign=False,
    doctor_passed=True, summary_line="solved: 3/3 (2026-05-27)",
)


# ---------- FROZEN score-independent rules (zero K4-score input) ----------
def rule_masks():
    """Yield (rule_id, params_str, frozenset(mask)) for R1-R5."""
    n = len(CT)
    # R1 doubled-letter members
    dbl = set()
    for i in range(n):
        if (i > 0 and CT[i] == CT[i - 1]) or (i < n - 1 and CT[i] == CT[i + 1]):
            dbl.add(i)
    first = {i for i in dbl if i == 0 or CT[i] != CT[i - 1]}
    second = {i for i in dbl if i > 0 and CT[i] == CT[i - 1]}
    yield ("R1", "mode=both", frozenset(dbl))
    yield ("R1", "mode=first", frozenset(first))
    yield ("R1", "mode=second", frozenset(second))
    # R2 Polybius coordinate band
    for gname, G in (("KA", KA), ("AZ", AZ)):
        idx = G.index_table
        for coord in ("row", "col"):
            for r in range(5):
                m = set()
                for i, ch in enumerate(CT):
                    rank = idx[ord(ch) - 65]
                    band = (rank // 5) if coord == "row" else (rank % 5)
                    if band == r:
                        m.add(i)
                yield ("R2", f"grid={gname},coord={coord},r={r}", frozenset(m))
    # R3 grid row-take (W in {7,14}; W=21 forbidden)
    for W in (7, 14):
        nrows = (n + W - 1) // W
        for R in range(nrows):
            m = {i for i in range(n) if i // W == R}
            yield ("R3", f"W={W},R={R}", frozenset(m))
    # R4 every-k-th
    for k in range(3, 9):
        for o in (0, 1, 2):
            m = {i for i in range(n) if (i - o) % k == 0 and i - o >= 0}
            yield ("R4", f"k={k},o={o}", frozenset(m))
    # R5 vowel-class
    yield ("R5", "V=AEIOU", frozenset(i for i, ch in enumerate(CT) if ch in VOWELS))
    yield ("R5", "V=AEIOUY", frozenset(i for i, ch in enumerate(CT) if ch in VOWELS_Y))


# ---------- T1 width-21 repeated-vertical-bigram metric ----------
def w21_repeat_count(text, width=W21):
    """Count vertical bigrams (column-adjacent pairs) that occur >= 2 times."""
    counts = {}
    rows = (len(text) + width - 1) // width
    for c in range(width):
        col = [text[r * width + c] for r in range(rows) if r * width + c < len(text)]
        for a, b in zip(col, col[1:]):
            counts[a + b] = counts.get(a + b, 0) + 1
    return sum(1 for v in counts.values() if v >= 2)


def w21_mc(text, trials, rng):
    chars = list(text)
    obs = w21_repeat_count(text)
    samples = []
    for _ in range(trials):
        rng.shuffle(chars)
        samples.append(w21_repeat_count("".join(chars)))
    mean = statistics.fmean(samples)
    sd = statistics.pstdev(samples) or 1e-9
    p = sum(1 for s in samples if s >= obs) / trials
    return {"obs": obs, "mc_mean": round(mean, 3), "mc_sd": round(sd, 3),
            "z": round((obs - mean) / sd, 3), "p_ge": p}


def main():
    t0 = datetime.now(timezone.utc)
    rng = random.Random(SEED)
    scorer = get_default_scorer()

    rules = list(rule_masks())
    rule_hash = hashlib.sha256(
        "|".join(f"{rid}:{p}:{','.join(map(str, sorted(m)))}" for rid, p, m in rules)
        .encode()
    ).hexdigest()

    # Baseline width-21 on raw CT97 (sanity: should be highly significant).
    baseline = w21_mc(CT, MC_TRIALS, random.Random(SEED + 1))

    admissible, rejected = [], []
    for rid, params, mask in rules:
        if mask & CRIB_POSITIONS:
            rejected.append({"rule": rid, "params": params, "mask_size": len(mask),
                             "reason": "intersects crib positions"})
            continue
        if not mask or len(mask) >= len(CT) - len(CRIB_POSITIONS):
            rejected.append({"rule": rid, "params": params, "mask_size": len(mask),
                             "reason": "empty or over-large mask"})
            continue
        admissible.append((rid, params, frozenset(mask)))

    # ---- T1 width-21 reduction per admissible mask ----
    t1_rows = []
    for rid, params, mask in admissible:
        ctp = extract_ct(CT, mask)
        res = w21_mc(ctp, MC_TRIALS, random.Random(SEED + 2 + len(t1_rows)))
        t1_rows.append({"rule": rid, "params": params, "mask_size": len(mask),
                        "ctprime_len": len(ctp), **res,
                        "z_drop_from_baseline": round(baseline["z"] - res["z"], 3)})

    # ---- T3 solver via the known-answer gate (one universe of all masks) ----
    universe = MaskUniverse(
        masks=tuple(m for _, _, m in admissible),
        description="GAP-09 pathway-2 score-independent masks R1-R5",
    )
    hyp = MaskHypothesis(
        mask_universe=universe, alignment_model="arbitrary_null_mask",
        provenance="docs/campaigns/gap09_null_mask_pathway2_2026_05_27.md",
        assumption_bundle=("cribs_not_null", "zero_score_derivation"),
        tier="secondary_exploratory",
        stop_rule="finite frozen rule set, fully enumerated",
    )
    candidates = run_guarded_mask_search(
        CT, hyp, readiness=READINESS, crib_dict=CRIB_DICT,
        periods=range(1, 13), alphabet=AZ, ngram_scorer=scorer,
        max_free_exhaustive=3,
    )
    # Best candidate per mask, and global best.
    best_by_mask = {}
    for c in candidates:
        key = tuple(sorted(c.mask))
        if key not in best_by_mask or (c.ngram_score or -1e9) > (best_by_mask[key].ngram_score or -1e9):
            best_by_mask[key] = c
    global_best = max(candidates, key=lambda c: (c.ngram_score or -1e9), default=None)
    # NOTE: T3=0 means no (mask,variant,period) produced a crib-consistent,
    # Bean-valid forced key at all (the residue-consistency/Bean prune) -- the
    # n-gram floor (select_solves) is downstream and was never reached.

    report = {
        "campaign": "gap09_null_mask_pathway2",
        "date": t0.isoformat(),
        "posture": "SYNTHETIC-FREE real-K4 masks; cannot CLOSE GAP-09 (T2 unrunnable); not promotable",
        "prereg": "docs/campaigns/gap09_null_mask_pathway2_2026_05_27.md",
        "rule_set_sha256": rule_hash,
        "n_rule_instances": len(rules),
        "n_admissible": len(admissible),
        "n_rejected": len(rejected),
        "rejected_summary": rejected[:20],
        "T2_status": "NOT_RUNNABLE: no K4-relative independent observable positions (YAR=K3-internal; ?-marks/line-breaks unmeasured). GAP-09 cannot close from current evidence.",
        "T1_baseline_ct97": baseline,
        "T1_results": sorted(t1_rows, key=lambda r: r["z"]),
        "T3_n_candidates": len(candidates),
        "T3_global_best": None if global_best is None else {
            "mask_size": len(global_best.mask), "variant": global_best.variant.value,
            "period": global_best.period, "crib_score": global_best.crib_score,
            "ngram_score": round(global_best.ngram_score, 3) if global_best.ngram_score is not None else None,
            "plaintext": global_best.plaintext,
        },
        "wall_seconds": (datetime.now(timezone.utc) - t0).total_seconds(),
    }
    outdir = os.path.join(_ROOT, "results", "gap09_null_mask_pathway2")
    os.makedirs(outdir, exist_ok=True)
    stamp = t0.strftime("%Y%m%d_%H%M%S")
    outpath = os.path.join(outdir, f"gap09_pathway2_{stamp}.json")
    with open(outpath, "w") as f:
        json.dump(report, f, indent=2)

    print(f"rule instances={len(rules)} admissible={len(admissible)} rejected={len(rejected)}")
    print(f"T1 baseline CT97: obs={baseline['obs']} z={baseline['z']} p={baseline['p_ge']}")
    print("T1 lowest-z (most reduced) masks:")
    for r in report["T1_results"][:5]:
        print(f"  {r['rule']} {r['params']}: |M|={r['mask_size']} obs={r['obs']} z={r['z']} (drop {r['z_drop_from_baseline']})")
    print(f"T3 candidates={len(candidates)} global_best_ngram="
          f"{report['T3_global_best']['ngram_score'] if report['T3_global_best'] else None}")
    print(f"\nartifact: {outpath}")


if __name__ == "__main__":
    main()
