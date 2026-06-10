#!/usr/bin/env python3
"""Campaign: Quagmire III tableau-axis completion (C1/C5 coverage debt).

ID:        f_quagmire_tableau_axis_completion_2026_06_09
Family:    campaigns / tableau (Quagmire III)
Status:    active (single bounded frontier cell)
Pre-reg:   docs/campaigns/quagmire_tableau_axis_completion_2026_06_09.md
Alignment: A-arms direct_positional; B-arms post_transposition

Pays the documented coverage debt from the 2026-05-28 k4-dynamic-solve run
(final_report.md:151: "The KRYPTOS-tableau pinning in C1 and C5 is a DSL
limitation ... NOT a tested negative"): the 5 never-tested Quagmire III
tableau keywords {PALIMPSEST, ABSCISSA, LATITUDE, MAGNETIC, COMPASS} on the
h12 (decoupled-period, direct) and h3 (boustrophedon-outer, post-transposition)
cluster shapes, enabled by the 2026-06-09 `tableau_keyword` dispatcher fix
(kryptosbot/tests/test_quagmire_tableau_sweep.py).

Structure (all thresholds frozen in the pre-reg BEFORE this ran):
  A0/B0  replication controls — re-dispatch the archived 2026-05-28 spec
         shapes; gates: A0 best crib == 5 (66 cfg), B0 best crib == 4 (24 cfg).
         Gate failure => REPLICATION_FAILURE, exit 3, no cell verdict.
  A1/B1  the new cell — 330 + 120 = 450 configs, one spec each via the real
         dispatcher (kryptosbot.job_dispatcher.execute).
  Null   M=200 matched keyword-population replicates per arm through the
         IDENTICAL execute() path (max-of-universe vs max-of-universe).
  Kill   CLEAN_NULL iff zero configs reach kernel-verified crib_score >= 18
         (Bean inapplicable-by-construction: non-additive inner).

Replay:
  PYTHONPATH=src python3 -u scripts/campaigns/f_quagmire_tableau_axis_completion_2026_06_09.py \
    --out results/k4_next_goal
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import random
import re
import subprocess
import sys
import time

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from pathlib import Path

from kryptos.kernel.constants import CRIB_DICT, CT_LEN
from kryptos.kernel.scoring.aggregate import score_candidate

from kryptosbot.hypothesis_dsl import (
    CipherLayer, HypothesisSpec, NullBaselineSpec, ParamRange,
    validate_hypothesis_spec,
)
from kryptosbot.job_dispatcher import execute

PREREG = "docs/campaigns/quagmire_tableau_axis_completion_2026_06_09.md"
ARCHIVE = "results/workflows/k4_dynamic_solve/20260528T222343Z/dispatched_specs"

NEW_TABLEAUS = ["PALIMPSEST", "ABSCISSA", "LATITUDE", "MAGNETIC", "COMPASS"]
H12_PERIODS = ["CIA", "WEST", "EAST", "NORTH", "SOUTH", "TIME", "CLOCK",
               "LIGHT", "NSA", "RED", "ZONE", "GRID", "CODE", "KEY", "ROW",
               "ARC", "SUN", "DIAL", "TICK", "HOUR", "WIND", "POLE"]
H3_PERIODS = ["PALIMPSEST", "ABSCISSA", "KRYPTOS", "CLOCK", "BERLIN", "NORTHEAST"]
INDICATORS_A = ["K", "A", "R"]

M_NULL = 200
SEED_BASE = 20260609000
CRIB_SIGNAL = 18
NGRAM_FLOOR = -4.5

OVERRIDE_JUSTIFICATION = (
    "Tableau axis documented as un-tested by the 2026-05-28 run "
    "(final_report.md:151 DERIVED FACT: KRYPTOS pinning was a DSL "
    "limitation, NOT a tested negative); overlap-flagged quagmire entries "
    "cover different mechanisms (cross-alphabet Q2/Q1, Q2 autokey on CT73, "
    "masked cell, w10 Bean-survivor context). See pre-reg section 1."
)


def _git_head() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=_ROOT,
                              capture_output=True, text=True).stdout.strip()
    except Exception:
        return "unknown"


def _self_sha256() -> str:
    return hashlib.sha256(open(os.path.abspath(__file__), "rb").read()).hexdigest()[:16]


def _result_brief(r) -> dict:
    bc = r.best_candidate or {}
    return {
        "admissibility_verdict": r.admissibility_verdict,
        "admissibility_reasons": r.admissibility_reasons,
        "spec_hash": r.spec_hash,
        "universe_hash": r.universe_hash,
        "total_tested": r.total_tested,
        "total_stored": r.total_stored,
        "best_score": r.best_score,
        "best_crib": int(bc.get("crib_score", 0) or 0),
        "best_ngram_per_char": bc.get("ngram_score"),
        "best_bean_passed": bc.get("bean_passed"),
        "best_scoring_mode": bc.get("scoring_mode"),
        "best_config_bindings": r.best_config_bindings,
        "best_candidate_pt": bc.get("candidate_pt"),
        "wall_time_sec": r.wall_time_sec,
        "artifact_path": r.artifact_path,
    }


def _load_archived_spec(name: str) -> dict:
    return json.load(open(os.path.join(_ROOT, ARCHIVE, name)))


def build_a0() -> HypothesisSpec:
    """Replication control A0: spec_h12 shape verbatim, crib_alignment flipped
    to direct_positional (the original declared 'free' was unimplemented at
    run time; the 2026-05-28 verdict was effectively anchored — pre-reg §2)."""
    raw = _load_archived_spec("spec_h12.json")
    raw["hypothesis_id"] = "qtab_A0_replication_h12"
    raw["crib_alignment"] = "direct_positional"
    raw["scoring"] = "composite"
    raw["override_exhaustion"] = True
    raw["override_justification"] = OVERRIDE_JUSTIFICATION
    parsed = validate_hypothesis_spec(raw)
    assert parsed.is_valid, parsed.errors
    return parsed.value


def build_b0() -> HypothesisSpec:
    """Replication control B0: spec_h3 verbatim (already post_transposition,
    override_exhaustion already True; refresh id + justification)."""
    raw = _load_archived_spec("spec_h3.json")
    raw["hypothesis_id"] = "qtab_B0_replication_h3"
    raw["override_exhaustion"] = True
    raw["override_justification"] = OVERRIDE_JUSTIFICATION
    parsed = validate_hypothesis_spec(raw)
    assert parsed.is_valid, parsed.errors
    return parsed.value


def build_a1(tableaus: list[str], periods: list[str], hid: str) -> HypothesisSpec:
    return HypothesisSpec(
        hypothesis_id=hid,
        pipeline=[CipherLayer(kind="quagmire", alphabet="AZ", params=[
            ParamRange(name="tableau_keyword", values=list(tableaus)),
            ParamRange(name="period_keyword", values=list(periods)),
            ParamRange(name="indicator", values=list(INDICATORS_A)),
            ParamRange(name="variant", values=["quagmire_iii"]),
        ])],
        crib_alignment="direct_positional",
        scoring="composite",
        null_baseline=NullBaselineSpec(method="shuffled_ct", n_samples=1000),
        compute_budget_cpu_minutes=10,
        assumption_bundle=["ct97_direct_positional", "az_a0", "no_null_mask",
                           "quagmire_iii_k1k2_convention",
                           "H1_effective_statistic_of_h12"],
        override_exhaustion=True,
        override_justification=OVERRIDE_JUSTIFICATION,
    )


def build_b1(tableaus: list[str], periods: list[str], hid: str) -> HypothesisSpec:
    return HypothesisSpec(
        hypothesis_id=hid,
        pipeline=[
            CipherLayer(kind="route_boustrophedon", alphabet="AZ", params=[
                ParamRange(name="width", values=[7, 14]),
                ParamRange(name="vertical", values=[False, True]),
            ]),
            CipherLayer(kind="quagmire", alphabet="AZ", params=[
                ParamRange(name="variant", values=["quagmire_iii"]),
                ParamRange(name="tableau_keyword", values=list(tableaus)),
                ParamRange(name="indicator", values=["K"]),
                ParamRange(name="period_keyword", values=list(periods)),
            ]),
        ],
        crib_alignment="post_transposition",
        scoring="composite",
        null_baseline=NullBaselineSpec(method="shuffled_ct", n_samples=1000),
        compute_budget_cpu_minutes=10,
        assumption_bundle=["transposed", "az_a0", "no_null_mask",
                           "non_direct_alignment",
                           "outer_route_then_quagmire_iii",
                           "bean_inapplicable_nonadditive_inner"],
        override_exhaustion=True,
        override_justification=OVERRIDE_JUSTIFICATION,
    )


# ─── Matched keyword-population null ─────────────────────────────────────────

REAL_KEYWORDS = set(NEW_TABLEAUS + H12_PERIODS + H3_PERIODS + ["KRYPTOS"])
TABLEAU_LENS = [len(w) for w in NEW_TABLEAUS]            # [10, 8, 8, 8, 7]
A1_PERIOD_LENS = [len(w) for w in H12_PERIODS]
B1_PERIOD_LENS = [len(w) for w in H3_PERIODS]            # [10, 8, 7, 5, 6, 9]


def load_word_pools() -> dict[int, list[str]]:
    need = set(TABLEAU_LENS + A1_PERIOD_LENS + B1_PERIOD_LENS)
    pools: dict[int, list[str]] = {n: [] for n in need}
    with open(os.path.join(_ROOT, "wordlists", "english.txt"), encoding="utf-8",
              errors="ignore") as fh:
        for line in fh:
            w = line.strip().upper()
            if not re.fullmatch(r"[A-Z]+", w):
                continue
            n = len(w)
            if n in pools and w not in REAL_KEYWORDS:
                pools[n].append(w)
    # Deterministic order regardless of wordlist duplicates.
    return {n: sorted(set(ws)) for n, ws in pools.items()}


def sample_keywords(rng: random.Random, pools: dict[int, list[str]],
                    lens: list[str]) -> list[str]:
    """Sample one distinct word per requested length (multiset), order-stable."""
    chosen: list[str] = []
    taken: set[str] = set()
    for n in lens:
        while True:
            w = rng.choice(pools[n])
            if w not in taken:
                taken.add(w)
                chosen.append(w)
                break
    return chosen


def run_null_arm(arm: str, real_best: float, pools: dict[int, list[str]],
                 out_null: Path, m_null: int) -> dict:
    arm_index = 0 if arm == "A1" else 1
    maxima: list[float] = []
    t0 = time.time()
    for r in range(m_null):
        rng = random.Random(SEED_BASE + 100000 * arm_index + r)
        tabs = sample_keywords(rng, pools, TABLEAU_LENS)
        if arm == "A1":
            periods = sample_keywords(rng, pools, A1_PERIOD_LENS)
            spec = build_a1(tabs, periods, f"qtab_null_A1_r{r:03d}")
        else:
            periods = sample_keywords(rng, pools, B1_PERIOD_LENS)
            spec = build_b1(tabs, periods, f"qtab_null_B1_r{r:03d}")
        spec.null_baseline = None  # campaign-level null IS this loop
        res = execute(spec, artifact_root=out_null)
        if res.admissibility_verdict == "rejected":
            raise SystemExit(f"null replicate {arm} r={r} rejected: "
                             f"{res.admissibility_reasons}")
        maxima.append(float(res.best_score))
        if (r + 1) % 10 == 0:
            print(f"  [{arm} null] {r + 1}/{m_null} "
                  f"(last max={res.best_score:.0f}, "
                  f"{time.time() - t0:.0f}s elapsed)", flush=True)
    ge = sum(1 for m in maxima if m >= real_best)
    return {
        "arm": arm,
        "m_null": m_null,
        "seed_base": SEED_BASE + 100000 * arm_index,
        "real_best": real_best,
        "null_max_distribution": maxima,
        "null_min": min(maxima), "null_max": max(maxima),
        "null_mean": sum(maxima) / len(maxima),
        "null_beats_real": ge / len(maxima),
        "empirical_tail": (1 + ge) / (len(maxima) + 1),
    }


def forced_crib_control() -> dict:
    """AUDIT-3 concretization: cribs pasted into random PT => crib 24/24 at
    the gibberish ngram floor. Crib score alone is not a solve."""
    from kryptos.kernel.scoring.ngram import get_default_scorer
    rng = random.Random(SEED_BASE)
    pt = [rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(CT_LEN)]
    for pos, ch in CRIB_DICT.items():
        pt[pos] = ch
    breakdown = score_candidate("".join(pt))
    return {
        "crib_score": int(breakdown.crib_score),
        # Same per-char statistic the dispatcher records on candidates.
        "ngram_per_char": float(get_default_scorer().score_per_char("".join(pt))),
        "note": "cribs pasted into seeded random PT; demonstrates crib==24 "
                "with gibberish ngram — crib alone is not a solve (AUDIT-3)",
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="results/k4_next_goal")
    ap.add_argument("--smoke", action="store_true",
                    help="plumbing check: M=2 nulls; summary marked SMOKE, "
                         "never citable")
    args = ap.parse_args(argv)
    m_null = 2 if args.smoke else M_NULL

    out = Path(_ROOT) / args.out
    out_jobs = out / "jobs"
    out_null = out / "null_jobs"
    out.mkdir(parents=True, exist_ok=True)

    summary: dict = {
        "campaign_id": "f_quagmire_tableau_axis_completion_2026_06_09",
        "prereg": PREREG,
        "git_head": _git_head(),
        "runner_sha256_16": _self_sha256(),
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "smoke": bool(args.smoke),
        "m_null": m_null,
    }

    # ── Replication controls ────────────────────────────────────────────
    print("[1/4] replication controls A0/B0 ...", flush=True)
    a0 = execute(build_a0(), artifact_root=out_jobs)
    b0 = execute(build_b0(), artifact_root=out_jobs)
    summary["A0"] = _result_brief(a0)
    summary["B0"] = _result_brief(b0)
    gates = {
        "A0_best_crib_eq_5": summary["A0"]["best_crib"] == 5,
        "A0_tested_eq_66": a0.total_tested == 66,
        "B0_best_crib_eq_4": summary["B0"]["best_crib"] == 4,
        "B0_tested_eq_24": b0.total_tested == 24,
    }
    summary["replication_gates"] = gates
    if not all(gates.values()):
        summary["verdict"] = "REPLICATION_FAILURE"
        (out / "qtab_summary.json").write_text(json.dumps(summary, indent=2))
        print(f"REPLICATION_FAILURE: {gates}", flush=True)
        return 3
    print(f"  gates PASS: A0 best={summary['A0']['best_crib']} "
          f"B0 best={summary['B0']['best_crib']}", flush=True)

    # ── New cell ────────────────────────────────────────────────────────
    print("[2/4] new-cell arms A1/B1 ...", flush=True)
    a1 = execute(build_a1(NEW_TABLEAUS, H12_PERIODS, "qtab_A1_new_tableaus"),
                 artifact_root=out_jobs)
    b1 = execute(build_b1(NEW_TABLEAUS, H3_PERIODS, "qtab_B1_new_tableaus"),
                 artifact_root=out_jobs)
    summary["A1"] = _result_brief(a1)
    summary["B1"] = _result_brief(b1)
    for arm, res, want in (("A1", a1, 330), ("B1", b1, 120)):
        if res.admissibility_verdict == "rejected":
            raise SystemExit(f"{arm} rejected: {res.admissibility_reasons}")
        if res.total_tested != want:
            raise SystemExit(f"{arm} tested {res.total_tested} != {want} "
                             "(universe not fully enumerated)")
    print(f"  A1 best={summary['A1']['best_crib']}/24 "
          f"B1 best={summary['B1']['best_crib']}/24", flush=True)

    # ── Forced-crib control ─────────────────────────────────────────────
    print("[3/4] forced-crib control ...", flush=True)
    summary["forced_crib_control"] = forced_crib_control()

    # ── Matched keyword-population null ─────────────────────────────────
    print(f"[4/4] matched nulls (M={m_null} per arm) ...", flush=True)
    pools = load_word_pools()
    summary["null_pool_sizes"] = {str(k): len(v) for k, v in sorted(pools.items())}
    summary["null_A1"] = run_null_arm("A1", float(a1.best_score), pools,
                                      out_null, m_null)
    summary["null_B1"] = run_null_arm("B1", float(b1.best_score), pools,
                                      out_null, m_null)

    # ── Verdict (frozen rule: pre-reg section 4) ────────────────────────
    any_signal = (summary["A1"]["best_crib"] >= CRIB_SIGNAL
                  or summary["B1"]["best_crib"] >= CRIB_SIGNAL)
    if args.smoke:
        summary["verdict"] = "SMOKE_ONLY_NOT_CITABLE"
    elif any_signal:
        summary["verdict"] = "ESCALATE"
    else:
        summary["verdict"] = "CLEAN_NULL"
    summary["kill_rule"] = (f"CLEAN_NULL iff zero configs reach kernel-verified "
                            f"crib_score >= {CRIB_SIGNAL} in A1 union B1; Bean "
                            "inapplicable-by-construction (non-additive inner)")
    summary["scope_eliminated"] = (
        "Quagmire III, tableau_keyword in {PALIMPSEST, ABSCISSA, LATITUDE, "
        "MAGNETIC, COMPASS}: (A1) direct-positional decoupled-period sweep "
        "{22 periods x 3 indicators}; (B1) boustrophedon-outer {w in {7,14} x "
        "vertical in {f,t}} x {6 periods x indicator K} under "
        "post_transposition. Scoped to recorded universe hashes."
    )
    summary["scope_not_eliminated"] = (
        "free-alignment scoring of these shapes; other tableau keywords; "
        "other period sets; other indicators; other routes/widths; "
        "quagmire_iv; KA-layer variants; masked/null-bearing models; the "
        "broader route-outer x Quagmire-inner matrix."
    )
    summary["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    summary["replay"] = ("PYTHONPATH=src python3 -u "
                         "scripts/campaigns/"
                         "f_quagmire_tableau_axis_completion_2026_06_09.py "
                         f"--out {args.out}")
    (out / "qtab_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: summary[k] for k in
                      ("verdict", "replication_gates")}, indent=2))
    print(f"A1 tail={summary['null_A1']['empirical_tail']:.4f} "
          f"null_beats_real={summary['null_A1']['null_beats_real']:.3f} | "
          f"B1 tail={summary['null_B1']['empirical_tail']:.4f} "
          f"null_beats_real={summary['null_B1']['null_beats_real']:.3f}",
          flush=True)
    print(f"summary -> {out / 'qtab_summary.json'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
