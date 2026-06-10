#!/usr/bin/env python3
"""Campaign: route-outer x Quagmire-III-inner under post_transposition.

ID:        f_route_outer_quagmire_iii_posttrans_2026_06_09
Family:    campaigns / tableau (Quagmire III) x non-direct alignment
Status:    active (single bounded frontier cell)
Pre-reg:   docs/campaigns/route_outer_quagmire_iii_posttrans_2026_06_09.md
Alignment: post_transposition (anchored after route undo; Bean N/A,
           non-additive inner)

The RANK-4 UNKNOWN cell from results/k4_next_goal/FINAL.md section 6.1:
the canonical 52-route byte-identical reordering universe (hash-locked) as
a grille hole_mask axis (decrypt step = gather(perm), verbatim perms) x
Quagmire III inner swept on the tableau_keyword axis (cf9dee1) x the 27
precedented period keywords x indicators {K, A, R}. 25,272 configs, one
spec, dispatched through the real kryptosbot.job_dispatcher.execute().

Structure (all thresholds frozen in the pre-reg BEFORE this ran):
  G0   drift gate -- archived spec_h3 verbatim; best crib == 4, tested 24.
  G1   dual-encoding gate -- route_boustrophedon vs grille encodings of the
       involutive serpentine corner must agree exactly (60 cfg each).
  MAIN the new cell -- 25,272 configs, one spec.
  Null M=200 matched keyword-population replicates through the IDENTICAL
       execute() path (max-of-universe vs max-of-universe).
  Kill CLEAN_NULL iff zero configs reach kernel-verified crib_score >= 18.

Replay:
  PYTHONPATH=src python3 -u scripts/campaigns/f_route_outer_quagmire_iii_posttrans_2026_06_09.py \
    --out results/k4_route_qiii_next
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
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

PREREG = "docs/campaigns/route_outer_quagmire_iii_posttrans_2026_06_09.md"
ARCHIVE = "results/workflows/k4_dynamic_solve/20260528T222343Z/dispatched_specs"
SIB = os.path.join(_ROOT, "scripts", "campaigns",
                   "f_non_direct_alignment_tape_inner_2026_05_29.py")

# Frozen universe (pre-reg section 2) -----------------------------------------
TABLEAUS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "LATITUDE", "MAGNETIC",
            "COMPASS"]
H12_PERIODS = ["CIA", "WEST", "EAST", "NORTH", "SOUTH", "TIME", "CLOCK",
               "LIGHT", "NSA", "RED", "ZONE", "GRID", "CODE", "KEY", "ROW",
               "ARC", "SUN", "DIAL", "TICK", "HOUR", "WIND", "POLE"]
H3_PERIODS = ["PALIMPSEST", "ABSCISSA", "KRYPTOS", "CLOCK", "BERLIN",
              "NORTHEAST"]
PERIODS = H12_PERIODS + [p for p in H3_PERIODS if p not in H12_PERIODS]  # 27
INDICATORS = ["K", "A", "R"]
NEW_TABLEAUS_B1 = ["PALIMPSEST", "ABSCISSA", "LATITUDE", "MAGNETIC", "COMPASS"]

EXPECTED_ROUTES = 52
EXPECTED_REORDERING_HASH = (
    "7a9ac67336cd37e2f7be75c59d549b75618395c47a4bcd515d652232996ae6aa"
)
EXPECTED_TOTAL = 52 * 6 * 27 * 3  # 25,272

M_NULL = 200
SEED_BASE = 20260610000
CRIB_SIGNAL = 18

OVERRIDE_JUSTIFICATION = (
    "RANK-4 UNKNOWN cell (results/k4_next_goal/FINAL.md section 6.1). "
    "Coverage audit results/k4_route_qiii_next/COVERAGE_AUDIT.md: the "
    "dispatcher ledger has ZERO multi-layer quagmire specs; adjacent "
    "closures (TABP, 52-route additive/key_tape inners, qtab B0/B1 "
    "boustrophedon corner) cover different mechanisms or an 84-config "
    "involution overlap exploited as gate G1."
)


def _git_head() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=_ROOT,
                              capture_output=True, text=True).stdout.strip()
    except Exception:
        return "unknown"


def _self_sha256() -> str:
    return hashlib.sha256(open(os.path.abspath(__file__), "rb").read()).hexdigest()[:16]


def _load_sib():
    spec = importlib.util.spec_from_file_location("roq_sib", SIB)
    sib = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sib)
    return sib


def load_routes() -> list[tuple[str, list[int]]]:
    """Canonical 52-route universe, hash-locked (fail-closed)."""
    sib = _load_sib()
    routes = [(name, list(perm)) for name, perm in sib.build_reordering_universe()]
    if len(routes) != EXPECTED_ROUTES:
        raise SystemExit(f"route universe drift: {len(routes)} != {EXPECTED_ROUTES}")
    got = sib.reordering_hash([(n, p) for n, p in routes])
    if got != EXPECTED_REORDERING_HASH:
        raise SystemExit(f"reordering_hash drift: {got} != {EXPECTED_REORDERING_HASH}")
    return routes


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


def _quagmire_layer(tableaus: list[str], periods: list[str],
                    indicators: list[str]) -> CipherLayer:
    return CipherLayer(kind="quagmire", alphabet="AZ", params=[
        ParamRange(name="variant", values=["quagmire_iii"]),
        ParamRange(name="tableau_keyword", values=list(tableaus)),
        ParamRange(name="period_keyword", values=list(periods)),
        ParamRange(name="indicator", values=list(indicators)),
    ])


def build_main_spec(routes: list[tuple[str, list[int]]], tableaus: list[str],
                    periods: list[str], hid: str) -> HypothesisSpec:
    return HypothesisSpec(
        hypothesis_id=hid,
        pipeline=[
            CipherLayer(kind="grille", alphabet="AZ", params=[
                ParamRange(name="hole_mask",
                           values=[perm for _, perm in routes]),
            ]),
            _quagmire_layer(tableaus, periods, INDICATORS),
        ],
        crib_alignment="post_transposition",
        scoring="composite",
        null_baseline=NullBaselineSpec(method="shuffled_ct", n_samples=1000),
        compute_budget_cpu_minutes=10,
        assumption_bundle=["transposed", "az_a0", "no_null_mask",
                           "non_direct_alignment",
                           "outer_byte_reordering_then_quagmire_iii",
                           "bean_inapplicable_nonadditive_inner",
                           "reordering_universe_7a9ac67336cd37e2"],
        override_exhaustion=True,
        override_justification=OVERRIDE_JUSTIFICATION,
    )


def build_g0() -> HypothesisSpec:
    raw = json.load(open(os.path.join(_ROOT, ARCHIVE, "spec_h3.json")))
    raw["hypothesis_id"] = "roq_G0_replication_h3"
    raw["override_exhaustion"] = True
    raw["override_justification"] = OVERRIDE_JUSTIFICATION
    parsed = validate_hypothesis_spec(raw)
    assert parsed.is_valid, parsed.errors
    return parsed.value


def build_g1a() -> HypothesisSpec:
    return HypothesisSpec(
        hypothesis_id="roq_G1a_boustrophedon_encoding",
        pipeline=[
            CipherLayer(kind="route_boustrophedon", alphabet="AZ", params=[
                ParamRange(name="width", values=[7, 14]),
                ParamRange(name="vertical", values=[False]),
            ]),
            _quagmire_layer(NEW_TABLEAUS_B1, H3_PERIODS, ["K"]),
        ],
        crib_alignment="post_transposition",
        scoring="composite",
        null_baseline=NullBaselineSpec(method="shuffled_ct", n_samples=1000),
        compute_budget_cpu_minutes=10,
        assumption_bundle=["transposed", "az_a0", "no_null_mask",
                           "non_direct_alignment"],
        override_exhaustion=True,
        override_justification=OVERRIDE_JUSTIFICATION,
    )


def build_g1b(routes: list[tuple[str, list[int]]]) -> HypothesisSpec:
    serp = {name: perm for name, perm in routes
            if name in ("grid7_serpRow", "grid14_serpRow")}
    assert len(serp) == 2, sorted(serp)
    return HypothesisSpec(
        hypothesis_id="roq_G1b_grille_encoding",
        pipeline=[
            CipherLayer(kind="grille", alphabet="AZ", params=[
                ParamRange(name="hole_mask",
                           values=[serp["grid7_serpRow"],
                                   serp["grid14_serpRow"]]),
            ]),
            _quagmire_layer(NEW_TABLEAUS_B1, H3_PERIODS, ["K"]),
        ],
        crib_alignment="post_transposition",
        scoring="composite",
        null_baseline=NullBaselineSpec(method="shuffled_ct", n_samples=1000),
        compute_budget_cpu_minutes=10,
        assumption_bundle=["transposed", "az_a0", "no_null_mask",
                           "non_direct_alignment"],
        override_exhaustion=True,
        override_justification=OVERRIDE_JUSTIFICATION,
    )


# --- Matched keyword-population null -----------------------------------------

REAL_KEYWORDS = set(TABLEAUS + PERIODS)
TABLEAU_LENS = [len(w) for w in TABLEAUS]   # [7, 10, 8, 8, 8, 7]
PERIOD_LENS = [len(w) for w in PERIODS]     # 27 lens


def load_word_pools() -> dict[int, list[str]]:
    need = set(TABLEAU_LENS + PERIOD_LENS)
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
    return {n: sorted(set(ws)) for n, ws in pools.items()}


def sample_keywords(rng: random.Random, pools: dict[int, list[str]],
                    lens: list[int]) -> list[str]:
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


def run_null(real_best: float, routes, pools, out_null: Path,
             m_null: int) -> dict:
    maxima: list[float] = []
    t0 = time.time()
    for r in range(m_null):
        rng = random.Random(SEED_BASE + r)
        tabs = sample_keywords(rng, pools, TABLEAU_LENS)
        periods = sample_keywords(rng, pools, PERIOD_LENS)
        spec = build_main_spec(routes, tabs, periods, f"roq_null_r{r:03d}")
        spec.null_baseline = None  # campaign-level null IS this loop
        res = execute(spec, artifact_root=out_null)
        if res.admissibility_verdict == "rejected":
            raise SystemExit(f"null replicate r={r} rejected: "
                             f"{res.admissibility_reasons}")
        if res.total_tested != EXPECTED_TOTAL:
            raise SystemExit(f"null replicate r={r} tested {res.total_tested} "
                             f"!= {EXPECTED_TOTAL}")
        maxima.append(float(res.best_score))
        if (r + 1) % 10 == 0:
            print(f"  [null] {r + 1}/{m_null} (last max={res.best_score:.0f}, "
                  f"{time.time() - t0:.0f}s elapsed)", flush=True)
    ge = sum(1 for m in maxima if m >= real_best)
    return {
        "m_null": m_null,
        "seed_base": SEED_BASE,
        "real_best": real_best,
        "null_max_distribution": maxima,
        "null_min": min(maxima), "null_max": max(maxima),
        "null_mean": sum(maxima) / len(maxima),
        "null_beats_real": ge / len(maxima),
        "empirical_tail": (1 + ge) / (len(maxima) + 1),
    }


def forced_crib_control() -> dict:
    from kryptos.kernel.scoring.ngram import get_default_scorer
    rng = random.Random(SEED_BASE)
    pt = [rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(CT_LEN)]
    for pos, ch in CRIB_DICT.items():
        pt[pos] = ch
    breakdown = score_candidate("".join(pt))
    return {
        "crib_score": int(breakdown.crib_score),
        "ngram_per_char": float(get_default_scorer().score_per_char("".join(pt))),
        "note": "cribs pasted into seeded random PT; crib==24 at gibberish "
                "ngram -- crib alone is not a solve (AUDIT-3)",
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="results/k4_route_qiii_next")
    ap.add_argument("--smoke", action="store_true",
                    help="plumbing check: M=2 nulls; summary marked SMOKE, "
                         "never citable")
    args = ap.parse_args(argv)
    m_null = 2 if args.smoke else M_NULL

    out = Path(_ROOT) / args.out
    out_jobs = out / "jobs"
    out_null = out / "null_jobs"
    out.mkdir(parents=True, exist_ok=True)

    routes = load_routes()
    summary: dict = {
        "campaign_id": "f_route_outer_quagmire_iii_posttrans_2026_06_09",
        "prereg": PREREG,
        "coverage_audit": "results/k4_route_qiii_next/COVERAGE_AUDIT.md",
        "git_head": _git_head(),
        "runner_sha256_16": _self_sha256(),
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "smoke": bool(args.smoke),
        "m_null": m_null,
        "n_routes": len(routes),
        "reordering_hash": EXPECTED_REORDERING_HASH,
        "expected_total": EXPECTED_TOTAL,
    }

    # -- G0 drift gate ----------------------------------------------------
    print("[1/5] G0 drift gate (spec_h3 verbatim) ...", flush=True)
    g0 = execute(build_g0(), artifact_root=out_jobs)
    summary["G0"] = _result_brief(g0)
    g0_ok = summary["G0"]["best_crib"] == 4 and g0.total_tested == 24
    summary["gates"] = {"G0_best_crib_eq_4": summary["G0"]["best_crib"] == 4,
                        "G0_tested_eq_24": g0.total_tested == 24}
    if not g0_ok:
        summary["verdict"] = "REPLICATION_FAILURE"
        (out / "route_qiii_summary.json").write_text(json.dumps(summary, indent=2))
        print(f"REPLICATION_FAILURE: {summary['gates']}", flush=True)
        return 3

    # -- G1 dual-encoding gate ---------------------------------------------
    print("[2/5] G1 dual-encoding gate (boustrophedon vs grille) ...", flush=True)
    g1a = execute(build_g1a(), artifact_root=out_jobs)
    g1b = execute(build_g1b(routes), artifact_root=out_jobs)
    summary["G1a"] = _result_brief(g1a)
    summary["G1b"] = _result_brief(g1b)
    g1_checks = {
        "G1_tested_60_each": g1a.total_tested == 60 and g1b.total_tested == 60,
        "G1_best_score_equal": float(g1a.best_score) == float(g1b.best_score),
        "G1_best_crib_equal":
            summary["G1a"]["best_crib"] == summary["G1b"]["best_crib"],
        "G1_best_pt_equal":
            summary["G1a"]["best_candidate_pt"] == summary["G1b"]["best_candidate_pt"],
    }
    summary["gates"].update(g1_checks)
    if not all(g1_checks.values()):
        summary["verdict"] = "ENCODING_MISMATCH"
        (out / "route_qiii_summary.json").write_text(json.dumps(summary, indent=2))
        print(f"ENCODING_MISMATCH: {g1_checks}", flush=True)
        return 3
    print(f"  gates PASS: G0 best={summary['G0']['best_crib']}, "
          f"G1 identical best (crib={summary['G1a']['best_crib']})", flush=True)

    # -- Main cell ----------------------------------------------------------
    print(f"[3/5] main cell ({EXPECTED_TOTAL} configs, one spec) ...", flush=True)
    main_res = execute(build_main_spec(routes, TABLEAUS, PERIODS, "roq_main"),
                       artifact_root=out_jobs)
    summary["MAIN"] = _result_brief(main_res)
    if main_res.admissibility_verdict == "rejected":
        raise SystemExit(f"MAIN rejected: {main_res.admissibility_reasons}")
    if main_res.total_tested != EXPECTED_TOTAL:
        raise SystemExit(f"MAIN tested {main_res.total_tested} != "
                         f"{EXPECTED_TOTAL} (universe not fully enumerated)")
    print(f"  MAIN best crib={summary['MAIN']['best_crib']}/24 "
          f"ngram/char={summary['MAIN']['best_ngram_per_char']}", flush=True)

    # -- Forced-crib control -------------------------------------------------
    print("[4/5] forced-crib control ...", flush=True)
    summary["forced_crib_control"] = forced_crib_control()

    # -- Matched null ---------------------------------------------------------
    print(f"[5/5] matched null (M={m_null}) ...", flush=True)
    pools = load_word_pools()
    summary["null_pool_sizes"] = {str(k): len(v) for k, v in sorted(pools.items())}
    summary["null"] = run_null(float(main_res.best_score), routes, pools,
                               out_null, m_null)

    # -- Verdict (frozen rule: pre-reg section 5) -----------------------------
    if args.smoke:
        summary["verdict"] = "SMOKE_ONLY_NOT_CITABLE"
    elif summary["MAIN"]["best_crib"] >= CRIB_SIGNAL:
        summary["verdict"] = "ESCALATE"
    else:
        summary["verdict"] = "CLEAN_NULL"
    summary["kill_rule"] = (
        f"CLEAN_NULL iff zero configs reach kernel-verified crib_score >= "
        f"{CRIB_SIGNAL}; Bean inapplicable-by-construction (non-additive inner)")
    summary["scope_eliminated"] = (
        "Quagmire III inner (tableau in {KRYPTOS, PALIMPSEST, ABSCISSA, "
        "LATITUDE, MAGNETIC, COMPASS}; period in the 27-keyword h12-union-h3 "
        "set; indicator in {K, A, R}) behind each of the canonical 52 "
        "byte-identical reorderings (hash 7a9ac67336cd37e2...) under "
        "post_transposition, AZ. Scoped to recorded spec/universe hashes."
    )
    summary["scope_not_eliminated"] = (
        "routes outside the canonical 52; other tableau/period/indicator "
        "values; quagmire_iv; KA-layer variants; free alignment; masked "
        "models; reorderings not byte-identical to this universe."
    )
    summary["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    summary["replay"] = ("PYTHONPATH=src python3 -u scripts/campaigns/"
                         "f_route_outer_quagmire_iii_posttrans_2026_06_09.py "
                         f"--out {args.out}")
    (out / "route_qiii_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: summary[k] for k in ("verdict", "gates")}, indent=2))
    print(f"null tail={summary['null']['empirical_tail']:.4f} "
          f"null_beats_real={summary['null']['null_beats_real']:.3f}",
          flush=True)
    print(f"summary -> {out / 'route_qiii_summary.json'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
