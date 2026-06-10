#!/usr/bin/env python3
"""Campaign: free-alignment classical sweep of the carved K4 CT.

ID:        f_free_alignment_classical_2026_06_10
Family:    campaigns / free alignment (non_direct_alignment, detection-level)
Status:    active (first free-alignment campaign in the repo)
Pre-reg:   docs/campaigns/free_alignment_classical_2026_06_10.md
Alignment: free (cribs matched ANYWHERE; Bean N/A by construction)

Tests whether any single-layer classical decrypt of the carved 97-char
CT contains EASTNORTHEAST and/or BERLINCLOCK at ANY offset. Every
historical single-layer sweep scored anchored and would have discarded
such a decrypt as noise. Free dispatch became real (Lever B1
2026-05-31), boundary-correct (B-1 2026-06-10), and null-calibrated
(G-1 2026-06-10) only now.

Arms (all crib_alignment="free", real dispatcher, kernel-verified):
  A1   additive {vig, beau, varbeau} x {AZ, KA} x thematic keywords
  A2   Quagmire III diagonal: 6 tableaus x 27 period keywords x {K,A,R}
  A3   additive {vig, beau, varbeau} x {AZ, KA} x english.txt len 4-11,
       sharded <=20k configs/spec (exploratory tier)

Controls C1 (kernel free scorer), C2 (worker fn on synthetic CT) run
first; abort on failure. Decision rules frozen in the pre-reg:
DETECT-24 / SIGNAL {11,13} investigate-first / CLEAN_NULL if zero >=11.

Replay:
  PYTHONPATH=src python3 -u scripts/campaigns/f_free_alignment_classical_2026_06_10.py \
      --out results/free_alignment_classical
  (add --arms A1,A2 for the motivated tier only, --max-shards N to limit A3)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from pathlib import Path

from kryptosbot.hypothesis_dsl import (
    CipherLayer, HypothesisSpec, NullBaselineSpec, ParamRange,
)
from kryptosbot.job_dispatcher import execute

PREREG = "docs/campaigns/free_alignment_classical_2026_06_10.md"

ADDITIVE_KINDS = ["vigenere", "beaufort", "variant_beaufort"]
ALPHABETS = ["AZ", "KA"]

TABLEAUS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "LATITUDE", "MAGNETIC",
            "COMPASS"]
H12_PERIODS = ["CIA", "WEST", "EAST", "NORTH", "SOUTH", "TIME", "CLOCK",
               "LIGHT", "NSA", "RED", "ZONE", "GRID", "CODE", "KEY", "ROW",
               "ARC", "SUN", "DIAL", "TICK", "HOUR", "WIND", "POLE"]
H3_PERIODS = ["PALIMPSEST", "ABSCISSA", "KRYPTOS", "CLOCK", "BERLIN",
              "NORTHEAST"]
PERIODS = H12_PERIODS + [p for p in H3_PERIODS if p not in H12_PERIODS]  # 27
INDICATORS = ["K", "A", "R"]

SHARD_SIZE = 10_000  # DSL per-axis cardinality cap is 10,000
SIGNAL_FLOOR = 11   # frozen: any free crib >= 11 is a reportable event
DETECT = 24

OVERRIDE_JUSTIFICATION = (
    "First free-alignment campaign (pre-reg "
    + PREREG +
    "): exhaustion_log.json has ZERO free-alignment entries; all prior "
    "single-layer sweeps scored anchored and the 2026-06-09 closures "
    "explicitly list free alignment as NOT closed. Non-direct spec; "
    "B-3 alignment-scoped overlap applies."
)


def _git_head() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=_ROOT,
                              capture_output=True, text=True).stdout.strip()
    except Exception:
        return "unknown"


def _sha(items: list[str]) -> str:
    return hashlib.sha256("\n".join(items).encode()).hexdigest()


def load_thematic() -> list[str]:
    words: set[str] = set()
    with open(os.path.join(_ROOT, "wordlists", "thematic_keywords.txt")) as f:
        for line in f:
            tok = line.strip().upper()
            if tok and tok.isalpha() and tok.isascii() and 3 <= len(tok) <= 12:
                words.add(tok)
    return sorted(words)


def load_english() -> list[str]:
    words: set[str] = set()
    with open(os.path.join(_ROOT, "wordlists", "english.txt")) as f:
        for line in f:
            tok = line.strip().upper()
            if tok and tok.isalpha() and tok.isascii() and 4 <= len(tok) <= 11:
                words.add(tok)
    return sorted(words)


# ─── Controls ────────────────────────────────────────────────────────────────

def control_c1() -> dict:
    """Kernel free scorer detects displaced cribs."""
    from kryptos.kernel.scoring.aggregate import score_candidate_free
    pt = list("Q" * 97)
    pt[5:18] = "EASTNORTHEAST"
    pt[60:71] = "BERLINCLOCK"
    fb = score_candidate_free("".join(pt))
    ok = int(fb.crib_score) == 24 and not bool(fb.canonical_positions)
    return {"control": "C1", "pass": ok, "crib_score": int(fb.crib_score),
            "canonical_positions": bool(fb.canonical_positions)}


def control_c2() -> dict:
    """The actual pool worker function free-scores a synthetic CT.

    Synthetic CT = vigenere_encrypt(displaced-crib PT, PALIMPSEST, AZ).
    The work item mirrors arm A1's shape (crib_alignment='free'). The
    real cribs are the kernel's; challenge_crib_dict stays None so the
    real-K4 free branch runs.
    """
    from kryptos.kernel.transforms.vigenere import encrypt_text, CipherVariant
    from kryptosbot.job_dispatcher import _evaluate_one

    pt = list("Q" * 97)
    pt[5:18] = "EASTNORTHEAST"
    pt[60:71] = "BERLINCLOCK"
    key = [ord(c) - 65 for c in "PALIMPSEST"]
    synthetic_ct = encrypt_text("".join(pt), key, CipherVariant.VIGENERE)

    work_item = {
        "config_id": "control_c2",
        "pipeline_dict": {
            "name": "control_c2",
            "direction": "decrypt",
            "steps": [{
                "type": "vigenere",
                "params": {"key": key, "direction": "decrypt"},
            }],
        },
        "crib_alignment": "free",
        "challenge_ciphertext": synthetic_ct,
        "challenge_crib_dict": None,
    }
    res = _evaluate_one(work_item)
    ok = (
        res.get("crib_score") == 24
        and res.get("scoring_mode") == "free"
        and not res.get("canonical_positions", True)
        and res.get("error") is None
    )
    return {"control": "C2", "pass": ok,
            "crib_score": res.get("crib_score"),
            "scoring_mode": res.get("scoring_mode"),
            "canonical_positions": res.get("canonical_positions"),
            "error": res.get("error")}


# ─── Spec builders ───────────────────────────────────────────────────────────

def _bundle(alphabet: str) -> list[str]:
    return [
        "az_a0" if alphabet == "AZ" else "ka_a0",
        "transposed",                # position convention: non-direct
        "no_null_mask",
        "non_direct_alignment",
        "crib_alignment_free_detection_level",
        "fixed_len_97_stream",
    ]


def build_additive_spec(hid: str, kind: str, alphabet: str,
                        keywords: list[str]) -> HypothesisSpec:
    return HypothesisSpec(
        hypothesis_id=hid,
        pipeline=[
            CipherLayer(kind=kind, alphabet=alphabet, params=[
                ParamRange(name="keyword", values=list(keywords)),
            ]),
        ],
        crib_alignment="free",
        scoring="composite",
        null_baseline=NullBaselineSpec(method="matched_variant_family",
                                       n_samples=1000),
        compute_budget_cpu_minutes=10,
        assumption_bundle=_bundle(alphabet),
        override_exhaustion=True,
        override_justification=OVERRIDE_JUSTIFICATION,
    )


SIB = os.path.join(_ROOT, "scripts", "campaigns",
                   "f_non_direct_alignment_tape_inner_2026_05_29.py")
EXPECTED_REORDERING_HASH = (
    "7a9ac67336cd37e2f7be75c59d549b75618395c47a4bcd515d652232996ae6aa"
)


def load_routes() -> list[list[int]]:
    """Canonical 52-route universe, hash-locked (fail-closed).

    Uses the sibling's own ``reordering_hash`` (the canonical encoding
    behind 7a9ac673...), not an ad-hoc serialization.
    """
    import importlib.util
    spec = importlib.util.spec_from_file_location("fac_sib", SIB)
    sib = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sib)
    routes = [(name, list(perm)) for name, perm in sib.build_reordering_universe()]
    if len(routes) != 52:
        raise SystemExit(f"route universe drift: {len(routes)} != 52")
    got = sib.reordering_hash([(n, p) for n, p in routes])
    if got != EXPECTED_REORDERING_HASH:
        raise SystemExit(
            f"route universe hash mismatch: {got} != {EXPECTED_REORDERING_HASH}"
        )
    return [perm for _, perm in routes]


def build_a4_spec(hid: str, kind: str, alphabet: str, keywords: list[str],
                  routes: list[list[int]]) -> HypothesisSpec:
    return HypothesisSpec(
        hypothesis_id=hid,
        pipeline=[
            CipherLayer(kind="grille", alphabet="AZ", params=[
                ParamRange(name="hole_mask", values=list(routes)),
            ]),
            CipherLayer(kind=kind, alphabet=alphabet, params=[
                ParamRange(name="keyword", values=list(keywords)),
            ]),
        ],
        crib_alignment="free",
        scoring="composite",
        null_baseline=NullBaselineSpec(method="matched_variant_family",
                                       n_samples=1000),
        compute_budget_cpu_minutes=10,
        assumption_bundle=_bundle(alphabet) + [
            "outer_byte_reordering_then_additive",
            "reordering_universe_7a9ac67336cd37e2",
        ],
        override_exhaustion=True,
        override_justification=OVERRIDE_JUSTIFICATION,
    )


def build_a2_spec() -> HypothesisSpec:
    return HypothesisSpec(
        hypothesis_id="freealign_A2_quagmire3_diagonal",
        pipeline=[
            CipherLayer(kind="quagmire", alphabet="AZ", params=[
                ParamRange(name="variant", values=["quagmire_iii"]),
                ParamRange(name="tableau_keyword", values=list(TABLEAUS)),
                ParamRange(name="period_keyword", values=list(PERIODS)),
                ParamRange(name="indicator", values=list(INDICATORS)),
            ]),
        ],
        crib_alignment="free",
        scoring="composite",
        null_baseline=NullBaselineSpec(method="random_text", n_samples=1000),
        compute_budget_cpu_minutes=10,
        assumption_bundle=_bundle("AZ") + ["quagmire_iii_diagonal_tableau"],
        override_exhaustion=True,
        override_justification=OVERRIDE_JUSTIFICATION,
    )


def build_a5_spec(hid: str, kind: str, alphabet: str, order: str,
                  keywords: list[str]) -> HypothesisSpec:
    """Two-layer columnar x additive, both peel orders (addendum 6c).

    order="trans_first": decrypt undoes the columnar BEFORE the additive
    decrypt (encrypt order: additive then columnar).
    order="sub_first": additive decrypt runs first, then the columnar
    undo (encrypt order: columnar then additive).
    """
    columnar = CipherLayer(kind="columnar", alphabet="AZ", params=[
        ParamRange(name="keyword", values=list(keywords)),
    ])
    additive = CipherLayer(kind=kind, alphabet=alphabet, params=[
        ParamRange(name="keyword", values=list(keywords)),
    ])
    pipeline = ([columnar, additive] if order == "trans_first"
                else [additive, columnar])
    return HypothesisSpec(
        hypothesis_id=hid,
        pipeline=pipeline,
        crib_alignment="free",
        scoring="composite",
        null_baseline=NullBaselineSpec(method="matched_variant_family",
                                       n_samples=1000),
        compute_budget_cpu_minutes=10,
        assumption_bundle=_bundle(alphabet) + [
            f"two_layer_columnar_additive_{order}",
        ],
        override_exhaustion=True,
        override_justification=OVERRIDE_JUSTIFICATION,
    )


def build_a6_spec(routes: list[list[int]]) -> HypothesisSpec:
    """Route x QIII diagonal matrix, free re-lens (addendum 6c)."""
    return HypothesisSpec(
        hypothesis_id="freealign_A6_route_quagmire3",
        pipeline=[
            CipherLayer(kind="grille", alphabet="AZ", params=[
                ParamRange(name="hole_mask", values=list(routes)),
            ]),
            CipherLayer(kind="quagmire", alphabet="AZ", params=[
                ParamRange(name="variant", values=["quagmire_iii"]),
                ParamRange(name="tableau_keyword", values=list(TABLEAUS)),
                ParamRange(name="period_keyword", values=list(PERIODS)),
                ParamRange(name="indicator", values=list(INDICATORS)),
            ]),
        ],
        crib_alignment="free",
        scoring="composite",
        null_baseline=NullBaselineSpec(method="random_text", n_samples=1000),
        compute_budget_cpu_minutes=10,
        assumption_bundle=_bundle("AZ") + [
            "quagmire_iii_diagonal_tableau",
            "outer_byte_reordering_then_quagmire_iii",
            "reordering_universe_7a9ac67336cd37e2",
        ],
        override_exhaustion=True,
        override_justification=OVERRIDE_JUSTIFICATION,
    )


# ─── Result digestion ────────────────────────────────────────────────────────

def digest(res, arm: str, spec_meta: dict) -> dict:
    """Summarize one JobResult; collect every config >= SIGNAL_FLOOR.

    Per-config results live in the artifact JSON (manifest + spec +
    all_results), not on the JobResult object. An admissibility
    rejection is surfaced loudly — a rejected spec tested NOTHING and
    must never be silently counted toward a clean null.
    """
    rejected = not str(res.admissibility_verdict).startswith("ok")
    hits: list[dict] = []
    best: dict = {"crib_score": -1}
    errors = 0
    if not rejected and res.artifact_path and os.path.exists(res.artifact_path):
        with open(res.artifact_path) as f:
            all_results = json.load(f).get("all_results", [])
        for r in all_results:
            if r.get("error"):
                errors += 1
                continue
            cs = int(r.get("crib_score", 0) or 0)
            if cs > int(best.get("crib_score", -1)):
                best = dict(r)
            if cs >= SIGNAL_FLOOR:
                hits.append(dict(r))
    return {
        "arm": arm,
        **spec_meta,
        "admissibility_verdict": res.admissibility_verdict,
        "admissibility_rejected": rejected,
        "admissibility_reasons": list(res.admissibility_reasons or []),
        "universe_hash": res.universe_hash,
        "total_tested": res.total_tested,
        "errors": errors,
        "best_crib_score": best.get("crib_score"),
        "best_config": best.get("config_id"),
        "best_ngram": best.get("ngram_score"),
        "best_p_value_vs_null": res.best_p_value_vs_null,
        "hits_ge_11": hits,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="results/free_alignment_classical")
    ap.add_argument("--arms", default="A1,A2,A3",
                    help="comma list of arms to run")
    ap.add_argument("--max-shards", type=int, default=None,
                    help="limit A3 shards (smoke/timing only; full run = all)")
    args = ap.parse_args(argv)

    arms = {a.strip().upper() for a in args.arms.split(",") if a.strip()}
    out = Path(_ROOT) / args.out
    out_jobs = out / "jobs"
    out.mkdir(parents=True, exist_ok=True)
    out_jobs.mkdir(parents=True, exist_ok=True)

    t0 = time.monotonic()
    summary: dict = {
        "campaign": "f_free_alignment_classical_2026_06_10",
        "prereg": PREREG,
        "git_head": _git_head(),
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "signal_floor": SIGNAL_FLOOR,
        "arms_requested": sorted(arms),
        "controls": [],
        "arm_digests": [],
    }

    # Controls (abort on failure — pre-reg section 4).
    c1, c2 = control_c1(), control_c2()
    summary["controls"] = [c1, c2]
    print(f"[controls] C1 pass={c1['pass']}  C2 pass={c2['pass']}", flush=True)
    if not (c1["pass"] and c2["pass"]):
        summary["verdict"] = "ABORTED_CONTROL_FAILURE"
        (out / "summary.json").write_text(json.dumps(summary, indent=2))
        print("CONTROL FAILURE — aborting before any arm runs.")
        return 2

    thematic = load_thematic()
    summary["thematic_count"] = len(thematic)
    summary["thematic_sha256"] = _sha(thematic)

    # ── A1: motivated additive ──────────────────────────────────────────────
    if "A1" in arms:
        for kind in ADDITIVE_KINDS:
            for alphabet in ALPHABETS:
                hid = f"freealign_A1_{kind}_{alphabet}"
                spec = build_additive_spec(hid, kind, alphabet, thematic)
                res = execute(spec, artifact_root=out_jobs)
                d = digest(res, "A1", {
                    "hypothesis_id": hid, "kind": kind, "alphabet": alphabet,
                    "spec_hash": spec.spec_hash,
                    "n_keywords": len(thematic),
                })
                summary["arm_digests"].append(d)
                print(f"[A1] {hid}: tested={d['total_tested']} "
                      f"best={d['best_crib_score']} hits>=11="
                      f"{len(d['hits_ge_11'])}", flush=True)

    # ── A2: Quagmire III diagonal ───────────────────────────────────────────
    if "A2" in arms:
        spec = build_a2_spec()
        res = execute(spec, artifact_root=out_jobs)
        d = digest(res, "A2", {
            "hypothesis_id": spec.hypothesis_id,
            "spec_hash": spec.spec_hash,
            "tableaus": TABLEAUS, "n_periods": len(PERIODS),
        })
        summary["arm_digests"].append(d)
        print(f"[A2] {spec.hypothesis_id}: tested={d['total_tested']} "
              f"best={d['best_crib_score']} hits>=11="
              f"{len(d['hits_ge_11'])}", flush=True)

    # ── A4: route-undo x additive, motivated keywords (addendum 6b) ────────
    if "A4" in arms:
        routes = load_routes()
        summary["a4_n_routes"] = len(routes)
        for kind in ADDITIVE_KINDS:
            for alphabet in ALPHABETS:
                hid = f"freealign_A4_route_{kind}_{alphabet}"
                spec = build_a4_spec(hid, kind, alphabet, thematic, routes)
                res = execute(spec, artifact_root=out_jobs)
                d = digest(res, "A4", {
                    "hypothesis_id": hid, "kind": kind, "alphabet": alphabet,
                    "spec_hash": spec.spec_hash,
                    "n_keywords": len(thematic), "n_routes": len(routes),
                })
                summary["arm_digests"].append(d)
                print(f"[A4] {hid}: tested={d['total_tested']} "
                      f"best={d['best_crib_score']} hits>=11="
                      f"{len(d['hits_ge_11'])}", flush=True)
                (out / "summary.json").write_text(json.dumps(summary, indent=2))

    # ── A5: two-layer columnar x additive, both peel orders (6c) ───────────
    if "A5" in arms:
        for kind in ADDITIVE_KINDS:
            for alphabet in ALPHABETS:
                for order in ("trans_first", "sub_first"):
                    hid = f"freealign_A5_col_{kind}_{alphabet}_{order}"
                    spec = build_a5_spec(hid, kind, alphabet, order, thematic)
                    res = execute(spec, artifact_root=out_jobs)
                    d = digest(res, "A5", {
                        "hypothesis_id": hid, "kind": kind,
                        "alphabet": alphabet, "order": order,
                        "spec_hash": spec.spec_hash,
                        "n_keywords": len(thematic),
                    })
                    summary["arm_digests"].append(d)
                    print(f"[A5] {hid}: tested={d['total_tested']} "
                          f"best={d['best_crib_score']} hits>=11="
                          f"{len(d['hits_ge_11'])}", flush=True)
                    (out / "summary.json").write_text(
                        json.dumps(summary, indent=2))

    # ── A6: route x QIII diagonal, free re-lens (6c) ────────────────────────
    if "A6" in arms:
        routes = load_routes()
        spec = build_a6_spec(routes)
        res = execute(spec, artifact_root=out_jobs)
        d = digest(res, "A6", {
            "hypothesis_id": spec.hypothesis_id,
            "spec_hash": spec.spec_hash,
            "n_routes": len(routes),
        })
        summary["arm_digests"].append(d)
        print(f"[A6] {spec.hypothesis_id}: tested={d['total_tested']} "
              f"best={d['best_crib_score']} hits>=11="
              f"{len(d['hits_ge_11'])}", flush=True)
        (out / "summary.json").write_text(json.dumps(summary, indent=2))

    # ── A3: exploratory breadth (sharded) ───────────────────────────────────
    if "A3" in arms:
        english = load_english()
        summary["english_count"] = len(english)
        summary["english_sha256"] = _sha(english)
        shards = [english[i:i + SHARD_SIZE]
                  for i in range(0, len(english), SHARD_SIZE)]
        if args.max_shards is not None:
            shards = shards[: args.max_shards]
            summary["a3_shard_limit"] = args.max_shards
        n_done = 0
        for kind in ADDITIVE_KINDS:
            for alphabet in ALPHABETS:
                for si, chunk in enumerate(shards):
                    hid = f"freealign_A3_{kind}_{alphabet}_s{si:03d}"
                    spec = build_additive_spec(hid, kind, alphabet, chunk)
                    res = execute(spec, artifact_root=out_jobs)
                    d = digest(res, "A3", {
                        "hypothesis_id": hid, "kind": kind,
                        "alphabet": alphabet, "shard": si,
                        "spec_hash": spec.spec_hash,
                        "n_keywords": len(chunk),
                    })
                    # A3 volume: keep per-shard digests lean unless hits.
                    if not d["hits_ge_11"]:
                        d.pop("best_config", None)
                    summary["arm_digests"].append(d)
                    n_done += 1
                    if d["hits_ge_11"] or d["best_crib_score"] >= SIGNAL_FLOOR:
                        print(f"[A3][HIT] {hid}: best={d['best_crib_score']} "
                              f"hits={len(d['hits_ge_11'])}", flush=True)
                    if n_done % 10 == 0:
                        el = time.monotonic() - t0
                        print(f"[A3] {n_done} shards done ({el:.0f}s)",
                              flush=True)
                        (out / "summary.json").write_text(
                            json.dumps(summary, indent=2))

    # ── Verdict (frozen rules, pre-reg section 5) ───────────────────────────
    all_hits = [h for d in summary["arm_digests"] for h in d["hits_ge_11"]]
    n24 = sum(1 for h in all_hits if int(h.get("crib_score", 0)) >= DETECT)
    rejections = [d["hypothesis_id"] for d in summary["arm_digests"]
                  if d.get("admissibility_rejected")]
    summary["admissibility_rejections"] = rejections
    if rejections:
        # A rejected spec tested nothing — the run is incomplete, never
        # a clean null.
        summary["verdict"] = "ABORTED_ADMISSIBILITY_REJECTION"
    elif n24:
        summary["verdict"] = "DETECT_24_INVESTIGATE"
    elif all_hits:
        summary["verdict"] = "SIGNAL_INVESTIGATE_FIRST"
    else:
        summary["verdict"] = "CLEAN_NULL"
    summary["n_hits_ge_11"] = len(all_hits)
    summary["n_detect_24"] = n24
    summary["total_configs"] = sum(
        d["total_tested"] or 0 for d in summary["arm_digests"])
    summary["wall_seconds"] = round(time.monotonic() - t0, 1)
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    print(f"\nVERDICT: {summary['verdict']}  "
          f"configs={summary['total_configs']}  "
          f"hits>=11={len(all_hits)}  wall={summary['wall_seconds']}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
