#!/usr/bin/env python3
"""Campaign: Carter-Gutenberg running-key inner under non-direct (post-transposition) alignment.

ID:        f_carter_gutenberg_running_key_nondirect_2026_06_07
Family:    key_tape / non_direct_alignment
Status:    active (single bounded frontier experiment)
Pre-reg:   docs/campaigns/carter_gutenberg_running_key_nondirect_2026_06_07.md
Alignment: non_direct_alignment (R1); crib_alignment="post_transposition"

Outer (one explicit route): route_boustrophedon width=14 vertical=False.
Inner (one additive variant): key_tape variant=vigenere alphabet=AZ, no nulls
  (running key — the tape IS the keystream).
Key material: reference/carter_gutenberg.txt (Project Gutenberg eBook #59783,
  *Tutankhamen and the Discovery of His Tomb*, Carnarvon & Carter; US public
  domain, license embedded in-file). Window=97, forward, stride=1, all offsets.
  NOT leaked K4 plaintext.

The preregistered HypothesisSpec is dispatched ONCE via the real dispatcher
(kryptosbot.job_dispatcher.execute) — this exercises the Task A post_transposition
Bean-frame fix (Bean re-derived against route_undo(CT), not the carved CT). A
matched-family null (shuffled-corpus windows, matched search depth) and a
forced-crib control are computed alongside. Hard kill rule:
  SIGNAL iff crib_score>=18 AND bean_passed AND per-char ngram>=-4.5.
No SIGNAL over the full finite universe => EXPERIMENT_COMPLETED_NULL, scoped to
universe_hash.

Replay:
  PYTHONPATH=src python3 -u scripts/campaigns/f_carter_gutenberg_running_key_nondirect_2026_06_07.py \
    --out results/final_k4_goal_next
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import re
import sys
import time

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

import numpy as np  # available in system python (2.4.x) and venv

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT
from kryptos.kernel.text import text_to_nums, nums_to_text
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.scoring.ngram import get_default_scorer
from kryptos.kernel.transforms.compose import (
    TransformConfig, TransformType, build_transform,
)
from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
from kryptosbot.job_dispatcher import (
    check_admissibility, execute, _build_pipeline_config, _enumerate_bindings,
    _candidate_bean_status,
)

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
IDX = {c: i for i, c in enumerate(AZ)}

CORPUS = "reference/carter_gutenberg.txt"
WIDTH, VERTICAL, VARIANT, ALPHABET = 14, False, "vigenere", "AZ"
WINDOW = CT_LEN  # 97
M_NULL = 24
NULL_SEED_BASE = 20260607
CRIB_SIGNAL = 18
NGRAM_FLOOR = -4.5


def extract_body() -> tuple[str, str]:
    """Return (A-Z body letters, sha256[:16]) from the declared corpus.

    Body = text strictly between the Project Gutenberg START/END markers,
    uppercased and reduced to A-Z (license boilerplate excluded).
    """
    raw = open(os.path.join(_ROOT, CORPUS), encoding="utf-8", errors="ignore").read()
    m0 = re.search(r"\*\*\* START OF THE PROJECT GUTENBERG EBOOK.*?\*\*\*", raw, re.S)
    m1 = re.search(r"\*\*\* END OF THE PROJECT GUTENBERG EBOOK.*?\*\*\*", raw, re.S)
    if not (m0 and m1):
        raise SystemError("Gutenberg START/END markers not found — provenance gate failed")
    body = re.sub(r"[^A-Z]", "", raw[m0.end():m1.start()].upper())
    return body, hashlib.sha256(body.encode()).hexdigest()[:16]


def build_spec(tape_values: list[list[int]]) -> dict:
    return {
        "hypothesis_id": "carter_gut_running_key_nondirect_20260607",
        "family": "key_tape",
        "pipeline": [
            {"kind": "route_boustrophedon", "alphabet": "AZ",
             "params": [{"name": "width", "values": [WIDTH]},
                        {"name": "vertical", "values": [VERTICAL]}]},
            {"kind": "key_tape", "alphabet": ALPHABET,
             "params": [{"name": "tape", "values": tape_values},
                        {"name": "variant", "values": [VARIANT]}]},
        ],
        "crib_alignment": "post_transposition",
        "scoring": "composite",
        "compute_budget_cpu_minutes": 30,
        "assumption_bundle": [
            "outer_boustrophedon_serpentine_route",
            "inner_running_key_public_corpus",
            "tape_content_swept_axis",
            "public_source_provenance_only",
            "geometric_alignment_not_ct_extraction",
            "not_H1_direct_positional",
            "bean_rederived_in_post_route_frame",
        ],
        "notes": (
            "Carter-Gutenberg (PG #59783) running-key inner; window=97 forward "
            "stride=1 all offsets; ONE route boustrophedon(w=14,horizontal); "
            "ONE variant vigenere AZ; post_transposition (Task A Bean frame)."
        ),
    }


def route_intermediate(spec_obj) -> tuple[str, list[int]]:
    """route_undo(CT) — the PT-frame intermediate the inner additive operates on.

    Built from the dispatcher's OWN translation of the route layer so it is
    byte-identical to what execute() decrypts.
    """
    first = next(iter(_enumerate_bindings(spec_obj)))
    steps = _build_pipeline_config(spec_obj, first)["steps"]
    route_step = steps[0]
    assert route_step["type"] == "transposition_full", route_step["type"]
    fn = build_transform(TransformConfig(
        transform_type=TransformType(route_step["type"]),
        params=dict(route_step["params"]),
    ))
    inter = fn(CT)
    return inter, text_to_nums(inter)


def crib_scores_over_offsets(body_arr: np.ndarray, targets: np.ndarray,
                             crib_pos: list[int], n_off: int) -> np.ndarray:
    """Exact anchored crib_score per forward offset (== kernel crib_score)."""
    scores = np.zeros(n_off, dtype=np.int16)
    for k, p in enumerate(crib_pos):
        scores += (body_arr[p:p + n_off] == targets[k])
    return scores


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="results/final_k4_goal_next")
    ap.add_argument("--workers", type=int, default=max(1, os.cpu_count() - 2))
    ap.add_argument("--null-trials", type=int, default=M_NULL)
    args = ap.parse_args()
    out_dir = os.path.join(_ROOT, args.out)
    os.makedirs(out_dir, exist_ok=True)
    t_start = time.time()

    body, body_sha = extract_body()
    N = len(body)
    n_off = N - WINDOW + 1
    print(f"[corpus] {CORPUS}  body A-Z={N}  sha256[:16]={body_sha}  forward offsets={n_off}")
    body_idx = [IDX[c] for c in body]
    body_arr = np.array(body_idx, dtype=np.int16)

    # full-universe identity (the closure is scoped to ALL offsets, not the
    # kernel-verified subset). The DSL caps a ParamRange at 10k, so the full
    # universe is scored exactly by the numpy prefilter and the high-crib
    # survivors are kernel-verified via one dispatch (the validated pattern
    # from the 2026-06-05 89.7M-config Carter closure).
    full_universe_hash = hashlib.sha256(json.dumps({
        "corpus_sha": body_sha, "n_offsets": n_off, "window": WINDOW,
        "direction": "forward", "stride": 1,
        "route": ["route_boustrophedon", WIDTH, VERTICAL],
        "inner": ["key_tape", VARIANT, ALPHABET],
    }, sort_keys=True).encode()).hexdigest()[:16]
    print(f"[universe] full_universe_hash={full_universe_hash} (all {n_off} offsets)")

    # route_undo(CT): build via a minimal 1-tape spec so the route translation
    # is byte-identical to the dispatcher's.
    probe = validate_hypothesis_spec(build_spec([body_idx[:WINDOW]]))
    assert probe.is_valid, probe.errors
    inter, inter_num = route_intermediate(probe.value)
    crib_pos = sorted(CRIB_DICT)
    targets = np.array([(inter_num[p] - IDX[CRIB_DICT[p]]) % 26 for p in crib_pos],
                       dtype=np.int16)

    # ── Stage 1: exact crib_score over the FULL finite universe (kernel-equiv) ──
    real_scores = crib_scores_over_offsets(body_arr, targets, crib_pos, n_off)
    real_best = int(real_scores.max())
    best_off = int(real_scores.argmax())
    hist = {int(s): int(c) for s, c in zip(*np.unique(real_scores, return_counts=True))}
    n_ge_signal = int((real_scores >= CRIB_SIGNAL).sum())
    print(f"[real] full universe: best crib_score={real_best}/24 @offset={best_off}  "
          f"#(crib>=18)={n_ge_signal}  histogram={hist}")

    # Prefilter integrity gate: numpy crib_score == kernel score_candidate crib on
    # a random sample of offsets (the prefilter must equal the kernel exactly).
    rng = np.random.default_rng(99)
    sample = sorted(set(int(x) for x in rng.integers(0, n_off, size=256)) | {best_off})
    mismatches = 0
    for o in sample:
        tp = body_idx[o:o + WINDOW]
        cpt = nums_to_text([(inter_num[i] - tp[i]) % 26 for i in range(WINDOW)])
        if score_candidate(cpt).crib_score != int(real_scores[o]):
            mismatches += 1
    print(f"[integrity] prefilter==kernel crib on {len(sample)} sampled offsets: "
          f"mismatches={mismatches}")
    assert mismatches == 0, "prefilter diverged from kernel crib_score"

    # Reconstruct + KERNEL-verify the global best candidate (Task A Bean frame).
    tape_best = body_idx[best_off:best_off + WINDOW]
    cand_pt = nums_to_text([(inter_num[i] - tape_best[i]) % 26 for i in range(WINDOW)])
    bd = score_candidate(cand_pt)
    bean_passed, bean_var = _candidate_bean_status(inter, cand_pt)  # post-route frame
    ngram = float(get_default_scorer().score_per_char(cand_pt))
    print(f"[real best kernel] crib={bd.crib_score} bean={bean_passed}({bean_var}) "
          f"ngram/char={ngram:.3f}")
    assert bd.crib_score == real_best, (bd.crib_score, real_best)

    # ── Stage 2: dispatch the preregistered spec ONCE over high-crib survivors ──
    DISPATCH_N = 4096
    order = np.argsort(-real_scores, kind="stable")
    sig_offsets = [int(o) for o in np.where(real_scores >= CRIB_SIGNAL)[0]]
    dispatch_offsets = sorted(set(int(o) for o in order[:DISPATCH_N]) | set(sig_offsets))
    dispatch_offsets = dispatch_offsets[:9999]  # DSL ParamRange cap
    dispatch_floor = int(real_scores[order[len(dispatch_offsets) - 1]]) if dispatch_offsets else 0
    tape_subset = [body_idx[o:o + WINDOW] for o in dispatch_offsets]
    spec = build_spec(tape_subset)
    pr = validate_hypothesis_spec(spec)
    assert pr.is_valid, pr.errors
    spec_obj = pr.value
    spec_hash = spec_obj.spec_hash
    cardinality = spec_obj.expected_cardinality()
    adm, reasons = check_admissibility(spec_obj)
    print(f"[dispatch-spec] hash={spec_hash} cardinality={cardinality} "
          f"(crib>= ~{dispatch_floor}, incl all {n_ge_signal} crib>=18) admissible={adm} {reasons}")
    assert adm, reasons
    t0 = time.time()
    jr = execute(spec_obj, workers=args.workers)
    dt = time.time() - t0
    jd = dataclasses.asdict(jr)
    disp_best = jd.get("best_candidate") or {}
    truncated = int(jd.get("total_tested") or 0) != cardinality
    print(f"[dispatch] tested={jd.get('total_tested')}/{cardinality} stored={jd.get('total_stored')} "
          f"in {dt:.1f}s  universe_hash={jd.get('universe_hash')}  truncated={truncated}")
    print(f"[dispatch] best crib={disp_best.get('crib_score')} bean={disp_best.get('bean_passed')} "
          f"mode={disp_best.get('scoring_mode')} ngram/char={disp_best.get('ngram_score')}")
    assert int(disp_best.get("crib_score", -1)) == real_best, (disp_best.get("crib_score"), real_best)

    # ── Matched-family null: shuffled-corpus windows, matched depth ──
    null_best = []
    for t in range(args.null_trials):
        rng = np.random.default_rng(NULL_SEED_BASE + t)
        shuf = body_arr.copy()
        rng.shuffle(shuf)
        ns = crib_scores_over_offsets(shuf, targets, crib_pos, n_off)
        null_best.append(int(ns.max()))
    null_best.sort()
    null_beats_real = sum(1 for b in null_best if b >= real_best) / len(null_best)
    print(f"[null] M={len(null_best)} matched-depth shuffled-corpus best-crib dist: "
          f"min={null_best[0]} max={null_best[-1]} mean={sum(null_best)/len(null_best):.2f}  "
          f"null_beats_real(P[null_best>=real_best])={null_beats_real:.3f}")

    # ── Forced-crib control: paste cribs into random body => crib 24, not a solve ──
    rng = np.random.default_rng(777)
    forced = list(rng.integers(0, 26, size=WINDOW))
    for p in crib_pos:
        forced[p] = IDX[CRIB_DICT[p]]
    forced_pt = nums_to_text([int(x) for x in forced])
    fbd = score_candidate(forced_pt)
    f_bean, _ = _candidate_bean_status(inter, forced_pt)
    f_ngram = float(get_default_scorer().score_per_char(forced_pt))
    print(f"[forced-crib control] crib={fbd.crib_score}/24 bean={f_bean} "
          f"ngram/char={f_ngram:.3f}  (crib=24 yet fails Bean+English => not a solve)")

    # ── Hard kill criterion ──
    signal = (real_best >= CRIB_SIGNAL) and bean_passed and (ngram >= NGRAM_FLOOR)
    verdict = "SOLVE_CANDIDATE" if signal else "EXPERIMENT_COMPLETED_NULL"
    print(f"[VERDICT] {verdict}  (real_best_crib={real_best} signal_threshold={CRIB_SIGNAL} "
          f"bean={bean_passed} ngram_floor={NGRAM_FLOOR})")

    # ── Persist ──
    with open(os.path.join(out_dir, "spec_carter_gut_nondirect.json"), "w") as fh:
        json.dump(spec, fh)  # full spec incl. tape universe (large)
    with open(os.path.join(out_dir, "jobresult_carter_gut_nondirect.json"), "w") as fh:
        json.dump(jd, fh, indent=2, default=str)
    summary = {
        "campaign": "f_carter_gutenberg_running_key_nondirect_2026_06_07",
        "prereg": "docs/campaigns/carter_gutenberg_running_key_nondirect_2026_06_07.md",
        "alignment_model": "non_direct_alignment",
        "crib_alignment": "post_transposition",
        "corpus": {"file": CORPUS, "source": "Project Gutenberg eBook #59783",
                   "license": "US public domain (PG License embedded in-file)",
                   "body_AZ_letters": N, "body_sha256_16": body_sha},
        "full_universe": {"full_universe_hash": full_universe_hash,
                          "n_offsets": n_off, "scored_exactly_by": "numpy_prefilter==kernel",
                          "prefilter_kernel_mismatches": mismatches,
                          "route": {"kind": "route_boustrophedon", "width": WIDTH, "vertical": VERTICAL},
                          "inner": {"kind": "key_tape", "variant": VARIANT, "alphabet": ALPHABET},
                          "window": WINDOW, "direction": "forward", "stride": 1},
        "spec": {"spec_hash": spec_hash, "expected_cardinality": cardinality,
                 "dispatch_subset": "high-crib survivors (+ all crib>=18)",
                 "approx_crib_floor": dispatch_floor},
        "dispatch": {"universe_hash": jd.get("universe_hash"),
                     "total_tested": jd.get("total_tested"),
                     "total_stored": jd.get("total_stored"),
                     "truncated": truncated, "wall_sec": round(dt, 1),
                     "best_candidate": disp_best},
        "real_best": {"crib_score": real_best, "offset": best_off,
                      "candidate_pt": cand_pt, "bean_passed": bean_passed,
                      "bean_variant": bean_var, "ngram_per_char": ngram,
                      "crib_histogram": hist},
        "matched_null": {"trials": len(null_best), "kind": "shuffled_corpus_matched_depth",
                         "best_crib_dist": null_best,
                         "mean": sum(null_best) / len(null_best),
                         "null_beats_real": null_beats_real},
        "forced_crib_control": {"crib_score": fbd.crib_score, "bean_passed": f_bean,
                                "ngram_per_char": f_ngram},
        "kill_criterion": {"crib_signal": CRIB_SIGNAL, "ngram_floor": NGRAM_FLOOR,
                           "requires": "crib>=18 AND bean AND ngram>=-4.5"},
        "verdict": verdict,
        "scope_eliminated": ("carter_gutenberg body x boustrophedon(w=14,horizontal) x "
                             "key_tape vigenere AZ x all forward window-97 offsets x "
                             "post_transposition"),
        "scope_not_eliminated": ("other routes/widths/verticals, other variants/alphabets, "
                                 "reverse/other windows, other corpora, direct alignment"),
        "replay": ("PYTHONPATH=src python3 -u scripts/campaigns/"
                   "f_carter_gutenberg_running_key_nondirect_2026_06_07.py --out results/final_k4_goal_next"),
        "wall_sec_total": round(time.time() - t_start, 1),
    }
    with open(os.path.join(out_dir, "summary_carter_gut_nondirect.json"), "w") as fh:
        json.dump(summary, fh, indent=2)
    print(f"[persist] wrote spec/jobresult/summary to {out_dir}")
    print(f"[done] total wall {summary['wall_sec_total']}s")


if __name__ == "__main__":
    main()
