#!/usr/bin/env python3
"""GAP-09 T2 closure PRE-REGISTRATION: frozen score-free candidate null-mask family.

Pre-reg doc: docs/campaigns/gap09_t2_prereg_mask_family_2026_06_07.md
Spec:        docs/REAL_K4_GAP09_ACQUISITION_SPEC_2026_05_29.md  (closure test T2)
Protocol:    docs/REAL_K4_O1_ACQUISITION_PROTOCOL_2026_05_29.md (the O1 observable)

WHY THIS EXISTS
GAP-09 closes only via an INDEPENDENT, K4-indexed observable (O1 = which carved
K4 glyph begins each physical row) co-locating with a SCORE-FREE null mask at
p<=1e-6 AND a verifying side-effect, with everything frozen + hashed BEFORE the
observable is seen (no post-hoc mask/delta/observable tuning). The observable is
acquisition-gated (a flat orthographic K4-panel photo; none in-repo). This script
freezes the candidate mask family + the matched-null assignment + the locked test
params so the closure is ONE push-button call the moment O1 arrives.

ANTI-CIRCULARITY (load-bearing)
- The family is pathway-2's R1-R5 score-free rules, imported VERBATIM from
  scripts/campaigns/gap09_null_mask_pathway2_2026_05_27.py (single source of
  truth) and HASH-VERIFIED against the pathway-2 artifact
  (rule_set_sha256 == 931ed3db...). Score-free = zero K4-decryption/score input
  (deterministic functions of public CT letters + public geometry only). It does
  NOT revive the retired {B,G,I,K,O,W,Z} palette / CONSENSUS_NULL_POSITIONS.
- NULL MODEL per rule (the misspecification fix, verified in
  tests/test_gap09_colocation.py): PERIODIC/GRID rules (R3 grid-row, R4 every-k)
  share period with quasi-periodic carved line-breaks, so they MUST use the
  family-matched null (gap09_t2_colocation_p_matched over all phases/rows of the
  same grammar). NON-periodic letter-class rules (R1 doubled-letter, R2 Polybius
  band, R5 vowel-class) scatter w.r.t. line-break geometry, so the exact
  uniform-hypergeometric null (gap09_t2_colocation_p) is the matched question
  there.
- DECISION (frozen): a candidate mask anchors GAP-09 iff its (Bonferroni-
  corrected) co-location p <= 1e-6 AND the side-effect predicate holds. Per
  pathway-2 (hash-matched family) the side-effect predicate is currently UNMET
  for ALL candidates (T3=0: no mask yields a crib-consistent Bean-valid forced
  key above the ngram floor on CT73), so co-location alone cannot close GAP-09 --
  a new cipher hypothesis on CT73 would be required in addition.

USAGE
  Freeze + write the artifact:
    PYTHONPATH=src python3 scripts/campaigns/gap09_t2_prereg_mask_family_2026_06_07.py
  Self-test the locked closure on synthetic observables (no real O1 needed):
    PYTHONPATH=src python3 scripts/campaigns/gap09_t2_prereg_mask_family_2026_06_07.py --selftest
  Run the closure when a real O1 observable arrives (JSON list of K4 indices 0-96):
    PYTHONPATH=src python3 scripts/campaigns/gap09_t2_prereg_mask_family_2026_06_07.py --observable path/to/o1_indices.json
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
from datetime import datetime, timezone
from math import comb

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CRIB_POSITIONS  # noqa: E402
from kryptos.admissibility.gap09_colocation import (  # noqa: E402
    gap09_t2_colocation_p, gap09_t2_colocation_p_matched, periodic_rule_masks,
)
from kryptos.admissibility.mask_hypothesis import (  # noqa: E402
    MaskUniverse, MaskHypothesis, validate_mask_hypothesis,
)

N = len(CT)  # 97
CRIBS = frozenset(CRIB_POSITIONS)
DELTA = 0                     # frozen tolerance (any delta>0 needs a NEW prereg)
P_GATE = 1e-6                 # frozen closure gate
PATHWAY2_RULE_SET_SHA256 = "931ed3db1b86093971a5ba7ce4dba00b71e877207fe2fb24f2c1f8bcfdd7a32b"
PERIODIC_RULES = frozenset({"R3", "R4"})   # grid/periodic -> matched null required

# Side-effect predicate (mandatory 2nd gate) is delegated to pathway-2's T3 with
# THIS pinned config. Frozen-UNMET (T3=0); flipping it requires recomputing T3 with
# this exact config AND issuing a NEW pre-registration (a fresh prereg_sha256) --
# the side-effect cannot be silently loosened, and this script can never on its own
# emit GAP09_ANCHORED. (BLOCKER-2 fix: pin the computation, not just prose.)
SIDE_EFFECT_T3_CONFIG = {
    "solver": "kryptos.admissibility.mask_campaign_gate.run_guarded_mask_search",
    "periods": "1..12", "max_free_exhaustive": 3, "alphabet": "AZ",
    "variants": "default (vigenere, beaufort, var_beaufort)",
    "ngram_floor": "calibrated_ngram_floor via select_solves",
    "frozen_result": "T3=0 candidates on the hash-matched family (931ed3db...)",
    "recompute_cmd": "PYTHONPATH=src python3 scripts/campaigns/gap09_null_mask_pathway2_2026_05_27.py",
}
SIDE_EFFECT_STATUS = "UNMET_FOR_ALL (pathway-2 T3=0, hash-matched family; config pinned)"

# The single observable this pre-registration covers. Testing these masks against
# any OTHER observable or segmentation is a SEPARATE pre-registration, NOT covered
# by this multiplicity budget. (MAJOR-4 fix: lock the observable axis.)
OBSERVABLE_LOCK = {
    "observable_id": "O1",
    "definition": "the K4 character index (0-96) that BEGINS each carved physical row of the K4 panel",
    "segmentation_rule": ("one row per carved physical line on the copper; row-start = the leftmost "
                          "glyph of each line, glyphs counted left-to-right, top-to-bottom; ORDINAL "
                          "only (no metric flattening of the S-curved panel)"),
    "delta": DELTA,
    "cross_observable_policy": ("covers O1 with this single segmentation ONLY; O2-O5 or any alternative "
                                "segmentation require a separate pre-registration (new prereg_sha256)"),
}


def _load_pathway2_rule_masks():
    """Import rule_masks() VERBATIM from the pathway-2 script (single source)."""
    path = os.path.join(_ROOT, "scripts", "campaigns",
                        "gap09_null_mask_pathway2_2026_05_27.py")
    spec = importlib.util.spec_from_file_location("_gap09_pw2", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.rule_masks


def _rule_set_sha256(rules) -> str:
    return hashlib.sha256(
        "|".join(f"{rid}:{p}:{','.join(map(str, sorted(m)))}" for rid, p, m in rules)
        .encode()
    ).hexdigest()


def _matched_null_family(rid: str, params: str) -> list[list[int]] | None:
    """The same-grammar matched-null family for a periodic/grid rule, or None.

    Built by the SAME rule that produced the candidate masks (consistency fix):
    R4 = all phases of period k; R3 = all WHOLE rows of width W that do NOT
    intersect a crib (pathway-2 drops crib-touching rows entirely -- so does this,
    avoiding the crib-truncated fragments a within-row strip would inject).
    """
    kv = dict(tok.split("=") for tok in params.split(","))
    if rid == "R4":                     # every-k-th: family = all phases of period k
        k = int(kv["k"])
        fam = periodic_rule_masks(k, n=N, crib_positions=CRIBS)
        return [sorted(m) for m in fam]
    if rid == "R3":                     # grid row-take: family = all crib-free rows of width W
        W = int(kv["W"])
        nrows = (N + W - 1) // W
        fam = []
        for R in range(nrows):
            row = {i for i in range(N) if i // W == R}
            if row and not (row & CRIBS):     # whole crib-free row (same rule as candidates)
                fam.append(sorted(row))
        return fam
    return None


def _best_case_p_raw(rec: dict) -> float:
    """Most-permissive achievable raw p for this mask (its theoretical floor).

    matched: Phipson-Smyth floor 1/(1+|family|) (only the candidate can reach its
             own maximal co-location when family members are disjoint rows).
    uniform: 1/C(|free pool|, |mask|) -- full co-location of the whole mask.
    A mask is LIVE (can ever clear the gate) iff this floor <= P_GATE.
    """
    if rec["null_model"] == "matched":
        return 1.0 / (1 + len(rec["matched_null_family"]))
    return 1.0 / comb(N - len(CRIBS), rec["mask_size"])


def build_family():
    """Return (admissible_records, rule_set_sha256). Deterministic, score-free."""
    rule_masks = _load_pathway2_rule_masks()
    rules = list(rule_masks())
    rule_hash = _rule_set_sha256(rules)
    assert rule_hash == PATHWAY2_RULE_SET_SHA256, (
        f"frozen family DRIFTED from pathway-2: {rule_hash} != {PATHWAY2_RULE_SET_SHA256}")

    records = []
    for rid, params, mask in rules:
        mask = frozenset(mask)
        if mask & CRIBS:
            continue                                  # cribs cannot be nulls
        if not mask or len(mask) >= N - len(CRIBS):
            continue                                  # empty / over-large
        null_model = "matched" if rid in PERIODIC_RULES else "uniform_hypergeometric"
        fam = _matched_null_family(rid, params) if null_model == "matched" else None
        records.append({
            "rule": rid, "params": params,
            "mask": sorted(mask), "mask_size": len(mask),
            "null_model": null_model,
            "matched_null_family": fam,
        })
    records.sort(key=lambda r: (r["rule"], r["params"]))
    # MAJOR-3 fix: mark which masks can EVER clear the gate. The matched-null
    # floor 1/(1+famsize) (R3: 0.077-0.33) is >> 1e-6, so all R3 grid-rows are
    # co-location-INERT regardless of the observable; only the uniform-null
    # letter-class masks (R2, R5) are live. Multiplicity is corrected to the live
    # count (inert masks contribute 0 to the family-wise error rate).
    for r in records:
        r["best_case_p_raw"] = _best_case_p_raw(r)
        r["can_clear_gate"] = r["best_case_p_raw"] <= P_GATE
    return records, rule_hash


def closure_p(rec: dict, observable) -> float:
    """Locked per-mask co-location p-value under the rule's frozen null model."""
    if rec["null_model"] == "matched":
        return gap09_t2_colocation_p_matched(
            rec["mask"], observable, null_masks=rec["matched_null_family"],
            n=N, crib_positions=CRIBS, delta=DELTA)
    return gap09_t2_colocation_p(
        rec["mask"], observable, n=N, crib_positions=CRIBS, delta=DELTA)


def run_closure(observable: list[int], records: list[dict]) -> dict:
    """Execute the FROZEN T2 co-location closure for an acquired O1 observable.

    The caller asserts the observable satisfies I1-I4 (score-blind, not a K4-CT
    statistic, frozen before this call, cross-source persistent) AND matches the
    OBSERVABLE_LOCK (O1, the single declared segmentation) -- this code cannot
    verify provenance/segmentation; that is the human acquisition step.

    Multiplicity is Bonferroni over the LIVE masks only (those that can ever clear
    the gate); inert masks (matched-null floor >> 1e-6) contribute 0 to the
    family-wise error rate and are reported but never significant. The side-effect
    predicate is frozen-UNMET (SIDE_EFFECT_T3_CONFIG; pathway-2 T3=0), so this
    script can emit at most COLOCATION_BUT_SIDE_EFFECT_UNMET -- GAP09_ANCHORED
    requires a SEPARATE pre-registration that recomputes + hashes a passing
    side-effect predicate.
    """
    n_live = sum(1 for r in records if r["can_clear_gate"])
    rows = []
    for rec in records:
        p = closure_p(rec, observable)
        p_bonf = min(1.0, p * max(1, n_live))         # correct multiplicity = live count
        coloc_sig = bool(rec["can_clear_gate"] and p_bonf <= P_GATE)
        rows.append({
            "rule": rec["rule"], "params": rec["params"], "mask_size": rec["mask_size"],
            "null_model": rec["null_model"], "can_clear_gate": rec["can_clear_gate"],
            "p_raw": p, "p_bonferroni": p_bonf, "colocation_significant": coloc_sig,
            "side_effect_met": False,                 # frozen-UNMET (SIDE_EFFECT_T3_CONFIG)
            "anchors_gap09": False,                   # unreachable here by construction
        })
    rows.sort(key=lambda r: r["p_bonferroni"])
    any_coloc = any(r["colocation_significant"] for r in rows)
    return {
        "observable_indices": sorted(set(observable)),
        "n_candidate_masks": len(records), "n_live_masks": n_live,
        "inert_masks": len(records) - n_live, "delta": DELTA, "p_gate": P_GATE,
        "multiplicity_correction": f"Bonferroni over {n_live} LIVE masks (inert masks excluded; FWER 0)",
        "any_colocation_significant": any_coloc,
        "side_effect_status": SIDE_EFFECT_STATUS,
        "side_effect_t3_config": SIDE_EFFECT_T3_CONFIG,
        "any_mask_anchors_gap09": False,
        "verdict": ("COLOCATION_BUT_SIDE_EFFECT_UNMET" if any_coloc
                    else "TESTED_NEGATIVE_GAP09_STAYS_OPEN"),
        "note": ("GAP09_ANCHORED is unreachable from this script: anchoring needs a NEW "
                 "pre-registration computing + hashing a passing side-effect predicate."),
        "per_mask": rows,
    }


def _selftest(records):
    """Prove the locked closure behaves correctly on synthetic observables."""
    # (a) MATCHED-NULL defeats shared-structure inflation: a width-7 grid-row (R3)
    #     candidate vs a period-7 line-break observable. Every same-width row
    #     contains exactly one multiple of 7, so all family members co-locate
    #     equally -> the matched null is (correctly) unimpressed (p ~ 1), even
    #     though the candidate "aligns" with the periodic observable.
    r3w7 = next((r for r in records if r["rule"] == "R3" and "W=7" in r["params"]), None)
    assert r3w7 is not None and r3w7["null_model"] == "matched"
    obs_period7 = list(range(0, N, 7))
    res = run_closure(obs_period7, [r3w7])
    assert not res["per_mask"][0]["colocation_significant"], \
        f"matched null must not call shared-period alignment significant; got {res['per_mask'][0]}"
    # (b) UNIFORM-HYPERGEOMETRIC retains sensitivity: a letter-class candidate (R5
    #     vowels, or R2 band) vs an observable equal to its own positions must fire.
    rlet = next((r for r in records if r["null_model"] == "uniform_hypergeometric"), None)
    assert rlet is not None
    res2 = run_closure(sorted(rlet["mask"]), [rlet])
    assert res2["per_mask"][0]["p_raw"] < 1e-6, \
        f"uniform null must retain sensitivity; got p={res2['per_mask'][0]['p_raw']}"
    # (c) Disjoint / empty observable -> nothing significant for any candidate.
    assert not run_closure([], records)["any_colocation_significant"]
    # (d) Side-effect gate holds: even a significant co-location does NOT anchor
    #     while the side-effect predicate is unmet (pathway-2 T3=0).
    assert res2["verdict"] == "COLOCATION_BUT_SIDE_EFFECT_UNMET"
    assert not res2["any_mask_anchors_gap09"]
    print("[selftest] PASS — matched-null defeats period inflation; uniform retains "
          "sensitivity; empty observable null; side-effect gate blocks anchoring.")


def build_frozen():
    """Deterministically build the frozen pre-registration object + records.

    The returned dict's ``prereg_sha256`` is computed over everything EXCEPT the
    ``date`` field, so re-freezing reproduces the same hash (tamper-evidence).
    """
    records, rule_hash = build_family()
    hyp = MaskHypothesis(
        mask_universe=MaskUniverse(
            masks=tuple(frozenset(r["mask"]) for r in records),
            description="GAP-09 T2 pre-registered score-free candidate mask family (pathway-2 R1-R5)"),
        alignment_model="arbitrary_null_mask",
        provenance="docs/campaigns/gap09_t2_prereg_mask_family_2026_06_07.md",
        assumption_bundle=("cribs_not_null", "zero_score_derivation",
                           "matched_null_for_periodic_rules", "frozen_before_observable"),
        tier="secondary_exploratory",
        stop_rule="finite frozen rule set (pathway-2 R1-R5), fully enumerated; delta=0 fixed")
    errs = validate_mask_hypothesis(hyp)
    assert not errs, errs
    n_live = sum(1 for r in records if r["can_clear_gate"])

    frozen = {
        "prereg": "docs/campaigns/gap09_t2_prereg_mask_family_2026_06_07.md",
        "date": datetime.now(timezone.utc).isoformat(),
        "n": N, "crib_positions": sorted(CRIBS), "delta": DELTA, "p_gate": P_GATE,
        "rule_set_sha256": rule_hash,
        "pathway2_rule_set_sha256": PATHWAY2_RULE_SET_SHA256,
        "family_hash_matches_pathway2": rule_hash == PATHWAY2_RULE_SET_SHA256,
        "mask_universe_hash": hyp.mask_universe.universe_hash,
        "n_candidate_masks": len(records),
        "n_live_masks": n_live,
        "n_inert_masks": len(records) - n_live,
        "live_masks_note": ("only the uniform-hypergeometric letter-class masks (R2, R5) can EVER clear "
                            "p<=1e-6; the 13 R3 grid-rows have a matched-null floor 1/(1+famsize)~0.08-0.33 "
                            ">> 1e-6 and are pre-registered ONLY as co-location-inert documented negatives. "
                            "R3 masks are contiguous row-CONTENT blocks while O1 is row-START landmarks, so "
                            "their co-location is also a region-vs-boundary category mismatch."),
        "multiplicity_correction": (f"Bonferroni over n_live={n_live} masks (inert R3 contribute 0 to FWER); "
                                    "single observable O1, delta=0"),
        "null_model_assignment": {
            "matched (gap09_t2_colocation_p_matched, same-grammar family)": ["R3"],
            "uniform_hypergeometric (gap09_t2_colocation_p)": ["R2", "R5"],
            "note": "R1 (doubled-letter) and R4 (every-k-th) produced ZERO admissible masks (all intersect cribs)",
        },
        "side_effect_predicate": (
            "MANDATORY 2nd gate beyond crib score: Bean reduction at non-null positions OR ngram-floor "
            "pass on the null-extracted CT73 plaintext. CURRENT STATUS: " + SIDE_EFFECT_STATUS +
            ". This script can therefore emit at most COLOCATION_BUT_SIDE_EFFECT_UNMET; GAP09_ANCHORED "
            "requires a SEPARATE pre-registration that recomputes + hashes a passing side-effect predicate."),
        "side_effect_t3_config": SIDE_EFFECT_T3_CONFIG,
        "decision_rule": "anchor iff (live mask AND Bonferroni p<=1e-6) AND side_effect_met (currently UNMET for all)",
        "observable_lock": OBSERVABLE_LOCK,
        "r2r5_uniform_null_caveat": ("the uniform-hypergeometric null for R2/R5 assumes O1 line-breaks are "
                                     "independent of CT letter content; if a future O1 is found correlated "
                                     "with letter classes, the same matched-null discipline must be applied "
                                     "(a new pre-registration)"),
        "candidate_masks": records,
    }
    frozen["prereg_sha256"] = hashlib.sha256(
        json.dumps({k: v for k, v in frozen.items() if k != "date"},
                   sort_keys=True).encode()).hexdigest()
    return frozen, records


def verify_frozen(outpath: str) -> bool:
    """Tamper-evidence: a fresh deterministic re-freeze must reproduce the stored
    prereg_sha256 / mask_universe_hash. Returns True iff the on-disk artifact
    matches what the (committed) generator produces now."""
    stored = json.load(open(outpath))
    fresh, _ = build_frozen()
    ok = (stored.get("prereg_sha256") == fresh["prereg_sha256"]
          and stored.get("mask_universe_hash") == fresh["mask_universe_hash"]
          and stored.get("rule_set_sha256") == fresh["rule_set_sha256"])
    print(f"[verify] on-disk prereg_sha256 == fresh re-freeze: {ok}")
    if not ok:
        print(f"  stored  prereg_sha256={stored.get('prereg_sha256')}")
        print(f"  fresh   prereg_sha256={fresh['prereg_sha256']}")
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--observable", help="JSON file: list of K4 indices 0-96 (acquired O1)")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--verify", action="store_true", help="check on-disk artifact matches a fresh re-freeze")
    ap.add_argument("--out", default="results/gap09_t2_prereg")
    args = ap.parse_args()

    frozen, records = build_frozen()
    outdir = os.path.join(_ROOT, args.out)
    os.makedirs(outdir, exist_ok=True)
    outpath = os.path.join(outdir, "gap09_t2_prereg_mask_family.json")
    with open(outpath, "w") as f:
        json.dump(frozen, f, indent=2)

    print(f"frozen candidate masks: {len(records)} ({frozen['n_live_masks']} LIVE / "
          f"{frozen['n_inert_masks']} inert)")
    print(f"family hash == pathway-2: {frozen['family_hash_matches_pathway2']}")
    print(f"rule_set_sha256:    {frozen['rule_set_sha256']}")
    print(f"mask_universe_hash: {frozen['mask_universe_hash']}")
    print(f"prereg_sha256:      {frozen['prereg_sha256']}")
    print("null-model: matched={R3 (inert)} ; uniform_hypergeometric={R2,R5 (live)}")
    print(f"side-effect status: {SIDE_EFFECT_STATUS}")
    print(f"observable lock: {OBSERVABLE_LOCK['observable_id']} ({OBSERVABLE_LOCK['cross_observable_policy']})")
    print(f"artifact: {outpath}")

    if args.verify:
        verify_frozen(outpath)

    if args.selftest:
        _selftest(records)

    if args.observable:
        # Tamper-evidence: the frozen artifact MUST match a fresh re-freeze before
        # any closure runs, so a post-O1 edit of the generator cannot be laundered.
        assert verify_frozen(outpath), "frozen artifact does not match generator — refusing closure"
        observable = json.load(open(args.observable))
        assert isinstance(observable, list) and all(isinstance(x, int) for x in observable), \
            "observable must be a JSON list of int K4 indices 0-96"
        result = run_closure(observable, records)
        respath = os.path.join(outdir, "gap09_t2_closure_result.json")
        with open(respath, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\n=== CLOSURE RESULT ===\nverdict: {result['verdict']}")
        print(f"live masks tested: {result['n_live_masks']}  any colocation significant: "
              f"{result['any_colocation_significant']}")
        print(f"side-effect status: {result['side_effect_status']}  (GAP09_ANCHORED unreachable here)")
        print(f"-> {respath}")


if __name__ == "__main__":
    main()
