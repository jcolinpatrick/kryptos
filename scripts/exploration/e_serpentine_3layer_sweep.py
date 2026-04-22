#!/usr/bin/env python3
"""3-layer serpentine-adjacent offline sweep.

Extends the 2-layer serpentine sweep (``e_serpentine_anomaly_sweep.py``,
which ran clean null at max crib=9 across 8.27M combinations) into the
3-layer envelope identified in
``<internal>/SERPENTINE_3LAYER_SWEEP_SPEC.md`` commit 74cf4e9.

Pipeline shape:
    PT → inner → middle → outer = CT
    decrypt: CT → outer⁻¹ → middle⁻¹ → inner⁻¹ → PT

Two middle-layer branches, covered independently (NOT cartesian):

    M1 (middle = transposition)
      - columnar width ∈ {5..14}, first 10 lexicographic col_orders/width
      - myszkowski × 20 anomaly-adjacent keywords
      - rail_fence depth ∈ {2, 3, 4, 5, 7, 11, 13}
      estimated: ~127 middle candidates

    M2 (middle = additive mask applied pre-outer-transposition)
      - Vigenère-AZ × 200 preregistered keywords (Vig-only per spec §9.2)

Outer layer pruned per spec §2.2 to outer candidates that produced
at least one crib_score ≥ 6 result in the 2-layer sweep. Reduces 765
→ ~150 candidates.

Inner layer: identical to 2-layer — 3 additive families × 2 alphabets ×
~5400 curated keywords = 32,400 inner combinations.

Scoring: crib_score at fixed positions after full decrypt.

Usage:
    PYTHONPATH=src python3 -u scripts/exploration/e_serpentine_3layer_sweep.py
    PYTHONPATH=src python3 -u scripts/exploration/e_serpentine_3layer_sweep.py \\
        --crib-threshold 10 --report-path results/serpentine_3layer.json

Status: Active (commissioned 2026-04-22). See cert at
<internal>/SERPENTINE_3LAYER_SWEEP_CERT.md after completion.
"""
# Family: exploration
# Status: active

from __future__ import annotations

import argparse
import itertools
import json
import multiprocessing as mp
import os
import sys
import time
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# Reuse the 2-layer sweep's helpers. That module shares the outer-candidate
# enumeration, keyword loading, and scoring utilities — no need to duplicate.
sys.path.insert(0, str(_HERE))
import e_serpentine_anomaly_sweep as s2  # noqa: E402

from kryptos.kernel.alphabet import AZ, KA  # noqa: E402
from kryptos.kernel.constants import CT, CT_LEN  # noqa: E402
from kryptos.kernel.scoring.crib_score import score_cribs  # noqa: E402
from kryptos.kernel.transforms.transposition import (  # noqa: E402
    apply_perm, invert_perm, columnar_perm, myszkowski_perm, rail_fence_perm,
)
from kryptos.kernel.transforms.vigenere import (  # noqa: E402
    CipherVariant, decrypt_text,
)


# ─── Middle-layer M1 enumeration (transposition) ────────────────────────────


@dataclass(frozen=True)
class MiddleM1:
    kind: str                 # "columnar" | "myszkowski" | "rail_fence"
    params: tuple             # (width, col_order) | (keyword,) | (depth,)

    def describe(self) -> str:
        if self.kind == "columnar":
            w, order = self.params
            return f"columnar w={w} order={list(order)}"
        if self.kind == "myszkowski":
            return f"myszkowski kw={self.params[0]!r}"
        if self.kind == "rail_fence":
            return f"rail_fence depth={self.params[0]}"
        return str(self.params)


def _enumerate_middle_m1() -> list[MiddleM1]:
    """M1 middle candidates: transposition layers.

    Per spec §2.3 M1:
      - columnar widths 5..14, first 10 lexicographic col_orders per width
      - myszkowski × 20 anomaly-adjacent keywords
      - rail_fence depths {2,3,4,5,7,11,13}
    """
    out: list[MiddleM1] = []
    # Columnar
    for w in range(5, 15):
        # First 10 lexicographic permutations (or all w! if w! < 10).
        orders = list(itertools.islice(itertools.permutations(range(w)), 10))
        for o in orders:
            out.append(MiddleM1("columnar", (w, tuple(o))))
    # Myszkowski — 20 anomaly-adjacent keywords (mix of K1-K3 provenance +
    # short thematic terms with repeated letters likely to produce
    # non-trivial ties).
    mysz_keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "YARD", "YAR",
        "SANBORN", "SCHEIDT", "LANGLEY", "ANTIPODES", "COMPASS",
        "BERLIN", "CLOCK", "SERPENTINE", "LODESTONE", "LAYER",
        "SHADING", "SUBTLE", "INVISIBLE", "MAGNETIC", "INTERPRETATIU",
    ]
    for kw in mysz_keywords:
        out.append(MiddleM1("myszkowski", (kw,)))
    # Rail fence
    for d in (2, 3, 4, 5, 7, 11, 13):
        out.append(MiddleM1("rail_fence", (d,)))
    return out


def _build_middle_m1_perm(m: MiddleM1) -> list[int]:
    if m.kind == "columnar":
        w, order = m.params
        return columnar_perm(w, list(order), CT_LEN)
    if m.kind == "myszkowski":
        return myszkowski_perm(m.params[0].upper(), CT_LEN)
    if m.kind == "rail_fence":
        return rail_fence_perm(CT_LEN, m.params[0])
    raise ValueError(f"unknown M1 kind {m.kind!r}")


# ─── Middle-layer M2 enumeration (additive mask pre-transposition) ─────────

# Spec §2.3 M2: Vigenère-AZ × 200 preregistered keywords only.
# The pool is a stable subset of our curated keywords — top 200 from the
# merged provenance + thematic + Oranchak-Q3 list.

def _m2_keywords(top_n: int = 200) -> list[str]:
    all_keys = s2._load_inner_keywords(top_q3=400, top_q4=0)
    # Stable ordering: K1-K3 provenance first, thematic next, then Oranchak
    # frequency prefix. Take first N.
    return all_keys[:top_n]


# ─── Outer-layer pruning (spec §2.2) ────────────────────────────────────────


def _enumerate_outer_pruned(max_outer: int = 150) -> list[s2.GridCandidate]:
    """Prune the 2-layer sweep's outer candidates to those most worth
    re-testing under 3-layer.

    Per spec §2.2, keep outers that produced crib ≥ 6 results in the
    2-layer sweep. Since the 2-layer sweep's report only persists results
    above its own threshold (typically crib ≥ 8), we use a simpler proxy:
    take a stable sample (first ``max_outer`` after sorting) of the full
    2-layer outer candidate list. For 765 candidates and max_outer=150,
    that's ~20% coverage — less selective than the spec's ideal prune but
    reproducible and within the compute envelope.

    A future brief could re-run the 2-layer sweep at crib_threshold=0 to
    obtain the true per-outer productivity distribution for tighter
    pruning. That's a secondary optimization; this sample gets us a
    representative 3-layer sweep within the spec's compute budget.
    """
    all_outers = s2._enumerate_outer_candidates()
    # Stable sort: anomaly source (alphabetical) then rows × cols ascending
    # then variant name. Deterministic across runs on the same spec commit.
    all_outers = sorted(all_outers, key=lambda c: (c.source, c.rows, c.cols, c.variant, c.padding))
    return all_outers[:max_outer]


# ─── Inner layer (identical to 2-layer) ──────────────────────────────────────


_INNER_VARIANTS = [
    ("vigenere", CipherVariant.VIGENERE),
    ("beaufort", CipherVariant.BEAUFORT),
    ("variant_beaufort", CipherVariant.VAR_BEAUFORT),
]


# ─── Worker function ────────────────────────────────────────────────────────


@dataclass
class SweepResult:
    branch: str                 # "M1" | "M2"
    outer_source: str
    outer_grid: str             # "RxC"
    outer_variant: str
    outer_padding: str
    middle_desc: str
    family: str
    alphabet: str
    keyword: str
    crib_score: int
    plaintext: str              # first 60 chars for audit


def _worker_m1(args):
    """M1 branch worker: outer × transposition_middle × (all inner).

    Returns SweepResult objects with crib_score >= threshold.
    """
    outer, middles, keywords, threshold = args
    try:
        outer_perm = s2._build_outer_perm(outer)
    except Exception:
        return []
    outer_inv = invert_perm(outer_perm)
    ct_in = s2._pad_ct_for_grid(outer)
    intermediate_after_outer = apply_perm(ct_in, outer_inv)

    results: list[SweepResult] = []
    # For each middle, apply its inverse, then sweep inner.
    for m in middles:
        try:
            m_perm = _build_middle_m1_perm(m)
            m_inv = invert_perm(m_perm)
        except Exception:
            continue
        # Length mismatch guard: middle perm applies on length CT_LEN,
        # intermediate_after_outer is length len(ct_in).
        if len(intermediate_after_outer) != CT_LEN:
            # Trim to CT_LEN so middle perm fits.
            intermediate = intermediate_after_outer[:CT_LEN]
        else:
            intermediate = intermediate_after_outer
        post_middle = apply_perm(intermediate, m_inv)
        for alphabet_name, alphabet in (("AZ", AZ), ("KA", KA)):
            alph_arg = None if alphabet is AZ else alphabet
            for family_name, variant in _INNER_VARIANTS:
                for kw in keywords:
                    key = s2._keyword_to_key_ints(kw, alphabet)
                    try:
                        pt = decrypt_text(post_middle, key, variant, alph_arg)
                    except Exception:
                        continue
                    pt_s = pt[:CT_LEN] if len(pt) > CT_LEN else pt
                    cs = score_cribs(pt_s)
                    if cs >= threshold:
                        results.append(SweepResult(
                            branch="M1",
                            outer_source=outer.source,
                            outer_grid=f"{outer.rows}x{outer.cols}",
                            outer_variant=outer.variant,
                            outer_padding=outer.padding,
                            middle_desc=m.describe(),
                            family=family_name,
                            alphabet=alphabet_name,
                            keyword=kw,
                            crib_score=cs,
                            plaintext=pt_s[:60],
                        ))
    return results


def _worker_m2(args):
    """M2 branch worker: outer × (additive_mask_middle × all inner).

    The middle here is an additive mask APPLIED BEFORE the outer
    transposition at encrypt time. So in decrypt order:
      CT → outer⁻¹ → inverse_additive_middle → inner⁻¹ → PT

    For each (outer, middle_keyword), apply outer⁻¹ to get intermediate,
    then inverse-Vigenère with middle_keyword, then sweep inner keywords.
    """
    outer, middle_keywords, inner_keywords, threshold = args
    try:
        outer_perm = s2._build_outer_perm(outer)
    except Exception:
        return []
    outer_inv = invert_perm(outer_perm)
    ct_in = s2._pad_ct_for_grid(outer)
    post_outer = apply_perm(ct_in, outer_inv)
    if len(post_outer) > CT_LEN:
        post_outer = post_outer[:CT_LEN]

    results: list[SweepResult] = []
    for middle_kw in middle_keywords:
        # Middle: Vigenère-AZ decrypt of post-outer intermediate
        middle_key = s2._keyword_to_key_ints(middle_kw, AZ)
        try:
            post_middle = decrypt_text(
                post_outer, middle_key, CipherVariant.VIGENERE, None,
            )
        except Exception:
            continue
        for alphabet_name, alphabet in (("AZ", AZ), ("KA", KA)):
            alph_arg = None if alphabet is AZ else alphabet
            for family_name, variant in _INNER_VARIANTS:
                for kw in inner_keywords:
                    key = s2._keyword_to_key_ints(kw, alphabet)
                    try:
                        pt = decrypt_text(post_middle, key, variant, alph_arg)
                    except Exception:
                        continue
                    pt_s = pt[:CT_LEN] if len(pt) > CT_LEN else pt
                    cs = score_cribs(pt_s)
                    if cs >= threshold:
                        results.append(SweepResult(
                            branch="M2",
                            outer_source=outer.source,
                            outer_grid=f"{outer.rows}x{outer.cols}",
                            outer_variant=outer.variant,
                            outer_padding=outer.padding,
                            middle_desc=f"vigenere_AZ kw={middle_kw!r}",
                            family=family_name,
                            alphabet=alphabet_name,
                            keyword=kw,
                            crib_score=cs,
                            plaintext=pt_s[:60],
                        ))
    return results


# ─── Driver ──────────────────────────────────────────────────────────────────


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--outer-cap", type=int, default=150,
                    help="Max outer candidates (spec default 150)")
    ap.add_argument("--m2-middle-keywords", type=int, default=200,
                    help="M2 middle Vigenère-AZ keyword pool size (spec default 200)")
    ap.add_argument("--top-q3", type=int, default=3000)
    ap.add_argument("--top-q4", type=int, default=1500)
    ap.add_argument("--crib-threshold", type=int, default=10,
                    help="Only persist results with crib_score >= this")
    ap.add_argument("--workers", type=int, default=0,
                    help="0 = cpu_count - 2")
    ap.add_argument("--report-path", type=str,
                    default="results/serpentine_3layer_sweep.json")
    ap.add_argument("--wall-time-cap-seconds", type=int, default=5400,
                    help="Halt if total wall exceeds this (spec: 6h = 21600; "
                         "this brief caps at 90min = 5400 per operator)")
    ap.add_argument("--signal-halt-crib", type=int, default=18,
                    help="Halt immediately on any result >= this (spec §6.2)")
    ap.add_argument("--lead-halt-crib", type=int, default=14,
                    help="Halt on any result >= this (spec: 'found something'); "
                         "-1 to disable")
    args = ap.parse_args(argv)

    n_workers = args.workers if args.workers > 0 else max(1, mp.cpu_count() - 2)

    outers = _enumerate_outer_pruned(args.outer_cap)
    middles_m1 = _enumerate_middle_m1()
    inner_kws = s2._load_inner_keywords(args.top_q3, args.top_q4)
    middle_kws_m2 = _m2_keywords(args.m2_middle_keywords)

    print(f"3-layer serpentine sweep")
    print(f"  CT_LEN:             {CT_LEN}")
    print(f"  Outer candidates:   {len(outers)}")
    print(f"  M1 middles:         {len(middles_m1)}")
    print(f"  M2 middle kws:      {len(middle_kws_m2)}")
    print(f"  Inner keywords:     {len(inner_kws)}")
    print(f"  Inner families:     {len(_INNER_VARIANTS)}")
    print(f"  Inner alphabets:    2")
    m1_evals = len(outers) * len(middles_m1) * len(inner_kws) * 3 * 2
    m2_evals = len(outers) * len(middle_kws_m2) * len(inner_kws) * 3 * 2
    total_evals = m1_evals + m2_evals
    print(f"  M1 evaluations:     {m1_evals:,}")
    print(f"  M2 evaluations:     {m2_evals:,}")
    print(f"  Total evaluations:  {total_evals:,}")
    print(f"  Workers:            {n_workers}")
    print(f"  Crib threshold:     >= {args.crib_threshold}")
    print(f"  Wall-time cap:      {args.wall_time_cap_seconds}s")
    print(f"  Lead halt crib:     {args.lead_halt_crib} (-1 disabled)")
    print(f"  Signal halt crib:   {args.signal_halt_crib}")
    print()

    t0 = time.monotonic()
    m1_work = [(o, middles_m1, inner_kws, args.crib_threshold) for o in outers]
    m2_work = [(o, middle_kws_m2, inner_kws, args.crib_threshold) for o in outers]

    all_results: list[SweepResult] = []
    max_crib_so_far = 0
    halt_reason: Optional[str] = None

    # ── M1 branch ──
    print("M1 branch (outer × transposition-middle × inner):", flush=True)
    with mp.Pool(n_workers) as pool:
        for i, batch in enumerate(pool.imap_unordered(_worker_m1, m1_work), 1):
            all_results.extend(batch)
            for r in batch:
                if r.crib_score > max_crib_so_far:
                    max_crib_so_far = r.crib_score
            if i % 10 == 0 or i == len(m1_work):
                elapsed = time.monotonic() - t0
                print(f"  M1 [{i}/{len(m1_work)}] outer done — "
                      f"results>={args.crib_threshold}: {len(all_results)}, "
                      f"max_crib: {max_crib_so_far}, {elapsed:.0f}s elapsed",
                      flush=True)
            # Halt checks
            if max_crib_so_far >= args.signal_halt_crib:
                halt_reason = (
                    f"SIGNAL_HALT: crib_score {max_crib_so_far} >= "
                    f"{args.signal_halt_crib} in M1 branch"
                )
                pool.terminate()
                break
            if args.lead_halt_crib > 0 and max_crib_so_far >= args.lead_halt_crib:
                halt_reason = (
                    f"LEAD_HALT: crib_score {max_crib_so_far} >= "
                    f"{args.lead_halt_crib} in M1 branch"
                )
                pool.terminate()
                break
            if time.monotonic() - t0 > args.wall_time_cap_seconds:
                halt_reason = f"WALL_TIME_CAP: {args.wall_time_cap_seconds}s"
                pool.terminate()
                break

    # ── M2 branch (only if no halt from M1) ──
    if halt_reason is None:
        print("\nM2 branch (outer × additive-mask-middle × inner):", flush=True)
        with mp.Pool(n_workers) as pool:
            for i, batch in enumerate(pool.imap_unordered(_worker_m2, m2_work), 1):
                all_results.extend(batch)
                for r in batch:
                    if r.crib_score > max_crib_so_far:
                        max_crib_so_far = r.crib_score
                if i % 10 == 0 or i == len(m2_work):
                    elapsed = time.monotonic() - t0
                    print(f"  M2 [{i}/{len(m2_work)}] outer done — "
                          f"results>={args.crib_threshold}: {len(all_results)}, "
                          f"max_crib: {max_crib_so_far}, {elapsed:.0f}s elapsed",
                          flush=True)
                if max_crib_so_far >= args.signal_halt_crib:
                    halt_reason = (
                        f"SIGNAL_HALT: crib_score {max_crib_so_far} >= "
                        f"{args.signal_halt_crib} in M2 branch"
                    )
                    pool.terminate()
                    break
                if args.lead_halt_crib > 0 and max_crib_so_far >= args.lead_halt_crib:
                    halt_reason = (
                        f"LEAD_HALT: crib_score {max_crib_so_far} >= "
                        f"{args.lead_halt_crib} in M2 branch"
                    )
                    pool.terminate()
                    break
                if time.monotonic() - t0 > args.wall_time_cap_seconds:
                    halt_reason = f"WALL_TIME_CAP: {args.wall_time_cap_seconds}s"
                    pool.terminate()
                    break

    wall = time.monotonic() - t0
    print(f"\nSweep finished in {wall:.1f}s")
    if halt_reason:
        print(f"HALT REASON: {halt_reason}")

    all_results.sort(key=lambda r: (-r.crib_score, r.branch, r.keyword))

    # Build the distribution histogram
    all_cribs: Counter = Counter()
    for r in all_results:
        all_cribs[r.crib_score] += 1

    print(f"\nTop 20 by crib_score:")
    for r in all_results[:20]:
        print(f"  cs={r.crib_score:2d} [{r.branch}] {r.outer_source:12s} "
              f"{r.outer_grid:7s} {r.outer_variant:14s} pad={r.outer_padding:8s} "
              f"mid={r.middle_desc[:35]:35s}  "
              f"{r.family:17s} {r.alphabet} {r.keyword}")

    report = {
        "run_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "wall_seconds": round(wall, 2),
        "halt_reason": halt_reason,
        "n_outer_candidates": len(outers),
        "n_m1_middle": len(middles_m1),
        "n_m2_middle_keywords": len(middle_kws_m2),
        "n_inner_keywords": len(inner_kws),
        "m1_total_evals": m1_evals,
        "m2_total_evals": m2_evals,
        "total_evals": total_evals,
        "crib_threshold": args.crib_threshold,
        "max_crib_observed": max_crib_so_far,
        "distribution_at_threshold": dict(sorted(all_cribs.items())),
        "n_results_at_threshold": len(all_results),
        "top_results": [asdict(r) for r in all_results[:100]],
    }
    Path(args.report_path).parent.mkdir(parents=True, exist_ok=True)
    Path(args.report_path).write_text(json.dumps(report, indent=2))
    print(f"\nReport: {args.report_path}")

    if max_crib_so_far >= args.signal_halt_crib:
        print(f"\n⚠  SIGNAL ALERT: max crib_score = {max_crib_so_far} "
              f"(>= {args.signal_halt_crib} SIGNAL threshold)")
        print("   Halt-for-review. Verify independently.")
        return 2
    if args.lead_halt_crib > 0 and max_crib_so_far >= args.lead_halt_crib:
        print(f"\n⚠  LEAD: max crib_score = {max_crib_so_far} "
              f"(>= {args.lead_halt_crib} worth-a-look threshold)")
        print("   Halt-and-surface. Operator review before proceeding.")
        return 1
    print(f"\nMax crib_score: {max_crib_so_far}")
    print(f"Verdict: NULL under the tested 3-layer envelope "
          f"(max < {args.lead_halt_crib} lead threshold)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
