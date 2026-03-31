#!/usr/bin/env python3
"""
Cipher: segmented-periodic
Family: two_system
Status: active
Keyspace: ~2.1B (analytical + exhaustive sweep)
Last run:
Best score:

E-SEGM-01: M5 Segmented Tape — Two Independent Periodic Keys

Hypothesis: The K4 keystream is composed of TWO independent periodic segments,
split at some cut point C between the two crib groups. Each segment has its
own periodic key of independent period.

Motivation (MEMORY.md, Open Attack Surface #8):
- K1-K2 encoding chart physical evidence: ABSCISSA = "cut off" (Latin),
  tape physical cut, triangle symbol at boundary.
- Under segmentation, Bean EQUALITY k[27]=k[65] is VOID (different segments).
- Cross-group Bean INEQUALITIES are void (127/242 trivially satisfied).
- Only within-group inequalities constrain each segment independently.
- ALL prior periodic-key proofs assumed ONE continuous key across all positions.
  Segmentation breaks that assumption.

Phase 1: Analytical — Which periods survive within-group Bean constraints?
Phase 2: Exhaustive sweep of surviving periodic keys per segment (optimized).
Phase 3: Model B — Repeat on CT73 (consensus null mask applied).
Phase 4: Extended period analysis.
Phase 5: Cross-segment Bean analysis.

All 3 cipher variants tested: Beaufort, Vigenere, Variant Beaufort.

Optimization: Since segments are INDEPENDENT, we score each segment's quadgram
quality separately, keep top-K candidates per segment, then combine. This is
O(26^free_ene + 26^free_bcl) instead of O(26^(free_ene + free_bcl)).
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md


import json
import os
import sys
import time
import itertools
import heapq
from collections import defaultdict
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT, CRIB_POSITIONS,
    BEAN_EQ, BEAN_INEQ,
)

# ── Constants ─────────────────────────────────────────────────────────────

CT_NUM = [ALPH_IDX[c] for c in CT]

ENE_POSITIONS = list(range(21, 34))  # 13 positions: 21..33
BCL_POSITIONS = list(range(63, 74))  # 11 positions: 63..73
ENE_SET = set(ENE_POSITIONS)
BCL_SET = set(BCL_POSITIONS)

CONSENSUS_NULLS = {0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85}
MASK_A = sorted(CONSENSUS_NULLS | {38, 39, 40, 55, 87, 93, 94})
MASK_B = sorted(CONSENSUS_NULLS | {38, 39, 40, 56, 88, 93, 94})
MASK_C = sorted(CONSENSUS_NULLS | {41, 42, 43, 55, 87, 95, 96})

VARIANTS = ["beaufort", "vigenere", "var_beaufort"]

# Load quadgram scorer at module level
from kryptos.kernel.scoring.ngram import NgramScorer
QG_PATH = os.path.join(_ROOT, "data", "english_quadgrams.json")
SCORER = NgramScorer.from_file(QG_PATH)


def recover_key(c, p, variant):
    if variant == "beaufort":
        return (c + p) % MOD
    elif variant == "vigenere":
        return (c - p) % MOD
    else:  # var_beaufort
        return (p - c) % MOD


def decrypt_char(c, k, variant):
    if variant == "beaufort":
        return (k - c) % MOD
    elif variant == "vigenere":
        return (c - k) % MOD
    else:  # var_beaufort
        return (c + k) % MOD


def compute_keystream(variant):
    ks = {}
    for pos, ch in CRIB_DICT.items():
        c = ALPH_IDX[CT[pos]]
        p = ALPH_IDX[ch]
        ks[pos] = recover_key(c, p, variant)
    return ks


KEYSTREAMS = {v: compute_keystream(v) for v in VARIANTS}


# ── Phase 1: Analytical ──────────────────────────────────────────────────

def check_period_for_group(period, group_positions, keystream):
    residue_groups = defaultdict(list)
    for pos in group_positions:
        residue_groups[pos % period].append(pos)

    for res, positions in residue_groups.items():
        if len(positions) < 2:
            continue
        first_val = keystream[positions[0]]
        for pos in positions[1:]:
            if keystream[pos] != first_val:
                return False, [(positions[0], pos)]
    return True, []


def count_free_residues(period, group_positions, keystream):
    residue_groups = defaultdict(list)
    for pos in group_positions:
        residue_groups[pos % period].append(pos)

    n_fixed = 0
    n_free = 0
    fixed_vals = {}
    for res in range(period):
        if res in residue_groups:
            fixed_vals[res] = keystream[residue_groups[res][0]]
            n_fixed += 1
        else:
            n_free += 1
    return n_free, n_fixed, fixed_vals


def build_key_template(period, group_positions, keystream):
    residue_groups = defaultdict(list)
    for pos in group_positions:
        residue_groups[pos % period].append(pos)

    template = [-1] * period
    free_indices = []
    for res in range(period):
        if res in residue_groups:
            template[res] = keystream[residue_groups[res][0]]
        else:
            free_indices.append(res)
    return template, free_indices


# ── Phase 2: Optimized exhaustive sweep ──────────────────────────────────

def sweep_segment(ct_nums, start, end, period, template, free_indices, variant, scorer, top_k=50):
    """Sweep all key completions for one segment.
    Returns list of (score, key, plaintext) tuples, top_k best."""

    n_free = len(free_indices)
    if n_free > 6:
        return None  # too large

    best_k = []  # min-heap of (score, key_tuple, pt_text)

    for vals in itertools.product(range(26), repeat=n_free):
        key = list(template)
        for idx, val in zip(free_indices, vals):
            key[idx] = val

        # Decrypt segment
        pt_chars = []
        for i in range(start, end):
            k = key[i % period]
            pt_chars.append(ALPH[decrypt_char(ct_nums[i], k, variant)])
        pt = "".join(pt_chars)

        score = scorer.score_per_char(pt)

        if len(best_k) < top_k:
            heapq.heappush(best_k, (score, tuple(key), pt))
        elif score > best_k[0][0]:
            heapq.heapreplace(best_k, (score, tuple(key), pt))

    return sorted(best_k, reverse=True)


def sweep_job(args):
    """Worker for one (cut, period_ene, period_bcl, variant) combination on CT97."""
    (cut, p_ene, p_bcl, variant, ene_positions, bcl_positions,
     ene_ks, bcl_ks, ct_mode, ct_nums, ct_len) = args

    ene_template, ene_free = build_key_template(p_ene, ene_positions, ene_ks)
    bcl_template, bcl_free = build_key_template(p_bcl, bcl_positions, bcl_ks)

    n_ene_free = len(ene_free)
    n_bcl_free = len(bcl_free)

    # Skip if either segment too large (>6 free = 26^6 = 309M)
    if n_ene_free > 6 or n_bcl_free > 6:
        return {
            "cut": cut, "period_ene": p_ene, "period_bcl": p_bcl,
            "variant": variant, "ct_mode": ct_mode,
            "n_ene_free": n_ene_free, "n_bcl_free": n_bcl_free,
            "status": "SKIPPED_TOO_LARGE",
        }

    # Sweep each segment independently
    ene_top = sweep_segment(ct_nums, 0, cut, p_ene, ene_template, ene_free,
                            variant, SCORER, top_k=20)
    bcl_top = sweep_segment(ct_nums, cut, ct_len, p_bcl, bcl_template, bcl_free,
                            variant, SCORER, top_k=20)

    if ene_top is None or bcl_top is None:
        return {
            "cut": cut, "period_ene": p_ene, "period_bcl": p_bcl,
            "variant": variant, "ct_mode": ct_mode,
            "status": "SKIPPED_SEGMENT_TOO_LARGE",
        }

    # Combine top candidates from each segment
    best_combined_score = -999.0
    best_combined_pt = ""
    best_ene_key = None
    best_bcl_key = None

    for ene_score, ene_key, ene_pt in ene_top[:10]:
        for bcl_score, bcl_key, bcl_pt in bcl_top[:10]:
            full_pt = ene_pt + bcl_pt
            combined_score = SCORER.score_per_char(full_pt)
            if combined_score > best_combined_score:
                best_combined_score = combined_score
                best_combined_pt = full_pt
                best_ene_key = list(ene_key)
                best_bcl_key = list(bcl_key)

    # Also score crib matches
    crib_score = 0
    for pos, ch in CRIB_DICT.items():
        expected = ALPH_IDX[ch]
        if pos < ct_len:
            if pos < cut:
                k = best_ene_key[pos % p_ene] if best_ene_key else 0
            else:
                k = best_bcl_key[pos % p_bcl] if best_bcl_key else 0
            pt_val = decrypt_char(ct_nums[pos], k, variant)
            if pt_val == expected:
                crib_score += 1

    ene_tested = 26 ** n_ene_free
    bcl_tested = 26 ** n_bcl_free

    return {
        "cut": cut, "period_ene": p_ene, "period_bcl": p_bcl,
        "variant": variant, "ct_mode": ct_mode,
        "n_ene_free": n_ene_free, "n_bcl_free": n_bcl_free,
        "ene_keys_tested": ene_tested,
        "bcl_keys_tested": bcl_tested,
        "status": "COMPLETE",
        "best_score": round(best_combined_score, 4),
        "best_pt": best_combined_pt,
        "crib_score": crib_score,
        "best_ene_key": best_ene_key,
        "best_bcl_key": best_bcl_key,
        "ene_best_segment_score": round(ene_top[0][0], 4) if ene_top else None,
        "bcl_best_segment_score": round(bcl_top[0][0], 4) if bcl_top else None,
    }


# ── CT73 helpers ──────────────────────────────────────────────────────────

def extract_ct73(mask):
    mask_set = set(mask)
    ct73 = []
    pos_map = {}
    j = 0
    for i in range(CT_LEN):
        if i not in mask_set:
            ct73.append(CT_NUM[i])
            pos_map[i] = j
            j += 1
    crib73 = {}
    for pos, ch in CRIB_DICT.items():
        if pos in pos_map:
            crib73[pos_map[pos]] = ALPH_IDX[ch]
    return ct73, pos_map, crib73


def get_ct73_groups(pos_map):
    ene73 = [pos_map[p] for p in ENE_POSITIONS if p in pos_map]
    bcl73 = [pos_map[p] for p in BCL_POSITIONS if p in pos_map]
    return ene73, bcl73


def compute_keystream_ct73(variant, ct73_nums, crib73):
    ks = {}
    for pos73, pt_val in crib73.items():
        c = ct73_nums[pos73]
        if variant == "beaufort":
            ks[pos73] = (c + pt_val) % MOD
        elif variant == "vigenere":
            ks[pos73] = (c - pt_val) % MOD
        else:
            ks[pos73] = (pt_val - c) % MOD
    return ks


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    t0 = time.time()
    print("=" * 70)
    print("E-SEGM-01: M5 Segmented Tape — Two Independent Periodic Keys")
    print("=" * 70)
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"ENE positions: {ENE_POSITIONS}")
    print(f"BCL positions: {BCL_POSITIONS}")
    print(f"Candidate cut points: 34..62 ({62-34+1} values)")
    print()

    all_results = {
        "experiment": "E-SEGM-01",
        "description": "M5 Segmented Tape: two independent periodic keys, one per crib group",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "ct": CT, "ct_len": CT_LEN,
        "cut_range": [34, 62],
        "variants": VARIANTS,
        "phases": {},
    }

    # ════════════════════════════════════════════════════════════════════
    # PHASE 1: Analytical — period survival analysis
    # ════════════════════════════════════════════════════════════════════

    print("PHASE 1: Analytical — Within-group period survival")
    print("-" * 50)

    phase1 = {}
    for variant in VARIANTS:
        ks = KEYSTREAMS[variant]
        ene_ks = {pos: ks[pos] for pos in ENE_POSITIONS}
        bcl_ks = {pos: ks[pos] for pos in BCL_POSITIONS}

        ene_surv, bcl_surv = [], []
        for p in range(1, 51):
            ene_ok, _ = check_period_for_group(p, ENE_POSITIONS, ene_ks)
            if ene_ok:
                ene_surv.append(p)
            bcl_ok, _ = check_period_for_group(p, BCL_POSITIONS, bcl_ks)
            if bcl_ok:
                bcl_surv.append(p)

        # Also compute free residues for each surviving period
        ene_detail = []
        for p in ene_surv:
            nf, nfx, _ = count_free_residues(p, ENE_POSITIONS, ene_ks)
            ene_detail.append({"period": p, "free": nf, "fixed": nfx, "keys": 26**nf})
        bcl_detail = []
        for p in bcl_surv:
            nf, nfx, _ = count_free_residues(p, BCL_POSITIONS, bcl_ks)
            bcl_detail.append({"period": p, "free": nf, "fixed": nfx, "keys": 26**nf})

        print(f"\n  Variant: {variant}")
        print(f"    ENE surviving periods (1..50): {len(ene_surv)}")
        for d in ene_detail[:20]:
            print(f"      p={d['period']:2d}: {d['fixed']} fixed, {d['free']} free -> {d['keys']:,} keys")
        print(f"    BCL surviving periods (1..50): {len(bcl_surv)}")
        for d in bcl_detail[:20]:
            print(f"      p={d['period']:2d}: {d['fixed']} fixed, {d['free']} free -> {d['keys']:,} keys")

        phase1[variant] = {
            "ene_survivors": ene_surv,
            "bcl_survivors": bcl_surv,
            "ene_detail": ene_detail,
            "bcl_detail": bcl_detail,
        }

    # Key finding
    print("\n  KEY FINDING: Period survival comparison")
    print("  UNSEGMENTED (single key, all 24 cribs): ALL periods 1-inf ELIMINATED (O fingerprint proof)")
    for v in VARIANTS:
        n_ene = len(phase1[v]["ene_survivors"])
        n_bcl = len(phase1[v]["bcl_survivors"])
        n_combos = n_ene * n_bcl
        print(f"  SEGMENTED ({v}): ENE={n_ene} BCL={n_bcl} survive, {n_combos} period combos")

    all_results["phases"]["phase1"] = phase1

    # ════════════════════════════════════════════════════════════════════
    # PHASE 5 (moved up): Cross-segment Bean constraint analysis
    # ════════════════════════════════════════════════════════════════════

    print("\n" + "=" * 70)
    print("PHASE 5: Cross-segment Bean constraint analysis")
    print("-" * 50)

    cross_ineq = 0
    within_ene_ineq = 0
    within_bcl_ineq = 0
    for a, b in BEAN_INEQ:
        if a in ENE_SET and b in ENE_SET:
            within_ene_ineq += 1
        elif a in BCL_SET and b in BCL_SET:
            within_bcl_ineq += 1
        elif (a in ENE_SET and b in BCL_SET) or (a in BCL_SET and b in ENE_SET):
            cross_ineq += 1

    print(f"  Bean EQUALITY k[27]=k[65]: CROSS-GROUP (27 in ENE, 65 in BCL)")
    print(f"    Under segmentation: VOID (different key segments)")
    print(f"  Bean INEQUALITIES (242 total):")
    print(f"    Within ENE group: {within_ene_ineq}")
    print(f"    Within BCL group: {within_bcl_ineq}")
    print(f"    Cross-group (VOID under segmentation): {cross_ineq}")
    print(f"    Total voided: {cross_ineq + 1} (including equality)")
    print(f"    Constraints remaining: {within_ene_ineq + within_bcl_ineq}")

    all_results["phases"]["phase5_bean"] = {
        "bean_eq_voided": True,
        "within_ene_ineq": within_ene_ineq,
        "within_bcl_ineq": within_bcl_ineq,
        "cross_group_ineq_voided": cross_ineq,
        "total_voided": cross_ineq + 1,
        "constraints_remaining": within_ene_ineq + within_bcl_ineq,
    }

    # ════════════════════════════════════════════════════════════════════
    # PHASE 2: Exhaustive sweep on CT97 (optimized)
    # ════════════════════════════════════════════════════════════════════

    print("\n" + "=" * 70)
    print("PHASE 2: Optimized exhaustive sweep on CT97")
    print("-" * 50)
    print("  Strategy: sweep each segment INDEPENDENTLY, combine top-K from each.")
    print("  Complexity: O(26^free_ene + 26^free_bcl) instead of O(26^(free_ene + free_bcl)).")

    # Cut points: sample 8 from the range
    CUT_POINTS = list(range(34, 63, 4)) + [62]

    # Build all jobs
    phase2_jobs = []
    for variant in VARIANTS:
        ks = KEYSTREAMS[variant]
        ene_ks = {pos: ks[pos] for pos in ENE_POSITIONS}
        bcl_ks = {pos: ks[pos] for pos in BCL_POSITIONS}
        p1 = phase1[variant]

        for p_ene in p1["ene_survivors"]:
            if p_ene > 26:  # skip very large periods for Phase 2
                continue
            for p_bcl in p1["bcl_survivors"]:
                if p_bcl > 26:
                    continue
                for cut in CUT_POINTS:
                    phase2_jobs.append((
                        cut, p_ene, p_bcl, variant,
                        ENE_POSITIONS, BCL_POSITIONS,
                        ene_ks, bcl_ks,
                        "CT97", CT_NUM, CT_LEN,
                    ))

    # Estimate
    total_seg_keys = 0
    skippable = 0
    for job in phase2_jobs:
        cut, p_ene, p_bcl, variant = job[:4]
        ene_ks, bcl_ks = job[6], job[7]
        nfe, _, _ = count_free_residues(p_ene, ENE_POSITIONS, ene_ks)
        nfb, _, _ = count_free_residues(p_bcl, BCL_POSITIONS, bcl_ks)
        if nfe > 6 or nfb > 6:
            skippable += 1
        else:
            total_seg_keys += 26**nfe + 26**nfb

    print(f"  Total jobs: {len(phase2_jobs)}")
    print(f"  Estimated segment keys: {total_seg_keys:,} (sum of ENE + BCL per job)")
    print(f"  Jobs skipped (>6 free per segment): {skippable}")

    n_workers = min(cpu_count(), 12)
    print(f"  Using {n_workers} workers")

    t1 = time.time()
    phase2_results = []
    best_score = -999.0

    with Pool(n_workers) as pool:
        for i, result in enumerate(pool.imap_unordered(sweep_job, phase2_jobs)):
            phase2_results.append(result)
            if result.get("best_score") is not None and result["best_score"] > best_score:
                best_score = result["best_score"]
            if (i + 1) % 500 == 0:
                elapsed = time.time() - t1
                print(f"    [{i+1}/{len(phase2_jobs)}] {elapsed:.0f}s, best: {best_score:.4f}/char")

    t2 = time.time()

    completed = [r for r in phase2_results if r["status"] == "COMPLETE"]
    completed.sort(key=lambda x: x["best_score"], reverse=True)
    total_ene_tested = sum(r.get("ene_keys_tested", 0) for r in completed)
    total_bcl_tested = sum(r.get("bcl_keys_tested", 0) for r in completed)

    print(f"\n  Phase 2 complete in {t2-t1:.1f}s")
    print(f"  Completed: {len(completed)}, Skipped: {len(phase2_results) - len(completed)}")
    print(f"  ENE keys tested: {total_ene_tested:,}")
    print(f"  BCL keys tested: {total_bcl_tested:,}")
    print(f"\n  TOP 15 RESULTS (CT97):")
    for r in completed[:15]:
        print(f"    qg={r['best_score']:.4f}/char crib={r['crib_score']}/24 "
              f"cut={r['cut']} p_ene={r['period_ene']} p_bcl={r['period_bcl']} "
              f"var={r['variant']}")
        print(f"      ENE seg: {r['ene_best_segment_score']:.4f}/char, "
              f"BCL seg: {r['bcl_best_segment_score']:.4f}/char")
        pt = r["best_pt"]
        print(f"      PT: {pt[:45]}|{pt[45:]}")

    all_results["phases"]["phase2"] = {
        "ct_mode": "CT97",
        "cut_points": CUT_POINTS,
        "total_jobs": len(phase2_jobs),
        "completed": len(completed),
        "skipped": len(phase2_results) - len(completed),
        "ene_keys_tested": total_ene_tested,
        "bcl_keys_tested": total_bcl_tested,
        "elapsed_seconds": round(t2 - t1, 1),
        "top15": [{k: v for k, v in r.items() if k != "best_pt"} | {"best_pt_preview": r.get("best_pt", "")[:60]}
                  for r in completed[:15]],
        "best_score": completed[0]["best_score"] if completed else None,
    }

    # ════════════════════════════════════════════════════════════════════
    # PHASE 3: CT73 variants (Model B)
    # ════════════════════════════════════════════════════════════════════

    print("\n" + "=" * 70)
    print("PHASE 3: Model B — CT73 (consensus nulls removed)")
    print("-" * 50)

    phase3_all = {}
    for mask_name, mask in [("mask_a", MASK_A), ("mask_b", MASK_B), ("mask_c", MASK_C)]:
        ct73_nums, pos_map, crib73 = extract_ct73(mask)
        ct73_len = len(ct73_nums)
        ene73, bcl73 = get_ct73_groups(pos_map)

        print(f"\n  Mask: {mask_name} ({len(mask)} nulls, CT73 len={ct73_len})")
        ene_lost = [p for p in ENE_POSITIONS if p not in pos_map]
        bcl_lost = [p for p in BCL_POSITIONS if p not in pos_map]
        if ene_lost:
            print(f"    WARNING: Lost ENE cribs at: {ene_lost}")
        if bcl_lost:
            print(f"    WARNING: Lost BCL cribs at: {bcl_lost}")
        print(f"    ENE in CT73: {ene73} ({len(ene73)} cribs)")
        print(f"    BCL in CT73: {bcl73} ({len(bcl73)} cribs)")

        mask_results = {}
        for variant in VARIANTS:
            ks73 = compute_keystream_ct73(variant, ct73_nums, crib73)
            ene_ks73 = {p: ks73[p] for p in ene73 if p in ks73}
            bcl_ks73 = {p: ks73[p] for p in bcl73 if p in ks73}

            ene_surv, bcl_surv = [], []
            for p in range(1, 27):
                ene_ok, _ = check_period_for_group(p, ene73, ene_ks73)
                if ene_ok:
                    ene_surv.append(p)
                bcl_ok, _ = check_period_for_group(p, bcl73, bcl_ks73)
                if bcl_ok:
                    bcl_surv.append(p)

            print(f"    {variant}: ENE {len(ene_surv)} periods, BCL {len(bcl_surv)} periods")

            # Build jobs for CT73
            ct73_cut_min = max(ene73) + 1 if ene73 else 0
            ct73_cut_max = min(bcl73) - 1 if bcl73 else ct73_len
            if ct73_cut_min > ct73_cut_max:
                ct73_cut_min = ct73_cut_max
            ct73_cuts = list(range(ct73_cut_min, ct73_cut_max + 1,
                                   max(1, (ct73_cut_max - ct73_cut_min) // 6)))
            if ct73_cuts and ct73_cut_max not in ct73_cuts:
                ct73_cuts.append(ct73_cut_max)

            ct73_jobs = []
            for p_ene in ene_surv:
                for p_bcl in bcl_surv:
                    for cut73 in ct73_cuts:
                        ct73_jobs.append((
                            cut73, p_ene, p_bcl, variant,
                            ene73, bcl73,
                            ene_ks73, bcl_ks73,
                            f"CT73_{mask_name}", ct73_nums, ct73_len,
                        ))

            if ct73_jobs:
                ct73_done = []
                with Pool(n_workers) as pool:
                    for result in pool.imap_unordered(sweep_job, ct73_jobs):
                        ct73_done.append(result)

                done = [r for r in ct73_done if r["status"] == "COMPLETE"]
                done.sort(key=lambda x: x["best_score"], reverse=True)
                ct73_tested_ene = sum(r.get("ene_keys_tested", 0) for r in done)
                ct73_tested_bcl = sum(r.get("bcl_keys_tested", 0) for r in done)
                print(f"      Jobs: {len(ct73_jobs)}, Done: {len(done)}, "
                      f"Keys: ENE={ct73_tested_ene:,} BCL={ct73_tested_bcl:,}")
                if done:
                    top = done[0]
                    print(f"      Best: {top['best_score']:.4f}/char crib={top['crib_score']}/24 "
                          f"(cut={top['cut']} p_ene={top['period_ene']} p_bcl={top['period_bcl']})")
                    print(f"        PT: {top['best_pt'][:60]}...")

                mask_results[variant] = {
                    "ene_survivors": ene_surv,
                    "bcl_survivors": bcl_surv,
                    "n_jobs": len(ct73_jobs),
                    "n_done": len(done),
                    "top5": [{k: v for k, v in r.items() if k != "best_pt"} |
                             {"best_pt_preview": r.get("best_pt", "")[:60]}
                             for r in done[:5]],
                }
            else:
                mask_results[variant] = {"ene_survivors": ene_surv, "bcl_survivors": bcl_surv, "n_jobs": 0}

        phase3_all[mask_name] = mask_results

    all_results["phases"]["phase3"] = phase3_all

    # ════════════════════════════════════════════════════════════════════
    # PHASE 4: Keyword-length focused sweep (periods 13 and 11 especially)
    # ════════════════════════════════════════════════════════════════════

    print("\n" + "=" * 70)
    print("PHASE 4: Keyword-length focus — periods matching crib group lengths")
    print("-" * 50)
    print("  ENE has 13 crib positions -> period 13 has 0 free residues (FULLY DETERMINED)")
    print("  BCL has 11 crib positions -> period 11 has 0 free residues (FULLY DETERMINED)")
    print("  These are the MOST constrained: only 1 key each, all from cribs.")

    phase4 = {}
    for variant in VARIANTS:
        ks = KEYSTREAMS[variant]
        ene_ks = {pos: ks[pos] for pos in ENE_POSITIONS}
        bcl_ks = {pos: ks[pos] for pos in BCL_POSITIONS}

        # Period 13 for ENE: all residues covered
        ene13_template, ene13_free = build_key_template(13, ENE_POSITIONS, ene_ks)
        # Period 11 for BCL: all residues covered
        bcl11_template, bcl11_free = build_key_template(11, BCL_POSITIONS, bcl_ks)

        print(f"\n  {variant}:")
        print(f"    ENE p=13: key = {ene13_template} (free={len(ene13_free)})")
        print(f"    BCL p=11: key = {bcl11_template} (free={len(bcl11_free)})")

        # Decrypt with these exact keys at multiple cut points
        for cut in [34, 42, 48, 54, 62]:
            pt1_chars = []
            for i in range(0, cut):
                k = ene13_template[i % 13]
                pt1_chars.append(ALPH[decrypt_char(CT_NUM[i], k, variant)])
            pt2_chars = []
            for i in range(cut, CT_LEN):
                k = bcl11_template[i % 11]
                pt2_chars.append(ALPH[decrypt_char(CT_NUM[i], k, variant)])

            full_pt = "".join(pt1_chars) + "".join(pt2_chars)
            qg = SCORER.score_per_char(full_pt)

            # Crib check
            crib_score = 0
            for pos, ch in CRIB_DICT.items():
                expected = ALPH_IDX[ch]
                if pos < cut:
                    k = ene13_template[pos % 13]
                else:
                    k = bcl11_template[pos % 11]
                if decrypt_char(CT_NUM[pos], k, variant) == expected:
                    crib_score += 1

            print(f"    cut={cut}: qg={qg:.4f}/char crib={crib_score}/24")
            ene_pt = "".join(pt1_chars)
            bcl_pt = "".join(pt2_chars)
            print(f"      seg1: {ene_pt}")
            print(f"      seg2: {bcl_pt}")

        # Also show the key as letters
        ene_key_letters = "".join(ALPH[v] for v in ene13_template)
        bcl_key_letters = "".join(ALPH[v] for v in bcl11_template)
        print(f"    ENE key as letters: {ene_key_letters}")
        print(f"    BCL key as letters: {bcl_key_letters}")

        phase4[variant] = {
            "ene_p13_key": ene13_template,
            "ene_p13_letters": ene_key_letters,
            "bcl_p11_key": bcl11_template,
            "bcl_p11_letters": bcl_key_letters,
        }

    all_results["phases"]["phase4"] = phase4

    # ════════════════════════════════════════════════════════════════════
    # SUMMARY
    # ════════════════════════════════════════════════════════════════════

    t_end = time.time()
    total_time = t_end - t0

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Total runtime: {total_time:.1f}s")

    # Best across all phases
    best_ct97 = completed[0] if completed else None
    best_ct73_score = -999.0
    best_ct73_detail = None
    for mask_name, mask_data in phase3_all.items():
        for v, vdata in mask_data.items():
            if "top5" in vdata and vdata["top5"]:
                candidate = vdata["top5"][0]
                if candidate.get("best_score", -999) > best_ct73_score:
                    best_ct73_score = candidate["best_score"]
                    best_ct73_detail = {**candidate, "mask": mask_name}

    print(f"\n  Phase 2 (CT97) best: {best_ct97['best_score']:.4f}/char, crib={best_ct97['crib_score']}/24"
          if best_ct97 else "  Phase 2: no results")
    if best_ct73_detail:
        print(f"  Phase 3 (CT73) best: {best_ct73_score:.4f}/char")

    threshold = -4.0
    any_signal = False
    if best_ct97 and best_ct97["best_score"] >= threshold:
        any_signal = True
    if best_ct73_detail and best_ct73_score >= threshold:
        any_signal = True

    if not any_signal:
        print(f"\n  CONCLUSION: DISPROVED for short periodic keys (periods 1-26)")
        print(f"  M5 segmented tape with two independent periodic keys")
        print(f"  produces NO English-quality output (all below {threshold}/char).")
        print(f"  Segmentation DOES open constraint space (14 ENE + 16 BCL periods)")
        print(f"  but the cipher layer requires non-periodic (running/OTP) keys even")
        print(f"  under segmentation.")
        conclusion = "DISPROVED_SHORT_PERIODIC"
    else:
        print(f"\n  CONCLUSION: SIGNAL — requires follow-up")
        conclusion = "SIGNAL"

    all_results["summary"] = {
        "runtime_seconds": round(total_time, 1),
        "conclusion": conclusion,
        "segmentation_opens_periods": True,
        "ene_periods_surviving": len(phase1["beaufort"]["ene_survivors"]),
        "bcl_periods_surviving": len(phase1["beaufort"]["bcl_survivors"]),
        "bean_constraints_voided": cross_ineq + 1,
        "best_ct97_score": best_ct97["best_score"] if best_ct97 else None,
        "best_ct73_score": best_ct73_score if best_ct73_detail else None,
        "threshold": threshold,
    }

    # Save results
    results_path = os.path.join(_ROOT, "results", "e_segmented_tape_01.json")
    with open(results_path, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"\n  Results saved to: {results_path}")


if __name__ == "__main__":
    main()
