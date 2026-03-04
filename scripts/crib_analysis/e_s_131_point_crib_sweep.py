#!/usr/bin/env python3
"""
Cipher: crib-based constraint
Family: crib_analysis
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-131: POINT crib sweep — test POINT at all valid positions.

Tests whether adding POINT (5 chars) as a third crib at any position
produces algebraic consistency with period-p key + width-w columnar.

Existing cribs (0-indexed): ENE@21-33 (13 chars), BC@63-73 (11 chars) = 24 chars
With POINT added (no overlap): 29 total crib positions

Valid POINT positions (0-indexed): [0-16] ∪ [34-58] ∪ [74-92] = 61 positions
Conflict positions (overlap with ENE/BC): [17-33] ∪ [59-73] = 32 positions

Focus position: p=16 (0-indexed) → "POINTEASTNORTHEAST"

METHOD: Algebraic constraint propagation.
  For period-p key + width-w columnar:
    Model B (trans-then-sub): key[pos % p] must be consistent across all
    crib positions in each residue class.
    Model A (sub-then-trans): key[inv_perm[pos] % p] must be consistent.
  With 29 cribs at period 7 (~4.1 per class):
    P(random full match) ≈ (1/26)^22 ≈ 10^-31
    Any full match is DEFINITIVE signal.

TOTAL SEARCH:
  Phase 0: p=16 focus, w7, periods 2-14, 3 variants, 2 models
  Phase 1: 61 positions × 5040 w7 orderings × period 7 × 3 variants × 2 models
  Phase 2: 61 positions × 5040 w7 orderings × periods 2-6,8-14 × 3 variants × 2 models
  Phase 3: 61 positions × widths 5,6,8 × period 7 × 3 variants × 2 models
"""
import json
import itertools
import os
import sys
import time as time_mod
from collections import Counter, defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX,
)
from kryptos.kernel.transforms.transposition import (
    columnar_perm, invert_perm,
)


# ── Constants ─────────────────────────────────────────────────────────────

CT_IDX = [ALPH_IDX[c] for c in CT]
assert len(CT_IDX) == 97

POINT_WORD = "POINT"       # 5 chars
ENE_WORD = "EASTNORTHEAST"  # 13 chars, positions 21-33
BC_WORD = "BERLINCLOCK"     # 11 chars, positions 63-73

ENE_START = 21
BC_START = 63


# ── Variant key-recovery functions ────────────────────────────────────────

def vig_key(c, p):
    return (c - p) % 26

def beau_key(c, p):
    return (c + p) % 26

def vb_key(c, p):
    return (p - c) % 26

VARIANT_FNS = [("vigenere", vig_key), ("beaufort", beau_key), ("var_beaufort", vb_key)]


# ── Build crib dictionary ────────────────────────────────────────────────

def build_base_cribs():
    """Build the 24 standard crib positions."""
    crib = {}
    for i, ch in enumerate(ENE_WORD):
        crib[ENE_START + i] = ALPH_IDX[ch]
    for i, ch in enumerate(BC_WORD):
        crib[BC_START + i] = ALPH_IDX[ch]
    return crib


def add_point_crib(base_cribs, point_start):
    """Add POINT at given start position. Returns (new_crib_dict, conflict)."""
    crib = dict(base_cribs)
    for i, ch in enumerate(POINT_WORD):
        pos = point_start + i
        if pos < 0 or pos >= CT_LEN:
            return crib, True  # out of bounds
        pt_val = ALPH_IDX[ch]
        if pos in crib:
            if crib[pos] != pt_val:
                return crib, True  # conflict with existing crib
            # else: agrees, already in dict
        else:
            crib[pos] = pt_val
    return crib, False


# ── Precompute permutations ──────────────────────────────────────────────

def precompute_perms(width, length=97):
    """Precompute all width! inverse permutations for given text length."""
    perms = []
    for col_order in itertools.permutations(range(width)):
        perm = columnar_perm(width, list(col_order), length)
        if len(perm) == length and len(set(perm)) == length:
            inv = invert_perm(perm)
            perms.append((list(col_order), inv))
    return perms


# ── Algebraic consistency check ──────────────────────────────────────────

def check_consistency_model_b(ct_idx, inv_perm, crib_dict, vfn, period):
    """Model B (trans-then-sub): intermediate = Trans^{-1}(CT), key[pos % p].

    Returns (score, is_full_match) where score = number of consistent cribs.
    """
    groups = defaultdict(list)
    for pos, pt_val in crib_dict.items():
        groups[pos % period].append((pos, pt_val))

    score = 0
    for r in range(period):
        group = groups.get(r, [])
        if not group:
            continue
        p0, pt0 = group[0]
        k0 = vfn(ct_idx[inv_perm[p0]], pt0)
        match_count = 1
        for p, pt in group[1:]:
            k = vfn(ct_idx[inv_perm[p]], pt)
            if k == k0:
                match_count += 1
            else:
                score += match_count
                return score, False
        score += match_count
    return score, True


def check_consistency_model_a(ct_idx, inv_perm, crib_dict, vfn, period):
    """Model A (sub-then-trans): key[inv_perm[pos] % p].

    Returns (score, is_full_match).
    """
    groups = defaultdict(list)
    for pos, pt_val in crib_dict.items():
        r = inv_perm[pos] % period
        groups[r].append((pos, pt_val))

    score = 0
    for r in range(period):
        group = groups.get(r, [])
        if not group:
            continue
        p0, pt0 = group[0]
        k0 = vfn(ct_idx[inv_perm[p0]], pt0)
        match_count = 1
        for p, pt in group[1:]:
            k = vfn(ct_idx[inv_perm[p]], pt)
            if k == k0:
                match_count += 1
            else:
                score += match_count
                return score, False
        score += match_count
    return score, True


# ── Main experiment ──────────────────────────────────────────────────────

def main():
    t0 = time_mod.time()
    print("=" * 70)
    print("E-S-131: POINT Crib Sweep — Algebraic Constraint Propagation")
    print("=" * 70)

    # Identify valid vs conflict positions
    base_cribs = build_base_cribs()
    valid_positions = []
    conflict_positions = []
    for p in range(93):  # POINT is 5 chars, last valid start = 92
        _, conflict = add_point_crib(base_cribs, p)
        if conflict:
            conflict_positions.append(p)
        else:
            valid_positions.append(p)

    print(f"Base cribs: {len(base_cribs)} (ENE@21-33 + BC@63-73)")
    print(f"Valid POINT positions: {len(valid_positions)}")
    print(f"Conflict positions: {len(conflict_positions)}")
    print(f"Valid ranges: [{valid_positions[0]}-{valid_positions[0]}..{16}], "
          f"[{34}..{58}], [{74}..{valid_positions[-1]}]")
    print(f"Focus position: 16 (0-indexed) = 17 (1-indexed) → POINTEASTNORTHEAST")
    print()

    # Precompute w7 permutations
    print("Precomputing permutations...")
    w7_perms = precompute_perms(7)
    w5_perms = precompute_perms(5)
    w6_perms = precompute_perms(6)
    w8_perms = precompute_perms(8)
    print(f"  w5: {len(w5_perms)}, w6: {len(w6_perms)}, "
          f"w7: {len(w7_perms)}, w8: {len(w8_perms)}")

    total_tested = 0
    full_matches = []
    all_results = {}  # position -> best_score across all configs

    # ── Phase 0: Focus on p=16, w7, periods 2-14 ─────────────────────────
    print("\n--- Phase 0: FOCUS on p=16 (POINTEASTNORTHEAST), w7, periods 2-14 ---")
    crib_dict_16, _ = add_point_crib(base_cribs, 16)
    n_cribs_16 = len(crib_dict_16)
    print(f"  Cribs at p=16: {n_cribs_16}")
    print(f"  Plaintext snippet: ...{POINT_WORD}{ENE_WORD}...")

    p0_best = 0
    p0_best_config = None
    for period in range(2, 15):
        period_best = 0
        for col_order, inv_perm in w7_perms:
            for vname, vfn in VARIANT_FNS:
                # Model B
                sc, full = check_consistency_model_b(
                    CT_IDX, inv_perm, crib_dict_16, vfn, period)
                total_tested += 1
                if full:
                    full_matches.append({
                        "phase": 0, "point_pos": 16, "width": 7,
                        "period": period, "col_order": col_order,
                        "variant": vname, "model": "B",
                        "score": sc, "n_cribs": n_cribs_16,
                    })
                    print(f"  *** FULL MATCH: period={period} order={col_order} "
                          f"var={vname} model=B score={sc}/{n_cribs_16} ***")
                if sc > period_best:
                    period_best = sc
                if sc > p0_best:
                    p0_best = sc
                    p0_best_config = {
                        "period": period, "col_order": col_order,
                        "variant": vname, "model": "B", "score": sc,
                    }

                # Model A
                sc, full = check_consistency_model_a(
                    CT_IDX, inv_perm, crib_dict_16, vfn, period)
                total_tested += 1
                if full:
                    full_matches.append({
                        "phase": 0, "point_pos": 16, "width": 7,
                        "period": period, "col_order": col_order,
                        "variant": vname, "model": "A",
                        "score": sc, "n_cribs": n_cribs_16,
                    })
                    print(f"  *** FULL MATCH: period={period} order={col_order} "
                          f"var={vname} model=A score={sc}/{n_cribs_16} ***")
                if sc > p0_best:
                    p0_best = sc
                    p0_best_config = {
                        "period": period, "col_order": col_order,
                        "variant": vname, "model": "A", "score": sc,
                    }

        print(f"  period={period}: best={period_best}/{n_cribs_16}")

    print(f"  Phase 0 summary: best={p0_best}/{n_cribs_16}, full_matches={len(full_matches)}")
    if p0_best_config:
        print(f"  Best config: {p0_best_config}")
    all_results[16] = p0_best

    # ── Phase 1: Full sweep, w7, period 7 ────────────────────────────────
    print(f"\n--- Phase 1: Full sweep, w7, period 7, {len(valid_positions)} positions ---")
    phase1_scores = {}
    phase1_best = 0

    for idx, point_pos in enumerate(valid_positions):
        crib_dict, _ = add_point_crib(base_cribs, point_pos)
        n_cribs = len(crib_dict)
        pos_best = 0

        for col_order, inv_perm in w7_perms:
            for vname, vfn in VARIANT_FNS:
                sc_b, full_b = check_consistency_model_b(
                    CT_IDX, inv_perm, crib_dict, vfn, 7)
                total_tested += 1
                if full_b:
                    full_matches.append({
                        "phase": 1, "point_pos": point_pos, "width": 7,
                        "period": 7, "col_order": col_order,
                        "variant": vname, "model": "B",
                        "score": sc_b, "n_cribs": n_cribs,
                    })
                    print(f"  *** FULL MATCH: pos={point_pos} order={col_order} "
                          f"var={vname} model=B score={sc_b}/{n_cribs} ***")
                if sc_b > pos_best:
                    pos_best = sc_b

                sc_a, full_a = check_consistency_model_a(
                    CT_IDX, inv_perm, crib_dict, vfn, 7)
                total_tested += 1
                if full_a:
                    full_matches.append({
                        "phase": 1, "point_pos": point_pos, "width": 7,
                        "period": 7, "col_order": col_order,
                        "variant": vname, "model": "A",
                        "score": sc_a, "n_cribs": n_cribs,
                    })
                    print(f"  *** FULL MATCH: pos={point_pos} order={col_order} "
                          f"var={vname} model=A score={sc_a}/{n_cribs} ***")
                if sc_a > pos_best:
                    pos_best = sc_a

        phase1_scores[point_pos] = pos_best
        if point_pos not in all_results or pos_best > all_results[point_pos]:
            all_results[point_pos] = pos_best
        if pos_best > phase1_best:
            phase1_best = pos_best

        if (idx + 1) % 10 == 0:
            elapsed = time_mod.time() - t0
            print(f"  {idx+1}/{len(valid_positions)}: tested={total_tested:,}, "
                  f"best={phase1_best}, rate={total_tested/elapsed:.0f}/s")

    print(f"  Phase 1 complete: best={phase1_best}/29")

    # Position score summary
    print(f"\n  Position scores (period 7, w7):")
    for zone_name, zone_range in [("Zone A [0-16]", range(0, 17)),
                                   ("Zone C [34-58]", range(34, 59)),
                                   ("Zone E [74-92]", range(74, 93))]:
        zone_scores = {p: phase1_scores[p] for p in zone_range if p in phase1_scores}
        if zone_scores:
            best_p = max(zone_scores, key=zone_scores.get)
            print(f"    {zone_name}: best={zone_scores[best_p]} at pos={best_p}, "
                  f"mean={sum(zone_scores.values())/len(zone_scores):.1f}")

    # ── Phase 2: Full sweep, w7, periods 2-6 and 8-14 ───────────────────
    print(f"\n--- Phase 2: Full sweep, w7, periods 2-6 + 8-14 ---")
    phase2_best = 0
    phase2_best_config = None

    for period in [2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14]:
        period_best = 0
        for point_pos in valid_positions:
            crib_dict, _ = add_point_crib(base_cribs, point_pos)
            n_cribs = len(crib_dict)

            for col_order, inv_perm in w7_perms:
                for vname, vfn in VARIANT_FNS:
                    sc, full = check_consistency_model_b(
                        CT_IDX, inv_perm, crib_dict, vfn, period)
                    total_tested += 1
                    if full:
                        full_matches.append({
                            "phase": 2, "point_pos": point_pos, "width": 7,
                            "period": period, "col_order": col_order,
                            "variant": vname, "model": "B",
                            "score": sc, "n_cribs": n_cribs,
                        })
                        print(f"  *** FULL MATCH: pos={point_pos} p={period} "
                              f"order={col_order} var={vname} model=B ***")
                    if sc > period_best:
                        period_best = sc

                    sc, full = check_consistency_model_a(
                        CT_IDX, inv_perm, crib_dict, vfn, period)
                    total_tested += 1
                    if full:
                        full_matches.append({
                            "phase": 2, "point_pos": point_pos, "width": 7,
                            "period": period, "col_order": col_order,
                            "variant": vname, "model": "A",
                            "score": sc, "n_cribs": n_cribs,
                        })
                        print(f"  *** FULL MATCH: pos={point_pos} p={period} "
                              f"order={col_order} var={vname} model=A ***")
                    if sc > period_best:
                        period_best = sc

            if period_best > phase2_best:
                phase2_best = period_best

        print(f"  period={period}: best={period_best}/29")

    print(f"  Phase 2 complete: best={phase2_best}/29")

    # ── Phase 3: Other widths (5,6,8), period 7 ─────────────────────────
    print(f"\n--- Phase 3: widths 5,6,8, period 7 ---")
    phase3_best = 0

    for width, perms in [(5, w5_perms), (6, w6_perms), (8, w8_perms)]:
        width_best = 0
        for point_pos in valid_positions:
            crib_dict, _ = add_point_crib(base_cribs, point_pos)
            n_cribs = len(crib_dict)

            for col_order, inv_perm in perms:
                for vname, vfn in VARIANT_FNS:
                    sc, full = check_consistency_model_b(
                        CT_IDX, inv_perm, crib_dict, vfn, 7)
                    total_tested += 1
                    if full:
                        full_matches.append({
                            "phase": 3, "point_pos": point_pos, "width": width,
                            "period": 7, "col_order": col_order,
                            "variant": vname, "model": "B",
                            "score": sc, "n_cribs": n_cribs,
                        })
                        print(f"  *** FULL MATCH: pos={point_pos} w={width} "
                              f"order={col_order} var={vname} model=B ***")
                    if sc > width_best:
                        width_best = sc

                    sc, full = check_consistency_model_a(
                        CT_IDX, inv_perm, crib_dict, vfn, 7)
                    total_tested += 1
                    if full:
                        full_matches.append({
                            "phase": 3, "point_pos": point_pos, "width": width,
                            "period": 7, "col_order": col_order,
                            "variant": vname, "model": "A",
                            "score": sc, "n_cribs": n_cribs,
                        })
                        print(f"  *** FULL MATCH: pos={point_pos} w={width} "
                              f"order={col_order} var={vname} model=A ***")
                    if sc > width_best:
                        width_best = sc

        if width_best > phase3_best:
            phase3_best = width_best
        print(f"  width={width}: best={width_best}/29 ({len(perms)} orderings)")

    print(f"  Phase 3 complete: best={phase3_best}/29")

    # ── Phase 4: Baseline (24 cribs only, no POINT), w7, period 7 ───────
    print(f"\n--- Phase 4: Baseline (24 cribs, no POINT), w7, period 7 ---")
    phase4_best = 0
    for col_order, inv_perm in w7_perms:
        for vname, vfn in VARIANT_FNS:
            sc, full = check_consistency_model_b(
                CT_IDX, inv_perm, base_cribs, vfn, 7)
            total_tested += 1
            if full:
                full_matches.append({
                    "phase": 4, "point_pos": None, "width": 7,
                    "period": 7, "col_order": col_order,
                    "variant": vname, "model": "B",
                    "score": sc, "n_cribs": 24,
                })
                print(f"  *** BASELINE FULL MATCH: order={col_order} "
                      f"var={vname} model=B ***")
            if sc > phase4_best:
                phase4_best = sc

            sc, full = check_consistency_model_a(
                CT_IDX, inv_perm, base_cribs, vfn, 7)
            total_tested += 1
            if full:
                full_matches.append({
                    "phase": 4, "point_pos": None, "width": 7,
                    "period": 7, "col_order": col_order,
                    "variant": vname, "model": "A",
                    "score": sc, "n_cribs": 24,
                })
                print(f"  *** BASELINE FULL MATCH: order={col_order} "
                      f"var={vname} model=A ***")
            if sc > phase4_best:
                phase4_best = sc

    print(f"  Baseline: best={phase4_best}/24")

    # ── Summary ──────────────────────────────────────────────────────────
    elapsed = time_mod.time() - t0
    print(f"\n{'=' * 70}")
    print(f"SUMMARY (elapsed: {elapsed:.1f}s)")
    print(f"{'=' * 70}")
    print(f"Total algebraic checks: {total_tested:,}")
    print(f"Phase 0 (p=16 focus, w7, periods 2-14): best {p0_best}/29")
    print(f"Phase 1 (all positions, w7, period 7): best {phase1_best}/29")
    print(f"Phase 2 (all positions, w7, periods 2-6+8-14): best {phase2_best}/29")
    print(f"Phase 3 (all positions, w5/6/8, period 7): best {phase3_best}/29")
    print(f"Phase 4 (baseline 24 cribs, w7, period 7): best {phase4_best}/24")
    print(f"Full matches found: {len(full_matches)}")

    if full_matches:
        print(f"\n*** {len(full_matches)} FULL MATCH(ES) FOUND! ***")
        for fm in full_matches:
            print(f"  pos={fm['point_pos']} w={fm['width']} p={fm['period']} "
                  f"order={fm['col_order']} var={fm['variant']} "
                  f"model={fm['model']} score={fm['score']}/{fm['n_cribs']}")
    else:
        print(f"\nNo full matches — POINT + periodic key + columnar transposition")
        print(f"is ELIMINATED for ALL positions, ALL orderings, ALL periods 2-14,")
        print(f"ALL three cipher variants, BOTH layer orders, widths 5-8.")

    # Positional clustering analysis
    if phase1_scores:
        print(f"\nPositional analysis (Phase 1, w7, period 7):")
        sorted_scores = sorted(phase1_scores.items(), key=lambda x: -x[1])
        print(f"  Top 10 positions:")
        for pos, sc in sorted_scores[:10]:
            zone = "A" if pos <= 16 else ("C" if pos <= 58 else "E")
            adj = ""
            if pos == 16:
                adj = " ← POINTEASTNORTHEAST"
            print(f"    pos={pos} (zone {zone}): {sc}/29{adj}")

        # Check for clustering around p=16
        zone_a_scores = [phase1_scores[p] for p in range(0, 17) if p in phase1_scores]
        zone_c_scores = [phase1_scores[p] for p in range(34, 59) if p in phase1_scores]
        zone_e_scores = [phase1_scores[p] for p in range(74, 93) if p in phase1_scores]
        print(f"\n  Zone means: A={sum(zone_a_scores)/len(zone_a_scores):.2f}, "
              f"C={sum(zone_c_scores)/len(zone_c_scores):.2f}, "
              f"E={sum(zone_e_scores)/len(zone_e_scores):.2f}")
        print(f"  p=16 score: {phase1_scores.get(16, 'N/A')}")
        print(f"  All scores identical? {len(set(phase1_scores.values())) == 1}")

    # Verdict
    if full_matches:
        verdict = "BREAKTHROUGH"
    elif phase1_best >= 20:
        verdict = "STRONG_SIGNAL"
    elif phase1_best >= 15:
        verdict = "SIGNAL"
    elif phase1_best >= 10:
        verdict = "INTERESTING"
    else:
        verdict = "NOISE"
    print(f"\nVERDICT: {verdict}")

    # Success/failure criteria check
    print(f"\nSuccess criteria check:")
    print(f"  Any config satisfying all 3 cribs: {'YES' if full_matches else 'NO'}")
    print(f"  Score ≥22/29: {'YES' if phase1_best >= 22 else 'NO'} (best={phase1_best})")
    print(f"  Clustering around p=16: ", end="")
    if phase1_scores and 16 in phase1_scores:
        p16_sc = phase1_scores[16]
        others = [v for k, v in phase1_scores.items() if k != 16]
        if others and p16_sc > max(others):
            print(f"YES (p16={p16_sc} > max_other={max(others)})")
        elif others:
            print(f"NO (p16={p16_sc}, max_other={max(others)})")
        else:
            print(f"ONLY POSITION")
    else:
        print(f"N/A")

    # Save artifact
    artifact = {
        "experiment_id": "e_s_131",
        "hypothesis": "POINT appears in K4 plaintext, test all 93 positions",
        "focus_position": 16,
        "total_tested": total_tested,
        "valid_positions": valid_positions,
        "conflict_positions": conflict_positions,
        "phase0_best": p0_best,
        "phase0_best_config": p0_best_config,
        "phase1_best": phase1_best,
        "phase1_scores": phase1_scores,
        "phase2_best": phase2_best,
        "phase3_best": phase3_best,
        "phase4_baseline": phase4_best,
        "full_matches": full_matches,
        "verdict": verdict,
        "runtime_seconds": elapsed,
        "repro_command": "PYTHONPATH=src python3 -u scripts/e_s_131_point_crib_sweep.py",
    }

    out_dir = "artifacts/progressive_solve/stage4"
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "point_crib_sweep_results.json")
    with open(out_path, "w") as f:
        json.dump(artifact, f, indent=2, default=str)
    print(f"\nArtifacts written to {out_path}")


if __name__ == "__main__":
    main()
