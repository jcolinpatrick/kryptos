#!/usr/bin/env python3
"""E-S-130: CHECKPOINT 98-char hypothesis — algebraic constraint propagation.

HYPOTHESIS: K4's true ciphertext is 98 characters. The plaintext contains
CHECKPOINT immediately before EASTNORTHEAST, giving 34 known PT chars.
One CT character was omitted from the copper plate.

STRUCTURAL ARGUMENT:
  98 = 14 × 7 (perfect width-7 grid, zero remainder)
  97 is prime (irregular grid with every width)

EXPANDED CRIBS (in 98-char true text, 0-indexed):
  Zone B gaps (gap at 0-indexed 0..20):
    CHECKPOINT     @ 12-21 (10 chars)
    EASTNORTHEAST  @ 22-34 (13 chars)
    BERLINCLOCK    @ 64-74 (11 chars)
    Total: 34 known plaintext characters

METHOD: Algebraic consistency check.
  For period-7 key + w7 columnar (Model B):
    key[p % 7] = f(intermediate[p], PT[p]) must be consistent across
    all crib positions in each residue class mod 7.

  With ~5 cribs per residue class, random consistency ≈ (1/26)^4 ≈ 2×10^-6
  Across 7 classes: ≈ 10^-40. A 34/34 match is DEFINITIVE.

  Early termination: break at first inconsistent residue class.
  Expected pruning: 96% of configs eliminated after 2 lookups.

TOTAL SEARCH: 98 gap positions × 26 chars × 5040 w7 orderings × 3 variants
              × 2 models = ~77M algebraic checks (runs in seconds).
"""
import json
import itertools
import os
import sys
import time as time_mod
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD,
)
from kryptos.kernel.transforms.transposition import (
    columnar_perm, invert_perm,
)


# ── Constants ─────────────────────────────────────────────────────────────

CT_IDX = [ALPH_IDX[c] for c in CT]
AUG_LEN = 98  # 14 × 7

# Crib words
CHECKPOINT_WORD = "CHECKPOINT"   # 10 chars
ENE_WORD = "EASTNORTHEAST"      # 13 chars
BC_WORD = "BERLINCLOCK"         # 11 chars
POINT_WORD = "POINT"            # 5 chars

# Known crib positions in 97-char inscribed text (0-indexed)
ENE_START_97 = 21
BC_START_97 = 63


# ── Variant key-recovery functions ────────────────────────────────────────
# Given ct_val and pt_val, recover the key value

def vig_key(c, p):
    return (c - p) % 26

def beau_key(c, p):
    return (c + p) % 26

def vb_key(c, p):
    return (p - c) % 26

VARIANT_FNS = [("vigenere", vig_key), ("beaufort", beau_key), ("var_beaufort", vb_key)]


# ── Crib position computation ─────────────────────────────────────────────

def compute_crib_positions(gap_pos, include_checkpoint=True, include_point=False):
    """Compute crib positions in the 98-char text for a given gap position.

    Maps 97-char known crib positions to 98-char positions,
    then optionally adds CHECKPOINT or POINT before ENE.

    Returns: dict {position_98: pt_value} and int total_cribs
    """
    def map_pos(p97):
        """Map 97-char position to 98-char position."""
        return p97 if p97 < gap_pos else p97 + 1

    crib = {}

    # ENE cribs (97-char positions 21-33)
    for i, ch in enumerate(ENE_WORD):
        p98 = map_pos(ENE_START_97 + i)
        crib[p98] = ALPH_IDX[ch]

    # BC cribs (97-char positions 63-73)
    for i, ch in enumerate(BC_WORD):
        p98 = map_pos(BC_START_97 + i)
        crib[p98] = ALPH_IDX[ch]

    # CHECKPOINT placed immediately before ENE
    if include_checkpoint:
        ene_start_98 = map_pos(ENE_START_97)
        cp_start = ene_start_98 - len(CHECKPOINT_WORD)
        for i, ch in enumerate(CHECKPOINT_WORD):
            p = cp_start + i
            if 0 <= p < AUG_LEN and p not in crib:
                crib[p] = ALPH_IDX[ch]

    # POINT placed immediately before ENE (alternative)
    if include_point and not include_checkpoint:
        ene_start_98 = map_pos(ENE_START_97)
        pt_start = ene_start_98 - len(POINT_WORD)
        for i, ch in enumerate(POINT_WORD):
            p = pt_start + i
            if 0 <= p < AUG_LEN and p not in crib:
                crib[p] = ALPH_IDX[ch]

    return crib


def group_by_residue(crib_dict, mod=7):
    """Group crib positions by residue mod 7."""
    groups = [[] for _ in range(mod)]
    for pos, pt_val in crib_dict.items():
        groups[pos % mod].append((pos, pt_val))
    return groups


# ── Precompute permutations ───────────────────────────────────────────────

def precompute_perms():
    """Precompute all 5040 w7 inverse permutations for 98-char text."""
    perms = []
    for col_order in itertools.permutations(range(7)):
        perm = columnar_perm(7, list(col_order), AUG_LEN)
        if len(perm) == AUG_LEN and len(set(perm)) == AUG_LEN:
            inv = invert_perm(perm)
            perms.append((list(col_order), inv))
    return perms


# ── Algebraic consistency check ───────────────────────────────────────────

def check_consistency_model_b(aug_idx, inv_perm, crib_groups, vfn):
    """Check period-7 key consistency for Model B (trans-then-sub).

    Model B: CT = Trans(Sub(PT))
    Decrypt: intermediate = Trans^{-1}(CT), PT = Sub^{-1}(intermediate)
    Key recovery: key[p % 7] = vfn(intermediate[p], PT[p])
    Group by p % 7, check if all values in each group agree.

    Returns: (score, is_full_match)
      score = number of consistent crib positions
      is_full_match = True if ALL cribs consistent (34/34)
    """
    score = 0
    for group in crib_groups:
        if not group:
            continue
        p0, pt0 = group[0]
        k0 = vfn(aug_idx[inv_perm[p0]], pt0)
        all_match = True
        match_count = 1
        for p, pt in group[1:]:
            k = vfn(aug_idx[inv_perm[p]], pt)
            if k == k0:
                match_count += 1
            else:
                all_match = False
                # Early termination: this group is inconsistent
                # Count how many match the most common value
                break
        if all_match:
            score += match_count
        else:
            # For partial scoring, count matches to first value
            score += match_count
            return score, False
    return score, True


def check_consistency_model_a(aug_idx, inv_perm, crib_dict, vfn):
    """Check period-7 key consistency for Model A (sub-then-trans).

    Model A: CT = Sub(Trans(PT))
    Decrypt: x = Sub^{-1}(CT), PT = Trans^{-1}(x)
    PT[i] = decrypt(CT[inv_perm[i]], key[inv_perm[i] % 7])
    Key recovery: key[inv_perm[p] % 7] = vfn(aug_idx[inv_perm[p]], PT[p])
    Group by inv_perm[p] % 7.

    Returns: (score, is_full_match)
    """
    # Group by inv_perm[p] % 7
    groups = [[] for _ in range(7)]
    for pos, pt_val in crib_dict.items():
        r = inv_perm[pos] % 7
        groups[r].append((pos, pt_val))

    score = 0
    for group in groups:
        if not group:
            continue
        p0, pt0 = group[0]
        k0 = vfn(aug_idx[inv_perm[p0]], pt0)
        all_match = True
        match_count = 1
        for p, pt in group[1:]:
            k = vfn(aug_idx[inv_perm[p]], pt)
            if k == k0:
                match_count += 1
            else:
                all_match = False
                score += match_count
                return score, False
        score += match_count
    return score, True


# ── Main experiment ───────────────────────────────────────────────────────

def main():
    t0 = time_mod.time()
    print("=" * 70)
    print("E-S-130: CHECKPOINT 98-Char Hypothesis — Algebraic Propagation")
    print("=" * 70)
    print(f"98 = 14 × 7 (perfect grid)")
    print(f"Expanded cribs: CHECKPOINT(10) + ENE(13) + BC(11) = 34 chars")
    print(f"Search: 98 gaps × 26 chars × 5040 w7 × 3 variants × 2 models")
    print()

    # Precompute permutations
    print("Precomputing 5040 w7 inverse permutations for 98 chars...")
    all_perms = precompute_perms()
    print(f"  {len(all_perms)} valid permutations")

    results = []
    total_tested = 0
    best_score = 0
    best_config = None
    full_matches = []

    # ── Phase 1: CHECKPOINT + ENE + BC (34 cribs), all gaps, all models ──
    print("\n--- Phase 1: CHECKPOINT hypothesis (34 cribs) ---")
    print("  Zones: B(0-20), D(34-62), F(74-97), boundaries(21-33, 63-73)")

    phase1_best = 0
    phase1_best_config = None
    score_distribution = Counter()

    for gap in range(AUG_LEN):  # 0..97
        crib_dict = compute_crib_positions(gap, include_checkpoint=True)
        n_cribs = len(crib_dict)
        crib_groups_b = group_by_residue(crib_dict)

        # Build augmented CT for this gap position
        aug_base = CT_IDX[:gap] + [0] + CT_IDX[gap:]  # placeholder at gap

        for c in range(26):  # inserted char A=0..Z=25
            aug_base[gap] = c

            for col_order, inv_perm in all_perms:
                for vname, vfn in VARIANT_FNS:
                    # Model B
                    sc_b, full_b = check_consistency_model_b(
                        aug_base, inv_perm, crib_groups_b, vfn)
                    total_tested += 1
                    score_distribution[sc_b] += 1

                    if full_b:
                        full_matches.append({
                            "gap": gap, "char": ALPH[c],
                            "col_order": col_order, "variant": vname,
                            "model": "B", "score": sc_b, "n_cribs": n_cribs,
                        })
                        print(f"  *** FULL MATCH: gap={gap} char={ALPH[c]} "
                              f"order={col_order} var={vname} model=B "
                              f"score={sc_b}/{n_cribs} ***")

                    if sc_b > phase1_best:
                        phase1_best = sc_b
                        phase1_best_config = {
                            "gap": gap, "char": ALPH[c],
                            "col_order": col_order, "variant": vname,
                            "model": "B", "score": sc_b, "n_cribs": n_cribs,
                        }

                    if sc_b >= 15:
                        results.append({
                            "phase": 1, "gap": gap, "char": ALPH[c],
                            "col_order": col_order, "variant": vname,
                            "model": "B", "score": sc_b, "n_cribs": n_cribs,
                        })

                    # Model A
                    sc_a, full_a = check_consistency_model_a(
                        aug_base, inv_perm, crib_dict, vfn)
                    total_tested += 1
                    score_distribution[sc_a] += 1

                    if full_a:
                        full_matches.append({
                            "gap": gap, "char": ALPH[c],
                            "col_order": col_order, "variant": vname,
                            "model": "A", "score": sc_a, "n_cribs": n_cribs,
                        })
                        print(f"  *** FULL MATCH: gap={gap} char={ALPH[c]} "
                              f"order={col_order} var={vname} model=A "
                              f"score={sc_a}/{n_cribs} ***")

                    if sc_a > phase1_best:
                        phase1_best = sc_a
                        phase1_best_config = {
                            "gap": gap, "char": ALPH[c],
                            "col_order": col_order, "variant": vname,
                            "model": "A", "score": sc_a, "n_cribs": n_cribs,
                        }

                    if sc_a >= 15:
                        results.append({
                            "phase": 1, "gap": gap, "char": ALPH[c],
                            "col_order": col_order, "variant": vname,
                            "model": "A", "score": sc_a, "n_cribs": n_cribs,
                        })

        # Progress
        if (gap + 1) % 10 == 0:
            elapsed = time_mod.time() - t0
            rate = total_tested / elapsed if elapsed > 0 else 0
            print(f"  gap {gap+1}/98: tested={total_tested}, best={phase1_best}, "
                  f"full_matches={len(full_matches)}, rate={rate:.0f}/s")

    if phase1_best > best_score:
        best_score = phase1_best
        best_config = phase1_best_config

    print(f"\n  Phase 1 complete: best={phase1_best}/34, full_matches={len(full_matches)}")

    # ── Phase 2: POINT-only + ENE + BC (29 cribs), Zone B only ───────────
    print("\n--- Phase 2: POINT-only hypothesis (29 cribs), Zone B ---")
    phase2_best = 0

    for gap in range(21):  # Zone B: 0..20
        crib_dict = compute_crib_positions(gap, include_checkpoint=False, include_point=True)
        n_cribs = len(crib_dict)
        crib_groups_b = group_by_residue(crib_dict)

        aug_base = CT_IDX[:gap] + [0] + CT_IDX[gap:]

        for c in range(26):
            aug_base[gap] = c

            for col_order, inv_perm in all_perms:
                for vname, vfn in VARIANT_FNS:
                    sc, full = check_consistency_model_b(
                        aug_base, inv_perm, crib_groups_b, vfn)
                    total_tested += 1

                    if full:
                        full_matches.append({
                            "gap": gap, "char": ALPH[c],
                            "col_order": col_order, "variant": vname,
                            "model": "B_point", "score": sc, "n_cribs": n_cribs,
                        })
                        print(f"  *** POINT FULL MATCH: gap={gap} char={ALPH[c]} "
                              f"order={col_order} var={vname} score={sc}/{n_cribs} ***")

                    if sc > phase2_best:
                        phase2_best = sc

    print(f"  Phase 2 complete: best={phase2_best}/29")

    # ── Phase 3: Standard 24 cribs only (no CHECKPOINT), all gaps ────────
    print("\n--- Phase 3: Standard 24 cribs (baseline), all gaps ---")
    phase3_best = 0

    for gap in range(AUG_LEN):
        crib_dict = compute_crib_positions(gap, include_checkpoint=False, include_point=False)
        n_cribs = len(crib_dict)
        crib_groups_b = group_by_residue(crib_dict)

        aug_base = CT_IDX[:gap] + [0] + CT_IDX[gap:]

        for c in range(26):
            aug_base[gap] = c

            for col_order, inv_perm in all_perms:
                for vname, vfn in VARIANT_FNS:
                    sc, full = check_consistency_model_b(
                        aug_base, inv_perm, crib_groups_b, vfn)
                    total_tested += 1

                    if full:
                        full_matches.append({
                            "gap": gap, "char": ALPH[c],
                            "col_order": col_order, "variant": vname,
                            "model": "B_24crib", "score": sc, "n_cribs": n_cribs,
                        })
                        print(f"  *** 24-CRIB FULL MATCH: gap={gap} char={ALPH[c]} "
                              f"order={col_order} var={vname} score={sc}/{n_cribs} ***")

                    if sc > phase3_best:
                        phase3_best = sc

        if (gap + 1) % 20 == 0:
            elapsed = time_mod.time() - t0
            print(f"  gap {gap+1}/98: tested={total_tested}, best={phase3_best}")

    print(f"  Phase 3 complete: best={phase3_best}/24")

    # ── Summary ──────────────────────────────────────────────────────────
    elapsed = time_mod.time() - t0
    print(f"\n{'=' * 70}")
    print(f"SUMMARY (elapsed: {elapsed:.1f}s)")
    print(f"{'=' * 70}")
    print(f"Total algebraic checks: {total_tested:,}")
    print(f"Phase 1 (CHECKPOINT, 34 cribs): best {phase1_best}/34")
    print(f"Phase 2 (POINT, 29 cribs, Zone B): best {phase2_best}/29")
    print(f"Phase 3 (standard 24 cribs): best {phase3_best}/24")
    print(f"Full matches found: {len(full_matches)}")

    if full_matches:
        print(f"\n*** {len(full_matches)} FULL MATCH(ES) FOUND! ***")
        for fm in full_matches:
            print(f"  gap={fm['gap']} char='{fm['char']}' order={fm['col_order']} "
                  f"var={fm['variant']} model={fm['model']} score={fm['score']}/{fm['n_cribs']}")
    else:
        print(f"\nNo full matches — 98-char + w7 columnar + periodic key hypothesis")
        print(f"is ELIMINATED for ALL gap positions, ALL inserted chars, ALL orderings,")
        print(f"ALL three cipher variants, BOTH layer orders.")

    # Score distribution for Phase 1
    print(f"\nScore distribution (Phase 1, 34-crib):")
    for sc in sorted(score_distribution.keys()):
        if score_distribution[sc] > 0:
            print(f"  {sc}/34: {score_distribution[sc]:,} configs")

    if results:
        print(f"\nTop partial matches (≥15):")
        for r in sorted(results, key=lambda x: -x["score"])[:20]:
            print(f"  score={r['score']}/{r['n_cribs']} gap={r['gap']} char={r.get('char','')} "
                  f"var={r['variant']} model={r['model']}")

    # Verdict
    if full_matches:
        verdict = "BREAKTHROUGH"
    elif phase1_best >= 25:
        verdict = "STRONG_SIGNAL"
    elif phase1_best >= 15:
        verdict = "SIGNAL"
    elif phase1_best >= 10:
        verdict = "INTERESTING"
    else:
        verdict = "NOISE"

    print(f"\nVERDICT: {verdict}")

    # Expected noise analysis
    print(f"\nNoise analysis:")
    print(f"  With 34 cribs and period 7 (~5 per residue class):")
    print(f"  P(random full match) ≈ (1/26)^28 ≈ 10^-40")
    print(f"  P(random ≥15/34) ≈ extremely low")
    print(f"  Expected score from {total_tested:,} random trials: ~5-7")
    print(f"  Observed best: {phase1_best}/34")

    artifact = {
        "experiment_id": "e_s_130",
        "hypothesis": "98-char CT with CHECKPOINT@12-21 + ENE@22-34 + BC@64-74",
        "structural": "98 = 14 × 7 (perfect width-7 grid)",
        "total_cribs": 34,
        "total_tested": total_tested,
        "phase1_best": phase1_best,
        "phase1_best_config": phase1_best_config,
        "phase2_best": phase2_best,
        "phase3_best": phase3_best,
        "full_matches": full_matches,
        "top_results": sorted(results, key=lambda x: -x["score"])[:50],
        "score_distribution": {str(k): v for k, v in sorted(score_distribution.items())},
        "verdict": verdict,
        "runtime_seconds": elapsed,
        "repro_command": "PYTHONPATH=src python3 -u scripts/e_s_130_checkpoint_98char.py",
    }

    out_path = "artifacts/progressive_solve/stage4/checkpoint_98char_results.json"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(artifact, f, indent=2, default=str)
    print(f"\nArtifacts written to {out_path}")


if __name__ == "__main__":
    main()
