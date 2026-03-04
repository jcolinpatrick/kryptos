#!/usr/bin/env python3
"""
Cipher: autokey
Family: polyalphabetic
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-AUTOKEY-BOOTSTRAP-01: Proper Cross-Validation for All Primer Lengths

FIXES the Phase 4 bug in E-AUTOKEY-BOOTSTRAP-00: that experiment pre-loaded
BOTH cribs before propagation, so the 24/24 scores were trivially achieved
without actual cross-validation.

THIS experiment:
1. Loads ONLY the ENE crib (positions 21-33)
2. Forward-propagates through the autokey chain to all reachable positions
3. Cross-validates EVERY position in the BC crib (63-73) against known values
4. For surviving configs, extends backward to fill the full plaintext
5. Scores through the canonical pipeline

Also includes CT-autokey and backward-from-BC-only propagation.

Primer lengths tested: 1..60 (covering all possible reach configurations)
"""

import json
import os
import sys
import time

sys.path.insert(0, "src")

from kryptos.kernel.constants import (
    CT, CT_LEN, MOD, ALPH, ALPH_IDX,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    KRYPTOS_ALPHABET,
    BEAN_EQ, BEAN_INEQ,
    NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.scoring.aggregate import score_candidate

N = CT_LEN
AZ = ALPH
AZ_IDX = ALPH_IDX
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

ENE_START, ENE_END = 21, 34
BC_START, BC_END = 63, 74
ENE_WORD = "EASTNORTHEAST"
BC_WORD = "BERLINCLOCK"

VARIANTS = {
    "vig": {
        "derive_key": lambda c, p: (c - p) % MOD,
        "decrypt":    lambda c, k: (c - k) % MOD,
    },
    "beau": {
        "derive_key": lambda c, p: (c + p) % MOD,
        "decrypt":    lambda c, k: (k - c) % MOD,
    },
    "var_beau": {
        "derive_key": lambda c, p: (p - c) % MOD,
        "decrypt":    lambda c, k: (c + k) % MOD,
    },
}

ALPHABETS = {
    "AZ": {"alph": AZ, "idx": AZ_IDX},
    "KA": {"alph": KA, "idx": KA_IDX},
}

print("=" * 72)
print("E-AUTOKEY-BOOTSTRAP-01: Proper Cross-Validation for All Primer Lengths")
print("=" * 72)

t_start = time.time()

# ── Part A: Forward from ENE only, cross-validate at BC (m=1..60) ────────

print("\n" + "─" * 72)
print("PART A: Forward propagation from ENE ONLY → cross-validate at BC")
print("  Primer lengths 1..60, 3 variants × 2 alphabets = 360 configs")
print("─" * 72)

total_configs = 0
best_bc_matches = {}  # key: (alph, variant) → best bc_matches across all m

# Expected random BC matches: 11 positions × 1/26 ≈ 0.42
# So anything >= 3 is worth noting, >= 5 is interesting

for alph_name, alph_cfg in ALPHABETS.items():
    idx_map = alph_cfg["idx"]
    alph_str = alph_cfg["alph"]
    ct_nums = [idx_map[c] for c in CT]

    # BC crib in this alphabet's numeric representation
    bc_nums = {BC_START + i: idx_map[ch] for i, ch in enumerate(BC_WORD)}

    for vname, vfns in VARIANTS.items():
        derive_key = vfns["derive_key"]
        decrypt_fn = vfns["decrypt"]

        best_for_combo = 0
        all_m_results = []

        for m in range(1, 61):
            total_configs += 1

            # Initialize ONLY ENE crib
            pt = [None] * N
            for i, ch in enumerate(ENE_WORD):
                pt[ENE_START + i] = idx_map[ch]

            # Forward propagation: PT[i] = decrypt(CT[i], PT[i-m])
            # Starting from ENE positions, chain forward through the message
            # Multi-pass to ensure all reachable positions are filled
            max_passes = 10
            for _ in range(max_passes):
                changed = False
                for i in range(m, N):
                    if pt[i] is None and pt[i - m] is not None:
                        pt[i] = decrypt_fn(ct_nums[i], pt[i - m])
                        changed = True
                if not changed:
                    break

            # Cross-validate at BC positions
            bc_matches = 0
            bc_total_reachable = 0
            for pos, expected in bc_nums.items():
                if pt[pos] is not None:
                    bc_total_reachable += 1
                    if pt[pos] == expected:
                        bc_matches += 1

            if bc_matches > best_for_combo:
                best_for_combo = bc_matches

            # Record result
            known_count = sum(1 for v in pt if v is not None)
            all_m_results.append({
                "m": m,
                "bc_matches": bc_matches,
                "bc_reachable": bc_total_reachable,
                "known_positions": known_count,
            })

            if bc_matches >= 3:
                pt_str = "".join(alph_str[v] if v is not None else '?' for v in pt)
                # Compute Bean on what we have
                if all(v is not None for v in pt):
                    ks = [derive_key(ct_nums[i], pt[i]) for i in range(N)]
                    bean_eq_ok = all(ks[a] == ks[b] for a, b in BEAN_EQ)
                    bean_ineq_ok = all(ks[a] != ks[b] for a, b in BEAN_INEQ)
                    bean_msg = "PASS" if (bean_eq_ok and bean_ineq_ok) else "FAIL"
                else:
                    bean_msg = "incomplete"

                print(f"  {alph_name} {vname:10s} m={m:2d}: "
                      f"BC={bc_matches}/{bc_total_reachable} reachable/{len(BC_WORD)} total, "
                      f"known={known_count}/97, Bean={bean_msg}")

            if bc_matches == len(BC_WORD) and bc_total_reachable == len(BC_WORD):
                # FULL CROSS-VALIDATION PASS!
                # Now backward-propagate from BC to fill remaining positions
                for _ in range(max_passes):
                    changed = False
                    for i in range(N - 1, m - 1, -1):
                        if pt[i] is not None:
                            bp = i - m
                            if 0 <= bp < N and pt[bp] is None:
                                pt[bp] = derive_key(ct_nums[i], pt[i])
                                changed = True
                    for i in range(m, N):
                        if pt[i] is None and pt[i - m] is not None:
                            pt[i] = decrypt_fn(ct_nums[i], pt[i - m])
                            changed = True
                    if not changed:
                        break

                pt_str = "".join(alph_str[v] if v is not None else '?' for v in pt)
                known_final = sum(1 for v in pt if v is not None)
                print(f"    *** FULL BC CROSS-VALIDATION PASS ***")
                print(f"    After full propagation: {known_final}/97 known")
                print(f"    PT: {pt_str[:80]}")

                if all(v is not None for v in pt):
                    sb = score_candidate(pt_str)
                    ks = [derive_key(ct_nums[i], pt[i]) for i in range(N)]
                    bean_eq_ok = all(ks[a] == ks[b] for a, b in BEAN_EQ)
                    bean_ineq_ok = all(ks[a] != ks[b] for a, b in BEAN_INEQ)
                    print(f"    Score: {sb.crib_score}/24, IC={sb.ic_value:.4f}, "
                          f"Bean EQ={'PASS' if bean_eq_ok else 'FAIL'}, "
                          f"Bean INEQ={'PASS' if bean_ineq_ok else 'FAIL'}")

        best_bc_matches[(alph_name, vname)] = best_for_combo

        # Summary for this variant combo
        print(f"\n  {alph_name} {vname}: best BC cross-val = {best_for_combo}/{len(BC_WORD)} "
              f"across m=1..60")

        # Detailed view of all m values
        nonzero = [(r["m"], r["bc_matches"], r["bc_reachable"]) for r in all_m_results
                   if r["bc_matches"] > 0]
        if nonzero:
            print(f"    Non-zero BC matches: "
                  + ", ".join(f"m={m}:{bc}/{reach}" for m, bc, reach in nonzero))


# ── Part B: Backward from BC only, cross-validate at ENE (m=1..60) ───────

print("\n" + "─" * 72)
print("PART B: Backward propagation from BC ONLY → cross-validate at ENE")
print("─" * 72)

best_ene_matches = {}

for alph_name, alph_cfg in ALPHABETS.items():
    idx_map = alph_cfg["idx"]
    alph_str = alph_cfg["alph"]
    ct_nums = [idx_map[c] for c in CT]
    ene_nums = {ENE_START + i: idx_map[ch] for i, ch in enumerate(ENE_WORD)}

    for vname, vfns in VARIANTS.items():
        derive_key = vfns["derive_key"]
        decrypt_fn = vfns["decrypt"]

        best_for_combo = 0

        for m in range(1, 61):
            total_configs += 1

            # Initialize ONLY BC crib
            pt = [None] * N
            for i, ch in enumerate(BC_WORD):
                pt[BC_START + i] = idx_map[ch]

            # Backward propagation: PT[i-m] = derive_key(CT[i], PT[i])
            # And forward: PT[i] = decrypt(CT[i], PT[i-m])
            for _ in range(10):
                changed = False
                for i in range(N - 1, m - 1, -1):
                    if pt[i] is not None:
                        bp = i - m
                        if 0 <= bp < N and pt[bp] is None:
                            pt[bp] = derive_key(ct_nums[i], pt[i])
                            changed = True
                for i in range(m, N):
                    if pt[i] is None and pt[i - m] is not None:
                        pt[i] = decrypt_fn(ct_nums[i], pt[i - m])
                        changed = True
                if not changed:
                    break

            # Cross-validate at ENE positions
            ene_matches = 0
            ene_reachable = 0
            for pos, expected in ene_nums.items():
                if pt[pos] is not None:
                    ene_reachable += 1
                    if pt[pos] == expected:
                        ene_matches += 1

            if ene_matches > best_for_combo:
                best_for_combo = ene_matches

            if ene_matches >= 3:
                known_count = sum(1 for v in pt if v is not None)
                print(f"  {alph_name} {vname:10s} m={m:2d}: "
                      f"ENE={ene_matches}/{ene_reachable} reachable/{len(ENE_WORD)} total, "
                      f"known={known_count}/97")

                if ene_matches == len(ENE_WORD):
                    pt_str = "".join(alph_str[v] if v is not None else '?' for v in pt)
                    print(f"    *** FULL ENE CROSS-VALIDATION PASS ***")
                    print(f"    PT: {pt_str[:80]}")

        best_ene_matches[(alph_name, vname)] = best_for_combo
        if best_for_combo > 0:
            print(f"  {alph_name} {vname}: best ENE cross-val = "
                  f"{best_for_combo}/{len(ENE_WORD)} across m=1..60")


# ── Part C: CT-autokey (deterministic, all primers 1..60) ────────────────

print("\n" + "─" * 72)
print("PART C: CT-autokey (Key[i] = CT[i-m]), primers 1..60")
print("─" * 72)

ct_autokey_best = {"score": 0, "config": None}

for alph_name, alph_cfg in ALPHABETS.items():
    idx_map = alph_cfg["idx"]
    alph_str = alph_cfg["alph"]
    ct_nums = [idx_map[c] for c in CT]
    crib_nums = {pos: idx_map[ch] for pos, ch in CRIB_DICT.items()}

    for vname, vfns in VARIANTS.items():
        decrypt_fn = vfns["decrypt"]

        for m in range(1, 61):
            total_configs += 1

            # PT[i] = decrypt(CT[i], CT[i-m]) for i >= m
            pt = [None] * N
            for i in range(m, N):
                pt[i] = decrypt_fn(ct_nums[i], ct_nums[i - m])

            # Count crib matches
            crib_score = sum(1 for pos, exp in crib_nums.items()
                            if pt[pos] is not None and pt[pos] == exp)

            if crib_score > ct_autokey_best["score"]:
                ct_autokey_best = {
                    "score": crib_score,
                    "config": {"alphabet": alph_name, "variant": vname, "m": m},
                }

            if crib_score >= 5:
                pt_str = "".join(alph_str[v] if v is not None else '?' for v in pt)
                print(f"  {alph_name} {vname:10s} m={m:2d}: cribs={crib_score}/24")

print(f"\n  CT-autokey best: {ct_autokey_best['score']}/24 at {ct_autokey_best['config']}")


# ── Part D: Bidirectional from both cribs (proper contradiction detection) ──

print("\n" + "─" * 72)
print("PART D: Bidirectional propagation — contradiction detection (m=1..60)")
print("  Load ENE only, propagate, then CHECK (don't set) BC positions.")
print("  Separately: load BC only, propagate, then CHECK ENE positions.")
print("  Report contradiction counts.")
print("─" * 72)

# For each (m, variant, alphabet):
# Forward from ENE: compute PT at BC positions, compare with known BC
# Backward from BC: compute PT at ENE positions, compare with known ENE
# If both match fully: BIDIRECTIONAL CROSS-VALIDATION

bidirectional_survivors = []

for alph_name, alph_cfg in ALPHABETS.items():
    idx_map = alph_cfg["idx"]
    alph_str = alph_cfg["alph"]
    ct_nums = [idx_map[c] for c in CT]
    ene_nums = {ENE_START + i: idx_map[ch] for i, ch in enumerate(ENE_WORD)}
    bc_nums = {BC_START + i: idx_map[ch] for i, ch in enumerate(BC_WORD)}

    for vname, vfns in VARIANTS.items():
        derive_key = vfns["derive_key"]
        decrypt_fn = vfns["decrypt"]

        for m in range(1, 61):
            # Forward from ENE
            pt_fwd = [None] * N
            for pos, val in ene_nums.items():
                pt_fwd[pos] = val
            for _ in range(10):
                changed = False
                for i in range(m, N):
                    if pt_fwd[i] is None and pt_fwd[i - m] is not None:
                        pt_fwd[i] = decrypt_fn(ct_nums[i], pt_fwd[i - m])
                        changed = True
                if not changed:
                    break

            # Check at BC positions
            fwd_bc_match = 0
            fwd_bc_reach = 0
            fwd_bc_contra = 0
            for pos, expected in bc_nums.items():
                if pt_fwd[pos] is not None:
                    fwd_bc_reach += 1
                    if pt_fwd[pos] == expected:
                        fwd_bc_match += 1
                    else:
                        fwd_bc_contra += 1

            # Backward from BC
            pt_bwd = [None] * N
            for pos, val in bc_nums.items():
                pt_bwd[pos] = val
            for _ in range(10):
                changed = False
                for i in range(N - 1, m - 1, -1):
                    if pt_bwd[i] is not None:
                        bp = i - m
                        if 0 <= bp < N and pt_bwd[bp] is None:
                            pt_bwd[bp] = derive_key(ct_nums[i], pt_bwd[i])
                            changed = True
                for i in range(m, N):
                    if pt_bwd[i] is None and pt_bwd[i - m] is not None:
                        pt_bwd[i] = decrypt_fn(ct_nums[i], pt_bwd[i - m])
                        changed = True
                if not changed:
                    break

            # Check at ENE positions
            bwd_ene_match = 0
            bwd_ene_reach = 0
            bwd_ene_contra = 0
            for pos, expected in ene_nums.items():
                if pt_bwd[pos] is not None:
                    bwd_ene_reach += 1
                    if pt_bwd[pos] == expected:
                        bwd_ene_match += 1
                    else:
                        bwd_ene_contra += 1

            # Report significant results
            if (fwd_bc_match >= 3 and fwd_bc_reach >= 3) or \
               (bwd_ene_match >= 3 and bwd_ene_reach >= 3):
                print(f"  {alph_name} {vname:10s} m={m:2d}: "
                      f"FWD→BC={fwd_bc_match}/{fwd_bc_reach}(+{fwd_bc_contra} contra), "
                      f"BWD→ENE={bwd_ene_match}/{bwd_ene_reach}(+{bwd_ene_contra} contra)")

            if fwd_bc_match == len(BC_WORD) and bwd_ene_match == len(ENE_WORD):
                print(f"    *** FULL BIDIRECTIONAL CROSS-VALIDATION ***")
                bidirectional_survivors.append({
                    "alphabet": alph_name, "variant": vname, "m": m,
                })


# ── Summary ──────────────────────────────────────────────────────────────

total_time = time.time() - t_start

print("\n" + "=" * 72)
print("SUMMARY — E-AUTOKEY-BOOTSTRAP-01")
print("=" * 72)
print(f"  Total configs tested: {total_configs}")

# Part A summary
print(f"\n  Part A (ENE→BC forward cross-val):")
max_bc = max(best_bc_matches.values()) if best_bc_matches else 0
print(f"    Best BC cross-val: {max_bc}/{len(BC_WORD)}")
for key, val in sorted(best_bc_matches.items(), key=lambda x: -x[1]):
    if val > 0:
        print(f"      {key[0]} {key[1]}: {val}/{len(BC_WORD)}")

# Part B summary
print(f"\n  Part B (BC→ENE backward cross-val):")
max_ene = max(best_ene_matches.values()) if best_ene_matches else 0
print(f"    Best ENE cross-val: {max_ene}/{len(ENE_WORD)}")
for key, val in sorted(best_ene_matches.items(), key=lambda x: -x[1]):
    if val > 0:
        print(f"      {key[0]} {key[1]}: {val}/{len(ENE_WORD)}")

# Part C summary
print(f"\n  Part C (CT-autokey): best {ct_autokey_best['score']}/24")

# Part D summary
print(f"\n  Part D (bidirectional cross-val): {len(bidirectional_survivors)} survivors")

# Overall verdict
overall_best_crossval = max(max_bc, max_ene)
exp_random_11 = 11.0 / 26.0  # ~0.42 expected for 11 positions
exp_random_13 = 13.0 / 26.0  # ~0.50 expected for 13 positions

print(f"\n  Expected random: ~{exp_random_11:.1f}/11 (BC), ~{exp_random_13:.1f}/13 (ENE)")
print(f"  Observed best: {max_bc}/11 (BC), {max_ene}/13 (ENE)")

if overall_best_crossval >= 8:
    verdict_status = "promising"
    verdict = f"SIGNAL at {overall_best_crossval} cross-val matches"
elif overall_best_crossval >= 4:
    verdict_status = "inconclusive"
    verdict = f"MARGINAL at {overall_best_crossval} cross-val matches"
else:
    verdict_status = "disproved"
    verdict = (f"ELIMINATED — PT-autokey (all variants, AZ+KA, primers 1-60) "
               f"under direct correspondence: max cross-val = {overall_best_crossval}, "
               f"expected random ~{exp_random_11:.1f}. "
               f"CT-autokey best = {ct_autokey_best['score']}/24.")

print(f"\n  VERDICT: {verdict}")

# Save
os.makedirs("results", exist_ok=True)
output = {
    "experiment": "E-AUTOKEY-BOOTSTRAP-01",
    "description": "Proper autokey cross-validation (ENE↔BC, no transposition)",
    "total_configs": total_configs,
    "best_bc_crossval": max_bc,
    "best_ene_crossval": max_ene,
    "ct_autokey_best": ct_autokey_best,
    "bidirectional_survivors": bidirectional_survivors,
    "verdict_status": verdict_status,
    "verdict": verdict,
    "runtime_seconds": round(total_time, 1),
    "repro": "PYTHONPATH=src python3 -u scripts/e_autokey_bootstrap_01_crossval.py",
}
with open("results/e_autokey_bootstrap_01_crossval.json", "w") as f:
    json.dump(output, f, indent=2, default=str)

print(f"\n  Artifact: results/e_autokey_bootstrap_01_crossval.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_autokey_bootstrap_01_crossval.py")
