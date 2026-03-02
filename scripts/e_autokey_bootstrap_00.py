#!/usr/bin/env python3
"""
E-AUTOKEY-BOOTSTRAP-00: Autokey Chain Propagation from Crib Bootstrap

STRATEGY
--------
In a PT-autokey cipher with primer length m:
  Key[i] = seed[i]     for i < m
  Key[i] = PT[i - m]   for i >= m

This creates a deterministic chain: knowing PT at any contiguous span of
length >= m lets us propagate FORWARD (decrypt) and BACKWARD (recover key
= prior plaintext).

We have two cribs:
  - ENE: PT[21..33] = EASTNORTHEAST (13 chars)
  - BC:  PT[63..73] = BERLINCLOCK   (11 chars)

PHASE 1: Forward propagation from ENE to BC (cross-validation gate)
  For m = 1..13:
    - Forward-decrypt from pos 34 using Key[34] = PT[34-m] (within ENE crib)
    - Continue through gap to pos 63-73
    - Cross-validate: does computed PT[63..73] match BERLINCLOCK?
    - If YES: extend to full plaintext (pos 0-96) and score

PHASE 2: Backward propagation from BC to ENE (independent cross-validation)
  For m = 30..52 (range where backward step from BC overlaps with ENE):
    - Derive Key[63..73] from CT and BC crib
    - Key[i] = PT[i-m], so PT[i-m] = Key[i] = back-derived
    - Cross-validate against known ENE positions

PHASE 3: CT-autokey bootstrap (deterministic, no propagation needed)
  For m = 1..15:
    - Key[i] = CT[i-m], PT[i] = decrypt(CT[i], CT[i-m])
    - Fully determined. Check all cribs. Score survivors.

PHASE 4: Multi-step backward chain from BC (m < 30)
  For m = 1..29:
    - Step 1: recover PT[63-m..73-m] from Key[63..73]
    - Step 2: recover PT[63-2m..73-2m] from Key[63-m..73-m]
    - Continue until overlap with ENE or pos 0
    - Cross-validate and extend

Each phase tests 3 cipher variants × 2 alphabets (AZ, KA).
Uses framework scoring pipeline for evaluation.

Output: results/e_autokey_bootstrap_00.json
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
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    NOISE_FLOOR, STORE_THRESHOLD,
    SIGNAL_THRESHOLD, BREAKTHROUGH_THRESHOLD,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.constraints.bean import verify_bean

# ── Setup ──────────────────────────────────────────────────────────────────

N = CT_LEN  # 97
AZ = ALPH
AZ_IDX = ALPH_IDX
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

ENE_START, ENE_END = 21, 34   # ENE spans [21, 34) = positions 21-33
BC_START, BC_END = 63, 74     # BC spans [63, 74) = positions 63-73
ENE_WORD = "EASTNORTHEAST"
BC_WORD = "BERLINCLOCK"

CRIB_POS = sorted(CRIB_DICT.keys())

# Cipher variant definitions
# Each variant defines:
#   derive_key(ct_val, pt_val) -> key_val
#   decrypt(ct_val, key_val)   -> pt_val
VARIANTS = {
    "vig": {
        "derive_key": lambda c, p: (c - p) % MOD,  # K = C - P
        "decrypt":    lambda c, k: (c - k) % MOD,  # P = C - K
    },
    "beau": {
        "derive_key": lambda c, p: (c + p) % MOD,  # K = C + P
        "decrypt":    lambda c, k: (k - c) % MOD,  # P = K - C
    },
    "var_beau": {
        "derive_key": lambda c, p: (p - c) % MOD,  # K = P - C
        "decrypt":    lambda c, k: (c + k) % MOD,  # P = C + K
    },
}

# Alphabet configurations
ALPHABETS = {
    "AZ": {"alph": AZ, "idx": AZ_IDX},
    "KA": {"alph": KA, "idx": KA_IDX},
}


def letter_to_num(ch, idx_map):
    return idx_map[ch]


def num_to_letter(v, alph_str):
    return alph_str[v % MOD]


def ct_as_nums(idx_map):
    return [idx_map[c] for c in CT]


def crib_as_nums(idx_map):
    """Return dict: position -> numeric value of plaintext."""
    return {pos: idx_map[ch] for pos, ch in CRIB_DICT.items()}


def count_crib_matches(pt_nums, crib_nums):
    """Count how many crib positions match in plaintext numeric array."""
    matches = 0
    for pos, expected in crib_nums.items():
        if 0 <= pos < len(pt_nums) and pt_nums[pos] == expected:
            matches += 1
    return matches


def pt_nums_to_str(pt_nums, alph_str):
    return "".join(alph_str[v % MOD] if v is not None else '?' for v in pt_nums)


def compute_full_keystream(ct_nums, pt_nums, variant_fns):
    """Derive full keystream from CT and PT numeric arrays."""
    derive_key = variant_fns["derive_key"]
    return [derive_key(ct_nums[i], pt_nums[i]) for i in range(len(ct_nums))]


def check_bean_on_keystream(ks):
    """Check Bean constraints on a full keystream."""
    # Equality
    for a, b in BEAN_EQ:
        if ks[a] != ks[b]:
            return False, f"EQ FAIL: k[{a}]={ks[a]} != k[{b}]={ks[b]}"
    # Inequalities
    for a, b in BEAN_INEQ:
        if ks[a] == ks[b]:
            return False, f"INEQ FAIL: k[{a}]=k[{b}]={ks[a]}"
    return True, "PASS"


# ── Phase 1: Forward propagation ENE → BC (m=1..13) ──────────────────────

print("=" * 72)
print("E-AUTOKEY-BOOTSTRAP-00: Autokey Chain Propagation from Crib Bootstrap")
print("=" * 72)

t_start = time.time()
all_results = []
best_overall = {"score": 0, "config": None, "pt": ""}
total_configs = 0

print("\n" + "─" * 72)
print("PHASE 1: Forward propagation from ENE through gap to BC (m=1..13)")
print("─" * 72)
print("  For PT-autokey with primer length m:")
print("  Key[i] = PT[i-m]. Forward from pos 34: Key[34] = PT[34-m] (in ENE).")
print("  Propagate through gap positions 34-62, then cross-validate at BC 63-73.")
print()

phase1_survivors = []

for alph_name, alph_cfg in ALPHABETS.items():
    idx_map = alph_cfg["idx"]
    alph_str = alph_cfg["alph"]
    ct_nums = ct_as_nums(idx_map)
    crib_nums = crib_as_nums(idx_map)

    for vname, vfns in VARIANTS.items():
        derive_key = vfns["derive_key"]
        decrypt_fn = vfns["decrypt"]

        for m in range(1, 14):  # primer length 1..13
            total_configs += 1

            # Build known PT array from ENE crib
            pt_nums = [None] * N
            for i, ch in enumerate(ENE_WORD):
                pt_nums[ENE_START + i] = idx_map[ch]
            for i, ch in enumerate(BC_WORD):
                pt_nums[BC_START + i] = idx_map[ch]

            # Forward propagation from pos max(m, ENE_START) to N-1
            # Key[i] = PT[i-m] for i >= m
            # We can start from the first position after ENE where PT[i-m] is known

            # Check: can we start propagating?
            # First propagation position is 34 (right after ENE)
            # Key[34] = PT[34-m]. Is 34-m within ENE (21-33)?
            start_key_pos = 34 - m
            if start_key_pos < ENE_START or start_key_pos >= ENE_END:
                continue  # can't start propagation with m at this value

            # Forward propagation through positions 34..N-1
            can_propagate = True
            for i in range(34, N):
                key_pos = i - m
                if key_pos < 0:
                    can_propagate = False
                    break
                if pt_nums[key_pos] is None:
                    can_propagate = False
                    break
                key_val = pt_nums[key_pos]
                pt_nums[i] = decrypt_fn(ct_nums[i], key_val)

            if not can_propagate:
                continue

            # Cross-validate at BC positions
            bc_matches = 0
            bc_details = []
            for i, ch in enumerate(BC_WORD):
                pos = BC_START + i
                expected = idx_map[ch]
                got = pt_nums[pos]
                match = (got == expected)
                bc_details.append((pos, ch, alph_str[got] if got is not None else '?', match))
                if match:
                    bc_matches += 1

            # Now backward propagation from ENE to fill positions 0..20
            # Key[i] = PT[i-m] for i >= m
            # At pos i (known): Key[i] = derive_key(CT[i], PT[i])
            # PT[i-m] = Key[i]
            # Work backward from pos 21 (start of ENE):
            #   Key[21] = PT[21-m] → compute PT[21-m]
            #   Then Key[20] = PT[20-m] → but we need to know PT[20] first
            # Actually, for backward propagation we work position by position going LEFT:
            # At position p (known), Key[p] = PT[p-m] → PT[p-m] is now known

            # We know PT[21..33] and now PT[34..96] from forward propagation.
            # Backward: from position m (first position where key = PT):
            # Key[p] = PT[p-m]. If p is known, then PT[p-m] = Key[p] = derive_key(CT[p], PT[p])
            for p in range(min(ENE_START + m, N) - 1, m - 1, -1):
                if pt_nums[p] is not None:
                    back_pos = p - m
                    if back_pos >= 0 and pt_nums[back_pos] is None:
                        key_val = derive_key(ct_nums[p], pt_nums[p])
                        pt_nums[back_pos] = key_val

            # Continue backward until we fill as much as we can
            changed = True
            while changed:
                changed = False
                for p in range(m, N):
                    if pt_nums[p] is not None:
                        back_pos = p - m
                        if back_pos >= 0 and pt_nums[back_pos] is None:
                            key_val = derive_key(ct_nums[p], pt_nums[p])
                            pt_nums[back_pos] = key_val
                            changed = True

            # For the primer region (positions 0..m-1):
            # We need seed values. If we've recovered all PT[m..N-1], we can try
            # all 26^m seeds (but only for m=1..3 to keep it tractable)
            # For now, just record what we have.

            # If m <= 3, try all possible seed values for remaining positions
            if m <= 3 and any(pt_nums[i] is None for i in range(m)):
                seed_candidates = []
                # For each unknown primer position, try all 26 values
                unknown_primer_pos = [i for i in range(m) if pt_nums[i] is None]

                if len(unknown_primer_pos) <= 3:
                    # Enumerate all seed combos
                    from itertools import product
                    best_seed_score = 0
                    best_seed_pt = pt_nums[:]

                    for seed_combo in product(range(MOD), repeat=len(unknown_primer_pos)):
                        trial = pt_nums[:]
                        for idx, pos in enumerate(unknown_primer_pos):
                            trial[pos] = seed_combo[idx]

                        # Count total crib matches
                        crib_score = count_crib_matches(trial, crib_nums)
                        if crib_score > best_seed_score:
                            best_seed_score = crib_score
                            best_seed_pt = trial[:]

                    pt_nums = best_seed_pt

            # Count overall crib matches
            total_crib = count_crib_matches(pt_nums, crib_nums)

            # Build full plaintext string (use '?' for unknown positions)
            pt_str = pt_nums_to_str(pt_nums, alph_str)

            # Compute keystream and check Bean
            if all(v is not None for v in pt_nums):
                ks = compute_full_keystream(ct_nums, pt_nums, vfns)
                bean_pass, bean_msg = check_bean_on_keystream(ks)
            else:
                bean_pass, bean_msg = None, "incomplete PT"
                ks = None

            config = {
                "phase": 1,
                "alphabet": alph_name,
                "variant": vname,
                "primer_length": m,
                "bc_cross_matches": bc_matches,
                "total_crib_matches": total_crib,
                "bean_pass": bean_pass,
                "bean_msg": bean_msg,
                "pt_preview": pt_str[:50],
            }

            # Report all results for m=1..13
            if bc_matches > 0 or total_crib > NOISE_FLOOR:
                flag = "*** SIGNAL ***" if bc_matches == len(BC_WORD) else ""
                print(f"  {alph_name} {vname:10s} m={m:2d}: "
                      f"BC cross-val={bc_matches}/{len(BC_WORD)}, "
                      f"total cribs={total_crib}/{N_CRIBS}, "
                      f"bean={bean_msg} {flag}")
                if bc_matches >= 5:
                    print(f"    BC detail: {bc_details}")
                    print(f"    PT: {pt_str[:80]}")

            if bc_matches == len(BC_WORD):
                # FULL cross-validation — this is significant!
                phase1_survivors.append(config)

                # Full scoring
                if all(v is not None for v in pt_nums):
                    sb = score_candidate(pt_str)
                    config["score_breakdown"] = {
                        "crib_score": sb.crib_score,
                        "ic": sb.ic_value,
                        "level": sb.level,
                    }
                    print(f"    FULL CROSS-VALIDATION PASS!")
                    print(f"    Score: {sb.crib_score}/24, IC={sb.ic_value:.4f}, Level={sb.level}")
                    print(f"    PT: {pt_str}")

                    if sb.crib_score > best_overall["score"]:
                        best_overall = {"score": sb.crib_score, "config": config, "pt": pt_str}

            all_results.append(config)

print(f"\n  Phase 1: {total_configs} configs tested, {len(phase1_survivors)} cross-validation passes")


# ── Phase 2: Backward propagation BC → ENE (m=30..52) ────────────────────

print("\n" + "─" * 72)
print("PHASE 2: Backward propagation from BC to ENE (m=30..52)")
print("─" * 72)
print("  Key[i] = PT[i-m]. At BC: Key[i] = derive_key(CT[i], PT[i]).")
print("  So PT[i-m] = Key[i]. For m in [30,52], positions 63-m..73-m")
print("  overlap with ENE (21..33). Cross-validate at overlap.")
print()

phase2_configs = 0
phase2_survivors = []

for alph_name, alph_cfg in ALPHABETS.items():
    idx_map = alph_cfg["idx"]
    alph_str = alph_cfg["alph"]
    ct_nums = ct_as_nums(idx_map)
    crib_nums = crib_as_nums(idx_map)

    for vname, vfns in VARIANTS.items():
        derive_key = vfns["derive_key"]
        decrypt_fn = vfns["decrypt"]

        for m in range(30, 53):  # m=30..52
            phase2_configs += 1
            total_configs += 1

            # Build known PT from both cribs
            pt_nums = [None] * N
            for i, ch in enumerate(ENE_WORD):
                pt_nums[ENE_START + i] = idx_map[ch]
            for i, ch in enumerate(BC_WORD):
                pt_nums[BC_START + i] = idx_map[ch]

            # Backward step: from BC crib positions 63..73
            # Key[i] = derive_key(CT[i], PT[i]) for known i
            # PT[i-m] = Key[i]
            ene_matches = 0
            total_overlap = 0

            for i in range(BC_START, BC_END):
                if pt_nums[i] is not None:
                    back_pos = i - m
                    if 0 <= back_pos < N:
                        key_val = derive_key(ct_nums[i], pt_nums[i])

                        # Check if back_pos is in ENE crib
                        if back_pos in crib_nums:
                            total_overlap += 1
                            if key_val == crib_nums[back_pos]:
                                ene_matches += 1
                            else:
                                pass  # mismatch

                        # Record derived PT
                        if pt_nums[back_pos] is None:
                            pt_nums[back_pos] = key_val
                        elif pt_nums[back_pos] != key_val:
                            pass  # contradiction with known PT

            if total_overlap > 0 and ene_matches > 0:
                # Some overlap — report
                flag = "*** FULL ***" if ene_matches == total_overlap else ""
                if ene_matches >= 3 or ene_matches == total_overlap:
                    print(f"  {alph_name} {vname:10s} m={m:2d}: "
                          f"ENE overlap={ene_matches}/{total_overlap} {flag}")

                if ene_matches == total_overlap and total_overlap >= 5:
                    phase2_survivors.append({
                        "phase": 2,
                        "alphabet": alph_name,
                        "variant": vname,
                        "primer_length": m,
                        "ene_overlap_matches": ene_matches,
                        "total_overlap": total_overlap,
                    })

                    # Full propagation if we have a good match
                    # Forward from ENE through gap
                    changed = True
                    while changed:
                        changed = False
                        for i in range(m, N):
                            if pt_nums[i] is None and pt_nums[i - m] is not None:
                                pt_nums[i] = decrypt_fn(ct_nums[i], pt_nums[i - m])
                                changed = True
                        # Backward
                        for i in range(N - 1, m - 1, -1):
                            if pt_nums[i] is not None:
                                back_pos = i - m
                                if 0 <= back_pos < N and pt_nums[back_pos] is None:
                                    pt_nums[back_pos] = derive_key(ct_nums[i], pt_nums[i])
                                    changed = True

                    total_crib = count_crib_matches(pt_nums, crib_nums)
                    pt_str = pt_nums_to_str(pt_nums, alph_str)
                    known_count = sum(1 for v in pt_nums if v is not None)

                    print(f"    After full propagation: {known_count}/97 positions known, "
                          f"cribs={total_crib}/24")
                    print(f"    PT: {pt_str[:80]}")

                    if all(v is not None for v in pt_nums):
                        sb = score_candidate(pt_str)
                        ks = compute_full_keystream(ct_nums, pt_nums, vfns)
                        bean_pass, bean_msg = check_bean_on_keystream(ks)
                        print(f"    Score: {sb.crib_score}/24, IC={sb.ic_value:.4f}, "
                              f"Bean={bean_msg}")

                        if sb.crib_score > best_overall["score"]:
                            best_overall = {"score": sb.crib_score, "config": {
                                "phase": 2, "alphabet": alph_name, "variant": vname,
                                "primer_length": m
                            }, "pt": pt_str}

print(f"\n  Phase 2: {phase2_configs} configs, {len(phase2_survivors)} survivors")


# ── Phase 3: CT-autokey (deterministic) ───────────────────────────────────

print("\n" + "─" * 72)
print("PHASE 3: CT-autokey bootstrap (fully deterministic)")
print("─" * 72)
print("  Key[i] = CT[i-m]. PT[i] = decrypt(CT[i], CT[i-m]).")
print("  No propagation needed — entire PT is determined for given m.")
print()

phase3_configs = 0
phase3_best = {"score": 0, "config": None}

for alph_name, alph_cfg in ALPHABETS.items():
    idx_map = alph_cfg["idx"]
    alph_str = alph_cfg["alph"]
    ct_nums = ct_as_nums(idx_map)
    crib_nums = crib_as_nums(idx_map)

    for vname, vfns in VARIANTS.items():
        decrypt_fn = vfns["decrypt"]
        derive_key = vfns["derive_key"]

        for m in range(1, 16):  # primer length 1..15
            phase3_configs += 1
            total_configs += 1

            # PT[i] = decrypt(CT[i], CT[i-m]) for i >= m
            # For i < m, we need the seed. Try all 26 seeds per primer position.
            # For simplicity with m=1, try all 26; for m>1, just mark unknown.

            # First compute positions m..N-1
            pt_nums = [None] * N
            for i in range(m, N):
                key_val = ct_nums[i - m]
                pt_nums[i] = decrypt_fn(ct_nums[i], key_val)

            # Count crib matches (positions m..N-1 only)
            crib_score_no_seed = count_crib_matches(pt_nums, crib_nums)

            # For m=1..3, try all seeds
            if m <= 3:
                from itertools import product
                best_seed_crib = crib_score_no_seed
                best_seed_pt = pt_nums[:]

                unknown_pos = [i for i in range(m) if pt_nums[i] is None]
                for seed_combo in product(range(MOD), repeat=len(unknown_pos)):
                    trial = pt_nums[:]
                    for idx, pos in enumerate(unknown_pos):
                        trial[pos] = seed_combo[idx]

                    crib_sc = count_crib_matches(trial, crib_nums)
                    if crib_sc > best_seed_crib:
                        best_seed_crib = crib_sc
                        best_seed_pt = trial[:]

                pt_nums = best_seed_pt
                crib_score_final = best_seed_crib
            else:
                crib_score_final = crib_score_no_seed

            pt_str = pt_nums_to_str(pt_nums, alph_str)

            if crib_score_final > phase3_best["score"]:
                phase3_best = {
                    "score": crib_score_final,
                    "config": {"alphabet": alph_name, "variant": vname, "m": m},
                    "pt": pt_str,
                }

            if crib_score_final > NOISE_FLOOR:
                # Full scoring
                if all(v is not None for v in pt_nums):
                    sb = score_candidate(pt_str)
                    ks = compute_full_keystream(ct_nums, pt_nums, vfns)
                    bean_pass, bean_msg = check_bean_on_keystream(ks)
                else:
                    bean_pass, bean_msg = None, "incomplete"

                print(f"  {alph_name} {vname:10s} m={m:2d}: cribs={crib_score_final}/24 "
                      f"bean={bean_msg}")
                if crib_score_final >= STORE_THRESHOLD:
                    print(f"    PT: {pt_str[:70]}...")

                if crib_score_final > best_overall["score"]:
                    best_overall = {
                        "score": crib_score_final,
                        "config": {"phase": 3, "alphabet": alph_name,
                                   "variant": vname, "m": m},
                        "pt": pt_str,
                    }

print(f"\n  Phase 3: {phase3_configs} configs, "
      f"best={phase3_best['score']}/24 at {phase3_best['config']}")


# ── Phase 4: Multi-step backward chain from BC (m=1..29) ─────────────────

print("\n" + "─" * 72)
print("PHASE 4: Multi-step backward chain BC → ENE (m=1..29)")
print("─" * 72)
print("  For m < 30, single backward step from BC doesn't reach ENE.")
print("  Chain: step k recovers PT[63-k*m..73-k*m].")
print("  Continue until overlap with ENE (pos 21-33).")
print()

phase4_configs = 0
phase4_survivors = []

for alph_name, alph_cfg in ALPHABETS.items():
    idx_map = alph_cfg["idx"]
    alph_str = alph_cfg["alph"]
    ct_nums = ct_as_nums(idx_map)
    crib_nums = crib_as_nums(idx_map)

    for vname, vfns in VARIANTS.items():
        derive_key = vfns["derive_key"]
        decrypt_fn = vfns["decrypt"]

        for m in range(14, 30):  # m=14..29 (m=1..13 covered in Phase 1)
            phase4_configs += 1
            total_configs += 1

            # Start with both cribs
            pt_nums = [None] * N
            for i, ch in enumerate(ENE_WORD):
                pt_nums[ENE_START + i] = idx_map[ch]
            for i, ch in enumerate(BC_WORD):
                pt_nums[BC_START + i] = idx_map[ch]

            # Iterative propagation: backward and forward until no more changes
            max_iters = 100
            for iteration in range(max_iters):
                changed = False

                # Forward: PT[i] = decrypt(CT[i], PT[i-m]) for i >= m
                for i in range(m, N):
                    if pt_nums[i] is None and pt_nums[i - m] is not None:
                        pt_nums[i] = decrypt_fn(ct_nums[i], pt_nums[i - m])
                        changed = True

                # Backward: PT[i-m] = derive_key(CT[i], PT[i]) for i >= m
                for i in range(N - 1, m - 1, -1):
                    if pt_nums[i] is not None:
                        back_pos = i - m
                        if 0 <= back_pos < N and pt_nums[back_pos] is None:
                            pt_nums[back_pos] = derive_key(ct_nums[i], pt_nums[i])
                            changed = True

                if not changed:
                    break

            # Check cross-validation: how many crib positions match?
            total_crib = count_crib_matches(pt_nums, crib_nums)
            known_count = sum(1 for v in pt_nums if v is not None)

            # Check for contradictions: if backward derivation gives different
            # value than known crib at same position
            contradictions = 0
            for pos in CRIB_POS:
                if pt_nums[pos] is not None and pt_nums[pos] != crib_nums[pos]:
                    contradictions += 1

            if contradictions == 0 and total_crib > NOISE_FLOOR:
                pt_str = pt_nums_to_str(pt_nums, alph_str)
                print(f"  {alph_name} {vname:10s} m={m:2d}: "
                      f"cribs={total_crib}/24, known={known_count}/97, "
                      f"contradictions={contradictions}")

                if total_crib >= STORE_THRESHOLD:
                    print(f"    PT: {pt_str[:70]}...")

                    if all(v is not None for v in pt_nums):
                        sb = score_candidate(pt_str)
                        ks = compute_full_keystream(ct_nums, pt_nums, vfns)
                        bean_pass, bean_msg = check_bean_on_keystream(ks)
                        print(f"    Score: {sb.crib_score}/24, IC={sb.ic_value:.4f}, "
                              f"Bean={bean_msg}")

                phase4_survivors.append({
                    "phase": 4,
                    "alphabet": alph_name,
                    "variant": vname,
                    "primer_length": m,
                    "total_crib_matches": total_crib,
                    "known_positions": known_count,
                    "contradictions": contradictions,
                })

                if total_crib > best_overall["score"]:
                    best_overall = {
                        "score": total_crib,
                        "config": {"phase": 4, "alphabet": alph_name,
                                   "variant": vname, "m": m},
                        "pt": pt_str,
                    }
            elif contradictions > 0:
                # This m is structurally incompatible
                pass

print(f"\n  Phase 4: {phase4_configs} configs, {len(phase4_survivors)} survivors")


# ── Phase 5: Extended seed search for Phase 1 m=1..13 ────────────────────

print("\n" + "─" * 72)
print("PHASE 5: Extended seed search for forward-propagation (m=1..13)")
print("  Trying all 26 seeds per primer position, scoring with full pipeline")
print("─" * 72)

phase5_best = {"score": 0, "config": None, "pt": ""}

for alph_name, alph_cfg in ALPHABETS.items():
    idx_map = alph_cfg["idx"]
    alph_str = alph_cfg["alph"]
    ct_nums = ct_as_nums(idx_map)
    crib_nums = crib_as_nums(idx_map)

    for vname, vfns in VARIANTS.items():
        derive_key = vfns["derive_key"]
        decrypt_fn = vfns["decrypt"]

        for m in range(1, 14):
            total_configs += 1

            # For PT-autokey: the chain from ENE propagates forward deterministically.
            # The only unknowns are:
            # 1. Seed positions 0..m-1 (if backward propagation doesn't reach them)
            # 2. Positions between pos 0 and where backward propagation reaches

            # Rebuild the forward propagation
            pt_core = [None] * N
            for i, ch in enumerate(ENE_WORD):
                pt_core[ENE_START + i] = idx_map[ch]

            # Forward from position max(m, 34)
            # Key[i] = PT[i-m] for i >= m
            start_key_pos = 34 - m
            if start_key_pos < ENE_START or start_key_pos >= ENE_END:
                continue

            for i in range(34, N):
                if pt_core[i - m] is not None:
                    pt_core[i] = decrypt_fn(ct_nums[i], pt_core[i - m])
                else:
                    break  # chain broken

            # Backward propagation
            changed = True
            while changed:
                changed = False
                for i in range(N - 1, m - 1, -1):
                    if pt_core[i] is not None:
                        back_pos = i - m
                        if 0 <= back_pos < N and pt_core[back_pos] is None:
                            pt_core[back_pos] = derive_key(ct_nums[i], pt_core[i])
                            changed = True

            # Check cross-validation
            bc_ok = all(
                pt_core[BC_START + i] is not None and
                pt_core[BC_START + i] == idx_map[BC_WORD[i]]
                for i in range(len(BC_WORD))
            )

            if not bc_ok:
                continue

            # Find unknown positions that need seed
            unknown_pos = [i for i in range(N) if pt_core[i] is None]

            if len(unknown_pos) == 0:
                # Fully determined
                pt_str = pt_nums_to_str(pt_core, alph_str)
                sb = score_candidate(pt_str)
                ks = compute_full_keystream(ct_nums, pt_core, vfns)
                bean_pass, bean_msg = check_bean_on_keystream(ks)

                if sb.crib_score > phase5_best["score"]:
                    phase5_best = {"score": sb.crib_score, "config": {
                        "alphabet": alph_name, "variant": vname, "m": m
                    }, "pt": pt_str}

                if sb.crib_score > NOISE_FLOOR:
                    print(f"  {alph_name} {vname:10s} m={m:2d}: "
                          f"cribs={sb.crib_score}/24, IC={sb.ic_value:.4f}, "
                          f"Bean={bean_msg}")
                    print(f"    PT: {pt_str[:70]}...")

            elif len(unknown_pos) <= 3:
                # Try all seed combos (26^1 to 26^3)
                from itertools import product
                best_seed_crib = 0
                best_seed_pt_str = ""

                for seed_combo in product(range(MOD), repeat=len(unknown_pos)):
                    trial = pt_core[:]
                    for idx, pos in enumerate(unknown_pos):
                        trial[pos] = seed_combo[idx]

                    # Forward/backward propagation from newly set positions
                    changed = True
                    while changed:
                        changed = False
                        for i in range(m, N):
                            if trial[i] is None and trial[i - m] is not None:
                                trial[i] = decrypt_fn(ct_nums[i], trial[i - m])
                                changed = True
                        for i in range(N - 1, m - 1, -1):
                            if trial[i] is not None:
                                bp = i - m
                                if 0 <= bp < N and trial[bp] is None:
                                    trial[bp] = derive_key(ct_nums[i], trial[i])
                                    changed = True

                    crib_sc = count_crib_matches(trial, crib_nums)
                    if crib_sc > best_seed_crib:
                        best_seed_crib = crib_sc
                        best_seed_pt_str = pt_nums_to_str(trial, alph_str)

                        if crib_sc > phase5_best["score"]:
                            phase5_best = {"score": crib_sc, "config": {
                                "alphabet": alph_name, "variant": vname, "m": m,
                                "seed_pos": unknown_pos, "seed": list(seed_combo),
                            }, "pt": best_seed_pt_str}

                if best_seed_crib > NOISE_FLOOR:
                    print(f"  {alph_name} {vname:10s} m={m:2d} (seed search): "
                          f"best cribs={best_seed_crib}/24")
                    if best_seed_crib >= STORE_THRESHOLD:
                        print(f"    PT: {best_seed_pt_str[:70]}...")

print(f"\n  Phase 5: best={phase5_best['score']}/24 at {phase5_best['config']}")


# ── Phase 6: ENE backward start + forward from BC (independent chains) ──

print("\n" + "─" * 72)
print("PHASE 6: Independent chain analysis")
print("  Analyze the structure of the autokey chain for EACH crib independently.")
print("  Key insight: for each m, each crib spans positions that are connected")
print("  by the autokey recurrence in 'chains' of period m.")
print("─" * 72)

# For PT-autokey with primer m:
# The positions 0, m, 2m, 3m, ... form one chain
# Positions 1, 1+m, 1+2m, ... form another
# Total m independent chains, each covering ~97/m positions.
# A crib at positions [a, a+len) connects chains that include those positions.

# For m=1: all 97 positions in ONE chain. ENE and BC are in the same chain.
# For m=2: two chains (even/odd). ENE starts at 21 (odd), BC starts at 63 (odd).
# For m=3: three chains. ENE positions are at residues 0,1,2 mod 3.
#   BC positions are at 63%3=0, 64%3=1, 65%3=2, etc. — also all three chains.

# The number of chains bridged by both cribs determines if forward propagation works.

for m in range(1, 20):
    # Which mod-m residues does ENE cover?
    ene_residues = set((ENE_START + i) % m for i in range(len(ENE_WORD)))
    # Which mod-m residues does BC cover?
    bc_residues = set((BC_START + i) % m for i in range(len(BC_WORD)))
    # Shared residues
    shared = ene_residues & bc_residues

    # How many of the m chains are covered by at least one crib?
    all_covered = ene_residues | bc_residues

    if len(all_covered) == m:
        cross_val_possible = len(shared) > 0
        print(f"  m={m:2d}: ALL {m} chains covered by cribs. "
              f"ENE covers {len(ene_residues)}/{m}, BC covers {len(bc_residues)}/{m}. "
              f"Shared={len(shared)}. "
              f"Cross-val={'YES' if cross_val_possible else 'NO'}")
    else:
        gap_residues = set(range(m)) - all_covered
        print(f"  m={m:2d}: {len(all_covered)}/{m} chains covered. "
              f"Gap residues: {sorted(gap_residues)}. "
              f"Need seed for {len(gap_residues)} chain(s).")


# ── Summary ──────────────────────────────────────────────────────────────

total_time = time.time() - t_start

print("\n" + "=" * 72)
print("SUMMARY — E-AUTOKEY-BOOTSTRAP-00")
print("=" * 72)
print(f"  Total configs tested:  {total_configs}")
print(f"  Phase 1 (ENE→BC fwd): {len(phase1_survivors)} cross-validation passes")
print(f"  Phase 2 (BC→ENE bwd): {len(phase2_survivors)} survivors")
print(f"  Phase 3 (CT-autokey):  best {phase3_best['score']}/24")
print(f"  Phase 4 (multi-step):  {len(phase4_survivors)} survivors")
print(f"  Phase 5 (seed search): best {phase5_best['score']}/24")
print(f"  Overall best:          {best_overall['score']}/24")
if best_overall["config"]:
    print(f"  Best config:           {best_overall['config']}")
    print(f"  Best PT:               {best_overall['pt'][:70]}...")
print(f"  Total time:            {total_time:.1f}s")

# Verdict
if best_overall["score"] >= BREAKTHROUGH_THRESHOLD:
    verdict = f"BREAKTHROUGH — {best_overall['score']}/24 cribs!"
elif best_overall["score"] >= SIGNAL_THRESHOLD:
    verdict = f"SIGNAL — {best_overall['score']}/24, investigate further"
elif best_overall["score"] > NOISE_FLOOR:
    verdict = f"INTERESTING — {best_overall['score']}/24, but likely noise"
else:
    verdict = (f"NO SIGNAL — best {best_overall['score']}/24 at noise level. "
               f"PT-autokey chain propagation from crib bootstrap: ELIMINATED "
               f"for all tested (m, variant, alphabet) under direct correspondence.")

print(f"\n  VERDICT: {verdict}")

# ── Structural Analysis ──────────────────────────────────────────────────

print("\n" + "─" * 72)
print("STRUCTURAL ANALYSIS: Why does Phase 1 work or fail?")
print("─" * 72)

# For m=1..13, the autokey chain from ENE forward through gap to BC
# is deterministic. The cross-validation at BC is a HARD constraint.
# If 0/11 BC positions match: the cipher model is WRONG for that (m, variant, alphabet).
# If 11/11 match: we have a candidate (but need Bean + English checks).

# Count how many (m, variant) achieve ANY BC matches
for alph_name in ALPHABETS:
    idx_map = ALPHABETS[alph_name]["idx"]
    alph_str = ALPHABETS[alph_name]["alph"]
    ct_nums = ct_as_nums(idx_map)

    print(f"\n  Alphabet: {alph_name}")
    print(f"  {'variant':<12} {'m':>3}  {'BC matches':>11}  {'Total cribs':>12}  Status")
    print(f"  {'─'*12} {'─'*3}  {'─'*11}  {'─'*12}  {'─'*20}")

    for vname, vfns in VARIANTS.items():
        decrypt_fn = vfns["decrypt"]

        for m in range(1, 14):
            pt_nums = [None] * N
            for i, ch in enumerate(ENE_WORD):
                pt_nums[ENE_START + i] = idx_map[ch]

            start_key_pos = 34 - m
            if start_key_pos < ENE_START or start_key_pos >= ENE_END:
                print(f"  {vname:<12} {m:>3}  {'N/A':>11}  {'N/A':>12}  SKIP (key pos {start_key_pos} not in ENE)")
                continue

            # Forward propagate
            ok = True
            for i in range(34, N):
                if pt_nums[i - m] is not None:
                    pt_nums[i] = decrypt_fn(ct_nums[i], pt_nums[i - m])
                else:
                    ok = False
                    break

            if not ok:
                print(f"  {vname:<12} {m:>3}  {'BROKEN':>11}  {'─':>12}  Chain broke before BC")
                continue

            # Count BC matches
            bc_match = sum(1 for i in range(len(BC_WORD))
                          if pt_nums[BC_START + i] == idx_map[BC_WORD[i]])

            total_crib = sum(1 for pos in CRIB_POS
                            if pt_nums[pos] is not None and pt_nums[pos] == crib_as_nums(idx_map)[pos])

            status = "ELIMINATED" if bc_match == 0 else (
                     "PARTIAL" if bc_match < len(BC_WORD) else "PASS")

            print(f"  {vname:<12} {m:>3}  {bc_match:>8}/11  {total_crib:>9}/24  {status}")

# ── Save artifact ─────────────────────────────────────────────────────────

os.makedirs("results", exist_ok=True)
output = {
    "experiment": "E-AUTOKEY-BOOTSTRAP-00",
    "description": "Autokey chain propagation from crib bootstrap — cross-validation gate",
    "total_configs": total_configs,
    "phase1_survivors": phase1_survivors,
    "phase2_survivors": phase2_survivors,
    "phase3_best": {
        "score": phase3_best["score"],
        "config": str(phase3_best["config"]),
    },
    "phase4_survivors": [str(s) for s in phase4_survivors],
    "phase5_best": {
        "score": phase5_best["score"],
        "config": str(phase5_best.get("config")),
    },
    "overall_best": {
        "score": best_overall["score"],
        "config": str(best_overall.get("config")),
        "pt": best_overall.get("pt", "")[:80],
    },
    "verdict": verdict,
    "runtime_seconds": round(total_time, 1),
    "repro": "PYTHONPATH=src python3 -u scripts/e_autokey_bootstrap_00.py",
}

with open("results/e_autokey_bootstrap_00.json", "w") as f:
    json.dump(output, f, indent=2, default=str)

print(f"\n  Artifact: results/e_autokey_bootstrap_00.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_autokey_bootstrap_00.py")
print(f"\n{'=' * 72}")
print("DONE — E-AUTOKEY-BOOTSTRAP-00")
print(f"{'=' * 72}")
