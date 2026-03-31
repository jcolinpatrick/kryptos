#!/usr/bin/env python3
"""
Cipher: tape-key OTP hypothesis
Family: team
Status: active
Keyspace: ~15,000 configs across 5 batteries
Last run:
Best score:
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md

"""E-TAPE-KEY-TEST: Test letters found on scotch tape on K1-K2 encoding chart.

Discovery: User identified letters written ON TOP OF SCOTCH TAPE in the
margin/overflow area of the K1-K2 encoding chart (Coding Chart.jpg).
Scheidt: "we used one-time pads and tape."

Primary candidate: GZLECGYUXUEENJTBJLBQCETB (24 chars)
 - This is a segment of K2 CT row (positions 2-25 of QZGZLECGYUXUEENJTBJLBQCETBJDFHRR)
 - 24 chars = QUADRUPLE-24 (null count, crib count, K3 chart rows)
 - Written on TAPE in MARGIN — not inside the grid where K2 CT belongs

Also tests: GZLETBJLHRRY (12 chars, original partial reading)
Also tests: QZGZLECGYUXUEENJTBJLBQCETBJDFHRR (full K2 CT row)

NOTE: K2 CT as standard running key at ALL offsets was already tested
and eliminated (PROVEN #27, best 5/24). These tests focus on NON-STANDARD
applications: seed extension, CKM combination, CT73 application.
"""
import sys
import os
import json
import time
from collections import Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, N_CRIBS,
    CRIB_DICT, CRIB_POSITIONS,
    BEAN_EQ, BEAN_INEQ,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    KRYPTOS_ALPHABET,
)
from kryptos.kernel.scoring.crib_score import score_cribs, score_cribs_detailed

RESULTS_PATH = os.path.join(_ROOT, "results", "e_tape_key_test.json")

# ── Tape key candidates ──────────────────────────────────────────────────

TAPE_24 = "GZLECGYUXUEENJTBJLBQCETB"       # Primary: 24 chars on tape
TAPE_12 = "GZLETBJLHRRY"                     # Original partial reading
TAPE_FULL_ROW = "QZGZLECGYUXUEENJTBJLBQCETBJDFHRR"  # Full K2 CT row

# Known consensus null positions (17 fixed)
CONSENSUS_NULLS = [0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85]

# ── Alphabet helpers ─────────────────────────────────────────────────────

AZ = ALPH
AZ_IDX = ALPH_IDX
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}


def to_nums(text, idx_map):
    return [idx_map[c] for c in text]


def from_nums(nums, alpha):
    return "".join(alpha[n % MOD] for n in nums)


def decrypt_beaufort(ct_nums, key_nums):
    """Beaufort: PT = (K - CT) mod 26"""
    return [(k - c) % MOD for c, k in zip(ct_nums, key_nums)]


def decrypt_vigenere(ct_nums, key_nums):
    """Vigenere: PT = (CT - K) mod 26"""
    return [(c - k) % MOD for c, k in zip(ct_nums, key_nums)]


def decrypt_var_beaufort(ct_nums, key_nums):
    """Variant Beaufort: PT = (K + CT) mod 26  -- wait, that's encrypt.
    Decrypt: PT = (CT + K) mod 26? No.
    VarBeau encrypt: C = (P - K) mod 26, so decrypt: P = (C + K) mod 26"""
    return [(c + k) % MOD for c, k in zip(ct_nums, key_nums)]


VARIANTS = {
    "beaufort": decrypt_beaufort,
    "vigenere": decrypt_vigenere,
    "var_beaufort": decrypt_var_beaufort,
}

# ── Null extraction ──────────────────────────────────────────────────────

def extract_ct73(null_positions):
    """Remove null positions from CT97 to get CT73."""
    null_set = set(null_positions)
    return "".join(CT[i] for i in range(CT_LEN) if i not in null_set)


# Build a default CT73 using consensus nulls + 7 most common varying positions
DEFAULT_VARYING = [38, 39, 40, 55, 88, 93, 94]  # one common mask
DEFAULT_NULL_24 = sorted(CONSENSUS_NULLS + DEFAULT_VARYING)
CT73_DEFAULT = extract_ct73(DEFAULT_NULL_24)

# ── Bean check ───────────────────────────────────────────────────────────

def check_bean(pt_text):
    """Check Bean constraints on a candidate plaintext applied to CT97."""
    if len(pt_text) < 97:
        return None  # Can't check on shorter texts

    keystream = {}
    for pos, expected_pt in CRIB_DICT.items():
        if pos < len(pt_text):
            ct_val = AZ_IDX[CT[pos]]
            pt_val = AZ_IDX[pt_text[pos]]
            keystream[pos] = (ct_val + pt_val) % MOD  # Beaufort keystream

    # Check equality
    eq_pass = True
    for a, b in BEAN_EQ:
        if a in keystream and b in keystream:
            if keystream[a] != keystream[b]:
                eq_pass = False

    # Check inequalities
    ineq_violations = 0
    for a, b in BEAN_INEQ:
        if a in keystream and b in keystream:
            if keystream[a] == keystream[b]:
                ineq_violations += 1

    return {"eq_pass": eq_pass, "ineq_violations": ineq_violations}


# ── Battery 1: Direct key application ────────────────────────────────────

def battery_1_direct(tape_keys):
    """Test tape keys as direct cipher keys at all offsets."""
    print("\n" + "=" * 70)
    print("BATTERY 1: Direct Key Application")
    print("=" * 70)

    results = []
    best_overall = {"score": 0}

    for key_name, key_str in tape_keys:
        key_len = len(key_str)
        print(f"\n  Key: {key_name} ({key_len} chars) = {key_str}")

        for alpha_name, alpha, idx in [("AZ", AZ, AZ_IDX), ("KA", KA, KA_IDX)]:
            key_nums = to_nums(key_str, idx)
            ct_nums_97 = to_nums(CT, idx)

            for variant_name, decrypt_fn in VARIANTS.items():
                best_score = 0
                best_offset = -1
                best_pt = ""

                # Test on CT97 at all offsets
                for offset in range(CT_LEN):
                    # Build full key by cycling from offset
                    full_key = [key_nums[(i - offset) % key_len] for i in range(CT_LEN)]
                    pt_nums = decrypt_fn(ct_nums_97, full_key)
                    pt_text = from_nums(pt_nums, alpha)
                    sc = score_cribs(pt_text)

                    if sc > best_score:
                        best_score = sc
                        best_offset = offset
                        best_pt = pt_text

                entry = {
                    "key": key_name, "alpha": alpha_name, "variant": variant_name,
                    "target": "CT97", "score": best_score,
                    "best_offset": best_offset, "best_pt_snippet": best_pt[20:35] if best_pt else "",
                }
                results.append(entry)

                if best_score > best_overall["score"]:
                    best_overall = {**entry, "full_pt": best_pt}

                if best_score >= 6:
                    detail = score_cribs_detailed(best_pt)
                    print(f"    ** {alpha_name}_{variant_name} CT97: {best_score}/24 at offset {best_offset}")
                    print(f"       ENE={detail['ene_score']}/13 BCL={detail['bc_score']}/11")
                    print(f"       PT[20:35] = {best_pt[20:35]}")

                # Also test on CT73 (default mask)
                ct73_nums = to_nums(CT73_DEFAULT, idx)
                best_73 = 0
                for offset in range(len(CT73_DEFAULT)):
                    full_key = [key_nums[(i - offset) % key_len] for i in range(len(CT73_DEFAULT))]
                    pt_nums = decrypt_fn(ct73_nums, full_key[:len(ct73_nums)])
                    pt_text = from_nums(pt_nums, alpha)
                    # For CT73, cribs shift — use free scoring
                    # Actually, under Model B, cribs are at CT97 positions. Can't directly
                    # score CT73 with score_cribs. Skip CT73 direct for now.
                    pass

        print(f"    Best for {key_name}: {best_overall.get('score', 0)}/24")

    print(f"\n  BATTERY 1 BEST: {best_overall['score']}/24")
    if best_overall['score'] >= 6:
        print(f"    Key={best_overall['key']} Alpha={best_overall['alpha']} "
              f"Variant={best_overall['variant']} Offset={best_overall['best_offset']}")
    return results, best_overall


# ── Battery 2: Key generation seeds ──────────────────────────────────────

def extend_chain_addition(seed_nums, target_len, lag_p, lag_q):
    """Extend seed via chain addition: key[i] = (key[i-p] + key[i-q]) mod 26"""
    key = list(seed_nums)
    while len(key) < target_len:
        if len(key) >= lag_q:
            new_val = (key[-lag_p] + key[-lag_q]) % MOD
        else:
            new_val = key[-1]  # Fallback if seed shorter than lag
        key.append(new_val)
    return key[:target_len]


def extend_chain_subtraction(seed_nums, target_len, lag_p, lag_q):
    """Extend via chain subtraction: key[i] = (key[i-p] - key[i-q]) mod 26"""
    key = list(seed_nums)
    while len(key) < target_len:
        if len(key) >= lag_q:
            new_val = (key[-lag_p] - key[-lag_q]) % MOD
        else:
            new_val = key[-1]
        key.append(new_val)
    return key[:target_len]


def extend_mod10_chain(seed_nums, target_len, lag_p, lag_q):
    """VIC-style mod-10 non-carrying addition on digit equivalents."""
    # Convert to digits: each value mod 10
    digits = [v % 10 for v in seed_nums]
    while len(digits) < target_len:
        if len(digits) >= lag_q:
            new_val = (digits[-lag_p] + digits[-lag_q]) % 10
        else:
            new_val = digits[-1]
        digits.append(new_val)
    # Convert back: digits represent key values mod 26 (map 0-9 to 0-9)
    return digits[:target_len]


def battery_2_seeds(tape_keys):
    """Test tape keys as seeds for key generation."""
    print("\n" + "=" * 70)
    print("BATTERY 2: Key Generation Seeds")
    print("=" * 70)

    results = []
    best_overall = {"score": 0}
    total_tests = 0

    for key_name, key_str in tape_keys:
        key_len = len(key_str)
        if key_len < 2:
            continue

        print(f"\n  Seed: {key_name} ({key_len} chars)")

        for alpha_name, alpha, idx in [("AZ", AZ, AZ_IDX), ("KA", KA, KA_IDX)]:
            seed_nums = to_nums(key_str, idx)
            ct_nums = to_nums(CT, idx)

            # Test lag pairs for chain addition
            for lag_p in range(1, min(key_len, 13)):
                for lag_q in range(lag_p + 1, min(key_len + 1, 25)):
                    for ext_name, ext_fn in [("chain_add", extend_chain_addition),
                                              ("chain_sub", extend_chain_subtraction),
                                              ("mod10", extend_mod10_chain)]:
                        extended = ext_fn(seed_nums, CT_LEN, lag_p, lag_q)

                        for variant_name, decrypt_fn in VARIANTS.items():
                            pt_nums = decrypt_fn(ct_nums, extended)
                            pt_text = from_nums(pt_nums, alpha)
                            sc = score_cribs(pt_text)
                            total_tests += 1

                            if sc > best_overall.get("score", 0):
                                best_overall = {
                                    "score": sc, "key": key_name, "alpha": alpha_name,
                                    "variant": variant_name, "ext": ext_name,
                                    "lag_p": lag_p, "lag_q": lag_q, "pt": pt_text,
                                }

                            if sc >= 10:
                                detail = score_cribs_detailed(pt_text)
                                print(f"    ** {alpha_name}_{variant_name} {ext_name} "
                                      f"p={lag_p} q={lag_q}: {sc}/24")
                                print(f"       ENE={detail['ene_score']}/13 BCL={detail['bc_score']}/11")
                                bean = check_bean(pt_text)
                                if bean:
                                    print(f"       Bean: eq={bean['eq_pass']} ineq_violations={bean['ineq_violations']}")

                                results.append({
                                    "score": sc, "key": key_name, "alpha": alpha_name,
                                    "variant": variant_name, "ext": ext_name,
                                    "lag_p": lag_p, "lag_q": lag_q,
                                })

    print(f"\n  BATTERY 2: {total_tests:,} tests, best={best_overall.get('score', 0)}/24")
    if best_overall.get("score", 0) >= 6:
        print(f"    {best_overall}")
    return results, best_overall


# ── Battery 3: Keystream alignment ───────────────────────────────────────

def battery_3_alignment(tape_keys):
    """Check alignment between tape key and known Beaufort keystream."""
    print("\n" + "=" * 70)
    print("BATTERY 3: Keystream Alignment Check")
    print("=" * 70)

    # Model B Beaufort keystream at all 24 crib positions
    model_b_keystream = {}
    for pos, pt_ch in CRIB_DICT.items():
        ct_val = AZ_IDX[CT[pos]]
        pt_val = AZ_IDX[pt_ch]
        model_b_keystream[pos] = (ct_val + pt_val) % MOD  # Beaufort: K = CT + PT

    ks_values = list(model_b_keystream.values())
    ks_letters = "".join(AZ[v] for v in ks_values)
    crib_pos_list = sorted(model_b_keystream.keys())

    print(f"  Model B keystream: {ks_letters}")
    print(f"  Crib positions: {crib_pos_list}")

    results = []

    for key_name, key_str in tape_keys:
        key_nums_az = to_nums(key_str, AZ_IDX)
        key_len = len(key_str)

        print(f"\n  Tape key: {key_name} = {key_str}")

        # Check: if tape key is applied starting at various positions,
        # how many keystream values match at crib positions?
        for start_pos in range(CT_LEN):
            matches = 0
            match_positions = []
            for cp in crib_pos_list:
                tape_idx = (cp - start_pos) % key_len
                if tape_idx < key_len and key_nums_az[tape_idx] == model_b_keystream[cp]:
                    matches += 1
                    match_positions.append(cp)

            if matches >= 3:
                print(f"    Start={start_pos}: {matches}/24 keystream matches at {match_positions}")
                results.append({
                    "key": key_name, "start": start_pos,
                    "matches": matches, "positions": match_positions,
                })

        # Direct comparison (no offset, tape[0] = key at pos 0)
        print(f"\n    Direct overlay (tape[i] vs keystream[crib_pos_i]):")
        direct_matches = 0
        for i, cp in enumerate(crib_pos_list):
            if i < key_len:
                tape_val = key_nums_az[i]
                ks_val = model_b_keystream[cp]
                match = "MATCH" if tape_val == ks_val else ""
                if tape_val == ks_val:
                    direct_matches += 1
                print(f"      tape[{i}]={AZ[tape_val]}({tape_val:2d}) vs ks[{cp}]={AZ[ks_val]}({ks_val:2d}) {match}")
        print(f"    Direct matches: {direct_matches}/{min(key_len, 24)}")

    return results


# ── Battery 4: CKM combination ──────────────────────────────────────────

def battery_4_ckm(tape_keys):
    """Test tape key combined with KRYPTOS/SEVEN via CKM."""
    print("\n" + "=" * 70)
    print("BATTERY 4: CKM Combination")
    print("=" * 70)

    combiners = {
        "add": lambda a, b: (a + b) % MOD,
        "sub": lambda a, b: (a - b) % MOD,
        "rsub": lambda a, b: (b - a) % MOD,
        "mul": lambda a, b: (a * b) % MOD,
        "xor": lambda a, b: a ^ b,  # Note: not mod 26, could exceed
        "min": lambda a, b: min(a, b),
        "max": lambda a, b: max(a, b),
    }

    second_sources = {
        "KRYPTOS": to_nums("KRYPTOS", AZ_IDX),
        "SEVEN": to_nums("SEVEN", AZ_IDX),
        "PALIMPSEST": to_nums("PALIMPSEST", AZ_IDX),
        "ABSCISSA": to_nums("ABSCISSA", AZ_IDX),
    }

    results = []
    best_overall = {"score": 0}
    total_tests = 0

    for key_name, key_str in tape_keys:
        key_nums = to_nums(key_str, AZ_IDX)
        key_len = len(key_str)
        ct_nums = to_nums(CT, AZ_IDX)

        for src_name, src_nums in second_sources.items():
            src_len = len(src_nums)

            for comb_name, comb_fn in combiners.items():
                # Build combined key: key[i] = comb(tape[i%tape_len], source[i%src_len])
                try:
                    combined = [comb_fn(key_nums[i % key_len], src_nums[i % src_len]) % MOD
                                for i in range(CT_LEN)]
                except:
                    continue

                for variant_name, decrypt_fn in VARIANTS.items():
                    pt_nums = decrypt_fn(ct_nums, combined)
                    pt_text = from_nums(pt_nums, AZ)
                    sc = score_cribs(pt_text)
                    total_tests += 1

                    if sc > best_overall.get("score", 0):
                        best_overall = {
                            "score": sc, "key": key_name, "source": src_name,
                            "combiner": comb_name, "variant": variant_name,
                            "pt": pt_text,
                        }

                    if sc >= 6:
                        print(f"    {key_name}×{src_name} {comb_name} {variant_name}: {sc}/24")
                        print(f"      PT[20:35] = {pt_text[20:35]}")
                        results.append({
                            "score": sc, "key": key_name, "source": src_name,
                            "combiner": comb_name, "variant": variant_name,
                        })

                    # Also test with phase offset d
                    for d in [1, 2, 3, 5, 7, 11, 13]:
                        try:
                            combined_d = [comb_fn(key_nums[i % key_len],
                                                  src_nums[(i + d) % src_len]) % MOD
                                          for i in range(CT_LEN)]
                        except:
                            continue
                        pt_nums_d = decrypt_fn(ct_nums, combined_d)
                        pt_text_d = from_nums(pt_nums_d, AZ)
                        sc_d = score_cribs(pt_text_d)
                        total_tests += 1

                        if sc_d > best_overall.get("score", 0):
                            best_overall = {
                                "score": sc_d, "key": key_name, "source": src_name,
                                "combiner": comb_name, "variant": variant_name,
                                "phase": d, "pt": pt_text_d,
                            }

                        if sc_d >= 6:
                            print(f"    {key_name}×{src_name} {comb_name} d={d} "
                                  f"{variant_name}: {sc_d}/24")

    print(f"\n  BATTERY 4: {total_tests:,} tests, best={best_overall.get('score', 0)}/24")
    if best_overall.get("score", 0) >= 6:
        print(f"    {best_overall}")
    return results, best_overall


# ── Battery 5: Reversed and transformed ──────────────────────────────────

def battery_5_transforms(tape_keys):
    """Test reversed, shifted, and transformed versions."""
    print("\n" + "=" * 70)
    print("BATTERY 5: Reversed and Transformed")
    print("=" * 70)

    results = []
    best_overall = {"score": 0}
    total_tests = 0

    for key_name, key_str in tape_keys:
        key_len = len(key_str)

        # Generate transformed versions
        transforms = {}
        transforms[f"{key_name}_rev"] = key_str[::-1]

        # Caesar shifts
        for shift in range(1, 26):
            shifted = "".join(AZ[(AZ_IDX[c] + shift) % MOD] for c in key_str)
            transforms[f"{key_name}_caesar{shift}"] = shifted

        # Beaufort with constant key
        for k_letter in ["K", "N", "S"]:  # Key letters: K(ryptos), N(=14), S(even)
            k_val = AZ_IDX[k_letter]
            beau = "".join(AZ[(k_val - AZ_IDX[c]) % MOD] for c in key_str)
            transforms[f"{key_name}_beau_{k_letter}"] = beau

        # KA-reindex: read key_str positions in KA ordering
        ka_reindexed = "".join(AZ[KA_IDX[c]] for c in key_str)
        transforms[f"{key_name}_ka_reindex"] = ka_reindexed

        # AZ↔KA swap: interpret as KA values, output as AZ
        az_from_ka = "".join(KA[AZ_IDX[c]] for c in key_str)
        transforms[f"{key_name}_az2ka"] = az_from_ka

        for t_name, t_str in transforms.items():
            t_nums = to_nums(t_str, AZ_IDX)
            ct_nums = to_nums(CT, AZ_IDX)

            for variant_name, decrypt_fn in VARIANTS.items():
                # Apply at offset 0 (cycling)
                full_key = [t_nums[i % len(t_str)] for i in range(CT_LEN)]
                pt_nums = decrypt_fn(ct_nums, full_key)
                pt_text = from_nums(pt_nums, AZ)
                sc = score_cribs(pt_text)
                total_tests += 1

                if sc > best_overall.get("score", 0):
                    best_overall = {
                        "score": sc, "transform": t_name,
                        "variant": variant_name, "pt": pt_text,
                    }

                if sc >= 6:
                    print(f"    {t_name} {variant_name}: {sc}/24")
                    print(f"      Key = {t_str}")
                    results.append({
                        "score": sc, "transform": t_name, "variant": variant_name,
                    })

    print(f"\n  BATTERY 5: {total_tests:,} tests, best={best_overall.get('score', 0)}/24")
    return results, best_overall


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    t0 = time.time()
    print("=" * 70)
    print("E-TAPE-KEY-TEST: Scotch Tape Key Hypothesis")
    print("=" * 70)
    print(f"  Primary:   {TAPE_24} (24 chars)")
    print(f"  Original:  {TAPE_12} (12 chars)")
    print(f"  Full row:  {TAPE_FULL_ROW} ({len(TAPE_FULL_ROW)} chars)")
    print()

    tape_keys = [
        ("tape_24", TAPE_24),
        ("tape_12", TAPE_12),
        ("full_row", TAPE_FULL_ROW),
    ]

    all_results = {"experiment_id": "e_tape_key_test", "batteries": {}}

    # Battery 1: Direct application
    b1_results, b1_best = battery_1_direct(tape_keys)
    all_results["batteries"]["1_direct"] = {
        "tests": len(b1_results), "best": b1_best.get("score", 0),
        "results": b1_results[:20],  # Top results only
    }

    # Battery 2: Seeds (only for 24-char and 12-char, not full row)
    seed_keys = [("tape_24", TAPE_24), ("tape_12", TAPE_12)]
    b2_results, b2_best = battery_2_seeds(seed_keys)
    all_results["batteries"]["2_seeds"] = {
        "best": b2_best.get("score", 0),
        "results": b2_results[:20],
    }

    # Battery 3: Keystream alignment
    b3_results = battery_3_alignment(tape_keys)
    all_results["batteries"]["3_alignment"] = {
        "results": b3_results,
    }

    # Battery 4: CKM combination
    b4_results, b4_best = battery_4_ckm([("tape_24", TAPE_24)])
    all_results["batteries"]["4_ckm"] = {
        "best": b4_best.get("score", 0),
        "results": b4_results[:20],
    }

    # Battery 5: Transforms
    b5_results, b5_best = battery_5_transforms([("tape_24", TAPE_24), ("tape_12", TAPE_12)])
    all_results["batteries"]["5_transforms"] = {
        "best": b5_best.get("score", 0),
        "results": b5_results[:20],
    }

    # ── Summary ──────────────────────────────────────────────────────────
    elapsed = time.time() - t0
    all_best = max(
        b1_best.get("score", 0),
        b2_best.get("score", 0),
        b4_best.get("score", 0),
        b5_best.get("score", 0),
    )

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Battery 1 (Direct):     best {b1_best.get('score', 0)}/24")
    print(f"  Battery 2 (Seeds):      best {b2_best.get('score', 0)}/24")
    print(f"  Battery 3 (Alignment):  see detailed output above")
    print(f"  Battery 4 (CKM):        best {b4_best.get('score', 0)}/24")
    print(f"  Battery 5 (Transforms): best {b5_best.get('score', 0)}/24")
    print(f"  OVERALL BEST:           {all_best}/24")
    print(f"  Elapsed:                {elapsed:.1f}s")

    if all_best >= 18:
        print("\n  *** SIGNAL DETECTED — INVESTIGATE IMMEDIATELY ***")
    elif all_best >= 10:
        print("\n  ** INTERESTING — worth deeper analysis **")
    elif all_best >= 6:
        print("\n  * Elevated but likely noise *")
    else:
        print("\n  Noise floor. Tape content does NOT directly decrypt K4.")
        print("  Tape may be procedural artifact (K2 workspace) rather than K4 key.")

    all_results["summary"] = {
        "overall_best": all_best,
        "elapsed_seconds": round(elapsed, 1),
        "verdict": (
            "SIGNAL" if all_best >= 18 else
            "INTERESTING" if all_best >= 10 else
            "ELEVATED" if all_best >= 6 else
            "NOISE"
        ),
    }

    # Save results
    os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)
    with open(RESULTS_PATH, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"\n  Results saved to {RESULTS_PATH}")


if __name__ == "__main__":
    main()
