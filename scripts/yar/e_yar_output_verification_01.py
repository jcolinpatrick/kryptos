#!/usr/bin/env python3
"""
Cipher: analysis/yar_verification
Family: yar
Status: active
Keyspace: N/A (analytical, not brute force)
Last run:
Best score:

E-YAR-VERIFY-01: Test YAR as OUTPUT verification rather than INPUT mechanism.

Prior work always used YAR as cipher INPUT (primer, key, grille positions).
This script inverts the hypothesis: if K4 is solved correctly, do the YAR
positions (or NDYAHR positions) have a special property in the PLAINTEXT?

Tests:
  1. At YAR letter positions in K4 CT, what letters appear in known cribs?
  2. Do YAR positions in K4 map to special positions after transposition?
  3. Under the best-lead Beaufort keystream, what are the key values at
     positions whose CT letters are Y, A, or R?
  4. Do positions containing Y/A/R in CT have unusual keystream properties?
  5. If we assume BERLINCLOCK and EASTNORTHEAST are correct, what do the
     YAR-position key values spell?
  6. Do NDYAHR numeric values (13,3,24,0,7,17) appear as keystream values
     at crib positions?
  7. Statistical test: are Y/A/R positions in K4 CT correlated with any
     structural feature (null positions, crib positions, Bean constraints)?

Output: results/yar_output_verification.json
"""
import json
import os
import sys
import time
from collections import Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT, CRIB_POSITIONS,
    CONSENSUS_NULL_POSITIONS, BEAN_EQ, BEAN_INEQ,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC, NULL_PALETTE,
)

# ── Setup ────────────────────────────────────────────────────────────────

# Positions in K4 CT where each letter appears
def find_positions(ct, letters):
    """Find all positions where CT contains one of the given letters."""
    return {ch: [i for i, c in enumerate(ct) if c == ch] for ch in letters}


YAR_LETTERS = set("YAR")
NDYAHR_LETTERS = set("NDYAHR")
NDYAHR_VALUES = {"N": 13, "D": 3, "Y": 24, "A": 0, "H": 7, "R": 17}

# Known keystream at crib positions (Beaufort, A=0)
CRIB_KS = {}
for pos in sorted(CRIB_DICT.keys()):
    ct_val = ALPH_IDX[CT[pos]]
    pt_val = ALPH_IDX[CRIB_DICT[pos]]
    CRIB_KS[pos] = (ct_val + pt_val) % MOD  # Beaufort: K = (CT + PT) mod 26


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-YAR-VERIFY-01: YAR as Output Verification")
    print("=" * 70)

    results = {}

    # ── Test 1: YAR letter positions in K4 ───────────────────────────────
    print("\n--- TEST 1: Where do Y, A, R appear in K4 CT? ---")
    yar_pos = find_positions(CT, "YAR")
    for ch, positions in sorted(yar_pos.items()):
        print(f"  {ch}: positions {positions} ({len(positions)} occurrences)")
        for p in positions:
            in_crib = "CRIB" if p in CRIB_DICT else ""
            in_null = "NULL" if p in CONSENSUS_NULL_POSITIONS else ""
            tags = " ".join(filter(None, [in_crib, in_null]))
            if tags:
                print(f"    pos {p}: {tags}")

    results["test1_yar_positions"] = {ch: pos for ch, pos in yar_pos.items()}

    # ── Test 2: At crib positions, which have CT = Y/A/R? ────────────────
    print("\n--- TEST 2: Crib positions with CT in {Y,A,R} ---")
    crib_yar = []
    for pos in sorted(CRIB_DICT.keys()):
        if CT[pos] in YAR_LETTERS:
            crib_yar.append({
                "pos": pos, "ct": CT[pos], "pt": CRIB_DICT[pos],
                "ks_beaufort": CRIB_KS[pos],
                "ks_letter": ALPH[CRIB_KS[pos]],
            })
            print(f"  pos {pos}: CT={CT[pos]} PT={CRIB_DICT[pos]} KS={ALPH[CRIB_KS[pos]]}({CRIB_KS[pos]})")

    results["test2_crib_yar"] = crib_yar
    print(f"  {len(crib_yar)} crib positions have CT in {{Y,A,R}} out of {len(CRIB_DICT)}")

    # ── Test 3: Keystream values at all Y/A/R positions ──────────────────
    print("\n--- TEST 3: Beaufort keystream at Y/A/R CT positions (crib-only) ---")
    ks_at_yar = []
    for ch in "YAR":
        for p in yar_pos.get(ch, []):
            if p in CRIB_KS:
                ks_val = CRIB_KS[p]
                ks_at_yar.append({"pos": p, "ct": ch, "ks": ks_val, "ks_letter": ALPH[ks_val]})
                print(f"  pos {p} (CT={ch}): KS={ALPH[ks_val]}({ks_val})")

    results["test3_ks_at_yar"] = ks_at_yar

    # ── Test 4: Do NDYAHR numeric values appear in the keystream? ────────
    print("\n--- TEST 4: NDYAHR values {13,3,24,0,7,17} in crib keystream ---")
    ndyahr_vals = set(NDYAHR_VALUES.values())
    ks_vals = set(CRIB_KS.values())
    overlap = ndyahr_vals & ks_vals
    print(f"  NDYAHR values: {sorted(ndyahr_vals)}")
    print(f"  Crib keystream values: {sorted(ks_vals)}")
    print(f"  Overlap: {sorted(overlap)} ({len(overlap)}/{len(ndyahr_vals)})")

    # Which crib positions have keystream matching NDYAHR values?
    ndyahr_matches = []
    for pos, ks in sorted(CRIB_KS.items()):
        if ks in ndyahr_vals:
            ndyahr_matches.append({
                "pos": pos, "ct": CT[pos], "pt": CRIB_DICT[pos],
                "ks": ks, "ndyahr_letter": [k for k, v in NDYAHR_VALUES.items() if v == ks]
            })
            ndyahr_letters = [k for k, v in NDYAHR_VALUES.items() if v == ks]
            print(f"  pos {pos}: KS={ks} matches {ndyahr_letters}")

    results["test4_ndyahr_in_ks"] = {
        "overlap_count": len(overlap),
        "overlap_values": sorted(overlap),
        "matching_positions": ndyahr_matches,
    }

    # ── Test 5: Statistical — Y/A/R position correlation with structure ──
    print("\n--- TEST 5: YAR position correlation with null/crib structure ---")
    all_yar_positions = set()
    for positions in yar_pos.values():
        all_yar_positions.update(positions)

    yar_in_nulls = all_yar_positions & CONSENSUS_NULL_POSITIONS
    yar_in_cribs = all_yar_positions & set(CRIB_DICT.keys())

    n_yar = len(all_yar_positions)
    n_null = len(CONSENSUS_NULL_POSITIONS)
    n_crib = len(CRIB_DICT)

    # Expected overlap under independence
    exp_null_overlap = n_yar * n_null / CT_LEN
    exp_crib_overlap = n_yar * n_crib / CT_LEN

    print(f"  Y/A/R positions in K4: {n_yar}")
    print(f"  Overlap with nulls: {len(yar_in_nulls)} (expected: {exp_null_overlap:.1f})")
    print(f"  Overlap with cribs: {len(yar_in_cribs)} (expected: {exp_crib_overlap:.1f})")

    # Are Y/A/R AVOIDED at null positions? (null palette is BGIKOWZ)
    yar_null_palette = YAR_LETTERS & NULL_PALETTE
    print(f"  Y/A/R in null palette {{BGIKOWZ}}: {yar_null_palette if yar_null_palette else 'NONE'}")

    results["test5_correlation"] = {
        "yar_positions": sorted(all_yar_positions),
        "yar_in_nulls": sorted(yar_in_nulls),
        "yar_in_cribs": sorted(yar_in_cribs),
        "expected_null_overlap": round(exp_null_overlap, 2),
        "expected_crib_overlap": round(exp_crib_overlap, 2),
        "yar_in_null_palette": bool(yar_null_palette),
    }

    # ── Test 6: Bean constraint positions involving Y/A/R CT letters ─────
    print("\n--- TEST 6: Bean constraints involving YAR CT positions ---")
    bean_eq_a, bean_eq_b = BEAN_EQ[0]
    eq_yar = CT[bean_eq_a] in YAR_LETTERS or CT[bean_eq_b] in YAR_LETTERS
    print(f"  Bean equality pos {bean_eq_a},{bean_eq_b}: CT={CT[bean_eq_a]},{CT[bean_eq_b]} -> YAR involved: {eq_yar}")

    ineq_yar_count = 0
    for a, b in BEAN_INEQ:
        if CT[a] in YAR_LETTERS or CT[b] in YAR_LETTERS:
            ineq_yar_count += 1
    exp_ineq = 242 * (1 - (1 - n_yar / CT_LEN) ** 2)
    print(f"  Bean inequalities involving YAR CT positions: {ineq_yar_count}/242 (expected: {exp_ineq:.0f})")

    results["test6_bean"] = {
        "eq_involves_yar": eq_yar,
        "ineq_involving_yar": ineq_yar_count,
        "expected_ineq": round(exp_ineq, 1),
    }

    # ── Test 7: Keystream at crib positions — spell anything with YAR? ──
    print("\n--- TEST 7: What do crib keystream values at YAR-CT positions spell? ---")
    ks_at_yar_ct = []
    for pos in sorted(CRIB_DICT.keys()):
        if CT[pos] in YAR_LETTERS:
            ks_at_yar_ct.append(ALPH[CRIB_KS[pos]])
    spelled = "".join(ks_at_yar_ct)
    print(f"  Keystream letters at YAR-CT crib positions: {spelled}")

    # And what do ALL crib keystream values spell?
    all_ks_letters = "".join(ALPH[CRIB_KS[p]] for p in sorted(CRIB_DICT.keys()))
    print(f"  Full crib keystream (Beaufort): {all_ks_letters}")

    results["test7_ks_spelling"] = {
        "yar_ct_crib_ks": spelled,
        "full_crib_ks": all_ks_letters,
    }

    # ── Test 8: NDYAHR sum=64 — does 64 appear anywhere structurally? ───
    print("\n--- TEST 8: NDYAHR sum=64 structural check ---")
    ndyahr_sum = sum(NDYAHR_VALUES.values())
    print(f"  NDYAHR sum: {ndyahr_sum}")
    print(f"  64 mod 26 = {64 % 26} = {ALPH[64 % 26]}")
    print(f"  CT[64] = {CT[64] if 64 < CT_LEN else 'N/A'}")
    print(f"  Position 64 in cribs: {64 in CRIB_DICT}")
    if 64 in CRIB_DICT:
        print(f"    PT[64] = {CRIB_DICT[64]}, KS[64] = {ALPH[CRIB_KS[64]]}")

    # Bean equality: k[27]=k[65]. Position 65-1=64.
    print(f"  Bean equality k[27]=k[65]: position 64 is one before k[65]")
    print(f"  64 = 2^6, and there are 6 displaced letters in NDYAHR")

    results["test8_sum64"] = {
        "ndyahr_sum": ndyahr_sum,
        "ct_at_64": CT[64] if 64 < CT_LEN else None,
        "pos_64_in_crib": 64 in CRIB_DICT,
    }

    # ── Summary ──────────────────────────────────────────────────────────
    elapsed = time.time() - t0
    print(f"\n{'=' * 70}")
    print(f"SUMMARY")
    print(f"{'=' * 70}")
    print(f"Runtime: {elapsed:.1f}s")

    # Key findings
    findings = []
    if len(overlap) >= 4:
        findings.append(f"NOTABLE: {len(overlap)}/6 NDYAHR values appear in crib keystream")
    if len(yar_in_nulls) == 0:
        findings.append("Y/A/R completely avoid consensus null positions")
    if not yar_null_palette:
        findings.append("Y/A/R are NOT in the null palette {BGIKOWZ}")
    if spelled and len(set(spelled)) < len(spelled):
        findings.append(f"Repeated letters in YAR-CT keystream: {spelled}")

    if findings:
        print("\nFindings:")
        for f in findings:
            print(f"  * {f}")
    else:
        print("\nNo notable findings.")

    results["summary"] = {
        "runtime_s": round(elapsed, 1),
        "findings": findings,
    }

    out_path = os.path.join(_ROOT, "results", "yar_output_verification.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nResults saved to: {out_path}")


if __name__ == "__main__":
    main()
