#!/usr/bin/env python3
"""
E-SOLVE-02: Deep K4 attacks — advanced position-dependent keys and
segmented dual-system models.

Tests:
  1. Sinusoidal keys (modeling physical S-curve of sculpture)
  2. Segmented dual-system encryption (split at every position)
  3. Multiplicative/power-law position functions
  4. CT-derived keystream (non-standard autokey variants)
  5. Two-keyword model with keyword-derived modular key
  6. "Try both" 97/98 chars (Sanborn clue)

Usage:
    PYTHONPATH=src python3 -u scripts/e_solve_02_deep_attacks.py
"""
from __future__ import annotations

import json
import math
import time
from pathlib import Path

from kryptos.kernel.constants import (
    ALPH, ALPH_IDX, CT, CT_LEN, MOD,
    CRIB_DICT, CRIB_ENTRIES, CRIB_WORDS, N_CRIBS,
    KRYPTOS_ALPHABET,
    BEAN_EQ, BEAN_INEQ,
    NOISE_FLOOR,
)


def vig_dec(ct_idx: int, key_val: int) -> int:
    return (ct_idx - key_val) % MOD

def beau_dec(ct_idx: int, key_val: int) -> int:
    return (key_val - ct_idx) % MOD

def crib_score_fast(candidate_indices: list[int]) -> int:
    """Count crib matches using integer indices."""
    score = 0
    for pos, ch in CRIB_ENTRIES:
        if pos < len(candidate_indices) and candidate_indices[pos] == ALPH_IDX[ch]:
            score += 1
    return score

def bean_check_fast(ks: list[int]) -> bool:
    for a, b in BEAN_EQ:
        if a < len(ks) and b < len(ks) and ks[a] != ks[b]:
            return False
    for a, b in BEAN_INEQ:
        if a < len(ks) and b < len(ks) and ks[a] == ks[b]:
            return False
    return True

CT_IDX = [ALPH_IDX[c] for c in CT]


# ── Hypothesis 6: Sinusoidal / S-Curve Keys ─────────────────────────────

def test_sinusoidal_keys():
    """
    The Kryptos sculpture is S-curved. Model the key as a sinusoidal
    function of position, testing various amplitudes, periods, and phases.

    k[i] = round(A * sin(2π*i/P + φ)) mod 26
    Also test: k[i] = round(A * sin(2π*i/P + φ) + B * cos(2π*i/Q + ψ)) mod 26
    """
    print("\n" + "="*70)
    print("HYPOTHESIS 6: Sinusoidal / S-Curve Keys")
    print("="*70)

    best_score = 0
    results = []
    configs_tested = 0

    # Single sinusoid
    for A in range(1, 26):  # amplitude
        for P_num in range(2, 98):  # period (not necessarily integer)
            P = float(P_num)
            for phi_steps in range(0, 26):  # phase in steps of 2π/26
                phi = 2 * math.pi * phi_steps / 26
                configs_tested += 1

                ks = [round(A * math.sin(2 * math.pi * i / P + phi)) % MOD for i in range(CT_LEN)]
                pt = [vig_dec(CT_IDX[i], ks[i]) for i in range(CT_LEN)]
                score = crib_score_fast(pt)

                if score > best_score:
                    best_score = score
                    if score > NOISE_FLOOR:
                        results.append({
                            "type": "single_sin",
                            "A": A, "P": P, "phi": phi_steps,
                            "score": score,
                            "bean": bean_check_fast(ks),
                        })

    # Double sinusoid (sum of two frequencies) — sample
    for A1 in [3, 7, 13]:
        for P1 in [7, 13, 24, 38, 97]:
            for A2 in [2, 5, 11]:
                for P2 in [11, 19, 31, 73]:
                    if P1 == P2:
                        continue
                    for phi1_s in range(0, 13, 2):
                        phi1 = 2 * math.pi * phi1_s / 26
                        for phi2_s in range(0, 13, 2):
                            phi2 = 2 * math.pi * phi2_s / 26
                            configs_tested += 1
                            ks = [round(A1 * math.sin(2*math.pi*i/P1 + phi1) +
                                       A2 * math.sin(2*math.pi*i/P2 + phi2)) % MOD
                                  for i in range(CT_LEN)]
                            pt = [vig_dec(CT_IDX[i], ks[i]) for i in range(CT_LEN)]
                            score = crib_score_fast(pt)
                            if score > best_score:
                                best_score = score

    print(f"  Tested {configs_tested} sinusoidal key configs")
    print(f"  Best score: {best_score}/24")
    if results:
        print(f"  Above-noise: {len(results)}")
    else:
        print("  RESULT: No sinusoidal key produces above-noise scores.")
    return results


# ── Hypothesis 7: Segmented Dual-System ──────────────────────────────────

def test_segmented_dual_system():
    """
    Test if K4 uses two different cipher systems applied to different
    segments of the text. For each split point, try all combinations
    of Vig/Beau/VarBeau with various keywords for each segment.
    """
    print("\n" + "="*70)
    print("HYPOTHESIS 7: Segmented Dual-System Encryption")
    print("="*70)

    KW_LIST = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SANBORN", "SCHEIDT",
               "SHADOW", "BERLIN", "CLOCK", "EAST", "NORTH"]

    variants = {
        "vig": lambda ct, k: (ct - k) % MOD,
        "beau": lambda ct, k: (k - ct) % MOD,
        "var_beau": lambda ct, k: (ct + k) % MOD,
    }

    best_score = 0
    results = []
    configs_tested = 0

    for split in range(15, 80):  # split point
        for kw1 in KW_LIST:
            kw1_vals = [ALPH_IDX[c] for c in kw1]
            for v1_name, v1_fn in variants.items():
                for kw2 in KW_LIST:
                    kw2_vals = [ALPH_IDX[c] for c in kw2]
                    for v2_name, v2_fn in variants.items():
                        configs_tested += 1

                        # Decrypt: first segment with system 1, second with system 2
                        pt = []
                        ks = []
                        for i in range(CT_LEN):
                            if i < split:
                                k = kw1_vals[i % len(kw1_vals)]
                                pt.append(v1_fn(CT_IDX[i], k))
                                ks.append(k)
                            else:
                                k = kw2_vals[(i - split) % len(kw2_vals)]
                                pt.append(v2_fn(CT_IDX[i], k))
                                ks.append(k)

                        score = crib_score_fast(pt)
                        if score > best_score:
                            best_score = score
                            if score > NOISE_FLOOR:
                                results.append({
                                    "split": split,
                                    "sys1": f"{v1_name}+{kw1}",
                                    "sys2": f"{v2_name}+{kw2}",
                                    "score": score,
                                    "bean": bean_check_fast(ks),
                                })

    # Also test: same keyword, different offset for second segment
    for kw in KW_LIST:
        kw_vals = [ALPH_IDX[c] for c in kw]
        for v_name, v_fn in variants.items():
            for split in range(15, 80, 5):
                for offset in range(len(kw)):
                    configs_tested += 1
                    pt = []
                    for i in range(CT_LEN):
                        if i < split:
                            k = kw_vals[i % len(kw_vals)]
                        else:
                            k = kw_vals[(i + offset) % len(kw_vals)]
                        pt.append(v_fn(CT_IDX[i], k))
                    score = crib_score_fast(pt)
                    if score > best_score:
                        best_score = score

    print(f"  Tested {configs_tested} segmented configs")
    print(f"  Best score: {best_score}/24")
    if results:
        print(f"  Above-noise: {len(results)}")
        for r in sorted(results, key=lambda x: -x['score'])[:5]:
            print(f"    split={r['split']} {r['sys1']}|{r['sys2']} score={r['score']} bean={r['bean']}")
    else:
        print("  RESULT: No segmented dual-system produces above-noise scores.")
    return results


# ── Hypothesis 8: CT-Derived Keystream (Non-Standard Autokey) ────────────

def test_ct_derived_keystream():
    """
    Test if the keystream is derived from the ciphertext itself in non-standard ways.

    Models:
    - k[i] = CT[i-j] for various offsets j (delayed CT autokey)
    - k[i] = CT[i-j] + CT[i-k] mod 26 (combined delayed)
    - k[i] = CT[97-1-i] (reversed CT as key)
    - k[i] = CT[(i*a) mod 97] for various a (permuted CT as key)
    - k[i] = CT[i] XOR CT[i-1] conceptually (difference of adjacent CT chars)
    """
    print("\n" + "="*70)
    print("HYPOTHESIS 8: CT-Derived Keystream (Non-Standard Autokey)")
    print("="*70)

    best_score = 0
    results = []
    configs_tested = 0

    # Model 1: Delayed CT autokey — k[i] = f(CT[i-j]) for offset j
    for j in range(1, CT_LEN):
        for variant in ["vig", "beau"]:
            configs_tested += 1
            ks = [CT_IDX[(i - j) % CT_LEN] for i in range(CT_LEN)]
            if variant == "vig":
                pt = [vig_dec(CT_IDX[i], ks[i]) for i in range(CT_LEN)]
            else:
                pt = [beau_dec(CT_IDX[i], ks[i]) for i in range(CT_LEN)]
            score = crib_score_fast(pt)
            if score > best_score:
                best_score = score
                if score > NOISE_FLOOR:
                    results.append({"type": "delayed_ct", "offset": j, "variant": variant, "score": score})

    # Model 2: Combined delayed — k[i] = (CT[i-a] + CT[i-b]) mod 26
    for a in range(1, 20):
        for b in range(a+1, 25):
            configs_tested += 1
            ks = [(CT_IDX[(i-a) % CT_LEN] + CT_IDX[(i-b) % CT_LEN]) % MOD for i in range(CT_LEN)]
            pt = [vig_dec(CT_IDX[i], ks[i]) for i in range(CT_LEN)]
            score = crib_score_fast(pt)
            if score > best_score:
                best_score = score

    # Model 3: Reversed CT as key
    for variant in ["vig", "beau", "var_beau"]:
        configs_tested += 1
        rev_ct = CT_IDX[::-1]
        if variant == "vig":
            pt = [vig_dec(CT_IDX[i], rev_ct[i]) for i in range(CT_LEN)]
        elif variant == "beau":
            pt = [beau_dec(CT_IDX[i], rev_ct[i]) for i in range(CT_LEN)]
        else:
            pt = [(CT_IDX[i] + rev_ct[i]) % MOD for i in range(CT_LEN)]
        score = crib_score_fast(pt)
        if score > best_score:
            best_score = score

    # Model 4: Permuted CT as key — k[i] = CT[(i*a) mod 97]
    for a in range(2, 97):
        if math.gcd(a, 97) != 1:
            continue
        configs_tested += 1
        ks = [CT_IDX[(i * a) % CT_LEN] for i in range(CT_LEN)]
        pt = [vig_dec(CT_IDX[i], ks[i]) for i in range(CT_LEN)]
        score = crib_score_fast(pt)
        if score > best_score:
            best_score = score

    # Model 5: CT difference key — k[i] = (CT[i] - CT[i-1]) mod 26
    for step in range(1, 10):
        configs_tested += 1
        ks = [(CT_IDX[i] - CT_IDX[(i - step) % CT_LEN]) % MOD for i in range(CT_LEN)]
        pt = [vig_dec(CT_IDX[i], ks[i]) for i in range(CT_LEN)]
        score = crib_score_fast(pt)
        if score > best_score:
            best_score = score

    # Model 6: CT cumulative sum as key
    configs_tested += 1
    cumsum = [0] * CT_LEN
    cumsum[0] = CT_IDX[0]
    for i in range(1, CT_LEN):
        cumsum[i] = (cumsum[i-1] + CT_IDX[i]) % MOD
    pt = [vig_dec(CT_IDX[i], cumsum[i]) for i in range(CT_LEN)]
    score = crib_score_fast(pt)
    if score > best_score:
        best_score = score

    print(f"  Tested {configs_tested} CT-derived keystream configs")
    print(f"  Best score: {best_score}/24")
    if results:
        for r in results[:5]:
            print(f"    {r}")
    else:
        print("  RESULT: No CT-derived keystream produces above-noise scores.")
    return results


# ── Hypothesis 9: Two-Keyword Modular Key ────────────────────────────────

def test_two_keyword_modular():
    """
    Model: k[i] = KW1[i % len(KW1)] * KW2[i % len(KW2)] mod 26
    (multiplicative combination of two periodic keys)

    Also test: k[i] = KW1[i % p1] + KW2[floor(i/p1) % p2] (row+col with keywords)
    """
    print("\n" + "="*70)
    print("HYPOTHESIS 9: Two-Keyword Modular Key Combination")
    print("="*70)

    KW_LIST = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SANBORN", "SCHEIDT",
               "SHADOW", "LUCID", "BERLIN", "CLOCK", "EAST", "POINT"]

    best_score = 0
    results = []
    configs_tested = 0

    for kw1 in KW_LIST:
        v1 = [ALPH_IDX[c] for c in kw1]
        for kw2 in KW_LIST:
            v2 = [ALPH_IDX[c] for c in kw2]
            p1, p2 = len(kw1), len(kw2)

            # Multiplicative: k = KW1 * KW2 mod 26
            configs_tested += 1
            ks_mult = [(v1[i % p1] * v2[i % p2]) % MOD for i in range(CT_LEN)]
            pt = [vig_dec(CT_IDX[i], ks_mult[i]) for i in range(CT_LEN)]
            score = crib_score_fast(pt)
            if score > best_score:
                best_score = score
                if score > NOISE_FLOOR:
                    results.append({"type": "mult", "kw1": kw1, "kw2": kw2, "score": score})

            # XOR: k = KW1 XOR KW2 (treating as mod-26 values)
            configs_tested += 1
            ks_xor = [(v1[i % p1] ^ v2[i % p2]) % MOD for i in range(CT_LEN)]
            pt = [vig_dec(CT_IDX[i], ks_xor[i]) for i in range(CT_LEN)]
            score = crib_score_fast(pt)
            if score > best_score:
                best_score = score

            # Additive with floor division: k = KW1[i%p1] + KW2[floor(i/p1)%p2]
            configs_tested += 1
            ks_floor = [(v1[i % p1] + v2[(i // p1) % p2]) % MOD for i in range(CT_LEN)]
            pt = [vig_dec(CT_IDX[i], ks_floor[i]) for i in range(CT_LEN)]
            score = crib_score_fast(pt)
            if score > best_score:
                best_score = score
                if score > NOISE_FLOOR:
                    results.append({"type": "floor_add", "kw1": kw1, "kw2": kw2, "score": score})

            # Beaufort variants
            for variant_name, dec_fn in [("beau", beau_dec)]:
                configs_tested += 1
                pt = [dec_fn(CT_IDX[i], ks_mult[i]) for i in range(CT_LEN)]
                score = crib_score_fast(pt)
                if score > best_score:
                    best_score = score

    print(f"  Tested {configs_tested} two-keyword modular configs")
    print(f"  Best score: {best_score}/24")
    if results:
        for r in sorted(results, key=lambda x: -x['score'])[:5]:
            print(f"    {r}")
    else:
        print("  RESULT: No two-keyword modular key produces above-noise scores.")
    return results


# ── Hypothesis 10: "Try Both" 97/98 Chars ────────────────────────────────

def test_try_both():
    """
    Sanborn said "try both" regarding 97/98 characters. Test:
    - CT with an extra character appended (A-Z) at various positions
    - CT with one character removed from each position
    - CT with characters shifted by 1 position (off-by-one reading)
    """
    print("\n" + "="*70)
    print('HYPOTHESIS 10: "Try Both" 97/98 Characters')
    print("="*70)

    KW_LIST = ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]
    best_score = 0
    results = []
    configs_tested = 0

    # Test 98-char CT (add one letter at each position)
    for insert_pos in range(CT_LEN + 1):
        for insert_char in range(26):
            ct98 = CT[:insert_pos] + ALPH[insert_char] + CT[insert_pos:]
            ct98_idx = [ALPH_IDX[c] for c in ct98]

            for kw in KW_LIST:
                kv = [ALPH_IDX[c] for c in kw]
                configs_tested += 1

                pt = [vig_dec(ct98_idx[i], kv[i % len(kv)]) for i in range(len(ct98))]

                # Check cribs (need to adjust positions based on insert)
                score = 0
                for crib_pos, ch in CRIB_ENTRIES:
                    adj_pos = crib_pos + (1 if insert_pos <= crib_pos else 0)
                    if adj_pos < len(pt) and pt[adj_pos] == ALPH_IDX[ch]:
                        score += 1

                if score > best_score:
                    best_score = score
                    if score > NOISE_FLOOR:
                        pt_str = ''.join(ALPH[p] for p in pt)
                        results.append({
                            "type": "insert",
                            "pos": insert_pos,
                            "char": ALPH[insert_char],
                            "kw": kw,
                            "score": score,
                            "pt": pt_str[:50],
                        })

    # Test 96-char CT (remove one character from each position)
    for remove_pos in range(CT_LEN):
        ct96 = CT[:remove_pos] + CT[remove_pos+1:]
        ct96_idx = [ALPH_IDX[c] for c in ct96]

        for kw in KW_LIST:
            kv = [ALPH_IDX[c] for c in kw]
            configs_tested += 1

            pt = [vig_dec(ct96_idx[i], kv[i % len(kv)]) for i in range(len(ct96))]
            score = 0
            for crib_pos, ch in CRIB_ENTRIES:
                adj_pos = crib_pos - (1 if remove_pos <= crib_pos else 0)
                if 0 <= adj_pos < len(pt) and pt[adj_pos] == ALPH_IDX[ch]:
                    score += 1

            if score > best_score:
                best_score = score
                if score > NOISE_FLOOR:
                    results.append({
                        "type": "remove",
                        "pos": remove_pos,
                        "kw": kw,
                        "score": score,
                    })

    # Test shifted reading (off-by-one in each direction)
    for shift in [-3, -2, -1, 1, 2, 3]:
        ct_shifted = CT[shift:] + CT[:shift] if shift > 0 else CT[shift:] + CT[:shift]
        ct_s_idx = [ALPH_IDX[c] for c in ct_shifted]
        for kw in KW_LIST:
            kv = [ALPH_IDX[c] for c in kw]
            configs_tested += 1
            pt = [vig_dec(ct_s_idx[i], kv[i % len(kv)]) for i in range(CT_LEN)]
            score = crib_score_fast(pt)
            if score > best_score:
                best_score = score

    print(f"  Tested {configs_tested} 97/98-char configs")
    print(f"  Best score: {best_score}/24")
    if results:
        for r in sorted(results, key=lambda x: -x['score'])[:5]:
            print(f"    {r}")
    else:
        print('  RESULT: No "try both" variant produces above-noise scores.')
    return results


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    print("E-SOLVE-02: Deep K4 Attacks")
    print(f"CT: {CT[:40]}...")
    print()

    start = time.time()
    all_results = {}

    all_results["h6_sinusoidal"] = test_sinusoidal_keys()
    all_results["h7_segmented"] = test_segmented_dual_system()
    all_results["h8_ct_derived"] = test_ct_derived_keystream()
    all_results["h9_two_keyword"] = test_two_keyword_modular()
    all_results["h10_try_both"] = test_try_both()

    elapsed = time.time() - start

    print("\n" + "="*70)
    print(f"E-SOLVE-02 SUMMARY ({elapsed:.1f}s)")
    print("="*70)

    total_signal = 0
    for hname, hresults in all_results.items():
        if isinstance(hresults, list):
            above = [r for r in hresults if isinstance(r, dict) and r.get("score", 0) > NOISE_FLOOR]
            print(f"  {hname}: {len(above)} above-noise results")
            total_signal += len(above)
        else:
            print(f"  {hname}: {hresults}")

    if total_signal == 0:
        print("\n  OVERALL: ALL NOISE — no deep attack produced signal above noise floor.")
    else:
        print(f"\n  OVERALL: {total_signal} above-noise results found!")

    output_path = Path("results")
    output_path.mkdir(exist_ok=True)
    serializable = {}
    for k, v in all_results.items():
        if isinstance(v, list):
            serializable[k] = [
                {kk: vv for kk, vv in item.items() if isinstance(vv, (str, int, float, bool, list, dict, type(None)))}
                for item in v if isinstance(item, dict)
            ]
    with open(output_path / "e_solve_02_results.json", "w") as f:
        json.dump(serializable, f, indent=2)
    print(f"  Results saved to results/e_solve_02_results.json")


if __name__ == "__main__":
    main()
