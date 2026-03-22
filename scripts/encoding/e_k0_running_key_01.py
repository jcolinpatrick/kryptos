#!/usr/bin/env python3
"""
E-K0-RUNNING-KEY-01: K0 Morse text as running key for K4 decryption.

K0 has been tested as null mask (e_k0_morse_null_mask.py) and alphabet ordering
(e_morse_indexed_alphabet_01.py), but NEVER as a running key source for K4.

Tests 10+ K0 text variants as running key at all circular offsets, under
Beaufort/Vigenere/Variant-Beaufort with AZ and KA alphabets. Both Model A
(raw CT97) and Model B (consensus nulls removed, cribs remapped to CT73).

Cipher: running key (K0 Morse text)
Family: encoding
Status: active
Keyspace: ~500K configs
Last run: never
Best score: n/a
"""

import sys
import os
import json
import time
from collections import defaultdict

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET, CRIB_DICT

# ── Alphabets ──────────────────────────────────────────────────────────────

AZ_SEQ = ALPH                             # "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
AZ_IDX = ALPH_IDX                         # {'A': 0, 'B': 1, ...}
KA_SEQ = KRYPTOS_ALPHABET                  # "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA_SEQ)}

ALPHABETS = {
    "AZ": (AZ_SEQ, AZ_IDX),
    "KA": (KA_SEQ, KA_IDX),
}

# ── Crib positions (0-indexed) ────────────────────────────────────────────

# Model A: cribs in CT97 space
CRIB_POS_A = sorted(CRIB_DICT.keys())  # 24 positions in [0, 96]
CRIB_PT_A = {p: ALPH_IDX[CRIB_DICT[p]] for p in CRIB_POS_A}  # pos -> numeric PT

# ── Consensus nulls (17 fixed positions from MEMORY.md) ──────────────────

CONSENSUS_NULLS_17 = sorted([0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85])

# For Model B we also need 7 varying null positions. MEMORY.md says 55 candidate
# masks collapse to 3 crib-scoring layouts (no varying null falls within/between
# crib groups). So for crib scoring on CT73, we just need the CT73 mapping.

def build_ct73_mapping():
    """Build CT73 from CT97 by removing consensus nulls.

    Returns:
        ct73: the 73-char ciphertext string (consensus nulls removed)
        crib_map_73: dict mapping CT73 positions -> known PT char (uppercase)

    Since consensus nulls (17 fixed) never overlap with crib positions
    {21-33, 63-73}, all 24 crib chars survive in CT73.
    """
    null_set = set(CONSENSUS_NULLS_17)
    ct73_chars = []
    old_to_new = {}
    for i, c in enumerate(CT):
        if i not in null_set:
            old_to_new[i] = len(ct73_chars)
            ct73_chars.append(c)
    ct73 = "".join(ct73_chars)
    assert len(ct73) == CT_LEN - len(CONSENSUS_NULLS_17)  # should be 80

    crib_map_73 = {}
    for pos, ch in CRIB_DICT.items():
        if pos in old_to_new:
            crib_map_73[old_to_new[pos]] = ALPH_IDX[ch]

    assert len(crib_map_73) == 24, f"Expected 24 cribs in CT73, got {len(crib_map_73)}"
    return ct73, crib_map_73

CT73, CRIB_MAP_73 = build_ct73_mapping()
CRIB_POS_B = sorted(CRIB_MAP_73.keys())

# ── K0 Morse text variants ───────────────────────────────────────────────

K0_PANELS = [
    "eeVIRTUALLYeeeeeINVISIBLE",
    "eDIGETALeeeINTERPRETATIU",
    "eeSHADOWeeFORCESeeeee",
    "LUCIDeeeNEMORYe",
    "TISYOURPOSITIONe",
    "SOS",
    "RQ",
]
K0_FULL_LOWER_E = "".join(K0_PANELS)  # 107 chars, e = Morse E, uppercase = message

# Variant with MEMORY instead of NEMORY
K0_PANELS_MEM = list(K0_PANELS)
K0_PANELS_MEM[3] = "LUCIDeeeMEMORYe"
K0_FULL_MEM = "".join(K0_PANELS_MEM)

def strip_e(text):
    """Remove lowercase e's, return uppercase letters only."""
    return "".join(c for c in text if c != 'e').upper()

def with_E(text):
    """Convert lowercase e to uppercase E, return all uppercase."""
    return text.upper()

def build_variants():
    """Build all K0 text variants to test as running keys."""
    variants = {}

    # 1. Message letters only (remove e's) — NEMORY version
    msg_nemory = strip_e(K0_FULL_LOWER_E)
    variants["K0_msg_NEMORY"] = msg_nemory

    # 2. Full with E's as letter E — NEMORY version
    full_E_nemory = with_E(K0_FULL_LOWER_E)
    variants["K0_full_E_NEMORY"] = full_E_nemory

    # 3. Message letters only — MEMORY version
    msg_memory = strip_e(K0_FULL_MEM)
    variants["K0_msg_MEMORY"] = msg_memory

    # 4. Full with E's as letter E — MEMORY version
    full_E_memory = with_E(K0_FULL_MEM)
    variants["K0_full_E_MEMORY"] = full_E_memory

    # 5. Reversed — message only NEMORY
    variants["K0_msg_NEMORY_rev"] = msg_nemory[::-1]

    # 6. Reversed — full E NEMORY
    variants["K0_full_E_NEMORY_rev"] = full_E_nemory[::-1]

    # 7. Reversed — message only MEMORY
    variants["K0_msg_MEMORY_rev"] = msg_memory[::-1]

    # 8. Reversed — full E MEMORY
    variants["K0_full_E_MEMORY_rev"] = full_E_memory[::-1]

    # 9. Without SOS and RQ (main message only) — NEMORY
    main_panels_nem = K0_PANELS[:5]
    main_nemory = strip_e("".join(main_panels_nem))
    variants["K0_main_NEMORY"] = main_nemory

    # 10. Without SOS and RQ — MEMORY
    main_panels_mem = K0_PANELS_MEM[:5]
    main_memory = strip_e("".join(main_panels_mem))
    variants["K0_main_MEMORY"] = main_memory

    # 11. "WHAT IS YOUR POSITION" restored (Sanborn says text wraps underneath)
    K0_PANELS_WHAT = list(K0_PANELS)
    K0_PANELS_WHAT[4] = "WHATISYOURPOSITION"  # no trailing e
    what_nemory = strip_e("".join(K0_PANELS_WHAT[:5]) + "SOSRQ")
    variants["K0_WHATISYOURPOSITION_NEMORY"] = what_nemory

    K0_PANELS_WHAT_MEM = list(K0_PANELS_MEM)
    K0_PANELS_WHAT_MEM[4] = "WHATISYOURPOSITION"
    what_memory = strip_e("".join(K0_PANELS_WHAT_MEM[:5]) + "SOSRQ")
    variants["K0_WHATISYOURPOSITION_MEMORY"] = what_memory

    # 12. All misspellings corrected: DIGITAL INTERPRETATION (not DIGETAL INTERPRETATIU)
    K0_CORRECTED = [
        "eeVIRTUALLYeeeeeINVISIBLE",
        "eDIGITALeeeINTERPRETATION",
        "eeSHADOWeeFORCESeeeee",
        "LUCIDeeeNEMORYe",
        "TISYOURPOSITIONe",
        "SOS",
        "RQ",
    ]
    corrected_msg = strip_e("".join(K0_CORRECTED))
    variants["K0_corrected_NEMORY"] = corrected_msg

    K0_CORRECTED_MEM = list(K0_CORRECTED)
    K0_CORRECTED_MEM[3] = "LUCIDeeeMEMORYe"
    corrected_msg_mem = strip_e("".join(K0_CORRECTED_MEM))
    variants["K0_corrected_MEMORY"] = corrected_msg_mem

    # 13. Doubled (for full 97-char coverage without wrapping)
    variants["K0_msg_NEMORY_x2"] = msg_nemory * 2
    variants["K0_msg_MEMORY_x2"] = msg_memory * 2

    # 14. Full with E's doubled
    variants["K0_full_E_NEMORY_x2"] = full_E_nemory * 2
    variants["K0_full_E_MEMORY_x2"] = full_E_memory * 2

    # 15. K0 individual words/phrases as short cycling keys
    k0_words = [
        "VIRTUALLYINVISIBLE",
        "DIGETAL", "INTERPRETATIU",
        "DIGETALINTERPRETATIU",
        "SHADOW", "FORCES", "SHADOWFORCES",
        "LUCID", "NEMORY", "LUCIDNEMORY",
        "MEMORY", "LUCIDMEMORY",
        "TISYOURPOSITION", "WHATISYOURPOSITION",
        "SOS", "RQ", "SOSRQ",
        "DIGITAL", "INTERPRETATION", "DIGITALINTERPRETATION",
        # Combine all words
        "VIRTUALLYINVISIBLEDIGETALINTERPRETATIU",
        "VIRTUALLYINVISIBLESHADOWFORCESLUCIDNEMORY",
        "VIRTUALLYINVISIBLEDIGITALINTERPRETATION",
        "VIRTUALLYINVISIBLESHADOWFORCESLUCIDMEMORY",
    ]
    for w in k0_words:
        key = f"K0_word_{w}"
        if key not in variants:
            variants[key] = w

    return variants


# ── Cipher operations ─────────────────────────────────────────────────────

def decrypt_beaufort(ct_nums, key_nums, alph_idx_unused=None):
    """Beaufort: P = (K - C) mod 26"""
    return [(k - c) % MOD for c, k in zip(ct_nums, key_nums)]

def decrypt_vigenere(ct_nums, key_nums, alph_idx_unused=None):
    """Vigenere: P = (C - K) mod 26"""
    return [(c - k) % MOD for c, k in zip(ct_nums, key_nums)]

def decrypt_var_beaufort(ct_nums, key_nums, alph_idx_unused=None):
    """Variant Beaufort: P = (C + K) mod 26"""
    return [(c + k) % MOD for c, k in zip(ct_nums, key_nums)]

CIPHER_VARIANTS = {
    "beaufort": decrypt_beaufort,
    "vigenere": decrypt_vigenere,
    "var_beaufort": decrypt_var_beaufort,
}


# ── Scoring ───────────────────────────────────────────────────────────────

def score_model_a(pt_nums, alph_label):
    """Score against cribs in CT97 positions. Returns count of matching crib chars."""
    score = 0
    for pos in CRIB_POS_A:
        if pos < len(pt_nums) and pt_nums[pos] == CRIB_PT_A[pos]:
            score += 1
    return score

def score_model_b(pt_nums, alph_label):
    """Score against cribs in CT73 positions. Returns count of matching crib chars."""
    score = 0
    for pos in CRIB_POS_B:
        if pos < len(pt_nums) and pt_nums[pos] == CRIB_MAP_73[pos]:
            score += 1
    return score


# ── Main search ───────────────────────────────────────────────────────────

def test_running_key(ct_text, crib_positions, crib_pt_map, key_text, alph_label, alph_seq, alph_idx):
    """Test a running key at all circular offsets under all 3 cipher variants.

    Returns list of (score, offset, variant_name, pt_snippet) for scores > 0.
    """
    ct_len = len(ct_text)
    key_len = len(key_text)

    # Convert CT to numeric using this alphabet
    ct_nums = [alph_idx[c] for c in ct_text]

    # Convert key text to numeric using this alphabet
    key_all_nums = [alph_idx[c] for c in key_text]

    results = []

    for variant_name, decrypt_fn in CIPHER_VARIANTS.items():
        for offset in range(key_len):
            # Build key stream: key_text[(i + offset) % key_len] for each position
            key_nums = [key_all_nums[(i + offset) % key_len] for i in range(ct_len)]

            # Decrypt
            pt_nums = decrypt_fn(ct_nums, key_nums)

            # Score
            score = 0
            for pos in crib_positions:
                if pos < len(pt_nums) and pt_nums[pos] == crib_pt_map[pos]:
                    score += 1

            if score > 0:
                # Convert PT to text for reporting
                pt_text = "".join(alph_seq[n] for n in pt_nums)
                results.append((score, offset, variant_name, pt_text))

    return results


def main():
    t0 = time.time()

    print("=" * 74)
    print("E-K0-RUNNING-KEY-01: K0 Morse Text as Running Key for K4")
    print("=" * 74)
    print(f"CT97: {CT} (len={len(CT)})")
    print(f"CT73: {CT73} (len={len(CT73)})")
    print(f"Crib positions Model A: {CRIB_POS_A}")
    print(f"Crib positions Model B: {CRIB_POS_B}")
    print()

    variants = build_variants()
    print(f"K0 variants to test: {len(variants)}")
    for name, text in sorted(variants.items()):
        print(f"  {name}: len={len(text)}, text={text[:60]}{'...' if len(text) > 60 else ''}")
    print()

    # Track all results
    all_results = []
    total_configs = 0
    best_score_a = 0
    best_score_b = 0
    best_result_a = None
    best_result_b = None

    # Score distribution
    score_dist_a = defaultdict(int)
    score_dist_b = defaultdict(int)

    for vi, (vname, vtext) in enumerate(sorted(variants.items())):
        for alph_label, (alph_seq, alph_idx) in ALPHABETS.items():
            # Model A: raw CT97
            results_a = test_running_key(
                CT, CRIB_POS_A, CRIB_PT_A,
                vtext, alph_label, alph_seq, alph_idx
            )
            n_offsets = len(vtext)
            n_variants_cipher = 3
            configs_this = n_offsets * n_variants_cipher
            total_configs += configs_this

            for score, offset, cipher_var, pt_text in results_a:
                score_dist_a[score] += 1
                entry = {
                    "model": "A",
                    "variant": vname,
                    "alphabet": alph_label,
                    "cipher": cipher_var,
                    "offset": offset,
                    "score": score,
                    "pt_snippet": pt_text[:40],
                    "key_len": len(vtext),
                }
                all_results.append(entry)
                if score > best_score_a:
                    best_score_a = score
                    best_result_a = entry
                    print(f"  [NEW BEST Model A] score={score}/24: "
                          f"{vname} {alph_label} {cipher_var} offset={offset}")

            # Model B: CT73 with consensus nulls removed
            results_b = test_running_key(
                CT73, CRIB_POS_B, CRIB_MAP_73,
                vtext, alph_label, alph_seq, alph_idx
            )
            total_configs += configs_this  # same number of offsets

            for score, offset, cipher_var, pt_text in results_b:
                score_dist_b[score] += 1
                entry = {
                    "model": "B",
                    "variant": vname,
                    "alphabet": alph_label,
                    "cipher": cipher_var,
                    "offset": offset,
                    "score": score,
                    "pt_snippet": pt_text[:40],
                    "key_len": len(vtext),
                }
                all_results.append(entry)
                if score > best_score_b:
                    best_score_b = score
                    best_result_b = entry
                    print(f"  [NEW BEST Model B] score={score}/24: "
                          f"{vname} {alph_label} {cipher_var} offset={offset}")

        # Progress
        pct = 100 * (vi + 1) / len(variants)
        print(f"  [{vi+1}/{len(variants)}] {vname} done ({pct:.0f}%)")

    elapsed = time.time() - t0

    # ── Summary ──────────────────────────────────────────────────────────
    print()
    print("=" * 74)
    print("RESULTS SUMMARY")
    print("=" * 74)
    print(f"Total configs tested: {total_configs:,}")
    print(f"Elapsed: {elapsed:.1f}s")
    print(f"Rate: {total_configs / elapsed:,.0f} configs/sec")
    print()

    print(f"Best score Model A (CT97): {best_score_a}/24")
    if best_result_a:
        print(f"  {best_result_a}")
    print(f"Best score Model B (CT73): {best_score_b}/24")
    if best_result_b:
        print(f"  {best_result_b}")
    print()

    print("Score distribution Model A:")
    for s in sorted(score_dist_a.keys()):
        print(f"  score {s}: {score_dist_a[s]} configs")
    print("Score distribution Model B:")
    for s in sorted(score_dist_b.keys()):
        print(f"  score {s}: {score_dist_b[s]} configs")
    print()

    # Top 20 results
    all_results.sort(key=lambda r: -r["score"])
    print("Top 20 results (all models):")
    for i, r in enumerate(all_results[:20]):
        print(f"  #{i+1}: score={r['score']}/24 model={r['model']} "
              f"{r['variant']} {r['alphabet']} {r['cipher']} offset={r['offset']} "
              f"pt={r['pt_snippet']}")

    # ── Thresholds ────────────────────────────────────────────────────────
    interesting = [r for r in all_results if r["score"] >= 10]
    signal = [r for r in all_results if r["score"] >= 18]
    breakthrough = [r for r in all_results if r["score"] >= 24]

    print()
    if breakthrough:
        print(f"*** BREAKTHROUGH: {len(breakthrough)} configs at 24/24 ***")
        for r in breakthrough:
            print(f"  {r}")
    elif signal:
        print(f"*** SIGNAL: {len(signal)} configs at >= 18/24 ***")
        for r in signal:
            print(f"  {r}")
    elif interesting:
        print(f"Interesting (>= 10/24): {len(interesting)} configs")
        for r in interesting:
            print(f"  {r}")
    else:
        max_score = max(r["score"] for r in all_results) if all_results else 0
        print(f"ALL NOISE. Max score: {max_score}/24")
        print("K0 Morse text as running key is ELIMINATED for both Model A and Model B.")

    # ── Conclusion ────────────────────────────────────────────────────────
    max_overall = max(best_score_a, best_score_b)
    if max_overall >= 18:
        conclusion = "SIGNAL"
    elif max_overall >= 10:
        conclusion = "INTERESTING"
    else:
        conclusion = "DISPROVED"

    print(f"\nConclusion: {conclusion}")

    # ── Save JSON ─────────────────────────────────────────────────────────
    output = {
        "experiment": "E-K0-RUNNING-KEY-01",
        "description": "K0 Morse text (10+ variants) as running key for K4, all offsets, "
                       "Beaufort/Vigenere/VarBeau, AZ/KA, Model A (CT97) + Model B (CT73)",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "total_configs": total_configs,
        "elapsed_seconds": round(elapsed, 1),
        "variants_tested": len(variants),
        "variant_names": sorted(variants.keys()),
        "best_score_model_a": best_score_a,
        "best_result_model_a": best_result_a,
        "best_score_model_b": best_score_b,
        "best_result_model_b": best_result_b,
        "score_distribution_a": {str(k): v for k, v in sorted(score_dist_a.items())},
        "score_distribution_b": {str(k): v for k, v in sorted(score_dist_b.items())},
        "top_20": all_results[:20],
        "interesting_ge10": interesting,
        "signal_ge18": signal,
        "breakthrough_24": breakthrough,
        "conclusion": conclusion,
        "ciphertext": CT,
        "ct73": CT73,
        "consensus_nulls": CONSENSUS_NULLS_17,
        "crib_positions_a": CRIB_POS_A,
        "crib_positions_b": CRIB_POS_B,
    }

    out_path = os.path.join(_ROOT, "results", "e_k0_running_key_01.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to: {out_path}")


if __name__ == "__main__":
    main()
