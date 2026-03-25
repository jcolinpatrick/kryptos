#!/usr/bin/env python3
"""
Cipher: multi_layer
Family: analysis
Status: active
Keyspace: 3 masks x ~50K keyword/variant configs + col7 transposition
Last run:
Best score:
"""
"""
E-TOP3-MASK-CIPHER-ATTACK: Cipher attacks on top 3 CT73 candidates

Tests the 3 best masks from Phase 5 (width-21 optimized, w21=8) against:
  1. Periodic Beaufort/Vigenere/VarBeau with thematic keywords (periods 1-13)
  2. Col7 transposition + periodic substitution
  3. Free-position crib scoring (score_candidate_free)
  4. All 26 single-letter keys (Caesar-like)
  5. Running key from K1/K2/K3 plaintext

Output: results/top3_mask_cipher_attack.json
Repro: PYTHONPATH=src python3 -u scripts/analysis/e_top3_mask_cipher_attack.py
"""

import json
import sys
import os
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH_IDX, MOD, CONSENSUS_NULL_POSITIONS, CRIB_POSITIONS, CRIB_DICT,
    BEAN_EQ, BEAN_INEQ, KRYPTOS_ALPHABET
)
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free
from kryptos.kernel.alphabet import AZ, KA

# ── Top 3 masks from Phase 5 ──
TOP_MASKS = [
    {"id": "mask_A", "extra": [18, 19, 46, 47, 56, 62, 93], "desc": "BB ZZ I B K"},
    {"id": "mask_B", "extra": [18, 19, 46, 48, 56, 62, 93], "desc": "BB Z W I B K"},
    {"id": "mask_C", "extra": [18, 19, 47, 48, 56, 62, 93], "desc": "BB Z W I B K (alt)"},
]

# ── Thematic keywords ──
KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "SHADOW", "BERLIN",
    "SCHEIDT", "SANBORN", "SEVEN", "CLOCK", "EAST", "NORTH", "LAYER",
    "CHART", "TOWER", "MORSE", "CIPHER", "SECRET", "HIDDEN",
    "ANTIPODES", "LUCID", "LIGHT", "DARK", "IQLUSION", "DIGETAL",
    "MEDUSA", "INVISIBLE", "MATRIX", "QUASI",
]

# K1/K2/K3 plaintexts for running-key test
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUABOROFBIQLUSION"  # approximate
K2_PT = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATION"
K3_PT = "SLOWLYDESPERATELYSLOWLYTHEREMAINSOFPASSAGEDEBABORISCLISOSEDWITHTHEUPPERPARTOFADOORWAYWASBLOCKEDTHERESTTHENWITHTREMBLIGHHANDSIMADEATINYBREACHINTHELEFTHANDCORNERANDTHENWIDENIGTHEHOALEALITTLEIINSERTEDTHECANDLEANDPEEREDINTHEHOTAIRERSAPINGFROMTHECHAMBERCAUSEDTHEFLAMETORFLICKERBUTPRESENTLYDETAILSOFTHEROOMWITHIGEMERGEDFROMTHEMISTXCANYOUSAEANYTHINGQ"

VARIANTS = ["vigenere", "beaufort", "var_beaufort"]


def decrypt(ct_nums, key_nums, variant):
    """Decrypt ct_nums with key_nums (cycling) under variant."""
    pt = []
    klen = len(key_nums)
    for i, c in enumerate(ct_nums):
        k = key_nums[i % klen]
        if variant == "vigenere":
            p = (c - k) % MOD
        elif variant == "beaufort":
            p = (k - c) % MOD
        elif variant == "var_beaufort":
            p = (c + k) % MOD
        pt.append(p)
    return pt


def nums_to_text(nums):
    return "".join(chr(n + ord('A')) for n in nums)


def text_to_nums(text):
    return [ALPH_IDX[c] for c in text.upper() if c in ALPH_IDX]


def columnar_untranspose(text, width):
    """Undo columnar transposition: text was read column-by-column, restore row-by-row."""
    n = len(text)
    nrows = (n + width - 1) // width
    full_cols = n % width or width

    # Build columns
    cols = []
    idx = 0
    for col in range(width):
        col_len = nrows if col < full_cols else nrows - 1
        cols.append(text[idx:idx + col_len])
        idx += col_len

    # Read row by row
    result = []
    for row in range(nrows):
        for col in range(width):
            if row < len(cols[col]):
                result.append(cols[col][row])
    return "".join(result)


def extract_ct73(extra_nulls):
    """Extract 73-char ciphertext given the 7 extra null positions."""
    null_mask = CONSENSUS_NULL_POSITIONS | set(extra_nulls)
    return "".join(CT[i] for i in range(CT_LEN) if i not in null_mask)


print("=" * 70)
print("E-TOP3-MASK-CIPHER-ATTACK: Cipher Attacks on Top 3 CT73 Candidates")
print("=" * 70)

all_results = {}
global_best = {"score": 0}

for mask_info in TOP_MASKS:
    mask_id = mask_info["id"]
    extra = mask_info["extra"]
    ct73 = extract_ct73(extra)
    ct73_nums = text_to_nums(ct73)
    n73 = len(ct73)

    print(f"\n{'=' * 70}")
    print(f"MASK {mask_id}: extra nulls = {extra} ({mask_info['desc']})")
    print(f"CT73 ({n73}): {ct73}")
    print("-" * 70)

    mask_results = {
        "mask_id": mask_id,
        "extra_nulls": extra,
        "ct73": ct73,
        "hits": [],
    }

    best_for_mask = {"score": 0}

    # ── Test 1: Periodic keywords ──
    print(f"\n  [1] Periodic keywords ({len(KEYWORDS)} keywords x {len(VARIANTS)} variants)...")
    for kw in KEYWORDS:
        kw_nums = text_to_nums(kw)
        if not kw_nums:
            continue
        for variant in VARIANTS:
            pt_nums = decrypt(ct73_nums, kw_nums, variant)
            pt_str = nums_to_text(pt_nums)
            fsb = score_candidate_free(pt_str)
            if fsb.crib_score >= 6:
                hit = {
                    "test": "periodic",
                    "keyword": kw,
                    "variant": variant,
                    "crib_score": fsb.crib_score,
                    "plaintext": pt_str[:80],
                }
                mask_results["hits"].append(hit)
                if fsb.crib_score > best_for_mask["score"]:
                    best_for_mask = {"score": fsb.crib_score, **hit}

    # ── Test 2: Col7 untranspose + periodic keywords ──
    print(f"  [2] Col7 untranspose + keywords...")
    for perm_id, col_order in enumerate([[0,1,2,3,4,5,6]]):  # Identity first
        ct73_col7 = columnar_untranspose(ct73, 7)
        ct73_col7_nums = text_to_nums(ct73_col7)
        for kw in KEYWORDS:
            kw_nums = text_to_nums(kw)
            for variant in VARIANTS:
                pt_nums = decrypt(ct73_col7_nums, kw_nums, variant)
                pt_str = nums_to_text(pt_nums)
                fsb = score_candidate_free(pt_str)
                if fsb.crib_score >= 6:
                    hit = {
                        "test": "col7_periodic",
                        "keyword": kw,
                        "variant": variant,
                        "crib_score": fsb.crib_score,
                        "plaintext": pt_str[:80],
                    }
                    mask_results["hits"].append(hit)
                    if fsb.crib_score > best_for_mask["score"]:
                        best_for_mask = {"score": fsb.crib_score, **hit}

    # ── Test 3: All 26 single-letter keys ──
    print(f"  [3] Single-letter keys (26 x 3 variants)...")
    for k in range(26):
        for variant in VARIANTS:
            pt_nums = decrypt(ct73_nums, [k], variant)
            pt_str = nums_to_text(pt_nums)
            fsb = score_candidate_free(pt_str)
            if fsb.crib_score >= 6:
                hit = {
                    "test": "single_key",
                    "key_letter": chr(k + ord('A')),
                    "variant": variant,
                    "crib_score": fsb.crib_score,
                    "plaintext": pt_str[:80],
                }
                mask_results["hits"].append(hit)
                if fsb.crib_score > best_for_mask["score"]:
                    best_for_mask = {"score": fsb.crib_score, **hit}

    # ── Test 4: Running key from K1/K2/K3 ──
    print(f"  [4] Running keys from K1/K2/K3 plaintexts...")
    for name, rk_text in [("K1", K1_PT), ("K2", K2_PT), ("K3", K3_PT)]:
        rk_clean = "".join(c for c in rk_text.upper() if c in ALPH_IDX)
        rk_nums = text_to_nums(rk_clean)
        max_offset = len(rk_nums) - n73
        if max_offset <= 0:
            continue
        for offset in range(max_offset):
            key_slice = rk_nums[offset:offset + n73]
            for variant in VARIANTS:
                pt_nums = decrypt(ct73_nums, key_slice, variant)
                pt_str = nums_to_text(pt_nums)
                fsb = score_candidate_free(pt_str)
                if fsb.crib_score >= 6:
                    hit = {
                        "test": "running_key",
                        "source": name,
                        "offset": offset,
                        "variant": variant,
                        "crib_score": fsb.crib_score,
                        "plaintext": pt_str[:80],
                    }
                    mask_results["hits"].append(hit)
                    if fsb.crib_score > best_for_mask["score"]:
                        best_for_mask = {"score": fsb.crib_score, **hit}

    # ── Test 5: KA alphabet periodic keywords ──
    print(f"  [5] KA-alphabet periodic keywords...")
    for kw in KEYWORDS:
        kw_ka_nums = [KRYPTOS_ALPHABET.index(c) for c in kw.upper() if c in KRYPTOS_ALPHABET]
        ct73_ka_nums = [KRYPTOS_ALPHABET.index(c) for c in ct73 if c in KRYPTOS_ALPHABET]
        if not kw_ka_nums or len(ct73_ka_nums) != n73:
            continue
        for variant in VARIANTS:
            pt_ka_nums = decrypt(ct73_ka_nums, kw_ka_nums, variant)
            pt_str = "".join(KRYPTOS_ALPHABET[n % 26] for n in pt_ka_nums)
            fsb = score_candidate_free(pt_str)
            if fsb.crib_score >= 6:
                hit = {
                    "test": "ka_periodic",
                    "keyword": kw,
                    "variant": variant,
                    "crib_score": fsb.crib_score,
                    "plaintext": pt_str[:80],
                }
                mask_results["hits"].append(hit)
                if fsb.crib_score > best_for_mask["score"]:
                    best_for_mask = {"score": fsb.crib_score, **hit}

    # ── Report ──
    n_hits = len(mask_results["hits"])
    print(f"\n  Results for {mask_id}:")
    print(f"    Total hits (score >= 6): {n_hits}")
    print(f"    Best score: {best_for_mask['score']}")
    if best_for_mask["score"] > 0:
        print(f"    Best: {best_for_mask}")

    all_results[mask_id] = mask_results
    if best_for_mask["score"] > global_best["score"]:
        global_best = {"mask": mask_id, **best_for_mask}


# ══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════
print(f"\n{'=' * 70}")
print("GLOBAL SUMMARY")
print("=" * 70)
for mask_id, mr in all_results.items():
    n_hits = len(mr["hits"])
    best = max((h["crib_score"] for h in mr["hits"]), default=0)
    print(f"  {mask_id}: {n_hits} hits >= 6, best score: {best}")

print(f"\n  Global best: {global_best}")

verdict = "SIGNAL" if global_best["score"] >= 18 else (
    "INTERESTING" if global_best["score"] >= 10 else "NOISE")
print(f"  VERDICT: {verdict}")

# ── Save artifact ──
os.makedirs(os.path.join(_ROOT, "results"), exist_ok=True)
artifact = {
    "experiment": "E-TOP3-MASK-CIPHER-ATTACK",
    "description": "Cipher attacks on top 3 CT73 candidates from width-21 mask resolution",
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    "masks_tested": [m["id"] for m in TOP_MASKS],
    "keywords_tested": KEYWORDS,
    "variants_tested": VARIANTS,
    "global_best": global_best,
    "verdict": verdict,
    "per_mask": all_results,
}

outpath = os.path.join(_ROOT, "results", "top3_mask_cipher_attack.json")
with open(outpath, "w") as f:
    json.dump(artifact, f, indent=2, default=str)
print(f"\n  Artifact saved: {outpath}")
