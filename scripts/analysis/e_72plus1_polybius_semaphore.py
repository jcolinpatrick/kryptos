#!/usr/bin/env python3
"""
Cipher: polybius_fractionation
Family: analysis
Status: active
Keyspace: 3 masks x 73 delimiter positions x 6 grid configs x 30+ keywords x 3 variants
Last run:
Best score:
"""
"""
E-72PLUS1-POLYBIUS-SEMAPHORE: Retest 72+1 delimiter with Polybius fractionation

Previous 72+1 test used wrong null mask and only tested width-6 columnar.
This script tests:
  1. Correct null masks (top 3 from width-21 optimization)
  2. Polybius fractionation: 72 chars = 36 coordinate pairs on keyword grids
  3. SEMAPHORE and other keywords as grid keywords and periodic keys
  4. Multiple grid sizes: 5x5 (I/J merge), 6x6, 6x5, 5x6
  5. Standard periodic Beaufort/Vigenere with SEMAPHORE as key
  6. CT80 (17-null) and CT97 direct tests with SEMAPHORE

Output: results/72plus1_polybius_semaphore.json
Repro: PYTHONPATH=src python3 -u scripts/analysis/e_72plus1_polybius_semaphore.py
"""

import json
import sys
import os
import time
from collections import Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, CONSENSUS_NULL_POSITIONS,
    CRIB_POSITIONS, CRIB_DICT, KRYPTOS_ALPHABET
)
from kryptos.kernel.scoring.aggregate import score_candidate_free

# ── Top 3 masks from Phase 5 ──
TOP_MASKS = [
    [18, 19, 46, 47, 56, 62, 93],
    [18, 19, 46, 48, 56, 62, 93],
    [18, 19, 47, 48, 56, 62, 93],
]

# ── Keywords ──
KEYWORDS = [
    "SEMAPHORE", "KRYPTOS", "TELEGRAPH", "CHAPPE", "CIPHER",
    "DEFECTOR", "PALIMPSEST", "ABSCISSA", "SHADOW", "BERLIN",
    "SANBORN", "SCHEIDT", "SEVEN", "MORSE", "SIGNAL",
    "HELIOGRAPH", "POLYBIUS", "OPTICAL", "TOWER", "CHART",
    "BAUDOT", "MARCONI", "TELEGRAPHY", "CLOCKWORK", "ENIGMA",
    "ANTIPODES", "INVISIBLE", "MATRIX", "LUCID", "SECRET",
]

VARIANTS = ["beaufort", "vigenere", "var_beaufort"]


def keyword_alphabet_5x5(keyword, merge_ij=True):
    """Build a 5x5 Polybius alphabet from a keyword. I/J merged."""
    seen = set()
    alpha = []
    for c in keyword.upper():
        if merge_ij and c == 'J':
            c = 'I'
        if c in ALPH and c not in seen:
            alpha.append(c)
            seen.add(c)
    for c in ALPH:
        if merge_ij and c == 'J':
            continue
        if c not in seen:
            alpha.append(c)
            seen.add(c)
    return alpha[:25]


def keyword_alphabet_6x6(keyword):
    """Build a 6x6 grid alphabet (A-Z + 0-9)."""
    seen = set()
    alpha = []
    chars = list(ALPH) + list("0123456789")
    for c in keyword.upper():
        if c in chars and c not in seen:
            alpha.append(c)
            seen.add(c)
    for c in chars:
        if c not in seen:
            alpha.append(c)
            seen.add(c)
    return alpha[:36]


def keyword_mixed_alphabet_26(keyword):
    """Build a 26-letter keyword-mixed alphabet."""
    seen = set()
    alpha = []
    for c in keyword.upper():
        if c in ALPH and c not in seen:
            alpha.append(c)
            seen.add(c)
    for c in ALPH:
        if c not in seen:
            alpha.append(c)
            seen.add(c)
    return alpha


def polybius_decrypt_5x5(ct_pairs, grid):
    """Decrypt pairs of characters as Polybius 5x5 coordinates.
    Each pair (a, b) where a=row index, b=col index into the grid.
    Values are taken mod 5."""
    pt = []
    for r_char, c_char in ct_pairs:
        r = ALPH_IDX.get(r_char, -1) % 5
        c = ALPH_IDX.get(c_char, -1) % 5
        idx = r * 5 + c
        if 0 <= idx < len(grid):
            pt.append(grid[idx])
        else:
            pt.append('?')
    return ''.join(pt)


def polybius_decrypt_bifid_5x5(ct72, grid):
    """Bifid-style decryption on 5x5 grid.
    Convert each CT char to (row, col), split into row-stream and col-stream,
    recombine pairs to get plaintext."""
    # Build lookup
    char_to_pos = {}
    for i, c in enumerate(grid):
        char_to_pos[c] = (i // 5, i % 5)

    n = len(ct72)
    rows = []
    cols = []
    for c in ct72:
        if c == 'J':
            c = 'I'
        if c in char_to_pos:
            r, co = char_to_pos[c]
            rows.append(r)
            cols.append(co)
        else:
            rows.append(0)
            cols.append(0)

    # Bifid: interleave rows then cols, take pairs
    combined = rows + cols
    pt = []
    for i in range(0, len(combined) - 1, 2):
        r = combined[i]
        c = combined[i + 1]
        idx = r * 5 + c
        if 0 <= idx < len(grid):
            pt.append(grid[idx])
        else:
            pt.append('?')
    return ''.join(pt)


def decrypt_periodic(ct_nums, key_nums, variant):
    """Decrypt with periodic key."""
    pt = []
    klen = len(key_nums)
    for i, c in enumerate(ct_nums):
        k = key_nums[i % klen]
        if variant == "beaufort":
            p = (k - c) % MOD
        elif variant == "vigenere":
            p = (c - k) % MOD
        elif variant == "var_beaufort":
            p = (c + k) % MOD
        pt.append(p)
    return pt


def nums_to_text(nums):
    return ''.join(chr(n + ord('A')) for n in nums)


def text_to_nums(text):
    return [ALPH_IDX[c] for c in text.upper() if c in ALPH_IDX]


def extract_ct(extra_nulls):
    null_mask = CONSENSUS_NULL_POSITIONS | set(extra_nulls)
    return ''.join(CT[i] for i in range(CT_LEN) if i not in null_mask)


print("=" * 70)
print("E-72PLUS1-POLYBIUS-SEMAPHORE")
print("=" * 70)

t0 = time.time()
all_hits = []
best_overall = {"score": 0}

# ══════════════════════════════════════════════════════════════════════════
# PHASE 1: SEMAPHORE as periodic key on CT73, CT80, CT97
# ══════════════════════════════════════════════════════════════════════════
print("\n[Phase 1] SEMAPHORE as periodic key")
print("-" * 50)

sem_nums = text_to_nums("SEMAPHORE")
sem_ka = [KRYPTOS_ALPHABET.index(c) for c in "SEMAPHORE"]

test_texts = {
    "CT97": CT,
    "CT80": ''.join(CT[i] for i in range(CT_LEN) if i not in CONSENSUS_NULL_POSITIONS),
}
for mi, extra in enumerate(TOP_MASKS):
    test_texts[f"CT73_mask{mi}"] = extract_ct(extra)

for name, ct_text in test_texts.items():
    ct_nums = text_to_nums(ct_text)

    for variant in VARIANTS:
        # AZ alphabet
        pt_nums = decrypt_periodic(ct_nums, sem_nums, variant)
        pt_str = nums_to_text(pt_nums)
        fsb = score_candidate_free(pt_str)
        if fsb.crib_score >= 4:
            hit = {"phase": 1, "text": name, "key": "SEMAPHORE_AZ", "variant": variant,
                   "score": fsb.crib_score, "pt": pt_str[:60]}
            all_hits.append(hit)
            if fsb.crib_score > best_overall["score"]:
                best_overall = hit

        # KA alphabet
        ct_ka = [KRYPTOS_ALPHABET.index(c) for c in ct_text if c in KRYPTOS_ALPHABET]
        if len(ct_ka) == len(ct_text):
            pt_ka = decrypt_periodic(ct_ka, sem_ka, variant)
            pt_str_ka = ''.join(KRYPTOS_ALPHABET[n % 26] for n in pt_ka)
            fsb_ka = score_candidate_free(pt_str_ka)
            if fsb_ka.crib_score >= 4:
                hit = {"phase": 1, "text": name, "key": "SEMAPHORE_KA", "variant": variant,
                       "score": fsb_ka.crib_score, "pt": pt_str_ka[:60]}
                all_hits.append(hit)
                if fsb_ka.crib_score > best_overall["score"]:
                    best_overall = hit

    print(f"  {name}: tested 6 SEMAPHORE configs")

# Also test other keywords on CT73
print("\n  Testing all keywords on CT73_mask0...")
ct73_0 = extract_ct(TOP_MASKS[0])
ct73_0_nums = text_to_nums(ct73_0)
for kw in KEYWORDS:
    kw_nums = text_to_nums(kw)
    for variant in VARIANTS:
        pt_nums = decrypt_periodic(ct73_0_nums, kw_nums, variant)
        pt_str = nums_to_text(pt_nums)
        fsb = score_candidate_free(pt_str)
        if fsb.crib_score >= 4:
            hit = {"phase": 1, "text": "CT73_mask0", "key": kw, "variant": variant,
                   "score": fsb.crib_score, "pt": pt_str[:60]}
            all_hits.append(hit)
            if fsb.crib_score > best_overall["score"]:
                best_overall = hit

print(f"  Phase 1 hits (score >= 4): {len(all_hits)}")


# ══════════════════════════════════════════════════════════════════════════
# PHASE 2: 72+1 DELIMITER — Remove each position from CT73, test Polybius
# ══════════════════════════════════════════════════════════════════════════
print(f"\n[Phase 2] 72+1 Delimiter + Polybius Fractionation")
print("-" * 50)

phase2_hits = []

for mi, extra in enumerate(TOP_MASKS[:1]):  # Test mask 0 first (most thorough)
    ct73 = extract_ct(extra)
    print(f"\n  Mask {mi}: {ct73[:40]}...")

    for delim_pos in range(len(ct73)):
        # Remove delimiter at position delim_pos
        ct72 = ct73[:delim_pos] + ct73[delim_pos + 1:]
        assert len(ct72) == 72

        # 2a: Polybius 5x5 — treat consecutive pairs as (row, col)
        pairs = [(ct72[i], ct72[i + 1]) for i in range(0, 72, 2)]  # 36 pairs

        for kw in KEYWORDS:
            grid = keyword_alphabet_5x5(kw)

            # Direct pair decoding
            pt = polybius_decrypt_5x5(pairs, grid)
            fsb = score_candidate_free(pt)
            if fsb.crib_score >= 4:
                hit = {"phase": 2, "method": "polybius_5x5_pairs", "mask": mi,
                       "delim_pos": delim_pos, "delim_char": ct73[delim_pos],
                       "keyword": kw, "score": fsb.crib_score, "pt": pt[:60]}
                phase2_hits.append(hit)
                if fsb.crib_score > best_overall["score"]:
                    best_overall = hit

            # Reverse pairs (col, row)
            pairs_rev = [(ct72[i + 1], ct72[i]) for i in range(0, 72, 2)]
            pt_rev = polybius_decrypt_5x5(pairs_rev, grid)
            fsb_rev = score_candidate_free(pt_rev)
            if fsb_rev.crib_score >= 4:
                hit = {"phase": 2, "method": "polybius_5x5_rev", "mask": mi,
                       "delim_pos": delim_pos, "delim_char": ct73[delim_pos],
                       "keyword": kw, "score": fsb_rev.crib_score, "pt": pt_rev[:60]}
                phase2_hits.append(hit)
                if fsb_rev.crib_score > best_overall["score"]:
                    best_overall = hit

            # Bifid-style (fractionation then recombination)
            pt_bifid = polybius_decrypt_bifid_5x5(ct72, grid)
            fsb_bifid = score_candidate_free(pt_bifid)
            if fsb_bifid.crib_score >= 4:
                hit = {"phase": 2, "method": "bifid_5x5", "mask": mi,
                       "delim_pos": delim_pos, "delim_char": ct73[delim_pos],
                       "keyword": kw, "score": fsb_bifid.crib_score, "pt": pt_bifid[:60]}
                phase2_hits.append(hit)
                if fsb_bifid.crib_score > best_overall["score"]:
                    best_overall = hit

    print(f"  Mask {mi}: {73 * len(KEYWORDS) * 3} Polybius configs tested, "
          f"{len(phase2_hits)} hits >= 4")

all_hits.extend(phase2_hits)


# ══════════════════════════════════════════════════════════════════════════
# PHASE 3: 72+1 DELIMITER — Periodic cipher on CT72
# ══════════════════════════════════════════════════════════════════════════
print(f"\n[Phase 3] 72+1 Delimiter + Periodic Cipher")
print("-" * 50)

phase3_hits = []

ct73_0 = extract_ct(TOP_MASKS[0])

# Test a subset of delimiter positions (all 73) with SEMAPHORE + top keywords
key_subset = ["SEMAPHORE", "KRYPTOS", "DEFECTOR", "ABSCISSA", "PALIMPSEST",
              "CHAPPE", "TELEGRAPH", "POLYBIUS", "SEVEN", "CHART"]

for delim_pos in range(73):
    ct72 = ct73_0[:delim_pos] + ct73_0[delim_pos + 1:]
    ct72_nums = text_to_nums(ct72)

    for kw in key_subset:
        kw_nums = text_to_nums(kw)
        for variant in VARIANTS:
            pt_nums = decrypt_periodic(ct72_nums, kw_nums, variant)
            pt_str = nums_to_text(pt_nums)
            fsb = score_candidate_free(pt_str)
            if fsb.crib_score >= 4:
                hit = {"phase": 3, "method": "periodic_ct72", "delim_pos": delim_pos,
                       "delim_char": ct73_0[delim_pos], "keyword": kw, "variant": variant,
                       "score": fsb.crib_score, "pt": pt_str[:60]}
                phase3_hits.append(hit)
                if fsb.crib_score > best_overall["score"]:
                    best_overall = hit

print(f"  {73 * len(key_subset) * 3} configs tested, {len(phase3_hits)} hits >= 4")
all_hits.extend(phase3_hits)


# ══════════════════════════════════════════════════════════════════════════
# PHASE 4: Columnar transposition on CT72 then periodic/Polybius
# ══════════════════════════════════════════════════════════════════════════
print(f"\n[Phase 4] CT72 Columnar Transposition (widths 6,8,9,12) + Cipher")
print("-" * 50)

phase4_hits = []

def columnar_read(text, width):
    """Read text written in rows, read by columns."""
    n = len(text)
    nrows = (n + width - 1) // width
    result = []
    for col in range(width):
        for row in range(nrows):
            idx = row * width + col
            if idx < n:
                result.append(text[idx])
    return ''.join(result)

ct73_0 = extract_ct(TOP_MASKS[0])

for delim_pos in [0, 36, 72] + list(range(73)):  # Test all positions
    ct72 = ct73_0[:delim_pos] + ct73_0[delim_pos + 1:]
    if len(ct72) != 72:
        continue

    for width in [6, 8, 9, 12, 18, 24, 36]:
        ct72_col = columnar_read(ct72, width)
        ct72_col_nums = text_to_nums(ct72_col)

        for kw in ["SEMAPHORE", "KRYPTOS", "DEFECTOR", "SEVEN"]:
            kw_nums = text_to_nums(kw)
            for variant in VARIANTS:
                pt_nums = decrypt_periodic(ct72_col_nums, kw_nums, variant)
                pt_str = nums_to_text(pt_nums)
                fsb = score_candidate_free(pt_str)
                if fsb.crib_score >= 4:
                    hit = {"phase": 4, "method": f"col{width}_periodic",
                           "delim_pos": delim_pos, "keyword": kw, "variant": variant,
                           "score": fsb.crib_score, "pt": pt_str[:60]}
                    phase4_hits.append(hit)
                    if fsb.crib_score > best_overall["score"]:
                        best_overall = hit

print(f"  {len(phase4_hits)} hits >= 4")
all_hits.extend(phase4_hits)


# ══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════
elapsed = time.time() - t0

print(f"\n{'=' * 70}")
print("SUMMARY")
print("=" * 70)
print(f"  Total hits (score >= 4): {len(all_hits)}")
print(f"  Best overall: {best_overall}")

# Group by score
score_dist = Counter(h["score"] for h in all_hits)
for s in sorted(score_dist.keys(), reverse=True):
    print(f"    score {s}: {score_dist[s]} hits")

if all_hits:
    print(f"\n  Top 10 hits:")
    all_hits.sort(key=lambda h: -h["score"])
    for i, h in enumerate(all_hits[:10]):
        print(f"    #{i+1}: score={h['score']} {h.get('method', h.get('key', ''))} "
              f"{h.get('keyword', '')} {h.get('variant', '')} "
              f"pt={h.get('pt', '')[:50]}")

verdict = "SIGNAL" if best_overall["score"] >= 18 else (
    "INTERESTING" if best_overall["score"] >= 10 else "NOISE")
print(f"\n  VERDICT: {verdict}")
print(f"  Elapsed: {elapsed:.1f}s")

# ── Save artifact ──
os.makedirs(os.path.join(_ROOT, "results"), exist_ok=True)
artifact = {
    "experiment": "E-72PLUS1-POLYBIUS-SEMAPHORE",
    "description": "72+1 delimiter + Polybius fractionation + SEMAPHORE key",
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    "keywords_tested": KEYWORDS,
    "masks_tested": TOP_MASKS,
    "total_hits": len(all_hits),
    "best_overall": best_overall,
    "verdict": verdict,
    "top_20": all_hits[:20],
    "elapsed_seconds": round(elapsed, 1),
}

outpath = os.path.join(_ROOT, "results", "72plus1_polybius_semaphore.json")
with open(outpath, "w") as f:
    json.dump(artifact, f, indent=2, default=str)
print(f"\n  Artifact saved: {outpath}")
