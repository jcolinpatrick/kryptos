#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""Deep dive into H5 (face-card markers) and H6 grid-9 result.

Follows up on findings from e_card_cipher_tests.py:
1. IC improvement when removing KQJA (0.0361 -> 0.0416)
2. H6 KA grid-9 row keystream scored 5/24

Usage:
    PYTHONPATH=src python3 -u scripts/e_card_cipher_h5_deep.py
"""
from __future__ import annotations

import json
import os
from collections import Counter

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_DICT, N_CRIBS,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.scoring.ic import ic

OUTDIR = "results/card_cipher_tests"
os.makedirs(OUTDIR, exist_ok=True)

FACE_CARD_LETTERS = set("KQJA")


def decrypt_vigenere(ct, ks):
    return "".join(ALPH[(ALPH_IDX[c] - ks[i]) % MOD] for i, c in enumerate(ct))


def decrypt_beaufort(ct, ks):
    return "".join(ALPH[(ks[i] - ALPH_IDX[c]) % MOD] for i, c in enumerate(ct))


print("=" * 70)
print("DEEP DIVE: H5 Face-Card Analysis + H6 Grid-9 Follow-up")
print("=" * 70)

# ── 1. Statistical significance of IC improvement ──
print("\n1. IC IMPROVEMENT SIGNIFICANCE")
print("-" * 40)

# When we remove KQJA, IC goes from 0.0361 to 0.0416
# Is this statistically significant for a 97->78 char reduction?
# Let's bootstrap: randomly remove 19 characters many times and see IC distribution

import random
random.seed(42)

n_trials = 10000
ic_samples_remove19 = []
for _ in range(n_trials):
    positions = random.sample(range(CT_LEN), CT_LEN - 19)
    positions.sort()
    subset = "".join(CT[p] for p in positions)
    ic_samples_remove19.append(ic(subset))

mean_ic = sum(ic_samples_remove19) / len(ic_samples_remove19)
ic_samples_remove19.sort()
p95 = ic_samples_remove19[int(0.95 * n_trials)]
p99 = ic_samples_remove19[int(0.99 * n_trials)]
p5 = ic_samples_remove19[int(0.05 * n_trials)]

ic_kqja = 0.0416  # measured

above_count = sum(1 for x in ic_samples_remove19 if x >= ic_kqja)
p_value = above_count / n_trials

print(f"  Full CT IC: {ic(CT):.4f}")
print(f"  After removing KQJA: {ic_kqja:.4f}")
print(f"  Bootstrap (remove random 19 chars, {n_trials} trials):")
print(f"    Mean IC: {mean_ic:.4f}")
print(f"    5th percentile: {p5:.4f}")
print(f"    95th percentile: {p95:.4f}")
print(f"    99th percentile: {p99:.4f}")
print(f"  P-value (IC >= {ic_kqja:.4f}): {p_value:.4f}")
print(f"  Conclusion: {'SIGNIFICANT (p<0.05)' if p_value < 0.05 else 'NOT significant'}")

# ── 2. Are face-card letters actually overrepresented? ──
print("\n2. FACE-CARD LETTER FREQUENCY")
print("-" * 40)

# K appears 8 times in 97 chars. Expected: 97/26 = 3.73
# Binomial test for K specifically
from math import comb
k_count = CT.count("K")
n = CT_LEN
p_letter = 1/26

# P(X >= k_count) under binomial(97, 1/26)
p_k_high = sum(comb(n, k) * (p_letter**k) * ((1-p_letter)**(n-k)) for k in range(k_count, n+1))
print(f"  K count: {k_count}/97, expected: {n/26:.1f}")
print(f"  P(K >= {k_count}): {p_k_high:.4f}")

# Combined KQJA
total_face = sum(CT.count(c) for c in "KQJA")
p_4letters = 4/26
p_combined = sum(comb(n, k) * (p_4letters**k) * ((1-p_4letters)**(n-k)) for k in range(total_face, n+1))
print(f"  KQJA combined: {total_face}/97, expected: {n*4/26:.1f}")
print(f"  P(KQJA >= {total_face}): {p_combined:.4f}")

# After Bonferroni correction (testing 26 letters for being overrepresented):
print(f"  After Bonferroni correction for K: {min(1, p_k_high * 26):.4f}")

# ── 3. Crib disruption analysis ──
print("\n3. CRIB DISRUPTION FROM FACE-CARD REMOVAL")
print("-" * 40)

print("  Crib positions containing KQJA letters in the CIPHERTEXT:")
for pos in sorted(CRIB_DICT.keys()):
    ct_char = CT[pos]
    pt_char = CRIB_DICT[pos]
    is_face = ct_char in FACE_CARD_LETTERS
    if is_face:
        print(f"    CT[{pos}]={ct_char} -> PT[{pos}]={pt_char}  ** FACE CARD **")

print("\n  Crib positions containing KQJA letters in the PLAINTEXT:")
for pos in sorted(CRIB_DICT.keys()):
    pt_char = CRIB_DICT[pos]
    is_face = pt_char in FACE_CARD_LETTERS
    if is_face:
        print(f"    PT[{pos}]={pt_char} (CT[{pos}]={CT[pos]})  ** FACE CARD **")

# Count how many known PT letters are face cards
pt_face = sum(1 for pos, ch in CRIB_DICT.items() if ch in FACE_CARD_LETTERS)
ct_face = sum(1 for pos in CRIB_DICT if CT[pos] in FACE_CARD_LETTERS)
print(f"\n  Face-card letters in known PT: {pt_face}/{N_CRIBS}")
print(f"  Face-card letters in CT at crib positions: {ct_face}/{N_CRIBS}")

# ── 4. H6 Grid-9 follow-up ──
print("\n4. H6 KA GRID-9 FOLLOW-UP")
print("-" * 40)

ka_idx = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}

# KA grid-9: row index as keystream
coords_9 = [(ka_idx[c] // 9, ka_idx[c] % 9) for c in CT]
ks_rows_9 = [r % MOD for r in [row for row, col in coords_9]]

pt_vig = decrypt_vigenere(CT, ks_rows_9)
pt_beau = decrypt_beaufort(CT, ks_rows_9)

sc_vig = score_candidate(pt_vig)
sc_beau = score_candidate(pt_beau)

print(f"  Grid-9 Vig: {sc_vig.summary}")
print(f"  PT: {pt_vig}")
print(f"  Grid-9 Beau: {sc_beau.summary}")
print(f"  PT: {pt_beau}")

# Is 5/24 significant? Expected random crib score:
# Each crib position has 1/26 chance of matching = ~0.92 expected
# P(X >= 5) for binomial(24, 1/26)
p_5plus = sum(comb(24, k) * (1/26)**k * (25/26)**(24-k) for k in range(5, 25))
print(f"\n  P(crib >= 5/24 by chance): {p_5plus:.6f}")
print(f"  Expected: ~0.92/24")
print(f"  This is {'notable but not definitive' if p_5plus < 0.01 else 'within random range'}")

# Test other grid sizes systematically
print("\n  Systematic grid-size scan:")
best_grid = {"score": 0}
for gw in range(2, 27):
    coords = [(ka_idx[c] // gw, ka_idx[c] % gw) for c in CT]

    # Row as keystream
    ks_row = [r % MOD for r in [row for row, col in coords]]
    pt = decrypt_vigenere(CT, ks_row)
    sc = score_candidate(pt)
    if sc.crib_score >= 3:
        print(f"    Grid-{gw} row->vig: crib={sc.crib_score}/24 IC={sc.ic_value:.4f}")
    if sc.crib_score > best_grid["score"]:
        best_grid = {"score": sc.crib_score, "gw": gw, "method": "row_vig"}

    # Col as keystream
    ks_col = [c % MOD for r, c in coords]
    pt = decrypt_vigenere(CT, ks_col)
    sc = score_candidate(pt)
    if sc.crib_score >= 3:
        print(f"    Grid-{gw} col->vig: crib={sc.crib_score}/24 IC={sc.ic_value:.4f}")
    if sc.crib_score > best_grid["score"]:
        best_grid = {"score": sc.crib_score, "gw": gw, "method": "col_vig"}

    # Row+col combined
    ks_rc = [(r + c) % MOD for r, c in coords]
    pt = decrypt_vigenere(CT, ks_rc)
    sc = score_candidate(pt)
    if sc.crib_score >= 3:
        print(f"    Grid-{gw} r+c->vig: crib={sc.crib_score}/24 IC={sc.ic_value:.4f}")
    if sc.crib_score > best_grid["score"]:
        best_grid = {"score": sc.crib_score, "gw": gw, "method": "r+c_vig"}

print(f"\n  Best grid result: {best_grid}")

# ── 5. Alternative null hypothesis: specific letters are nulls ──
print("\n5. EXHAUSTIVE NULL-LETTER SCAN")
print("-" * 40)
print("  Testing all possible 1-4 letter null sets for IC improvement...")

# For each subset of 1-4 letters, remove those letters and check IC
from itertools import combinations

best_nulls = []
for n_nulls in range(1, 5):
    for null_set in combinations(ALPH, n_nulls):
        null_set_s = set(null_set)
        remaining = "".join(c for c in CT if c not in null_set_s)
        if len(remaining) < 20:
            continue
        ic_val = ic(remaining)
        if ic_val > 0.050:  # Well above random
            best_nulls.append((null_set, len(remaining), ic_val))

best_nulls.sort(key=lambda x: x[2], reverse=True)
print(f"  Null sets producing IC > 0.050:")
for null_set, rem_len, ic_val in best_nulls[:20]:
    print(f"    Remove {''.join(null_set)}: {rem_len} chars, IC={ic_val:.4f}")

if not best_nulls:
    print(f"  No null set produced IC > 0.050")

# Check KQJA ranking among all 4-letter null sets
all_4_null_ics = []
for null_set in combinations(ALPH, 4):
    null_set_s = set(null_set)
    remaining = "".join(c for c in CT if c not in null_set_s)
    if len(remaining) < 20:
        continue
    ic_val = ic(remaining)
    all_4_null_ics.append(("".join(null_set), ic_val))

all_4_null_ics.sort(key=lambda x: x[1], reverse=True)
kqja_rank = next(i for i, (s, _) in enumerate(all_4_null_ics) if set(s) == set("KQJA"))
total_4sets = len(all_4_null_ics)
print(f"\n  KQJA IC rank among all 4-letter null sets: {kqja_rank+1}/{total_4sets}")
print(f"  Top 10 4-letter null sets by IC:")
for letters, ic_val in all_4_null_ics[:10]:
    is_kqja = " ** KQJA **" if set(letters) == set("KQJA") else ""
    print(f"    Remove {letters}: IC={ic_val:.4f}{is_kqja}")

# ── Summary ──
print("\n" + "=" * 70)
print("DEEP DIVE SUMMARY")
print("=" * 70)
print(f"  1. IC improvement from KQJA removal: p={p_value:.4f} "
      f"({'significant' if p_value < 0.05 else 'not significant'})")
print(f"  2. K overrepresentation: p={p_k_high:.4f} (Bonferroni: {min(1,p_k_high*26):.4f})")
print(f"  3. KQJA combined overrepresentation: p={p_combined:.4f}")
print(f"  4. Face cards in crib positions: {ct_face} CT, {pt_face} PT — disrupts nulls hypothesis")
print(f"  5. H6 grid-9 score of 5/24: p={p_5plus:.6f} — "
      f"{'borderline interesting' if p_5plus < 0.01 else 'consistent with noise'}")
print(f"  6. KQJA ranked #{kqja_rank+1}/{total_4sets} among 4-letter null sets by IC")

# Save
results = {
    "ic_improvement_p_value": p_value,
    "k_overrep_p_value": p_k_high,
    "kqja_overrep_p_value": p_combined,
    "crib_face_ct": ct_face,
    "crib_face_pt": pt_face,
    "grid9_significance": p_5plus,
    "kqja_ic_rank": kqja_rank + 1,
    "kqja_ic_rank_total": total_4sets,
    "best_grid": best_grid,
    "top_null_sets": [{"letters": l, "ic": round(v, 4)} for l, v in all_4_null_ics[:10]],
}

with open(os.path.join(OUTDIR, "h5_deep_dive.json"), "w") as f:
    json.dump(results, f, indent=2, default=str)

print(f"\nResults saved to {os.path.join(OUTDIR, 'h5_deep_dive.json')}")
