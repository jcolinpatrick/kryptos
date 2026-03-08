#!/usr/bin/env python3
"""
# Cipher:   W-Removal + Substitution
# Family:   grille
# Status:   active
# Keyspace: ~2,400 (15 keywords x 3 variants x 2 alphabets x 26 shifts) + grid reads
# Last run: 2026-03-07
# Best score: TBD

Hypothesis: The 5 W's in K4 at positions [20, 36, 48, 58, 74] are INSERTED
MARKERS. W[20] is immediately before EASTNORTHEAST, W[74] is immediately
after BERLINCLOCK. Remove them to get a 92-char text, then try Vigenere/
Beaufort/VarBeaufort with various keywords and alphabets.

Also tries columnar transposition reads of the 92-char text (92=4x23, 2x46)
and Caesar pre-shifts before keyword decryption.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD
from kryptos.kernel.alphabet import AZ, KA, Alphabet
from kryptos.kernel.transforms.vigenere import (
    decrypt_text, CipherVariant,
)
from kryptos.kernel.scoring.aggregate import score_candidate_free
from kryptos.kernel.scoring.ic import ic

# ── Step 1: Identify and remove W positions ──────────────────────────────

print("=" * 80)
print("W-REMOVAL HYPOTHESIS EXPERIMENT")
print("=" * 80)

# Verify W positions
w_positions = [i for i, c in enumerate(CT) if c == 'W']
print(f"\nOriginal CT ({CT_LEN} chars):")
print(CT)
print(f"\nW positions (0-indexed): {w_positions}")
print(f"Number of W's: {len(w_positions)}")

# Show context around each W
for wp in w_positions:
    start = max(0, wp - 3)
    end = min(CT_LEN, wp + 4)
    ctx = CT[start:end]
    marker = ' ' * (wp - start) + '^'
    print(f"  W[{wp}]: ...{ctx}...")
    print(f"         {' ' * 3}{marker}")

# Remove all W's
ct_no_w = CT.replace('W', '')
ct_no_w_len = len(ct_no_w)
print(f"\nW-removed text ({ct_no_w_len} chars):")
print(ct_no_w)

# ── Step 2: Recalculate crib positions ───────────────────────────────────

print("\n" + "=" * 80)
print("CRIB POSITION RECALCULATION")
print("=" * 80)

# For each original position, calculate the new position after W removal
def original_to_new_pos(orig_pos, w_positions):
    """Map original position to new position after removing W's."""
    # Count how many W's are before this position
    ws_before = sum(1 for wp in w_positions if wp < orig_pos)
    return orig_pos - ws_before

# Original crib positions
ene_orig_start = 21
ene_orig_end = 33  # inclusive
bc_orig_start = 63
bc_orig_end = 73   # inclusive

# New positions
ene_new_start = original_to_new_pos(ene_orig_start, w_positions)
ene_new_end = original_to_new_pos(ene_orig_end, w_positions)
bc_new_start = original_to_new_pos(bc_orig_start, w_positions)
bc_new_end = original_to_new_pos(bc_orig_end, w_positions)

print(f"\nENE crib: original [{ene_orig_start}-{ene_orig_end}] -> new [{ene_new_start}-{ene_new_end}]")
print(f"  W's before pos 21: {[wp for wp in w_positions if wp < 21]}")
print(f"  W's between ENE positions: {[wp for wp in w_positions if 21 <= wp <= 33]}")

print(f"\nBC  crib: original [{bc_orig_start}-{bc_orig_end}] -> new [{bc_new_start}-{bc_new_end}]")
print(f"  W's before pos 63: {[wp for wp in w_positions if wp < 63]}")
print(f"  W's between BC positions: {[wp for wp in w_positions if 63 <= wp <= 73]}")

# DETAILED position-by-position check
print("\nDetailed position mapping:")
print("  Original CT with W markers:")
for i, c in enumerate(CT):
    if c == 'W':
        print(f"    pos {i}: W (REMOVED)")

# Verify by checking what's at the new crib positions
# After removing W's, build a mapping
new_pos_map = {}
new_idx = 0
for orig_idx in range(CT_LEN):
    if CT[orig_idx] != 'W':
        new_pos_map[orig_idx] = new_idx
        new_idx += 1

print(f"\n  ENE original positions and new mapping:")
for i in range(13):
    orig = ene_orig_start + i
    new = new_pos_map.get(orig, "REMOVED")
    ch = CT[orig]
    print(f"    orig[{orig}] = {ch} -> new[{new}]")

print(f"\n  BC original positions and new mapping:")
for i in range(11):
    orig = bc_orig_start + i
    new = new_pos_map.get(orig, "REMOVED")
    ch = CT[orig]
    print(f"    orig[{orig}] = {ch} -> new[{new}]")

# ── Step 3: IC analysis ─────────────────────────────────────────────────

print("\n" + "=" * 80)
print("IC ANALYSIS")
print("=" * 80)

ic_orig = ic(CT)
ic_new = ic(ct_no_w)
print(f"IC of original CT (97 chars): {ic_orig:.6f}")
print(f"IC of W-removed text (92 chars): {ic_new:.6f}")
print(f"IC random expectation: {1/26:.6f}")
print(f"IC English: 0.0667")

# Letter frequency analysis
from collections import Counter
freq_orig = Counter(CT)
freq_new = Counter(ct_no_w)
print(f"\nLetter frequencies in original CT:")
for ch in sorted(freq_orig.keys()):
    print(f"  {ch}: {freq_orig[ch]}", end="")
print()
print(f"\nLetter frequencies after W removal:")
for ch in sorted(freq_new.keys()):
    print(f"  {ch}: {freq_new[ch]}", end="")
print()

# ── Step 4: Keyword decryption trials ────────────────────────────────────

print("\n" + "=" * 80)
print("KEYWORD DECRYPTION TRIALS (W-removed text)")
print("=" * 80)

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "PARALLAX",
    "COLOPHON", "SHADOW", "COMPASS", "POINT", "WEST", "FIVE",
    "NEEDLE", "BEARING", "LODESTONE", "MAGNETIC",
]

VARIANTS = [
    CipherVariant.VIGENERE,
    CipherVariant.BEAUFORT,
    CipherVariant.VAR_BEAUFORT,
]

ALPHABETS = [
    ("AZ", AZ),
    ("KA", KA),
]

results_above_noise = []

total_configs = 0
for kw in KEYWORDS:
    for variant in VARIANTS:
        for alph_name, alph in ALPHABETS:
            # Convert keyword to numeric key using this alphabet
            key_nums = alph.encode(kw)

            # Decrypt
            # For non-AZ alphabets, we need to convert CT through the alphabet
            if alph_name == "AZ":
                pt = decrypt_text(ct_no_w, key_nums, variant)
            else:
                # Convert CT to indices in this alphabet, decrypt, convert back
                ct_indices = alph.encode(ct_no_w)
                key_cycle = key_nums
                from kryptos.kernel.transforms.vigenere import DECRYPT_FN
                fn = DECRYPT_FN[variant]
                klen = len(key_cycle)
                pt_indices = [fn(ct_indices[i], key_cycle[i % klen]) for i in range(len(ct_indices))]
                pt = alph.decode(pt_indices)

            # Score with free crib scorer
            fsb = score_candidate_free(pt)
            total_configs += 1

            if fsb.crib_score > 0 or fsb.ic_value > 0.055:
                results_above_noise.append({
                    'keyword': kw,
                    'variant': variant.value,
                    'alphabet': alph_name,
                    'plaintext': pt,
                    'score': fsb.crib_score,
                    'ic': fsb.ic_value,
                    'summary': fsb.summary,
                })
                if fsb.crib_score > 0:
                    print(f"  HIT: {kw}/{variant.value}/{alph_name} -> score={fsb.crib_score} IC={fsb.ic_value:.4f}")
                    print(f"        PT: {pt[:50]}...")
                    print(f"        {fsb.summary}")

print(f"\nTested {total_configs} keyword/variant/alphabet combinations")
print(f"Results with crib hits or high IC: {len(results_above_noise)}")

# ── Step 5: Columnar transposition reads ─────────────────────────────────

print("\n" + "=" * 80)
print("COLUMNAR TRANSPOSITION READS (92 chars)")
print("=" * 80)

# 92 = 4 * 23 = 2 * 46
grid_dims = [(4, 23), (23, 4), (2, 46), (46, 2)]

columnar_texts = {}

for nrows, ncols in grid_dims:
    if nrows * ncols != ct_no_w_len:
        print(f"  SKIP {nrows}x{ncols} = {nrows*ncols} != {ct_no_w_len}")
        continue

    # Fill grid by rows, read by columns
    grid = []
    for r in range(nrows):
        row = ct_no_w[r * ncols:(r + 1) * ncols]
        grid.append(row)

    # Read by columns
    col_read = ""
    for c in range(ncols):
        for r in range(nrows):
            col_read += grid[r][c]

    columnar_texts[f"{nrows}x{ncols}_col"] = col_read
    print(f"\n  Grid {nrows}x{ncols}, read by columns:")
    print(f"    {col_read[:50]}...")

    # Also read by rows (this is just the original, skip)

    # Read by columns in reverse
    col_read_rev = ""
    for c in range(ncols - 1, -1, -1):
        for r in range(nrows):
            col_read_rev += grid[r][c]

    columnar_texts[f"{nrows}x{ncols}_col_rev"] = col_read_rev

    # Spiral read (for rectangular grids)
    # Skip for very elongated grids

    # Try decrypting each columnar read
    for read_name, read_text in [(f"{nrows}x{ncols}_col", col_read),
                                   (f"{nrows}x{ncols}_col_rev", col_read_rev)]:
        for kw in KEYWORDS:
            for variant in VARIANTS:
                for alph_name, alph in ALPHABETS:
                    key_nums = alph.encode(kw)

                    if alph_name == "AZ":
                        pt = decrypt_text(read_text, key_nums, variant)
                    else:
                        ct_indices = alph.encode(read_text)
                        key_cycle = key_nums
                        fn = DECRYPT_FN[variant]
                        klen = len(key_cycle)
                        pt_indices = [fn(ct_indices[i], key_cycle[i % klen]) for i in range(len(ct_indices))]
                        pt = alph.decode(pt_indices)

                    fsb = score_candidate_free(pt)
                    total_configs += 1

                    if fsb.crib_score > 0:
                        print(f"  HIT: {read_name}/{kw}/{variant.value}/{alph_name}")
                        print(f"        score={fsb.crib_score} IC={fsb.ic_value:.4f}")
                        print(f"        PT: {pt[:50]}...")

print(f"\nTotal configs tested so far: {total_configs}")

# ── Step 6: Caesar pre-shift + keyword decryption ────────────────────────

print("\n" + "=" * 80)
print("CAESAR PRE-SHIFT + KEYWORD DECRYPTION")
print("=" * 80)

for shift in range(26):
    # Apply Caesar shift to the W-removed text
    shifted = "".join(chr((ord(c) - 65 + shift) % 26 + 65) for c in ct_no_w)

    for kw in KEYWORDS:
        for variant in VARIANTS:
            for alph_name, alph in ALPHABETS:
                key_nums = alph.encode(kw)

                if alph_name == "AZ":
                    pt = decrypt_text(shifted, key_nums, variant)
                else:
                    ct_indices = alph.encode(shifted)
                    key_cycle = key_nums
                    fn = DECRYPT_FN[variant]
                    klen = len(key_cycle)
                    pt_indices = [fn(ct_indices[i], key_cycle[i % klen]) for i in range(len(ct_indices))]
                    pt = alph.decode(pt_indices)

                fsb = score_candidate_free(pt)
                total_configs += 1

                if fsb.crib_score > 0:
                    print(f"  HIT: shift={shift}/{kw}/{variant.value}/{alph_name}")
                    print(f"        score={fsb.crib_score} IC={fsb.ic_value:.4f}")
                    print(f"        PT: {pt[:50]}...")
                    print(f"        {fsb.summary}")

print(f"\nTotal configs tested (with Caesar shifts): {total_configs}")

# ── Step 7: Manual anchored crib check ───────────────────────────────────

print("\n" + "=" * 80)
print("MANUAL ANCHORED CRIB CHECK AT ADJUSTED POSITIONS")
print("=" * 80)

# After W removal, recalculated positions:
# W positions removed: [20, 36, 48, 58, 74]
# ENE was at 21-33. W[20] is before it. 1 W removed before pos 21.
# So ENE now at 20-32.
# BC was at 63-73. W's at [20, 36, 48, 58] are before pos 63 = 4 removed.
# So BC now at 59-69.

ene_adj_start = 20
ene_adj_end = 32
bc_adj_start = 59
bc_adj_end = 69

print(f"Adjusted ENE position: {ene_adj_start}-{ene_adj_end}")
print(f"Adjusted BC position: {bc_adj_start}-{bc_adj_end}")

# Verify: extract from W-removed text at those positions
print(f"\nW-removed text at ENE positions [{ene_adj_start}:{ene_adj_end+1}]: {ct_no_w[ene_adj_start:ene_adj_end+1]}")
print(f"W-removed text at BC positions [{bc_adj_start}:{bc_adj_end+1}]: {ct_no_w[bc_adj_start:bc_adj_end+1]}")

# Now check: for each keyword/variant/alphabet, recover key at the adjusted
# crib positions and check for periodicity
print("\nKey recovery at adjusted crib positions:")
ENE_PT = "EASTNORTHEAST"
BC_PT = "BERLINCLOCK"

best_periodic_score = 0
best_periodic_config = None

for kw in KEYWORDS:
    for variant in VARIANTS:
        for alph_name, alph in ALPHABETS:
            key_nums = alph.encode(kw)

            if alph_name == "AZ":
                pt = decrypt_text(ct_no_w, key_nums, variant)
            else:
                ct_indices = alph.encode(ct_no_w)
                key_cycle = key_nums
                fn = DECRYPT_FN[variant]
                klen = len(key_cycle)
                pt_indices = [fn(ct_indices[i], key_cycle[i % klen]) for i in range(len(ct_indices))]
                pt = alph.decode(pt_indices)

            # Check if the crib text appears at adjusted positions
            ene_match = pt[ene_adj_start:ene_adj_end+1]
            bc_match = pt[bc_adj_start:bc_adj_end+1]

            ene_hits = sum(1 for i in range(13) if ene_match[i] == ENE_PT[i])
            bc_hits = sum(1 for i in range(11) if bc_match[i] == BC_PT[i])
            total_hits = ene_hits + bc_hits

            if total_hits > best_periodic_score:
                best_periodic_score = total_hits
                best_periodic_config = (kw, variant.value, alph_name)

            if total_hits > 6:
                print(f"\n  {kw}/{variant.value}/{alph_name}: ENE={ene_hits}/13 BC={bc_hits}/11 total={total_hits}/24")
                print(f"    PT at ENE pos: {ene_match}")
                print(f"    PT at BC pos:  {bc_match}")
                print(f"    Full PT: {pt}")

print(f"\nBest anchored score at adjusted positions: {best_periodic_score}/24 ({best_periodic_config})")

# ── Step 8: Also try removing W's and keeping positions ──────────────────

print("\n" + "=" * 80)
print("ALTERNATIVE: REPLACE W WITH EACH LETTER (null hypothesis)")
print("=" * 80)

# What if W is not removed but replaced? Try replacing all W's with each letter
for replacement in ALPH:
    ct_replaced = CT.replace('W', replacement)
    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
            key_nums = AZ.encode(kw)
            pt = decrypt_text(ct_replaced, key_nums, variant)
            fsb = score_candidate_free(pt)
            if fsb.crib_score > 0:
                print(f"  HIT: W->{replacement}/{kw}/{variant.value}/AZ score={fsb.crib_score}")
                print(f"        PT: {pt[:50]}...")

# ── Step 9: Try W positions as key to transposition ──────────────────────

print("\n" + "=" * 80)
print("W POSITIONS AS SEGMENTATION MARKERS")
print("=" * 80)

# W's at [20, 36, 48, 58, 74] divide CT into 6 segments
# (before first W, between consecutive W's, after last W)
segments = []
w_all = [-1] + w_positions + [CT_LEN]
for i in range(len(w_all) - 1):
    start = w_all[i] + 1
    end = w_all[i + 1]
    seg = CT[start:end]
    segments.append(seg)
    print(f"  Segment {i}: pos [{start}-{end-1}] len={len(seg)}: {seg}")

print(f"\nSegment lengths: {[len(s) for s in segments]}")
print(f"Sum of segment lengths: {sum(len(s) for s in segments)}")

# Try reading segments in different orders
from itertools import permutations
print("\nTrying all permutations of 6 segments with keyword decryption...")
best_seg_score = 0
seg_configs_tested = 0

for perm in permutations(range(6)):
    reordered = "".join(segments[i] for i in perm)

    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR"]:
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
            key_nums = AZ.encode(kw)
            pt = decrypt_text(reordered, key_nums, variant)
            fsb = score_candidate_free(pt)
            seg_configs_tested += 1

            if fsb.crib_score > 0:
                if fsb.crib_score > best_seg_score:
                    best_seg_score = fsb.crib_score
                print(f"  HIT: perm={perm}/{kw}/{variant.value} score={fsb.crib_score}")
                print(f"        PT: {pt[:60]}...")

print(f"  Segment permutation configs tested: {seg_configs_tested}")
print(f"  Best segment score: {best_seg_score}")

# ── Summary ──────────────────────────────────────────────────────────────

print("\n" + "=" * 80)
print("SUMMARY")
print("=" * 80)
print(f"Original CT: {CT} ({CT_LEN} chars)")
print(f"W positions: {w_positions}")
print(f"W-removed text: {ct_no_w} ({ct_no_w_len} chars)")
print(f"IC original: {ic_orig:.6f}")
print(f"IC W-removed: {ic_new:.6f}")
print(f"Adjusted ENE crib: positions {ene_adj_start}-{ene_adj_end}")
print(f"Adjusted BC crib: positions {bc_adj_start}-{bc_adj_end}")
print(f"Total configs tested: {total_configs + seg_configs_tested}")
print(f"Best anchored score: {best_periodic_score}/24")
if results_above_noise:
    print(f"\nResults above noise ({len(results_above_noise)}):")
    for r in sorted(results_above_noise, key=lambda x: -x['score']):
        print(f"  score={r['score']} IC={r['ic']:.4f} {r['keyword']}/{r['variant']}/{r['alphabet']}")
        print(f"    {r['plaintext'][:60]}...")
else:
    print("\nNo results above noise floor.")
print("\nDone.")
