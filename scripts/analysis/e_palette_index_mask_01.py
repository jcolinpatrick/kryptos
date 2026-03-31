#!/usr/bin/env python3
"""
Cipher:    Palette index/mask/selection tests
Family:    analysis
Status:    active
Keyspace:  ~200 targeted configs
Last run:  2026-03-23
Best score: TBD

Test the null palette letters {B,G,I,K,O,W,Z} as index/mask/selection
key material for K4. Six test families:

1. Palette numeric values (AZ) as positions into CT, with multipliers
2. Palette as KA-indexed positions into CT
3. Palette letters as running-key selector (take/skip based on palette membership)
4. Palette letter frequency vector as a key (Gromark primer, transposition, etc.)
5. Palette positions (where they appear in CT) as difference key
6. Palette letters as Polybius coordinates in 5-wide KA grid
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md


import sys, os, json, time
from datetime import datetime

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, KRYPTOS_ALPHABET, MOD,
    NULL_PALETTE, CONSENSUS_NULL_POSITIONS, CRIB_DICT, N_CRIBS,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)
from kryptos.kernel.scoring.crib_score import score_cribs, score_cribs_detailed
from kryptos.kernel.scoring.free_crib import score_free, score_free_fast
from kryptos.kernel.scoring.ic import ic

# ---- Helpers ----

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

PALETTE = sorted(NULL_PALETTE)  # [B, G, I, K, O, W, Z]
PALETTE_SET = NULL_PALETTE

# Palette positions in CT (all occurrences)
PALETTE_POSITIONS = sorted(i for i, c in enumerate(CT) if c in PALETTE_SET)

# Non-palette positions
NON_PALETTE_POSITIONS = sorted(i for i, c in enumerate(CT) if c not in PALETTE_SET)

# Palette AZ indices: B=1, G=6, I=8, K=10, O=14, W=22, Z=25
PAL_AZ = sorted(ALPH_IDX[c] for c in PALETTE)

# Palette KA indices: K=0, R=... etc
PAL_KA = sorted(KA_IDX[c] for c in PALETTE)

results = {
    "timestamp": datetime.now().isoformat(),
    "ciphertext": CT,
    "palette": sorted(PALETTE_SET),
    "tests": {},
}

print("=" * 70)
print("PALETTE INDEX/MASK EXPERIMENT")
print("=" * 70)
print(f"CT: {CT}")
print(f"Palette: {sorted(PALETTE_SET)}")
print(f"Palette AZ indices: {PAL_AZ}")
print(f"Palette KA indices: {PAL_KA}")
print(f"Palette positions in CT ({len(PALETTE_POSITIONS)}): {PALETTE_POSITIONS}")
print()


# ============================================================================
# TEST 1: Palette numeric values as positions
# ============================================================================
print("=" * 70)
print("TEST 1: Palette AZ-numeric values as CT positions")
print("=" * 70)

test1_results = {}

# Direct: extract CT at palette AZ index positions
positions_direct = PAL_AZ  # [1, 6, 8, 10, 14, 22, 25]
extracted_direct = "".join(CT[p] for p in positions_direct)
print(f"  Direct AZ positions {positions_direct}: {extracted_direct}")
crib_score_direct = score_free_fast(extracted_direct)
test1_results["direct_az"] = {
    "positions": positions_direct,
    "extracted": extracted_direct,
    "free_crib_score": crib_score_direct,
}

# Multipliers x2, x3, x4 (mod 97)
for mult in [2, 3, 4, 5, 7, 11, 13, 14]:
    positions = [(p * mult) % CT_LEN for p in PAL_AZ]
    positions_sorted = sorted(set(positions))
    extracted = "".join(CT[p] for p in positions_sorted)
    fcr = score_free_fast(extracted)
    label = f"az_x{mult}"
    test1_results[label] = {
        "positions": positions_sorted,
        "extracted": extracted,
        "free_crib_score": fcr,
    }
    print(f"  AZ * {mult} (mod 97) positions {positions_sorted}: {extracted} (free_score={fcr})")

# Also try KA indices directly as positions
positions_ka = sorted(set(p for p in PAL_KA if p < CT_LEN))
extracted_ka = "".join(CT[p] for p in positions_ka)
print(f"  Direct KA positions {positions_ka}: {extracted_ka}")
test1_results["direct_ka"] = {
    "positions": positions_ka,
    "extracted": extracted_ka,
    "free_crib_score": score_free_fast(extracted_ka),
}

# KA indices with multipliers
for mult in [2, 3, 4, 5, 7, 11, 13, 14]:
    positions = [(p * mult) % CT_LEN for p in PAL_KA]
    positions_sorted = sorted(set(positions))
    extracted = "".join(CT[p] for p in positions_sorted)
    fcr = score_free_fast(extracted)
    label = f"ka_x{mult}"
    test1_results[label] = {
        "positions": positions_sorted,
        "extracted": extracted,
        "free_crib_score": fcr,
    }
    print(f"  KA * {mult} (mod 97) positions {positions_sorted}: {extracted} (free_score={fcr})")

results["tests"]["test1_palette_as_positions"] = test1_results
print()


# ============================================================================
# TEST 2: Palette as KA-indexed positions (already partly in test 1)
# ============================================================================
print("=" * 70)
print("TEST 2: Palette as KA-indexed positions + pattern checks")
print("=" * 70)

test2_results = {}

# KA indices: K=0, O=5, B=8, G=13, I=15, W=23, Z=25
# In the order B,G,I,K,O,W,Z (AZ order):
ka_indices_az_order = [KA_IDX[c] for c in sorted(PALETTE_SET)]
print(f"  Palette KA indices (AZ order): {list(zip(sorted(PALETTE_SET), ka_indices_az_order))}")

# In the order of KA index:
ka_sorted = sorted(PALETTE_SET, key=lambda c: KA_IDX[c])
ka_indices_sorted = [KA_IDX[c] for c in ka_sorted]
print(f"  Palette KA indices (sorted): {list(zip(ka_sorted, ka_indices_sorted))}")

# Check differences between consecutive KA indices
diffs_ka = [ka_indices_sorted[i+1] - ka_indices_sorted[i] for i in range(len(ka_indices_sorted)-1)]
print(f"  KA index differences: {diffs_ka}")
print(f"  KA index sum: {sum(ka_indices_sorted)} (mod 26 = {sum(ka_indices_sorted) % 26})")

# Extract CT chars at KA-derived positions
extracted_ka_positions = "".join(CT[p] for p in ka_indices_sorted if p < CT_LEN)
print(f"  CT at KA positions: {extracted_ka_positions}")

# Try using KA differences as shift key for Vigenere/Beaufort on CT
# Apply differences [5,3,5,2,8,2] as a repeating key
key_from_diffs = diffs_ka
print(f"  Using KA diffs as Vigenere key: {key_from_diffs}")

# Vigenere decrypt of full CT with this 6-element key
vig_pt = []
beau_pt = []
for i, c in enumerate(CT):
    k = key_from_diffs[i % len(key_from_diffs)]
    vig_pt.append(ALPH[(ALPH_IDX[c] - k) % MOD])
    beau_pt.append(ALPH[(k - ALPH_IDX[c]) % MOD])
vig_text = "".join(vig_pt)
beau_text = "".join(beau_pt)
vig_crib = score_cribs(vig_text)
beau_crib = score_cribs(beau_text)
vig_free = score_free_fast(vig_text)
beau_free = score_free_fast(beau_text)

print(f"  Vig decrypt (KA-diff key): {vig_text[:40]}... crib={vig_crib} free={vig_free}")
print(f"  Beau decrypt (KA-diff key): {beau_text[:40]}... crib={beau_crib} free={beau_free}")

test2_results["ka_indices_az_order"] = ka_indices_az_order
test2_results["ka_indices_sorted"] = ka_indices_sorted
test2_results["ka_diffs"] = diffs_ka
test2_results["ka_sum"] = sum(ka_indices_sorted)
test2_results["vig_decrypt_ka_diff"] = {"text": vig_text, "crib": vig_crib, "free": vig_free}
test2_results["beau_decrypt_ka_diff"] = {"text": beau_text, "crib": beau_crib, "free": beau_free}

# Also try AZ index differences as key
az_sorted = sorted(PALETTE_SET)
az_indices_sorted = [ALPH_IDX[c] for c in az_sorted]
diffs_az = [az_indices_sorted[i+1] - az_indices_sorted[i] for i in range(len(az_indices_sorted)-1)]
print(f"  AZ index differences: {diffs_az}")
key_from_az_diffs = diffs_az
vig_pt2 = []
beau_pt2 = []
for i, c in enumerate(CT):
    k = key_from_az_diffs[i % len(key_from_az_diffs)]
    vig_pt2.append(ALPH[(ALPH_IDX[c] - k) % MOD])
    beau_pt2.append(ALPH[(k - ALPH_IDX[c]) % MOD])
vig_text2 = "".join(vig_pt2)
beau_text2 = "".join(beau_pt2)
vig_crib2 = score_cribs(vig_text2)
beau_crib2 = score_cribs(beau_text2)
vig_free2 = score_free_fast(vig_text2)
beau_free2 = score_free_fast(beau_text2)

print(f"  Vig decrypt (AZ-diff key): {vig_text2[:40]}... crib={vig_crib2} free={beau_free2}")
print(f"  Beau decrypt (AZ-diff key): {beau_text2[:40]}... crib={beau_crib2} free={beau_free2}")

test2_results["az_diffs"] = diffs_az
test2_results["vig_decrypt_az_diff"] = {"text": vig_text2, "crib": vig_crib2, "free": vig_free2}
test2_results["beau_decrypt_az_diff"] = {"text": beau_text2, "crib": beau_crib2, "free": beau_free2}

results["tests"]["test2_ka_indexed_positions"] = test2_results
print()


# ============================================================================
# TEST 3: Palette letters as running-key selector
# ============================================================================
print("=" * 70)
print("TEST 3: Palette letters as running-key selector")
print("=" * 70)

test3_results = {}

# Mode A: Take non-palette letters only (skip palette letters)
non_palette_chars = "".join(c for c in CT if c not in PALETTE_SET)
print(f"  Non-palette chars ({len(non_palette_chars)}): {non_palette_chars}")
crib_non = score_free_fast(non_palette_chars)
ic_non = ic(non_palette_chars) if len(non_palette_chars) > 1 else 0
print(f"  Free score: {crib_non}, IC: {ic_non:.4f}")
test3_results["non_palette_only"] = {
    "text": non_palette_chars,
    "length": len(non_palette_chars),
    "free_score": crib_non,
    "ic": ic_non,
}

# Mode B: Take palette letters only
palette_chars = "".join(c for c in CT if c in PALETTE_SET)
print(f"  Palette chars only ({len(palette_chars)}): {palette_chars}")
crib_pal = score_free_fast(palette_chars)
ic_pal = ic(palette_chars) if len(palette_chars) > 1 else 0
print(f"  Free score: {crib_pal}, IC: {ic_pal:.4f}")
test3_results["palette_only"] = {
    "text": palette_chars,
    "length": len(palette_chars),
    "free_score": crib_pal,
    "ic": ic_pal,
}

# Mode C: For each palette letter, take the NEXT non-palette letter
selector_next = []
for i, c in enumerate(CT):
    if c in PALETTE_SET:
        # Find next non-palette letter
        for j in range(i + 1, CT_LEN):
            if CT[j] not in PALETTE_SET:
                selector_next.append(CT[j])
                break
selected_next = "".join(selector_next)
print(f"  Palette->next non-palette ({len(selected_next)}): {selected_next}")
crib_sel = score_free_fast(selected_next)
test3_results["palette_next_nonpalette"] = {
    "text": selected_next,
    "length": len(selected_next),
    "free_score": crib_sel,
}

# Mode D: For each palette letter, take the PREVIOUS non-palette letter
selector_prev = []
for i, c in enumerate(CT):
    if c in PALETTE_SET:
        for j in range(i - 1, -1, -1):
            if CT[j] not in PALETTE_SET:
                selector_prev.append(CT[j])
                break
selected_prev = "".join(selector_prev)
print(f"  Palette->prev non-palette ({len(selected_prev)}): {selected_prev}")
crib_sel_prev = score_free_fast(selected_prev)
test3_results["palette_prev_nonpalette"] = {
    "text": selected_prev,
    "length": len(selected_prev),
    "free_score": crib_sel_prev,
}

# Mode E: At palette positions, take the NEXT letter (any); skip non-palette positions
selector_next_any = []
for i, c in enumerate(CT):
    if c in PALETTE_SET and i + 1 < CT_LEN:
        selector_next_any.append(CT[i + 1])
selected_next_any = "".join(selector_next_any)
print(f"  Palette position -> next char ({len(selected_next_any)}): {selected_next_any}")
crib_sel_next = score_free_fast(selected_next_any)
test3_results["palette_pos_next_char"] = {
    "text": selected_next_any,
    "length": len(selected_next_any),
    "free_score": crib_sel_next,
}

# Mode F: Non-palette chars scored against anchored cribs
# (put non-palette chars into a 97-char string, padding palette positions with '?')
padded_non_palette = list("?" * CT_LEN)
for i, c in enumerate(CT):
    if c not in PALETTE_SET:
        padded_non_palette[i] = c
padded_str = "".join(padded_non_palette)
anchored_score = score_cribs(padded_str)
print(f"  Non-palette at original positions (anchored crib): {anchored_score}/24")
test3_results["non_palette_anchored_crib"] = anchored_score

# Mode G: Palette chars at original positions (anchored)
padded_palette = list("?" * CT_LEN)
for i, c in enumerate(CT):
    if c in PALETTE_SET:
        padded_palette[i] = c
padded_pal_str = "".join(padded_palette)
pal_anchored = score_cribs(padded_pal_str)
print(f"  Palette at original positions (anchored crib): {pal_anchored}/24")
test3_results["palette_anchored_crib"] = pal_anchored

results["tests"]["test3_palette_selector"] = test3_results
print()


# ============================================================================
# TEST 4: Palette letter COUNT as key
# ============================================================================
print("=" * 70)
print("TEST 4: Palette letter frequency vector as key")
print("=" * 70)

test4_results = {}

# Count each palette letter in CT
from collections import Counter
ct_counts = Counter(CT)
pal_counts = {c: ct_counts[c] for c in sorted(PALETTE_SET)}
print(f"  Palette letter counts: {pal_counts}")

# Frequency vector in AZ order: B,G,I,K,O,W,Z
freq_vec_az = [ct_counts[c] for c in sorted(PALETTE_SET)]
print(f"  Frequency vector (AZ order BGIKOW Z): {freq_vec_az}")

# Also in KA order: K,O,B,G,I,W,Z
freq_vec_ka = [ct_counts[c] for c in sorted(PALETTE_SET, key=lambda x: KA_IDX[x])]
print(f"  Frequency vector (KA order): {freq_vec_ka}")

# Test as Vigenere/Beaufort key
for key_name, freq_vec in [("az_order", freq_vec_az), ("ka_order", freq_vec_ka)]:
    vig_pt = []
    beau_pt = []
    for i, c in enumerate(CT):
        k = freq_vec[i % len(freq_vec)]
        vig_pt.append(ALPH[(ALPH_IDX[c] - k) % MOD])
        beau_pt.append(ALPH[(k - ALPH_IDX[c]) % MOD])
    vig_text = "".join(vig_pt)
    beau_text = "".join(beau_pt)
    vig_crib = score_cribs(vig_text)
    beau_crib = score_cribs(beau_text)
    print(f"  Vig ({key_name}): {vig_text[:40]}... crib={vig_crib}")
    print(f"  Beau ({key_name}): {beau_text[:40]}... crib={beau_crib}")
    test4_results[f"vig_{key_name}"] = {"text": vig_text, "crib": vig_crib}
    test4_results[f"beau_{key_name}"] = {"text": beau_text, "crib": beau_crib}

# Test as transposition key (columnar)
# freq_vec = [5,4,4,8,5,5,4] -> ranking: K(8)=0, B(5)=1, O(5)=2, W(5)=3, G(4)=4, I(4)=5, Z(4)=6
# Using the vector directly as column order
for key_name, freq_vec in [("az_order", freq_vec_az), ("ka_order", freq_vec_ka)]:
    n_cols = len(freq_vec)
    # Sort columns by key value (ascending) to get read-off order
    col_order = sorted(range(n_cols), key=lambda x: (freq_vec[x], x))

    # Fill grid row by row
    n_rows = (CT_LEN + n_cols - 1) // n_cols
    grid = [[""] * n_cols for _ in range(n_rows)]
    for idx, c in enumerate(CT):
        r, col = divmod(idx, n_cols)
        grid[r][col] = c

    # Read off in column order
    col_read = ""
    for col in col_order:
        for r in range(n_rows):
            if grid[r][col]:
                col_read += grid[r][col]

    free_col = score_free_fast(col_read)
    crib_col = score_cribs(col_read)
    print(f"  Columnar transposition ({key_name}, order={col_order}): crib={crib_col} free={free_col}")
    print(f"    Result: {col_read[:60]}...")
    test4_results[f"columnar_{key_name}"] = {"text": col_read, "crib": crib_col, "free": free_col, "col_order": col_order}

# Test frequency vector as direct numeric key applied to non-palette chars (62 chars)
non_pal = "".join(c for i, c in enumerate(CT) if c not in PALETTE_SET)
for key_name, freq_vec in [("az_order", freq_vec_az), ("ka_order", freq_vec_ka)]:
    vig_pt = []
    beau_pt = []
    for i, c in enumerate(non_pal):
        k = freq_vec[i % len(freq_vec)]
        vig_pt.append(ALPH[(ALPH_IDX[c] - k) % MOD])
        beau_pt.append(ALPH[(k - ALPH_IDX[c]) % MOD])
    vig_text = "".join(vig_pt)
    beau_text = "".join(beau_pt)
    vig_free = score_free_fast(vig_text)
    beau_free = score_free_fast(beau_text)
    print(f"  Non-palette Vig ({key_name}): {vig_text[:40]}... free={vig_free}")
    print(f"  Non-palette Beau ({key_name}): {beau_text[:40]}... free={beau_free}")
    test4_results[f"nonpal_vig_{key_name}"] = {"text": vig_text, "free": vig_free}
    test4_results[f"nonpal_beau_{key_name}"] = {"text": beau_text, "free": beau_free}

results["tests"]["test4_frequency_vector_key"] = test4_results
print()


# ============================================================================
# TEST 5: Palette positions as difference key
# ============================================================================
print("=" * 70)
print("TEST 5: Consecutive palette position differences as key")
print("=" * 70)

test5_results = {}

# Differences between consecutive palette positions
pal_diffs = [PALETTE_POSITIONS[i+1] - PALETTE_POSITIONS[i] for i in range(len(PALETTE_POSITIONS)-1)]
print(f"  Palette positions ({len(PALETTE_POSITIONS)}): {PALETTE_POSITIONS}")
print(f"  Position differences ({len(pal_diffs)}): {pal_diffs}")
print(f"  Diff sum: {sum(pal_diffs)}, range: {min(pal_diffs)}-{max(pal_diffs)}")

# Reduce diffs mod 26 for use as key
pal_diffs_mod26 = [d % 26 for d in pal_diffs]
print(f"  Diffs mod 26: {pal_diffs_mod26}")

# Use as Vigenere/Beaufort key (34-element key)
for key_name, key in [("raw_diffs", pal_diffs_mod26)]:
    vig_pt = []
    beau_pt = []
    for i, c in enumerate(CT):
        k = key[i % len(key)]
        vig_pt.append(ALPH[(ALPH_IDX[c] - k) % MOD])
        beau_pt.append(ALPH[(k - ALPH_IDX[c]) % MOD])
    vig_text = "".join(vig_pt)
    beau_text = "".join(beau_pt)
    vig_crib = score_cribs(vig_text)
    beau_crib = score_cribs(beau_text)
    print(f"  Vig (pos diffs, period {len(key)}): crib={vig_crib}")
    print(f"  Beau (pos diffs, period {len(key)}): crib={beau_crib}")
    test5_results[f"vig_{key_name}"] = {"text": vig_text, "crib": vig_crib}
    test5_results[f"beau_{key_name}"] = {"text": beau_text, "crib": beau_crib}

# Also try: differences between consecutive CONSENSUS null positions only
cnp_sorted = sorted(CONSENSUS_NULL_POSITIONS)
cnp_diffs = [cnp_sorted[i+1] - cnp_sorted[i] for i in range(len(cnp_sorted)-1)]
cnp_diffs_mod26 = [d % 26 for d in cnp_diffs]
print(f"  Consensus null positions ({len(cnp_sorted)}): {cnp_sorted}")
print(f"  CNP diffs ({len(cnp_diffs)}): {cnp_diffs}")
print(f"  CNP diffs mod 26: {cnp_diffs_mod26}")

for key_name, key in [("cnp_diffs", cnp_diffs_mod26)]:
    vig_pt = []
    beau_pt = []
    for i, c in enumerate(CT):
        k = key[i % len(key)]
        vig_pt.append(ALPH[(ALPH_IDX[c] - k) % MOD])
        beau_pt.append(ALPH[(k - ALPH_IDX[c]) % MOD])
    vig_text = "".join(vig_pt)
    beau_text = "".join(beau_pt)
    vig_crib = score_cribs(vig_text)
    beau_crib = score_cribs(beau_text)
    print(f"  Vig (CNP diffs, period {len(key)}): crib={vig_crib}")
    print(f"  Beau (CNP diffs, period {len(key)}): crib={beau_crib}")
    test5_results[f"vig_{key_name}"] = {"text": vig_text, "crib": vig_crib}
    test5_results[f"beau_{key_name}"] = {"text": beau_text, "crib": beau_crib}

# Try: palette positions themselves (mod 26) as key
pal_pos_mod26 = [p % 26 for p in PALETTE_POSITIONS]
print(f"  Palette positions mod 26 ({len(pal_pos_mod26)}): {pal_pos_mod26}")
for key_name, key in [("pal_pos_mod26", pal_pos_mod26)]:
    vig_pt = []
    beau_pt = []
    for i, c in enumerate(CT):
        k = key[i % len(key)]
        vig_pt.append(ALPH[(ALPH_IDX[c] - k) % MOD])
        beau_pt.append(ALPH[(k - ALPH_IDX[c]) % MOD])
    vig_text = "".join(vig_pt)
    beau_text = "".join(beau_pt)
    vig_crib = score_cribs(vig_text)
    beau_crib = score_cribs(beau_text)
    print(f"  Vig (pal positions mod 26, period {len(key)}): crib={vig_crib}")
    print(f"  Beau (pal positions mod 26, period {len(key)}): crib={beau_crib}")
    test5_results[f"vig_{key_name}"] = {"text": vig_text, "crib": vig_crib}
    test5_results[f"beau_{key_name}"] = {"text": beau_text, "crib": beau_crib}

results["tests"]["test5_position_difference_key"] = test5_results
print()


# ============================================================================
# TEST 6: Palette as Polybius coordinates
# ============================================================================
print("=" * 70)
print("TEST 6: Palette as Polybius coordinates in 5-wide KA grid")
print("=" * 70)

test6_results = {}

# 5-wide KA grid layout:
# Row 0: K R Y P T
# Row 1: O S A B C
# Row 2: D E F G H
# Row 3: I J L M N
# Row 4: Q U V W X
# Row 5: Z
ka_grid = {}
for i, c in enumerate(KA):
    r, col = divmod(i, 5)
    ka_grid[c] = (r, col)

print("  Palette Polybius coordinates (row, col) in 5-wide KA grid:")
pal_coords = []
for c in sorted(PALETTE_SET, key=lambda x: KA_IDX[x]):
    r, col = ka_grid[c]
    print(f"    {c}: ({r}, {col})")
    pal_coords.append((r, col))

# Flatten to key: [0,0, 1,0, 1,3, 2,3, 3,0, 4,3, 5,0] = 14 digits
flat_coords = []
for r, c in pal_coords:
    flat_coords.extend([r, c])
print(f"  Flattened coordinates (14 digits): {flat_coords}")

# Use as period-14 Vigenere/Beaufort key
for key_name, key in [("polybius_14", flat_coords)]:
    vig_pt = []
    beau_pt = []
    for i, c in enumerate(CT):
        k = key[i % len(key)]
        vig_pt.append(ALPH[(ALPH_IDX[c] - k) % MOD])
        beau_pt.append(ALPH[(k - ALPH_IDX[c]) % MOD])
    vig_text = "".join(vig_pt)
    beau_text = "".join(beau_pt)
    vig_crib = score_cribs(vig_text)
    beau_crib = score_cribs(beau_text)
    print(f"  Vig (Polybius coords, period 14): {vig_text[:40]}... crib={vig_crib}")
    print(f"  Beau (Polybius coords, period 14): {beau_text[:40]}... crib={beau_crib}")
    test6_results[f"vig_{key_name}"] = {"text": vig_text, "crib": vig_crib}
    test6_results[f"beau_{key_name}"] = {"text": beau_text, "crib": beau_crib}

# Try rows only as key (7-element): [0, 1, 1, 2, 3, 4, 5]
rows_only = [r for r, c in pal_coords]
cols_only = [c for r, c in pal_coords]
print(f"  Rows only: {rows_only}")
print(f"  Cols only: {cols_only}")

for key_name, key in [("rows_7", rows_only), ("cols_7", cols_only)]:
    vig_pt = []
    beau_pt = []
    for i, c in enumerate(CT):
        k = key[i % len(key)]
        vig_pt.append(ALPH[(ALPH_IDX[c] - k) % MOD])
        beau_pt.append(ALPH[(k - ALPH_IDX[c]) % MOD])
    vig_text = "".join(vig_pt)
    beau_text = "".join(beau_pt)
    vig_crib = score_cribs(vig_text)
    beau_crib = score_cribs(beau_text)
    vig_free = score_free_fast(vig_text)
    beau_free = score_free_fast(beau_text)
    print(f"  Vig ({key_name}): crib={vig_crib} free={vig_free}")
    print(f"  Beau ({key_name}): crib={beau_crib} free={beau_free}")
    test6_results[f"vig_{key_name}"] = {"text": vig_text, "crib": vig_crib, "free": vig_free}
    test6_results[f"beau_{key_name}"] = {"text": beau_text, "crib": beau_crib, "free": beau_free}

# Try: Polybius coords in pairs as digraph substitution values
# Each palette letter contributes a 2-digit number: row*5+col (= KA index already)
# or row*6+col (for 6-row grid)
# Let's try row+col as a single key element (7-element key)
row_plus_col = [r + c for r, c in pal_coords]
print(f"  Row + col: {row_plus_col}")

for key_name, key in [("row_plus_col_7", row_plus_col)]:
    vig_pt = []
    beau_pt = []
    for i, c in enumerate(CT):
        k = key[i % len(key)]
        vig_pt.append(ALPH[(ALPH_IDX[c] - k) % MOD])
        beau_pt.append(ALPH[(k - ALPH_IDX[c]) % MOD])
    vig_text = "".join(vig_pt)
    beau_text = "".join(beau_pt)
    vig_crib = score_cribs(vig_text)
    beau_crib = score_cribs(beau_text)
    print(f"  Vig ({key_name}): crib={vig_crib}")
    print(f"  Beau ({key_name}): crib={beau_crib}")
    test6_results[f"vig_{key_name}"] = {"text": vig_text, "crib": vig_crib}
    test6_results[f"beau_{key_name}"] = {"text": beau_text, "crib": beau_crib}

# Try: flattened coords applied to non-palette chars only (62 chars)
for key_name, key in [("polybius_14_nonpal", flat_coords)]:
    vig_pt = []
    beau_pt = []
    for i, c in enumerate(non_pal):
        k = key[i % len(key)]
        vig_pt.append(ALPH[(ALPH_IDX[c] - k) % MOD])
        beau_pt.append(ALPH[(k - ALPH_IDX[c]) % MOD])
    vig_text = "".join(vig_pt)
    beau_text = "".join(beau_pt)
    vig_free = score_free_fast(vig_text)
    beau_free = score_free_fast(beau_text)
    print(f"  Non-pal Vig (Polybius 14): free={vig_free}")
    print(f"  Non-pal Beau (Polybius 14): free={beau_free}")
    test6_results[f"vig_{key_name}"] = {"text": vig_text, "free": vig_free}
    test6_results[f"beau_{key_name}"] = {"text": beau_text, "free": beau_free}

results["tests"]["test6_polybius_coordinates"] = test6_results
print()


# ============================================================================
# BONUS TESTS: Palette letters as alphabet positions modulo various bases
# ============================================================================
print("=" * 70)
print("BONUS: Palette indices as composite keys (various combinations)")
print("=" * 70)

bonus_results = {}

# B=1, G=6, I=8, K=10, O=14, W=22, Z=25 (AZ)
# Their mod-7 values: 1,6,1,3,0,1,4 -- not all distinct
# Try: palette AZ indices mapped to letters (as keyword)
pal_keyword = "".join(ALPH[i % 26] for i in PAL_AZ)
print(f"  Palette AZ -> keyword: {pal_keyword}")

# Try: palette letters themselves as Vigenere keyword (BGIKOWZ period 7)
pal_kw = "".join(sorted(PALETTE_SET))
print(f"  Palette as keyword '{pal_kw}' (AZ order):")
vig_pt = []
beau_pt = []
for i, c in enumerate(CT):
    k = ALPH_IDX[pal_kw[i % len(pal_kw)]]
    vig_pt.append(ALPH[(ALPH_IDX[c] - k) % MOD])
    beau_pt.append(ALPH[(k - ALPH_IDX[c]) % MOD])
vig_text = "".join(vig_pt)
beau_text = "".join(beau_pt)
vig_crib = score_cribs(vig_text)
beau_crib = score_cribs(beau_text)
vig_free = score_free_fast(vig_text)
beau_free = score_free_fast(beau_text)
print(f"  Vig: {vig_text[:50]}... crib={vig_crib} free={vig_free}")
print(f"  Beau: {beau_text[:50]}... crib={beau_crib} free={beau_free}")
bonus_results["vig_palette_keyword_az"] = {"text": vig_text, "crib": vig_crib, "free": vig_free}
bonus_results["beau_palette_keyword_az"] = {"text": beau_text, "crib": beau_crib, "free": beau_free}

# KA order: KOBGIWZ
pal_kw_ka = "".join(sorted(PALETTE_SET, key=lambda x: KA_IDX[x]))
print(f"  Palette as keyword '{pal_kw_ka}' (KA order):")
vig_pt = []
beau_pt = []
for i, c in enumerate(CT):
    k = ALPH_IDX[pal_kw_ka[i % len(pal_kw_ka)]]
    vig_pt.append(ALPH[(ALPH_IDX[c] - k) % MOD])
    beau_pt.append(ALPH[(k - ALPH_IDX[c]) % MOD])
vig_text = "".join(vig_pt)
beau_text = "".join(beau_pt)
vig_crib = score_cribs(vig_text)
beau_crib = score_cribs(beau_text)
print(f"  Vig: {vig_text[:50]}... crib={vig_crib}")
print(f"  Beau: {beau_text[:50]}... crib={beau_crib}")
bonus_results["vig_palette_keyword_ka"] = {"text": vig_text, "crib": vig_crib}
bonus_results["beau_palette_keyword_ka"] = {"text": beau_text, "crib": beau_crib}

# Try: palette letter count (35) as period, with palette positions mod 26 as key
# 35 palette occurrences, each position mod 26
pal_pos_35 = [p % 26 for p in PALETTE_POSITIONS]
print(f"  35 palette positions mod 26: {pal_pos_35}")
for key_name, key in [("pal_pos_35", pal_pos_35)]:
    vig_pt = []
    beau_pt = []
    for i, c in enumerate(CT):
        k = key[i % len(key)]
        vig_pt.append(ALPH[(ALPH_IDX[c] - k) % MOD])
        beau_pt.append(ALPH[(k - ALPH_IDX[c]) % MOD])
    vig_text = "".join(vig_pt)
    beau_text = "".join(beau_pt)
    vig_crib = score_cribs(vig_text)
    beau_crib = score_cribs(beau_text)
    print(f"  Vig (35-position key): crib={vig_crib}")
    print(f"  Beau (35-position key): crib={beau_crib}")
    bonus_results[f"vig_{key_name}"] = {"text": vig_text, "crib": vig_crib}
    bonus_results[f"beau_{key_name}"] = {"text": beau_text, "crib": beau_crib}

# Try: SEVEN as Beaufort key (key=N maps to palette), test with both alphabets
for alpha_name, alpha in [("AZ", ALPH), ("KA", KA)]:
    alpha_idx = {c: i for i, c in enumerate(alpha)}
    kw = "SEVEN"
    vig_pt = []
    beau_pt = []
    for i, c in enumerate(CT):
        k = alpha_idx.get(kw[i % len(kw)], 0)
        ci = alpha_idx.get(c, 0)
        vig_pt.append(alpha[(ci - k) % 26])
        beau_pt.append(alpha[(k - ci) % 26])
    vig_text = "".join(vig_pt)
    beau_text = "".join(beau_pt)
    vig_crib = score_cribs(vig_text)
    beau_crib = score_cribs(beau_text)
    vig_free = score_free_fast(vig_text)
    beau_free = score_free_fast(beau_text)
    print(f"  SEVEN {alpha_name} Vig: crib={vig_crib} free={vig_free}  {vig_text[:40]}...")
    print(f"  SEVEN {alpha_name} Beau: crib={beau_crib} free={beau_free}  {beau_text[:40]}...")
    bonus_results[f"vig_SEVEN_{alpha_name}"] = {"text": vig_text, "crib": vig_crib, "free": vig_free}
    bonus_results[f"beau_SEVEN_{alpha_name}"] = {"text": beau_text, "crib": beau_crib, "free": beau_free}

# Try: Non-palette chars with palette chars removed, anchored scoring
# Extract the 62 non-palette chars and score them against cribs
# But positions shift -- so test: do the non-palette chars at their original
# positions happen to match cribs?
crib_match_at_nonpal = 0
for pos, expected in CRIB_DICT.items():
    if pos < CT_LEN and CT[pos] not in PALETTE_SET:
        # This is a non-palette position that's also a crib position
        # After removing palette chars, does the same char remain at
        # the same crib position? Only if no palette chars before it were removed.
        pass
    if pos < CT_LEN and CT[pos] == expected and CT[pos] not in PALETTE_SET:
        crib_match_at_nonpal += 1

print(f"\n  Crib positions that are non-palette AND self-matching: {crib_match_at_nonpal}")
# These are the self-encrypting positions
for pos, expected in CRIB_DICT.items():
    if CT[pos] == expected:
        in_pal = "PALETTE" if CT[pos] in PALETTE_SET else "not palette"
        print(f"    pos {pos}: CT={CT[pos]} PT={expected} ({in_pal})")

bonus_results["self_encrypt_palette_check"] = crib_match_at_nonpal

results["tests"]["bonus_composite_keys"] = bonus_results
print()


# ============================================================================
# SUMMARY
# ============================================================================
print("=" * 70)
print("SUMMARY")
print("=" * 70)

# Collect all crib scores
all_scores = []
for test_name, test_data in results["tests"].items():
    if isinstance(test_data, dict):
        for key, val in test_data.items():
            if isinstance(val, dict):
                crib = val.get("crib", 0)
                free = val.get("free_crib_score", val.get("free", val.get("free_score", 0)))
                if crib and crib > 0:
                    all_scores.append((crib, "crib", test_name, key))
                if free and free > 0:
                    all_scores.append((free, "free", test_name, key))

all_scores.sort(reverse=True)

print(f"  Total configs tested: {len(all_scores)}")
print(f"  Max anchored crib: {max((s for s, t, _, _ in all_scores if t == 'crib'), default=0)}/24")
print(f"  Max free crib: {max((s for s, t, _, _ in all_scores if t == 'free'), default=0)}")
print()

print("  Top 10 scores:")
for score, stype, test, key in all_scores[:10]:
    print(f"    {score:2d} ({stype:4s})  {test}.{key}")

# Determine verdict
max_crib = max((s for s, t, _, _ in all_scores if t == "crib"), default=0)
max_free = max((s for s, t, _, _ in all_scores if t == "free"), default=0)

if max_crib >= 10 or max_free >= 10:
    verdict = "INTERESTING — further investigation warranted"
elif max_crib >= 6 or max_free >= 6:
    verdict = "MARGINAL — some scores above noise floor but likely coincidence"
else:
    verdict = "NOISE — all palette-as-key-material tests produce noise-level scores"

results["summary"] = {
    "total_configs": len(all_scores),
    "max_anchored_crib": max_crib,
    "max_free_crib": max_free,
    "verdict": verdict,
}

print(f"\n  VERDICT: {verdict}")

# Write results
out_path = os.path.join(_ROOT, "results", "e_palette_index_mask.json")
with open(out_path, "w") as f:
    json.dump(results, f, indent=2)
print(f"\n  Results written to: {out_path}")
