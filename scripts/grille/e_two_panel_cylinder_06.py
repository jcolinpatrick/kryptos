#!/usr/bin/env python3
"""Two-panel Code Room cylinder: K1K2 beside K3K4 = 14 rows × 62 cols.

Cipher: various reading orders + Vigenere/Beaufort
Family: grille
Status: active
Keyspace: ~500K configs
Last run: never
Best score: n/a

MOTIVATION (Colin, 2026-03-07): Physical paper model of cipher panels
wrapped into a cylinder (Code Room style) reveals FIVE at the seam where
K1 row 0 ends (...FIV) and K3 row 0 starts (E...). This arrangement has:
- K1+K2 panel (14 rows × 31 cols) beside K3+K4 panel (14 rows × 31 cols)
- 14-row cylinder with 62-char circumference
- FIVE at seam is UNIQUE to width 31 and this arrangement
- Two seams: seam_A (K1K2→K3K4) and seam_B (K3K4→K1K2)

This script tests reading orders and decryptions on the TWO-PANEL cylinder.
"""
from __future__ import annotations
import sys, os, itertools
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD
from kryptos.kernel.transforms.vigenere import decrypt_text, CipherVariant
from kryptos.kernel.scoring.free_crib import score_free_fast

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA)}

W = 31  # single panel width
CYL_W = 62  # two-panel cylinder circumference
CYL_H = 14  # rows

# === BUILD CIPHER TEXT ===
K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
K2_CT = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLG"
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRR"
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVHDWKBFUFPWNTDFIYCUQZERE"
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZFKZBSFDQVGOGIPUFXHHDRKF"
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
)
K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOE"
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLB"
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"
)
K4_CT = CT

# Top half: K1 + ? + K2 + ? = 434 chars
top_half = K1_CT + "?" + K2_CT + "?"
# Bottom half: K3 + ? + K4 = 434 chars
bottom_half = K3_CT + "?" + K4_CT
assert len(top_half) == 434 and len(bottom_half) == 434

# Build 14×31 grids
top_grid = [top_half[r*W:(r+1)*W] for r in range(CYL_H)]
bot_grid = [bottom_half[r*W:(r+1)*W] for r in range(CYL_H)]

# Build the two-panel cylinder: each row = top_row + bot_row
cyl_grid = [top_grid[r] + bot_grid[r] for r in range(CYL_H)]
assert all(len(row) == CYL_W for row in cyl_grid)

# Identify K4 positions in the two-panel cylinder
# K4 starts at bottom_half position 337 (= 336 K3 chars + 1 ?)
# In bottom grid: row 337//31 = 10, col 337%31 = 27
# On cylinder: K4[i] is at row r, col (31 + c) where (r,c) is bottom-grid position
k4_cyl_positions = []  # (row, col_in_cylinder, k4_index)
for i in range(CT_LEN):
    pos_in_bot = 337 + i  # position in bottom_half
    r = pos_in_bot // W
    c = pos_in_bot % W
    cyl_col = W + c  # offset by 31 (right half of cylinder)
    k4_cyl_positions.append((r, cyl_col, i))
    assert cyl_grid[r][cyl_col] == CT[i], f"K4[{i}] mismatch at ({r},{cyl_col})"

print("=" * 78)
print("  TWO-PANEL CODE ROOM CYLINDER (14 rows × 62 cols)")
print("=" * 78)
print()
print(f"     {''.join(str(c%10) for c in range(62))}")
print(f"     {'K1+K2 panel (cols 0-30)':^31}|{'K3+K4 panel (cols 31-61)':^31}")
for r in range(CYL_H):
    # Mark K4 chars
    row_display = list(cyl_grid[r])
    print(f" {r:2d}: {''.join(row_display[:31])}|{''.join(row_display[31:])}")

# Show the FIVE seam
print()
print("FIVE at seam (row 0):")
print(f"  ...{cyl_grid[0][27:31]}|{cyl_grid[0][31:35]}... = {cyl_grid[0][28:32]}")
print()

# K4 zone
print("K4 positions on cylinder:")
print(f"  Rows {k4_cyl_positions[0][0]}-{k4_cyl_positions[-1][0]}, "
      f"cols {k4_cyl_positions[0][1]}-{k4_cyl_positions[-1][1]}")
print(f"  First: K4[0]='O' at row {k4_cyl_positions[0][0]}, col {k4_cyl_positions[0][1]}")
print(f"  Last:  K4[96]='R' at row {k4_cyl_positions[-1][0]}, col {k4_cyl_positions[-1][1]}")
print()

# === KEYWORDS AND VARIANTS ===
KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "HOROLOGE",
    "DEFECTOR", "PARALLAX", "COLOPHON", "BERLIN",
    "FIVE", "CLOCK", "POINT", "SHADOW", "URANIA",
]
VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]
THRESHOLD = 7

results = []
total = 0

def test_ct(ct_str, label):
    """Test a ciphertext string against all keywords and variants."""
    global total
    clean = ct_str.replace('?', 'A')
    for kw in KEYWORDS:
        kw_nums = [ALPH_IDX[c] for c in kw]
        for variant in VARIANTS:
            pt = decrypt_text(clean, kw_nums, variant)
            sc = score_free_fast(pt)
            if sc > THRESHOLD:
                results.append((sc, label, kw, variant.value, pt[:60]))
                print(f"  ** SCORE {sc}: {label} + {kw} ({variant.value}): {pt[:60]}")
            total += 1

def test_k4_perm(perm, label):
    """Apply permutation to K4 and test."""
    global total
    if len(perm) != CT_LEN:
        return
    permuted = "".join(CT[perm[i]] for i in range(CT_LEN))
    for kw in KEYWORDS:
        kw_nums = [ALPH_IDX[c] for c in kw]
        for variant in VARIANTS:
            pt = decrypt_text(permuted, kw_nums, variant)
            sc = score_free_fast(pt)
            if sc > THRESHOLD:
                results.append((sc, label, kw, variant.value, pt[:60]))
                print(f"  ** SCORE {sc}: {label} + {kw} ({variant.value}): {pt[:60]}")
            total += 1


# ================================================================
# PHASE 1: Full 868-char cylinder readings
# ================================================================
print("=" * 78)
print("  PHASE 1: Full cylinder readings (868 chars)")
print("=" * 78)
print()

# 1a. Row-first (standard on cylinder)
row_lr = ''.join(cyl_grid)
test_ct(row_lr, "cyl_row_LR")

# 1b. Starting from the FIVE seam (column 28)
for start_col in [28, 29, 30, 31]:
    reading = ''
    for r in range(CYL_H):
        for c in range(CYL_W):
            reading += cyl_grid[r][(start_col + c) % CYL_W]
    test_ct(reading, f"cyl_row_start{start_col}")

# 1c. Column-first on cylinder
for start_col in range(CYL_W):
    reading = ''
    for c_off in range(CYL_W):
        c = (start_col + c_off) % CYL_W
        for r in range(CYL_H):
            reading += cyl_grid[r][c]
    test_ct(reading, f"cyl_col_start{start_col}")

# 1d. Boustrophedon on cylinder
for start_col in [0, 28, 31]:
    reading = ''
    for r in range(CYL_H):
        row_chars = ''
        for c_off in range(CYL_W):
            c = (start_col + c_off) % CYL_W
            row_chars += cyl_grid[r][c]
        if r % 2 == 1:
            row_chars = row_chars[::-1]
        reading += row_chars
    test_ct(reading, f"cyl_boustro_start{start_col}")

print(f"  Phase 1: {total} configs tested")

# ================================================================
# PHASE 2: K4 extraction via cylinder column-first
# ================================================================
print()
print("=" * 78)
print("  PHASE 2: K4 extraction in cylinder column order")
print("=" * 78)
print()

# K4 occupies rows 10-13 in the right half (cols 58-61 on row 10, cols 31-61 on rows 11-13)
# Build (row, cyl_col) -> k4_index mapping
k4_map = {}
for r, cyl_col, k4_idx in k4_cyl_positions:
    k4_map[(r, cyl_col)] = k4_idx

# 2a. Column-first reading of K4 zone (various start columns)
for start_col in range(CYL_W):
    perm = []
    for c_off in range(CYL_W):
        c = (start_col + c_off) % CYL_W
        for r in range(CYL_H):
            if (r, c) in k4_map:
                perm.append(k4_map[(r, c)])
    if len(perm) == CT_LEN:
        test_k4_perm(perm, f"k4_col_start{start_col}")

# 2b. Column-first reversed (bottom-up)
for start_col in range(CYL_W):
    perm = []
    for c_off in range(CYL_W):
        c = (start_col + c_off) % CYL_W
        for r in range(CYL_H - 1, -1, -1):
            if (r, c) in k4_map:
                perm.append(k4_map[(r, c)])
    if len(perm) == CT_LEN:
        test_k4_perm(perm, f"k4_col_BT_start{start_col}")

print(f"  Phase 2: {total} configs tested")

# ================================================================
# PHASE 3: Helical reads on the 14×62 cylinder
# ================================================================
print()
print("=" * 78)
print("  PHASE 3: Helical K4 extraction on 14×62 cylinder")
print("=" * 78)
print()

# Helical: start at some position, advance column by 1 and row by pitch
# after each step. Extract K4 chars in encounter order.
phase3_start = total
for pitch_num in range(1, CYL_H):  # pitch = rows per revolution
    for start_r in range(CYL_H):
        for start_c in range(CYL_W):
            visited = set()
            perm = []
            r, c = start_r, start_c
            for _ in range(CYL_H * CYL_W):
                if (r, c) not in visited:
                    visited.add((r, c))
                    if (r, c) in k4_map:
                        perm.append(k4_map[(r, c)])
                c = (c + 1) % CYL_W
                if c == start_c % CYL_W or (c == (start_c + CYL_W) % CYL_W):
                    pass
                # Advance row every CYL_W steps
                if (len(visited)) % CYL_W == 0:
                    r = (r + pitch_num) % CYL_H
            # Only test if we got all 97 K4 chars
            if len(perm) == CT_LEN:
                test_k4_perm(perm, f"helix_p{pitch_num}_r{start_r}_c{start_c}")

    if (pitch_num % 3) == 0:
        print(f"  ... pitch {pitch_num}/{CYL_H-1}, {total - phase3_start} configs")

print(f"  Phase 3: {total - phase3_start} configs tested")

# ================================================================
# PHASE 4: Step-5 readings (FIVE = parameter 5)
# ================================================================
print()
print("=" * 78)
print("  PHASE 4: Step-5 inspired readings")
print("=" * 78)
print()

phase4_start = total

# 4a. Every 5th character from K4 (various start positions)
for start in range(5):
    perm = list(range(start, CT_LEN, 5))
    remaining = [i for i in range(CT_LEN) if i not in perm]
    # Try different orderings of the remaining chars
    for n_pass in range(1, 6):
        full_perm = []
        for p in range(n_pass):
            offset = (start + p) % 5
            full_perm.extend(range(offset, CT_LEN, 5))
        # Deduplicate while preserving order
        seen = set()
        deduped = []
        for x in full_perm:
            if x not in seen and x < CT_LEN:
                seen.add(x)
                deduped.append(x)
        if len(deduped) == CT_LEN:
            test_k4_perm(deduped, f"step5_start{start}_pass{n_pass}")

# 4b. Column groups of 5 on the cylinder
for start_col in range(CYL_W):
    perm = []
    for group_start in range(0, CYL_W, 5):
        for c_off in range(5):
            c = (start_col + group_start + c_off) % CYL_W
            for r in range(CYL_H):
                if (r, c) in k4_map:
                    perm.append(k4_map[(r, c)])
    if len(perm) == CT_LEN:
        test_k4_perm(perm, f"colgroup5_start{start_col}")

# 4c. Diagonal with slope 5 on the 14×62 cylinder
for start_c in range(CYL_W):
    perm = []
    visited = set()
    for step in range(CYL_H * CYL_W):
        r = step // CYL_W
        c = (start_c + step * 5) % CYL_W
        if r >= CYL_H:
            break
        if (r, c) not in visited:
            visited.add((r, c))
            if (r, c) in k4_map:
                perm.append(k4_map[(r, c)])
    if len(perm) == CT_LEN:
        test_k4_perm(perm, f"diag5_start{start_c}")

# 4d. Width-5 columnar transposition of K4
for col_order in itertools.permutations(range(5)):
    perm = []
    # Write K4 into 5 columns, read in col_order
    n_rows = (CT_LEN + 4) // 5  # 20 rows
    for c in col_order:
        for r in range(n_rows):
            idx = r * 5 + c
            if idx < CT_LEN:
                perm.append(idx)
    if len(perm) == CT_LEN:
        test_k4_perm(perm, f"colwidth5_{''.join(str(c) for c in col_order)}")

print(f"  Phase 4: {total - phase4_start} configs tested")

# ================================================================
# PHASE 5: Cross-panel key extraction
# ================================================================
print()
print("=" * 78)
print("  PHASE 5: Cross-panel key (K2 text as key for K4)")
print("=" * 78)
print()

phase5_start = total

# On the two-panel cylinder, K4 sits opposite K2 at the same rows.
# K4 row 10 cols 58-61 is opposite K2 row 10 cols 27-30
# K4 rows 11-13 cols 31-61 is opposite K2 rows 11-13 cols 0-30
# Use the K2 chars at the same (row, col_offset) as the key

for h_offset in range(W):
    key_chars = []
    for r, cyl_col, k4_idx in k4_cyl_positions:
        # Corresponding position in top half (K1K2 panel)
        top_col = (cyl_col - W + h_offset) % W  # map to top-half column
        key_char = top_grid[r][top_col]
        if key_char == '?':
            key_char = 'A'
        key_chars.append(ALPH_IDX[key_char])

    for variant in VARIANTS:
        pt = decrypt_text(CT, key_chars, variant)
        sc = score_free_fast(pt)
        if sc > THRESHOLD:
            results.append((sc, f"cross_panel_h{h_offset}", "K2_text", variant.value, pt[:60]))
            print(f"  ** SCORE {sc}: cross_panel_h{h_offset} ({variant.value}): {pt[:60]}")
        total += 1

# Also try: K1+K2 text at mirrored position (reflected across seam)
for h_offset in range(W):
    key_chars = []
    for r, cyl_col, k4_idx in k4_cyl_positions:
        # Mirror: if K4 is at col 58, mirrored is col 31-1-(58-31) = 3
        mirror_col = W - 1 - (cyl_col - W)
        mirror_col = (mirror_col + h_offset) % W
        if 0 <= mirror_col < W:
            key_char = top_grid[r][mirror_col]
        else:
            key_char = 'A'
        if key_char == '?':
            key_char = 'A'
        key_chars.append(ALPH_IDX[key_char])

    for variant in VARIANTS:
        pt = decrypt_text(CT, key_chars, variant)
        sc = score_free_fast(pt)
        if sc > THRESHOLD:
            results.append((sc, f"mirror_panel_h{h_offset}", "K2_mirror", variant.value, pt[:60]))
            print(f"  ** SCORE {sc}: mirror_panel_h{h_offset} ({variant.value}): {pt[:60]}")
        total += 1

print(f"  Phase 5: {total - phase5_start} configs tested")

# ================================================================
# PHASE 6: Seam-relative readings
# ================================================================
print()
print("=" * 78)
print("  PHASE 6: Seam-relative K4 extraction")
print("=" * 78)
print()

phase6_start = total

# The FIVE seam is at columns 30-31 (between K1K2 and K3K4)
# The other seam is at columns 61-0 (between K3K4 and K1K2)
# Try reading K4 starting from various seam-relative positions

# 6a. Spiral from FIVE seam outward
for seam_col in [31, 30, 0, 61]:
    perm = []
    visited = set()
    # Expand outward from seam
    for dist in range(CYL_W):
        for direction in [1, -1]:
            c = (seam_col + direction * dist) % CYL_W
            for r in range(CYL_H):
                if (r, c) not in visited:
                    visited.add((r, c))
                    if (r, c) in k4_map:
                        perm.append(k4_map[(r, c)])
    if len(perm) == CT_LEN:
        test_k4_perm(perm, f"spiral_from_seam{seam_col}")

# 6b. Diagonal reads crossing the FIVE seam
for slope in range(1, 14):
    for start_r in range(CYL_H):
        perm = []
        visited = set()
        r, c = start_r, 28  # Start at F of FIVE
        for _ in range(CYL_H * CYL_W):
            if (r, c) not in visited:
                visited.add((r, c))
                if (r, c) in k4_map:
                    perm.append(k4_map[(r, c)])
            c = (c + 1) % CYL_W
            r = (r + slope) % CYL_H
        if len(perm) == CT_LEN:
            test_k4_perm(perm, f"diag_seam_s{slope}_r{start_r}")

print(f"  Phase 6: {total - phase6_start} configs tested")

# ================================================================
# SUMMARY
# ================================================================
print()
print("=" * 78)
print(f"  TOTAL: {total} configurations tested")
print("=" * 78)

if results:
    results.sort(reverse=True)
    print(f"\n{len(results)} results above threshold {THRESHOLD}:")
    for sc, label, kw, var, pt in results[:20]:
        print(f"  SCORE {sc:2d}: {label} + {kw} ({var}): {pt}")
else:
    print("\nNo results above threshold.")

print("\nDONE")
