#!/usr/bin/env python3
"""Cipher panel as cylinder: Code Room clue applied to cipher text.

Cipher: cylinder reading order
Family: grille
Status: active
Keyspace: structural + decrypt tests
Last run: never
Best score: n/a

INSIGHT (Colin, 2026-03-07): The Code Room (1990) is an INSTRUCTION.
Wrap the cipher panel into a cylinder (like the tableau in Code Room).
Read it in new orders: column-first, helical, diagonal.
This produces ENTIRELY NEW ciphertext strings — potentially much longer
than 97 characters. The message may be the full 868-char cylinder reading.

On Antipodes: tableau on top, cipher on bottom. Two concentric cylinders.
The "real" ciphertext is what you read off the cipher cylinder, not the
flat left-to-right rows we've always assumed.
"""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD
from kryptos.kernel.transforms.vigenere import decrypt_text, CipherVariant
from kryptos.kernel.scoring.free_crib import score_free_fast

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA)}

GRID_W = 31
GRID_H = 28

# === BUILD THE CIPHER PANEL GRID (28×31) ===
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

# Full cipher grid: K1 + ? + K2 + ? + K3 + ? + K4 = 868 chars
FULL_CIPHER = K1_CT + "?" + K2_CT + "?" + K3_CT + "?" + CT
assert len(FULL_CIPHER) == 868, f"Length {len(FULL_CIPHER)} != 868"

# Build 28×31 grid
cipher_grid = []
for r in range(GRID_H):
    start = r * GRID_W
    row = FULL_CIPHER[start:start + GRID_W]
    cipher_grid.append(row)
    assert len(row) == GRID_W

print("=" * 78)
print("  CIPHER PANEL GRID (28 rows × 31 cols)")
print("=" * 78)
print()
print(f"     {''.join(f'{c%10}' for c in range(31))}")
for r in range(GRID_H):
    section = ""
    pos = r * GRID_W
    if pos < 63:
        section = "K1"
    elif pos < 64:
        section = "?"
    elif pos < 433:
        section = "K2"
    elif pos < 434:
        section = "?"
    elif pos < 770:
        section = "K3"
    elif pos < 771:
        section = "?"
    else:
        section = "K4"
    print(f" {r:2d}: {cipher_grid[r]}  {section}")

# === GENERATE ALL CYLINDER READINGS ===
print()
print("=" * 78)
print("  CYLINDER READINGS OF CIPHER PANEL")
print("=" * 78)

readings = {}

# 1. Row-first (standard — this is what we already have)
row_first = FULL_CIPHER
readings['row_LR'] = row_first
print(f"\n1. ROW-FIRST (standard, L→R): {len(row_first)} chars")
print(f"   First 60: {row_first[:60]}")
print(f"   Last 60:  {row_first[-60:]}")

# 2. Row-first reversed (R→L each row)
row_rl = ''
for r in range(GRID_H):
    row_rl += cipher_grid[r][::-1]
readings['row_RL'] = row_rl
print(f"\n2. ROW-FIRST REVERSED (R→L each row): {len(row_rl)} chars")
print(f"   First 60: {row_rl[:60]}")

# 3. Boustrophedon (alternating L→R and R→L)
boustro = ''
for r in range(GRID_H):
    if r % 2 == 0:
        boustro += cipher_grid[r]
    else:
        boustro += cipher_grid[r][::-1]
readings['boustro'] = boustro
print(f"\n3. BOUSTROPHEDON (alternating): {len(boustro)} chars")
print(f"   First 60: {boustro[:60]}")

# 4. Column-first (top→bottom, L→R columns)
col_tb = ''
for c in range(GRID_W):
    for r in range(GRID_H):
        col_tb += cipher_grid[r][c]
readings['col_TB_LR'] = col_tb
print(f"\n4. COLUMN-FIRST (T→B, L→R): {len(col_tb)} chars")
print(f"   First 60: {col_tb[:60]}")
print(f"   Last 60:  {col_tb[-60:]}")

# 5. Column-first (bottom→top, L→R)
col_bt = ''
for c in range(GRID_W):
    for r in range(GRID_H - 1, -1, -1):
        col_bt += cipher_grid[r][c]
readings['col_BT_LR'] = col_bt
print(f"\n5. COLUMN-FIRST (B→T, L→R): {len(col_bt)} chars")
print(f"   First 60: {col_bt[:60]}")

# 6. Column-first (T→B, R→L)
col_tb_rl = ''
for c in range(GRID_W - 1, -1, -1):
    for r in range(GRID_H):
        col_tb_rl += cipher_grid[r][c]
readings['col_TB_RL'] = col_tb_rl
print(f"\n6. COLUMN-FIRST (T→B, R→L): {len(col_tb_rl)} chars")
print(f"   First 60: {col_tb_rl[:60]}")

# 7. Column boustrophedon
col_boustro = ''
for c in range(GRID_W):
    if c % 2 == 0:
        for r in range(GRID_H):
            col_boustro += cipher_grid[r][c]
    else:
        for r in range(GRID_H - 1, -1, -1):
            col_boustro += cipher_grid[r][c]
readings['col_boustro'] = col_boustro
print(f"\n7. COLUMN BOUSTROPHEDON: {len(col_boustro)} chars")
print(f"   First 60: {col_boustro[:60]}")

# 8-12. Helical readings (various slopes)
print(f"\n8-12. HELICAL READINGS:")
for slope in [1, 2, 3, 5, 7, 9, 11, 13, 14, 15]:
    helix = ''
    visited = set()
    r, c = 0, 0
    for step in range(868):
        if (r, c) in visited:
            # Find next unvisited
            found = False
            for cc in range(GRID_W):
                for rr in range(GRID_H):
                    if (rr, cc) not in visited:
                        r, c = rr, cc
                        found = True
                        break
                if found:
                    break
            if not found:
                break
        visited.add((r, c))
        helix += cipher_grid[r][c]
        c = (c + 1) % GRID_W
        if c == 0:  # wrapped around
            r = (r + slope) % GRID_H

    if len(helix) == 868:
        readings[f'helix_s{slope}'] = helix
        print(f"   Slope {slope:2d}: {len(helix)} chars, first 50: {helix[:50]}...")

# 13. Diagonal readings
print(f"\n13. DIAGONAL READINGS:")
for slope in [1, 2, 3]:
    diag = ''
    visited = set()
    for start_c in range(GRID_W):
        r = 0
        c = start_c
        while r < GRID_H:
            if (r, c) not in visited:
                visited.add((r, c))
                diag += cipher_grid[r][c]
            r += 1
            c = (c + slope) % GRID_W
    # Fill any missed cells
    for r in range(GRID_H):
        for c in range(GRID_W):
            if (r, c) not in visited:
                visited.add((r, c))
                diag += cipher_grid[r][c]
    if len(diag) == 868:
        readings[f'diag_s{slope}'] = diag
        print(f"   Slope {slope}: {len(diag)} chars, first 50: {diag[:50]}...")

# === ANALYSIS OF EACH READING ===
print()
print("=" * 78)
print("  ANALYSIS OF CYLINDER READINGS")
print("=" * 78)

from collections import Counter
import math

for name, text in sorted(readings.items()):
    # Remove ? marks for analysis
    letters = text.replace('?', '')
    freq = Counter(letters)
    ic = sum(f * (f - 1) for f in freq.values()) / (len(letters) * (len(letters) - 1))

    # Check for cribs
    has_ene = 'EASTNORTHEAST' in letters
    has_bc = 'BERLINCLOCK' in letters

    print(f"\n  {name}: {len(text)} chars, IC={ic:.4f}, ENE={'YES' if has_ene else 'no'}, BC={'YES' if has_bc else 'no'}")

# === DECRYPT TESTS ON ALL READINGS ===
print()
print("=" * 78)
print("  DECRYPT TESTS ON CYLINDER READINGS")
print("=" * 78)
print()

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "HOROLOGE",
    "DEFECTOR", "PARALLAX", "COLOPHON", "BERLIN",
]
VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]
THRESHOLD = 8  # higher threshold for 868-char texts (more noise expected)

results = []
total = 0

for name, text in readings.items():
    # Skip ? characters — replace with A for decrypt
    clean = text.replace('?', 'A')

    for kw in KEYWORDS:
        kw_nums = [ALPH_IDX[c] for c in kw]
        for variant in VARIANTS:
            pt = decrypt_text(clean, kw_nums, variant)
            sc = score_free_fast(pt)
            if sc > THRESHOLD:
                results.append((sc, name, kw, variant.value, pt[:60]))
                print(f"  SCORE {sc:2d}: {name} + {kw} ({variant.value}): {pt[:60]}...")
            total += 1

print(f"\n  Tested {total} configurations across {len(readings)} readings × {len(KEYWORDS)} keywords × 3 variants")

# === FOCUSED K4 ZONE READINGS ===
print()
print("=" * 78)
print("  K4 ZONE CYLINDER READINGS (rows 24-27 only)")
print("=" * 78)
print()

# K4 occupies rows 24-27: row 24 cols 27-30, rows 25-27 full
# Build K4 position map
k4_positions = []
for i in range(CT_LEN):
    pos = 771 + i
    r = pos // GRID_W
    c = pos % GRID_W
    k4_positions.append((r, c, CT[i]))

k4_zone = {}  # (r,c) -> char, for the full rows 24-27
for r in range(24, 28):
    for c in range(GRID_W):
        pos = r * GRID_W + c
        k4_zone[(r, c)] = FULL_CIPHER[pos]

print(f"K4 zone: rows 24-27, all 31 cols = {4 * 31} = 124 cells")
print(f"K4 actual: 97 chars (row 24 starts at col 27)")
print()

# Column-first reading of K4 zone (124 chars)
k4z_col = ''
for c in range(GRID_W):
    for r in range(24, 28):
        k4z_col += k4_zone[(r, c)]
print(f"K4 zone column-first (124 chars): {k4z_col}")
print()

# Column-first reading of JUST K4 characters (97 chars)
k4_col = ''
for c in range(GRID_W):
    for r in range(24, 28):
        if (r, c) in dict((pos[:2], pos[2]) for pos in k4_positions):
            pass  # handled below

# Better: extract K4 chars in column order
k4_char_map = {}
for r, c, ch in k4_positions:
    k4_char_map[(r, c)] = ch

k4_col_order = ''
for c in range(GRID_W):
    for r in range(24, 28):
        if (r, c) in k4_char_map:
            k4_col_order += k4_char_map[(r, c)]
print(f"K4 column-order (97 chars): {k4_col_order}")
print()

# Also try diagonal readings of K4 zone
for slope in range(1, 31):
    k4_diag = ''
    visited = set()
    for start_c in range(GRID_W):
        c = (start_c + slope * 0) % GRID_W
        for r in range(24, 28):
            cc = (start_c + slope * (r - 24)) % GRID_W
            if (r, cc) in k4_char_map and (r, cc) not in visited:
                visited.add((r, cc))
                k4_diag += k4_char_map[(r, cc)]

    if len(k4_diag) == CT_LEN:
        for kw in KEYWORDS:
            kw_nums = [ALPH_IDX[c] for c in kw]
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt = decrypt_text(k4_diag, kw_nums, variant)
                sc = score_free_fast(pt)
                if sc > 6:
                    results.append((sc, f"k4_diag_s{slope}", kw, variant.value, pt[:50]))
                    print(f"  SCORE {sc}: k4_diag slope={slope} + {kw} ({variant.value}): {pt[:50]}...")
                total += 1

# === FULL 868-CHAR DECRYPT (column readings) ===
print()
print("=" * 78)
print("  FULL 868-CHAR COLUMN READING — DECRYPT WITH LONG KEYWORDS")
print("=" * 78)
print()

# The column-first reading is the most natural "cylinder" reading
# Try decrypting the full 868-char column reading
col_reading = readings['col_TB_LR'].replace('?', 'A')

# Try standard keywords
for kw in KEYWORDS:
    kw_nums = [ALPH_IDX[c] for c in kw]
    for variant in VARIANTS:
        pt = decrypt_text(col_reading, kw_nums, variant)
        # Check for English words anywhere in the first 200 chars
        sc = score_free_fast(pt)
        if sc > THRESHOLD:
            print(f"  SCORE {sc}: col_TB_LR + {kw} ({variant.value})")
            print(f"    PT: {pt[:80]}...")

# Try with K1/K2/K3 solutions as running key
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUABOROFLIQLUSION"  # IQLUSION
K2_PT = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFI"
    "ELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWN"
    "LOCATIONXDOESLANGABORKNOWABOUTTHISTHEYSHOULDITSBURABORIEDOUTTHER"
    "ESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEX"
    "THIRTYEABORIGHTNORTHSEVENTYSABORVENWESTXLAYERTWO"
)  # approximate
# Actually let's use the known CT and the known PT relationship
# K1 PT is 63 chars, K2 PT is 369 chars, K3 PT is 336 chars
# For a running key, we could use the full known plaintext

print()
print("=" * 78)
print("  COLUMN READING — LOOKING FOR ENGLISH IN SUBSECTIONS")
print("=" * 78)
print()

# The column-first reading of the full 868-char cipher panel
# might contain English in certain stretches when decrypted
col_text = readings['col_TB_LR']
print(f"Column reading (868 chars):")
print(f"  {col_text[:80]}")
print(f"  {col_text[80:160]}")
print(f"  ...")
print(f"  {col_text[-80:]}")
print()

# Check IC of various sections
for start in range(0, 800, 100):
    end = min(start + 100, 868)
    section = col_text[start:end].replace('?', '')
    freq = Counter(section)
    ic = sum(f * (f - 1) for f in freq.values()) / max(1, len(section) * (len(section) - 1))
    print(f"  Chars {start:3d}-{end:3d}: IC={ic:.4f} ({len(section)} chars)")

# === FULL 868 READING — WHAT DOES IT LOOK LIKE? ===
print()
print("=" * 78)
print("  EXTRACT: THE NEW CIPHERTEXT (column-first, all 868 chars)")
print("=" * 78)
print()
print("This is what you get when you read the cipher panel cylinder")
print("column-by-column (top to bottom, left to right):")
print()

col_ct = readings['col_TB_LR']
# Print in rows of 31 (same width as the grid)
for i in range(0, len(col_ct), 31):
    chunk = col_ct[i:i+31]
    print(f"  {i:3d}: {chunk}")

print()
print(f"Total: {len(col_ct)} characters")
print(f"? marks at positions: {[i for i, c in enumerate(col_ct) if c == '?']}")

# === SUMMARY ===
print()
print("=" * 78)
print("  SUMMARY")
print("=" * 78)

if results:
    results.sort(reverse=True)
    print(f"\n{len(results)} results above threshold:")
    for sc, name, kw, var, pt in results[:20]:
        print(f"  SCORE {sc:2d}: {name} + {kw} ({var}): {pt}")
else:
    print("\nNo results above threshold from automated tests.")

print(f"\nTotal configs tested: {total}")
print()
print("KEY OUTPUTS for manual analysis:")
print(f"  Column-first (TB,LR) 868 chars — the primary 'cylinder CT'")
print(f"  K4 zone column-order (97 chars): {k4_col_order}")
print(f"  K4 zone full (124 chars): {k4z_col}")
print()
print("NEXT STEPS:")
print("  1. The 868-char column reading is a NEW ciphertext nobody has tried")
print("  2. Try decrypting with longer keys or different periods")
print("  3. Look for patterns in the column reading that suggest structure")
print("  4. The 124-char K4 zone includes K3 tail — may hold extra context")
print("  5. Colin: compare your hand-extracted CT from the paper model")

print("\nDONE")
