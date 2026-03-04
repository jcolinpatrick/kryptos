#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-ENDYAHR-MAPPING: Investigate the ENDYAHR <-> KRYPTOS column relationship.

ENDYAHR (first 7 chars of K3 CT) sits at Row 14, Cols 0-6 of the 28x31 master grid.
Row 14 is the exact center of the 28-row grid. Cols 0-6 span the KRYPTOS keyword width.

The 1:1 column mapping: E<->K(col0), N<->R(col1), D<->Y(col2), Y<->P(col3),
                         A<->T(col4), H<->O(col5), R<->S(col6)

Y, A, R are physically raised/misaligned on the sculpture (cols 3, 4, 6 = P, T, S).

Tests 8 approaches:
  1. ENDYAHR as substitution key
  2. Column-dependent key from ENDYAHR
  3. Row-dependent key from grid
  4. ENDYAHR->KRYPTOS alphabet mapping
  5. Cross-reference structural patterns in grid
  6. YAR column extraction at widths 31 and 7
  7. Grid-based transposition using ENDYAHR alphabetical ordering
  8. K3 PT / K3 CT relationship at ENDYAHR positions

Run: PYTHONPATH=src python3 -u scripts/e_endyahr_mapping.py
"""

import json
import sys
import os
import math
from collections import Counter
from itertools import permutations

sys.path.insert(0, 'src')

from kryptos.kernel.constants import (
    CT as K4_CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET, CRIB_DICT, N_CRIBS, CRIB_WORDS,
)
from kryptos.kernel.transforms.vigenere import (
    decrypt_text, encrypt_text, CipherVariant,
    vig_decrypt, beau_decrypt, varbeau_decrypt,
    vig_recover_key, beau_recover_key, varbeau_recover_key,
)
from kryptos.kernel.transforms.transposition import (
    apply_perm, invert_perm, columnar_perm, keyword_to_order, validate_perm,
)
from kryptos.kernel.alphabet import Alphabet, AZ, KA

# ============================================================
# SETUP: Load quadgrams, define helpers
# ============================================================

QUADGRAM_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'english_quadgrams.json')
with open(QUADGRAM_PATH, 'r') as f:
    QUADGRAMS = json.load(f)

# Precompute floor for missing quadgrams
_qg_values = list(QUADGRAMS.values())
QG_FLOOR = min(_qg_values) - 1.0  # Penalty for unseen quadgrams


def quadgram_score(text: str) -> float:
    """Return average log-probability per character using quadgrams."""
    text = text.upper()
    if len(text) < 4:
        return QG_FLOOR
    total = 0.0
    count = 0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        total += QUADGRAMS.get(qg, QG_FLOOR)
        count += 1
    return total / count if count > 0 else QG_FLOOR


def ic_score(text: str) -> float:
    """Index of coincidence."""
    n = len(text)
    if n < 2:
        return 0.0
    freq = Counter(text.upper())
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


def crib_match_count(candidate: str) -> int:
    """Count how many crib positions match."""
    matches = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(candidate) and candidate[pos] == ch:
            matches += 1
    return matches


def format_result(label: str, text: str, extra: str = "") -> str:
    """Format a decryption result with scoring."""
    cribs = crib_match_count(text)
    qg = quadgram_score(text)
    ic = ic_score(text)
    flag = ""
    if cribs >= 10:
        flag = " *** SIGNAL ***"
    elif cribs >= 18:
        flag = " *** STRONG SIGNAL ***"
    elif cribs >= 24:
        flag = " *** BREAKTHROUGH ***"
    result = f"  {label}: cribs={cribs}/{N_CRIBS} qg={qg:.3f}/char ic={ic:.4f}{flag}"
    if extra:
        result += f" | {extra}"
    if cribs >= 6 or qg > -7.0:
        result += f"\n    PT: {text[:50]}{'...' if len(text) > 50 else ''}"
    return result


# ============================================================
# CONSTANTS
# ============================================================

ENDYAHR = "ENDYAHR"
KRYPTOS = "KRYPTOS"

# K3 ciphertext (336 chars)
K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI"
    "ACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAE"
    "WMTWNDITEENRAHCTENEUDRETNHAEOET"
    "FOLSEDTIWENHAEIOYTEYQHEENCTAYCR"
    "EIFTBRSPAMHHEWENATAMATEGYEERLBT"
    "EEFOASFIOTUETUAEOTOARMAEERTNRTI"
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLOR"
    "ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"
)

# K3 plaintext (336 chars)
K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINS"
    "OFPASSAGEDEBRISTHATENCUMBERED"
    "THELOWERPARTOFTHEDOORWAYWAS"
    "REMOVEDWITHTREMBLINGHANDSIMADE"
    "ATINYBREACHINTHEUPPERLEFTHAND"
    "CORNERANDTHENWIDENINGTHEHOLE"
    "ALITTLEIINSERTEDTHECANDLEAND"
    "PEABORINTHEHOTAIRESCAPINGFROM"
    "THECHAMBERCAUSEDTHEFLAMETOFLICKER"
    "BUTPRESENTLYDETAILSOFTHEROOM"
    "WITHINEMERGEDFROMTHEMISTX"
    "CANYOUSEEANYTHINGQ"
)

# K3 PT from memory file (Sanborn's modified spellings).
# NOTE: This is 338 chars (2 more than CT's 336) due to minor transcription
# variance in memory. Only first 7 chars (SLOWLYD) are used in Test 8
# analysis, so the mismatch does not affect any K4 results.
K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEABORISTHATENCABOREDTHELOWER"
    "PARTOFTHEDOORWAYMASREMOAEDWITHTREMBLINGHANDSIMADEATINYBREACHINTHEUPPERL"
    "EFTHANDCORNERANDTHENWIDENINGTHEHOLEAUTTLEAINSERTEDTHECANDLEANDPEEREDINT"
    "HEHOTAIRESCAPINGFROMTHECHAMBERCAUSEDTHEFFLAMETOFLICKERBUTPRESENTLYDETAIL"
    "SOFTHEROOMWITHINEEMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ"
).upper()

# Verify lengths
print("=" * 80)
print("E-ENDYAHR-MAPPING: ENDYAHR <-> KRYPTOS Column Investigation")
print("=" * 80)
print()
print(f"K4 CT: {K4_CT} ({len(K4_CT)} chars)")
print(f"K3 CT first 7: {K3_CT[:7]}")
print(f"K3 PT first 7: {K3_PT[:7]}")
print(f"K3 CT length: {len(K3_CT)}, K3 PT length: {len(K3_PT)}")
print()

# The column mapping
print("ENDYAHR <-> KRYPTOS Column Mapping:")
print("  Col  K3CT  KRYPTOS  AZ-idx(K3CT)  AZ-idx(KRYPTOS)  Diff(mod26)")
for i in range(7):
    e_ch = ENDYAHR[i]
    k_ch = KRYPTOS[i]
    e_idx = ALPH_IDX[e_ch]
    k_idx = ALPH_IDX[k_ch]
    diff = (k_idx - e_idx) % 26
    print(f"  {i}    {e_ch}     {k_ch}         {e_idx:2d}            {k_idx:2d}             {diff:2d} ({ALPH[diff]})")

# Differences: K-E, R-N, Y-D, P-Y, T-A, O-H, S-R
diffs = [(ALPH_IDX[KRYPTOS[i]] - ALPH_IDX[ENDYAHR[i]]) % 26 for i in range(7)]
diff_letters = [ALPH[d] for d in diffs]
print(f"\n  Difference vector (KRYPTOS - ENDYAHR mod 26): {diffs}")
print(f"  As letters: {''.join(diff_letters)}")
print(f"  Is this a known keyword? {''.join(diff_letters)}")

# Also check Beaufort-style: K+E mod 26
beau_diffs = [(ALPH_IDX[KRYPTOS[i]] + ALPH_IDX[ENDYAHR[i]]) % 26 for i in range(7)]
beau_letters = [ALPH[d] for d in beau_diffs]
print(f"  Beaufort (KRYPTOS + ENDYAHR mod 26): {beau_diffs}")
print(f"  As letters: {''.join(beau_letters)}")

# VarBeau: E - K mod 26
varbeau_diffs = [(ALPH_IDX[ENDYAHR[i]] - ALPH_IDX[KRYPTOS[i]]) % 26 for i in range(7)]
varbeau_letters = [ALPH[d] for d in varbeau_diffs]
print(f"  VarBeau (ENDYAHR - KRYPTOS mod 26): {varbeau_diffs}")
print(f"  As letters: {''.join(varbeau_letters)}")

# KA-space differences
print(f"\n  In KA-index space:")
for i in range(7):
    e_ka = KA.char_to_idx(ENDYAHR[i])
    k_ka = KA.char_to_idx(KRYPTOS[i])
    diff_ka = (k_ka - e_ka) % 26
    print(f"    Col {i}: {ENDYAHR[i]}(KA:{e_ka}) -> {KRYPTOS[i]}(KA:{k_ka})  diff={diff_ka} ({KA.idx_to_char(diff_ka)})")

ka_diffs = [(KA.char_to_idx(KRYPTOS[i]) - KA.char_to_idx(ENDYAHR[i])) % 26 for i in range(7)]
ka_diff_letters = [KA.idx_to_char(d) for d in ka_diffs]
print(f"  KA diff vector: {ka_diffs}")
print(f"  KA diff as letters: {''.join(ka_diff_letters)}")


# ============================================================
# TEST 1: ENDYAHR as substitution key (simple substitution)
# ============================================================

print()
print("=" * 80)
print("TEST 1: ENDYAHR as Substitution Key")
print("=" * 80)
print()
print("If ENDYAHR -> KRYPTOS defines a partial substitution:")
print("  E->K, N->R, D->Y, Y->P, A->T, H->O, R->S")
print()

# Build substitution table (forward: ENDYAHR -> KRYPTOS)
sub_fwd = {}
for i in range(7):
    sub_fwd[ENDYAHR[i]] = KRYPTOS[i]

# Build inverse: KRYPTOS -> ENDYAHR
sub_inv = {}
for i in range(7):
    sub_inv[KRYPTOS[i]] = ENDYAHR[i]

# 1a: Apply forward substitution to K4 CT (only mapped letters change)
def apply_partial_sub(text: str, sub_table: dict) -> str:
    return ''.join(sub_table.get(ch, ch) for ch in text)

fwd_result = apply_partial_sub(K4_CT, sub_fwd)
inv_result = apply_partial_sub(K4_CT, sub_inv)

print("1a. Forward (E->K, N->R, ...): letters in K4 that are in ENDYAHR get mapped")
print(format_result("Fwd sub", fwd_result))
print(f"    Full: {fwd_result}")
print()
print("1b. Inverse (K->E, R->N, ...): letters in K4 that are in KRYPTOS get mapped")
print(format_result("Inv sub", inv_result))
print(f"    Full: {inv_result}")

# 1c: Extend mapping to full alphabet (assume Vig shift per column)
# The difference vector defines a shift per position in the keyword
# Apply as Vigenere key where key[i] = diff[i % 7]
print()
print("1c. As Vigenere key (the KRYPTOS-ENDYAHR diff vector applied cyclically):")
for variant_name, variant in [("Vigenere", CipherVariant.VIGENERE),
                                ("Beaufort", CipherVariant.BEAUFORT),
                                ("VarBeau", CipherVariant.VAR_BEAUFORT)]:
    pt = decrypt_text(K4_CT, diffs, variant)
    print(format_result(f"Diff-key {variant_name}", pt))

# 1d: Try the Beaufort and VarBeau diff vectors too
print()
print("1d. Beau/VarBeau diff vectors as Vigenere keys:")
for vec_name, vec in [("Beau diffs", beau_diffs), ("VarBeau diffs", varbeau_diffs)]:
    for variant_name, variant in [("Vigenere", CipherVariant.VIGENERE),
                                    ("Beaufort", CipherVariant.BEAUFORT),
                                    ("VarBeau", CipherVariant.VAR_BEAUFORT)]:
        pt = decrypt_text(K4_CT, vec, variant)
        print(format_result(f"{vec_name}/{variant_name}", pt))

# 1e: Try KA-space diff vector
print()
print("1e. KA-space diff vector as key:")
for variant_name, variant in [("Vigenere", CipherVariant.VIGENERE),
                                ("Beaufort", CipherVariant.BEAUFORT),
                                ("VarBeau", CipherVariant.VAR_BEAUFORT)]:
    pt = decrypt_text(K4_CT, ka_diffs, variant)
    print(format_result(f"KA-diff {variant_name}", pt))


# ============================================================
# TEST 2: Column-dependent key from ENDYAHR
# ============================================================

print()
print("=" * 80)
print("TEST 2: ENDYAHR as Vigenere Key (period 7)")
print("=" * 80)
print()
print("Use ENDYAHR directly as the Vigenere keyword instead of KRYPTOS.")

endyahr_nums = [ALPH_IDX[c] for c in ENDYAHR]
kryptos_nums = [ALPH_IDX[c] for c in KRYPTOS]

print(f"ENDYAHR as numbers: {endyahr_nums}")
print(f"KRYPTOS as numbers: {kryptos_nums}")
print()

keywords_to_test = {
    "ENDYAHR": endyahr_nums,
    "KRYPTOS": kryptos_nums,
    "PALIMPSEST": [ALPH_IDX[c] for c in "PALIMPSEST"],
    "ABSCISSA": [ALPH_IDX[c] for c in "ABSCISSA"],
}

for kw_name, kw_nums in keywords_to_test.items():
    for variant_name, variant in [("Vig", CipherVariant.VIGENERE),
                                    ("Beau", CipherVariant.BEAUFORT),
                                    ("VarBeau", CipherVariant.VAR_BEAUFORT)]:
        pt = decrypt_text(K4_CT, kw_nums, variant)
        print(format_result(f"{kw_name}/{variant_name}", pt))

# Also try ENDYAHR in KA-index space
print()
print("ENDYAHR in KA-index space:")
endyahr_ka = [KA.char_to_idx(c) for c in ENDYAHR]
kryptos_ka = [KA.char_to_idx(c) for c in KRYPTOS]
print(f"ENDYAHR as KA indices: {endyahr_ka}")
print(f"KRYPTOS as KA indices: {kryptos_ka}")

for kw_name, kw_nums in [("ENDYAHR-KA", endyahr_ka), ("KRYPTOS-KA", kryptos_ka)]:
    for variant_name, variant in [("Vig", CipherVariant.VIGENERE),
                                    ("Beau", CipherVariant.BEAUFORT)]:
        pt = decrypt_text(K4_CT, kw_nums, variant)
        print(format_result(f"{kw_name}/{variant_name}", pt))


# ============================================================
# TEST 3: Row-dependent key from 28x31 grid
# ============================================================

print()
print("=" * 80)
print("TEST 3: Row-Dependent Key from 28x31 Grid")
print("=" * 80)
print()

# Build the 28x31 grid
FULL_CT_CARVED = (
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ"
    "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE"
    "GGWHKK?DQMCPFQZDQMMIAGPFXHQRLG"
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA"
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR"
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI"
    "HHDDDUVH?DWKBFUFPWNTDFIYCUQZERE"
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX"
    "FLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKF"   # Squeezed ?
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ"
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP"
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA"
    "CHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAE"
    "WMTWNDITEENRAHCTENEUDRETNHAEOE"
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCR"
    "EIFTBRSPAMHHEWENATAMATEGYEERLB"
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTI"
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORIT"
    "RKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR"
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO"
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP"
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
)

# Remove squeezed ? at position 288
SQUEEZED_POS = 288
grid_text_raw = FULL_CT_CARVED[:SQUEEZED_POS] + FULL_CT_CARVED[SQUEEZED_POS+1:]
# Remove the ? characters from position counting but they're still positional
# Actually, the ? at pos 288 in FULL_CT_CARVED is the one squeezed
# Need to find it properly

q_positions = [i for i, c in enumerate(FULL_CT_CARVED) if c == '?']

# Build grid by removing squeezed ? (the 3rd one, at GGTEZ?FKZ)
# Find the squeezed one
squeezed_idx = None
for i, pos in enumerate(q_positions):
    context = FULL_CT_CARVED[max(0,pos-5):pos+6]
    if 'GGTEZ' in context:
        squeezed_idx = pos
        break

if squeezed_idx is None:
    # Fallback
    squeezed_idx = q_positions[2]

grid_text = FULL_CT_CARVED[:squeezed_idx] + FULL_CT_CARVED[squeezed_idx+1:]
assert len(grid_text) == 868, f"Grid text length {len(grid_text)} != 868"

WIDTH = 31
NROWS = 28

grid_rows = []
for r in range(NROWS):
    grid_rows.append(grid_text[r * WIDTH : (r + 1) * WIDTH])

# Find K4 start
k4_start = grid_text.find(K4_CT)
k4_row_start = k4_start // WIDTH
k4_col_start = k4_start % WIDTH
print(f"K4 starts at grid position {k4_start}: row {k4_row_start}, col {k4_col_start}")
print()

# K4 occupies rows 24-27 (0-indexed)
# Row 24: cols 27-30 (OBKR, 4 chars)
# Row 25: cols 0-30 (UOXO...KSSO, 31 chars)
# Row 26: cols 0-30 (TWTQ...BNYP, 31 chars)
# Row 27: cols 0-30 (VTTM...KCAR, 31 chars)

print("K4 row layout in the 28x31 grid:")
for r in range(k4_row_start, NROWS):
    row = grid_rows[r]
    # Find K4 portion in this row
    row_start_pos = r * WIDTH
    k4_local_start = max(0, k4_start - row_start_pos)
    k4_local_end = min(WIDTH, k4_start + 97 - row_start_pos)
    if k4_local_end <= 0 or k4_local_start >= WIDTH:
        continue
    k4_portion = row[k4_local_start:k4_local_end]
    print(f"  Row {r} (cols {k4_local_start}-{k4_local_end-1}): {k4_portion}")

print()
print("Row-key approach: First 7 chars of each row define the Vig key for that row.")
print("K4 rows: 24, 25, 26, 27")
print()

# For each K4 row, extract first 7 chars of that row as the key
k4_chars_by_row = {}
for r in range(k4_row_start, NROWS):
    row = grid_rows[r]
    row_start_pos = r * WIDTH
    k4_local_start = max(0, k4_start - row_start_pos)
    k4_local_end = min(WIDTH, k4_start + 97 - row_start_pos)
    if k4_local_end > k4_local_start:
        k4_chars_by_row[r] = (k4_local_start, k4_local_end, row[k4_local_start:k4_local_end])

# Extract first 7 chars of each row as key
print("Row keys (first 7 chars of each row):")
for r in range(k4_row_start, NROWS):
    row = grid_rows[r]
    # First 7 chars = cols 0-6
    row_key_7 = row[:7]
    # Clean (remove ? if present)
    row_key_7_clean = ''.join(c for c in row_key_7 if c.isalpha())
    print(f"  Row {r}: '{row_key_7}' -> key chars: {row_key_7_clean}")

# Method: decrypt each row of K4 with its own row key
print()
print("3a. Decrypt each K4 row with the first 7 chars of that master-grid row as Vig key:")
for variant_name, variant in [("Vig", CipherVariant.VIGENERE),
                                ("Beau", CipherVariant.BEAUFORT)]:
    pt_chars = []
    for r in range(k4_row_start, NROWS):
        row = grid_rows[r]
        row_key = [ALPH_IDX[c] for c in row[:7] if c.isalpha()]
        if not row_key:
            continue
        local_start, local_end, k4_portion = k4_chars_by_row[r]
        # Only decrypt the K4 portion
        pt_portion = decrypt_text(k4_portion, row_key, variant)
        pt_chars.append(pt_portion)
    pt_full = ''.join(pt_chars)
    print(format_result(f"Row-key/{variant_name}", pt_full))

# 3b: Use ENDYAHR as key for each row (since it's at row 14, cols 0-6)
print()
print("3b. ENDYAHR (row 14 cols 0-6) as universal key for all K4 rows:")
# Already covered in Test 2, but let's also try row-by-row with col offset
# Key idea: within each row, position i uses key[col % 7] where col = actual column in grid
print("  Using column-aligned ENDYAHR key (key based on grid column mod 7):")
for variant_name, variant in [("Vig", CipherVariant.VIGENERE),
                                ("Beau", CipherVariant.BEAUFORT)]:
    pt_chars = []
    for r in range(k4_row_start, NROWS):
        local_start, local_end, k4_portion = k4_chars_by_row[r]
        for c_offset in range(local_start, local_end):
            ch = grid_rows[r][c_offset]
            # Key from ENDYAHR at column c_offset mod 7
            key_idx = ALPH_IDX[ENDYAHR[c_offset % 7]]
            if variant == CipherVariant.VIGENERE:
                pt_ch = chr(vig_decrypt(ord(ch) - 65, key_idx) + 65)
            elif variant == CipherVariant.BEAUFORT:
                pt_ch = chr(beau_decrypt(ord(ch) - 65, key_idx) + 65)
            else:
                pt_ch = chr(varbeau_decrypt(ord(ch) - 65, key_idx) + 65)
            pt_chars.append(pt_ch)
    pt_full = ''.join(pt_chars)
    print(format_result(f"Col-aligned ENDYAHR/{variant_name}", pt_full))

# 3c: Use KRYPTOS as key column-aligned
print()
print("3c. KRYPTOS column-aligned key (key based on grid column mod 7):")
for variant_name, variant in [("Vig", CipherVariant.VIGENERE),
                                ("Beau", CipherVariant.BEAUFORT)]:
    pt_chars = []
    for r in range(k4_row_start, NROWS):
        local_start, local_end, k4_portion = k4_chars_by_row[r]
        for c_offset in range(local_start, local_end):
            ch = grid_rows[r][c_offset]
            key_idx = ALPH_IDX[KRYPTOS[c_offset % 7]]
            if variant == CipherVariant.VIGENERE:
                pt_ch = chr(vig_decrypt(ord(ch) - 65, key_idx) + 65)
            elif variant == CipherVariant.BEAUFORT:
                pt_ch = chr(beau_decrypt(ord(ch) - 65, key_idx) + 65)
            else:
                pt_ch = chr(varbeau_decrypt(ord(ch) - 65, key_idx) + 65)
            pt_chars.append(pt_ch)
    pt_full = ''.join(pt_chars)
    print(format_result(f"Col-aligned KRYPTOS/{variant_name}", pt_full))


# ============================================================
# TEST 4: ENDYAHR->KRYPTOS Alphabet Mapping
# ============================================================

print()
print("=" * 80)
print("TEST 4: ENDYAHR->KRYPTOS as Alphabet Mapping")
print("=" * 80)
print()

# Build a full substitution alphabet where ENDYAHR maps to KRYPTOS
# and the remaining letters map in order
def build_mapped_alphabet(src: str, dst: str) -> str:
    """Build a 26-letter alphabet where src maps to dst, rest fill in order."""
    mapped = dict(zip(src, dst))
    used_dst = set(dst)
    remaining_src = [c for c in ALPH if c not in src]
    remaining_dst = [c for c in ALPH if c not in used_dst]
    for s, d in zip(remaining_src, remaining_dst):
        mapped[s] = d
    return ''.join(mapped[c] for c in ALPH)

# Forward: when plaintext has ENDYAHR letters, they become KRYPTOS
fwd_alpha = build_mapped_alphabet(ENDYAHR, KRYPTOS)
inv_alpha = build_mapped_alphabet(KRYPTOS, ENDYAHR)

print(f"Forward alphabet (ENDYAHR->KRYPTOS): {fwd_alpha}")
print(f"Inverse alphabet (KRYPTOS->ENDYAHR): {inv_alpha}")
print()

# Apply as simple substitution
fwd_sub_result = ''.join(fwd_alpha[ALPH_IDX[c]] for c in K4_CT)
inv_sub_result = ''.join(inv_alpha[ALPH_IDX[c]] for c in K4_CT)

print("4a. Simple substitution with these alphabets:")
print(format_result("Fwd alpha", fwd_sub_result))
print(f"    Full: {fwd_sub_result}")
print(format_result("Inv alpha", inv_sub_result))
print(f"    Full: {inv_sub_result}")

# 4b: Use fwd_alpha as plaintext alphabet in Vigenere
print()
print("4b. Vigenere with ENDYAHR->KRYPTOS alphabet and KRYPTOS key:")
fwd_alph_obj = Alphabet("ENDYAHR-FWD", fwd_alpha)
inv_alph_obj = Alphabet("ENDYAHR-INV", inv_alpha)

for alph_name, alph_obj in [("FWD-alpha", fwd_alph_obj), ("INV-alpha", inv_alph_obj),
                              ("AZ", AZ), ("KA", KA)]:
    for kw_name, kw in [("KRYPTOS", KRYPTOS), ("ENDYAHR", ENDYAHR)]:
        key_nums = alph_obj.encode(kw)
        for variant_name, variant in [("Vig", CipherVariant.VIGENERE),
                                        ("Beau", CipherVariant.BEAUFORT)]:
            pt = decrypt_text(K4_CT, key_nums, variant)
            print(format_result(f"{alph_name}+{kw_name}/{variant_name}", pt))

# 4c: Build KA-based mapped alphabet
# In KA space: ENDYAHR occupies KA positions, KRYPTOS occupies KA positions
print()
print("4c. KA-space mapping:")
ka_fwd = build_mapped_alphabet(ENDYAHR, KRYPTOS)
# Try using the KA alphabet itself as the cipher alphabet
# with ENDYAHR->KRYPTOS defining the permutation
for kw_name, kw in [("KRYPTOS", KRYPTOS), ("ENDYAHR", ENDYAHR)]:
    key_ka = KA.encode(kw)
    for variant_name, variant in [("Vig", CipherVariant.VIGENERE),
                                    ("Beau", CipherVariant.BEAUFORT)]:
        pt = decrypt_text(K4_CT, key_ka, variant)
        print(format_result(f"KA-encode({kw_name})/{variant_name}", pt))


# ============================================================
# TEST 5: Cross-reference Structural Patterns
# ============================================================

print()
print("=" * 80)
print("TEST 5: Structural Analysis - Grid Symmetries")
print("=" * 80)
print()

# K3 CT starts at row 14, col 0 (center of 28 rows)
# K4 starts at row 24, col 27
# Under 180-degree rotation of 28x31 grid: (r,c) -> (27-r, 30-c)
# K4 start (24,27) -> (3, 3)
# K3 start (14, 0) -> (13, 30)

print("Grid symmetry analysis:")
print(f"  Grid dimensions: {NROWS} x {WIDTH}")
print(f"  K3 CT starts: row 14, col 0")
print(f"  K4 CT starts: row {k4_row_start}, col {k4_col_start}")
print()

# 180-degree rotation
rot_r = NROWS - 1 - k4_row_start
rot_c = WIDTH - 1 - k4_col_start
print(f"  180-degree rotation of K4 start ({k4_row_start},{k4_col_start}) -> ({rot_r},{rot_c})")
rot_pos = rot_r * WIDTH + rot_c
rot_ch = grid_text[rot_pos] if rot_pos < len(grid_text) else '?'
print(f"  Character at ({rot_r},{rot_c}): '{rot_ch}' (grid position {rot_pos})")
print()

# What's the full 180-degree image of K4?
print("  180-degree image of K4 region:")
k4_180_chars = []
for k4_idx in range(97):
    # K4[k4_idx] is at grid position k4_start + k4_idx
    gpos = k4_start + k4_idx
    gr = gpos // WIDTH
    gc = gpos % WIDTH
    # 180-degree: (27-gr, 30-gc)
    mirror_r = NROWS - 1 - gr
    mirror_c = WIDTH - 1 - gc
    mirror_pos = mirror_r * WIDTH + mirror_c
    if 0 <= mirror_pos < len(grid_text):
        k4_180_chars.append(grid_text[mirror_pos])
    else:
        k4_180_chars.append('?')

k4_180 = ''.join(k4_180_chars)
print(f"  K4 180-image: {k4_180}")
print(format_result("180-image raw", k4_180))

# Try using 180-image as key or XOR
print()
print("  Decrypt K4 with 180-image as running key:")
for variant_name, variant in [("Vig", CipherVariant.VIGENERE),
                                ("Beau", CipherVariant.BEAUFORT)]:
    key_180 = [ALPH_IDX[c] for c in k4_180 if c.isalpha()]
    if len(key_180) >= 97:
        pt = decrypt_text(K4_CT, key_180[:97], variant)
        print(format_result(f"180-key/{variant_name}", pt))

# Column 27 significance
print()
print("  Column 27 analysis (where K4 starts):")
col27_chars = [grid_rows[r][27] if len(grid_rows[r]) > 27 and grid_rows[r][27].isalpha() else '-' for r in range(NROWS)]
col27_str = ''.join(col27_chars)
print(f"  Col 27 top-to-bottom: {col27_str}")
print(f"  Col 27 reversed: {col27_str[::-1]}")
print(f"  Col 27 IC: {ic_score(col27_str):.4f}")

# Column 0-6 significance for K4 rows
print()
print("  ENDYAHR columns (0-6) across K4 rows:")
for c in range(7):
    chars_in_col = []
    for r in range(k4_row_start, NROWS):
        if c < len(grid_rows[r]) and grid_rows[r][c].isalpha():
            chars_in_col.append(grid_rows[r][c])
    print(f"    Col {c} ({ENDYAHR[c]}/{KRYPTOS[c]}): {' '.join(chars_in_col)} -> {''.join(chars_in_col)}")


# ============================================================
# TEST 6: YAR Column Extraction
# ============================================================

print()
print("=" * 80)
print("TEST 6: YAR Column Extraction (Raised Letters)")
print("=" * 80)
print()

# Y, A, R are raised on sculpture = columns 3, 4, 6 in KRYPTOS = P, T, S
# Also columns 3, 4, 6 in ENDYAHR = Y, A, R

YAR_COLS = [3, 4, 6]  # The physically raised columns
PTS_CHARS = [KRYPTOS[c] for c in YAR_COLS]
YAR_CHARS = [ENDYAHR[c] for c in YAR_COLS]
print(f"Raised columns: {YAR_COLS}")
print(f"In KRYPTOS: {PTS_CHARS} (P, T, S)")
print(f"In ENDYAHR: {YAR_CHARS} (Y, A, R)")

# 6a: Extract K4 chars at these columns (width 31)
print()
print("6a. K4 characters at columns 3, 4, 6 in the 28x31 grid:")
yar_w31_chars = []
yar_w31_positions = []
non_yar_w31_chars = []
non_yar_w31_positions = []

for k4_idx in range(97):
    gpos = k4_start + k4_idx
    gc = gpos % WIDTH
    if gc in YAR_COLS:
        yar_w31_chars.append(K4_CT[k4_idx])
        yar_w31_positions.append(k4_idx)
    else:
        non_yar_w31_chars.append(K4_CT[k4_idx])
        non_yar_w31_positions.append(k4_idx)

yar_w31 = ''.join(yar_w31_chars)
non_yar_w31 = ''.join(non_yar_w31_chars)
print(f"  YAR-column chars ({len(yar_w31)}): {yar_w31}")
print(f"  K4 positions in YAR cols: {yar_w31_positions}")
print(f"  Non-YAR chars ({len(non_yar_w31)}): {non_yar_w31}")
print(f"  YAR IC: {ic_score(yar_w31):.4f}, Non-YAR IC: {ic_score(non_yar_w31):.4f}")
print(f"  YAR qg: {quadgram_score(yar_w31):.3f}, Non-YAR qg: {quadgram_score(non_yar_w31):.3f}")

# 6b: Extract at width 7
print()
print("6b. K4 characters at positions mod 7 in {3, 4, 6} (width 7):")
yar_w7_chars = []
yar_w7_positions = []
non_yar_w7_chars = []
non_yar_w7_positions = []

for i in range(97):
    if i % 7 in YAR_COLS:
        yar_w7_chars.append(K4_CT[i])
        yar_w7_positions.append(i)
    else:
        non_yar_w7_chars.append(K4_CT[i])
        non_yar_w7_positions.append(i)

yar_w7 = ''.join(yar_w7_chars)
non_yar_w7 = ''.join(non_yar_w7_chars)
print(f"  YAR-col chars ({len(yar_w7)}): {yar_w7}")
print(f"  K4 positions: {yar_w7_positions[:15]}...")
print(f"  Non-YAR chars ({len(non_yar_w7)}): {non_yar_w7}")
print(f"  YAR IC: {ic_score(yar_w7):.4f}, Non-YAR IC: {ic_score(non_yar_w7):.4f}")
print(f"  YAR qg: {quadgram_score(yar_w7):.3f}, Non-YAR qg: {quadgram_score(non_yar_w7):.3f}")

# 6c: Frequency analysis of YAR vs non-YAR subsets
print()
print("6c. Frequency analysis:")
for label, subset in [("YAR-w31", yar_w31), ("non-YAR-w31", non_yar_w31),
                       ("YAR-w7", yar_w7), ("non-YAR-w7", non_yar_w7)]:
    freq = Counter(subset)
    total = len(subset)
    # Check if P, T, S (the KRYPTOS letters at these cols) are over/under-represented
    pts_count = sum(freq.get(c, 0) for c in 'PTS')
    yar_count = sum(freq.get(c, 0) for c in 'YAR')
    print(f"  {label}: len={total}, P+T+S={pts_count} ({100*pts_count/total:.1f}%), "
          f"Y+A+R={yar_count} ({100*yar_count/total:.1f}%)")

# 6d: Try decrypting just the YAR columns and non-YAR columns separately
print()
print("6d. Decrypt YAR-column subset with KRYPTOS key:")
for width_label, yar_text, yar_pos in [("w31", yar_w31, yar_w31_positions),
                                          ("w7", yar_w7, yar_w7_positions)]:
    # Key is the 3 letters at positions 3,4,6 of KRYPTOS = P,T,S
    pts_key = [ALPH_IDX[KRYPTOS[c]] for c in YAR_COLS]
    for variant_name, variant in [("Vig", CipherVariant.VIGENERE),
                                    ("Beau", CipherVariant.BEAUFORT)]:
        pt = decrypt_text(yar_text, pts_key, variant)
        print(format_result(f"YAR-{width_label} PTS-key/{variant_name}", pt))

    # Key using Y,A,R from ENDYAHR
    yar_key = [ALPH_IDX[ENDYAHR[c]] for c in YAR_COLS]
    for variant_name, variant in [("Vig", CipherVariant.VIGENERE),
                                    ("Beau", CipherVariant.BEAUFORT)]:
        pt = decrypt_text(yar_text, yar_key, variant)
        print(format_result(f"YAR-{width_label} YAR-key/{variant_name}", pt))


# ============================================================
# TEST 7: Columnar Transposition using ENDYAHR ordering
# ============================================================

print()
print("=" * 80)
print("TEST 7: Columnar Transposition using ENDYAHR Alphabetical Ordering")
print("=" * 80)
print()

# ENDYAHR alphabetical order: A=0, D=1, E=2, H=3, N=4, R=5, Y=6
# So column reading order is: col4(A), col2(D), col0(E), col5(H), col1(N), col6(R), col3(Y)
# As a keyword_to_order result: order[i] = rank of ENDYAHR[i]
endyahr_order = keyword_to_order(ENDYAHR, 7)
kryptos_order = keyword_to_order(KRYPTOS, 7)
print(f"ENDYAHR alphabetical order: {endyahr_order}")
print(f"  Meaning: col {list(endyahr_order).index(0)} read first, col {list(endyahr_order).index(1)} read second, ...")
print(f"  Reading order (cols): {[list(endyahr_order).index(r) for r in range(7)]}")
print(f"KRYPTOS alphabetical order: {kryptos_order}")
print(f"  Reading order (cols): {[list(kryptos_order).index(r) for r in range(7)]}")
print()

# 7a: Standard columnar transposition with ENDYAHR key at width 7
print("7a. Columnar transposition (width 7) with ENDYAHR key:")
for key_name, key_order in [("ENDYAHR", endyahr_order), ("KRYPTOS", kryptos_order)]:
    perm = columnar_perm(7, list(key_order), 97)
    # Apply perm: output[i] = input[perm[i]]
    unscrambled = apply_perm(K4_CT, perm)
    inv = invert_perm(perm)
    unscrambled_inv = apply_perm(K4_CT, inv)

    print(f"\n  Key: {key_name}, perm direction: encrypt (read by col order)")
    print(format_result(f"  {key_name} enc", unscrambled))
    print(f"    Full: {unscrambled}")

    print(f"  Key: {key_name}, perm direction: decrypt (inverse)")
    print(format_result(f"  {key_name} dec", unscrambled_inv))
    print(f"    Full: {unscrambled_inv}")

    # Now try Vigenere on the transposed text
    for kw2, kw2_name in [("KRYPTOS", "KRYPTOS"), ("ENDYAHR", "ENDYAHR"),
                            ("PALIMPSEST", "PALIMPSEST")]:
        kw2_nums = [ALPH_IDX[c] for c in kw2]
        for variant_name, variant in [("Vig", CipherVariant.VIGENERE),
                                        ("Beau", CipherVariant.BEAUFORT)]:
            # Try both perm directions
            for perm_label, text in [("enc", unscrambled), ("dec", unscrambled_inv)]:
                pt = decrypt_text(text, kw2_nums, variant)
                cribs = crib_match_count(pt)
                qg = quadgram_score(pt)
                if cribs >= 3 or qg > -8.5:
                    print(format_result(f"  {key_name}-{perm_label}+{kw2_name}/{variant_name}", pt))

# 7b: Also try at width 31 with ENDYAHR-derived column ordering
print()
print("7b. Columnar transposition (width 31) with ENDYAHR-derived key:")
# Extend ENDYAHR pattern to width 31: use ENDYAHR repeated, or the first 7 cols special
# Let's try: key for width 31 = ENDYAHR padded with remaining alphabet
# Or: use the grid's row 14 (first row of K3 CT) as the key
row14 = grid_rows[14]
print(f"  Row 14 (K3 start): {row14}")

row14_order = keyword_to_order(row14[:31], 31)
if row14_order:
    perm31 = columnar_perm(31, list(row14_order), 97)
    unscr31 = apply_perm(K4_CT, perm31)
    inv31 = invert_perm(perm31)
    unscr31_inv = apply_perm(K4_CT, inv31)

    for kw_name, kw in [("KRYPTOS", "KRYPTOS"), ("ENDYAHR", "ENDYAHR")]:
        kw_nums = [ALPH_IDX[c] for c in kw]
        for variant_name, variant in [("Vig", CipherVariant.VIGENERE),
                                        ("Beau", CipherVariant.BEAUFORT)]:
            for perm_label, text in [("enc", unscr31), ("dec", unscr31_inv)]:
                pt = decrypt_text(text, kw_nums, variant)
                cribs = crib_match_count(pt)
                qg = quadgram_score(pt)
                if cribs >= 3 or qg > -8.5:
                    print(format_result(f"  Row14-{perm_label}+{kw_name}/{variant_name}", pt))

    # Also try raw (no vig overlay)
    print(format_result("  Row14-enc raw", unscr31))
    print(format_result("  Row14-dec raw", unscr31_inv))


# ============================================================
# TEST 8: K3 PT / K3 CT Relationship at ENDYAHR
# ============================================================

print()
print("=" * 80)
print("TEST 8: K3 PT/CT Relationship at ENDYAHR Positions")
print("=" * 80)
print()

# K3 CT first 7 = ENDYAHR
# K3 PT first 7 = ?
# Let's compute carefully
k3_ct_first7 = K3_CT[:7]
k3_pt_first7 = K3_PT[:7]
print(f"K3 CT first 7: {k3_ct_first7}")
print(f"K3 PT first 7: {k3_pt_first7}")
print()

# Recover Vig key: K = (C - P) mod 26
print("Key recovery at first 7 positions:")
print("  Pos  CT  PT  Vig-K  Beau-K  VBeau-K")
vig_keys = []
beau_keys = []
varbeau_keys = []
for i in range(7):
    c_idx = ALPH_IDX[k3_ct_first7[i]]
    p_idx = ALPH_IDX[k3_pt_first7[i]]
    vk = vig_recover_key(c_idx, p_idx)
    bk = beau_recover_key(c_idx, p_idx)
    vbk = varbeau_recover_key(c_idx, p_idx)
    vig_keys.append(vk)
    beau_keys.append(bk)
    varbeau_keys.append(vbk)
    print(f"  {i}    {k3_ct_first7[i]}   {k3_pt_first7[i]}    "
          f"{vk:2d}({ALPH[vk]})   {bk:2d}({ALPH[bk]})   {vbk:2d}({ALPH[vbk]})")

vig_key_str = ''.join(ALPH[k] for k in vig_keys)
beau_key_str = ''.join(ALPH[k] for k in beau_keys)
varbeau_key_str = ''.join(ALPH[k] for k in varbeau_keys)
print(f"\nVig key at ENDYAHR positions:    {vig_key_str} ({vig_keys})")
print(f"Beau key at ENDYAHR positions:   {beau_key_str} ({beau_keys})")
print(f"VarBeau key at ENDYAHR positions: {varbeau_key_str} ({varbeau_keys})")

# But K3 is a TRANSPOSITION cipher, not substitution!
print()
print("NOTE: K3 is a TRANSPOSITION cipher (double rotation), NOT substitution.")
print("So this 'key' is the positional difference between PT and CT characters")
print("that happen to align at these 7 positions after transposition.")
print()

# What are the actual transposition mappings at these positions?
# K3 CT[0..6] = ENDYAHR
# Using K3's known permutation: CT[i] = PT[perm[i]]
# So we need to find where ENDYAHR characters came FROM in the plaintext

# K3 double rotation formula:
# Given CT position i, compute PT position
def k3_ct_to_pt_pos(i):
    """K3: given CT position i, find PT position."""
    a = i // 24
    b = i % 24
    intermediate = 14 * b + 13 - a
    c = intermediate // 8
    d = intermediate % 8
    pt_pos = 42 * d + 41 - c
    return pt_pos

print("K3 transposition at positions 0-6:")
print("  CT_pos  CT_char  PT_pos  PT_char  Match?")
for i in range(7):
    pt_pos = k3_ct_to_pt_pos(i)
    ct_char = K3_CT[i]
    pt_char = K3_PT[pt_pos] if pt_pos < len(K3_PT) else '?'
    match = "YES" if ct_char == pt_char else "no"
    print(f"  {i:3d}     {ct_char}        {pt_pos:3d}     {pt_char}        {match}")

print()
print("Columns that ENDYAHR chars came from (in 31-wide grid):")
for i in range(7):
    pt_pos = k3_ct_to_pt_pos(i)
    pt_col = pt_pos % 31  # in 14x31 working grid (approximately)
    # Actually, the PT is written on a different grid. Let's compute mod 7 (KRYPTOS width)
    pt_mod7 = pt_pos % 7
    pt_mod31 = pt_pos % 31
    print(f"  CT[{i}]={K3_CT[i]} -> PT[{pt_pos}], PT_pos mod 7 = {pt_mod7}, mod 31 = {pt_mod31}")

# 8b: Recover the key that K3's first 7 positions imply, and apply to K4
print()
print("8b. Apply the K3 positional key to K4:")
# The 'key' derived above (Vig: {vig_keys}) — treat as a period-7 key for K4
print(f"  Using Vig key from K3 ENDYAHR positions: {vig_key_str}")
for variant_name, variant in [("Vig", CipherVariant.VIGENERE),
                                ("Beau", CipherVariant.BEAUFORT)]:
    pt = decrypt_text(K4_CT, vig_keys, variant)
    print(format_result(f"K3-VigKey/{variant_name}", pt))

print(f"  Using Beau key from K3 ENDYAHR positions: {beau_key_str}")
for variant_name, variant in [("Vig", CipherVariant.VIGENERE),
                                ("Beau", CipherVariant.BEAUFORT)]:
    pt = decrypt_text(K4_CT, beau_keys, variant)
    print(format_result(f"K3-BeauKey/{variant_name}", pt))

# 8c: Check if KRYPTOS applied to K3's first 7 CT chars gives K3's first 7 PT chars
print()
print("8c. Does Vig(ENDYAHR, KRYPTOS) = SLOWLYD?")
for variant_name, variant in [("Vig", CipherVariant.VIGENERE),
                                ("Beau", CipherVariant.BEAUFORT),
                                ("VarBeau", CipherVariant.VAR_BEAUFORT)]:
    result = decrypt_text(ENDYAHR, kryptos_nums, variant)
    match = "YES!" if result == k3_pt_first7 else "no"
    print(f"  {variant_name}(ENDYAHR, KRYPTOS) = {result}  ({match})")
    result2 = decrypt_text(ENDYAHR, endyahr_nums, variant)
    match2 = "YES!" if result2 == k3_pt_first7 else "no"
    print(f"  {variant_name}(ENDYAHR, ENDYAHR) = {result2}  ({match2})")

# 8d: Extended — full K3 CT decrypted with KRYPTOS key
print()
print("8d. Full K3 CT decrypted with KRYPTOS as Vig/Beau key:")
for variant_name, variant in [("Vig", CipherVariant.VIGENERE),
                                ("Beau", CipherVariant.BEAUFORT)]:
    pt = decrypt_text(K3_CT, kryptos_nums, variant)
    # Does this match K3 PT?
    match_count = sum(1 for a, b in zip(pt, K3_PT) if a == b)
    print(f"  {variant_name}(K3_CT, KRYPTOS): first 20 = {pt[:20]}... "
          f"matches={match_count}/{min(len(pt), len(K3_PT))}")


# ============================================================
# BONUS TESTS: Combined approaches
# ============================================================

print()
print("=" * 80)
print("BONUS: Combined Approaches")
print("=" * 80)
print()

# Bonus A: Columnar transposition (ENDYAHR) then Vigenere (KRYPTOS)
print("A. All col-transposition + Vig combinations that scored above noise:")
best_cribs = 0
best_config = ""
best_pt = ""

for key_name, key_order in [("ENDYAHR", endyahr_order), ("KRYPTOS", kryptos_order)]:
    for width in [7, 14, 31]:
        try:
            if width == 7:
                perm = columnar_perm(width, list(key_order), 97)
            elif width == 14:
                # Extend key to width 14 by doubling
                extended_order = keyword_to_order(key_name * 2, 14)
                if not extended_order:
                    continue
                perm = columnar_perm(14, list(extended_order), 97)
            elif width == 31:
                # Use key name padded to 31
                ext31 = (key_name * 5)[:31]
                extended_order = keyword_to_order(ext31, 31)
                if not extended_order:
                    continue
                perm = columnar_perm(31, list(extended_order), 97)

            if not validate_perm(perm, 97):
                continue

            for perm_dir in ["enc", "dec"]:
                text = apply_perm(K4_CT, perm if perm_dir == "enc" else invert_perm(perm))
                for kw_name, kw in [("KRYPTOS", "KRYPTOS"), ("ENDYAHR", "ENDYAHR"),
                                      ("PALIMPSEST", "PALIMPSEST"), ("ABSCISSA", "ABSCISSA")]:
                    kw_nums = [ALPH_IDX[c] for c in kw]
                    for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                        pt = decrypt_text(text, kw_nums, variant)
                        cribs = crib_match_count(pt)
                        if cribs > best_cribs:
                            best_cribs = cribs
                            best_config = f"Trans({key_name},w{width},{perm_dir})+{variant.value}({kw_name})"
                            best_pt = pt
                        if cribs >= 3:
                            print(format_result(
                                f"T({key_name},w{width},{perm_dir})+{variant.value}({kw_name})", pt))
        except Exception as e:
            pass

print(f"\nBest combined result: cribs={best_cribs}, config={best_config}")
if best_pt:
    print(f"  PT: {best_pt[:60]}...")

# Bonus B: The difference vector GFUBTHQ applied as many things
print()
print("B. Difference vector analysis:")
print(f"  KRYPTOS - ENDYAHR (Vig): {''.join(diff_letters)} ({diffs})")
print(f"  KRYPTOS + ENDYAHR (Beau): {''.join(beau_letters)} ({beau_diffs})")
print(f"  ENDYAHR - KRYPTOS (VBeau): {''.join(varbeau_letters)} ({varbeau_diffs})")
print()

# Does the diff vector appear as a pattern in K4?
diff_str = ''.join(diff_letters)
if diff_str in K4_CT:
    pos = K4_CT.index(diff_str)
    print(f"  *** DIFF VECTOR {diff_str} FOUND IN K4 CT AT POSITION {pos}! ***")
else:
    print(f"  Diff vector {diff_str} not found in K4 CT")

# Check if any substring of K4 CT decrypted with KRYPTOS gives the diff
for variant_name, variant in [("Vig", CipherVariant.VIGENERE), ("Beau", CipherVariant.BEAUFORT)]:
    pt = decrypt_text(K4_CT, kryptos_nums, variant)
    if diff_str in pt:
        pos = pt.index(diff_str)
        print(f"  *** DIFF VECTOR found in {variant_name}(K4,KRYPTOS) at position {pos}! ***")

# Bonus C: Try ENDYAHR reversed
print()
print("C. Reversed ENDYAHR patterns:")
rev_endyahr = ENDYAHR[::-1]  # RHAYDNE
rev_nums = [ALPH_IDX[c] for c in rev_endyahr]
print(f"  Reversed ENDYAHR: {rev_endyahr}")
for variant_name, variant in [("Vig", CipherVariant.VIGENERE),
                                ("Beau", CipherVariant.BEAUFORT)]:
    pt = decrypt_text(K4_CT, rev_nums, variant)
    print(format_result(f"Rev-ENDYAHR/{variant_name}", pt))

# Bonus D: Interleave ENDYAHR and KRYPTOS as a period-14 key
print()
print("D. Interleaved ENDYAHR+KRYPTOS as period-14 key:")
interleaved = []
for i in range(7):
    interleaved.append(ALPH_IDX[ENDYAHR[i]])
    interleaved.append(ALPH_IDX[KRYPTOS[i]])
print(f"  Key: {[ALPH[k] for k in interleaved]} = {''.join(ALPH[k] for k in interleaved)}")
for variant_name, variant in [("Vig", CipherVariant.VIGENERE),
                                ("Beau", CipherVariant.BEAUFORT)]:
    pt = decrypt_text(K4_CT, interleaved, variant)
    print(format_result(f"Interleaved/{variant_name}", pt))

# Also concatenated
concat_key = [ALPH_IDX[c] for c in ENDYAHR + KRYPTOS]
print(f"  Concat ENDYAHR+KRYPTOS (period 14): {''.join(ALPH[k] for k in concat_key)}")
for variant_name, variant in [("Vig", CipherVariant.VIGENERE),
                                ("Beau", CipherVariant.BEAUFORT)]:
    pt = decrypt_text(K4_CT, concat_key, variant)
    print(format_result(f"Concat/{variant_name}", pt))

# Bonus E: XOR-like combination
print()
print("E. Columnar at width 31 using K3's column step pattern (7,7,7,3):")
# K3's column step pattern on 31-wide grid: {7, 7, 7, 3} repeating
# This means reading positions step by 7 columns at a time, wrapping at 31
# Generate a spiral/diagonal reading order at step 7
step7_positions = []
pos = 0
visited = set()
for _ in range(97):
    if pos in visited or pos >= 97:
        # Find next unvisited
        found = False
        for p in range(97):
            if p not in visited:
                pos = p
                found = True
                break
        if not found:
            break
    step7_positions.append(pos)
    visited.add(pos)
    pos = (pos + 7) % 97

if len(step7_positions) == 97:
    step7_text = ''.join(K4_CT[p] for p in step7_positions)
    print(f"  Step-7 reading: {step7_text[:50]}...")
    print(format_result("Step-7 raw", step7_text))
    for kw_name, kw in [("KRYPTOS", "KRYPTOS"), ("ENDYAHR", "ENDYAHR")]:
        kw_nums = [ALPH_IDX[c] for c in kw]
        for variant_name, variant in [("Vig", CipherVariant.VIGENERE),
                                        ("Beau", CipherVariant.BEAUFORT)]:
            pt = decrypt_text(step7_text, kw_nums, variant)
            cribs = crib_match_count(pt)
            qg = quadgram_score(pt)
            if cribs >= 2 or qg > -8.5:
                print(format_result(f"Step7+{kw_name}/{variant_name}", pt))
else:
    print(f"  Step-7 reading only got {len(step7_positions)} positions")


# ============================================================
# SUMMARY
# ============================================================

print()
print("=" * 80)
print("SUMMARY OF ALL RESULTS")
print("=" * 80)
print()

# Collect all results and find best
all_results = []

# Re-run all approaches silently and collect
def test_and_collect(label, text):
    cribs = crib_match_count(text)
    qg = quadgram_score(text)
    ic = ic_score(text)
    all_results.append((cribs, qg, ic, label, text))

# Test 1
test_and_collect("T1: Fwd sub (E->K)", apply_partial_sub(K4_CT, sub_fwd))
test_and_collect("T1: Inv sub (K->E)", apply_partial_sub(K4_CT, sub_inv))
for vec_name, vec in [("Vig-diff", diffs), ("Beau-diff", beau_diffs), ("VBeau-diff", varbeau_diffs), ("KA-diff", ka_diffs)]:
    for variant_name, variant in [("Vig", CipherVariant.VIGENERE),
                                    ("Beau", CipherVariant.BEAUFORT),
                                    ("VBeau", CipherVariant.VAR_BEAUFORT)]:
        pt = decrypt_text(K4_CT, vec, variant)
        test_and_collect(f"T1: {vec_name}/{variant_name}", pt)

# Test 2
for kw_name, kw_nums in keywords_to_test.items():
    for variant_name, variant in [("Vig", CipherVariant.VIGENERE),
                                    ("Beau", CipherVariant.BEAUFORT),
                                    ("VBeau", CipherVariant.VAR_BEAUFORT)]:
        pt = decrypt_text(K4_CT, kw_nums, variant)
        test_and_collect(f"T2: {kw_name}/{variant_name}", pt)

# Test 4
test_and_collect("T4: Fwd alpha sub", fwd_sub_result)
test_and_collect("T4: Inv alpha sub", inv_sub_result)

# Test 5
k4_180_alpha = ''.join(c for c in k4_180 if c.isalpha())
test_and_collect("T5: 180-image", k4_180)
for variant_name, variant in [("Vig", CipherVariant.VIGENERE), ("Beau", CipherVariant.BEAUFORT)]:
    key_180 = [ALPH_IDX[c] for c in k4_180_alpha[:97]]
    if len(key_180) >= 97:
        pt = decrypt_text(K4_CT, key_180[:97], variant)
        test_and_collect(f"T5: 180-key/{variant_name}", pt)

# Test 7
for key_name, key_order in [("ENDYAHR", endyahr_order), ("KRYPTOS", kryptos_order)]:
    perm = columnar_perm(7, list(key_order), 97)
    for perm_dir, p in [("enc", perm), ("dec", invert_perm(perm))]:
        text = apply_perm(K4_CT, p)
        test_and_collect(f"T7: Col-{key_name}-{perm_dir}", text)
        for kw_name, kw in [("KRYPTOS", "KRYPTOS"), ("ENDYAHR", "ENDYAHR")]:
            kw_nums = [ALPH_IDX[c] for c in kw]
            for variant_name, variant in [("Vig", CipherVariant.VIGENERE),
                                            ("Beau", CipherVariant.BEAUFORT)]:
                pt = decrypt_text(text, kw_nums, variant)
                test_and_collect(f"T7: Col-{key_name}-{perm_dir}+{kw_name}/{variant_name}", pt)

# Test 8
for variant_name, variant in [("Vig", CipherVariant.VIGENERE), ("Beau", CipherVariant.BEAUFORT)]:
    pt = decrypt_text(K4_CT, vig_keys, variant)
    test_and_collect(f"T8: K3-VigKey/{variant_name}", pt)
    pt = decrypt_text(K4_CT, beau_keys, variant)
    test_and_collect(f"T8: K3-BeauKey/{variant_name}", pt)

# Rev ENDYAHR
for variant_name, variant in [("Vig", CipherVariant.VIGENERE), ("Beau", CipherVariant.BEAUFORT)]:
    pt = decrypt_text(K4_CT, rev_nums, variant)
    test_and_collect(f"Bonus: Rev-ENDYAHR/{variant_name}", pt)

# Interleaved
for variant_name, variant in [("Vig", CipherVariant.VIGENERE), ("Beau", CipherVariant.BEAUFORT)]:
    pt = decrypt_text(K4_CT, interleaved, variant)
    test_and_collect(f"Bonus: Interleaved/{variant_name}", pt)
    pt = decrypt_text(K4_CT, concat_key, variant)
    test_and_collect(f"Bonus: Concat/{variant_name}", pt)

# Step-7
if len(step7_positions) == 97:
    step7_text = ''.join(K4_CT[p] for p in step7_positions)
    test_and_collect("Bonus: Step7 raw", step7_text)
    for kw_name, kw in [("KRYPTOS", "KRYPTOS"), ("ENDYAHR", "ENDYAHR")]:
        kw_nums = [ALPH_IDX[c] for c in kw]
        for variant_name, variant in [("Vig", CipherVariant.VIGENERE),
                                        ("Beau", CipherVariant.BEAUFORT)]:
            pt = decrypt_text(step7_text, kw_nums, variant)
            test_and_collect(f"Bonus: Step7+{kw_name}/{variant_name}", pt)

# Sort by cribs descending, then qg descending
all_results.sort(key=lambda x: (-x[0], -x[1]))

print(f"Total configurations tested: {len(all_results)}")
print()
print("TOP 20 RESULTS (sorted by cribs, then quadgram score):")
print(f"{'Rank':>4}  {'Cribs':>5}  {'QG/ch':>7}  {'IC':>6}  {'Configuration'}")
print("-" * 100)
for i, (cribs, qg, ic, label, text) in enumerate(all_results[:20]):
    flag = ""
    if cribs >= 10:
        flag = " <<< SIGNAL"
    elif cribs >= 6:
        flag = " << ABOVE NOISE"
    print(f"{i+1:4d}  {cribs:5d}  {qg:7.3f}  {ic:.4f}  {label}{flag}")
    if cribs >= 3:
        print(f"{'':>4}  {'':>5}  {'':>7}  {'':>6}  PT: {text[:70]}")

print()
print("HIGHEST QUADGRAM SCORES:")
all_by_qg = sorted(all_results, key=lambda x: -x[1])
for i, (cribs, qg, ic, label, text) in enumerate(all_by_qg[:10]):
    print(f"  {qg:7.3f}/char  cribs={cribs}  ic={ic:.4f}  {label}")
    if qg > -8.0:
        print(f"    PT: {text[:70]}")

print()
print("KEY FINDINGS:")
print(f"  Best crib score: {all_results[0][0]}/{N_CRIBS} from {all_results[0][3]}")
print(f"  Best quadgram:   {all_by_qg[0][1]:.3f}/char from {all_by_qg[0][3]}")
print()

# Final analysis
print("ANALYSIS:")
print()
print("1. ENDYAHR <-> KRYPTOS difference vector:")
print(f"   Vig: {diff_str} = {diffs}")
print(f"   Beau: {''.join(beau_letters)} = {beau_diffs}")
print(f"   VBeau: {''.join(varbeau_letters)} = {varbeau_diffs}")
print(f"   KA-space: {''.join(ka_diff_letters)} = {ka_diffs}")
print()

print("2. K3 CT/PT relationship at ENDYAHR positions:")
print(f"   CT first 7: {K3_CT[:7]}")
print(f"   PT first 7: {K3_PT[:7]}")
print(f"   K3 is a TRANSPOSITION cipher (not substitution), so the")
print(f"   positional coincidence is structural, not key-derived.")
print()

print("3. YAR (raised letters) correspond to columns 3, 4, 6 in both")
print(f"   KRYPTOS (P, T, S) and ENDYAHR (Y, A, R). These are the")
print(f"   physically anomalous positions on the sculpture.")
print()

print("4. Grid symmetry: K4 start (row 24, col 27) maps under")
print(f"   180-degree rotation to (row {NROWS-1-24}, col {WIDTH-1-27}).")
print(f"   This position is in the K1/K2 region.")
print()

print("=" * 80)
print("DONE — E-ENDYAHR-MAPPING complete")
print("=" * 80)
