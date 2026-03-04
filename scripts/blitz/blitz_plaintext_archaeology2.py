"""
Cipher: multi-method blitz
Family: blitz
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
blitz_plaintext_archaeology2.py — Deep dive on the most promising K1-K3 instruction models.

Part 2: More creative compound approaches based on K1-K3 plaintext interpretation.

Key insights being tested:
1. K2 IDBYROWS + LAYERTWO = TWO DIFFERENT instructions
2. K3 double-rotation dimensions (24,14,8,42) as key material
3. "BETWEEN" = interleave two permutation systems
4. Columnar with K3 dimensions on K4 within the 14x31 grid
5. K3 answer "YES WONDERFUL THINGS" + auto-detect key periodicity
6. Route cipher guided by K3 action sequence
7. "SLOWLY DESPARATLY SLOWLY" as a substitution indicator (6-10-6 blocks)
8. K1 IQLUSION: Q=L substitution THEN standard decode (pre-substitution layer)

Run: cd /home/cpatrick/kryptos && PYTHONPATH=src python3 -u scripts/blitz_plaintext_archaeology2.py
"""

import sys
import math
from itertools import permutations, product
from collections import Counter

sys.path.insert(0, 'scripts')
from kbot_harness import (
    K4_CARVED, AZ, KA, KEYWORDS,
    score_text, score_text_per_char, has_cribs,
    vig_decrypt, beau_decrypt, vig_encrypt,
    apply_permutation, test_perm,
    load_quadgrams,
)

K4_LEN = 97

# K3 known dimensions
K3_WIDTHS = [24, 14, 8, 42]  # encryption grid widths/heights
K3_STEP = 86  # dominant step in K3 permutation
K3_COL_STEP = 7  # column step on 31-wide grid

# K4 grid rows
k4_row0 = K4_CARVED[0:4]
k4_row1 = K4_CARVED[4:35]
k4_row2 = K4_CARVED[35:66]
k4_row3 = K4_CARVED[66:97]

best_global_score = -10.0
best_global_result = None

def score(text):
    return score_text_per_char(text)

def report(label, pt, sc_per_char, extra=""):
    global best_global_score, best_global_result
    cribs = has_cribs(pt)
    if cribs:
        print(f"\n!!! CRIB HIT !!! [{label}] score={sc_per_char:.4f}/char cribs={cribs}")
        print(f"  PT: {pt}")
        print(f"  {extra}")
    if sc_per_char > best_global_score:
        best_global_score = sc_per_char
        best_global_result = {"label": label, "pt": pt, "score": sc_per_char, "extra": extra}
    if sc_per_char > -5.5 or cribs:
        print(f"  ** NOTABLE [{label}] {sc_per_char:.4f}/char: {pt[:60]}... {extra}")

def try_decryptions(ct_text, label):
    """Try all keyword x cipher x alpha combos."""
    best_sc = -999
    best_info = None
    for kw in KEYWORDS:
        for aname, alpha in [("AZ", AZ), ("KA", KA)]:
            for cname, cfn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                try:
                    pt = cfn(ct_text, kw, alpha)
                except:
                    continue
                sc = score(pt)
                cribs = has_cribs(pt)
                lbl = f"{label}|{cname}/{kw}/{aname}"
                if cribs:
                    report(lbl, pt, sc, f"CRIB HIT key={kw}")
                    return {"pt": pt, "score": sc, "key": kw, "cipher": cname, "alpha": aname, "cribs": cribs}
                if sc > best_sc:
                    best_sc = sc
                    best_info = {"pt": pt, "score": sc, "key": kw, "cipher": cname, "alpha": aname}
    if best_info and best_sc > -5.5:
        report(f"{label}|best", best_info["pt"], best_sc,
               f"key={best_info['key']} cipher={best_info['cipher']} alpha={best_info['alpha']}")
    return best_info

def columnar_transpose(text, key_word):
    """Apply columnar transposition using keyword to define column order."""
    width = len(key_word)
    nrows = math.ceil(len(text) / width)
    padded = text.ljust(nrows * width, 'X')

    indexed = sorted(range(width), key=lambda i: (key_word[i], i))
    col_order = [0] * width
    for rank, orig_idx in enumerate(indexed):
        col_order[orig_idx] = rank

    result = ""
    for rank in range(width):
        col = col_order.index(rank)
        for row in range(nrows):
            idx = row * width + col
            if idx < len(text):
                result += padded[idx]
    return result[:len(text)]

def inverse_columnar(text, key_word):
    """Apply inverse columnar transposition."""
    width = len(key_word)
    nrows = math.ceil(len(text) / width)

    indexed = sorted(range(width), key=lambda i: (key_word[i], i))
    col_order = [0] * width
    for rank, orig_idx in enumerate(indexed):
        col_order[orig_idx] = rank

    grid = [[''] * width for _ in range(nrows)]
    pos = 0
    for rank in range(width):
        col = col_order.index(rank)
        for row in range(nrows):
            if pos < len(text):
                grid[row][col] = text[pos]
                pos += 1

    result = ""
    for row in range(nrows):
        for col in range(width):
            if grid[row][col]:
                result += grid[row][col]
    return result[:len(text)]


# ─────────────────────────────────────────────────────────────────────────────
# SECTION A: Two-Layer Models from "LAYER TWO"
# ─────────────────────────────────────────────────────────────────────────────
print("=" * 80)
print("SECTION A: Two-Layer Models — 'X LAYER TWO'")
print("=" * 80)

# Model: carved = Columnar(Vig(PT, key1), key2) or Vig(Columnar(PT, key2), key1)
# To decrypt: reverse both layers.

# A1: Vig/Beau decrypt THEN columnar with thematic keywords
print("\n--- A1: Cipher then columnar (all keyword combos) ---")
best_a1 = -10
count_a1 = 0
for cipher_kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
    for aname, alpha in [("AZ", AZ), ("KA", KA)]:
        for cname, cfn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
            intermediate = cfn(K4_CARVED, cipher_kw, alpha)

            for col_kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BETWEEN",
                           "SLOWLY", "LIGHT", "SHADOW", "BREACH",
                           "IDBYROWS", "LAYERTWO", "INVISIBLE"]:
                # Forward columnar on intermediate
                ct_fwd = columnar_transpose(intermediate, col_kw)
                sc_fwd = score(ct_fwd)
                cribs_fwd = has_cribs(ct_fwd)
                if cribs_fwd or sc_fwd > -5.5:
                    report(f"A1-{cname}/{cipher_kw}/{aname}+col/{col_kw}",
                           ct_fwd, sc_fwd)
                if sc_fwd > best_a1:
                    best_a1 = sc_fwd

                # Inverse columnar on intermediate
                ct_inv = inverse_columnar(intermediate, col_kw)
                sc_inv = score(ct_inv)
                cribs_inv = has_cribs(ct_inv)
                if cribs_inv or sc_inv > -5.5:
                    report(f"A1-{cname}/{cipher_kw}/{aname}+inv-col/{col_kw}",
                           ct_inv, sc_inv)
                if sc_inv > best_a1:
                    best_a1 = sc_inv

                count_a1 += 2

print(f"  Tested {count_a1} two-layer combos, best score: {best_a1:.4f}/char")

# A2: Columnar THEN Vig/Beau
print("\n--- A2: Columnar first, then cipher (all keyword combos) ---")
best_a2 = -10
count_a2 = 0
for col_kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BETWEEN",
               "SLOWLY", "LIGHT", "SHADOW", "BREACH",
               "IDBYROWS", "LAYERTWO", "INVISIBLE"]:
    # Forward and inverse columnar
    for col_fn, col_label in [(columnar_transpose, "col"), (inverse_columnar, "invcol")]:
        intermediate = col_fn(K4_CARVED, col_kw)

        for cipher_kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            for aname, alpha in [("AZ", AZ), ("KA", KA)]:
                for cname, cfn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                    pt = cfn(intermediate, cipher_kw, alpha)
                    sc = score(pt)
                    cribs = has_cribs(pt)
                    if cribs or sc > -5.5:
                        report(f"A2-{col_label}/{col_kw}+{cname}/{cipher_kw}/{aname}",
                               pt, sc)
                    if sc > best_a2:
                        best_a2 = sc
                    count_a2 += 1

print(f"  Tested {count_a2} combos, best score: {best_a2:.4f}/char")


# ─────────────────────────────────────────────────────────────────────────────
# SECTION B: K3 Dimensions as Transposition Parameters
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 80)
print("SECTION B: K3 dimensions (24,14,8,42) as K4 transposition keys")
print("=" * 80)

# K3 used grids of width 24 and 8. Key numbers: 7, 8, 14, 24, 31, 42.
# GCD(24,8) = 8. GCD(14,42) = 14. All multiples of 7.

# B1: Single rotation at K3-related widths (with padding to nearest multiple)
print("\n--- B1: Single rotation at K3 widths (padded) ---")
for width in [7, 8, 14, 24, 31, 42]:
    for total_pad in [97, 98, 100, 104, 112]:
        if total_pad < 97:
            continue
        if total_pad % width != 0:
            continue
        height = total_pad // width
        padded = K4_CARVED.ljust(total_pad, 'X')

        # Write row by row, read column by column (CW rotation)
        rotated = ""
        for col in range(width):
            for row in range(height - 1, -1, -1):
                rotated += padded[row * width + col]
        rotated = rotated[:97]
        if len(rotated) == 97:
            try_decryptions(rotated, f"B1-rot-w{width}-pad{total_pad}")

        # Also reverse rotation (CCW)
        rotated_ccw = ""
        for col in range(width - 1, -1, -1):
            for row in range(height):
                rotated_ccw += padded[row * width + col]
        rotated_ccw = rotated_ccw[:97]
        if len(rotated_ccw) == 97:
            try_decryptions(rotated_ccw, f"B1-rot-ccw-w{width}-pad{total_pad}")

# B2: Use step 7 (K3 column step = KRYPTOS length) with various starting positions
print("\n--- B2: Step-7 reading (KRYPTOS length, K3 column step) ---")
for start in range(97):
    perm = []
    pos = start
    visited = set()
    while len(perm) < 97:
        while pos in visited:
            pos = (pos + 1) % 97
        perm.append(pos)
        visited.add(pos)
        pos = (pos + 7) % 97

    ct_s7 = apply_permutation(K4_CARVED, perm)
    # Quick test with just top keywords
    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
        for alpha in [AZ, KA]:
            pt = vig_decrypt(ct_s7, kw, alpha)
            cribs = has_cribs(pt)
            if cribs:
                sc = score(pt)
                report(f"B2-step7-start{start}-vig/{kw}", pt, sc)
            pt = beau_decrypt(ct_s7, kw, alpha)
            cribs = has_cribs(pt)
            if cribs:
                sc = score(pt)
                report(f"B2-step7-start{start}-beau/{kw}", pt, sc)


# ─────────────────────────────────────────────────────────────────────────────
# SECTION C: K3 "UPPER LEFT HAND CORNER" → Grid Offset Experiments
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 80)
print("SECTION C: Grid offset — K4 starting at different grid positions")
print("=" * 80)

# K3 says "I MADE A TINY BREACH IN THE UPPER LEFT HAND CORNER"
# What if K4 should be positioned differently on the grid?
# Currently K4 starts at row 10 col 27. What if it should start at col 0?

# C1: Reposition K4 at the "upper left" of a fresh grid
print("\n--- C1: K4 at top-left of various grid widths, read by columns ---")
for width in [7, 8, 10, 11, 13, 14, 31]:
    nrows = math.ceil(97 / width)
    padded = K4_CARVED.ljust(nrows * width, 'X')

    # Read by columns
    col_read = ""
    for col in range(width):
        for row in range(nrows):
            idx = row * width + col
            if idx < 97:
                col_read += padded[idx]
    col_read = col_read[:97]
    if len(col_read) == 97:
        try_decryptions(col_read, f"C1-grid-w{width}-cols")

# C2: K4 starting at different columns in the 14x31 grid
# "BREACH IN THE UPPER LEFT" → read from position 0 of the grid, not from K4's natural position
print("\n--- C2: Read full grid from upper-left, extract K4-length fragment ---")
# The full K3+?+K4 grid read by columns
full_text = "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI" + \
            "ACHTNREYULDSLLSLLNOHSNOSMRWXMNE" + \
            "TPRNGATIHNRARPESLNNELEBLPIIACAE" + \
            "WMTWNDITEENRAHCTENEUDRETNHAEOET" + \
            "FOLSEDTIWENHAEIOYTEYQHEENCTAYCR" + \
            "EIFTBRSPAMHHEWENATAMATEGYEERLBT" + \
            "EEFOASFIOTUETUAEOTOARMAEERTNRTI" + \
            "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB" + \
            "AECTDDHILCEIHSITEGOEAOSDDRYDLOR" + \
            "ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE" + \
            "ECDMRIPFEIMEHNLSSTTRTVDOHW" + "?" + K4_CARVED

assert len(full_text) == 434, f"Grid text length {len(full_text)} != 434"

# Read by columns
for start_row in range(14):
    for start_col in range(31):
        # Read 97 chars starting at (start_row, start_col) column-by-column
        fragment = ""
        col = start_col
        row = start_row
        count = 0
        while count < 97:
            idx = row * 31 + col
            if 0 <= idx < 434:
                ch = full_text[idx]
                if ch != '?':
                    fragment += ch
                    count += 1
            row += 1
            if row >= 14:
                row = 0
                col = (col + 1) % 31

        if len(fragment) == 97:
            for kw in ["KRYPTOS", "ABSCISSA"]:
                for alpha in [AZ, KA]:
                    pt = vig_decrypt(fragment, kw, alpha)
                    cribs = has_cribs(pt)
                    if cribs:
                        sc = score(pt)
                        report(f"C2-grid-start({start_row},{start_col})-vig/{kw}", pt, sc)
                    pt = beau_decrypt(fragment, kw, alpha)
                    cribs = has_cribs(pt)
                    if cribs:
                        sc = score(pt)
                        report(f"C2-grid-start({start_row},{start_col})-beau/{kw}", pt, sc)


# ─────────────────────────────────────────────────────────────────────────────
# SECTION D: "NUANCE OF IQLUSION" — Mirror/Reflection Transformations
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 80)
print("SECTION D: Mirror/reflection transformations")
print("=" * 80)

# "IQLUSION" = things are not what they seem. Mirror image.
# D1: Reverse the entire K4 text
print("\n--- D1: Reversed K4 ---")
ct_rev = K4_CARVED[::-1]
try_decryptions(ct_rev, "D1-reversed")

# D2: Atbash (A↔Z, B↔Y, ...) substitution on K4 before decryption
print("\n--- D2: Atbash then decrypt ---")
atbash_ct = "".join(AZ[25 - AZ.index(c)] for c in K4_CARVED)
print(f"  Atbash K4: {atbash_ct[:50]}...")
try_decryptions(atbash_ct, "D2-atbash")

# D3: KA-Atbash (mirror within KA alphabet)
ka_atbash_ct = "".join(KA[25 - KA.index(c)] for c in K4_CARVED)
print(f"  KA-Atbash K4: {ka_atbash_ct[:50]}...")
try_decryptions(ka_atbash_ct, "D3-ka-atbash")

# D4: Reversed THEN decrypt (read sculpture backwards)
print("\n--- D4: Various reversed combinations ---")
# Reverse + atbash
ct_rev_atbash = "".join(AZ[25 - AZ.index(c)] for c in ct_rev)
try_decryptions(ct_rev_atbash, "D4-rev+atbash")

# D5: Mirror on 31-wide grid (reverse each row, or reverse columns)
print("\n--- D5: Grid mirror operations ---")
# Reverse each row
k4_rows = [k4_row0, k4_row1, k4_row2, k4_row3]
ct_mirror_rows = "".join(r[::-1] for r in k4_rows)
try_decryptions(ct_mirror_rows, "D5-mirror-rows")

# Reverse column order (read right to left within each row, keep row order)
# Same as above actually. Try vertical mirror: reverse row order
ct_mirror_vert = "".join(reversed(k4_rows))
if len(ct_mirror_vert) == 97:
    try_decryptions(ct_mirror_vert, "D5-mirror-vert")

# 180-degree rotation = reverse entire text on grid
ct_180 = ct_mirror_vert[::-1]  # not same as simple reverse due to partial row
# Actually for a complete 180: reverse the linearized text
try_decryptions(K4_CARVED[::-1], "D5-180-simple")


# ─────────────────────────────────────────────────────────────────────────────
# SECTION E: K3 Answer Chain — "YES WONDERFUL THINGS" Position Analysis
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 80)
print("SECTION E: 'YES WONDERFUL THINGS' — position-based key derivation")
print("=" * 80)

# K3 ends "CAN YOU SEE ANYTHING Q". Carter's actual answer: "Yes, wonderful things!"
# If K4 PT starts with this, can we derive the key from the crib?

print("\n--- E1: Derive key from 'YESWONDERFULTHINGS' crib at various positions ---")
ywt = "YESWONDERFULTHINGS"
for start_pos in range(97 - len(ywt) + 1):
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        for direction in ["vig", "beau"]:
            key_fragment = []
            for i in range(len(ywt)):
                ct_i = alpha.index(K4_CARVED[start_pos + i])
                pt_i = alpha.index(ywt[i])
                if direction == "vig":
                    k = (ct_i - pt_i) % 26
                else:
                    k = (ct_i + pt_i) % 26
                key_fragment.append(alpha[k])

            key_str = "".join(key_fragment)

            # Check for periodic key
            for period in [7, 8, 10]:
                if period >= len(key_fragment):
                    continue
                matches = 0
                total = 0
                for j in range(len(key_fragment) - period):
                    total += 1
                    if key_fragment[j] == key_fragment[j + period]:
                        matches += 1
                if total > 0 and matches == total:
                    # PERFECT periodicity! Extract key and decrypt full text
                    kw_derived = key_str[:period]
                    if direction == "vig":
                        full_pt = vig_decrypt(K4_CARVED, kw_derived, alpha)
                    else:
                        full_pt = beau_decrypt(K4_CARVED, kw_derived, alpha)
                    sc = score(full_pt)
                    cribs = has_cribs(full_pt)
                    report(f"E1-YWT-pos{start_pos}-{direction}/{alpha_name}-period{period}",
                           full_pt, sc, f"Key={kw_derived}")

# E2: Also try "WONDERFUL" (without YES)
print("\n--- E2: 'WONDERFUL' and 'WONDERFULTHINGS' at various positions ---")
for crib in ["WONDERFUL", "WONDERFULTHINGS", "YESINDEEDWONDERFUL"]:
    for start_pos in range(97 - len(crib) + 1):
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for direction in ["vig", "beau"]:
                key_fragment = []
                for i in range(len(crib)):
                    ct_i = alpha.index(K4_CARVED[start_pos + i])
                    pt_i = alpha.index(crib[i])
                    if direction == "vig":
                        k = (ct_i - pt_i) % 26
                    else:
                        k = (ct_i + pt_i) % 26
                    key_fragment.append(alpha[k])

                for period in [7, 8, 10]:
                    if period >= len(key_fragment):
                        continue
                    matches = sum(1 for j in range(len(key_fragment) - period)
                                  if key_fragment[j] == key_fragment[j + period])
                    total = len(key_fragment) - period
                    if total > 0 and matches == total:
                        kw_derived = "".join(key_fragment[:period])
                        if direction == "vig":
                            full_pt = vig_decrypt(K4_CARVED, kw_derived, alpha)
                        else:
                            full_pt = beau_decrypt(K4_CARVED, kw_derived, alpha)
                        sc = score(full_pt)
                        report(f"E2-{crib[:8]}-pos{start_pos}-{direction}/{alpha_name}-p{period}",
                               full_pt, sc, f"Key={kw_derived}")


# ─────────────────────────────────────────────────────────────────────────────
# SECTION F: K2 "TOTALLY INVISIBLE" — Hidden Message Models
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 80)
print("SECTION F: K2 'TOTALLY INVISIBLE' — null cipher / hidden message models")
print("=" * 80)

# K2: "IT WAS TOTALLY INVISIBLE" — what if some K4 chars are "invisible" (nulls)?
# Take first letters of each N-letter block, or every Nth letter

# F1: First-letter extraction from N-length blocks
print("\n--- F1: Extract first letter of each N-letter block ---")
for block_size in range(2, 15):
    first_letters = ""
    for i in range(0, 97, block_size):
        first_letters += K4_CARVED[i]
    if len(first_letters) >= 10:
        # Check for English or keyword patterns
        for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            for alpha in [AZ, KA]:
                pt = vig_decrypt(first_letters, kw, alpha)
                cribs = has_cribs(pt)
                if cribs:
                    report(f"F1-block{block_size}-vig/{kw}", pt, score(pt))
                pt = beau_decrypt(first_letters, kw, alpha)
                cribs = has_cribs(pt)
                if cribs:
                    report(f"F1-block{block_size}-beau/{kw}", pt, score(pt))

# F2: "TRANSMITTED UNDERGROUND" — message hidden in subsurface
# Take K4 letters at positions corresponding to K3 "underground" section
# K3 talks about underground chambers. What K4 positions map to "underground" in K3?
print("\n--- F2: K3 'underground' positions mapped to K4 ---")
K3_PT_full = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHAT"
    "ENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTRE"
    "MBLINGHANDSIMADEATINYBREACHINTHEUPPERLEFTHANDCORNER"
    "ANDTHENWIDDENINGTHEHOLEALITTLEIPEEREDINTHEHOTAIRESC"
    "APINGFROMTHECHAMBERENABLINGMETOSEEACROSSTHETHRESHOLD"
    "ASANCIENTLIGHTFILLSTHEENTRYCHAMBERITISDIFFICULTTOLD"
    "IFFERENTIATETHEFLOORFROMTHEWALLSFROMTHECEILINGTHERE"
    "ISNOEASYWAYTOTAKEMEASUREMENTSANDTHENWHENASLIGHTLYMO"
    "REENLIGHTENEDLOOKREVEALEDGOLDANDPRECIOUSTHINGSIMADE"
    "NOTETHATIHADMISSPELLEDDESPARATEINMYNOTES"
)

underground_pos = K3_PT_full.find("LOWERPART")
if underground_pos >= 0:
    print(f"  'LOWERPART' at K3_PT[{underground_pos}]")
    # Map to K4 position: mod 97
    mapped_pos = underground_pos % 97
    print(f"  Maps to K4 position {mapped_pos}")


# ─────────────────────────────────────────────────────────────────────────────
# SECTION G: Double Columnar Transposition
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 80)
print("SECTION G: Double columnar transposition (K3 analog for K4)")
print("=" * 80)

# K3 uses double rotation (write in W1, read by cols, write in W2, read by cols).
# For K4, try double columnar with keyword-derived column orders.

print("\n--- G1: Double columnar (two keywords) ---")
best_g1 = -10
col_keywords = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BETWEEN", "SLOWLY",
                "LIGHT", "BREACH", "SHADOW"]
count_g1 = 0
for kw1 in col_keywords:
    for kw2 in col_keywords:
        # First columnar transposition with kw1
        inter = columnar_transpose(K4_CARVED, kw1)
        # Second columnar transposition with kw2
        result = columnar_transpose(inter, kw2)
        if len(result) == 97:
            res = try_decryptions(result, f"G1-dblcol-{kw1}+{kw2}")
            if res and res["score"] > best_g1:
                best_g1 = res["score"]

        # Also try inverse + forward and vice versa
        inter_inv = inverse_columnar(K4_CARVED, kw1)
        result_inv = columnar_transpose(inter_inv, kw2)
        if len(result_inv) == 97:
            res = try_decryptions(result_inv, f"G1-inv+col-{kw1}+{kw2}")
            if res and res["score"] > best_g1:
                best_g1 = res["score"]

        inter_inv2 = inverse_columnar(K4_CARVED, kw1)
        result_inv2 = inverse_columnar(inter_inv2, kw2)
        if len(result_inv2) == 97:
            res = try_decryptions(result_inv2, f"G1-inv+inv-{kw1}+{kw2}")
            if res and res["score"] > best_g1:
                best_g1 = res["score"]

        count_g1 += 3

print(f"  Tested {count_g1} double columnar combos, best: {best_g1:.4f}/char")


# ─────────────────────────────────────────────────────────────────────────────
# SECTION H: K2 "EARTHS MAGNETIC FIELD" — Compass-Based Reading
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 80)
print("SECTION H: Compass directions as reading patterns")
print("=" * 80)

# K2 mentions EARTHS MAGNETIC FIELD, K4 crib is EASTNORTHEAST.
# "EAST NORTH EAST" = a direction pattern: go right, go up, go right.
# On a grid: read right, then up, then right again.

# H1: Follow compass directions on K4 grid
print("\n--- H1: Compass-directed reading on grid ---")
# Start at various positions, follow ENE direction pattern
# E = right, N = up, NE = up-right, etc.
compass = {
    'E': (0, 1),   # same row, next col
    'N': (-1, 0),  # prev row, same col
    'NE': (-1, 1), # prev row, next col
    'S': (1, 0),
    'W': (0, -1),
    'SE': (1, 1),
    'SW': (1, -1),
    'NW': (-1, -1),
}

# Build K4 as 4-row grid for navigation
# Pad row0 to align with other rows on the 31-wide grid
k4_full_grid = [[''] * 31 for _ in range(4)]
# Row 0: only cols 27-30
for c in range(4):
    k4_full_grid[0][27 + c] = k4_row0[c]
# Rows 1-3: full width
for c in range(31):
    k4_full_grid[1][c] = k4_row1[c]
    k4_full_grid[2][c] = k4_row2[c]
    k4_full_grid[3][c] = k4_row3[c]

# Try reading pattern: EAST, NORTH, EAST (direction of the crib itself!)
direction_sequences = [
    ("ENE", ['E', 'N', 'E']),
    ("ENNE", ['E', 'N', 'N', 'E']),
    ("ENEE", ['E', 'N', 'E', 'E']),
    ("zigzag-NE-SE", ['NE', 'SE']),
    ("zigzag-E-N", ['E', 'N']),
    ("zigzag-E-NE", ['E', 'NE']),
]

for dir_name, dir_seq in direction_sequences:
    for start_row in range(4):
        for start_col in range(31):
            chars = []
            r, c = start_row, start_col
            step_idx = 0
            while len(chars) < 97:
                if 0 <= r < 4 and 0 <= c < 31 and k4_full_grid[r][c]:
                    chars.append(k4_full_grid[r][c])
                dr, dc = compass[dir_seq[step_idx % len(dir_seq)]]
                r += dr
                c += dc
                step_idx += 1
                # Wrap around
                r = r % 4
                c = c % 31
                if len(chars) > 0 and step_idx > 200:
                    break  # prevent infinite loops

            if len(chars) == 97:
                ct_compass = "".join(chars)
                for kw in ["KRYPTOS", "ABSCISSA"]:
                    for alpha in [AZ, KA]:
                        pt = vig_decrypt(ct_compass, kw, alpha)
                        cribs = has_cribs(pt)
                        if cribs:
                            report(f"H1-compass-{dir_name}-({start_row},{start_col})-vig/{kw}",
                                   pt, score(pt))


# ─────────────────────────────────────────────────────────────────────────────
# SECTION I: K1 Word Boundaries as Block Cipher Structure
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 80)
print("SECTION I: K1 word boundaries define K4 block structure")
print("=" * 80)

# K1: BETWEEN(7) SUBTLE(6) SHADING(7) AND(3) THE(3) ABSENCE(7) OF(2) LIGHT(5)
# LIES(4) THE(3) NUANCE(6) OF(2) IQLUSION(8)
# Word lengths: 7,6,7,3,3,7,2,5,4,3,6,2,8 = 63

# What if these define block lengths for K4? Read K4 in blocks of these sizes,
# then rearrange the blocks.

print("\n--- I1: K1 word-length blocks, rearranged ---")
k1_block_sizes = [7, 6, 7, 3, 3, 7, 2, 5, 4, 3, 6, 2, 8]
# Split K4 into blocks of these sizes
# Sum = 63, need 97. Repeat the pattern: 63 + 34 more
extended_sizes = k1_block_sizes.copy()
remaining = 97 - sum(extended_sizes)
idx = 0
while remaining > 0:
    take = min(extended_sizes[idx % len(extended_sizes)], remaining)
    extended_sizes.append(take)
    remaining -= take
    idx += 1

# Split K4 into blocks
blocks = []
pos = 0
for sz in extended_sizes:
    if pos + sz <= 97:
        blocks.append(K4_CARVED[pos:pos+sz])
        pos += sz
    else:
        blocks.append(K4_CARVED[pos:97])
        break

print(f"  Blocks: {blocks}")
print(f"  Block count: {len(blocks)}, sizes: {[len(b) for b in blocks]}")

# Try reversing each block
ct_block_rev = "".join(b[::-1] for b in blocks)
if len(ct_block_rev) == 97:
    try_decryptions(ct_block_rev, "I1-k1-blocks-reversed")

# Try rearranging blocks in various orders
if len(blocks) <= 8:
    for perm in permutations(range(len(blocks))):
        ct_bp = "".join(blocks[p] for p in perm)
        if len(ct_bp) == 97:
            for kw in ["KRYPTOS", "ABSCISSA"]:
                pt = vig_decrypt(ct_bp, kw, AZ)
                cribs = has_cribs(pt)
                if cribs:
                    report(f"I1-blocks-perm-{perm}", pt, score(pt))

# I2: Use K1 word-length pattern as a period structure
# Period switches at word boundaries: different key offsets per block
print("\n--- I2: K1 words as variable-period Vigenere key ---")
for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        # Build key stream: use word index as additional offset
        pt_chars = []
        pos = 0
        for word_idx, word in enumerate(k1_block_sizes):
            for j in range(word):
                if pos >= 97:
                    break
                ct_i = alpha.index(K4_CARVED[pos])
                ki = alpha.index(kw[(pos + word_idx) % len(kw)])
                pt_chars.append(alpha[(ct_i - ki) % 26])
                pos += 1

        pt_str = "".join(pt_chars)
        sc = score(pt_str)
        cribs = has_cribs(pt_str)
        if cribs or sc > -5.5:
            report(f"I2-varperiod-{kw}/{alpha_name}", pt_str, sc)


# ─────────────────────────────────────────────────────────────────────────────
# SECTION J: "BURIED OUT THERE SOMEWHERE" — K4 in K1/K2/K3 CT
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 80)
print("SECTION J: K4 'buried' in K1-K3 ciphertext")
print("=" * 80)

# K2: "IT WAS...BURIED OUT THERE SOMEWHERE"
# What if the K4 plaintext or key is hidden within K1/K2/K3 ciphertext?

K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOET"
    "FOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLBT"
    "EEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"
)

# J1: Use K1 CT as a running key for K4
print("\n--- J1: K1/K3 CT as running key for K4 ---")
for source_name, source_ct in [("K1", K1_CT), ("K3", K3_CT)]:
    for offset in range(min(len(source_ct), 50)):
        key = source_ct[offset:offset + 97]
        if len(key) < 97:
            key = key + source_ct[:97 - len(key)]  # wrap around

        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cname, cfn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                pt = cfn(K4_CARVED, key, alpha)
                cribs = has_cribs(pt)
                sc = score(pt)
                if cribs or sc > -5.0:
                    report(f"J1-{source_name}-offset{offset}-{cname}/{alpha_name}",
                           pt, sc)

# J2: Use K3 PLAINTEXT as running key for K4
print("\n--- J2: K3 PT as running key for K4 ---")
for offset in range(min(len(K3_PT_full), 250)):
    key = K3_PT_full[offset:offset + 97]
    if len(key) < 97:
        continue

    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        pt = vig_decrypt(K4_CARVED, key, alpha)
        cribs = has_cribs(pt)
        sc = score(pt)
        if cribs or sc > -5.0:
            report(f"J2-K3PT-offset{offset}-vig/{alpha_name}", pt, sc)

        pt = beau_decrypt(K4_CARVED, key, alpha)
        cribs = has_cribs(pt)
        sc = score(pt)
        if cribs or sc > -5.0:
            report(f"J2-K3PT-offset{offset}-beau/{alpha_name}", pt, sc)


# ─────────────────────────────────────────────────────────────────────────────
# SECTION K: "PRIME LANG MERIDIAN" — Prime Number Permutations
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 80)
print("SECTION K: 'DOES THE PRIME LANG MERIDIAN PASS THIS PLACE' — prime-based methods")
print("=" * 80)

# K2 mentions "PRIME" (as in Prime Meridian, but also: prime numbers).
# 97 is prime! Try prime-based permutations.

print("\n--- K1: Read K4 at prime-indexed positions ---")
primes_under_97 = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
                   53, 59, 61, 67, 71, 73, 79, 83, 89]
# Extract chars at prime positions
prime_chars = "".join(K4_CARVED[p] for p in primes_under_97 if p < 97)
print(f"  K4 at prime positions ({len(prime_chars)} chars): {prime_chars}")

# Also: non-prime positions
non_prime = [i for i in range(97) if i not in primes_under_97]
non_prime_chars = "".join(K4_CARVED[p] for p in non_prime)
print(f"  K4 at non-prime positions ({len(non_prime_chars)} chars): {non_prime_chars[:50]}...")

# Interleave: primes first, then non-primes
ct_prime_first = prime_chars + non_prime_chars
if len(ct_prime_first) == 97:
    try_decryptions(ct_prime_first, "K1-primes-first")

# Non-primes first, then primes
ct_nonprime_first = non_prime_chars + prime_chars
if len(ct_nonprime_first) == 97:
    try_decryptions(ct_nonprime_first, "K1-nonprimes-first")


# ─────────────────────────────────────────────────────────────────────────────
# FINAL SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 80)
print("FINAL SUMMARY (Part 2)")
print("=" * 80)

if best_global_result:
    print(f"\nBest overall score: {best_global_score:.4f}/char")
    print(f"  Label: {best_global_result['label']}")
    print(f"  PT: {best_global_result['pt'][:80]}...")
    print(f"  Extra: {best_global_result['extra']}")
else:
    print("\nNo notable results found.")

print("=" * 80)
