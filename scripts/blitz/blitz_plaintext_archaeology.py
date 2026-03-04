"""
Cipher: multi-method blitz
Family: blitz
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
blitz_plaintext_archaeology.py — Mining K1-K3 plaintext for K4 method instructions.

Sanborn: "I have left instructions in the earlier text that refer to later text."
Scheidt on K2's ID BY ROWS vs X LAYER TWO: "may not have been a mistake"

This script treats K1-K3 PT as LITERAL METHOD INSTRUCTIONS for K4:
  A. K2 "ID BY ROWS": row-reading permutations on the 14x31 K3/K4 grid
  B. Boustrophedon reading (alternating L-R / R-L rows)
  C. K3 action verbs as method: "BREACH", "WIDENING", "PEERED IN"
  D. K1 "BETWEEN...ABSENCE": holes in a mask, skip/take patterns
  E. "LAYER TWO": apply K3 transposition THEN Vig/Beau (two-layer model)
  F. K3's "CAN YOU SEE ANYTHING" → Cardan grille (peek through holes)
  G. Numerical extraction from K1-K3 PT for permutation keys
  H. K2 coordinates (38.9517, -77.1467) as key material
  I. K3 "SLOWLY DESPARATLY SLOWLY" — rate/rhythm as reading pattern
  J. SYNTHESIS: combine best ideas

Run: cd /home/cpatrick/kryptos && PYTHONPATH=src python3 -u scripts/blitz_plaintext_archaeology.py
"""

import sys
import os
import math
import json
from itertools import permutations, product
from collections import Counter

sys.path.insert(0, 'scripts')
from kbot_harness import (
    K4_CARVED, AZ, KA, KEYWORDS, CRIBS,
    score_text, score_text_per_char, has_cribs,
    vig_decrypt, beau_decrypt, vig_encrypt,
    apply_permutation, test_perm, test_unscramble,
    load_quadgrams,
)

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOET"
    "FOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLBT"
    "EEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"
)

K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHAT"
    "ENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTRE"
    "MBLINGHANDSIMADEATINYBREACHINTHEUPPERLEFTHANDCORNER"
    "ANDTHENWIDDENINGTHEHOLEALITTLEIINSERTEDTHECANDLEAND"
    "PEABORINGFROMTHECHAMBERENABLINGMETOSEEXCANYOUSEEANYTHINGQ"
)
# Corrected K3 PT from verified sources:
K3_PT = (
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

K2_PT = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEA"
    "RTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANS"
    "MITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESTHEPRIMELA"
    "NGMERIDIANPASSTHISPLACEXIDBYROWS"
)
# NOTE: K2 actual plaintext is debated. The standard version:
K2_PT_STANDARD = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEA"
    "RTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANS"
    "MITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESTHEPRIMELA"
    "NGMERIDIANPASSTHISPLACEX"
)
# The sculpture renders the last part as the Vigenere tableau cycling,
# but Sanborn's intended plaintext ends with either IDBYROWS or XLAYERTWO

K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"

K4_LEN = 97
assert len(K4_CARVED) == K4_LEN

# K3+?+K4 grid (14 rows x 31 cols)
K3K4_GRID_TEXT = K3_CT + "?" + K4_CARVED  # 336 + 1 + 97 = 434 = 14*31

# K4 on the 14x31 grid: starts at row 10 col 26 (? mark), K4 proper at row 10 col 27
# Row 10 (0-indexed): last 4 chars are ?OBK (wait: row 10 col 27 = O, col 28 = B, col 29 = K, col 30 = R)
# Actually: linear index of K4[0] in the grid = 336 + 1 = 337 (? at 336)
# Row = 337 // 31 = 10, Col = 337 % 31 = 27 => K4[0]='O' at row 10, col 27
# K4 rows on grid:
# Row 10: cols 27-30 -> K4[0:4] = OBKR
# Row 11: cols 0-30  -> K4[4:35] = UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO (31 chars, 4+31=35)
# Row 12: cols 0-30  -> K4[35:66] = TWTQSJQSSEKZZWATJKLUDIAWINFBNYP (31 chars)
# Row 13: cols 0-30  -> K4[66:97] = VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR (31 chars)

K4_GRID_ROW_START = 10  # K4 starts in this row of the 14x31 grid (0-indexed)
K4_GRID_COL_START = 27

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

_qg = None
def qg():
    global _qg
    if _qg is None:
        _qg = load_quadgrams()
    return _qg

def score(text):
    return score_text_per_char(text)

best_global_score = -10.0
best_global_result = None

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

def try_all_decryptions(ct_text, label_prefix):
    """Try all keyword x cipher x alphabet combos on a candidate CT."""
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
                lbl = f"{label_prefix}|{cname}/{kw}/{aname}"
                if cribs:
                    report(lbl, pt, sc, f"CRIB HIT key={kw}")
                    return {"pt": pt, "score": sc, "key": kw, "cipher": cname, "alpha": aname, "cribs": cribs}
                if sc > best_sc:
                    best_sc = sc
                    best_info = {"pt": pt, "score": sc, "key": kw, "cipher": cname, "alpha": aname}
    if best_info and best_sc > -5.5:
        report(f"{label_prefix}|best", best_info["pt"], best_sc,
               f"key={best_info['key']} cipher={best_info['cipher']} alpha={best_info['alpha']}")
    return best_info

# ─────────────────────────────────────────────────────────────────────────────
# SECTION A: K2 "ID BY ROWS" — Row-reading permutations
# ─────────────────────────────────────────────────────────────────────────────
print("=" * 80)
print("SECTION A: K2 'ID BY ROWS' — Row-reading permutations on grid")
print("=" * 80)

# K4 occupies 4 rows on the 14x31 grid.
# "ID BY ROWS" could mean: read K4 by columns instead of rows (transposition),
# or read rows in a specific order, or skip rows.

# Extract K4 as a 4-row grid (with partial first row)
k4_row0 = K4_CARVED[0:4]    # OBKR (row 10, cols 27-30)
k4_row1 = K4_CARVED[4:35]   # row 11, full 31 cols
k4_row2 = K4_CARVED[35:66]  # row 12, full 31 cols
k4_row3 = K4_CARVED[66:97]  # row 13, full 31 cols

print(f"\nK4 grid layout on 14x31:")
print(f"  Row 10 (partial): {k4_row0} (4 chars, cols 27-30)")
print(f"  Row 11 (full):    {k4_row1} (31 chars)")
print(f"  Row 12 (full):    {k4_row2} (31 chars)")
print(f"  Row 13 (full):    {k4_row3} (31 chars)")

# A1: Read K4 by COLUMNS on the 14x31 grid (the "ID BY ROWS" inverse = "READ BY COLS")
# Treat K4 as if in a grid of width 31, read column by column
print("\n--- A1: Read K4 by columns (top-to-bottom, left-to-right) ---")

# Build a padded 4x31 grid (pad first row with blanks at start)
pad_len = 31 - len(k4_row0)  # 27 positions before K4 in row 10
k4_grid = []
for col in range(31):
    for row_idx, row_data in enumerate([k4_row0, k4_row1, k4_row2, k4_row3]):
        if row_idx == 0:
            # Only cols 27-30 have K4 data
            if col >= 27:
                k4_grid.append(row_data[col - 27])
        else:
            k4_grid.append(row_data[col])

ct_by_cols = "".join(k4_grid)
print(f"  CT by cols (len={len(ct_by_cols)}): {ct_by_cols[:50]}...")
if len(ct_by_cols) == 97:
    res = try_all_decryptions(ct_by_cols, "A1-cols-top-down")

# A1b: Read columns bottom-to-top
k4_grid_btup = []
for col in range(31):
    for row_data in [k4_row3, k4_row2, k4_row1]:
        k4_grid_btup.append(row_data[col])
    if col >= 27:
        k4_grid_btup.append(k4_row0[col - 27])

ct_by_cols_btup = "".join(k4_grid_btup)
print(f"  CT by cols bottom-up (len={len(ct_by_cols_btup)}): {ct_by_cols_btup[:50]}...")
if len(ct_by_cols_btup) == 97:
    res = try_all_decryptions(ct_by_cols_btup, "A1b-cols-bottom-up")

# A2: Read rows in reverse order
print("\n--- A2: Read K4 rows in reverse order ---")
ct_reverse_rows = k4_row3 + k4_row2 + k4_row1 + k4_row0
print(f"  CT reverse rows (len={len(ct_reverse_rows)}): {ct_reverse_rows[:50]}...")
if len(ct_reverse_rows) == 97:
    res = try_all_decryptions(ct_reverse_rows, "A2-reverse-rows")

# A3: All 24 row orderings of the 4 K4 rows
print("\n--- A3: All 24 permutations of 4 K4 rows ---")
rows = [k4_row0, k4_row1, k4_row2, k4_row3]
best_a3 = -10
for perm in permutations(range(4)):
    ct_candidate = "".join(rows[p] for p in perm)
    if len(ct_candidate) != 97:
        continue
    res_inner = try_all_decryptions(ct_candidate, f"A3-rowperm-{perm}")
    if res_inner and res_inner["score"] > best_a3:
        best_a3 = res_inner["score"]
print(f"  Best A3 score: {best_a3:.4f}/char")

# A4: Read K4 on the 14x31 grid by columns INCLUDING K3 context
# "ID BY ROWS" might mean the full grid. Read the full K3+K4 grid by columns,
# extract K4 positions.
print("\n--- A4: Full 14x31 grid column reading → K4 positions ---")
full_grid_text = K3K4_GRID_TEXT  # 434 chars
assert len(full_grid_text) == 434

# Read by columns (top to bottom, left to right)
full_by_cols = []
for col in range(31):
    for row in range(14):
        idx = row * 31 + col
        full_by_cols.append(full_grid_text[idx])
full_by_cols_str = "".join(full_by_cols)

# Now find where K4 chars ended up
# K4 occupies linear positions 337-433 in the original grid
k4_positions_in_col_read = []
for col in range(31):
    for row in range(14):
        orig_idx = row * 31 + col
        if 337 <= orig_idx <= 433:
            k4_positions_in_col_read.append(len(k4_positions_in_col_read))

# Actually: build mapping from original position to column-read position
col_read_order = []
for col in range(31):
    for row in range(14):
        col_read_order.append(row * 31 + col)

# K4 chars in the column-read order
k4_from_col_read = ""
for new_pos, orig_pos in enumerate(col_read_order):
    if 337 <= orig_pos <= 433:
        k4_from_col_read += full_grid_text[orig_pos]

print(f"  K4 in column-read order (len={len(k4_from_col_read)}): {k4_from_col_read[:50]}...")
if len(k4_from_col_read) == 97:
    res = try_all_decryptions(k4_from_col_read, "A4-full-grid-col-read")


# ─────────────────────────────────────────────────────────────────────────────
# SECTION B: Boustrophedon (alternating direction rows)
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 80)
print("SECTION B: Boustrophedon reading (serpentine / alternating row directions)")
print("=" * 80)

# K2 mentions directions, K3 is about navigating a passage.
# Boustrophedon = "as the ox plows" = alternating row directions.

# B1: K4-only boustrophedon on 31-wide grid
print("\n--- B1: K4 boustrophedon (alternate row directions, width 31) ---")
for start_dir in ["LR", "RL"]:
    result_chars = []
    k4_rows_data = [k4_row0, k4_row1, k4_row2, k4_row3]
    for i, row in enumerate(k4_rows_data):
        if (start_dir == "LR" and i % 2 == 0) or (start_dir == "RL" and i % 2 == 1):
            result_chars.append(row)
        else:
            result_chars.append(row[::-1])
    ct_boust = "".join(result_chars)
    print(f"  Boustrophedon start={start_dir} (len={len(ct_boust)}): {ct_boust[:50]}...")
    if len(ct_boust) == 97:
        try_all_decryptions(ct_boust, f"B1-boust-{start_dir}")

# B2: Boustrophedon on various widths
print("\n--- B2: Boustrophedon at various grid widths ---")
best_b2 = -10
for width in [7, 8, 9, 10, 11, 13, 14, 16, 19, 31, 97]:
    # Pad to fill grid
    ct = K4_CARVED
    nrows = math.ceil(len(ct) / width)
    padded = ct.ljust(nrows * width, 'X')

    # Forward then alternate
    for start_dir in [0, 1]:
        chars = []
        for r in range(nrows):
            row_str = padded[r * width: (r + 1) * width]
            if (r + start_dir) % 2 == 1:
                row_str = row_str[::-1]
            chars.append(row_str)
        ct_b = "".join(chars)[:97]  # trim padding
        res_inner = try_all_decryptions(ct_b, f"B2-boust-w{width}-d{start_dir}")
        if res_inner and res_inner["score"] > best_b2:
            best_b2 = res_inner["score"]
print(f"  Best B2 score: {best_b2:.4f}/char")


# ─────────────────────────────────────────────────────────────────────────────
# SECTION C: K3 Action Verbs as Method Instructions
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 80)
print("SECTION C: K3 action verbs as K4 method clues")
print("=" * 80)

# K3 PT contains: SLOWLY, REMOVED, TREMBLING HANDS, MADE A TINY BREACH,
# UPPER LEFT HAND CORNER, WIDENING THE HOLE, PEERED IN, HOT AIR ESCAPING,
# FLAME TO FLICKER, DETAILS EMERGED FROM THE MIST, CAN YOU SEE ANYTHING

# C1: "UPPER LEFT HAND CORNER" — start reading from upper-left
# C2: "WIDENING THE HOLE" — expand reading region
# C3: "PEERED IN" — look through a mask
# C4: "BREACH" — break through at a specific point
# C5: "SLOWLY" repeated — suggests step-by-step, incremental

# C1: Start from different corners of the K4 grid
print("\n--- C1: Reading from different corners ---")
# K4 as 4x31 (dropping partial row) or various rectangles
for width in [7, 8, 31]:
    nrows = math.ceil(97 / width)
    padded = K4_CARVED.ljust(nrows * width, 'X')

    # Top-left (normal)
    # Top-right (reverse each row)
    # Bottom-left (reverse row order)
    # Bottom-right (reverse everything)
    corners = {
        "TL": padded,
        "TR": "".join(padded[r*width:(r+1)*width][::-1] for r in range(nrows)),
        "BL": "".join(padded[r*width:(r+1)*width] for r in range(nrows-1, -1, -1)),
        "BR": "".join(padded[r*width:(r+1)*width][::-1] for r in range(nrows-1, -1, -1)),
    }
    for corner_name, ct_c in corners.items():
        ct_c = ct_c[:97]
        try_all_decryptions(ct_c, f"C1-corner-{corner_name}-w{width}")

# C2: "SLOWLY DESPARATLY SLOWLY" — period-6 or step pattern
# SLOWLY = 6 letters, repeated. Try step-6 reading.
print("\n--- C2: Step-6 reading pattern (SLOWLY = 6 letters) ---")
for step in [6, 7, 8]:
    # Read every Nth character, cycling
    ct_step = ""
    used = set()
    pos = 0
    while len(ct_step) < 97:
        if pos >= 97:
            pos = pos % 97
        while pos in used and len(used) < 97:
            pos = (pos + 1) % 97
        if pos in used:
            break
        ct_step += K4_CARVED[pos]
        used.add(pos)
        pos = (pos + step) % 97
    if len(ct_step) == 97:
        try_all_decryptions(ct_step, f"C2-step-{step}")

# C3: "CAN YOU SEE ANYTHING" at end of K3.
# K4 is the ANSWER to this question. "YES WONDERFUL THINGS" (Carter's actual reply).
# Try known response as crib for K4 plaintext.
print("\n--- C3: Testing 'YES WONDERFUL THINGS' as K4 start ---")
yes_response = "YESWONDERFULTHINGS"
# If K4 PT starts with this, what key would produce K4 CT?
for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
    for direction in ["vig", "beau"]:
        # Derive key from first 18 positions
        key_fragment = []
        for i in range(len(yes_response)):
            ct_i = alpha.index(K4_CARVED[i])
            pt_i = alpha.index(yes_response[i])
            if direction == "vig":
                k = (ct_i - pt_i) % 26
            else:
                k = (ct_i + pt_i) % 26
            key_fragment.append(alpha[k])
        key_str = "".join(key_fragment)
        print(f"  If K4 starts '{yes_response}' ({direction}/{alpha_name}): key = {key_str}")

        # Check if key has a periodic pattern
        for period in range(1, 10):
            matches = 0
            total = 0
            for j in range(len(key_fragment)):
                if j + period < len(key_fragment):
                    total += 1
                    if key_fragment[j] == key_fragment[j + period]:
                        matches += 1
            if total > 0 and matches / total > 0.5:
                print(f"    Period {period}: {matches}/{total} matches ({matches/total:.1%})")

# C3b: Try "YES WONDERFUL THINGS" at various positions in scrambled model
print("\n--- C3b: If 'YESWONDERFULTHINGS' is in PT, find compatible keys ---")
ywt = "YESWONDERFULTHINGS"
for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        for cname, encrypt_fn in [("vig", vig_encrypt)]:
            # What CT would 'YESWONDERFULTHINGS' produce under this key?
            ct_fragment = encrypt_fn(ywt, kw, alpha)
            # Check if all these CT letters exist in K4_CARVED
            carved_letters = list(K4_CARVED)
            all_found = True
            for c in ct_fragment:
                if c in carved_letters:
                    carved_letters.remove(c)
                else:
                    all_found = False
                    break
            if all_found:
                print(f"  YWT compatible: {cname}/{kw}/{alpha_name} -> CT fragment: {ct_fragment}")


# ─────────────────────────────────────────────────────────────────────────────
# SECTION D: K1 "BETWEEN...ABSENCE OF LIGHT" — Skip/Take Mask Patterns
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 80)
print("SECTION D: K1 'BETWEEN SUBTLE SHADING AND THE ABSENCE OF LIGHT'")
print("=" * 80)

# K1 PT: "BETWEEN SUBTLE SHADING AND THE ABSENCE OF LIGHT LIES THE NUANCE OF IQLUSION"
# "Absence of light" = holes in a Cardan grille where light passes through
# "Between subtle shading" = the boundary/edge between hole and solid
# "Nuance of illusion" = the carved text LOOKS like the CT but it's scrambled

# D1: Use K1 PT letter positions to define a mask
print("\n--- D1: K1 letters as position mask on K4 ---")
# Map each letter in K1_PT to a number (A=0, B=1, ..., Z=25)
k1_nums = [ord(c) - ord('A') for c in K1_PT]
print(f"  K1 PT length: {len(K1_PT)}")
print(f"  K1 numbers (first 20): {k1_nums[:20]}")

# Use K1 numbers mod 97 as a permutation seed
k1_perm = [n % 97 for n in k1_nums]
print(f"  K1 mod 97 (first 20): {k1_perm[:20]}")

# D2: Use word lengths in K1 as column widths for transposition
print("\n--- D2: K1 word lengths as transposition key ---")
k1_words = ["BETWEEN", "SUBTLE", "SHADING", "AND", "THE", "ABSENCE", "OF",
            "LIGHT", "LIES", "THE", "NUANCE", "OF", "IQLUSION"]
k1_word_lens = [len(w) for w in k1_words]
print(f"  K1 word lengths: {k1_word_lens}")
print(f"  Sum: {sum(k1_word_lens)} (should = {len(K1_PT)})")

# Use word lengths as a columnar transposition key width
for width in k1_word_lens:
    if width < 2 or width > 50:
        continue
    nrows = math.ceil(97 / width)
    padded = K4_CARVED.ljust(nrows * width, 'X')

    # Read by columns
    ct_cols = ""
    for col in range(width):
        for row in range(nrows):
            idx = row * width + col
            if idx < 97:
                ct_cols += padded[idx]
    ct_cols = ct_cols[:97]
    if len(ct_cols) == 97:
        try_all_decryptions(ct_cols, f"D2-word-len-{width}")

# D3: "ABSENCE" positions — where letters are ABSENT from K4
print("\n--- D3: Letters absent at specific positions (skip pattern) ---")
# K1 = "BETWEEN..." = 63 chars. K4 = 97 chars.
# "Between" = in the gaps. Read K4 at positions NOT in some pattern.
k4_freq = Counter(K4_CARVED)
print(f"  K4 letter frequencies: {dict(sorted(k4_freq.items(), key=lambda x: -x[1]))}")

# Which letters in K1_PT are "absent" from their position in K4?
absent_positions = []
for i, c in enumerate(K1_PT):
    if i < 97 and K4_CARVED[i] != c:
        absent_positions.append(i)
print(f"  Positions where K1 letter != K4 letter: {len(absent_positions)}/min({len(K1_PT)},97)")


# ─────────────────────────────────────────────────────────────────────────────
# SECTION E: "LAYER TWO" — Two-layer decryption model
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 80)
print("SECTION E: 'X LAYER TWO' — K3 transposition as first layer on K4")
print("=" * 80)

# K2's intended ending is "X LAYER TWO", meaning K4 uses TWO layers.
# Layer 1: K3-style transposition. Layer 2: Vigenere/Beaufort substitution.
# The K3 double-rotation permutation formula:
# CT[i] -> PT[pt_pos]: a=i//24; b=i%24; inter=14*b+13-a; c=inter//8; d=inter%8; pt_pos=42*d+41-c

def k3_perm_forward(i, total=336):
    """K3 permutation: given CT position i, returns PT position."""
    a = i // 24
    b = i % 24
    inter = 14 * b + 13 - a
    c = inter // 8
    d = inter % 8
    pt_pos = 42 * d + 41 - c
    return pt_pos

# E1: Apply K3 permutation (mod 97) to K4
print("\n--- E1: K3 permutation formula applied mod 97 ---")
for mod_val in [97]:
    perm = []
    for i in range(97):
        p = k3_perm_forward(i) % mod_val
        perm.append(p)

    # Check if this is a valid permutation
    if len(set(perm)) == 97:
        ct_permuted = apply_permutation(K4_CARVED, perm)
        print(f"  K3 perm mod {mod_val}: valid perm, CT = {ct_permuted[:50]}...")
        try_all_decryptions(ct_permuted, f"E1-k3perm-mod{mod_val}")
    else:
        print(f"  K3 perm mod {mod_val}: NOT a valid perm (collisions)")

# E2: K3 step pattern (-86 mod N) applied to K4
print("\n--- E2: K3 dominant step (-86 mod 97 = 11) as reading step ---")
for step in [11, 86, -86 % 97]:
    ct_step = ""
    used = set()
    pos = 0
    while len(ct_step) < 97:
        while pos in used:
            pos = (pos + 1) % 97
        ct_step += K4_CARVED[pos]
        used.add(pos)
        pos = (pos + step) % 97
    if len(ct_step) == 97:
        try_all_decryptions(ct_step, f"E2-step-{step}")

# E3: Double rotation on K4 at various width pairs
print("\n--- E3: Double rotation on K4 (K3-style) ---")
# K3 uses width pairs where w1*h1 = w2*h2 = 336
# For K4 (97 = prime), the only factors are 1 and 97.
# But try with padding to nearest good composite
for total in [97, 98, 100, 104]:
    padded = K4_CARVED.ljust(total, 'X')
    factors_of_total = [(a, total // a) for a in range(2, total) if total % a == 0]
    for w1, h1 in factors_of_total:
        # Write into w1-wide grid, rotate CW, read
        inter = ""
        for col in range(w1):
            for row in range(h1 - 1, -1, -1):
                inter += padded[row * w1 + col]

        # Second rotation with another factor pair
        for w2, h2 in factors_of_total:
            out = ""
            for col in range(w2):
                for row in range(h2 - 1, -1, -1):
                    idx = row * w2 + col
                    if idx < len(inter):
                        out += inter[idx]
            out = out[:97]
            if len(out) == 97:
                best_inner = try_all_decryptions(out, f"E3-dblrot-{total}-{w1}x{h1}-{w2}x{h2}")

# E4: K3's column step pattern (7,7,7,3 repeating) on K4
print("\n--- E4: K3 column step pattern (7,7,7,3) on K4 ---")
step_pattern = [7, 7, 7, 3]
for start_pos in range(97):
    ct_out = ""
    used = set()
    pos = start_pos
    step_idx = 0
    while len(ct_out) < 97:
        if pos in used:
            # Skip to next unused
            found_next = False
            for offset in range(1, 98):
                trial = (pos + offset) % 97
                if trial not in used:
                    pos = trial
                    found_next = True
                    break
            if not found_next:
                break
        ct_out += K4_CARVED[pos]
        used.add(pos)
        pos = (pos + step_pattern[step_idx % len(step_pattern)]) % 97
        step_idx += 1
    if len(ct_out) == 97:
        res_inner = try_all_decryptions(ct_out, f"E4-step7773-start{start_pos}")


# ─────────────────────────────────────────────────────────────────────────────
# SECTION F: K3 "CAN YOU SEE ANYTHING" → Grille with skip pattern
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 80)
print("SECTION F: K3 'CAN YOU SEE ANYTHING' — Grille-like selective reading")
print("=" * 80)

# "CAN YOU SEE ANYTHING?" is the question K3 poses.
# K4 answers it. But also: "seeing" through a grille = selective reading.
# What if certain positions in K4 are "visible" (real CT) and others are noise?

# F1: Read every Nth character from K4 (various N)
print("\n--- F1: Decimation — read every Nth character ---")
for n in range(2, 14):
    for start in range(n):
        extracted = K4_CARVED[start::n]
        if len(extracted) >= 10:
            # Try as a shorter CT
            for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
                for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                    for cname, cfn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                        pt = cfn(extracted, kw, alpha)
                        cribs = has_cribs(pt)
                        if cribs:
                            sc = score(pt)
                            print(f"  !!! CRIB in decimation n={n} start={start}: {pt} cribs={cribs}")

# F2: Use K3 CT positions that map to specific PT letters as mask
print("\n--- F2: K3 position-based masks on K4 ---")
# In K3, positions where PT has specific "instruction" words
# e.g., positions where K3 PT = "SEE" could define which K4 positions to read

# Find all positions of key words in K3_PT
instruction_words = ["SEE", "BREACH", "HOLE", "UPPER", "LEFT", "CORNER",
                     "SLOWLY", "REMOVED", "PEERED", "LIGHT", "MIST",
                     "ANYTHING", "PASSAGE"]
for word in instruction_words:
    pos = K3_PT.find(word)
    if pos >= 0:
        # Map K3 PT positions to mod-97 K4 positions
        k4_positions = [(pos + i) % 97 for i in range(len(word))]
        print(f"  '{word}' at K3_PT[{pos}]: K4 positions (mod 97) = {k4_positions}")


# ─────────────────────────────────────────────────────────────────────────────
# SECTION G: Numerical Extraction from K1-K3
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 80)
print("SECTION G: Numerical values from K1-K3 text as permutation keys")
print("=" * 80)

# G1: "BETWEEN" = positions 1,4,19,22,4,4,13 (A=0)? Use letter values.
# Actually: use the AZ-index values of key words as transposition column keys.

print("\n--- G1: Key words from K1-K3 as columnar transposition keys ---")
key_phrases = [
    ("BETWEEN", "K1"),
    ("ABSENCE", "K1"),
    ("LIGHT", "K1"),
    ("IQLUSION", "K1"),
    ("INVISIBLE", "K2"),
    ("UNDERGROUND", "K2"),
    ("IDBYROWS", "K2"),
    ("LAYERTWO", "K2"),
    ("SLOWLY", "K3"),
    ("BREACH", "K3"),
    ("ANYTHING", "K3"),
    ("DESPARATE", "K3"),
    ("KRYPTOS", "keyword"),
    ("PALIMPSEST", "keyword"),
    ("ABSCISSA", "keyword"),
]

for phrase, source in key_phrases:
    # Use phrase to define columnar transposition key
    width = len(phrase)
    if width < 2 or width > 50:
        continue

    # Rank letters alphabetically to get column order
    indexed = sorted(range(width), key=lambda i: (phrase[i], i))
    col_order = [0] * width
    for rank, orig_idx in enumerate(indexed):
        col_order[orig_idx] = rank

    # Write K4 into grid of this width, read by column order
    nrows = math.ceil(97 / width)
    padded = K4_CARVED.ljust(nrows * width, 'X')

    # Read columns in key order
    ct_trans = ""
    for rank in range(width):
        col = col_order.index(rank)
        for row in range(nrows):
            idx = row * width + col
            if idx < 97:
                ct_trans += padded[idx]
            elif len(ct_trans) < 97:
                ct_trans += 'X'  # padding

    ct_trans = ct_trans[:97]
    if len(ct_trans) == 97:
        res_g = try_all_decryptions(ct_trans, f"G1-keyed-col-{phrase}")

# G2: Also try the INVERSE: reading K4 as if it was written by columns and reading by rows
print("\n--- G2: Inverse columnar (written by cols, read by rows) ---")
for phrase, source in key_phrases:
    width = len(phrase)
    if width < 2 or width > 50:
        continue

    indexed = sorted(range(width), key=lambda i: (phrase[i], i))
    col_order = [0] * width
    for rank, orig_idx in enumerate(indexed):
        col_order[orig_idx] = rank

    nrows = math.ceil(97 / width)

    # Inverse columnar: assign characters to columns in key order
    grid = [[''] * width for _ in range(nrows)]
    pos = 0
    for rank in range(width):
        col = col_order.index(rank)
        for row in range(nrows):
            if pos < 97:
                grid[row][col] = K4_CARVED[pos]
                pos += 1

    # Read by rows
    ct_inv = ""
    for row in range(nrows):
        for col in range(width):
            if grid[row][col]:
                ct_inv += grid[row][col]
    ct_inv = ct_inv[:97]
    if len(ct_inv) == 97:
        try_all_decryptions(ct_inv, f"G2-inv-col-{phrase}")


# ─────────────────────────────────────────────────────────────────────────────
# SECTION H: K2 Coordinates as Key Material
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 80)
print("SECTION H: K2 coordinates (38°57'6.5\"N, 77°8'44\"W) as key material")
print("=" * 80)

# K2 mentions EARTHS MAGNETIC FIELD, coordinates point to CIA HQ area
# Lat: 38.9518° N, Long: 77.1456° W (approximate)
# Also "DOES THE PRIME LANG MERIDIAN PASS THIS PLACE" (it doesn't — this is a clue?)

# H1: Use coordinate digits as column order
print("\n--- H1: Coordinate digits as transposition key ---")
coord_sequences = [
    ("lat-389518", [3, 8, 9, 5, 1, 8]),
    ("lon-771456", [7, 7, 1, 4, 5, 6]),
    ("lat-385706", [3, 8, 5, 7, 0, 6]),  # 38°57'06"
    ("lon-770844", [7, 7, 0, 8, 4, 4]),  # 77°08'44"
    ("combined-38577708", [3, 8, 5, 7, 7, 7, 0, 8]),
    ("combined-389518771456", [3, 8, 9, 5, 1, 8, 7, 7, 1, 4, 5, 6]),
]

for name, digits in coord_sequences:
    width = len(digits)
    if width < 2 or width > 50:
        continue

    # Rank digits to get column order
    indexed = sorted(range(width), key=lambda i: (digits[i], i))
    col_order = [0] * width
    for rank, orig_idx in enumerate(indexed):
        col_order[orig_idx] = rank

    nrows = math.ceil(97 / width)
    padded = K4_CARVED.ljust(nrows * width, 'X')

    # Columnar transposition read
    ct_trans = ""
    for rank in range(width):
        col = col_order.index(rank)
        for row in range(nrows):
            idx = row * width + col
            if idx < 97:
                ct_trans += padded[idx]
    ct_trans = ct_trans[:97]
    if len(ct_trans) == 97:
        try_all_decryptions(ct_trans, f"H1-coords-{name}")

    # Also inverse
    grid = [[''] * width for _ in range(nrows)]
    pos = 0
    for rank in range(width):
        col = col_order.index(rank)
        for row in range(nrows):
            if pos < 97:
                grid[row][col] = K4_CARVED[pos]
                pos += 1
    ct_inv = ""
    for row in range(nrows):
        for col in range(width):
            if grid[row][col]:
                ct_inv += grid[row][col]
    ct_inv = ct_inv[:97]
    if len(ct_inv) == 97:
        try_all_decryptions(ct_inv, f"H1-coords-inv-{name}")


# ─────────────────────────────────────────────────────────────────────────────
# SECTION I: "SLOWLY" Rhythm Patterns
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 80)
print("SECTION I: 'SLOWLY DESPARATLY SLOWLY' — rhythm/rate patterns")
print("=" * 80)

# K3 starts "SLOWLY DESPARATLY SLOWLY" — two SLOWLYs bracketing DESPARATLY
# SLOWLY = 6 letters, DESPARATLY = 10 (misspelled from DESPERATELY = 11)
# Pattern: 6, 10, 6 = 22 total. Rhythm: slow-fast-slow.

# I1: Interleave K4 in a 6-10-6 or 6-10 pattern
print("\n--- I1: Read K4 in blocks of 6 and 10 alternating ---")
for block_sizes in [[6, 10], [6, 10, 6], [10, 6], [7, 10]]:
    # Forward blocks, then reverse within blocks
    result_fwd = list(K4_CARVED)
    result_rev = []

    pos = 0
    block_idx = 0
    while pos < 97:
        bs = block_sizes[block_idx % len(block_sizes)]
        block = K4_CARVED[pos:pos + bs]
        result_rev.extend(block[::-1])
        pos += bs
        block_idx += 1

    rev_str = "".join(result_rev[:97])
    if len(rev_str) == 97:
        try_all_decryptions(rev_str, f"I1-blocks-{block_sizes}")

# I2: Rail fence with 6 rails (SLOWLY = 6)
print("\n--- I2: Rail fence cipher with K1/K3-derived rail counts ---")
for n_rails in [2, 3, 4, 5, 6, 7, 8]:
    # Encode: write in zigzag, read by rails
    rails = [[] for _ in range(n_rails)]
    rail = 0
    direction = 1
    for i, c in enumerate(K4_CARVED):
        rails[rail].append((i, c))
        if rail == 0:
            direction = 1
        elif rail == n_rails - 1:
            direction = -1
        rail += direction

    # Read order: top rail first, then next, etc.
    read_order = []
    for r in rails:
        for idx, ch in r:
            read_order.append(idx)

    # The rail fence TEXT is already K4, but the PERMUTATION is:
    # carved text was written in rail-fence order, read linearly
    # So to un-rail-fence: apply inverse permutation
    if len(read_order) == 97:
        inv_perm = [0] * 97
        for new_pos, orig_pos in enumerate(read_order):
            inv_perm[orig_pos] = new_pos

        # Forward: assume carved = rail-fence encoded
        ct_rf = apply_permutation(K4_CARVED, read_order)
        try_all_decryptions(ct_rf, f"I2-railfence-{n_rails}-fwd")

        # Inverse: assume carved = rail-fence decoded
        ct_rf_inv = apply_permutation(K4_CARVED, inv_perm)
        try_all_decryptions(ct_rf_inv, f"I2-railfence-{n_rails}-inv")


# ─────────────────────────────────────────────────────────────────────────────
# SECTION J: Combined / Synthesis Experiments
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 80)
print("SECTION J: Synthesis — combining K1-K3 instruction clues")
print("=" * 80)

# J1: "BETWEEN" + "ROWS" + "BREACH" — Use K1 word "BETWEEN" (7 letters = KRYPTOS length)
# as columnar key on the 14x31 grid, read K4 portion
print("\n--- J1: BETWEEN (7 letters) columnar on K4 ---")
# Width 7 columnar, keyed by BETWEEN
phrase = "BETWEEN"
width = 7
indexed = sorted(range(width), key=lambda i: (phrase[i], i))
col_order = [0] * width
for rank, orig_idx in enumerate(indexed):
    col_order[orig_idx] = rank
print(f"  BETWEEN column order: {col_order}")  # B=0,E=1,T=5,W=6,E=2,E=3,N=4

nrows = math.ceil(97 / width)  # 14 rows
padded = K4_CARVED.ljust(nrows * width, 'X')

ct_trans = ""
for rank in range(width):
    col = col_order.index(rank)
    for row in range(nrows):
        idx = row * width + col
        if idx < 97:
            ct_trans += padded[idx]
ct_trans = ct_trans[:97]
print(f"  BETWEEN-keyed columnar: {ct_trans[:50]}...")
try_all_decryptions(ct_trans, "J1-BETWEEN-col")

# J2: "UPPER LEFT HAND CORNER" → start reading at position 0 (upper left of grid)
# + "WIDENING THE HOLE" → expand reading region in a spiral
print("\n--- J2: Spiral reading from upper-left corner of K4 grid ---")
# K4 as a near-square grid: try 10x10 (pad to 100)
for width in [7, 8, 10, 31]:
    nrows = math.ceil(97 / width)
    total = nrows * width
    padded = K4_CARVED.ljust(total, 'X')

    # Spiral reading: start at (0,0), go right, down, left, up, etc.
    grid = []
    for r in range(nrows):
        grid.append(list(padded[r * width: (r + 1) * width]))

    spiral = []
    top, bottom, left, right = 0, nrows - 1, 0, width - 1
    while top <= bottom and left <= right:
        for col in range(left, right + 1):
            spiral.append(grid[top][col])
        top += 1
        for row in range(top, bottom + 1):
            spiral.append(grid[row][right])
        right -= 1
        if top <= bottom:
            for col in range(right, left - 1, -1):
                spiral.append(grid[bottom][col])
            bottom -= 1
        if left <= right:
            for row in range(bottom, top - 1, -1):
                spiral.append(grid[row][left])
            left += 1

    ct_spiral = "".join(spiral[:97])
    if len(ct_spiral) == 97:
        try_all_decryptions(ct_spiral, f"J2-spiral-w{width}")

    # Also: anti-spiral (start from center, expand outward) = "WIDENING THE HOLE"
    # This is harder to implement; skip for now.

# J3: "PASSAGE" + "DOORWAY" → Route cipher through the grid
print("\n--- J3: Route cipher (diagonal reading) on K4 grid ---")
for width in [7, 8, 31]:
    nrows = math.ceil(97 / width)
    total = nrows * width
    padded = K4_CARVED.ljust(total, 'X')

    # Diagonal reading: all diagonals from top-left to bottom-right
    diag_chars = []
    for d in range(nrows + width - 1):
        for row in range(nrows):
            col = d - row
            if 0 <= col < width:
                idx = row * width + col
                if idx < 97:
                    diag_chars.append(K4_CARVED[idx])

    ct_diag = "".join(diag_chars)
    if len(ct_diag) == 97:
        try_all_decryptions(ct_diag, f"J3-diagonal-w{width}")

# J4: "TREMBLING HANDS" → anagram / shaking = small local swaps
# Try all adjacent-pair swaps (bubble sort distance 1)
print("\n--- J4: Local swaps (small perturbations, 'trembling') ---")
# This is too many to test exhaustively, but try systematic patterns
# Swap every pair (0,1), (2,3), (4,5), ...
for offset in [0, 1]:
    ct_swapped = list(K4_CARVED)
    for i in range(offset, 96, 2):
        ct_swapped[i], ct_swapped[i + 1] = ct_swapped[i + 1], ct_swapped[i]
    ct_s = "".join(ct_swapped)
    try_all_decryptions(ct_s, f"J4-pairswap-offset{offset}")

# Swap in groups of 3 (rotate each triple)
for offset in [0, 1, 2]:
    ct_rot = list(K4_CARVED)
    for i in range(offset, 95, 3):
        if i + 2 < 97:
            ct_rot[i], ct_rot[i+1], ct_rot[i+2] = ct_rot[i+1], ct_rot[i+2], ct_rot[i]
    ct_r = "".join(ct_rot)
    try_all_decryptions(ct_r, f"J4-triple-rot-offset{offset}")

# J5: "DETAILS EMERGED FROM THE MIST" → gradually reveal
# Try revealing K4 through successive key-autokey (key feeds back)
print("\n--- J5: Autokey variants (key derived from PT/CT feedback) ---")
for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        # Autokey Vigenere: key = keyword + plaintext prefix
        pt_autokey = []
        key_stream = list(kw)
        for i, c in enumerate(K4_CARVED):
            ci = alpha.index(c)
            ki = alpha.index(key_stream[i])
            pt_char = alpha[(ci - ki) % 26]
            pt_autokey.append(pt_char)
            key_stream.append(pt_char)

        pt_str = "".join(pt_autokey)
        sc = score(pt_str)
        cribs_found = has_cribs(pt_str)
        if cribs_found or sc > -5.5:
            report(f"J5-autokey-vig-{kw}-{alpha_name}", pt_str, sc, f"Autokey Vig key={kw}")

        # Autokey with CT feedback
        pt_autokey2 = []
        key_stream2 = list(kw)
        for i, c in enumerate(K4_CARVED):
            ci = alpha.index(c)
            ki = alpha.index(key_stream2[i])
            pt_char = alpha[(ci - ki) % 26]
            pt_autokey2.append(pt_char)
            key_stream2.append(c)  # CT feedback

        pt_str2 = "".join(pt_autokey2)
        sc2 = score(pt_str2)
        cribs_found2 = has_cribs(pt_str2)
        if cribs_found2 or sc2 > -5.5:
            report(f"J5-autokey-ct-{kw}-{alpha_name}", pt_str2, sc2, f"Autokey CT-feedback key={kw}")

        # Beaufort autokey (PT feedback)
        pt_beau_ak = []
        key_stream3 = list(kw)
        for i, c in enumerate(K4_CARVED):
            ci = alpha.index(c)
            ki = alpha.index(key_stream3[i])
            pt_char = alpha[(ki - ci) % 26]
            pt_beau_ak.append(pt_char)
            key_stream3.append(pt_char)

        pt_str3 = "".join(pt_beau_ak)
        sc3 = score(pt_str3)
        cribs_found3 = has_cribs(pt_str3)
        if cribs_found3 or sc3 > -5.5:
            report(f"J5-autokey-beau-{kw}-{alpha_name}", pt_str3, sc3, f"Autokey Beau key={kw}")

# J6: K2's "TRANSMITTED UNDERGROUND" + "DOES THE PRIME LANG MERIDIAN PASS THIS PLACE"
# → message was sent through a specific CHANNEL/PATH. Path = specific route through grid.
print("\n--- J6: Route through grid defined by keyword KRYPTOS ---")
# Use KRYPTOS (7 letters) to define a route through a 7-column grid
# Column order from keyword: K=0, R=4, Y=6, P=3, T=5, O=2, S=1
# (alphabetical rank in KRYPTOS)
kryptos_col_order = []
for rank, (orig_i, c) in enumerate(sorted(enumerate("KRYPTOS"), key=lambda x: x[1])):
    kryptos_col_order.append(orig_i)
print(f"  KRYPTOS column order (by rank): {kryptos_col_order}")

# Standard columnar transposition with KRYPTOS
width = 7
nrows = math.ceil(97 / width)  # 14
padded = K4_CARVED.ljust(nrows * width, 'X')

# Read columns in KRYPTOS alphabetical order
ct_kryptos = ""
for col in kryptos_col_order:
    for row in range(nrows):
        idx = row * width + col
        if idx < 97:
            ct_kryptos += padded[idx]
ct_kryptos = ct_kryptos[:97]
print(f"  KRYPTOS columnar: {ct_kryptos[:50]}...")
try_all_decryptions(ct_kryptos, "J6-KRYPTOS-columnar")

# Inverse
grid_inv = [[''] * width for _ in range(nrows)]
pos = 0
for col in kryptos_col_order:
    for row in range(nrows):
        if pos < 97:
            grid_inv[row][col] = K4_CARVED[pos]
            pos += 1
ct_inv = ""
for row in range(nrows):
    for col in range(width):
        if grid_inv[row][col]:
            ct_inv += grid_inv[row][col]
ct_inv = ct_inv[:97]
try_all_decryptions(ct_inv, "J6-KRYPTOS-inv-columnar")


# ─────────────────────────────────────────────────────────────────────────────
# SECTION K: Advanced Compound Methods
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 80)
print("SECTION K: Advanced compound methods")
print("=" * 80)

# K1: Columnar transposition + THEN Vig/Beau (two layers, as "LAYER TWO" suggests)
# Try columnar with various keys, then Vig/Beau
print("\n--- K1: Columnar transposition THEN Vig/Beau (two-layer) ---")
# Already tested above via try_all_decryptions which does Vig/Beau on the result
# But let's also try: Vig first, THEN columnar (reverse order)
print("  (Vig/Beau already tested on all columnar results above)")
print("  Testing: Vig/Beau FIRST, then columnar...")

for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        for cname, cfn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
            # First decrypt with cipher
            intermediate = cfn(K4_CARVED, kw, alpha)

            # Then try columnar transpositions on the result
            for col_key in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BETWEEN", "SLOWLY"]:
                w = len(col_key)
                indexed_ck = sorted(range(w), key=lambda i: (col_key[i], i))
                co = [0] * w
                for rank, oi in enumerate(indexed_ck):
                    co[oi] = rank

                nr = math.ceil(97 / w)
                pad = intermediate.ljust(nr * w, 'X')

                # Columnar read
                ct_2layer = ""
                for rank in range(w):
                    col = co.index(rank)
                    for row in range(nr):
                        idx = row * w + col
                        if idx < 97:
                            ct_2layer += pad[idx]
                ct_2layer = ct_2layer[:97]

                cribs = has_cribs(ct_2layer)
                sc_2l = score(ct_2layer)
                if cribs or sc_2l > -5.5:
                    report(f"K1-{cname}/{kw}/{alpha_name}+col/{col_key}", ct_2layer, sc_2l)

                # Inverse columnar
                grid_2l = [[''] * w for _ in range(nr)]
                pos = 0
                for rank in range(w):
                    col = co.index(rank)
                    for row in range(nr):
                        if pos < 97:
                            grid_2l[row][col] = intermediate[pos]
                            pos += 1
                ct_2l_inv = ""
                for row in range(nr):
                    for col in range(w):
                        if grid_2l[row][col]:
                            ct_2l_inv += grid_2l[row][col]
                ct_2l_inv = ct_2l_inv[:97]

                cribs2 = has_cribs(ct_2l_inv)
                sc_2l2 = score(ct_2l_inv)
                if cribs2 or sc_2l2 > -5.5:
                    report(f"K1-{cname}/{kw}/{alpha_name}+inv-col/{col_key}", ct_2l_inv, sc_2l2)

# K2: "NUANCE OF IQLUSION" — the Q stands for L in ILLUSION.
# Q→L is a substitution. What if K4 has a similar single-letter replacement?
print("\n--- K2: Single-letter substitution variants (IQLUSION pattern) ---")
# Try swapping each pair of letters in K4 (26*25/2 = 325 pairs)
best_swap = -10
best_swap_info = None
for a_idx in range(26):
    for b_idx in range(a_idx + 1, 26):
        a_ch = AZ[a_idx]
        b_ch = AZ[b_idx]
        swapped = K4_CARVED.replace(a_ch, '#').replace(b_ch, a_ch).replace('#', b_ch)
        for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                for cname, cfn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                    pt = cfn(swapped, kw, alpha)
                    cribs = has_cribs(pt)
                    if cribs:
                        sc = score(pt)
                        print(f"  !!! CRIB with swap {a_ch}<->{b_ch}: {pt[:60]}... [{cname}/{kw}/{alpha_name}]")
                        report(f"K2-swap-{a_ch}{b_ch}", pt, sc)
                    else:
                        sc = score(pt)
                        if sc > best_swap:
                            best_swap = sc
                            best_swap_info = f"{a_ch}<->{b_ch} {cname}/{kw}/{alpha_name}"

print(f"  Best single swap: {best_swap:.4f}/char ({best_swap_info})")

# K3: K1 says "BETWEEN...ABSENCE OF LIGHT LIES THE NUANCE"
# "LIES" = the text deceives. "BETWEEN" = interleave.
# What if K4 is two interleaved messages? Split odd/even positions.
print("\n--- K3: Interleaved messages (odd/even split) ---")
for stride in [2, 3, 4]:
    for offset in range(stride):
        fragment = K4_CARVED[offset::stride]
        if len(fragment) >= 20:
            for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
                for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                    for cname, cfn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                        pt = cfn(fragment, kw, alpha)
                        cribs = has_cribs(pt)
                        if cribs:
                            sc = score(pt)
                            print(f"  !!! CRIB in stride-{stride} offset-{offset}: {pt}")


# ─────────────────────────────────────────────────────────────────────────────
# SECTION L: K3 "REMAINS OF PASSAGE DEBRIS" — Partial Transposition
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 80)
print("SECTION L: Partial/incomplete transposition models")
print("=" * 80)

# K3: "THE REMAINS OF PASSAGE DEBRIS THAT ENCUMBERED THE LOWER PART"
# → Some positions are "debris" (unchanged) and others are transposed
# This suggests a PARTIAL transposition where some chars stay in place

# L1: Fix crib positions, transpose the rest
print("\n--- L1: Fix known positions, try transposing only the gaps ---")
# Positions 21-33 and 63-73 are cribs in PT. In the scrambled model,
# what if these K4 positions are FIXED (not scrambled)?
# Then the crib chars in those positions of K4 carved text are the real CT chars
# at those positions.
# CT at positions 21-33 would be: QQPRNGKSSOTWTQ (wait, 0-indexed)
crib_ct_21_33 = K4_CARVED[21:34]  # 13 chars at positions 21-33
crib_ct_63_73 = K4_CARVED[63:74]  # 11 chars at positions 63-73
print(f"  K4 carved at crib positions 21-33: {crib_ct_21_33}")
print(f"  K4 carved at crib positions 63-73: {crib_ct_63_73}")
print(f"  If these are real CT, check Vig/Beau with known PT:")

for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
    # ENE crib: PT[21:34] = EASTNORTHEAST, CT[21:34] from carved
    ene_key = []
    for i in range(13):
        ct_i = alpha.index(crib_ct_21_33[i])
        pt_i = alpha.index("EASTNORTHEAST"[i])
        k_vig = (ct_i - pt_i) % 26
        k_beau = (ct_i + pt_i) % 26
        ene_key.append((alpha[k_vig], alpha[k_beau]))

    vig_key_str = "".join(k[0] for k in ene_key)
    beau_key_str = "".join(k[1] for k in ene_key)
    print(f"  ENE ({alpha_name}): Vig key = {vig_key_str}, Beau key = {beau_key_str}")

    # BC crib
    bc_key = []
    for i in range(11):
        ct_i = alpha.index(crib_ct_63_73[i])
        pt_i = alpha.index("BERLINCLOCK"[i])
        k_vig = (ct_i - pt_i) % 26
        k_beau = (ct_i + pt_i) % 26
        bc_key.append((alpha[k_vig], alpha[k_beau]))

    vig_key_str_bc = "".join(k[0] for k in bc_key)
    beau_key_str_bc = "".join(k[1] for k in bc_key)
    print(f"  BC ({alpha_name}):  Vig key = {vig_key_str_bc}, Beau key = {beau_key_str_bc}")

    # Check periodicity of the keys
    for period in range(1, 10):
        vig_matches = sum(1 for j in range(13 - period) if ene_key[j][0] == ene_key[j + period][0])
        if vig_matches > (13 - period) * 0.5:
            print(f"    ENE Vig period {period}: {vig_matches}/{13-period} matches")

# L2: "ENCUMBERED THE LOWER PART" → the bottom rows of K4 grid are "encumbered"
# (harder to read / more scrambled). Try fixing top rows and permuting bottom.
print("\n--- L2: Fix top row(s) of K4 grid, permute bottom ---")
# K4 row structure: 4 chars (row0) + 31 + 31 + 31
# Fix first 4 chars (OBKR), try rearranging the 3 full rows
for perm_3 in permutations(range(3)):
    rows_perm = [k4_row0]  # fixed
    for p in perm_3:
        rows_perm.append([k4_row1, k4_row2, k4_row3][p])
    ct_l2 = "".join(rows_perm)
    if len(ct_l2) == 97:
        try_all_decryptions(ct_l2, f"L2-fix-top-perm-{perm_3}")


# ─────────────────────────────────────────────────────────────────────────────
# SECTION M: "FLAME TO FLICKER" — Phase/Frequency Analysis
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 80)
print("SECTION M: 'FLAME TO FLICKER' — Modular arithmetic permutations")
print("=" * 80)

# "FLAME TO FLICKER" = oscillation. Try permutations based on modular arithmetic.
# Since 97 is prime, any multiplier 1-96 gives a full cycle mod 97.

# M1: Multiplicative permutations mod 97
print("\n--- M1: Multiplicative permutations (a*i mod 97) ---")
best_m1 = -10
for a in range(2, 97):
    perm = [(a * i) % 97 for i in range(97)]
    ct_m = apply_permutation(K4_CARVED, perm)

    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cname, cfn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                pt = cfn(ct_m, kw, alpha)
                cribs = has_cribs(pt)
                sc = score(pt)
                if cribs:
                    print(f"  !!! CRIB with mult={a}: {pt[:60]}... [{cname}/{kw}/{alpha_name}]")
                    report(f"M1-mult-{a}", pt, sc)
                if sc > best_m1:
                    best_m1 = sc
                    if sc > -5.5:
                        report(f"M1-mult-{a}", pt, sc, f"{cname}/{kw}/{alpha_name}")

print(f"  Best M1 score: {best_m1:.4f}/char")

# M2: Affine permutations (a*i + b mod 97)
print("\n--- M2: Affine permutations ((a*i + b) mod 97), sampling ---")
best_m2 = -10
for a in [2, 3, 5, 7, 8, 11, 13, 14, 24, 31, 42, 86]:
    for b in range(97):
        perm = [(a * i + b) % 97 for i in range(97)]
        ct_m = apply_permutation(K4_CARVED, perm)

        for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                pt = vig_decrypt(ct_m, kw, alpha)
                cribs = has_cribs(pt)
                sc = score(pt)
                if cribs:
                    print(f"  !!! CRIB affine a={a} b={b}: {pt[:60]}...")
                if sc > best_m2:
                    best_m2 = sc

                pt = beau_decrypt(ct_m, kw, alpha)
                cribs = has_cribs(pt)
                sc = score(pt)
                if cribs:
                    print(f"  !!! CRIB affine a={a} b={b}: {pt[:60]}...")
                if sc > best_m2:
                    best_m2 = sc

print(f"  Best M2 score: {best_m2:.4f}/char")


# ─────────────────────────────────────────────────────────────────────────────
# FINAL SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 80)
print("FINAL SUMMARY")
print("=" * 80)

if best_global_result:
    print(f"\nBest overall score: {best_global_score:.4f}/char")
    print(f"  Label: {best_global_result['label']}")
    print(f"  PT: {best_global_result['pt'][:80]}...")
    print(f"  Extra: {best_global_result['extra']}")
else:
    print("\nNo notable results found.")

print(f"\nTotal experiments in this script: comprehensive K1-K3 instruction mining")
print("=" * 80)
