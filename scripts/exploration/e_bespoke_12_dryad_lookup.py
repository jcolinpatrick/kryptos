#!/usr/bin/env python3
"""
Cipher: exploratory/bespoke
Family: exploration
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-BESPOKE-12: 2D DRYAD lookup from K1/K2/K3 plaintext and ciphertext.

Hypothesis: Fill a grid with K1/K2/K3 text, then decrypt K4 by looking up
characters in this grid using a 2D addressing scheme (CT letter + position).
A DRYAD sheet is a military one-time lookup table. The "coding charts" sold
at auction ($962.5K) may be a modified DRYAD-style encoding sheet.

Phases:
  1. Build lookup grids from K1/K2/K3 PT/CT at various widths
  2. Method A: CT letter -> row, position -> column
  3. Method B: Position -> row, CT letter -> column
  4. Method C: Same as A/B but using KRYPTOS alphabet indices
  5. Method D: Substitution from grid (find CT letter in row, return col header)
  6. XOR/Subtraction model (grid as running key source)
  7. Running key from grid read in various orders

Usage: PYTHONPATH=src python3 -u scripts/e_bespoke_12_dryad_lookup.py
"""

import sys
import time

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, CRIB_WORDS, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET, NOISE_FLOOR,
)

# ── Setup ─────────────────────────────────────────────────────────────

AZ = ALPH
AZ_IDX = ALPH_IDX
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

CT_AZ = [AZ_IDX[c] for c in CT]
CRIB_POSITIONS = sorted(CRIB_DICT.keys())
CRIB_PT_AZ = {pos: AZ_IDX[ch] for pos, ch in CRIB_DICT.items()}

N = CT_LEN  # 97

def clean(s):
    return ''.join(c for c in s.upper() if c in AZ)

def score_cribs(pt_chars):
    """Count crib matches. pt_chars is list of uppercase chars, length 97."""
    if len(pt_chars) < N:
        return 0
    return sum(1 for pos in CRIB_POSITIONS if pt_chars[pos] == CRIB_DICT[pos])

def score_cribs_num(pt_nums):
    """Count crib matches. pt_nums is list of ints (0-25), length 97."""
    if len(pt_nums) < N:
        return 0
    return sum(1 for pos in CRIB_POSITIONS if pt_nums[pos] == CRIB_PT_AZ[pos])

# ── K1/K2/K3 Plaintexts (verified from repo) ─────────────────────────

# K1 plaintext — two variants (NUALCE vs NUANCE)
K1_PT_V1 = clean("BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUALCEOFIQLUSION")
K1_PT_V2 = clean("BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION")

# K2 plaintext (with Sanborn's UNDERGRUUND misspelling)
K2_PT = clean(
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSED"
    "THEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHERED"
    "ANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONX"
    "DOESLANGLEYKNOWABOUTTHISTHEYSHOULDITS BURIEDOUT"
    "THERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWW"
    "THISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTY"
    "SEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVEN"
    "DEGREESEIGHTMINUTESFORTYFOURSECONDSWES TLAYERTWO"
)

# K3 plaintext (with Sanborn's DESPARATLY misspelling)
K3_PT = clean(
    "SLOWLYDESPARATLYSLOW LYTHEREMAINS OFPASSAGEDEBRIS"
    "THATENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVED"
    "WITHTREMB LINGHANDSIMADETINYBREACHINTHEUPPERLEFT"
    "HANDCORNERANDTHENW IDENINGTHEHOLEALITTLEIINSERTED"
    "THECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHE"
    "CHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILS"
    "OFTHEROOMWITHIN EMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ"
)

# K3 with corrected spelling
K3_PT_CORRECT = clean(
    "SLOWLYDESPERATELYSLOWLYTHEREMAINSOFPASSAGEDEBRIS"
    "THATENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVED"
    "WITHTREMBLING HANDSIMADEATINYBREACHINTHEUPPERLEFT"
    "HANDCORNERANDTHENW IDENINGTHEHOLEALITTLEIINSERTED"
    "THECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHE"
    "CHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILS"
    "OFTHEROOMWITHINMERGEDFROMTHEMISTCANYOUSEEANYTHINGQ"
)

# K2 with corrected spelling
K2_PT_CORRECT = clean(
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSED"
    "THEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHERED"
    "ANDTRANSMITTEDUNDERGROUNDTOANUNKNOWNLOCATIONX"
    "DOESLANGLEYKNOWABOUTTHISTHEYSHOULDITS BURIEDOUT"
    "THERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWW"
    "THISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTY"
    "SEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVEN"
    "DEGREESEIGHTMINUTESFORTYFOURSECONDSWES TLAYERTWO"
)

# K1/K2/K3 Ciphertexts (from the sculpture)
K1_CT = clean("EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD")
K2_CT = clean(
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKK"
    "DQMCPFQZDQMMIAGPFXHQRLGTIMVMZJANQLVKQE"
    "DAGARQMCQAQVJQCDZAOHQCQAAGJQKMMFDAZQFHQQ"
    "KDQMQPQABQKNQIDNQERTEAEZQVPQNNTQQMJQQ"
    "SQJQWNSQVQIQQVJQCKAQKQMMFDAZQFHQQ"
)
K3_CT = clean(
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLLSLKNQIORAATOYETW"
    "QRXTQRSKSPTQUMWKFLRUQISASXDGMMJKJDMQICQTGLKZUGYSYQXQKOFYPJ"
    "XZHQKTAYGCUEOGXIXEFGIUZEJTQHNZ"
)

# Build all source texts
SOURCES = {}

# Plaintexts
SOURCES["K1_v1"] = K1_PT_V1
SOURCES["K1_v2_nuance"] = K1_PT_V2
SOURCES["K2"] = K2_PT
SOURCES["K2_correct"] = K2_PT_CORRECT
SOURCES["K3"] = K3_PT
SOURCES["K3_correct"] = K3_PT_CORRECT

# Concatenations
SOURCES["K1+K2+K3"] = K1_PT_V2 + K2_PT + K3_PT
SOURCES["K2+K3"] = K2_PT + K3_PT
SOURCES["K3+K2+K1"] = K3_PT + K2_PT + K1_PT_V2
SOURCES["K1+K2+K3_correct"] = K1_PT_V2 + K2_PT_CORRECT + K3_PT_CORRECT

# Ciphertexts
SOURCES["K1_CT"] = K1_CT
SOURCES["K2_CT"] = K2_CT
SOURCES["K3_CT"] = K3_CT
SOURCES["K1+K2+K3_CT"] = K1_CT + K2_CT + K3_CT

# Reversed
SOURCES["K1+K2+K3_rev"] = (K1_PT_V2 + K2_PT + K3_PT)[::-1]
SOURCES["K2+K3_rev"] = (K2_PT + K3_PT)[::-1]

WIDTHS = [7, 9, 10, 11, 13, 14, 26]

REPORT_THRESHOLD = 7  # Report anything >= 7/24

# ── Grid builder ──────────────────────────────────────────────────────

def build_grid(text, width):
    """Build a 2D grid from text with given width. Returns list of rows (each a list of chars)."""
    rows = []
    for i in range(0, len(text), width):
        row = list(text[i:i+width])
        if len(row) < width:
            # Pad with wrapping
            for j in range(width - len(row)):
                row.append(text[(i + len(row) + j) % len(text)])
        rows.append(row)
    return rows

def build_grid_num(text, width, idx_map):
    """Build numeric grid. Returns list of rows (each a list of ints)."""
    grid = build_grid(text, width)
    return [[idx_map[c] for c in row] for row in grid]

# ── Results tracking ──────────────────────────────────────────────────

best_overall = 0
total_configs = 0

def report(method, source_name, width, extra, score, pt_str):
    global best_overall
    if score > best_overall:
        best_overall = score
    if score >= REPORT_THRESHOLD:
        print(f"  ** SCORE {score}/24: {method} | src={source_name} | w={width} | {extra}")
        print(f"     PT: {pt_str}")

# ── Phase 1 setup (grids built on demand) ─────────────────────────────

print("=" * 70)
print("E-BESPOKE-12: 2D DRYAD Lookup from K1/K2/K3 Text")
print(f"  Sources: {len(SOURCES)}, Widths: {WIDTHS}")
print(f"  K4 CT length: {N}")
print("=" * 70)
t0 = time.time()

# ── Phase 2: Method A — CT letter selects row, position selects column ─

print("\n--- Phase 2: Method A (CT letter -> row, position -> col) ---")
phase_count = 0
for src_name, src_text in SOURCES.items():
    for w in WIDTHS:
        grid = build_grid(src_text, w)
        n_rows = len(grid)

        # A1: row = ALPH_IDX[CT[i]] % n_rows, col = i % w
        pt = []
        for i in range(N):
            row = AZ_IDX[CT[i]] % n_rows
            col = i % w
            pt.append(grid[row][col])
        sc = score_cribs(pt)
        phase_count += 1
        report("A1_AZ", src_name, w, f"rows={n_rows}", sc, ''.join(pt))

        # A2: row = KA_IDX[CT[i]] % n_rows, col = i % w
        pt = []
        for i in range(N):
            row = KA_IDX[CT[i]] % n_rows
            col = i % w
            pt.append(grid[row][col])
        sc = score_cribs(pt)
        phase_count += 1
        report("A2_KA", src_name, w, f"rows={n_rows}", sc, ''.join(pt))

total_configs += phase_count
print(f"  Phase 2 done: {phase_count} configs, best so far: {best_overall}/24")

# ── Phase 3: Method B — Position selects row, CT letter selects column ─

print("\n--- Phase 3: Method B (position -> row, CT letter -> col) ---")
phase_count = 0
for src_name, src_text in SOURCES.items():
    for w in WIDTHS:
        grid = build_grid(src_text, w)
        n_rows = len(grid)

        # B1: row = i % n_rows, col = ALPH_IDX[CT[i]] % w
        pt = []
        for i in range(N):
            row = i % n_rows
            col = AZ_IDX[CT[i]] % w
            pt.append(grid[row][col])
        sc = score_cribs(pt)
        phase_count += 1
        report("B1_AZ", src_name, w, f"rows={n_rows}", sc, ''.join(pt))

        # B2: row = i // w, col = ALPH_IDX[CT[i]] % w
        pt = []
        for i in range(N):
            row = (i // w) % n_rows
            col = AZ_IDX[CT[i]] % w
            pt.append(grid[row][col])
        sc = score_cribs(pt)
        phase_count += 1
        report("B2_AZ", src_name, w, f"rows={n_rows}", sc, ''.join(pt))

        # B3: row = i % n_rows, col = KA_IDX[CT[i]] % w
        pt = []
        for i in range(N):
            row = i % n_rows
            col = KA_IDX[CT[i]] % w
            pt.append(grid[row][col])
        sc = score_cribs(pt)
        phase_count += 1
        report("B3_KA", src_name, w, f"rows={n_rows}", sc, ''.join(pt))

        # B4: row = i // w, col = KA_IDX[CT[i]] % w
        pt = []
        for i in range(N):
            row = (i // w) % n_rows
            col = KA_IDX[CT[i]] % w
            pt.append(grid[row][col])
        sc = score_cribs(pt)
        phase_count += 1
        report("B4_KA", src_name, w, f"rows={n_rows}", sc, ''.join(pt))

total_configs += phase_count
print(f"  Phase 3 done: {phase_count} configs, best so far: {best_overall}/24")

# ── Phase 4: Method C — Mixed addressing (CT idx for one, position for other) ─

print("\n--- Phase 4: Method C (additional KA-indexed addressing) ---")
phase_count = 0
for src_name, src_text in SOURCES.items():
    for w in WIDTHS:
        grid = build_grid(src_text, w)
        n_rows = len(grid)

        # C1: row = (ALPH_IDX[CT[i]] + i) % n_rows, col = i % w
        pt = []
        for i in range(N):
            row = (AZ_IDX[CT[i]] + i) % n_rows
            col = i % w
            pt.append(grid[row][col])
        sc = score_cribs(pt)
        phase_count += 1
        report("C1_sum", src_name, w, f"rows={n_rows}", sc, ''.join(pt))

        # C2: row = (ALPH_IDX[CT[i]] * i) % n_rows, col = i % w (multiplicative)
        pt = []
        for i in range(N):
            row = (AZ_IDX[CT[i]] * (i + 1)) % n_rows
            col = i % w
            pt.append(grid[row][col])
        sc = score_cribs(pt)
        phase_count += 1
        report("C2_mult", src_name, w, f"rows={n_rows}", sc, ''.join(pt))

        # C3: row = ALPH_IDX[CT[i]] % n_rows, col = (ALPH_IDX[CT[i]] + i) % w
        pt = []
        for i in range(N):
            row = AZ_IDX[CT[i]] % n_rows
            col = (AZ_IDX[CT[i]] + i) % w
            pt.append(grid[row][col])
        sc = score_cribs(pt)
        phase_count += 1
        report("C3_mixed", src_name, w, f"rows={n_rows}", sc, ''.join(pt))

        # C4: row = KA_IDX[CT[i]] % n_rows, col = (KA_IDX[CT[i]] + i) % w
        pt = []
        for i in range(N):
            row = KA_IDX[CT[i]] % n_rows
            col = (KA_IDX[CT[i]] + i) % w
            pt.append(grid[row][col])
        sc = score_cribs(pt)
        phase_count += 1
        report("C4_KA_mixed", src_name, w, f"rows={n_rows}", sc, ''.join(pt))

total_configs += phase_count
print(f"  Phase 4 done: {phase_count} configs, best so far: {best_overall}/24")

# ── Phase 5: Method D — Substitution from grid ──────────────────────

print("\n--- Phase 5: Method D (find CT letter in grid row, return col header) ---")
phase_count = 0
for src_name, src_text in SOURCES.items():
    for w in WIDTHS:
        grid = build_grid(src_text, w)
        n_rows = len(grid)

        # D1: For position i, pick row = i % n_rows. Search for CT[i] in that row.
        # If found at column j, PT[i] = ALPH[j % 26]
        pt = []
        valid = True
        for i in range(N):
            row = i % n_rows
            ct_char = CT[i]
            found = False
            for j, c in enumerate(grid[row]):
                if c == ct_char:
                    pt.append(AZ[j % 26])
                    found = True
                    break
            if not found:
                # Letter not in this row — use position mod 26
                pt.append(AZ[i % 26])
                valid = False
        sc = score_cribs(pt)
        phase_count += 1
        report("D1_rowsearch", src_name, w, f"rows={n_rows}", sc, ''.join(pt))

        # D2: For position i, pick row = i // w. Search for CT[i] in that row.
        pt = []
        for i in range(N):
            row = (i // w) % n_rows
            ct_char = CT[i]
            found = False
            for j, c in enumerate(grid[row]):
                if c == ct_char:
                    pt.append(AZ[j % 26])
                    found = True
                    break
            if not found:
                pt.append(AZ[i % 26])
        sc = score_cribs(pt)
        phase_count += 1
        report("D2_rowsearch", src_name, w, f"rows={n_rows}", sc, ''.join(pt))

        # D3: For position i, pick col = i % w. Search for CT[i] in that column.
        # If found at row j, PT[i] = ALPH[j % 26]
        pt = []
        for i in range(N):
            col = i % w
            ct_char = CT[i]
            found = False
            for j in range(n_rows):
                if grid[j][col] == ct_char:
                    pt.append(AZ[j % 26])
                    found = True
                    break
            if not found:
                pt.append(AZ[i % 26])
        sc = score_cribs(pt)
        phase_count += 1
        report("D3_colsearch", src_name, w, f"rows={n_rows}", sc, ''.join(pt))

total_configs += phase_count
print(f"  Phase 5 done: {phase_count} configs, best so far: {best_overall}/24")

# ── Phase 6: XOR/Subtraction model ──────────────────────────────────

print("\n--- Phase 6: Grid as running key source (Vig/Beau subtraction) ---")
phase_count = 0
for src_name, src_text in SOURCES.items():
    src_num = [AZ_IDX[c] for c in src_text]
    src_num_ka = [KA_IDX[c] for c in src_text]

    for w in WIDTHS:
        grid_num = build_grid_num(src_text, w, AZ_IDX)
        grid_num_ka = build_grid_num(src_text, w, KA_IDX)
        n_rows = len(grid_num)

        # 6A: Sequential reading: key[i] = grid[i // w][i % w]
        key_seq = []
        for i in range(N):
            r = (i // w) % n_rows
            c = i % w
            key_seq.append(grid_num[r][c])

        # Vigenere: PT = (CT - key) mod 26
        pt_vig = [(CT_AZ[i] - key_seq[i]) % 26 for i in range(N)]
        sc = score_cribs_num(pt_vig)
        phase_count += 1
        report("6A_seq_Vig", src_name, w, "", sc, ''.join(AZ[v] for v in pt_vig))

        # Beaufort: PT = (key - CT) mod 26
        pt_beau = [(key_seq[i] - CT_AZ[i]) % 26 for i in range(N)]
        sc = score_cribs_num(pt_beau)
        phase_count += 1
        report("6A_seq_Beau", src_name, w, "", sc, ''.join(AZ[v] for v in pt_beau))

        # Variant Beaufort: PT = (CT + key) mod 26
        pt_vb = [(CT_AZ[i] + key_seq[i]) % 26 for i in range(N)]
        sc = score_cribs_num(pt_vb)
        phase_count += 1
        report("6A_seq_VBeau", src_name, w, "", sc, ''.join(AZ[v] for v in pt_vb))

        # 6B: Column-major reading: key[i] = grid[i % n_rows][i // n_rows % w]
        key_col = []
        for i in range(N):
            r = i % n_rows
            c = (i // n_rows) % w
            key_col.append(grid_num[r][c])

        pt_vig = [(CT_AZ[i] - key_col[i]) % 26 for i in range(N)]
        sc = score_cribs_num(pt_vig)
        phase_count += 1
        report("6B_col_Vig", src_name, w, "", sc, ''.join(AZ[v] for v in pt_vig))

        pt_beau = [(key_col[i] - CT_AZ[i]) % 26 for i in range(N)]
        sc = score_cribs_num(pt_beau)
        phase_count += 1
        report("6B_col_Beau", src_name, w, "", sc, ''.join(AZ[v] for v in pt_beau))

        pt_vb = [(CT_AZ[i] + key_col[i]) % 26 for i in range(N)]
        sc = score_cribs_num(pt_vb)
        phase_count += 1
        report("6B_col_VBeau", src_name, w, "", sc, ''.join(AZ[v] for v in pt_vb))

        # 6C: KA alphabet subtraction
        key_seq_ka = []
        for i in range(N):
            r = (i // w) % n_rows
            c = i % w
            key_seq_ka.append(grid_num_ka[r][c])

        ct_ka = [KA_IDX[c] for c in CT]
        pt_vig_ka = [(ct_ka[i] - key_seq_ka[i]) % 26 for i in range(N)]
        sc_ka = score_cribs([KA[v] for v in pt_vig_ka])
        phase_count += 1
        report("6C_seq_KA_Vig", src_name, w, "", sc_ka, ''.join(KA[v] for v in pt_vig_ka))

        pt_beau_ka = [(key_seq_ka[i] - ct_ka[i]) % 26 for i in range(N)]
        sc_ka = score_cribs([KA[v] for v in pt_beau_ka])
        phase_count += 1
        report("6C_seq_KA_Beau", src_name, w, "", sc_ka, ''.join(KA[v] for v in pt_beau_ka))

total_configs += phase_count
print(f"  Phase 6 done: {phase_count} configs, best so far: {best_overall}/24")

# ── Phase 7: Running key from grid read in various orders ─────────────

print("\n--- Phase 7: Running key from grid read orders ---")
phase_count = 0

def read_row_major(grid, n_rows, w):
    """Read grid row by row, left to right."""
    out = []
    for r in range(n_rows):
        for c in range(w):
            out.append(grid[r][c])
    return out

def read_col_major(grid, n_rows, w):
    """Read grid column by column, top to bottom."""
    out = []
    for c in range(w):
        for r in range(n_rows):
            out.append(grid[r][c])
    return out

def read_spiral(grid, n_rows, w):
    """Read grid in clockwise spiral from top-left."""
    out = []
    top, bottom, left, right = 0, n_rows - 1, 0, w - 1
    while top <= bottom and left <= right:
        for c in range(left, right + 1):
            out.append(grid[top][c])
        top += 1
        for r in range(top, bottom + 1):
            out.append(grid[r][right])
        right -= 1
        if top <= bottom:
            for c in range(right, left - 1, -1):
                out.append(grid[bottom][c])
            bottom -= 1
        if left <= right:
            for r in range(bottom, top - 1, -1):
                out.append(grid[r][left])
            left += 1
    return out

def read_diagonal(grid, n_rows, w):
    """Read grid along diagonals (top-left to bottom-right)."""
    out = []
    for d in range(n_rows + w - 1):
        for r in range(max(0, d - w + 1), min(n_rows, d + 1)):
            c = d - r
            if 0 <= c < w:
                out.append(grid[r][c])
    return out

def read_boustrophedon(grid, n_rows, w):
    """Read grid alternating left-right and right-left by row."""
    out = []
    for r in range(n_rows):
        if r % 2 == 0:
            for c in range(w):
                out.append(grid[r][c])
        else:
            for c in range(w - 1, -1, -1):
                out.append(grid[r][c])
    return out

def read_reverse_row(grid, n_rows, w):
    """Read grid row by row, bottom to top."""
    out = []
    for r in range(n_rows - 1, -1, -1):
        for c in range(w):
            out.append(grid[r][c])
    return out

READERS = {
    "row": read_row_major,
    "col": read_col_major,
    "spiral": read_spiral,
    "diag": read_diagonal,
    "boustro": read_boustrophedon,
    "rev_row": read_reverse_row,
}

for src_name, src_text in SOURCES.items():
    for w in WIDTHS:
        grid = build_grid(src_text, w)
        n_rows = len(grid)

        for reader_name, reader_fn in READERS.items():
            chars = reader_fn(grid, n_rows, w)
            if len(chars) < N:
                # Extend by cycling
                full = chars * ((N // len(chars)) + 2)
                chars = full[:N]
            else:
                chars = chars[:N]

            key_num = [AZ_IDX[c] for c in chars]

            # Vigenere
            pt_vig = [(CT_AZ[i] - key_num[i]) % 26 for i in range(N)]
            sc = score_cribs_num(pt_vig)
            phase_count += 1
            report(f"7_{reader_name}_Vig", src_name, w, "", sc, ''.join(AZ[v] for v in pt_vig))

            # Beaufort
            pt_beau = [(key_num[i] - CT_AZ[i]) % 26 for i in range(N)]
            sc = score_cribs_num(pt_beau)
            phase_count += 1
            report(f"7_{reader_name}_Beau", src_name, w, "", sc, ''.join(AZ[v] for v in pt_beau))

            # Variant Beaufort
            pt_vb = [(CT_AZ[i] + key_num[i]) % 26 for i in range(N)]
            sc = score_cribs_num(pt_vb)
            phase_count += 1
            report(f"7_{reader_name}_VBeau", src_name, w, "", sc, ''.join(AZ[v] for v in pt_vb))

total_configs += phase_count
print(f"  Phase 7 done: {phase_count} configs, best so far: {best_overall}/24")

# ── Phase 8 (bonus): Offset sweeps for direct running key ────────────

print("\n--- Phase 8: Direct running key with offset sweep ---")
phase_count = 0

for src_name, src_text in SOURCES.items():
    src_len = len(src_text)
    src_num = [AZ_IDX[c] for c in src_text]

    for offset in range(src_len):
        # Build key from offset, wrapping
        key = [src_num[(offset + i) % src_len] for i in range(N)]

        # Vigenere
        pt_vig = [(CT_AZ[i] - key[i]) % 26 for i in range(N)]
        sc = score_cribs_num(pt_vig)
        phase_count += 1
        if sc >= REPORT_THRESHOLD:
            report("8_direct_Vig", src_name, 0, f"offset={offset}", sc, ''.join(AZ[v] for v in pt_vig))

        # Beaufort
        pt_beau = [(key[i] - CT_AZ[i]) % 26 for i in range(N)]
        sc = score_cribs_num(pt_beau)
        phase_count += 1
        if sc >= REPORT_THRESHOLD:
            report("8_direct_Beau", src_name, 0, f"offset={offset}", sc, ''.join(AZ[v] for v in pt_beau))

        # Variant Beaufort
        pt_vb = [(CT_AZ[i] + key[i]) % 26 for i in range(N)]
        sc = score_cribs_num(pt_vb)
        phase_count += 1
        if sc >= REPORT_THRESHOLD:
            report("8_direct_VBeau", src_name, 0, f"offset={offset}", sc, ''.join(AZ[v] for v in pt_vb))

        # KA Vigenere
        key_ka = [KA_IDX[src_text[(offset + i) % src_len]] for i in range(N)]
        ct_ka = [KA_IDX[c] for c in CT]
        pt_ka_vig = [(ct_ka[i] - key_ka[i]) % 26 for i in range(N)]
        sc = score_cribs([KA[v] for v in pt_ka_vig])
        phase_count += 1
        if sc >= REPORT_THRESHOLD:
            report("8_direct_KA_Vig", src_name, 0, f"offset={offset}", sc, ''.join(KA[v] for v in pt_ka_vig))

        # KA Beaufort
        pt_ka_beau = [(key_ka[i] - ct_ka[i]) % 26 for i in range(N)]
        sc = score_cribs([KA[v] for v in pt_ka_beau])
        phase_count += 1
        if sc >= REPORT_THRESHOLD:
            report("8_direct_KA_Beau", src_name, 0, f"offset={offset}", sc, ''.join(KA[v] for v in pt_ka_beau))

total_configs += phase_count
print(f"  Phase 8 done: {phase_count} configs, best so far: {best_overall}/24")

# ── Summary ───────────────────────────────────────────────────────────

elapsed = time.time() - t0
print("\n" + "=" * 70)
print(f"E-BESPOKE-12 COMPLETE")
print(f"  Total configs tested: {total_configs:,}")
print(f"  Best score: {best_overall}/24")
print(f"  Time: {elapsed:.1f}s")
if best_overall <= NOISE_FLOOR:
    print(f"  RESULT: ALL NOISE (best {best_overall} <= noise floor {NOISE_FLOOR})")
elif best_overall < 18:
    print(f"  RESULT: STORE-level hits, likely noise")
else:
    print(f"  RESULT: SIGNAL-level hits detected — investigate!")
print("=" * 70)
