#!/usr/bin/env python3
"""
VIC cipher keygroup from NDYAHR raised/displaced letters on Kryptos sculpture.

Cipher:  Simplified VIC (straddling checkerboard + columnar transposition)
Family:  analysis
Status:  active
Keyspace: ~50K configs (7 keygroups x dates x phrases x checkerboards x trans widths)
Last run: never
Best score: N/A

HYPOTHESIS: The raised/displaced letters on Kryptos (NDYAHR or subsets
NDYAR, DYAHR, NDYAH, DYARN, RAHYD) encode VIC-style keygroup digits when
converted via KA or AZ alphabet positions mod 10.

VIC keygroup = 5 digits derived from the sculpture's physical anomaly.
These digits seed the VIC key derivation pipeline (chain addition,
straddling checkerboard construction, transposition key generation).

NDYAHR positions in ENDYAHROHN... sequence on sculpture:
  N, D, Y, A, H, R = 6 letters, choose 5 for keygroup.

Digit conversions tested:
  KA (KRYPTOSABCDEFGHIJLMNQUVWXZ, 0-indexed):
    N=19->9, D=10->0, Y=2, A=7, H=14->4, R=1
  AZ (ABCDEFGHIJKLMNOPQRSTUVWXYZ, 0-indexed):
    N=13->3, D=3, Y=24->4, A=0, H=7, R=17->7

Keygroups: 90271, 02741, 90274, 02719, 17420, 33407, 34077
Plus NDYAHR full (6-digit): 902741

Also tests: raised letter POSITIONS in CT97 as keygroup insertion point.
"""
import sys
import json
import time
import math
from pathlib import Path
from itertools import permutations
from collections import Counter

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kryptos.kernel.constants import CT, CT_LEN, ALPH, KRYPTOS_ALPHABET, CRIB_WORDS

# ── Constants ────────────────────────────────────────────────────────────────
AZ = ALPH
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}
AZ_IDX = {c: i for i, c in enumerate(AZ)}

CRIB_ENE = "EASTNORTHEAST"
CRIB_BC = "BERLINCLOCK"

# ── Quadgram scorer ──────────────────────────────────────────────────────────
QUADGRAMS = {}
QG_FLOOR = -10.0

def load_quadgrams():
    global QUADGRAMS, QG_FLOOR
    qpath = Path(__file__).resolve().parents[2] / "data" / "english_quadgrams.json"
    with open(qpath) as f:
        QUADGRAMS = json.load(f)
    QG_FLOOR = min(QUADGRAMS.values()) - 1.0

def qscore(text):
    if len(text) < 4:
        return QG_FLOOR
    total = sum(QUADGRAMS.get(text[i:i+4], QG_FLOOR) for i in range(len(text) - 3))
    return total / (len(text) - 3)

# ── Keygroups from NDYAHR ────────────────────────────────────────────────────
# KA positions mod 10: N=9, D=0, Y=2, A=7, H=4, R=1
# AZ positions mod 10: N=3, D=3, Y=4, A=0, H=7, R=7

NDYAHR_KA = {'N': 9, 'D': 0, 'Y': 2, 'A': 7, 'H': 4, 'R': 1}
NDYAHR_AZ = {'N': 3, 'D': 3, 'Y': 4, 'A': 0, 'H': 7, 'R': 7}

KEYGROUPS = {
    # 5-letter subsets via KA
    "NDYAR_KA": [9, 0, 2, 7, 1],   # 90271
    "DYAHR_KA": [0, 2, 7, 4, 1],   # 02741
    "NDYAH_KA": [9, 0, 2, 7, 4],   # 90274
    "DYARN_KA": [0, 2, 7, 1, 9],   # 02719
    "RAHYD_KA": [1, 7, 4, 2, 0],   # 17420 (reversed)
    # 5-letter subsets via AZ
    "NDYAR_AZ": [3, 3, 4, 0, 7],   # 33407
    "DYAHR_AZ": [3, 4, 0, 7, 7],   # 34077
    "NDYAH_AZ": [3, 3, 4, 0, 7],   # 33407 (same as NDYAR_AZ by coincidence)
    "DYARN_AZ": [3, 4, 0, 7, 3],   # 34073
    "RAHYD_AZ": [7, 0, 7, 4, 3],   # 70743 (reversed)
    # Full 6-letter NDYAHR
    "NDYAHR_KA_6": [9, 0, 2, 7, 4, 1],  # 902741
    "NDYAHR_AZ_6": [3, 3, 4, 0, 7, 7],  # 334077
    # YAR only (3 confirmed raised)
    "YAR_KA": [2, 7, 1],   # 271
    "YAR_AZ": [4, 0, 7],   # 407 (pad to 5 with zeros)
    # DYARO (5 chars, alternative reading)
    "DYARO_KA": [0, 2, 7, 1, 5],   # 02715 (O=5 in KA)
    "DYARO_AZ": [3, 4, 0, 7, 4],   # 34074 (O=14->4 in AZ)
}

# ── VIC Date numbers ─────────────────────────────────────────────────────────
DATES = {
    "berlin_wall_ddmmyy": [0, 9, 1, 1, 8, 9],  # 09-11-1989
    "berlin_wall_mmddyy": [1, 1, 0, 9, 8, 9],  # 11-09-1989
    "kryptos_dedication": [0, 3, 1, 1, 9, 0],   # 03-11-1990
    "kryptos_ded_mmddyy": [1, 1, 0, 3, 9, 0],   # 11-03-1990
    "reunification_ddmmyy": [0, 3, 1, 0, 9, 0],  # 03-10-1990
    "reunification_mmddyy": [1, 0, 0, 3, 9, 0],  # 10-03-1990
    "cia_founding": [1, 8, 0, 9, 4, 7],          # 18-09-1947
    "berlin_wall_fall_yymmdd": [8, 9, 1, 1, 0, 9],
}

# Personal number (Scheidt's era number or significance of 5)
PERSONAL_NUMBERS = [5, 7, 3, 13, 24, 73, 97]

# ── VIC Key Derivation ───────────────────────────────────────────────────────

def chain_add(digits, length, modulus=10):
    """VIC-style lagged Fibonacci chain addition to expand digits."""
    result = list(digits)
    while len(result) < length:
        result.append((result[-len(digits)] + result[-len(digits)+1]) % modulus)
    return result[:length]

def chain_add_pair(digits, length, modulus=10):
    """Standard chain addition: each new digit = (d[-2] + d[-1]) mod M."""
    result = list(digits)
    while len(result) < length:
        result.append((result[-2] + result[-1]) % modulus)
    return result[:length]

def noncary_subtract(a, b, modulus=10):
    """Non-carrying subtraction (digit-by-digit mod)."""
    minlen = min(len(a), len(b))
    return [(a[i] - b[i]) % modulus for i in range(minlen)]

def noncary_add(a, b, modulus=10):
    """Non-carrying addition (digit-by-digit mod)."""
    minlen = min(len(a), len(b))
    return [(a[i] + b[i]) % modulus for i in range(minlen)]

def sequentialize(digits):
    """Rank digits to produce a permutation (ties broken left-to-right)."""
    indexed = [(d, i) for i, d in enumerate(digits)]
    ranked = sorted(indexed)
    perm = [0] * len(digits)
    for rank, (_, pos) in enumerate(ranked):
        perm[pos] = rank
    return perm

def vic_derive_intermediate(keygroup, date_digits, personal_num):
    """Simplified VIC intermediate key derivation.

    Step 1: Subtract first 5 date digits from keygroup (non-carrying)
    Step 2: Chain-add result to get 10 digits
    Step 3: Add personal number chain to get column permutation digits
    """
    kg = keygroup[:5] if len(keygroup) >= 5 else keygroup + [0] * (5 - len(keygroup))
    dd = date_digits[:5] if len(date_digits) >= 5 else date_digits + [0] * (5 - len(date_digits))

    # Step 1: non-carrying subtraction
    diff = noncary_subtract(kg, dd)

    # Step 2: chain addition to 10 digits
    expanded = chain_add_pair(diff, 10)

    # Step 3: add personal number cyclically
    pn_digits = []
    pn = personal_num
    while pn > 0:
        pn_digits.append(pn % 10)
        pn //= 10
    pn_digits = pn_digits[::-1] if pn_digits else [0]

    modified = [(expanded[i] + pn_digits[i % len(pn_digits)]) % 10 for i in range(10)]

    return expanded, modified

def build_checkerboard(top_row_letters, row_label_1, row_label_2, remaining_letters):
    """Build straddling checkerboard.

    top_row_letters: 8 letters for single-digit codes
    row_label_1, row_label_2: digits 0-9 used as row labels (escape digits)
    remaining_letters: 18 letters for double-digit codes

    Column headers are 0-9. Top row uses non-escape columns.
    """
    l2c = {}
    c2l = {}

    # Non-escape column digits
    non_escape = [d for d in range(10) if d != row_label_1 and d != row_label_2]

    # Top row: 8 single-digit codes
    for i, letter in enumerate(top_row_letters[:8]):
        if i < len(non_escape):
            digit = non_escape[i]
            l2c[letter] = (digit,)
            c2l[(digit,)] = letter

    # Row 1: 10 double-digit codes
    for col in range(10):
        idx = i + 1 if 'i' in dir() else 0
        # Actually index into remaining_letters
        pass

    # Better approach: fill rows sequentially
    idx = 0
    for col in range(10):
        if idx < 10 and idx < len(remaining_letters):
            l2c[remaining_letters[idx]] = (row_label_1, col)
            c2l[(row_label_1, col)] = remaining_letters[idx]
            idx += 1

    for col in range(10):
        if idx < 18 and idx < len(remaining_letters):
            code = (row_label_2, non_escape[col % len(non_escape)] if col < len(non_escape) else col)
            # Standard: row2 uses all 10 columns but only 8 non-escape
            l2c[remaining_letters[idx]] = (row_label_2, col)
            c2l[(row_label_2, col)] = remaining_letters[idx]
            idx += 1

    return l2c, c2l

def build_checkerboard_standard(fill_alphabet, row_labels):
    """Build standard straddling checkerboard from ordered alphabet and row labels.

    fill_alphabet: 26-char alphabet (first 8 go to top row, next 10 to row1, last 8 to row2)
    row_labels: tuple of 2 digits (escape digits)
    """
    r1, r2 = row_labels
    non_escape = [d for d in range(10) if d != r1 and d != r2]

    l2c = {}
    c2l = {}
    idx = 0

    # Top row: 8 letters at non-escape columns
    for col_idx, col_digit in enumerate(non_escape):
        if idx < len(fill_alphabet):
            l2c[fill_alphabet[idx]] = (col_digit,)
            c2l[(col_digit,)] = fill_alphabet[idx]
            idx += 1

    # Row r1: 10 letters at all columns
    for col in range(10):
        if idx < len(fill_alphabet):
            l2c[fill_alphabet[idx]] = (r1, col)
            c2l[(r1, col)] = fill_alphabet[idx]
            idx += 1

    # Row r2: 8 letters at non-escape columns
    for col_digit in non_escape:
        if idx < len(fill_alphabet):
            l2c[fill_alphabet[idx]] = (r2, col_digit)
            c2l[(r2, col_digit)] = fill_alphabet[idx]
            idx += 1

    return l2c, c2l

def encode_checkerboard(text, l2c):
    """Encode text to digit stream via checkerboard."""
    digits = []
    for ch in text:
        if ch in l2c:
            digits.extend(l2c[ch])
        else:
            return None  # unmappable character
    return digits

def decode_checkerboard(digits, row_labels, c2l):
    """Decode digit stream via checkerboard."""
    r1, r2 = row_labels
    result = []
    i = 0
    while i < len(digits):
        d = digits[i]
        if d == r1 or d == r2:
            if i + 1 >= len(digits):
                return None
            code = (d, digits[i+1])
            if code not in c2l:
                return None
            result.append(c2l[code])
            i += 2
        else:
            code = (d,)
            if code not in c2l:
                return None
            result.append(c2l[code])
            i += 1
    return ''.join(result)

def ct_to_digits_ka(ct):
    """Convert CT letters to digits via KA position mod 10."""
    return [KA_IDX[ch] % 10 for ch in ct]

def ct_to_digits_az(ct):
    """Convert CT letters to digits via AZ position mod 10."""
    return [AZ_IDX[ch] % 10 for ch in ct]

def keyword_mixed_alphabet(kw, base=AZ):
    """Build keyword-mixed alphabet."""
    seen = set()
    out = []
    for ch in kw.upper():
        if ch in set(base) and ch not in seen:
            seen.add(ch)
            out.append(ch)
    for ch in base:
        if ch not in seen:
            seen.add(ch)
            out.append(ch)
    return ''.join(out)

def columnar_undo(seq, width, col_order):
    """Undo columnar transposition given column reading order."""
    n = len(seq)
    nrows = math.ceil(n / width)
    rem = n % width

    # Column lengths
    col_lens = []
    for c in range(width):
        if rem == 0:
            col_lens.append(nrows)
        else:
            col_lens.append(nrows if c < rem else nrows - 1)

    # Split seq into columns according to col_order
    cols = [None] * width
    pos = 0
    for rank in range(width):
        col_idx = col_order.index(rank)
        cl = col_lens[col_idx]
        cols[col_idx] = seq[pos:pos+cl]
        pos += cl

    # Read off row-by-row
    result = []
    for r in range(nrows):
        for c in range(width):
            if cols[c] is not None and r < len(cols[c]):
                result.append(cols[c][r])

    if isinstance(seq, str):
        return ''.join(result)
    return result

def columnar_do(seq, width, col_order):
    """Apply columnar transposition: write row-by-row, read columns in order."""
    n = len(seq)
    nrows = math.ceil(n / width)

    # Build grid
    grid = []
    pos = 0
    for r in range(nrows):
        row = []
        for c in range(width):
            if pos < n:
                row.append(seq[pos])
                pos += 1
            else:
                row.append(None)
        grid.append(row)

    # Read columns in col_order
    result = []
    for rank in range(width):
        col_idx = col_order.index(rank)
        for r in range(nrows):
            if grid[r][col_idx] is not None:
                result.append(grid[r][col_idx])

    if isinstance(seq, str):
        return ''.join(result)
    return result

def check_cribs(text, free=False):
    """Check for cribs. Returns (total_score, ene_score, bc_score, ene_pos, bc_pos)."""
    if text is None:
        return 0, 0, 0, -1, -1

    if free:
        best = 0
        best_ep, best_bp = -1, -1
        n = len(text)
        for p in range(max(0, n - 12)):
            es = sum(1 for i, ch in enumerate(CRIB_ENE) if p+i < n and text[p+i] == ch)
            if es >= 3:
                for q in range(max(0, n - 10)):
                    bs = sum(1 for i, ch in enumerate(CRIB_BC) if q+i < n and text[q+i] == ch)
                    if es + bs > best:
                        best = es + bs
                        best_ep, best_bp = p, q
        return best, 0, 0, best_ep, best_bp
    else:
        # Fixed positions
        ene_s = 0
        bc_s = 0
        n = len(text)
        if 21 + 13 <= n:
            ene_s = sum(1 for i, ch in enumerate(CRIB_ENE) if text[21+i] == ch)
        if 63 + 11 <= n:
            bc_s = sum(1 for i, ch in enumerate(CRIB_BC) if text[63+i] == ch)
        return ene_s + bc_s, ene_s, bc_s, 21, 63

def find_ndyahr_in_ct():
    """Find positions of N, D, Y, A, H, R in K4 CT97."""
    positions = {}
    for ch in "NDYAHR":
        positions[ch] = [i for i, c in enumerate(CT) if c == ch]
    return positions

# ── Main ─────────────────────────────────────────────────────────────────────

def run():
    t0 = time.time()
    load_quadgrams()

    print("=" * 72)
    print("VIC NDYAHR KEYGROUP: Raised letters as VIC cipher keygroup digits")
    print("=" * 72)
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print()

    # ── Phase 0: NDYAHR digit conversions ─────────────────────────────────
    print("Phase 0: NDYAHR digit conversions")
    print(f"  KA alphabet: {KA}")
    print(f"  KA positions: " + ", ".join(f"{c}={KA_IDX[c]}({KA_IDX[c]%10})" for c in "NDYAHR"))
    print(f"  AZ positions: " + ", ".join(f"{c}={AZ_IDX[c]}({AZ_IDX[c]%10})" for c in "NDYAHR"))
    print()
    print("  Keygroups:")
    for name, digits in KEYGROUPS.items():
        print(f"    {name}: {''.join(str(d) for d in digits)}")
    print()

    # ── Phase 0b: NDYAHR positions in CT97 ────────────────────────────────
    print("Phase 0b: NDYAHR letter positions in CT97")
    ndyahr_positions = find_ndyahr_in_ct()
    for ch, positions in ndyahr_positions.items():
        print(f"  {ch}: positions {positions} (count={len(positions)})")

    # Possible keygroup insertion points from positions
    # Use first occurrence of each letter
    first_positions = {ch: pos[0] for ch, pos in ndyahr_positions.items() if pos}
    print(f"\n  First occurrences: {first_positions}")
    print(f"  As mod-10 digits: " + ", ".join(f"{ch}={first_positions[ch]%10}" for ch in "NDYAHR" if ch in first_positions))

    # Create keygroup from first-occurrence positions mod 10
    pos_keygroup = [first_positions[ch] % 10 for ch in "NDYAR" if ch in first_positions]
    if len(pos_keygroup) == 5:
        KEYGROUPS["NDYAR_pos_mod10"] = pos_keygroup
        print(f"  Position-derived keygroup (NDYAR): {''.join(str(d) for d in pos_keygroup)}")

    pos_keygroup6 = [first_positions[ch] % 10 for ch in "NDYAHR" if ch in first_positions]
    if len(pos_keygroup6) == 6:
        KEYGROUPS["NDYAHR_pos_mod10_6"] = pos_keygroup6
        print(f"  Position-derived keygroup (NDYAHR): {''.join(str(d) for d in pos_keygroup6)}")
    print()

    # ── Cipher components ─────────────────────────────────────────────────
    # Phrases for VIC-style key derivation
    PHRASES = {
        "KA_first20": list(KA[:20]),
        "A_SIN_TO_ERR": list("ASINTOERR"),  # Classic VIC top row
        "KRYPTOS": list("KRYPTOS"),
        "PALIMPSEST": list("PALIMPSEST"),
        "DEFECTOR": list("DEFECTOR"),
    }

    # Fill alphabets for checkerboard
    FILL_ALPHABETS = {
        "AZ": AZ,
        "KA": KA,
        "kw_KRYPTOS_AZ": keyword_mixed_alphabet("KRYPTOS", AZ),
        "kw_KRYPTOS_KA": keyword_mixed_alphabet("KRYPTOS", KA),
        "kw_DEFECTOR_AZ": keyword_mixed_alphabet("DEFECTOR", AZ),
        "kw_PALIMPSEST_AZ": keyword_mixed_alphabet("PALIMPSEST", AZ),
        "kw_ABSCISSA_AZ": keyword_mixed_alphabet("ABSCISSA", AZ),
        "kw_KOMPASS_AZ": keyword_mixed_alphabet("KOMPASS", AZ),
        "ASINTOER_AZ": "ASINTOERBCDFGHJKLMPQUVWXYZ"[:26],  # A SIN TO ERR top row style
    }
    # Ensure ASINTOER has all 26
    asintoer_seen = set()
    asintoer_alpha = []
    for ch in "ASINTOER":
        if ch not in asintoer_seen:
            asintoer_alpha.append(ch)
            asintoer_seen.add(ch)
    for ch in AZ:
        if ch not in asintoer_seen:
            asintoer_alpha.append(ch)
            asintoer_seen.add(ch)
    FILL_ALPHABETS["ASINTOER_AZ"] = ''.join(asintoer_alpha)

    # Checkerboard row label pairs to test
    ROW_LABELS = [
        (3, 8),  # from K2 "thirty-eight"
        (3, 7),  # from digits in keygroups
        (2, 7),  # YAR_KA first two digits
        (0, 9),  # from NDYAR_KA endpoints
        (0, 4),  # from DYAHR_KA endpoints
    ]

    # Transposition widths
    TRANS_WIDTHS = [5, 7, 8, 9, 10, 11, 13, 14]

    # Digit mapping functions
    DIGIT_MAPS = {
        "KA_mod10": ct_to_digits_ka,
        "AZ_mod10": ct_to_digits_az,
    }
    # Add keyword-mixed alphabet mappings
    for kw in ["KRYPTOS", "DEFECTOR", "PALIMPSEST", "ABSCISSA"]:
        alpha_az = keyword_mixed_alphabet(kw, AZ)
        idx_map = {ch: i % 10 for i, ch in enumerate(alpha_az)}
        DIGIT_MAPS[f"kw_{kw}_mod10"] = lambda ct, m=idx_map: [m[ch] for ch in ct]

    all_results = []
    total_configs = 0
    global_best_score = 0
    global_best_free = 0
    global_best_qg = QG_FLOOR

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 1: Simplified VIC — keygroup seeds checkerboard + single trans
    # Pipeline: CT97 -> digit_map -> digits -> subtract_additive ->
    #           checkerboard_decode -> undo_trans -> PT
    # ══════════════════════════════════════════════════════════════════════
    print("=" * 72)
    print("PHASE 1: Keygroup-seeded VIC pipeline")
    print("  CT -> digits -> subtract additive -> checkerboard -> undo trans -> PT")
    print("=" * 72)

    phase1_configs = 0
    phase1_best = 0
    phase1_best_free = 0
    phase1_hits = []

    for kg_name, kg_digits in KEYGROUPS.items():
        for date_name, date_digits in DATES.items():
            for pn in PERSONAL_NUMBERS:
                # Derive VIC intermediate key
                expanded, modified = vic_derive_intermediate(kg_digits, date_digits, pn)

                # Use expanded/modified as additive key (chain-add to 97 digits)
                additive_exp = chain_add_pair(expanded, 97)
                additive_mod = chain_add_pair(modified, 97)

                # Also derive transposition column order from modified digits
                if len(modified) >= 5:
                    trans_order_5 = sequentialize(modified[:5])
                    trans_order_7 = sequentialize(chain_add_pair(modified, 7)[:7])
                    trans_order_10 = sequentialize(modified[:10])
                else:
                    trans_order_5 = list(range(5))
                    trans_order_7 = list(range(7))
                    trans_order_10 = list(range(10))

                for map_name, map_fn in DIGIT_MAPS.items():
                    base_digits = map_fn(CT)

                    for additive_label, additive in [("expanded", additive_exp), ("modified", additive_mod)]:
                        # Subtract additive
                        adjusted = [(base_digits[i] - additive[i]) % 10 for i in range(97)]
                        # Also try adding
                        adjusted_add = [(base_digits[i] + additive[i]) % 10 for i in range(97)]

                        for adj_label, adj_digits in [("sub", adjusted), ("add", adjusted_add)]:
                            for fill_name, fill_alpha in FILL_ALPHABETS.items():
                                for rl in ROW_LABELS:
                                    phase1_configs += 1
                                    total_configs += 1

                                    l2c, c2l = build_checkerboard_standard(fill_alpha, rl)
                                    decoded = decode_checkerboard(adj_digits, rl, c2l)

                                    if decoded is None:
                                        continue

                                    pt_len = len(decoded)
                                    if pt_len < 50 or pt_len > 90:
                                        continue

                                    # Score without transposition first
                                    fixed_s, ene_s, bc_s, _, _ = check_cribs(decoded)
                                    free_s, _, _, fe, fb = check_cribs(decoded, free=True)
                                    qg = qscore(decoded)

                                    if fixed_s > phase1_best:
                                        phase1_best = fixed_s
                                    if free_s > phase1_best_free:
                                        phase1_best_free = free_s
                                    if fixed_s > global_best_score:
                                        global_best_score = fixed_s
                                    if free_s > global_best_free:
                                        global_best_free = free_s
                                    if qg > global_best_qg:
                                        global_best_qg = qg

                                    if fixed_s >= 5 or free_s >= 7 or pt_len == 73 or qg > -5.0:
                                        hit = {
                                            'phase': 1,
                                            'keygroup': kg_name,
                                            'date': date_name,
                                            'personal_num': pn,
                                            'digit_map': map_name,
                                            'additive': additive_label,
                                            'adj_op': adj_label,
                                            'fill': fill_name,
                                            'row_labels': rl,
                                            'trans': 'none',
                                            'pt_len': pt_len,
                                            'fixed': fixed_s,
                                            'free': free_s,
                                            'qg': round(qg, 3),
                                            'decoded': decoded[:60],
                                        }
                                        phase1_hits.append(hit)
                                        if fixed_s >= 5 or free_s >= 8 or pt_len == 73:
                                            print(f"  HIT: kg={kg_name} date={date_name} pn={pn} "
                                                  f"map={map_name} {adj_label} fill={fill_name} "
                                                  f"rl={rl} len={pt_len} fixed={fixed_s} free={free_s}")

                                    # Now try with transposition undo
                                    for trans_label, trans_order in [
                                        ("t5", trans_order_5),
                                        ("t7", trans_order_7),
                                        ("t10", trans_order_10),
                                    ]:
                                        phase1_configs += 1
                                        total_configs += 1

                                        undone = columnar_undo(decoded, len(trans_order), trans_order)

                                        fixed_t, ene_t, bc_t, _, _ = check_cribs(undone)
                                        free_t, _, _, ft_e, ft_b = check_cribs(undone, free=True)
                                        qg_t = qscore(undone)

                                        if fixed_t > phase1_best:
                                            phase1_best = fixed_t
                                        if free_t > phase1_best_free:
                                            phase1_best_free = free_t
                                        if fixed_t > global_best_score:
                                            global_best_score = fixed_t
                                        if free_t > global_best_free:
                                            global_best_free = free_t
                                        if qg_t > global_best_qg:
                                            global_best_qg = qg_t

                                        if fixed_t >= 5 or free_t >= 7 or qg_t > -5.0:
                                            hit = {
                                                'phase': 1,
                                                'keygroup': kg_name,
                                                'date': date_name,
                                                'personal_num': pn,
                                                'digit_map': map_name,
                                                'additive': additive_label,
                                                'adj_op': adj_label,
                                                'fill': fill_name,
                                                'row_labels': rl,
                                                'trans': trans_label,
                                                'pt_len': len(undone),
                                                'fixed': fixed_t,
                                                'free': free_t,
                                                'qg': round(qg_t, 3),
                                                'decoded': undone[:60],
                                            }
                                            phase1_hits.append(hit)

        if phase1_configs % 10000 == 0 and phase1_configs > 0:
            print(f"  ... {phase1_configs:,} configs ({time.time()-t0:.1f}s)", flush=True)

    print(f"\nPhase 1: {phase1_configs:,} configs")
    print(f"  Best fixed: {phase1_best}/24, Best free: {phase1_best_free}/24")
    print(f"  Notable hits: {len(phase1_hits)}")
    all_results.extend(phase1_hits)

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 2: Direct keygroup as transposition seed (no date/personal)
    # Simpler model: keygroup -> chain add -> trans key -> undo trans on CT
    # Then apply periodic/autokey substitution
    # ══════════════════════════════════════════════════════════════════════
    print()
    print("=" * 72)
    print("PHASE 2: Keygroup -> chain add -> transposition key")
    print("  CT -> undo columnar(keygroup-derived) -> substitute -> PT")
    print("=" * 72)

    phase2_configs = 0
    phase2_best = 0
    phase2_best_free = 0
    phase2_hits = []

    for kg_name, kg_digits in KEYGROUPS.items():
        # Expand keygroup to various transposition widths
        for width in TRANS_WIDTHS:
            expanded_w = chain_add_pair(kg_digits, width)
            col_order = sequentialize(expanded_w[:width])

            # Undo transposition on CT
            undone_ct = columnar_undo(CT, width, col_order)

            # Score directly (maybe it's already readable?)
            fixed_s, ene_s, bc_s, _, _ = check_cribs(undone_ct)
            free_s, _, _, fe, fb = check_cribs(undone_ct, free=True)
            qg = qscore(undone_ct)

            phase2_configs += 1
            total_configs += 1

            if fixed_s > phase2_best:
                phase2_best = fixed_s
            if free_s > phase2_best_free:
                phase2_best_free = free_s
            if fixed_s > global_best_score:
                global_best_score = fixed_s
            if free_s > global_best_free:
                global_best_free = free_s
            if qg > global_best_qg:
                global_best_qg = qg

            if fixed_s >= 5 or free_s >= 7 or qg > -5.0:
                hit = {
                    'phase': 2,
                    'keygroup': kg_name,
                    'width': width,
                    'col_order': col_order,
                    'fixed': fixed_s,
                    'free': free_s,
                    'qg': round(qg, 3),
                    'undone': undone_ct[:60],
                }
                phase2_hits.append(hit)
                print(f"  HIT: kg={kg_name} w={width} fixed={fixed_s} free={free_s} qg={qg:.3f}")

            # Also try: undo trans on digit stream, then checkerboard decode
            for map_name, map_fn in DIGIT_MAPS.items():
                digit_stream = map_fn(CT)
                undone_digits = columnar_undo(digit_stream, width, col_order)

                for fill_name, fill_alpha in [("kw_KRYPTOS_AZ", FILL_ALPHABETS.get("kw_KRYPTOS_AZ", AZ)),
                                               ("AZ", AZ), ("KA", KA)]:
                    for rl in ROW_LABELS:
                        phase2_configs += 1
                        total_configs += 1

                        l2c, c2l = build_checkerboard_standard(fill_alpha, rl)
                        decoded = decode_checkerboard(undone_digits, rl, c2l)

                        if decoded is None:
                            continue
                        pt_len = len(decoded)
                        if pt_len < 50 or pt_len > 90:
                            continue

                        fixed_d, _, _, _, _ = check_cribs(decoded)
                        free_d, _, _, _, _ = check_cribs(decoded, free=True)
                        qg_d = qscore(decoded)

                        if fixed_d > phase2_best:
                            phase2_best = fixed_d
                        if free_d > phase2_best_free:
                            phase2_best_free = free_d
                        if fixed_d > global_best_score:
                            global_best_score = fixed_d
                        if free_d > global_best_free:
                            global_best_free = free_d
                        if qg_d > global_best_qg:
                            global_best_qg = qg_d

                        if fixed_d >= 5 or free_d >= 7 or pt_len == 73 or qg_d > -5.0:
                            hit = {
                                'phase': 2,
                                'keygroup': kg_name,
                                'width': width,
                                'digit_map': map_name,
                                'fill': fill_name,
                                'row_labels': rl,
                                'pt_len': pt_len,
                                'fixed': fixed_d,
                                'free': free_d,
                                'qg': round(qg_d, 3),
                                'decoded': decoded[:60],
                            }
                            phase2_hits.append(hit)
                            if fixed_d >= 5 or free_d >= 8 or pt_len == 73:
                                print(f"  HIT: kg={kg_name} w={width} map={map_name} "
                                      f"fill={fill_name} rl={rl} len={pt_len} "
                                      f"fixed={fixed_d} free={free_d}")

    print(f"\nPhase 2: {phase2_configs:,} configs")
    print(f"  Best fixed: {phase2_best}/24, Best free: {phase2_best_free}/24")
    print(f"  Notable hits: {len(phase2_hits)}")
    all_results.extend(phase2_hits)

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 3: Keygroup-derived additive on raw CT digit stream (no trans)
    # Simplest model: CT -> digits -> subtract keygroup-chain -> decode
    # ══════════════════════════════════════════════════════════════════════
    print()
    print("=" * 72)
    print("PHASE 3: Keygroup chain as additive (no transposition)")
    print("  CT -> digits -> subtract chain(keygroup) -> checkerboard -> PT")
    print("=" * 72)

    phase3_configs = 0
    phase3_best = 0
    phase3_best_free = 0
    phase3_hits = []

    for kg_name, kg_digits in KEYGROUPS.items():
        # Chain-add keygroup to 97 digits
        additive_chain = chain_add_pair(kg_digits, 97)

        for map_name, map_fn in DIGIT_MAPS.items():
            base_digits = map_fn(CT)

            for op_label, op_fn in [("sub", lambda a, b: [(a[i]-b[i])%10 for i in range(len(a))]),
                                     ("add", lambda a, b: [(a[i]+b[i])%10 for i in range(len(a))])]:
                adj_digits = op_fn(base_digits, additive_chain)

                for fill_name, fill_alpha in FILL_ALPHABETS.items():
                    for rl in ROW_LABELS:
                        phase3_configs += 1
                        total_configs += 1

                        l2c, c2l = build_checkerboard_standard(fill_alpha, rl)
                        decoded = decode_checkerboard(adj_digits, rl, c2l)

                        if decoded is None:
                            continue
                        pt_len = len(decoded)
                        if pt_len < 50 or pt_len > 90:
                            continue

                        fixed_s, ene_s, bc_s, _, _ = check_cribs(decoded)
                        free_s, _, _, _, _ = check_cribs(decoded, free=True)
                        qg = qscore(decoded)

                        if fixed_s > phase3_best:
                            phase3_best = fixed_s
                        if free_s > phase3_best_free:
                            phase3_best_free = free_s
                        if fixed_s > global_best_score:
                            global_best_score = fixed_s
                        if free_s > global_best_free:
                            global_best_free = free_s
                        if qg > global_best_qg:
                            global_best_qg = qg

                        if fixed_s >= 5 or free_s >= 7 or pt_len == 73 or qg > -5.0:
                            hit = {
                                'phase': 3,
                                'keygroup': kg_name,
                                'op': op_label,
                                'digit_map': map_name,
                                'fill': fill_name,
                                'row_labels': rl,
                                'pt_len': pt_len,
                                'fixed': fixed_s,
                                'free': free_s,
                                'qg': round(qg, 3),
                                'decoded': decoded[:60],
                            }
                            phase3_hits.append(hit)
                            if fixed_s >= 5 or free_s >= 8 or pt_len == 73:
                                print(f"  HIT: kg={kg_name} {op_label} map={map_name} "
                                      f"fill={fill_name} rl={rl} len={pt_len} "
                                      f"fixed={fixed_s} free={free_s}")

    print(f"\nPhase 3: {phase3_configs:,} configs")
    print(f"  Best fixed: {phase3_best}/24, Best free: {phase3_best_free}/24")
    print(f"  Notable hits: {len(phase3_hits)}")
    all_results.extend(phase3_hits)

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 4: Full VIC pipeline with date interaction
    # keygroup + date -> intermediate -> disrupted columnar key
    # ══════════════════════════════════════════════════════════════════════
    print()
    print("=" * 72)
    print("PHASE 4: Full VIC pipeline (keygroup + date + disrupted columnar)")
    print("=" * 72)

    phase4_configs = 0
    phase4_best = 0
    phase4_best_free = 0
    phase4_hits = []

    def disrupted_columnar_undo(seq, col_order):
        """Undo VIC-style disrupted columnar transposition."""
        width = len(col_order)
        n = len(seq)
        nrows = math.ceil(n / width)

        # Find disruption column (highest key digit column)
        disrupt_rank = max(col_order)
        disrupt_col = col_order.index(disrupt_rank)

        # Build the grid structure to figure out column lengths
        grid = [[False] * width for _ in range(nrows)]
        pos = 0

        # Phase 1: Fill triangle
        for row in range(nrows):
            end_col = min(disrupt_col + row + 1, width)
            for col in range(end_col):
                if pos < n:
                    grid[row][col] = True
                    pos += 1
            if end_col >= width:
                break

        # Phase 2: Fill remaining
        for row in range(nrows):
            for col in range(width):
                if not grid[row][col] and pos < n:
                    grid[row][col] = True
                    pos += 1

        # Count cells per column
        col_lens = [sum(1 for row in range(nrows) if grid[row][col]) for col in range(width)]

        # Split seq into columns by reading order
        cols = [None] * width
        pos = 0
        for rank in range(width):
            col_idx = col_order.index(rank)
            cl = col_lens[col_idx]
            cols[col_idx] = list(seq[pos:pos+cl])
            pos += cl

        # Read row by row
        result = []
        col_ptrs = [0] * width
        for row in range(nrows):
            for col in range(width):
                if grid[row][col] and col_ptrs[col] < len(cols[col]):
                    result.append(cols[col][col_ptrs[col]])
                    col_ptrs[col] += 1

        if isinstance(seq, str):
            return ''.join(result)
        return result

    for kg_name, kg_digits in KEYGROUPS.items():
        for date_name, date_digits in DATES.items():
            for pn in PERSONAL_NUMBERS[:3]:  # Top 3 personal numbers
                expanded, modified = vic_derive_intermediate(kg_digits, date_digits, pn)

                # Derive disrupted columnar key from modified digits
                dc_order_10 = sequentialize(modified[:10])
                dc_order_5 = sequentialize(expanded[:5])
                dc_order_7 = sequentialize(chain_add_pair(expanded, 7)[:7])

                for dc_label, dc_key in [("dc10", dc_order_10),
                                           ("dc5", dc_order_5),
                                           ("dc7", dc_order_7)]:
                    # Undo disrupted columnar on CT
                    try:
                        undone = disrupted_columnar_undo(CT, dc_key)
                    except (IndexError, ValueError):
                        continue

                    phase4_configs += 1
                    total_configs += 1

                    fixed_s, ene_s, bc_s, _, _ = check_cribs(undone)
                    free_s, _, _, _, _ = check_cribs(undone, free=True)
                    qg = qscore(undone)

                    if fixed_s > phase4_best:
                        phase4_best = fixed_s
                    if free_s > phase4_best_free:
                        phase4_best_free = free_s
                    if fixed_s > global_best_score:
                        global_best_score = fixed_s
                    if free_s > global_best_free:
                        global_best_free = free_s
                    if qg > global_best_qg:
                        global_best_qg = qg

                    if fixed_s >= 5 or free_s >= 7 or qg > -5.0:
                        hit = {
                            'phase': 4,
                            'keygroup': kg_name,
                            'date': date_name,
                            'personal_num': pn,
                            'dc_key': dc_label,
                            'fixed': fixed_s,
                            'free': free_s,
                            'qg': round(qg, 3),
                            'undone': undone[:60],
                        }
                        phase4_hits.append(hit)
                        print(f"  HIT: kg={kg_name} date={date_name} pn={pn} "
                              f"{dc_label} fixed={fixed_s} free={free_s} qg={qg:.3f}")

                    # Also try on digit streams + checkerboard
                    for map_name, map_fn in list(DIGIT_MAPS.items())[:2]:  # KA and AZ only
                        digit_stream = map_fn(CT)
                        try:
                            undone_digits = disrupted_columnar_undo(digit_stream, dc_key)
                        except (IndexError, ValueError):
                            continue

                        for fill_name in ["kw_KRYPTOS_AZ", "KA", "ASINTOER_AZ"]:
                            fill_alpha = FILL_ALPHABETS.get(fill_name, AZ)
                            for rl in ROW_LABELS[:3]:  # Top 3 row labels
                                phase4_configs += 1
                                total_configs += 1

                                l2c, c2l = build_checkerboard_standard(fill_alpha, rl)
                                decoded = decode_checkerboard(undone_digits, rl, c2l)

                                if decoded is None:
                                    continue
                                pt_len = len(decoded)
                                if pt_len < 50 or pt_len > 90:
                                    continue

                                fixed_d, _, _, _, _ = check_cribs(decoded)
                                free_d, _, _, _, _ = check_cribs(decoded, free=True)

                                if fixed_d > phase4_best:
                                    phase4_best = fixed_d
                                if free_d > phase4_best_free:
                                    phase4_best_free = free_d
                                if fixed_d > global_best_score:
                                    global_best_score = fixed_d
                                if free_d > global_best_free:
                                    global_best_free = free_d

                                if fixed_d >= 5 or free_d >= 7 or pt_len == 73:
                                    hit = {
                                        'phase': 4,
                                        'keygroup': kg_name,
                                        'date': date_name,
                                        'personal_num': pn,
                                        'dc_key': dc_label,
                                        'digit_map': map_name,
                                        'fill': fill_name,
                                        'row_labels': rl,
                                        'pt_len': pt_len,
                                        'fixed': fixed_d,
                                        'free': free_d,
                                        'decoded': decoded[:60],
                                    }
                                    phase4_hits.append(hit)

        if phase4_configs % 5000 == 0 and phase4_configs > 0:
            print(f"  ... {phase4_configs:,} configs ({time.time()-t0:.1f}s)", flush=True)

    print(f"\nPhase 4: {phase4_configs:,} configs")
    print(f"  Best fixed: {phase4_best}/24, Best free: {phase4_best_free}/24")
    print(f"  Notable hits: {len(phase4_hits)}")
    all_results.extend(phase4_hits)

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 5: Keygroup as direct periodic key on raw CT
    # Maybe the keygroup IS the key (repeating), not just a seed
    # ══════════════════════════════════════════════════════════════════════
    print()
    print("=" * 72)
    print("PHASE 5: Keygroup as direct periodic shift key on CT97")
    print("=" * 72)

    phase5_configs = 0
    phase5_best = 0
    phase5_best_free = 0
    phase5_hits = []

    for kg_name, kg_digits in KEYGROUPS.items():
        kg = kg_digits
        period = len(kg)

        # Extend to CT_LEN by cycling
        extended_key = (kg * (CT_LEN // period + 1))[:CT_LEN]

        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            alpha_idx = {c: i for i, c in enumerate(alpha)}

            # Vigenere-style: PT[i] = (CT[i] - key[i]) mod 26
            pt_vig = ''.join(alpha[(alpha_idx[CT[i]] - extended_key[i]) % 26] for i in range(CT_LEN))
            # Beaufort-style: PT[i] = (key[i] - CT[i]) mod 26
            pt_beau = ''.join(alpha[(extended_key[i] - alpha_idx[CT[i]]) % 26] for i in range(CT_LEN))
            # Variant Beaufort: PT[i] = (CT[i] + key[i]) mod 26
            pt_vbeau = ''.join(alpha[(alpha_idx[CT[i]] + extended_key[i]) % 26] for i in range(CT_LEN))

            for var_name, pt in [("vig", pt_vig), ("beau", pt_beau), ("vbeau", pt_vbeau)]:
                phase5_configs += 1
                total_configs += 1

                fixed_s, ene_s, bc_s, _, _ = check_cribs(pt)
                free_s, _, _, _, _ = check_cribs(pt, free=True)
                qg = qscore(pt)

                if fixed_s > phase5_best:
                    phase5_best = fixed_s
                if free_s > phase5_best_free:
                    phase5_best_free = free_s
                if fixed_s > global_best_score:
                    global_best_score = fixed_s
                if free_s > global_best_free:
                    global_best_free = free_s
                if qg > global_best_qg:
                    global_best_qg = qg

                if fixed_s >= 3 or free_s >= 5 or qg > -5.5:
                    hit = {
                        'phase': 5,
                        'keygroup': kg_name,
                        'key_digits': ''.join(str(d) for d in kg),
                        'alphabet': alpha_name,
                        'variant': var_name,
                        'period': period,
                        'fixed': fixed_s,
                        'free': free_s,
                        'qg': round(qg, 3),
                        'pt': pt[:60],
                    }
                    phase5_hits.append(hit)
                    if fixed_s >= 5 or free_s >= 7:
                        print(f"  HIT: kg={kg_name} {alpha_name}_{var_name} "
                              f"fixed={fixed_s} free={free_s} qg={qg:.3f}")

    print(f"\nPhase 5: {phase5_configs:,} configs")
    print(f"  Best fixed: {phase5_best}/24, Best free: {phase5_best_free}/24")
    print(f"  Notable hits: {len(phase5_hits)}")
    all_results.extend(phase5_hits)

    # ══════════════════════════════════════════════════════════════════════
    # SUMMARY
    # ══════════════════════════════════════════════════════════════════════
    elapsed = time.time() - t0

    print()
    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"Total configs: {total_configs:,}")
    print(f"Total elapsed: {elapsed:.1f}s")
    print(f"Global best fixed score: {global_best_score}/24")
    print(f"Global best free score: {global_best_free}/24")
    print(f"Global best quadgram: {global_best_qg:.3f}")
    print()

    # Phase breakdown
    print("Phase breakdown:")
    print(f"  Phase 1 (full VIC pipeline): {phase1_configs:,} configs, "
          f"best fixed={phase1_best}/24, free={phase1_best_free}/24")
    print(f"  Phase 2 (keygroup->trans key): {phase2_configs:,} configs, "
          f"best fixed={phase2_best}/24, free={phase2_best_free}/24")
    print(f"  Phase 3 (keygroup chain additive): {phase3_configs:,} configs, "
          f"best fixed={phase3_best}/24, free={phase3_best_free}/24")
    print(f"  Phase 4 (disrupted columnar): {phase4_configs:,} configs, "
          f"best fixed={phase4_best}/24, free={phase4_best_free}/24")
    print(f"  Phase 5 (direct periodic key): {phase5_configs:,} configs, "
          f"best fixed={phase5_best}/24, free={phase5_best_free}/24")
    print()

    if global_best_score >= 18 or global_best_free >= 18:
        verdict = "SIGNAL"
    elif global_best_score >= 10 or global_best_free >= 10:
        verdict = "INTERESTING"
    elif global_best_score >= 5 or global_best_free >= 7:
        verdict = "WEAK_HITS"
    else:
        verdict = "NOISE"

    print(f"Verdict: {verdict}")

    # Top results
    all_results.sort(key=lambda h: max(h.get('fixed', 0), h.get('free', 0)), reverse=True)
    if all_results:
        print(f"\nTop 10 results:")
        for i, hit in enumerate(all_results[:10]):
            phase = hit.get('phase', '?')
            kg = hit.get('keygroup', '?')
            fixed = hit.get('fixed', 0)
            free = hit.get('free', 0)
            qg = hit.get('qg', 0)
            pt_or_decoded = hit.get('decoded', hit.get('pt', hit.get('undone', '?')))
            print(f"  {i+1}. Phase {phase} | kg={kg} | fixed={fixed} free={free} qg={qg}")
            print(f"     {pt_or_decoded}")

    # Save results
    output = {
        'experiment': 'e_vic_ndyar_keygroup',
        'description': 'NDYAHR raised letters as VIC cipher keygroup digits',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'total_configs': total_configs,
        'elapsed_seconds': round(elapsed, 1),
        'global_best_fixed': global_best_score,
        'global_best_free': global_best_free,
        'global_best_qg': round(global_best_qg, 3),
        'verdict': verdict,
        'keygroups_tested': {name: ''.join(str(d) for d in digits) for name, digits in KEYGROUPS.items()},
        'ndyahr_positions_in_ct': {ch: pos for ch, pos in ndyahr_positions.items()},
        'phase_summary': {
            'phase1_full_vic': {'configs': phase1_configs, 'best_fixed': phase1_best, 'best_free': phase1_best_free, 'hits': len(phase1_hits)},
            'phase2_trans_key': {'configs': phase2_configs, 'best_fixed': phase2_best, 'best_free': phase2_best_free, 'hits': len(phase2_hits)},
            'phase3_additive': {'configs': phase3_configs, 'best_fixed': phase3_best, 'best_free': phase3_best_free, 'hits': len(phase3_hits)},
            'phase4_disrupted': {'configs': phase4_configs, 'best_fixed': phase4_best, 'best_free': phase4_best_free, 'hits': len(phase4_hits)},
            'phase5_periodic': {'configs': phase5_configs, 'best_fixed': phase5_best, 'best_free': phase5_best_free, 'hits': len(phase5_hits)},
        },
        'top_results': [
            {k: (v if not isinstance(v, tuple) else list(v)) for k, v in h.items()}
            for h in all_results[:20]
        ],
    }

    outpath = Path(__file__).resolve().parents[2] / "results" / "vic_ndyar_keygroup.json"
    outpath.parent.mkdir(parents=True, exist_ok=True)
    with open(outpath, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to: {outpath}")


if __name__ == "__main__":
    run()
