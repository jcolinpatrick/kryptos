#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: grille
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-GRILLE-15: "T IS YOUR POSITION" — Cardan grille from T-positions

HYPOTHESIS: The Morse code instruction "T IS YOUR POSITION" tells the solver
to mark every T on the cipher panel, cut those positions out to form a Cardan
grille, then overlay the grille on the Vigenère tableau and read through the
holes. Classical Cardan grilles are rotated to read multiple passes.

Key numeric relationship:
  - 53 T's on cipher panel
  - 53 × 2 = 106 = length of grille extract (from YAR-based mask)
  - 53 × 2 + 1 = 107 = number of holes in YAR-based mask

This script tests:
  1. Mark all T positions on cipher panel (28-row grid)
  2. Apply 180° rotation → union of positions
  3. Read through T-holes on the Vigenère tableau
  4. Analyze result: letter frequencies, missing letters, English metrics
  5. Try as unscrambling permutation for K4
  6. Also test: original only (no rotation), 4×90° if feasible
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from collections import Counter
import itertools

# ─── CIPHER PANEL (left side, 28 rows, as carved on sculpture) ───────────────
# Source: e_grille_04_missing_t_analysis.py, verified against photos
CIPHER_PANEL = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ",   # Row  0 (K1)
    "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD",     # Row  1
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE",      # Row  2
    "GGWHKK?DQMCPFQZDQMMIAGPFXHQRLG",       # Row  3
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",       # Row  4
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR",     # Row  5
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI",       # Row  6
    "HHDDDUVH?DWKBFUFPWNTDFIYCUQZERE",      # Row  7
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX",      # Row  8
    "FLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKF",      # Row  9
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ",        # Row 10
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",       # Row 11
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP",       # Row 12
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",       # Row 13
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA",      # Row 14 (K3)
    "CHTNREYULDSLLSLLNOHSNOSMRWXMNE",        # Row 15
    "TPRNGATIHNRARPESLNNELEBLPIIACAE",        # Row 16
    "WMTWNDITEENRAHCTENEUDRETNHAEOE",         # Row 17
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCR",      # Row 18
    "EIFTBRSPAMHHEWENATAMATEGYEERLB",         # Row 19
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTI",       # Row 20
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",       # Row 21
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORIT",     # Row 22
    "RKLMLEHAGTDHARDPNEOHMGFMFEUHE",         # Row 23
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",       # Row 24 (K3→K4 boundary)
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",        # Row 25
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",        # Row 26
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",       # Row 27
]

# ─── VIGENÈRE TABLEAU (right side, 28 rows, KA alphabet) ─────────────────────
# Source: memory/kryptos_tableau.md, grille_mask_decrypt.py
# Row 0 = header, Rows 1-26 = body (A-Z keys), Row 27 = footer
# Row 14 (Key N) has extra L, Row 22 (Key V) has extra T — as on sculpture
TABLEAU = [
    "ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",         # Row  0: Header
    "AKRYPTOSABCDEFGHIJLMNQUVWXZKRYP",        # Row  1: Key A
    "BRYPTOSABCDEFGHIJLMNQUVWXZKRYPT",        # Row  2: Key B
    "CYPTOSABCDEFGHIJLMNQUVWXZKRYPTO",        # Row  3: Key C
    "DPTOSABCDEFGHIJLMNQUVWXZKRYPTOS",        # Row  4: Key D
    "ETOSABCDEFGHIJLMNQUVWXZKRYPTOSA",        # Row  5: Key E
    "FOSABCDEFGHIJLMNQUVWXZKRYPTOSAB",        # Row  6: Key F
    "GSABCDEFGHIJLMNQUVWXZKRYPTOSABC",        # Row  7: Key G
    "HABCDEFGHIJLMNQUVWXZKRYPTOSABCD",        # Row  8: Key H
    "IBCDEFGHIJLMNQUVWXZKRYPTOSABCDE",        # Row  9: Key I
    "JCDEFGHIJLMNQUVWXZKRYPTOSABCDEF",        # Row 10: Key J
    "KDEFGHIJLMNQUVWXZKRYPTOSABCDEFG",        # Row 11: Key K
    "LEFGHIJLMNQUVWXZKRYPTOSABCDEFGH",        # Row 12: Key L
    "MFGHIJLMNQUVWXZKRYPTOSABCDEFGHI",        # Row 13: Key M
    "NGHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",       # Row 14: Key N (EXTRA L)
    "OHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",        # Row 15: Key O
    "PIJLMNQUVWXZKRYPTOSABCDEFGHIJLM",        # Row 16: Key P
    "QJLMNQUVWXZKRYPTOSABCDEFGHIJLMN",        # Row 17: Key Q
    "RLMNQUVWXZKRYPTOSABCDEFGHIJLMNQ",        # Row 18: Key R
    "SMNQUVWXZKRYPTOSABCDEFGHIJLMNQU",        # Row 19: Key S
    "TNQUVWXZKRYPTOSABCDEFGHIJLMNQUV",        # Row 20: Key T
    "UQUVWXZKRYPTOSABCDEFGHIJLMNQUVW",        # Row 21: Key U
    "VUVWXZKRYPTOSABCDEFGHIJLMNQUVWXT",       # Row 22: Key V (EXTRA T)
    "WVWXZKRYPTOSABCDEFGHIJLMNQUVWXZ",        # Row 23: Key W
    "XWXZKRYPTOSABCDEFGHIJLMNQUVWXZK",        # Row 24: Key X
    "YXZKRYPTOSABCDEFGHIJLMNQUVWXZKR",        # Row 25: Key Y
    "ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY",        # Row 26: Key Z
    "ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",         # Row 27: Footer
]

# ─── K4 constants ─────────────────────────────────────────────────────────────
K4_CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
CRIB1 = (21, "EASTNORTHEAST")   # 0-indexed positions in K4
CRIB2 = (63, "BERLINCLOCK")

# ─── HELPER FUNCTIONS ─────────────────────────────────────────────────────────

def find_letter_positions(grid, letter):
    """Find all (row, col) positions of a letter in a grid."""
    positions = []
    for r, row in enumerate(grid):
        for c, ch in enumerate(row):
            if ch == letter:
                positions.append((r, c))
    return positions


def rotate_180(positions, num_rows, num_cols):
    """Rotate positions 180° around center of num_rows × num_cols grid."""
    return [(num_rows - 1 - r, num_cols - 1 - c) for r, c in positions]


def rotate_90cw(positions, num_rows, num_cols):
    """Rotate 90° clockwise: (r,c) → (c, num_rows-1-r) in new grid of num_cols × num_rows."""
    return [(c, num_rows - 1 - r) for r, c in positions]


def rotate_90ccw(positions, num_rows, num_cols):
    """Rotate 90° counter-clockwise: (r,c) → (num_cols-1-c, r) in new grid of num_cols × num_rows."""
    return [(num_cols - 1 - c, r) for r, c in positions]


def read_through_holes(grid, positions, label=""):
    """Read characters from grid at given positions (in order). Skip out-of-bounds."""
    chars = []
    valid_positions = []
    oob = 0
    for r, c in positions:
        if 0 <= r < len(grid) and 0 <= c < len(grid[r]):
            chars.append(grid[r][c])
            valid_positions.append((r, c))
        else:
            oob += 1
    text = ''.join(chars)
    return text, valid_positions, oob


def analyze_text(text, label=""):
    """Analyze extracted text: frequencies, missing letters, patterns."""
    print(f"\n{'='*70}")
    print(f"  {label}")
    print(f"{'='*70}")
    print(f"  Length: {len(text)}")
    print(f"  Text: {text}")

    # Letter frequency
    alpha_only = ''.join(c for c in text if c.isalpha())
    freq = Counter(alpha_only)
    print(f"  Alpha chars: {len(alpha_only)}")

    # Missing letters
    all_letters = set('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    present = set(alpha_only.upper())
    missing = all_letters - present
    if missing:
        print(f"  *** MISSING LETTERS: {sorted(missing)} ({len(missing)} missing) ***")
    else:
        print(f"  All 26 letters present")

    # IC
    if len(alpha_only) > 1:
        n = len(alpha_only)
        ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
        print(f"  IC: {ic:.4f} (English ~0.067, random ~0.038)")

    # Most/least common
    if freq:
        by_freq = freq.most_common()
        print(f"  Most common: {by_freq[:5]}")
        print(f"  Least common: {by_freq[-5:]}")

    # Check for T specifically
    t_count = freq.get('T', 0)
    print(f"  T count: {t_count} ({t_count/len(alpha_only)*100:.1f}%)" if alpha_only else "")

    return alpha_only


def check_cribs_in_extract(extract):
    """Check if any crib fragments appear in the extract."""
    cribs = ["EASTNORTHEAST", "BERLINCLOCK", "EAST", "NORTH", "BERLIN", "CLOCK"]
    for crib in cribs:
        for i in range(len(extract) - len(crib) + 1):
            if extract[i:i+len(crib)] == crib:
                print(f"  *** CRIB HIT: '{crib}' at position {i} ***")


def try_vig_decrypt(ct, key, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
    """Vigenère decrypt: PT[i] = (CT[i] - KEY[i]) mod 26."""
    pt = []
    for i, c in enumerate(ct):
        if c in alphabet:
            ci = alphabet.index(c)
            ki = alphabet.index(key[i % len(key)])
            pi = (ci - ki) % len(alphabet)
            pt.append(alphabet[pi])
        else:
            pt.append(c)
    return ''.join(pt)


def try_beaufort_decrypt(ct, key, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
    """Beaufort decrypt: PT[i] = (KEY[i] - CT[i]) mod 26."""
    pt = []
    for i, c in enumerate(ct):
        if c in alphabet:
            ci = alphabet.index(c)
            ki = alphabet.index(key[i % len(key)])
            pi = (ki - ci) % len(alphabet)
            pt.append(alphabet[pi])
        else:
            pt.append(c)
    return ''.join(pt)


# ─── MAIN ANALYSIS ───────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("  E-GRILLE-15: 'T IS YOUR POSITION' — Cardan Grille from T-positions")
    print("=" * 70)

    # ─── Step 1: Find all T positions on cipher panel ─────────────────────
    t_positions = find_letter_positions(CIPHER_PANEL, 'T')
    print(f"\n[STEP 1] T positions on cipher panel")
    print(f"  Total T's found: {len(t_positions)}")
    print(f"  Positions (row, col):")
    for r, c in t_positions:
        char_context = CIPHER_PANEL[r][max(0,c-2):c+3]
        print(f"    ({r:2d}, {c:2d})  ...{char_context}...")

    # Grid dimensions
    num_rows = len(CIPHER_PANEL)
    row_widths = [len(row) for row in CIPHER_PANEL]
    max_cols = max(row_widths)
    min_cols = min(row_widths)
    print(f"\n  Grid: {num_rows} rows, width {min_cols}-{max_cols} (using {max_cols} for rotation)")

    # ─── Step 2: 180° rotation ────────────────────────────────────────────
    print(f"\n[STEP 2] 180° rotation of T-positions")
    t_rot180 = rotate_180(t_positions, num_rows, max_cols)

    # Check validity of rotated positions
    valid_rot = [(r, c) for r, c in t_rot180 if 0 <= r < num_rows and 0 <= c < len(CIPHER_PANEL[r])]
    oob_rot = len(t_rot180) - len(valid_rot)
    print(f"  Rotated positions: {len(t_rot180)} total, {len(valid_rot)} valid, {oob_rot} out-of-bounds")

    # Union of original + 180° rotated
    union_set = set(t_positions) | set(valid_rot)
    overlap = set(t_positions) & set(valid_rot)
    print(f"  Original T-positions: {len(t_positions)}")
    print(f"  Valid rotated positions: {len(valid_rot)}")
    print(f"  Overlap (T maps to T under 180°): {len(overlap)}")
    print(f"  Union size: {len(union_set)}")
    print(f"  Expected if no overlap: {len(t_positions) + len(valid_rot)}")
    if overlap:
        print(f"  Overlapping positions: {sorted(overlap)}")

    # ─── Step 3: Read through T-holes on TABLEAU ──────────────────────────
    # Sort positions by reading order (row-major, left to right, top to bottom)
    t_sorted = sorted(t_positions, key=lambda p: (p[0], p[1]))

    print(f"\n[STEP 3a] Read TABLEAU through original T-holes (pass 1, top-down L-R)")
    text1, valid1, oob1 = read_through_holes(TABLEAU, t_sorted, "Pass 1")
    print(f"  Characters read: {len(text1)}, OOB: {oob1}")
    analyze_text(text1, "TABLEAU — Pass 1 (original T-positions, row-major order)")
    check_cribs_in_extract(text1)

    # 180° rotated positions, also sorted row-major
    rot_sorted = sorted(valid_rot, key=lambda p: (p[0], p[1]))

    print(f"\n[STEP 3b] Read TABLEAU through 180°-rotated T-holes (pass 2)")
    text2, valid2, oob2 = read_through_holes(TABLEAU, rot_sorted, "Pass 2")
    print(f"  Characters read: {len(text2)}, OOB: {oob2}")
    analyze_text(text2, "TABLEAU — Pass 2 (180°-rotated T-positions, row-major order)")
    check_cribs_in_extract(text2)

    # Combined: pass1 + pass2
    combined = text1 + text2
    analyze_text(combined, "TABLEAU — Combined (Pass 1 + Pass 2)")
    check_cribs_in_extract(combined)

    # ─── Step 3c: Read CIPHER PANEL through 180°-rotated T-holes ──────────
    # (What letters does the rotated grille reveal on the cipher panel itself?)
    print(f"\n[STEP 3c] Read CIPHER PANEL through 180°-rotated T-holes")
    text_cp_rot, _, oob_cp = read_through_holes(CIPHER_PANEL, rot_sorted, "CP rotated")
    print(f"  Characters read: {len(text_cp_rot)}, OOB: {oob_cp}")
    analyze_text(text_cp_rot, "CIPHER PANEL — through 180°-rotated T-holes")

    # ─── Step 4: Read union positions on TABLEAU ──────────────────────────
    union_sorted = sorted(union_set, key=lambda p: (p[0], p[1]))

    print(f"\n[STEP 4] Read TABLEAU through ALL T-holes (original ∪ 180°)")
    text_union, valid_union, oob_union = read_through_holes(TABLEAU, union_sorted)
    print(f"  Characters read: {len(text_union)}, OOB: {oob_union}")
    analyze_text(text_union, "TABLEAU — Union of original + 180° T-positions")
    check_cribs_in_extract(text_union)

    # ─── Step 5: Try different reading orders ─────────────────────────────
    print(f"\n[STEP 5] Alternative reading orders on TABLEAU")

    # Column-major (top to bottom, left to right)
    t_col_major = sorted(t_positions, key=lambda p: (p[1], p[0]))
    text_cm, _, _ = read_through_holes(TABLEAU, t_col_major)
    analyze_text(text_cm, "TABLEAU — Pass 1, column-major order")

    # Reverse row-major (bottom to top, right to left)
    t_reverse = sorted(t_positions, key=lambda p: (-p[0], -p[1]))
    text_rev, _, _ = read_through_holes(TABLEAU, t_reverse)
    analyze_text(text_rev, "TABLEAU — Pass 1, reverse order (bottom-up R-L)")

    # Boustrophedon (alternate L-R and R-L by row)
    def boustrophedon_sort(positions):
        by_row = {}
        for r, c in positions:
            by_row.setdefault(r, []).append((r, c))
        result = []
        for r in sorted(by_row):
            row_positions = sorted(by_row[r], key=lambda p: p[1])
            if r % 2 == 1:  # odd rows right-to-left
                row_positions.reverse()
            result.extend(row_positions)
        return result

    t_boust = boustrophedon_sort(t_positions)
    text_boust, _, _ = read_through_holes(TABLEAU, t_boust)
    analyze_text(text_boust, "TABLEAU — Pass 1, boustrophedon order")

    # ─── Step 6: Try as K4 unscrambling permutation ───────────────────────
    print(f"\n[STEP 6] Use tableau extract as K4 unscrambling key")
    print(f"  K4 length: {len(K4_CT)}")
    print(f"  Pass 1 extract length: {len(text1)}")
    print(f"  Combined extract length: {len(combined)}")

    # If extract length >= 97, try interpreting letters as numeric permutation
    for label, extract in [("Pass1", text1), ("Pass2", text2), ("Combined", combined),
                            ("ColMajor", text_cm), ("Reverse", text_rev)]:
        alpha = ''.join(c for c in extract if c.isalpha())
        if len(alpha) < 97:
            print(f"\n  {label}: only {len(alpha)} alpha chars, need 97 — skipping permutation test")
            continue

        # Method: rank each character position by (letter_value, position) to get unique ordering
        alpha97 = alpha[:97]
        indexed = [(ord(c) - ord('A'), i) for i, c in enumerate(alpha97)]
        ranked = sorted(range(97), key=lambda i: indexed[i])

        # Apply permutation to K4
        unscrambled = ''.join(K4_CT[ranked[i]] for i in range(97))
        print(f"\n  {label} → rank permutation → unscrambled K4:")
        print(f"    {unscrambled}")

        # Try Vig/Beaufort with known keywords
        KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
        AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        for key in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            for alph_label, alph in [("AZ", AZ), ("KA", KA)]:
                pt_vig = try_vig_decrypt(unscrambled, key, alph)
                pt_beau = try_beaufort_decrypt(unscrambled, key, alph)

                # Check for crib fragments
                for pt_label, pt in [("Vig", pt_vig), ("Beau", pt_beau)]:
                    hits = 0
                    for crib_word in ["EAST", "NORTH", "BERLIN", "CLOCK", "THE", "AND"]:
                        if crib_word in pt:
                            hits += 1
                    if hits > 0:
                        print(f"    *** {pt_label}/{key}/{alph_label}: {pt}  ({hits} word hits)")

    # ─── Step 7: Broader rotation experiments ─────────────────────────────
    print(f"\n{'='*70}")
    print(f"  [STEP 7] Rotation variants")
    print(f"{'='*70}")

    # Try different grid widths for rotation center
    for grid_width in [29, 30, 31, 32, 33]:
        rot = rotate_180(t_positions, num_rows, grid_width)
        valid = [(r, c) for r, c in rot if 0 <= r < num_rows and 0 <= c < len(CIPHER_PANEL[r])]
        union = set(t_positions) | set(valid)
        overlap_count = len(set(t_positions) & set(valid))
        text_r, _, oob_r = read_through_holes(TABLEAU, sorted(valid, key=lambda p: (p[0], p[1])))
        alpha_r = ''.join(c for c in text_r if c.isalpha())
        missing_r = set('ABCDEFGHIJKLMNOPQRSTUVWXYZ') - set(alpha_r)
        print(f"  Width={grid_width}: valid_rot={len(valid)}, overlap={overlap_count}, "
              f"union={len(union)}, read={len(alpha_r)} chars, "
              f"missing={sorted(missing_r) if missing_r else 'none'}")

    # ─── Step 8: What if we use BOTH panels? ──────────────────────────────
    print(f"\n{'='*70}")
    print(f"  [STEP 8] T-positions: cipher panel reading ITSELF")
    print(f"{'='*70}")
    print(f"  (Read cipher panel through its own T-holes — what's NOT T?)")

    # Read cipher panel through 180°-rotated T-positions
    # (original positions are all T by definition)
    print(f"\n  Reading cipher panel at 180°-rotated T-positions:")
    text_self, _, _ = read_through_holes(CIPHER_PANEL, rot_sorted)
    analyze_text(text_self, "CIPHER PANEL at 180°-rotated T-positions")

    # ─── Step 9: What about T on the TABLEAU? ─────────────────────────────
    print(f"\n{'='*70}")
    print(f"  [STEP 9] T-positions on TABLEAU (alternative: cut T from tableau)")
    print(f"{'='*70}")

    t_tab_positions = find_letter_positions(TABLEAU, 'T')
    print(f"  T's on tableau: {len(t_tab_positions)}")

    t_tab_rot180 = rotate_180(t_tab_positions, len(TABLEAU), max(len(r) for r in TABLEAU))
    valid_tab_rot = [(r, c) for r, c in t_tab_rot180
                     if 0 <= r < len(TABLEAU) and 0 <= c < len(TABLEAU[r])]
    union_tab = set(t_tab_positions) | set(valid_tab_rot)
    print(f"  T's rotated 180°: {len(valid_tab_rot)} valid")
    print(f"  Union: {len(union_tab)}")

    # Read cipher panel through tableau T-holes
    text_tab_on_cp, _, oob_tab = read_through_holes(
        CIPHER_PANEL, sorted(t_tab_positions, key=lambda p: (p[0], p[1])))
    print(f"  Tableau T-holes on cipher panel: {len(text_tab_on_cp)} chars, {oob_tab} OOB")
    analyze_text(text_tab_on_cp, "CIPHER PANEL through tableau T-holes (original)")

    text_tab_rot_on_cp, _, oob_tab2 = read_through_holes(
        CIPHER_PANEL, sorted(valid_tab_rot, key=lambda p: (p[0], p[1])))
    print(f"  Tableau T-holes (180° rot) on cipher panel: {len(text_tab_rot_on_cp)} chars, {oob_tab2} OOB")
    analyze_text(text_tab_rot_on_cp, "CIPHER PANEL through tableau T-holes (180° rotated)")

    # ─── Step 10: Statistical context ─────────────────────────────────────
    print(f"\n{'='*70}")
    print(f"  [STEP 10] Statistical context")
    print(f"{'='*70}")

    total_alpha_cp = sum(1 for row in CIPHER_PANEL for c in row if c.isalpha())
    total_alpha_tab = sum(1 for row in TABLEAU for c in row if c.isalpha())

    print(f"  Cipher panel: {total_alpha_cp} alpha chars, {len(t_positions)} T's "
          f"({len(t_positions)/total_alpha_cp*100:.2f}%)")
    print(f"  Tableau: {total_alpha_tab} alpha chars, {len(t_tab_positions)} T's "
          f"({len(t_tab_positions)/total_alpha_tab*100:.2f}%)")
    print(f"  English T frequency: ~9.1%")
    print(f"  53 × 2 = {53*2} (grille extract length = 106)")
    print(f"  53 × 2 + 1 = {53*2+1} (known grille holes = 107)")
    print(f"  53 + 33 = {53+33} (total T's both panels)")

    # Per-row T distribution
    print(f"\n  T distribution by row (cipher panel):")
    for r in range(num_rows):
        t_in_row = sum(1 for c in CIPHER_PANEL[r] if c == 'T')
        bar = '█' * t_in_row
        section = "K1" if r < 8 else "K2" if r < 14 else "K3" if r < 24 else "K4"
        print(f"    Row {r:2d} ({section}): {t_in_row:2d} {bar}  [{len(CIPHER_PANEL[r]):2d} chars]")

    print(f"\n  T distribution by row (tableau):")
    for r in range(len(TABLEAU)):
        t_in_row = sum(1 for c in TABLEAU[r] if c == 'T')
        bar = '█' * t_in_row
        label = "Hdr" if r == 0 else "Ftr" if r == 27 else f"Key {chr(64+r)}"
        print(f"    Row {r:2d} ({label:5s}): {t_in_row:2d} {bar}  [{len(TABLEAU[r]):2d} chars]")


if __name__ == "__main__":
    main()
