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
E-GRILLE-19: Tableau Geometry → Grille Mask Derivation

HYPOTHESIS: The Kryptos Vigenère tableau (right panel) contains instructions
for building a grille mask. The tableau is 28 rows using the KA alphabet
(KRYPTOSABCDEFGHIJLMNQUVWXZ), with two known anomalies:
  - Row 14 (Key N): 31 body chars instead of 30 (extra L at end)
  - Row 22 (Key V): 31 body chars instead of 30 (extra T at end)

This script tests 7 approaches to deriving a mask from the tableau:
  1. Deviation positions — where tableau differs from perfect KA cyclic shift
  2. X-position mapping — X is the omitted K2 delimiter
  3. Diagonal letter patterns — which letter's diagonal gives best mask?
  4. Row N (extra L) / Row V (extra T) analysis — numeric relationships
  5. Header/footer vs body alphabet difference positions
  6. Self-referential fixed points — where tableau[r][c] == row label or col header
  7. Positions of specific letters (EQUAL anagram, KRYPTOS keyword)

For each candidate mask: count holes, read cipher panel through holes,
try as permutation for K4.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from collections import Counter
from kryptos.kernel.constants import CT, CT_LEN, KRYPTOS_ALPHABET, ALPH, CRIB_DICT

# ─── KA alphabet ─────────────────────────────────────────────────────────────
KA = KRYPTOS_ALPHABET  # "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA)}
AZ = ALPH  # "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
AZ_IDX = {c: i for i, c in enumerate(AZ)}

# ─── TABLEAU (right panel, 28 rows) ──────────────────────────────────────────
# Row 0 = header, Rows 1–26 = body (Key A–Z), Row 27 = footer
# Row 14 (Key N) has extra L; Row 22 (Key V) has extra T — as on sculpture
TABLEAU = [
    "ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",         # Row  0: Header (standard alphabet + ABCD)
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
    "NGHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",       # Row 14: Key N (EXTRA L → 32 chars)
    "OHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",        # Row 15: Key O
    "PIJLMNQUVWXZKRYPTOSABCDEFGHIJLM",        # Row 16: Key P
    "QJLMNQUVWXZKRYPTOSABCDEFGHIJLMN",        # Row 17: Key Q
    "RLMNQUVWXZKRYPTOSABCDEFGHIJLMNQ",        # Row 18: Key R
    "SMNQUVWXZKRYPTOSABCDEFGHIJLMNQU",        # Row 19: Key S
    "TNQUVWXZKRYPTOSABCDEFGHIJLMNQUV",        # Row 20: Key T
    "UQUVWXZKRYPTOSABCDEFGHIJLMNQUVW",        # Row 21: Key U
    "VUVWXZKRYPTOSABCDEFGHIJLMNQUVWXT",       # Row 22: Key V (EXTRA T → 32 chars)
    "WVWXZKRYPTOSABCDEFGHIJLMNQUVWXZ",        # Row 23: Key W
    "XWXZKRYPTOSABCDEFGHIJLMNQUVWXZK",        # Row 24: Key X
    "YXZKRYPTOSABCDEFGHIJLMNQUVWXZKR",        # Row 25: Key Y
    "ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY",        # Row 26: Key Z
    "ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",         # Row 27: Footer (same as header)
]

# ─── CIPHER PANEL (left panel, 28 rows) ──────────────────────────────────────
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


# ═══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def expected_tableau_char(row_idx, col_idx):
    """Return the expected character at body row row_idx (1-based), col col_idx (0-based).

    Body rows 1–26 correspond to key letters A–Z (standard alphabet order).
    Each row is the KA alphabet cyclically shifted:
      Row 1 (Key A): KA shifted by KA.index(A) = KA[7:] + KA[:7] = ABCDEFGHIJLMNQUVWXZKRYPTOS
    Wait — actually the tableau row for Key X starts at KA position of X in KA.

    Row label = key letter. The row body (after the label) is:
      KA cyclically shifted so that column 0 maps to key_letter's position in KA.

    Actually from the data: Row 1 = "AKRYPTOSABCDEFGHIJLMNQUVWXZKRYP"
    The first char is 'A' (the label), then "KRYPTOSABCDEFGHIJLMNQUVWXZKRYP" (30 chars).
    KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ" (26 chars).
    So body = KA + KA[:4] = "KRYPTOSABCDEFGHIJLMNQUVWXZKRYP" — correct, that's KA shifted by 0.

    Row 2 = "BRYPTOSABCDEFGHIJLMNQUVWXZKRYPT"
    Body (after B) = "RYPTOSABCDEFGHIJLMNQUVWXZKRYPT" = KA[1:] + KA[:5] — shifted by 1.

    Row 3 = "CYPTOSABCDEFGHIJLMNQUVWXZKRYPTO"
    Body (after C) = "YPTOSABCDEFGHIJLMNQUVWXZKRYPTO" = KA[2:] + KA[:6] — shifted by 2.

    Pattern: body row i (1-indexed) has body = KA shifted left by (i-1).
    Body[col] = KA[(col + i - 1) % 26]

    But wait — the row labels go A,B,C,D... not K,R,Y,P... So row_idx 1 = Key A,
    and the KA shift for key A is... let's check:
      Key A: KA.index('A') = 7. But the shift is 0, not 7.
    Actually the shift is just (row_idx - 1), where row_idx 1 = Key A.
    """
    # row_idx is 1-based (1 = Key A, 2 = Key B, ..., 26 = Key Z)
    # col_idx is 0-based (first char AFTER the row label)
    shift = row_idx - 1
    return KA[(col_idx + shift) % 26]


def compute_ic(text):
    """Compute Index of Coincidence for a text."""
    n = len(text)
    if n < 2:
        return 0.0
    freq = Counter(text)
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


def check_cribs(text, label=""):
    """Check if K4 cribs appear at any position in the text."""
    hits = []
    for word in ["EASTNORTHEAST", "BERLINCLOCK", "EAST", "NORTH", "BERLIN", "CLOCK",
                 "THE", "AND", "WAS", "SLOWLY"]:
        for i in range(len(text) - len(word) + 1):
            if text[i:i + len(word)] == word:
                hits.append((word, i))
    return hits


def try_decrypt(ct_text, key, mode="vig", alphabet=AZ):
    """Decrypt ct_text with key using Vigenere or Beaufort."""
    pt = []
    for i, c in enumerate(ct_text):
        ci = alphabet.index(c) if c in alphabet else -1
        if ci < 0:
            pt.append(c)
            continue
        ki = alphabet.index(key[i % len(key)]) if key[i % len(key)] in alphabet else 0
        if mode == "vig":
            pi = (ci - ki) % len(alphabet)
        elif mode == "beau":
            pi = (ki - ci) % len(alphabet)
        else:  # variant beaufort
            pi = (ci + ki) % len(alphabet)
        pt.append(alphabet[pi])
    return ''.join(pt)


def positions_to_permutation(positions, target_len=97):
    """Convert a set of (row, col) positions to a permutation of indices.

    Reads positions in row-major order and maps to sequential indices.
    Returns a list of length target_len if enough positions exist.
    """
    sorted_pos = sorted(positions, key=lambda p: (p[0], p[1]))
    if len(sorted_pos) < target_len:
        return None
    return sorted_pos[:target_len]


def try_as_k4_unscramble(positions, label):
    """Try a set of positions as a K4 unscrambling permutation.

    Convert positions to a numeric permutation and apply to K4.
    """
    sorted_pos = sorted(positions, key=lambda p: (p[0], p[1]))
    n = len(sorted_pos)
    if n < 97:
        print(f"  [{label}] Only {n} positions, need 97 — skipping K4 unscramble")
        return

    # Method 1: Use first 97 positions directly as indices
    # Flatten (row, col) to a linear index using a fixed width
    max_col = max(c for _, c in sorted_pos) + 1
    linear = [(r * max_col + c) for r, c in sorted_pos[:97]]
    # Rank to get a permutation [0..96]
    ranked = sorted(range(97), key=lambda i: linear[i])
    unscrambled = ''.join(CT[ranked[i]] for i in range(97))

    print(f"  [{label}] Unscrambled (rank of linear index, first 97 positions):")
    print(f"    {unscrambled}")

    # Check for crib fragments
    hits = check_cribs(unscrambled)
    if hits:
        print(f"    *** CRIB HITS: {hits} ***")

    # Try Vig/Beaufort with standard keywords
    for key in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
        for mode in ["vig", "beau"]:
            for alph_label, alph in [("AZ", AZ), ("KA", KA)]:
                pt = try_decrypt(unscrambled, key, mode, alph)
                pt_hits = check_cribs(pt)
                if pt_hits:
                    print(f"    *** {mode}/{key}/{alph_label}: {pt}  HITS={pt_hits} ***")

    # Method 2: Use column indices directly mod 97
    col_indices = [c % 97 for _, c in sorted_pos[:97]]
    if len(set(col_indices)) == 97:  # Only if all unique
        unscrambled2 = ''.join(CT[c] for c in col_indices)
        print(f"  [{label}] Unscrambled (col % 97):")
        print(f"    {unscrambled2}")
        hits2 = check_cribs(unscrambled2)
        if hits2:
            print(f"    *** CRIB HITS: {hits2} ***")


def read_through_positions(grid, positions, label=""):
    """Read characters from grid at given positions in order."""
    chars = []
    for r, c in positions:
        if 0 <= r < len(grid) and 0 <= c < len(grid[r]):
            ch = grid[r][c]
            if ch.isalpha():
                chars.append(ch)
    return ''.join(chars)


def analyze_mask(positions, label):
    """Analyze a set of positions as a mask: count, read from both panels, stats."""
    print(f"\n{'─' * 70}")
    print(f"  MASK: {label}")
    print(f"{'─' * 70}")
    print(f"  Hole count: {len(positions)}")

    if not positions:
        print(f"  (empty mask)")
        return

    sorted_pos = sorted(positions, key=lambda p: (p[0], p[1]))

    # Read from tableau
    tab_text = read_through_positions(TABLEAU, sorted_pos)
    # Read from cipher panel
    cp_text = read_through_positions(CIPHER_PANEL, sorted_pos)

    print(f"  Tableau read ({len(tab_text)} chars): {tab_text[:80]}{'...' if len(tab_text) > 80 else ''}")
    print(f"  Cipher panel read ({len(cp_text)} chars): {cp_text[:80]}{'...' if len(cp_text) > 80 else ''}")

    for text, src in [(tab_text, "tableau"), (cp_text, "cipher_panel")]:
        if len(text) > 5:
            ic = compute_ic(text)
            freq = Counter(text)
            missing = set(AZ) - set(text)
            print(f"  {src}: IC={ic:.4f}, missing={sorted(missing) if missing else 'none'}")

            hits = check_cribs(text)
            if hits:
                print(f"    *** CRIB HITS in {src}: {hits} ***")

    # Try as K4 unscrambling
    if len(positions) >= 97:
        try_as_k4_unscramble(positions, label)


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 1: DEVIATION POSITIONS — where tableau differs from perfect KA cyclic shift
# ═══════════════════════════════════════════════════════════════════════════════

def test_deviation_positions():
    print("\n" + "=" * 70)
    print("  TEST 1: Deviation positions (actual vs expected KA cyclic shift)")
    print("=" * 70)

    deviation_positions = []
    extra_positions = []

    for row_idx in range(1, 27):  # Body rows 1–26
        row_str = TABLEAU[row_idx]
        label = row_str[0]  # Row label (first char)
        body = row_str[1:]  # Body chars (after label)

        expected_len = 30  # Normal body length

        for col_idx in range(min(len(body), 30)):
            actual = body[col_idx]
            expected = expected_tableau_char(row_idx, col_idx)
            if actual != expected:
                deviation_positions.append((row_idx, col_idx + 1, actual, expected))

        # Check for extra characters beyond position 30
        if len(body) > 30:
            for col_idx in range(30, len(body)):
                extra_positions.append((row_idx, col_idx + 1, body[col_idx]))

    print(f"\n  Deviations within first 30 body columns: {len(deviation_positions)}")
    for r, c, actual, expected in deviation_positions:
        key_letter = chr(64 + r)
        print(f"    Row {r:2d} (Key {key_letter}), col {c:2d}: actual={actual}, expected={expected}")

    print(f"\n  Extra characters beyond col 30: {len(extra_positions)}")
    for r, c, ch in extra_positions:
        key_letter = chr(64 + r)
        print(f"    Row {r:2d} (Key {key_letter}), col {c:2d}: extra char = {ch}")

    # The deviation positions form a candidate mask
    # Include both deviations and extra positions
    all_anomalous = set()
    for r, c, _, _ in deviation_positions:
        all_anomalous.add((r, c))
    for r, c, _ in extra_positions:
        all_anomalous.add((r, c))

    analyze_mask(all_anomalous, "All deviations from expected KA shift")

    # Also check: are the deviations in Row 15 (Key O)?
    # Row 15 data: "OHIJLMNQUVWXZKRYPTOSABCDEFGHIJL"
    # Expected for row 15 (shift 14): KA[(col + 14) % 26]
    print(f"\n  Detailed check of anomalous rows:")
    for anomalous_row in [14, 15, 22]:
        row_str = TABLEAU[anomalous_row]
        label = row_str[0]
        body = row_str[1:]
        print(f"\n  Row {anomalous_row} (Key {label}): len={len(body)} body chars")
        print(f"    Body: {body}")
        expected_body = ''.join(expected_tableau_char(anomalous_row, c) for c in range(30))
        print(f"    Expd: {expected_body}")
        # Character-by-character diff
        diffs = []
        for c in range(min(len(body), len(expected_body))):
            if body[c] != expected_body[c]:
                diffs.append((c, body[c], expected_body[c]))
        if len(body) > len(expected_body):
            for c in range(len(expected_body), len(body)):
                diffs.append((c, body[c], '-'))
        if diffs:
            print(f"    Diffs: {diffs}")
        else:
            print(f"    MATCHES perfectly in first {min(len(body), 30)} chars")
            if len(body) > 30:
                print(f"    Extra: {body[30:]}")


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 2: X-POSITION MAPPING — X is the omitted K2 delimiter
# ═══════════════════════════════════════════════════════════════════════════════

def test_x_positions():
    print("\n" + "=" * 70)
    print("  TEST 2: All X positions on tableau (X = omitted K2 delimiter)")
    print("=" * 70)

    x_positions_tab = []
    for r, row in enumerate(TABLEAU):
        for c, ch in enumerate(row):
            if ch == 'X':
                x_positions_tab.append((r, c))

    print(f"\n  Total X positions on tableau: {len(x_positions_tab)}")

    # Distribution by row
    by_row = Counter(r for r, _ in x_positions_tab)
    for r in sorted(by_row):
        label = "Hdr" if r == 0 else "Ftr" if r == 27 else f"Key {chr(64+r)}"
        cols = sorted(c for rr, c in x_positions_tab if rr == r)
        print(f"    Row {r:2d} ({label:5s}): {by_row[r]} X's at cols {cols}")

    analyze_mask(set(x_positions_tab), "All X positions on tableau")

    # Also: X positions on cipher panel
    x_positions_cp = []
    for r, row in enumerate(CIPHER_PANEL):
        for c, ch in enumerate(row):
            if ch == 'X':
                x_positions_cp.append((r, c))

    print(f"\n  Total X positions on cipher panel: {len(x_positions_cp)}")

    # Cross-reference: X on cipher panel, read corresponding position on tableau
    cross_text = read_through_positions(TABLEAU, sorted(x_positions_cp, key=lambda p: (p[0], p[1])))
    print(f"  Tableau chars at cipher panel X positions ({len(cross_text)} chars): {cross_text}")
    if cross_text:
        ic = compute_ic(cross_text)
        missing = set(AZ) - set(cross_text)
        print(f"    IC={ic:.4f}, missing={sorted(missing) if missing else 'none'}")
        hits = check_cribs(cross_text)
        if hits:
            print(f"    *** CRIB HITS: {hits} ***")


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 3: DIAGONAL LETTER PATTERNS
# ═══════════════════════════════════════════════════════════════════════════════

def test_diagonals():
    print("\n" + "=" * 70)
    print("  TEST 3: Diagonal letter patterns on tableau body")
    print("=" * 70)

    # In the KA tableau, each letter traces a diagonal.
    # For body rows 1–26, col 1–30 (after label):
    # The letter at body row r, col c is KA[(c + r - 2) % 26] (adjusting for 0-based)
    # So letter L at KA index k appears at positions where (c + r - 2) % 26 == k
    # i.e., c = (k - r + 2) % 26

    # For each letter, collect its diagonal positions on the full tableau
    print(f"\n  Diagonal positions for each letter (body rows 1-26, cols 1-30):")

    best_letter = None
    best_count = 0

    for letter in AZ:
        positions = []
        for r in range(1, 27):  # Body rows
            row_str = TABLEAU[r]
            for c in range(1, len(row_str)):  # Skip label
                if row_str[c] == letter:
                    positions.append((r, c))

        # Read cipher panel at these positions
        cp_text = read_through_positions(CIPHER_PANEL, sorted(positions, key=lambda p: (p[0], p[1])))
        ic = compute_ic(cp_text) if len(cp_text) > 5 else 0.0
        missing_from_cp = set(AZ) - set(cp_text)

        # Check for cribs in the cipher panel reading
        hits = check_cribs(cp_text)
        flag = " ***" if hits else ""

        # T is special
        t_flag = " [T-ABSENT FROM GRILLE EXTRACT]" if letter == 'T' else ""

        print(f"    {letter}: {len(positions):3d} positions, CP read={len(cp_text):3d} chars, "
              f"IC={ic:.4f}, missing_CP={len(missing_from_cp)}{t_flag}{flag}")

        if hits:
            print(f"        CRIB HITS: {hits}")
            print(f"        CP text: {cp_text[:60]}...")

        if len(positions) > best_count:
            best_count = len(positions)
            best_letter = letter

    # Analyze the T diagonal specifically (T is absent from grille extract)
    print(f"\n  Best coverage letter: {best_letter} ({best_count} positions)")

    # Non-T positions as a mask (since T is absent from grille extract)
    non_t_positions = []
    for r in range(1, 27):
        row_str = TABLEAU[r]
        for c in range(1, len(row_str)):
            if row_str[c] != 'T':
                non_t_positions.append((r, c))

    t_only_positions = []
    for r in range(1, 27):
        row_str = TABLEAU[r]
        for c in range(1, len(row_str)):
            if row_str[c] == 'T':
                t_only_positions.append((r, c))

    print(f"\n  T positions on tableau body: {len(t_only_positions)}")
    print(f"  Non-T positions on tableau body: {len(non_t_positions)}")
    analyze_mask(set(t_only_positions), "T-only positions on tableau body")


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 4: ROW N (extra L) and ROW V (extra T) analysis
# ═══════════════════════════════════════════════════════════════════════════════

def test_anomalous_rows():
    print("\n" + "=" * 70)
    print("  TEST 4: Row N (extra L) and Row V (extra T) — numeric analysis")
    print("=" * 70)

    # Row 14 (Key N): extra L
    # Row 22 (Key V): extra T
    # N = position 13 (A=0), V = position 21 (A=0)
    # L = position 11 (A=0), T = position 19 (A=0)
    # In KA: N at KA index 18, V at KA index 22, L at KA index 16, T at KA index 6

    n_az = AZ_IDX['N']  # 13
    v_az = AZ_IDX['V']  # 21
    l_az = AZ_IDX['L']  # 11
    t_az = AZ_IDX['T']  # 19

    n_ka = KA_IDX['N']  # 18
    v_ka = KA_IDX['V']  # 22
    l_ka = KA_IDX['L']  # 16
    t_ka = KA_IDX['T']  # 6

    print(f"\n  AZ indices: N={n_az}, V={v_az}, L={l_az}, T={t_az}")
    print(f"  KA indices: N={n_ka}, V={v_ka}, L={l_ka}, T={t_ka}")

    print(f"\n  Numeric relationships:")
    print(f"    N + V = {n_az + v_az} (AZ), {n_ka + v_ka} (KA)")
    print(f"    L + T = {l_az + t_az} (AZ), {l_ka + t_ka} (KA)")
    print(f"    N - V = {n_az - v_az} (AZ), {n_ka - v_ka} (KA)")
    print(f"    L - T = {l_az - t_az} (AZ), {l_ka - t_ka} (KA)")
    print(f"    N * V = {n_az * v_az} (AZ), {n_ka * v_ka} (KA)")
    print(f"    L * T = {l_az * t_az} (AZ), {l_ka * t_ka} (KA)")
    print(f"    N × L = {n_az * l_az} (AZ), V × T = {v_az * t_az} (AZ)")
    print(f"    (N-L) = {n_az - l_az}, (V-T) = {v_az - t_az}  → both = {n_az - l_az == v_az - t_az}")
    print(f"    Row 14 + Row 22 = {14 + 22} = 36")
    print(f"    Row 22 - Row 14 = {22 - 14} = 8")
    print(f"    97 mod (N_az+1) = {97 % (n_az + 1)}, 97 mod (V_az+1) = {97 % (v_az + 1)}")
    print(f"    97 mod 8 = {97 % 8} (row difference = 8)")
    print(f"    26 * 30 = {26 * 30} (normal tableau body cells)")
    print(f"    26 * 30 + 2 = {26 * 30 + 2} (with two extra chars)")

    # NL and VT as position pairs
    print(f"\n  NL as a pair: positions ({n_az}, {l_az}) — distance {abs(n_az - l_az)}")
    print(f"  VT as a pair: positions ({v_az}, {t_az}) — distance {abs(v_az - t_az)}")
    print(f"  NL → VT mapping: {n_az}→{v_az} (+{v_az - n_az}), {l_az}→{t_az} (+{t_az - l_az})")
    print(f"  Both differ by 8 in AZ: N(13)+8=V(21), L(11)+8=T(19)")

    # Use the extra-char rows to define mask regions
    # The extra L is at position 31 (0-indexed) in row 14
    # The extra T is at position 31 (0-indexed) in row 22
    print(f"\n  Extra char positions:")
    print(f"    Row 14 body length: {len(TABLEAU[14]) - 1} (expected 30, got {len(TABLEAU[14]) - 1})")
    print(f"    Row 22 body length: {len(TABLEAU[22]) - 1} (expected 30, got {len(TABLEAU[22]) - 1})")
    print(f"    Row 14 last char: {TABLEAU[14][-1]} at overall position {len(TABLEAU[14])-1}")
    print(f"    Row 22 last char: {TABLEAU[22][-1]} at overall position {len(TABLEAU[22])-1}")

    # What if N and V define the KEY period? N-L = V-T = 2
    # What if the ROW difference (8) is the period?
    print(f"\n  Period hypothesis: row difference = 8")
    print(f"    Rows at period 8 from row 14: {[14 + 8*i for i in range(-2, 3) if 0 <= 14 + 8*i <= 27]}")
    print(f"    Rows at period 8 from row 22: {[22 + 8*i for i in range(-3, 2) if 0 <= 22 + 8*i <= 27]}")

    # Check if rows 14 and 22 content, when XOR'd/combined, produces something
    row14_body = TABLEAU[14][1:]  # Skip label N
    row22_body = TABLEAU[22][1:]  # Skip label V
    print(f"\n  Row 14 body: {row14_body}")
    print(f"  Row 22 body: {row22_body}")

    # Overlap region (first min(len) chars)
    overlap_len = min(len(row14_body), len(row22_body))
    combined = []
    for i in range(overlap_len):
        a = AZ_IDX.get(row14_body[i], 0)
        b = AZ_IDX.get(row22_body[i], 0)
        diff = (a - b) % 26
        combined.append(AZ[diff])
    combined_str = ''.join(combined)
    print(f"  (Row14 - Row22) mod 26: {combined_str}")
    hits = check_cribs(combined_str)
    if hits:
        print(f"    *** CRIB HITS: {hits} ***")

    # Read cipher panel rows 14 and 22
    cp14 = CIPHER_PANEL[14]
    cp22 = CIPHER_PANEL[22]
    print(f"\n  Cipher panel row 14: {cp14}")
    print(f"  Cipher panel row 22: {cp22}")


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 5: HEADER/FOOTER vs BODY alphabet difference
# ═══════════════════════════════════════════════════════════════════════════════

def test_header_body_diff():
    print("\n" + "=" * 70)
    print("  TEST 5: Header/footer (standard AZ) vs body (KA) — difference positions")
    print("=" * 70)

    # Header = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCD" (30 chars)
    # Body row 1 starts with KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ..."
    # At each column position, where does the header letter differ from the body letter?

    header = TABLEAU[0]  # "ABCDEFGHIJKLMNOPQRSTUVWXYZABCD"
    print(f"  Header: {header}")

    # Compare header with each body row
    diff_by_col = [0] * 30
    all_diff_positions = set()

    for body_row_idx in range(1, 27):
        row = TABLEAU[body_row_idx]
        body = row[1:]  # Skip label
        for col in range(min(30, len(header), len(body))):
            if header[col] != body[col]:
                diff_by_col[col] += 1
                all_diff_positions.add((body_row_idx, col + 1))

    print(f"\n  Number of body rows differing from header at each column (0-29):")
    for col in range(30):
        bar = '#' * diff_by_col[col]
        print(f"    Col {col:2d} ({header[col]}): {diff_by_col[col]:2d}/26 differ  {bar}")

    # Where does header MATCH body? These are "agreement positions"
    agreement_positions = set()
    for body_row_idx in range(1, 27):
        row = TABLEAU[body_row_idx]
        body = row[1:]
        for col in range(min(30, len(header), len(body))):
            if header[col] == body[col]:
                agreement_positions.add((body_row_idx, col + 1))

    print(f"\n  Total agreement positions (header == body cell): {len(agreement_positions)}")
    analyze_mask(agreement_positions, "Header-body agreement positions")

    # Also: where does KA differ from AZ in ordering?
    print(f"\n  KA vs AZ letter ordering:")
    print(f"    AZ: {AZ}")
    print(f"    KA: {KA}")
    diff_indices = [i for i in range(26) if AZ[i] != KA[i]]
    same_indices = [i for i in range(26) if AZ[i] == KA[i]]
    print(f"    Positions where AZ[i] == KA[i]: {same_indices} → letters {[AZ[i] for i in same_indices]}")
    print(f"    Positions where AZ[i] != KA[i]: {diff_indices} → AZ={[AZ[i] for i in diff_indices]}, KA={[KA[i] for i in diff_indices]}")


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 6: SELF-REFERENTIAL FIXED POINTS
# ═══════════════════════════════════════════════════════════════════════════════

def test_fixed_points():
    print("\n" + "=" * 70)
    print("  TEST 6: Self-referential fixed points")
    print("=" * 70)

    # Fixed point type 1: tableau[r][c] == row label
    row_label_matches = []
    for r in range(1, 27):
        label = TABLEAU[r][0]
        for c in range(1, len(TABLEAU[r])):
            if TABLEAU[r][c] == label:
                row_label_matches.append((r, c))

    print(f"\n  Type 1: tableau[r][c] == row label ({len(row_label_matches)} positions)")
    by_label = {}
    for r, c in row_label_matches:
        label = TABLEAU[r][0]
        by_label.setdefault(label, []).append((r, c))
    for label in sorted(by_label):
        cols = [c for _, c in by_label[label]]
        print(f"    Key {label} (row {AZ_IDX[label]+1:2d}): cols {cols}")

    analyze_mask(set(row_label_matches), "Row-label fixed points")

    # Fixed point type 2: tableau[r][c] == column header
    header = TABLEAU[0]
    col_header_matches = []
    for r in range(1, 27):
        for c in range(1, min(len(TABLEAU[r]), len(header))):
            if TABLEAU[r][c] == header[c - 1]:  # Column c in body, header at c-1 (body offset by 1 for label)
                col_header_matches.append((r, c))

    # Actually the header has no offset — column 0 of header = 'A', and body row label is at position 0.
    # So body column 1 aligns with header column 0? Let me check alignment.
    # Header: "ABCDEFGHIJKLMNOPQRSTUVWXYZABCD" — positions 0-29
    # Body row 1: "AKRYPTOSABCDEFGHIJLMNQUVWXZKRYP" — position 0 = label, positions 1-30 = body
    # On the physical sculpture, header position 0 ('A') aligns with body position 1 ('K')
    # Actually looking at the sculpture image, the label is to the LEFT of the body,
    # so header col 0 aligns with body col 1.

    # Let's try both alignments
    col_header_matches_a = []  # header[c] aligns with body[c+1]
    col_header_matches_b = []  # header[c] aligns with body[c] (treating label as col 0 = off-grid)

    for r in range(1, 27):
        body = TABLEAU[r]
        for c in range(len(header)):
            # Alignment A: header[c] aligns with body[c+1]
            if c + 1 < len(body) and body[c + 1] == header[c]:
                col_header_matches_a.append((r, c + 1))
            # Alignment B: header[c] aligns with body[c] (label is body[0])
            if c < len(body) and body[c] == header[c]:
                col_header_matches_b.append((r, c))

    print(f"\n  Type 2a: tableau_body[r][c+1] == header[c] ({len(col_header_matches_a)} positions)")
    analyze_mask(set(col_header_matches_a), "Column-header matches (alignment A)")

    print(f"\n  Type 2b: tableau[r][c] == header[c] ({len(col_header_matches_b)} positions)")
    analyze_mask(set(col_header_matches_b), "Column-header matches (alignment B)")

    # Fixed point type 3: "true" fixed points where the letter IS its own position
    # i.e., the letter value equals its column index in some alphabet
    true_fixed = []
    for r in range(1, 27):
        body = TABLEAU[r][1:]  # body only
        for c in range(len(body)):
            ch = body[c]
            # Fixed in AZ: AZ_IDX[ch] == c
            if AZ_IDX.get(ch, -1) == c:
                true_fixed.append((r, c + 1, ch, "AZ"))
            # Fixed in KA: KA_IDX[ch] == c
            if KA_IDX.get(ch, -1) == c:
                true_fixed.append((r, c + 1, ch, "KA"))

    print(f"\n  Type 3: 'True' fixed points (letter == col index in AZ or KA): {len(true_fixed)}")
    for r, c, ch, alph_label in true_fixed[:30]:
        key = TABLEAU[r][0]
        print(f"    Row {r:2d} (Key {key}), col {c:2d}: {ch} ({alph_label})")
    if len(true_fixed) > 30:
        print(f"    ... ({len(true_fixed) - 30} more)")


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 7: POSITIONS OF SPECIFIC LETTER GROUPS
# ═══════════════════════════════════════════════════════════════════════════════

def test_specific_letters():
    print("\n" + "=" * 70)
    print("  TEST 7: Positions of specific letter groups on tableau")
    print("=" * 70)

    groups = {
        "EQUAL (Q,U,A,L)": set("QUAL"),
        "KRYPTOS": set("KRYPTOS"),
        "PALIMPSEST": set("PALIMPSEST"),
        "ABSCISSA": set("ABSCISSA"),
        "BERLINCLOCK": set("BERLINCLOCK"),
        "YAR": set("YAR"),
    }

    for group_name, letters in groups.items():
        positions = []
        for r in range(1, 27):
            for c in range(1, len(TABLEAU[r])):
                if TABLEAU[r][c] in letters:
                    positions.append((r, c))

        print(f"\n  {group_name}: {len(letters)} unique letters → {len(positions)} positions on tableau body")

        # Read cipher panel at these positions
        cp_text = read_through_positions(CIPHER_PANEL, sorted(positions, key=lambda p: (p[0], p[1])))
        if cp_text:
            ic = compute_ic(cp_text) if len(cp_text) > 5 else 0.0
            hits = check_cribs(cp_text)
            print(f"    CP read: {len(cp_text)} chars, IC={ic:.4f}")
            if hits:
                print(f"    *** CRIB HITS: {hits} ***")

    # Special: positions where tableau body has letters from EQUAL anagram
    # but NOT from KRYPTOS keyword (difference set)
    equal_only = set("QUAL") - set("KRYPTOS")
    kryptos_only = set("KRYPTOS") - set("QUAL")
    overlap_set = set("QUAL") & set("KRYPTOS")
    print(f"\n  EQUAL letters not in KRYPTOS: {sorted(equal_only)}")
    print(f"  KRYPTOS letters not in EQUAL: {sorted(kryptos_only)}")
    print(f"  Overlap: {sorted(overlap_set)}")


# ═══════════════════════════════════════════════════════════════════════════════
# BONUS TEST: Reading order from row-column structure
# ═══════════════════════════════════════════════════════════════════════════════

def test_row_column_reading():
    print("\n" + "=" * 70)
    print("  BONUS: Column-by-column reading of tableau body → permutation ideas")
    print("=" * 70)

    # Read tableau body column by column (top to bottom within each column)
    # This gives a 26-char string per column, using KA cyclic shifts
    for col in range(30):
        col_chars = []
        for r in range(1, 27):
            body = TABLEAU[r][1:]
            if col < len(body):
                col_chars.append(body[col])
            else:
                col_chars.append('?')
        col_str = ''.join(col_chars)
        # Check if this column is just the KA alphabet (possibly shifted)
        is_ka_shift = False
        for shift in range(26):
            shifted = ''.join(KA[(i + shift) % 26] for i in range(26))
            if col_str == shifted:
                is_ka_shift = True
                break
        ka_note = f" = KA shifted by {shift}" if is_ka_shift else ""
        # Only print non-trivial columns
        if not is_ka_shift or col < 5 or col > 25:
            print(f"  Col {col:2d}: {col_str}{ka_note}")

    # Reading tableau in specific patterns to get 97 chars
    print(f"\n  Total body cells (26 rows × 30 cols + 2 extra): {26 * 30 + 2}")
    print(f"  782 / 97 = {782 / 97:.4f}")
    print(f"  780 / 97 = {780 / 97:.4f}")
    print(f"  782 mod 97 = {782 % 97}")
    print(f"  780 mod 97 = {780 % 97}")

    # What if we read every 8th cell (from the N-V distance)?
    linear_body = []
    for r in range(1, 27):
        body = TABLEAU[r][1:]
        for c in range(len(body)):
            linear_body.append(body[c])

    total = len(linear_body)
    print(f"\n  Total linear body chars: {total}")

    for step in [8, 13, 16, 19, 20, 23, 24, 26]:
        reading = ''.join(linear_body[i] for i in range(0, total, step) if i < total)
        reading97 = reading[:97] if len(reading) >= 97 else reading
        hits = check_cribs(reading97)
        print(f"  Every {step}th cell: {len(reading)} chars. First 97: {reading97[:40]}... {'HITS=' + str(hits) if hits else ''}")


# ═══════════════════════════════════════════════════════════════════════════════
# BONUS TEST: Cross-panel overlay
# ═══════════════════════════════════════════════════════════════════════════════

def test_cross_panel():
    print("\n" + "=" * 70)
    print("  BONUS: Cross-panel analysis (cipher panel letter → tableau position)")
    print("=" * 70)

    # For each cell (r,c) on the cipher panel, the cipher panel has letter CP[r][c]
    # and the tableau has letter TAB[r][c]. The combination could be meaningful.

    # Specifically: where CP[r][c] == TAB[r][c] (same letter at same position)
    same_positions = []
    for r in range(min(len(CIPHER_PANEL), len(TABLEAU))):
        for c in range(min(len(CIPHER_PANEL[r]), len(TABLEAU[r]))):
            cp_ch = CIPHER_PANEL[r][c]
            tab_ch = TABLEAU[r][c]
            if cp_ch.isalpha() and tab_ch.isalpha() and cp_ch == tab_ch:
                same_positions.append((r, c, cp_ch))

    print(f"\n  Positions where cipher_panel[r][c] == tableau[r][c]: {len(same_positions)}")
    for r, c, ch in same_positions:
        cp_section = "K1" if r < 8 else "K2" if r < 14 else "K3" if r < 24 else "K4"
        tab_section = "Hdr" if r == 0 else "Ftr" if r == 27 else f"Key {chr(64+r)}"
        print(f"    ({r:2d},{c:2d}): {ch}  (CP={cp_section}, TAB={tab_section})")

    # Read K4 rows specifically: rows 24-27
    k4_same = [(r, c, ch) for r, c, ch in same_positions if r >= 24]
    print(f"\n  K4-region matches (rows 24-27): {len(k4_same)}")
    for r, c, ch in k4_same:
        print(f"    ({r},{c}): {ch}")

    # Where CP[r][c] + TAB[r][c] (mod 26) gives a specific value
    # (Vig-style: K = (CT - PT) mod 26 where CT=cipher_panel, PT=tableau)
    print(f"\n  Vigenère 'key' from (CP - TAB) mod 26 for K4 rows:")
    for r in range(24, 28):
        keys = []
        for c in range(min(len(CIPHER_PANEL[r]), len(TABLEAU[r]))):
            cp_ch = CIPHER_PANEL[r][c]
            tab_ch = TABLEAU[r][c]
            if cp_ch.isalpha() and tab_ch.isalpha():
                k = (AZ_IDX[cp_ch] - AZ_IDX[tab_ch]) % 26
                keys.append(AZ[k])
            else:
                keys.append('?')
        print(f"    Row {r}: {''.join(keys)}")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 70)
    print("  E-GRILLE-19: Tableau Geometry → Grille Mask Derivation")
    print("=" * 70)
    print(f"  K4 CT: {CT}")
    print(f"  K4 length: {CT_LEN}")
    print(f"  KA: {KA}")
    print(f"  Tableau: {len(TABLEAU)} rows, widths {[len(r) for r in TABLEAU]}")

    test_deviation_positions()
    test_x_positions()
    test_diagonals()
    test_anomalous_rows()
    test_header_body_diff()
    test_fixed_points()
    test_specific_letters()
    test_row_column_reading()
    test_cross_panel()

    print("\n" + "=" * 70)
    print("  E-GRILLE-19: COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
