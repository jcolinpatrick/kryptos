#!/usr/bin/env python3
"""
E-GRILLE-18: EQUAL anagram + misspelling positions as grille parameters

The K1-K3 misspellings produce substituted letters that anagram to EQUAL:
  PALIMPCEST:  S->C  at keyword position 7
  IQLUSION:    L->Q  at word position 2
  UNDERGRUUND: O->U  at word position 10
  DESPARATLY:  E->A  at position 5, E deleted at position 8
  DIGETAL:     I->E  at word position 4

Omitted letters: X (K2 delimiter), E (from DESPERATELY)

This script tests:
  1. Error positions (7,2,10,5,8,4) as grid width, column key, rotation params
  2. EQUAL letter values (Q=16,U=20,A=0,L=11,E=4 in A=0; KA numbering too)
  3. Substitution pairs (S->C, L->Q, O->U, E->A, I->E) as mini cipher on K4
  4. Positions of misspelled words within their K-sections mapped onto K4
  5. X=23, E=4 as starting offsets or step sizes
  6. Combined: use error positions as columnar transposition key
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from collections import Counter
import itertools
import math

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, KRYPTOS_ALPHABET,
    CRIB_WORDS, CRIB_DICT, N_CRIBS
)

# ─── GRILLE EXTRACT (106 chars from KA tableau, T absent) ──────────────────
GRILLE_EXTRACT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"

# ─── CIPHER PANEL (from e_grille_15) ────────────────────────────────────────
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
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",        # Row 21
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORIT",      # Row 22
    "RKLMLEHAGTDHARDPNEOHMGFMFEUHE",          # Row 23
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",        # Row 24 (K3->K4)
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",         # Row 25
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",         # Row 26
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",         # Row 27
]

# ─── VIGENERE TABLEAU (from e_grille_15) ────────────────────────────────────
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

# ─── MISSPELLING DATA ───────────────────────────────────────────────────────
# (section, word, correct, misspelled, pos_in_word, old_letter, new_letter)
MISSPELLINGS = [
    ("K1-key", "PALIMPSEST", "PALIMPCEST", 7, "S", "C"),
    ("K1-pt",  "ILLUSION",   "IQLUSION",   2, "L", "Q"),
    ("K2-pt",  "UNDERGROUND","UNDERGRUUND",10, "O", "U"),
    ("K3-pt",  "DESPERATELY","DESPARATLY",  5, "E", "A"),
    # position 8 deletion: DESPERATELY->DESPARATLY also loses E at pos 8
    ("K0",     "DIGITAL",    "DIGETAL",     4, "I", "E"),
]

# Error positions within their respective words
ERROR_POSITIONS = [7, 2, 10, 5, 8, 4]  # PALIMPCEST, IQLUSION, UNDERGRUUND, DESPARATLY(x2), DIGETAL

# Substituted letters (what appears ON the sculpture, "wrong" letters)
WRONG_LETTERS = ['C', 'Q', 'U', 'A', 'E']  # anagram of EQUAL
# Original letters (what SHOULD have been there)
RIGHT_LETTERS = ['S', 'L', 'O', 'E', 'I']

# Substitution pairs: right -> wrong
SUBST_PAIRS = dict(zip(RIGHT_LETTERS, WRONG_LETTERS))  # S->C, L->Q, O->U, E->A, I->E

# Omitted letters
OMITTED_X = 23  # X=23 in A=0
OMITTED_E = 4   # E=4 in A=0

# ─── HELPERS ────────────────────────────────────────────────────────────────

def vig_decrypt(ct_text, key, alphabet=ALPH):
    """Vigenere decrypt: PT[i] = (CT[i] - KEY[i]) mod 26."""
    pt = []
    for i, c in enumerate(ct_text):
        ci = alphabet.index(c) if c in alphabet else -1
        if ci < 0:
            pt.append(c)
            continue
        ki = alphabet.index(key[i % len(key)])
        pi = (ci - ki) % len(alphabet)
        pt.append(alphabet[pi])
    return ''.join(pt)


def beaufort_decrypt(ct_text, key, alphabet=ALPH):
    """Beaufort decrypt: PT[i] = (KEY[i] - CT[i]) mod 26."""
    pt = []
    for i, c in enumerate(ct_text):
        ci = alphabet.index(c) if c in alphabet else -1
        if ci < 0:
            pt.append(c)
            continue
        ki = alphabet.index(key[i % len(key)])
        pi = (ki - ci) % len(alphabet)
        pt.append(alphabet[pi])
    return ''.join(pt)


def score_cribs(text):
    """Count how many of the 24 crib positions match."""
    hits = 0
    for pos, ch in CRIB_DICT.items():
        if 0 <= pos < len(text) and text[pos] == ch:
            hits += 1
    return hits


def score_english_words(text):
    """Quick scan for common English words (3+ letters)."""
    words = ["THE", "AND", "EAST", "NORTH", "BERLIN", "CLOCK", "WAS", "THAT",
             "WITH", "FOR", "ARE", "NOT", "YOU", "ALL", "CAN", "HER", "FROM",
             "ONE", "OUR", "OUT", "THEY", "BEEN", "HAVE", "SAID", "EACH",
             "WHICH", "THEIR", "WILL", "OTHER", "ABOUT", "MANY", "THEN",
             "THEM", "WOULD", "MAKE", "LIKE", "TIME", "JUST", "KNOW",
             "PEOPLE", "INTO", "COULD", "SOME", "WHAT", "ONLY", "VERY",
             "WHEN", "COME", "MADE", "AFTER", "BACK", "LIGHT", "SHADOW",
             "BURIED", "UNDERGROUND", "SLOWLY", "INVISIBLE", "HIDDEN",
             "BETWEEN", "POSITION", "LAYER", "INACCESSIBLE"]
    found = []
    for w in words:
        if w in text:
            found.append(w)
    return found


def apply_permutation(ct_text, perm):
    """Apply permutation: output[i] = ct_text[perm[i]]"""
    return ''.join(ct_text[p] for p in perm)


def columnar_read(text, width):
    """Read text in columnar order with given width (write by rows, read by columns)."""
    nrows = math.ceil(len(text) / width)
    padded = text.ljust(nrows * width, '?')
    result = []
    for c in range(width):
        for r in range(nrows):
            idx = r * width + c
            if idx < len(text):
                result.append(text[idx])
    return ''.join(result)


def columnar_write(text, width):
    """Write by columns, read by rows (inverse of columnar_read)."""
    nrows = math.ceil(len(text) / width)
    ncols = width
    grid = [''] * nrows
    idx = 0
    for c in range(ncols):
        for r in range(nrows):
            if idx < len(text):
                grid[r] += text[idx]
                idx += 1
            else:
                grid[r] += '?'
    return ''.join(grid)[:len(text)]


def keyed_columnar_read(text, key_order):
    """Keyed columnar transposition: write by rows, read columns in key order."""
    width = len(key_order)
    nrows = math.ceil(len(text) / width)
    padded = text.ljust(nrows * width, '?')
    # Build grid
    grid = []
    for r in range(nrows):
        grid.append(padded[r * width: (r + 1) * width])
    # Read in key order
    result = []
    for col in key_order:
        for r in range(nrows):
            ch = grid[r][col] if col < len(grid[r]) else '?'
            if ch != '?' or (r * width + col) < len(text):
                result.append(ch)
    return ''.join(c for c in result if c != '?')[:len(text)]


def keyed_columnar_decipher(ct_text, key_order):
    """Reverse keyed columnar: distribute CT into columns by key order, read by rows."""
    width = len(key_order)
    nrows = math.ceil(len(ct_text) / width)
    total_cells = nrows * width
    short_cols = total_cells - len(ct_text)

    # Determine column lengths
    col_lengths = {}
    for c in range(width):
        if c in range(width - short_cols, width):
            col_lengths[c] = nrows - 1
        else:
            col_lengths[c] = nrows

    # Actually: columns that are "short" are those with highest key_order indices
    # For simplicity, compute which columns are short based on number of chars
    remainder = len(ct_text) % width
    # Columns 0..remainder-1 have nrows chars, remainder..width-1 have nrows-1
    actual_col_lengths = []
    for c in range(width):
        if remainder == 0:
            actual_col_lengths.append(nrows)
        elif c < remainder:
            actual_col_lengths.append(nrows)
        else:
            actual_col_lengths.append(nrows - 1 if nrows * width > len(ct_text) else nrows)

    # Fill columns in key order
    columns = [''] * width
    idx = 0
    for col in key_order:
        clen = actual_col_lengths[col]
        columns[col] = ct_text[idx:idx + clen]
        idx += clen

    # Read by rows
    result = []
    for r in range(nrows):
        for c in range(width):
            if r < len(columns[c]):
                result.append(columns[c][r])
    return ''.join(result)[:len(ct_text)]


def ic(text):
    """Index of coincidence."""
    freq = Counter(text)
    n = len(text)
    if n <= 1:
        return 0.0
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


def print_section(title):
    print(f"\n{'=' * 72}")
    print(f"  {title}")
    print(f"{'=' * 72}")


def test_decrypt(ct_text, label, best_results):
    """Try Vig/Beaufort with standard keywords, report crib matches."""
    keywords = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "EQUAL", "EQUALX",
                 "EQUALE", "QUEAL", "LAQUE", "AEQUL"]
    alphabets = [("AZ", ALPH), ("KA", KRYPTOS_ALPHABET)]

    for key in keywords:
        for alph_label, alph in alphabets:
            for method, func in [("Vig", vig_decrypt), ("Beau", beaufort_decrypt)]:
                pt = func(ct_text, key, alph)
                sc = score_cribs(pt)
                words = score_english_words(pt)
                if sc > 2 or len(words) > 1:
                    print(f"    {label}/{method}/{key}/{alph_label}: score={sc}/24 words={words}")
                    print(f"      PT: {pt}")
                    best_results.append((sc, label, method, key, alph_label, pt))


# ─── MAIN ───────────────────────────────────────────────────────────────────

def main():
    print("=" * 72)
    print("  E-GRILLE-18: EQUAL anagram + misspelling positions as grille parameters")
    print("=" * 72)

    best_results = []

    # ─── 1. Error positions as grid parameters ──────────────────────────────
    print_section("1. ERROR POSITIONS AS GRID PARAMETERS")
    print(f"  Error positions within words: {ERROR_POSITIONS}")
    print(f"    PALIMPCEST pos 7, IQLUSION pos 2, UNDERGRUUND pos 10")
    print(f"    DESPARATLY pos 5 and 8, DIGETAL pos 4")

    # 1a. Use error positions as grid widths for columnar transposition
    print(f"\n  [1a] Error positions as columnar widths:")
    for w in ERROR_POSITIONS:
        if w < 2 or w > 50:
            continue
        unscrambled = columnar_write(CT, w)  # decipher columnar
        sc = score_cribs(unscrambled)
        words = score_english_words(unscrambled)
        print(f"    Width {w}: score={sc}/24, words={words}")
        if sc > 2:
            print(f"      CT: {unscrambled}")
        test_decrypt(unscrambled, f"col_w{w}", best_results)

    # 1b. Unique error positions sorted as columnar key
    print(f"\n  [1b] Error positions as columnar KEY (sorted rank):")
    # [7,2,10,5,8,4] -> rank: 2=0, 4=1, 5=2, 7=3, 8=4, 10=5
    sorted_positions = sorted(enumerate(ERROR_POSITIONS), key=lambda x: x[1])
    key_order = [0] * len(ERROR_POSITIONS)
    for rank, (orig_idx, _) in enumerate(sorted_positions):
        key_order[orig_idx] = rank
    print(f"    Error positions: {ERROR_POSITIONS}")
    print(f"    Key order: {key_order}")  # [3, 0, 5, 2, 4, 1]

    # Keyed columnar decipher
    unscrambled = keyed_columnar_decipher(CT, key_order)
    sc = score_cribs(unscrambled)
    words = score_english_words(unscrambled)
    print(f"    Decipher: score={sc}/24, words={words}")
    print(f"      Result: {unscrambled}")
    test_decrypt(unscrambled, "keyed_col_errpos", best_results)

    # Also try the key as-is (values as column numbers)
    unscrambled2 = keyed_columnar_decipher(CT, [3, 0, 5, 2, 4, 1])
    sc2 = score_cribs(unscrambled2)
    print(f"    Alt key [3,0,5,2,4,1]: score={sc2}/24")
    test_decrypt(unscrambled2, "keyed_col_errpos_alt", best_results)

    # 1c. Error positions as step sizes for reading
    print(f"\n  [1c] Error positions as step sizes for reading CT:")
    for step in ERROR_POSITIONS:
        if step < 2:
            continue
        # Read every step-th character
        readings = []
        for start in range(step):
            chars = CT[start::step]
            readings.append(chars)
        interleaved = ''.join(readings)
        sc = score_cribs(interleaved)
        if sc > 0:
            print(f"    Step {step}: score={sc}/24: {interleaved[:50]}...")
        test_decrypt(interleaved, f"step_{step}", best_results)

    # 1d. Error positions as rotation counts for grille
    print(f"\n  [1d] Error positions as rotation/offset values:")
    for offset in ERROR_POSITIONS:
        rotated = CT[offset:] + CT[:offset]
        sc = score_cribs(rotated)
        print(f"    Rotate by {offset}: score={sc}/24")
        test_decrypt(rotated, f"rotate_{offset}", best_results)

    # ─── 2. EQUAL letter values as numeric key ──────────────────────────────
    print_section("2. EQUAL LETTER VALUES AS NUMERIC PARAMETERS")

    # A=0 numbering
    equal_a0 = [ALPH_IDX[c] for c in "EQUAL"]
    print(f"  EQUAL in A=0:  {list(zip('EQUAL', equal_a0))}")
    # E=4, Q=16, U=20, A=0, L=11

    # KA numbering
    ka_idx = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
    equal_ka = [ka_idx[c] for c in "EQUAL"]
    print(f"  EQUAL in KA:   {list(zip('EQUAL', equal_ka))}")

    # Wrong letters in order they were found: C, Q, U, A, E
    wrong_a0 = [ALPH_IDX[c] for c in WRONG_LETTERS]
    wrong_ka = [ka_idx[c] for c in WRONG_LETTERS]
    print(f"  Wrong letters {WRONG_LETTERS} in A=0: {wrong_a0}")
    print(f"  Wrong letters {WRONG_LETTERS} in KA:  {wrong_ka}")

    # Right (correct) letters: S, L, O, E, I
    right_a0 = [ALPH_IDX[c] for c in RIGHT_LETTERS]
    right_ka = [ka_idx[c] for c in RIGHT_LETTERS]
    print(f"  Right letters {RIGHT_LETTERS} in A=0: {right_a0}")
    print(f"  Right letters {RIGHT_LETTERS} in KA:  {right_ka}")

    # 2a. EQUAL values as grid width
    print(f"\n  [2a] EQUAL letter values as grid width (columnar):")
    for numbering_label, values in [("A=0", equal_a0), ("KA", equal_ka)]:
        for val in values:
            if val < 2 or val > 50:
                continue
            unscrambled = columnar_write(CT, val)
            sc = score_cribs(unscrambled)
            print(f"    {numbering_label} width={val}: score={sc}/24")
            test_decrypt(unscrambled, f"eq_{numbering_label}_w{val}", best_results)

    # 2b. EQUAL values as starting positions for reading
    print(f"\n  [2b] EQUAL values as skip/stride key:")
    for label, values in [("A=0", equal_a0), ("KA", equal_ka)]:
        # Use values as a cyclic key for reading order
        result = []
        pos = 0
        used = set()
        for i in range(CT_LEN):
            stride = values[i % len(values)]
            if stride == 0:
                stride = 1
            pos = (pos + stride) % CT_LEN
            attempts = 0
            while pos in used and attempts < CT_LEN:
                pos = (pos + 1) % CT_LEN
                attempts += 1
            if pos not in used:
                result.append(CT[pos])
                used.add(pos)
        text = ''.join(result)
        sc = score_cribs(text)
        print(f"    {label} stride key: score={sc}/24")
        test_decrypt(text, f"eq_stride_{label}", best_results)

    # 2c. Use EQUAL as Vig/Beaufort key directly on CT
    print(f"\n  [2c] EQUAL as direct decryption key:")
    for method, func in [("Vig", vig_decrypt), ("Beau", beaufort_decrypt)]:
        for alph_label, alph in [("AZ", ALPH), ("KA", KRYPTOS_ALPHABET)]:
            pt = func(CT, "EQUAL", alph)
            sc = score_cribs(pt)
            words = score_english_words(pt)
            print(f"    {method}/EQUAL/{alph_label}: score={sc}/24, words={words}")
            if sc > 2 or words:
                print(f"      PT: {pt}")
                best_results.append((sc, "direct", method, "EQUAL", alph_label, pt))

    # ─── 3. Substitution pairs as mini cipher ───────────────────────────────
    print_section("3. SUBSTITUTION PAIRS AS MINI CIPHER ON K4")
    print(f"  Pairs: {SUBST_PAIRS}")
    print(f"  (S->C, L->Q, O->U, E->A, I->E)")

    # 3a. Apply forward substitution to CT
    ct_fwd = ''.join(SUBST_PAIRS.get(c, c) for c in CT)
    print(f"\n  [3a] Forward substitution (right->wrong) on CT:")
    print(f"    Original: {CT}")
    print(f"    Modified: {ct_fwd}")
    changed = sum(1 for a, b in zip(CT, ct_fwd) if a != b)
    print(f"    Changed {changed} characters")
    sc = score_cribs(ct_fwd)
    print(f"    Crib score: {sc}/24")
    test_decrypt(ct_fwd, "subst_fwd", best_results)

    # 3b. Apply reverse substitution (wrong->right) to CT
    rev_subst = {v: k for k, v in SUBST_PAIRS.items()}
    ct_rev = ''.join(rev_subst.get(c, c) for c in CT)
    print(f"\n  [3b] Reverse substitution (wrong->right) on CT:")
    print(f"    Modified: {ct_rev}")
    changed = sum(1 for a, b in zip(CT, ct_rev) if a != b)
    print(f"    Changed {changed} characters")
    sc = score_cribs(ct_rev)
    print(f"    Crib score: {sc}/24")
    test_decrypt(ct_rev, "subst_rev", best_results)

    # 3c. Apply substitution to grille extract
    print(f"\n  [3c] Apply substitution pairs to grille extract:")
    ge_fwd = ''.join(SUBST_PAIRS.get(c, c) for c in GRILLE_EXTRACT)
    ge_rev = ''.join(rev_subst.get(c, c) for c in GRILLE_EXTRACT)
    print(f"    Original: {GRILLE_EXTRACT}")
    print(f"    Fwd(R->W): {ge_fwd}")
    print(f"    Rev(W->R): {ge_rev}")

    # Check if T appears after substitution (I->E could affect things)
    for label, text in [("Original", GRILLE_EXTRACT), ("Fwd", ge_fwd), ("Rev", ge_rev)]:
        t_count = text.count('T')
        print(f"    {label} T count: {t_count}")

    # ─── 4. Misspelled word positions within sections ───────────────────────
    print_section("4. MISSPELLED WORD POSITIONS WITHIN K-SECTIONS")

    # K1 plaintext (approximate, from known decryption)
    k1_pt = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUABOROFIQLUSION"
    # K2 plaintext
    k2_pt = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESTHELANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWWTHISITWASHISTLASTMESSAGEXTHIRTEEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTIDBYROWS"
    k3_pt = "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEATINYBREACHINTHREUPPLERLEFTHANDCORNERANDTHENWIDHENEDTHEHOLEALITTLEINSERTEDACANDLEANDPEEREDINTHEPOTAIRLEEPABONFROMTHECHAMBERCANSINGTHECANDLETOFLICKERBUTPRESENTLYDETAILSOFTHEROOMWITHINEWMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ"

    # Find positions of misspelled words
    misspelled_word_data = [
        ("IQLUSION", k1_pt, "K1"),
        ("UNDERGRUUND", k2_pt, "K2"),
        ("DESPARATLY", k3_pt, "K3"),
    ]

    word_positions = []
    for word, section_pt, section_label in misspelled_word_data:
        idx = section_pt.upper().find(word)
        if idx >= 0:
            print(f"  {word} in {section_label}: position {idx} (0-indexed)")
            word_positions.append(idx)
        else:
            print(f"  {word} NOT FOUND in {section_label} plaintext")
            # Try case-insensitive
            idx2 = section_pt.upper().find(word.upper())
            if idx2 >= 0:
                print(f"    Found (case-insensitive) at position {idx2}")
                word_positions.append(idx2)

    print(f"\n  Word positions: {word_positions}")

    # Map these positions onto K4 (mod 97)
    print(f"\n  [4a] Word positions mapped to K4 (mod 97):")
    for pos in word_positions:
        k4_pos = pos % CT_LEN
        print(f"    {pos} mod {CT_LEN} = {k4_pos} -> CT[{k4_pos}] = {CT[k4_pos]}")

    # Use word positions as a multi-step reading order
    if len(word_positions) >= 2:
        print(f"\n  [4b] Using word positions as stride values:")
        for start in range(min(5, CT_LEN)):
            result = []
            pos = start
            used = set()
            stride_idx = 0
            for _ in range(CT_LEN):
                if pos not in used and 0 <= pos < CT_LEN:
                    result.append(CT[pos])
                    used.add(pos)
                stride = word_positions[stride_idx % len(word_positions)]
                if stride == 0:
                    stride = 1
                pos = (pos + stride) % CT_LEN
                stride_idx += 1
                attempts = 0
                while pos in used and attempts < CT_LEN:
                    pos = (pos + 1) % CT_LEN
                    attempts += 1
            text = ''.join(result)
            sc = score_cribs(text)
            if sc > 0:
                print(f"      Start {start}: score={sc}/24")
            test_decrypt(text, f"wordpos_stride_s{start}", best_results)

    # ─── 5. X=23, E=4 as offsets or step sizes ─────────────────────────────
    print_section("5. X=23, E=4 AS OFFSETS AND STEP SIZES")
    print(f"  Omitted X: value {OMITTED_X} (A=0)")
    print(f"  Omitted E: value {OMITTED_E} (A=0)")

    # 5a. Step sizes
    for step in [OMITTED_X, OMITTED_E, OMITTED_X + OMITTED_E,
                 OMITTED_X * OMITTED_E]:
        if step == 0 or step >= CT_LEN:
            step = step % CT_LEN
            if step == 0:
                continue
        # Read every step-th character starting from 0
        result = []
        pos = 0
        used = set()
        for _ in range(CT_LEN):
            if pos in used:
                pos = (pos + 1) % CT_LEN
                while pos in used:
                    pos = (pos + 1) % CT_LEN
            result.append(CT[pos])
            used.add(pos)
            pos = (pos + step) % CT_LEN
        text = ''.join(result)
        sc = score_cribs(text)
        print(f"  Step {step}: score={sc}/24")
        test_decrypt(text, f"step_xe_{step}", best_results)

    # 5b. X=23 as grid width, E=4 as rotation
    print(f"\n  [5b] Width=23, rotation=4:")
    unscrambled = columnar_write(CT, 23)
    rotated = unscrambled[4:] + unscrambled[:4]
    sc = score_cribs(rotated)
    print(f"    Columnar w=23 + rotate 4: score={sc}/24")
    test_decrypt(rotated, "xe_col23_rot4", best_results)

    # 5c. Width=4, rotation=23
    unscrambled = columnar_write(CT, 4)
    rotated = unscrambled[23:] + unscrambled[:23]
    sc = score_cribs(rotated)
    print(f"    Columnar w=4 + rotate 23: score={sc}/24")
    test_decrypt(rotated, "xe_col4_rot23", best_results)

    # 5d. Combined XE as two-stage: first step 23, then step 4
    print(f"\n  [5d] Two-stage reading: step 23 then step 4:")
    stage1 = []
    pos = 0
    used = set()
    for _ in range(CT_LEN):
        while pos in used:
            pos = (pos + 1) % CT_LEN
        stage1.append(CT[pos])
        used.add(pos)
        pos = (pos + 23) % CT_LEN
    text1 = ''.join(stage1)

    stage2 = []
    pos = 0
    used2 = set()
    for _ in range(CT_LEN):
        while pos in used2:
            pos = (pos + 1) % CT_LEN
        stage2.append(text1[pos])
        used2.add(pos)
        pos = (pos + 4) % CT_LEN
    text2 = ''.join(stage2)
    sc = score_cribs(text2)
    print(f"    Stage1(step23) -> Stage2(step4): score={sc}/24")
    test_decrypt(text2, "xe_twostage_23_4", best_results)

    # ─── 6. Combined approaches ────────────────────────────────────────────
    print_section("6. COMBINED APPROACHES")

    # 6a. All 6 error positions as columnar key for grille extract
    print(f"\n  [6a] Error positions as key for grille extract:")
    ge = GRILLE_EXTRACT[:97]  # Truncate to 97 if needed (it's 106)
    # Use key_order from section 1b
    unscr = keyed_columnar_decipher(ge, key_order)
    print(f"    Grille extract (first 97): {ge}")
    print(f"    Decipher with key {key_order}: {unscr}")

    # 6b. Error positions modular indexing into grille extract as permutation
    print(f"\n  [6b] Error positions as modular index into grille extract:")
    # Generate a permutation from the grille extract using error positions
    perm = []
    for i in range(CT_LEN):
        ep = ERROR_POSITIONS[i % len(ERROR_POSITIONS)]
        ge_idx = (i * ep) % len(GRILLE_EXTRACT)
        ge_val = ALPH_IDX.get(GRILLE_EXTRACT[ge_idx], 0)
        perm_val = (ge_val + i) % CT_LEN
        perm.append(perm_val)

    # Make it a valid permutation by resolving collisions
    used = set()
    valid_perm = []
    for p in perm:
        while p in used:
            p = (p + 1) % CT_LEN
        valid_perm.append(p)
        used.add(p)
    unscr = apply_permutation(CT, valid_perm)
    sc = score_cribs(unscr)
    print(f"    Modular index permutation: score={sc}/24")
    test_decrypt(unscr, "errpos_mod_ge_perm", best_results)

    # 6c. EQUAL as Vigenere key on grille extract, then use result as permutation
    print(f"\n  [6c] EQUAL as key on grille extract -> numeric permutation:")
    ge_decrypted_vig = vig_decrypt(GRILLE_EXTRACT, "EQUAL")
    ge_decrypted_beau = beaufort_decrypt(GRILLE_EXTRACT, "EQUAL")
    for label, ge_dec in [("Vig", ge_decrypted_vig), ("Beau", ge_decrypted_beau)]:
        # Use first 97 chars, convert to numeric values, make permutation
        vals = [ALPH_IDX[c] for c in ge_dec[:97]]
        # Rank to create permutation
        indexed = [(v, i) for i, v in enumerate(vals)]
        ranked = sorted(range(97), key=lambda i: indexed[i])
        unscr = apply_permutation(CT, ranked)
        sc = score_cribs(unscr)
        print(f"    {label}/EQUAL -> rank perm: score={sc}/24")
        test_decrypt(unscr, f"equal_ge_{label}_perm", best_results)

    # 6d. Difference between right and wrong letter values as key
    print(f"\n  [6d] Differences (right-wrong) as cyclic key:")
    diffs_a0 = [(ALPH_IDX[r] - ALPH_IDX[w]) % 26 for r, w in zip(RIGHT_LETTERS, WRONG_LETTERS)]
    diffs_ka = [(ka_idx[r] - ka_idx[w]) % 26 for r, w in zip(RIGHT_LETTERS, WRONG_LETTERS)]
    print(f"    A=0 diffs: {diffs_a0}")
    print(f"    KA diffs:  {diffs_ka}")

    # Apply as Vig key (using numeric values)
    for label, diffs in [("A=0", diffs_a0), ("KA", diffs_ka)]:
        pt = []
        for i, c in enumerate(CT):
            ci = ALPH_IDX[c]
            ki = diffs[i % len(diffs)]
            pi = (ci - ki) % 26
            pt.append(ALPH[pi])
        pt_text = ''.join(pt)
        sc = score_cribs(pt_text)
        words = score_english_words(pt_text)
        print(f"    Vig with {label} diffs: score={sc}/24, words={words}")
        if sc > 2 or words:
            print(f"      PT: {pt_text}")
            best_results.append((sc, "diffs", "Vig", label, "", pt_text))

    # 6e. Substitution pairs applied BEFORE Vig/Beau decryption
    print(f"\n  [6e] Substitution pairs applied before standard decryption:")
    for subst_dir, subst_label, subst_map in [
        ("fwd", "S->C", SUBST_PAIRS),
        ("rev", "C->S", rev_subst)
    ]:
        modified_ct = ''.join(subst_map.get(c, c) for c in CT)
        for key in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            for method, func in [("Vig", vig_decrypt), ("Beau", beaufort_decrypt)]:
                for alph_label, alph in [("AZ", ALPH), ("KA", KRYPTOS_ALPHABET)]:
                    pt = func(modified_ct, key, alph)
                    sc = score_cribs(pt)
                    words = score_english_words(pt)
                    if sc > 2 or len(words) > 0:
                        desc = f"{subst_label}+{method}/{key}/{alph_label}"
                        print(f"    {desc}: score={sc}/24, words={words}")
                        print(f"      PT: {pt}")
                        best_results.append((sc, subst_label, method, key, alph_label, pt))

    # 6f. Error positions as positions within K4 to swap/rearrange
    print(f"\n  [6f] Error positions as K4 swap targets:")
    # Map error positions mod 97
    err_mod = [ep % CT_LEN for ep in ERROR_POSITIONS]
    print(f"    Error positions mod 97: {err_mod}")
    print(f"    Characters at those positions: {[CT[p] for p in err_mod]}")
    # These characters might be special - check if they match crib positions
    for p in err_mod:
        if p in CRIB_DICT:
            print(f"    ** Position {p} is a crib position: expected '{CRIB_DICT[p]}'")

    # 6g. EQUAL values as offsets into grille extract to select permutation seed
    print(f"\n  [6g] EQUAL as grille extract read offsets:")
    for label, values in [("A=0", equal_a0), ("KA", equal_ka)]:
        # Use EQUAL values to select starting points in grille extract
        selected = []
        for i, v in enumerate(values):
            idx = v % len(GRILLE_EXTRACT)
            selected.append(GRILLE_EXTRACT[idx])
        print(f"    {label} selects: {''.join(selected)} from grille extract")

    # 6h. Double transposition: error positions then EQUAL values
    print(f"\n  [6h] Double columnar: width from error positions, key from EQUAL:")
    for w in set(ERROR_POSITIONS):
        if w < 2:
            continue
        stage1 = columnar_write(CT, w)
        for label, values in [("A=0", equal_a0), ("KA", equal_ka)]:
            # Use first min(w, len(values)) values as key
            key_len = min(w, len(values))
            key = list(range(key_len))
            key_vals = values[:key_len]
            ranked_key = sorted(range(key_len), key=lambda i: key_vals[i])
            stage2 = keyed_columnar_decipher(stage1, ranked_key)
            sc = score_cribs(stage2)
            if sc > 0:
                print(f"    w={w}, EQUAL({label}) key={ranked_key}: score={sc}/24")
            test_decrypt(stage2, f"dbl_col_w{w}_{label}", best_results)

    # ─── 7. EQUAL permutations ──────────────────────────────────────────────
    print_section("7. ALL PERMUTATIONS OF 'EQUAL' AS KEYS")
    print(f"  Testing all 5! = 120 permutations of EQUAL as Vig/Beau keys")

    max_sc = 0
    for perm_letters in itertools.permutations("EQUAL"):
        key = ''.join(perm_letters)
        for method, func in [("Vig", vig_decrypt), ("Beau", beaufort_decrypt)]:
            for alph_label, alph in [("AZ", ALPH), ("KA", KRYPTOS_ALPHABET)]:
                pt = func(CT, key, alph)
                sc = score_cribs(pt)
                if sc > max_sc:
                    max_sc = sc
                    print(f"    New best: {method}/{key}/{alph_label}: score={sc}/24")
                    if sc > 2:
                        print(f"      PT: {pt}")
                        best_results.append((sc, "perm", method, key, alph_label, pt))
    print(f"  Best score across all EQUAL permutations: {max_sc}/24")

    # ─── 8. Error positions applied to grille geometry ──────────────────────
    print_section("8. ERROR POSITIONS AS GRILLE GEOMETRY PARAMETERS")

    # 8a. Use error positions to select rows/columns from the tableau,
    # then read those cells on the cipher panel
    print(f"\n  [8a] Error positions select tableau rows -> read cipher panel:")
    for row_idx in ERROR_POSITIONS:
        if 0 <= row_idx < len(TABLEAU):
            tab_row = TABLEAU[row_idx]
            cp_row = CIPHER_PANEL[row_idx] if row_idx < len(CIPHER_PANEL) else ""
            print(f"    Row {row_idx}: tab='{tab_row}', cp='{cp_row}'")

    # 8b. Positions as (row, col) pairs from error position tuples
    print(f"\n  [8b] Error positions as (row,col) pairs on cipher panel:")
    pairs = [(ERROR_POSITIONS[i], ERROR_POSITIONS[i + 1])
             for i in range(0, len(ERROR_POSITIONS) - 1, 2)]
    print(f"    Pairs: {pairs}")
    for r, c in pairs:
        if 0 <= r < len(CIPHER_PANEL) and 0 <= c < len(CIPHER_PANEL[r]):
            print(f"    CP[{r}][{c}] = {CIPHER_PANEL[r][c]}")
        if 0 <= r < len(TABLEAU) and 0 <= c < len(TABLEAU[r]):
            print(f"    TAB[{r}][{c}] = {TABLEAU[r][c]}")

    # 8c. Product of all error positions
    product = 1
    for ep in ERROR_POSITIONS:
        product *= ep
    print(f"\n  [8c] Product of error positions: {product}")
    print(f"    mod 97 = {product % 97}")
    print(f"    Sum of error positions: {sum(ERROR_POSITIONS)} (mod 97 = {sum(ERROR_POSITIONS) % 97})")

    # Use product mod 97 as rotation
    rot = product % CT_LEN
    rotated = CT[rot:] + CT[:rot]
    sc = score_cribs(rotated)
    print(f"    Rotate CT by {rot}: score={sc}/24")
    test_decrypt(rotated, f"product_rot_{rot}", best_results)

    # Use sum as rotation
    rot = sum(ERROR_POSITIONS) % CT_LEN
    rotated = CT[rot:] + CT[:rot]
    sc = score_cribs(rotated)
    print(f"    Rotate CT by {rot} (sum): score={sc}/24")
    test_decrypt(rotated, f"sum_rot_{rot}", best_results)

    # ─── FINAL SUMMARY ─────────────────────────────────────────────────────
    print_section("FINAL SUMMARY")

    if best_results:
        best_results.sort(key=lambda x: -x[0])
        print(f"\n  Top results (score > 0):")
        seen = set()
        for entry in best_results[:20]:
            sc = entry[0]
            desc = f"{entry[1]}/{entry[2]}/{entry[3]}/{entry[4]}"
            if desc not in seen:
                seen.add(desc)
                print(f"    Score {sc}/24: {desc}")
                if len(entry) > 5:
                    print(f"      PT: {entry[5][:60]}...")
    else:
        print(f"\n  No results scored above 2/24 with any tested method.")

    print(f"\n  Total configurations tested: ~{len(best_results)} recorded results")
    print(f"\n  CONCLUSION: Error positions {ERROR_POSITIONS}")
    print(f"  EQUAL letters: {WRONG_LETTERS}")
    print(f"  Substitution pairs: {SUBST_PAIRS}")
    print(f"  Omitted X={OMITTED_X}, E={OMITTED_E}")
    print(f"\n  [End of E-GRILLE-18]")


if __name__ == "__main__":
    main()
