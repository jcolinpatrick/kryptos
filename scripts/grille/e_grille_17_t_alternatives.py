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
E-GRILLE-17: Alternative T-based grille constructions

HYPOTHESIS: "T IS YOUR POSITION" has meanings beyond marking T-positions
on the cipher panel as grille holes. This script tests 7 alternative
interpretations of T as a grille construction parameter.

Tested variants:
  1. T on TABLEAU defines grille → overlay on cipher panel (34 T's, IC=0.0624 noted)
  2. Inverse T mask (T=opaque, not T=hole)
  3. T positions as columnar transposition key
  4. T=starting position (position 19 in alphabet → start reading at index 19)
  5. T-count per row as grille parameter
  6. T positions in K4 rows only → permutation for 97 chars
  7. Both panels: where BOTH have T at same position = hole
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from collections import Counter

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, KRYPTOS_ALPHABET, CRIB_WORDS, N_CRIBS,
)

# ─── Panel data (from e_grille_15_t_is_your_position.py) ─────────────────────
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
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",        # Row 24 (K3->K4 boundary)
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",         # Row 25
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",         # Row 26
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",        # Row 27
]

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

# K4 is rows 24-27 on cipher panel
K4_ROWS = [24, 25, 26, 27]

# ─── HELPER FUNCTIONS ───────────────────────────────────────────────────────

def find_letter_positions(grid, letter):
    """Find all (row, col) positions of a letter in a grid."""
    positions = []
    for r, row in enumerate(grid):
        for c, ch in enumerate(row):
            if ch == letter:
                positions.append((r, c))
    return positions


def rotate_180(positions, num_rows, num_cols):
    """Rotate positions 180 degrees around center of grid."""
    return [(num_rows - 1 - r, num_cols - 1 - c) for r, c in positions]


def read_through_holes(grid, positions):
    """Read characters from grid at given positions (row-major sorted). Skip OOB."""
    chars = []
    oob = 0
    for r, c in positions:
        if 0 <= r < len(grid) and 0 <= c < len(grid[r]):
            chars.append(grid[r][c])
        else:
            oob += 1
    return ''.join(chars), oob


def ic(text):
    """Index of coincidence."""
    freq = Counter(text)
    n = len(text)
    if n < 2:
        return 0.0
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


def vig_decrypt(ct_text, key, alph=ALPH):
    """Vigenere: PT = (CT - KEY) mod N"""
    n = len(alph)
    return ''.join(alph[(alph.index(c) - alph.index(key[i % len(key)])) % n]
                   for i, c in enumerate(ct_text) if c in alph)


def beaufort_decrypt(ct_text, key, alph=ALPH):
    """Beaufort: PT = (KEY - CT) mod N"""
    n = len(alph)
    return ''.join(alph[(alph.index(key[i % len(key)]) - alph.index(c)) % n]
                   for i, c in enumerate(ct_text) if c in alph)


def check_cribs(text, label=""):
    """Check for crib words and fragments. Return number of hits."""
    cribs = ["EASTNORTHEAST", "BERLINCLOCK", "EASTNORTH", "NORTHEAST",
             "EAST", "NORTH", "BERLIN", "CLOCK", "THE", "THAT", "TION"]
    hits = []
    for crib in cribs:
        for i in range(len(text) - len(crib) + 1):
            if text[i:i+len(crib)] == crib:
                hits.append((crib, i))
    return hits


def score_crib_positions(pt):
    """Score how many of the 24 crib positions match (if text is 97 chars)."""
    if len(pt) < CT_LEN:
        return 0
    score = 0
    for pos, word in CRIB_WORDS:
        for i, ch in enumerate(word):
            if pos + i < len(pt) and pt[pos + i] == ch:
                score += 1
    return score


def try_all_decryptions(candidate_ct, label, max_print=5):
    """Try Vig/Beaufort with standard keywords on AZ and KA. Report best."""
    keywords = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK",
                "EASTNORTHEAST", "EQUINOX", "SHADOW", "LIGHT", "POSITION"]
    keywords += [chr(c) for c in range(ord('A'), ord('Z') + 1)]
    alphabets = [("AZ", ALPH), ("KA", KRYPTOS_ALPHABET)]
    methods = [("Vig", vig_decrypt), ("Beau", beaufort_decrypt)]

    results = []
    for key in keywords:
        for alph_label, alph in alphabets:
            for method_label, method in methods:
                pt = method(candidate_ct, key, alph)
                # Check for crib fragments anywhere
                crib_hits = check_cribs(pt)
                # Check positional crib score if 97 chars
                pos_score = score_crib_positions(pt) if len(pt) == CT_LEN else 0
                ic_val = ic(pt) if len(pt) > 1 else 0.0
                results.append((len(crib_hits), pos_score, ic_val,
                                method_label, key, alph_label, pt, crib_hits))

    # Sort by: crib hits desc, pos_score desc, IC desc
    results.sort(key=lambda x: (-x[0], -x[1], -x[2]))

    printed = 0
    for n_hits, pos_score, ic_val, meth, key, al, pt, hits in results:
        if n_hits > 0 or pos_score > 0:
            print(f"    {meth}/{key}/{al}: pos_score={pos_score}/{N_CRIBS}, "
                  f"IC={ic_val:.4f}, crib_hits={hits}")
            print(f"      PT: {pt[:80]}...")
            printed += 1
            if printed >= max_print:
                break

    # Always show top by IC
    top_ic = sorted(results, key=lambda x: -x[2])[:3]
    if printed == 0:
        print(f"    No crib hits found. Top by IC:")
        for _, pos_score, ic_val, meth, key, al, pt, _ in top_ic:
            print(f"      {meth}/{key}/{al}: IC={ic_val:.4f}, pos_score={pos_score}")

    return results


# ─── VARIANT 1: T on TABLEAU defines grille → read cipher panel ──────────────

def variant_1_tableau_t_grille():
    """T positions on TABLEAU form the grille mask; overlay on cipher panel."""
    print("\n" + "=" * 70)
    print("  VARIANT 1: T on TABLEAU defines grille -> overlay on cipher panel")
    print("=" * 70)

    t_positions = find_letter_positions(TABLEAU, 'T')
    print(f"  T positions on tableau: {len(t_positions)}")

    # Sort row-major
    t_sorted = sorted(t_positions, key=lambda p: (p[0], p[1]))

    # Read cipher panel through these holes
    text, oob = read_through_holes(CIPHER_PANEL, t_sorted)
    alpha = ''.join(c for c in text if c.isalpha())
    print(f"  Read from cipher panel: {len(text)} chars ({oob} OOB)")
    print(f"  Alpha chars: {len(alpha)}")
    print(f"  Text: {alpha}")
    print(f"  IC: {ic(alpha):.4f}")
    missing = set(ALPH) - set(alpha)
    if missing:
        print(f"  Missing letters: {sorted(missing)}")
    hits = check_cribs(alpha)
    if hits:
        print(f"  *** CRIB HITS: {hits} ***")

    # Try decryptions
    print(f"\n  Decryption attempts on {len(alpha)}-char extract:")
    try_all_decryptions(alpha, "V1-original")

    # 180 degree rotation
    num_rows_tab = len(TABLEAU)
    max_cols_tab = max(len(r) for r in TABLEAU)
    t_rot = rotate_180(t_positions, num_rows_tab, max_cols_tab)
    t_rot_valid = [(r, c) for r, c in t_rot
                   if 0 <= r < len(CIPHER_PANEL) and 0 <= c < len(CIPHER_PANEL[r])]
    t_rot_sorted = sorted(t_rot_valid, key=lambda p: (p[0], p[1]))

    text_rot, oob_rot = read_through_holes(CIPHER_PANEL, t_rot_sorted)
    alpha_rot = ''.join(c for c in text_rot if c.isalpha())
    print(f"\n  180-degree rotated T-holes on cipher panel: {len(alpha_rot)} chars ({oob_rot} OOB)")
    print(f"  Text: {alpha_rot}")
    print(f"  IC: {ic(alpha_rot):.4f}")
    hits_rot = check_cribs(alpha_rot)
    if hits_rot:
        print(f"  *** CRIB HITS: {hits_rot} ***")

    # Combined (pass1 + pass2)
    combined = alpha + alpha_rot
    print(f"\n  Combined (pass1+pass2): {len(combined)} chars")
    print(f"  IC: {ic(combined):.4f}")

    # If combined has enough chars, try as K4 candidate
    if len(combined) >= CT_LEN:
        print(f"  Combined has >= 97 chars; trying first 97 as candidate CT:")
        try_all_decryptions(combined[:CT_LEN], "V1-combined-97")

    return alpha, alpha_rot


# ─── VARIANT 2: Inverse T mask (T=opaque, not-T=hole) ────────────────────────

def variant_2_inverse_t():
    """Inverse mask: everything that is NOT T on cipher panel = hole."""
    print("\n" + "=" * 70)
    print("  VARIANT 2: Inverse T mask (T=opaque, not-T=hole)")
    print("=" * 70)

    # All non-T positions on cipher panel
    not_t_positions = []
    for r, row in enumerate(CIPHER_PANEL):
        for c, ch in enumerate(row):
            if ch != 'T' and ch.isalpha():
                not_t_positions.append((r, c))

    t_count = sum(1 for r in CIPHER_PANEL for c in r if c == 'T')
    print(f"  Cipher panel T positions (opaque): {t_count}")
    print(f"  Non-T positions (holes): {len(not_t_positions)}")

    # Read tableau through non-T holes
    not_t_sorted = sorted(not_t_positions, key=lambda p: (p[0], p[1]))
    text, oob = read_through_holes(TABLEAU, not_t_sorted)
    alpha = ''.join(c for c in text if c.isalpha())
    print(f"  Read from tableau: {len(alpha)} chars ({oob} OOB)")
    print(f"  IC: {ic(alpha):.4f}")
    missing = set(ALPH) - set(alpha)
    if missing:
        print(f"  Missing letters: {sorted(missing)}")
    else:
        print(f"  All 26 letters present")
    hits = check_cribs(alpha)
    if hits:
        print(f"  *** CRIB HITS: {hits} ***")

    # Also: inverse on tableau (non-T on tableau → read cipher panel)
    not_t_tab = []
    for r, row in enumerate(TABLEAU):
        for c, ch in enumerate(row):
            if ch != 'T' and ch.isalpha():
                not_t_tab.append((r, c))

    not_t_tab_sorted = sorted(not_t_tab, key=lambda p: (p[0], p[1]))
    text2, oob2 = read_through_holes(CIPHER_PANEL, not_t_tab_sorted)
    alpha2 = ''.join(c for c in text2 if c.isalpha())
    print(f"\n  Non-T on TABLEAU → read cipher panel: {len(alpha2)} chars ({oob2} OOB)")
    print(f"  IC: {ic(alpha2):.4f}")
    hits2 = check_cribs(alpha2)
    if hits2:
        print(f"  *** CRIB HITS: {hits2} ***")

    return alpha, alpha2


# ─── VARIANT 3: T positions as columnar transposition key ─────────────────────

def variant_3_columnar_key():
    """Use T positions to define a columnar transposition key for K4."""
    print("\n" + "=" * 70)
    print("  VARIANT 3: T positions as columnar transposition key")
    print("=" * 70)

    # T column positions on cipher panel
    t_cols_cp = [c for r, row in enumerate(CIPHER_PANEL) for c, ch in enumerate(row) if ch == 'T']
    print(f"  T column positions (cipher panel): {t_cols_cp}")
    print(f"  Count: {len(t_cols_cp)}")

    # T row positions on cipher panel
    t_rows_cp = [r for r, row in enumerate(CIPHER_PANEL) for c, ch in enumerate(row) if ch == 'T']
    print(f"  T row positions (cipher panel): {t_rows_cp}")

    # T column positions on tableau
    t_cols_tab = [c for r, row in enumerate(TABLEAU) for c, ch in enumerate(row) if ch == 'T']
    print(f"  T column positions (tableau): {t_cols_tab}")
    print(f"  Count: {len(t_cols_tab)}")

    # Try using T column positions as key for columnar transposition of K4
    # Method: write K4 into rows of width W, read columns in order specified by key
    def columnar_decipher(text, key_order):
        """Decipher columnar transposition given column read order."""
        n = len(text)
        ncols = len(key_order)
        nrows = (n + ncols - 1) // ncols
        extra = n % ncols if n % ncols != 0 else ncols

        # Determine column lengths
        col_lengths = []
        for col_idx in range(ncols):
            if col_idx < extra or extra == ncols:
                col_lengths.append(nrows)
            else:
                col_lengths.append(nrows - 1)

        # Read columns in key order
        columns = {}
        pos = 0
        for rank in range(ncols):
            # Find which column has this rank in key_order
            col = key_order.index(rank)
            clen = col_lengths[col]
            columns[col] = text[pos:pos+clen]
            pos += clen

        # Read row-by-row
        result = []
        for row in range(nrows):
            for col in range(ncols):
                if row < len(columns.get(col, '')):
                    result.append(columns[col][row])
        return ''.join(result)

    # Method A: Use unique T column positions as key
    # Make a key from unique T column positions, ranked
    unique_t_cols = sorted(set(t_cols_cp))
    if len(unique_t_cols) > 1:
        # Try different widths based on number of unique T columns
        for width in [len(unique_t_cols), 7, 8, 10, 13]:
            if width > CT_LEN or width < 2:
                continue
            # Simple: use first `width` T column positions, rank them
            key_source = t_cols_cp[:width]
            # Rank: assign order based on value
            ranked = sorted(range(len(key_source)), key=lambda i: (key_source[i], i))
            key_order = [0] * len(key_source)
            for rank, idx in enumerate(ranked):
                key_order[idx] = rank

            pt = columnar_decipher(CT, key_order)
            pos_score = score_crib_positions(pt)
            hits = check_cribs(pt)
            ic_val = ic(pt)
            print(f"  Width {width} (CP T-cols): score={pos_score}/{N_CRIBS}, IC={ic_val:.4f}, "
                  f"hits={len(hits)}")
            if pos_score > 0 or hits:
                print(f"    PT: {pt}")
                print(f"    Hits: {hits}")

    # Method B: T columns from tableau as key
    unique_t_cols_tab = sorted(set(t_cols_tab))
    for width in [len(unique_t_cols_tab), 7, 8, 10, 13]:
        if width > CT_LEN or width < 2:
            continue
        key_source = t_cols_tab[:width]
        ranked = sorted(range(len(key_source)), key=lambda i: (key_source[i], i))
        key_order = [0] * len(key_source)
        for rank, idx in enumerate(ranked):
            key_order[idx] = rank

        pt = columnar_decipher(CT, key_order)
        pos_score = score_crib_positions(pt)
        hits = check_cribs(pt)
        ic_val = ic(pt)
        print(f"  Width {width} (TAB T-cols): score={pos_score}/{N_CRIBS}, IC={ic_val:.4f}, "
              f"hits={len(hits)}")
        if pos_score > 0 or hits:
            print(f"    PT: {pt}")
            print(f"    Hits: {hits}")

    # Method C: T-position row numbers as columnar key
    # Per-row T counts on cipher panel: use as key
    t_per_row = []
    for r, row in enumerate(CIPHER_PANEL):
        t_per_row.append(sum(1 for ch in row if ch == 'T'))
    print(f"\n  T per row (cipher panel): {t_per_row}")

    # Use T-per-row for K4 rows (24-27) as width
    k4_t_counts = [t_per_row[r] for r in K4_ROWS]
    print(f"  K4 rows T counts: {k4_t_counts} (rows {K4_ROWS})")

    return


# ─── VARIANT 4: T = starting position ────────────────────────────────────────

def variant_4_start_position():
    """T = position 19 in standard alphabet (0-indexed). Start reading at offset 19."""
    print("\n" + "=" * 70)
    print("  VARIANT 4: T = starting position (T=19 in AZ, or T=8 in KA)")
    print("=" * 70)

    # T is position 19 in AZ (A=0), position 8 in KA
    t_az = ALPH.index('T')  # 19
    t_ka = KRYPTOS_ALPHABET.index('T')  # position in KA

    print(f"  T in AZ: position {t_az}")
    print(f"  T in KA: position {t_ka}")

    # Method A: Rotate K4 by T positions
    for offset_label, offset in [("AZ(19)", t_az), ("KA({})".format(t_ka), t_ka)]:
        rotated = CT[offset:] + CT[:offset]
        print(f"\n  Rotate K4 by {offset_label}:")
        print(f"    CT rotated: {rotated}")
        pos_score = score_crib_positions(rotated)
        hits = check_cribs(rotated)
        print(f"    Direct crib check: score={pos_score}, hits={hits}")

        # Try decryptions on rotated CT
        for key in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            for al_label, al in [("AZ", ALPH), ("KA", KRYPTOS_ALPHABET)]:
                pt_v = vig_decrypt(rotated, key, al)
                pt_b = beaufort_decrypt(rotated, key, al)
                for ml, pt in [("Vig", pt_v), ("Beau", pt_b)]:
                    ch = check_cribs(pt)
                    ps = score_crib_positions(pt)
                    if ch or ps > 0:
                        print(f"    {ml}/{key}/{al_label}: score={ps}, hits={ch}")
                        print(f"      PT: {pt}")

    # Method B: Read every 19th character (decimation by T)
    for step in [t_az, t_ka]:
        decimated = ''.join(CT[(step * i) % CT_LEN] for i in range(CT_LEN))
        print(f"\n  Decimation by {step}: {decimated}")
        hits = check_cribs(decimated)
        pos_score = score_crib_positions(decimated)
        print(f"    Score: {pos_score}, hits: {hits}")
        ic_val = ic(decimated)
        print(f"    IC: {ic_val:.4f}")

        # Try decryptions
        for key in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            for al_label, al in [("AZ", ALPH), ("KA", KRYPTOS_ALPHABET)]:
                pt_v = vig_decrypt(decimated, key, al)
                pt_b = beaufort_decrypt(decimated, key, al)
                for ml, pt in [("Vig", pt_v), ("Beau", pt_b)]:
                    ch = check_cribs(pt)
                    if ch:
                        print(f"    {ml}/{key}/{al_label}: hits={ch}")

    # Method C: Start reading the grille extract from position 19 (T in AZ)
    # or position 8 (T in KA)
    grille_extract = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
    for offset_label, offset in [("AZ(19)", t_az), ("KA({})".format(t_ka), t_ka)]:
        rotated_extract = grille_extract[offset:] + grille_extract[:offset]
        # Take first 97 chars, convert to permutation
        extract97 = rotated_extract[:CT_LEN]
        # Rank to get permutation
        indexed = [(ord(c) - ord('A'), i) for i, c in enumerate(extract97)]
        ranked = sorted(range(CT_LEN), key=lambda i: indexed[i])
        unscrambled = ''.join(CT[ranked[i]] for i in range(CT_LEN))
        print(f"\n  Grille extract rotated by {offset_label}, first 97 -> rank permutation:")
        print(f"    Unscrambled: {unscrambled}")
        hits = check_cribs(unscrambled)
        pos_score = score_crib_positions(unscrambled)
        print(f"    Score: {pos_score}, hits: {hits}")

    return


# ─── VARIANT 5: T-count per row as grille parameter ─────────────────────────

def variant_5_t_count_per_row():
    """Use T-count per row as a route cipher parameter."""
    print("\n" + "=" * 70)
    print("  VARIANT 5: T-count per row as grille parameter")
    print("=" * 70)

    # T counts per row for both panels
    cp_t_counts = []
    for r, row in enumerate(CIPHER_PANEL):
        cp_t_counts.append(sum(1 for ch in row if ch == 'T'))
    tab_t_counts = []
    for r, row in enumerate(TABLEAU):
        tab_t_counts.append(sum(1 for ch in row if ch == 'T'))

    print(f"  Cipher panel T/row: {cp_t_counts}")
    print(f"  Tableau T/row:      {tab_t_counts}")
    print(f"  CP sum: {sum(cp_t_counts)}, TAB sum: {sum(tab_t_counts)}")

    # K4 rows on cipher panel (rows 24-27)
    k4_t = [cp_t_counts[r] for r in K4_ROWS]
    print(f"  K4 rows (24-27) T counts: {k4_t}, sum={sum(k4_t)}")

    # Method A: T-count as column offset per row
    # Read K4 starting at column = T-count for that K4 row
    print(f"\n  Method A: T-count as column offset for reading K4")
    k4_text = ''.join(CIPHER_PANEL[r] for r in K4_ROWS)
    k4_offsets = []
    result_chars = []
    for idx, r in enumerate(K4_ROWS):
        row = CIPHER_PANEL[r]
        offset = cp_t_counts[r]
        shifted = row[offset:] + row[:offset]
        k4_offsets.append(offset)
        result_chars.append(shifted)
        print(f"    Row {r}: offset={offset}, shifted={shifted}")

    shifted_ct = ''.join(result_chars)
    # Extract K4-length portion
    # K4 starts at row 24, col 28 (after K3). In row 24: "OBKR" is the K4 part
    # Actually K4 is: row24[28:32] + row25[0:31] + row26[0:31] + row27[0:31] = 4+31+31+31=97
    print(f"  Shifted combined: {shifted_ct[:100]}...")

    # Method B: T-count sequence as key for Vig/Beau
    # K4 has 97 chars; use T-counts cycled as key values
    key_from_counts = cp_t_counts  # 28 values
    print(f"\n  Method B: T-counts as Vigenere key values")
    pt_chars = []
    for i, c in enumerate(CT):
        ki = key_from_counts[i % len(key_from_counts)]
        pi = (ALPH.index(c) - ki) % 26
        pt_chars.append(ALPH[pi])
    pt = ''.join(pt_chars)
    print(f"    Vig with T-count key: {pt}")
    print(f"    IC: {ic(pt):.4f}")
    hits = check_cribs(pt)
    pos_score = score_crib_positions(pt)
    print(f"    Score: {pos_score}, hits: {hits}")

    # Beaufort with T-count key
    pt_chars_b = []
    for i, c in enumerate(CT):
        ki = key_from_counts[i % len(key_from_counts)]
        pi = (ki - ALPH.index(c)) % 26
        pt_chars_b.append(ALPH[pi])
    pt_b = ''.join(pt_chars_b)
    print(f"    Beau with T-count key: {pt_b}")
    print(f"    IC: {ic(pt_b):.4f}")
    hits_b = check_cribs(pt_b)
    pos_score_b = score_crib_positions(pt_b)
    print(f"    Score: {pos_score_b}, hits: {hits_b}")

    # Method C: T-count determines route cipher reading order
    # K4 is ~31 chars per row; T-counts per row define column widths or offsets
    print(f"\n  Method C: T-counts as column-width key for K4")
    # Write K4 into columns with widths = T-counts of K4 rows
    # k4_t = [3, 1, 3, 3] for rows 24-27
    # Total T's in K4 rows = 10; not directly useful as column width

    # Use all 28 T-counts as a columnar key of width 28
    # Rank them
    if len(set(cp_t_counts)) > 1:
        ranked_counts = sorted(range(len(cp_t_counts)),
                               key=lambda i: (cp_t_counts[i], i))
        key_order = [0] * len(cp_t_counts)
        for rank, idx in enumerate(ranked_counts):
            key_order[idx] = rank

        # Too wide for 97 chars (28 cols, ~4 rows) - still try
        ncols = len(key_order)
        nrows = (CT_LEN + ncols - 1) // ncols
        # Simple columnar: write row-by-row, read by key column order
        grid = []
        pos = 0
        for row in range(nrows):
            grid_row = []
            for col in range(ncols):
                if pos < CT_LEN:
                    grid_row.append(CT[pos])
                    pos += 1
                else:
                    grid_row.append('')
            grid.append(grid_row)

        result = []
        for rank in range(ncols):
            col = key_order.index(rank)
            for row in range(nrows):
                if grid[row][col]:
                    result.append(grid[row][col])
        pt_col = ''.join(result)
        pos_score_col = score_crib_positions(pt_col)
        hits_col = check_cribs(pt_col)
        print(f"    Columnar (w=28, T-count ranked): score={pos_score_col}, hits={len(hits_col)}")
        if pos_score_col > 0 or hits_col:
            print(f"      PT: {pt_col}")

    return


# ─── VARIANT 6: T positions in K4 rows → permutation ─────────────────────────

def variant_6_k4_t_permutation():
    """T positions within K4 rows on cipher panel define a permutation for 97 chars."""
    print("\n" + "=" * 70)
    print("  VARIANT 6: T positions in K4 rows -> permutation for 97 chars")
    print("=" * 70)

    # K4 is rows 24-27 on cipher panel
    # K4 starts at row 24, and the K4 ciphertext maps to:
    # Row 24: last 4 chars (OBKR), Row 25: 31 chars, Row 26: 31 chars, Row 27: 31 chars
    # Total: 4 + 31 + 31 + 31 = 97

    # Map K4 character index to (row, col) on cipher panel
    k4_mapping = []
    # Row 24: K4 starts at col 28 (after "ECDMRIPFEIMEHNLSSTTRTVDOHW?")
    # The '?' is at position 27, then OBKR at positions 28-31
    row24 = CIPHER_PANEL[24]
    k4_start_col = row24.index('O')  # Find where K4 starts in row 24
    # Actually let's just find "OBKR" in row 24
    obkr_start = row24.find("OBKR")
    if obkr_start >= 0:
        for c in range(obkr_start, obkr_start + 4):
            k4_mapping.append((24, c))
    else:
        # Fallback: last 4 chars
        for c in range(len(row24) - 4, len(row24)):
            k4_mapping.append((24, c))

    for r in [25, 26, 27]:
        for c in range(len(CIPHER_PANEL[r])):
            k4_mapping.append((r, c))

    print(f"  K4 character positions on cipher panel: {len(k4_mapping)}")
    # Verify
    k4_from_panel = ''.join(CIPHER_PANEL[r][c] for r, c in k4_mapping)
    print(f"  Reconstructed K4: {k4_from_panel}")
    print(f"  Matches CT: {k4_from_panel == CT}")

    # Find T positions within K4 on cipher panel
    t_positions_in_k4 = []
    for idx, (r, c) in enumerate(k4_mapping):
        if CIPHER_PANEL[r][c] == 'T':
            t_positions_in_k4.append(idx)

    print(f"  T positions within K4 (0-indexed): {t_positions_in_k4}")
    print(f"  Count: {len(t_positions_in_k4)}")

    # Also: T positions on the TABLEAU at K4-corresponding locations
    t_tab_at_k4 = []
    for idx, (r, c) in enumerate(k4_mapping):
        if 0 <= r < len(TABLEAU) and 0 <= c < len(TABLEAU[r]):
            if TABLEAU[r][c] == 'T':
                t_tab_at_k4.append(idx)

    print(f"  T positions on TABLEAU at K4 locations: {t_tab_at_k4}")
    print(f"  Count: {len(t_tab_at_k4)}")

    # Method A: T positions define the reading order seed
    # Read T positions first, then non-T positions
    non_t = [i for i in range(CT_LEN) if i not in t_positions_in_k4]
    perm_t_first = t_positions_in_k4 + non_t
    unscrambled_a = ''.join(CT[i] for i in perm_t_first)
    print(f"\n  Method A: Read T positions first, then non-T:")
    print(f"    Unscrambled: {unscrambled_a}")
    hits_a = check_cribs(unscrambled_a)
    pos_a = score_crib_positions(unscrambled_a)
    print(f"    Score: {pos_a}, hits: {hits_a}")

    # Try reverse: non-T first
    perm_nont_first = non_t + t_positions_in_k4
    unscrambled_b = ''.join(CT[i] for i in perm_nont_first)
    print(f"\n  Method B: Read non-T positions first, then T:")
    print(f"    Unscrambled: {unscrambled_b}")
    hits_b = check_cribs(unscrambled_b)
    pos_b = score_crib_positions(unscrambled_b)
    print(f"    Score: {pos_b}, hits: {hits_b}")

    # Method C: Interleave T and non-T
    interleaved = []
    ti, ni = 0, 0
    for i in range(CT_LEN):
        if i % 2 == 0 and ti < len(t_positions_in_k4):
            interleaved.append(CT[t_positions_in_k4[ti]])
            ti += 1
        elif ni < len(non_t):
            interleaved.append(CT[non_t[ni]])
            ni += 1
        elif ti < len(t_positions_in_k4):
            interleaved.append(CT[t_positions_in_k4[ti]])
            ti += 1
    unscrambled_c = ''.join(interleaved)
    print(f"\n  Method C: Interleave T/non-T positions:")
    print(f"    Unscrambled: {unscrambled_c}")
    hits_c = check_cribs(unscrambled_c)
    pos_c = score_crib_positions(unscrambled_c)
    print(f"    Score: {pos_c}, hits: {hits_c}")

    # Method D: T positions encode gaps/spacing
    # Number of non-T chars between T's gives segment lengths
    segments = []
    last_t = -1
    for tp in sorted(t_positions_in_k4):
        gap = tp - last_t - 1
        segments.append(gap)
        last_t = tp
    segments.append(CT_LEN - 1 - last_t)
    print(f"\n  Method D: Gaps between T positions: {segments}")
    print(f"    Sum of gaps: {sum(segments)}, expected: {CT_LEN - len(t_positions_in_k4)}")

    # Method E: T-positions in K4 rows as column indices for columnar transposition
    # Use T column positions within each K4 row
    t_cols_per_k4_row = {}
    for idx, (r, c) in enumerate(k4_mapping):
        if CIPHER_PANEL[r][c] == 'T':
            t_cols_per_k4_row.setdefault(r, []).append(c)
    print(f"\n  Method E: T column positions per K4 row:")
    for r in K4_ROWS:
        print(f"    Row {r}: cols {t_cols_per_k4_row.get(r, [])}")

    # Try decryptions on best candidates
    for label, candidate in [("T-first", unscrambled_a), ("nonT-first", unscrambled_b),
                              ("interleaved", unscrambled_c)]:
        best_ic = 0
        best_config = ""
        for key in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            for al_label, al in [("AZ", ALPH), ("KA", KRYPTOS_ALPHABET)]:
                pt_v = vig_decrypt(candidate, key, al)
                pt_b = beaufort_decrypt(candidate, key, al)
                for ml, pt in [("Vig", pt_v), ("Beau", pt_b)]:
                    ch = check_cribs(pt)
                    ps = score_crib_positions(pt)
                    iv = ic(pt)
                    if ch or ps > 0:
                        print(f"    {label}/{ml}/{key}/{al_label}: score={ps}, hits={ch}, IC={iv:.4f}")
                    if iv > best_ic:
                        best_ic = iv
                        best_config = f"{ml}/{key}/{al_label}"
        print(f"    {label} best IC: {best_ic:.4f} ({best_config})")

    return


# ─── VARIANT 7: Both panels — where BOTH have T = hole ──────────────────────

def variant_7_both_panels():
    """Where BOTH cipher panel and tableau have T at the same (row,col) = hole."""
    print("\n" + "=" * 70)
    print("  VARIANT 7: Both panels — where BOTH have T at same position = hole")
    print("=" * 70)

    t_cp = set(find_letter_positions(CIPHER_PANEL, 'T'))
    t_tab = set(find_letter_positions(TABLEAU, 'T'))

    both_t = sorted(t_cp & t_tab, key=lambda p: (p[0], p[1]))
    either_t = sorted(t_cp | t_tab, key=lambda p: (p[0], p[1]))
    cp_only_t = sorted(t_cp - t_tab, key=lambda p: (p[0], p[1]))
    tab_only_t = sorted(t_tab - t_cp, key=lambda p: (p[0], p[1]))
    neither_t = []
    for r in range(min(len(CIPHER_PANEL), len(TABLEAU))):
        for c in range(min(len(CIPHER_PANEL[r]), len(TABLEAU[r]))):
            if (r, c) not in t_cp and (r, c) not in t_tab:
                if CIPHER_PANEL[r][c].isalpha() and TABLEAU[r][c].isalpha():
                    neither_t.append((r, c))

    print(f"  T on cipher panel: {len(t_cp)}")
    print(f"  T on tableau: {len(t_tab)}")
    print(f"  Both T (intersection): {len(both_t)}")
    print(f"  Either T (union): {len(either_t)}")
    print(f"  CP-only T: {len(cp_only_t)}")
    print(f"  TAB-only T: {len(tab_only_t)}")
    print(f"  Neither T: {len(neither_t)}")

    # What positions have T on both?
    print(f"\n  Positions where BOTH panels have T:")
    for r, c in both_t:
        cp_char = CIPHER_PANEL[r][c] if c < len(CIPHER_PANEL[r]) else '?'
        tab_char = TABLEAU[r][c] if c < len(TABLEAU[r]) else '?'
        print(f"    ({r:2d}, {c:2d}): CP={cp_char}, TAB={tab_char}")

    # Read through "both T" holes
    # On cipher panel
    text_cp_both, oob1 = read_through_holes(CIPHER_PANEL, both_t)
    print(f"\n  Read cipher panel through 'both T' holes: '{text_cp_both}' ({len(text_cp_both)} chars)")

    # On tableau
    text_tab_both, oob2 = read_through_holes(TABLEAU, both_t)
    print(f"  Read tableau through 'both T' holes: '{text_tab_both}' ({len(text_tab_both)} chars)")

    # More interesting: use "both T" positions to read the OTHER panel
    # Already done above. Let's also try XOR-like combinations.

    # What about "CP has T, TAB does not" — read the tableau char at those positions
    text_tab_at_cp_only, _ = read_through_holes(TABLEAU, cp_only_t)
    print(f"\n  CP-only-T positions → read tableau: '{text_tab_at_cp_only}' ({len(text_tab_at_cp_only)} chars)")
    ic_val = ic(text_tab_at_cp_only) if len(text_tab_at_cp_only) > 1 else 0
    print(f"  IC: {ic_val:.4f}")
    hits = check_cribs(text_tab_at_cp_only)
    if hits:
        print(f"  *** CRIB HITS: {hits} ***")

    # TAB-only T → read cipher panel
    text_cp_at_tab_only, _ = read_through_holes(CIPHER_PANEL, tab_only_t)
    print(f"\n  TAB-only-T positions → read cipher panel: '{text_cp_at_tab_only}' ({len(text_cp_at_tab_only)} chars)")
    ic_val2 = ic(text_cp_at_tab_only) if len(text_cp_at_tab_only) > 1 else 0
    print(f"  IC: {ic_val2:.4f}")
    hits2 = check_cribs(text_cp_at_tab_only)
    if hits2:
        print(f"  *** CRIB HITS: {hits2} ***")

    # Neither-T positions → this is the "definite opaque" region; what's here?
    text_cp_neither, _ = read_through_holes(CIPHER_PANEL, neither_t)
    text_tab_neither, _ = read_through_holes(TABLEAU, neither_t)
    print(f"\n  Neither-T positions ({len(neither_t)} cells):")
    print(f"    CP chars: {len(text_cp_neither)} chars, IC={ic(text_cp_neither):.4f}")
    print(f"    TAB chars: {len(text_tab_neither)} chars, IC={ic(text_tab_neither):.4f}")

    # Try using "both T" count as a signal
    # XOR interpretation: same letter on both panels = transparent
    xor_positions = []
    for r in range(min(len(CIPHER_PANEL), len(TABLEAU))):
        for c in range(min(len(CIPHER_PANEL[r]), len(TABLEAU[r]))):
            if CIPHER_PANEL[r][c].isalpha() and TABLEAU[r][c].isalpha():
                if CIPHER_PANEL[r][c] == TABLEAU[r][c]:
                    xor_positions.append((r, c))

    xor_sorted = sorted(xor_positions, key=lambda p: (p[0], p[1]))
    text_xor, _ = read_through_holes(CIPHER_PANEL, xor_sorted)
    print(f"\n  XOR (same char on both panels): {len(xor_positions)} positions")
    print(f"  Text: {text_xor}")
    freq_xor = Counter(text_xor)
    print(f"  Freq: {freq_xor.most_common()}")

    # Interesting subset: try decrypting the cp-only and tab-only extracts
    for label, extract in [("cp-only-T->tab", text_tab_at_cp_only),
                           ("tab-only-T->cp", text_cp_at_tab_only)]:
        if len(extract) < 5:
            continue
        print(f"\n  Decryption attempts on '{label}' ({len(extract)} chars):")
        try_all_decryptions(extract, label, max_print=3)

    return


# ─── MAIN ────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("  E-GRILLE-17: Alternative T-based Grille Constructions")
    print("  Testing 7 interpretations of 'T IS YOUR POSITION'")
    print("=" * 70)
    print(f"  K4 CT: {CT}")
    print(f"  K4 length: {CT_LEN}")
    print(f"  Cribs: {CRIB_WORDS}")

    v1_orig, v1_rot = variant_1_tableau_t_grille()
    variant_2_inverse_t()
    variant_3_columnar_key()
    variant_4_start_position()
    variant_5_t_count_per_row()
    variant_6_k4_t_permutation()
    variant_7_both_panels()

    # ─── SUMMARY ──────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("  SUMMARY")
    print("=" * 70)
    print("""
  VARIANT 1 (T on TABLEAU -> read CP): Most promising due to IC=0.0624 signal
  VARIANT 2 (Inverse T mask): Large extracts, mostly noise
  VARIANT 3 (T cols as columnar key): Various widths tested
  VARIANT 4 (T=start position 19): Rotation, decimation, extract offset
  VARIANT 5 (T-count per row as key): Used as Vig/Beau key values
  VARIANT 6 (K4-row T positions -> permutation): T-first, interleaved, gap analysis
  VARIANT 7 (Both panels T overlap): Intersection, XOR, panel-specific extracts

  Any crib hits or high IC values above are flagged with *** markers.
  Look for: score > 0/24, IC > 0.050, or crib fragment matches.
""")


if __name__ == "__main__":
    main()
