#!/usr/bin/env python3
"""
Test substitution methods on columnar-transposition-undone K4 texts.

Width-6 order [3,0,1,2,5,4] and Width-5 order [0,3,1,2,4].

Cipher: Columnar transposition undo + substitution
Family: two_system
Status: active
Keyspace: ~10K configs per text
Last run: 2026-03-11
Best score: TBD
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CRIB_WORDS

# ── Constants ────────────────────────────────────────────────────────────────

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

KEYWORDS = [
    "KRYPTOS", "KOMPASS", "DEFECTOR", "COLOPHON", "ABSCISSA",
    "PARALLAX", "TOPOLOGY", "PEDESTAL", "MONOLITH", "PALIMPSEST",
]

CRIB_FRAGMENTS = ["EASTNORTHEAST", "BERLINCLOCK", "NORTHEAST", "BERLIN", "CLOCK", "NORTH", "EAST"]

# Original crib positions in carved text (0-indexed)
ORIG_CRIB_POS = [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]


# ── Columnar transposition position mapping ──────────────────────────────────

def columnar_undo_positions(length, width, col_order):
    """
    Given a columnar transposition with given width and column read order,
    compute the mapping: undone_pos -> original_pos.

    Columnar transposition ENCRYPTION:
    - Write plaintext into rows of given width
    - Read off columns in col_order

    So UNDO means: given ciphertext written by columns in col_order,
    reconstruct the row-order plaintext.
    """
    nrows = (length + width - 1) // width
    full_cols = length % width  # number of columns with nrows chars
    if full_cols == 0:
        full_cols = width

    # Build the mapping: for each position in the undone text,
    # what position in the original (carved) text did it come from?

    # The original text was read column by column in col_order.
    # Column col_order[c] has nrows chars if col_order[c] < full_cols, else nrows-1.

    # Wait - let me think about this more carefully.
    #
    # ENCRYPTION process (how the carved text was created from intermediate):
    # 1. Write intermediate text row by row into grid of width W
    # 2. Read columns in order col_order to produce carved text
    #
    # UNDO process:
    # Given carved text, reverse the column reading to get intermediate text.
    #
    # So: carved_text was produced by reading columns in col_order.
    # Column c (the c-th column in order) = col_order[c]
    # Column col_order[c] in the grid has nrows chars if col_order[c] < full_cols, else nrows-1

    # Actually, let me reconsider. For 97 chars, width 6:
    # nrows = ceil(97/6) = 17. 17*6 = 102, so 5 short.
    # Actually: 16 full rows of 6 = 96, plus 1 char in last row.
    # So nrows = 17, and only 1 column has 17 chars (column 0), rest have 16.
    # full_cols = 97 - 16*6 = 97 - 96 = 1

    nrows_full = nrows
    nrows_short = nrows - 1

    # Build: for each column in read order, assign positions
    orig_pos = 0
    col_contents = {}  # col_index -> list of original positions
    for c in col_order:
        if c < full_cols:
            n = nrows_full
        else:
            n = nrows_short
        col_contents[c] = list(range(orig_pos, orig_pos + n))
        orig_pos += n

    # Now reconstruct the grid row by row
    # Row r, column c -> the r-th element of col_contents[c]
    undone_to_orig = []
    for r in range(nrows_full):
        for c in range(width):
            if c < full_cols:
                max_r = nrows_full
            else:
                max_r = nrows_short
            if r < max_r:
                undone_to_orig.append(col_contents[c][r])

    return undone_to_orig


def compute_remapped_crib_positions(length, width, col_order, orig_crib_positions):
    """
    Given original crib positions in carved text, compute where they end up
    after columnar undo.

    undone_to_orig[undone_pos] = orig_pos
    So we need: orig_to_undone[orig_pos] = undone_pos
    """
    undone_to_orig = columnar_undo_positions(length, width, col_order)

    # Invert: orig_pos -> undone_pos
    orig_to_undone = {}
    for undone_pos, orig_pos in enumerate(undone_to_orig):
        orig_to_undone[orig_pos] = undone_pos

    remapped = []
    for start, word in orig_crib_positions:
        new_positions = []
        for i, ch in enumerate(word):
            orig_p = start + i
            if orig_p in orig_to_undone:
                new_positions.append((orig_to_undone[orig_p], ch))
        remapped.append((word, new_positions))

    return remapped


# ── Cipher implementations ──────────────────────────────────────────────────

def char_to_idx(c, alph):
    return alph.index(c)

def idx_to_char(i, alph):
    return alph[i % 26]

def vigenere_decrypt(ct, key, alph):
    """Vigenere decrypt: PT[i] = (CT[i] - KEY[i]) mod 26 in given alphabet"""
    pt = []
    for i, c in enumerate(ct):
        ci = char_to_idx(c, alph)
        ki = char_to_idx(key[i % len(key)], alph)
        pi = (ci - ki) % 26
        pt.append(idx_to_char(pi, alph))
    return ''.join(pt)

def beaufort_decrypt(ct, key, alph):
    """Beaufort: PT[i] = (KEY[i] - CT[i]) mod 26 in given alphabet"""
    pt = []
    for i, c in enumerate(ct):
        ci = char_to_idx(c, alph)
        ki = char_to_idx(key[i % len(key)], alph)
        pi = (ki - ci) % 26
        pt.append(idx_to_char(pi, alph))
    return ''.join(pt)

def variant_beaufort_decrypt(ct, key, alph):
    """Variant Beaufort: PT[i] = (CT[i] + KEY[i]) mod 26 in given alphabet
    (encryption was PT = CT - KEY, so decrypt is CT + KEY... wait)
    Actually VB encrypt: CT = (PT - KEY) mod 26 → PT = (CT + KEY) mod 26"""
    pt = []
    for i, c in enumerate(ct):
        ci = char_to_idx(c, alph)
        ki = char_to_idx(key[i % len(key)], alph)
        pi = (ci + ki) % 26
        pt.append(idx_to_char(pi, alph))
    return ''.join(pt)

def autokey_vig_decrypt(ct, primer, alph):
    """Autokey Vigenère: key = primer + plaintext
    CT[i] = (PT[i] + KEY[i]) mod 26
    PT[i] = (CT[i] - KEY[i]) mod 26
    KEY[i] = primer[i] if i < len(primer) else PT[i - len(primer)]
    """
    pt = []
    key_stream = list(primer)
    for i, c in enumerate(ct):
        ci = char_to_idx(c, alph)
        ki = char_to_idx(key_stream[i], alph)
        pi = (ci - ki) % 26
        p = idx_to_char(pi, alph)
        pt.append(p)
        if i + len(primer) < len(ct):
            key_stream.append(p)
    return ''.join(pt)

def autokey_beau_decrypt(ct, primer, alph):
    """Autokey Beaufort: key = primer + plaintext
    CT[i] = (KEY[i] - PT[i]) mod 26
    PT[i] = (KEY[i] - CT[i]) mod 26
    KEY[i] = primer[i] if i < len(primer) else PT[i - len(primer)]
    """
    pt = []
    key_stream = list(primer)
    for i, c in enumerate(ct):
        ci = char_to_idx(c, alph)
        ki = char_to_idx(key_stream[i], alph)
        pi = (ki - ci) % 26
        p = idx_to_char(pi, alph)
        pt.append(p)
        if i + len(primer) < len(ct):
            key_stream.append(p)
    return ''.join(pt)

def caesar_decrypt(ct, shift, alph):
    """Caesar: PT[i] = (CT[i] - shift) mod 26"""
    return ''.join(idx_to_char((char_to_idx(c, alph) - shift) % 26, alph) for c in ct)

def atbash_decrypt(ct, alph):
    """Atbash: reverse alphabet mapping"""
    return ''.join(alph[25 - alph.index(c)] for c in ct)


# ── Scoring ──────────────────────────────────────────────────────────────────

def count_crib_hits_at_positions(pt, crib_positions):
    """Count how many crib characters match at specified positions.
    crib_positions: list of (position, expected_char)
    """
    hits = 0
    for pos, ch in crib_positions:
        if 0 <= pos < len(pt) and pt[pos] == ch:
            hits += 1
    return hits

def free_crib_search(pt, fragments):
    """Search for crib fragments anywhere in plaintext.
    Returns list of (fragment, position) for each found.
    """
    found = []
    for frag in fragments:
        idx = 0
        while True:
            idx = pt.find(frag, idx)
            if idx == -1:
                break
            found.append((frag, idx))
            idx += 1
    return found


# ── Main test runner ─────────────────────────────────────────────────────────

def run_tests(undone_text, label, width, col_order):
    print(f"\n{'='*80}")
    print(f"TESTING: {label}")
    print(f"Undone text ({len(undone_text)} chars): {undone_text}")
    print(f"Width: {width}, Column order: {col_order}")
    print(f"{'='*80}")

    # Compute position mappings
    remapped_cribs = compute_remapped_crib_positions(len(CT), width, col_order, ORIG_CRIB_POS)

    print(f"\n--- Remapped crib positions after columnar undo ---")
    for word, positions in remapped_cribs:
        pos_list = [(p, ch) for p, ch in positions]
        print(f"  {word}: {pos_list}")

    # Build flat crib position lists
    orig_flat = []
    for start, word in ORIG_CRIB_POS:
        for i, ch in enumerate(word):
            if start + i < len(undone_text):
                orig_flat.append((start + i, ch))

    remapped_flat = []
    for word, positions in remapped_cribs:
        for p, ch in positions:
            if p < len(undone_text):
                remapped_flat.append((p, ch))

    results = []  # (hits, method_desc, pt, hit_type)
    free_results = []  # (method_desc, pt, found_list)

    alphabets = [("AZ", AZ), ("KA", KA)]

    for alph_name, alph in alphabets:
        # 1-3. Vigenere, Beaufort, Variant Beaufort with keywords
        for keyword in KEYWORDS:
            for cipher_name, cipher_fn in [
                ("Vigenere", vigenere_decrypt),
                ("Beaufort", beaufort_decrypt),
                ("VarBeau", variant_beaufort_decrypt),
            ]:
                pt = cipher_fn(undone_text, keyword, alph)
                desc = f"{cipher_name}/{alph_name}/key={keyword}"

                orig_hits = count_crib_hits_at_positions(pt, orig_flat)
                remap_hits = count_crib_hits_at_positions(pt, remapped_flat)

                best_hits = max(orig_hits, remap_hits)
                hit_type = "orig" if orig_hits >= remap_hits else "remap"

                if best_hits >= 2:
                    results.append((best_hits, desc, pt, hit_type, orig_hits, remap_hits))

                found = free_crib_search(pt, CRIB_FRAGMENTS)
                if found:
                    free_results.append((desc, pt, found))

        # 4-5. Autokey Vigenere and Beaufort
        # 1-char primers
        for primer_char in AZ:
            for cipher_name, cipher_fn in [
                ("AutokeyVig", autokey_vig_decrypt),
                ("AutokeyBeau", autokey_beau_decrypt),
            ]:
                pt = cipher_fn(undone_text, primer_char, alph)
                desc = f"{cipher_name}/{alph_name}/primer={primer_char}"

                orig_hits = count_crib_hits_at_positions(pt, orig_flat)
                remap_hits = count_crib_hits_at_positions(pt, remapped_flat)

                best_hits = max(orig_hits, remap_hits)
                hit_type = "orig" if orig_hits >= remap_hits else "remap"

                if best_hits >= 2:
                    results.append((best_hits, desc, pt, hit_type, orig_hits, remap_hits))

                found = free_crib_search(pt, CRIB_FRAGMENTS)
                if found:
                    free_results.append((desc, pt, found))

        # 2-char primers
        for c1 in AZ:
            for c2 in AZ:
                primer = c1 + c2
                for cipher_name, cipher_fn in [
                    ("AutokeyVig", autokey_vig_decrypt),
                    ("AutokeyBeau", autokey_beau_decrypt),
                ]:
                    pt = cipher_fn(undone_text, primer, alph)
                    desc = f"{cipher_name}/{alph_name}/primer={primer}"

                    orig_hits = count_crib_hits_at_positions(pt, orig_flat)
                    remap_hits = count_crib_hits_at_positions(pt, remapped_flat)

                    best_hits = max(orig_hits, remap_hits)
                    hit_type = "orig" if orig_hits >= remap_hits else "remap"

                    if best_hits >= 2:
                        results.append((best_hits, desc, pt, hit_type, orig_hits, remap_hits))

                    found = free_crib_search(pt, CRIB_FRAGMENTS)
                    if found:
                        free_results.append((desc, pt, found))

        # 6. Caesar shifts
        for shift in range(26):
            pt = caesar_decrypt(undone_text, shift, alph)
            desc = f"Caesar/{alph_name}/shift={shift}"

            orig_hits = count_crib_hits_at_positions(pt, orig_flat)
            remap_hits = count_crib_hits_at_positions(pt, remapped_flat)

            best_hits = max(orig_hits, remap_hits)
            hit_type = "orig" if orig_hits >= remap_hits else "remap"

            if best_hits >= 2:
                results.append((best_hits, desc, pt, hit_type, orig_hits, remap_hits))

            found = free_crib_search(pt, CRIB_FRAGMENTS)
            if found:
                free_results.append((desc, pt, found))

        # 7. Atbash
        pt = atbash_decrypt(undone_text, alph)
        desc = f"Atbash/{alph_name}"

        orig_hits = count_crib_hits_at_positions(pt, orig_flat)
        remap_hits = count_crib_hits_at_positions(pt, remapped_flat)

        best_hits = max(orig_hits, remap_hits)
        hit_type = "orig" if orig_hits >= remap_hits else "remap"

        if best_hits >= 2:
            results.append((best_hits, desc, pt, hit_type, orig_hits, remap_hits))

        found = free_crib_search(pt, CRIB_FRAGMENTS)
        if found:
            free_results.append((desc, pt, found))

    # Sort and print results
    results.sort(key=lambda x: -x[0])

    print(f"\n{'='*80}")
    print(f"RESULTS WITH CRIB HITS >= 2 (sorted by hits desc)")
    print(f"{'='*80}")

    if not results:
        print("  (none)")
    else:
        for hits, desc, pt, hit_type, orig_hits, remap_hits in results:
            print(f"\n  HITS={hits} ({hit_type}: orig={orig_hits}, remap={remap_hits})")
            print(f"  Method: {desc}")
            print(f"  PT: {pt}")
            # Show which positions matched
            if orig_hits >= remap_hits:
                matches = [(p, ch) for p, ch in orig_flat if 0 <= p < len(pt) and pt[p] == ch]
            else:
                matches = [(p, ch) for p, ch in remapped_flat if 0 <= p < len(pt) and pt[p] == ch]
            print(f"  Matching positions: {matches}")

    print(f"\n{'='*80}")
    print(f"FREE CRIB SEARCH RESULTS (fragments found anywhere)")
    print(f"{'='*80}")

    if not free_results:
        print("  (none)")
    else:
        # Deduplicate and sort by longest fragment found
        for desc, pt, found in sorted(free_results, key=lambda x: -max(len(f) for f, _ in x[2])):
            print(f"\n  Method: {desc}")
            print(f"  PT: {pt}")
            for frag, pos in found:
                print(f"    Found '{frag}' at position {pos}")

    return results, free_results


def verify_undone_text(ct, width, col_order, expected_undone):
    """Verify that the undone text matches by redoing the columnar transposition."""
    mapping = columnar_undo_positions(len(ct), width, col_order)
    undone = ''.join(ct[mapping[i]] for i in range(len(ct)))

    # But wait - the user provided specific undone texts. Let me also try
    # the forward direction: given undone text, apply columnar transposition
    # to get carved text.

    # Actually, let's think about what "undo" means here:
    # If columnar transposition was applied to create the carved text,
    # then "undo" reverses it. But which direction?
    #
    # The user says undone text with order [3,0,1,2,5,4] is:
    # WOISJPABFSCVTKBODTJRBTITKUWWGMLOFTKZUXLQUFDORSHPIGVJUKAHQQAWWUQSUGILPSEDNBREKKFSNKCZBOGZAXNLKZRTY
    #
    # Let me just verify this matches.

    if undone == expected_undone:
        print(f"  VERIFIED: Width-{width} order {col_order} undone text matches.")
    else:
        print(f"  MISMATCH for width-{width} order {col_order}!")
        print(f"  Expected: {expected_undone}")
        print(f"  Got:      {undone}")
        # Try the other interpretation: col_order specifies which column to read as the i-th column
        # vs col_order specifies the position of the i-th column in the output

        # Alternative: the col_order is the write order (inverse permutation)
        inv_order = [0] * width
        for i, c in enumerate(col_order):
            inv_order[c] = i
        mapping2 = columnar_undo_positions(len(ct), width, inv_order)
        undone2 = ''.join(ct[mapping2[i]] for i in range(len(ct)))
        if undone2 == expected_undone:
            print(f"  VERIFIED with INVERTED order {inv_order}")
            return inv_order
        else:
            print(f"  Also tried inverted: {undone2}")
            # Try yet another interpretation: direct scatter
            # Let me just try all approaches
            print(f"  Trying brute force approach...")
            # Direct approach: simulate columnar encryption and decryption

            # Approach: columnar encryption writes rows, reads columns in order
            # For width 6, 97 chars: 17 rows (last row has 1 char)
            nrows = (len(ct) + width - 1) // width
            last_row_len = len(ct) - (nrows - 1) * width

            # Try: the carved text IS the result of columnar transposition
            # undo = write carved text into columns (in col_order), read rows
            for interp in range(2):
                order = col_order if interp == 0 else inv_order

                # Determine column lengths
                col_lens = []
                for c in range(width):
                    if c < last_row_len:
                        col_lens.append(nrows)
                    else:
                        col_lens.append(nrows - 1)

                # Fill columns in the specified order
                grid = [[] for _ in range(width)]
                pos = 0
                for c_idx in order:
                    for r in range(col_lens[c_idx]):
                        if pos < len(ct):
                            grid[c_idx].append(ct[pos])
                            pos += 1

                # Read rows
                result = []
                for r in range(nrows):
                    for c in range(width):
                        if r < len(grid[c]):
                            result.append(grid[c][r])
                result = ''.join(result)

                if result == expected_undone:
                    print(f"  VERIFIED with fill-columns interpretation, order={order} (interp={interp})")
                    return order

                # Alternative: fill rows, read columns in order (encryption direction)
                # Then undo = inverse
                grid2 = [[] for _ in range(width)]
                pos = 0
                for r in range(nrows):
                    for c in range(width):
                        if pos < len(ct):
                            grid2[c].append(ct[pos])
                            pos += 1

                # Read columns in order
                result2_parts = []
                for c_idx in order:
                    result2_parts.extend(grid2[c_idx])
                result2 = ''.join(result2_parts)

                if result2 == expected_undone:
                    print(f"  Wait - that would be APPLYING transposition, not undoing.")

        return col_order  # fallback
    return col_order


def main():
    # The two undone texts
    W6_UNDONE = "WOISJPABFSCVTKBODTJRBTITKUWWGMLOFTKZUXLQUFDORSHPIGVJUKAHQQAWWUQSUGILPSEDNBREKKFSNKCZBOGZAXNLKZRTY"
    W5_UNDONE = "OWWSZBIFJXKNLQTRFRSJUBVSCONQEDXYQKIOPPZGGVRZKHTNWUUTGAHLMKTUBZSJASFSKUOPOLELKTUKIWWDCFGTIABDQARBK"

    assert len(W6_UNDONE) == 97, f"W6 length: {len(W6_UNDONE)}"
    # W5 might be different length
    print(f"W5 undone length: {len(W5_UNDONE)}")
    # If 97, check. Actually let me verify:
    # width 5, 97 chars: 20 rows (20*5=100, but 97 chars means last rows are short)
    # Actually 19 full rows = 95, + 2 more = row 20 with 2 chars. So 20 rows.

    print("="*80)
    print("VERIFICATION: Checking undone texts against carved CT")
    print("="*80)

    print(f"\nCarved CT ({len(CT)} chars): {CT}")
    print(f"\nW6 undone ({len(W6_UNDONE)} chars): {W6_UNDONE}")
    print(f"W5 undone ({len(W5_UNDONE)} chars): {W5_UNDONE}")

    # Verify W6
    print("\nVerifying width-6 [3,0,1,2,5,4]...")
    w6_order = verify_undone_text(CT, 6, [3,0,1,2,5,4], W6_UNDONE)

    # Verify W5
    print("\nVerifying width-5 [0,3,1,2,4]...")
    w5_order = verify_undone_text(CT, 5, [0,3,1,2,4], W5_UNDONE)

    # Show WW positions
    print(f"\nW6 W positions: {[i for i, c in enumerate(W6_UNDONE) if c == 'W']}")
    print(f"W5 W positions: {[i for i, c in enumerate(W5_UNDONE) if c == 'W']}")

    # Run tests on both texts
    r1, f1 = run_tests(W6_UNDONE, "Width-6 columnar undo [3,0,1,2,5,4]", 6, [3,0,1,2,5,4])
    r2, f2 = run_tests(W5_UNDONE, "Width-5 columnar undo [0,3,1,2,4]", 5, [0,3,1,2,4])

    # Summary
    print(f"\n{'='*80}")
    print(f"SUMMARY")
    print(f"{'='*80}")
    print(f"Width-6: {len(r1)} results with >= 2 crib hits, {len(f1)} free crib finds")
    print(f"Width-5: {len(r2)} results with >= 2 crib hits, {len(f2)} free crib finds")

    if r1:
        best = r1[0]
        print(f"\nBest W6: {best[0]} hits - {best[1]}")
        print(f"  PT: {best[2]}")
    if r2:
        best = r2[0]
        print(f"\nBest W5: {best[0]} hits - {best[1]}")
        print(f"  PT: {best[2]}")

    # Total configs tested
    n_keywords = len(KEYWORDS)
    n_cipher_types = 3  # Vig, Beau, VBeau
    n_alphs = 2  # AZ, KA
    n_keyword_configs = n_keywords * n_cipher_types * n_alphs  # 60
    n_autokey_1char = 26 * 2 * n_alphs  # 104
    n_autokey_2char = 676 * 2 * n_alphs  # 2704
    n_caesar = 26 * n_alphs  # 52
    n_atbash = n_alphs  # 2
    total = n_keyword_configs + n_autokey_1char + n_autokey_2char + n_caesar + n_atbash
    print(f"\nTotal configs tested per text: {total}")
    print(f"Total configs tested: {total * 2}")


if __name__ == "__main__":
    main()
