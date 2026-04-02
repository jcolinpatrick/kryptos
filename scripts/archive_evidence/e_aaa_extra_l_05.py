#!/usr/bin/env python3
"""
Cipher: two_system
Family: archive_evidence
Status: superseded
Keyspace: ~2000 configs
Last run:
Best score:
"""
# DEPRECATED + SUPERSEDED by e_aaa_extra_l_07_corrected.py (2026-04-01).
# CRITICAL BUG: beaufort_decrypt_tableau() performs VIGENERE, not Beaufort.
# Both "Beaufort" and "Vigenere" branches produce identical Vigenere results.
# True Beaufort on misaligned row N was NEVER tested by this script.
# See e_aaa_extra_l_07_corrected.py for correct implementation with all 3 variants.

"""E-AAA-EXTRA-L-05: Extra L on tableau + Bottom chart seeding + ABSCISSA.

SOURCE: Archives of American Art:
  - IMG_1342: "Extra L at end of line, Bottom chart seeding / ABSCISSA"
  - IMG_1340: "★ Definition of ABSCISSA", "4, 8, 10, 26 = Col"
  - Anomaly registry B1: Row N has extra L, creates H-I-L-L reading down

HYPOTHESES TESTED:
  H1: Physical tableau misalignment — row N's extra L shifts all lookups
      for key=N by 1 position for CT letters after L in that row
  H2: Bottom chart reading — reversed row order in Beaufort/Vigenere
  H3: ABSCISSA seeded from bottom row of tableau
  H4: Grid width 27 (26+1) for transposition
  H5: L is a null marker (extra L = L is padding/null)
  H6: Combined: misaligned Beaufort + columnar with archive widths
"""
import sys, os
_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, 'src')):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CONSENSUS_NULL_POSITIONS
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free
from kryptos.kernel.alphabet import KA

CT97 = CT
CT73 = ''.join(c for i, c in enumerate(CT97) if i not in CONSENSUS_NULL_POSITIONS)

# The KRYPTOS alphabet
KA_STR = 'KRYPTOSABCDEFGHIJLMNQUVWXZ'
KA_I = {c: i for i, c in enumerate(KA_STR)}

# Standard alphabet for comparison
AZ = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
AZ_I = {c: i for i, c in enumerate(AZ)}

# Build the physical tableau (26 rows of the KA alphabet, shifted)
def build_tableau():
    """Standard KA Vigenere tableau."""
    rows = {}
    for i, key_letter in enumerate(KA_STR):
        row = KA_STR[i:] + KA_STR[:i]
        rows[key_letter] = row
    return rows

# Build the MISALIGNED tableau where row N has an extra L
def build_misaligned_tableau():
    """Row N has 27 chars with extra L inserted."""
    rows = {}
    for i, key_letter in enumerate(KA_STR):
        row = KA_STR[i:] + KA_STR[:i]
        if key_letter == 'N':
            # Insert extra L before M (creating L,L,M sequence)
            l_pos = row.index('L')
            row = row[:l_pos+1] + 'L' + row[l_pos+1:]  # Now 27 chars
        rows[key_letter] = row
    return rows

def beaufort_decrypt_tableau(ct, key, tableau):
    """Beaufort decrypt using a specific tableau. PT = position of CT in key's row."""
    klen = len(key)
    pt = []
    for i, c in enumerate(ct):
        k = key[i % klen]
        row = tableau[k]
        # Find c in the row — for misaligned rows, take FIRST occurrence
        idx = row.index(c)
        pt.append(KA_STR[idx % 26])  # Map back to standard 26-letter position
    return ''.join(pt)

def vigenere_decrypt_tableau(ct, key, tableau):
    """Vigenere decrypt: PT = KA_STR[ (KA_I[ct] - KA_I[key]) % 26 ] but using tableau lookup."""
    klen = len(key)
    pt = []
    for i, c in enumerate(ct):
        k = key[i % klen]
        # In Vigenere, PT is found by: find CT in key's row, read column header
        row = tableau[k]
        idx = row.index(c)
        pt.append(KA_STR[idx % 26])
    return ''.join(pt)

def beaufort_bottom_decrypt(ct, key):
    """Beaufort with reversed row order (bottom chart reading).
    Instead of row[k] starting at position KA_I[k], start at 25-KA_I[k]."""
    klen = len(key)
    pt = []
    for i, c in enumerate(ct):
        k = key[i % klen]
        # Bottom reading: reverse the row index
        rev_idx = 25 - KA_I[k]
        row = KA_STR[rev_idx:] + KA_STR[:rev_idx]
        idx = row.index(c)
        pt.append(KA_STR[idx])
    return ''.join(pt)

def beaufort_misaligned_with_shift(ct, key):
    """When key letter is N, the extra L shifts positions ≥ L by +1.
    For all other key letters, standard Beaufort."""
    klen = len(key)
    pt = []
    tableau = build_misaligned_tableau()
    for i, c in enumerate(ct):
        k = key[i % klen]
        row = tableau[k]
        if c in row:
            idx = row.index(c)
            pt.append(KA_STR[idx % 26])
        else:
            pt.append('?')
    return ''.join(pt)

def columnar_decipher(ct, width):
    n = len(ct)
    nrows = (n + width - 1) // width
    full_cols = n % width or width
    grid = [''] * width
    pos = 0
    for col in range(width):
        col_len = nrows if col < full_cols else nrows - 1
        grid[col] = ct[pos:pos + col_len]
        pos += col_len
    result = []
    for row in range(nrows):
        for col in range(width):
            if row < len(grid[col]):
                result.append(grid[col][row])
    return ''.join(result)

def remove_all_L(ct):
    """If L is a null, remove all L's from ciphertext."""
    return ''.join(c for c in ct if c != 'L')

# Keywords
KEYWORDS = ['ABSCISSA', 'ECLIPSE', 'NORMANDY', 'PALIMPSEST', 'KRYPTOS',
            'KUBARK', 'SHADOW', 'COMPASS', 'HELIED']
WIDTHS = [4, 8, 10, 26, 27]  # 27 = 26+1 for extra L

best_score = 0
best_result = None
total = 0
hits = []

def test(pt, ct_label, desc):
    global best_score, best_result, total
    if '?' in pt:
        return
    sc = score_candidate(pt) if ct_label == 'CT97' else score_candidate_free(pt)
    total += 1
    if sc.crib_score > best_score:
        best_score = sc.crib_score
        best_result = (ct_label, desc, pt, sc)
    if sc.crib_score >= 10:
        hits.append((sc.crib_score, ct_label, desc, pt[:40]))

tableau_std = build_tableau()
tableau_mis = build_misaligned_tableau()

for ct_text, ct_label in [(CT97, 'CT97'), (CT73, 'CT73')]:
    for kw in KEYWORDS:

        # H1: Misaligned Beaufort (extra L in row N)
        pt = beaufort_decrypt_tableau(ct_text, kw, tableau_mis)
        test(pt, ct_label, f'H1_misaligned_beau_{kw}')

        # H1b: Misaligned Vigenere
        pt = vigenere_decrypt_tableau(ct_text, kw, tableau_mis)
        test(pt, ct_label, f'H1_misaligned_vig_{kw}')

        # H2: Bottom chart reading Beaufort
        pt = beaufort_bottom_decrypt(ct_text, kw)
        test(pt, ct_label, f'H2_bottom_beau_{kw}')

        # H3: Standard Beaufort but using KA alphabet (not AZ)
        pt = beaufort_decrypt_tableau(ct_text, kw, tableau_std)
        test(pt, ct_label, f'H3_ka_beau_{kw}')

        # H6: Misaligned + columnar
        for w in WIDTHS:
            # Misaligned Beaufort then columnar decipher
            mis_pt = beaufort_decrypt_tableau(ct_text, kw, tableau_mis)
            pt = columnar_decipher(mis_pt, w)
            test(pt, ct_label, f'H6_mis_beau_{kw}_col{w}')

            # Columnar then misaligned Beaufort
            dt = columnar_decipher(ct_text, w)
            pt = beaufort_decrypt_tableau(dt, kw, tableau_mis)
            test(pt, ct_label, f'H6_col{w}_mis_beau_{kw}')

            # Bottom Beaufort then columnar
            bpt = beaufort_bottom_decrypt(ct_text, kw)
            pt = columnar_decipher(bpt, w)
            test(pt, ct_label, f'H6_bot_beau_{kw}_col{w}')

            # Columnar then bottom Beaufort
            dt = columnar_decipher(ct_text, w)
            pt = beaufort_bottom_decrypt(dt, kw)
            test(pt, ct_label, f'H6_col{w}_bot_beau_{kw}')

    # H5: L is a null — remove all L's, then decrypt
    ct_no_l = remove_all_L(ct_text)
    if len(ct_no_l) >= 20:
        for kw in KEYWORDS:
            pt = beaufort_decrypt_tableau(ct_no_l, kw, tableau_std)
            test(pt, 'CT_noL', f'H5_removeL_beau_{kw}')

            pt = beaufort_decrypt_tableau(ct_no_l, kw, tableau_mis)
            test(pt, 'CT_noL', f'H5_removeL_mis_beau_{kw}')

# H4: Width 27 specifically (26+1 for extra L)
for ct_text, ct_label in [(CT97, 'CT97'), (CT73, 'CT73')]:
    for kw in KEYWORDS:
        dt = columnar_decipher(ct_text, 27)
        for fn_name, tableau in [('std', tableau_std), ('mis', tableau_mis)]:
            pt = beaufort_decrypt_tableau(dt, kw, tableau)
            test(pt, ct_label, f'H4_col27_{fn_name}_beau_{kw}')

        pt2 = beaufort_decrypt_tableau(ct_text, kw, tableau_std)
        pt3 = columnar_decipher(pt2, 27)
        test(pt3, ct_label, f'H4_beau_{kw}_col27')

print(f"\n{'='*70}")
print(f"E-AAA-EXTRA-L-05: Extra L + Bottom chart + ABSCISSA")
print(f"{'='*70}")
print(f"Configurations tested: {total}")
print(f"Best score: {best_score}")
if best_result:
    ct_label, desc, pt, sc = best_result
    print(f"  CT: {ct_label}")
    print(f"  Method: {desc}")
    print(f"  PT: {pt[:60]}...")
    print(f"  Score: {sc}")
if hits:
    print(f"\nHits (score >= 10):")
    for h in sorted(hits, reverse=True):
        print(f"  score={h[0]} {h[1]} method={h[2]} pt={h[3]}")
else:
    print(f"\nNo hits >= 10")
print(f"{'='*70}")
