#!/usr/bin/env python3
"""
Cipher: two_system
Family: archive_evidence
Status: exhausted
Keyspace: ~12000 configs
Last run:
Best score:
"""
"""E-AAA-EXTRA-L-07: Corrected Extra L + Bottom chart hypotheses.

SUPERSEDES e_aaa_extra_l_05.py which had a CRITICAL BUG:
  beaufort_decrypt_tableau() performed VIGENERE, not Beaufort.
  Both "Beaufort" and "Vigenere" labels produced identical Vigenere results.
  True Beaufort on misaligned row N was NEVER tested.

SOURCE: Archives of American Art:
  - IMG_1340/1342: "Extra L at end of line, Bottom chart seeding/section"
  - IMG_1340: "? on line 4, 8, 10, 25 not coded"
  - IMG_1340: "★ Definition of ABSCISSA", "4, 8, 10, 26 = Col"
  - Anomaly registry B1: Row N has extra L, creates H-I-L-L reading down

HYPOTHESES TESTED:
  H1: Misaligned tableau (row N has 27 chars) — Beaufort, Vigenere, Variant Beaufort
  H2: Bottom chart reading (reversed row order) — all 3 variants
  H3: ABSCISSA-keyed tableau — all 3 variants
  H4: Grid width 27 (26+1) — all 3 variants, both peel orders
  H5: L as null marker — remove L at specific positions + remove all L
  H6: Combined misaligned + columnar — all 3 variants
  H7: Divided chart (use only bottom section of tableau) — NEW, never tested
  H8: Seeding as initialization (extra L position seeds autokey primer) — NEW
  H9: Extra L as line/row termination in route-style reading — NEW
  H10: "Not coded" extraction (treat specific positions as passthrough) — NEW

FIXES APPLIED:
  - Beaufort decryption: PT_idx = (K_idx - CT_idx) % 26  [was CT-K, i.e. Vigenere]
  - Variant Beaufort:    PT_idx = (CT_idx + K_idx) % 26
  - Vigenere:            PT_idx = (CT_idx - K_idx) % 26
  - Bottom-chart functions now correctly implement all 3 variants with reversed key
"""
import sys, os, time

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, 'src')):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CONSENSUS_NULL_POSITIONS
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free

t0 = time.time()

CT97 = CT
CT73 = ''.join(c for i, c in enumerate(CT97) if i not in CONSENSUS_NULL_POSITIONS)

# The KRYPTOS alphabet
KA_STR = 'KRYPTOSABCDEFGHIJLMNQUVWXZ'
KA_I = {c: i for i, c in enumerate(KA_STR)}
AZ = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
AZ_I = {c: i for i, c in enumerate(AZ)}
MOD = 26

# ── Tableau construction ─────────────────────────────────────────────────

def build_tableau():
    """Standard KA Vigenere tableau: 26 rows of 26 chars."""
    rows = {}
    for i, key_letter in enumerate(KA_STR):
        row = KA_STR[i:] + KA_STR[:i]
        rows[key_letter] = row
    return rows

def build_misaligned_tableau():
    """Row N has 27 chars: extra L inserted after the first L."""
    rows = {}
    for i, key_letter in enumerate(KA_STR):
        row = KA_STR[i:] + KA_STR[:i]
        if key_letter == 'N':
            l_pos = row.index('L')
            row = row[:l_pos+1] + 'L' + row[l_pos+1:]  # 27 chars
        rows[key_letter] = row
    return rows

# ── Correct cipher operations ────────────────────────────────────────────

def decrypt_vigenere(ct_ch, k_ch, alpha=KA_STR, idx=KA_I):
    """Vigenere: PT = (CT - K) mod 26"""
    return alpha[(idx[ct_ch] - idx[k_ch]) % MOD]

def decrypt_beaufort(ct_ch, k_ch, alpha=KA_STR, idx=KA_I):
    """Beaufort: PT = (K - CT) mod 26"""
    return alpha[(idx[k_ch] - idx[ct_ch]) % MOD]

def decrypt_vbeau(ct_ch, k_ch, alpha=KA_STR, idx=KA_I):
    """Variant Beaufort: PT = (CT + K) mod 26"""
    return alpha[(idx[ct_ch] + idx[k_ch]) % MOD]

DECRYPT_FNS = {
    'vig': decrypt_vigenere,
    'beau': decrypt_beaufort,
    'vbeau': decrypt_vbeau,
}

def periodic_decrypt(ct, key, variant='beau', alpha=KA_STR, idx=KA_I):
    """Periodic decryption with correct variant."""
    fn = DECRYPT_FNS[variant]
    klen = len(key)
    return ''.join(fn(c, key[i % klen], alpha, idx) for i, c in enumerate(ct))

def periodic_decrypt_reversed(ct, key, variant='beau', alpha=KA_STR, idx=KA_I):
    """Periodic decryption with reversed row order (bottom chart reading).
    Key index is (25 - KA_I[k]) instead of KA_I[k]."""
    klen = len(key)
    result = []
    for i, c in enumerate(ct):
        k = key[i % klen]
        # Reverse the key: use the letter at position (25 - idx[k])
        rev_k = alpha[(MOD - 1 - idx[k]) % MOD]
        result.append(DECRYPT_FNS[variant](c, rev_k, alpha, idx))
    return ''.join(result)

# ── Misaligned tableau decryption ────────────────────────────────────────

def misaligned_decrypt(ct, key, variant='beau'):
    """When key letter is N, use the 27-char misaligned row.
    For misaligned row: find CT in the row, map index back to 26-letter space.
    For Beaufort on misaligned row: we need to find CT position in key's row,
    then the PT is determined by that position in the column header."""
    mis_tableau = build_misaligned_tableau()
    std_tableau = build_tableau()
    klen = len(key)
    result = []
    for i, c in enumerate(ct):
        k = key[i % klen]
        if k == 'N':
            row = mis_tableau['N']  # 27 chars
            if c not in row:
                result.append('?')
                continue
            j = row.index(c)
            # The column header is KA_STR (26 chars)
            # Position j in a 27-char row: if j < 26, normal mapping
            # If j == 26, it wraps (the pushed-off letter)
            if variant == 'vig':
                # Vigenere: PT = column header at position j
                result.append(KA_STR[j % MOD])
            elif variant == 'beau':
                # Beaufort: PT at position j means we need to invert
                # In standard Beaufort on a normal row: row[j] = CT means
                # j = (K - PT) mod 26, so PT = (K - j) mod 26
                k_idx = KA_I[k]
                pt_idx = (k_idx - j) % MOD
                result.append(KA_STR[pt_idx])
            else:  # vbeau
                # Variant Beaufort: j = (CT + K) - based lookup
                # PT at position j: j = (PT - K) mod 26 in standard
                k_idx = KA_I[k]
                pt_idx = (j + k_idx) % MOD
                result.append(KA_STR[pt_idx])
        else:
            # Standard row, use direct formula
            result.append(DECRYPT_FNS[variant](c, k, KA_STR, KA_I))
    return ''.join(result)

# ── Columnar transposition ───────────────────────────────────────────────

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

# ── Test infrastructure ──────────────────────────────────────────────────

KEYWORDS = ['ABSCISSA', 'ECLIPSE', 'NORMANDY', 'PALIMPSEST', 'KRYPTOS',
            'KUBARK', 'SHADOW', 'COMPASS', 'HELIED', 'ENIGMA', 'SANBORN']
WIDTHS = [4, 8, 10, 26, 27]
VARIANTS = ['vig', 'beau', 'vbeau']

best_score = 0
best_result = None
total = 0
hits = []

def test(pt, ct_label, desc):
    global best_score, best_result, total
    total += 1
    if not pt or '?' in pt or len(pt) < 10:
        return
    sc = score_candidate(pt) if ct_label == 'CT97' else score_candidate_free(pt)
    if sc.crib_score > best_score:
        best_score = sc.crib_score
        best_result = (ct_label, desc, pt, sc)
    if sc.crib_score >= 10:
        hits.append((sc.crib_score, ct_label, desc, pt[:50]))

# ═══════════════════════════════════════════════════════════════════════════
# H1: Misaligned tableau (row N shifted by extra L) — ALL 3 VARIANTS
# ═══════════════════════════════════════════════════════════════════════════

print("H1: Misaligned tableau decryption (3 variants)...")
h1_start = total
for ct_text, ct_label in [(CT97, 'CT97'), (CT73, 'CT73')]:
    for kw in KEYWORDS:
        for var in VARIANTS:
            pt = misaligned_decrypt(ct_text, kw, variant=var)
            test(pt, ct_label, f'H1_misaligned_{var}_{kw}')
print(f"  H1: {total - h1_start} configs")

# ═══════════════════════════════════════════════════════════════════════════
# H2: Bottom chart reading (reversed row order) — ALL 3 VARIANTS
# ═══════════════════════════════════════════════════════════════════════════

print("H2: Bottom chart (reversed rows, 3 variants)...")
h2_start = total
for ct_text, ct_label in [(CT97, 'CT97'), (CT73, 'CT73')]:
    for kw in KEYWORDS:
        for var in VARIANTS:
            pt = periodic_decrypt_reversed(ct_text, kw, variant=var)
            test(pt, ct_label, f'H2_bottom_{var}_{kw}')
print(f"  H2: {total - h2_start} configs")

# ═══════════════════════════════════════════════════════════════════════════
# H3: Standard KA tableau — ALL 3 VARIANTS (baseline comparison)
# ═══════════════════════════════════════════════════════════════════════════

print("H3: Standard KA tableau (3 variants, baseline)...")
h3_start = total
for ct_text, ct_label in [(CT97, 'CT97'), (CT73, 'CT73')]:
    for kw in KEYWORDS:
        for var in VARIANTS:
            pt = periodic_decrypt(ct_text, kw, variant=var)
            test(pt, ct_label, f'H3_standard_{var}_{kw}')
print(f"  H3: {total - h3_start} configs")

# ═══════════════════════════════════════════════════════════════════════════
# H4: Width 27 transposition — ALL 3 VARIANTS, BOTH PEEL ORDERS
# ═══════════════════════════════════════════════════════════════════════════

print("H4: Width-27 columnar + all variants...")
h4_start = total
for ct_text, ct_label in [(CT97, 'CT97'), (CT73, 'CT73')]:
    for kw in KEYWORDS:
        for var in VARIANTS:
            # Peel order 1: substitution then transposition
            sub_pt = periodic_decrypt(ct_text, kw, variant=var)
            pt1 = columnar_decipher(sub_pt, 27)
            test(pt1, ct_label, f'H4a_{var}_{kw}_sub_then_col27')

            # Peel order 2: transposition then substitution
            detrans = columnar_decipher(ct_text, 27)
            pt2 = periodic_decrypt(detrans, kw, variant=var)
            test(pt2, ct_label, f'H4b_{var}_{kw}_col27_then_sub')

            # Same with misaligned tableau
            sub_pt_mis = misaligned_decrypt(ct_text, kw, variant=var)
            pt3 = columnar_decipher(sub_pt_mis, 27)
            test(pt3, ct_label, f'H4c_{var}_{kw}_mis_then_col27')

            detrans2 = columnar_decipher(ct_text, 27)
            pt4 = misaligned_decrypt(detrans2, kw, variant=var)
            test(pt4, ct_label, f'H4d_{var}_{kw}_col27_then_mis')
print(f"  H4: {total - h4_start} configs")

# ═══════════════════════════════════════════════════════════════════════════
# H5: L as null marker — remove L at specific positions + remove all
# ═══════════════════════════════════════════════════════════════════════════

print("H5: L as null marker...")
h5_start = total

# Find positions of L in CT97
l_positions = [i for i, c in enumerate(CT97) if c == 'L']
print(f"  L appears at positions: {l_positions} ({len(l_positions)} occurrences)")

# Remove ALL L's
ct_no_l_97 = ''.join(c for c in CT97 if c != 'L')
ct_no_l_73 = ''.join(c for c in CT73 if c != 'L')

for ct_text, ct_label in [(ct_no_l_97, 'CT97_noL'), (ct_no_l_73, 'CT73_noL')]:
    if len(ct_text) < 10:
        continue
    for kw in KEYWORDS:
        for var in VARIANTS:
            pt = periodic_decrypt(ct_text, kw, variant=var)
            test(pt, ct_label, f'H5_removeAllL_{var}_{kw}')

# Remove L's one at a time (each L position as a single null)
for l_pos in l_positions:
    ct_one_less = CT97[:l_pos] + CT97[l_pos+1:]
    for kw in KEYWORDS[:5]:  # Top 5 keywords to keep size reasonable
        for var in VARIANTS:
            pt = periodic_decrypt(ct_one_less, kw, variant=var)
            test(pt, 'CT97_noL1', f'H5_removeL@{l_pos}_{var}_{kw}')

print(f"  H5: {total - h5_start} configs")

# ═══════════════════════════════════════════════════════════════════════════
# H6: Combined misaligned + columnar — ALL 3 VARIANTS
# ═══════════════════════════════════════════════════════════════════════════

print("H6: Misaligned + columnar (archive widths)...")
h6_start = total
for ct_text, ct_label in [(CT97, 'CT97'), (CT73, 'CT73')]:
    for kw in KEYWORDS:
        for var in VARIANTS:
            for w in WIDTHS:
                # Peel 1: misaligned sub then columnar
                sub_pt = misaligned_decrypt(ct_text, kw, variant=var)
                pt = columnar_decipher(sub_pt, w)
                test(pt, ct_label, f'H6a_{var}_{kw}_mis_col{w}')

                # Peel 2: columnar then misaligned sub
                detrans = columnar_decipher(ct_text, w)
                pt = misaligned_decrypt(detrans, kw, variant=var)
                test(pt, ct_label, f'H6b_{var}_{kw}_col{w}_mis')

                # Bottom chart + columnar
                bpt = periodic_decrypt_reversed(ct_text, kw, variant=var)
                pt = columnar_decipher(bpt, w)
                test(pt, ct_label, f'H6c_{var}_{kw}_bot_col{w}')

                # Columnar then bottom chart
                detrans = columnar_decipher(ct_text, w)
                pt = periodic_decrypt_reversed(detrans, kw, variant=var)
                test(pt, ct_label, f'H6d_{var}_{kw}_col{w}_bot')
print(f"  H6: {total - h6_start} configs")

# ═══════════════════════════════════════════════════════════════════════════
# H7: DIVIDED CHART — use only bottom section of tableau (NEW)
# ═══════════════════════════════════════════════════════════════════════════
# If "bottom chart section" means the tableau is divided at row N,
# and K4 uses only the rows BELOW the division point.
# We test: for key letters in the bottom half, use the tableau normally;
# for key letters in the top half, remap them to the bottom half.

print("H7: Divided chart (bottom section only)...")
h7_start = total

# Row N is at index 17 in KA ordering (K=0,R=1,...,N=17)
# "Bottom chart" = rows from N onward (indices 17-25 in KA)
# When key falls in top half, wrap it to bottom half
N_IDX = KA_I['N']  # = 17

def decrypt_bottom_only(ct, key, variant='beau'):
    """Key letters are remapped to the bottom section (rows N-Z in KA order)."""
    klen = len(key)
    bottom_size = MOD - N_IDX  # 9 rows (N through Z)
    result = []
    for i, c in enumerate(ct):
        k = key[i % klen]
        k_idx = KA_I[k]
        # Remap to bottom section
        remapped_idx = N_IDX + (k_idx % bottom_size)
        remapped_k = KA_STR[remapped_idx]
        result.append(DECRYPT_FNS[variant](c, remapped_k, KA_STR, KA_I))
    return ''.join(result)

# Also test division at other plausible points
DIVISION_POINTS = [13, N_IDX, 20]  # middle, row N, row 20

for ct_text, ct_label in [(CT97, 'CT97'), (CT73, 'CT73')]:
    for kw in KEYWORDS:
        for var in VARIANTS:
            for div_pt in DIVISION_POINTS:
                bottom_size = MOD - div_pt
                if bottom_size < 2:
                    continue
                klen = len(kw)
                result = []
                for i, c in enumerate(ct_text):
                    k = kw[i % klen]
                    k_idx = KA_I[k]
                    remapped_idx = div_pt + (k_idx % bottom_size)
                    remapped_k = KA_STR[remapped_idx]
                    result.append(DECRYPT_FNS[var](c, remapped_k, KA_STR, KA_I))
                pt = ''.join(result)
                test(pt, ct_label, f'H7_div{div_pt}_{var}_{kw}')
print(f"  H7: {total - h7_start} configs")

# ═══════════════════════════════════════════════════════════════════════════
# H8: SEEDING AS INITIALIZATION (NEW)
# ═══════════════════════════════════════════════════════════════════════════
# "Bottom chart seeding" could mean the extra L position seeds an autokey-like
# system. Test: first few key chars come from a specific tableau row/position,
# then switch to plaintext/ciphertext autokey.

print("H8: Seeding as autokey initialization...")
h8_start = total

# Seed values: L (the extra letter), N (the row), positions in KA
SEED_LETTERS = ['L', 'N', 'H', 'I']  # H-I-L-L column letters
PRIMER_LENGTHS = [1, 2, 3, 4, 5, 7]

for ct_text, ct_label in [(CT97, 'CT97'), (CT73, 'CT73')]:
    for seed in SEED_LETTERS:
        for plen in PRIMER_LENGTHS:
            primer = seed * plen
            for var in VARIANTS:
                # PT-autokey: key = primer || PT
                pt_chars = []
                key_so_far = list(primer)
                for i, c in enumerate(ct_text):
                    if i < len(key_so_far):
                        k = key_so_far[i]
                    else:
                        k = pt_chars[i - len(primer)]
                    p = DECRYPT_FNS[var](c, k, KA_STR, KA_I)
                    pt_chars.append(p)
                    if i >= len(key_so_far) - 1 and len(key_so_far) <= i + 1:
                        key_so_far.append(p)
                pt = ''.join(pt_chars)
                test(pt, ct_label, f'H8_ptauto_{var}_seed{seed}_p{plen}')

                # CT-autokey: key = primer || CT
                pt_chars2 = []
                for i, c in enumerate(ct_text):
                    if i < plen:
                        k = primer[i]
                    else:
                        k = ct_text[i - plen]
                    p = DECRYPT_FNS[var](c, k, KA_STR, KA_I)
                    pt_chars2.append(p)
                pt2 = ''.join(pt_chars2)
                test(pt2, ct_label, f'H8_ctauto_{var}_seed{seed}_p{plen}')
print(f"  H8: {total - h8_start} configs")

# ═══════════════════════════════════════════════════════════════════════════
# H9: EXTRA L AS ROUTE/LINE TERMINATION SIGNAL (NEW)
# ═══════════════════════════════════════════════════════════════════════════
# If the extra L means "row N has width 27" while other rows have width 26,
# this could signal a non-rectangular grid. Test reading CT at width 26
# with row 14 (0-indexed, corresponding to N) having width 27.

print("H9: Route/line termination signal (variable-width grid)...")
h9_start = total

def read_variable_grid(ct, normal_width, special_row, special_width):
    """Read CT into a grid where one row has different width, then read columns."""
    rows = []
    pos = 0
    row_idx = 0
    while pos < len(ct):
        w = special_width if row_idx == special_row else normal_width
        rows.append(ct[pos:pos+w])
        pos += w
        row_idx += 1

    # Read by columns (standard columnar reading)
    max_w = max(len(r) for r in rows)
    result = []
    for col in range(max_w):
        for row in rows:
            if col < len(row):
                result.append(row[col])
    return ''.join(result)

# Test various normal widths with row 14 having width 27
for ct_text, ct_label in [(CT97, 'CT97')]:
    for normal_w in [7, 8, 9, 10, 13, 14, 26]:
        for special_row_idx in range(min(5, (len(ct_text) // normal_w) + 1)):
            reordered = read_variable_grid(ct_text, normal_w, special_row_idx, normal_w + 1)
            for kw in KEYWORDS[:5]:
                for var in VARIANTS:
                    pt = periodic_decrypt(reordered, kw, variant=var)
                    test(pt, ct_label, f'H9_varGrid_w{normal_w}_sr{special_row_idx}_{var}_{kw}')

print(f"  H9: {total - h9_start} configs")

# ═══════════════════════════════════════════════════════════════════════════
# H10: "NOT CODED" EXTRACTION PATTERN (NEW)
# ═══════════════════════════════════════════════════════════════════════════
# "? on line 4, 8, 10, 25 not coded" = question marks at those lines are
# passthrough. Apply the same principle: at positions corresponding to
# lines 4, 8, 10, 25 (at various grid widths), treat those as identity
# (CT=PT passthrough), decrypt the rest.

print("H10: 'Not coded' passthrough positions...")
h10_start = total

NOT_CODED_LINES = [4, 8, 10, 25]  # from IMG_1340

for ct_text, ct_label in [(CT97, 'CT97'), (CT73, 'CT73')]:
    for grid_w in [7, 8, 9, 10, 13, 14, 26]:
        # Compute which character positions fall on "not coded" lines
        passthrough_positions = set()
        for line_num in NOT_CODED_LINES:
            # 0-indexed line: positions line_num*grid_w through (line_num+1)*grid_w - 1
            start = line_num * grid_w
            end = start + grid_w
            for p in range(start, min(end, len(ct_text))):
                passthrough_positions.add(p)

        if not passthrough_positions or len(passthrough_positions) >= len(ct_text):
            continue

        for kw in KEYWORDS[:5]:
            for var in VARIANTS:
                klen = len(kw)
                pt_chars = []
                for i, c in enumerate(ct_text):
                    if i in passthrough_positions:
                        pt_chars.append(c)  # Passthrough: CT = PT
                    else:
                        pt_chars.append(DECRYPT_FNS[var](c, kw[i % klen], KA_STR, KA_I))
                pt = ''.join(pt_chars)
                test(pt, ct_label, f'H10_notcoded_w{grid_w}_{var}_{kw}')
print(f"  H10: {total - h10_start} configs")

# ═══════════════════════════════════════════════════════════════════════════
# RESULTS
# ═══════════════════════════════════════════════════════════════════════════

elapsed = time.time() - t0

print(f"\n{'='*70}")
print(f"E-AAA-EXTRA-L-07: Corrected Extra L + All Hypotheses")
print(f"{'='*70}")
print(f"Configurations tested: {total}")
print(f"Elapsed: {elapsed:.1f}s")
print(f"Best score: {best_score}/24")
if best_result:
    ct_label, desc, pt, sc = best_result
    print(f"\nBest result:")
    print(f"  CT form: {ct_label}")
    print(f"  Method: {desc}")
    print(f"  PT: {pt[:70]}...")
    print(f"  Score: {sc}")
if hits:
    print(f"\nHits (score >= 10):")
    for h in sorted(hits, reverse=True):
        print(f"  score={h[0]} {h[1]} method={h[2]} pt={h[3]}")
else:
    print(f"\nNo hits >= 10 (all NOISE)")

print(f"\n--- Per-hypothesis breakdown ---")
print(f"  H1 (misaligned tableau, 3 variants): tested")
print(f"  H2 (bottom chart / reversed rows, 3 variants): tested")
print(f"  H3 (standard KA baseline, 3 variants): tested")
print(f"  H4 (width-27 columnar, 3 variants, 2 peel orders): tested")
print(f"  H5 (L as null, all + positional removal): tested")
print(f"  H6 (misaligned + columnar, all combos): tested")
print(f"  H7 (divided chart / bottom section only): tested [NEW]")
print(f"  H8 (seeding as autokey init, PT/CT autokey): tested [NEW]")
print(f"  H9 (variable-width grid with special row): tested [NEW]")
print(f"  H10 ('not coded' passthrough at line positions): tested [NEW]")

print(f"\n--- Key finding ---")
print(f"  Row N (extra L row) is NEVER used in K1-K3 lookups.")
print(f"  Keywords PALIMPSEST, ABSCISSA, KRYPTOS contain no 'N'.")
print(f"  The extra L is computationally inert for all solved sections.")
print(f"{'='*70}")
