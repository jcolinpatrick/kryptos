#!/usr/bin/env python3
"""
Test several genuinely new cipher models:

1. DIFFERENCE CIPHER: PT[i] = (CT[i] - CT[i-k]) % 26 for all shifts k=1..96
   (CT autokey where key[i] = CT[i-k], circular)
   Also: Beaufort and VBeau variants

2. REVERSED CT: Reverse the 97-char CT, then check all 6 periodic variants
   (Cribs would appear at mirrored positions if cipher operates on reversed text)

3. BOUSTROPHEDON reading: K4 spans 4 rows of the 28×31 grid.
   Row 24(partial), 25, 26, 27. Boustrophedon: alternating L→R, R→L.

4. PORTA CIPHER: Each key letter pair selects one of 13 table rows.
   Test all periods 1-26 with the standard Porta table.
"""
import sys
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT as CT_STR, CRIB_DICT, KRYPTOS_ALPHABET as KA

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CT = [ord(c)-65 for c in CT_STR]
N = len(CT)

ALL_CRIBS = list(CRIB_DICT.items())

def count_cribs(pt_list):
    return sum(1 for pos, ch in ALL_CRIBS if pos < len(pt_list) and AZ[pt_list[pos]] == ch)

# ── 1. DIFFERENCE CIPHER ────────────────────────────────────────────────────
print("=" * 60)
print("1. DIFFERENCE CIPHER: PT[i] = (CT[i] - CT[(i-k)%N]) % 26")
print("=" * 60)

best_diff = []
for k in range(1, N):
    # Vigenère-like: key[i] = CT[(i-k)%N] → PT[i] = CT[i] - key[i]
    pt_vig = [(CT[i] - CT[(i-k)%N]) % 26 for i in range(N)]
    # Beaufort: key[i] = CT[(i-k)%N] → PT[i] = key[i] - CT[i]
    pt_beau = [(CT[(i-k)%N] - CT[i]) % 26 for i in range(N)]
    # VBeau: key[i] = CT[(i-k)%N] → PT[i] = CT[i] + key[i]
    pt_vbeau = [(CT[i] + CT[(i-k)%N]) % 26 for i in range(N)]

    for vname, pt in [('Vig', pt_vig), ('Beau', pt_beau), ('VBeau', pt_vbeau)]:
        hits = count_cribs(pt)
        if hits >= 3:
            pt_str = ''.join(AZ[x] for x in pt)
            best_diff.append((hits, k, vname, pt_str))

best_diff.sort(key=lambda x: -x[0])
print(f"\n{'Hits':>5} {'k':>4} {'Variant':<8}  Plaintext[:50]")
print("-" * 70)
for hits, k, vname, pt_str in best_diff[:20]:
    flag = " ★" if hits == 24 else ""
    print(f"{hits:>5}/24  {k:>3}  {vname:<8}  {pt_str[:50]}{flag}")

# Show top result
if best_diff:
    hits, k, vname, pt_str = best_diff[0]
    print(f"\nTop: k={k} {vname}, hits={hits}/24")
    print(f"PT: {pt_str}")
    print(f"ENE[21:34]: {pt_str[21:34]}")
    print(f"BLK[63:74]: {pt_str[63:74]}")

# ── 2. REVERSED CT ──────────────────────────────────────────────────────────
print("\n\n" + "=" * 60)
print("2. REVERSED CT + periodic substitution")
print("=" * 60)

CT_rev = CT[::-1]
CT_rev_str = ''.join(AZ[x] for x in CT_rev)
print(f"CT_rev: {CT_rev_str}")

# For reversed CT, where should the cribs appear?
# If encryption was applied left-to-right on a reversed PT,
# then the REVERSED CT[i] = original CT[N-1-i]
# The cribs at original positions 21-33 → in reversed: N-1-33=63 to N-1-21=75 (reversed order)
# The cribs at original positions 63-73 → in reversed: N-1-73=23 to N-1-63=33 (reversed order)

# Modified crib dict for reversed CT
rev_crib_dict = {}
for orig_pos, ch in CRIB_DICT.items():
    rev_pos = N - 1 - orig_pos
    rev_crib_dict[rev_pos] = ch

# Also try the cribs at the SAME positions (maybe the cipher is palindromic)
print(f"\nCrib positions in reversed CT: {sorted(rev_crib_dict.keys())}")

# Test all 6 variants × periods 1-26 on reversed CT
from collections import defaultdict

best_rev = []
for period in range(1, 27):
    for vname, alpha in [('AZ-Vig', AZ), ('AZ-Beau', AZ), ('AZ-VBeau', AZ),
                          ('KA-Vig', KA), ('KA-Beau', KA), ('KA-VBeau', KA)]:
        # Derive key constraints from rev_crib_dict
        key_reqs = {}
        conflict = False
        for pos, ch in rev_crib_dict.items():
            ct_ch = CT_rev_str[pos]
            key_pos = pos % period
            if 'Vig' in vname:
                req = (alpha.index(ct_ch) - alpha.index(ch)) % 26
            elif 'Beau' in vname:
                req = (alpha.index(ct_ch) + alpha.index(ch)) % 26
            else:  # VBeau
                req = (alpha.index(ch) - alpha.index(ct_ch)) % 26

            if key_pos in key_reqs:
                if key_reqs[key_pos] != req:
                    conflict = True
                    break
            else:
                key_reqs[key_pos] = req

        if not conflict:
            coverage = len(key_reqs)
            key = [key_reqs.get(i) for i in range(period)]
            key_str = ''.join(alpha[x] if x is not None else '?' for x in key)
            best_rev.append((coverage, period, vname, key_str))

print(f"\n{len(best_rev)} variants consistent with reversed CT cribs")
best_rev.sort(key=lambda x: (-x[0]/x[1], x[1]))
for cov, period, vname, key_str in best_rev[:10]:
    print(f"  {vname:<12} p={period}  cov={cov}/{period}  key={key_str}")

# ── 3. BOUSTROPHEDON READING ─────────────────────────────────────────────────
print("\n\n" + "=" * 60)
print("3. BOUSTROPHEDON reading of K4 grid rows")
print("=" * 60)

# K4 rows in the 28×31 grid:
# Row 24 (partial): cols 27-30 = CT[0:4]
# Row 25: cols 0-30 = CT[4:35]  (31 chars)
# Row 26: cols 0-30 = CT[35:66] (31 chars)
# Row 27: cols 0-30 = CT[66:97] (31 chars)
# Wait: CT starts at row 24 col 27. K4 has 97 chars total.
# Row 24: 31-27 = 4 chars → CT[0:4]
# Row 25: 31 chars → CT[4:35]
# Row 26: 31 chars → CT[35:66]
# Row 27: 31 chars → CT[66:97]

rows = [CT[:4], CT[4:35], CT[35:66], CT[66:97]]

# Boustrophedon: even rows L→R, odd rows R→L
# (or vice versa - try both)
boustroph_a = rows[0] + rows[1] + rows[2][::-1] + rows[3]  # row 26 reversed
boustroph_b = rows[0] + rows[1][::-1] + rows[2] + rows[3][::-1]  # rows 25,27 reversed
boustroph_c = rows[0][::-1] + rows[1] + rows[2][::-1] + rows[3]  # rows 24,26 reversed

for bname, bct in [('boustroph_a (row26 rev)', boustroph_a),
                    ('boustroph_b (rows25,27 rev)', boustroph_b),
                    ('boustroph_c (rows24,26 rev)', boustroph_c)]:
    bct_str = ''.join(AZ[x] for x in bct)
    # Check all variants, period 1-26
    best_hits = 0
    for period in range(1, 27):
        for vname, alpha in [('AZ-Vig', AZ), ('AZ-Beau', AZ), ('AZ-VBeau', AZ)]:
            key_reqs = {}
            conflict = False
            for pos, ch in CRIB_DICT.items():
                ct_ch = bct_str[pos]
                key_pos = pos % period
                if 'Vig' in vname:
                    req = (alpha.index(ct_ch) - alpha.index(ch)) % 26
                elif 'Beau' in vname:
                    req = (alpha.index(ct_ch) + alpha.index(ch)) % 26
                else:
                    req = (alpha.index(ch) - alpha.index(ct_ch)) % 26
                if key_pos in key_reqs:
                    if key_reqs[key_pos] != req:
                        conflict = True
                        break
                else:
                    key_reqs[key_pos] = req
            if not conflict:
                best_hits = max(best_hits, len(key_reqs))
    print(f"  {bname}: best coverage = {best_hits}/{period}")

# ── 4. PORTA CIPHER ─────────────────────────────────────────────────────────
print("\n\n" + "=" * 60)
print("4. PORTA CIPHER (standard table)")
print("=" * 60)

# Standard Porta table (Beauchamp's version, common implementation)
# Row r (key letters 2r, 2r+1) contains letter pairs that encrypt to each other
# Each row is a permutation where each pair (p, q) means p↔q
# Row 0 (A/B): NOPQRSTUVWXYZABCDEFGHIJKLM (shift 13 from A)
# Actually Porta table varies by source. Using most common version:

# Porta table: porta[r][p] = CT for row r, PT letter p
# Standard Porta (from Kasiski/Beauchamp):
PORTA_ROWS = [
    "NOPQRSTUVWXYZABCDEFGHIJKLM",  # row 0: key A or B
    "NOPQRSTUVWXYABCDEFGHIJKLMZ",  # row 1: key C or D
    "NOPQRSTUVWXABCDEFGHIJKLMYZ",  # row 2: key E or F
    "NOPQRSTUVWABCDEFGHIJKLMXYZ",  # row 3: key G or H
    "NOPQRSTUVABCDEFGHIJKLMWXYZ",  # row 4: key I or J
    "NOPQRSTUABCDEFGHIJKLMVWXYZ",  # row 5: key K or L
    "NOPQRSTABCDEFGHIJKLMUVWXYZ",  # row 6: key M or N
    "NOPQRSABCDEFGHIJKLMTUVWXYZ",  # row 7: key O or P
    "NOPQRABCDEFGHIJKLMSTUVWXYZ",  # row 8: key Q or R
    "NOPQABCDEFGHIJKLMRSTUVWXYZ",  # row 9: key S or T
    "NOPABCDEFGHIJKLMQRSTUVWXYZ",  # row 10: key U or V
    "NOABCDEFGHIJKLMPQRSTUVWXYZ",  # row 11: key W or X
    "NABCDEFGHIJKLMOPQRSTUVWXYZ",  # row 12: key Y or Z
]

# For each crib (CT[pos], PT[pos]), determine which row must be used
def porta_row_for_pair(ct_ch, pt_ch):
    """Find which Porta row maps ct_ch ↔ pt_ch. Returns row index or -1."""
    ct_idx = AZ.index(ct_ch)
    pt_idx = AZ.index(pt_ch)
    for r, row in enumerate(PORTA_ROWS):
        # In row r: AZ[i] encrypts to row[i] (and vice versa since Porta is self-reciprocal)
        # So if ct_ch = row[pt_idx] or pt_ch = row[ct_idx], this row works
        if row[pt_idx] == ct_ch:
            return r
        if row[ct_idx] == pt_ch:
            return r
    return -1

# Determine required row for each crib position
crib_rows = {}
for pos, ch in CRIB_DICT.items():
    row = porta_row_for_pair(CT_STR[pos], ch)
    crib_rows[pos] = row

print("\nRequired Porta row for each crib position:")
for pos in sorted(crib_rows):
    r = crib_rows[pos]
    key_opts = [AZ[2*r], AZ[2*r+1]] if r >= 0 else ['?', '?']
    print(f"  pos {pos}: CT={CT_STR[pos]} PT={CRIB_DICT[pos]} → row {r} (key={key_opts[0]} or {key_opts[1]})")

# For period p, key[i%p] must satisfy:
# key[i%p] in {AZ[2*row_i], AZ[2*row_i+1]} for each crib at pos i
# Check consistency: for each key position, the intersection of valid sets must be non-empty
# AND all keys at same key_pos must have same row r (since row = floor(key_idx/2))

print("\n\nPorta period analysis:")
porta_passing = []
for period in range(1, 27):
    # For each key_pos, determine required row(s)
    key_row_reqs = {}  # key_pos → set of required rows
    conflict = False

    for pos, ch in CRIB_DICT.items():
        key_pos = pos % period
        r = crib_rows[pos]
        if r < 0:
            conflict = True
            break

        if key_pos in key_row_reqs:
            if key_row_reqs[key_pos] != r:
                conflict = True
                break
        else:
            key_row_reqs[key_pos] = r

    if not conflict:
        coverage = len(key_row_reqs)
        porta_passing.append((coverage, period, dict(key_row_reqs)))
        key_str = ''.join(str(key_row_reqs.get(i, '?')) for i in range(period))
        print(f"  p={period:2d}: {coverage}/{period} key positions constrained. Rows: {key_str}")

print(f"\n{len(porta_passing)} periods pass Porta consistency check")
