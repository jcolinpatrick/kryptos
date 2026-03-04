#!/usr/bin/env python3
"""
Cipher: tableau analysis
Family: tableau
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
e_tableau_comparison.py — Detailed comparison between Kryptos and Antipodes tableaux.

Analyzes structural differences, content alignment, overlay extraction,
wrapping patterns, and KA-index mappings.
"""

import math
from collections import Counter

# === CONSTANTS ===

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

assert len(KA) == 26
assert len(AZ) == 26
assert set(KA) == set(AZ)

# Kryptos tableau as given (28 rows, including header/footer with leading space)
KRYPTOS_RAW = [
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",
    "AKRYPTOSABCDEFGHIJLMNQUVWXZKRYP",
    "BRYPTOSABCDEFGHIJLMNQUVWXZKRYPT",
    "CYPTOSABCDEFGHIJLMNQUVWXZKRYPTO",
    "DPTOSABCDEFGHIJLMNQUVWXZKRYPTOS",
    "ETOSABCDEFGHIJLMNQUVWXZKRYPTOSA",
    "FOSABCDEFGHIJLMNQUVWXZKRYPTOSAB",
    "GSABCDEFGHIJLMNQUVWXZKRYPTOSABC",
    "HABCDEFGHIJLMNQUVWXZKRYPTOSABCD",
    "IBCDEFGHIJLMNQUVWXZKRYPTOSABCDE",
    "JCDEFGHIJLMNQUVWXZKRYPTOSABCDEF",
    "KDEFGHIJLMNQUVWXZKRYPTOSABCDEFG",
    "LEFGHIJLMNQUVWXZKRYPTOSABCDEFGH",
    "MFGHIJLMNQUVWXZKRYPTOSABCDEFGHI",
    "NGHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",  # 32 chars! Extra L
    "OHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",
    "PIJLMNQUVWXZKRYPTOSABCDEFGHIJLM",
    "QJLMNQUVWXZKRYPTOSABCDEFGHIJLMN",
    "RLMNQUVWXZKRYPTOSABCDEFGHIJLMNQ",
    "SMNQUVWXZKRYPTOSABCDEFGHIJLMNQU",
    "TNQUVWXZKRYPTOSABCDEFGHIJLMNQUV",
    "UQUVWXZKRYPTOSABCDEFGHIJLMNQUVW",
    "VUVWXZKRYPTOSABCDEFGHIJLMNQUVWX",
    "WVWXZKRYPTOSABCDEFGHIJLMNQUVWXZ",
    "XWXZKRYPTOSABCDEFGHIJLMNQUVWXZK",
    "YXZKRYPTOSABCDEFGHIJLMNQUVWXZKR",
    "ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY",
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",
]

# Antipodes tableau (32 rows x 33 cols, pure KA content)
ANTIPODES_RAW = [
    "KRYPTOSABCDEFGHIJLMNQUVWXZKRYPTOS",
    "RYPTOSABCDEFGHIJLMNQUVWXZKRYPTOSA",
    "YPTOSABCDEFGHIJLMNQUVWXZKRYPTOSAB",
    "PTOSABCDEFGHIJLMNQUVWXZKRYPTOSABC",
    "TOSABCDEFGHIJLMNQUVWXZKRYPTOSABCD",
    "OSABCDEFGHIJLMNQUVWXZKRYPTOSABCDE",
    "SABCDEFGHIJLMNQUVWXZKRYPTOSABCDEF",
    "ABCDEFGHIJLMNQUVWXZKRYPTOSABCDEFG",
    "BCDEFGHIJLMNQUVWXZKRYPTOSABCDEFGH",
    "CDEFGHIJLMNQUVWXZKRYPTOSABCDEFGHI",
    "DEFGHIJLMNQUVWXZKRYPTOSABCDEFGHIJ",
    "EFGHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",
    "FGHIJLMNQUVWXZKRYPTOSABCDEFGHIJLM",
    "GHIJLMNQUVWXZKRYPTOSABCDEFGHIJLMN",
    "HIJLMNQUVWXZKRYPTOSABCDEFGHIJLMNQ",
    "IJLMNQUVWXZKRYPTOSABCDEFGHIJLMNQU",
    "JLMNQUVWXZKRYPTOSABCDEFGHIJLMNQUV",
    "LMNQUVWXZKRYPTOSABCDEFGHIJLMNQUVW",
    "MNQUVWXZKRYPTOSABCDEFGHIJLMNQUVWX",
    "NQUVWXZKRYPTOSABCDEFGHIJLMNQUVWXZ",
    "QUVWXZKRYPTOSABCDEFGHIJLMNQUVWXZK",
    "UVWXZKRYPTOSABCDEFGHIJLMNQUVWXZKR",
    "VWXZKRYPTOSABCDEFGHIJLMNQUVWXZKRY",
    "WXZKRYPTOSABCDEFGHIJLMNQUVWXZKRYP",
    "XZKRYPTOSABCDEFGHIJLMNQUVWXZKRYPT",
    "ZKRYPTOSABCDEFGHIJLMNQUVWXZKRYPTO",
    "KRYPTOSABCDEFGHIJLMNQUVWXZKRYPTOS",
    "RYPTOSABCDEFGHIJLMNQUVWXZKRYPTOSA",
    "YPTOSABCDEFGHIJLMNQUVWXZKRYPTOSAB",
    "PTOSABCDEFGHIJLMNQUVWXZKRYPTOSABC",
    "TOSABCDEFGHIJLMNQUVWXZKRYPTOSABCD",
    "OSABCDEFGHIJLMNQUVWXZKRYPTOSABCDE",
]

def separator(title):
    print()
    print("=" * 80)
    print(f"  {title}")
    print("=" * 80)
    print()


def factorize(n):
    """Return prime factorization as a dict."""
    factors = {}
    d = 2
    while d * d <= n:
        while n % d == 0:
            factors[d] = factors.get(d, 0) + 1
            n //= d
        d += 1
    if n > 1:
        factors[n] = factors.get(n, 0) + 1
    return factors


def factors_str(n):
    f = factorize(n)
    parts = []
    for p in sorted(f):
        if f[p] == 1:
            parts.append(str(p))
        else:
            parts.append(f"^{f[p]}".join([str(p), ""]).rstrip(""))
            parts[-1] = f"{p}^{f[p]}"
    return " x ".join(parts)


def all_divisors(n):
    divs = []
    for i in range(1, n + 1):
        if n % i == 0:
            divs.append(i)
    return divs


# =====================================================================
# SECTION 1: STRUCTURAL COMPARISON
# =====================================================================
separator("1. STRUCTURAL COMPARISON")

print("KRYPTOS TABLEAU:")
print(f"  Rows: {len(KRYPTOS_RAW)}")
for i, row in enumerate(KRYPTOS_RAW):
    print(f"  Row {i+1:2d}: {len(row)} chars", end="")
    if len(row) != 31:
        print(f"  <-- ANOMALOUS (expected 31)", end="")
    print()
k_total = sum(len(r) for r in KRYPTOS_RAW)
print(f"  Total chars: {k_total}")
print(f"  Row lengths: {sorted(set(len(r) for r in KRYPTOS_RAW))}")

print()
print("ANTIPODES TABLEAU:")
print(f"  Rows: {len(ANTIPODES_RAW)}")
for i, row in enumerate(ANTIPODES_RAW):
    print(f"  Row {i+1:2d}: {len(row)} chars", end="")
    if len(row) != 33:
        print(f"  <-- ANOMALOUS (expected 33)", end="")
    print()
a_total = sum(len(r) for r in ANTIPODES_RAW)
print(f"  Total chars: {a_total}")
print(f"  Row lengths: {sorted(set(len(r) for r in ANTIPODES_RAW))}")

print()
print("DIMENSIONAL RELATIONSHIP:")
print(f"  Kryptos:   28 rows x ~31 cols = {k_total} total chars")
print(f"  Antipodes: 32 rows x 33 cols  = {a_total} total chars")
print(f"  Kryptos body (rows 2-27, excluding key col): 26 rows x 30 cols = {26*30}")
print(f"  Antipodes core (rows 1-26, cols 1-26):       26 rows x 26 cols = {26*26}")
print(f"  Antipodes full:                               32 rows x 33 cols = {32*33}")
print()
print(f"  Row difference:    32 - 26 body = 6 extra rows (wrap)")
print(f"  Col difference:    33 - 26 core = 7 extra cols (wrap)")
print(f"  Kryptos body cols: 30 = 26 + 4 wrap")
print(f"  Antipodes cols:    33 = 26 + 7 wrap")
print(f"  Extra wrap on Antipodes: 7 - 4 = 3 more cols, 6 - 0 = 6 more rows")


# =====================================================================
# SECTION 2: CONTENT ALIGNMENT
# =====================================================================
separator("2. CONTENT ALIGNMENT — Cell-by-cell comparison")

# Kryptos body: rows 2-27 (0-indexed: 1-26), strip first char (key column)
# Body is 26 rows, each with 30 chars (except row N which has 31)
kryptos_body = []
for i in range(1, 27):  # rows 2-27 (1-indexed) = indices 1-26
    row = KRYPTOS_RAW[i]
    body = row[1:]  # strip key column
    kryptos_body.append(body)

# Expected body construction: for key letter at AZ index i, body = KA[i:] + KA[:i], repeated to fill 30 cols
print("Verifying Kryptos body construction (key=AZ[i], body=KA shifted by i):")
print()
for i in range(26):
    key_letter = AZ[i]
    expected = (KA[i:] + KA[:i]) * 2  # double for wrap
    expected_30 = expected[:30]
    actual = kryptos_body[i]

    if i == 13:  # Row N (0-indexed 13), has extra L
        match_30 = actual[:30] == expected_30
        extra = actual[30:]
        print(f"  Row {key_letter} (AZ[{i:2d}]): first 30 chars match={match_30}, "
              f"extra char(s)='{extra}' (len={len(actual)})")
    else:
        match = actual == expected_30
        if not match:
            # Find mismatches
            mismatches = []
            for j in range(min(len(actual), len(expected_30))):
                if actual[j] != expected_30[j]:
                    mismatches.append((j, actual[j], expected_30[j]))
            print(f"  Row {key_letter} (AZ[{i:2d}]): MISMATCH at {mismatches}")
        else:
            print(f"  Row {key_letter} (AZ[{i:2d}]): OK (30 chars)")

# Compare to Antipodes
print()
print("Comparing Kryptos body to Antipodes (first 30 cols of each):")
print()

# Antipodes rows 1-26 (0-indexed 0-25) should match Kryptos body rows
# But Antipodes starts with KA[0]=K row, while Kryptos body starts with key=A (AZ[0])
# Kryptos row for key=A has body KA[0:]+KA[:0] = KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
# Antipodes row 1 starts with K = KA[0], same thing.
# So Kryptos body row i (key=AZ[i]) has shift i, and we need to find matching Antipodes row.
# Antipodes row j (0-indexed) starts at KA[j], which is shift j.
# So Kryptos body row i should match Antipodes row i.

mismatches_total = 0
for i in range(26):
    key_letter = AZ[i]
    k_row = kryptos_body[i][:30]  # first 30 chars
    a_row = ANTIPODES_RAW[i][:30]

    if k_row == a_row:
        print(f"  Kryptos row {key_letter} (body, 30 chars) == Antipodes row {i+1:2d} (first 30): MATCH")
    else:
        diffs = [(j, k_row[j], a_row[j]) for j in range(30) if k_row[j] != a_row[j]]
        print(f"  Kryptos row {key_letter} (body, 30 chars) vs Antipodes row {i+1:2d} (first 30): "
              f"{len(diffs)} MISMATCHES: {diffs}")
        mismatches_total += len(diffs)

print(f"\n  TOTAL MISMATCHES (26 body rows x 30 cols = 780 cells): {mismatches_total}")


# =====================================================================
# SECTION 3: WHAT KRYPTOS ADDS THAT ANTIPODES DOESN'T
# =====================================================================
separator("3. WHAT KRYPTOS ADDS THAT ANTIPODES DOESN'T")

# 3a. Key column analysis
print("3a. KEY COLUMN")
key_col = [KRYPTOS_RAW[i][0] for i in range(len(KRYPTOS_RAW))]
print(f"  Key column (top to bottom): {''.join(key_col)}")
print(f"  Row  1: '{key_col[0]}' (space/blank)")
print(f"  Rows 2-27: {''.join(key_col[1:27])}")
print(f"  Row 28: '{key_col[27]}' (space/blank)")
print()
print(f"  Key column letters = AZ order: {''.join(key_col[1:27])} == {AZ}")
print(f"  Match: {''.join(key_col[1:27]) == AZ}")
print()
print("  OBSERVATION: The key column uses STANDARD AZ order (A,B,C,...,Z)")
print("  But the body rows use KA-shifted content. This means:")
print("    - Row labeled 'A' contains KA shifted by 0 (starts with K)")
print("    - Row labeled 'K' contains KA shifted by 10 (starts with D)")
print("    - The labels map AZ index -> KA shift amount")
print("  If labels used KA order, row 'K' would be first (shift 0).")
print("  Using AZ labels is a CONVENTION CHOICE — it matches standard Vigenere.")

# 3b. Header/footer analysis
print()
print("3b. HEADER AND FOOTER ROWS")
header = KRYPTOS_RAW[0]
footer = KRYPTOS_RAW[27]
print(f"  Header: '{header}'")
print(f"  Footer: '{footer}'")
print(f"  Match:  {header == footer}")
print()
# Extract just the letters
header_letters = header.strip()
print(f"  Header letters: '{header_letters}' ({len(header_letters)} chars)")
print(f"  Standard AZ:    '{AZ}' (26 chars)")
print(f"  First 26 chars: '{header_letters[:26]}'")
print(f"  Match AZ:       {header_letters[:26] == AZ}")
print(f"  Last 4 chars:   '{header_letters[26:]}' (wrap: ABCD)")
print()
print("  KEY OBSERVATION: Headers use STANDARD alphabet ABCDEFGHIJ*K*LMNOPQRSTUVWXYZ")
print("  In standard alphabet, J is at position 9, K at position 10 — ADJACENT")
print("  In KA alphabet, J is at position 16, L is at position 17 — K is at position 0")
print("  So the header has J-K-L-M-N-O-P... but KA has J-L-M-N-Q...")
print()
print("  The header serves as a COLUMN INDEX for plaintext letters.")
print("  Column 1 (after key col) = A, column 2 = B, ..., column 26 = Z, cols 27-30 = A,B,C,D")
print("  This uses standard alphabet ordering — you look up your plaintext letter")
print("  in the header to find the column, then go down to the key row to find CT.")

# 3c. Extra L analysis
print()
print("3c. THE EXTRA L")
row_n = KRYPTOS_RAW[14]  # Row N (0-indexed 14 in raw, which is row 15 = key N)
print(f"  Row N (raw): '{row_n}' ({len(row_n)} chars)")
print(f"  Normal row length: 31 (1 key + 30 body)")
print(f"  Row N length:      {len(row_n)} (1 key + {len(row_n)-1} body)")
print(f"  Extra char:        '{row_n[-1]}' at position {len(row_n)-1}")
print()

# What should row N contain?
n_idx = AZ.index('N')  # 13
expected_n = KA[n_idx:] + KA[:n_idx]
print(f"  AZ index of N: {n_idx}")
print(f"  Expected body (KA shifted by {n_idx}): '{expected_n}' (26 chars)")
print(f"  Expected with 4-char wrap:              '{expected_n}{expected_n[:4]}' (30 chars)")
print(f"  Actual body:                            '{row_n[1:]}' ({len(row_n)-1} chars)")
print(f"  Actual has 5-char wrap:                 '{expected_n}{expected_n[:5]}' matches=", end="")
print(f"{row_n[1:] == expected_n + expected_n[:5]}")
print()

# L's significance
l_az = AZ.index('L')
l_ka = KA.index('L')
print(f"  L in AZ: position {l_az} (0-indexed)")
print(f"  L in KA: position {l_ka} (0-indexed)")
print(f"  L is the {l_ka+1}th letter in KA order")
print()

# Check HILL reading
print("  'HILL' downward reading on right edge:")
# Rows around N: M(row13), N(row14), O(row15), P(row16) in 0-indexed raw
for ri in [13, 14, 15, 16]:  # M, N, O, P
    row = KRYPTOS_RAW[ri]
    key = row[0]
    last_char = row[-1]
    second_last = row[-2] if len(row) > 1 else '?'
    print(f"    Row {key}: ...{row[-5:]}  (last='{last_char}', col {len(row)-1})")

print()
print("  Reading the last character of rows M, N (pos 31), O, P:")
print(f"    M[-1] = '{KRYPTOS_RAW[13][-1]}'")
print(f"    N[-1] = '{KRYPTOS_RAW[14][-1]}'")  # extra L at position 32
print(f"    N[-2] = '{KRYPTOS_RAW[14][-2]}'")  # the J at position 31
print()

# Check what columns 30 and 31 read downward
print("  Column 30 (0-indexed) reading downward through body rows:")
for i in range(1, 27):
    row = KRYPTOS_RAW[i]
    ch = row[30] if len(row) > 30 else '-'
    key = row[0]
    print(f"    Row {key}[30] = '{ch}'", end="")
    if i == 14:
        print(f"  (Row N also has [31]='{row[31]}')", end="")
    print()

print()
print("  Column 31 (0-indexed) reading downward — only Row N has this position:")
for i in range(1, 27):
    row = KRYPTOS_RAW[i]
    key = row[0]
    if len(row) > 31:
        print(f"    Row {key}[31] = '{row[31]}'")
    else:
        print(f"    Row {key}[31] = (does not exist)")


# =====================================================================
# SECTION 4: OVERLAY EXTRACTION
# =====================================================================
separator("4. OVERLAY EXTRACTION — Finding best alignment of Kryptos body in Antipodes")

# Kryptos body: 26 rows x 30 cols (row N trimmed to 30 for comparison)
k_body = []
for i in range(1, 27):
    row = KRYPTOS_RAW[i][1:31]  # strip key col, take first 30 body chars
    k_body.append(row)

print("Testing all row offsets 0-6, col offsets 0-7:")
print(f"  Kryptos body: 26 rows x 30 cols")
print(f"  Antipodes: 32 rows x 33 cols")
print(f"  Max row offset: {32-26} = 6")
print(f"  Max col offset: {33-30} = 3")
print()

best_match = (0, 0, 0)
results = []

for r_off in range(7):  # row offset 0-6
    for c_off in range(4):  # col offset 0-3
        matches = 0
        total = 0
        for r in range(26):
            a_row = r + r_off
            if a_row >= 32:
                break
            for c in range(30):
                a_col = c + c_off
                if a_col >= 33:
                    break
                total += 1
                if k_body[r][c] == ANTIPODES_RAW[a_row][a_col]:
                    matches += 1

        pct = 100.0 * matches / total if total > 0 else 0
        results.append((r_off, c_off, matches, total, pct))
        if matches > best_match[2]:
            best_match = (r_off, c_off, matches)

print(f"  {'RowOff':>6} {'ColOff':>6} {'Matches':>7} {'Total':>5} {'Pct':>7}")
print(f"  {'-'*6} {'-'*6} {'-'*7} {'-'*5} {'-'*7}")
for r_off, c_off, matches, total, pct in results:
    flag = " <-- BEST" if (r_off, c_off) == (best_match[0], best_match[1]) else ""
    print(f"  {r_off:>6} {c_off:>6} {matches:>7} {total:>5} {pct:>6.1f}%{flag}")

# Show mismatches for the best alignment
r_off, c_off = best_match[0], best_match[1]
print(f"\nMismatches at best alignment (row_off={r_off}, col_off={c_off}):")
for r in range(26):
    a_row = r + r_off
    if a_row >= 32:
        break
    for c in range(30):
        a_col = c + c_off
        if a_col >= 33:
            break
        if k_body[r][c] != ANTIPODES_RAW[a_row][a_col]:
            key_letter = AZ[r]
            print(f"  Row {key_letter} col {c}: Kryptos='{k_body[r][c]}' vs Antipodes='{ANTIPODES_RAW[a_row][a_col]}'")


# =====================================================================
# SECTION 5: THE "EXTRA" CONTENT ON ANTIPODES
# =====================================================================
separator("5. THE 'EXTRA' CONTENT ON ANTIPODES — Wrapping analysis")

print("DIMENSIONS:")
print(f"  Antipodes: 32 rows x 33 cols = {32*33}")
print(f"  Factorization of 1056: {factors_str(1056)}")
print(f"  Divisors of 1056: {all_divisors(1056)}")
print()
print(f"  Kryptos master grid: 28 x 31 = 868")
print(f"  Factorization of 868: {factors_str(868)}")
print()
print(f"  K4 length: 97 (prime)")
print(f"  K3+?+K4 = 434 = {factors_str(434)}")
print(f"  Full cipher side = 868 = {factors_str(868)}")
print()

print("WRAPPING AMOUNTS:")
print(f"  33 cols = 26 (full KA) + 7 extra")
print(f"  7 = len('KRYPTOS') = len(KA keyword)")
print(f"  32 rows = 26 (full KA) + 6 extra")
print(f"  6 = len('KRYPTOS') - 1")
print(f"  6 = index of 'S' in KA (KA[6]='S', last letter of KRYPTOS)")
print()

print("VERIFICATION — Rows 27-32 repeat rows 1-6:")
for i in range(6):
    match = ANTIPODES_RAW[26 + i] == ANTIPODES_RAW[i]
    print(f"  Row {27+i} == Row {i+1}: {match}")

print()
print("VERIFICATION — Cols 27-33 repeat cols 1-7:")
all_col_wrap = True
for r in range(32):
    for c in range(7):
        if ANTIPODES_RAW[r][26 + c] != ANTIPODES_RAW[r][c]:
            print(f"  MISMATCH: Row {r+1} col {27+c} ('{ANTIPODES_RAW[r][26+c]}') != col {c+1} ('{ANTIPODES_RAW[r][c]}')")
            all_col_wrap = False
if all_col_wrap:
    print("  All column wraps verify correctly.")

print()
print("NUMERIC RELATIONSHIPS:")
print(f"  1056 / 868 = {1056/868:.6f}")
print(f"  1056 - 868 = {1056-868}")
print(f"  gcd(1056, 868) = {math.gcd(1056, 868)}")
print(f"  1056 / 97 = {1056/97:.4f} (not integer)")
print(f"  1056 mod 97 = {1056 % 97}")
print(f"  868 / 97 = {868/97:.4f} (not integer)")
print(f"  868 mod 97 = {868 % 97}")
print(f"  33 * 32 = {33*32}")
print(f"  33 - 31 = 2 (Antipodes cols vs Kryptos header cols)")
print(f"  32 - 28 = 4 (Antipodes rows vs Kryptos total rows)")
print(f"  32 - 26 = 6 (Antipodes rows vs Kryptos body rows)")


# =====================================================================
# SECTION 6: READING PATTERN ANALYSIS
# =====================================================================
separator("6. READING PATTERN ANALYSIS — Wrap regions")

print("6a. WRAP COLUMNS (cols 27-33, i.e. indices 26-32) of Antipodes:")
print("    These are the first 7 chars of each row repeated = first 7 KA letters from each shift")
print()
wrap_cols_text = []
for r in range(32):
    wrap = ANTIPODES_RAW[r][26:33]
    wrap_cols_text.append(wrap)
    print(f"  Row {r+1:2d} wrap cols: {wrap}")

print()
print("  Reading wrap columns top-to-bottom, left-to-right:")
for c in range(7):
    col_reading = ''.join(ANTIPODES_RAW[r][26 + c] for r in range(32))
    print(f"    Wrap col {c+1} (absolute col {27+c}): {col_reading}")

print()
print("6b. WRAP ROWS (rows 27-32, indices 26-31) of Antipodes:")
for r in range(26, 32):
    print(f"  Row {r+1}: {ANTIPODES_RAW[r]}")

print()
print("  The wrap rows spell the first 6 KA shifts again:")
for r in range(6):
    ka_letter = KA[r]
    print(f"    Row {27+r} starts with KA[{r}] = {ka_letter} = '{ANTIPODES_RAW[26+r][:7]}...'")

print()
print("6c. WRAP CORNER (rows 27-32, cols 27-33) — the overlap of both wraps:")
print("     7 cols x 6 rows = 42 cells")
print(f"     42 = 2 x 3 x 7. Note: 42 = 6 x 7 = (KRYPTOS-1) x KRYPTOS")
print()
for r in range(26, 32):
    corner = ANTIPODES_RAW[r][26:33]
    print(f"  Row {r+1}, cols 27-33: {corner}")

# Check if this corner is significant
corner_text = ''.join(ANTIPODES_RAW[r][26:33] for r in range(26, 32))
print(f"\n  Corner as flat string: {corner_text}")
print(f"  Corner length: {len(corner_text)}")

# Letter frequency in corner
corner_freq = Counter(corner_text)
print(f"  Letter frequency in corner: {dict(sorted(corner_freq.items()))}")


# =====================================================================
# SECTION 7: KA-INDEX MAPPING
# =====================================================================
separator("7. KA-INDEX MAPPING")

# Build KA index lookup
ka_idx = {ch: i for i, ch in enumerate(KA)}

print("KA alphabet: " + KA)
print("KA indices:  " + " ".join(f"{i:2d}" for i in range(26)))
print("AZ alphabet: " + AZ)
print()

# Map each AZ letter to its KA index
print("7a. AZ-to-KA index mapping:")
print(f"  {'AZ_letter':>10} {'AZ_idx':>6} {'KA_idx':>6}")
for i, ch in enumerate(AZ):
    print(f"  {ch:>10} {i:>6} {ka_idx[ch]:>6}")

print()
print("7b. HEADER ROW KA-INDEX SEQUENCE:")
header_body = KRYPTOS_RAW[0][1:]  # strip leading space
print(f"  Header body: '{header_body}' ({len(header_body)} chars)")
print()

header_ka_indices = []
for i, ch in enumerate(header_body):
    ki = ka_idx[ch]
    header_ka_indices.append(ki)

print(f"  Positions:  {' '.join(f'{i:3d}' for i in range(len(header_body)))}")
print(f"  Letters:    {' '.join(f'{ch:>3}' for ch in header_body)}")
print(f"  KA indices: {' '.join(f'{ki:3d}' for ki in header_ka_indices)}")

print()
print("  First 26 KA indices (one full AZ cycle):")
first26 = header_ka_indices[:26]
print(f"    {first26}")
print()

# Check for patterns
print("  Consecutive differences:")
diffs = [header_ka_indices[i+1] - header_ka_indices[i] for i in range(len(header_ka_indices)-1)]
print(f"    First 26 diffs: {diffs[:26]}")
print(f"    Last 4 diffs (wrap): {diffs[25:]}")
print()

# The AZ->KA index mapping is itself a permutation
print("  The AZ->KA index mapping as a permutation (position i in AZ maps to KA index):")
az_to_ka_perm = [ka_idx[AZ[i]] for i in range(26)]
print(f"    {az_to_ka_perm}")
print()

# Check if it's a known mathematical function
print("  Is this a simple affine function? a*i + b mod 26?")
for a in range(1, 26):
    if math.gcd(a, 26) != 1:
        continue
    for b in range(26):
        test = [(a * i + b) % 26 for i in range(26)]
        if test == az_to_ka_perm:
            print(f"    YES: KA_idx = ({a} * AZ_idx + {b}) mod 26")
            break
    else:
        continue
    break
else:
    print("    NO — not an affine function mod 26")

print()
print("  Cycle structure of the AZ->KA permutation:")
visited = [False] * 26
cycles = []
for start in range(26):
    if visited[start]:
        continue
    cycle = []
    cur = start
    while not visited[cur]:
        visited[cur] = True
        cycle.append(AZ[cur])
        cur = az_to_ka_perm[cur]
    if len(cycle) > 1:
        cycles.append(cycle)
    elif len(cycle) == 1:
        cycles.append(cycle)

print(f"    Number of cycles: {len(cycles)}")
for i, cyc in enumerate(cycles):
    letters = " -> ".join(cyc) + " -> " + cyc[0]
    print(f"    Cycle {i+1} (len {len(cyc)}): ({letters})")

# Fixed points
fixed = [AZ[i] for i in range(26) if az_to_ka_perm[i] == i]
print(f"    Fixed points (AZ_idx == KA_idx): {fixed if fixed else 'NONE'}")

print()
print("7c. KEY COLUMN KA-INDEX SEQUENCE:")
print("  Key column letters: blank, A, B, C, ..., Z, blank")
print("  KA indices of key column body (A-Z in AZ order):")
key_ka_indices = [ka_idx[AZ[i]] for i in range(26)]
print(f"    {key_ka_indices}")
print(f"  (Same as header mapping — both use AZ order)")

print()
print("7d. COMPLETE KRYPTOS TABLEAU KA-INDEX GRID:")
print("  (Space/blank = -1, letters = KA index)")
print()
print(f"  {'':>3}", end="")
for c in range(31):
    print(f"{c:>3}", end="")
print()

for i, row in enumerate(KRYPTOS_RAW):
    print(f"  {i+1:2d}:", end="")
    for j, ch in enumerate(row):
        if ch == ' ':
            print(f" -1", end="")
        else:
            print(f"{ka_idx[ch]:3d}", end="")
    print()

print()
print("7e. DIAGONAL PATTERNS IN KA-INDEX GRID:")
print("  In the body (rows 2-27, cols 2-31), KA indices should form a simple pattern.")
print("  Each body cell at (row r, col c) in the body should have KA index = (r + c) mod 26")
print("  where r = AZ index of key letter, c = AZ index of plaintext letter... but using KA shifts.")
print()
print("  Actually, body[r][c] = KA[(AZ_idx_of_key + c) mod 26]")
print("  So KA_idx of body[r][c] = (AZ_idx_of_key + c) mod 26")
print()
print("  Verification (first 5 body rows, first 10 cols):")
for i in range(5):
    key = AZ[i]
    key_az_idx = i
    print(f"    Row {key}: ", end="")
    for c in range(10):
        actual_ch = kryptos_body[i][c]
        actual_ki = ka_idx[actual_ch]
        expected_ki = (key_az_idx + c) % 26
        match = "OK" if actual_ki == expected_ki else "!!"
        print(f"{actual_ch}({actual_ki:2d}/{expected_ki:2d}{match}) ", end="")
    print()


# =====================================================================
# SUMMARY
# =====================================================================
separator("SUMMARY OF FINDINGS")

print("""
1. STRUCTURAL:
   - Kryptos: 28 rows (2 header/footer + 26 body) x 31 cols (1 key + 30 body)
   - Antipodes: 32 rows (26 + 6 wrap) x 33 cols (26 + 7 wrap)
   - Both contain the same 26x26 core KA Vigenere tableau

2. CONTENT ALIGNMENT:
   - Kryptos body (26 rows x 30 cols) aligns perfectly with Antipodes rows 1-26,
     cols 1-30, with ZERO mismatches (except row N's extra L position)
   - The two tableaux are THE SAME underlying mathematical object

3. KRYPTOS-ONLY ELEMENTS:
   a) Key column: AZ-ordered (A,B,...,Z), NOT KA-ordered
      - This is a standard Vigenere convention (key letter = row label)
   b) Header/footer: STANDARD alphabet (ABCDEFGHIJKLMNOPQRSTUVWXYZ+ABCD)
      - Uses all 26 standard letters including J adjacent to K
      - Acts as plaintext column index
      - Notable: mixes two alphabets (AZ header + KA body)
   c) Extra L on row N: creates 31-body-char row (all others have 30)
      - L = KA[17], AZ[11]
      - Creates "HILL" downward reading possibility
      - ABSENT from Antipodes — confirmed intentional

4. OVERLAY:
   - Best alignment at row_off=0, col_off=0 gives perfect match
   - The Kryptos body IS the top-left 26x30 of the Antipodes tableau

5. WRAPPING:
   - 33 = 26 + 7 (7 = KRYPTOS length)
   - 32 = 26 + 6 (6 = KRYPTOS length - 1)
   - 1056 = 2^5 x 3 x 11. No obvious relationship to 868 or 97
   - The wrap corner (6x7=42 cells) contains KA cyclic shifts — pure repetition

6. KA-INDEX PATTERNS:
   - The AZ->KA permutation is NOT an affine function mod 26
   - It has a complex cycle structure determined by the KRYPTOS keyword insertion
   - Header KA indices follow the same non-linear permutation
   - Body cell KA indices follow: idx = (AZ_key_position + column) mod 26
""")
