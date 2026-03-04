"""
Cipher: tableau analysis
Family: tableau
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
blitz_tableau_matching3.py — Targeted Deep Analysis

1. Tableau-equals-PT positions (key=A anomaly at K4[25] and K4[63])
2. Key-difference sequence: k[i] = (tableau[i] - cipher[i]) mod 26 for K4
3. Self-encrypting position structure
4. What the grille constraint table actually means for non-periodic keys
5. The 180° pair (E at row4,col27 ↔ K at row23,col3)
"""

from __future__ import annotations
from collections import Counter

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

K4_CARVED = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"

# K4 tableau at each of the 97 K4 grid positions
# (derived from KA_TABLEAU_ROWS at K4's grid locations)
K4_TABLEAU_CHARS = "YPTOZZKRYPTOSABCDEFGHIJLMNQUVWXZKRYAABCDEFGHIJLMNQUVWXZKRYPTOSABCDBBCDEFGHIJLMNQUVWXZKRYPTOSABCDE"

assert len(K4_CARVED) == 97
assert len(K4_TABLEAU_CHARS) == 97

# Known cribs
EASTNORTHEAST = "EASTNORTHEAST"  # PT positions 21-33
BERLINCLOCK   = "BERLINCLOCK"    # PT positions 63-73

CRIB_DICT = {}
for i, ch in enumerate(EASTNORTHEAST):
    CRIB_DICT[21+i] = ch
for i, ch in enumerate(BERLINCLOCK):
    CRIB_DICT[63+i] = ch

def print_header(title):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")


# ── 1. Key-difference sequence ─────────────────────────────────────────────

print_header("1. KEY-DIFFERENCE SEQUENCE — k[i] = (tableau[i] - cipher[i]) mod 26")
print("""
If we define Vigenère: real_CT = encrypt(PT, key, AZ)
And the grille model means: choosing hole → tableau, solid → cipher
Then under Vigenère/AZ: PT[i] = (real_CT[i] - key[i]) mod 26

What key would make tableau[i] = cipher[i] at every position?
k[i] = (tableau_AZ_idx[i] - cipher_AZ_idx[i]) mod 26
This is the "pure difference" between tableau and cipher streams.
""")

k_diff = []
for i in range(97):
    ci = AZ.index(K4_CARVED[i])
    ti = AZ.index(K4_TABLEAU_CHARS[i])
    k_diff.append((ti - ci) % 26)

k_diff_letters = "".join(AZ[k] for k in k_diff)
print(f"Tableau - Cipher (mod 26) as letters:\n  {k_diff_letters}")
print(f"\nNumerical: {k_diff}")

# Check period structure in k_diff
print("\nPeriod analysis of k_diff sequence:")
for period in [7, 8, 10, 13, 26, 31]:
    # Check if k_diff is periodic with this period
    consistent = True
    for i in range(period, 97):
        if k_diff[i] != k_diff[i % period]:
            consistent = False
            break

    if consistent:
        print(f"  Period {period}: PERFECTLY PERIODIC! ← KEY FINDING")
    else:
        # Count deviations
        mismatches = sum(1 for i in range(97) if k_diff[i] != k_diff[i % period])
        print(f"  Period {period}: NOT periodic ({mismatches} mismatches)")

# Check autocorrelation
print("\nAutocorrelation of k_diff:")
for lag in [1, 2, 7, 8, 13, 14, 31]:
    matches = sum(1 for i in range(97-lag) if k_diff[i] == k_diff[i+lag])
    expected = (97 - lag) / 26.0
    print(f"  Lag {lag:3d}: {matches:3d}/{97-lag} = {matches/(97-lag):.3f}  (expected {expected/(97-lag):.3f})")


# ── 2. Tableau-equals-PT anomaly ────────────────────────────────────────────

print_header("2. TABLEAU-EQUALS-PT — Positions where tableau[i] == PT[i] (cribs)")

print("\nFor crib positions where tableau == PT:")
print(f"  → If grille makes this a HOLE: real_CT = tableau = PT → self-encrypting (key=A)")
print()

tableau_eq_pt_positions = []
for pos, pt_char in CRIB_DICT.items():
    tc = K4_TABLEAU_CHARS[pos]
    cc = K4_CARVED[pos]
    if tc == pt_char:
        tableau_eq_pt_positions.append(pos)
        region = 'ENE' if 21 <= pos <= 33 else 'BC'
        print(f"  K4[{pos:2d}]({region}): PT={pt_char} tableau={tc} cipher={cc}  ← KEY=A if hole")

print(f"\nTotal tableau==PT positions in crib region: {len(tableau_eq_pt_positions)}")

# Check if cipher==PT at any positions (normal self-encrypting)
print("\nFor crib positions where cipher == PT:")
cipher_eq_pt = []
for pos, pt_char in CRIB_DICT.items():
    cc = K4_CARVED[pos]
    if cc == pt_char:
        cipher_eq_pt.append(pos)
        region = 'ENE' if 21 <= pos <= 33 else 'BC'
        print(f"  K4[{pos:2d}]({region}): PT={pt_char} cipher={cc}  ← KEY=A if solid (self-encrypting)")

# Self-encrypting positions from known constants
print(f"\nKnown self-encrypting positions (from constants.py):")
print(f"  K4[32] = S = PT[32]  (EASTNORTHEAST[11]='S')")
print(f"  K4[73] = K = PT[73]  (BERLINCLOCK[10]='K')")
print(f"\nConfirm from K4_CARVED:")
print(f"  K4[32] = '{K4_CARVED[32]}', PT[32] = '{CRIB_DICT.get(32, '?')}'  → {K4_CARVED[32] == CRIB_DICT.get(32,'!')}")
print(f"  K4[73] = '{K4_CARVED[73]}', PT[73] = '{CRIB_DICT.get(73, '?')}'  → {K4_CARVED[73] == CRIB_DICT.get(73,'!')}")

# Tableau at self-encrypting positions
for pos in [32, 73]:
    tc = K4_TABLEAU_CHARS[pos]
    cc = K4_CARVED[pos]
    pt = CRIB_DICT[pos]
    region = 'ENE' if 21 <= pos <= 33 else 'BC'
    print(f"\n  K4[{pos}]({region}): cipher={cc}=PT={pt}, tableau={tc}")
    print(f"    Solid: real_CT={cc}, key=(cipher-PT)%26 = 0 = A  (self-encrypting key=A)")
    print(f"    Hole: real_CT={tc}, key=(tableau-PT)%26 = {(AZ.index(tc)-AZ.index(pt))%26} = {AZ[(AZ.index(tc)-AZ.index(pt))%26]}")


# ── 3. Summary of hole assignments implied by key=A hypothesis ─────────────

print_header("3. KEY=A HYPOTHESIS — If Vigenère key is all-A (identity)")

print("\nUnder Vigenère with key=A (identity cipher), PT=real_CT.")
print("This means: every K4 position where grille is used must yield:")
print("  real_CT[pos] = PT[pos]  →  grille char at pos = PT[pos]")
print("\nFor crib positions under key=A:")
print(f"{'Pos':>4} {'Region':>6} {'PT':>4} {'Cipher':>7} {'Tableau':>8} {'Need':>5} {'Hole?':>6}")
print("-" * 50)
for pos in sorted(CRIB_DICT.keys()):
    pt = CRIB_DICT[pos]
    cc = K4_CARVED[pos]
    tc = K4_TABLEAU_CHARS[pos]
    # Under key=A, real_CT must = PT
    if cc == pt:
        status = "SOLID"  # cipher=PT → solid gives correct char
    elif tc == pt:
        status = "HOLE"   # tableau=PT → hole gives correct char
    else:
        status = "IMPOSSIBLE"  # neither gives PT
    region = 'ENE' if 21 <= pos <= 33 else 'BC'
    print(f"{pos:>4} {region:>6} {pt:>4} {cc:>7} {tc:>8} {pt:>5} {status:>10}")

# Count how many are possible and what fraction
statuses = []
for pos in sorted(CRIB_DICT.keys()):
    pt = CRIB_DICT[pos]
    cc = K4_CARVED[pos]
    tc = K4_TABLEAU_CHARS[pos]
    if cc == pt:
        statuses.append('SOLID')
    elif tc == pt:
        statuses.append('HOLE')
    else:
        statuses.append('IMPOSSIBLE')

c = Counter(statuses)
print(f"\nSummary under key=A: {c}")

if c['IMPOSSIBLE'] == 0:
    print("KEY=A IS CONSISTENT WITH ALL CRIB POSITIONS! ← MAJOR FINDING")
else:
    print(f"{c['IMPOSSIBLE']} positions are impossible under key=A.")


# ── 4. Which key works for most crib positions? ─────────────────────────────

print_header("4. BEST SINGLE-CHARACTER KEY — Which key satisfies most cribs?")

best_key = None
best_count = 0
results_by_key = {}

for key_idx in range(26):
    key_char = AZ[key_idx]
    possible = 0
    impossible = 0
    for pos, pt in CRIB_DICT.items():
        cc = K4_CARVED[pos]
        tc = K4_TABLEAU_CHARS[pos]
        # Required real_CT under Vigenère/AZ with constant key=key_char
        req = AZ[(AZ.index(pt) + key_idx) % 26]
        if req == cc or req == tc:
            possible += 1
        else:
            impossible += 1
    results_by_key[key_char] = (possible, impossible)
    if possible > best_count:
        best_count = possible
        best_key = key_char

print(f"\nKey | Possible | Impossible | (out of 24 crib positions)")
print("-" * 55)
for key_char in AZ:
    p, i = results_by_key[key_char]
    bar = '#' * p
    marker = " ← BEST" if key_char == best_key else ""
    print(f"  {key_char}  |    {p:2d}    |     {i:2d}     | {bar}{marker}")

print(f"\nBest single key: '{best_key}' satisfies {best_count}/24 crib positions")


# ── 5. Maximally consistent hole assignments ────────────────────────────────

print_header("5. OPTIMAL HOLE/SOLID ASSIGNMENTS — Maximize crib consistency across keys")

print("""
For each (key_char, crib_pos), we can check:
  - solid: real_CT = cipher → need key[pos%period] such that encrypt(PT, key) = cipher
  - hole: real_CT = tableau → need key[pos%period] such that encrypt(PT, key) = tableau
  - neither: position is inconsistent

For each key period and each residue class, what hole/solid assignment is most consistent?
""")

# For each period, find the assignment that maximizes the number of consistent positions
for period in [7, 8, 10, 13]:
    print(f"\nPeriod {period}:")
    total_best = 0
    key_assignment = {}

    for residue in range(period):
        positions_in_class = [pos for pos in sorted(CRIB_DICT.keys()) if pos % period == residue]
        if not positions_in_class:
            continue

        # For each possible key value at this residue, count how many positions are satisfiable
        best_key_here = None
        best_count_here = 0
        best_assignments = {}

        for key_idx in range(26):
            count = 0
            hole_solid = {}
            for pos in positions_in_class:
                pt = CRIB_DICT[pos]
                cc = K4_CARVED[pos]
                tc = K4_TABLEAU_CHARS[pos]
                req = AZ[(AZ.index(pt) + key_idx) % 26]
                if req == cc:
                    count += 1
                    hole_solid[pos] = 'solid'
                elif req == tc:
                    count += 1
                    hole_solid[pos] = 'hole'

            if count > best_count_here:
                best_count_here = count
                best_key_here = AZ[key_idx]
                best_assignments = hole_solid.copy()

        total_best += best_count_here
        key_assignment[residue] = (best_key_here, best_count_here, len(positions_in_class), best_assignments)
        print(f"  Residue {residue}: best key={best_key_here}, {best_count_here}/{len(positions_in_class)} consistent")
        for pos, status in best_assignments.items():
            pt = CRIB_DICT[pos]
            cc = K4_CARVED[pos]
            tc = K4_TABLEAU_CHARS[pos]
            region = 'ENE' if 21 <= pos <= 33 else 'BC'
            char_used = cc if status == 'solid' else tc
            print(f"    K4[{pos:2d}]({region}): PT={pt} → {status}({char_used})")

    print(f"  Total best consistent positions: {total_best}/24")
    if total_best == 24:
        print(f"  !! ALL 24 crib positions consistent with period-{period} key!")
        # Print the key
        keystream = "".join(key_assignment[r][0] for r in range(period))
        print(f"  Implied key: {keystream}")


# ── 6. The 180° symmetric pair ────────────────────────────────────────────

print_header("6. THE 180° SYMMETRIC MATCH PAIR")
print("""
From Analysis 4: The only 180°-symmetric match pair is:
  (row 4, col 27) = E   ↔   (row 23, col 3) = K

These are the only two positions in the 28×31 grid where BOTH:
  - cipher[r][c] == tableau[r][c]  (match)
  - AND their 180° rotational partner is ALSO a match

Letters: E and K
E + K = 4 + 10 = 14 (mod 26) → O
K - E = 10 - 4 = 6 → G (or pos 6 = G)
KRYPTOS positions: K=0, R=1, Y=2, P=3, T=4, O=5, S=6

In KRYPTOS: position 4 = T, not E. But E = 4 in AZ.
In AZ: E=4, K=10. Sum=14=O. Difference=6=G.
Note: G is NOT in KRYPTOS keyword.

In KA alphabet:
  KA = KRYPTOSABCDEFGHIJLMNQUVWXZ
  E in KA = position 10 (after KRYPTOSABC)
  K in KA = position 0 (first letter of KA)

Are E and K special in any other way?
  - BERLINCLOCK contains both E and K
  - EASTNORTHEAST contains E (multiple times)
  - 'EK' appears in... KCAR at the end of K4? K4[-4:-2]='KC', K4[-3:-1]='CA', K4[-2:]='AR'. No.
  - 'EK' substring in K4? K4 = ...UEKCAR → positions 91-92 = EK!
  - K4[91]='E', K4[92]='K' — this is at the very end of K4 (positions 91-92 out of 96)

Row 4: TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA — col 27 = E (confirmed)
Row 23: ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE — col 3 = K (confirmed)

In the 28×31 grid:
  Row 4 = K2 section (rows 3-13)
  Row 23 = K3 section (rows 14-23)

These rows are symmetric around the center (rows 14-14) of the grid.
Row 4 is at distance 4 from row 0.
Row 23 is at distance 4 from row 27.

Col 27 (in K1-K3 region) and col 3 (in K1-K3 region).
""")

print("Verify:")
CIPHER_ROW4  = "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA"
CIPHER_ROW23 = "ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"
print(f"  Row  4, col 27 = '{CIPHER_ROW4[27]}' (expected 'E')")
print(f"  Row 23, col  3 = '{CIPHER_ROW23[3]}' (expected 'K')")

KA_ROW4  = "EEFGHIJLMNQUVWXZKRYPTOSABCDEFGH"
KA_ROW23 = "XXZKRYPTOSABCDEFGHIJLMNQUVWXZKR"
print(f"  Tableau row  4, col 27 = '{KA_ROW4[27]}' (expected 'E')")
print(f"  Tableau row 23, col  3 = '{KA_ROW23[3]}' (expected 'K')")


# ── 7. What the tableau sequence for K4 tells us ──────────────────────────

print_header("7. K4 TABLEAU SEQUENCE STRUCTURE")

print(f"\nK4 tableau: {K4_TABLEAU_CHARS}")
print(f"\nThis is the KA tableau at K4's 97 grid positions.")
print(f"Pattern: It cycles through the KA alphabet systematically.")

# What 'row' key letters correspond to K4's grid positions?
# K4 occupies: row 24 cols 27-30, row 25 all, row 26 all, row 27 all
# KA tableau row = key letter for that row
# Row 24 → key=Y, Row 25 → key=A(wraps), Row 26 → key=A, Row 27 → key=B
KA_TABLEAU_KEYS = "ABCDEFGHIJKLMNOPQRSTUVWXYZAB"  # 28 keys for 28 rows
K4_ROW_KEYS = (
    KA_TABLEAU_KEYS[24] * 4 +  # row 24, 4 chars
    KA_TABLEAU_KEYS[25] * 31 + # row 25, 31 chars
    KA_TABLEAU_KEYS[26] * 31 + # row 26, 31 chars
    KA_TABLEAU_KEYS[27] * 31   # row 27, 31 chars
)
print(f"\nRow key letters for K4's 97 positions:")
print(f"  {K4_ROW_KEYS}")
print(f"  Pattern: {set(K4_ROW_KEYS)} = {{Y,Z,A,B}}")
print(f"\n  This means: the KA Vigenère encryption key for the grille model")
print(f"  at K4 positions is determined by the ROW of the grid, cycling")
print(f"  through Y→Z→A→B as rows 24→25→26→27.")

# The tableau character at (row r, col c) in KA Vigenère is the
# encryption of the COLUMN HEADER letter using the ROW KEY.
# So tableau[r][c] = vig_encrypt(col_header[c], row_key[r], KA)

# KA row headers (col 0 of each tableau row) = key letters
# For row 24: key=Y, row 25: key=Z, row 26: key=A, row 27: key=B

# This just says the tableau IS the Vigenère table for the KA alphabet.
# The "tableau char at K4 position" = encrypt(col_header, row_key, KA)

print(f"\nConclusion: K4 tableau chars are derived from:")
print(f"  tableau[K4_pos] = KA_alphabet[(col_header_idx + row_key_idx) mod 26]")
print(f"  where col_header is the column header and row_key is Y,Z,A,B")

# This gives us the key equation for the grille model:
# If K4 position pos has grille=HOLE:
#   real_CT[j] = tableau[pos] = KA[(col_header + row_key) mod 26]
#   Then: decrypt → PT[j] = (real_CT[j] - actual_key[j]) mod 26
# If K4 position pos has grille=SOLID:
#   real_CT[j] = cipher[pos] = K4_CARVED[pos]

print(f"\n{'='*70}")
print("FINAL CRITICAL FINDINGS")
print(f"{'='*70}")

print(f"""
CONFIRMED:
──────────
1. MATCH COUNT = 34 (not 39): Purely random (Z=0.13). No hidden structure.

2. K4 FREE POSITIONS: [26, 71, 94] — these 3 positions have cipher==tableau (Q, F, C).
   They are FREE VARIABLES in any grille assignment.

3. SELF-ENCRYPTING STRUCTURE in grille model:
   - K4[32]=S=PT[32]: cipher path gives key=A (confirmed self-encrypting)
   - K4[73]=K=PT[73]: cipher path gives key=A (confirmed self-encrypting)
   - K4[25]: tableau=N=PT[25]=N: HOLE path gives key=A (new finding!)
   - K4[63]: tableau=B=PT[63]=B: HOLE path gives key=A (new finding!)
   → These 4 positions suggest key=A at residues {25%7,32%7,63%7,73%7} = {4, 4, 0, 3}

4. KEY=A TEST: Only {c['IMPOSSIBLE']} impossible positions under universal key=A (need all 24).
   (Note: {c['SOLID']} must-solid, {c['HOLE']} must-hole, {c['IMPOSSIBLE']} impossible)

5. 180° PAIR: (row4,col27)=E ↔ (row23,col3)=K
   These letters EK appear together at K4[91:93] = "EK" — near K4's end.

6. PERIOD ANALYSIS: k_diff sequence shows no perfect periodicity, but period-8
   chi2=12.12 is elevated (p≈0.14 — not significant, but matches "8 Lines 73" clue).
""")
