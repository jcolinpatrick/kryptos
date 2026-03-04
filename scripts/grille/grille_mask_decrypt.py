#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: grille
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""Parse the user's corrected binary mask, extract from tableau, decrypt K4.

Binary mask: 0=VISIBLE (hole), 1=MASKED, ~=no mask no letter (off-grid)
"""
import sys, json, os
from collections import Counter

sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT as K4_CT

# ── Tableau (from e_grille_08, authoritative) ────────────────────────────
TABLEAU_ROWS = [
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",                # Row 1: header (31)
    "AKRYPTOSABCDEFGHIJLMNQUVWXZKRYP",                # Row 2: A (31)
    "BRYPTOSABCDEFGHIJLMNQUVWXZKRYPT",                # Row 3: B (31)
    "CYPTOSABCDEFGHIJLMNQUVWXZKRYPTO",                # Row 4: C (31)
    "DPTOSABCDEFGHIJLMNQUVWXZKRYPTOS",                # Row 5: D (31)
    "ETOSABCDEFGHIJLMNQUVWXZKRYPTOSA",                # Row 6: E (31)
    "FOSABCDEFGHIJLMNQUVWXZKRYPTOSAB",                # Row 7: F (31)
    "GSABCDEFGHIJLMNQUVWXZKRYPTOSABC",                # Row 8: G (31)
    "HABCDEFGHIJLMNQUVWXZKRYPTOSABCD",                # Row 9: H (31)
    "IBCDEFGHIJLMNQUVWXZKRYPTOSABCDE",                # Row 10: I (31)
    "JCDEFGHIJLMNQUVWXZKRYPTOSABCDEF",                # Row 11: J (31)
    "KDEFGHIJLMNQUVWXZKRYPTOSABCDEFG",                # Row 12: K (31)
    "LEFGHIJLMNQUVWXZKRYPTOSABCDEFGH",                # Row 13: L (31)
    "MFGHIJLMNQUVWXZKRYPTOSABCDEFGHI",                # Row 14: M (31)
    "NGHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",               # Row 15: N (32) extra L
    "OHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",                # Row 16: O (31)
    "PIJLMNQUVWXZKRYPTOSABCDEFGHIJLM",                # Row 17: P (31)
    "QJLMNQUVWXZKRYPTOSABCDEFGHIJLMN",                # Row 18: Q (31)
    "RLMNQUVWXZKRYPTOSABCDEFGHIJLMNQ",                # Row 19: R (31)
    "SMNQUVWXZKRYPTOSABCDEFGHIJLMNQU",                # Row 20: S (31)
    "TNQUVWXZKRYPTOSABCDEFGHIJLMNQUV",                # Row 21: T (31)
    "UQUVWXZKRYPTOSABCDEFGHIJLMNQUVW",                # Row 22: U (31)
    "VUVWXZKRYPTOSABCDEFGHIJLMNQUVWXT",               # Row 23: V (32) extra T
    "WVWXZKRYPTOSABCDEFGHIJLMNQUVWXZ",                # Row 24: W (31)
    "XWXZKRYPTOSABCDEFGHIJLMNQUVWXZK",                # Row 25: X (31)
    "YXZKRYPTOSABCDEFGHIJLMNQUVWXZKR",                # Row 26: Y (31)
    "ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY",                # Row 27: Z (31)
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",                # Row 28: footer (31)
]

# ── Parse binary mask ────────────────────────────────────────────────────
MASK_TEXT = """1    1    1    1    1    1    1    1    0    1    0    1    0    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    ~
0    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    0    1    1    1    0    1    1    1    1    0    0    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    0    1    1    0    ~    ~
1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    0    1    1    1    1    0    1    1    1    1    1    1    1    1    0    ~    ~
1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    ~    ~
0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    0    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    0    1    1    1    1    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    ~    ~
1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    ~    ~
1    1    1    1    1    0    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    0    0    1    1    1    1    1    1    1    1    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    ~
1    1    1    0    0    1    0    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    0    1    0    ~
1    1    1    1    0    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    0    ~    ~
1    1    0    1    1    0    1    1    1    1    0    0    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    0    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    0    0    1    1    1    1    1    1    1    1    0    1    1    1    1    0    1    1    1    0    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    0    1    1    0    1    1    1    1    1    1    1    0    0    1    ~    ~
1    1    1    1    1    0    1    1    0    1    1    1    1    1    1    1    0    1    0    1    0    1    1    1    0    1    1    0    1    1    0    ~    ~
1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    0    1    1    1    1    0    0    1    0    1    1    0    1    1    0    1    1    ~
1    1    1    1    1    1    1    0    0    1    1    1    1    1    1    1    1    1    1    1    0    1    0    1    0    1    1    1    1    1    1    ~    ~
0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    0    0    1    1    1    0    1    1
0    1    1    1    1    1    1    0    1    1    1    1    0    0    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    0    0    ~    ~
1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    0    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    0    1    1    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    0    1    1    1    1    1    1    0    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    0    0    ~    ~"""

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

USER_CT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"

print("=" * 80)
print("BINARY MASK EXTRACTION + K4 DECRYPTION")
print("=" * 80)

# ── Parse mask ───────────────────────────────────────────────────────────
mask_rows = MASK_TEXT.strip().split('\n')
assert len(mask_rows) == 28, f"Expected 28 rows, got {len(mask_rows)}"

visible_cells = []  # (col_1based, row_1based)
tilde_cells = []
total_zeros = 0

for row_idx, line in enumerate(mask_rows):
    row_num = row_idx + 1
    values = line.split()
    assert len(values) == 33, f"Row {row_num}: expected 33 values, got {len(values)}"

    for col_idx, val in enumerate(values):
        col_num = col_idx + 1
        if val == '0':
            visible_cells.append((col_num, row_num))
            total_zeros += 1
        elif val == '~':
            tilde_cells.append((col_num, row_num))

print(f"\nParsed mask: {total_zeros} visible (0) cells, {len(tilde_cells)} tilde (~) cells")

# ── Extract letters ──────────────────────────────────────────────────────
# Sort in reading order (row, then col)
visible_cells.sort(key=lambda c: (c[1], c[0]))

extracted = []
extraction_trace = []

for col, row in visible_cells:
    tab_row = TABLEAU_ROWS[row - 1]
    if col <= len(tab_row):
        letter = tab_row[col - 1]
        extracted.append(letter)
        extraction_trace.append((col, row, letter))
    else:
        # Out of bounds — flag but don't extract
        extraction_trace.append((col, row, '?OOB'))

extracted_str = ''.join(extracted)

print(f"\nExtracted {len(extracted_str)} letters from {total_zeros} visible cells")
print(f"Extracted: {extracted_str}")
print(f"User CT:   {USER_CT}")

# ── Compare ──────────────────────────────────────────────────────────────
min_len = min(len(extracted_str), len(USER_CT))
matches = sum(1 for i in range(min_len) if extracted_str[i] == USER_CT[i])
print(f"\nMatch: {matches}/{min_len} ({100*matches/min_len:.1f}%)")
if len(extracted_str) != len(USER_CT):
    print(f"LENGTH DIFFERS: extracted={len(extracted_str)} vs user={len(USER_CT)}")

if matches < min_len:
    print("\nMismatches:")
    for i in range(min_len):
        if extracted_str[i] != USER_CT[i]:
            c, r, l = extraction_trace[i]
            print(f"  pos {i}: extracted '{extracted_str[i]}' vs user '{USER_CT[i]}' at ({c},{r})")

# ── Frequency analysis ───────────────────────────────────────────────────
print(f"\n{'─' * 80}")
print("FREQUENCY ANALYSIS OF EXTRACTED STRING")
print(f"{'─' * 80}")
freq = Counter(extracted_str)
print(f"\nLetters present: {len(freq)}/26")
missing = set(AZ) - set(freq.keys())
print(f"MISSING letters: {missing if missing else 'none'}")

for ch in AZ:
    count = freq.get(ch, 0)
    bar = '#' * count
    marker = " *** MISSING ***" if count == 0 else ""
    print(f"  {ch}: {count:3d} {bar}{marker}")

n = len(extracted_str)
ic = sum(f * (f-1) for f in freq.values()) / (n * (n-1)) if n > 1 else 0
print(f"\nIC: {ic:.4f} (English ~0.0667, random ~0.0385)")

# ── Per-row extraction ───────────────────────────────────────────────────
print(f"\n{'─' * 80}")
print("PER-ROW EXTRACTION")
print(f"{'─' * 80}")
row_groups = {}
for c, r, l in extraction_trace:
    row_groups.setdefault(r, []).append((c, l))

for rn in sorted(row_groups.keys()):
    cells = row_groups[rn]
    letters = ''.join(l for _, l in cells if l != '?OOB')
    cols = [c for c, l in cells]
    label = TABLEAU_ROWS[rn-1][0] if TABLEAU_ROWS[rn-1][0] != ' ' else 'hdr' if rn == 1 else 'ftr'
    print(f"  Row {rn:2d} ({label:3s}): {letters:20s} cols={cols}")

# ── DECRYPTION: use extracted string as running key for K4 ──────────────
print(f"\n{'=' * 80}")
print("DECRYPTION: GRILLE EXTRACT AS RUNNING KEY FOR K4")
print(f"{'=' * 80}")

# Use the USER's string (ground truth) for decryption
GRILLE = USER_CT  # 106 chars
K4 = K4_CT        # 97 chars

def decrypt_vig(ct, key, alpha):
    return ''.join(alpha[(alpha.index(c) - alpha.index(k)) % 26] for c, k in zip(ct, key))

def decrypt_beau(ct, key, alpha):
    return ''.join(alpha[(alpha.index(k) - alpha.index(c)) % 26] for c, k in zip(ct, key))

def decrypt_vbeau(ct, key, alpha):
    return ''.join(alpha[(alpha.index(c) + alpha.index(k)) % 26] for c, k in zip(ct, key))

variants = [("Vig", decrypt_vig), ("Beau", decrypt_beau), ("VBeau", decrypt_vbeau)]
alphabets = [("AZ", AZ), ("KA", KA)]

# Crib positions
CRIB_ENE_START = 21
CRIB_ENE = "EASTNORTHEAST"
CRIB_BC_START = 63
CRIB_BC = "BERLINCLOCK"

def score_cribs(pt):
    score = 0
    for start, crib in [(CRIB_ENE_START, CRIB_ENE), (CRIB_BC_START, CRIB_BC)]:
        for i, ch in enumerate(crib):
            if start + i < len(pt) and pt[start + i] == ch:
                score += 1
    return score

def check_bean(ct_str, pt_str, alpha):
    if len(pt_str) <= 65:
        return None
    k27 = (alpha.index(ct_str[27]) - alpha.index(pt_str[27])) % 26
    k65 = (alpha.index(ct_str[65]) - alpha.index(pt_str[65])) % 26
    return k27 == k65

# Load quadgrams
quadgrams = {}
if os.path.exists("data/english_quadgrams.json"):
    with open("data/english_quadgrams.json") as f:
        quadgrams = json.load(f)

def qg_score(text):
    if not quadgrams or len(text) < 4:
        return -10
    return sum(quadgrams.get(text[i:i+4], -10.0) for i in range(len(text)-3)) / (len(text)-3)

results = []
for (vn, vf), (an, alpha) in [(v, a) for v in variants for a in alphabets]:
    for offset in range(len(GRILLE) - len(K4) + 1):
        key = GRILLE[offset:offset + len(K4)]
        pt = vf(K4, key, alpha)
        cs = score_cribs(pt)
        bean = check_bean(K4, pt, alpha)
        qg = qg_score(pt)
        results.append((cs, bean, qg, vn, an, offset, pt))

results.sort(key=lambda x: (-x[0], -x[2]))

print(f"\n{'Rank':>4} {'Crib':>5} {'Bean':>5} {'QG':>7} {'Var':>6} {'Alp':>4} {'Off':>4}  PT[0:50]")
print("─" * 100)
for i, (cs, bean, qg, vn, an, off, pt) in enumerate(results[:20]):
    b = "PASS" if bean else "FAIL" if bean is not None else "?"
    print(f"{i+1:4d} {cs:5d} {b:>5} {qg:7.3f} {vn:>6} {an:>4} {off:4d}  {pt[:50]}")

# ── Show top results with crib detail ────────────────────────────────────
print(f"\n{'─' * 80}")
print("TOP RESULTS DETAIL (crib >= 2)")
print(f"{'─' * 80}")
for cs, bean, qg, vn, an, off, pt in results:
    if cs >= 2:
        b = "PASS" if bean else "FAIL"
        print(f"\n  {vn}/{an}/off={off}: crib={cs}/24 bean={b} qg={qg:.3f}")
        print(f"  Full PT: {pt}")
        ene = pt[21:34]
        bc = pt[63:74]
        marks_e = ''.join('✓' if i < len(CRIB_ENE) and ene[i] == CRIB_ENE[i] else '·' for i in range(len(ene)))
        marks_b = ''.join('✓' if i < len(CRIB_BC) and bc[i] == CRIB_BC[i] else '·' for i in range(len(bc)))
        print(f"  ENE: {ene} ({marks_e})")
        print(f"  BC:  {bc} ({marks_b})")

# ── "T IS YOUR POSITION" ANALYSIS ───────────────────────────────────────
print(f"\n{'=' * 80}")
print("'T IS YOUR POSITION' ANALYSIS")
print(f"{'=' * 80}")
print(f"\nT count in grille extract: {GRILLE.count('T')}")
print(f"T count in K4 CT: {K4.count('T')}")
if GRILLE.count('T') == 0:
    print("\n*** CONFIRMED: Zero T's in the 106-char grille extract ***")
    print("This is notable. 'T is your position' may mean:")
    print("  1. T-positions in the tableau are systematically avoided by the grille")
    print("  2. T marks where the grille should be placed (positioning reference)")
    print("  3. T needs to be INSERTED at specific positions")

    # Find where T would appear if we extended the tableau or used different rows
    print(f"\n  Tableau row T (row 21): {TABLEAU_ROWS[20]}")
    print(f"  Row 21 visible cells: {[c for c, r in visible_cells if r == 21]}")

    # Check: what letters at row 21 visible positions?
    r21_cells = [(c, TABLEAU_ROWS[20][c-1]) for c, r in visible_cells if r == 21 and c <= len(TABLEAU_ROWS[20])]
    print(f"  Row 21 extracted letters: {r21_cells}")

    # In the FULL KA alphabet, where is T?
    print(f"\n  T in KA alphabet: position {KA.index('T')} (0-indexed)")
    print(f"  T in AZ alphabet: position {AZ.index('T')} (0-indexed)")

    # What if T-holes mean: replace extracted letter with T?
    # Or: T marks the positions that need special treatment?

# ── Wordlist check on top candidates ─────────────────────────────────────
print(f"\n{'─' * 80}")
print("WORD SEARCH IN TOP CANDIDATES")
print(f"{'─' * 80}")
# Check for common 4+ letter English words
wordfile = "wordlists/english.txt"
if os.path.exists(wordfile):
    with open(wordfile) as f:
        words = set(w.strip().upper() for w in f if len(w.strip()) >= 5)

    for cs, bean, qg, vn, an, off, pt in results[:10]:
        found = []
        for wlen in range(7, 4, -1):
            for i in range(len(pt) - wlen + 1):
                substr = pt[i:i+wlen]
                if substr in words:
                    found.append((i, substr))
        if found:
            b = "PASS" if bean else "FAIL"
            print(f"\n  {vn}/{an}/off={off} (crib={cs}, bean={b}):")
            for pos, word in found[:5]:
                print(f"    pos {pos}: {word}")

print(f"\n{'=' * 80}")
print("DONE")
print(f"{'=' * 80}")
