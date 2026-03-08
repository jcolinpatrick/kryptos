#!/usr/bin/env python3
"""
Cipher: K4
Family: grille
Status: active
Keyspace: cardan_grille_wildcard
Last run: 2026-03-05
Best score: TBD

Comprehensive Kryptos K4 Cardan Grille Exploration Script.
Tests 30+ grille construction approaches against the 28x31 cipher grid,
extracting characters through holes and testing multiple decryption methods.
"""

import json
import math
import sys
from pathlib import Path
from itertools import product

# ─── Constants ───────────────────────────────────────────────────────────────

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

K4_CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
assert len(K4_CT) == 97, f"K4 length {len(K4_CT)} != 97"

KEYWORDS = ["KRYPTOS", "ABSCISSA", "PALIMPSEST", "SHADOW", "BERLIN", "CLOCK", "NORTHEAST"]

CRIBS = [("EASTNORTHEAST", 21), ("BERLINCLOCK", 63)]

# Self-encrypting positions (0-indexed in K4)
SELF_ENC = [(32, 'S'), (73, 'K')]

# AZ → KA permutation
AZ_TO_KA = {AZ[i]: KA[i] for i in range(26)}
KA_TO_AZ = {KA[i]: AZ[i] for i in range(26)}

# Cycle structure of AZ→KA permutation
# Build cycles
def build_cycles():
    visited = set()
    cycles = []
    for start in AZ:
        if start in visited:
            continue
        cycle = []
        c = start
        while c not in visited:
            visited.add(c)
            cycle.append(c)
            c = AZ_TO_KA[c]
        cycles.append(cycle)
    return cycles

ALL_CYCLES = build_cycles()
# C17: 17-cycle, C8: 8-cycle, C1: fixed Z
C17 = set()
C8 = set()
C1 = set()
for cyc in ALL_CYCLES:
    if len(cyc) == 17:
        C17 = set(cyc)
    elif len(cyc) == 8:
        C8 = set(cyc)
    elif len(cyc) == 1:
        C1 = set(cyc)

print(f"C17 (17-cycle): {sorted(C17)}")
print(f"C8  (8-cycle):  {sorted(C8)}")
print(f"C1  (fixed):    {sorted(C1)}")
assert len(C17) == 17 and len(C8) == 8 and len(C1) == 1

# KA indices for cycle members
C17_indices = {KA.index(c) for c in C17}
C8_indices  = {KA.index(c) for c in C8}

# ─── 28×31 Cipher Grid ───────────────────────────────────────────────────────

CIPHER_RAW = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIV",   # row 0  (31)
    "JYQTQUXQBQVYUVLLTREVJYQTMKYRDMF",   # row 1  (32? check)
    "DVFPJUDEEHZWETZYVGWHKKQETGFQJNC",   # row 2  (31)
    "EGGWHKK?DQMCPFQZDQMMIAGPFXHQRLG",  # row 3  (32 with ?)
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",   # row 4  (31)
    "QZGZLECGYUXUEENJTBJLBQCETBJDFHR",   # row 5  (31)
    "RYIZETKZEMVDUFKSJHKFWHKUWQLSZFT",   # row 6  (31)
    "IHHDDDUVH?DWKBFUFPWNTDFIYCUQZER",   # row 7  (32 with ?)
    "EEVLDKFEZMOQQJLTTUGSYQPFEUNLAVI",   # row 8  (31)
    "DXFLGGTEZFKZBSFDQVGOGIPUFXHHDRK",   # row 9  (31)
    "FFHQNTGPUAECNUVPDJMQCLQUMUNEDFQ",   # row 10 (31)
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",   # row 11 (31)
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP",   # row 12 (31)
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",   # row 13 (31)
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI",   # row 14 (31)
    "ACHTNREYULDSLLSLLNOHSNOSMRWXMNE",   # row 15 (31)
    "TPRNGATIHNRARPESLNNELEBLPIIACAE",   # row 16 (31)
    "WMTWNDITEENRAHCTENEUDRETNHAEOET",   # row 17 (31)
    "FOLSEDTIWENHAEIOYTEYQHEENCTAYCR",   # row 18 (31)
    "EIFTBRSPAMHHEWENATAMATEGYEERLBT",   # row 19 (31)
    "EEFOASFIOTUETUAEOTOARMAEERTNRTI",   # row 20 (31)
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",   # row 21 (31)
    "AECTDDHILCEIHSITEGOEAOSDDRYDLOR",   # row 22 (31)
    "ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE",   # row 23 (31)
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",   # row 24 (32 with ?)
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",   # row 25 (31)
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",   # row 26 (31)
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",   # row 27 (31)
]

# Normalize: strip to 31 chars, replacing '?' with '?'
CIPHER = []
for i, row in enumerate(CIPHER_RAW):
    # keep only first 31 chars, pad if needed
    r = row[:31]
    if len(r) < 31:
        r = r + '?' * (31 - len(r))
    CIPHER.append(r)
    if len(row) != 31:
        print(f"  Row {i:2d}: original len={len(row)}, truncated to 31: {r}")

assert all(len(r) == 31 for r in CIPHER), "Some rows not 31 chars!"
assert len(CIPHER) == 28, f"Expected 28 rows, got {len(CIPHER)}"

# ─── KA Vigenère Tableau ─────────────────────────────────────────────────────
# Row 0: header = " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD" (space + 30 chars)
# Row r (1-26): col0 = AZ[r-1], col j = KA[(r-1+j-1)%26] = KA[(r+j-2)%26]
# Row 27: footer = same as row 0

def build_tableau():
    header = " " + "ABCDEFGHIJKLMNOPQRSTUVWXYZABCD"  # 31 chars total
    assert len(header) == 31
    rows = [header]
    for r in range(1, 27):
        key_letter = AZ[r - 1]
        row = key_letter
        for j in range(1, 31):
            row += KA[(r - 1 + j - 1) % 26]
        rows.append(row)
    rows.append(header)  # footer
    return rows

TABLEAU = build_tableau()
assert len(TABLEAU) == 28
assert all(len(r) == 31 for r in TABLEAU)

# Verify: TABLEAU[r][c] for r in 1..26 c in 0..30
# cipher[r][c] == tableau[r][c] match count
matches = [(r, c) for r in range(28) for c in range(31)
           if CIPHER[r][c].isalpha() and TABLEAU[r][c].isalpha()
           and CIPHER[r][c] == TABLEAU[r][c]]
print(f"\nCipher==Tableau matches: {len(matches)} cells")
print(f"Match positions: {matches[:10]}...")

# ─── K4 Position Map ─────────────────────────────────────────────────────────
# K4 occupies: row 24 cols 27-30 (4 chars), rows 25-27 cols 0-30 (93 chars)
# Total = 4 + 3*31 = 97 ✓

K4_POSITIONS = []
for c in range(27, 31):
    K4_POSITIONS.append((24, c))
for r in range(25, 28):
    for c in range(31):
        K4_POSITIONS.append((r, c))

assert len(K4_POSITIONS) == 97
# Verify K4 chars match
k4_from_grid = ''.join(CIPHER[r][c] for r, c in K4_POSITIONS)
assert k4_from_grid == K4_CT, f"K4 grid mismatch:\n{k4_from_grid}\n{K4_CT}"
print(f"\nK4 grid verification: OK (97 chars)")

# ─── Quadgram Scorer ─────────────────────────────────────────────────────────

def load_quadgrams(path=None):
    if path is None:
        path = str(Path(__file__).resolve().parents[2] / "data" / "english_quadgrams.json")
    with open(path) as f:
        raw = json.load(f)
    # File already contains log10 probabilities
    if all(v <= 0 for v in list(raw.values())[:10]):
        floor = min(raw.values()) - 1.0
        return raw, floor
    # Otherwise treat as counts
    total = sum(raw.values())
    log_probs = {k: math.log10(v / total) for k, v in raw.items()}
    floor = math.log10(0.01 / total)
    return log_probs, floor

QG, QG_FLOOR = load_quadgrams()

def score_text(text):
    """Quadgram score per character. Higher = more English."""
    t = ''.join(c for c in text.upper() if c in AZ)
    if len(t) < 4:
        return -10.0
    s = sum(QG.get(t[i:i+4], QG_FLOOR) for i in range(len(t) - 3))
    return s / max(1, len(t) - 3)

def check_cribs(text):
    """Return list of (crib, position) found in text."""
    hits = []
    t = ''.join(c for c in text.upper() if c.isalpha())
    for crib, _ in CRIBS:
        pos = t.find(crib)
        if pos >= 0:
            hits.append((crib, pos))
    return hits

def check_self_enc(text97):
    """Check if K4[32]=S and K4[73]=K → PT same."""
    alpha_only = [c for c in text97 if c in AZ]
    ok = []
    if len(alpha_only) > 32 and alpha_only[32] == 'S':
        ok.append((32, 'S'))
    if len(alpha_only) > 73 and alpha_only[73] == 'K':
        ok.append((73, 'K'))
    return ok

# ─── Cipher Functions ────────────────────────────────────────────────────────

def ka_vig_d(ct, key):
    """KA Vigenère decrypt. Key letters looked up in KA."""
    res = []; ki = 0
    for c in ct:
        if c not in KA and c not in AZ:
            res.append(c); continue
        c_idx = KA.index(c) if c in KA else AZ.index(c)
        k = key[ki % len(key)]
        k_idx = KA.index(k) if k in KA else (AZ.index(k) if k in AZ else 0)
        res.append(KA[(c_idx - k_idx) % 26])
        ki += 1
    return ''.join(res)

def az_vig_d(ct, key):
    """AZ Vigenère decrypt."""
    res = []; ki = 0
    for c in ct:
        if c not in AZ:
            res.append(c); continue
        k = key[ki % len(key)]; k_idx = AZ.index(k)
        res.append(AZ[(AZ.index(c) - k_idx) % 26])
        ki += 1
    return ''.join(res)

def az_beau_d(ct, key):
    """AZ Beaufort decrypt: PT = (KEY - CT) % 26."""
    res = []; ki = 0
    for c in ct:
        if c not in AZ:
            res.append(c); continue
        k = key[ki % len(key)]; k_idx = AZ.index(k)
        res.append(AZ[(k_idx - AZ.index(c)) % 26])
        ki += 1
    return ''.join(res)

# ─── Fibonacci and Primes ────────────────────────────────────────────────────

def gen_fibs(limit):
    fibs = set()
    a, b = 0, 1
    while a <= limit:
        fibs.add(a)
        a, b = b, a + b
    return fibs

def gen_primes(limit):
    sieve = [True] * (limit + 1)
    sieve[0] = sieve[1] = False
    for i in range(2, int(limit**0.5) + 1):
        if sieve[i]:
            for j in range(i*i, limit+1, i):
                sieve[j] = False
    return {i for i in range(limit + 1) if sieve[i]}

TOTAL_CELLS = 28 * 31  # 868
FIBS = gen_fibs(TOTAL_CELLS)
PRIMES = gen_primes(TOTAL_CELLS)

# ─── Results Collector ───────────────────────────────────────────────────────

all_results = []  # (score, approach, extraction, key, plaintext)

SCORE_THRESHOLD = -5.0

def record(score, approach, extraction, key, pt, mask_holes=None):
    """Record a result if score is interesting."""
    if score > SCORE_THRESHOLD:
        cribs = check_cribs(pt)
        self_enc = check_self_enc(pt) if len([c for c in pt if c in AZ]) >= 74 else []
        all_results.append((score, approach, extraction, key, pt, cribs, self_enc))

# ─── Extraction Functions ─────────────────────────────────────────────────────

def extract_full_grid(mask):
    """Read all hole positions (row-major, alpha only)."""
    chars = []
    for r in range(28):
        for c in range(31):
            if mask[r][c] and CIPHER[r][c].isalpha():
                chars.append(CIPHER[r][c])
    return ''.join(chars)

def extract_k4_reorder(mask):
    """
    Rank K4 positions: holes first (row-major within), then non-holes.
    Return K4 chars in this order.
    """
    holes = [(r, c) for r, c in K4_POSITIONS if mask[r][c]]
    nonholes = [(r, c) for r, c in K4_POSITIONS if not mask[r][c]]
    ordered_pos = holes + nonholes
    return ''.join(CIPHER[r][c] for r, c in ordered_pos)

def extract_k4_holes_only(mask):
    """K4 chars at hole positions only."""
    chars = [CIPHER[r][c] for r, c in K4_POSITIONS if mask[r][c] and CIPHER[r][c].isalpha()]
    return ''.join(chars)

def extract_k4_nonholes_only(mask):
    """K4 chars at non-hole positions only."""
    chars = [CIPHER[r][c] for r, c in K4_POSITIONS if not mask[r][c] and CIPHER[r][c].isalpha()]
    return ''.join(chars)

# ─── Test Approach ────────────────────────────────────────────────────────────

def test_approach(name, mask):
    """
    Given a binary mask (28x31 list of lists of bool),
    test multiple extractions and decryptions. Record interesting results.
    """
    hole_count = sum(mask[r][c] for r in range(28) for c in range(31))
    k4_holes = sum(mask[r][c] for r, c in K4_POSITIONS)
    print(f"\n  [{name}] holes={hole_count}/{TOTAL_CELLS} ({100*hole_count//TOTAL_CELLS}%)  K4 holes={k4_holes}/97")

    # Extraction 1: Full grid (all holes, alpha only)
    full = extract_full_grid(mask)
    if len(full) >= 4:
        sc = score_text(full)
        print(f"    Full grid ({len(full)} chars): score={sc:.3f}")
        record(sc, name, "full_grid_raw", "none", full)
        for kw in KEYWORDS:
            for fn, fn_name in [(az_vig_d, "AZ-Vig"), (az_beau_d, "AZ-Beau"), (ka_vig_d, "KA-Vig")]:
                pt = fn(full, kw)
                sc2 = score_text(pt)
                if sc2 > SCORE_THRESHOLD:
                    record(sc2, name, f"full_grid_{fn_name}", kw, pt)

    # Extraction 2: K4 reorder (holes first)
    k4r = extract_k4_reorder(mask)
    if len(k4r) >= 4:
        sc = score_text(k4r)
        if sc > SCORE_THRESHOLD:
            record(sc, name, "k4_reorder_raw", "none", k4r)
        for kw in KEYWORDS:
            for fn, fn_name in [(az_vig_d, "AZ-Vig"), (az_beau_d, "AZ-Beau"), (ka_vig_d, "KA-Vig")]:
                pt = fn(k4r, kw)
                sc2 = score_text(pt)
                if sc2 > SCORE_THRESHOLD:
                    record(sc2, name, f"k4_reorder_{fn_name}", kw, pt)

    # Extraction 3: K4 holes only
    k4h = extract_k4_holes_only(mask)
    if len(k4h) >= 4:
        sc = score_text(k4h)
        if sc > SCORE_THRESHOLD:
            record(sc, name, "k4_holes_raw", "none", k4h)
        for kw in KEYWORDS:
            for fn, fn_name in [(az_vig_d, "AZ-Vig"), (az_beau_d, "AZ-Beau"), (ka_vig_d, "KA-Vig")]:
                pt = fn(k4h, kw)
                sc2 = score_text(pt)
                if sc2 > SCORE_THRESHOLD:
                    record(sc2, name, f"k4_holes_{fn_name}", kw, pt)

    # Extraction 4: K4 non-holes only
    k4nh = extract_k4_nonholes_only(mask)
    if len(k4nh) >= 4:
        sc = score_text(k4nh)
        if sc > SCORE_THRESHOLD:
            record(sc, name, "k4_nonholes_raw", "none", k4nh)
        for kw in KEYWORDS:
            for fn, fn_name in [(az_vig_d, "AZ-Vig"), (az_beau_d, "AZ-Beau"), (ka_vig_d, "KA-Vig")]:
                pt = fn(k4nh, kw)
                sc2 = score_text(pt)
                if sc2 > SCORE_THRESHOLD:
                    record(sc2, name, f"k4_nonholes_{fn_name}", kw, pt)

    # Also try complement mask
    comp_name = name + "_COMP"
    comp_full = ''.join(CIPHER[r][c] for r in range(28) for c in range(31)
                        if not mask[r][c] and CIPHER[r][c].isalpha())
    if len(comp_full) >= 4:
        sc = score_text(comp_full)
        if sc > SCORE_THRESHOLD:
            record(sc, comp_name, "full_grid_raw", "none", comp_full)
        for kw in KEYWORDS:
            for fn, fn_name in [(az_vig_d, "AZ-Vig"), (az_beau_d, "AZ-Beau"), (ka_vig_d, "KA-Vig")]:
                pt = fn(comp_full, kw)
                sc2 = score_text(pt)
                if sc2 > SCORE_THRESHOLD:
                    record(sc2, comp_name, f"full_grid_{fn_name}", kw, pt)

    # Print top score for this approach
    approach_results = [(sc, ext, kw, pt) for sc, ap, ext, kw, pt, _, _ in all_results
                        if ap in (name, comp_name)]
    if approach_results:
        approach_results.sort(reverse=True)
        best = approach_results[0]
        print(f"    Best: score={best[0]:.3f} [{best[1]}] key={best[2]} pt={best[3][:50]!r}")

# ─── Build Mask Helper ────────────────────────────────────────────────────────

def make_mask(fn):
    """Create 28x31 mask from a function (r,c) -> bool."""
    return [[bool(fn(r, c)) for c in range(31)] for r in range(28)]

# ─── APPROACH A: KA Cycle Membership ─────────────────────────────────────────

print("\n" + "="*70)
print("APPROACH A: KA Cycle Membership")
print("="*70)

# A1: cipher[r][c] in C17 → hole
mask_A1 = make_mask(lambda r, c: CIPHER[r][c] in C17)
test_approach("A1_cipher_in_C17", mask_A1)

# A2: cipher[r][c] in C8 → hole
mask_A2 = make_mask(lambda r, c: CIPHER[r][c] in C8)
test_approach("A2_cipher_in_C8", mask_A2)

# A3: tableau[r][c] in C17 → hole
mask_A3 = make_mask(lambda r, c: TABLEAU[r][c] in C17)
test_approach("A3_tableau_in_C17", mask_A3)

# A4: tableau[r][c] in C8 → hole
mask_A4 = make_mask(lambda r, c: TABLEAU[r][c] in C8)
test_approach("A4_tableau_in_C8", mask_A4)

# A5: cipher in C17 XOR tableau in C17 → hole
mask_A5 = make_mask(lambda r, c: (CIPHER[r][c] in C17) ^ (TABLEAU[r][c] in C17))
test_approach("A5_C17_xor", mask_A5)

# ─── APPROACH B: "8 Lines 73" Hypothesis ─────────────────────────────────────

print("\n" + "="*70)
print("APPROACH B: '8 Lines 73' Hypothesis")
print("="*70)

# B1: rows {0,7,14,21,24,25,26,27} all-hole (8 rows)
B1_rows = {0, 7, 14, 21, 24, 25, 26, 27}
mask_B1 = make_mask(lambda r, c: r in B1_rows)
test_approach("B1_8special_rows", mask_B1)

# B2: rows where row_index % 7 == 0 → all-hole
mask_B2 = make_mask(lambda r, c: r % 7 == 0)
test_approach("B2_mod7_rows", mask_B2)

# B3: every 8th row has holes: rows 0,8,16,24
mask_B3 = make_mask(lambda r, c: r % 8 == 0)
test_approach("B3_mod8_rows", mask_B3)

# B4: column 73 special (col 73%31 = 11)
# "73" in "8 Lines 73" → col 73 mod 31 = 11
mask_B4 = make_mask(lambda r, c: c == (73 % 31))
test_approach("B4_col73mod31", mask_B4)

# B5: flat position 73 and multiples
mask_B5 = make_mask(lambda r, c: (r*31 + c) % 73 == 0)
test_approach("B5_flat_mod73", mask_B5)

# ─── APPROACH C: Fibonacci/Prime Positions ───────────────────────────────────

print("\n" + "="*70)
print("APPROACH C: Fibonacci/Prime Positions")
print("="*70)

# C1: hole at flat position p if p is prime
mask_C1 = make_mask(lambda r, c: (r*31 + c) in PRIMES)
test_approach("C1_prime_positions", mask_C1)

# C2: hole at flat position p if p is Fibonacci
mask_C2 = make_mask(lambda r, c: (r*31 + c) in FIBS)
test_approach("C2_fibonacci_positions", mask_C2)

# C3: primes AND alpha
mask_C3 = make_mask(lambda r, c: ((r*31 + c) in PRIMES) and CIPHER[r][c].isalpha())
test_approach("C3_prime_alpha_only", mask_C3)

# ─── APPROACH D: KRYPTOS Periodic Column Key ─────────────────────────────────

print("\n" + "="*70)
print("APPROACH D: KRYPTOS Periodic Column Key")
print("="*70)

KRYPTOS = "KRYPTOS"

# D1: hole at (r,c) if KA.index(KRYPTOS[c%7]) < 13 (lower half of KA → hole)
mask_D1 = make_mask(lambda r, c: KA.index(KRYPTOS[c % 7]) < 13)
test_approach("D1_KRYPTOS_key_lower13", mask_D1)

# D2: hole at (r,c) if KRYPTOS[c%7] in C17
mask_D2 = make_mask(lambda r, c: KRYPTOS[c % 7] in C17)
test_approach("D2_KRYPTOS_col_in_C17", mask_D2)

# D3: hole at (r,c) if KRYPTOS[r%7] in C17
mask_D3 = make_mask(lambda r, c: KRYPTOS[r % 7] in C17)
test_approach("D3_KRYPTOS_row_in_C17", mask_D3)

# D4: hole if KRYPTOS[r%7] in C17 AND KRYPTOS[c%7] in C8 (or vice versa)
mask_D4 = make_mask(lambda r, c: (KRYPTOS[r % 7] in C17) and (KRYPTOS[c % 7] in C8))
test_approach("D4_KRYPTOS_rowC17_colC8", mask_D4)

# D5: KA.index(KRYPTOS[c%7]) < KA.index(KRYPTOS[r%7])
mask_D5 = make_mask(lambda r, c: KA.index(KRYPTOS[c % 7]) < KA.index(KRYPTOS[r % 7]))
test_approach("D5_KRYPTOS_col_lt_row", mask_D5)

# ─── APPROACH E: Checkerboard / Geometric ────────────────────────────────────

print("\n" + "="*70)
print("APPROACH E: Checkerboard / Geometric")
print("="*70)

# E1: (r+c) % 2 == 0 → hole
mask_E1 = make_mask(lambda r, c: (r + c) % 2 == 0)
test_approach("E1_checkerboard_rc", mask_E1)

# E2: r % 2 == 0 → hole (even rows)
mask_E2 = make_mask(lambda r, c: r % 2 == 0)
test_approach("E2_even_rows", mask_E2)

# E3: c % 2 == 0 → hole (even cols)
mask_E3 = make_mask(lambda r, c: c % 2 == 0)
test_approach("E3_even_cols", mask_E3)

# E4: (r//7 + c//7) % 2 == 0 → hole (7×7 super-checkerboard)
mask_E4 = make_mask(lambda r, c: (r // 7 + c // 7) % 2 == 0)
test_approach("E4_7x7_supercheck", mask_E4)

# E5: center region (rows 10-17, cols 8-22) → hole
mask_E5 = make_mask(lambda r, c: (10 <= r <= 17) and (8 <= c <= 22))
test_approach("E5_center_block", mask_E5)

# E6: (r*c) % 2 == 0 → hole
mask_E6 = make_mask(lambda r, c: (r * c) % 2 == 0)
test_approach("E6_product_even", mask_E6)

# ─── APPROACH F: T-Diagonal (Tableau) ────────────────────────────────────────

print("\n" + "="*70)
print("APPROACH F: T-Diagonal")
print("="*70)

# F1: tableau[r][c] == 'T' → hole
mask_F1 = make_mask(lambda r, c: TABLEAU[r][c] == 'T')
test_approach("F1_tableau_T", mask_F1)

# F2: cipher[r][c] == 'T' → hole
mask_F2 = make_mask(lambda r, c: CIPHER[r][c] == 'T')
test_approach("F2_cipher_T", mask_F2)

# F3: tableau[r][c] in 'KRYPTOS' → hole (keyword letters)
mask_F3 = make_mask(lambda r, c: TABLEAU[r][c] in set('KRYPTOS'))
test_approach("F3_tableau_KRYPTOS_letters", mask_F3)

# F4: cipher[r][c] in 'KRYPTOS' → hole
mask_F4 = make_mask(lambda r, c: CIPHER[r][c] in set('KRYPTOS'))
test_approach("F4_cipher_KRYPTOS_letters", mask_F4)

# ─── APPROACH G: XOR / Difference ────────────────────────────────────────────

print("\n" + "="*70)
print("APPROACH G: XOR / Difference Between Cipher and Tableau")
print("="*70)

def g_diff(r, c):
    ch = CIPHER[r][c]
    tb = TABLEAU[r][c]
    if not (ch.isalpha() and tb.isalpha()):
        return False
    return (KA.index(ch) - KA.index(tb)) % 26 < 13

mask_G1 = make_mask(g_diff)
test_approach("G1_KA_diff_lt13", mask_G1)

def g_diff_c17(r, c):
    ch = CIPHER[r][c]
    tb = TABLEAU[r][c]
    if not (ch.isalpha() and tb.isalpha()):
        return False
    d = (KA.index(ch) - KA.index(tb)) % 26
    return d in C17_indices

mask_G2 = make_mask(g_diff_c17)
test_approach("G2_KA_diff_in_C17idx", mask_G2)

# G3: cipher[r][c] == tableau[r][c] → hole (the 39 match positions)
mask_G3 = make_mask(lambda r, c: CIPHER[r][c].isalpha() and CIPHER[r][c] == TABLEAU[r][c])
test_approach("G3_cipher_eq_tableau", mask_G3)

# G4: AZ diff (cipher AZ index - tableau AZ index) % 26 < 13
def g_az_diff(r, c):
    ch = CIPHER[r][c]
    tb = TABLEAU[r][c]
    if not (ch in AZ and tb in AZ):
        return False
    return (AZ.index(ch) - AZ.index(tb)) % 26 < 13

mask_G4 = make_mask(g_az_diff)
test_approach("G4_AZ_diff_lt13", mask_G4)

# G5: cipher char encrypted by tableau char (as Vigenère key) == 'K' or 'A'
def g_vig_ka(r, c):
    ch = CIPHER[r][c]
    tb = TABLEAU[r][c]
    if not (ch in KA and tb in KA):
        return False
    result = KA[(KA.index(ch) - KA.index(tb)) % 26]
    return result in ('K', 'A')

mask_G5 = make_mask(g_vig_ka)
test_approach("G5_vigdecrypt_is_KA", mask_G5)

# ─── APPROACH H: Period-8 Row Pattern ────────────────────────────────────────

print("\n" + "="*70)
print("APPROACH H: Period-8 Row Pattern ('V-N=T-L=8')")
print("="*70)

# H1: row % 8 == 0 → all holes in that row
mask_H1 = make_mask(lambda r, c: r % 8 == 0)
test_approach("H1_row_mod8", mask_H1)

# H2: col % 8 == 0 → all holes in that col
mask_H2 = make_mask(lambda r, c: c % 8 == 0)
test_approach("H2_col_mod8", mask_H2)

# H3: (r+c) % 8 == 0 → hole
mask_H3 = make_mask(lambda r, c: (r + c) % 8 == 0)
test_approach("H3_sum_mod8", mask_H3)

# H4: (r*31+c) % 8 == 0 → hole
mask_H4 = make_mask(lambda r, c: (r*31 + c) % 8 == 0)
test_approach("H4_flat_mod8", mask_H4)

# H5: (r+c) % 8 < 4 → hole (half of period-8 cycles)
mask_H5 = make_mask(lambda r, c: (r + c) % 8 < 4)
test_approach("H5_sum_mod8_lt4", mask_H5)

# H6: row % 8 < 4 → hole (first half of each period-8 block of rows)
mask_H6 = make_mask(lambda r, c: r % 8 < 4)
test_approach("H6_row_mod8_lt4", mask_H6)

# ─── APPROACH I: KA Position Parity ──────────────────────────────────────────

print("\n" + "="*70)
print("APPROACH I: KA Position Parity")
print("="*70)

def ka_idx_safe(ch):
    if ch in KA:
        return KA.index(ch)
    if ch in AZ:
        return AZ.index(ch)
    return -1

# I1: KA.index(cipher[r][c]) % 2 == 0 → hole
mask_I1 = make_mask(lambda r, c: ka_idx_safe(CIPHER[r][c]) % 2 == 0 if CIPHER[r][c].isalpha() else False)
test_approach("I1_cipher_KAidx_even", mask_I1)

# I2: KA.index(tableau[r][c]) % 2 == 0 → hole
mask_I2 = make_mask(lambda r, c: ka_idx_safe(TABLEAU[r][c]) % 2 == 0 if TABLEAU[r][c].isalpha() else False)
test_approach("I2_tableau_KAidx_even", mask_I2)

# I3: (KA.index(cipher) + KA.index(tableau)) % 2 == 0 → hole
def i3_fn(r, c):
    ch = CIPHER[r][c]; tb = TABLEAU[r][c]
    if not (ch.isalpha() and tb.isalpha()):
        return False
    return (ka_idx_safe(ch) + ka_idx_safe(tb)) % 2 == 0

mask_I3 = make_mask(i3_fn)
test_approach("I3_sum_KAidx_even", mask_I3)

# I4: cipher KA index in top 13 (0..12)
mask_I4 = make_mask(lambda r, c: 0 <= ka_idx_safe(CIPHER[r][c]) < 13 if CIPHER[r][c].isalpha() else False)
test_approach("I4_cipher_KAidx_lt13", mask_I4)

# I5: tableau KA index in top 13
mask_I5 = make_mask(lambda r, c: 0 <= ka_idx_safe(TABLEAU[r][c]) < 13 if TABLEAU[r][c].isalpha() else False)
test_approach("I5_tableau_KAidx_lt13", mask_I5)

# ─── APPROACH J: Cardan 180° Constraint ──────────────────────────────────────

print("\n" + "="*70)
print("APPROACH J: Cardan 180-degree Rotation Constraint")
print("="*70)

# For each pair (r,c) <-> (27-r, 30-c), pick hole based on cipher letter KA rank
def cardan_180_mask(higher_gets_hole=True):
    mask = [[False]*31 for _ in range(28)]
    for r in range(28):
        for c in range(31):
            r2, c2 = 27 - r, 30 - c
            if r > r2 or (r == r2 and c > c2):
                continue  # already handled
            ch1 = CIPHER[r][c]
            ch2 = CIPHER[r2][c2]
            idx1 = ka_idx_safe(ch1)
            idx2 = ka_idx_safe(ch2)
            if idx1 < 0 or idx2 < 0:
                continue
            if idx1 == idx2:
                # tie: both hole or neither
                mask[r][c] = mask[r2][c2] = True
            elif (idx1 > idx2) == higher_gets_hole:
                mask[r][c] = True
                mask[r2][c2] = False
            else:
                mask[r][c] = False
                mask[r2][c2] = True
    return mask

mask_J1 = cardan_180_mask(higher_gets_hole=True)
test_approach("J1_cardan180_higher_hole", mask_J1)

mask_J2 = cardan_180_mask(higher_gets_hole=False)
test_approach("J2_cardan180_lower_hole", mask_J2)

# J3: Cardan using tableau rank
def cardan_180_tableau(higher_gets_hole=True):
    mask = [[False]*31 for _ in range(28)]
    for r in range(28):
        for c in range(31):
            r2, c2 = 27 - r, 30 - c
            if r > r2 or (r == r2 and c > c2):
                continue
            ch1 = TABLEAU[r][c]
            ch2 = TABLEAU[r2][c2]
            idx1 = ka_idx_safe(ch1)
            idx2 = ka_idx_safe(ch2)
            if idx1 < 0 or idx2 < 0:
                continue
            if idx1 == idx2:
                mask[r][c] = mask[r2][c2] = True
            elif (idx1 > idx2) == higher_gets_hole:
                mask[r][c] = True
                mask[r2][c2] = False
            else:
                mask[r][c] = False
                mask[r2][c2] = True
    return mask

mask_J3 = cardan_180_tableau(higher_gets_hole=True)
test_approach("J3_cardan180_tableau_higher", mask_J3)

mask_J4 = cardan_180_tableau(higher_gets_hole=False)
test_approach("J4_cardan180_tableau_lower", mask_J4)

# J5: Cardan using AZ diff: hole at (r,c) if AZ_diff > 0, else at (r2,c2)
def cardan_180_diff():
    mask = [[False]*31 for _ in range(28)]
    for r in range(28):
        for c in range(31):
            r2, c2 = 27 - r, 30 - c
            if r > r2 or (r == r2 and c > c2):
                continue
            ch1 = CIPHER[r][c]; ch2 = CIPHER[r2][c2]
            if not (ch1.isalpha() and ch2.isalpha()):
                continue
            d1 = AZ.index(ch1) if ch1 in AZ else 0
            d2 = AZ.index(ch2) if ch2 in AZ else 0
            if d1 >= d2:
                mask[r][c] = True
            else:
                mask[r2][c2] = True
    return mask

mask_J5 = cardan_180_diff()
test_approach("J5_cardan180_AZ_rank", mask_J5)

# ─── APPROACH K: Combo / Intersection Masks ───────────────────────────────────

print("\n" + "="*70)
print("APPROACH K: Combination / Intersection Masks")
print("="*70)

# K1: A1 AND E1 (C17 AND checkerboard)
mask_K1 = [[mask_A1[r][c] and mask_E1[r][c] for c in range(31)] for r in range(28)]
test_approach("K1_C17_AND_checkerboard", mask_K1)

# K2: A1 OR G3 (C17 OR cipher==tableau)
mask_K2 = [[mask_A1[r][c] or mask_G3[r][c] for c in range(31)] for r in range(28)]
test_approach("K2_C17_OR_cipherEQtableau", mask_K2)

# K3: D1 AND A1 (KRYPTOS col key AND C17)
mask_K3 = [[mask_D1[r][c] and mask_A1[r][c] for c in range(31)] for r in range(28)]
test_approach("K3_KRYPTOS_AND_C17", mask_K3)

# K4: Period-8 rows AND C17 letters
mask_K4m = [[mask_H1[r][c] and mask_A1[r][c] for c in range(31)] for r in range(28)]
test_approach("K4mask_period8row_AND_C17", mask_K4m)

# K5: Tableau T-holes XOR cipher C17 holes
mask_K5 = [[mask_F1[r][c] ^ mask_A1[r][c] for c in range(31)] for r in range(28)]
test_approach("K5_tableauT_XOR_C17", mask_K5)

# ─── APPROACH L: Grid-based reading patterns ──────────────────────────────────

print("\n" + "="*70)
print("APPROACH L: Grid-based / Structural Reading Patterns")
print("="*70)

# L1: K4 region (rows 24-27) all holes
mask_L1 = make_mask(lambda r, c: r >= 24)
test_approach("L1_K4_region_all", mask_L1)

# L2: K1 region (rows 0-3) all holes → read K1 region
mask_L2 = make_mask(lambda r, c: r <= 3)
test_approach("L2_K1_region_all", mask_L2)

# L3: Top half (rows 0-13) all holes
mask_L3 = make_mask(lambda r, c: r < 14)
test_approach("L3_top_half", mask_L3)

# L4: Bottom half (rows 14-27) all holes
mask_L4 = make_mask(lambda r, c: r >= 14)
test_approach("L4_bottom_half", mask_L4)

# L5: K4 region positions rotated 180 → map to K1 region, read cipher
# The 97 K4 positions rotated: (27-r, 30-c)
K4_ROTATED = [(27-r, 30-c) for r, c in K4_POSITIONS]
k4_rotated_text = ''.join(CIPHER[r][c] for r, c in K4_ROTATED if CIPHER[r][c].isalpha())
print(f"\n  [L5_K4_rotated_180] Reading cipher at K4-rotated positions:")
print(f"    Raw ({len(k4_rotated_text)} chars): {k4_rotated_text[:60]}")
sc_l5 = score_text(k4_rotated_text)
print(f"    Score: {sc_l5:.3f}")
if sc_l5 > SCORE_THRESHOLD:
    record(sc_l5, "L5_K4_rotated_180", "raw", "none", k4_rotated_text)
for kw in KEYWORDS:
    for fn, fn_name in [(az_vig_d, "AZ-Vig"), (az_beau_d, "AZ-Beau"), (ka_vig_d, "KA-Vig")]:
        pt = fn(k4_rotated_text, kw)
        sc2 = score_text(pt)
        if sc2 > SCORE_THRESHOLD:
            record(sc2, "L5_K4_rotated_180", fn_name, kw, pt)

# L6: K4 backwards
k4_rev = K4_CT[::-1]
sc_l6 = score_text(k4_rev)
print(f"\n  [L6_K4_reversed] Raw: {k4_rev[:50]} score={sc_l6:.3f}")
if sc_l6 > SCORE_THRESHOLD:
    record(sc_l6, "L6_K4_reversed", "raw", "none", k4_rev)
for kw in KEYWORDS:
    for fn, fn_name in [(az_vig_d, "AZ-Vig"), (az_beau_d, "AZ-Beau"), (ka_vig_d, "KA-Vig")]:
        pt = fn(k4_rev, kw)
        sc2 = score_text(pt)
        if sc2 > SCORE_THRESHOLD:
            record(sc2, "L6_K4_reversed", fn_name, kw, pt)

# ─── APPROACH M: Letter-value Threshold Masks ─────────────────────────────────

print("\n" + "="*70)
print("APPROACH M: Letter-Value Threshold Masks")
print("="*70)

# M1: AZ.index(cipher) < AZ.index(tableau) → hole
def m1_fn(r, c):
    ch = CIPHER[r][c]; tb = TABLEAU[r][c]
    if not (ch in AZ and tb in AZ):
        return False
    return AZ.index(ch) < AZ.index(tb)

mask_M1 = make_mask(m1_fn)
test_approach("M1_AZidx_cipher_lt_tableau", mask_M1)

# M2: AZ.index(cipher) < 13
mask_M2 = make_mask(lambda r, c: (AZ.index(CIPHER[r][c]) < 13) if CIPHER[r][c] in AZ else False)
test_approach("M2_cipher_AZ_lt13", mask_M2)

# M3: KA index of cipher < KA index of tableau → hole
def m3_fn(r, c):
    ch = CIPHER[r][c]; tb = TABLEAU[r][c]
    if not (ch in KA and tb in KA):
        return False
    return KA.index(ch) < KA.index(tb)

mask_M3 = make_mask(m3_fn)
test_approach("M3_KAidx_cipher_lt_tableau", mask_M3)

# M4: AZ.index(cipher) in {0,1,...,12} (first half) AND tableau in second half
def m4_fn(r, c):
    ch = CIPHER[r][c]; tb = TABLEAU[r][c]
    if not (ch in AZ and tb in AZ):
        return False
    return AZ.index(ch) < 13 and AZ.index(tb) >= 13

mask_M4 = make_mask(m4_fn)
test_approach("M4_cipher_firsthalf_AND_tableau_secondhalf", mask_M4)

# ─── APPROACH N: Misspelling + KA signal ─────────────────────────────────────

print("\n" + "="*70)
print("APPROACH N: Misspelling KA-signal Masks")
print("="*70)

# K from IQLUSION → K at position [56] in cipher grid (flat)
# A from DESPARATLY → A at position [89] in K3 → find in grid
# The misspelling CT letters spell KA → use K and A positions as seeds

# Find all 'K' and 'A' positions in cipher grid
K_positions = [(r, c) for r in range(28) for c in range(31) if CIPHER[r][c] == 'K']
A_positions = [(r, c) for r in range(28) for c in range(31) if CIPHER[r][c] == 'A']
print(f"  'K' in cipher: {len(K_positions)} positions")
print(f"  'A' in cipher: {len(A_positions)} positions")

# N1: cipher == 'K' → hole
mask_N1 = make_mask(lambda r, c: CIPHER[r][c] == 'K')
test_approach("N1_cipher_K", mask_N1)

# N2: cipher == 'A' → hole
mask_N2 = make_mask(lambda r, c: CIPHER[r][c] == 'A')
test_approach("N2_cipher_A", mask_N2)

# N3: cipher in {'K','A'} → hole
mask_N3 = make_mask(lambda r, c: CIPHER[r][c] in {'K', 'A'})
test_approach("N3_cipher_KA", mask_N3)

# N4: tableau == 'K' → hole
mask_N4 = make_mask(lambda r, c: TABLEAU[r][c] == 'K')
test_approach("N4_tableau_K", mask_N4)

# N5: tableau == 'A' → hole
mask_N5 = make_mask(lambda r, c: TABLEAU[r][c] == 'A')
test_approach("N5_tableau_A", mask_N5)

# ─── APPROACH O: Flat index modular patterns ──────────────────────────────────

print("\n" + "="*70)
print("APPROACH O: Flat Index Modular Patterns")
print("="*70)

# O1: flat % 26 == 0
mask_O1 = make_mask(lambda r, c: (r*31 + c) % 26 == 0)
test_approach("O1_flat_mod26", mask_O1)

# O2: flat % 13 == 0
mask_O2 = make_mask(lambda r, c: (r*31 + c) % 13 == 0)
test_approach("O2_flat_mod13", mask_O2)

# O3: flat % 31 == 0 (every 31st = start of each "row" when read as 31-wide)
mask_O3 = make_mask(lambda r, c: (r*31 + c) % 31 == 0)
test_approach("O3_flat_mod31", mask_O3)

# O4: flat % 28 == 0
mask_O4 = make_mask(lambda r, c: (r*31 + c) % 28 == 0)
test_approach("O4_flat_mod28", mask_O4)

# O5: flat % 97 == 0 (K4 length)
mask_O5 = make_mask(lambda r, c: (r*31 + c) % 97 == 0)
test_approach("O5_flat_mod97", mask_O5)

# ─── APPROACH P: Tableau row/col letter patterns ──────────────────────────────

print("\n" + "="*70)
print("APPROACH P: Tableau Row/Col Structural Patterns")
print("="*70)

# P1: KA index of tableau row-key letter < 13 (row is "first-half KA" row)
# Row key = tableau[r][0] (first column)
def p1_fn(r, c):
    row_key = TABLEAU[r][0]
    if row_key not in KA and row_key != ' ':
        return False
    if row_key == ' ':
        return False
    return KA.index(row_key) < 13

mask_P1 = make_mask(p1_fn)
test_approach("P1_tableau_rowkey_lt13", mask_P1)

# P2: tableau row key in C17
def p2_fn(r, c):
    row_key = TABLEAU[r][0]
    return row_key in C17

mask_P2 = make_mask(p2_fn)
test_approach("P2_tableau_rowkey_in_C17", mask_P2)

# P3: tableau col header letter (col 0 header = ' ABCDEFGHIJKLMNOPQRSTUVWXYZABCD')
# col c header = header[c] (where header = TABLEAU[0])
def p3_fn(r, c):
    col_header = TABLEAU[0][c]
    return col_header in C17

mask_P3 = make_mask(p3_fn)
test_approach("P3_tableau_colheader_in_C17", mask_P3)

# P4: row key C17 AND col header AZ first half
def p4_fn(r, c):
    row_key = TABLEAU[r][0]
    col_header = TABLEAU[0][c]
    if row_key not in C17:
        return False
    if col_header not in AZ:
        return False
    return AZ.index(col_header) < 13

mask_P4 = make_mask(p4_fn)
test_approach("P4_rowkey_C17_AND_colhdr_lt13", mask_P4)

# ─── SELF-ENCRYPTING CHECK ────────────────────────────────────────────────────

print("\n" + "="*70)
print("SELF-ENCRYPTING POSITION CHECK")
print("="*70)
print("Checking: K4[32]=S and K4[73]=K must map to PT[32]=S and PT[73]=K")
print("under any valid decryption.")
print()

se_results = []
for sc, ap, ext, kw, pt, cribs, self_enc in all_results:
    if len(self_enc) == 2:
        se_results.append((sc, ap, ext, kw, pt, cribs, self_enc))
        print(f"  *** SELF-ENCRYPTING BOTH *** {ap} [{ext}] key={kw} score={sc:.3f}")
        print(f"    PT: {pt[:80]}")
    elif len(self_enc) == 1:
        print(f"  Self-enc partial ({self_enc[0][1]}@{self_enc[0][0]}): {ap} [{ext}] key={kw} score={sc:.3f}")

# ─── CRIB CHECK ──────────────────────────────────────────────────────────────

print("\n" + "="*70)
print("CRIB HITS")
print("="*70)

crib_hits = [(sc, ap, ext, kw, pt, cribs, se) for sc, ap, ext, kw, pt, cribs, se in all_results if cribs]
if crib_hits:
    for sc, ap, ext, kw, pt, cribs, se in sorted(crib_hits, reverse=True):
        print(f"\n  *** CRIB HIT *** {ap} [{ext}] key={kw} score={sc:.3f}")
        print(f"    Cribs found: {cribs}")
        print(f"    PT: {pt[:80]}")
else:
    print("  No crib hits found.")

# ─── FINAL SUMMARY ───────────────────────────────────────────────────────────

print("\n" + "="*70)
print("TOP 20 RESULTS (by quadgram score)")
print("="*70)

sorted_results = sorted(all_results, reverse=True, key=lambda x: x[0])
seen = set()
unique_results = []
for entry in sorted_results:
    sc, ap, ext, kw, pt = entry[:5]
    key_sig = pt[:30]
    if key_sig not in seen:
        seen.add(key_sig)
        unique_results.append(entry)

print(f"\nTotal results above threshold ({SCORE_THRESHOLD}): {len(all_results)}")
print(f"Unique top results: {len(unique_results)}")
print()

for i, (sc, ap, ext, kw, pt, cribs, se) in enumerate(unique_results[:20], 1):
    crib_str = " *** CRIB HIT ***" if cribs else ""
    se_str = " *** SELF-ENC ***" if se else ""
    print(f"{i:2d}. [{sc:7.3f}] {ap} | {ext} | key={kw}")
    print(f"     PT: {pt[:70]}{crib_str}{se_str}")
    if cribs:
        print(f"     Cribs: {cribs}")
    if se:
        print(f"     Self-enc: {se}")
    print()

print("\n" + "="*70)
print("DONE")
print("="*70)
