#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: grille
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
blitz_grille_mask.py — Systematic Cardan Grille Mask Construction

PARADIGM (2026-03-04):
  The cipher panel (28×31 = 868 cells) sits ON TOP of the KA Vigenère tableau.
  A Cardan grille mask determines which cells are HOLES (tableau shows through)
  and which are SOLID (cipher text visible).

  PT → Cipher(key) → real_CT → SCRAMBLE(σ) → carved text

  The grille defines the scrambling permutation σ.

KEY STRUCTURAL FACTS:
  - 28×31 = 868 = 4×7×31. K3 center at row 14.
  - 180° rotation: (r,c) → (27-r, 30-c) maps K1+K2 ↔ K3+K4
  - K3 PT and CT are BOTH KNOWN → perfect test case
  - 39 cells where cipher[r][c] == tableau[r][c]
  - K4 has 9 positions with Y, A, R (potentially grille holes)

APPROACHES:
  A. 180° rotation grille analysis (structural constraint)
  B. K3 verification (known PT+CT to test any grille theory)
  C. Match-based seeding (39 cipher=tableau positions)
  D. YAR positions in K4
  E. Exhaustive small hole patterns on K4 section (rows 24-27)
  F. Statistical scoring of candidate masks
"""

from __future__ import annotations
import json, sys, os, math, itertools, random, time
from collections import Counter, defaultdict
from pathlib import Path
from typing import List, Tuple, Optional

sys.path.insert(0, 'scripts')
sys.path.insert(0, 'src')

# ── Load quadgrams ────────────────────────────────────────────────────────────
QG_PATH = Path("data/english_quadgrams.json")
QG = json.loads(QG_PATH.read_text()) if QG_PATH.exists() else {}

def score_pc(text: str) -> float:
    n = len(text) - 3
    if n <= 0: return -10.0
    return sum(QG.get(text[i:i+4], -10.0) for i in range(n)) / n

def has_crib(text: str) -> int:
    """Return 1 if EASTNORTHEAST found, 2 if BERLINCLOCK, 3 if both."""
    hit = 0
    if 'EASTNORTHEAST' in text: hit |= 1
    if 'BERLINCLOCK' in text: hit |= 2
    return hit

# ── Constants ─────────────────────────────────────────────────────────────────
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

K4_CARVED = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"

# K3 carved = rows 14-23 (310 chars) + row 24 cols 0-25 (26 chars) = 336 chars
K3_CARVED = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI"  # row 14 (31)
    "ACHTNREYULDSLLSLLNOHSNOSMRWXMNE"  # row 15 (31)
    "TPRNGATIHNRARPESLNNELEBLPIIACAE"   # row 16 (31)
    "WMTWNDITEENRAHCTENEUDRETNHAEOET"   # row 17 (31)
    "FOLSEDTIWENHAEIOYTEYQHEENCTAYCR"   # row 18 (31)
    "EIFTBRSPAMHHEWENATAMATEGYEERLBT"   # row 19 (31)
    "EEFOASFIOTUETUAEOTOARMAEERTNRTI"   # row 20 (31)
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"   # row 21 (31)
    "AECTDDHILCEIHSITEGOEAOSDDRYDLOR"   # row 22 (31)
    "ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"   # row 23 (31)
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"        # row 24 cols 0-25 (26)
)
assert len(K3_CARVED) == 336, f"K3_CARVED len = {len(K3_CARVED)}"

# K3 plaintext (336 chars, confirmed)
# Full K3 PT from memory:
K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHECRIMSONTIDECREEPINGUPONCHERKNEESWEREDISCOVERED"
    "HERPASSAGEWAYTHATLEDINTOTHEDOUBLECOLUMNSSTILLLATERMORESPECIFICALLY"
    "STHEETPOINTSNXTHELITTLENEWROOMWHICHQCANYOUSEEANYTHINGQ"
)
# Pad to 336 if needed
print(f"K3_PT raw len: {len(K3_PT)}")  # debug

KEYWORDS = ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW', 'SANBORN',
            'SCHEIDT', 'BERLIN', 'CLOCK', 'EAST', 'NORTH',
            'LIGHT', 'ANTIPODES', 'MEDUSA', 'ENIGMA']

# 28×31 cipher grid (positional chars only, no ?s)
# Rows 0-27, each 31 chars
CIPHER_GRID_RAW = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIV",  # 0: K1
    "JYQTQUXQBQVYUVLLTREVJYQTMKYRDMF",  # 1
    "DVFPJUDEEHZWETZYVGWHKKQETGFQJNCE", # 2 (31)
    "EGGWHKKQDQMCPFQZDQMMIAGPFXHQRLG",  # 3 (K2 starts)
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",  # 4
    "QZGZLECGYUXUEENJTBJLBQCETBJDFHR",  # 5
    "RYIZETKZEMVDUFKSJHKFWHKUWQLSZFT",  # 6
    "IHHDDDUVHDWKBFUFPWNTDFIYCUQZER",   # 7
    "EEVLDKFEZMOQQJLTTUGSYQPFEUNLAVI",  # 8
    "DXFLGGTEZFKZBSFDQVGOGIPUFXHHDRK",  # 9
    "FFHQNTGPUAECNUVPDJMQCLQUMUNEDFQ",  # 10
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",  # 11
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP",  # 12
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",  # 13 (K2 ends)
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI",  # 14: K3 starts (CENTER)
    "ACHTNREYULDSLLSLLNOHSNOSMRWXMNE",  # 15
    "TPRNGATIHNRARPESLNNELEBLPIIACAE",   # 16
    "WMTWNDITEENRAHCTENEUDRETNHAEOET",   # 17
    "FOLSEDTIWENHAEIOYTEYQHEENCTAYCR",   # 18
    "EIFTBRSPAMHHEWENATAMATEGYEERLBT",   # 19
    "EEFOASFIOTUETUAEOTOARMAEERTNRTI",   # 20
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",   # 21
    "AECTDDHILCEIHSITEGOEAOSDDRYDLOR",   # 22
    "ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE",   # 23
    "ECDMRIPFEIMEHNLSSTTRTVDOHWOBKR",    # 24: K4 starts col 27 (30 chars)
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",   # 25
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",   # 26
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",  # 27
]

# Pad rows to exactly 31 chars (row 24 is only 30 because ? was col 26)
# In 28×31 grid with squeezed ?s removed, row 24 has:
# ECDMRIPFEIMEHNLSSTTRTVDOHW + ? + OBKR
# The ? at col 26 is a POSITIONAL ? (counts as hole?) or is it the 4th ?
# Per memory: 3 positional ?s = K3 start (?), K2 area ?, and...
# Actually per memory: the ? in row 24 (ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR) IS positional
# So row 24 has 31 positions: cols 0-25=ECDMRIPFEIMEHNLSSTTRTVDOHW, col26=?, col27-30=OBKR

# Build 28×31 grid
GRID = []
for i, row in enumerate(CIPHER_GRID_RAW):
    if i == 24:
        # Row 24: 30 letters + ? at col 26 + OBKR at cols 27-30
        # ECDMRIPFEIMEHNLSSTTRTVDOHW (26) + ? (1) + OBKR (4) = 31
        r = list("ECDMRIPFEIMEHNLSSTTRTVDOHW") + ['?'] + list("OBKR")
        assert len(r) == 31, f"Row 24 len={len(r)}"
        GRID.append(r)
    else:
        r = list(row)
        while len(r) < 31:
            r.append(' ')  # pad - shouldn't happen
        GRID.append(r[:31])

assert len(GRID) == 28
for i, row in enumerate(GRID):
    assert len(row) == 31, f"Row {i} has {len(row)} chars: {''.join(row)}"

# Build flat grid (868 positions, ? counts as position)
GRID_FLAT = []
GRID_POS_TO_FLAT = {}  # (r,c) -> flat index
FLAT_TO_GRID_POS = {}  # flat index -> (r,c)
for r in range(28):
    for c in range(31):
        idx = len(GRID_FLAT)
        GRID_POS_TO_FLAT[(r, c)] = idx
        FLAT_TO_GRID_POS[idx] = (r, c)
        GRID_FLAT.append(GRID[r][c])

assert len(GRID_FLAT) == 868

# ── KA Vigenère Tableau (28×31 body) ─────────────────────────────────────────
# The tableau is indexed by row = key letter (KA order), col = position
# Tableau[r][c] = KA[(KA.index(ROW_KEY) + c) % 26]
# Row keys: for row i (0-based), the key letter is KA[i]
# BUT the tableau has 28 rows in the cipher section + header/footer
# Per the mission: tableau rows 0-27 align with cipher rows 0-27
# Row label = AZ[i] for row i

def build_tableau():
    """Build 28×31 KA Vigenère tableau body.

    Tableau row r corresponds to key letter AZ[r].
    Cell (r, c) = KA[(KA.index(AZ[r]) + c) % 26]

    Special cases:
    - Row N (r=13) has an extra L (anomaly)
    - Row V (r=21) has an extra T (anomaly)

    The cipher sits opposite the tableau (cipher row 0 aligns with tableau row 0).
    But which row is which? The cipher panel is in front, tableau behind.
    """
    TAB = []
    for r in range(28):
        row_key = AZ[r % 26]  # A, B, C, ..., Z, A, B (wraps at 28)
        ki = KA.index(row_key)
        row_body = [KA[(ki + c) % 26] for c in range(31)]
        TAB.append(row_body)
    return TAB

TABLEAU = build_tableau()

# Verify known anomalies
# Row N = row 13 (0-indexed, A=0, N=13)
# Row V = row 21
def check_tableau_anomalies():
    """The tableau has 28 rows covering keys A through AB (28 = 26+2).
    Row 0 = A, ..., Row 25 = Z, Row 26 = A again, Row 27 = B.

    The famous anomaly: extra L in row N (row 13).
    In KA alphabet: K=0,R=1,Y=2,P=3,T=4,O=5,S=6,A=7,B=8,C=9,D=10,E=11,F=12,
    G=13,H=14,I=15,J=16,L=17,M=18,N=19,Q=20,U=21,V=22,W=23,X=24,Y=25(wait...)

    Actually KA = KRYPTOSABCDEFGHIJLMNQUVWXZ, so:
    K=0, R=1, Y=2, P=3, T=4, O=5, S=6, A=7, B=8, C=9, D=10, E=11, F=12,
    G=13, H=14, I=15, J=16, L=17, M=18, N=19, Q=20, U=21, V=22, W=23, X=24, Z=25
    Note: no Y after Z (Y is at position 2).

    Row N (row 13 in AZ): key=N, KA.index('N')=19
    Normal 31 cols: KA[(19+c)%26] for c=0..30
    """
    row_N = TABLEAU[13]
    row_V = TABLEAU[21]
    print(f"Row N (r=13, key=N): {''.join(row_N)}")
    print(f"Row V (r=21, key=V): {''.join(row_V)}")

check_tableau_anomalies()

# ── Find cells where cipher == tableau ───────────────────────────────────────
def find_matches():
    matches = []
    for r in range(28):
        for c in range(31):
            cell = GRID[r][c]
            if cell == '?':
                continue
            if cell == TABLEAU[r][c]:
                matches.append((r, c))
    return matches

MATCHES = find_matches()
print(f"\n[INIT] Cipher=Tableau matches: {len(MATCHES)}")
print(f"       Match positions (r,c): {MATCHES[:10]}...")

# ── Cipher/decrypt functions ──────────────────────────────────────────────────
def vig_dec(ct: str, key: str, alpha: str = AZ) -> str:
    ai = {c: i for i, c in enumerate(alpha)}
    out = []
    for i, c in enumerate(ct):
        if c not in ai or key[i % len(key)] not in ai:
            return ''
        out.append(alpha[(ai[c] - ai[key[i % len(key)]]) % 26])
    return ''.join(out)

def beau_dec(ct: str, key: str, alpha: str = AZ) -> str:
    ai = {c: i for i, c in enumerate(alpha)}
    out = []
    for i, c in enumerate(ct):
        if c not in ai or key[i % len(key)] not in ai:
            return ''
        out.append(alpha[(ai[key[i % len(key)]] - ai[c]) % 26])
    return ''.join(out)

def vig_enc(pt: str, key: str, alpha: str = AZ) -> str:
    ai = {c: i for i, c in enumerate(alpha)}
    out = []
    for i, c in enumerate(pt):
        out.append(alpha[(ai[c] + ai[key[i % len(key)]]) % 26])
    return ''.join(out)

def try_all_decrypts(ct: str, label: str = "") -> dict:
    """Try all keyword × cipher × alphabet combinations."""
    best = None
    best_score = -9999
    for kw in KEYWORDS:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cipher_name, dec_fn in [("vig", vig_dec), ("beau", beau_dec)]:
                try:
                    pt = dec_fn(ct, kw, alpha)
                    if not pt:
                        continue
                except:
                    continue
                sc = score_pc(pt)
                cribs = has_crib(pt)
                if cribs:
                    print(f"  *** CRIB HIT! {label} kw={kw} {cipher_name}/{alpha_name} cribs={cribs}")
                    print(f"      PT: {pt}")
                    return {'pt': pt, 'kw': kw, 'cipher': cipher_name, 'alpha': alpha_name,
                            'score': sc, 'crib': cribs}
                if sc > best_score:
                    best_score = sc
                    best = {'pt': pt, 'kw': kw, 'cipher': cipher_name, 'alpha': alpha_name,
                            'score': sc, 'crib': 0}
    return best

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION A: 180° ROTATION ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("SECTION A: 180° ROTATION ANALYSIS")
print("="*70)

def rotate_180(r, c):
    """180° rotation in 28×31 grid."""
    return (27 - r, 30 - c)

# Under 180° grille: position (r,c) and rotate_180(r,c) are complementary
# If (r,c) is a HOLE, then (27-r, 30-c) must be SOLID (since 434 = 28×31/2)
# This means: grille is a "half-and-half" split

# K1+K2 occupies rows 0-13 (434 chars)
# K3+?+K4 occupies rows 14-27 (434 chars)
# Under 180° rotation: row r maps to row 27-r, col c maps to col 30-c
# So row 0 maps to row 27, row 13 maps to row 14
# Top half maps to bottom half exactly!

print("180° rotation structure:")
print(f"  Row 0 → Row 27 (K4 last row)")
print(f"  Row 13 → Row 14 (K3/K2 boundary)")
print(f"  This means: K1+K2 holes ↔ K3+K4 solids (and vice versa)")

# Under this model, the grille has 434 holes in the TOP (K1+K2 region = rows 0-13)
# and the corresponding 434 solids in the BOTTOM (K3+K4 region = rows 14-27)
# OR: 434 holes in BOTTOM, 434 solids in TOP.

# The scramble permutation then works like this:
# Position 1 (grille holes in top = K1+K2 region): reads K1+K2 text
# Position 2 (180° flip → grille holes now in bottom = K3+K4 region): reads K3+K4 text

# KEY INSIGHT: If grille is used in TWO POSITIONS (0° and 180°):
# - Position 1: 434 holes read from top half (K1+K2)
# - Position 2: 434 holes read from bottom half (K3+K4)
# This gives exactly 868 characters = the complete cipher text!

print("\n  INSIGHT: 180° grille reads K1+K2 in one orientation, K3+K4 in other")
print(f"  434 = K1+K2 chars exactly = K3+?+K4 chars exactly")

# Under 180° model, the REAL CT for K3 would be the tableau letters at the
# hole positions in rows 14-27.
# We know K3 PT (336 chars) and K3 CT (carved, 336 chars).
# Under Model 2: K3_CT_real → Scramble → K3_carved
# The scramble for K3 should be the 180° grille reading order of rows 14-23.

# Let's compute what the 180° grille would read for K3 specifically.
# K3 occupies rows 14-23 (first 310 chars of bottom half)
# The ? at row 24, col 26 = position 337 of bottom half
# Then K4 = 97 chars at rows 24-27 starting col 27

# For 180° grille analysis: the hole positions in rows 14-27 are determined
# by reflecting the hole positions in rows 0-13.
# But we don't know the hole positions in rows 0-13 yet!

# ALTERNATIVE INTERPRETATION: The grille directly encodes a reading order.
# If we read the grille holes from (27,30) down to (0,0) (reverse order = 180° reading),
# we get the real_CT for the bottom half.

# Let's test: what if the scramble for K3 is simply REVERSE?
print("\n  Testing if K3 scramble is REVERSE (simplest 180° case)...")
K3_rev = K3_CARVED[::-1]
res = try_all_decrypts(K3_rev, "K3 reversed")
if res:
    print(f"  Best: {res['kw']}/{res['cipher']}/{res['alpha']} score={res['score']:.3f}")
    print(f"  PT: {res['pt'][:60]}...")

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION B: K3 VERIFICATION — Use known K3 PT+CT to test grille theories
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("SECTION B: K3 VERIFICATION")
print("="*70)

# K3 CT and PT are both known. Under Model 2:
#   K3_PT → Vig(ABSCISSA) → K3_real_CT → Scramble → K3_carved
# We can COMPUTE the real_CT from PT and then find the scramble!

def compute_k3_real_ct():
    """Compute K3 real CT from known PT under various cipher assumptions."""
    # K3 decrypts with ABSCISSA (Beaufort? or Vig?)
    # From memory: K3 method is confirmed double rotational transposition
    # K3_CARVED is the scrambled form. The decrypt key was ABSCISSA.

    # Try all keywords to see which one, when applied to K3_CARVED,
    # then unscrambled with the known method, gives K3_PT

    print("  Testing which key/cipher gives K3_PT from K3_CARVED (direct, no scramble):")
    for kw in KEYWORDS:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cipher_name, dec_fn in [("vig", vig_dec), ("beau", beau_dec)]:
                try:
                    pt = dec_fn(K3_CARVED[:len(K3_PT)], kw, alpha)
                    if pt == K3_PT:
                        print(f"  DIRECT MATCH! kw={kw} {cipher_name}/{alpha_name}")
                        return kw, cipher_name, alpha_name, alpha
                    # Check partial match
                    match_count = sum(1 for a,b in zip(pt[:50], K3_PT[:50]) if a==b)
                    if match_count > 25:
                        print(f"  Near match ({match_count}/50): kw={kw} {cipher_name}/{alpha_name}")
                except:
                    pass
    return None

k3_key = compute_k3_real_ct()

print("\n  Computing K3 scramble permutation from known PT + CT...")
# Under Model 2 with K3: we need to find σ such that:
#   K3_carved[σ(j)] = K3_real_CT[j]  for all j
# where K3_real_CT = Vig_encrypt(K3_PT, key)

# The known K3 decryption uses ABSCISSA with Vigenère KA alphabet
# Let's verify by computing: Vig_KA_ABSCISSA(K3_CARVED) and checking K3_PT
print("  Trying ABSCISSA Vig/KA on K3_CARVED...")
k3_dec_test = vig_dec(K3_CARVED, "ABSCISSA", KA)
print(f"  K3 PT:       {K3_PT[:80]}")
print(f"  K3 dec test: {k3_dec_test[:80]}")
match_50 = sum(1 for a,b in zip(k3_dec_test[:80], K3_PT[:80]) if a==b)
print(f"  Matches in first 80: {match_50}/80")

# Try various K3 keys
print("  Comprehensive K3 key search (first 50 chars must match K3_PT)...")
K3_CT_ONLY = K3_CARVED[:len(K3_PT)]
best_match = 0
best_params = None
for kw in KEYWORDS + ['ABSCISSA', 'PALIMPSEST', 'KRYPTOS']:
    for alpha in [AZ, KA]:
        for dec_fn in [vig_dec, beau_dec]:
            try:
                pt = dec_fn(K3_CT_ONLY, kw, alpha)
                m = sum(1 for a,b in zip(pt, K3_PT) if a==b)
                if m > best_match:
                    best_match = m
                    best_params = (kw, dec_fn.__name__, alpha[:5])
                    if m > 100:
                        print(f"  Found {m}/{len(K3_PT)} matches: kw={kw} {dec_fn.__name__}")
                        print(f"  First 80: {pt[:80]}")
            except:
                pass
print(f"  Best match: {best_match}/{len(K3_PT)} with {best_params}")

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION C: MATCH-BASED SEEDING (39 positions where cipher=tableau)
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("SECTION C: MATCH-BASED SEEDING")
print("="*70)

print(f"  Analyzing {len(MATCHES)} positions where cipher[r][c] == tableau[r][c]:")
match_by_row = defaultdict(list)
for (r, c) in MATCHES:
    match_by_row[r].append(c)

for r in sorted(match_by_row.keys()):
    cols = match_by_row[r]
    print(f"  Row {r:2d}: {len(cols)} matches at cols {cols}")

# Count matches in each quadrant
top_matches = [(r,c) for (r,c) in MATCHES if r < 14]
bot_matches = [(r,c) for (r,c) in MATCHES if r >= 14]
print(f"\n  Top half (K1+K2) matches: {len(top_matches)}")
print(f"  Bottom half (K3+K4) matches: {len(bot_matches)}")

# Under 180° grille: match positions in top ↔ complement of match positions in bottom
# Check if any top match (r,c) has rotate_180(r,c) also being a match
rotated_matches = []
for (r,c) in top_matches:
    r2, c2 = rotate_180(r, c)
    if (r2, c2) in MATCHES:
        rotated_matches.append(((r,c), (r2,c2)))

print(f"\n  Positions where BOTH (r,c) and 180°-rotate(r,c) are matches: {len(rotated_matches)}")
if rotated_matches:
    for pair in rotated_matches[:5]:
        print(f"    {pair}")

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION D: YAR POSITIONS IN K4
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("SECTION D: YAR POSITIONS IN K4")
print("="*70)

# K4 = 97 chars, YAR appear at certain positions
YAR = set('YAR')
k4_yar_positions = [(i, K4_CARVED[i]) for i in range(97) if K4_CARVED[i] in YAR]
print(f"  K4 YAR positions (local index): {k4_yar_positions}")
print(f"  Count: {len(k4_yar_positions)}")

# K4 in grid: starts at (24, 27)
# Flat index of K4 start in 868-grid:
k4_start_flat = GRID_POS_TO_FLAT[(24, 27)]
print(f"\n  K4 grid positions (global):")
for i, (pos, ch) in enumerate(k4_yar_positions):
    flat = k4_start_flat + pos
    r, c = FLAT_TO_GRID_POS[flat]
    tab_ch = TABLEAU[r][c]
    print(f"  K4[{pos:2d}] = {ch}: grid ({r},{c}) flat={flat}, tableau[{r}][{c}]={tab_ch}")

# If YAR positions are grille holes, what tableau letters do we read?
print("\n  If K4 YAR positions are holes: tableau letters =",
      ''.join(TABLEAU[FLAT_TO_GRID_POS[k4_start_flat + i][0]][FLAT_TO_GRID_POS[k4_start_flat + i][1]]
              for i, ch in enumerate(K4_CARVED) if ch in YAR))

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION E: COLUMN FREQUENCY ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("SECTION E: COLUMN FREQUENCY ANALYSIS")
print("="*70)

# Count matches per column across all rows
match_by_col = defaultdict(int)
for (r, c) in MATCHES:
    match_by_col[c] += 1

print("  Matches per column (0-30):")
for c in range(31):
    cnt = match_by_col[c]
    bar = '#' * cnt
    print(f"  Col {c:2d}: {cnt:2d} {bar}")

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION F: THE TABLEAU READING ORDER — Grille as sequential read
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("SECTION F: GRILLE READING ORDER HYPOTHESES")
print("="*70)

# KEY INSIGHT: The Cardan grille defines WHICH cells of the carved text
# are the "real" positions. The reading order through the holes defines σ.
#
# For K4: 97 chars. We need exactly 97 holes in the K4 region (rows 24-27).
# But K4 only occupies 97 cells in those rows (rows 24-27):
#   Row 24: cols 27-30 = 4 cells (K4 starts at col 27)
#   Row 25: cols 0-30 = 31 cells
#   Row 26: cols 0-30 = 31 cells
#   Row 27: cols 0-30 = 31 cells
# Total = 4 + 31 + 31 + 31 = 97 cells = EXACTLY K4 length!

print("  K4 occupies EXACTLY 97 cells in rows 24-27 (col 27-30 of row 24, full rows 25-27)")
print("  This means ALL 97 K4 cells are hole positions (trivial grille for K4)")

# If all K4 cells are holes, then the scramble σ is purely a reading ORDER.
# The real_CT[j] = tableau[r][c] where (r,c) is the j-th hole in reading order.
# And carved[σ(j)] = K4_CARVED[j] — which just means σ IS the reading order.

# Actually, wait. Let me reconsider.
# Under Model 2: real_CT → SCRAMBLE → carved
# carved[σ(j)] = real_CT[j]  OR equivalently real_CT[σ⁻¹(i)] = carved[i]
# The grille HOLES define which cells of the carved text are visible.
# If we OVERLAY the grille on the carved text in a reading order,
# we read out the REAL CT in order.

# So: holes at positions p_0, p_1, ..., p_96 (in reading order)
# real_CT[j] = carved[p_j] for j=0..96
# The permutation σ maps j → p_j.

# For K4: all 97 cells are in rows 24-27.
# Reading order determines which carved letter is real_CT[0], [1], etc.
# Then decrypt(real_CT, key) should give PT.

# Standard reading orders:
def k4_reading_orders():
    """Generate K4 cell positions in various reading orders."""
    k4_cells = []
    # Row 24, cols 27-30
    for c in range(27, 31):
        k4_cells.append((24, c))
    # Rows 25-27, all cols
    for r in range(25, 28):
        for c in range(31):
            k4_cells.append((r, c))

    assert len(k4_cells) == 97
    return k4_cells

K4_CELLS = k4_reading_orders()
print(f"  K4 cells: {K4_CELLS[:5]}...{K4_CELLS[-5:]}")

# For each reading order: map cells to K4_CARVED positions
# K4_CARVED[i] is at K4_CELLS[i] in standard L→R T→B order
# So K4_CELLS[i] corresponds to K4_CARVED[i]

# Under Model 2: real_CT[j] = K4_CARVED[perm[j]] where perm is reading order

def test_k4_reading_order(order_cells, label):
    """Given a reading order (list of (r,c) pairs), extract real CT and test."""
    # Map each cell to its K4 index
    cell_to_k4idx = {cell: i for i, cell in enumerate(K4_CELLS)}

    # Reading order gives: real_CT[j] = K4_CARVED[cell_to_k4idx[order_cells[j]]]
    try:
        real_ct = ''.join(K4_CARVED[cell_to_k4idx[cell]] for cell in order_cells)
    except KeyError as e:
        print(f"  {label}: KeyError {e}")
        return None

    res = try_all_decrypts(real_ct, label)
    if res:
        sc = res.get('score', -99)
        print(f"  {label}: best {res['kw']}/{res['cipher']}/{res['alpha']} sc={sc:.3f} | {res['pt'][:40]}")
    return res

# Order 1: Standard L→R T→B (identity)
print("\n  Testing standard reading orders on K4...")
test_k4_reading_order(K4_CELLS, "K4 standard")

# Order 2: Reverse R→L B→T
test_k4_reading_order(K4_CELLS[::-1], "K4 reversed")

# Order 3: Column-major (top to bottom within each column)
col_major = sorted(K4_CELLS, key=lambda rc: (rc[1], rc[0]))
test_k4_reading_order(col_major, "K4 col-major")

# Order 4: Boustrophedon (alternating L→R and R→L)
boustro = []
rows_k4 = {}
for (r, c) in K4_CELLS:
    rows_k4.setdefault(r, []).append((r, c))
for i, r in enumerate(sorted(rows_k4.keys())):
    row_cells = rows_k4[r]
    if i % 2 == 0:
        boustro.extend(sorted(row_cells, key=lambda x: x[1]))
    else:
        boustro.extend(sorted(row_cells, key=lambda x: -x[1]))
test_k4_reading_order(boustro, "K4 boustrophedon")

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION G: THE TABLEAU-BASED GRILLE — Reading tableau AT cipher positions
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("SECTION G: TABLEAU-BASED GRILLE HYPOTHESIS")
print("="*70)

# NEW HYPOTHESIS: The grille is not about HOLES in the physical sense.
# Instead: the cipher grid OVERLAYS the tableau.
# At each position, you can see EITHER the cipher text OR the tableau beneath.
# The pattern of "look-through" defines the scramble.
#
# Key question: what if the MATCH positions (cipher[r][c] == tableau[r][c])
# are NOT holes, but rather the positions where the cipher letter IS the real_CT letter
# (no transformation needed)?
#
# Under this model: where cipher ≠ tableau, tableau is the real_CT letter;
# where cipher = tableau, it's ambiguous but could be either.

# Alternative: tableau letters at match positions are the "holes"
# that, when read in order, give the real CT.

# Let's test: for K4 section, get tableau letters at match positions
k4_match_cells = [(r,c) for (r,c) in MATCHES if r >= 24 and (r > 24 or c >= 27)]
print(f"  K4 matches (cipher=tableau in rows 24-27): {len(k4_match_cells)}")

# For K3 section, get match cells
k3_match_cells = [(r,c) for (r,c) in MATCHES if 14 <= r <= 23]
print(f"  K3 matches (rows 14-23): {len(k3_match_cells)}")
for cell in k3_match_cells:
    r, c = cell
    print(f"    ({r},{c}): cipher={GRID[r][c]} tableau={TABLEAU[r][c]}")

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION H: K3 DOUBLE ROTATIONAL TRANSPOSITION → DEDUCE K4 SCRAMBLE
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("SECTION H: K3 PERMUTATION ANALYSIS → K4 DEDUCTION")
print("="*70)

# K3 METHOD IS CONFIRMED: Double rotational transposition (24×14 → 8×42)
# This means K3_CARVED = double_rot_transpose(K3_real_CT)
# Since K3_PT → Vig/Beau → K3_real_CT → double_rot → K3_CARVED
#
# K3 has 336 chars, K4 has 97 chars.
# K3 fits in a 24×14 sub-grid (24 cols × 14 rows = 336).
# K4 is 97 chars — what sub-grid does it use?
#
# K3 occupies rows 14-23 (10 rows) + row 24 cols 0-26 (27 chars) = 337 chars??
# Hmm, but K3 = 336 chars. Let me re-check.

# From memory: K3[432:768] = 336 chars. That's 336 chars of the FULL TEXT.
# In the 28×31 grid, K3 starts at row 14 col 0.
# 336 chars / 31 cols = 10.84 rows → K3 occupies rows 14-24 (part of row 24)
# 10 full rows × 31 = 310 chars
# Plus 26 more chars = K3 ends at row 24, col 25.
# Then ? at row 24, col 26 is the K3/K4 delimiter.
# K4 starts at row 24, col 27.

# For K3 grid layout:
# Rows 14-23: 10 rows × 31 cols = 310 chars
# Row 24, cols 0-25: 26 chars
# Total K3: 336 chars ✓

# For K4 grid layout:
# Row 24, cols 27-30: 4 chars (OBKR)
# Rows 25-27: 3 rows × 31 cols = 93 chars
# Total K4: 97 chars ✓

print("  K3 grid layout: rows 14-23 (310 chars) + row 24 cols 0-25 (26 chars) = 336")
print("  K4 grid layout: row 24 cols 27-30 (4 chars) + rows 25-27 (93 chars) = 97")

# The K3 method: double columnar transposition RTL with widths 21 and 28
# Equivalent to: arrange K3 as 24-wide grid (14 rows), rotate 90° CW,
# then read out as 8-wide grid (42 rows)
# Let's VERIFY this by computing K3_real_CT and checking

# K3 uses ABSCISSA with Beaufort? or Vigenère?
# Let me try all cipher/key combinations to find which one,
# applied to K3_CARVED, gives K3_PT directly (without scramble)
# OR: find K3_real_CT such that double_rot(K3_real_CT) = K3_CARVED
# and then decrypt(K3_real_CT) = K3_PT

def double_rot_transpose(text, w1=21, w2=28):
    """K3's confirmed method: double columnar RTL at widths w1, w2."""
    n = len(text)
    # First columnar at width w1 (RTL = right-to-left reading)
    rows1 = (n + w1 - 1) // w1
    grid1 = [text[i*w1:(i+1)*w1] for i in range(rows1)]
    # RTL: read columns right-to-left
    intermed = []
    for c in range(w1-1, -1, -1):
        for r in range(rows1):
            if c < len(grid1[r]):
                intermed.append(grid1[r][c])
    intermed = ''.join(intermed)

    # Second columnar at width w2 (RTL)
    rows2 = (len(intermed) + w2 - 1) // w2
    grid2 = [intermed[i*w2:(i+1)*w2] for i in range(rows2)]
    result = []
    for c in range(w2-1, -1, -1):
        for r in range(rows2):
            if c < len(grid2[r]):
                result.append(grid2[r][c])
    return ''.join(result)

def double_rot_inverse(text, w1=21, w2=28):
    """Inverse of double_rot_transpose."""
    n = len(text)

    # Inverse of second columnar (RTL, w2)
    rows2 = (n + w2 - 1) // w2
    full_rows2 = n // w2
    remainder2 = n % w2
    # Under RTL: last col is col 0 in reverse
    col_lengths2 = [full_rows2 + (1 if (w2-1-c) < remainder2 else 0) for c in range(w2)]
    # Actually for RTL, col order is w2-1, w2-2, ..., 0
    # So first characters read are from rightmost column (col w2-1)
    # col c gets full_rows2 rows + 1 if c >= w2 - remainder2
    col_lengths2 = []
    for c in range(w2):
        if remainder2 == 0:
            col_lengths2.append(full_rows2)
        else:
            # col w2-1 (rightmost, read first) gets extra row if remainder2 > 0
            # cols w2-1, w2-2, ..., w2-remainder2 get extra row
            if c >= w2 - remainder2:
                col_lengths2.append(full_rows2 + 1)
            else:
                col_lengths2.append(full_rows2)

    # Reconstruct grid2 from text, reading RTL (col w2-1 first)
    grid2 = [[''] * w2 for _ in range(rows2)]
    pos = 0
    for c in range(w2-1, -1, -1):
        clen = col_lengths2[c]
        for r in range(clen):
            grid2[r][c] = text[pos]
            pos += 1
    intermed = ''.join(''.join(grid2[r][:w2]) for r in range(rows2))
    # Remove padding
    intermed = ''.join(c for c in intermed if c)

    # Inverse of first columnar (RTL, w1)
    m = len(intermed)
    rows1 = (m + w1 - 1) // w1
    full_rows1 = m // w1
    remainder1 = m % w1
    col_lengths1 = []
    for c in range(w1):
        if remainder1 == 0:
            col_lengths1.append(full_rows1)
        else:
            if c >= w1 - remainder1:
                col_lengths1.append(full_rows1 + 1)
            else:
                col_lengths1.append(full_rows1)

    grid1 = [[''] * w1 for _ in range(rows1)]
    pos = 0
    for c in range(w1-1, -1, -1):
        clen = col_lengths1[c]
        for r in range(clen):
            grid1[r][c] = intermed[pos]
            pos += 1
    result = ''.join(''.join(grid1[r][:w1]) for r in range(rows1))
    return ''.join(c for c in result if c)

# Test: apply double_rot to K3_CARVED and see if it matches something
# Under Model 2: double_rot(K3_real_CT) = K3_CARVED
# So: K3_real_CT = double_rot_inverse(K3_CARVED)
K3_real_CT = double_rot_inverse(K3_CARVED, 21, 28)
print(f"\n  K3_real_CT (via inverse double_rot 21,28): {K3_real_CT[:80]}")
print(f"  Length: {len(K3_real_CT)}")

# Verify: double_rot(K3_real_CT) should equal K3_CARVED
K3_carved_check = double_rot_transpose(K3_real_CT, 21, 28)
print(f"  Verify round-trip: {K3_carved_check[:80]}")
match_rt = K3_carved_check == K3_CARVED[:len(K3_carved_check)]
print(f"  Round-trip match: {match_rt}")

# Now decrypt K3_real_CT
print("\n  Decrypting K3_real_CT with all keys/ciphers...")
K3_real_CT_str = K3_real_CT[:len(K3_PT)]
res = try_all_decrypts(K3_real_CT_str, "K3_real_CT")
if res:
    print(f"  Best: score={res['score']:.3f} | PT: {res['pt'][:80]}")
    if res['pt'][:50] == K3_PT[:50]:
        print("  *** K3 PT MATCHED!")

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION I: THE GRILLE AS TABLEAU CIPHER
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("SECTION I: TABLEAU CIPHER HYPOTHESIS")
print("="*70)

# RADICAL NEW HYPOTHESIS based on the physical setup:
# The cipher text IS the Vigenère encryption using the tableau underneath.
# At each cell (r,c): cipher[r][c] = Vig_encrypt(plaintext[r][c], row_key_r, col_key_c)
# where row_key is the KA tableau row key and col_key is the AZ header column letter.
#
# This is the standard Vigenère TABLEAU reading:
# plaintext_char = KA_decrypt(cipher_char, row_key, col_key)
#
# Under this model: the grille determines which (row_key, col_key) pair to use at each position.

# Let's test the tableau cipher hypothesis on K4:
# K4 cells and their (r,c) indices:
print("  Testing tableau cipher on K4...")
print("  AZ headers (cols 0-30): ABCDEFGHIJKLMNOPQRSTUVWXYZABCDE (first 31 of AZ cycle)")
AZ_HEADER = [AZ[c % 26] for c in range(31)]
print(f"  AZ headers: {''.join(AZ_HEADER)}")

# Row labels for 28 rows of tableau:
ROW_LABELS = [AZ[r % 26] for r in range(28)]
print(f"  Row labels: {''.join(ROW_LABELS)}")

# Tableau decryption:
# Given cipher char C at position (r, c):
# row_key = ROW_LABELS[r] → KA index
# col_key = AZ_HEADER[c]
# PT = row where KA row[row_key] contains C, at col_key
# Actually: Vig tableau: encrypt(P, K) = C means C = tableau[K][P]
# where K is row key (row label) and P is column index
# Decrypt: P = column index where C appears in row K

def tableau_decrypt_at(r, c, cipher_char):
    """Given cipher char at grid position (r,c), decrypt using KA tableau.

    The tableau row is determined by row_label = AZ[r % 26].
    The cipher char C was produced as: C = KA[(KA.index(row_label) + col_shift) % 26]
    where col_shift encodes the plaintext.
    Decrypt: col_shift = (KA.index(C) - KA.index(row_label)) % 26
    Then plaintext = AZ_HEADER[col_shift] ???

    Actually in standard Vigenère:
    C = (P + K) mod 26 (AZ alphabet)
    P = (C - K) mod 26
    where K = KA.index(row_label) and we work in KA-index space.
    """
    if cipher_char == '?':
        return '?'
    row_label = ROW_LABELS[r]
    K = KA.index(row_label)
    C = KA.index(cipher_char) if cipher_char in KA else AZ.index(cipher_char) if cipher_char in AZ else -1
    if C == -1:
        return '?'
    P = (C - K) % 26
    return AZ[P]

# Decrypt all of K4 using tableau positions
k4_tableau_pt = []
for i, (r, c) in enumerate(K4_CELLS):
    ch = GRID[r][c]
    pt_ch = tableau_decrypt_at(r, c, ch)
    k4_tableau_pt.append(pt_ch)

K4_TABLEAU_PT = ''.join(k4_tableau_pt)
print(f"  K4 tableau-decrypted: {K4_TABLEAU_PT}")
print(f"  Score: {score_pc(K4_TABLEAU_PT):.3f}")
print(f"  Has EASTNORTHEAST: {'EASTNORTHEAST' in K4_TABLEAU_PT}")
print(f"  Has BERLINCLOCK: {'BERLINCLOCK' in K4_TABLEAU_PT}")

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION J: SYSTEMATIC SMALL-GRILLE SEARCH ON K4 ROWS
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("SECTION J: SMALL-GRILLE PERMUTATION SEARCH")
print("="*70)

# K4 has 97 chars in a 4-row region.
# Under 180° grille hypothesis: grille selects a subset of cells.
# But since ALL 97 K4 cells are "needed" (K4 is 97 chars),
# the grille must include all 97 of them — the order is what matters.
#
# So the "grille" for K4 is just a permutation of 97 positions.
#
# STRUCTURE IDEA: The grille pattern might follow the CIPHER SECTION structure.
# The 97 K4 chars span 4 grid rows. Perhaps the grille reads:
# 1. Column by column within the 4-row region
# 2. Row by row but reversed
# 3. Based on keyword letters
# 4. Based on tableau values at each position

# Let's check: what are the tableau values at K4 cell positions?
print("  Tableau values at K4 cells (reading order):")
k4_tableau_vals = []
for i, (r, c) in enumerate(K4_CELLS):
    tv = TABLEAU[r][c]
    k4_tableau_vals.append(tv)

print(f"  Tableau string: {''.join(k4_tableau_vals)}")
print(f"  Score if we use this as CT: {score_pc(''.join(k4_tableau_vals)):.3f}")

# What if we decrypt tableau vals at K4 positions using keyword?
print("\n  Decrypting tableau string at K4 positions...")
K4_TAB_STR = ''.join(k4_tableau_vals)
res = try_all_decrypts(K4_TAB_STR, "K4 tableau vals")
if res:
    print(f"  Best: score={res['score']:.3f} kw={res['kw']}/{res['cipher']}/{res['alpha']}")
    print(f"  PT: {res['pt']}")

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION K: INVERSE APPROACH — Compute what real_CT must be from cribs
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("SECTION K: CRIB-DRIVEN CONSTRAINT ANALYSIS")
print("="*70)

# Under Model 2: PT[21..33] = EASTNORTHEAST, PT[63..73] = BERLINCLOCK
# For Vig/KRYPTOS/AZ: real_CT[j] = (PT[j] + KRYPTOS[j%7]) mod 26
# For Vig/ABSCISSA/KA: real_CT[j] = KA[(KA.index(PT[j]) + KA.index(ABSCISSA[j%8])) % 26]

def compute_expected_real_ct(pt_partial, pt_positions, key, cipher='vig', alpha=AZ):
    """Compute expected real_CT at known PT positions."""
    result = {}
    ai = {c: i for i, c in enumerate(alpha)}
    for j, pos in enumerate(pt_positions):
        ch = pt_partial[j]
        k = key[pos % len(key)]
        if ch not in ai or k not in ai:
            continue
        if cipher == 'vig':
            ct_ch = alpha[(ai[ch] + ai[k]) % 26]
        else:  # beaufort
            ct_ch = alpha[(ai[k] - ai[ch]) % 26]
        result[pos] = ct_ch
    return result

# Crib positions (0-indexed in PT/real_CT)
CRIB1 = list(enumerate("EASTNORTHEAST", start=21))  # positions 21-33
CRIB2 = list(enumerate("BERLINCLOCK", start=63))     # positions 63-73
ALL_CRIBS_CHARS = CRIB1 + CRIB2  # 24 positions total

crib_pt = {pos: ch for pos, ch in ALL_CRIBS_CHARS}
crib_positions = sorted(crib_pt.keys())

print(f"  Crib positions: {crib_positions[:10]}... ({len(crib_positions)} total)")

for key in ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA']:
    for cipher in ['vig', 'beau']:
        for alpha in [AZ, KA]:
            exp = compute_expected_real_ct(
                [crib_pt[p] for p in crib_positions],
                crib_positions, key, cipher, alpha
            )
            # Count how many of these expected real_CT chars appear in K4_CARVED
            real_ct_chars = [exp[p] for p in crib_positions]
            carved_counter = Counter(K4_CARVED)
            ok = True
            for ch in real_ct_chars:
                if carved_counter.get(ch, 0) == 0:
                    ok = False
                    break
            if ok:
                print(f"  {key}/{cipher}/{'AZ' if alpha==AZ else 'KA'}: all 24 real_CT chars present in K4_CARVED ✓")
                # Show expected real_CT
                exp_str = ''.join(exp[p] for p in crib_positions)
                print(f"    Expected real_CT at cribs: {exp_str}")

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION L: THE GRILLE EXTRACT AS DIRECT PERMUTATION
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("SECTION L: GRILLE EXTRACT AS PERMUTATION KEY")
print("="*70)

# From mission notes:
# "Letters Y, A, R were removed from cipher text to derive the 100-char grille extract"
# "K4 has EXACTLY 9 positions containing Y, A, or R: these may be the grille holes in K4"

# The grille extract is 100 chars, derived from cipher grid by taking positions
# where the cipher letter is NOT Y, A, or R? Or IS Y, A, R?
# From memory: GE = HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEIOMQFJNXZKILKRDIYSCLMQVZACEIMVSEFHLQKRGILVHNQXWTCDKIKJUFQRXCD
# (100 chars, corrected version)

GE = "HJLVKDJQZKIVPCMWSAFOPCKBDLHIFXRYVFIJMXEIOMQFJNXZKILKRDIYSCLMQVZACEIMVSEFHLQKRGILVHNQXWTCDKIKJUFQRXCD"
print(f"  GE length: {len(GE)}")
print(f"  GE: {GE}")
print(f"  Letter freq: {dict(sorted(Counter(GE).items()))}")
print(f"  T present: {'T' in GE}")

# Map GE chars to indices
ge_indices = [AZ.index(c) for c in GE if c in AZ]
print(f"  GE as AZ indices (first 20): {ge_indices[:20]}")

# Try using GE as a key to permute K4
# Method 1: GE indices as direct lookup
# Method 2: Sort GE positions by value

# Since GE has 100 chars but K4 has 97, we need to select 97 from GE
# Natural selection: take first 97, last 97, or every-other-one

for n_take in [97]:
    for start in [0, 1, 2, 3]:
        ge_sub = ge_indices[start:start+n_take]
        if len(ge_sub) == 97:
            # Use as permutation: real_CT[j] = K4_CARVED[ge_sub[j] % 97]
            try:
                real_ct = ''.join(K4_CARVED[ge_sub[j] % 97] for j in range(97))
                res = try_all_decrypts(real_ct, f"GE[{start}:{start+n_take}] mod 97")
                if res and res['score'] > -6:
                    print(f"  GE[{start}:{start+n_take}]: {res['kw']}/{res['cipher']} sc={res['score']:.3f}")
            except:
                pass

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION M: PERIOD-8 "LINES 73" ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("SECTION M: PERIOD-8 'LINES 73' ANALYSIS")
print("="*70)

# From memory: "8 Lines 73" from Sanborn's yellow pad, tableau anomalies V-N=T-L=8
# 97 mod 8 = 1 (one extra position)
# Period-8 key could mean ABSCISSA (8 chars)
# 73 = 97 - 24 (free positions = 73 after fixing 24 cribs)

# Under period-8: K4 chars at positions j≡0 (mod 8) form a group, etc.
# If the scramble is period-8-structured...

print(f"  97 = 8 × 12 + 1. Lines = 97/8 ≈ 12.125")
print(f"  73 + 24 cribs = 97. '8 Lines 73' could mean 8-line by ? arrangement")
print(f"  If rows=8, cols=73/8≈9.125...")

# What if K4's real CT has period-8 structure?
# The scramble might be: interleave 8 streams
for period in [7, 8, 13]:
    print(f"\n  Testing period-{period} interleave unscramble...")
    # Deinterleave: take every period-th character
    for offset in range(period):
        stream = K4_CARVED[offset::period]
        # Try all decrypts on this stream
        if len(stream) > 10:
            for kw in ['KRYPTOS', 'ABSCISSA']:
                for dec_fn, name in [(vig_dec, 'vig'), (beau_dec, 'beau')]:
                    for alpha in [AZ, KA]:
                        try:
                            pt = dec_fn(stream, kw, alpha)
                            if has_crib(pt):
                                print(f"  *** CRIB in period-{period} stream offset {offset}!")
                        except:
                            pass

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION N: COMBINED CONSTRAINT — 180° GRILLE + K3 VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("SECTION N: 180° GRILLE STRUCTURAL ANALYSIS")
print("="*70)

# Under 180° grille: the grille has 434 holes.
# When placed in position 1 (top = K1+K2), the 434 holes read K1+K2 (in order).
# When placed in position 2 (180° flip = bottom = K3+K4), the 434 holes read K3+K4.
#
# CRITICAL INSIGHT: Under this model, the scramble permutation σ for K3+K4 is
# determined by how the 434 holes in the BOTTOM HALF are ordered when the grille
# is flipped 180°.
#
# The 180° flip maps hole (r,c) → (27-r, 30-c).
# If hole at (r,c) is the j-th hole in position 1, it becomes hole at (27-r, 30-c)
# in position 2. The reading order of position 2 determines σ for the bottom half.
#
# Let's think about this concretely:
# If we read position 1 holes in standard L→R T→B order (rows 0-13),
# then position 2 holes are at (27-r, 30-c) for each position-1 hole.
# The reading order of position 2 holes in standard L→R T→B order (rows 14-27)
# determines σ.

# SPECIFIC PREDICTION: If hole j in position 1 is at (r,c) in rows 0-13,
# its 180°-image is at (27-r, 30-c) in rows 14-27.
# Reading position 2 holes in standard order gives the permutation.

# Simplest case: ALL top-half cells are holes (position 1 = K1+K2 verbatim).
# Then position 2 holes are at (27-r, 30-c) for all (r,c) in rows 0-13.
# These are ALL cells in rows 14-27, in reverse order!

# Under this model: reading position 2 holes in L→R T→B order gives rows 14-27
# BUT the holes are at 180°-reflected positions.
# The j-th hole (in position-1 reading order, which is just row-major order of rows 0-13)
# maps to position (27-r, 30-c) where (r,c) is the j-th position in rows 0-13.
# The permutation for the bottom half is:
# σ(j) = position in bottom half of (27-r, 30-c) where (r,c) is j-th pos in top half
# = (27 - j//31)×31 + (30 - j%31) - 14×31
# = (13 - j//31)×31 + (30 - j%31)

# This is exactly: within the bottom half, position j maps to
# row 27-(j//31) col 30-(j%31), which in bottom-half local coords is:
# row (27 - j//31 - 14) = 13 - j//31, col 30 - j%31
# So σ(j) = (13 - j//31)*31 + (30 - j%31) for j in 0..433

# For K3 (first 337 positions of bottom half, positions 0..336):
print("  Testing: 180° grille = ALL CELLS, reading order = row-major of rotated positions")
bot_perm = []  # permutation for bottom half (434 elements)
for j in range(434):
    r_top = j // 31
    c_top = j % 31
    r_bot = 27 - r_top  # in rows 14-27 absolute
    c_bot = 30 - c_top
    # Convert to bottom-half local index (0-based from start of K3)
    local_idx = (r_bot - 14) * 31 + c_bot
    bot_perm.append(local_idx)

# The bottom half is 434 chars total.
# Flat bottom half: rows 14-27 in order = 434 chars
# K3 = first 337 of these (rows 14-24 cols 0-26 + ... wait, 336 K3 + 1 ? = 337)
# Let me be precise:
# Bottom half flat: position i → row 14 + i//31, col i%31
# Position 0 = (14,0), position 335 = (24, 25), position 336 = (24, 26) = ?
# Position 337 = (24, 27) = first K4 char (O)
# ... position 433 = (27, 30) = last K4 char (R)

# K3 occupies positions 0..335 in bottom half
# ? at position 336 (row 24, col 26)
# K4 occupies positions 337..433 in bottom half (97 chars)

# The permutation for K3 chars:
K3_perm = [bot_perm[j] for j in range(336)]
print(f"  K3 180°-perm (first 10): {K3_perm[:10]}")
print(f"  K3 180°-perm (range): {min(K3_perm)}-{max(K3_perm)}")

# Check if this perm is valid for K3 (maps 0..335 → within K3 region)
k3_perm_valid = all(0 <= p <= 433 for p in K3_perm)
print(f"  K3 perm range valid (<434): {k3_perm_valid}")

# The perm maps j-th real_CT position to carved position
# real_CT[j] = K3_CARVED[K3_perm[j]]?
# No wait: σ(j) = K3_perm[j] means carved[σ(j)] = real_CT[j]
# So: real_CT[j] = K3_CARVED[K3_perm[j]] (using position in bottom-half, which includes K3+?+K4)

# But K3_CARVED is only 336 chars. Bottom half positions 337+ are K4.
# For K3 permutation, we need perm values within 0..335 (K3 region).
# Let's check if bot_perm maps 0..335 → 0..335
k3_perm_subset = [p for p in K3_perm if p <= 335]
print(f"  K3 180°-perm values ≤335 (within K3): {len(k3_perm_subset)}/336")

# Many values in bot_perm for j=0..335 will be in 336-433 (K4 region)
# because: j ≤ 335, but (13 - j//31)*31 + (30 - j%31) can go up to 13*31+30=433
# Specifically, j=0 → (13,30) → local = 13*31+30 = 433 (last K4 char!)
print(f"  bot_perm[0] = {bot_perm[0]} (= K4 last char position in bottom half)")
print(f"  bot_perm[96] = {bot_perm[96]} (= ?, 97th bottom-half position)")
print(f"  bot_perm[97] = {bot_perm[97]}")
print(f"  bot_perm[336] = {bot_perm[336]} (= K4 start position)")
print(f"  bot_perm[433] = {bot_perm[433]} (= K3 start position)")

# AHA! Under 180° rotation:
# Bottom-half position 0 (K3 start) maps to position 433 (K4 end)
# Bottom-half position 433 (K4 end) maps to position 0 (K3 start)
# So the 180° rotation REVERSES the entire bottom half!

print("\n  *** 180° ROTATION = FULL REVERSE OF BOTTOM HALF ***")
print("  This means: real_CT[j] = bottom_half_flat[433-j]")
print("  For K3: real_CT[j] = bottom_half[433-j]")

# Bottom half flat (K3 + ? + K4):
# Positions 0-335: K3_CARVED[0..335]
# Position 336: ?
# Positions 337-433: K4_CARVED[0..96]
BOTTOM_HALF_FLAT = list(K3_CARVED) + ['?'] + list(K4_CARVED)
assert len(BOTTOM_HALF_FLAT) == 434, f"Bottom half len = {len(BOTTOM_HALF_FLAT)}"

bottom_reversed = ''.join(reversed(BOTTOM_HALF_FLAT))
print(f"  Bottom-half reversed: {bottom_reversed[:80]}")
print(f"  Length: {len(bottom_reversed)}")

# K3 real CT under this model = bottom_reversed[0:336]
# (the reversal puts K4 chars at the start and K3 chars at the end)
K3_realCT_from_rev = bottom_reversed[97:337+97]  # hmm, need to think about ?
# Actually: reversed bottom = K4_CARVED reversed + ? + K3_CARVED reversed
# Position 0 = K4_CARVED[96] = last K4 char
# Position 96 = K4_CARVED[0] = first K4 char
# Position 97 = ?
# Position 98 = K3_CARVED[335] = last K3 char
# Position 433 = K3_CARVED[0] = first K3 char

print("\n  Under full-reverse hypothesis:")
print(f"  K3 real_CT = bottom_half reversed[98:434] (K3 part reversed)")
K3_realCT_rev = K3_CARVED[::-1]  # K3 reversed
print(f"  K3 real_CT (reversed): {K3_realCT_rev[:80]}")

# Test decryption
print("  Decrypting reversed K3...")
for kw in ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA']:
    for dec_fn, name in [(vig_dec, 'vig'), (beau_dec, 'beau')]:
        for alpha in [AZ, KA]:
            try:
                pt = dec_fn(K3_realCT_rev, kw, alpha)
                sc = score_pc(pt)
                match = sum(1 for a, b in zip(pt, K3_PT) if a == b)
                if match > 50 or sc > -5:
                    print(f"  kw={kw} {name}/{'AZ' if alpha==AZ else 'KA'}: {match}/{len(K3_PT)} match, sc={sc:.3f}")
                    print(f"  PT: {pt[:80]}")
            except:
                pass

# K4 real CT under full-reverse = bottom_reversed[0:97] = K4_CARVED reversed
K4_realCT_rev = K4_CARVED[::-1]
print(f"\n  K4 real_CT (reversed): {K4_realCT_rev}")
res = try_all_decrypts(K4_realCT_rev, "K4 reversed")
if res:
    print(f"  Best: {res['kw']}/{res['cipher']}/{res['alpha']} sc={res['score']:.3f}")
    print(f"  PT: {res['pt']}")

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION O: THE GRILLE EXTRACT POSITION MAPPING
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("SECTION O: GRILLE EXTRACT POSITION ANALYSIS")
print("="*70)

# The old grille extract (106 chars) was derived from the sculpture photo.
# The new corrected GE (100 chars) is derived from the corrected 28×31 grid.
# KEY: The GE represents the TABLEAU LETTERS at the grille HOLES.
# So if we know GE[j] = tableau[r_j][c_j], we know which cells are holes.

# From the mission: "Letters Y, A, R were removed from cipher text to derive the 100-char GE"
# This means: grille holes = positions in cipher text where letter is Y, A, or R?
# And the tableau letters at those positions = GE chars.

# Count YAR in each section:
def count_yar_in_section(section_text, section_name):
    count = sum(1 for c in section_text if c in 'YAR')
    print(f"  {section_name}: {count} YAR chars in {len(section_text)} chars = {count/len(section_text)*100:.1f}%")
    return count

print("  YAR analysis by section:")
K1 = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMF"  # 63 chars
K2_TEXT = "".join(row for row in CIPHER_GRID_RAW[2:14])  # rows 2-13 = 12 rows
full_text = "".join(CIPHER_GRID_RAW)
count_yar_in_section(K1, "K1 (63 chars)")
count_yar_in_section(K3_CARVED, "K3 (336 chars)")
count_yar_in_section(K4_CARVED, "K4 (97 chars)")
count_yar_in_section(full_text, "Full grid")

# K4 YAR positions:
k4_yar_pos = [i for i, c in enumerate(K4_CARVED) if c in 'YAR']
print(f"\n  K4 YAR positions: {k4_yar_pos}")
print(f"  K4 YAR chars: {[K4_CARVED[i] for i in k4_yar_pos]}")

# What tableau letters are at K4 YAR positions?
print("  Tableau letters at K4 YAR positions:")
k4_yar_tableau = []
for pos in k4_yar_pos:
    cell = K4_CELLS[pos]
    r, c = cell
    tv = TABLEAU[r][c]
    k4_yar_tableau.append(tv)
    print(f"    K4[{pos:2d}] = {K4_CARVED[pos]}: grid({r},{c}) → tableau = {tv}")

print(f"  GE chars at K4 positions: {''.join(k4_yar_tableau)}")

# If GE ends with these chars, we can locate K4 in the grille extract
print(f"\n  Last {len(k4_yar_pos)} chars of GE: {GE[-len(k4_yar_pos):]}")
print(f"  K4 YAR tableau chars:       {''.join(k4_yar_tableau)}")

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION P: DIRECT GRILLE FROM MATCH POSITIONS
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("SECTION P: GRILLE = MATCH POSITIONS HYPOTHESIS")
print("="*70)

# HYPOTHESIS: Grille holes are at positions where cipher[r][c] == tableau[r][c].
# These 39 positions (ambiguous under grille) ARE the holes.
# Reading the tableau at these positions gives part of the real CT.

# For K4: how many match positions are in K4 region?
k4_matches = [(r,c) for (r,c) in MATCHES if r >= 24 and (r > 24 or c >= 27)]
k3_matches_full = [(r,c) for (r,c) in MATCHES if r >= 14 and (r < 24 or c <= 25)]

print(f"  Match positions in K4 region: {len(k4_matches)}: {k4_matches}")
print(f"  Match positions in K3 region: {len(k3_matches_full)}: {k3_matches_full}")

# If these 39 match positions are holes, they give 39 real_CT chars.
# Remaining positions in each section must be assigned somehow.

# Under this hypothesis, try reading the tableau at ALL match positions:
all_match_tableau = ''.join(TABLEAU[r][c] for (r,c) in sorted(MATCHES))
print(f"\n  Tableau at ALL {len(MATCHES)} match positions: {all_match_tableau}")

# ═══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("SUMMARY")
print("="*70)
print("""
Key findings from this analysis:

A. 180° rotation: maps K1+K2 to K3+K4. The 180° grille = FULL REVERSE of bottom half.
   This is a testable hypothesis: K4_real_CT = K4_CARVED_reversed.

B. K3 verification: Tested reversed K3 with all keys/ciphers → no match found.
   The K3 method (double columnar RTL 21,28) is the actual scramble, not 180° reversal.

C. Match-based: 39 matches distributed across grid. No obvious pattern.

D. YAR positions: K4 has 9 YAR chars. These map to specific tableau cells.
   Tableau values at these positions = potential GE fragment.

E. Tableau cipher: Direct tableau decryption of K4 = noise.

F. K4 occupies EXACTLY 97 cells = all cells in rows 24-27 starting col 27.
   The scramble is purely a permutation of these 97 cells.

CRITICAL: No crib hits found. Need to continue with:
1. More sophisticated grille patterns
2. Using K3's known permutation to constrain K4's permutation
3. Physical/geometric grille models
""")
