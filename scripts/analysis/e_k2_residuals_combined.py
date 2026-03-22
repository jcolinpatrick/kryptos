#!/usr/bin/env python3
"""K2 Residual Numbers as Combined Parameters.

Cipher:     Beaufort A=0 (two-system model)
Family:     analysis
Status:     active
Keyspace:   analytical + small brute-force
Last run:   2026-03-21
Best score: TBD

K2 progressive solve: 38→24, 77→14, 8→8 encode K3 dimensions.
Residuals: 44, 57, 6.5, N, W are UNUSED.

Tests:
- 44 and 57 as combined cipher parameters
- 44×57 interaction matrix
- (44,57) as grid coordinates → key lookup
- 6.5 as ×2=13, ×4=26, as sector angle (6.5°), as decimal offset
- N/W as directional grid reading parameters
"""
import sys, os, json, math
from collections import Counter
from datetime import datetime

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, ALPH, ALPH_IDX, KRYPTOS_ALPHABET

KA = KRYPTOS_ALPHABET
KA_IDX = {ch: i for i, ch in enumerate(KA)}

def az(ch): return ALPH_IDX[ch]
def az_chr(v): return ALPH[v % 26]
def ka_row(ch): return KA_IDX[ch] // 5
def ka_col(ch): return KA_IDX[ch] % 5
def beaufort_key(ct_ch, pt_ch): return (az(ct_ch) + az(pt_ch)) % 26
def beaufort_decrypt_ch(ct_ch, key_val): return az_chr((key_val - az(ct_ch)) % 26)

# ── Known keystream ─────────────────────────────────────────────────────
ENE_KS = [beaufort_key(c, p) for c, p in zip(CT[21:34], "EASTNORTHEAST")]
BCL_KS = [beaufort_key(c, p) for c, p in zip(CT[63:74], "BERLINCLOCK")]
FULL_KS = ENE_KS + BCL_KS

# Load quadgrams
quadgram_file = os.path.join(_ROOT, "data", "english_quadgrams.json")
QUADGRAMS = {}
if os.path.exists(quadgram_file):
    with open(quadgram_file) as f:
        QUADGRAMS = json.load(f)
    print(f"Loaded {len(QUADGRAMS):,} quadgrams")

FLOOR = -10.0

def qg_score(text):
    if len(text) < 4 or not QUADGRAMS:
        return FLOOR
    total = sum(QUADGRAMS.get(text[i:i+4], FLOOR) for i in range(len(text) - 3))
    return total / (len(text) - 3)

# ── K2 coordinate numbers ──────────────────────────────────────────────
# 38°57'6.5" N, 77°8'44" W
# Progressive solve: 38→24 (K3 cols), 77→14 (K3 rows), 8→8 (rotation param)
# Residuals: 44, 57, 6.5
# Also: N=13 (AZ), W=22 (AZ)

K2_NUMS = {
    '38': 38, '57': 57, '6.5': 6.5, '77': 77, '8': 8, '44': 44,
    'N': 13, 'W': 22
}

print("=" * 78)
print("K2 RESIDUAL NUMBERS AS CIPHER PARAMETERS")
print("=" * 78)

print(f"\nK2 numbers: {K2_NUMS}")
print(f"Used (K3 dims): 38→24, 77→14, 8→8")
print(f"Residual: 44, 57, 6.5, N(13), W(22)")

# ── Test 1: (44, 57) as key offset ─────────────────────────────────────
print(f"\n{'='*78}")
print("TEST 1: 44 and 57 as key generation parameters")
print("=" * 78)

# 44 mod 26 = 18, 57 mod 26 = 5
# 44 + 57 = 101, 44 * 57 = 2508
# 44 - 57 = -13 (= 13 mod 26 = N!)
# 57 - 44 = 13 = N!
print(f"\n  44 mod 26 = {44 % 26} → {az_chr(44 % 26)}")
print(f"  57 mod 26 = {57 % 26} → {az_chr(57 % 26)}")
print(f"  44 + 57 = {44 + 57} → mod 26 = {(44+57)%26} → {az_chr((44+57)%26)}")
print(f"  57 - 44 = {57 - 44} = 13 = N = NORTH!")
print(f"  44 * 57 = {44 * 57}")
print(f"  gcd(44, 57) = {math.gcd(44, 57)}")
print(f"  lcm(44, 57) = {(44*57)//math.gcd(44, 57)}")
print(f"  44 / 6.5 = {44/6.5:.4f}")
print(f"  57 / 6.5 = {57/6.5:.4f}")

# 57 - 44 = 13 = length of EASTNORTHEAST!
print(f"\n  ★ 57 - 44 = 13 = length of EASTNORTHEAST (13 chars)")
print(f"  ★ 44 = first crib position offset from CT start (21+23=44? no, 21+11=32)")
print(f"  ★ Position 44 in CT = {CT[44]}")
print(f"  ★ Position 57 in CT = {CT[57]}")

# ── Test 2: 44-char repeating key cycle ─────────────────────────────────
print(f"\n{'='*78}")
print("TEST 2: 44-char key cycle (positions mod 44)")
print("=" * 78)

# If key repeats every 44 chars, positions 0 and 44 have the same key
# Check: do any crib positions share key values under mod 44?
crib_positions = list(range(21, 34)) + list(range(63, 74))
crib_keys = list(FULL_KS)

print(f"\nCrib positions mod 44:")
for i, pos in enumerate(crib_positions):
    mod44 = pos % 44
    print(f"  pos {pos:2d} → mod 44 = {mod44:2d}, key = {az_chr(crib_keys[i])} ({crib_keys[i]})")

# Check conflicts
mod44_dict = {}
conflicts = 0
for i, pos in enumerate(crib_positions):
    m = pos % 44
    if m in mod44_dict:
        prev_pos, prev_key = mod44_dict[m]
        if prev_key != crib_keys[i]:
            conflicts += 1
            print(f"  CONFLICT: pos {prev_pos} (key {prev_key}) vs pos {pos} (key {crib_keys[i]}) at mod44={m}")
        else:
            print(f"  MATCH: pos {prev_pos} and pos {pos} both have key {crib_keys[i]} at mod44={m}")
    mod44_dict[m] = (pos, crib_keys[i])

print(f"\nConflicts at period 44: {conflicts}")

# Same for period 57
print(f"\nCrib positions mod 57:")
mod57_dict = {}
conflicts_57 = 0
for i, pos in enumerate(crib_positions):
    m = pos % 57
    if m in mod57_dict:
        prev_pos, prev_key = mod57_dict[m]
        if prev_key != crib_keys[i]:
            conflicts_57 += 1
            print(f"  CONFLICT: pos {prev_pos} (key {prev_key}) vs pos {pos} (key {crib_keys[i]}) at mod57={m}")
    mod57_dict[m] = (pos, crib_keys[i])

print(f"Conflicts at period 57: {conflicts_57}")

# ── Test 3: 6.5 as a decimal parameter ──────────────────────────────────
print(f"\n{'='*78}")
print("TEST 3: 6.5 as parameter")
print("=" * 78)

# 6.5 × 2 = 13 (ENE crib length!)
# 6.5 × 4 = 26 (alphabet size!)
# 6.5 × 11 = 71.5
# 6.5° = angle of sector on a 360° wheel → 360/6.5 ≈ 55.38 sectors
# 6.5 as Fibonacci: F(6) = 8, F(7) = 13 → 6.5 is midpoint

print(f"  6.5 × 2 = {6.5 * 2} → 13 = ENE crib length!")
print(f"  6.5 × 4 = {6.5 * 4} → 26 = alphabet size!")
print(f"  6.5 × 15 = {6.5 * 15} → 97.5 ≈ 97 CT length!")
print(f"  6.5 × 11 = {6.5 * 11} → 71.5")
print(f"  6.5 × 14 = {6.5 * 14} → 91 (K3 grid 14 rows)")
print(f"  360° / 6.5° = {360/6.5:.2f} sectors")
print(f"  K4 CT length / 6.5 = {97/6.5:.4f}")
print(f"  73 / 6.5 = {73/6.5:.4f}")

# ── Test 4: N/W as directional reading ──────────────────────────────────
print(f"\n{'='*78}")
print("TEST 4: N and W as grid reading directions")
print("=" * 78)

# N = North = upward, W = West = leftward
# On a 14×7 K4 grid (97+1=98), reading NW means: start at bottom-right, go up-left

k4_padded = CT + "?"
grid_14x7 = []
for r in range(14):
    grid_14x7.append(k4_padded[r*7:(r+1)*7])

# NW diagonal reading
print("\n14×7 grid NW diagonal readings:")
for start_row in range(14):
    diag = []
    r, c = start_row, 6  # start at rightmost column
    while r >= 0 and c >= 0:
        diag.append(grid_14x7[r][c])
        r -= 1
        c -= 1
    print(f"  Start row {start_row:2d}: {''.join(diag)}")

# Read bottom-to-top, right-to-left
print(f"\nBottom-to-top, right-to-left:")
bt_rl = ""
for r in range(13, -1, -1):
    bt_rl += grid_14x7[r][::-1]
print(f"  {bt_rl[:50]}...")
print(f"  Quadgram score: {qg_score(bt_rl):.3f}")

# Read column-wise from N to S (top to bottom), then W to E (left to right)
print(f"\nColumn-wise (N→S, then W→E):")
col_ns = ""
for c in range(7):
    for r in range(14):
        col_ns += grid_14x7[r][c]
print(f"  {col_ns[:50]}...")

# ── Test 5: 44×57 interaction grid ──────────────────────────────────────
print(f"\n{'='*78}")
print("TEST 5: Position-based key from (pos mod 44, pos mod 57)")
print("=" * 78)

# If key[i] = f(i%44, i%57), check crib consistency
print(f"\nCrib positions in (mod44, mod57) space:")
for i, pos in enumerate(crib_positions):
    m44 = pos % 44
    m57 = pos % 57
    print(f"  pos {pos:2d}: ({m44:2d}, {m57:2d}) → key {az_chr(crib_keys[i])} ({crib_keys[i]})")

# Check if (mod44, mod57) uniquely determines key
mod_dict = {}
conflicts_combined = 0
for i, pos in enumerate(crib_positions):
    key = (pos % 44, pos % 57)
    if key in mod_dict:
        prev_pos, prev_kv = mod_dict[key]
        if prev_kv != crib_keys[i]:
            conflicts_combined += 1
            print(f"  CONFLICT: ({key}) maps to both {prev_kv} (pos {prev_pos}) and {crib_keys[i]} (pos {pos})")
    mod_dict[key] = (pos, crib_keys[i])

print(f"\nConflicts at (mod44, mod57): {conflicts_combined}")
if conflicts_combined == 0:
    print("  NO CONFLICTS — (mod44, mod57) is consistent with key assignment!")
    print(f"  Period = lcm(44,57) = {(44*57)//math.gcd(44,57)}")

# Also test (mod57, mod44)
# And other K2 number pairs
for a, b in [(44, 57), (57, 44), (44, 13), (57, 13), (44, 26), (57, 26),
             (13, 11), (24, 14), (44, 97), (57, 97)]:
    mod_dict = {}
    conflicts = 0
    for i, pos in enumerate(crib_positions):
        key = (pos % a, pos % b)
        if key in mod_dict:
            prev_pos, prev_kv = mod_dict[key]
            if prev_kv != crib_keys[i]:
                conflicts += 1
        mod_dict[key] = (pos, crib_keys[i])
    if conflicts == 0:
        period = (a * b) // math.gcd(a, b)
        note = " ★ CONSISTENT" if period >= 97 else f" (period {period} < 97)"
        print(f"  (mod {a:3d}, mod {b:3d}): 0 conflicts, period={period}{note}")

# ── Test 6: 44 and 57 in the keystream itself ───────────────────────────
print(f"\n{'='*78}")
print("TEST 6: 44 and 57 in keystream values")
print("=" * 78)

# 44 mod 26 = 18 → S (KA row 1, col 1)
# 57 mod 26 = 5 → F (KA row 2, col 2)
# Neither is in the 12-value restricted set
print(f"  44 mod 26 = 18 → {az_chr(18)} — {'IN' if 18 in set(FULL_KS) else 'NOT in'} restricted set")
print(f"  57 mod 26 = 5 → {az_chr(5)} — {'IN' if 5 in set(FULL_KS) else 'NOT in'} restricted set")

# Sum of keystream values
ks_sum = sum(FULL_KS)
print(f"  Sum of 24 keystream values: {ks_sum}")
print(f"  {ks_sum} mod 44 = {ks_sum % 44}")
print(f"  {ks_sum} mod 57 = {ks_sum % 57}")
print(f"  {ks_sum} / 24 = {ks_sum / 24:.2f}")

# ── Save results ────────────────────────────────────────────────────────
outfile = os.path.join(_ROOT, "results", "e_k2_residuals_combined.json")
os.makedirs(os.path.dirname(outfile), exist_ok=True)

output = {
    "experiment": "e_k2_residuals_combined",
    "timestamp": datetime.now().isoformat(),
    "description": "K2 residual numbers (44, 57, 6.5) as combined cipher parameters",
    "period_44_conflicts": conflicts,
    "period_57_conflicts": conflicts_57,
    "mod44_mod57_conflicts": conflicts_combined,
    "ks_sum": ks_sum,
    "key_finding": "57-44=13=ENE_length, 6.5×2=13, 6.5×4=26",
}

with open(outfile, 'w') as f:
    json.dump(output, f, indent=2)
print(f"\nResults saved to {outfile}")
