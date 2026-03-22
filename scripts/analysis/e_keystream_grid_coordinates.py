#!/usr/bin/env python3
"""Keystream as Grid Coordinates: map keystream to physical grids.

Cipher:     Beaufort A=0 (two-system model)
Family:     analysis
Status:     active
Keyspace:   analytical
Last run:   2026-03-21
Best score: TBD

Maps 24 keystream values to (row, col) pairs on the 5-wide KA Polybius grid,
then uses those coordinates to read characters from K4's physical grids
(14x7, 14x24, 14x31, 28x31). Also tests reversed coordinates and modular
wrapping.
"""
import sys, os, json
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

def beaufort_key(ct_ch, pt_ch):
    return (az(ct_ch) + az(pt_ch)) % 26

# ── Known keystream ─────────────────────────────────────────────────────
ENE_PT = "EASTNORTHEAST"
BCL_PT = "BERLINCLOCK"
ENE_KS = [beaufort_key(c, p) for c, p in zip(CT[21:34], ENE_PT)]
BCL_KS = [beaufort_key(c, p) for c, p in zip(CT[63:74], BCL_PT)]
FULL_KS = ENE_KS + BCL_KS

KS_LETTERS = [az_chr(v) for v in FULL_KS]
KS_ROWS = [ka_row(ch) for ch in KS_LETTERS]
KS_COLS = [ka_col(ch) for ch in KS_LETTERS]
KS_KA = [KA_IDX[ch] for ch in KS_LETTERS]

# ── Grid definitions ────────────────────────────────────────────────────

# K3 ciphertext (336 chars) - read from K3 code chart columns bottom-to-top
K3_CT = ("ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA"
         "CHTNREYULDSLLSLLNOHSNOSMRWXMNET"
         "PRNGATIHNRARPESLNNELEBLPIIACAEWM"
         "TWNDITEENRAHCTENEUDRETNHAEOETFOL"
         "SEDNTITISETHAMREHINMENOCAFDIAANE"
         "IRLMKSHPTTLVMRLLHSQTOTINMVYAPC"
         "PJAHVARTJNLHWKAALRBIDPSHEVCPNKA"
         "FIYYYQPWMQNCYIXNHRMFVHLGTTMFRYP"
         "TTELAOSMMSKHFDBCPRBRELNNIELSYNTE"
         "COYQTCFPJCFKVSTHIPHFHEIRLPFDQFP"
         "JQBAXJERHTIKNBYPTGQRLTQEKNECRYG")
K3_CT = K3_CT[:336]  # Ensure exactly 336

# K4 ciphertext = CT (97 chars)
K4_CT = CT

# K1 PT (63 chars)
K1_PT = ("BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUAN"
         "CEOFIQLUSION")[:63]

# K2 PT (69 chars)
K2_PT = ("ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDT"
         "HEEARTHSMAGNETICFIELDX")[:69]

# K3 PT (336 chars)
K3_PT = ("SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBR"
         "ISTHATENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASRE"
         "MOVEDWITHTREMBLINGHANDSIMADEATINYBREACHINTHEM"
         "UPPERLEFTHANDCORNERANDTHENWIDENINGTHEHOLEALIT"
         "TLEINSERTEDACANDLEANDPEEREDINTHEHOTAIRESCA"
         "PINGFROMTHECHAMBERMADETHECANDLEFLICKERBUTP"
         "RESENTLYDETAILSOFTHEROOMWITHINEMERGEDFROM"
         "THEMISTXCANYOUSEEANYTHINGQ")[:336]

print("=" * 78)
print("KEYSTREAM AS GRID COORDINATES")
print("=" * 78)

print(f"\nKeystream letters: {''.join(KS_LETTERS)}")
print(f"KA indices:        {KS_KA}")
print(f"Polybius rows:     {KS_ROWS}")
print(f"Polybius cols:     {KS_COLS}")

# ── Grid 1: K4 in 14×7 grid (97+1=98=14×7) ────────────────────────────
print(f"\n{'='*78}")
print("GRID 1: K4 CT in 14×7 grid (98 = 14 rows × 7 cols)")
print("=" * 78)

# Pad K4 to 98 with ?
k4_padded = K4_CT + "?"
grid_14x7 = []
for r in range(14):
    row_chars = k4_padded[r*7:(r+1)*7]
    grid_14x7.append(row_chars)
    print(f"  Row {r:2d}: {row_chars}")

print("\nReading keystream (row,col) → grid character:")
for mode_name, row_fn, col_fn in [
    ("Direct (row,col)", lambda r,c: r, lambda r,c: c),
    ("Reversed (col,row)", lambda r,c: c, lambda r,c: r),
    ("(row, col%7)", lambda r,c: r, lambda r,c: c % 7),
    ("(row%14, col)", lambda r,c: r % 14, lambda r,c: c),
    ("(KA_idx%14, KA_idx%7)", None, None),
]:
    extracted = []
    valid = True
    for i in range(24):
        if mode_name == "(KA_idx%14, KA_idx%7)":
            r = KS_KA[i] % 14
            c = KS_KA[i] % 7
        else:
            r = row_fn(KS_ROWS[i], KS_COLS[i])
            c = col_fn(KS_ROWS[i], KS_COLS[i])
        if r < 14 and c < 7:
            extracted.append(grid_14x7[r][c])
        else:
            extracted.append('?')
            valid = False
    result = ''.join(extracted)
    print(f"  {mode_name:30s} → {result}")

# ── Grid 2: K4 CT in 4×24 grid ─────────────────────────────────────────
print(f"\n{'='*78}")
print("GRID 2: K4 CT in 4×24+1 grid")
print("=" * 78)

k4_pad24 = K4_CT + "?"*(-len(K4_CT) % 24)  # pad to multiple of 24
grid_4x24 = []
for r in range(4):
    row_chars = k4_pad24[r*24:(r+1)*24]
    grid_4x24.append(row_chars)
    print(f"  Row {r}: {row_chars}")

print("\nReading (row%4, col) → grid character:")
for i in range(24):
    r = KS_ROWS[i] % 4
    c = KS_COLS[i]
    if c < 24:
        ch = grid_4x24[r][c]
    else:
        ch = '?'
print(f"  (row%4, col):   {''.join(grid_4x24[KS_ROWS[i]%4][KS_COLS[i]] if KS_COLS[i]<24 else '?' for i in range(24))}")

# ── Grid 3: K3 code chart 14×24 ────────────────────────────────────────
print(f"\n{'='*78}")
print("GRID 3: K3 PT in 14×24 code chart grid")
print("=" * 78)

grid_14x24 = []
for r in range(14):
    row_chars = K3_PT[r*24:(r+1)*24]
    grid_14x24.append(row_chars)
    print(f"  Row {r:2d}: {row_chars}")

print("\nReading keystream coordinates on K3 PT grid:")
for mode_name, get_rc in [
    ("Direct (row,col)", lambda i: (KS_ROWS[i], KS_COLS[i])),
    ("Reversed (col,row)", lambda i: (KS_COLS[i], KS_ROWS[i])),
    ("(KA%14, KA%24)", lambda i: (KS_KA[i]%14, KS_KA[i]%24)),
    ("(row%14, col%24)", lambda i: (KS_ROWS[i]%14, KS_COLS[i]%24)),
    ("(AZ_val%14, AZ_val%24)", lambda i: (FULL_KS[i]%14, FULL_KS[i]%24)),
]:
    extracted = []
    for i in range(24):
        r, c = get_rc(i)
        if r < 14 and c < 24:
            extracted.append(grid_14x24[r][c])
        else:
            extracted.append('?')
    result = ''.join(extracted)
    print(f"  {mode_name:35s} → {result}")

# ── Grid 4: K3 CT in 14×24 grid ────────────────────────────────────────
print(f"\n{'='*78}")
print("GRID 4: K3 CT in 14×24 grid")
print("=" * 78)

grid_k3ct = []
for r in range(14):
    row_chars = K3_CT[r*24:(r+1)*24]
    grid_k3ct.append(row_chars)
    print(f"  Row {r:2d}: {row_chars}")

print("\nReading keystream coordinates on K3 CT grid:")
for mode_name, get_rc in [
    ("Direct (row,col)", lambda i: (KS_ROWS[i], KS_COLS[i])),
    ("(KA%14, KA%24)", lambda i: (KS_KA[i]%14, KS_KA[i]%24)),
    ("(AZ%14, AZ%24)", lambda i: (FULL_KS[i]%14, FULL_KS[i]%24)),
]:
    extracted = []
    for i in range(24):
        r, c = get_rc(i)
        if r < 14 and c < 24:
            extracted.append(grid_k3ct[r][c])
        else:
            extracted.append('?')
    result = ''.join(extracted)
    print(f"  {mode_name:35s} → {result}")

# ── Grid 5: Full lower panel 14×31 (K3+?+K4) ──────────────────────────
print(f"\n{'='*78}")
print("GRID 5: Lower panel 14×31 (K3 336 + ? + K4 97 = 434)")
print("=" * 78)

lower_panel = K3_CT + "?" + K4_CT  # 336 + 1 + 97 = 434 = 14×31
grid_14x31 = []
for r in range(14):
    row_chars = lower_panel[r*31:(r+1)*31]
    grid_14x31.append(row_chars)
    print(f"  Row {r:2d}: {row_chars}")

print("\nReading keystream coordinates on 14×31 lower panel:")
for mode_name, get_rc in [
    ("Direct (row,col)", lambda i: (KS_ROWS[i], KS_COLS[i])),
    ("(KA%14, KA%31)", lambda i: (KS_KA[i]%14, KS_KA[i]%31)),
    ("(AZ%14, AZ%31)", lambda i: (FULL_KS[i]%14, FULL_KS[i]%31)),
]:
    extracted = []
    for i in range(24):
        r, c = get_rc(i)
        if r < 14 and c < 31:
            extracted.append(grid_14x31[r][c])
        else:
            extracted.append('?')
    result = ''.join(extracted)
    print(f"  {mode_name:35s} → {result}")

# ── Grid 6: K4 CT in 7×14 grid (transposed) ────────────────────────────
print(f"\n{'='*78}")
print("GRID 6: K4 CT in 7×14 grid (7 rows × 14 cols, 98=97+1)")
print("=" * 78)

grid_7x14 = []
for r in range(7):
    row_chars = k4_padded[r*14:(r+1)*14]
    grid_7x14.append(row_chars)
    print(f"  Row {r}: {row_chars}")

print("\nReading keystream coordinates on 7×14 grid:")
for mode_name, get_rc in [
    ("Direct (row,col)", lambda i: (KS_ROWS[i], KS_COLS[i])),
    ("(row%7, col)", lambda i: (KS_ROWS[i]%7, KS_COLS[i])),
    ("(KA%7, KA%14)", lambda i: (KS_KA[i]%7, KS_KA[i]%14)),
    ("(AZ%7, AZ%14)", lambda i: (FULL_KS[i]%7, FULL_KS[i]%14)),
]:
    extracted = []
    for i in range(24):
        r, c = get_rc(i)
        if r < 7 and c < 14:
            extracted.append(grid_7x14[r][c])
        else:
            extracted.append('?')
    result = ''.join(extracted)
    print(f"  {mode_name:35s} → {result}")

# ── Row sequence analysis ───────────────────────────────────────────────
print(f"\n{'='*78}")
print("ROW SEQUENCE STRUCTURE")
print("=" * 78)

print(f"\nRow sequence: {KS_ROWS}")
print(f"Col sequence: {KS_COLS}")

# Run-length encoding of rows
runs = []
cur_val, cur_len = KS_ROWS[0], 1
for i in range(1, len(KS_ROWS)):
    if KS_ROWS[i] == cur_val:
        cur_len += 1
    else:
        runs.append((cur_val, cur_len))
        cur_val, cur_len = KS_ROWS[i], 1
runs.append((cur_val, cur_len))
print(f"Row runs: {runs}")
print(f"Run lengths: {[r[1] for r in runs]}")

# Autocorrelation of row sequence
print(f"\nRow sequence autocorrelation:")
n = len(KS_ROWS)
mean_r = sum(KS_ROWS) / n
var_r = sum((r - mean_r)**2 for r in KS_ROWS) / n
if var_r > 0:
    for lag in range(1, 13):
        cov = sum((KS_ROWS[i] - mean_r) * (KS_ROWS[i+lag] - mean_r)
                  for i in range(n - lag)) / (n - lag)
        acf = cov / var_r
        bar = '#' * int(abs(acf) * 30)
        sign = '+' if acf >= 0 else '-'
        print(f"  lag {lag:2d}: {acf:+.3f} {sign}{bar}")

# ── Coordinate pair analysis ────────────────────────────────────────────
print(f"\n{'='*78}")
print("COORDINATE PAIR ANALYSIS")
print("=" * 78)

print(f"\n  Pos  KS_letter  AZ   KA   Row  Col  (row,col)")
crib_positions = list(range(21, 34)) + list(range(63, 74))
for i, pos in enumerate(crib_positions):
    ch = KS_LETTERS[i]
    print(f"  {pos:3d}  {ch}          {FULL_KS[i]:3d}  {KS_KA[i]:3d}  {KS_ROWS[i]:3d}  {KS_COLS[i]:3d}    ({KS_ROWS[i]},{KS_COLS[i]})")

# Check for (row,col) pairs that repeat
pair_counts = Counter(zip(KS_ROWS, KS_COLS))
print(f"\nRepeated (row,col) pairs:")
for (r, c), cnt in sorted(pair_counts.items(), key=lambda x: -x[1]):
    if cnt > 1:
        positions = [i for i in range(24) if KS_ROWS[i] == r and KS_COLS[i] == c]
        letters_at = [KS_LETTERS[i] for i in positions]
        print(f"  ({r},{c}) × {cnt}: positions {positions} → letters {letters_at}")

# ── AZ value as direct coordinate ───────────────────────────────────────
print(f"\n{'='*78}")
print("AZ VALUE AS DIRECT GRID INDEX")
print("=" * 78)

# Use AZ values (0-25) directly as indices into CT97
print(f"\nAZ values as positions in CT97: ", end="")
extracted = ''.join(CT[v] if v < 97 else '?' for v in FULL_KS)
print(extracted)

# Use KA values as positions in CT97
print(f"KA values as positions in CT97: ", end="")
extracted = ''.join(CT[v] if v < 97 else '?' for v in KS_KA)
print(extracted)

# Use AZ values as positions in K3 CT
print(f"AZ values as positions in K3 CT: ", end="")
extracted = ''.join(K3_CT[v] if v < len(K3_CT) else '?' for v in FULL_KS)
print(extracted)

# Use AZ values (cumulative sum mod 97) as positions
cumsum = []
total = 0
for v in FULL_KS:
    total = (total + v) % 97
    cumsum.append(total)
print(f"Cumulative AZ mod 97 → CT97: ", end="")
extracted = ''.join(CT[p] for p in cumsum)
print(extracted)

# ── Save results ────────────────────────────────────────────────────────
outfile = os.path.join(_ROOT, "results", "e_keystream_grid_coordinates.json")
os.makedirs(os.path.dirname(outfile), exist_ok=True)

output = {
    "experiment": "e_keystream_grid_coordinates",
    "timestamp": datetime.now().isoformat(),
    "description": "Map keystream Polybius coordinates to physical K4 grids",
    "keystream_letters": ''.join(KS_LETTERS),
    "polybius_rows": KS_ROWS,
    "polybius_cols": KS_COLS,
    "ka_indices": KS_KA,
    "row_runs": [(v, l) for v, l in runs],
    "repeated_pairs": {f"({r},{c})": cnt for (r, c), cnt in pair_counts.items() if cnt > 1},
}

with open(outfile, 'w') as f:
    json.dump(output, f, indent=2)
print(f"\nResults saved to {outfile}")
