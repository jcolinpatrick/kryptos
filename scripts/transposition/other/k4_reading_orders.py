"""
Cipher: non-columnar transposition
Family: transposition/other
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
Test non-standard reading orders, CT superposition, and coordinate-derived keys.
If K4's CT should be read in a non-standard order before decryption,
the cribs would match after reordering + Vigenère/Beaufort decryption.
"""
import sys
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from math import gcd

CT = 'OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR'
CT_NUM = [ord(c) - ord('A') for c in CT]
N = len(CT)  # 97

CRIBS = [
    (21, 'EASTNORTHEAST'),
    (63, 'BERLINCLOCK'),
]

def c2n(c): return ord(c) - ord('A')
def n2c(n): return chr(n % 26 + ord('A'))

def score_crib(text_nums, pos, pt):
    """Count how many positions in pt match the decrypted text at pos."""
    matches = 0
    for i, ch in enumerate(pt):
        if pos + i < len(text_nums):
            if text_nums[pos + i] == c2n(ch):
                matches += 1
    return matches

def score_all_cribs(text_nums):
    """Score a candidate plaintext against all cribs. Return total matches."""
    total = 0
    for pos, pt in CRIBS:
        total += score_crib(text_nums, pos, pt)
    return total

def best_crib_score(text_nums):
    """Try all crib positions and return best total."""
    best = 0
    for pos, pt in CRIBS:
        s = score_crib(text_nums, pos, pt)
        best = max(best, s)
    return best

print("=" * 70)
print("K4 NON-STANDARD READING ORDER ANALYSIS")
print("=" * 70)

# ============================================================
# 1. CT REVERSED
# ============================================================
print("\n1. REVERSED CIPHERTEXT")
rev_ct = CT[::-1]
rev_num = [c2n(c) for c in rev_ct]
# Try Vigenere decryption with periodic keys period 1-13
best_rev = 0
for period in range(1, 14):
    for key_start in range(26):
        key = [(key_start + i) % 26 for i in range(period)]  # simple progressive
        pt = [(rev_num[i] - key[i % period]) % 26 for i in range(N)]
        s = score_all_cribs(pt)
        best_rev = max(best_rev, s)
# Also try raw reversed
s_raw = score_all_cribs(rev_num)
print(f"  Raw reversed (no key): {s_raw}/24")
print(f"  Best with progressive keys: {best_rev}/24")

# ============================================================
# 2. CT SUPERPOSITION (differential analysis)
# ============================================================
print("\n2. CT SUPERPOSITION (CT[i] - CT[i+d] mod 26)")
print("  Testing if differencing CT at offset d yields cribs:")
for d in range(1, N):
    diff = [(CT_NUM[i] - CT_NUM[(i + d) % N]) % 26 for i in range(N)]
    s = score_all_cribs(diff)
    if s >= 4:
        print(f"  d={d:2d}: {s}/24 matches")

# Also try (CT[i+d] - CT[i]) mod 26
print("  Reverse direction:")
for d in range(1, N):
    diff = [(CT_NUM[(i + d) % N] - CT_NUM[i]) % 26 for i in range(N)]
    s = score_all_cribs(diff)
    if s >= 4:
        print(f"  d={d:2d}: {s}/24 matches")

# ============================================================
# 3. COLUMNAR READ-OFF (route cipher)
# ============================================================
print("\n3. COLUMNAR READ-OFF (grid rearrangements)")
print("  Arrange CT in grid of width W, read by columns, then try Vig decryption:")

def read_by_columns(text, width):
    """Arrange text in rows of given width, read by columns."""
    n = len(text)
    nrows = (n + width - 1) // width
    result = []
    for col in range(width):
        for row in range(nrows):
            idx = row * width + col
            if idx < n:
                result.append(text[idx])
    return result

def read_by_columns_bottom_up(text, width):
    """Arrange in rows, read columns bottom to top."""
    n = len(text)
    nrows = (n + width - 1) // width
    result = []
    for col in range(width):
        for row in range(nrows - 1, -1, -1):
            idx = row * width + col
            if idx < n:
                result.append(text[idx])
    return result

def read_by_rows_reversed(text, width):
    """Serpentine: odd rows read right-to-left."""
    n = len(text)
    nrows = (n + width - 1) // width
    result = []
    for row in range(nrows):
        row_chars = []
        for col in range(width):
            idx = row * width + col
            if idx < n:
                row_chars.append(text[idx])
        if row % 2 == 1:
            row_chars.reverse()
        result.extend(row_chars)
    return result

def diagonal_read(text, width):
    """Read diagonals top-left to bottom-right."""
    n = len(text)
    nrows = (n + width - 1) // width
    result = []
    for diag in range(nrows + width - 1):
        for row in range(nrows):
            col = diag - row
            if 0 <= col < width:
                idx = row * width + col
                if idx < n:
                    result.append(text[idx])
    return result

known_key_vals = {}
for pos, pt in CRIBS:
    for i, ch in enumerate(pt):
        known_key_vals[pos + i] = (CT_NUM[pos + i] - c2n(ch)) % 26

best_grid = (0, 0, "")
for width in range(2, 50):
    for read_fn_name, read_fn in [
        ("cols", read_by_columns),
        ("cols_btm", read_by_columns_bottom_up),
        ("serpentine", read_by_rows_reversed),
        ("diagonal", diagonal_read),
    ]:
        reordered = read_fn(CT, width)
        reordered_num = [c2n(c) for c in reordered]

        # Direct crib check (no Vig key)
        s = score_all_cribs(reordered_num)
        if s > best_grid[0]:
            best_grid = (s, width, read_fn_name)
        if s >= 5:
            print(f"  W={width:2d} {read_fn_name}: {s}/24 (raw)")

        # Try with all single-key Vig shifts
        for shift in range(26):
            pt_attempt = [(v - shift) % 26 for v in reordered_num]
            s = score_all_cribs(pt_attempt)
            if s >= 6:
                print(f"  W={width:2d} {read_fn_name} shift={shift}: {s}/24")

print(f"  Best grid result: {best_grid}")

# ============================================================
# 4. MULTIPLICATIVE / DECIMATION READING ORDER
# ============================================================
print("\n4. DECIMATION READING ORDER (step through CT by stride)")
print("  Read CT[0], CT[s], CT[2s], ... mod 97:")
for stride in range(2, N):
    if gcd(stride, N) != 1:
        continue  # skip non-coprime strides (won't visit all positions)
    reordered_num = [CT_NUM[(i * stride) % N] for i in range(N)]
    s = score_all_cribs(reordered_num)
    if s >= 4:
        print(f"  stride={stride:2d}: {s}/24")

# ============================================================
# 5. COORDINATE-DERIVED KEYS
# ============================================================
print("\n" + "=" * 70)
print("5. COORDINATE-DERIVED KEYS")
print("=" * 70)

# K2 coordinates: 38°57'6.5"N, 77°8'44"W
# Various numeric encodings
coord_keys = {
    'lat_digits': [3,8,5,7,6,5],
    'lon_digits': [7,7,8,4,4],
    'lat_lon': [3,8,5,7,6,5,7,7,8,4,4],
    'lon_lat': [7,7,8,4,4,3,8,5,7,6,5],
    'lat_dms': [3,8,5,7,0,6,5],  # 38 57 06.5
    'lon_dms': [7,7,0,8,4,4],     # 77 08 44
    'full_coords': [3,8,5,7,0,6,5,7,7,0,8,4,4],
    'lat_int': [3,8,5,7],
    'lon_int': [7,7,0,8],
    'coords_mod26': [(385765 * i) % 26 for i in range(13)],
    'reversed_lat': [5,6,7,5,8,3],
    'reversed_lon': [4,4,8,7,7],
}

for name, key in coord_keys.items():
    if not key:
        continue
    period = len(key)
    # Vig decrypt
    pt_vig = [(CT_NUM[i] - key[i % period]) % 26 for i in range(N)]
    s_vig = score_all_cribs(pt_vig)
    # Beaufort
    pt_beau = [(key[i % period] - CT_NUM[i]) % 26 for i in range(N)]
    s_beau = score_all_cribs(pt_beau)

    if s_vig >= 3 or s_beau >= 3:
        print(f"  '{name}' (p={period}): Vig={s_vig}/24, Beau={s_beau}/24")

# Also try coordinates as letter keys
print("\n  Coordinate letters as key:")
coord_words = ['NORTH', 'SOUTH', 'EAST', 'WEST', 'NORTHEAST',
               'NORTHWEST', 'POINT', 'LANGLEY', 'VIRGINIA', 'COMPASS',
               'KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'BERLIN', 'CLOCK',
               'EGYPT', 'CAIRO', 'WALL', 'DELIVER', 'MESSAGE',
               'SHADOW', 'LIGHT', 'MAGNETIC', 'FIELD', 'BURIED',
               'WHATSTHEPOINT', 'THEPOINT']

best_word = ("", 0, "")
for word in coord_words:
    key = [c2n(c) for c in word]
    period = len(key)
    # Vig
    pt_vig = [(CT_NUM[i] - key[i % period]) % 26 for i in range(N)]
    s_vig = score_all_cribs(pt_vig)
    # Beaufort
    pt_beau = [(key[i % period] - CT_NUM[i]) % 26 for i in range(N)]
    s_beau = score_all_cribs(pt_beau)
    # Variant Beaufort
    pt_vbeau = [(CT_NUM[i] + key[i % period]) % 26 for i in range(N)]
    s_vbeau = score_all_cribs(pt_vbeau)

    best_s = max(s_vig, s_beau, s_vbeau)
    variant = 'Vig' if best_s == s_vig else ('Beau' if best_s == s_beau else 'VBeau')
    if best_s >= 3:
        print(f"  '{word}' (p={period}): best={best_s}/24 ({variant})")
    if best_s > best_word[1]:
        best_word = (word, best_s, variant)

print(f"\n  Best keyword: '{best_word[0]}' → {best_word[1]}/24 ({best_word[2]})")

# ============================================================
# 6. NULL CIPHER / STEGANOGRAPHIC PATTERNS
# ============================================================
print("\n" + "=" * 70)
print("6. NULL CIPHER / SKIP PATTERNS")
print("=" * 70)
print("  Reading every Nth letter of CT:")
for skip in range(2, 20):
    for start in range(skip):
        extracted = ''.join(CT[i] for i in range(start, N, skip))
        # Check if it contains any known words
        if 'BERLIN' in extracted or 'EAST' in extracted or 'CLOCK' in extracted or \
           'NORTH' in extracted or 'POINT' in extracted or 'WALL' in extracted:
            print(f"  skip={skip} start={start}: {extracted}")

# Check for words in diagonals of grid arrangements
print("\n  Checking grid diagonals for embedded words:")
target_words = ['BERLIN', 'EAST', 'NORTH', 'CLOCK', 'POINT', 'WALL', 'EGYPT',
                'CAIRO', 'MESSAGE', 'DELIVER', 'SHADOW', 'LIGHT']
for width in range(5, 30):
    nrows = (N + width - 1) // width
    # Main diagonal
    diag = ''
    for i in range(min(nrows, width)):
        idx = i * width + i
        if idx < N:
            diag += CT[idx]
    for word in target_words:
        if word in diag:
            print(f"  W={width} main diag: found '{word}' in '{diag}'")

    # Anti-diagonal
    adiag = ''
    for i in range(min(nrows, width)):
        idx = i * width + (width - 1 - i)
        if idx < N:
            adiag += CT[idx]
    for word in target_words:
        if word in adiag:
            print(f"  W={width} anti-diag: found '{word}' in '{adiag}'")

print("\n" + "=" * 70)
print("READING ORDER ANALYSIS COMPLETE")
print("=" * 70)
