"""
"What's the point?" — Sanborn's deliberate embedded clue.

Explore interpretations:
1. POINT as compass point (ENE = 67.5°)
2. POINT as decimal point (coordinates)
3. POINT as punctuation mark (period/stop)
4. POINT as a location on the sculpture
5. POINT as index of coincidence / mathematical point
6. The letter sequences in "WHATSTHEPOINT" as key material
7. Morse code (dots = points)
8. K2 coordinates: 38°57'6.5"N 77°8'44"W — the POINT
9. Position of "POINT" within various grids
"""
import sys, math
sys.path.insert(0, '/home/cpatrick/kryptos/src')

CT = 'OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR'
CT_NUM = [ord(c) - ord('A') for c in CT]
N = 97

ENE_POS, ENE_PT = 21, 'EASTNORTHEAST'
BC_POS, BC_PT = 63, 'BERLINCLOCK'

def c2n(c): return ord(c) - ord('A')
def n2c(n): return chr(n % 26 + ord('A'))

known_vig = {}
known_beau = {}
for start, pt in [(ENE_POS, ENE_PT), (BC_POS, BC_PT)]:
    for i, ch in enumerate(pt):
        pos = start + i
        known_vig[pos] = (CT_NUM[pos] - c2n(ch)) % 26
        known_beau[pos] = (CT_NUM[pos] + c2n(ch)) % 26

def score_vig(key): return sum(1 for p,v in known_vig.items() if p<len(key) and key[p]==v)
def score_beau(key): return sum(1 for p,v in known_beau.items() if p<len(key) and key[p]==v)

print("=" * 70)
print("K4 'WHAT'S THE POINT?' ANALYSIS")
print("=" * 70)

# ============================================================
# 1. COORDINATE ANALYSIS
# ============================================================
print("\n1. K2 COORDINATES AS KEY GENERATOR")
print("-" * 70)

# K2 decoded coordinates: 38°57'6.5"N, 77°8'44"W
# These point to CIA HQ / Kryptos location
# Various numeric representations

lat = 38 + 57/60 + 6.5/3600   # = 38.95180...
lon = -(77 + 8/60 + 44/3600)  # = -77.14555...

print(f"  Latitude:  {lat:.10f}")
print(f"  Longitude: {lon:.10f}")

# Method: Use decimal digits of coordinates as key
lat_digits = [int(d) for d in f"{lat:.20f}".replace('.', '') if d.isdigit()][:N]
lon_digits = [int(d) for d in f"{abs(lon):.20f}".replace('.', '') if d.isdigit()][:N]

# Interleave lat/lon digits
interleaved = []
for i in range(max(len(lat_digits), len(lon_digits))):
    if i < len(lat_digits):
        interleaved.append(lat_digits[i])
    if i < len(lon_digits):
        interleaved.append(lon_digits[i])
interleaved = interleaved[:N]

for name, digits in [
    ("lat_digits", lat_digits),
    ("lon_digits", lon_digits),
    ("interleaved", interleaved),
]:
    if len(digits) < N:
        digits = (digits * ((N // len(digits)) + 2))[:N]

    # As direct key values
    s_v = score_vig(digits)
    s_b = score_beau(digits)

    # Cumulative sum mod 26
    cum = [0] * N
    cum[0] = digits[0]
    for i in range(1, N):
        cum[i] = (cum[i-1] + digits[i]) % 26
    s_vc = score_vig(cum)
    s_bc = score_beau(cum)

    print(f"  {name}: direct Vig={s_v}/24 Beau={s_b}/24, cumul Vig={s_vc}/24 Beau={s_bc}/24")

# Method: map coordinate to alphabet
# 38.9518 → 3+8+9+5+1+8 = 34, 34%26=8=I, etc.
coord_str = "3895180555771455555"
print(f"\n  Coordinate string: {coord_str}")

# Rolling digit sum
for window in range(2, 8):
    key = []
    for i in range(N):
        idx = i % (len(coord_str) - window + 1)
        digit_sum = sum(int(coord_str[idx + j]) for j in range(window))
        key.append(digit_sum % 26)
    s = score_vig(key)
    if s >= 4:
        print(f"  Rolling sum window={window}: {s}/24")

# ============================================================
# 2. "WHATSTHEPOINT" AS KEYED ALPHABET / SUBSTITUTION
# ============================================================
print("\n2. WHATSTHEPOINT AS KEY")
print("-" * 70)

WTP = 'WHATSTHEPOINT'
wtp_nums = [c2n(c) for c in WTP]
wtp_len = len(WTP)

# As a repeating Vigenère key
key = [wtp_nums[i % wtp_len] for i in range(N)]
s = score_vig(key)
print(f"  WTP as Vig key (p={wtp_len}): {s}/24")

# As a keyword-mixed alphabet
def keyword_alphabet(kw):
    seen = set()
    result = []
    for c in kw.upper():
        if c not in seen and c.isalpha():
            seen.add(c)
            result.append(c)
    for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        if c not in seen:
            result.append(c)
    return ''.join(result)

wtp_alpha = keyword_alphabet(WTP)
print(f"  WTP keyword alphabet: {wtp_alpha}")
wtp_map = {c: i for i, c in enumerate(wtp_alpha)}

# Use WTP alphabet as substitution: CT letters → WTP positions
ct_wtp = [wtp_map[c] for c in CT]
s = score_vig(ct_wtp)
print(f"  CT through WTP alphabet (as Vig key): {s}/24")

# Combined: WTP alphabet + periodic Vig
for period in range(1, 15):
    key_vals = {}
    ok = True
    for start, pt in [(ENE_POS, ENE_PT), (BC_POS, BC_PT)]:
        for i, ch in enumerate(pt):
            pos = start + i
            needed = (ct_wtp[pos] - c2n(ch)) % 26
            r = pos % period
            if r in key_vals:
                if key_vals[r] != needed:
                    ok = False
                    break
            else:
                key_vals[r] = needed
        if not ok:
            break
    if ok:
        matches = sum(1 for start, pt in [(ENE_POS, ENE_PT), (BC_POS, BC_PT)]
                     for i, ch in enumerate(pt)
                     if (ct_wtp[start+i] - key_vals.get((start+i) % period, -99)) % 26 == c2n(ch))
        if matches == 24:
            key_full = [key_vals[i % period] for i in range(N)]
            pt_text = ''.join(n2c((ct_wtp[i] - key_full[i]) % 26) for i in range(N))
            print(f"  WTP-alphabet + Vig period {period}: {matches}/24 FULL!")
            print(f"  PT: {pt_text}")
            print(f"  Key: {''.join(n2c(k) for k in key_full[:period])}")

# ============================================================
# 3. MORSE CODE INTERPRETATION
# ============================================================
print("\n3. MORSE CODE / DOT-DASH ANALYSIS")
print("-" * 70)

# Map letters to Morse, then interpret dots as 0, dashes as 1
morse = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
    'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
    'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
    'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
    'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
    'Z': '--..',
}

# Convert CT to Morse bit stream
ct_morse = ''.join(morse[c] for c in CT)
print(f"  CT as Morse ({len(ct_morse)} symbols): {ct_morse[:60]}...")

# Check if Morse lengths could encode key values
# Length of Morse for each letter: E=1, T=1, A=2, I=2, M=2, N=2, ...
morse_lens = [len(morse[c]) for c in CT]
print(f"  Morse lengths: {morse_lens[:30]}...")

# Use Morse length as key
s = score_vig(morse_lens)
print(f"  Morse length as Vig key: {s}/24")

# Morse dot count as key
morse_dots = [morse[c].count('.') for c in CT]
s = score_vig(morse_dots)
print(f"  Morse dot count as Vig key: {s}/24")

# Morse dash count as key
morse_dashes = [morse[c].count('-') for c in CT]
s = score_vig(morse_dashes)
print(f"  Morse dash count as Vig key: {s}/24")

# ============================================================
# 4. POLYBIUS / ADFGVX GRID WITH THEMATIC KEYWORD
# ============================================================
print("\n4. POLYBIUS GRID WITH THEMATIC KEYWORDS")
print("-" * 70)

keywords_5x5 = [
    'WHATSTHEPOINT',
    'KRYPTOS',
    'PALIMPSEST',
    'ABSCISSA',
    'BERLINCLOCK',
    'EASTNORTHEAST',
    'SHADOW',
    'MAGNETIC',
    'BURIED',
    'DELIVER',
    'MESSAGE',
    'EGYPT',
    'CAIRO',
]

def make_polybius(kw):
    """Make 5x5 Polybius square from keyword (I/J merged)."""
    alpha = keyword_alphabet(kw).replace('J', 'I')
    seen = set()
    result = []
    for c in alpha:
        if c not in seen:
            seen.add(c)
            result.append(c)
    if len(result) > 25:
        result = result[:25]
    return result

def polybius_coords(grid, letter):
    """Get (row, col) for a letter in 5x5 grid."""
    if letter == 'J':
        letter = 'I'
    try:
        idx = grid.index(letter)
        return (idx // 5, idx % 5)
    except ValueError:
        return (0, 0)

# For each keyword, create Polybius square and convert CT to coordinates
for kw in keywords_5x5:
    grid = make_polybius(kw)

    # Convert CT to pairs of coordinates
    ct_coords = [polybius_coords(grid, c) for c in CT.replace('J', 'I')]

    # Method: read row digits, then col digits (Bifid-like without period fractionation)
    rows = [r for r, c in ct_coords]
    cols = [c for r, c in ct_coords]

    # Concatenate and re-read as pairs
    combined = rows + cols
    if len(combined) >= N * 2:
        new_pairs = [(combined[2*i], combined[2*i+1]) for i in range(N)]
        pt_nums = [r * 5 + c for r, c in new_pairs]
        pt_text = ''.join(grid[min(n, 24)] for n in pt_nums)
        # Score against cribs
        matches = sum(1 for start, cr in [(ENE_POS, ENE_PT), (BC_POS, BC_PT)]
                     for i, ch in enumerate(cr)
                     if start + i < len(pt_text) and pt_text[start + i] == ch.replace('J', 'I'))
        if matches >= 4:
            print(f"  '{kw}': full-length Bifid: {matches}/24")

    # Also: digit interleave (row0, col0, row1, col1, ...)
    interleaved_digits = []
    for r, c in ct_coords:
        interleaved_digits.extend([r, c])

    # Use interleaved digits as key values (mod 26)
    key = [(interleaved_digits[i] if i < len(interleaved_digits) else 0) for i in range(N)]
    s = score_vig(key)
    if s >= 4:
        print(f"  '{kw}': Polybius digit stream as key: {s}/24")

# ============================================================
# 5. PHYSICAL SCULPTURE FEATURES
# ============================================================
print("\n5. SCULPTURE-DERIVED PARAMETERS")
print("-" * 70)
print("  Testing parameters that could come from the physical sculpture:")

# The sculpture has specific dimensions and features
# Key numbers associated with Kryptos:
# - 97 characters in K4
# - 4 sections (K1-K4)
# - Installed 1990
# - Artist: Jim Sanborn
# - Consultant: Ed Scheidt (retired CIA cryptographer)
# - Located at CIA HQ, Langley, Virginia
# - Coordinates in K2: 38°57'6.5"N, 77°8'44"W
# - The copperplate has specific character grid dimensions

# Character grid on sculpture (approximate)
# K1-K4 are on the right side, roughly 30 chars wide
# Test: what if K4 should be read as a grid?
for width in [7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 19, 97]:
    # height = ceil(97/width)
    height = (N + width - 1) // width

    # Spiral read
    spiral = []
    grid = []
    idx = 0
    for row in range(height):
        row_data = []
        for col in range(width):
            if idx < N:
                row_data.append(CT[idx])
            else:
                row_data.append('_')
            idx += 1
        grid.append(row_data)

    # Clockwise spiral read
    top, bottom, left, right = 0, height - 1, 0, width - 1
    while top <= bottom and left <= right:
        for col in range(left, right + 1):
            if top < height and col < width and grid[top][col] != '_':
                spiral.append(grid[top][col])
        top += 1
        for row in range(top, bottom + 1):
            if row < height and right < width and grid[row][right] != '_':
                spiral.append(grid[row][right])
        right -= 1
        if top <= bottom:
            for col in range(right, left - 1, -1):
                if bottom < height and col < width and grid[bottom][col] != '_':
                    spiral.append(grid[bottom][col])
            bottom -= 1
        if left <= right:
            for row in range(bottom, top - 1, -1):
                if row < height and left < width and grid[row][left] != '_':
                    spiral.append(grid[row][left])
            left += 1

    if len(spiral) >= N:
        spiral_nums = [c2n(c) for c in spiral[:N]]
        # Check: does spiral reading + identity key give cribs?
        matches = 0
        for start, pt in [(ENE_POS, ENE_PT), (BC_POS, BC_PT)]:
            for i, ch in enumerate(pt):
                pos = start + i
                if pos < N and spiral_nums[pos] == c2n(ch):
                    matches += 1
        if matches >= 3:
            print(f"  Grid {width}×{height} spiral read: {matches}/24 raw matches")

# ============================================================
# 6. ACROSTIC / POSITIONAL ENCODING
# ============================================================
print("\n6. ACROSTIC / POSITIONAL WORD SEARCH")
print("-" * 70)

# What if specific positions in CT spell a hidden message?
# "What's the point?" → look for POINT in positional patterns

# Every Nth letter starting from position P
for n_skip in range(2, 25):
    for start in range(n_skip):
        extracted = CT[start::n_skip]
        if 'POINT' in extracted:
            print(f"  Skip={n_skip} start={start}: found POINT in '{extracted}'")
        if 'WHAT' in extracted:
            print(f"  Skip={n_skip} start={start}: found WHAT in '{extracted}'")
        if 'MESSAGE' in extracted:
            print(f"  Skip={n_skip} start={start}: found MESSAGE in '{extracted}'")

# Check first letters of groups (acrostic by splitting CT into words)
for word_len in range(3, 15):
    acrostic = ''.join(CT[i] for i in range(0, N, word_len))
    if any(w in acrostic for w in ['POINT', 'WHAT', 'THE', 'BERLIN', 'EAST']):
        print(f"  Acrostic (every {word_len}th): {acrostic}")

# ============================================================
# 7. XOR-LIKE OPERATIONS IN MOD-26
# ============================================================
print("\n7. CT ⊕ CT SHIFTED (mod-26 XOR equivalent)")
print("-" * 70)

# If CT has a pattern where CT[i] ⊕ CT[i+d] reveals plaintext...
# Already tested superposition, but let's test with affine combinations
for a in range(1, 26):
    for d in range(1, N):
        key = [(a * CT_NUM[(i + d) % N]) % 26 for i in range(N)]
        s = score_vig(key)
        if s >= 7:
            pt = ''.join(n2c((CT_NUM[i] - key[i]) % 26) for i in range(N))
            print(f"  a={a} d={d}: {s}/24 → PT={pt[:40]}...")
        s_b = score_beau(key)
        if s_b >= 7:
            pt = ''.join(n2c((key[i] - CT_NUM[i]) % 26) for i in range(N))
            print(f"  a={a} d={d} (Beau): {s_b}/24 → PT={pt[:40]}...")

# ============================================================
# 8. NIHILIST CIPHER
# ============================================================
print("\n8. NIHILIST CIPHER")
print("-" * 70)
print("  Nihilist: CT_digit_pair = PT_coord + KEY_coord (mod 10 or addition)")

# In a Nihilist cipher, both PT and key are converted to Polybius coordinates
# and then added digit by digit. Since K4 is 97 letters (not digit pairs),
# this doesn't directly apply. But what if K4 is interpreted as Polybius?

# Split CT into pairs: 48 pairs + 1 leftover
for kw in ['KRYPTOS', 'WHATSTHEPOINT', 'PALIMPSEST', 'ABSCISSA']:
    grid = make_polybius(kw)
    grid_map = {c: (i // 5 + 1, i % 5 + 1) for i, c in enumerate(grid)}

    # Interpret pairs of CT letters as Nihilist cipher pairs
    # Each CT letter gives coordinates; adjacent pairs add up
    ct_coords_list = [grid_map.get(c.replace('J', 'I'), c) if isinstance(c, str) else c
                      for c in CT.replace('J', 'I')]

    # Method: treat consecutive pairs as Nihilist encoding
    # (row1*10+col1) - (key_row*10+key_col) = pt_row*10+pt_col
    # This is getting complex... just check if decoding as digit pairs gives anything
    for key_kw in ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW', 'BURIED', 'DELIVER']:
        key_grid = make_polybius(key_kw)
        key_map = {c: (i // 5 + 1, i % 5 + 1) for i, c in enumerate(key_grid)}
        key_str = key_kw * ((N // len(key_kw)) + 1)

        pt_chars = []
        ok = True
        for i in range(N):
            ct_r, ct_c = grid_map.get(CT[i].replace('J','I'), (0,0))
            k_r, k_c = key_map.get(key_str[i].replace('J','I'), (0,0))
            pt_r = ct_r - k_r
            pt_c = ct_c - k_c
            if 1 <= pt_r <= 5 and 1 <= pt_c <= 5:
                pt_idx = (pt_r - 1) * 5 + (pt_c - 1)
                pt_chars.append(grid[pt_idx])
            else:
                # Try mod 5
                pt_r = ((ct_r - k_r) % 5) + 1
                pt_c = ((ct_c - k_c) % 5) + 1
                pt_idx = (pt_r - 1) * 5 + (pt_c - 1)
                pt_chars.append(grid[pt_idx])

        pt_text = ''.join(pt_chars)
        # Check cribs
        matches = sum(1 for start, cr in [(ENE_POS, ENE_PT), (BC_POS, BC_PT)]
                     for i, ch in enumerate(cr)
                     if start + i < len(pt_text) and pt_text[start+i] == ch.replace('J','I'))
        if matches >= 5:
            print(f"  Grid={kw}, Key={key_kw}: {matches}/24")
            if matches >= 8:
                print(f"    PT: {pt_text}")

print("\n" + "=" * 70)
print("'WHAT'S THE POINT?' ANALYSIS COMPLETE")
print("=" * 70)
