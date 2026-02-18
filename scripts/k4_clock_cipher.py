"""
Clock cipher and time-based key generation for K4.

The crib BERLINCLOCK directly references the Berlin Clock (Mengenlehreuhr),
a clock that displays time using set theory / colored blocks.

Tests:
1. Berlin Clock time encoding → keystream
2. Clock arithmetic (hours, minutes mapped to key values)
3. Specific dates: 1986 Egypt trip, 1989 Berlin Wall fall
4. CLOCK as a cipher mechanism (rotating alphabets)
5. Compass/direction-based key generation (EASTNORTHEAST → angles)
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

# Known key values (Vigenere)
known_vig = {}
for start, pt in [(ENE_POS, ENE_PT), (BC_POS, BC_PT)]:
    for i, ch in enumerate(pt):
        pos = start + i
        known_vig[pos] = (CT_NUM[pos] - c2n(ch)) % 26

def score_key(key_slice):
    """Score a key against known crib-derived values."""
    matches = 0
    for pos, expected in known_vig.items():
        if pos < len(key_slice):
            if key_slice[pos] == expected:
                matches += 1
    return matches

def decrypt_vig(key):
    return ''.join(n2c((CT_NUM[i] - key[i]) % 26) for i in range(min(N, len(key))))

print("=" * 70)
print("K4 CLOCK CIPHER & TIME-BASED KEY ANALYSIS")
print("=" * 70)

# ============================================================
# 1. BERLIN CLOCK TIME ENCODING
# ============================================================
print("\n1. BERLIN CLOCK TIME ENCODING")
print("-" * 70)
print("""
The Berlin Clock (Mengenlehreuhr) displays time as:
- Row 1: 1 lamp for seconds (on/off, 2-second cycle)
- Row 2: 4 lamps, each = 5 hours (0-20 hours)
- Row 3: 4 lamps, each = 1 hour (0-4 additional hours)
- Row 4: 11 lamps, each = 5 minutes (0-55 minutes), 3rd/6th/9th are red
- Row 5: 4 lamps, each = 1 minute (0-4 additional minutes)
""")

# Convert a time to Berlin Clock representation → numbers
def berlin_clock_encode(hour, minute, second=0):
    """Encode time as Berlin Clock → sequence of numbers."""
    seq = []
    # Seconds: 0 or 1
    seq.append(second % 2)
    # 5-hour blocks (0-4)
    seq.append(hour // 5)
    # 1-hour blocks (0-4)
    seq.append(hour % 5)
    # 5-minute blocks (0-11)
    seq.append(minute // 5)
    # 1-minute blocks (0-4)
    seq.append(minute % 5)
    return seq

# Generate keystreams from significant times
significant_times = [
    (6, 30, "6:30 - Berlin Clock as 'BERLINCLOCK'"),
    (11, 4, "11:04 - Nov 4 1989 (Berlin demonstration)"),
    (11, 9, "11:09 - Nov 9 1989 (Wall opened)"),
    (0, 0, "Midnight"),
    (12, 0, "Noon"),
    (19, 86, "19:86 → 20:26 (1986 overflow)"),
    (19, 89, "19:89 → 20:29 (1989 overflow)"),
    (3, 25, "3:25 - March 25 (KA first trip)"),
    (10, 3, "10:03 - Oct 3 1990 (reunification)"),
]

# For each time, generate repeating key from Berlin Clock digits
for h, m, desc in significant_times:
    h_eff = h % 24
    m_eff = m % 60
    bc = berlin_clock_encode(h_eff, m_eff)

    # Several ways to use Berlin Clock as key:
    # Method A: Use the raw numbers as key values (period 5)
    key_a = [bc[i % 5] for i in range(N)]
    s_a = score_key(key_a)

    # Method B: Map to alphabet positions (multiply by various factors)
    for mult in [1, 2, 3, 5, 7, 13]:
        key_b = [(bc[i % 5] * mult) % 26 for i in range(N)]
        s_b = score_key(key_b)
        if s_b >= 4:
            print(f"  {desc}: BC digits={bc} ×{mult}: {s_b}/24")

    # Method C: Cumulative sum of Berlin Clock digits
    key_c = [0] * N
    key_c[0] = bc[0]
    for i in range(1, N):
        key_c[i] = (key_c[i-1] + bc[i % 5]) % 26
    s_c = score_key(key_c)
    if s_c >= 4:
        print(f"  {desc}: cumulative BC: {s_c}/24")

# ============================================================
# 2. DATE-DERIVED KEYS
# ============================================================
print("\n2. DATE-DERIVED KEYS")
print("-" * 70)

# Key dates
dates = [
    (1986, 1, 1, "1986-01-01 (Egypt year)"),
    (1986, 3, 25, "1986-03-25"),
    (1986, 11, 3, "1986-11-03"),
    (1989, 11, 9, "1989-11-09 (Wall falls)"),
    (1989, 11, 10, "1989-11-10"),
    (1989, 10, 3, "1989-10-03"),
    (1990, 10, 3, "1990-10-03 (Reunification)"),
    (1990, 11, 3, "1990-11-03 (Kryptos dedication)"),
]

# Various date → key encodings
for year, month, day, desc in dates:
    digits = [int(d) for d in f"{year:04d}{month:02d}{day:02d}"]  # YYYYMMDD

    # Period-8 repeating
    key_8 = [digits[i % 8] for i in range(N)]
    s = score_key(key_8)
    if s >= 4:
        print(f"  {desc} (period 8): {s}/24")

    # Various digit combinations
    for combo_name, combo in [
        ("YYMM", [int(d) for d in f"{year%100:02d}{month:02d}"]),
        ("MMDD", [int(d) for d in f"{month:02d}{day:02d}"]),
        ("DDMM", [int(d) for d in f"{day:02d}{month:02d}"]),
        ("Y2", [int(d) for d in str(year)]),
        ("MD", [month, day]),
        ("DMY", [day, month, year % 100]),
    ]:
        if not combo:
            continue
        p = len(combo)
        key = [combo[i % p] for i in range(N)]
        s = score_key(key)
        if s >= 3:
            print(f"  {desc} {combo_name}={combo}: {s}/24")

    # Two-date interleave: 1986 and 1989
    if year == 1986:
        d1 = digits
        d2 = [int(d) for d in "19891109"]
        interleaved = []
        for i in range(8):
            interleaved.append(d1[i])
            interleaved.append(d2[i])
        p = len(interleaved)
        key = [interleaved[i % p] for i in range(N)]
        s = score_key(key)
        if s >= 3:
            print(f"  Interleaved {desc}+1989-11-09: {s}/24")

# ============================================================
# 3. CLOCK ROTATION CIPHER
# ============================================================
print("\n3. CLOCK ROTATION CIPHER")
print("-" * 70)
print("  Each position advances the 'clock hand' by an amount derived from CT/position")

# Clock cipher: key[i] = (a * i + b * i^2 + c) mod 26
# But polynomial degree ≤20 already eliminated. Try non-polynomial clocks.

# Method: key[i] = floor(26 * frac(i * phi)) where phi = golden ratio
# This gives a quasi-random but deterministic sequence
phi = (1 + math.sqrt(5)) / 2
for base in [phi, math.pi, math.e, math.sqrt(2), math.sqrt(3)]:
    for scale in [1, 2, 3, 5, 7, 11, 13, 26, 97]:
        key = [int(26 * ((i * base * scale) % 1)) % 26 for i in range(N)]
        s = score_key(key)
        if s >= 5:
            print(f"  base={base:.4f} scale={scale}: {s}/24")

# Method: Fibonacci-like key generation
# key[0]=a, key[1]=b, key[i] = (key[i-1] + key[i-2]) mod 26
print("\n  Fibonacci-type key (k[i] = k[i-1] + k[i-2] mod 26):")
best_fib = (0, 0, 0)
for a in range(26):
    for b in range(26):
        key = [0] * N
        key[0] = a
        key[1] = b
        for i in range(2, N):
            key[i] = (key[i-1] + key[i-2]) % 26
        s = score_key(key)
        if s > best_fib[0]:
            best_fib = (s, a, b)
        if s >= 6:
            print(f"    seed=({a},{b}): {s}/24")
print(f"  Best Fibonacci: {best_fib[0]}/24 (seed={best_fib[1]},{best_fib[2]})")

# Tribonacci: k[i] = k[i-1] + k[i-2] + k[i-3]
print("\n  Tribonacci-type key (k[i] = k[i-1] + k[i-2] + k[i-3] mod 26):")
best_trib = (0, 0, 0, 0)
for a in range(26):
    for b in range(26):
        for c in range(26):
            key = [0] * N
            key[0], key[1], key[2] = a, b, c
            for i in range(3, N):
                key[i] = (key[i-1] + key[i-2] + key[i-3]) % 26
            s = score_key(key)
            if s > best_trib[0]:
                best_trib = (s, a, b, c)
best_s, a, b, c = best_trib
print(f"  Best Tribonacci: {best_s}/24 (seed={a},{b},{c})")
if best_s >= 6:
    key = [0] * N
    key[0], key[1], key[2] = a, b, c
    for i in range(3, N):
        key[i] = (key[i-1] + key[i-2] + key[i-3]) % 26
    print(f"  Key: {''.join(n2c(k) for k in key)}")
    print(f"  PT:  {decrypt_vig(key)}")

# ============================================================
# 4. COMPASS / DIRECTION ENCODING
# ============================================================
print("\n4. COMPASS / DIRECTION ENCODING")
print("-" * 70)

# EASTNORTHEAST = 67.5 degrees
# Map compass directions to degrees, use as key
compass = {
    'N': 0, 'NNE': 22.5, 'NE': 45, 'ENE': 67.5,
    'E': 90, 'ESE': 112.5, 'SE': 135, 'SSE': 157.5,
    'S': 180, 'SSW': 202.5, 'SW': 225, 'WSW': 247.5,
    'W': 270, 'WNW': 292.5, 'NW': 315, 'NNW': 337.5,
}

# Key from compass angle progression
ene_degrees = 67.5
print(f"  ENE = {ene_degrees}° from N")

# Method: key[i] = floor(ene_degrees * i / scale) mod 26
for scale in [1, 2, 3, 5, 10, 15, 26, 67.5, 97, 180, 360]:
    key = [int(ene_degrees * i / scale) % 26 for i in range(N)]
    s = score_key(key)
    if s >= 4:
        print(f"  67.5°×i/{scale}: {s}/24")

# Method: alternating compass readings
# What if key letters come from cycling through compass directions?
direction_sequence = [
    c2n('E'), c2n('N'), c2n('E'),  # E-N-E
    c2n('B'), c2n('C'),  # Berlin Clock initials
]
for extra in range(26):
    seq = direction_sequence + [extra]
    p = len(seq)
    key = [seq[i % p] for i in range(N)]
    s = score_key(key)
    if s >= 5:
        print(f"  ENE+BC+{n2c(extra)} cycle: {s}/24")

# ============================================================
# 5. KRYPTOS ALPHABET (KA) WITH CLOCK MECHANISM
# ============================================================
print("\n5. KRYPTOS ALPHABET CLOCK MECHANISM")
print("-" * 70)

KA = 'KRYPTOSABCDEFGHIJLMNQUVWXZ'
KA_MAP = {c: i for i, c in enumerate(KA)}

# What if KA itself is used as a clock: advance through KA by steps?
# key[i] = KA[i * step mod 26]
for step in range(1, 26):
    key = [KA_MAP[KA[(i * step) % 26]] for i in range(N)]
    # Wait, that's just identity. Let's use KA position as key value
    key = [(i * step) % 26 for i in range(N)]
    s = score_key(key)
    if s >= 4:
        print(f"  KA step={step}: {s}/24")

# Key from KA applied to CT: key[i] = KA_pos(CT[i])
key_ka_ct = [KA_MAP[c] for c in CT]
s = score_key(key_ka_ct)
print(f"  KA position of CT letters: {s}/24")

# Key from KA-standard difference: key[i] = KA_pos(CT[i]) - standard_pos(CT[i])
key_diff = [(KA_MAP[c] - (ord(c) - ord('A'))) % 26 for c in CT]
s = score_key(key_diff)
print(f"  KA-AZ difference of CT: {s}/24")

# ============================================================
# 6. MULTIPLICATIVE CIPHER VARIANTS
# ============================================================
print("\n6. MULTIPLICATIVE / AFFINE PER-POSITION CIPHER")
print("-" * 70)

# PT[i] = (a * CT[i] + b) mod 26 where a,b vary by position
# Under Vig, key = CT - PT. Under affine: PT = (a*CT + b) mod 26
# So key[i] = (CT[i] - a*CT[i] - b) mod 26 = ((1-a)*CT[i] - b) mod 26
# This is a KEY that depends linearly on CT values → test if crib-derived
# key values fit: k[pos] = ((1-a)*CT[pos] - b) mod 26 for all crib positions

from math import gcd

print("  Testing: k[i] = (a*CT[i] + b) mod 26")
best_affine_ct = (0, 0, 0)
for a in range(26):
    for b in range(26):
        key = [(a * CT_NUM[i] + b) % 26 for i in range(N)]
        s = score_key(key)
        if s > best_affine_ct[0]:
            best_affine_ct = (s, a, b)
        if s >= 8:
            pt = decrypt_vig(key)
            print(f"  a={a}, b={b}: {s}/24 → PT={pt}")
print(f"  Best: {best_affine_ct[0]}/24 (a={best_affine_ct[1]}, b={best_affine_ct[2]})")

# Test: k[i] = (a*i + b*CT[i] + c) mod 26
print("\n  Testing: k[i] = (a*i + b*CT[i] + c) mod 26")
best_mixed = (0, 0, 0, 0)
for a in range(26):
    for b in range(26):
        for c in range(26):
            key = [(a * i + b * CT_NUM[i] + c) % 26 for i in range(N)]
            s = score_key(key)
            if s > best_mixed[0]:
                best_mixed = (s, a, b, c)
if best_mixed[0] >= 6:
    print(f"  Best: {best_mixed[0]}/24 (a={best_mixed[1]}, b={best_mixed[2]}, c={best_mixed[3]})")
    a, b, c = best_mixed[1], best_mixed[2], best_mixed[3]
    key = [(a * i + b * CT_NUM[i] + c) % 26 for i in range(N)]
    print(f"  PT: {decrypt_vig(key)}")
else:
    print(f"  Best: {best_mixed[0]}/24")

# ============================================================
# 7. BEAUFORT WITH ALL ABOVE
# ============================================================
print("\n7. BEAUFORT VARIANTS OF KEY TESTS")
print("-" * 70)

# Known key values under Beaufort: key = (CT + PT) mod 26
known_beau = {}
for start, pt in [(ENE_POS, ENE_PT), (BC_POS, BC_PT)]:
    for i, ch in enumerate(pt):
        pos = start + i
        known_beau[pos] = (CT_NUM[pos] + c2n(ch)) % 26

def score_beau(key_slice):
    matches = 0
    for pos, expected in known_beau.items():
        if pos < len(key_slice):
            if key_slice[pos] == expected:
                matches += 1
    return matches

# Fibonacci under Beaufort
best_fib_b = (0, 0, 0)
for a in range(26):
    for b in range(26):
        key = [0] * N
        key[0] = a
        key[1] = b
        for i in range(2, N):
            key[i] = (key[i-1] + key[i-2]) % 26
        s = score_beau(key)
        if s > best_fib_b[0]:
            best_fib_b = (s, a, b)
        if s >= 6:
            print(f"  Fibonacci Beaufort seed=({a},{b}): {s}/24")
print(f"  Best Fibonacci Beaufort: {best_fib_b[0]}/24")

# Tribonacci under Beaufort
best_trib_b = (0, 0, 0, 0)
for a in range(26):
    for b in range(26):
        for c in range(26):
            key = [0] * N
            key[0], key[1], key[2] = a, b, c
            for i in range(3, N):
                key[i] = (key[i-1] + key[i-2] + key[i-3]) % 26
            s = score_beau(key)
            if s > best_trib_b[0]:
                best_trib_b = (s, a, b, c)
print(f"  Best Tribonacci Beaufort: {best_trib_b[0]}/24")

# Affine of CT under Beaufort
print("\n  k[i] = (a*CT[i] + b) mod 26 under Beaufort:")
best_ab = (0, 0, 0)
for a in range(26):
    for b in range(26):
        key = [(a * CT_NUM[i] + b) % 26 for i in range(N)]
        s = score_beau(key)
        if s > best_ab[0]:
            best_ab = (s, a, b)
        if s >= 8:
            pt = ''.join(n2c((key[i] - CT_NUM[i]) % 26) for i in range(N))
            print(f"  a={a}, b={b}: {s}/24 → PT={pt}")
print(f"  Best: {best_ab[0]}/24")

print("\n" + "=" * 70)
print("CLOCK CIPHER ANALYSIS COMPLETE")
print("=" * 70)
