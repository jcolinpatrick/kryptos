"""
Cipher: multi-vector campaign
Family: campaigns
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
Novel K4 attack vectors:
1. Self-keyed cipher: key[i] = CT[f(i)] for all affine f over Z_97
2. Bifid cipher with keyword alphabets
3. Two-square/Four-square with non-standard alphabets
4. Simulated annealing for plaintext (optimizing key quadgram score)
"""
import sys, json, os, random, math
from collections import Counter
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

REPO_ROOT = Path(__file__).resolve().parents[1]
BASE_DIR = Path(os.getenv("K4_BASE_DIR", str(REPO_ROOT)))

CT = 'OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR'
CT_NUM = [ord(c) - ord('A') for c in CT]
N = 97

ENE_POS, ENE_PT = 21, 'EASTNORTHEAST'
BC_POS, BC_PT = 63, 'BERLINCLOCK'

def c2n(c): return ord(c) - ord('A')
def n2c(n): return chr(n % 26 + ord('A'))

# Known key values under standard Vigenere
known = {}
for start, pt in [(ENE_POS, ENE_PT), (BC_POS, BC_PT)]:
    for i, ch in enumerate(pt):
        pos = start + i
        known[pos] = (CT_NUM[pos] - c2n(ch)) % 26

# Load quadgrams
QUADGRAM_PATH = str(BASE_DIR / "data" / "english_quadgrams.json")
qg = {}
if os.path.exists(QUADGRAM_PATH):
    with open(QUADGRAM_PATH) as f:
        data = json.load(f)
    # Handle nested "logp" format
    if isinstance(data, dict) and 'logp' in data and isinstance(data['logp'], dict):
        raw = data['logp']
        # Nested: logp["T"]["H"]["E"]["N"] = -2.34
        for a, d1 in raw.items():
            if isinstance(d1, dict):
                for b, d2 in d1.items():
                    if isinstance(d2, dict):
                        for c, d3 in d2.items():
                            if isinstance(d3, dict):
                                for d, val in d3.items():
                                    qg[a+b+c+d] = val
                            elif isinstance(d3, (int, float)):
                                qg[a+b+c] = d3
    elif isinstance(data, dict) and all(len(k) == 4 for k in list(data.keys())[:10]):
        qg = data
    print(f"Loaded {len(qg)} quadgrams")
else:
    print("WARNING: Quadgram file not found")

FLOOR = min(qg.values()) if qg else -10.0

def qg_score(text):
    if not qg or len(text) < 4:
        return 0.0
    s = 0.0
    for i in range(len(text) - 3):
        gram = text[i:i+4]
        s += qg.get(gram, FLOOR)
    return s

print("=" * 70)
print("K4 NOVEL ATTACK VECTORS")
print("=" * 70)

# ============================================================
# 1. SELF-KEYED: key[i] = CT[f(i)] where f is affine over Z_97
# ============================================================
print("\n" + "=" * 70)
print("1. SELF-KEYED CIPHER: key[i] = CT[(a*i + b) mod 97]")
print("=" * 70)
print("   Testing all 96 × 97 = 9,312 affine position mappings...")

# For Vigenere: PT[i] = (CT[i] - key[i]) mod 26 = (CT[i] - CT[f(i)]) mod 26
# For Beaufort: PT[i] = (key[i] - CT[i]) mod 26 = (CT[f(i)] - CT[i]) mod 26

best_vig = (0, 0, 0)  # (score, a, b)
best_beau = (0, 0, 0)
total_tested = 0

for a in range(1, N):  # a=0 gives constant, skip
    for b in range(N):
        # Check crib matches under Vigenere
        vig_matches = 0
        beau_matches = 0
        for pos, exp_key in known.items():
            mapped = (a * pos + b) % N
            ct_at_mapped = CT_NUM[mapped]
            # Vig: key = ct_at_mapped, so exp_key should equal ct_at_mapped
            if ct_at_mapped == exp_key:
                vig_matches += 1
            # Beaufort: key = (CT[pos] + PT[pos]) mod 26
            beau_exp = (CT_NUM[pos] + (CT_NUM[pos] - exp_key)) % 26  # wrong, let me redo
            # Actually: Beaufort PT = (key - CT) mod 26, so key = (PT + CT) mod 26
            # If key = CT[f(i)], then PT[i] = (CT[f(i)] - CT[i]) mod 26
            # exp_PT at pos: from cribs
            pass

        if vig_matches > best_vig[0]:
            best_vig = (vig_matches, a, b)
        total_tested += 1

        if vig_matches >= 10:
            print(f"   Vig a={a}, b={b}: {vig_matches}/24 matches!")

print(f"   Tested {total_tested} mappings")
print(f"   Best Vigenere self-keyed: {best_vig[0]}/24 (a={best_vig[1]}, b={best_vig[2]})")

# Now do Beaufort variant properly
print("\n   Testing Beaufort self-keyed...")
best_beau = (0, 0, 0)
# Beaufort: PT[i] = (CT[f(i)] - CT[i]) mod 26
# Known PT at crib positions → check (CT[f(pos)] - CT[pos]) mod 26 == c2n(pt_char)
crib_checks = []
for start, pt in [(ENE_POS, ENE_PT), (BC_POS, BC_PT)]:
    for i, ch in enumerate(pt):
        pos = start + i
        crib_checks.append((pos, c2n(ch)))

for a in range(1, N):
    for b in range(N):
        matches = 0
        for pos, exp_pt in crib_checks:
            mapped = (a * pos + b) % N
            actual_pt = (CT_NUM[mapped] - CT_NUM[pos]) % 26
            if actual_pt == exp_pt:
                matches += 1
        if matches > best_beau[0]:
            best_beau = (matches, a, b)
        if matches >= 10:
            print(f"   Beau a={a}, b={b}: {matches}/24 matches!")

print(f"   Best Beaufort self-keyed: {best_beau[0]}/24 (a={best_beau[1]}, b={best_beau[2]})")

# Also try variant: PT[i] = (CT[i] + CT[f(i)]) mod 26
print("\n   Testing additive self-keyed (PT = CT + CT[f])...")
best_add = (0, 0, 0)
for a in range(1, N):
    for b in range(N):
        matches = 0
        for pos, exp_pt in crib_checks:
            mapped = (a * pos + b) % N
            actual_pt = (CT_NUM[pos] + CT_NUM[mapped]) % 26
            if actual_pt == exp_pt:
                matches += 1
        if matches > best_add[0]:
            best_add = (matches, a, b)
        if matches >= 10:
            print(f"   Add a={a}, b={b}: {matches}/24 matches!")

print(f"   Best additive self-keyed: {best_add[0]}/24 (a={best_add[1]}, b={best_add[2]})")

# ============================================================
# 2. BIFID CIPHER
# ============================================================
print("\n" + "=" * 70)
print("2. BIFID CIPHER")
print("=" * 70)

def make_polybius(keyword='', merge_ij=True):
    """Create a 5x5 Polybius square from keyword."""
    seen = set()
    alpha = []
    for c in keyword.upper():
        if merge_ij and c == 'J':
            c = 'I'
        if c not in seen and c.isalpha():
            seen.add(c)
            alpha.append(c)
    for c in 'ABCDEFGHIKLMNOPQRSTUVWXYZ':  # no J
        if c not in seen:
            seen.add(c)
            alpha.append(c)
    return alpha

def bifid_decrypt(ct, square, period=None):
    """Decrypt ciphertext using Bifid cipher with given Polybius square."""
    if period is None:
        period = len(ct)  # full-length Bifid

    # Build lookup
    pos_of = {}
    for i, c in enumerate(square):
        pos_of[c] = (i // 5, i % 5)

    result = []
    for block_start in range(0, len(ct), period):
        block = ct[block_start:block_start + period]
        if not block:
            continue

        # Convert to row/col pairs
        rows = []
        cols = []
        for c in block:
            ch = c if c != 'J' else 'I'
            if ch in pos_of:
                r, col = pos_of[ch]
                rows.append(r)
                cols.append(col)
            else:
                rows.append(0)
                cols.append(0)

        # Interleave: take all rows then all cols
        combined = rows + cols

        # Re-pair
        pt_block = []
        for i in range(len(block)):
            r = combined[i]
            c = combined[i + len(block)]
            idx = r * 5 + c
            pt_block.append(square[idx])

        result.extend(pt_block)

    return ''.join(result)

def score_cribs(pt_text):
    """Score how many crib positions match."""
    matches = 0
    for start, crib in [(ENE_POS, ENE_PT), (BC_POS, BC_PT)]:
        for i, ch in enumerate(crib):
            if start + i < len(pt_text):
                # Handle I/J merge
                expected = ch if ch != 'J' else 'I'
                actual = pt_text[start + i] if pt_text[start + i] != 'J' else 'I'
                if actual == expected:
                    matches += 1
    return matches

# Test keywords
keywords = [
    '', 'KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'BERLIN', 'CLOCK',
    'BERLINCLOCK', 'EGYPT', 'CAIRO', 'SHADOW', 'LIGHT', 'CIA',
    'LANGLEY', 'VIRGINIA', 'SANBORN', 'SCHEIDT', 'MESSAGE',
    'DELIVER', 'POINT', 'COMPASS', 'MAGNETIC', 'FIELD',
    'BURIED', 'LOCATION', 'NORTHWEST', 'NORTHEAST', 'EAST',
    'NORTH', 'SOUTH', 'WEST', 'WHATSTHEPOINT', 'IQLUSION',
    'UNDERGRUUND', 'DESPERATELY', 'SLOWLY', 'INVISIBLE',
    'TUTANKHAMUN', 'CARTER',
]

print(f"Testing {len(keywords)} keywords × periods 2-48 (full-length too)...")
best_bifid = (0, '', 0)

for kw in keywords:
    square = make_polybius(kw)

    # Full-length Bifid (period = 97)
    pt = bifid_decrypt(CT, square, period=N)
    s = score_cribs(pt)
    if s > best_bifid[0]:
        best_bifid = (s, kw, N)
    if s >= 5:
        print(f"   kw='{kw}' period=full: {s}/24")

    # Period Bifid
    for period in range(2, 49):
        pt = bifid_decrypt(CT, square, period=period)
        s = score_cribs(pt)
        if s > best_bifid[0]:
            best_bifid = (s, kw, period)
        if s >= 5:
            print(f"   kw='{kw}' period={period}: {s}/24")

print(f"\n   Best Bifid: {best_bifid[0]}/24 (kw='{best_bifid[1]}', period={best_bifid[2]})")

# ============================================================
# 3. TRIFID CIPHER
# ============================================================
print("\n" + "=" * 70)
print("3. TRIFID CIPHER")
print("=" * 70)

def make_trifid_cube(keyword=''):
    """Create a 3x3x3 = 27-position Trifid arrangement (26 letters + filler)."""
    seen = set()
    alpha = []
    for c in keyword.upper():
        if c not in seen and c.isalpha():
            seen.add(c)
            alpha.append(c)
    for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        if c not in seen:
            seen.add(c)
            alpha.append(c)
    alpha.append('+')  # 27th position (filler)
    return alpha

def trifid_decrypt(ct, cube, period=5):
    """Decrypt using Trifid cipher."""
    pos_of = {}
    for i, c in enumerate(cube[:27]):
        layer = i // 9
        row = (i % 9) // 3
        col = i % 3
        pos_of[c] = (layer, row, col)

    result = []
    for block_start in range(0, len(ct), period):
        block = ct[block_start:block_start + period]
        if not block:
            continue

        layers, rows, cols = [], [], []
        for c in block:
            if c in pos_of:
                l, r, co = pos_of[c]
            else:
                l, r, co = 0, 0, 0
            layers.append(l)
            rows.append(r)
            cols.append(co)

        combined = layers + rows + cols
        n_block = len(block)

        pt_block = []
        for i in range(n_block):
            l = combined[i]
            r = combined[i + n_block]
            c = combined[i + 2 * n_block]
            idx = l * 9 + r * 3 + c
            if idx < 27:
                pt_block.append(cube[idx])
            else:
                pt_block.append('?')

        result.extend(pt_block)

    return ''.join(result)

best_trifid = (0, '', 0)
for kw in keywords[:15]:  # test fewer keywords for Trifid (slower)
    cube = make_trifid_cube(kw)
    for period in range(2, 30):
        pt = trifid_decrypt(CT, cube, period=period)
        s = score_cribs(pt)
        if s > best_trifid[0]:
            best_trifid = (s, kw, period)
        if s >= 5:
            print(f"   kw='{kw}' period={period}: {s}/24")

print(f"   Best Trifid: {best_trifid[0]}/24 (kw='{best_trifid[1]}', period={best_trifid[2]})")

# ============================================================
# 4. SIMULATED ANNEALING: plaintext search optimizing key quality
# ============================================================
print("\n" + "=" * 70)
print("4. SIMULATED ANNEALING — Plaintext search")
print("=" * 70)

if not qg:
    print("   Skipping SA — no quadgram data loaded")
else:
    random.seed(42)

    # Initialize plaintext with cribs and random elsewhere
    pt = list('A' * N)
    for i, ch in enumerate(ENE_PT):
        pt[ENE_POS + i] = ch
    for i, ch in enumerate(BC_PT):
        pt[BC_POS + i] = ch

    # Random fill for unknown positions
    unknown_positions = [i for i in range(N)
                         if not (ENE_POS <= i < ENE_POS + len(ENE_PT))
                         and not (BC_POS <= i < BC_POS + len(BC_PT))]
    for i in unknown_positions:
        pt[i] = n2c(random.randint(0, 25))

    def compute_score(pt_list):
        """Score = quadgram(plaintext) + quadgram(key)."""
        pt_text = ''.join(pt_list)
        key_text = ''.join(n2c((CT_NUM[i] - c2n(pt_list[i])) % 26) for i in range(N))
        return qg_score(pt_text) + qg_score(key_text) * 0.5

    current_score = compute_score(pt)
    best_pt = pt[:]
    best_score = current_score

    T = 10.0
    T_min = 0.01
    cooling = 0.9999
    iterations = 500000

    print(f"   Running SA: {iterations} iterations, T={T}→{T_min}")
    print(f"   Initial score: {current_score:.1f}")

    for iteration in range(iterations):
        # Pick a random unknown position and change it
        pos = random.choice(unknown_positions)
        old_char = pt[pos]
        new_char = n2c(random.randint(0, 25))
        if new_char == old_char:
            continue

        pt[pos] = new_char
        new_score = compute_score(pt)
        delta = new_score - current_score

        if delta > 0 or random.random() < math.exp(delta / max(T, 0.001)):
            current_score = new_score
            if new_score > best_score:
                best_score = new_score
                best_pt = pt[:]
        else:
            pt[pos] = old_char

        T *= cooling

        if iteration % 100000 == 0:
            print(f"   iter={iteration:7d} T={T:.3f} current={current_score:.1f} best={best_score:.1f}")

    best_pt_text = ''.join(best_pt)
    best_key_text = ''.join(n2c((CT_NUM[i] - c2n(best_pt[i])) % 26) for i in range(N))
    print(f"\n   Final best score: {best_score:.1f}")
    print(f"   PT: {best_pt_text}")
    print(f"   Key: {best_key_text}")
    print(f"   PT quadgram: {qg_score(best_pt_text):.1f}")
    print(f"   Key quadgram: {qg_score(best_key_text):.1f}")

    # Check crib integrity
    pt_check = ''.join(best_pt)
    assert pt_check[ENE_POS:ENE_POS+len(ENE_PT)] == ENE_PT
    assert pt_check[BC_POS:BC_POS+len(BC_PT)] == BC_PT
    print("   Crib integrity: PASS")

print("\n" + "=" * 70)
print("NOVEL ATTACKS COMPLETE")
print("=" * 70)
