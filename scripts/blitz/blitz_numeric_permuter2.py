#!/usr/bin/env python3
"""
Cipher: multi-method blitz
Family: blitz
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
BLITZ Wave 2: Numeric Permuter — advanced approaches

New approaches:
  K. Fisher-Yates shuffle seeded by grille extract (LCG, various seed encodings)
  L. K4 on 2D grid + grille overlay at K4 scale
  M. Rail-fence transposition (various rail counts)
  N. Column-major grille reading → different extract → permutation
  O. Grille holes → K4 coordinate mapping
  P. Interleaved / stride-based permutations
  Q. AMSCO-style unscrambling
  R. "8 Lines" interpretation
  S. Grille as Polybius/checkerboard index
  T. Extract bigram/trigram as base-97 encoding
  U. Reverse approach: try all permutations of a small "anchor" set
  V. Hill-based from grille alphabet
"""
import json, sys, os, math, random, itertools
from collections import defaultdict, Counter

K4     = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
GRILLE = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
AZ     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA     = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KEYWORDS = ['KRYPTOS','PALIMPSEST','ABSCISSA','SHADOW','SANBORN','SCHEIDT',
            'BERLIN','CLOCK','EAST','NORTH','LIGHT','ANTIPODES','MEDUSA','ENIGMA']
N = 97
assert len(K4) == N
assert len(GRILLE) == 106

AZ_IDX = {c: i for i, c in enumerate(AZ)}
KA_IDX = {c: i for i, c in enumerate(KA)}
GRILLE_AZ  = [AZ_IDX[c] for c in GRILLE]
GRILLE_KA  = [KA_IDX[c] for c in GRILLE]
K4_AZ      = [AZ_IDX[c] for c in K4]
K4_KA      = [KA_IDX[c] for c in K4]

QG_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'english_quadgrams.json')
with open(QG_PATH) as f:
    qg = json.load(f)

def qgscore(text):
    return sum(qg.get(text[i:i+4], -10.0) for i in range(len(text)-3))

def vig_dec(ct, key, alpha=AZ):
    n = len(alpha); idx = {c: i for i, c in enumerate(alpha)}
    return ''.join(alpha[(idx[ct[i]] - idx[key[i % len(key)]]) % n] for i in range(len(ct)))

def beau_dec(ct, key, alpha=AZ):
    n = len(alpha); idx = {c: i for i, c in enumerate(alpha)}
    return ''.join(alpha[(idx[key[i % len(key)]] - idx[ct[i]]) % n] for i in range(len(ct)))

def is_valid_perm(p, n=N):
    return len(p) == n and sorted(p) == list(range(n))

def apply_perm(text, perm):
    return ''.join(text[p] for p in perm)

def values_to_perm(vals):
    indexed = sorted(range(N), key=lambda i: vals[i])
    perm = [0]*N
    for rank, idx in enumerate(indexed): perm[idx] = rank
    return perm

RESULTS = []
BEST_SCORE = -9999
TRIED = set()
TRIED_COUNT = 0

def try_perm(perm, label):
    global BEST_SCORE, TRIED_COUNT
    key = tuple(perm)
    if key in TRIED: return
    TRIED.add(key)
    TRIED_COUNT += 1
    candidate_ct = apply_perm(K4, perm)
    for kw in KEYWORDS:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cname, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                pt = fn(candidate_ct, kw, alpha)
                sc = qgscore(pt)
                ene = pt.find("EASTNORTHEAST")
                bc  = pt.find("BERLINCLOCK")
                if ene >= 0 or bc >= 0:
                    print(f"\n{'='*60}")
                    print(f"*** CRIB HIT *** label={label}")
                    print(f"  ENE@{ene}  BC@{bc}  key={kw}  {cname}/{alpha_name}")
                    print(f"  PT : {pt}")
                    print(f"  CT': {candidate_ct}")
                    print(f"  Score: {sc:.2f}")
                    print(f"{'='*60}\n")
                    RESULTS.append({'label':label,'ene':ene,'bc':bc,'kw':kw,
                                    'cipher':cname,'alpha':alpha_name,
                                    'pt':pt,'score':sc,'perm':list(perm)})
                    return
                if sc > BEST_SCORE:
                    BEST_SCORE = sc
                    print(f"  [best] {sc:.2f}  {label}  {kw}/{cname}/{alpha_name}  {pt[:40]}…")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH K — Fisher-Yates with various PRNG seeds from grille
# ─────────────────────────────────────────────────────────────────────────────
def approach_K():
    print("\n--- APPROACH K: Fisher-Yates PRNG seeded by grille ---")

    def fy_shuffle(seed):
        """Fisher-Yates using LCG-style seeding."""
        perm = list(range(N))
        rng = random.Random(seed)
        for i in range(N-1, 0, -1):
            j = rng.randint(0, i)
            perm[i], perm[j] = perm[j], perm[i]
        return perm

    # K1. Seed from grille as integer (base 26)
    print("  K1: grille bigint as seed...")
    for vals, sfx in [(GRILLE_KA, "ka"), (GRILLE_AZ, "az")]:
        seed = 0
        for v in vals: seed = seed * 26 + v
        p = fy_shuffle(seed % (2**32))
        try_perm(p, f"K1_fy_bigint_{sfx}")
        # Also use seed directly (Python handles big ints in random)
        p2 = fy_shuffle(seed)
        try_perm(p2, f"K1_fy_bigint_{sfx}_full")

    # K2. Seed from sum/product of grille values
    print("  K2: seed from aggregates...")
    for vals, sfx in [(GRILLE_KA, "ka"), (GRILLE_AZ, "az")]:
        seeds = {
            'sum': sum(vals),
            'prod': 1,
            'xorall': 0,
            'str': int(''.join(str(v).zfill(2) for v in vals)),
        }
        for v in vals:
            seeds['prod'] = (seeds['prod'] * max(v, 1)) % (2**64)
            seeds['xorall'] ^= v
        for sname, seed in seeds.items():
            p = fy_shuffle(seed)
            try_perm(p, f"K2_fy_{sname}_{sfx}")

    # K3. Seed from each grille char's KA/AZ index (seed = individual char)
    # Use cumulative product
    print("  K3: cumulative product seeds...")
    for vals, sfx in [(GRILLE_KA[:N], "ka"), (GRILLE_AZ[:N], "az")]:
        running = 1
        seeds_list = []
        for v in vals:
            running = running * max(v+1, 2) + v
            seeds_list.append(running)
        for i in range(0, len(seeds_list), 10):
            p = fy_shuffle(seeds_list[i])
            try_perm(p, f"K3_fy_cumprod_{sfx}_i{i}")

    # K4. Grille chars interpreted as decimal digits → seed
    print("  K4: decimal digit seed...")
    dec_str_ka = ''.join(str(v) for v in GRILLE_KA)
    dec_str_az = ''.join(str(v) for v in GRILLE_AZ)
    for ds, sfx in [(dec_str_ka, "ka"), (dec_str_az, "az")]:
        for start in [0, 10, 20, 50]:
            chunk = ds[start:start+18]  # 18-digit int
            if chunk:
                seed = int(chunk) if chunk else 0
                p = fy_shuffle(seed)
                try_perm(p, f"K4_fy_dec_{sfx}_s{start}")

    # K5. Grille chars as bytes → hash → seed
    print("  K5: hash-based seeds...")
    import hashlib
    for vals, sfx in [(GRILLE_KA, "ka"), (GRILLE_AZ, "az")]:
        data = bytes(vals)
        for algo in ['md5', 'sha1', 'sha256']:
            h = hashlib.new(algo, data).digest()
            seed = int.from_bytes(h[:8], 'big')
            p = fy_shuffle(seed)
            try_perm(p, f"K5_fy_{algo}_{sfx}")
        # Also try individual substrings
        for start in range(0, 106, 13):
            h = hashlib.md5(bytes(vals[start:start+13])).digest()
            seed = int.from_bytes(h[:4], 'big')
            p = fy_shuffle(seed)
            try_perm(p, f"K5_fy_md5_{sfx}_s{start}")

    print(f"  Approach K done. Tried={TRIED_COUNT}")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH L — K4 on a 2D grid, grille overlay defines permutation
# ─────────────────────────────────────────────────────────────────────────────
def approach_L():
    """Lay K4 out on rectangle, apply grille holes to get reading order."""
    print("\n--- APPROACH L: K4 on 2D grid + grille overlay ---")

    # Grille hole coordinates
    GRILLE_MASK_ROWS = [
        "000000001010100000000010000000001~~",
        "100000000010000001000100110000011~~",
        "000000000000001000000000000000011~~",
        "00000000000000000000100000010011~~",
        "00000001000000001000010000000011~~",
        "000000001000000000000000000000011~",
        "100000000000000000000000000000011",
        "00000000000000000000000100000100~~",
        "0000000000000000000100000001000~~",
        "0000000000000000000000000000100~~",
        "000000001000000000000000000000~~",
        "00000110000000000000000000000100~~",
        "00000000000000100010000000000001~~",
        "00000000000100000000000000001000~~",
        "000110100001000000000000001000010~~",
        "00001010000000000000000001000001~~",
        "001001000010010000000000000100010~~",
        "00000000000100000000010000010001~~",
        "000000000000010001001000000010001~~",
        "00000000000000001001000000000100~~",
        "000000001100000010100100010001001~~",
        "000000000000000100001010100100011~",
        "00000000100000000000100001100001~~~",
        "100000000000000000001000001000010~",
        "10000001000001000000100000000001~~",
        "000010000000000000010000100000011",
        "0000000000000000000100001000000011",
        "00000000000000100000001010000001~~",
    ]
    GRILLE_ROWS = 28
    GRILLE_COLS = 33

    holes_rc = []
    for r, row in enumerate(GRILLE_MASK_ROWS):
        for c, ch in enumerate(row):
            if ch == '0':
                holes_rc.append((r, c))
    # holes_rc: 107 holes, reading order (row-major)

    # L1. Scale grille to fit K4 on various rectangles
    # For each K4 rectangle width W (height H = ceil(97/W)):
    #   Map each grille hole (r,c) → K4 cell (floor(r*H/GRILLE_ROWS), floor(c*W/GRILLE_COLS))
    #   Collect unique K4 cells hit, in hole reading order → that's the permutation

    print("  L1: scaled grille overlay on K4 rectangles...")
    for W in range(5, 34):
        H = math.ceil(N / W)
        if W * H < N: continue
        if W * H > N + 5: pass  # allow up to 5 pad cells

        k4_positions_hit = []
        seen = set()
        for r, c in holes_rc:
            kr = math.floor(r * H / GRILLE_ROWS)
            kc = math.floor(c * W / GRILLE_COLS)
            k4_pos = kr * W + kc
            if k4_pos < N and k4_pos not in seen:
                seen.add(k4_pos)
                k4_positions_hit.append(k4_pos)

        # k4_positions_hit is the order in which K4 positions are "revealed"
        # The permutation: slot i goes to position k4_positions_hit[i]
        if len(k4_positions_hit) >= N:
            perm = k4_positions_hit[:N]
            if is_valid_perm(perm):
                try_perm(perm, f"L1_scaled_W{W}H{H}")
                inv = [0]*N
                for i, v in enumerate(perm): inv[v] = i
                try_perm(inv, f"L1_scaled_W{W}H{H}_inv")
            else:
                # Use as rank values
                try_perm(values_to_perm(perm[:N]), f"L1_scaled_rank_W{W}H{H}")
        elif len(k4_positions_hit) > 0:
            # Rank the positions hit first
            vals = k4_positions_hit + [i for i in range(N) if i not in set(k4_positions_hit)]
            # "order" permutation: vals[rank] = original_pos
            if len(vals) == N:
                perm_candidate = vals
                if is_valid_perm(perm_candidate):
                    try_perm(perm_candidate, f"L1_partial_W{W}H{H}")

    # L2. Same but column-major hole reading order
    print("  L2: scaled grille (column-major holes) on K4 rectangles...")
    holes_colmaj = sorted(holes_rc, key=lambda x: (x[1], x[0]))
    for W in range(5, 34):
        H = math.ceil(N / W)
        if W * H < N: continue

        k4_positions_hit = []
        seen = set()
        for r, c in holes_colmaj:
            kr = math.floor(r * H / GRILLE_ROWS)
            kc = math.floor(c * W / GRILLE_COLS)
            k4_pos = kr * W + kc
            if k4_pos < N and k4_pos not in seen:
                seen.add(k4_pos)
                k4_positions_hit.append(k4_pos)

        if len(k4_positions_hit) >= N:
            perm = k4_positions_hit[:N]
            if is_valid_perm(perm):
                try_perm(perm, f"L2_colmaj_W{W}H{H}")
                inv = [0]*N
                for i, v in enumerate(perm): inv[v] = i
                try_perm(inv, f"L2_colmaj_W{W}H{H}_inv")

    # L3. Direct overlay: hole (r,c) hits K4 position if r < H and c < W
    print("  L3: direct overlay (no scaling)...")
    for W in range(5, 34):
        H = math.ceil(N / W)
        if H > GRILLE_ROWS: continue
        if W > GRILLE_COLS: continue

        k4_positions_hit = []
        seen = set()
        for r, c in holes_rc:
            if r < H and c < W:
                k4_pos = r * W + c
                if k4_pos < N and k4_pos not in seen:
                    seen.add(k4_pos)
                    k4_positions_hit.append(k4_pos)

        if len(k4_positions_hit) >= N:
            perm = k4_positions_hit[:N]
            if is_valid_perm(perm):
                try_perm(perm, f"L3_direct_W{W}H{H}")
                inv = [0]*N
                for i, v in enumerate(perm): inv[v] = i
                try_perm(inv, f"L3_direct_W{W}H{H}_inv")

    print(f"  Approach L done. Tried={TRIED_COUNT}")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH M — Rail-fence transposition
# ─────────────────────────────────────────────────────────────────────────────
def approach_M():
    print("\n--- APPROACH M: Rail-fence transposition ---")

    def railfence_perm(n, rails):
        """Rail-fence write order → read order permutation."""
        # Assign each position 0..n-1 to a rail
        pattern = []
        cycle = 2*(rails-1)
        for i in range(n):
            pos_in_cycle = i % cycle
            if pos_in_cycle < rails:
                pattern.append(pos_in_cycle)
            else:
                pattern.append(cycle - pos_in_cycle)

        # Group by rail
        rail_positions = [[] for _ in range(rails)]
        for i, rail in enumerate(pattern):
            rail_positions[rail].append(i)

        # Build permutation: where did output position k come from?
        # Reading: concatenate rails 0,1,...,rails-1
        perm = []
        for rail in range(rails):
            perm.extend(rail_positions[rail])
        return perm  # perm[output_pos] = input_pos

    for rails in range(2, 25):
        p = railfence_perm(N, rails)
        if is_valid_perm(p):
            try_perm(p, f"M_railfence_{rails}")
            inv = [0]*N
            for i, v in enumerate(p): inv[v] = i
            try_perm(inv, f"M_railfence_{rails}_inv")

    # Also try with offset starting rail
    def railfence_perm_offset(n, rails, offset):
        cycle = 2*(rails-1)
        pattern = []
        for i in range(n):
            pos_in_cycle = (i + offset) % cycle
            if pos_in_cycle < rails:
                pattern.append(pos_in_cycle)
            else:
                pattern.append(cycle - pos_in_cycle)
        rail_positions = [[] for _ in range(rails)]
        for i, rail in enumerate(pattern):
            rail_positions[rail].append(i)
        perm = []
        for rail in range(rails):
            perm.extend(rail_positions[rail])
        return perm

    for rails in range(2, 15):
        for offset in range(1, 2*(rails-1)):
            p = railfence_perm_offset(N, rails, offset)
            if is_valid_perm(p):
                try_perm(p, f"M_railfence_r{rails}_off{offset}")
                inv = [0]*N
                for i, v in enumerate(p): inv[v] = i
                try_perm(inv, f"M_railfence_r{rails}_off{offset}_inv")

    print(f"  Approach M done. Tried={TRIED_COUNT}")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH N — Column-major grille reading → alternative extract
# ─────────────────────────────────────────────────────────────────────────────
def approach_N():
    """Re-derive the grille extract using different reading orders of the KA tableau."""
    print("\n--- APPROACH N: Alternative grille reading orders ---")

    # The KA Vigenère tableau cell (r,c) = KA[(r+c) mod 26]
    # (row 0 = KA shifted by 0, row 1 = shifted by 1, etc.)
    # Hole coordinates from the grille mask
    GRILLE_MASK_ROWS = [
        "000000001010100000000010000000001~~",
        "100000000010000001000100110000011~~",
        "000000000000001000000000000000011~~",
        "00000000000000000000100000010011~~",
        "00000001000000001000010000000011~~",
        "000000001000000000000000000000011~",
        "100000000000000000000000000000011",
        "00000000000000000000000100000100~~",
        "0000000000000000000100000001000~~",
        "0000000000000000000000000000100~~",
        "000000001000000000000000000000~~",
        "00000110000000000000000000000100~~",
        "00000000000000100010000000000001~~",
        "00000000000100000000000000001000~~",
        "000110100001000000000000001000010~~",
        "00001010000000000000000001000001~~",
        "001001000010010000000000000100010~~",
        "00000000000100000000010000010001~~",
        "000000000000010001001000000010001~~",
        "00000000000000001001000000000100~~",
        "000000001100000010100100010001001~~",
        "000000000000000100001010100100011~",
        "00000000100000000000100001100001~~~",
        "100000000000000000001000001000010~",
        "10000001000001000000100000000001~~",
        "000010000000000000010000100000011",
        "0000000000000000000100001000000011",
        "00000000000000100000001010000001~~",
    ]
    holes_rc = []
    for r, row_str in enumerate(GRILLE_MASK_ROWS):
        for c, ch in enumerate(row_str):
            if ch == '0':
                holes_rc.append((r, c))

    def tableau_cell(r, c, alpha=KA):
        return alpha[(r + c) % 26]

    # N1. Column-major reading (sort by col, then row)
    print("  N1: column-major extract...")
    holes_colmaj = sorted(holes_rc, key=lambda x: (x[1], x[0]))
    extract_colmaj = ''.join(tableau_cell(r, c) for r, c in holes_colmaj)
    print(f"    Extract (col-maj): {extract_colmaj[:40]}...")
    g_colmaj_ka = [KA_IDX[c] for c in extract_colmaj]
    g_colmaj_az = [AZ_IDX[c] for c in extract_colmaj]

    # N2. Diagonal reading (sort by r+c, then r)
    print("  N2: diagonal extract...")
    holes_diag = sorted(holes_rc, key=lambda x: (x[0]+x[1], x[0]))
    extract_diag = ''.join(tableau_cell(r, c) for r, c in holes_diag)
    print(f"    Extract (diag):    {extract_diag[:40]}...")
    g_diag_ka = [KA_IDX[c] for c in extract_diag]
    g_diag_az = [AZ_IDX[c] for c in extract_diag]

    # N3. Anti-diagonal (sort by r-c, then r)
    print("  N3: anti-diagonal extract...")
    holes_antidiag = sorted(holes_rc, key=lambda x: (x[0]-x[1], x[0]))
    extract_antidiag = ''.join(tableau_cell(r, c) for r, c in holes_antidiag)
    g_antidiag_ka = [KA_IDX[c] for c in extract_antidiag]

    # N4. Reverse row-major
    print("  N4: reverse row-major...")
    holes_rev = list(reversed(holes_rc))
    extract_rev = ''.join(tableau_cell(r, c) for r, c in holes_rev)
    g_rev_ka = [KA_IDX[c] for c in extract_rev]
    g_rev_az = [AZ_IDX[c] for c in extract_rev]

    # N5. Sorted by value (tableau cell value)
    print("  N5: value-sorted extract...")
    holes_byval = sorted(holes_rc, key=lambda x: (KA_IDX[tableau_cell(x[0], x[1])], x[0], x[1]))
    extract_byval = ''.join(tableau_cell(r, c) for r, c in holes_byval)
    g_byval_ka = [KA_IDX[c] for c in extract_byval]

    # For each alternative extract, try the same range of approaches
    extracts = {
        'colmaj_ka': g_colmaj_ka,
        'colmaj_az': g_colmaj_az,
        'diag_ka': g_diag_ka,
        'diag_az': g_diag_az,
        'antidiag_ka': g_antidiag_ka,
        'rev_ka': g_rev_ka,
        'rev_az': g_rev_az,
        'byval_ka': g_byval_ka,
    }

    for sfx, vals in extracts.items():
        # Rank first 97
        try_perm(values_to_perm(vals[:N]), f"N_rank_{sfx}")
        # Reverse rank
        inv_vals = [-v for v in vals[:N]]
        try_perm(values_to_perm(inv_vals), f"N_revrank_{sfx}")
        # Pair encoding
        pair_vals = [(vals[i]*26 + vals[i+1]) % N for i in range(N-1)] + [vals[96] % N]
        try_perm(values_to_perm(pair_vals), f"N_pair_{sfx}")
        # Cumsum
        s = 0
        cs = []
        for v in vals[:N]:
            s = (s + v) % N
            cs.append(s)
        if is_valid_perm(cs): try_perm(cs, f"N_cumsum_{sfx}")
        try_perm(values_to_perm(cs), f"N_cumsum_rank_{sfx}")

    print(f"  Approach N done. Tried={TRIED_COUNT}")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH O — Hole coordinate arithmetic
# ─────────────────────────────────────────────────────────────────────────────
def approach_O():
    """Use hole (r,c) coordinates directly to build permutations."""
    print("\n--- APPROACH O: Hole coordinate arithmetic ---")

    GRILLE_MASK_ROWS = [
        "000000001010100000000010000000001~~",
        "100000000010000001000100110000011~~",
        "000000000000001000000000000000011~~",
        "00000000000000000000100000010011~~",
        "00000001000000001000010000000011~~",
        "000000001000000000000000000000011~",
        "100000000000000000000000000000011",
        "00000000000000000000000100000100~~",
        "0000000000000000000100000001000~~",
        "0000000000000000000000000000100~~",
        "000000001000000000000000000000~~",
        "00000110000000000000000000000100~~",
        "00000000000000100010000000000001~~",
        "00000000000100000000000000001000~~",
        "000110100001000000000000001000010~~",
        "00001010000000000000000001000001~~",
        "001001000010010000000000000100010~~",
        "00000000000100000000010000010001~~",
        "000000000000010001001000000010001~~",
        "00000000000000001001000000000100~~",
        "000000001100000010100100010001001~~",
        "000000000000000100001010100100011~",
        "00000000100000000000100001100001~~~",
        "100000000000000000001000001000010~",
        "10000001000001000000100000000001~~",
        "000010000000000000010000100000011",
        "0000000000000000000100001000000011",
        "00000000000000100000001010000001~~",
    ]
    holes_rc = []
    for r, row_str in enumerate(GRILLE_MASK_ROWS):
        for c, ch in enumerate(row_str):
            if ch == '0':
                holes_rc.append((r, c))

    # Take first 97 holes (row-major order)
    h97 = holes_rc[:N]
    rows = [r for r, c in h97]
    cols = [c for r, c in h97]
    rowcols = [(r, c) for r, c in h97]

    # O1. Row × col mod 97
    vals = [(r * c + r + c) % N for r, c in h97]
    try_perm(values_to_perm(vals), "O1_rc_cross")

    # O2. (r^2 + c^2) mod 97
    vals = [(r*r + c*c) % N for r, c in h97]
    try_perm(values_to_perm(vals), "O2_r2c2")

    # O3. r×33 + c (absolute position mod 97)
    vals = [(r*33 + c) % N for r, c in h97]
    try_perm(values_to_perm(vals), "O3_abs_mod97")
    if is_valid_perm(vals): try_perm(vals, "O3_abs_mod97_direct")

    # O4. c×28 + r (transposed absolute position)
    vals = [(c*28 + r) % N for r, c in h97]
    try_perm(values_to_perm(vals), "O4_transpose_abs")

    # O5. Row-within-column-group: within each column, rank by row
    col_groups = defaultdict(list)
    for i, (r, c) in enumerate(h97):
        col_groups[c].append((r, i))
    vals = [0]*N
    for col_idx, (col, entries) in enumerate(sorted(col_groups.items())):
        for row_rank, (r, orig_i) in enumerate(sorted(entries)):
            vals[orig_i] = col_idx * 10 + row_rank
    try_perm(values_to_perm(vals), "O5_col_then_row_rank")

    # O6. Row-major but rank by (col, row) — effectively col-major rank
    vals = [(c*100 + r) for r, c in h97]
    try_perm(values_to_perm(vals), "O6_colmaj_rank")

    # O7. Hole index in column-major order vs row-major order
    # Build inverse lookup
    hole_idx_rowmaj = {(r, c): i for i, (r, c) in enumerate(holes_rc[:N])}
    holes_colmaj = sorted(holes_rc[:N], key=lambda x: (x[1], x[0]))
    vals = [hole_idx_rowmaj.get(rc, 0) for rc in holes_colmaj[:N]]
    if is_valid_perm(vals): try_perm(vals, "O7_rowvscol_direct")
    try_perm(values_to_perm(vals), "O7_rowvscol_rank")

    # O8. All 107 holes: 97 holes hit K4, 10 are "padding"
    # Try each subset of 97 holes from the 107
    # (C(107,97) = 107!/(97!*10!) ≈ 3B — too many)
    # But try: first 97, last 97, skip-1, skip-every-11
    subsets = {
        'first97': holes_rc[:97],
        'last97': holes_rc[-97:],
        'skip1': holes_rc[1:98],
        'every': holes_rc[::2][:97] if len(holes_rc[::2]) >= 97 else holes_rc[:97],
    }
    # Also: remove the 10 most-common or least-common column holes
    col_freq = Counter(c for r, c in holes_rc)
    most_common_cols = [c for c, _ in col_freq.most_common(3)]
    filtered = [(r, c) for r, c in holes_rc if c not in most_common_cols[:1]]
    if len(filtered) >= 97:
        subsets['no_freqcol'] = filtered[:97]

    for sfx, subset in subsets.items():
        if len(subset) < N: continue
        vals = [(r*33 + c) % N for r, c in subset[:N]]
        try_perm(values_to_perm(vals), f"O8_{sfx}_rank")
        # Row-major order of the subset positions
        perm = [(r*33 + c) for r, c in subset[:N]]
        ranked = sorted(range(N), key=lambda i: perm[i])
        perm2 = [0]*N
        for rank, idx in enumerate(ranked): perm2[idx] = rank
        try_perm(perm2, f"O8_{sfx}_orderperm")

    print(f"  Approach O done. Tried={TRIED_COUNT}")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH P — AMSCO cipher
# ─────────────────────────────────────────────────────────────────────────────
def approach_P():
    """AMSCO transposition — alternating 1 and 2 char chunks."""
    print("\n--- APPROACH P: AMSCO transposition ---")

    def amsco_perm(width, key_order, n=N, start_long=True):
        """
        AMSCO: write text in rows of alternating 1/2 char columns.
        key_order: column reading order
        Returns permutation: output position i came from input position perm[i]
        """
        ncols = width
        # Assign chars to cells: alternate 1/2 per cell, row by row
        cells = []  # cells[row][col] = list of input positions
        pos = 0
        row = 0
        while pos < n:
            row_cells = []
            for col in range(ncols):
                if pos >= n:
                    row_cells.append([])
                    continue
                # Cell (row,col): length alternates based on (row+col) % 2
                is_long = ((row + col) % 2 == (0 if start_long else 1))
                length = 2 if is_long else 1
                end = min(pos + length, n)
                row_cells.append(list(range(pos, end)))
                pos = end
            cells.append(row_cells)
            row += 1

        # Read columns in key_order
        perm = []
        for col in key_order:
            for row_cells in cells:
                if col < len(row_cells):
                    perm.extend(row_cells[col])

        if len(perm) == n and is_valid_perm(perm):
            return perm
        return None

    # Try with grille chars as key for AMSCO
    for w in range(3, 20):
        # Sort columns by KA-index of first w grille chars
        key_str = GRILLE[:w]
        col_order_ka = sorted(range(w), key=lambda j: (KA_IDX.get(key_str[j], 99), j))
        col_order_az = sorted(range(w), key=lambda j: (AZ_IDX.get(key_str[j], 99), j))
        for col_order, sfx in [(col_order_ka, "ka"), (col_order_az, "az")]:
            for start_long in [True, False]:
                p = amsco_perm(w, col_order, start_long=start_long)
                if p:
                    lbl = f"P_amsco_w{w}_{sfx}_{'long' if start_long else 'short'}"
                    try_perm(p, lbl)
                    inv = [0]*N
                    for i, v in enumerate(p): inv[v] = i
                    try_perm(inv, lbl+"_inv")

    # Also try pure AMSCO (no external key, just width-based)
    for w in range(3, 32):
        for start_long in [True, False]:
            # Natural key order (0,1,2,...,w-1)
            p = amsco_perm(w, list(range(w)), start_long=start_long)
            if p:
                lbl = f"P_amsco_nat_w{w}_{'L' if start_long else 'S'}"
                try_perm(p, lbl)
                inv = [0]*N
                for i, v in enumerate(p): inv[v] = i
                try_perm(inv, lbl+"_inv")

    print(f"  Approach P done. Tried={TRIED_COUNT}")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH Q — "8 Lines" and strip interpretations
# ─────────────────────────────────────────────────────────────────────────────
def approach_Q():
    """K4 as 8 strips/lines; grille reorders them."""
    print("\n--- APPROACH Q: Strip cipher / 8-lines ---")

    # Q1. K4 in 8 strips, reorder strips by grille
    # Various strip lengths summing to 97
    # 8 strips: widths that sum to 97
    # Natural: [12,12,12,12,12,12,12,13] or [13,12,12,12,12,12,12,12]

    def strip_perm(widths, strip_order):
        """Reorder strips of K4 according to strip_order."""
        starts = [sum(widths[:i]) for i in range(len(widths))]
        perm = []
        for s in strip_order:
            start = starts[s]
            end = starts[s] + widths[s]
            perm.extend(range(start, end))
        return perm if is_valid_perm(perm) else None

    # 8 strips of equal widths (approximately)
    strip_configs = []
    for total_strips in range(2, 14):
        base_w = N // total_strips
        rem = N % total_strips
        widths = [base_w + (1 if i < rem else 0) for i in range(total_strips)]
        strip_configs.append((total_strips, widths))

    # For each strip config, try all orders derivable from grille
    for total_strips, widths in strip_configs:
        # Grille-derived order: rank first total_strips chars of grille extract
        key_vals_ka = GRILLE_KA[:total_strips]
        key_vals_az = GRILLE_AZ[:total_strips]
        for kv, sfx in [(key_vals_ka, "ka"), (key_vals_az, "az")]:
            order_asc  = sorted(range(total_strips), key=lambda i: (kv[i], i))
            order_desc = sorted(range(total_strips), key=lambda i: (-kv[i], i))
            for order, osf in [(order_asc, "asc"), (order_desc, "desc")]:
                p = strip_perm(widths, order)
                if p: try_perm(p, f"Q_strip_n{total_strips}_{sfx}_{osf}")
                if p:
                    inv = [0]*N
                    for i, v in enumerate(p): inv[v] = i
                    try_perm(inv, f"Q_strip_n{total_strips}_{sfx}_{osf}_inv")

    # Q2. Specific "8 lines" widths from KryptosFan hint
    # "8 Lines 73" might mean 8 lines with 73 being the last position?
    # Try: 8 lines, last strip at position 73..96 (length 24)
    # Rest: 73/7 = 10.4 chars per line → [11,10,10,11,10,10,11,24]?
    special_widths = [
        [12,12,12,12,12,12,12,13],  # standard
        [13,12,12,12,12,12,12,12],  # reversed standard
        [11,11,11,11,11,11,11,20],  # last line longer
        [12,12,12,12,12,12,11,14],  # variant
        [10,10,10,10,10,10,10,37],  # "73" as offset idea
        [13,13,13,13,12,11,11,11],  # decreasing
        [9,9,9,9,9,9,9,9,9,9,9,7], # 12 strips × 9 - 5
    ]
    for widths in special_widths:
        if sum(widths) != N: continue
        total_strips = len(widths)
        kv = GRILLE_KA[:total_strips]
        order = sorted(range(total_strips), key=lambda i: (kv[i], i))
        p = strip_perm(widths, order)
        if p: try_perm(p, f"Q_special_{'_'.join(map(str,widths))}")

    print(f"  Approach Q done. Tried={TRIED_COUNT}")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH R — Wide columnar transposition (widths 11-30)
# ─────────────────────────────────────────────────────────────────────────────
def approach_R():
    """Columnar transposition with widths 11-30 using grille as key."""
    print("\n--- APPROACH R: Wide columnar (w=11-30) ---")
    import math

    for w in range(11, 31):
        rows = math.ceil(N / w)
        # Use first w chars of grille as key
        key_ka = GRILLE_KA[:w]
        key_az = GRILLE_AZ[:w]
        for kv, sfx in [(key_ka, "ka"), (key_az, "az")]:
            col_order = sorted(range(w), key=lambda j: (kv[j], j))
            col_order_rev = sorted(range(w), key=lambda j: (-kv[j], j))
            for order, osf in [(col_order, "asc"), (col_order_rev, "desc")]:
                perm = []
                for col in order:
                    for row in range(rows):
                        src = row * w + col
                        if src < N:
                            perm.append(src)
                if len(perm) == N and is_valid_perm(perm):
                    try_perm(perm, f"R_col_w{w}_{sfx}_{osf}")
                    inv = [0]*N
                    for i, v in enumerate(perm): inv[v] = i
                    try_perm(inv, f"R_col_w{w}_{sfx}_{osf}_inv")

        # Also try: all 106 grille KA values (periodic) as key
        key_long = (GRILLE_KA * (w//106 + 2))[:w]
        col_order_long = sorted(range(w), key=lambda j: (key_long[j], j))
        perm = []
        for col in col_order_long:
            for row in range(rows):
                src = row * w + col
                if src < N:
                    perm.append(src)
        if len(perm) == N and is_valid_perm(perm):
            try_perm(perm, f"R_col_w{w}_longkey")

    print(f"  Approach R done. Tried={TRIED_COUNT}")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH S — Grille as Polybius / index mapping
# ─────────────────────────────────────────────────────────────────────────────
def approach_S():
    """Treat grille chars as Polybius square coordinates."""
    print("\n--- APPROACH S: Polybius / index mapping ---")

    # S1. Pair consecutive grille chars as (row,col) of a 26×26 → single index
    # Then take mod 97
    for offset in range(9):  # 9 offsets to get 97 pairs: 106-97=9
        pairs_ka = [(GRILLE_KA[offset+i], GRILLE_KA[offset+i+1])
                    for i in range(0, N*2, 2) if offset+i+1 < 106]
        if len(pairs_ka) < N: continue
        pairs_ka = pairs_ka[:N]
        vals = [(r*26 + c) % N for r, c in pairs_ka]
        try_perm(values_to_perm(vals), f"S1_poly_ka_off{offset}")
        if is_valid_perm(vals): try_perm(vals, f"S1_poly_ka_off{offset}_direct")

    # S2. Same with AZ indices
    for offset in range(9):
        pairs_az = [(GRILLE_AZ[offset+i], GRILLE_AZ[offset+i+1])
                    for i in range(0, N*2, 2) if offset+i+1 < 106]
        if len(pairs_az) < N: continue
        pairs_az = pairs_az[:N]
        vals = [(r*26 + c) % N for r, c in pairs_az]
        try_perm(values_to_perm(vals), f"S2_poly_az_off{offset}")

    # S3. Non-overlapping pairs of grille extract (53 pairs → need 97, so also overlapping)
    # Overlapping: slide window by 1
    for stride in [1, 2]:
        vals_ka = [(GRILLE_KA[i]*26 + GRILLE_KA[i+1]) % N
                   for i in range(0, 106-1, stride)][:N]
        if len(vals_ka) >= N:
            try_perm(values_to_perm(vals_ka[:N]), f"S3_slide_ka_stride{stride}")
        vals_az = [(GRILLE_AZ[i]*26 + GRILLE_AZ[i+1]) % N
                   for i in range(0, 106-1, stride)][:N]
        if len(vals_az) >= N:
            try_perm(values_to_perm(vals_az[:N]), f"S3_slide_az_stride{stride}")

    # S4. Use K4 positions as Polybius: (K4_KA[i] * grille_KA[j]) % 97
    vals = [(K4_KA[i] * GRILLE_KA[i]) % N for i in range(N)]
    try_perm(values_to_perm(vals), "S4_k4ka_gka_mul97")
    vals2 = [(K4_AZ[i] * GRILLE_AZ[i]) % N for i in range(N)]
    try_perm(values_to_perm(vals2), "S4_k4az_gaz_mul97")

    # S5. Interleaved K4 and grille as coordinate pairs
    vals = [(K4_KA[i]*26 + GRILLE_KA[i]) % N for i in range(N)]
    try_perm(values_to_perm(vals), "S5_k4ka_gka_pair")
    vals2 = [(GRILLE_KA[i]*26 + K4_KA[i]) % N for i in range(N)]
    try_perm(values_to_perm(vals2), "S5_gka_k4ka_pair")

    print(f"  Approach S done. Tried={TRIED_COUNT}")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH T — Self-referential / K1-K3 keys
# ─────────────────────────────────────────────────────────────────────────────
def approach_T():
    """Use K1-K3 plaintexts as keys for K4 transposition."""
    print("\n--- APPROACH T: K1-K3 based permutations ---")

    # Known K1-K3 plaintexts
    K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
    K2_PT = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDINTHEUNDERGROUNDOUTSIDETHEXLATITUDEANDLONGITUDEXEASTXEAST"
    K3_PT = "SLOWLYDESPERATELYSLOWTHEREMAINSOFPASSAGEDEBRISTHATEVENEDGEOFTHEDIGGINGBLAZEDALITTLEBITMOREOFITSTORYTOLDOFCOLLAPSEDINTERNALWALLSOFTHEHORIZONHESITANTSILVERLIGHTPROBEDALITTLEBITOFITSTORYTOLDOFCOLLAPSEDXINTERNALWALLSOFTHEHORIZONS"

    # Trim/extend K1-K3 to length 97 or use modular indexing
    for name, pt in [("K1", K1_PT), ("K2", K2_PT), ("K3", K3_PT)]:
        # Use as columnar key (first 97 chars, mod)
        pt97 = (pt * 2)[:N]
        vals_az = [AZ_IDX.get(c, 0) for c in pt97]
        vals_ka = [KA_IDX.get(c, 0) for c in pt97]
        try_perm(values_to_perm(vals_az), f"T_{name}_pt_az_rank")
        try_perm(values_to_perm(vals_ka), f"T_{name}_pt_ka_rank")
        # Also: use as columnar transposition key
        for w in [7, 9, 11, 12, 13, 14, 15, 16, 17, 19, 23]:
            key_w = (pt * 2)[:w]
            col_order = sorted(range(w), key=lambda j: (AZ_IDX.get(key_w[j], 99), j))
            rows = math.ceil(N / w)
            perm = []
            for col in col_order:
                for row in range(rows):
                    src = row * w + col
                    if src < N: perm.append(src)
            if len(perm) == N and is_valid_perm(perm):
                try_perm(perm, f"T_{name}_col_w{w}")
                inv = [0]*N
                for i, v in enumerate(perm): inv[v] = i
                try_perm(inv, f"T_{name}_col_w{w}_inv")

    print(f"  Approach T done. Tried={TRIED_COUNT}")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH U — Sparse / partial grille: 9 extra holes = 9 "skip" markers
# ─────────────────────────────────────────────────────────────────────────────
def approach_U():
    """The 106 vs 97 difference: 9 holes are 'extra'. Try choosing which 9 to skip."""
    print("\n--- APPROACH U: 9-skip selection from 106 holes ---")

    # 107 total holes, 106 with letters. We need 97 of the 106.
    # That means we skip 9 letters.
    # Try structured ways to pick which 9 to skip:
    # - Skip every 11th: positions 10,21,32,43,54,65,76,87,98 → 9 items
    # - Skip first 9, last 9
    # - Skip every k-th

    all106 = list(range(106))

    def perm_from_selection(indices, label):
        """Given 97 indices into the grille extract, build permutation."""
        if len(indices) != N: return
        vals = [GRILLE_KA[i] for i in indices]
        try_perm(values_to_perm(vals), label+"_rank_ka")
        vals_az = [GRILLE_AZ[i] for i in indices]
        try_perm(values_to_perm(vals_az), label+"_rank_az")

    # U1. Skip every 11th (0-indexed: 10, 21, ..., 98)
    skip_every11 = [i for i in range(106) if (i+1) % 11 != 0 and (i+1) % 11 != 0]
    skip_every12 = [i for i in range(106) if i % 12 != 11][:N]
    for label, skip_set in [("U1_skip11", set(range(10, 106, 11))),
                              ("U2_skip12", set(range(11, 106, 12)))]:
        sel = [i for i in range(106) if i not in skip_set][:N]
        perm_from_selection(sel, label)

    # U3. First 97
    perm_from_selection(all106[:N], "U3_first97")

    # U4. Last 97
    perm_from_selection(all106[-N:], "U4_last97")

    # U5. Skip the 9 with the MOST COMMON KA values
    from collections import Counter
    freq = Counter(GRILLE_KA)
    sorted_by_freq = sorted(range(106), key=lambda i: (-freq[GRILLE_KA[i]], i))
    skip_common = set(sorted_by_freq[:9])
    sel = [i for i in range(106) if i not in skip_common]
    perm_from_selection(sel[:N], "U5_skip_common")

    # U6. Skip the 9 with the LEAST COMMON KA values
    skip_rare = set(sorted_by_freq[-9:])
    sel = [i for i in range(106) if i not in skip_rare]
    perm_from_selection(sel[:N], "U6_skip_rare")

    # U7. Skip 9 equally spaced positions
    for start in range(12):
        skip_eq = set(range(start, 106, (106//9) if 106//9 > 0 else 12))
        sel = [i for i in range(106) if i not in skip_eq][:N]
        if len(sel) == N:
            perm_from_selection(sel, f"U7_skip_eq_start{start}")

    # U8. Skip positions corresponding to letter T in AZ (T=19) or 'T' in extract
    # There is no T in the extract (design choice!), so this produces no skips
    # Instead, try skipping positions where GRILLE_KA[i] == 4 (T's KA index)
    # There are no such positions (T absent) — consistent!
    # So: the 9 skips might be positions where a certain other letter appears
    for target_ka in range(26):
        positions = [i for i, v in enumerate(GRILLE_KA) if v == target_ka]
        if len(positions) == 9:
            skip_set = set(positions)
            sel = [i for i in range(106) if i not in skip_set]
            if len(sel) == N:
                perm_from_selection(sel, f"U8_skip_ka{target_ka}")
        if len(positions) >= 9:
            # Skip first 9 occurrences
            skip_set = set(positions[:9])
            sel = [i for i in range(106) if i not in skip_set]
            if len(sel) == N:
                perm_from_selection(sel, f"U8_skip_first9_ka{target_ka}")

    print(f"  Approach U done. Tried={TRIED_COUNT}")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH V — Exhaustive search on structured permutation families
# ─────────────────────────────────────────────────────────────────────────────
def approach_V():
    """Try permutation families defined by a small set of parameters."""
    print("\n--- APPROACH V: Parameterized permutation families ---")

    # V1. Affine permutation: perm[i] = (a*i + b) mod 97 (a coprime to 97)
    # Since 97 is prime, all a in 1..96 work
    print("  V1: affine permutations a*i+b mod 97...")
    for a in range(1, N):
        for b in range(0, N, 7):  # sample b values
            perm = [(a*i + b) % N for i in range(N)]
            if is_valid_perm(perm):
                try_perm(perm, f"V1_affine_a{a}_b{b}")
    print(f"    V1 done. Tried={TRIED_COUNT}")

    # V2. Bit-reversal permutation (for powers of 2, but generalized)
    print("  V2: bit-reversal inspired...")
    # Reverse bits of i in log2(N) ≈ 7 bits, mod 97
    for nbits in [6, 7, 8]:
        perm_vals = [int(f"{i:0{nbits}b}"[::-1], 2) % N for i in range(N)]
        try_perm(values_to_perm(perm_vals), f"V2_bitrev_{nbits}")

    # V3. Perfect shuffle (riffle shuffle)
    print("  V3: riffle shuffle permutations...")
    def riffle(n, k):
        """k-th riffle shuffle permutation."""
        half = n // 2
        perm = []
        for i in range(half):
            perm.append(i)
            if i + half < n:
                perm.append(i + half)
        if n % 2 == 1:
            perm.append(n-1)
        return perm

    p = riffle(N, 1)
    if is_valid_perm(p): try_perm(p, "V3_riffle1")
    inv = [0]*N
    for i, v in enumerate(p): inv[v] = i
    try_perm(inv, "V3_riffle1_inv")

    # Multiple riffles
    p_cur = list(range(N))
    for k in range(1, 20):
        r = riffle(N, 1)
        p_new = [p_cur[r[i]] for i in range(N)]
        p_cur = p_new
        if is_valid_perm(p_cur): try_perm(p_cur, f"V3_riffle{k}")

    # V4. Knuth/LFSR permutation
    print("  V4: LFSR-based permutation...")
    def lfsr_perm(seed, poly, n):
        """Linear feedback shift register to generate permutation."""
        state = seed
        perm = []
        seen = set()
        for _ in range(n * 3):
            if state not in seen and state < n:
                seen.add(state)
                perm.append(state)
            if len(perm) == n: break
            # XOR shift
            lsb = state & 1
            state >>= 1
            if lsb:
                state ^= poly
        return perm if len(perm) == n and is_valid_perm(perm) else None

    # Primitive polynomials over GF(2) for various degrees
    for seed in [1, 2, 3, 5, 7]:
        for poly in [0x41, 0x61, 0x7B, 0x83, 0xA9]:
            p = lfsr_perm(seed, poly, N)
            if p: try_perm(p, f"V4_lfsr_s{seed}_p{poly:x}")

    print(f"  Approach V done. Tried={TRIED_COUNT}")

# ─────────────────────────────────────────────────────────────────────────────
def save_results():
    out_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "blitz_results", "numeric_permuter")
    os.makedirs(out_dir, exist_ok=True)
    summary = {
        "wave": 2,
        "total_tried": TRIED_COUNT,
        "crib_hits": len(RESULTS),
        "best_score": BEST_SCORE,
        "hits": RESULTS
    }
    with open(f"{out_dir}/results_wave2.json", "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n✓ Wave 2 results saved to {out_dir}/results_wave2.json")
    print(f"  Total permutations tried: {TRIED_COUNT}")
    print(f"  Crib hits: {len(RESULTS)}")
    print(f"  Best quadgram score: {BEST_SCORE:.2f}")

# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"K4 Numeric Permuter WAVE 2 — {N} chars, grille {len(GRILLE)} chars")
    print()

    approach_K()
    approach_L()
    approach_M()
    approach_N()
    approach_O()
    approach_P()
    approach_Q()
    approach_R()
    approach_S()
    approach_T()
    approach_U()
    approach_V()

    save_results()

    if RESULTS:
        print("\n" + "="*60)
        print("CRIB HITS FOUND:")
        for r in RESULTS:
            print(f"  label={r['label']}  ENE@{r['ene']} BC@{r['bc']}")
            print(f"  PT: {r['pt']}")
    else:
        print("\nNo crib hits. Best score:", BEST_SCORE)
