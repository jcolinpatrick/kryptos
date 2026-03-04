#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: grille
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
blitz_grille_geometry_v9.py — Constraint-Satisfying Columnar Search

KEY FINDING from v7/v8:
  - Column 31: 17 holes, Column 32: 10 holes → boundary artifacts?
  - "Real" grille may only use cols 0..30 (87 holes) or other subset
  - Physical overlay: 0 exact layouts → direct hole-to-K4-pos doesn't work
  - No simple geometric ordering satisfies forced constraints

NEW STRATEGY:
1. CONSTRAINED COLUMNAR SEARCH (exhaustive for small W):
   For each width W, find ALL column orderings where:
   - sigma[29]=64 is satisfied (for KRYPTOS/vig/AZ)
   - sigma[29]=69 AND sigma[71]=64 (for ABSCISSA/beau/KA)
   - sigma[21]=64 AND sigma[67]=69 (for MEDUSA/vig/AZ)
   Test ALL such columnar transpositions.

2. STRIPPED GRILLE (exclude cols 30-32):
   Use only 87 "inner" holes (cols 0..30) and try all approaches again.

3. KEYWORD COLUMNAR WITH GRILLE COLUMN COUNTS:
   Holes per col 0..29 gives a 30-element key for 30-wide columnar.
   Actually try cols 0..29 key ordering.

4. MIXED READING ORDER:
   Read grille holes left-to-right WITHIN each row, but ORDER rows
   by: hole count DESC, then hole count ASC, then row number.

5. PERIOD-7 CYCLE ANALYSIS:
   Since KRYPTOS has period 7, check if sigma could be built from
   period-7 structure. Enumerate all period-7 permutations of 97.

6. KEYWORD-DERIVED PERMUTATIONS (not columnar):
   For keyword KW of length L:
   sigma[k] = (some function of KW[k%L]) mod 97.
   Try: sigma[k] = KA.index(KW[k%L]) * 97/26 (scaled), etc.

7. TWO-LEVEL HIERARCHY:
   Top level: keyword defines which of 7 (or 8) groups each position goes to.
   Bottom level: within each group, grille defines order.
   Combined: gives 97-element permutation.

8. GE AS DIRECT PERMUTATION INDEX:
   GE has 106 chars. Each char gives an index 0..25.
   Map via: take GE chars, convert to 0..25, then use bijection
   from 25-char alphabet to 97-char space.
   (25-char, since T is missing from GE)
"""

import json, sys, os, itertools, math
from collections import defaultdict, Counter

sys.path.insert(0, 'src')

K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
GE = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KEYWORDS = ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW', 'SANBORN',
            'SCHEIDT', 'BERLIN', 'CLOCK', 'EAST', 'NORTH',
            'LIGHT', 'ANTIPODES', 'MEDUSA', 'ENIGMA']
CRIBS = [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]

QG = json.load(open('data/english_quadgrams.json'))

def score_pc(text):
    n = len(text) - 3
    return sum(QG.get(text[i:i+4], -10.0) for i in range(n)) / n if n > 0 else -10.0

def vig_dec(ct, key, alpha=AZ):
    ai = {c: i for i, c in enumerate(alpha)}
    return ''.join(alpha[(ai[ct[i]] - ai[key[i % len(key)]]) % 26] for i in range(len(ct)))

def beau_dec(ct, key, alpha=AZ):
    ai = {c: i for i, c in enumerate(alpha)}
    return ''.join(alpha[(ai[key[i % len(key)]] - ai[ct[i]]) % 26] for i in range(len(ct)))

RESULTS_DIR = "results/blitz_v9"
os.makedirs(RESULTS_DIR, exist_ok=True)

hits = []
best_score_seen = -10.0
tested = 0
K4_POS = defaultdict(list)
for i, c in enumerate(K4): K4_POS[c].append(i)

def test_perm(sigma, label):
    global tested, best_score_seen
    if len(sigma) != 97 or sorted(sigma) != list(range(97)):
        return None
    tested += 1
    real_ct = ''.join(K4[sigma[j]] for j in range(97))
    best_local = -10.0
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        for kw in KEYWORDS:
            for cname, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                pt = fn(real_ct, kw, alpha)
                sc = score_pc(pt)
                ene = pt.find("EASTNORTHEAST")
                bc  = pt.find("BERLINCLOCK")
                if ene >= 0 or bc >= 0:
                    print(f"\n{'!'*70}")
                    print(f"*** CRIB HIT: {label}")
                    print(f"    ENE@{ene}  BC@{bc}  score={sc:.4f}")
                    print(f"    PT: {pt}")
                    print(f"    Key:{kw} Cipher:{cname} Alpha:{alpha_name}")
                    print('!'*70)
                    hits.append({"label": label, "pt": pt, "ene": ene, "bc": bc,
                                 "score": sc, "key": kw})
                    return sc
                if sc > best_local:
                    best_local = sc
    if best_local > best_score_seen:
        best_score_seen = best_local
        print(f"  NEW BEST [{label}]: {best_local:.4f}/char")
    return best_local

# Mask
MASK_ROWS_RAW = [
    "000000001010100000000010000000001",   # row 0
    "100000000010000001000100110000011",   # row 1
    "000000000000001000000000000000011",   # row 2
    "00000000000000000000100000010011",    # row 3
    "00000001000000001000010000000011",    # row 4
    "000000001000000000000000000000011",   # row 5
    "100000000000000000000000000000011",   # row 6
    "00000000000000000000000100000100",    # row 7
    "0000000000000000000100000001000",     # row 8
    "0000000000000000000000000000100",     # row 9
    "000000001000000000000000000000",      # row 10
    "00000110000000000000000000000100",    # row 11
    "00000000000000100010000000000001",    # row 12
    "00000000000100000000000000001000",    # row 13
    "000110100001000000000000001000010",   # row 14
    "00001010000000000000000001000001",    # row 15
    "001001000010010000000000000100010",   # row 16
    "00000000000100000000010000010001",    # row 17
    "000000000000010001001000000010001",   # row 18
    "00000000000000001001000000000100",    # row 19
    "000000001100000010100100010001001",   # row 20
    "000000000000000100001010100100011",   # row 21
    "00000000100000000000100001100001",    # row 22
    "100000000000000000001000001000010",   # row 23
    "10000001000001000000100000000001",    # row 24
    "000010000000000000010000100000011",   # row 25
    "0000000000000000000100001000000011",  # row 26
    "00000000000000100000001010000001",    # row 27
]
NROWS = 28; NCOLS = 33
holes_all = [(r, c) for r, row in enumerate(MASK_ROWS_RAW)
             for c, ch in enumerate(row) if ch == '1' and c < 33]
holes_inner = [(r, c) for r, c in holes_all if c < 31]  # exclude cols 31-32
print(f"All holes (c<33): {len(holes_all)}, Inner holes (c<31): {len(holes_inner)}")

holes_per_col = [0]*33
for r, c in holes_all: holes_per_col[c] += 1
print(f"Holes per col: {holes_per_col}")

def columnar_sigma(n, col_order):
    """Generate sigma for columnar transposition with given column reading order."""
    W = len(col_order)
    nrows = (n + W - 1) // W
    sigma = []
    for col in col_order:
        for row in range(nrows):
            pos = row * W + col
            if pos < n:
                sigma.append(pos)
    return sigma

def compute_exp(kw, cipher, alpha):
    ai = {c: i for i, c in enumerate(alpha)}
    exp = {}
    for start, text in CRIBS:
        for j, ch in enumerate(text):
            pos = start + j
            ki = ai[kw[pos % len(kw)]]
            pi = ai[ch]
            exp[pos] = alpha[(pi + ki) % 26] if cipher == 'vig' else alpha[(ki - pi) % 26]
    return exp

# All forced constraints
all_forced = {}
for kw in KEYWORDS:
    for cipher in ['vig', 'beau']:
        for an, alpha in [('AZ', AZ), ('KA', KA)]:
            exp = compute_exp(kw, cipher, alpha)
            need = Counter(exp.values())
            if all(len(K4_POS.get(ch, [])) >= cnt for ch, cnt in need.items()):
                forced = {p: K4_POS[ch][0] for p, ch in exp.items() if len(K4_POS[ch]) == 1}
                if len(forced) >= 2:
                    all_forced[(kw, cipher, an)] = forced

print(f"\nFeasible combos with ≥2 forced: {list(all_forced.keys())}")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 1: CONSTRAINED COLUMNAR SEARCH (exhaustive small W)
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH 1: Constrained columnar search (find orderings satisfying forced)")
print("="*70)

def columnar_read_pos(n, W, col_order, write_pos):
    """What read position does write_pos end up at?"""
    row = write_pos // W
    col = write_pos % W
    col_rank = col_order.index(col) if col in col_order else -1
    if col_rank < 0: return -1
    # Count positions before this one in reading order
    nrows = (n + W - 1) // W
    # Positions read before current column's first element = sum of full cols before
    count_before = 0
    for i in range(col_rank):
        c = col_order[i]
        count_before += sum(1 for r2 in range(nrows) if r2 * W + c < n)
    count_before += row
    return count_before

# For each (kw, cipher, an) with 2+ forced, find columnar configs that satisfy all
for (kw, cipher, an), fc in all_forced.items():
    alpha = AZ if an == 'AZ' else KA
    print(f"\n  {kw}/{cipher}/{an}: forced {fc}")

    for W in range(7, 17):
        nrows = (97 + W - 1) // W
        # Find column orderings where all forced constraints are satisfied
        # For each forced (sigma_pos → k4_pos):
        #   write_pos = sigma_pos
        #   This write_pos must map to read_pos = sigma_pos
        #   Actually: sigma[write_pos] = k4_pos is what we need
        #   For columnar: sigma[write_pos] depends on when write_pos is read
        #   No: sigma[read_pos] = write_pos
        #   We need: sigma[fc_sigma_pos] = fc_k4_pos
        #   i.e., sigma[fc_sigma_pos] = fc_k4_pos
        #   The sigma function for columnar: sigma[read_pos] = write_pos
        #   So we need: fc_k4_pos to be READ at position fc_sigma_pos.
        #   fc_k4_pos = write position in the grid
        #   fc_k4_pos = row * W + col
        # Actually: sigma[k] maps read_pos k → write_pos = row*W+col.
        # We want sigma[fc_sigma_pos] = fc_k4_pos.
        # So write_pos = fc_k4_pos must be the fc_sigma_pos-th element read.
        # fc_k4_pos is at (fc_k4_pos // W, fc_k4_pos % W) in the grid.
        # The col_order determines when this cell is read.

        # For each forced pair (sigma_pos, k4_pos):
        # The column (k4_pos % W) must be at position KEY_RANK in col_order such that:
        # sum(nrows_before_col) + (k4_pos // W) = sigma_pos

        # Precompute for each forced pair: which column position in key satisfies it?
        required_col_ranks = {}
        feasible = True
        for sigma_pos, k4_pos in fc.items():
            write_row = k4_pos // W
            write_col = k4_pos % W
            if write_row >= nrows:
                feasible = False; break
            # Number of elements read in full columns before write_col = ?
            # Let key_rank be the rank of write_col in col_order (0..W-1)
            # elements_before = sum(count(r < nrows such that r*W+c' < 97) for c' at ranks < key_rank)
            # For simplicity (no partial last row): elements_before = key_rank * nrows
            # Then: elements_before + write_row = sigma_pos
            # key_rank = (sigma_pos - write_row) / nrows
            # This must be an integer in 0..W-1
            target_key_rank = sigma_pos - write_row
            if target_key_rank < 0 or target_key_rank % nrows != 0:
                feasible = False; break
            key_rank = target_key_rank // nrows
            if key_rank >= W:
                feasible = False; break
            required_col_ranks[write_col] = key_rank

        if not feasible:
            continue

        # Check if required_col_ranks is consistent (no two cols need same rank)
        if len(set(required_col_ranks.values())) != len(required_col_ranks):
            continue  # inconsistent

        # Build partial column ordering
        required_positions = {}  # rank → col
        for col, rank in required_col_ranks.items():
            required_positions[rank] = col

        # Check for conflicts
        if len(set(required_positions.values())) != len(required_positions):
            continue

        # Fill remaining positions with remaining columns
        fixed_cols = set(required_positions.values())
        free_cols = [c for c in range(W) if c not in fixed_cols]
        free_ranks = [r for r in range(W) if r not in required_positions]

        print(f"    W={W}: required_col_ranks={required_col_ranks}, "
              f"free_cols={len(free_cols)}, free_ranks={len(free_ranks)}")

        # Enumerate all permutations of free_cols into free_ranks
        if len(free_cols) <= 8:
            for perm in itertools.permutations(free_cols):
                col_order = [None] * W
                for rank, col in required_positions.items():
                    col_order[rank] = col
                for i, rank in enumerate(free_ranks):
                    col_order[rank] = perm[i]

                if None in col_order:
                    continue

                sigma = columnar_sigma(97, col_order)
                if len(sigma) == 97:
                    # Verify forced constraints
                    fc_ok = all(sigma[sp] == k4p for sp, k4p in fc.items()
                                if sp < len(sigma))
                    if fc_ok:
                        test_perm(sigma, f"1-{kw}-{cipher}-{an}-W{W}")
        else:
            print(f"    Too many free cols ({len(free_cols)}) to enumerate")

print(f"  [Approach 1 done, tested {tested}]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 2: INNER HOLES (cols 0..30) APPROACHES
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH 2: Inner holes (exclude cols 31-32)")
print("="*70)

inner = holes_inner  # 87 holes in cols 0..30
print(f"  Inner holes: {len(inner)}")

# Can we get 97 from 87? No. But maybe some other column cutoff works.
for max_col in range(28, 33):
    sub = [(r, c) for r, c in holes_all if c <= max_col]
    print(f"  cols 0..{max_col}: {len(sub)} holes")
    if len(sub) >= 97:
        lin = [(r * 33 + c) % 97 for r, c in sub[:97]]
        if len(set(lin)) == 97:
            test_perm(lin, f"2-cols0to{max_col}-first97-mod97")
        # Rank
        sigma = sorted(range(97), key=lambda k: sub[k][0]*33 + sub[k][1])
        test_perm(sigma, f"2-cols0to{max_col}-rank")
        inv = [0]*97
        for i,v in enumerate(sigma): inv[v] = i
        test_perm(inv, f"2-cols0to{max_col}-rank-inv")

print(f"  [Approach 2 done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 3: HOLES PER COL (NARROW RANGE) AS KEY
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH 3: Holes-per-col (various ranges) as transposition key")
print("="*70)

for col_start, col_end in [(0, 30), (0, 29), (0, 28), (0, 26), (2, 28), (0, 25)]:
    key = [holes_per_col[c] for c in range(col_start, col_end)]
    nonzero_key = [v for v in key if v > 0]
    W = len(nonzero_key)
    print(f"  cols {col_start}-{col_end-1}: W={W}, key={nonzero_key}")
    if 6 <= W <= 25:
        # Need to figure out which columns have holes to define the mapping
        nonzero_cols = [c for c in range(col_start, col_end) if holes_per_col[c] > 0]
        # Columnar: write K4 in W cols, read by sorted key order
        col_order = sorted(range(W), key=lambda i: (nonzero_key[i], i))
        sigma = columnar_sigma(97, col_order)
        if len(sigma) == 97:
            test_perm(sigma, f"3-cols{col_start}-{col_end}-hpc-asc")
        col_order_d = sorted(range(W), key=lambda i: (-nonzero_key[i], i))
        sigma_d = columnar_sigma(97, col_order_d)
        if len(sigma_d) == 97:
            test_perm(sigma_d, f"3-cols{col_start}-{col_end}-hpc-desc")

print(f"  [Approach 3 done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 4: ROW ORDERING BY HOLE COUNT
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH 4: Mixed reading order (rows ordered by hole count)")
print("="*70)

holes_per_row = [0] * NROWS
for r, c in holes_all: holes_per_row[r] += 1
print(f"  Holes per row: {holes_per_row}")

# Order rows by hole count, then read holes within each row left-to-right
for descending in [True, False]:
    row_order = sorted(range(NROWS), key=lambda r: (-holes_per_row[r] if descending else holes_per_row[r], r))

    ordered_holes = []
    for r in row_order:
        row_h = sorted([(rr, cc) for rr, cc in holes_all if rr == r], key=lambda x: x[1])
        ordered_holes.extend(row_h)

    lin = [(r * 33 + c) % 97 for r, c in ordered_holes[:97]]
    if len(set(lin)) == 97:
        test_perm(lin, f"4-row-{'desc' if descending else 'asc'}-mod97")

    # Rank
    sub97 = ordered_holes[:97]
    sigma = sorted(range(97), key=lambda k: sub97[k][0]*33 + sub97[k][1])
    test_perm(sigma, f"4-row-{'desc' if descending else 'asc'}-rank")

    # Also: dedup mod97
    seen = set(); dedup = []
    for r, c in ordered_holes:
        v = (r * 33 + c) % 97
        if v not in seen:
            seen.add(v); dedup.append(v)
        if len(dedup) == 97: break
    if len(dedup) == 97 and len(set(dedup)) == 97:
        test_perm(dedup, f"4-row-{'desc' if descending else 'asc'}-dedup")

print(f"  [Approach 4 done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 5: KEYWORD COLUMNAR WITH ACTUAL KEYWORD LETTERS
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH 5: Keyword-columnar using actual keyword letters")
print("="*70)

# Standard keyword-columnar: use keyword to define column order
# Alphabetical order of keyword letters → column reading order

def keyword_columnar(text_len, kw):
    W = len(kw)
    # Column i has key letter kw[i]
    # Read columns in alphabetical order of key letters (stable sort)
    col_order = sorted(range(W), key=lambda i: (kw[i], i))
    return columnar_sigma(text_len, col_order)

for kw in KEYWORDS:
    if len(kw) <= 15:
        sig = keyword_columnar(97, kw)
        if len(sig) == 97:
            test_perm(sig, f"5-kc-{kw}")
        # Also inverse
        inv = [0]*97
        for i,v in enumerate(sig): inv[v] = i
        test_perm(inv, f"5-kc-{kw}-inv")

# KRYPTOS repeated (period 7 but 13+ wide)
for repeat in [2, 3]:
    kw_rep = ("KRYPTOS" * repeat)[:14]
    sig = keyword_columnar(97, kw_rep)
    if len(sig) == 97:
        test_perm(sig, f"5-kc-KRYPTOS-x{repeat}")

print(f"  [Approach 5 done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 6: GE AS PERMUTATION SEED (various decodings)
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH 6: GE as permutation seed")
print("="*70)

# The GE is 106 chars from 25 letters (T absent).
# Map each GE char to AZ index (0..25), then scale/mod to 0..96.

ge_az = [AZ.index(c) for c in GE]
ge_ka = [KA.index(c) for c in GE]

# 6a: GE[k] * 4 mod 97 (scaling 25→97 approximately)
for alpha_name, ge_vals in [('AZ', ge_az), ('KA', ge_ka)]:
    for multiplier in [4, 97//25+1, 97//26+1, 3, 5, 6, 7]:
        vals = [(v * multiplier) % 97 for v in ge_vals[:97]]
        if len(set(vals)) == 97:
            test_perm(vals, f"6-GE-{alpha_name}-x{multiplier}")
        # Also with offset
        for offset in range(0, 5):
            vals2 = [(v * multiplier + offset) % 97 for v in ge_vals[:97]]
            if len(set(vals2)) == 97:
                test_perm(vals2, f"6-GE-{alpha_name}-x{multiplier}+{offset}")

# 6b: Cumulative GE product mod 97
for alpha_name, ge_vals in [('AZ', ge_az), ('KA', ge_ka)]:
    prod = 1
    seen6 = set(); dedup6 = []
    for v in ge_vals:
        prod = (prod * (v + 2)) % 97  # +2 to avoid 0
        if prod not in seen6:
            seen6.add(prod); dedup6.append(prod - 1 if prod > 0 else 96)
        if len(dedup6) == 97: break
    if len(dedup6) == 97 and len(set(dedup6)) == 97:
        test_perm(dedup6, f"6b-GE-{alpha_name}-cumprod")

# 6c: GE as base-26 digits, take mod 97
for chunk_size in [2, 3]:
    for alpha_name, ge_vals in [('AZ', ge_az), ('KA', ge_ka)]:
        seen6c = set(); dedup6c = []
        for i in range(0, len(ge_vals), chunk_size):
            chunk = ge_vals[i:i+chunk_size]
            v = sum(c * 26**j for j, c in enumerate(reversed(chunk))) % 97
            if v not in seen6c:
                seen6c.add(v); dedup6c.append(v)
            if len(dedup6c) == 97: break
        if len(dedup6c) == 97 and len(set(dedup6c)) == 97:
            test_perm(dedup6c, f"6c-GE-{alpha_name}-base26-chunk{chunk_size}")

print(f"  [Approach 6 done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 7: TWO-LEVEL HIERARCHY PERMUTATIONS
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH 7: Two-level hierarchy (keyword groups + grille order)")
print("="*70)

# Level 1: Keyword KRYPTOS (period 7) assigns each PT position to a group 0..6
# based on key_char_position = pos % 7 → which group
# Level 2: Within each group, grille defines the reading order

# Group assignments (0-indexed):
# Group g contains positions {g, g+7, g+14, ..., g+7*k, ...} ∩ [0..96]
# KRYPTOS: period 7
for period in [7, 8]:
    groups = defaultdict(list)
    for i in range(97):
        groups[i % period].append(i)

    # Grille order: use hole sequence to reorder each group
    # Within group g (size ~97//period ≈ 12-14), use first len(group) holes
    # from hole sequence starting at some offset
    for group_order in [list(range(period)), list(reversed(range(period)))]:
        sigma = [None] * 97
        hole_idx = 0
        read_pos = 0
        for g in group_order:
            grp = groups[g]
            # Use next len(grp) holes as reading order for this group
            grp_holes = holes_all[hole_idx:hole_idx + len(grp)]
            if len(grp_holes) < len(grp):
                break
            # Rank holes within this group's allocation
            sorted_grp_holes = sorted(grp_holes, key=lambda rc: rc[0]*33+rc[1])
            for k, pos in enumerate(grp):
                # sigma[read_pos] = pos → this says which K4 pos gets real_CT[read_pos]
                # Actually we want sigma[real_ct_pos] = k4_carved_pos
                # Let's define: sigma[grp[k]] = some K4 carved position
                pass
            hole_idx += len(grp)
            read_pos += len(grp)

        # Simpler: flatten groups in order, this gives a permutation of 0..96
        flat = []
        for g in group_order:
            flat.extend(groups[g])
        # flat is a permutation of 0..96
        if sorted(flat) == list(range(97)):
            test_perm(flat, f"7-group-p{period}-order{group_order[0]}")

        # Combined with grille reordering within groups
        flat2 = []
        for g in group_order:
            grp = groups[g]
            # Sort group members by their hole-sequence rank
            hole_linear_97 = [r * 33 + c for r, c in holes_all[:97]]
            grp_sorted = sorted(grp, key=lambda p: hole_linear_97[p] if p < 97 else 999)
            flat2.extend(grp_sorted)
        if sorted(flat2) == list(range(97)):
            test_perm(flat2, f"7-group-p{period}-holererank-order{group_order[0]}")

print(f"  [Approach 7 done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 8: KNIGHT'S TOUR / SPACE-FILLING ON HOLE GRID
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH 8: Novel geometric traversals of hole positions")
print("="*70)

# 8a: Concentric rectangular shells
# For the 28×33 grid, read holes in concentric shells (outer first)
def shells_order(nrows, ncols, holes_set):
    result = []
    top, bottom, left, right = 0, nrows-1, 0, ncols-1
    while top <= bottom and left <= right:
        for c in range(left, right+1):
            if (top, c) in holes_set: result.append((top, c))
        for r in range(top+1, bottom+1):
            if (r, right) in holes_set: result.append((r, right))
        if top < bottom:
            for c in range(right-1, left-1, -1):
                if (bottom, c) in holes_set: result.append((bottom, c))
        if left < right:
            for r in range(bottom-1, top, -1):
                if (r, left) in holes_set: result.append((r, left))
        top += 1; bottom -= 1; left += 1; right -= 1
    return result

holes_set = set(holes_all)
shell_order = shells_order(NROWS, NCOLS, holes_set)
print(f"  Shell order: {len(shell_order)} holes")

if len(shell_order) >= 97:
    lin8a = [(r*33+c) % 97 for r, c in shell_order[:97]]
    if len(set(lin8a)) == 97:
        test_perm(lin8a, "8a-shells-mod97")
    sigma8a = sorted(range(97), key=lambda k: shell_order[k][0]*33 + shell_order[k][1])
    test_perm(sigma8a, "8a-shells-rank")

# 8b: Zigzag (boustrophedon) column reading
bous_cols = []
for c in range(NCOLS):
    col_holes = sorted([(r, cc) for r, cc in holes_all if cc == c],
                       key=lambda x: x[0] if c % 2 == 0 else -x[0])
    bous_cols.extend(col_holes)
print(f"  Boustrophedon cols: {len(bous_cols)} holes")
if len(bous_cols) >= 97:
    lin8b = [(r*33+c) % 97 for r, c in bous_cols[:97]]
    if len(set(lin8b)) == 97:
        test_perm(lin8b, "8b-bous-col-mod97")
    sigma8b = sorted(range(97), key=lambda k: bous_cols[k][0]*33 + bous_cols[k][1])
    test_perm(sigma8b, "8b-bous-col-rank")

# 8c: Read holes by distance from a specific "center" point
center_r, center_c = NROWS//2, NCOLS//2
holes_by_dist = sorted(holes_all, key=lambda rc: (rc[0]-center_r)**2 + (rc[1]-center_c)**2)
lin8c = [(r*33+c) % 97 for r, c in holes_by_dist[:97]]
if len(set(lin8c)) == 97:
    test_perm(lin8c, "8c-from-center-mod97")
sigma8c = sorted(range(97), key=lambda k: holes_by_dist[k][0]*33+holes_by_dist[k][1])
test_perm(sigma8c, "8c-from-center-rank")

# 8d: Read holes from specific feature points (rows 5, 13, 21)
for focal_r in [5, 13, 21, 14, 6]:
    holes_by_focal = sorted(holes_all, key=lambda rc: (abs(rc[0]-focal_r), rc[1]))
    sigma8d = sorted(range(97), key=lambda k: holes_by_focal[k][0]*33+holes_by_focal[k][1])
    test_perm(sigma8d, f"8d-focal-row{focal_r}-rank")

print(f"  [Approach 8 done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 9: HOLE-BASED RUNNING KEY PERMUTATION
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH 9: Hole structure defines key for NEW sigma generation")
print("="*70)

# The grille's holes, read in order, give a sequence of (r, c) pairs.
# For each hole k, define val_k = r_k * 33 + c_k (linear position in 28×33 grid).
# The sequence {val_k mod 97} has collisions (not a permutation directly).
# BUT: we can use these values as a KEYSTREAM for a scramble:
# sigma_k = (val_k + k) mod 97 → might avoid collisions

for shift in range(0, 97):
    vals = [(hole_linear[k] + k * shift) % 97 for k in range(min(97, len(holes_all)))]
    if len(vals) == 97 and len(set(vals)) == 97:
        test_perm(vals, f"9-lin+k*{shift}")

# Also: val_k + previous val_{k-1} (running sum)
seen9 = set(); dedup9 = []; running = 0
for k, (r, c) in enumerate(holes_all):
    running = (running + r * 33 + c) % 97
    if running not in seen9:
        seen9.add(running); dedup9.append(running)
    if len(dedup9) == 97: break
if len(dedup9) == 97 and len(set(dedup9)) == 97:
    test_perm(dedup9, "9-running-sum")

print(f"  [Approach 9 done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 10: FOCUSED BRUTE FORCE ON SMALL PERMUTATION FAMILIES
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH 10: Brute force over small families with constraint filter")
print("="*70)

# Forced: sigma[29]=64 (KRYPTOS/vig/AZ)
# For width 9 columnar: col64=1, nrows=11, row64=7
# Need col1 to be read after 29-7=22 = 2*11 = 2 columns' worth → key_rank=2
# So col 1 must be at key_rank=2 in column ordering.
# Remaining 8 columns (0,2,3,4,5,6,7,8) in 8 positions (0,1,3,4,5,6,7,8)
# 8! = 40320 combinations

W = 9
nrows = (97 + W - 1) // W  # 11
col64 = 64 % W  # 64%9=1
row64 = 64 // W  # 64//9=7
# Need key_rank of col64 such that key_rank * nrows + row64 = 29
# key_rank * 11 + 7 = 29 → key_rank*11 = 22 → key_rank = 2
target_rank = (29 - row64)
if target_rank >= 0 and target_rank % nrows == 0:
    key_rank_needed = target_rank // nrows
    print(f"  W={W}: col{col64} must be at key_rank={key_rank_needed}")
    free_cols = [c for c in range(W) if c != col64]
    free_ranks = [r for r in range(W) if r != key_rank_needed]
    print(f"  Enumerating {math.factorial(len(free_cols))} orderings...")

    found_10 = 0
    for perm in itertools.permutations(free_cols):
        col_order = [None] * W
        col_order[key_rank_needed] = col64
        for i, rank in enumerate(free_ranks):
            col_order[rank] = perm[i]

        sigma = columnar_sigma(97, col_order)
        if len(sigma) == 97:
            # Verify sigma[29]=64
            if sigma[29] == 64:
                found_10 += 1
                test_perm(sigma, f"10-W9-col1at2")
                if found_10 <= 3:
                    print(f"    Found sigma[29]={sigma[29]} ✓, testing...")
    print(f"  Found {found_10} W=9 orderings with sigma[29]=64")

print(f"  [Approach 10 done, total tested={tested}]")

# ══════════════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("FINAL SUMMARY")
print("="*70)
print(f"Total permutations tested: {tested}")
print(f"Best score seen: {best_score_seen:.4f}/char")
print(f"Crib hits: {len(hits)}")
if hits:
    for h in hits:
        print(f"  *** HIT: {h['label']}, PT: {h['pt'][:50]}")
else:
    print("  No crib hits.")

import json as json2
with open(f"{RESULTS_DIR}/results.json", 'w') as f:
    json2.dump({"tested": tested, "best_score": best_score_seen, "hits": hits}, f, indent=2)
print(f"Results: {RESULTS_DIR}/results.json")
