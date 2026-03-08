#!/usr/bin/env python3
"""
Cipher: non-columnar transposition
Family: transposition/other
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
scripts/blitz_strip_route.py
K4 strip/route cipher unscrambling — comprehensive search

Approaches:
  Part 1: "8 Lines 73" (Sanborn yellow pad clue)
  Part 2: Extended columnar W11-20, keyword-derived only
  Part 3: EXHAUSTIVE columnar W11 + W12 (numpy + multiprocessing)
  Part 4: Double transposition (keyword pairs)
  Part 5: Rail fence depths 2-20 + combos
  Part 6: Myszkowski transposition
  Part 7: Disrupted columnar
  Part 8: AMSCO cipher
  Part 9: Extended columnar exhaustive W13 (optional, slow)
"""

import numpy as np
import json, os, sys, time
import multiprocessing as mp
from itertools import permutations
from collections import defaultdict
from numpy.lib.stride_tricks import sliding_window_view

sys.path.insert(0, 'src')
os.makedirs('blitz_results/strip_route', exist_ok=True)
RESULTS_DIR = 'blitz_results/strip_route'

# ─── CONSTANTS ────────────────────────────────────────────────────────────────
K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
GRILLE = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
N = 97
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
ENE = "EASTNORTHEAST"
BC  = "BERLINCLOCK"
KEYWORDS = ['KRYPTOS','PALIMPSEST','ABSCISSA','SHADOW','SANBORN','SCHEIDT',
            'BERLIN','CLOCK','EAST','NORTH','LIGHT','ANTIPODES','MEDUSA','ENIGMA']

ct_np  = np.array([ord(c)-65 for c in K4],  dtype=np.int32)
ene_np = np.array([ord(c)-65 for c in ENE], dtype=np.int32)
bc_np  = np.array([ord(c)-65 for c in BC],  dtype=np.int32)

# ─── QUADGRAMS ────────────────────────────────────────────────────────────────
QG = {}
for p in ['data/english_quadgrams.json']:
    if os.path.exists(p):
        with open(p) as f: QG = json.load(f)
        break
if not QG:
    print("WARNING: No quadgram file found — using 0.0 scores")

def qscore(t):
    return sum(QG.get(t[i:i+4], -10.0) for i in range(len(t)-3)) if QG else 0.0

# ─── DECODE CONFIGS ───────────────────────────────────────────────────────────
def build_configs():
    configs = []
    for kw in KEYWORDS:
        for aname, astr in [('AZ',AZ),('KA',KA)]:
            idx = {c:i for i,c in enumerate(astr)}
            kw_arr = np.array([idx[kw[i%len(kw)]] for i in range(N)], dtype=np.int32)
            configs.append((kw, aname, 'vig',  kw_arr))
            configs.append((kw, aname, 'beau', kw_arr))
    return configs

CONFIGS = build_configs()

# ─── REPORTING ────────────────────────────────────────────────────────────────
ALL_HITS = []
TOP = []  # (score, method, desc, kw, aname, cipher, pt)

def report_hit(method, desc, real_ct, pt, sc, ene_p, bc_p, kw, aname, cipher):
    msg = (f"\n{'='*65}\n*** CRIB HIT ***\n"
           f"Method: {method}\nDesc:   {desc}\n"
           f"KW/Alpha/Cipher: {kw}/{aname}/{cipher}\n"
           f"ENE@{ene_p}  BC@{bc_p}\n"
           f"RealCT: {real_ct}\n"
           f"PT:     {pt}\n"
           f"Score:  {sc:.2f}\n")
    print(msg, flush=True)
    ALL_HITS.append(msg)
    with open(f'{RESULTS_DIR}/HITS.txt', 'a') as f:
        f.write(msg)

def update_top(sc, method, desc, kw, aname, cipher, pt):
    TOP.append((sc, method, desc, kw, aname, cipher, pt))
    TOP.sort(reverse=True)
    if len(TOP) > 300: del TOP[300:]

def test_candidate(method, desc, real_ct_str):
    """Test a real-CT string against all configs. Print and return True on crib hit."""
    found = False
    for kw, aname, cipher, kw_arr in CONFIGS:
        astr = AZ if aname=='AZ' else KA
        ct_ints = np.array([ord(c)-65 for c in real_ct_str], dtype=np.int32)
        if cipher == 'vig':
            pt_ints = (ct_ints - kw_arr) % 26
        else:
            pt_ints = (kw_arr - ct_ints) % 26
        pt = ''.join(chr(v+65) for v in pt_ints)
        ene_p = pt.find(ENE)
        bc_p  = pt.find(BC)
        sc = qscore(pt)
        if ene_p >= 0 or bc_p >= 0:
            report_hit(method, desc, real_ct_str, pt, sc, ene_p, bc_p, kw, aname, cipher)
            found = True
        update_top(sc, method, desc, kw, aname, cipher, pt)
    return found

# ─── COLUMNAR HELPERS ─────────────────────────────────────────────────────────
def kw_col_order(kw):
    """Standard keyword → column-read-order (alphabetical, left-first tiebreak)."""
    return sorted(range(len(kw)), key=lambda i: (kw[i], i))

def columnar_unscramble(ct_str, col_order):
    """
    Inverse columnar transposition (Convention 1: short cols = rightmost natural cols).
    col_order[i] = natural column index that is read i-th during encryption.
    Applies to unscramble carved_text → real_CT.
    """
    W = len(col_order)
    n = len(ct_str)
    R     = (n + W - 1) // W
    extra = n % W
    if extra == 0: extra = W
    col_len = [R if c < extra else R-1 for c in range(W)]

    cols = {}
    offset = 0
    for c in col_order:
        cols[c] = ct_str[offset : offset + col_len[c]]
        offset += col_len[c]

    result = []
    for r in range(R):
        for c in range(W):
            if r < col_len[c]:
                result.append(cols[c][r])
    return ''.join(result)

def columnar_unscramble_conv2(ct_str, col_order):
    """
    Convention 2: short cols = last key-positions (i.e., the last col_order entries get
    one fewer character). More natural for hand-done transposition.
    """
    W = len(col_order)
    n = len(ct_str)
    R     = (n + W - 1) // W
    extra = n % W
    if extra == 0: extra = W
    # Long columns: first `extra` in KEY order
    col_len_key = [R if i < extra else R-1 for i in range(W)]
    # Map natural col → length
    col_len = {}
    for i, c in enumerate(col_order):
        col_len[c] = col_len_key[i]

    cols = {}
    offset = 0
    for i, c in enumerate(col_order):
        L = col_len_key[i]
        cols[c] = ct_str[offset : offset + L]
        offset += L

    result = []
    for r in range(R):
        for c in range(W):
            if r < col_len[c]:
                result.append(cols[c][r])
    return ''.join(result)

# ─── NUMPY BATCH COLUMNAR CHECK ───────────────────────────────────────────────
def batch_columnar_check(col_orders_list, W, configs=None, convention=1):
    """
    Test a batch of column orderings via numpy.
    Returns list of hit dicts (only crib hits).
    """
    if not col_orders_list:
        return []
    if configs is None:
        configs = CONFIGS

    B = len(col_orders_list)
    R     = (N + W - 1) // W
    extra = N % W
    if extra == 0: extra = W

    col_orders_arr = np.array(col_orders_list, dtype=np.int32)  # (B, W)

    if convention == 1:
        # Short cols = rightmost natural columns
        col_len_nat = np.array([R if c < extra else R-1 for c in range(W)], dtype=np.int32)
        ordered_lengths = col_len_nat[col_orders_arr]  # (B, W): lengths in key order
    else:
        # Short cols = last key-positions
        col_len_key = np.array([R if i < extra else R-1 for i in range(W)], dtype=np.int32)
        ordered_lengths = np.tile(col_len_key, (B, 1))  # (B, W): same for all

    # Cumulative start positions of each key-order slot in carved text
    starts_in_carved = np.zeros((B, W), dtype=np.int32)
    if W > 1:
        starts_in_carved[:, 1:] = np.cumsum(ordered_lengths[:, :-1], axis=1)

    # For each natural column c, find its key-position (rank)
    rank = np.argsort(col_orders_arr, axis=1)  # (B, W)

    # Start-in-carved for natural column c = starts_in_carved[b, rank[b,c]]
    start_natural = np.take_along_axis(starts_in_carved, rank, axis=1)  # (B, W)

    # Build full permutation: perm[b, pos] = where in carved text does real_CT[pos] come from
    col_of_pos = np.arange(N, dtype=np.int32) % W   # (N,)
    row_of_pos = np.arange(N, dtype=np.int32) // W  # (N,)
    perm = start_natural[:, col_of_pos] + row_of_pos  # (B, N)

    # Clip to valid range (safety)
    perm = np.clip(perm, 0, N-1)

    # Unscramble: real_CT[b, pos] = carved_CT[perm[b, pos]]
    unscrambled = ct_np[perm]  # (B, N)

    hits = []
    for kw, aname, cipher, kw_arr in configs:
        if cipher == 'vig':
            pt = (unscrambled - kw_arr) % 26  # (B, N)
        else:
            pt = (kw_arr - unscrambled) % 26

        # ENE crib check using sliding windows
        windows_ene = sliding_window_view(pt, len(ENE), axis=1)  # (B, N-12, 13)
        match_ene = np.all(windows_ene == ene_np, axis=2)        # (B, N-12)
        rows_e, cols_e = np.where(match_ene)
        for b, j in zip(rows_e, cols_e):
            pt_str = ''.join(chr(c+65) for c in pt[b])
            hits.append({'W': W, 'col_order': tuple(col_orders_list[b]),
                         'kw': kw, 'alpha': aname, 'cipher': cipher,
                         'crib': 'ENE', 'pos': int(j), 'pt': pt_str,
                         'conv': convention})

        # BC crib check
        windows_bc = sliding_window_view(pt, len(BC), axis=1)  # (B, N-10, 11)
        match_bc = np.all(windows_bc == bc_np, axis=2)
        rows_b, cols_b = np.where(match_bc)
        for b, j in zip(rows_b, cols_b):
            pt_str = ''.join(chr(c+65) for c in pt[b])
            hits.append({'W': W, 'col_order': tuple(col_orders_list[b]),
                         'kw': kw, 'alpha': aname, 'cipher': cipher,
                         'crib': 'BC', 'pos': int(j), 'pt': pt_str,
                         'conv': convention})

    return hits

# ─── WORKER FOR EXHAUSTIVE SEARCH ─────────────────────────────────────────────
def _worker_exhaustive(args):
    """Subprocess worker: test all permutations sharing the given prefix."""
    W, prefix_tuple, batch_size = args
    configs = build_configs()

    prefix_list = list(prefix_tuple)
    remaining   = [c for c in range(W) if c not in prefix_list]

    all_hits = []
    batch    = []
    count    = 0

    for rest in permutations(remaining):
        batch.append(prefix_list + list(rest))
        count += 1
        if len(batch) >= batch_size:
            # Test both conventions
            for conv in [1, 2]:
                h = batch_columnar_check(batch, W, configs, convention=conv)
                all_hits.extend(h)
            if any(all_hits):
                print(f"  [W{W} pfx={prefix_tuple}] {len(all_hits)} hits so far!", flush=True)
            batch = []

    if batch:
        for conv in [1, 2]:
            h = batch_columnar_check(batch, W, configs, convention=conv)
            all_hits.extend(h)

    return all_hits, count

def exhaustive_columnar(W, batch_size=4000):
    """Exhaustive columnar search over all W! permutations (both conventions)."""
    total_perms = 1
    for i in range(1, W+1): total_perms *= i

    print(f"\n=== Exhaustive W{W}: {total_perms:,} perms × 2 conventions === ", flush=True)
    t0 = time.time()

    # Split by first 2 elements to get many independent tasks
    prefixes = [(i, j) for i in range(W) for j in range(W) if i != j]
    args = [(W, p, batch_size) for p in prefixes]

    n_cores = min(mp.cpu_count(), len(prefixes))
    print(f"  Dispatching {len(prefixes)} tasks to {n_cores} cores ...", flush=True)

    with mp.Pool(n_cores) as pool:
        results = pool.map(_worker_exhaustive, args)

    all_hits = []
    total = 0
    for hits, cnt in results:
        all_hits.extend(hits)
        total += cnt

    elapsed = time.time() - t0
    rate = total / max(elapsed, 0.001)
    print(f"  W{W}: {total:,} perms in {elapsed:.1f}s ({rate:,.0f}/s) | {len(all_hits)} hits",
          flush=True)

    for h in all_hits:
        sc  = qscore(h['pt'])
        ep  = h['pt'].find(ENE)
        bp  = h['pt'].find(BC)
        # Reconstruct real_CT string from col_order + convention
        co = list(h['col_order'])
        if h['conv'] == 1:
            real_ct = columnar_unscramble(K4, co)
        else:
            real_ct = columnar_unscramble_conv2(K4, co)
        report_hit(f"ExhaustiveW{W}/conv{h['conv']}",
                   f"col_order={h['col_order']}",
                   real_ct, h['pt'], sc, ep, bp,
                   h['kw'], h['alpha'], h['cipher'])
    return all_hits

# ─── RAIL FENCE ───────────────────────────────────────────────────────────────
def rail_fence_decrypt(ct_str, depth):
    """Undo rail fence cipher."""
    n = len(ct_str)
    rails = [[] for _ in range(depth)]
    d, r = 1, 0
    for pos in range(n):
        rails[r].append(pos)
        if r == 0: d = 1
        elif r == depth-1: d = -1
        r += d
    result = [''] * n
    ct_idx = 0
    for rail in rails:
        for pos in rail:
            result[pos] = ct_str[ct_idx]
            ct_idx += 1
    return ''.join(result)

# ─── MYSZKOWSKI ───────────────────────────────────────────────────────────────
def myszkowski_decrypt(ct_str, kw):
    """Myszkowski transposition decrypt."""
    W = len(kw)
    n = len(ct_str)
    R     = (n + W - 1) // W
    extra = n % W
    if extra == 0: extra = W
    col_len = [R if c < extra else R-1 for c in range(W)]

    unique_letters = sorted(set(kw))
    grid = [[None]*W for _ in range(R)]
    ct_idx = 0
    for letter in unique_letters:
        col_group = [i for i, c in enumerate(kw) if c == letter]
        for r in range(R):
            for c in col_group:
                if r < col_len[c]:
                    grid[r][c] = ct_str[ct_idx]
                    ct_idx += 1

    result = []
    for r in range(R):
        for c in range(W):
            if r < col_len[c]:
                result.append(grid[r][c])
    return ''.join(result)

# ─── AMSCO ────────────────────────────────────────────────────────────────────
def amsco_decrypt(ct_str, kw):
    """AMSCO alternating transposition cipher decrypt."""
    W = len(kw)
    n = len(ct_str)

    # Build grid: cells at (row, col) alternately hold 1 or 2 chars
    cells = []  # (row, col, size, start_in_pt)
    r, c, total = 0, 0, 0
    while total < n:
        size = 1 if (r + c) % 2 == 0 else 2
        if total + size > n:
            size = n - total
        if size > 0:
            cells.append((r, c, size, total))
            total += size
        c += 1
        if c >= W:
            c = 0
            r += 1

    col_order = sorted(range(W), key=lambda i: (kw[i], i))

    col_cells = defaultdict(list)
    for (row, col, size, start) in cells:
        col_cells[col].append((row, size, start))
    for c2 in col_cells:
        col_cells[c2].sort()

    cell_chars = {}
    ct_idx = 0
    for c2 in col_order:
        for (row, size, start) in col_cells.get(c2, []):
            cell_chars[(row, c2)] = ct_str[ct_idx:ct_idx+size]
            ct_idx += size

    result = [''] * n
    for (row, col, size, start) in cells:
        chars = cell_chars.get((row, col), '')
        for k, ch in enumerate(chars):
            if start + k < n:
                result[start + k] = ch
    return ''.join(result)

# ─── PART 1: "8 LINES 73" ─────────────────────────────────────────────────────
def part1_eight_lines():
    print("\n=== PART 1: '8 Lines 73' (Sanborn yellow pad) ===", flush=True)
    n_tested = 0
    seen = set()

    def try_real_ct(method, desc, real_ct):
        nonlocal n_tested
        key = real_ct
        if key in seen: return
        seen.add(key)
        test_candidate(method, desc, real_ct)
        n_tested += 1

    # A: Simple rotations / splits (73 and its complement 24)
    for split in [73, 24, 8, 13, 48, 49, 12]:
        try_real_ct("8Lines/rotate", f"rotate{split}", K4[split:]+K4[:split])

    # B: Swap halves / sections
    try_real_ct("8Lines/reverse", "reverse", K4[::-1])
    try_real_ct("8Lines/even_odd", "even+odd", K4[::2]+K4[1::2])
    try_real_ct("8Lines/odd_even", "odd+even", K4[1::2]+K4[::2])

    # C: Width 12 and 13 columnar (8 rows × 12 ≈ 97)
    for W in [12, 13, 11]:
        for kw in KEYWORDS:
            if len(kw) == W:
                co = kw_col_order(kw)
                try_real_ct(f"8Lines/col{W}", f"kw={kw}", columnar_unscramble(K4, co))
                try_real_ct(f"8Lines/col{W}C2", f"kw={kw}C2", columnar_unscramble_conv2(K4, co))

        # Grille-derived
        if W <= len(GRILLE):
            co = kw_col_order(GRILLE[:W])
            try_real_ct(f"8Lines/grilleW{W}", f"grille[:{W}]", columnar_unscramble(K4, co))
            co = kw_col_order(GRILLE[:W][::-1])
            try_real_ct(f"8Lines/grilleW{W}rev", f"grille_rev[:{W}]", columnar_unscramble(K4, co))

        # BERLINCLOCK (11) + extension to reach W=12
        if W == 12:
            for ext in AZ:
                kw2 = BC + ext
                co = kw_col_order(kw2)
                try_real_ct(f"8Lines/BC+{ext}", kw2, columnar_unscramble(K4, co))

        # KRYPTOS + suffix to reach W
        if W > 7:
            suffix_len = W - 7
            # Use AZ letters not in KRYPTOS: ABCDEFHIJLMNQUVWXZ...
            avail = [c for c in AZ if c not in 'KRYPTOS']
            if suffix_len <= len(avail):
                kw2 = 'KRYPTOS' + ''.join(avail[:suffix_len])
                co = kw_col_order(kw2)
                try_real_ct(f"8Lines/KRY+{suffix_len}", kw2, columnar_unscramble(K4, co))

    # D: Try cribs as keywords (if right length)
    for crib in [ENE, BC]:
        for W in range(8, 16):
            if len(crib) >= W:
                kw2 = crib[:W]
                co = kw_col_order(kw2)
                try_real_ct(f"8Lines/crib{W}", kw2, columnar_unscramble(K4, co))

    # E: "73" = column width 73? (very wide, just 1 row — identity)
    # Or: "8 Lines" means 8-rail rail fence (already in part 5, but try here)
    for depth in [8, 7, 9]:
        try_real_ct(f"8Lines/railfence{depth}", f"rf_depth={depth}", rail_fence_decrypt(K4, depth))

    print(f"  8Lines: {n_tested} tested", flush=True)

# ─── PART 2: EXTENDED COLUMNAR W11-20 ─────────────────────────────────────────
def part2_extended_columnar():
    print("\n=== PART 2: Extended Columnar W11-20 (keyword-derived) ===", flush=True)
    n_tested = 0
    seen = set()

    def try_co(method, desc, co, conv=1):
        nonlocal n_tested
        key = (tuple(co), conv)
        if key in seen: return
        seen.add(key)
        if conv == 1:
            real_ct = columnar_unscramble(K4, co)
        else:
            real_ct = columnar_unscramble_conv2(K4, co)
        test_candidate(method, desc, real_ct)
        n_tested += 1

    for W in range(11, 21):
        # Standard keywords (exact length match)
        for kw in KEYWORDS:
            if len(kw) == W:
                co = kw_col_order(kw)
                try_co(f"ColW{W}", f"kw={kw}", co, 1)
                try_co(f"ColW{W}C2", f"kw={kw}C2", co, 2)

        # Grille prefix (both conventions)
        if W <= len(GRILLE):
            co = kw_col_order(GRILLE[:W])
            try_co(f"ColW{W}", f"grille[:{W}]", co, 1)
            try_co(f"ColW{W}", f"grille[:{W}]", co, 2)

            co = kw_col_order(GRILLE[:W][::-1])
            try_co(f"ColW{W}", f"grilleRev[:{W}]", co, 1)

        # Crib prefixes
        for crib in [ENE, BC]:
            if len(crib) >= W:
                co = kw_col_order(crib[:W])
                try_co(f"ColW{W}", f"crib{crib[:W]}", co, 1)

        # Natural and reverse orders
        try_co(f"ColW{W}", "natural", list(range(W)), 1)
        try_co(f"ColW{W}", "reverse", list(range(W-1,-1,-1)), 1)

        # Even-cols-first, odd-cols-first
        evens = list(range(0,W,2)) + list(range(1,W,2))
        odds  = list(range(1,W,2)) + list(range(0,W,2))
        try_co(f"ColW{W}", "even_odd", evens, 1)
        try_co(f"ColW{W}", "odd_even", odds, 1)

        # KA-alphabet rank for each position 0..W-1
        KA_IDX = {c: i for i, c in enumerate(KA)}
        # Map K4 chars at positions 0..W-1 to their KA rank, sort
        k4_slice = K4[:W]
        co_k4 = sorted(range(W), key=lambda i: (KA_IDX[k4_slice[i]], i))
        try_co(f"ColW{W}", f"K4slice_KA", co_k4, 1)

    print(f"  Extended columnar: {n_tested} tested", flush=True)

# ─── PART 3: EXHAUSTIVE W11 + W12 ─────────────────────────────────────────────
def part3_exhaustive():
    # W=11: 11! = 39.9M × 2 conventions
    hits11 = exhaustive_columnar(11, batch_size=4000)
    if hits11:
        print(f"\n  *** W11 HITS: {len(hits11)} ***", flush=True)
        for h in hits11:
            print(f"    {h}", flush=True)

    # W=12: 12! = 479M × 2 conventions  (~10-15 min on all cores)
    hits12 = exhaustive_columnar(12, batch_size=4000)
    if hits12:
        print(f"\n  *** W12 HITS: {len(hits12)} ***", flush=True)
        for h in hits12:
            print(f"    {h}", flush=True)

# ─── PART 4: DOUBLE TRANSPOSITION ─────────────────────────────────────────────
def part4_double_trans():
    print("\n=== PART 4: Double Transposition ===", flush=True)
    n_tested = 0
    seen = set()

    # Build a list of keywords to try (include grille prefixes)
    kw_list = list(KEYWORDS)
    for L in range(7, 15):
        if L <= len(GRILLE):
            kw_list.append(GRILLE[:L])

    for kw1 in kw_list:
        for kw2 in kw_list:
            for conv1 in [1, 2]:
                for conv2 in [1, 2]:
                    co1 = kw_col_order(kw1)
                    co2 = kw_col_order(kw2)
                    key = (tuple(co1), conv1, tuple(co2), conv2)
                    if key in seen: continue
                    seen.add(key)

                    if conv1 == 1:
                        ct1 = columnar_unscramble(K4, co1)
                    else:
                        ct1 = columnar_unscramble_conv2(K4, co1)

                    if conv2 == 1:
                        real_ct = columnar_unscramble(ct1, co2)
                    else:
                        real_ct = columnar_unscramble_conv2(ct1, co2)

                    test_candidate(f"DblTrans/C{conv1}C{conv2}",
                                   f"{kw1}+{kw2}", real_ct)
                    n_tested += 1

    print(f"  Double transposition: {n_tested} tested", flush=True)

# ─── PART 5: RAIL FENCE ────────────────────────────────────────────────────────
def part5_rail_fence():
    print("\n=== PART 5: Rail Fence ===", flush=True)
    n_tested = 0
    seen = set()

    for depth in range(2, 25):
        real_ct = rail_fence_decrypt(K4, depth)
        if real_ct not in seen:
            seen.add(real_ct)
            test_candidate(f"RailFence/d{depth}", f"depth={depth}", real_ct)
            n_tested += 1

        # Rail fence + columnar
        for kw in ['KRYPTOS','ABSCISSA','BERLINCLOCK','PALIMPSEST','SHADOW']:
            co = kw_col_order(kw)
            for conv in [1, 2]:
                ct1 = rail_fence_decrypt(K4, depth)
                if conv == 1:
                    real_ct2 = columnar_unscramble(ct1, co)
                else:
                    real_ct2 = columnar_unscramble_conv2(ct1, co)
                if real_ct2 not in seen:
                    seen.add(real_ct2)
                    test_candidate(f"RF+Col/d{depth}C{conv}",
                                   f"d={depth}+{kw}", real_ct2)
                    n_tested += 1

        # Columnar + rail fence
        for kw in ['KRYPTOS','ABSCISSA']:
            co = kw_col_order(kw)
            ct1 = columnar_unscramble(K4, co)
            real_ct2 = rail_fence_decrypt(ct1, depth)
            if real_ct2 not in seen:
                seen.add(real_ct2)
                test_candidate(f"Col+RF/d{depth}",
                               f"{kw}+d={depth}", real_ct2)
                n_tested += 1

    print(f"  Rail fence: {n_tested} tested", flush=True)

# ─── PART 6: MYSZKOWSKI ────────────────────────────────────────────────────────
def part6_myszkowski():
    print("\n=== PART 6: Myszkowski Transposition ===", flush=True)
    n_tested = 0

    mys_kws = [
        'PALIMPSEST',       # P(×2), S(×2)
        'ABSCISSA',         # A(×3), S(×2)
        'BERLINCLOCK',      # C(×2), L(×2)
        'EASTNORTHEAST',    # E(×3), T(×3), A(×2), S(×2)
        'KRYPTOSKRYPTOS',   # KRYPTOS repeated
        'ABCABC',
        'KRYPTOSABSCISSA',
        'AABBCCDD',
        'ABABABAB',
        'KRYPTOS' + 'KRYPTOS',
        # Use grille extract (has letter repeats)
        GRILLE[:10],
        GRILLE[:14],
    ]

    for kw in mys_kws:
        if any(kw.count(c) > 1 for c in set(kw)):  # must have repeats
            real_ct = myszkowski_decrypt(K4, kw)
            if len(real_ct) == N:
                test_candidate("Myszkowski", kw, real_ct)
                n_tested += 1

    print(f"  Myszkowski: {n_tested} tested", flush=True)

# ─── PART 7: DISRUPTED COLUMNAR ───────────────────────────────────────────────
def part7_disrupted():
    print("\n=== PART 7: Disrupted Columnar ===", flush=True)
    n_tested = 0

    for kw in ['KRYPTOS','ABSCISSA','BERLINCLOCK','PALIMPSEST','SHADOW']:
        W = len(kw)
        co = kw_col_order(kw)
        R_full = (N + W - 1) // W
        extra  = N % W
        if extra == 0: extra = W

        # Default col lengths
        col_len_default = [R_full if c < extra else R_full-1 for c in range(W)]

        # Try moving one unit of length between columns
        for src_col in range(W):
            for dst_col in range(W):
                if src_col == dst_col: continue
                if col_len_default[src_col] <= 1: continue
                col_len_mod = list(col_len_default)
                col_len_mod[src_col] -= 1
                col_len_mod[dst_col] += 1
                if sum(col_len_mod) != N: continue

                # Assign chunks
                cols = {}
                offset = 0
                for c in co:
                    cols[c] = K4[offset:offset+col_len_mod[c]]
                    offset += col_len_mod[c]

                result = []
                for r in range(R_full + 1):
                    for c in range(W):
                        if r < col_len_mod[c]:
                            result.append(cols[c][r])
                real_ct = ''.join(result)
                if len(real_ct) == N:
                    test_candidate(f"Disrupted/{kw}",
                                   f"src={src_col}→dst={dst_col}", real_ct)
                    n_tested += 1

    print(f"  Disrupted: {n_tested} tested", flush=True)

# ─── PART 8: AMSCO ────────────────────────────────────────────────────────────
def part8_amsco():
    print("\n=== PART 8: AMSCO Cipher ===", flush=True)
    n_tested = 0
    tested_kws = KEYWORDS + [GRILLE[:7], GRILLE[:8], GRILLE[:9],
                              GRILLE[:10], GRILLE[:11], GRILLE[:12]]
    for kw in tested_kws:
        try:
            real_ct = amsco_decrypt(K4, kw)
            if len(real_ct) == N:
                test_candidate("AMSCO", kw, real_ct)
                n_tested += 1
        except Exception as e:
            pass
    print(f"  AMSCO: {n_tested} tested", flush=True)

# ─── SAVE RESULTS ─────────────────────────────────────────────────────────────
def save_results():
    with open(f'{RESULTS_DIR}/top_results.txt', 'w') as f:
        f.write(f"Top {min(len(TOP), 100)} results by quadgram score\n{'='*65}\n")
        for i, (sc, method, desc, kw, aname, cipher, pt) in enumerate(TOP[:100]):
            f.write(f"{i+1:3d}. Score={sc:8.2f}  {method:<30} {desc}\n"
                    f"      KW={kw}/{aname}/{cipher}\n"
                    f"      PT: {pt}\n\n")
    print(f"  Saved top {min(len(TOP), 100)} results to {RESULTS_DIR}/top_results.txt")

# ─── MAIN ─────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print(f"K4 Strip/Route Unscrambling | N={N} | CPUs={mp.cpu_count()}")
    print(f"K4:     {K4}")
    print(f"GRILLE: {GRILLE[:40]}...")
    print(f"Configs: {len(CONFIGS)} (keyword×alpha×cipher combos)")
    print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    t_start = time.time()

    # ── Fast targeted tests ──────────────────────────────────────────────────
    part1_eight_lines()
    save_results()

    part2_extended_columnar()
    save_results()

    part4_double_trans()
    save_results()

    part5_rail_fence()
    save_results()

    part6_myszkowski()
    part7_disrupted()
    part8_amsco()
    save_results()

    # ── Exhaustive search (main computation) ─────────────────────────────────
    part3_exhaustive()
    save_results()

    # ── Final summary ────────────────────────────────────────────────────────
    elapsed = time.time() - t_start
    print(f"\n{'='*65}")
    print(f"DONE — Total time: {elapsed:.1f}s")
    print(f"Total crib hits: {len(ALL_HITS)}")

    if ALL_HITS:
        print("\n*** ALL HITS ***")
        for h in ALL_HITS:
            print(h)
    else:
        print("No crib hits found in any search.")
        if TOP:
            best = TOP[0]
            print(f"Best quadgram score: {best[0]:.2f}")
            print(f"  Method: {best[1]}  Desc: {best[2]}")
            print(f"  KW: {best[3]}/{best[4]}/{best[5]}")
            print(f"  PT: {best[6]}")
