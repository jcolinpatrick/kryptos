#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: blitz
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
BLITZ: Numeric Permuter — derives 97-char permutations from the Cardan grille extract.

Approaches:
  A. KA-index arithmetic (cumsum, rundiff, pairs, triples, etc.)
  B. Rank-order with tie-breaking variations
  C. Base-26 factorial / Lehmer code
  D. Character frequency ranking
  E. Pattern matching / occurrence mapping
  F. Modular chain walks
  G. Extract as columnar transposition key

Each valid permutation is tested against K4 with Vig/Beau × AZ/KA × all keywords.
A crib hit (EASTNORTHEAST or BERLINCLOCK anywhere in PT) is immediately reported.
"""

import json, sys, os, itertools, random, math
from collections import defaultdict

# ── constants ────────────────────────────────────────────────────────────────
K4     = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
GRILLE = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
AZ     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA     = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KEYWORDS = ['KRYPTOS','PALIMPSEST','ABSCISSA','SHADOW','SANBORN','SCHEIDT',
            'BERLIN','CLOCK','EAST','NORTH','LIGHT','ANTIPODES','MEDUSA','ENIGMA']
N = 97
assert len(K4) == N
assert len(GRILLE) == 106

# ── pre-compute index maps ───────────────────────────────────────────────────
AZ_IDX = {c: i for i, c in enumerate(AZ)}
KA_IDX = {c: i for i, c in enumerate(KA)}

GRILLE_AZ  = [AZ_IDX[c] for c in GRILLE]   # 0-25
GRILLE_KA  = [KA_IDX[c] for c in GRILLE]   # 0-25
K4_AZ      = [AZ_IDX[c] for c in K4]
K4_KA      = [KA_IDX[c] for c in K4]

# ── load quadgrams ───────────────────────────────────────────────────────────
QG_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'english_quadgrams.json')
with open(QG_PATH) as f:
    qg = json.load(f)

def qgscore(text):
    return sum(qg.get(text[i:i+4], -10.0) for i in range(len(text)-3))

# ── cipher helpers ───────────────────────────────────────────────────────────
def vig_dec(ct, key, alpha=AZ):
    n = len(alpha)
    idx = {c: i for i, c in enumerate(alpha)}
    return ''.join(alpha[(idx[ct[i]] - idx[key[i % len(key)]]) % n] for i in range(len(ct)))

def beau_dec(ct, key, alpha=AZ):
    n = len(alpha)
    idx = {c: i for i, c in enumerate(alpha)}
    return ''.join(alpha[(idx[key[i % len(key)]] - idx[ct[i]]) % n] for i in range(len(ct)))

# ── permutation validator ────────────────────────────────────────────────────
def is_valid_perm(p, n=N):
    """Check that p is a permutation of 0..n-1"""
    if len(p) != n: return False
    return sorted(p) == list(range(n))

def apply_perm(text, perm):
    return ''.join(text[p] for p in perm)

# ── result store ─────────────────────────────────────────────────────────────
RESULTS = []
BEST_SCORE = -9999
TRIED = set()

def try_perm(perm, label):
    global BEST_SCORE
    key = tuple(perm)
    if key in TRIED:
        return
    TRIED.add(key)
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

# ── helpers for permutation generation ──────────────────────────────────────
def values_to_perm(vals):
    """Convert a list of N values to a rank-based permutation."""
    indexed = sorted(range(N), key=lambda i: vals[i])
    perm = [0]*N
    for rank, idx in enumerate(indexed):
        perm[idx] = rank
    return perm

def lehmer_to_perm(code):
    """Convert Lehmer code (list of N ints) to permutation."""
    pool = list(range(N))
    perm = []
    for c in code:
        if c >= len(pool): return None
        perm.append(pool[c])
        pool.pop(c)
    return perm

# ═══════════════════════════════════════════════════════════════════════════
# APPROACH A — KA-index arithmetic on first-97 values
# ═══════════════════════════════════════════════════════════════════════════
def approach_A():
    print("\n--- APPROACH A: KA-index arithmetic ---")
    g = GRILLE_KA[:N]   # first 97 KA values  (0-25 each)
    g_az = GRILLE_AZ[:N]

    # A1. cumulative sum mod N
    def cumsum_perm(vals, m=N):
        s, seen, p = 0, set(), []
        for v in vals:
            s = (s + v) % m
            p.append(s)
        if is_valid_perm(p): return p
        return None

    for label, vals in [("A1_cumsumKA", g), ("A1_cumsumAZ", g_az)]:
        p = cumsum_perm(vals)
        if p: try_perm(p, label)
        else: print(f"  {label}: not a valid perm (duplicates expected)")

    # A2. running difference mod N
    def rundiff_perm(vals, m=N):
        p = [(vals[i] - vals[i-1]) % m for i in range(len(vals))]
        if is_valid_perm(p): return p
        return None

    for label, vals in [("A2_rundiffKA", g), ("A2_rundiffAZ", g_az)]:
        p = rundiff_perm(vals)
        if p: try_perm(p, label)
        else: print(f"  {label}: not a valid perm")

    # A3. pair encoding (a*26+b) mod N for pairs from 106-char extract
    # 106 chars → 53 pairs; not 97. Try overlapping pairs (105 pairs)
    print("  A3: pair encoding overlapping...")
    g_all_ka = GRILLE_KA
    g_all_az = GRILLE_AZ
    for offset in range(106 - 97):
        sub = g_all_ka[offset:offset+97]
        # overlapping pairs from sub (96 pairs): not 97. Skip.
        # Try: each value (a_i * 26 + a_{i+1}) mod 97
        vals = [(sub[i]*26 + sub[i+1]) % N for i in range(N-1)] + [sub[96] % N]
        p = list(vals)
        if is_valid_perm(p): try_perm(p, f"A3_pair_ka_off{offset}")
        # As rank instead
        try_perm(values_to_perm(vals), f"A3_pair_ka_rank_off{offset}")

    # A4. triple encoding (a*676+b*26+c) mod N
    print("  A4: triple encoding...")
    for offset in range(106 - N):
        sub = g_all_ka[offset:offset+N]
        vals = [(sub[i]*676 + sub[(i+1)%N]*26 + sub[(i+2)%N]) % N for i in range(N)]
        if is_valid_perm(vals): try_perm(vals, f"A4_triple_ka_off{offset}")
        try_perm(values_to_perm(vals), f"A4_triple_ka_rank_off{offset}")

    # A5. sum of consecutive K elements mod N
    print("  A5: rolling sums mod N...")
    for k in range(2, 8):
        for offset in range(min(10, 106-N)):
            sub = g_all_ka[offset:offset+N+k]
            vals = [sum(sub[i:i+k]) % N for i in range(N)]
            if is_valid_perm(vals): try_perm(vals, f"A5_rollsum{k}_off{offset}")
            try_perm(values_to_perm(vals), f"A5_rollsum{k}_rank_off{offset}")

    # A6. XOR of consecutive pairs mod N
    print("  A6: XOR of consecutive pairs...")
    for offset in range(min(10, 106-N)):
        sub = g_all_ka[offset:offset+N+1]
        vals = [(sub[i] ^ sub[i+1]) % N for i in range(N)]
        if is_valid_perm(vals): try_perm(vals, f"A6_xorpair_off{offset}")
        try_perm(values_to_perm(vals), f"A6_xorpair_rank_off{offset}")

    # A7. multiply consecutive
    print("  A7: multiply consecutive...")
    for offset in range(min(10, 106-N)):
        sub = g_all_ka[offset:offset+N+1]
        vals = [((sub[i]+1)*(sub[i+1]+1)) % N for i in range(N)]
        if is_valid_perm(vals): try_perm(vals, f"A7_mulpair_off{offset}")
        try_perm(values_to_perm(vals), f"A7_mulpair_rank_off{offset}")

    # A8. polynomial: a_i^2 + b_i mod N  (square each value)
    print("  A8: polynomial a^2 mod N...")
    for offset in range(min(10, 106-N)):
        sub = g_all_ka[offset:offset+N]
        vals = [(v*v) % N for v in sub]
        if is_valid_perm(vals): try_perm(vals, f"A8_sq_off{offset}")
        try_perm(values_to_perm(vals), f"A8_sq_rank_off{offset}")

    # A9. k4 index XOR grille index
    print("  A9: K4_AZ XOR GRILLE_KA[:97]...")
    vals = [K4_AZ[i] ^ g[i] for i in range(N)]
    if is_valid_perm(vals): try_perm(vals, "A9_xor_k4az_gka")
    try_perm(values_to_perm(vals), "A9_xor_k4az_gka_rank")
    vals2 = [K4_KA[i] ^ g[i] for i in range(N)]
    if is_valid_perm(vals2): try_perm(vals2, "A9_xor_k4ka_gka")
    try_perm(values_to_perm(vals2), "A9_xor_k4ka_gka_rank")

    # A10. difference: grille - k4 mod N
    print("  A10: grille - k4 mod N...")
    for gv, kv, sfx in [(g, K4_AZ, "ka_az"), (g, K4_KA, "ka_ka"),
                         (g_az, K4_AZ, "az_az"), (g_az, K4_KA, "az_ka")]:
        vals = [(gv[i] - kv[i]) % N for i in range(N)]
        if is_valid_perm(vals): try_perm(vals, f"A10_diff_{sfx}")
        try_perm(values_to_perm(vals), f"A10_diff_{sfx}_rank")

    # A11. multiply: grille * k4 mod N
    print("  A11: grille * k4 mod N...")
    for gv, kv, sfx in [(g, K4_AZ, "ka_az"), (g, K4_KA, "ka_ka")]:
        vals = [(gv[i] * kv[i]) % N for i in range(N)]
        if is_valid_perm(vals): try_perm(vals, f"A11_mul_{sfx}")
        try_perm(values_to_perm(vals), f"A11_mul_{sfx}_rank")

    print(f"  Approach A done. Tried={len(TRIED)}")

# ═══════════════════════════════════════════════════════════════════════════
# APPROACH B — Rank-order with tie-breaking variations
# ═══════════════════════════════════════════════════════════════════════════
def approach_B():
    print("\n--- APPROACH B: Rank-order tie-breaking ---")
    g = GRILLE_KA[:N]
    g_az = GRILLE_AZ[:N]

    # B1. reverse-position tie-break
    print("  B1: reverse-position tie-break...")
    for vals, sfx in [(g, "ka"), (g_az, "az")]:
        ranked = sorted(range(N), key=lambda i: (vals[i], -i))
        perm = [0]*N
        for rank, idx in enumerate(ranked): perm[idx] = rank
        try_perm(perm, f"B1_rev_pos_{sfx}")
        # inverse
        inv = [0]*N
        for i, v in enumerate(perm): inv[v] = i
        try_perm(inv, f"B1_rev_pos_{sfx}_inv")

    # B2. next-char tie-break
    print("  B2: next-char tie-break...")
    for vals, sfx in [(g, "ka"), (g_az, "az")]:
        ranked = sorted(range(N), key=lambda i: (vals[i], vals[(i+1)%N]))
        perm = [0]*N
        for rank, idx in enumerate(ranked): perm[idx] = rank
        try_perm(perm, f"B2_next_{sfx}")
        inv = [0]*N
        for i, v in enumerate(perm): inv[v] = i
        try_perm(inv, f"B2_next_{sfx}_inv")

    # B3. prev-char tie-break
    print("  B3: prev-char tie-break...")
    for vals, sfx in [(g, "ka"), (g_az, "az")]:
        ranked = sorted(range(N), key=lambda i: (vals[i], vals[(i-1)%N]))
        perm = [0]*N
        for rank, idx in enumerate(ranked): perm[idx] = rank
        try_perm(perm, f"B3_prev_{sfx}")
        inv = [0]*N
        for i, v in enumerate(perm): inv[v] = i
        try_perm(inv, f"B3_prev_{sfx}_inv")

    # B4. sum-of-neighbours tie-break
    print("  B4: sum-of-neighbours tie-break...")
    for vals, sfx in [(g, "ka"), (g_az, "az")]:
        nbr = [(vals[(i-1)%N] + vals[(i+1)%N]) % 26 for i in range(N)]
        ranked = sorted(range(N), key=lambda i: (vals[i], nbr[i]))
        perm = [0]*N
        for rank, idx in enumerate(ranked): perm[idx] = rank
        try_perm(perm, f"B4_nbr_{sfx}")
        inv = [0]*N
        for i, v in enumerate(perm): inv[v] = i
        try_perm(inv, f"B4_nbr_{sfx}_inv")

    # B5. random tie-breaking — 50000 samples
    print("  B5: random tie-breaking (50000 samples)...")
    rng = random.Random(42)
    hit_threshold = -300  # if near this, report it
    best_rand = -9999
    for trial in range(50000):
        noise = [rng.random() for _ in range(N)]
        for vals, sfx in [(g, "ka"), (g_az, "az")]:
            ranked = sorted(range(N), key=lambda i: (vals[i], noise[i]))
            perm = [0]*N
            for rank, idx in enumerate(ranked): perm[idx] = rank
            try_perm(perm, f"B5_rand_{sfx}_t{trial}")
        if trial % 10000 == 9999:
            print(f"    {trial+1} random trials done, best_global={BEST_SCORE:.1f}")

    print(f"  Approach B done. Tried={len(TRIED)}")

# ═══════════════════════════════════════════════════════════════════════════
# APPROACH C — Base-26 / Lehmer code
# ═══════════════════════════════════════════════════════════════════════════
def approach_C():
    print("\n--- APPROACH C: Base-26 Lehmer code ---")

    # C1. First 97 chars as Lehmer code directly
    # Lehmer[i] must be in 0..N-1-i
    # Raw KA values 0-25, use mod (N-i)
    print("  C1: raw KA values as Lehmer code (mod N-i)...")
    g = GRILLE_KA[:N]
    g_az = GRILLE_AZ[:N]
    for vals, sfx in [(g, "ka"), (g_az, "az")]:
        code = [vals[i] % (N - i) for i in range(N)]
        p = lehmer_to_perm(code)
        if p and is_valid_perm(p):
            try_perm(p, f"C1_lehmer_raw_{sfx}")
        # inverse
        if p:
            inv = [0]*N
            for i, v in enumerate(p): inv[v] = i
            try_perm(inv, f"C1_lehmer_raw_{sfx}_inv")

    # C2. Cumulative sum as Lehmer code
    print("  C2: cumsum as Lehmer code...")
    for vals, sfx in [(g, "ka"), (g_az, "az")]:
        s = 0
        code = []
        for i, v in enumerate(vals):
            s = (s + v) % (N - i) if (N - i) > 0 else 0
            code.append(s)
        p = lehmer_to_perm(code)
        if p and is_valid_perm(p):
            try_perm(p, f"C2_lehmer_cumsum_{sfx}")

    # C3. 106-char extract → big integer (base 26) → Lehmer code
    # This generates a HUGE integer. Extract factoriadic digits.
    print("  C3: 106-char big integer → factoriadic → Lehmer...")
    for vals, sfx in [(GRILLE_KA, "ka"), (GRILLE_AZ, "az")]:
        big = 0
        for v in vals:
            big = big * 26 + v
        # Extract N! Lehmer digits (factoriadic)
        code = []
        for k in range(N, 0, -1):
            code.append(big % k)
            big //= k
        code.reverse()  # code[0] in 0..N-1, code[1] in 0..N-2, ...
        p = lehmer_to_perm(code)
        if p and is_valid_perm(p):
            try_perm(p, f"C3_lehmer_bigint_{sfx}")

    # C4. Subsets: first N chars, last N chars, every-other
    print("  C4: subsets...")
    subsets = {
        'first97_ka': GRILLE_KA[:N],
        'last97_ka': GRILLE_KA[-N:],
        'even_ka': [GRILLE_KA[i] for i in range(0,106,2)][:N],
        'odd_ka': [GRILLE_KA[i] for i in range(1,106,2)][:N],
        'first97_az': GRILLE_AZ[:N],
        'last97_az': GRILLE_AZ[-N:],
        'even_az': [GRILLE_AZ[i] for i in range(0,106,2)][:N],
        'odd_az': [GRILLE_AZ[i] for i in range(1,106,2)][:N],
    }
    for sfx, vals in subsets.items():
        if len(vals) < N: continue
        big = 0
        for v in vals[:N]:
            big = big * 26 + v
        code = []
        for k in range(N, 0, -1):
            code.append(big % k)
            big //= k
        code.reverse()
        p = lehmer_to_perm(code)
        if p and is_valid_perm(p):
            try_perm(p, f"C4_lehmer_{sfx}")

    print(f"  Approach C done. Tried={len(TRIED)}")

# ═══════════════════════════════════════════════════════════════════════════
# APPROACH D — Character frequency ranking
# ═══════════════════════════════════════════════════════════════════════════
def approach_D():
    print("\n--- APPROACH D: Frequency ranking ---")

    # Count frequency of each K4 char in the grille extract
    from collections import Counter
    grille_freq = Counter(GRILLE)
    k4_freq     = Counter(K4)

    # D1. K4 positions sorted by how often that char appears in grille
    # (most frequent in grille → position 0, etc.)
    print("  D1: K4 positions sorted by grille frequency of that char...")
    # ascending (rare chars first)
    ranked = sorted(range(N), key=lambda i: (grille_freq[K4[i]], i))
    perm = [0]*N
    for rank, idx in enumerate(ranked): perm[idx] = rank
    try_perm(perm, "D1_grille_freq_asc")
    inv = [0]*N
    for i, v in enumerate(perm): inv[v] = i
    try_perm(inv, "D1_grille_freq_asc_inv")

    # descending
    ranked = sorted(range(N), key=lambda i: (-grille_freq[K4[i]], i))
    perm = [0]*N
    for rank, idx in enumerate(ranked): perm[idx] = rank
    try_perm(perm, "D1_grille_freq_desc")
    inv = [0]*N
    for i, v in enumerate(perm): inv[v] = i
    try_perm(inv, "D1_grille_freq_desc_inv")

    # D2. Sort by K4 char's own frequency (most common CT char → first)
    print("  D2: sort by K4 char frequency in K4...")
    ranked_asc = sorted(range(N), key=lambda i: (k4_freq[K4[i]], i))
    ranked_desc = sorted(range(N), key=lambda i: (-k4_freq[K4[i]], i))
    for ranked, sfx in [(ranked_asc, "asc"), (ranked_desc, "desc")]:
        perm = [0]*N
        for rank, idx in enumerate(ranked): perm[idx] = rank
        try_perm(perm, f"D2_k4freq_{sfx}")
        inv = [0]*N
        for i, v in enumerate(perm): inv[v] = i
        try_perm(inv, f"D2_k4freq_{sfx}_inv")

    # D3. Rank by (grille_pos_of_first_occurrence_of_K4[i])
    print("  D3: rank by first occurrence in grille...")
    first_occ = {}
    for i, c in enumerate(GRILLE):
        if c not in first_occ:
            first_occ[c] = i
    ranked = sorted(range(N), key=lambda i: (first_occ.get(K4[i], 999), i))
    perm = [0]*N
    for rank, idx in enumerate(ranked): perm[idx] = rank
    try_perm(perm, "D3_first_occ_asc")
    inv = [0]*N
    for i, v in enumerate(perm): inv[v] = i
    try_perm(inv, "D3_first_occ_asc_inv")

    ranked = sorted(range(N), key=lambda i: (-first_occ.get(K4[i], 0), i))
    perm = [0]*N
    for rank, idx in enumerate(ranked): perm[idx] = rank
    try_perm(perm, "D3_first_occ_desc")

    # D4. Rank by last occurrence in grille
    print("  D4: rank by last occurrence in grille...")
    last_occ = {}
    for i, c in enumerate(GRILLE):
        last_occ[c] = i
    ranked = sorted(range(N), key=lambda i: (last_occ.get(K4[i], -1), i))
    perm = [0]*N
    for rank, idx in enumerate(ranked): perm[idx] = rank
    try_perm(perm, "D4_last_occ_asc")
    inv = [0]*N
    for i, v in enumerate(perm): inv[v] = i
    try_perm(inv, "D4_last_occ_asc_inv")

    print(f"  Approach D done. Tried={len(TRIED)}")

# ═══════════════════════════════════════════════════════════════════════════
# APPROACH E — Pattern matching / occurrence mapping
# ═══════════════════════════════════════════════════════════════════════════
def approach_E():
    print("\n--- APPROACH E: Pattern/occurrence mapping ---")

    # For each K4 position i, find occurrence of K4[i] in grille
    # Assign positions in order of appearance
    from collections import defaultdict

    # Build occurrence lists for each letter in grille
    occ = defaultdict(list)
    for i, c in enumerate(GRILLE):
        occ[c].append(i)

    # E1. Map K4[i] → grille occurrence (sequential), mod 97
    print("  E1: sequential occurrence mapping...")
    counters = defaultdict(int)
    vals = []
    for c in K4:
        oc = occ[c]
        if len(oc) > 0:
            vals.append(oc[counters[c] % len(oc)] % N)
        else:
            vals.append(0)
        counters[c] += 1
    try_perm(values_to_perm(vals), "E1_seq_occ_mod97")

    # E2. Map K4[i] → KA-index of its grille occurrence position
    print("  E2: grille occurrence KA-index...")
    counters = defaultdict(int)
    vals2 = []
    for c in K4:
        oc = occ[c]
        if len(oc) > 0:
            gpos = oc[counters[c] % len(oc)]
            vals2.append(KA_IDX[GRILLE[gpos]])
        else:
            vals2.append(0)
        counters[c] += 1
    try_perm(values_to_perm(vals2), "E2_occ_ka_idx")

    # E3. For each K4 char, find ALL positions in grille, use sum mod 97
    print("  E3: sum of grille positions per char...")
    vals3 = [sum(occ[K4[i]]) % N for i in range(N)]
    try_perm(values_to_perm(vals3), "E3_sum_positions")

    # E4. Absolute position of k-th occurrence in grille
    # where k = position of that char in K4 (by occurrence count)
    print("  E4: k-th occurrence (k = count at position i)...")
    counters = defaultdict(int)
    vals4 = []
    for i, c in enumerate(K4):
        oc = occ[c]
        k = counters[c]
        if len(oc) > 0:
            vals4.append(oc[k % len(oc)])
        else:
            vals4.append(i)
        counters[c] += 1
    if is_valid_perm(vals4): try_perm(vals4, "E4_kth_occ_direct")
    try_perm(values_to_perm(vals4), "E4_kth_occ_rank")

    # E5. XOR of all grille positions for that letter
    print("  E5: XOR of all grille positions per char...")
    xor_pos = {}
    for c in AZ:
        x = 0
        for p in occ[c]:
            x ^= p
        xor_pos[c] = x
    vals5 = [xor_pos[K4[i]] % N for i in range(N)]
    try_perm(values_to_perm(vals5), "E5_xor_positions")

    # E6. Grille positions where char equals K4[i], wrap with cycle
    print("  E6: cycle through grille positions matching K4[i]...")
    # Build a sequence: traverse grille and assign positions to K4 chars in order
    grille_q = defaultdict(list)
    for i, c in enumerate(GRILLE):
        grille_q[c].append(i % N)
    counters = defaultdict(int)
    vals6 = []
    for c in K4:
        q = grille_q[c]
        vals6.append(q[counters[c] % len(q)] if q else 0)
        counters[c] += 1
    try_perm(values_to_perm(vals6), "E6_cycle_match")

    print(f"  Approach E done. Tried={len(TRIED)}")

# ═══════════════════════════════════════════════════════════════════════════
# APPROACH F — Modular chain walks
# ═══════════════════════════════════════════════════════════════════════════
def approach_F():
    print("\n--- APPROACH F: Modular chain walks ---")

    def chain_walk(start, step_vals, n=N):
        """Walk: pos = (pos + step_vals[i]) mod n, collect all visited."""
        visited = []
        seen = set()
        pos = start
        for i in range(len(step_vals)):
            if pos not in seen:
                seen.add(pos)
                visited.append(pos)
            pos = (pos + step_vals[i]) % n
        # If we have a cycle that doesn't cover all n, fail
        if len(visited) != n:
            return None
        # Build permutation: visited[i] = position of slot i in original
        return visited

    g_ka = GRILLE_KA
    g_az = GRILLE_AZ

    print("  F1: chain walks with KA steps...")
    for start in range(N):
        for vals, sfx in [(g_ka[:N], "ka"), (g_az[:N], "az")]:
            # steps = grille vals (each 0-25, all add at least 1 to avoid stuck)
            steps = [max(1, v) for v in vals]
            p = chain_walk(start, steps)
            if p and is_valid_perm(p):
                try_perm(p, f"F1_chain_{sfx}_start{start}")
                # Also inverse
                inv = [0]*N
                for i, v in enumerate(p): inv[v] = i
                try_perm(inv, f"F1_chain_{sfx}_start{start}_inv")
        if start % 20 == 19:
            print(f"    start={start+1}/{N} done")

    # F2. Chain with step = (grille[i] + 1) mod N to avoid 0-step
    print("  F2: chain walks (step+1 mod N)...")
    for start in range(N):
        for vals, sfx in [(g_ka[:N], "ka"), (g_az[:N], "az")]:
            steps = [(v + 1) % N for v in vals]
            p = chain_walk(start, steps)
            if p and is_valid_perm(p):
                try_perm(p, f"F2_chain1_{sfx}_start{start}")
        if start % 20 == 19:
            print(f"    start={start+1}/{N} done")

    # F3. Multiplicative chain: pos = (pos * step) mod N (need gcd(step,N)=1)
    # N=97 is prime, so any step 1..96 works
    print("  F3: multiplicative chain walks...")
    for start in range(1, N):
        for vals, sfx in [(g_ka[:N], "ka")]:
            steps = [max(1, v) for v in vals]
            pos = start
            visited = []
            seen = set()
            for v in steps:
                if pos not in seen:
                    seen.add(pos)
                    visited.append(pos)
                pos = (pos * v) % N
                if pos == 0: pos = 1  # avoid stuck at 0
            if len(visited) == N and is_valid_perm(visited):
                try_perm(visited, f"F3_mul_chain_ka_start{start}")
        if start % 20 == 19:
            print(f"    start={start+1}/{N} done")

    # F4. Fibonacci-like chain: pos[i] = (pos[i-1] + pos[i-2]) mod N
    print("  F4: Fibonacci chain...")
    for a0 in range(N):
        for a1 in range(N):
            visited = []
            seen = set()
            prev2, prev1 = a0, a1
            for _ in range(N):
                nxt = (prev2 + prev1) % N
                if nxt not in seen:
                    seen.add(nxt)
                    visited.append(nxt)
                prev2, prev1 = prev1, nxt
            if len(visited) == N and is_valid_perm(visited):
                try_perm(visited, f"F4_fib_a0{a0}_a1{a1}")

    print(f"  Approach F done. Tried={len(TRIED)}")

# ═══════════════════════════════════════════════════════════════════════════
# APPROACH G — Extract as columnar transposition key
# ═══════════════════════════════════════════════════════════════════════════
def approach_G():
    print("\n--- APPROACH G: Columnar transposition key ---")

    # Use grille chars as a columnar keyword: sort alphabetically → column read order
    # Width w = len(key), rows = ceil(N / w)

    # G1. Use grille extract directly as columnar key
    print("  G1: grille as columnar key (various widths)...")
    for w in range(2, 54):  # width 2..53
        rows = math.ceil(N / w)
        if w * rows < N: continue
        # Use first w chars of grille as key
        key_str = GRILLE[:w]
        # Sort columns by key char (AZ and KA)
        for alpha, alpha_name in [(AZ, "az"), (KA, "ka")]:
            alpha_idx = {c: i for i, c in enumerate(alpha)}
            col_order = sorted(range(w), key=lambda j: (alpha_idx.get(key_str[j], 99), j))
            # Read K4 into rows
            # perm[dest] = src: position dest in output came from src in input
            perm = []
            for col in col_order:
                for row in range(rows):
                    src = row * w + col
                    if src < N:
                        perm.append(src)
            if len(perm) == N and is_valid_perm(perm):
                try_perm(perm, f"G1_col_w{w}_{alpha_name}")
                inv = [0]*N
                for i, v in enumerate(perm): inv[v] = i
                try_perm(inv, f"G1_col_w{w}_{alpha_name}_inv")

    # G2. Use KA-index of grille chars as columnar key values (numerical key)
    print("  G2: KA-index as numerical columnar key...")
    for w in range(2, 54):
        rows = math.ceil(N / w)
        key_vals = GRILLE_KA[:w]
        col_order = sorted(range(w), key=lambda j: (key_vals[j], j))
        perm = []
        for col in col_order:
            for row in range(rows):
                src = row * w + col
                if src < N:
                    perm.append(src)
        if len(perm) == N and is_valid_perm(perm):
            try_perm(perm, f"G2_numkey_w{w}_ka")
            inv = [0]*N
            for i, v in enumerate(perm): inv[v] = i
            try_perm(inv, f"G2_numkey_w{w}_ka_inv")

    # G3. Double transposition: two columnar passes
    print("  G3: double columnar (w1 × w2 combos, limited)...")
    widths_small = list(range(3, 14))
    count_g3 = 0
    for w1 in widths_small:
        rows1 = math.ceil(N / w1)
        key1 = GRILLE[:w1]
        col1 = sorted(range(w1), key=lambda j: (AZ_IDX.get(key1[j], 99), j))
        perm1 = []
        for col in col1:
            for row in range(rows1):
                src = row * w1 + col
                if src < N:
                    perm1.append(src)
        if len(perm1) != N: continue

        for w2 in widths_small:
            if w2 == w1: continue
            rows2 = math.ceil(N / w2)
            key2 = GRILLE[w1:w1+w2]
            if len(key2) < w2: continue
            col2 = sorted(range(w2), key=lambda j: (AZ_IDX.get(key2[j], 99), j))
            perm2 = []
            for col in col2:
                for row in range(rows2):
                    src = row * w2 + col
                    if src < N:
                        perm2.append(src)
            if len(perm2) != N: continue
            # Compose: first apply perm1, then perm2
            composed = [perm1[perm2[i]] for i in range(N)]
            if is_valid_perm(composed):
                try_perm(composed, f"G3_double_w{w1}w{w2}")
                inv = [0]*N
                for i, v in enumerate(composed): inv[v] = i
                try_perm(inv, f"G3_double_w{w1}w{w2}_inv")
            count_g3 += 1
    print(f"    G3: {count_g3} double-columnar combos tested")

    # G4. Use all 106 grille chars as key, width=106 (single-pass with blanks)
    # Actually treat as route cipher: write K4 row-by-row width w, read cols sorted by key
    print("  G4: full grille 106 as key (padded rows)...")
    for w in [53, 106]:
        rows = math.ceil(N / w)
        if w > 106: continue
        key_str = GRILLE[:w]
        col_order = sorted(range(w), key=lambda j: (AZ_IDX.get(key_str[j], 99), j))
        perm = []
        for col in col_order:
            for row in range(rows):
                src = row * w + col
                if src < N:
                    perm.append(src)
        if len(perm) == N and is_valid_perm(perm):
            try_perm(perm, f"G4_fullkey_w{w}")
            inv = [0]*N
            for i, v in enumerate(perm): inv[v] = i
            try_perm(inv, f"G4_fullkey_w{w}_inv")

    print(f"  Approach G done. Tried={len(TRIED)}")

# ═══════════════════════════════════════════════════════════════════════════
# BONUS APPROACHES
# ═══════════════════════════════════════════════════════════════════════════

def approach_H_extended():
    """H: Extended approaches — mixed, interleaved, arithmetic sequences."""
    print("\n--- APPROACH H: Extended / mixed ---")

    g = GRILLE_KA[:N]
    g_az = GRILLE_AZ[:N]

    # H1. Grille char repeated mod 97 as additive step (i-th step = g[i])
    # Build a "step permutation": p[i] = (sum of g[0..i]) mod 97
    print("  H1: step-permutation from grille sums...")
    for vals, sfx in [(g, "ka"), (g_az, "az")]:
        running = 0
        p = []
        for v in vals:
            running = (running + max(v, 1)) % N
            p.append(running)
        if is_valid_perm(p): try_perm(p, f"H1_step_{sfx}")
        # Also cumsum-only (no max)
        running = 0
        p2 = []
        for v in vals:
            running = (running + v) % N
            p2.append(running)
        if is_valid_perm(p2): try_perm(p2, f"H1_cumsum_raw_{sfx}")
        try_perm(values_to_perm(p2), f"H1_cumsum_raw_{sfx}_rank")

    # H2. Interleave first-half and second-half of grille
    print("  H2: interleaved halves...")
    half = 53
    g1 = GRILLE_KA[:half]
    g2 = GRILLE_KA[half:2*half]  # 53 values
    interleaved = []
    for a, b in zip(g1, g2):
        interleaved.extend([a, b])
    interleaved = interleaved[:N]
    try_perm(values_to_perm(interleaved), "H2_interleaved_ka")

    g1_az = GRILLE_AZ[:half]
    g2_az = GRILLE_AZ[half:2*half]
    interleaved_az = []
    for a, b in zip(g1_az, g2_az):
        interleaved_az.extend([a, b])
    interleaved_az = interleaved_az[:N]
    try_perm(values_to_perm(interleaved_az), "H2_interleaved_az")

    # H3. Grille as base-97 index sequence (each char value mod 97 = index)
    print("  H3: each char → KA-position as direct index (pool removal)...")
    # Use the 106 values, try to pick 97 unique positions
    # Greedy: scan grille, for each value v mod 97, if not taken, assign
    pool = list(range(N))
    used = [False]*N
    assigned = [None]*N
    # map K4 positions to grille positions
    # Idea: for K4 position i, use GRILLE_KA[i] mod 97 as the target slot
    vals_mod = [GRILLE_KA[i] % N for i in range(N)]
    # Assign greedily, resolving conflicts by next available
    result = []
    taken = set()
    for i in range(N):
        v = vals_mod[i]
        if v not in taken:
            taken.add(v)
            result.append(v)
        else:
            # find next available
            candidate = (v + 1) % N
            while candidate in taken:
                candidate = (candidate + 1) % N
            taken.add(candidate)
            result.append(candidate)
    if is_valid_perm(result): try_perm(result, "H3_greedy_ka")
    try_perm(values_to_perm(result), "H3_greedy_ka_rank")

    # H4. Skipping: use every k-th character of grille (extended cycle)
    print("  H4: skip-k sampling of grille (extended cycle)...")
    for k in range(1, 20):
        idxs = [(k * i) % 106 for i in range(N)]
        vals = [GRILLE_KA[j] for j in idxs]
        try_perm(values_to_perm(vals), f"H4_skip{k}_ka")
        vals_az = [GRILLE_AZ[j] for j in idxs]
        try_perm(values_to_perm(vals_az), f"H4_skip{k}_az")

    # H5. Mirror/palindrome: compare grille[i] and grille[105-i]
    print("  H5: mirror comparison...")
    diff_mirror = [(GRILLE_KA[i] - GRILLE_KA[105-i]) % N for i in range(N)]
    try_perm(values_to_perm(diff_mirror), "H5_mirror_diff_ka")
    sum_mirror = [(GRILLE_KA[i] + GRILLE_KA[105-i]) % N for i in range(N)]
    try_perm(values_to_perm(sum_mirror), "H5_mirror_sum_ka")

    # H6. Rotate grille by offset, rank
    print("  H6: rotated grille rank...")
    for offset in range(0, 106, 5):
        rotated = GRILLE_KA[offset:] + GRILLE_KA[:offset]
        try_perm(values_to_perm(rotated[:N]), f"H6_rot{offset}_ka")

    # H7. Grille × K4 combined arithmetic
    print("  H7: grille + k4 combined arithmetic...")
    for gv, sfxg in [(GRILLE_KA[:N], "ka"), (GRILLE_AZ[:N], "az")]:
        for kv, sfxk in [(K4_KA, "ka"), (K4_AZ, "az")]:
            for op_name, op in [("sum", lambda a,b:(a+b)%N),
                                  ("diff", lambda a,b:(a-b)%N),
                                  ("mul", lambda a,b:(a*b)%N)]:
                vals = [op(gv[i], kv[i]) for i in range(N)]
                try_perm(values_to_perm(vals), f"H7_{op_name}_g{sfxg}_k{sfxk}")

    print(f"  Approach H done. Tried={len(TRIED)}")


def approach_I_grille_geometry():
    """I: Use the actual hole coordinates of the grille mask as permutation."""
    print("\n--- APPROACH I: Grille geometry (hole coordinates) ---")

    # Grille mask: 28 rows × 33 cols, holes = 0
    GRILLE_MASK = [
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

    # Extract hole coordinates (row, col) for cells with '0' that are not '~'
    holes = []
    for r, row in enumerate(GRILLE_MASK):
        for c, ch in enumerate(row):
            if ch == '0':
                holes.append((r, c))

    print(f"  Total holes: {len(holes)}")

    # I1. Use hole positions directly: (row*33 + col) mod 97 as rank values
    vals = [(r*33 + c) % N for r, c in holes[:N]]
    try_perm(values_to_perm(vals), "I1_hole_pos_rank")

    # I2. row-major index of each hole mod 97
    vals2 = [(r*33 + c) % N for r, c in holes][:N]
    if is_valid_perm(vals2): try_perm(vals2, "I2_hole_rowmaj_direct")
    try_perm(values_to_perm(vals2), "I2_hole_rowmaj_rank")

    # I3. col-major index of each hole mod 97
    holes_colmaj = sorted(holes, key=lambda x: (x[1], x[0]))
    vals3 = [(r*33 + c) % N for r, c in holes_colmaj[:N]]
    try_perm(values_to_perm(vals3), "I3_hole_colmaj_rank")

    # I4. Hole row sums: for each of 97 holes, row number mod 28
    vals4 = [r % 28 for r, c in holes[:N]]
    try_perm(values_to_perm(vals4), "I4_hole_row_rank")

    # I5. Hole col sums
    vals5 = [c % 33 for r, c in holes[:N]]
    try_perm(values_to_perm(vals5), "I5_hole_col_rank")

    # I6. (row + col) mod 97
    vals6 = [(r + c) % N for r, c in holes[:N]]
    try_perm(values_to_perm(vals6), "I6_hole_sum_rank")

    # I7. (row * col) mod 97
    vals7 = [((r+1) * (c+1)) % N for r, c in holes[:N]]
    try_perm(values_to_perm(vals7), "I7_hole_prod_rank")

    # I8. Distance from center hole
    cx = sum(r for r,c in holes) / len(holes)
    cy = sum(c for r,c in holes) / len(holes)
    dists = [((r-cx)**2 + (c-cy)**2)**0.5 for r,c in holes[:N]]
    try_perm(values_to_perm(dists), "I8_hole_dist_rank")

    # I9. Diagonal index: row - col
    vals9 = [(r - c) % N for r, c in holes[:N]]
    try_perm(values_to_perm(vals9), "I9_hole_diag_rank")

    print(f"  Approach I done. Tried={len(TRIED)}")


def approach_J_number_theory():
    """J: Number-theoretic permutations — N=97 is prime, use field arithmetic."""
    print("\n--- APPROACH J: Number theory (N=97 prime) ---")

    g = GRILLE_KA[:N]
    g_az = GRILLE_AZ[:N]

    # J1. Quadratic residues: perm[i] = (i^2) mod 97
    print("  J1: quadratic residue permutation...")
    qr = [(i*i) % N for i in range(N)]
    # This has duplicates for non-zero elements (each QR appears twice), skip direct
    # Instead use grille values as exponent: g[i]^2 mod 97
    vals = [(max(g[i],1)**2) % N for i in range(N)]
    try_perm(values_to_perm(vals), "J1_QR_ka")

    # J2. Discrete log: find x such that generator^x ≡ grille[i] mod 97
    # Generator of GF(97): 5 is a primitive root mod 97
    print("  J2: discrete log in GF(97)...")
    # Build dlog table
    gen = 5
    dlog = {}
    x = 1
    for i in range(N-1):
        dlog[x] = i
        x = (x * gen) % N
    dlog[0] = N-1  # placeholder

    for vals_src, sfx in [(g, "ka"), (g_az, "az")]:
        vals = [dlog.get(max(v, 1) % N, 0) for v in vals_src]
        try_perm(values_to_perm(vals), f"J2_dlog_{sfx}")

    # J3. Fermat: g[i]^(97-2) mod 97 = modular inverse
    print("  J3: modular inverse in GF(97)...")
    def modinv(a, p): return pow(a, p-2, p) if a != 0 else 0
    for vals_src, sfx in [(g, "ka"), (g_az, "az")]:
        vals = [modinv(max(v,1), N) for v in vals_src]
        try_perm(values_to_perm(vals), f"J3_modinv_{sfx}")

    # J4. Primitive root powers: sequence g^0, g^1, ..., g^96 mod 97
    print("  J4: powers of grille chars as primitive roots...")
    for start_val, sfx in [(GRILLE_KA[0], "ka0"), (GRILLE_KA[1], "ka1")]:
        base = max(start_val, 2)
        if base >= N: base = base % N
        if base < 2: base = 5
        seq = [pow(base, i, N) for i in range(N)]
        if is_valid_perm(seq): try_perm(seq, f"J4_pow{base}_mod97")

    # J5. Lucas sequence: L[i] = (L[i-1] + L[i-2]) mod 97 with seeds from grille
    print("  J5: Lucas sequences with grille seeds...")
    for i in range(10):
        a0 = GRILLE_KA[i] % N
        a1 = GRILLE_KA[i+1] % N
        seq = [a0, a1]
        for k in range(N-2):
            seq.append((seq[-1] + seq[-2]) % N)
        if is_valid_perm(seq[:N]): try_perm(seq[:N], f"J5_lucas_g{i}g{i+1}")
        try_perm(values_to_perm(seq[:N]), f"J5_lucas_rank_g{i}g{i+1}")

    print(f"  Approach J done. Tried={len(TRIED)}")


def save_results():
    out_dir = "/home/cpatrick/kryptos/blitz_results/numeric_permuter"
    os.makedirs(out_dir, exist_ok=True)
    summary = {
        "total_tried": len(TRIED),
        "crib_hits": len(RESULTS),
        "best_score": BEST_SCORE,
        "hits": RESULTS
    }
    with open(f"{out_dir}/results.json", "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n✓ Results saved to {out_dir}/results.json")
    print(f"  Total permutations tried: {len(TRIED)}")
    print(f"  Crib hits: {len(RESULTS)}")
    print(f"  Best quadgram score: {BEST_SCORE:.2f}")


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print(f"K4 Numeric Permuter — {N} chars, grille {len(GRILLE)} chars")
    print(f"K4  : {K4}")
    print(f"GRIL: {GRILLE}")
    print()

    approach_A()
    approach_B()
    approach_C()
    approach_D()
    approach_E()
    approach_F()
    approach_G()
    approach_H_extended()
    approach_I_grille_geometry()
    approach_J_number_theory()

    save_results()

    if RESULTS:
        print("\n" + "="*60)
        print("CRIB HITS FOUND:")
        for r in RESULTS:
            print(f"  label={r['label']}  ENE@{r['ene']} BC@{r['bc']}")
            print(f"  PT: {r['pt']}")
    else:
        print("\nNo crib hits. Best score:", BEST_SCORE)
