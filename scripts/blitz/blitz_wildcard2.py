#!/usr/bin/env python3
"""
Cipher: multi-method blitz
Family: blitz
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
blitz_wildcard2.py — Deep Dive Approaches (Part 2)
===================================================
Covers approaches NOT done in blitz_wildcard.py:

Q. Affine permutations: p(i) = (a*i + b) % 97 — ALL 9312 combinations
   (Part 1 only tested b=0, i.e., stride permutations)
R. T-separator strip cipher — T's at positions 35,37,50,67,68,80 as delimiters
   6! = 720 block arrangements
S. 91-non-T chars in 7×13 grid — 7 rows of 13 cols
   (97 = 7×13 + 6 → 6 T's + 91 non-T → 7×13 grid)
T. Grille overlay on K4 grid — exhaustive search over all (width, row_off, col_off)
U. PALIMPSEST+KRYPTOS two-key approach (scramble with one, cipher with other)
V. Compete block transpositions (sizes 2-20)
W. The "IDBYROWS 97" interpretation — specific width 97/N for integer N
X. Tableau-path permutation — traverse KA tableau by steps defined by K4

Run: cd /home/cpatrick/kryptos && PYTHONPATH=src python3 -u scripts/blitz_wildcard2.py
"""

import sys, json, math, os, time, random, itertools
from collections import Counter, defaultdict
from itertools import permutations as iperm

sys.path.insert(0, 'src')

# ── Constants ────────────────────────────────────────────────────────────────

K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(K4)
assert N == 97

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

GRILLE_EXTRACT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"

KEYWORDS = [
    'KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW', 'SANBORN', 'SCHEIDT',
    'BERLIN', 'CLOCK', 'EAST', 'NORTH', 'LIGHT', 'ANTIPODES', 'MEDUSA',
    'ENIGMA', 'COMPASS', 'WELTZEITUHR', 'IQLUSION', 'ILLUSION', 'LAYER',
]
KEYWORDS = list(dict.fromkeys(KEYWORDS))

CRIB_ENE = "EASTNORTHEAST"
CRIB_BC  = "BERLINCLOCK"

# Authoritative mask
MASK_TEXT = """\
1    1    1    1    1    1    1    1    0    1    0    1    0    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    ~
0    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    0    1    1    1    0    1    1    1    1    0    0    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    0    1    1    0    ~    ~
1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    0    1    1    1    1    0    1    1    1    1    1    1    1    1    0    ~    ~
1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    ~    ~
0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    0    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    0    1    1    1    1    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    ~    ~
1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    ~    ~
1    1    1    1    1    0    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    0    0    1    1    1    1    1    1    1    1    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    ~
1    1    1    0    0    1    0    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    0    1    0    ~
1    1    1    1    0    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    0    ~    ~
1    1    0    1    1    0    1    1    1    1    0    0    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    0    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    0    0    1    1    1    1    1    1    1    1    0    1    1    1    1    0    1    1    1    0    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    0    1    1    0    1    1    1    1    1    1    1    0    0    1    ~    ~
1    1    1    1    1    0    1    1    0    1    1    1    1    1    1    1    0    1    0    1    0    1    1    1    0    1    1    0    1    1    0    ~    ~
1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    0    1    1    1    1    0    0    1    0    1    1    0    1    1    0    1    1    ~
1    1    1    1    1    1    1    0    0    1    1    1    1    1    1    1    1    1    1    1    0    1    0    1    0    1    1    1    1    1    1    ~    ~
0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    0    0    1    1    1    0    1    1
0    1    1    1    1    1    1    0    1    1    1    1    0    0    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    0    0    ~    ~
1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    0    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    0    1    1    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    0    1    1    1    1    1    1    0    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    0    0    ~    ~"""

HOLES = []
for r, line in enumerate(MASK_TEXT.strip().split('\n')):
    vals = line.split()
    for c, v in enumerate(vals):
        if v != '~' and v == '0':
            HOLES.append((r, c))
assert len(HOLES) == 107

# ── Quadgrams ────────────────────────────────────────────────────────────────
print("Loading quadgrams...", flush=True)
QG = json.load(open('data/english_quadgrams.json'))
MISS = min(QG.values()) - 2.0

def qscore(text):
    n = len(text)
    if n < 4: return MISS
    return sum(QG.get(text[i:i+4], MISS) for i in range(n-3)) / (n-3)

print(f"  {len(QG)} quadgrams loaded", flush=True)

AZI = {c: i for i, c in enumerate(AZ)}
KAI = {c: i for i, c in enumerate(KA)}

CIPHERS = [
    ("vig_AZ",  lambda ct, kw: ''.join(AZ[(AZI[ct[i]] - AZI.get(kw[i%len(kw)], 0)) % 26] for i in range(len(ct)))),
    ("beau_AZ", lambda ct, kw: ''.join(AZ[(AZI.get(kw[i%len(kw)], 0) - AZI[ct[i]]) % 26] for i in range(len(ct)))),
    ("vig_KA",  lambda ct, kw: ''.join(KA[(KAI[ct[i]] - KAI.get(kw[i%len(kw)], 0)) % 26] for i in range(len(ct)))),
    ("beau_KA", lambda ct, kw: ''.join(KA[(KAI.get(kw[i%len(kw)], 0) - KAI[ct[i]]) % 26] for i in range(len(ct)))),
]

os.makedirs('blitz_results/wildcard2', exist_ok=True)
RF = open('blitz_results/wildcard2/results.jsonl', 'a')
HITS = []
_tested = set()
total_tested = 0

def save(d):
    RF.write(json.dumps(d) + '\n')
    RF.flush()

def argsort(seq):
    return sorted(range(len(seq)), key=lambda i: (seq[i], i))

def validate_perm(perm):
    return len(perm) == N and sorted(perm) == list(range(N))

def apply_perm(text, perm):
    return ''.join(text[p] for p in perm)

def test_ct(ct, label):
    global total_tested
    if ct in _tested: return None
    _tested.add(ct)
    total_tested += 1

    best = None; best_sc = MISS - 1
    for kw in KEYWORDS:
        for cname, cfn in CIPHERS:
            try:
                pt = cfn(ct, kw)
            except:
                continue
            ene = pt.find(CRIB_ENE)
            bc  = pt.find(CRIB_BC)
            if ene >= 0 or bc >= 0:
                sc = qscore(pt)
                print(f"*** CRIB HIT [{label}]: ENE@{ene} BC@{bc} key={kw} {cname} sc={sc:.3f}", flush=True)
                print(f"    CT: {ct}", flush=True)
                print(f"    PT: {pt}", flush=True)
                d = {'label': label, 'ct': ct, 'key': kw, 'cipher': cname,
                     'ene': ene, 'bc': bc, 'pt': pt, 'score': sc}
                HITS.append(d); save(d)
                return d
            sc = qscore(pt)
            if sc > best_sc:
                best_sc = sc
                best = {'label': label, 'key': kw, 'cipher': cname, 'pt': pt, 'score': sc}
    if best and best['score'] > -7.0:
        save(best)
    return best

def test_perm(perm, label):
    if not validate_perm(perm): return None
    return test_ct(apply_perm(K4, perm), label)

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH Q: ALL AFFINE PERMUTATIONS mod 97
# p(i) = (a*i + b) % 97  for a in 1..96, b in 0..96
# ─────────────────────────────────────────────────────────────────────────────
def approach_Q():
    print("\n" + "="*70, flush=True)
    print("APPROACH Q: ALL AFFINE PERMUTATIONS mod 97 (9312 perms)", flush=True)
    print("="*70, flush=True)
    results = []
    best_score = MISS - 1
    best_result = None

    count = 0
    for a in range(1, 97):   # 97 is prime so all a ≠ 0 give valid perms
        for b in range(97):
            perm = [(a*i + b) % 97 for i in range(97)]
            ct = apply_perm(K4, perm)
            r = test_ct(ct, f"Q_a{a}_b{b}")
            count += 1
            if r and r.get('ene', -1) >= 0 or (r and r.get('bc', -1) >= 0):
                print(f"  *** CRIB HIT: a={a} b={b}", flush=True)
                HITS.append(r)
                return [r]
            if r and r.get('score', MISS-1) > best_score:
                best_score = r['score']
                best_result = r
            if count % 1000 == 0:
                print(f"  Q: tested {count}/9312 affine perms, best_score={best_score:.3f}", flush=True)

    print(f"  Q: Done. Tested {count} affine perms. Best: {best_result}", flush=True)
    return [best_result] if best_result else []

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH R: T-SEPARATOR STRIP CIPHER
# T's at positions 35,37,50,67,68,80 divide K4 into blocks
# Try all arrangements of blocks
# ─────────────────────────────────────────────────────────────────────────────
def approach_R():
    print("\n" + "="*70, flush=True)
    print("APPROACH R: T-SEPARATOR STRIP CIPHER", flush=True)
    print("="*70, flush=True)
    results = []

    t_positions = [i for i, c in enumerate(K4) if c == 'T']
    print(f"  T positions: {t_positions}", flush=True)
    # T positions: 35, 37, 50, 67, 68, 80

    # Strategy 1: T's as delimiters between "blocks"
    # Blocks: segments between consecutive T's (including before first T and after last T)
    boundaries = [0] + t_positions + [97]
    segments = []  # (start, end) for each segment (not including T's)
    for i in range(len(boundaries)-1):
        s = boundaries[i]
        e = boundaries[i+1]
        # s is either 0 or a T position; e is either a T position or 97
        if i == 0:
            # Before first T
            seg_start = 0
            seg_end = t_positions[0]
        else:
            seg_start = boundaries[i] + 1  # skip the T
            seg_end = boundaries[i+1] if boundaries[i+1] == 97 else boundaries[i+1]
        if seg_start < seg_end:
            segments.append((seg_start, seg_end))

    print(f"  Segments (excluding T's):", flush=True)
    for s, e in segments:
        print(f"    [{s}:{e}] = '{K4[s:e]}' (len={e-s})", flush=True)

    # R1: Arrange blocks (WITHOUT T's) in all possible orders → concatenate
    seg_texts = [K4[s:e] for s, e in segments]
    for seg_order in iperm(range(len(segments))):
        candidate_ct = ''.join(seg_texts[i] for i in seg_order)
        if len(candidate_ct) != 91:
            continue
        # This gives 91 chars. Pad/extend to 97 somehow, or test as 91-char CT
        # For now, test as 91-char CT
        for kw in KEYWORDS:
            for cname, cfn in CIPHERS:
                try:
                    pt = cfn(candidate_ct, kw)
                except:
                    continue
                if CRIB_ENE in pt or CRIB_BC in pt:
                    sc = qscore(pt)
                    label = f"R_notT_order_{''.join(map(str,seg_order))}"
                    print(f"  *** R1 HIT: order={seg_order} kw={kw} {cname}", flush=True)
                    print(f"      PT: {pt}", flush=True)
                    d = {'label': label, 'ct': candidate_ct, 'kw': kw, 'cipher': cname, 'pt': pt, 'score': sc}
                    HITS.append(d); save(d)

    # R2: "Blocks" that INCLUDE T markers
    # Build blocks: [segment + T_at_end] or similar
    # Block scheme A: {chars_before_T + T} for each T, plus trailing segment
    block_scheme_A = []
    prev = 0
    for t in t_positions:
        block_scheme_A.append(list(range(prev, t+1)))  # include the T
        prev = t + 1
    block_scheme_A.append(list(range(prev, 97)))  # trailing segment

    print(f"\n  Block scheme A (include T in block):", flush=True)
    for b in block_scheme_A:
        if b:
            print(f"    [{b[0]}:{b[-1]+1}] = '{K4[b[0]:b[-1]+1]}' (len={len(b)})", flush=True)

    for seg_order in iperm(range(len(block_scheme_A))):
        perm = []
        for si in seg_order:
            perm.extend(block_scheme_A[si])
        if len(perm) == 97 and validate_perm(perm):
            label = f"R_blockA_order_{''.join(map(str,seg_order))}"
            r = test_perm(perm, label)
            results.append(r)

    # R3: Block scheme B: {T + chars_after_T} (T goes with the next segment)
    block_scheme_B = []
    prev = 0
    for t in t_positions:
        seg = list(range(prev, t))  # chars before T, not including T
        if seg:
            block_scheme_B.append(seg)
        prev = t
    block_scheme_B_trailing = list(range(prev, 97))  # T's and trailing
    # Actually restructure: trailing T at start of next block
    block_scheme_B = []
    block_scheme_B.append(list(range(0, t_positions[0])))  # before first T
    for i in range(len(t_positions)):
        t = t_positions[i]
        t_end = t_positions[i+1] if i+1 < len(t_positions) else 97
        block_scheme_B.append(list(range(t, t_end)))  # T + chars until next T (or end)
    print(f"\n  Block scheme B (T at start of block):", flush=True)
    for b in block_scheme_B:
        if b:
            print(f"    [{b[0]}:{b[-1]+1}] = '{K4[b[0]:b[-1]+1]}' (len={len(b)})", flush=True)

    for seg_order in iperm(range(len(block_scheme_B))):
        perm = []
        for si in seg_order:
            perm.extend(block_scheme_B[si])
        if len(perm) == 97 and validate_perm(perm):
            label = f"R_blockB_order_{''.join(map(str,seg_order))}"
            r = test_perm(perm, label)
            results.append(r)

    # R4: Treat T's as "null" characters and the 91 non-T chars as real CT
    # Insert the 6 T's back at regular intervals after rearranging
    non_t = ''.join(K4[i] for i in range(97) if K4[i] != 'T')
    assert len(non_t) == 91

    for kw in KEYWORDS:
        for cname, cfn in CIPHERS:
            try:
                pt = cfn(non_t, kw)
            except:
                continue
            if CRIB_ENE in pt or CRIB_BC in pt:
                sc = qscore(pt)
                print(f"  *** R4 HIT (91-char non-T): kw={kw} {cname}", flush=True)
                print(f"      PT: {pt}", flush=True)
                d = {'label': f'R4_{kw}_{cname}', 'ct': non_t, 'kw': kw, 'cipher': cname, 'pt': pt, 'score': sc}
                HITS.append(d); save(d)

    # R5: The consecutive TT (positions 67-68) might mean something special
    # BERLINCLOCK is at carved positions 63-73 (11 chars)
    # The TT at 67-68 is WITHIN the BERLINCLOCK region!
    # PT[67]=PT[68]=? (the self-encrypting position 73=K, not 67/68)
    print(f"\n  TT is within BERLINCLOCK region [63:74]: ", flush=True)
    print(f"  K4[63:74] = {K4[63:74]}", flush=True)
    # K4[63:74] = NYPVTTMZFPK → includes TT at positions 67-68

    # R6: Use the DOUBLED T's as a special pivot
    # 6 T's → encode a value: TWTTWT pattern...
    # T at 35, W at 36, T at 37 → TWT
    # T at 67, T at 68 → TT (consecutive)
    # Positions: {35, 37} are separated by 1 char, {67, 68} are consecutive
    # {50} and {80} are singletons
    print(f"\n  T pattern: {[K4[i-1:i+2] for i in t_positions]}", flush=True)

    valid = [r for r in results if r is not None]
    if valid:
        best = max(valid, key=lambda r: r.get('score', MISS))
        print(f"  R best: {best['label']} score={best.get('score', 'N/A'):.3f}", flush=True)
    return results

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH S: 91 NON-T CHARS IN 7×13 GRID
# 97 = 7×13 + 6, 6 T's = the "remainder"
# ─────────────────────────────────────────────────────────────────────────────
def approach_S():
    print("\n" + "="*70, flush=True)
    print("APPROACH S: 91 NON-T CHARS IN 7×13 GRID", flush=True)
    print("="*70, flush=True)
    results = []

    non_t_chars = ''.join(c for c in K4 if c != 'T')
    non_t_positions = [i for i in range(97) if K4[i] != 'T']
    t_positions = [i for i in range(97) if K4[i] == 'T']
    assert len(non_t_chars) == 91
    assert 91 == 7 * 13

    print(f"  91 non-T chars: {non_t_chars}", flush=True)
    print(f"  T positions: {t_positions}", flush=True)

    # S1: Write non-T chars in 7×13 grid, try all column orderings (standard columnar)
    W = 13; H = 7
    for kw in ['KRYPTOS', 'ABSCISSA', 'PALIMPSEST', 'BERLINCLOCK', 'EASTNORTHEAST',
               'ANTIPODES', 'SHADOW']:
        if len(kw) >= W:
            key_part = kw[:W]
        else:
            key_part = (kw * 2)[:W]
        col_order = sorted(range(W), key=lambda i: (key_part[i], i))
        # Read non-T chars in column order
        ct_91 = ''.join(non_t_chars[r*W + c] for c in col_order for r in range(H))
        for cname, cfn in CIPHERS:
            pt = cfn(ct_91, kw[:W] if len(kw) >= W else kw)
            if CRIB_ENE in pt or CRIB_BC in pt:
                sc = qscore(pt)
                print(f"  *** S1 HIT: w={W} kw={kw} {cname}", flush=True)
                print(f"      PT: {pt}", flush=True)
                d = {'label': f'S1_{kw}_{cname}', 'ct': ct_91, 'pt': pt, 'score': sc}
                HITS.append(d); save(d)

    # S2: Read non-T chars in 13×7 grid (transposed)
    W2 = 7; H2 = 13
    for kw in ['KRYPTOS', 'ABSCISSA', 'BERLINCLOCK']:
        key_part = kw[:W2] if len(kw) >= W2 else (kw * 2)[:W2]
        col_order = sorted(range(W2), key=lambda i: (key_part[i], i))
        ct_91 = ''.join(non_t_chars[r*W2 + c] for c in col_order for r in range(H2))
        for cname, cfn in CIPHERS:
            pt = cfn(ct_91, kw)
            if CRIB_ENE in pt or CRIB_BC in pt:
                sc = qscore(pt)
                print(f"  *** S2 HIT: w={W2} kw={kw} {cname}", flush=True)
                d = {'label': f'S2_{kw}_{cname}', 'ct': ct_91, 'pt': pt, 'score': sc}
                HITS.append(d); save(d)

    # S3: Write in 7×13 grid, apply ALL 13! columnar orderings (too many — sample)
    # Try all (7! ×13 col orderings are too many, but try all 7-char and 13-char keywords)
    additional_kws = ['KRYPTOS', 'LAYERTWO', 'ABSCISSA', 'BERLINCL', 'SHADOWS7']
    for kw in additional_kws:
        key13 = (kw * 2)[:13]
        col_order = sorted(range(13), key=lambda i: (key13[i], i))
        ct = ''.join(non_t_chars[r*13 + c] for c in col_order for r in range(7))
        for cname, cfn in CIPHERS:
            pt = cfn(ct, kw)
            if CRIB_ENE in pt or CRIB_BC in pt:
                sc = qscore(pt)
                print(f"  *** S3 HIT: kw={kw} {cname}", flush=True)
                d = {'label': f'S3_{kw}_{cname}', 'ct': ct, 'pt': pt, 'score': sc}
                HITS.append(d); save(d)

    # S4: Re-insert T's back into column-sorted non-T sequence
    # After doing the 7×13 transposition on non-T chars, re-insert T's at their
    # original proportional positions
    for kw in ['KRYPTOS', 'ABSCISSA', 'PALIMPSEST']:
        key_part = (kw * 2)[:13]
        col_order = sorted(range(13), key=lambda i: (key_part[i], i))
        sorted_non_t = ''.join(non_t_chars[r*13 + c] for c in col_order for r in range(7))
        # Re-insert T's at their proportional positions
        result = list(sorted_non_t)
        for t_pos in t_positions:
            # Insert T at proportional position in the 91-char string
            prop_pos = int(t_pos * 91 / 97)
            result.insert(prop_pos, 'T')
        # Trim to 97
        candidate_ct = ''.join(result[:97])
        if len(candidate_ct) == 97:
            r = test_ct(candidate_ct, f"S4_reinsert_{kw}")
            results.append(r)

    # S5: Non-T chars as already the real CT — test directly!
    r = test_ct(non_t_chars, "S5_nonT_direct")
    results.append(r)

    # S6: Reversed non-T chars
    r = test_ct(non_t_chars[::-1], "S5_nonT_reversed")
    results.append(r)

    valid = [r for r in results if r is not None]
    if valid:
        best = max(valid, key=lambda r: r.get('score', MISS))
        print(f"  S best: {best.get('label','?')} score={best.get('score', MISS):.3f}", flush=True)
    return results

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH T: GRILLE OVERLAY ON K4 GRID (exhaustive width×offset search)
# ─────────────────────────────────────────────────────────────────────────────
def approach_T():
    print("\n" + "="*70, flush=True)
    print("APPROACH T: GRILLE OVERLAY ON K4 GRID (exhaustive)", flush=True)
    print("="*70, flush=True)
    results = []

    # The grille is 28 rows × up to 33 cols
    # K4 (97 chars) is written in a grid of width W
    # The grille is positioned over K4 at row offset R0 and col offset C0
    # Holes that fall within K4's area define the reading order

    best_coverage = 0
    best_config = None
    hit_configs = []

    for W in range(5, 34):
        nrows = math.ceil(97 / W)

        for R0 in range(0, 28 - nrows + 2):  # K4 starts at grille row R0
            for C0 in range(0, 33 - W + 2):  # K4 starts at grille col C0

                # Find holes that fall within K4's grid area
                covered = []  # (grille_reading_order, k4_position)
                for hole_idx, (r, c) in enumerate(HOLES):
                    # Translate to K4 coordinates
                    k4_row = r - R0
                    k4_col = c - C0
                    if 0 <= k4_row < nrows and 0 <= k4_col < W:
                        k4_pos = k4_row * W + k4_col
                        if k4_pos < 97:
                            covered.append(k4_pos)

                n_covered = len(covered)
                n_unique = len(set(covered))

                if n_unique > best_coverage:
                    best_coverage = n_unique
                    best_config = (W, R0, C0, n_covered, n_unique, covered)

                # If we have a complete permutation (all 97 positions covered uniquely):
                if n_unique == 97 and n_covered == 97:
                    print(f"  PERFECT COVERAGE: W={W} R0={R0} C0={C0}", flush=True)
                    perm = covered  # reading order = K4 positions in grille order
                    if validate_perm(perm):
                        r = test_perm(perm, f"T_W{W}_R0{R0}_C0{C0}_perfect")
                        results.append(r)
                        hit_configs.append((W, R0, C0, 'perfect'))

                # If we have a NEAR-complete coverage (90+ unique positions):
                elif n_unique >= 90:
                    # Build a permutation from the covered positions
                    # covered gives reading order; fill missing positions at end
                    seen = set()
                    perm = []
                    for p in covered:
                        if p not in seen:
                            perm.append(p)
                            seen.add(p)
                    # Fill missing
                    for p in range(97):
                        if p not in seen:
                            perm.append(p)
                    if validate_perm(perm):
                        r = test_perm(perm, f"T_W{W}_R0{R0}_C0{C0}_n{n_unique}")
                        results.append(r)

    print(f"  Best coverage: {best_coverage} unique K4 positions", flush=True)
    if best_config:
        W, R0, C0, n_cov, n_uniq, cov = best_config
        print(f"  Best config: W={W} R0={R0} C0={C0} covered={n_cov} unique={n_uniq}", flush=True)
        print(f"  Covered K4 positions: {sorted(set(cov))[:20]}...", flush=True)

    if not results:
        print("  No near-complete coverages found. Showing stats.", flush=True)
        # Find configs with most coverage
        max_cov = 0
        for W in range(5, 34):
            nrows = math.ceil(97 / W)
            for R0 in range(0, 28 - nrows + 2):
                for C0 in range(0, 33 - W + 2):
                    covered = []
                    for r, c in HOLES:
                        k4_row = r - R0; k4_col = c - C0
                        if 0 <= k4_row < nrows and 0 <= k4_col < W:
                            k4_pos = k4_row * W + k4_col
                            if k4_pos < 97:
                                covered.append(k4_pos)
                    n_unique = len(set(covered))
                    if n_unique > max_cov:
                        max_cov = n_unique
                        if max_cov > 40:
                            print(f"    New max: W={W} R0={R0} C0={C0} unique={n_unique}", flush=True)

    valid = [r for r in results if r is not None]
    if valid:
        best = max(valid, key=lambda r: r.get('score', MISS))
        print(f"  T best: {best.get('label','?')} score={best.get('score', MISS):.3f}", flush=True)
    return results

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH U: TWO-KEYWORD APPROACH (KRYPTOS for scramble + other for cipher)
# ─────────────────────────────────────────────────────────────────────────────
def approach_U():
    print("\n" + "="*70, flush=True)
    print("APPROACH U: TWO-KEYWORD APPROACH", flush=True)
    print("="*70, flush=True)
    results = []

    # Kryptosfan: "Two keywords expected (one=KRYPTOS)"
    # One keyword for the scramble (transposition), one for the substitution cipher
    # Hypothesis: KRYPTOS is the columnar key for the scramble

    # U1: KRYPTOS as columnar transposition key for K4, then decrypt with other keywords
    kw_kryptos = 'KRYPTOS'  # length 7
    col_order_kryptos = sorted(range(7), key=lambda i: (kw_kryptos[i], i))
    print(f"  KRYPTOS col order: {col_order_kryptos}", flush=True)

    for W in [7, 14, 21]:  # multiples of 7 (KRYPTOS length)
        nrows = math.ceil(97 / W)
        padded = K4 + 'X' * (nrows * W - 97)
        grid_rows = [padded[r*W:(r+1)*W] for r in range(nrows)]

        # Standard columnar: write by rows, read by KRYPTOS-ordered columns
        if W == 7:
            candidate_ct = ''.join(grid_rows[r][c] for c in col_order_kryptos for r in range(nrows) if r*W + c < 97)
        elif W == 14:
            col_order_14 = sorted(range(14), key=lambda i: (kw_kryptos[i%7], i))
            candidate_ct = ''.join(grid_rows[r][c] for c in col_order_14 for r in range(nrows) if r*14 + c < 97)
        else:
            continue
        candidate_ct = ''.join(c for c in candidate_ct if c != 'X')[:97]
        if len(candidate_ct) == 97:
            r = test_ct(candidate_ct, f"U_kryptos_w{W}")
            results.append(r)

    # U2: PALIMPSEST as columnar key (10 chars)
    kw_pal = 'PALIMPSEST'  # length 10, has repeated P, S
    col_order_pal = sorted(range(10), key=lambda i: (kw_pal[i], i))
    print(f"  PALIMPSEST col order: {col_order_pal}", flush=True)

    for W in [10, 20]:
        nrows = math.ceil(97 / W)
        padded = K4 + 'X' * (nrows * W - 97)
        grid_rows = [padded[r*W:(r+1)*W] for r in range(nrows)]
        candidate_ct = ''.join(grid_rows[r][c] for c in col_order_pal
                               for r in range(nrows) if r*W + c < 97)
        candidate_ct = ''.join(c for c in candidate_ct if c != 'X')[:97]
        if len(candidate_ct) == 97:
            r = test_ct(candidate_ct, f"U_palimpsest_w{W}")
            results.append(r)

    # U3: ABSCISSA (8 chars), SHADOW (6 chars), etc.
    for kw, W_list in [('ABSCISSA', [8, 16]), ('SHADOW', [6, 12]), ('SCHEIDT', [7, 14]),
                        ('BERLINCLOCK', [11]), ('EASTNORTHEAST', [13])]:
        for W in W_list:
            if W > 33: continue
            nrows = math.ceil(97 / W)
            padded = K4 + 'X' * (nrows * W - 97)
            key_part = (kw * 3)[:W]
            col_order = sorted(range(W), key=lambda i: (key_part[i], i))
            candidate_ct = ''.join(K4[r*W + c] for c in col_order for r in range(nrows)
                                   if r*W + c < 97)
            candidate_ct = candidate_ct[:97]
            if len(candidate_ct) == 97:
                r = test_ct(candidate_ct, f"U_{kw[:8]}_w{W}")
                results.append(r)

    # U4: Use GRILLE EXTRACT as running key to scramble, then short keyword to decrypt
    # Hypothesis: scramble = grille-extract Vigenère of K4 → that gives real CT
    # Then: real CT → short keyword Vigenère → PT
    # So: PT = shortkey_dec(grille_vig(K4))
    for alpha_name, alpha, ai in [("AZ", AZ, AZI), ("KA", KA, KAI)]:
        n = len(alpha)
        # First apply grille as Vigenère key to K4
        G = GRILLE_EXTRACT[:97]
        gk = [ai.get(c, 0) for c in G]
        k4v = [ai.get(c, 0) for c in K4]
        for g_op in ['add', 'sub', 'beau']:
            if g_op == 'add':
                real_ct = ''.join(alpha[(k4v[i] + gk[i]) % n] for i in range(97))
            elif g_op == 'sub':
                real_ct = ''.join(alpha[(k4v[i] - gk[i]) % n] for i in range(97))
            else:
                real_ct = ''.join(alpha[(gk[i] - k4v[i]) % n] for i in range(97))

            # Now decrypt real_ct with short keywords
            for kw in KEYWORDS:
                for cname, cfn in CIPHERS:
                    pt = cfn(real_ct, kw)
                    if CRIB_ENE in pt or CRIB_BC in pt:
                        sc = qscore(pt)
                        print(f"  *** U4 HIT: {g_op}/{alpha_name} kw={kw} {cname}", flush=True)
                        print(f"      PT: {pt}", flush=True)
                        d = {'label': f'U4_{g_op}_{alpha_name}_{kw}_{cname}', 'pt': pt, 'score': sc}
                        HITS.append(d); save(d)

    valid = [r for r in results if r is not None]
    if valid:
        best = max(valid, key=lambda r: r.get('score', MISS))
        print(f"  U best: {best.get('label','?')} score={best.get('score', MISS):.3f}", flush=True)
    return results

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH V: BLOCK TRANSPOSITIONS (systematic block sizes)
# ─────────────────────────────────────────────────────────────────────────────
def approach_V():
    print("\n" + "="*70, flush=True)
    print("APPROACH V: BLOCK TRANSPOSITIONS (systematic block sizes)", flush=True)
    print("="*70, flush=True)
    results = []

    # For each block size b (2..20):
    # - Divide K4 into blocks of size b (last block may be shorter)
    # - Try all permutations of blocks (if feasible) or heuristic orderings
    for b in range(2, 21):
        nblocks = math.ceil(97 / b)
        # Construct blocks as lists of positions
        blocks = [list(range(i*b, min((i+1)*b, 97))) for i in range(nblocks)]
        n_blocks = len(blocks)
        print(f"  b={b}: {n_blocks} blocks, sizes {[len(bl) for bl in blocks[:5]]}...", flush=True)

        # V1: All permutations (only if feasible)
        if n_blocks <= 8:  # 8! = 40320 (feasible)
            for block_order in iperm(range(n_blocks)):
                perm = []
                for bi in block_order:
                    perm.extend(blocks[bi])
                if validate_perm(perm):
                    r = test_perm(perm, f"V_b{b}_order_{''.join(map(str,block_order))}")
                    results.append(r)
                    if r and (r.get('ene', -1) >= 0 or r.get('bc', -1) >= 0):
                        print(f"  *** V CRIB HIT: b={b} order={block_order}", flush=True)
        else:
            # V2: Selected orderings only
            # Reverse all blocks
            perm_rev = []
            for bi in range(n_blocks-1, -1, -1):
                perm_rev.extend(blocks[bi])
            if validate_perm(perm_rev):
                r = test_perm(perm_rev, f"V_b{b}_reversed")
                results.append(r)

            # Alternate-direction (boustrophedon of blocks)
            perm_bous = []
            for bi in range(n_blocks):
                if bi % 2 == 0:
                    perm_bous.extend(blocks[bi])
                else:
                    perm_bous.extend(reversed(blocks[bi]))
            if validate_perm(perm_bous):
                r = test_perm(perm_bous, f"V_b{b}_boustro")
                results.append(r)

            # Rotate blocks (shift by n_blocks//2)
            shift = n_blocks // 2
            shifted_order = list(range(shift, n_blocks)) + list(range(shift))
            perm_shift = []
            for bi in shifted_order:
                perm_shift.extend(blocks[bi])
            if validate_perm(perm_shift):
                r = test_perm(perm_shift, f"V_b{b}_shift{shift}")
                results.append(r)

            # Keyword-ordered blocks
            for kw in ['KRYPTOS', 'ABSCISSA']:
                key_part = (kw * 10)[:n_blocks]
                block_order = sorted(range(n_blocks), key=lambda i: (key_part[i], i))
                perm_kw = []
                for bi in block_order:
                    perm_kw.extend(blocks[bi])
                if validate_perm(perm_kw):
                    r = test_perm(perm_kw, f"V_b{b}_{kw[:4]}")
                    results.append(r)

    valid = [r for r in results if r is not None]
    if valid:
        best = max(valid, key=lambda r: r.get('score', MISS))
        print(f"  V best: {best.get('label','?')} score={best.get('score', MISS):.3f}", flush=True)
    return results

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH W: "8 LINES 73" INTERPRETATION
# kryptosfan: "Yellow pad: '8 Lines 73' (K4)"
# ─────────────────────────────────────────────────────────────────────────────
def approach_W():
    print("\n" + "="*70, flush=True)
    print("APPROACH W: '8 LINES 73' INTERPRETATIONS", flush=True)
    print("="*70, flush=True)
    results = []

    # Interpretation 1: K4 is written on 8 lines, 73 in something
    # 97 chars on 8 lines → average 12.125 chars per line
    # Possible: 8 lines with varying lengths summing to 97

    # Interpretation 2: The 73 non-doubled chars (97 - 24 = 73? No, 97 - 2×5 = 87 non-doubled positions)
    # Actually: K4 has 5 doubled pairs = 10 "doubled" chars, 87 single chars
    # Or: K4 has 24 "crib" chars (at the carved positions) and 73 "other" chars
    # 24 + 73 = 97 ✓

    # Interpretation 3: The 73 = carved positions 0-72 (positions 0 to 72 = 73 chars)
    # and positions 73-96 = 24 chars
    print(f"  K4[0:73] = {K4[0:73]}", flush=True)
    print(f"  K4[73:97] = {K4[73:97]}", flush=True)

    # Try splitting at position 73: first 73 chars + last 24 chars
    for swap_order in [[0, 1], [1, 0]]:
        parts = [K4[0:73], K4[73:97]]
        candidate_ct = ''.join(parts[i] for i in swap_order)
        r = test_ct(candidate_ct, f"W_split73_order_{''.join(map(str,swap_order))}")
        results.append(r)

    # Interpretation 4: 8 rows × some_width = 97 with last row having different length
    # Width 12: 8 lines × 12 = 96 + 1 = 97 chars → first 7 lines of 12, last line of 13
    # Width 13: 7 lines × 13 = 91 + 6 = 97 → 7 lines × 13 + 1 line of 6?
    # Width 11: 8 lines × 11 = 88 + 9 = 97 → 8 lines of 11 + 1 line of 9
    # Width 9: 10 lines × 9 = 90 + 7 = 97 → 10 × 9 + 7

    # For "8 lines":
    for W in range(5, 25):
        nrows = math.ceil(97 / W)
        if nrows != 8:
            # Try to find W such that exactly 8 rows
            continue
        # W such that ceil(97/W) = 8: 8*W >= 97 and 7*W < 97
        # 7W < 97 → W < 13.86 → W ≤ 13
        # 8W >= 97 → W >= 12.125 → W ≥ 13
        # So only W = 13 gives exactly 8 lines (8×13=104 ≥ 97, 7×13=91 < 97)

    # W=13, 8 lines:
    W = 13; nrows = 8
    padded = K4 + 'X' * (nrows * W - 97)  # 104 - 97 = 7 padding chars
    grid_rows = [padded[r*W:(r+1)*W] for r in range(nrows)]
    print(f"  W=13, 8 rows layout:", flush=True)
    for i, row in enumerate(grid_rows):
        print(f"    Row {i}: {row}", flush=True)

    # For 8-line layout, try all 8! = 40320 row permutations
    for row_order in iperm(range(nrows)):
        candidate_ct = ''.join(grid_rows[r] for r in row_order)
        candidate_ct = ''.join(c for c in candidate_ct if c != 'X')[:97]
        if len(candidate_ct) == 97:
            r = test_ct(candidate_ct, f"W_8row_w13_order_{''.join(map(str,row_order))}")
            results.append(r)
            if r and (r.get('ene', -1) >= 0 or r.get('bc', -1) >= 0):
                print(f"  *** W CRIB HIT (8 rows, w=13): order={row_order}", flush=True)
                break

    # Also try W=12 (which gives 9 rows, but maybe "8 lines" means something else)
    W = 12; nrows = math.ceil(97/W)
    padded = K4 + 'X' * (nrows * W - 97)
    grid_rows = [padded[r*W:(r+1)*W] for r in range(nrows)]
    print(f"\n  W=12, {nrows} rows:", flush=True)
    for i, row in enumerate(grid_rows):
        print(f"    Row {i}: {row}", flush=True)

    # For W=12 (9 rows), if "73" means skip row 0 (73 remaining chars):
    # Rows 1-8 = 8 rows × 12 chars = 96 chars... that's 96 not 73
    # Alternatively: the first 73 chars are on rows, the remaining 24 are different

    # Interpretation: 73 chars + 24 chars = two separate groups
    # The crib positions (24 chars total: 13 ENE + 11 BC = 24) = "8 Lines"
    # The 73 non-crib chars form the scrambled part
    # Maybe: 8 specific "lines" of the PT, and 73 tells us the length?

    valid = [r for r in results if r is not None]
    if valid:
        best = max(valid, key=lambda r: r.get('score', MISS))
        print(f"  W best: {best.get('label','?')} score={best.get('score', MISS):.3f}", flush=True)
    return results

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH X: TABLEAU PATH PERMUTATION
# ─────────────────────────────────────────────────────────────────────────────
def approach_X():
    print("\n" + "="*70, flush=True)
    print("APPROACH X: TABLEAU PATH PERMUTATION", flush=True)
    print("="*70, flush=True)
    results = []

    # The KA tableau has 26 rows × 26 cols (plus extended section)
    # Each cell contains a letter. K4's chars define a path through the tableau.
    # The path defines a permutation of 97 positions.

    # Build KA tableau as a 2D array
    # KA = 'KRYPTOSABCDEFGHIJLMNQUVWXZ'
    # Row i of tableau: shift KA by i positions (Vigenère style)
    tableau = []
    for i in range(26):
        row = KA[i:] + KA[:i]
        tableau.append(row)

    # X1: K4[i]'s position in KA row i gives next column
    # Follow: start at (row=0, col=0), each step: row = tableau row, col = KAI[K4[i]]
    for start_row in range(26):
        for start_col in range(26):
            path_positions = []
            seen_pairs = set()
            r, c = start_row, start_col
            for i in range(97):
                pair = (r, c)
                if pair in seen_pairs:
                    # Collision: jump to new start
                    r = (r + 7) % 26
                    c = (c + 11) % 26
                path_positions.append(r * 97 // 26 + c * 97 // (26*26))
                seen_pairs.add(pair)
                # Next: use K4[i] to update row/col
                k4_val = AZI.get(K4[i], 0)
                r = (r + k4_val) % 26
                c = tableau[r][k4_val] if kk4_val < 26 else c
            # This is getting complicated... skip for now

    # X2: Use K4's character sequence as a path through a 26-letter cycle
    # K4 → sequence of values v_0..v_96 (each in 0-25)
    # Path: p(0)=v_0, p(i) = (p(i-1) + v_i) % 97
    for alpha_name, alpha, ai in [("AZ", AZ, AZI), ("KA", KA, KAI)]:
        vals = [ai.get(c, 0) for c in K4]
        # Cumulative sum mod 97
        cumsum = []
        s = 0
        for v in vals:
            s = (s + v) % 97
            cumsum.append(s)
        perm = sorted(range(97), key=lambda i: cumsum[i])
        if validate_perm(perm):
            r = test_perm(perm, f"X_cumsum_path_{alpha_name}")
            results.append(r)

        # Multiplicative cumulative product mod 97
        cumprod = []
        p = 1
        for v in vals:
            if v == 0: v = 1
            p = (p * v) % 97
            cumprod.append(p)
        perm2 = sorted(range(97), key=lambda i: cumprod[i])
        if validate_perm(perm2):
            r = test_perm(perm2, f"X_cumprod_path_{alpha_name}")
            results.append(r)

    # X3: Use tableau lookup
    # K4[i] = c → look up c in KA tableau row (i%26) → get column position
    # This maps each K4 position to a tableau column
    col_vals = [KAI.get(K4[i], 0) for i in range(97)]
    # Scale to 0-96 range
    scaled = [(v * 97 // 26 + i // 4) % 97 for i, v in enumerate(col_vals)]
    perm_X3 = sorted(range(97), key=lambda i: scaled[i])
    if validate_perm(perm_X3):
        r = test_perm(perm_X3, "X_tableau_col_scaled")
        results.append(r)

    valid = [r for r in results if r is not None]
    if valid:
        best = max(valid, key=lambda r: r.get('score', MISS))
        print(f"  X best: {best.get('label','?')} score={best.get('score', MISS):.3f}", flush=True)
    return results

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH Y: EXTENDED KEYWORD SEARCH (more keywords + variant Beaufort)
# ─────────────────────────────────────────────────────────────────────────────
def approach_Y():
    print("\n" + "="*70, flush=True)
    print("APPROACH Y: EXTENDED KEYWORD SEARCH (K4 directly, more keywords)", flush=True)
    print("="*70, flush=True)

    # Test K4 directly (identity permutation) with many more keywords
    extended_keywords = [
        # Standard ones
        'KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW', 'SANBORN', 'SCHEIDT',
        'BERLIN', 'CLOCK', 'EAST', 'NORTH', 'LIGHT', 'ANTIPODES', 'MEDUSA',
        'ENIGMA', 'COMPASS', 'WELTZEITUHR', 'IQLUSION', 'ILLUSION', 'LAYER',
        # Additional
        'DIPTERA', 'KRYPTOS', 'MONUMENT', 'VIRTUAL', 'FORCES', 'AGENCY',
        'LANGLEY', 'BURIED', 'SECRETS', 'MESSAGE', 'ANCIENT', 'EGYPT',
        'CARTER', 'HOWARD', 'DISCOVERY', 'DECODED', 'PASSAGE', 'DOOR',
        'CANDLE', 'PEERED', 'CHAMBER', 'FLAME', 'FLICKER', 'DETAIL',
        'SLOWLY', 'REMAINS', 'DEBRIS', 'TREMBLING', 'BREACH', 'CORNER',
        # Berlin Clock specific
        'ZEITUHR', 'UHRTURM', 'ZERBST', 'TIERGARTEN',
        # JAMES SANBORN
        'JAMES', 'SANBORN', 'CIA', 'LANGLEY',
        # Geographic
        'THIRTYNINE', 'FIFTYSEVEN', 'DEGREES', 'MINUTES',
        # Kryptos variants
        'IQLUSION', 'ILLUSION', 'DIGETAL',
    ]
    extended_keywords = list(dict.fromkeys(extended_keywords))

    # Check K4 directly
    for kw in extended_keywords:
        # Filter to only valid chars
        kw_clean = ''.join(c for c in kw if c in AZ)
        if len(kw_clean) < 2:
            continue
        for alpha_name, alpha, ai in [("AZ", AZ, AZI), ("KA", KA, KAI)]:
            for cipher_name in ['vig', 'beau']:
                if cipher_name == 'vig':
                    n = len(alpha)
                    ki = [ai.get(c, 0) for c in kw_clean]
                    pt = ''.join(alpha[(ai.get(K4[i], 0) - ki[i % len(ki)]) % n] for i in range(97))
                else:
                    n = len(alpha)
                    ki = [ai.get(c, 0) for c in kw_clean]
                    pt = ''.join(alpha[(ki[i % len(ki)] - ai.get(K4[i], 0)) % n] for i in range(97))

                ene = pt.find(CRIB_ENE)
                bc  = pt.find(CRIB_BC)
                if ene >= 0 or bc >= 0:
                    sc = qscore(pt)
                    print(f"  *** Y DIRECT HIT: kw={kw_clean} {cipher_name}/{alpha_name} ENE@{ene} BC@{bc}", flush=True)
                    print(f"      PT: {pt}", flush=True)
                    d = {'label': f'Y_direct_{kw_clean}_{cipher_name}_{alpha_name}',
                         'kw': kw_clean, 'cipher': cipher_name, 'alpha': alpha_name,
                         'ene': ene, 'bc': bc, 'pt': pt, 'score': sc}
                    HITS.append(d); save(d)

    print(f"  Y: Tested {len(extended_keywords)} extended keywords on K4 directly.", flush=True)

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH Z: SYSTEMATIC CRIB PLACEMENT + SA-LIKE NEIGHBORHOOD SEARCH
# ─────────────────────────────────────────────────────────────────────────────
def approach_Z():
    print("\n" + "="*70, flush=True)
    print("APPROACH Z: SYSTEMATIC CRIB PLACEMENT SEARCH", flush=True)
    print("="*70, flush=True)

    # For each keyword and cipher, and each plausible (ene_pos, bc_pos) pair:
    # - Compute what the real_CT must look like at those positions
    # - Check if K4 contains a subset of those chars
    # - If yes, try to build a permutation via constraint propagation

    # The M3 approach in wildcard.py found many "potential matches"
    # Here we go deeper: actually try to construct a valid permutation
    # from those constraints

    hits_Z = []
    for kw in ['KRYPTOS', 'ABSCISSA', 'PALIMPSEST']:
        for alpha_name, alpha, ai in [("AZ", AZ, AZI), ("KA", KA, KAI)]:
            n = len(alpha)
            ki = [ai.get(c, 0) for c in kw]

            for ene_start in range(85):  # ENE at positions 0..84 of PT
                # Compute required real_CT chars at positions ene_start..ene_start+12
                needed_ene = [(ene_start + j, (ai.get(CRIB_ENE[j], 0) + ki[(ene_start+j) % len(ki)]) % n)
                               for j in range(13)]
                needed_ene_chars = [alpha[v] for _, v in needed_ene]

                # Check: all needed_ene_chars available in K4?
                k4_cnt = Counter(K4)
                needed_cnt = Counter(needed_ene_chars)
                if not all(k4_cnt.get(c, 0) >= needed_cnt[c] for c in needed_cnt):
                    continue

                for bc_start in range(86):
                    if abs(bc_start - ene_start) < 13:
                        continue  # overlap with ENE
                    # Compute needed BC chars
                    needed_bc = [(bc_start + j, (ai.get(CRIB_BC[j], 0) + ki[(bc_start+j) % len(ki)]) % n)
                                  for j in range(11)]
                    needed_bc_chars = [alpha[v] for _, v in needed_bc]

                    # Check combined availability
                    both_cnt = Counter(needed_ene_chars + needed_bc_chars)
                    if not all(k4_cnt.get(c, 0) >= both_cnt[c] for c in both_cnt):
                        continue

                    # We have a feasible pair! Constraint propagation:
                    # - Positions [ene_start..ene_start+12] of PT map to specific real_CT chars
                    # - Positions [bc_start..bc_start+10] of PT map to specific real_CT chars
                    # - K4 must be PERMUTED to achieve this

                    # Build partial assignment:
                    # perm[pt_pos] = k4_pos (which K4 position has the required char)
                    assignment = {}  # pt_position → k4_position

                    # For ENE positions:
                    all_positions = list(range(13)) + []  # ENE positions
                    needed_positions = [(ene_start + j, needed_ene_chars[j]) for j in range(13)]
                    needed_positions += [(bc_start + j, needed_bc_chars[j]) for j in range(11)]

                    # Try to assign K4 positions to satisfy constraints
                    # Sort K4 positions by character availability
                    available_k4 = list(range(97))  # all K4 positions
                    assigned_k4 = set()
                    valid = True

                    for pt_pos, required_char in needed_positions:
                        # Find an available K4 position with required_char
                        found = False
                        for k4_p in available_k4:
                            if k4_p not in assigned_k4 and K4[k4_p] == required_char:
                                assignment[pt_pos] = k4_p
                                assigned_k4.add(k4_p)
                                found = True
                                break
                        if not found:
                            valid = False
                            break

                    if not valid:
                        continue

                    # We have a partial assignment! Build full permutation:
                    # Remaining K4 positions go to remaining PT positions
                    remaining_k4 = [p for p in range(97) if p not in assigned_k4]
                    remaining_pt = [p for p in range(97) if p not in assignment]
                    assert len(remaining_k4) == len(remaining_pt)

                    # Fill in order
                    for pt_pos, k4_pos in zip(remaining_pt, remaining_k4):
                        assignment[pt_pos] = k4_pos

                    # Build permutation: perm[pt_pos] = k4_pos
                    # So real_CT[pt_pos] = K4[perm[pt_pos]]
                    # But our test_perm expects: real_CT[i] = K4[perm[i]]
                    # So perm[i] should give which K4 position goes to real_CT position i
                    perm = [assignment[i] for i in range(97)]

                    if validate_perm(perm):
                        label = f"Z_{kw}_{alpha_name}_e{ene_start}_b{bc_start}"
                        r = test_perm(perm, label)
                        if r and (r.get('ene', -1) >= 0 or r.get('bc', -1) >= 0):
                            print(f"  *** Z CRIB HIT: {label}", flush=True)
                            hits_Z.append(r)

    print(f"  Z: Done. Found {len(hits_Z)} crib hits.", flush=True)
    return hits_Z

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print(f"\nK4: {K4}", flush=True)
    print(f"HOLES: {len(HOLES)}", flush=True)
    t_start = time.time()

    all_results = []
    for approach_fn, name in [
        (approach_Q, "Q: Affine Permutations"),
        (approach_R, "R: T-Separator Strips"),
        (approach_S, "S: 91-non-T in 7×13 Grid"),
        (approach_T, "T: Grille Overlay on K4 Grid"),
        (approach_U, "U: Two-Keyword Approach"),
        (approach_V, "V: Block Transpositions"),
        (approach_W, "W: 8-Lines 73 Interpretations"),
        (approach_X, "X: Tableau Path Permutation"),
        (approach_Y, "Y: Extended Keyword Search"),
        (approach_Z, "Z: Systematic Crib Placement"),
    ]:
        try:
            t0 = time.time()
            res = approach_fn()
            elapsed = time.time() - t0
            if res:
                all_results.extend(r for r in res if r is not None)
            print(f"\n  [{name}] Done in {elapsed:.1f}s, total tested: {total_tested}", flush=True)
        except Exception as e:
            print(f"\n  [{name}] ERROR: {e}", flush=True)
            import traceback
            traceback.print_exc()

    elapsed_total = time.time() - t_start
    print("\n" + "="*70, flush=True)
    print(f"DONE — Total time: {elapsed_total:.1f}s", flush=True)
    print(f"Total unique CTs tested: {total_tested}", flush=True)
    print(f"CRIB HITS: {len(HITS)}", flush=True)

    if HITS:
        print("\n*** CRIB HITS SUMMARY ***", flush=True)
        for h in HITS:
            print(f"  {h}", flush=True)
    else:
        valid = [r for r in all_results if r is not None and 'score' in r]
        if valid:
            top = sorted(valid, key=lambda r: r['score'], reverse=True)[:10]
            print(f"\nTop 10 results:", flush=True)
            for r in top:
                print(f"  {r.get('label','?')}: score={r['score']:.3f} key={r.get('key','?')}", flush=True)
                print(f"    PT: {r.get('pt','?')}", flush=True)

    RF.close()
    print(f"\nResults saved to blitz_results/wildcard2/results.jsonl", flush=True)
