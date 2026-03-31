#!/usr/bin/env python3
"""
E-RAW97-NONSTANDARD: Focused sweep on raw 97-char K4 with NO null mask,
testing non-standard transpositions × autokey/Q2 ciphers × thematic keywords.

This is the least-explored territory: the standard transposition families
were exhaustively tested with periodic sub (~1.2B configs), but autokey
and Q2 autokey with non-standard transpositions have NOT been systematically
tested on raw 97.

Transpositions:
  - Serpentine (widths 5-19, horiz + vertical)
  - Spiral (widths 5-15, CW + CCW)
  - Myszkowski (with thematic keywords that have repeated letters)
  - Rail fence (depths 2-15)
  - Columnar (widths 5-19, natural order — already partially tested but
    not with all keywords)
  - Double columnar (col A then col B)
  - Reversed columnar (read columns backwards)

Ciphers:
  - Autokey Vig/Beau (AZ, KA)
  - Quagmire II Autokey (indicator K, A, T, O, S)
  - Standard Vig/Beau (for comparison)

Keywords: 40 thematic + cable-format inspired

Cipher: raw97-nonstandard
Family: substitution
Status: active
Keyspace: ~200K configs
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md


import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CRIB_DICT

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

def score(pt):
    s = sorted(CRIB_DICT.keys())
    ene_p, bc_p = s[:13], s[13:]
    ene = sum(1 for p in ene_p if p < len(pt) and pt[p] == CRIB_DICT[p])
    bc = sum(1 for p in bc_p if p < len(pt) and pt[p] == CRIB_DICT[p])
    return ene + bc, ene, bc

# --- Ciphers ---
def vig(ct, key, a):
    return "".join(a[(a.index(c) - a.index(key[i%len(key)])) % 26] for i, c in enumerate(ct))
def beau(ct, key, a):
    return "".join(a[(a.index(key[i%len(key)]) - a.index(c)) % 26] for i, c in enumerate(ct))
def avig(ct, key, a):
    pt, fk = [], list(key)
    for i, c in enumerate(ct):
        p = (a.index(c) - a.index(fk[i])) % 26
        pt.append(a[p]); fk.append(a[p])
    return "".join(pt)
def abeau(ct, key, a):
    pt, fk = [], list(key)
    for i, c in enumerate(ct):
        p = (a.index(fk[i]) - a.index(c)) % 26
        pt.append(a[p]); fk.append(a[p])
    return "".join(pt)

def q2auto(ct, key, indicator):
    """Quagmire II Autokey: KA body, AZ key indexing, PT feedback."""
    ind_pos = KA.index(indicator) if indicator in KA else 0
    pt, fk = [], list(key)
    for i, c in enumerate(ct):
        ci = KA.index(c)
        ki = AZ.index(fk[i])
        p_idx = (ci - ki + ind_pos) % 26
        p_char = KA[p_idx]
        pt.append(p_char)
        fk.append(p_char)
    return "".join(pt)

# --- Transpositions ---
def col_undo(ct, w):
    n = len(ct); rows = -(-n // w); rem = n % w
    r = [''] * n; pos = 0
    for c in range(w):
        cl = rows if (rem == 0 or c < rem) else rows - 1
        for row in range(cl):
            r[row * w + c] = ct[pos]; pos += 1
    return "".join(r)

def col_undo_reverse(ct, w):
    """Columnar with reversed column read order."""
    n = len(ct); rows = -(-n // w); rem = n % w
    r = [''] * n; pos = 0
    for c in range(w - 1, -1, -1):
        cl = rows if (rem == 0 or c < rem) else rows - 1
        for row in range(cl):
            r[row * w + c] = ct[pos]; pos += 1
    return "".join(r)

def rail_undo(ct, depth):
    n = len(ct)
    if depth <= 1 or depth >= n: return ct
    rl = [0] * depth; rail = 0; d = 1
    for _ in range(n):
        rl[rail] += 1
        if rail == 0: d = 1
        elif rail == depth - 1: d = -1
        rail += d
    rails = []; pos = 0
    for r in range(depth):
        rails.append(ct[pos:pos+rl[r]]); pos += rl[r]
    result = []; indices = [0]*depth; rail = 0; d = 1
    for _ in range(n):
        result.append(rails[rail][indices[rail]]); indices[rail] += 1
        if rail == 0: d = 1
        elif rail == depth - 1: d = -1
        rail += d
    return "".join(result)

def serpentine_undo(ct, w, vertical=False):
    n = len(ct); rows = -(-n // w)
    perm = []
    if not vertical:
        for r in range(rows):
            if r % 2 == 0:
                for c in range(w):
                    p = r * w + c
                    if p < n: perm.append(p)
            else:
                for c in range(w - 1, -1, -1):
                    p = r * w + c
                    if p < n: perm.append(p)
    else:
        for c in range(w):
            if c % 2 == 0:
                for r in range(rows):
                    p = r * w + c
                    if p < n: perm.append(p)
            else:
                for r in range(rows - 1, -1, -1):
                    p = r * w + c
                    if p < n: perm.append(p)
    # Undo: result[perm[i]] = ct[i]
    result = [''] * n
    for i, p in enumerate(perm):
        if i < len(ct):
            result[p] = ct[i]
    return "".join(result)

def spiral_undo(ct, w, ccw=False):
    n = len(ct); rows = -(-n // w)
    visited = [[False]*w for _ in range(rows)]
    dirs = [(0,1),(1,0),(0,-1),(-1,0)] if not ccw else [(1,0),(0,1),(-1,0),(0,-1)]
    perm = []
    r, c, d = 0, 0, 0
    for _ in range(rows * w):
        p = r * w + c
        if p < n: perm.append(p)
        visited[r][c] = True
        nr, nc = r + dirs[d][0], c + dirs[d][1]
        if 0 <= nr < rows and 0 <= nc < w and not visited[nr][nc]:
            r, c = nr, nc
        else:
            d = (d + 1) % 4
            nr, nc = r + dirs[d][0], c + dirs[d][1]
            if 0 <= nr < rows and 0 <= nc < w and not visited[nr][nc]:
                r, c = nr, nc
            else:
                break
    result = [''] * n
    for i, p in enumerate(perm):
        if i < len(ct):
            result[p] = ct[i]
    return "".join(result)

def myszkowski_undo(ct, keyword):
    kw = keyword.upper()
    w = len(kw); n = len(ct); rows = -(-n // w)
    # Rank with ties
    unique = sorted(set(kw))
    rank = {ch: i for i, ch in enumerate(unique)}
    col_ranks = [rank[ch] for ch in kw]
    # Group by rank
    rank_to_cols = {}
    for ci, rk in enumerate(col_ranks):
        rank_to_cols.setdefault(rk, []).append(ci)
    # Build perm
    perm = []
    for rk in sorted(rank_to_cols):
        tied = rank_to_cols[rk]
        if len(tied) == 1:
            for row in range(rows):
                p = row * w + tied[0]
                if p < n: perm.append(p)
        else:
            for row in range(rows):
                for tc in tied:
                    p = row * w + tc
                    if p < n: perm.append(p)
    result = [''] * n
    for i, p in enumerate(perm):
        if i < len(ct):
            result[p] = ct[i]
    return "".join(result)

def double_col_undo(ct, w1, w2):
    """Double columnar: undo col w2 first, then undo col w1."""
    return col_undo(col_undo(ct, w2), w1)

# --- Build transposition list ---
TRANSPOSITIONS = []

# Columnar (widths 5-19)
for w in range(5, 20):
    TRANSPOSITIONS.append((f"col{w}", lambda ct, w=w: col_undo(ct, w)))
    TRANSPOSITIONS.append((f"colrev{w}", lambda ct, w=w: col_undo_reverse(ct, w)))

# Serpentine
for w in range(5, 16):
    TRANSPOSITIONS.append((f"serp{w}", lambda ct, w=w: serpentine_undo(ct, w)))
    TRANSPOSITIONS.append((f"serpV{w}", lambda ct, w=w: serpentine_undo(ct, w, vertical=True)))

# Spiral
for w in range(5, 14):
    TRANSPOSITIONS.append((f"spiral{w}", lambda ct, w=w: spiral_undo(ct, w)))
    TRANSPOSITIONS.append((f"spiralCCW{w}", lambda ct, w=w: spiral_undo(ct, w, ccw=True)))

# Rail fence
for d in range(2, 16):
    TRANSPOSITIONS.append((f"rail{d}", lambda ct, d=d: rail_undo(ct, d)))

# Myszkowski with thematic keywords (must have repeated letters)
MYSZ_KEYS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "ASSESS", "COPPER",
             "ASSES", "ATTACK", "CASSETTE", "PALLOR", "COFFEE",
             "BABOON", "TATTOO", "MAMMAL", "PUPPET", "ARRIVE"]
for mk in MYSZ_KEYS:
    TRANSPOSITIONS.append((f"mysz_{mk}", lambda ct, mk=mk: myszkowski_undo(ct, mk)))

# Double columnar (small widths)
for w1 in [5, 7, 8, 9]:
    for w2 in [5, 7, 8, 9, 11]:
        if w1 != w2:
            TRANSPOSITIONS.append((f"dcol{w1}x{w2}", lambda ct, w1=w1, w2=w2: double_col_undo(ct, w1, w2)))

# No transposition
TRANSPOSITIONS.append(("none", lambda ct: ct))

print(f"Total transpositions: {len(TRANSPOSITIONS)}")

# --- Keywords ---
KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "KOMPASS",
    "COLOPHON", "SHADOW", "INVISIBLE", "COPPER", "HIDDEN",
    "SECRET", "LANGLEY", "OLYMPUS", "MERCURY", "PHOENIX",
    "HANDLER", "POSITION", "LAYERTWO", "BERLINCLOCK", "POINT",
    "NORTHEAST", "COMPASS", "REPORT", "SIGNAL", "CABLE",
    "TELEGRAM", "CENTRAL", "AGENCY", "MOLE", "ENIGMA",
    "MASQUERADE", "DEADDROP", "WONDERFUL", "TREASURE", "PHARAOH",
    "CANOPIC", "LUCID", "FORCES", "VIRTUAL", "DIGETAL",
]

# --- Cipher configs ---
CIPHERS = [
    ("avig_AZ", lambda ct, k: avig(ct, k, AZ)),
    ("abeau_AZ", lambda ct, k: abeau(ct, k, AZ)),
    ("avig_KA", lambda ct, k: avig(ct, k, KA)),
    ("abeau_KA", lambda ct, k: abeau(ct, k, KA)),
    ("vig_AZ", lambda ct, k: vig(ct, k, AZ)),
    ("beau_AZ", lambda ct, k: beau(ct, k, AZ)),
    ("vig_KA", lambda ct, k: vig(ct, k, KA)),
    ("beau_KA", lambda ct, k: beau(ct, k, KA)),
]

# Q2 autokey with different indicators
Q2_INDICATORS = ["K", "A", "T", "O", "S", "Z"]
for ind in Q2_INDICATORS:
    CIPHERS.append((f"q2auto_{ind}", lambda ct, k, ind=ind: q2auto(ct, k, ind)))

print(f"Keywords: {len(KEYWORDS)}")
print(f"Ciphers: {len(CIPHERS)}")
total = len(TRANSPOSITIONS) * len(KEYWORDS) * len(CIPHERS)
print(f"Total configs: {total:,}")
print("=" * 70)

results = []
tested = 0
milestone = 50000

for tn, tf in TRANSPOSITIONS:
    try:
        wct = tf(CT)
    except:
        continue
    if len(wct) != 97:
        continue
    for kw in KEYWORDS:
        for cn, cf in CIPHERS:
            try:
                pt = cf(wct, kw)
            except:
                continue
            tested += 1
            s, ene, bc = score(pt)
            if s >= 7:
                results.append((s, ene, bc, f"{tn}+{kw}:{cn}", pt[:50]))
            if tested % milestone == 0:
                print(f"  ...{tested:,} tested, {len(results)} hits >= 7")

results.sort(key=lambda x: (-x[0], -x[1]))

print(f"\n{'='*70}")
print(f"TOTAL TESTED: {tested:,}")
print(f"SCORES >= 7: {len(results)}")
print(f"{'='*70}")

if results:
    print("\nTOP 30:")
    print("-" * 70)
    seen = set()
    shown = 0
    for s, ene, bc, desc, pt in results:
        if shown >= 30:
            break
        # Deduplicate by score+PT prefix
        key = (s, pt[:20])
        if key in seen:
            continue
        seen.add(key)
        print(f"  {s:2d}/24 (ene={ene:2d}/13 bc={bc:2d}/11) {desc}")
        print(f"      PT: {pt}...")
        shown += 1
    print("-" * 70)

    best = results[0]
    if best[0] >= 13:
        print(f"\n*** MATCHES CURRENT CEILING ({best[0]}/24) — INVESTIGATE ***")
    elif best[0] >= 10:
        print(f"\n*** ABOVE NOISE ({best[0]}/24) — INVESTIGATE ***")
    elif best[0] >= 8:
        print(f"\nBest: {best[0]}/24 — slightly above noise. Worth noting.")
    else:
        print(f"\nBest: {best[0]}/24 — noise floor.")
else:
    print("\nNo results >= 7. All noise.")
