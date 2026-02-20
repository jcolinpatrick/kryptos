#!/usr/bin/env python3
"""
E-S-71: Seriated Key Generation + Width-7 Columnar

"Coding charts" could be a key generation grid: write a key text (phrase,
sentence, or keyword) into a W×H grid, then read off the key in a different
order. This produces a non-periodic key from a structured source.

Key generation methods:
1. Write keyword/phrase into a grid, read off columns in keyword order
2. Read off in spiral, diagonal, snake patterns
3. Multiple passes through the grid with different patterns

Combined with width-7 columnar transposition (Model B).

This is distinct from E-S-68 which used small grids (3-10 columns).
Here we test grids sized to produce exactly 97 key chars (7×14, 97×1, etc.)
using LONGER key texts (full phrases/sentences).
"""

import json
import os
import sys
import time
from itertools import permutations

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)  # 97
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
IDX = {c: i for i, c in enumerate(AZ)}
CT_IDX = [IDX[c] for c in CT]

CRIB_DICT = {
    21: 'E', 22: 'A', 23: 'S', 24: 'T', 25: 'N', 26: 'O', 27: 'R',
    28: 'T', 29: 'H', 30: 'E', 31: 'A', 32: 'S', 33: 'T',
    63: 'B', 64: 'E', 65: 'R', 66: 'L', 67: 'I', 68: 'N', 69: 'C',
    70: 'L', 71: 'O', 72: 'C', 73: 'K'
}

WIDTH = 7
COL_LENS = [14, 14, 14, 14, 14, 14, 13]

# Key phrases — longer texts that could be "coding charts"
KEY_PHRASES = [
    # Kryptos-related
    "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION",
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLE",
    "THEYUSEDTHEEARTHSMAGNETICFIELD",
    "THEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATION",
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRIS",
    "CANYOUSEEANYTHING",
    "WHATSTHEPOINT",
    "DELIVERINGAMESSAGE",
    "VIRTUALLYINVISIBLE",

    # CIA-related
    "CENTRALINTELLIGENCEAGENCY",
    "ANDYESHALLKNOWTHETRUTHANDTHETRUTHSHALLMAKEYOUFREE",
    "NATIONALSECULITYACT",
    "THEAGENCYSHALLHAVENOLAW",
    "DIRECTORCENTRALINTELLIGENCE",

    # Historical
    "ICHBINEINBERLINER",
    "MRGORBUACHEVTEARDOWNTHISWALL",
    "THETOMBOFTUTANKHAMUN",
    "WONDERFULTHINGSIWONDERFULTHINGS",
    "THEFALLOFTHEBERLINWALL",
    "HOWARDCARTER",
    "VALLEYOFTHEKINGS",
    "ATFIRSTICOULDSEENOTHING",

    # Kryptos keywords combined
    "KRYPTOSPALIMPSESTABSCISSA",
    "PALIMPSESTKRYPTOSABSCISSA",
    "ABSCISSAKRYPTOSPALIMPSEST",
    "KRYPTOSSHADOWLUCID",
    "SHADOWFORCESINTELLIGENCE",
    "THEPOINTISTHEQUESTION",
    "WHATISTHEPOINT",

    # Coordinates
    "THIRTYEIGHTDEGREESNINEMINUTESFIFTYSEVENSECONDSNNORTH",
    "SEVENTYSEVENDEGREEEIGHTMINUTESFOURTYFOURSECONDSWWEST",
    "NORTHLATITUDEWESTLONGITUDE",

    # K1-K3 combined PT
    "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSIONITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLE",
]

# Also generate key phrases from K1-K3 plaintexts
K1 = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K2 = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERE"
K3 = "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISOUTTHETYPPEROPPENINODTHEDOORWAYWIDEDANDCHAMBERANDBYLIGHTOFDACANMADEOUTNOTHINGTHEHOTAIRFLORWARDANDTHEFLAMEFLICKEREDAWHOLEEVERYTHINGOKCANXOUVSEEANYTYHING"

KEY_PHRASES.extend([K1, K2, K3, K1+K2, K2+K3, K1+K2+K3])

print("=" * 70)
print("E-S-71: Seriated Key Generation + Width-7 Columnar")
print("=" * 70)
print(f"Key phrases: {len(KEY_PHRASES)}")

crib_items = list(CRIB_DICT.items())

def check_cribs(key, var_sign=1, inv_perm=None):
    cribs = 0
    for p, expected in crib_items:
        j = inv_perm[p] if inv_perm else p
        kv = key[j % len(key)]
        ct_v = CT_IDX[j]
        pt_v = (ct_v - var_sign * kv) % 26
        if AZ[pt_v] == expected:
            cribs += 1
    return cribs

def build_inv_perm(order):
    inv_perm = [0] * N
    pos = 0
    for grid_col in order:
        for row in range(COL_LENS[grid_col]):
            pt_pos = row * WIDTH + grid_col
            inv_perm[pt_pos] = pos
            pos += 1
    return inv_perm

def grid_readings(text_idx, rows, cols):
    """Read text arranged in rows×cols grid in different patterns."""
    total = rows * cols
    if len(text_idx) < total:
        text_idx = text_idx + [0] * (total - len(text_idx))

    grid = [[text_idx[r * cols + c] for c in range(cols)] for r in range(rows)]

    readings = {}

    # Column-major (transposition key)
    readings['col_major'] = [grid[r][c] for c in range(cols) for r in range(rows)]

    # Snake
    snake = []
    for r in range(rows):
        row = grid[r] if r % 2 == 0 else list(reversed(grid[r]))
        snake.extend(row)
    readings['snake'] = snake

    # Spiral clockwise
    spiral = []
    t, b, l, rr = 0, rows-1, 0, cols-1
    while t <= b and l <= rr:
        for c in range(l, rr+1): spiral.append(grid[t][c])
        t += 1
        for r in range(t, b+1): spiral.append(grid[r][rr])
        rr -= 1
        if t <= b:
            for c in range(rr, l-1, -1): spiral.append(grid[b][c])
            b -= 1
        if l <= rr:
            for r in range(b, t-1, -1): spiral.append(grid[r][l])
            l += 1
    readings['spiral'] = spiral

    # Diagonal
    diag = []
    for d in range(rows + cols - 1):
        for r in range(rows):
            c = d - r
            if 0 <= c < cols:
                diag.append(grid[r][c])
    readings['diagonal'] = diag

    # Anti-diagonal
    adiag = []
    for d in range(rows + cols - 1):
        for r in range(rows):
            c = (cols - 1) - (d - r)
            if 0 <= c < cols:
                adiag.append(grid[r][c])
    readings['anti_diagonal'] = adiag

    # Column-major with column permutations (using keyword)
    # We'll add columnar transpositions separately

    return readings

# ── Phase 1: Direct application (key from grid reading) ───────────────────
print("\n" + "-" * 50)
print("Phase 1: Seriated key (grid reading), direct application")
print("-" * 50)

best_p1 = {'cribs': 0}
configs_p1 = 0
t0 = time.time()

grid_dims = [(7, 14), (14, 7), (10, 10), (5, 20), (20, 5), (97, 1), (1, 97)]

for phrase in KEY_PHRASES:
    phrase_idx = [IDX[c] for c in phrase if c in AZ]
    if not phrase_idx:
        continue

    for rows, cols in grid_dims:
        # Pad or truncate phrase to fill grid
        total = rows * cols
        extended = (phrase_idx * ((total // len(phrase_idx)) + 1))[:total]

        readings = grid_readings(extended, rows, cols)

        for rname, key_vals in readings.items():
            key = key_vals[:N]
            if len(key) < N:
                key = key + [0] * (N - len(key))

            for var_sign in (1, -1):
                cribs = check_cribs(key, var_sign)
                configs_p1 += 1
                if cribs > best_p1['cribs']:
                    vname = 'vig' if var_sign == 1 else 'beau'
                    best_p1 = {'cribs': cribs, 'phrase': phrase[:30], 'grid': f'{rows}x{cols}',
                               'reading': rname, 'variant': vname}
                    if cribs >= 8:
                        print(f"  {cribs}/24 {phrase[:20]}... {rows}x{cols} {rname} {vname}")

t1 = time.time()
print(f"  {configs_p1:,} configs, {t1-t0:.1f}s, best={best_p1['cribs']}/24")

# ── Phase 2: Columnar reading of key grid ──────────────────────────────────
print("\n" + "-" * 50)
print("Phase 2: Columnar transposition of key grid")
print("-" * 50)

best_p2 = {'cribs': 0}
configs_p2 = 0
t2 = time.time()

for phrase in KEY_PHRASES:
    phrase_idx = [IDX[c] for c in phrase if c in AZ]
    if not phrase_idx:
        continue

    for key_width in [5, 7, 10]:
        key_rows = (N + key_width - 1) // key_width
        total = key_rows * key_width
        extended = (phrase_idx * ((total // len(phrase_idx)) + 1))[:total]

        # Write into grid, read columns in all orderings
        grid = [[extended[r * key_width + c] for c in range(key_width)] for r in range(key_rows)]

        for key_order in permutations(range(key_width)):
            key = []
            for c in key_order:
                for r in range(key_rows):
                    idx = r * key_width + c
                    if idx < total:
                        key.append(extended[idx])
            key = key[:N]
            if len(key) < N:
                key = key + [0] * (N - len(key))

            # Direct
            for var_sign in (1, -1):
                cribs = check_cribs(key, var_sign)
                configs_p2 += 1
                if cribs > best_p2['cribs']:
                    vname = 'vig' if var_sign == 1 else 'beau'
                    best_p2 = {'cribs': cribs, 'phrase': phrase[:30], 'key_width': key_width,
                               'key_order': list(key_order), 'variant': vname}
                    if cribs >= 8:
                        print(f"  {cribs}/24 {phrase[:20]}... kw={key_width} ko={list(key_order)} {vname}")

        if time.time() - t2 > 300:
            break
    if time.time() - t2 > 300:
        print(f"  Phase 2 timeout after {phrase[:20]}...")
        break

t3 = time.time()
print(f"  {configs_p2:,} configs, {t3-t2:.1f}s, best={best_p2['cribs']}/24")

# ── Phase 3: Seriated key + width-7 columnar transposition ────────────────
print("\n" + "-" * 50)
print("Phase 3: Seriated key + width-7 columnar (Model B)")
print("-" * 50)

best_p3 = {'cribs': 0}
configs_p3 = 0
t4 = time.time()

# Test only the most promising grid dimensions and key phrases
for phrase in KEY_PHRASES[:20]:
    phrase_idx = [IDX[c] for c in phrase if c in AZ]
    if not phrase_idx:
        continue

    for rows, cols in [(7, 14), (14, 7)]:
        total = rows * cols
        extended = (phrase_idx * ((total // len(phrase_idx)) + 1))[:total]
        readings = grid_readings(extended, rows, cols)

        for rname, key_vals in readings.items():
            key = key_vals[:N]
            if len(key) < N:
                key = key + [0] * (N - len(key))

            for ct_order in permutations(range(WIDTH)):
                inv_perm = build_inv_perm(ct_order)
                for var_sign in (1, -1):
                    cribs = check_cribs(key, var_sign, inv_perm)
                    configs_p3 += 1
                    if cribs > best_p3['cribs']:
                        vname = 'vig' if var_sign == 1 else 'beau'
                        best_p3 = {'cribs': cribs, 'phrase': phrase[:30],
                                   'grid': f'{rows}x{cols}', 'reading': rname,
                                   'variant': vname, 'ct_order': list(ct_order)}
                        if cribs >= 10:
                            print(f"  ** HIT: {cribs}/24 {phrase[:20]}... {rows}x{cols} {rname} {vname} ct={list(ct_order)}")

        if time.time() - t4 > 600:
            break
    if time.time() - t4 > 600:
        print(f"  Phase 3 timeout after {phrase[:20]}...")
        break

t5 = time.time()
print(f"  {configs_p3:,} configs, {t5-t4:.1f}s, best={best_p3['cribs']}/24")

# ── Summary ────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  Phase 1 (grid reading, direct): best {best_p1['cribs']}/24 — {best_p1}")
print(f"  Phase 2 (columnar key grid, direct): best {best_p2['cribs']}/24 — {best_p2}")
print(f"  Phase 3 (seriated key + w7): best {best_p3['cribs']}/24 — {best_p3}")

max_cribs = max(best_p1['cribs'], best_p2['cribs'], best_p3['cribs'])
if max_cribs >= 18:
    verdict = f"SIGNAL — {max_cribs}/24"
elif max_cribs >= 10:
    verdict = f"WEAK SIGNAL — {max_cribs}/24"
else:
    verdict = f"NO SIGNAL — best {max_cribs}/24"

print(f"\n  Verdict: {verdict}")
total = configs_p1 + configs_p2 + configs_p3
print(f"  Total configs: {total:,}")

output = {
    'experiment': 'E-S-71',
    'description': 'Seriated key generation + width-7 columnar',
    'phase1': best_p1,
    'phase2': best_p2,
    'phase3': best_p3,
    'verdict': verdict,
    'total_configs': total,
}
os.makedirs("results", exist_ok=True)
with open("results/e_s_71_seriated_key.json", "w") as f:
    json.dump(output, f, indent=2)
print(f"\n  Artifact: results/e_s_71_seriated_key.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_71_seriated_key.py")
