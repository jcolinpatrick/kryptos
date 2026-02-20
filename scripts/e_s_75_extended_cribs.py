#!/usr/bin/env python3
"""
E-S-75: Extended Crib Guessing

Sanborn's hints suggest the plaintext contains thematic content about:
- Navigation/compass bearings ("EAST NORTH EAST")
- Time/clocks ("BERLIN CLOCK")
- Berlin Wall (1989)
- Egypt (1986 trip)
- "Delivering a message"
- "What's the point?"

Strategy: Generate candidate extended cribs and test them against K4 under
width-7 columnar + Vigenère/Beaufort at period 7 (the most likely structure).

If we can extend the known 24 crib positions to 30+, this dramatically
increases discrimination power and may break through the underdetermination wall.

Key insight: Extended cribs don't need to be exact — we test MANY candidates
and look for those that produce significantly more period-7 consistency than
expected by chance.
"""

import json
import os
import random
import sys
import time
from itertools import permutations

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
IDX = {c: i for i, c in enumerate(AZ)}
CT_IDX = [IDX[c] for c in CT]

CRIB_DICT = {
    21: 'E', 22: 'A', 23: 'S', 24: 'T', 25: 'N', 26: 'O', 27: 'R',
    28: 'T', 29: 'H', 30: 'E', 31: 'A', 32: 'S', 33: 'T',
    63: 'B', 64: 'E', 65: 'R', 66: 'L', 67: 'I', 68: 'N', 69: 'C',
    70: 'L', 71: 'O', 72: 'C', 73: 'K'
}
CRIB_POS = sorted(CRIB_DICT.keys())

WIDTH = 7
NROWS_FULL = N // WIDTH
NROWS_EXTRA = N % WIDTH

print("=" * 70)
print("E-S-75: Extended Crib Guessing")
print("=" * 70)

def build_col_perm(order):
    col_lengths = []
    for col_idx in range(WIDTH):
        if col_idx < NROWS_EXTRA:
            col_lengths.append(NROWS_FULL + 1)
        else:
            col_lengths.append(NROWS_FULL)
    perm = [0] * N
    j = 0
    for rank in range(WIDTH):
        c = order[rank]
        clen = col_lengths[c]
        for row in range(clen):
            pt_pos = row * WIDTH + c
            perm[j] = pt_pos
            j += 1
    inv_perm = [0] * N
    for j in range(N):
        inv_perm[perm[j]] = j
    return perm, inv_perm

# ── Generate extended crib candidates ────────────────────────────────────

# Position 34+ (after EASTNORTHEAST at 21-33)
after_ene = [
    # Compass/navigation continued
    "DEGREES",
    "BEARING",
    "HEADING",
    "LATITUDE",
    "LONGITUDE",
    "COORDINATES",
    "SOUTHEAST",
    "SOUTHWEST",
    "NORTHWEST",
    "NORTHEAST",
    "MAGNETIC",
    "TRUE",
    "DECLINATION",
    # What's the point
    "WHATSTHEPOINT",
    "THEPOINT",
    "POINTIS",
    # Delivering a message
    "AMESSAGE",
    "MESSAGE",
    "DELIVERING",
    "DELIVERED",
    "THEDEAD",
    "DEADD",
    "DROP",
    "DROPP",
    # Egypt trip
    "CAIROTOTHE",
    "PYRAMIDS",
    "PHARAOH",
    "GIZAPLAT",
    "VALLEYOF",
    # Berlin
    "CHECKPOINT",
    "CHARLI",
    "THEWALL",
    "CROSSING",
    # CIA
    "LANGLEY",
    "DIRECTOR",
    "AGENT",
    "ATSIX",
    "ATNOON",
    "ATDAWN",
    # Time
    "OCLOCK",
    "HOURS",
    "MINUTES",
    "MIDNIGHT",
    # General
    "SLOWLY",  # K3 starts with SLOWLY
    "THEREWAS",
    "ITWAS",
    "THEYHAD",
    "UNDERGROUND",
    "BURIED",
    "HIDDEN",
    "INANARCHWAY",
    "INAGROTTO",
    "OFTHEANCIENT",
    "SHADOW",
    "SHADOWS",
    "LIGHT",
    "DARKNESS",
    "BETWEEN",
    "THROUGH",
    "BENEATH",
    "ABOVE",
    "LAYTHE",
    "WASTHE",
    "ISTHE",
    "ANDTHE",
]

# Position 74+ (after BERLINCLOCK at 63-73)
after_bc = [
    # Clock/time
    "TOWER",
    "READS",
    "SHOWS",
    "SHOWSTHE",
    "STRIKING",
    "STRUCK",
    "TIME",
    "TIMES",
    "ATONE",
    "ATTWO",
    "ATTHREE",
    "ATFOUR",
    "ATFIVE",
    "NOON",
    "MIDNIGHT",
    "HOUR",
    "HOURS",
    "ISNOW",
    "WASSET",
    "STOPPED",
    "BEGAN",
    # Berlin Wall
    "FELL",
    "FALLS",
    "STOOD",
    "WALL",
    "THEWA",
    "INBER",
    "WASBU",
    # General
    "ANDTHE",
    "ITREAD",
    "ITWAS",
    "WASTHE",
    "ONTHE",
    "INTHE",
    "BYTHE",
    "FORTHE",
    "ATTHE",
    "THATIS",
    "WHICH",
    "WHERE",
    "WHENT",
    "SOUTH",
    "NORTH",
    "POINT",
    "THEPO",
    "LAYER",
]

# Position 0-20 (before EASTNORTHEAST)
before_ene = [
    # Various starts
    "ITISTOTALLYINVISIBLE",
    "BETWEENSUBTLESHADING",
    "SLOWLYDESPARATLY",
    "THECOORDINATESARE",
    "ONTHESOUTHERNWALL",
    "INTHEDARKNESS",
    "ATCOORDINATES",
    "FOLLOWTHECLUES",
    "THELOCATIONOFTHE",
    "WHOYOUWORKEDFOR",
    "THEREISONLYONE",
    "FROMTHESHADOWOF",
    "ATTHEBASEOFTHE",
    "THEDIRECTORHAS",
    "INFORMATIONWAS",
    "WHATSTHEPOINTOF",
    "DIGITALINTERPR",
    "ITHOUGHTITWASCL",
    "THESECRETLIESIN",
    "BENEATHTHESURFAC",
    "LAYERSOFDECEPTIO",
    "VIRTUALLYINVISIBL",
    "CANUBEANYMORE",
    "OBSCURITYISASECUR",
    "WHOYOUTRUSTTHEMOS",
]

def score_extended_crib(extended_crib, order, variant='vig', period=7):
    """Score an extended crib (dict pos→letter) against width-7 columnar + period-7 key.

    Returns (total_matches, consistent_matches):
    - total_matches: how many positions match under the derived period-7 key
    - consistent_matches: how many of these are consistent with each other at same residue
    """
    _, inv_perm = build_col_perm(order)

    # Derive key at each crib position
    residue_keys = {}  # residue → list of key values seen
    key_at_pos = {}

    for p, letter in extended_crib.items():
        if p < 0 or p >= N:
            continue
        j = inv_perm[p]  # CT position after transposition
        pt_v = IDX[letter]
        ct_v = CT_IDX[j]
        if variant == 'vig':
            kv = (ct_v - pt_v) % 26
        elif variant == 'beau':
            kv = (ct_v + pt_v) % 26
        else:
            kv = (pt_v - ct_v) % 26
        key_at_pos[p] = kv
        r = j % period
        if r not in residue_keys:
            residue_keys[r] = {}
        if kv not in residue_keys[r]:
            residue_keys[r][kv] = 0
        residue_keys[r][kv] += 1

    # Find the best assignment: for each residue, pick the most common key value
    total_consistent = 0
    for r, kv_counts in residue_keys.items():
        best_count = max(kv_counts.values())
        total_consistent += best_count

    return len(key_at_pos), total_consistent

# ── Phase 1: Test extended cribs at positions 34+ and 74+ ───────────────
print("\n" + "-" * 50)
print("Phase 1: Extended cribs, direct (no transposition)")
print("-" * 50)

best_p1 = {'score': 0, 'crib': '', 'pos': 0}

# Direct scoring (no transposition)
for pos_start, candidates in [(34, after_ene), (74, after_bc), (0, before_ene)]:
    for cand in candidates:
        extended = dict(CRIB_DICT)  # Start with known cribs
        for i, c in enumerate(cand):
            p = pos_start + i
            if 0 <= p < N and p not in CRIB_DICT:
                extended[p] = c

        # Score under direct Vig/Beau at various periods
        for variant in ['vig', 'beau']:
            for period in [7, 5, 9, 11, 13]:
                # Derive key
                residue_vals = {}
                consistent = 0
                for p, letter in extended.items():
                    pt_v = IDX[letter]
                    ct_v = CT_IDX[p]
                    if variant == 'vig':
                        kv = (ct_v - pt_v) % 26
                    else:
                        kv = (ct_v + pt_v) % 26
                    r = p % period
                    if r in residue_vals:
                        if residue_vals[r] == kv:
                            consistent += 1
                    else:
                        residue_vals[r] = kv
                        consistent += 1

                if consistent > best_p1['score']:
                    best_p1 = {'score': consistent, 'crib': cand, 'pos': pos_start,
                               'variant': variant, 'period': period, 'total': len(extended)}
                    if consistent >= len(extended) - 2:
                        print(f"    pos={pos_start} '{cand}' {variant} p={period}: {consistent}/{len(extended)}")

print(f"  Phase 1 best: {best_p1['score']}/{best_p1.get('total', '?')} — {best_p1}")

# ── Phase 2: Extended cribs + width-7 columnar ──────────────────────────
print("\n" + "-" * 50)
print("Phase 2: Extended cribs + width-7 columnar (all orderings)")
print("-" * 50)

all_orders = list(permutations(range(WIDTH)))
best_p2 = {'score': 0, 'total': 0}
t2 = time.time()

# Only test the most promising extension candidates
top_extensions = []
for pos_start, candidates in [(34, after_ene), (74, after_bc)]:
    for cand in candidates:
        extended = dict(CRIB_DICT)
        for i, c in enumerate(cand):
            p = pos_start + i
            if 0 <= p < N and p not in CRIB_DICT:
                extended[p] = c
        top_extensions.append((pos_start, cand, extended))

# Also test before-ENE candidates
for cand in before_ene:
    extended = dict(CRIB_DICT)
    cand_upper = cand.upper()
    # Align so the cand ENDS at position 20 (just before ENE at 21)
    start_pos = 21 - len(cand_upper)
    if start_pos < 0:
        # Trim from the beginning
        cand_upper = cand_upper[-21:]
        start_pos = 0
    for i, c in enumerate(cand_upper):
        p = start_pos + i
        if 0 <= p < N and p not in CRIB_DICT:
            extended[p] = c
    top_extensions.append((start_pos, cand, extended))

print(f"  Testing {len(top_extensions)} extension candidates × {len(all_orders)} orderings × 2 variants")

for ext_idx, (pos_start, cand, extended) in enumerate(top_extensions):
    for oi, order in enumerate(all_orders):
        order = list(order)
        for variant in ['vig', 'beau']:
            total, consistent = score_extended_crib(extended, order, variant, period=7)
            if consistent > best_p2['score']:
                best_p2 = {'score': consistent, 'total': total, 'crib': cand,
                           'pos': pos_start, 'order': order, 'variant': variant}
                if consistent >= total - 1:
                    print(f"    '{cand}' pos={pos_start} order={order} {variant}: {consistent}/{total}")

    if (ext_idx + 1) % 20 == 0:
        elapsed = time.time() - t2
        print(f"  {ext_idx+1}/{len(top_extensions)}, {elapsed:.0f}s, best={best_p2['score']}/{best_p2['total']}")

t3 = time.time()
print(f"\n  Phase 2: {t3-t2:.1f}s, best={best_p2['score']}/{best_p2['total']} — {best_p2}")

# ── Phase 3: Combinatorial extension — pairs of extensions ──────────────
print("\n" + "-" * 50)
print("Phase 3: Pairs of extensions (before + after, both sides)")
print("-" * 50)

best_p3 = {'score': 0, 'total': 0}
t4 = time.time()

# Combine after_ene + after_bc
combo_count = 0
for cand_ene in after_ene[:30]:
    for cand_bc in after_bc[:25]:
        extended = dict(CRIB_DICT)
        for i, c in enumerate(cand_ene):
            p = 34 + i
            if 0 <= p < N and p not in CRIB_DICT:
                extended[p] = c
        for i, c in enumerate(cand_bc):
            p = 74 + i
            if 0 <= p < N and p not in CRIB_DICT:
                extended[p] = c

        # Quick test: only test the top orderings from Phase 2 + a few extras
        test_orders = [[0,1,2,3,4,5,6], [3,1,5,0,4,2,6], [4,0,6,1,3,5,2]]
        if best_p2.get('order'):
            test_orders.append(best_p2['order'])

        for order in test_orders:
            for variant in ['vig', 'beau']:
                total, consistent = score_extended_crib(extended, order, variant, period=7)
                if consistent > best_p3['score']:
                    best_p3 = {'score': consistent, 'total': total,
                               'ene': cand_ene, 'bc': cand_bc,
                               'order': order, 'variant': variant}
                    if consistent >= total - 2 and total > 28:
                        print(f"    ENE+'{cand_ene}' BC+'{cand_bc}' order={order} {variant}: {consistent}/{total}")

        combo_count += 1
        if combo_count % 100 == 0:
            elapsed = time.time() - t4
            print(f"  {combo_count} combos, {elapsed:.0f}s, best={best_p3['score']}/{best_p3['total']}")

# Now test the best combo against ALL orderings
if best_p3['score'] > 24:
    print(f"\n  Testing best combo against all orderings...")
    extended = dict(CRIB_DICT)
    for i, c in enumerate(best_p3['ene']):
        p = 34 + i
        if 0 <= p < N and p not in CRIB_DICT:
            extended[p] = c
    for i, c in enumerate(best_p3['bc']):
        p = 74 + i
        if 0 <= p < N and p not in CRIB_DICT:
            extended[p] = c

    for order in all_orders:
        order = list(order)
        for variant in ['vig', 'beau']:
            total, consistent = score_extended_crib(extended, order, variant, period=7)
            if consistent > best_p3['score']:
                best_p3 = {'score': consistent, 'total': total,
                           'ene': best_p3['ene'], 'bc': best_p3['bc'],
                           'order': order, 'variant': variant}

t5 = time.time()
print(f"\n  Phase 3: {t5-t4:.1f}s, best={best_p3['score']}/{best_p3['total']} — {best_p3}")

# ── Summary ──────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  Phase 1 (direct, no trans): {best_p1['score']}/{best_p1.get('total', '?')}")
print(f"  Phase 2 (w7 + single ext): {best_p2['score']}/{best_p2['total']}")
print(f"  Phase 3 (w7 + pair ext): {best_p3['score']}/{best_p3['total']}")

# Expected: with random text, period-7 consistency = total * (1/7 + 6/7 * 1/26) ≈ total * 0.176
# So for total=30, expected ≈ 5.3; for total=35, expected ≈ 6.2
# Signal threshold: significantly above this

best_all = max(best_p1['score'], best_p2['score'], best_p3['score'])
best_total = max(best_p1.get('total', 24), best_p2.get('total', 24), best_p3.get('total', 24))
expected_random = best_total * (1.0/7 + 6.0/7 * 1.0/26)

print(f"\n  Expected random consistency at best total ({best_total}): {expected_random:.1f}")
if best_all >= best_total - 2:
    verdict = f"STRONG SIGNAL — {best_all}/{best_total}"
elif best_all >= best_total * 0.8:
    verdict = f"POSSIBLE SIGNAL — investigate"
else:
    verdict = f"NO SIGNAL — best {best_all}/{best_total}"

print(f"  Verdict: {verdict}")

output = {
    'experiment': 'E-S-75',
    'description': 'Extended crib guessing',
    'phase1_best': best_p1,
    'phase2_best': {'score': best_p2['score'], 'total': best_p2['total'],
                    'crib': best_p2.get('crib'), 'order': best_p2.get('order')},
    'phase3_best': {'score': best_p3['score'], 'total': best_p3['total']},
    'verdict': verdict,
}
os.makedirs("results", exist_ok=True)
with open("results/e_s_75_extended_cribs.json", "w") as f:
    json.dump(output, f, indent=2)
print(f"\n  Artifact: results/e_s_75_extended_cribs.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_75_extended_cribs.py")
