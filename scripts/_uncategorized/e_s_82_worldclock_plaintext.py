#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-S-82: World Clock Plaintext Hypothesis + Width-7 Constraint Propagation

New clue (Nov 2025): "BERLINCLOCK" refers to the World Clock (Weltzeituhr)
in Alexanderplatz, Berlin. Combined with:
- 1986 Egypt trip (pyramids, pharaoh, sphinx)
- 1989 Berlin Wall fall
- "Delivering a message"
- "What's the point?"

This experiment:
1. Generates aggressive plaintext hypotheses using these thematic elements
2. For each hypothesis, tests all 5040 width-7 orderings for consistency
3. Uses Latin square constraints to further filter
4. Any hypothesis that reduces orderings to <10 is worth deep investigation

The key insight: with MORE known plaintext (hypothesized), the constraints
become tighter and the underdetermination wall may be broken.
"""

import json
import os
import sys
import time
from itertools import permutations

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
IDX = {c: i for i, c in enumerate(AZ)}

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
COL_LENGTHS = [NROWS_FULL + 1 if c < NROWS_EXTRA else NROWS_FULL for c in range(WIDTH)]

print("=" * 70)
print("E-S-82: World Clock Plaintext Hypothesis")
print("=" * 70)
print(f"CT length: {N}")
print(f"Known: positions 21-33 = EASTNORTHEAST, 63-73 = BERLINCLOCK")
print(f"Available for extension: positions 0-20, 34-62, 74-96")


def build_inv_perm(order):
    inv_perm = [0] * N
    j = 0
    for rank in range(WIDTH):
        c = order[rank]
        clen = COL_LENGTHS[c]
        for row in range(clen):
            pt_pos = row * WIDTH + c
            inv_perm[pt_pos] = j
            j += 1
    return inv_perm


def check_constraints(extended_cribs, all_orders):
    """Check how many orderings survive bijectivity + Latin square constraints."""
    ext_pos = sorted(extended_cribs.keys())
    survivors = []

    for order in all_orders:
        order = list(order)
        inv_perm = build_inv_perm(order)
        ok = True

        # Constraint A: within column, different PT → different CT
        col_maps = {}
        for p in ext_pos:
            col = p % WIDTH
            j = inv_perm[p]
            ct = CT[j]
            pt = extended_cribs[p]
            if col not in col_maps:
                col_maps[col] = {}
            if pt in col_maps[col]:
                if col_maps[col][pt] != ct:
                    ok = False
                    break
            else:
                # Check bijectivity: different PT → different CT
                for existing_pt, existing_ct in col_maps[col].items():
                    if existing_ct == ct and existing_pt != pt:
                        ok = False
                        break
                if not ok:
                    break
                col_maps[col][pt] = ct

        if not ok:
            continue

        # Constraint B: cross-column, same PT → different CT (Latin square)
        for i in range(len(ext_pos)):
            if not ok:
                break
            for k in range(i + 1, len(ext_pos)):
                p1, p2 = ext_pos[i], ext_pos[k]
                if (extended_cribs[p1] == extended_cribs[p2]
                        and p1 % WIDTH != p2 % WIDTH):
                    j1 = inv_perm[p1]
                    j2 = inv_perm[p2]
                    if CT[j1] == CT[j2]:
                        ok = False
                        break

        if ok:
            survivors.append(tuple(order))

    return survivors


# ── Generate plaintext hypotheses ───────────────────────────────────────

# Structure: positions 0-20 (21 chars), 21-33 (EASTNORTHEAST), 34-62 (29 chars),
#            63-73 (BERLINCLOCK), 74-96 (23 chars)

# The plaintext is about:
# - A journey/message delivery involving Egypt (1986) and Berlin (1989)
# - Compass directions (EAST NORTHEAST)
# - The World Clock in Berlin
# - "What's the point?" is embedded

# Generate candidate extensions for each section
# Positions 14-20 (before EASTNORTHEAST): compass-related
before_ene = [
    "DEGREES",      # "...DEGREES EAST NORTHEAST..."
    "HEADING",      # "...HEADING EAST NORTHEAST..."
    "BEARING",      # "...BEARING EAST NORTHEAST..."
    "POINTED",      # "...POINTED EAST NORTHEAST..."
    "TRAVELS",      # "...TRAVELS EAST NORTHEAST..."
]

# Positions 34-62 (29 chars between cribs): message content
# These should reference Egypt, message delivery, the clock
middle_candidates = [
    "FROMTHEPYRAMIDSITRAVELLEDTO",   # 27 chars (too short by 2)
    "THECLOCKREADFIVEOCLOCKINTHE",   # 27 chars
    "THEWORLDCLOCKSHOWSTHETIMEIN",   # 27 chars
    "TODELIVERAMESSAGEABOUTTHEIR",   # 27 chars
    "OFTHEPYRAMIDSTHENEWMESSAGE",    # 26 chars
    "THEANSWERISTHEWORLDCLOCKINT",   # 27 chars
]

# Positions 74-96 (23 chars after BERLINCLOCK): conclusion/riddle
after_bc = [
    "SHOWSTHETIMEWHATSTHEPOINT",  # 25 chars (too long)
    "READSWHATSTHEPOINT",         # 18 chars (5 short)
    "SHOWSTHETIMEOFTHEFALL",      # 21 chars (2 short)
    "TOWERWHATSTHEPOINT",         # 18 chars
    "WHATSTHEPOINTOFITALL",       # 20 chars (3 short)
    "THENWHATSTHEPOINT",          # 17 chars (6 short)
]

# Build specific full hypotheses
hypotheses = []

# Hypothesis 1: "X DEGREES EASTNORTHEAST ... BERLINCLOCK READS WHATS THE POINT"
# Try fitting DEGREES before ENE (positions 14-20)
# and WHATSTHEPOINT after BC
h1_extensions = {}
# DEGREES at positions 14-20
for i, c in enumerate("DEGREES"):
    h1_extensions[14 + i] = c
# WHATSTHEPOINT at positions 74-86
for i, c in enumerate("WHATSTHEPOINT"):
    h1_extensions[74 + i] = c
hypotheses.append(("DEGREES_before + WHATSTHEPOINT_after", h1_extensions))

# Hypothesis 2: WHATSTHEPOINT starting at position 0
h2 = {}
for i, c in enumerate("WHATSTHEPOINT"):
    h2[i] = c
hypotheses.append(("WHATSTHEPOINT_at_0", h2))

# Hypothesis 3: WHATSTHEPOINT at various positions
for start in [0, 34, 38, 42, 46, 50, 74, 78, 82, 84]:
    phrase = "WHATSTHEPOINT"
    if start + len(phrase) > N:
        continue
    h = {}
    conflict = False
    for i, c in enumerate(phrase):
        pos = start + i
        if pos in CRIB_DICT:
            if CRIB_DICT[pos] != c:
                conflict = True
                break
        else:
            h[pos] = c
    if not conflict and h:
        hypotheses.append((f"WHATSTHEPOINT_at_{start}", h))

# Hypothesis 4: POINT at various positions (shorter, more flexible)
for start in range(N - 5 + 1):
    phrase = "POINT"
    h = {}
    conflict = False
    for i, c in enumerate(phrase):
        pos = start + i
        if pos in CRIB_DICT:
            if CRIB_DICT[pos] != c:
                conflict = True
                break
        else:
            h[pos] = c
    if not conflict and h:
        hypotheses.append((f"POINT_at_{start}", h))

# Hypothesis 5: WORLDCLOCK at 55-64 (ending at BERLINCLOCK start)
for start in [52, 53, 54, 55, 56]:
    phrase = "WORLDCLOCK"
    h = {}
    conflict = False
    for i, c in enumerate(phrase):
        pos = start + i
        if pos in CRIB_DICT:
            if CRIB_DICT[pos] != c:
                conflict = True
                break
        else:
            h[pos] = c
    if not conflict and h:
        hypotheses.append((f"WORLDCLOCK_at_{start}", h))

# Hypothesis 6: THEWORLDCLOCK at positions before BERLINCLOCK
for start in [49, 50, 51, 52]:
    phrase = "THEWORLDCLOCK"
    h = {}
    conflict = False
    for i, c in enumerate(phrase):
        pos = start + i
        if pos in CRIB_DICT:
            if CRIB_DICT[pos] != c:
                conflict = True
                break
        else:
            h[pos] = c
    if not conflict and h:
        hypotheses.append((f"THEWORLDCLOCK_at_{start}", h))

# Hypothesis 7: PYRAMIDS at various positions
for start in range(N - 8 + 1):
    phrase = "PYRAMIDS"
    h = {}
    conflict = False
    for i, c in enumerate(phrase):
        pos = start + i
        if pos in CRIB_DICT:
            if CRIB_DICT[pos] != c:
                conflict = True
                break
        else:
            h[pos] = c
    if not conflict and h:
        hypotheses.append((f"PYRAMIDS_at_{start}", h))

# Hypothesis 8: SPHINX at various positions
for start in range(N - 6 + 1):
    phrase = "SPHINX"
    h = {}
    conflict = False
    for i, c in enumerate(phrase):
        pos = start + i
        if pos in CRIB_DICT:
            if CRIB_DICT[pos] != c:
                conflict = True
                break
        else:
            h[pos] = c
    if not conflict and h:
        hypotheses.append((f"SPHINX_at_{start}", h))

# Hypothesis 9: WALL / THEWALL at various positions
for phrase_name, phrase in [("THEWALL", "THEWALL"), ("BERLINWALL", "BERLINWALL")]:
    for start in range(N - len(phrase) + 1):
        h = {}
        conflict = False
        for i, c in enumerate(phrase):
            pos = start + i
            if pos in CRIB_DICT:
                if CRIB_DICT[pos] != c:
                    conflict = True
                    break
            else:
                h[pos] = c
        if not conflict and h:
            hypotheses.append((f"{phrase_name}_at_{start}", h))

# Hypothesis 10: Egyptian/Berlin related words
for phrase in ["EGYPT", "CAIRO", "NILE", "GIZA", "TOMB", "FALLS", "FELL",
               "TOWER", "TIME", "CLOCK", "WORLD", "DELIVERS", "DELIVERED",
               "MESSAGE", "SECRET", "HIDDEN", "BURIED"]:
    for start in range(N - len(phrase) + 1):
        h = {}
        conflict = False
        for i, c in enumerate(phrase):
            pos = start + i
            if pos in CRIB_DICT:
                if CRIB_DICT[pos] != c:
                    conflict = True
                    break
            else:
                h[pos] = c
        if not conflict and h:
            hypotheses.append((f"{phrase}_at_{start}", h))

print(f"\n  Generated {len(hypotheses)} hypotheses")

# ── Test hypotheses ─────────────────────────────────────────────────────

print("\n" + "-" * 50)
print("Phase 1: Test hypotheses (bijectivity filter, no Latin square)")
print("-" * 50)

all_orders = list(permutations(range(WIDTH)))
t0 = time.time()

# Baseline: just the 24 known cribs
baseline_biject = []
for order in all_orders:
    order = list(order)
    inv_perm = build_inv_perm(order)
    ok = True
    col_maps = {}
    for p in CRIB_POS:
        col = p % WIDTH
        j = inv_perm[p]
        ct = CT[j]
        pt = CRIB_DICT[p]
        if col not in col_maps:
            col_maps[col] = {}
        if pt in col_maps[col]:
            if col_maps[col][pt] != ct:
                ok = False
                break
        else:
            for ep, ec in col_maps[col].items():
                if ec == ct:
                    ok = False
                    break
            if not ok:
                break
            col_maps[col][pt] = ct
    if ok:
        baseline_biject.append(tuple(order))

print(f"  Baseline (24 cribs, bijectivity): {len(baseline_biject)} orderings")

# Test each hypothesis
interesting = []
for name, ext in hypotheses:
    extended = dict(CRIB_DICT)
    extended.update(ext)

    survivors = check_constraints(extended, all_orders)

    total_cribs = len(extended)
    if len(survivors) < len(baseline_biject) * 0.3:  # >70% reduction
        interesting.append((name, total_cribs, len(survivors), survivors[:5]))

tested = len(hypotheses)
elapsed = time.time() - t0
print(f"  Tested {tested} hypotheses in {elapsed:.1f}s")
print(f"  Interesting hypotheses (>70% reduction): {len(interesting)}")

# Sort by number of survivors
interesting.sort(key=lambda x: x[2])

print(f"\n  Top 30 most constraining hypotheses:")
for name, n_cribs, n_surv, _ in interesting[:30]:
    reduction = 100 * (1 - n_surv / len(baseline_biject))
    print(f"    {name}: {n_cribs} cribs → {n_surv} orderings ({reduction:.0f}% reduction)")


# ── Phase 2: Deeper analysis of top hypotheses ─────────────────────────

if interesting:
    print("\n" + "-" * 50)
    print("Phase 2: Deeper analysis of top hypotheses")
    print("-" * 50)

    for name, n_cribs, n_surv, sample_orders in interesting[:10]:
        if n_surv == 0:
            print(f"\n  {name}: ELIMINATED (0 survivors) — placement inconsistent")
            continue

        extended = dict(CRIB_DICT)
        for n2, ext2 in hypotheses:
            if n2 == name:
                extended.update(ext2)
                break

        survivors = check_constraints(extended, all_orders)

        print(f"\n  {name}: {n_cribs} cribs, {len(survivors)} survivors")

        # For each survivor, compute keystream and check patterns
        for oi, order in enumerate(survivors[:5]):
            order = list(order)
            inv_perm = build_inv_perm(order)
            ext_pos = sorted(extended.keys())

            # Compute keystream per column
            col_keys = {}
            for p in ext_pos:
                col = p % WIDTH
                j = inv_perm[p]
                pt_v = IDX[extended[p]]
                ct_v = IDX[CT[j]]
                kv = (ct_v - pt_v) % 26  # Vigenère
                if col not in col_keys:
                    col_keys[col] = []
                col_keys[col].append((p, kv))

            # Check period-7 consistency
            consistent_cols = 0
            for col in range(WIDTH):
                if col in col_keys:
                    kvs = [kv for _, kv in col_keys[col]]
                    if len(set(kvs)) == 1:
                        consistent_cols += 1

            if oi == 0 or consistent_cols >= 5:
                p7_str = f"{consistent_cols}/7 period-7" + (" ✓" if consistent_cols == 7 else "")
                print(f"    Order {order}: {p7_str}")

                if consistent_cols >= 5:
                    for col in range(WIDTH):
                        if col in col_keys:
                            vals = [f"k[{p}]={kv}" for p, kv in sorted(col_keys[col])]
                            print(f"      Col {col}: {', '.join(vals)}")


# ── Summary ──────────────────────────────────────────────────────────────

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  Baseline survivors: {len(baseline_biject)}")
print(f"  Hypotheses tested: {len(hypotheses)}")
print(f"  Interesting (>70% reduction): {len(interesting)}")

if interesting:
    best = interesting[0]
    print(f"  Most constraining: '{best[0]}' ({best[1]} cribs → {best[2]} orderings)")

    if best[2] == 0:
        verdict = "Most constraining hypothesis ELIMINATES all orderings — placement inconsistent"
    elif best[2] <= 5:
        verdict = f"HIGHLY CONSTRAINED — only {best[2]} orderings survive, investigate"
    elif best[2] <= 20:
        verdict = f"WELL CONSTRAINED — {best[2]} orderings survive"
    else:
        verdict = f"MODERATELY CONSTRAINED — {best[2]} orderings survive"
else:
    verdict = "No hypothesis achieves >70% reduction — underdetermination persists"

print(f"  Verdict: {verdict}")

output = {
    'experiment': 'E-S-82',
    'description': 'World Clock Plaintext Hypothesis + Width-7 Constraint Propagation',
    'baseline_survivors': len(baseline_biject),
    'hypotheses_tested': len(hypotheses),
    'interesting_count': len(interesting),
    'top_hypotheses': [(name, n_cribs, n_surv) for name, n_cribs, n_surv, _ in interesting[:50]],
    'verdict': verdict,
}
os.makedirs("results", exist_ok=True)
with open("results/e_s_82_worldclock_plaintext.json", "w") as f:
    json.dump(output, f, indent=2)
print(f"\n  Artifact: results/e_s_82_worldclock_plaintext.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_82_worldclock_plaintext.py")
