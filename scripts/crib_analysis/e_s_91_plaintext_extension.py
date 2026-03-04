#!/usr/bin/env python3
"""
Cipher: crib-based constraint
Family: crib_analysis
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-91: Plaintext Extension + Period-7 Consistency Filter

Tests hypothetical plaintext extensions at all valid positions.
With 34+ total known chars (24 confirmed + 10+ guessed), the period-7 +
width-7 columnar model becomes dramatically more constrained.

E-S-87 showed 20.2% of random period-7 keys satisfy 24 cribs under
arbitrary transposition. Each additional crib multiplies by ~1/26,
so with 34 cribs: ~20.2% × 26^{-10} ≈ 10^{-15}. With 37 cribs: ~10^{-19}.
This makes the filter EXTREMELY powerful.

Strategy:
  Phase 1: Test each phrase at each valid position against width-7 columnar
           (5040 orderings × 3 variants × 7 periods). Count survivors.
  Phase 2: For surviving placements, check if bipartite matching narrows
           the key space (arbitrary transposition model).
  Phase 3: Cross-consistency between multiple phrase placements.

Key phrases from Sanborn's 2025 clues and community proposals:
  - WHATSTHEPOINT (Sanborn's embedded clue)
  - DELIVERING / MESSAGE / DELIVERINGAMESSAGE
  - EGYPT / PYRAMIDS / CAIRO
  - BERLINWALL / WALLFALL
  - BURIED / ITISBURIED (K2 connection)
  - WORLDCLOCK / WELTZEITUHR
  - COMPASS / BEARING / DEGREES
"""

import json, os, time
from itertools import permutations
from collections import defaultdict, Counter

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
I2N = {c: i for i, c in enumerate(AZ)}
CT_N = [I2N[c] for c in CT]

CRIBS_BASE = {
    21:'E',22:'A',23:'S',24:'T',25:'N',26:'O',27:'R',28:'T',29:'H',30:'E',31:'A',32:'S',33:'T',
    63:'B',64:'E',65:'R',66:'L',67:'I',68:'N',69:'C',70:'L',71:'O',72:'C',73:'K'}
PT_BASE = {p: I2N[c] for p, c in CRIBS_BASE.items()}
CPOS_BASE = sorted(CRIBS_BASE.keys())

W = 7

def kobs(j, pt, vi):
    if vi == 0: return (CT_N[j] - pt) % 26
    if vi == 1: return (CT_N[j] + pt) % 26
    return (pt - CT_N[j]) % 26

def build_perm(order):
    nr = (N + W - 1) // W
    ns = nr * W - N
    p = []
    for k in range(W):
        c = order[k]
        sz = nr - 1 if c >= W - ns else nr
        for r in range(sz):
            p.append(r * W + c)
    return p

def inv_perm(perm):
    iv = [0] * N
    for i, p in enumerate(perm):
        iv[p] = i
    return iv

ORDERS = [list(o) for o in permutations(range(W))]
PERMS = [build_perm(o) for o in ORDERS]
INVS = [inv_perm(p) for p in PERMS]

def count_period7_survivors(all_cribs, period=7):
    """Count orderings × variants where ALL cribs are period-7 consistent.

    Returns dict of (oi, vi) -> key_values for each survivor.
    """
    pt_num = {p: I2N[c] for p, c in all_cribs.items()}
    cpos = sorted(all_cribs.keys())
    survivors = {}

    for oi in range(len(ORDERS)):
        iv = INVS[oi]
        for vi in range(3):
            # Check period-7 consistency
            residue_keys = {}
            consistent = True
            for p in cpos:
                j = iv[p]
                k = kobs(j, pt_num[p], vi)
                r = j % period
                if r in residue_keys:
                    if residue_keys[r] != k:
                        consistent = False
                        break
                else:
                    residue_keys[r] = k

            if consistent:
                survivors[(oi, vi)] = residue_keys

    return survivors


# ── Define candidate phrases ──────────────────────────────────────────
PHRASES = [
    # Sanborn's clues
    "WHATSTHEPOINT",
    "WHATISTHEPOINT",
    "THEPOINT",
    "DELIVERING",
    "DELIVERINGAMESSAGE",
    "AMESSAGE",
    "MESSAGE",

    # Egypt 1986
    "EGYPT",
    "PYRAMIDS",
    "CAIRO",
    "GIZA",
    "NILE",
    "PHARAOH",
    "TUTANKHAMUN",
    "CARTER",

    # Berlin 1989
    "BERLINWALL",
    "THEWALL",
    "WALLFALL",
    "CHECKPOINT",
    "FREEDOM",

    # Berlin Clock
    "WORLDCLOCK",
    "WELTZEITUHR",
    "ALEXANDERPLATZ",
    "HOURHAND",
    "HOURS",
    "MINUTES",
    "TIME",
    "DEGREES",

    # K2 connection
    "BURIED",
    "ITISBURIED",
    "ITSBURIED",
    "UNDERGROUND",
    "SECRET",
    "HIDDEN",

    # Compass/navigation
    "COMPASS",
    "BEARING",
    "NORTHWEST",
    "COORDINATES",

    # Community proposals
    "FORTYYARDS",
    "GROSSERSTERN",

    # Common English connectors
    "SLOWLY",
    "DESPERATELY",
    "BETWEEN",
    "THROUGH",
    "TOWARD",
    "ACROSS",

    # Structural / meta
    "LAYERTWO",
    "SHADOW",
    "PALIMPSEST",
    "ABSCISSA",
    "KRYPTOS",
]

print("=" * 70)
print("E-S-91: Plaintext Extension + Period-7 Consistency Filter")
print(f"  CT length: {N}, Base cribs: {len(CRIBS_BASE)}")
print(f"  Phrases to test: {len(PHRASES)}")
print("=" * 70)

t0 = time.time()

# Phase 0: Baseline — how many orderings survive with just 24 cribs?
print("\n--- Phase 0: Baseline (24 cribs only) ---")
base_survivors = count_period7_survivors(CRIBS_BASE)
print(f"  Survivors with 24 base cribs: {len(base_survivors)}/15120")
print(f"  ({len(base_survivors)/15120*100:.1f}%)")

# Count by variant
by_var = Counter(vi for _, vi in base_survivors.keys())
VNAMES = ['Vig', 'Beau', 'VBeau']
for vi in range(3):
    print(f"    {VNAMES[vi]}: {by_var.get(vi, 0)}")


# ── Phase 1: Test each phrase at each valid position ──────────────────
print("\n--- Phase 1: Phrase placement filter ---")

results = []

for phrase in PHRASES:
    plen = len(phrase)

    # Valid start positions: must not overlap with existing cribs
    for start in range(N - plen + 1):
        end = start + plen - 1

        # Check for overlap with base cribs
        positions = list(range(start, start + plen))
        overlap = [p for p in positions if p in CRIBS_BASE]

        if overlap:
            # Check consistency: overlapping positions must match
            consistent = True
            for p in overlap:
                if phrase[p - start] != CRIBS_BASE[p]:
                    consistent = False
                    break
            if not consistent:
                continue  # Skip — phrase contradicts known cribs

        # Build extended crib set
        extended = dict(CRIBS_BASE)
        new_chars = 0
        for i, c in enumerate(phrase):
            pos = start + i
            if pos not in extended:
                extended[pos] = c
                new_chars += 1

        if new_chars == 0:
            continue  # Phrase is entirely within known cribs

        total_cribs = len(extended)

        # Count survivors
        survivors = count_period7_survivors(extended)
        n_surv = len(survivors)

        # Record
        results.append({
            'phrase': phrase,
            'start': start,
            'end': end,
            'new_chars': new_chars,
            'total_cribs': total_cribs,
            'survivors': n_surv,
            'survivor_rate': n_surv / 15120,
        })

        if n_surv > 0 and n_surv < len(base_survivors) * 0.1:
            print(f"  FILTER: '{phrase}' @ {start}-{end} ({new_chars} new, "
                  f"{total_cribs} total): {n_surv}/{len(base_survivors)} "
                  f"({n_surv/len(base_survivors)*100:.1f}% of base)")

        if n_surv > 0 and total_cribs >= 34 and n_surv <= 10:
            print(f"  *** STRONG: '{phrase}' @ {start}-{end}: only {n_surv} survivors!")
            for (oi, vi), keys in survivors.items():
                print(f"      order={ORDERS[oi]} {VNAMES[vi]} key={[keys.get(r, '?') for r in range(7)]}")

    # Progress
    elapsed = time.time() - t0
    phrase_results = [r for r in results if r['phrase'] == phrase]
    if phrase_results:
        min_surv = min(r['survivors'] for r in phrase_results)
        n_placements = len(phrase_results)
        zero_count = sum(1 for r in phrase_results if r['survivors'] == 0)
        print(f"  '{phrase}': {n_placements} placements, {zero_count} eliminated, "
              f"min survivors={min_surv} ({elapsed:.0f}s)")


# ── Phase 2: Summary statistics ───────────────────────────────────────
print("\n" + "-" * 50)
print("Phase 2: Summary")
print("-" * 50)

# Group by phrase
phrase_stats = {}
for r in results:
    p = r['phrase']
    if p not in phrase_stats:
        phrase_stats[p] = {'placements': 0, 'eliminated': 0, 'min_surv': float('inf'),
                          'best_pos': None}
    phrase_stats[p]['placements'] += 1
    if r['survivors'] == 0:
        phrase_stats[p]['eliminated'] += 1
    if r['survivors'] < phrase_stats[p]['min_surv']:
        phrase_stats[p]['min_surv'] = r['survivors']
        phrase_stats[p]['best_pos'] = r['start']

# Sort by min survivors (most constrained first)
sorted_phrases = sorted(phrase_stats.items(), key=lambda x: x[1]['min_surv'])

print(f"\n  Top 20 most constraining phrases:")
for phrase, stats in sorted_phrases[:20]:
    print(f"    '{phrase}': min_surv={stats['min_surv']} "
          f"(pos {stats['best_pos']}), "
          f"{stats['eliminated']}/{stats['placements']} placements eliminated")


# ── Phase 3: Find placements with very few survivors ──────────────────
print("\n" + "-" * 50)
print("Phase 3: Narrow survivors (≤100)")
print("-" * 50)

narrow = [r for r in results if 0 < r['survivors'] <= 100]
narrow.sort(key=lambda x: x['survivors'])

for r in narrow[:30]:
    print(f"  '{r['phrase']}' @ {r['start']}-{r['end']}: "
          f"{r['survivors']} survivors ({r['new_chars']} new, {r['total_cribs']} total)")


# ── Phase 4: Cross-phrase consistency ─────────────────────────────────
# Test pairs of phrases: if both are placed simultaneously, do any orderings survive?
print("\n" + "-" * 50)
print("Phase 4: Cross-phrase consistency (top pairs)")
print("-" * 50)

# Get the phrases with narrow survivor counts
top_placements = [r for r in results if 0 < r['survivors'] <= 500]
top_placements.sort(key=lambda x: x['survivors'])

if len(top_placements) >= 2:
    tested = 0
    for i in range(min(20, len(top_placements))):
        for j in range(i + 1, min(30, len(top_placements))):
            r1 = top_placements[i]
            r2 = top_placements[j]

            # Check position overlap
            pos1 = set(range(r1['start'], r1['end'] + 1))
            pos2 = set(range(r2['start'], r2['end'] + 1))
            overlap = pos1 & pos2

            if overlap:
                # Check letter consistency in overlap
                consistent = True
                for p in overlap:
                    c1 = r1['phrase'][p - r1['start']]
                    c2 = r2['phrase'][p - r2['start']]
                    if c1 != c2:
                        consistent = False
                        break
                if not consistent:
                    continue

            # Build combined crib set
            combined = dict(CRIBS_BASE)
            for k, c in enumerate(r1['phrase']):
                combined[r1['start'] + k] = c
            for k, c in enumerate(r2['phrase']):
                combined[r2['start'] + k] = c

            survivors = count_period7_survivors(combined)
            tested += 1

            if len(survivors) > 0:
                print(f"  PAIR: '{r1['phrase']}'@{r1['start']} + '{r2['phrase']}'@{r2['start']}: "
                      f"{len(survivors)} survivors ({len(combined)} cribs)")
                if len(survivors) <= 5:
                    for (oi, vi), keys in survivors.items():
                        print(f"    order={ORDERS[oi]} {VNAMES[vi]} key={[keys.get(r, '?') for r in range(7)]}")

            if tested >= 200:
                break
        if tested >= 200:
            break

    print(f"  Tested {tested} pairs")
else:
    print("  No narrow placements to cross-test")


# ── Summary ───────────────────────────────────────────────────────────
total_elapsed = time.time() - t0

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  Total phrases tested: {len(PHRASES)}")
print(f"  Total placements tested: {len(results)}")
print(f"  Baseline survivors (24 cribs): {len(base_survivors)}")

n_eliminated = sum(1 for r in results if r['survivors'] == 0)
n_narrow = sum(1 for r in results if 0 < r['survivors'] <= 10)
print(f"  Placements eliminated (0 survivors): {n_eliminated}")
print(f"  Narrow placements (1-10 survivors): {n_narrow}")
print(f"  Time: {total_elapsed:.1f}s")

out = {
    'experiment': 'E-S-91',
    'description': 'Plaintext extension + period-7 consistency filter',
    'baseline_survivors': len(base_survivors),
    'phrases_tested': len(PHRASES),
    'placements_tested': len(results),
    'eliminated': n_eliminated,
    'narrow': n_narrow,
    'top_constraining': [{
        'phrase': p,
        'min_survivors': s['min_surv'],
        'best_position': s['best_pos'],
        'eliminated_placements': s['eliminated'],
        'total_placements': s['placements'],
    } for p, s in sorted_phrases[:20]],
    'elapsed_seconds': total_elapsed,
}
os.makedirs("results", exist_ok=True)
with open("results/e_s_91_plaintext_extension.json", "w") as f:
    json.dump(out, f, indent=2)
print(f"\n  Artifact: results/e_s_91_plaintext_extension.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_91_plaintext_extension.py")
