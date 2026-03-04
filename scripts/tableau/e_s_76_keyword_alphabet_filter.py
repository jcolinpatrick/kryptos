#!/usr/bin/env python3
"""
Cipher: tableau analysis
Family: tableau
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-S-76: Keyword Mixed Alphabet Filter

If K4's "coding charts" define 7 keyword mixed alphabets (one per column under
width-7 columnar), then each alphabet is determined by a keyword. The crib
constraints narrow which keywords are valid for each column.

For a keyword mixed alphabet from keyword W:
  alpha = unique_letters(W) + remaining_letters_in_order
  This defines a simple substitution: CT_letter = alpha[IDX[PT_letter]]

With 3-4 crib constraints per column, most keywords are eliminated.
We enumerate valid keywords per column, then combine.

This is a STRUCTURAL approach: instead of SA (which is underdetermined),
we constrain the alphabets to keyword-derived form, massively reducing DOF.
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

# Load quadgrams
with open("data/english_quadgrams.json") as f:
    qg_data = json.load(f)
if isinstance(qg_data, dict) and "logp" in qg_data:
    qg_data = qg_data["logp"]

QG_TABLE = [0.0] * (26**4)
QG_FLOOR = -15.0
for qg, logp in qg_data.items():
    if len(qg) == 4:
        a, b, c, d = [IDX[ch] for ch in qg]
        QG_TABLE[a*17576 + b*676 + c*26 + d] = logp
for i in range(len(QG_TABLE)):
    if QG_TABLE[i] == 0.0:
        QG_TABLE[i] = QG_FLOOR

# Load wordlist
with open("wordlists/english.txt") as f:
    ALL_WORDS = [w.strip().upper() for w in f if w.strip()]
print(f"Loaded {len(ALL_WORDS)} words")

# Also add Kryptos-specific keywords
KRYPTOS_KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "INVISIBLE",
    "BERLIN", "CLOCK", "EAST", "NORTH", "NORTHEAST", "COMPASS",
    "CIA", "LANGLEY", "SANBORN", "SCHEIDT", "WEBSTER", "CARTER",
    "EGYPT", "PYRAMID", "GIZA", "PHARAOH", "ARCHAEOLOGY",
    "INTELLIGENCE", "SECRET", "CIPHER", "CODE", "ENIGMA",
    "DECEPTION", "ILLUSION", "MIRAGE", "PHANTOM",
    "SCULPTURE", "COPPER", "PETRIFIED", "LODGE",
    "WHATSTHEPOINT", "THEPOINT", "POINT",
    "MAGNETIC", "DECLINATION", "COORDINATES",
    "DESPERATELY", "SLOWLY", "PASSAGE", "DEBRIS",
    "ANCIENT", "TOMB", "UNDERGROUND", "BURIED",
]
ALL_WORDS.extend(KRYPTOS_KEYWORDS)
ALL_WORDS = list(set(ALL_WORDS))
print(f"Total keywords (with Kryptos-specific): {len(ALL_WORDS)}")

print("=" * 70)
print("E-S-76: Keyword Mixed Alphabet Filter")
print("=" * 70)

def keyword_to_alphabet(keyword):
    """Generate mixed alphabet from keyword."""
    seen = set()
    alpha = []
    for c in keyword:
        if c in IDX and c not in seen:
            seen.add(c)
            alpha.append(IDX[c])
    for i in range(26):
        if i not in seen:
            alpha.append(i)
    return alpha  # alpha[plain_idx] = cipher_idx


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


def get_constraints_per_col(order):
    """Get (pt_idx, ct_idx) constraints per column for Option B.

    Model B: CT[j] = alpha_{col}[PT[perm[j]]]
    where col = perm[j] % 7 (the original grid column of PT position perm[j])

    For crib at position p: col = p % 7, j = inv_perm[p]
    Constraint: alpha_{p%7}[IDX[PT[p]]] = CT_IDX[inv_perm[p]]
    i.e., alpha maps IDX[CRIB_DICT[p]] → CT_IDX[inv_perm[p]]
    """
    _, inv_perm = build_col_perm(order)
    constraints = {c: [] for c in range(WIDTH)}

    for p in CRIB_POS:
        col = p % WIDTH
        pt_val = IDX[CRIB_DICT[p]]
        j = inv_perm[p]
        ct_val = CT_IDX[j]
        constraints[col].append((pt_val, ct_val))

    return constraints, inv_perm


def check_alphabet_constraints(alpha, constraints):
    """Check if a keyword alphabet satisfies all constraints.
    constraint: (pt_idx, ct_idx) means alpha[pt_idx] must equal ct_idx.
    """
    for pt_v, ct_v in constraints:
        if alpha[pt_v] != ct_v:
            return False
    return True


# ── Phase 1: Count valid keywords per column for each ordering ───────────
print("\n" + "-" * 50)
print("Phase 1: Precompute all keyword alphabets")
print("-" * 50)

t0 = time.time()

# Precompute all keyword alphabets
keyword_alphabets = []
for w in ALL_WORDS:
    if len(w) < 2:
        continue
    alpha = keyword_to_alphabet(w)
    keyword_alphabets.append((w, alpha))

print(f"  {len(keyword_alphabets)} keyword alphabets precomputed")

# ── Phase 2: For each ordering, filter keywords per column ───────────────
print("\n" + "-" * 50)
print("Phase 2: Filter keywords per column for all orderings")
print("-" * 50)

all_orders = list(permutations(range(WIDTH)))
t1 = time.time()

results = []
combo_count_total = 0

for oi, order in enumerate(all_orders):
    order = list(order)
    constraints, inv_perm = get_constraints_per_col(order)

    # Check for internal conflicts (same pt mapping to different ct or vice versa)
    valid = True
    for c in range(WIDTH):
        pt_to_ct = {}
        ct_to_pt = {}
        for pt_v, ct_v in constraints[c]:
            if pt_v in pt_to_ct:
                if pt_to_ct[pt_v] != ct_v:
                    valid = False
                    break
            else:
                pt_to_ct[pt_v] = ct_v
            if ct_v in ct_to_pt:
                if ct_to_pt[ct_v] != pt_v:
                    valid = False
                    break
            else:
                ct_to_pt[ct_v] = pt_v
        if not valid:
            break

    if not valid:
        continue

    # For each column, find valid keywords
    col_valid = []
    total_combos = 1
    for c in range(WIDTH):
        valids = []
        for w, alpha in keyword_alphabets:
            if check_alphabet_constraints(alpha, constraints[c]):
                valids.append((w, alpha))
        col_valid.append(valids)
        total_combos *= max(1, len(valids))

    combo_count_total += total_combos

    # Count constraints per column
    n_constraints = [len(constraints[c]) for c in range(WIDTH)]
    min_valid = min(len(v) for v in col_valid)

    if total_combos > 0 and total_combos <= 1e12:
        results.append({
            'order': order,
            'n_constraints': n_constraints,
            'valid_per_col': [len(v) for v in col_valid],
            'total_combos': total_combos,
            'col_valid': col_valid,
        })

    if (oi + 1) % 1000 == 0:
        elapsed = time.time() - t1
        print(f"  {oi+1}/5040, {elapsed:.0f}s, {len(results)} feasible orderings")

t2 = time.time()
print(f"\n  {len(all_orders)} orderings, {len(results)} feasible, {t2-t1:.1f}s")

# Sort by total_combos (fewest first = most constrained)
results.sort(key=lambda x: x['total_combos'])

print(f"\n  Most constrained orderings:")
for i, r in enumerate(results[:20]):
    print(f"    #{i+1}: order={r['order']} combos={r['total_combos']:.0f} "
          f"valid/col={r['valid_per_col']} constraints/col={r['n_constraints']}")

# ── Phase 3: Enumerate and score small combo spaces ──────────────────────
print("\n" + "-" * 50)
print("Phase 3: Enumerate and score keyword combinations")
print("-" * 50)

MAX_COMBOS = 1_000_000  # Max combinations to enumerate per ordering

def decrypt_with_kw_alphabets(perm, alphabets_list):
    """Decrypt using keyword alphabets (simple substitution per column)."""
    inv_alphas = []
    for alpha in alphabets_list:
        inv = [0] * 26
        for i in range(26):
            inv[alpha[i]] = i
        inv_alphas.append(inv)

    pt = [0] * N
    for j in range(N):
        pt_pos = perm[j]
        col = pt_pos % WIDTH
        pt[pt_pos] = inv_alphas[col][CT_IDX[j]]
    return pt


def score_quadgrams(pt_vals):
    score = 0.0
    for i in range(len(pt_vals) - 3):
        score += QG_TABLE[pt_vals[i]*17576 + pt_vals[i+1]*676 + pt_vals[i+2]*26 + pt_vals[i+3]]
    return score / (len(pt_vals) - 3)


best_overall = {'score': -999}
t3 = time.time()
orderings_tested = 0

for r in results:
    if r['total_combos'] > MAX_COMBOS:
        continue
    if r['total_combos'] == 0:
        continue

    orderings_tested += 1
    order = r['order']
    perm, _ = build_col_perm(order)
    col_valid = r['col_valid']

    # Enumerate all combinations iteratively
    # Build all combos per column first, then iterate
    best_for_order = -999
    best_kws_for_order = None
    count = 0

    # Iterative enumeration using index arrays
    col_sizes = [len(col_valid[c]) for c in range(WIDTH)]
    if 0 in col_sizes:
        continue  # Skip if any column has no valid keywords

    indices = [0] * WIDTH
    done = False
    while not done:
        # Build current alphabets
        alphas = [col_valid[c][indices[c]][1] for c in range(WIDTH)]
        kws = [col_valid[c][indices[c]][0] for c in range(WIDTH)]

        pt = decrypt_with_kw_alphabets(perm, alphas)
        qg = score_quadgrams(pt)
        count += 1

        if qg > best_for_order:
            best_for_order = qg
            best_kws_for_order = list(kws)

        # Increment indices (odometer style)
        carry = True
        for c in range(WIDTH - 1, -1, -1):
            if carry:
                indices[c] += 1
                if indices[c] >= col_sizes[c]:
                    indices[c] = 0
                else:
                    carry = False
        if carry:
            done = True

        if count > MAX_COMBOS:
            break

    if best_for_order > best_overall['score']:
        best_overall = {
            'score': best_for_order,
            'order': order,
            'keywords': best_kws_for_order,
            'combos': count,
        }
        if best_for_order > -6.0:
            print(f"    order={order} qg/c={best_for_order:.4f} kws={best_kws_for_order} ({count} combos)")

    if orderings_tested % 10 == 0:
        elapsed = time.time() - t3
        print(f"  {orderings_tested} orderings tested, {elapsed:.0f}s, best_qg/c={best_overall['score']:.4f}")

t4 = time.time()
print(f"\n  {orderings_tested} orderings enumerated, {t4-t3:.1f}s")
print(f"  Best: qg/c={best_overall['score']:.4f} order={best_overall.get('order')} keywords={best_overall.get('keywords')}")

if best_overall.get('order') and best_overall['score'] > -8.0:
    # Decrypt and show
    perm, _ = build_col_perm(best_overall['order'])
    alphas = [keyword_to_alphabet(w) for w in best_overall['keywords']]
    pt_vals = decrypt_with_kw_alphabets(perm, alphas)
    pt_str = ''.join(AZ[v] for v in pt_vals)
    print(f"  PT: {pt_str}")

    # Verify cribs
    crib_matches = 0
    for p in CRIB_POS:
        if pt_vals[p] == IDX[CRIB_DICT[p]]:
            crib_matches += 1
    print(f"  Crib matches: {crib_matches}/24")

# ── Summary ──────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  Total orderings: {len(all_orders)}")
print(f"  Feasible (no constraint conflicts): {len(results)}")
print(f"  Enumerable (≤{MAX_COMBOS} combos): {orderings_tested}")
if results:
    print(f"  Most constrained: order={results[0]['order']} combos={results[0]['total_combos']:.0f}")
print(f"  Best: qg/c={best_overall['score']:.4f}")

if best_overall['score'] > -5.0:
    verdict = "SIGNAL — investigate"
elif best_overall['score'] > -6.0:
    verdict = "WEAK — possible but may be underdetermined"
else:
    verdict = "NO SIGNAL"

print(f"  Verdict: {verdict}")

output = {
    'experiment': 'E-S-76',
    'description': 'Keyword mixed alphabet filter',
    'feasible_orderings': len(results),
    'enumerable_orderings': orderings_tested,
    'best_qgc': best_overall['score'],
    'best_order': best_overall.get('order'),
    'best_keywords': best_overall.get('keywords'),
    'verdict': verdict,
}
os.makedirs("results", exist_ok=True)
with open("results/e_s_76_keyword_alphabet_filter.json", "w") as f:
    json.dump(output, f, indent=2)
print(f"\n  Artifact: results/e_s_76_keyword_alphabet_filter.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_76_keyword_alphabet_filter.py")
