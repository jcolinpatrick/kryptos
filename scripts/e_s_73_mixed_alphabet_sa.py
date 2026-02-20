#!/usr/bin/env python3
"""
E-S-73: 7 Mixed Alphabets + Width-7 Columnar SA

Hypothesis: K4 uses width-7 columnar transposition (Model B: trans→sub)
followed by 7 independent mixed-alphabet substitutions (one per column
position = one per residue mod 7). This is the "coding charts" hypothesis.

This is consistent with:
  - Lag-7 autocorrelation (z=3.036)
  - Crib alignment at width 7 (p=0.021)
  - K3's width-7 columnar structure
  - Model B (trans→sub) preferred over Model A
  - "Coding charts" sold at auction → physical substitution tables
  - "Change in methodology" from K3→K4
  - Non-periodic keystream (7 independent alphabets are non-periodic)

Attack: For each of 5040 column orderings:
  1. Apply inverse columnar transposition to get intermediate text
  2. Use SA to optimize 7 mixed alphabets (each a permutation of A-Z)
     to maximize quadgram score of decrypted plaintext
  3. Cribs constrain the alphabets: for each known (PT, CT_intermediate)
     pair, the alphabet for that residue must map CT→PT

SA neighborhood: swap two elements in one alphabet (preserves permutation property).
Score: quadgram log-probability of the full 97-char plaintext.

Phase 1: Test all 5040 orderings with short SA to find promising candidates
Phase 2: Deep SA on top orderings
"""

import json
import math
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

WIDTH = 7
NROWS_FULL = N // WIDTH   # 13
NROWS_EXTRA = N % WIDTH   # 6 (columns 0-5 have 14 rows, column 6 has 13)

print("=" * 70)
print("E-S-73: 7 Mixed Alphabets + Width-7 Columnar SA")
print("=" * 70)
print(f"CT length: {N}, Width: {WIDTH}")
print(f"Column lengths: {[NROWS_FULL+1]*NROWS_EXTRA + [NROWS_FULL]*(WIDTH-NROWS_EXTRA)}")

def build_col_perm(order):
    """Build the permutation for width-7 columnar transposition.

    Model B (trans→sub): The CT was produced by:
      1. Write PT into grid row by row (width 7)
      2. Read columns in key order → intermediate
      3. Apply substitution to intermediate → CT

    So to decrypt:
      1. Undo substitution: intermediate = decrypt(CT)
      2. Undo columnar: write intermediate into columns in key order, read row by row → PT

    The intermediate text positions map to PT positions via the columnar permutation.
    intermediate[j] → PT[perm[j]]

    Returns: perm such that PT[perm[j]] was read from intermediate position j.
    Also returns: inv_perm such that intermediate[inv_perm[i]] = the value that goes to PT[i].
    """
    col_lengths = []
    for col_idx in range(WIDTH):
        if col_idx < NROWS_EXTRA:
            col_lengths.append(NROWS_FULL + 1)
        else:
            col_lengths.append(NROWS_FULL)

    # Column start positions in the intermediate text
    col_starts = [0]
    for i in range(WIDTH - 1):
        col_starts.append(col_starts[-1] + col_lengths[order[i]])

    # perm[j] = PT position for intermediate position j
    # Reading columns in order: column order[0], then order[1], etc.
    # Within a column, cells go row 0, row 1, ...
    # Column c has cells at PT positions: c, c+7, c+14, ..., c+7*(col_len-1)
    perm = [0] * N
    j = 0
    for rank in range(WIDTH):
        c = order[rank]  # actual column index
        clen = col_lengths[c]
        for row in range(clen):
            pt_pos = row * WIDTH + c
            perm[j] = pt_pos
            j += 1

    # inv_perm[pt_pos] = intermediate position
    inv_perm = [0] * N
    for j in range(N):
        inv_perm[perm[j]] = j

    return perm, inv_perm


def get_crib_constraints(order):
    """Get alphabet constraints from cribs for a given column ordering.

    For each crib position p, we know PT[p] and the corresponding intermediate
    position inv_perm[p]. The intermediate position mod 7 tells us which
    alphabet applies (wait, actually under Model B trans→sub, the substitution
    is applied AFTER transposition).

    Model B encryption:
      1. PT → columnar trans → intermediate
      2. intermediate → substitution → CT

    So CT[j] = alphabet[j % 7].encrypt(intermediate[j])
    And intermediate[j] = PT[perm[j]]  (where perm comes from columnar)

    Therefore: CT[j] = alphabet[j % 7].encrypt(PT[perm[j]])

    Wait, but the substitution indices should be based on the CT position (j),
    not the intermediate position. Under Model B, substitution is the SECOND step,
    applied to the intermediate text position-by-position.

    Actually for position-dependent alphabets, there's a question: are the 7
    alphabets indexed by the CT/intermediate position (j mod 7), or by the
    PT position (perm[j] mod 7, which equals the column number)?

    Option A: alphabets indexed by CT position (j mod 7)
      - This means alphabet changes every position in reading order
      - Not connected to column structure

    Option B: alphabets indexed by column (one alphabet per column)
      - This IS connected to the columnar structure
      - Each column uses one alphabet consistently
      - This is more natural for "coding charts" (one chart per column)

    Let's try BOTH, but Option B first as it's more natural.

    Under Option B:
      Column c uses alphabet[c]
      CT[j] = alphabet[column_of_j].encrypt(intermediate[j])
      intermediate[j] = PT[perm[j]], and perm[j] is in column order[rank] for rank-th column

      Actually, j indexes the intermediate text. For intermediate position j,
      it came from some column. Which column? The first col_lengths[order[0]] positions
      are from column order[0], etc.

      For crib position p (known PT):
        intermediate_pos = inv_perm[p]
        Which column produced intermediate_pos? It's the column that p belongs to in the grid.
        p's column = p mod 7 (since PT is written row-by-row into width-7 grid)

    So for Option B:
      alphabet[p % 7].encrypt(PT[p]) = CT[inv_perm[p]]
      i.e., alphabet[p % 7][IDX[PT[p]]] = IDX[CT[inv_perm[p]]]

      Wait, but that's saying the alphabet for column (p%7) maps PT[p] to CT[inv_perm[p]].

    For Option A:
      intermediate position j = inv_perm[p]
      alphabet[j % 7].encrypt(PT[p]) = CT[j]
      Hmm, but CT and intermediate have the same positional indexing here.

      Actually no. Model B:
        intermediate = columnar_trans(PT)  → positions 0..96
        CT[j] = sub(intermediate[j], j)   for some position-dependent sub

      So CT[j] = alphabet[j % 7](intermediate[j])
      And intermediate[j] = PT[perm[j]]
      So CT[j] = alphabet[j % 7](PT[perm[j]])

      For crib: if we know PT[p], then j = inv_perm[p] gives us:
        CT[inv_perm[p]] = alphabet[inv_perm[p] % 7](PT[p])

    Hmm, for Option A, the alphabet index depends on inv_perm[p] % 7, which varies
    with the column ordering.

    For Option B, the alphabet index is p % 7, which is fixed regardless of ordering.
    But then CT[inv_perm[p]] is what the alphabet produces, and that varies with ordering.

    Let me be more careful:

    OPTION B (one alphabet per column, most natural):
      The grid has 7 columns. Column c uses alphabet alpha_c.
      After columnar transposition, columns are read in key order.
      The substitution is then applied. But where? Before or after reading columns?

      If substitution is per-column (applied to each column independently before
      reading them out):
        For each cell (row, col) in grid:
          CT_cell = alpha_col(PT_cell)
        Then read columns in key order to produce CT.

      This means: for PT position p, column = p%7, row = p//7
        CT at position (start_of_column_rank + row) = alpha_{p%7}(PT[p])
        where column_rank is the position of column p%7 in the ordering.

      So: CT[inv_perm[p]] = alpha_{p%7}(PT[p])
      Constraint: alpha_{p%7} maps PT[p] → CT[inv_perm[p]]

    OPTION A (alphabet based on output position):
      CT[j] = alpha_{j%7}(intermediate[j]) = alpha_{j%7}(PT[perm[j]])
      For crib at p: j = inv_perm[p], so:
        CT[inv_perm[p]] = alpha_{inv_perm[p] % 7}(PT[p])

    Both options give the same form of constraint but with different alphabet indexing.
    Let me try Option B first.
    """
    _, inv_perm = build_col_perm(order)

    # constraints[col] = list of (pt_letter_idx, ct_letter_idx) pairs
    constraints = {c: [] for c in range(WIDTH)}

    for p in CRIB_POS:
        col = p % WIDTH
        pt_val = IDX[CRIB_DICT[p]]
        j = inv_perm[p]  # intermediate/CT position
        ct_val = CT_IDX[j]
        constraints[col].append((pt_val, ct_val))

    # Check for conflicts: same pt_val mapping to different ct_val (or vice versa)
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

    return constraints, valid, inv_perm


def init_alphabets(constraints):
    """Initialize 7 alphabets respecting crib constraints.
    Each alphabet is a permutation: alpha[c][i] = j means letter i encrypts to letter j.
    """
    alphabets = []
    for c in range(WIDTH):
        # Start with identity
        alpha = list(range(26))

        # Apply constraints
        fixed_pt = set()
        fixed_ct = set()
        pt_to_ct = {}
        for pt_v, ct_v in constraints[c]:
            pt_to_ct[pt_v] = ct_v
            fixed_pt.add(pt_v)
            fixed_ct.add(ct_v)

        # Place fixed mappings
        # First, figure out what's currently at those positions
        # We need alpha[pt_v] = ct_v for all constraints
        for pt_v, ct_v in pt_to_ct.items():
            # Find where ct_v currently is
            current_pos = alpha.index(ct_v)
            # Swap alpha[pt_v] and alpha[current_pos]
            alpha[current_pos] = alpha[pt_v]
            alpha[pt_v] = ct_v

        # Shuffle non-fixed positions
        free_pts = [i for i in range(26) if i not in fixed_pt]
        free_cts = [alpha[i] for i in free_pts]
        random.shuffle(free_cts)
        for i, pt in enumerate(free_pts):
            alpha[pt] = free_cts[i]

        alphabets.append(alpha)

    return alphabets


def decrypt_with_alphabets(perm, alphabets):
    """Decrypt CT using column permutation and 7 mixed alphabets.

    Model B (Option B): CT[j] = alpha_{perm[j]%7}(PT[perm[j]])
    So: PT[perm[j]] = inv_alpha_{perm[j]%7}(CT[j])
    """
    # Build inverse alphabets
    inv_alphas = []
    for alpha in alphabets:
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
    """Score plaintext quadgrams."""
    score = 0.0
    for i in range(len(pt_vals) - 3):
        score += QG_TABLE[pt_vals[i]*17576 + pt_vals[i+1]*676 + pt_vals[i+2]*26 + pt_vals[i+3]]
    return score


def sa_mixed_alphabets(order, constraints, n_iters=50000, T_start=1.0, T_min=0.001, seed=None):
    """SA to optimize 7 mixed alphabets for a given column ordering."""
    if seed is not None:
        random.seed(seed)

    perm, _ = build_col_perm(order)
    alphabets = init_alphabets(constraints)

    # Precompute fixed positions per alphabet
    fixed = []
    for c in range(WIDTH):
        fixed_pts = set()
        for pt_v, ct_v in constraints[c]:
            fixed_pts.add(pt_v)
        fixed.append(fixed_pts)

    # Free positions per alphabet (positions we can swap)
    free_pos = []
    for c in range(WIDTH):
        free_pos.append([i for i in range(26) if i not in fixed[c]])

    pt_vals = decrypt_with_alphabets(perm, alphabets)
    current_score = score_quadgrams(pt_vals)

    best_score = current_score
    best_alphabets = [list(a) for a in alphabets]

    alpha_decay = (T_min / T_start) ** (1.0 / n_iters)
    T = T_start

    for step in range(n_iters):
        # Pick a random alphabet
        c = random.randint(0, WIDTH - 1)
        fp = free_pos[c]
        if len(fp) < 2:
            T *= alpha_decay
            continue

        # Swap two free positions in this alphabet
        i1, i2 = random.sample(fp, 2)

        # Swap
        alphabets[c][i1], alphabets[c][i2] = alphabets[c][i2], alphabets[c][i1]

        new_pt = decrypt_with_alphabets(perm, alphabets)
        new_score = score_quadgrams(new_pt)

        delta = new_score - current_score
        if delta > 0 or random.random() < math.exp(delta / T):
            current_score = new_score
            pt_vals = new_pt
            if current_score > best_score:
                best_score = current_score
                best_alphabets = [list(a) for a in alphabets]
        else:
            # Undo swap
            alphabets[c][i1], alphabets[c][i2] = alphabets[c][i2], alphabets[c][i1]

        T *= alpha_decay

    return best_score, best_alphabets


# ── Phase 1: Quick screen of all 5040 orderings ─────────────────────────
print("\n" + "-" * 50)
print("Phase 1: Screen all 5040 orderings (short SA per ordering)")
print("-" * 50)

random.seed(42)
all_orders = list(permutations(range(WIDTH)))
print(f"  Testing {len(all_orders)} orderings × 2 options (A/B) × 20K SA steps")

results = []
t0 = time.time()
valid_count = 0
best_global = -999

for idx, order in enumerate(all_orders):
    order = list(order)

    # Option B: alphabets indexed by column
    constraints_b, valid_b, inv_perm_b = get_crib_constraints(order)

    if valid_b:
        valid_count += 1
        score_b, alphas_b = sa_mixed_alphabets(order, constraints_b, n_iters=20000, T_start=2.0, seed=42+idx)
        qg_per_char = score_b / (N - 3)

        results.append({
            'order': order,
            'option': 'B',
            'score': score_b,
            'qg_per_char': qg_per_char,
            'alphabets': alphas_b,
            'n_constraints': sum(len(v) for v in constraints_b.values()),
        })

        if score_b > best_global:
            best_global = score_b

    if (idx + 1) % 1000 == 0:
        elapsed = time.time() - t0
        print(f"  {idx+1}/5040, {elapsed:.0f}s, valid={valid_count}, best_qg={best_global/(N-3):.4f}")

t1 = time.time()
print(f"\n  {len(all_orders)} orderings, {valid_count} valid, {t1-t0:.1f}s")

# Sort by score
results.sort(key=lambda x: -x['score'])

# Print top 20
print(f"\n  Top 20 orderings:")
for i, r in enumerate(results[:20]):
    print(f"    #{i+1}: order={r['order']} qg/c={r['qg_per_char']:.4f} constraints={r['n_constraints']}")

# ── Phase 2: Deep SA on top orderings ────────────────────────────────────
print("\n" + "-" * 50)
print("Phase 2: Deep SA on top 50 orderings (200K steps × 10 restarts)")
print("-" * 50)

top_n = min(50, len(results))
deep_results = []
t2 = time.time()

for rank in range(top_n):
    r = results[rank]
    order = r['order']
    constraints_b, valid_b, _ = get_crib_constraints(order)

    best_for_order = r['score']
    best_alphas_for_order = r['alphabets']

    for restart in range(10):
        score, alphas = sa_mixed_alphabets(
            order, constraints_b,
            n_iters=200000, T_start=5.0, T_min=0.0001,
            seed=1000*rank + restart
        )
        if score > best_for_order:
            best_for_order = score
            best_alphas_for_order = alphas

    deep_results.append({
        'order': order,
        'score': best_for_order,
        'qg_per_char': best_for_order / (N - 3),
        'alphabets': best_alphas_for_order,
    })

    if (rank + 1) % 10 == 0:
        elapsed = time.time() - t2
        print(f"  {rank+1}/{top_n}, {elapsed:.0f}s")

t3 = time.time()
deep_results.sort(key=lambda x: -x['score'])

print(f"\n  Deep SA: {top_n} orderings × 10 restarts × 200K steps, {t3-t2:.1f}s")
print(f"\n  Top 10 after deep SA:")
for i, r in enumerate(deep_results[:10]):
    # Decrypt and show plaintext
    perm, _ = build_col_perm(r['order'])
    pt_vals = decrypt_with_alphabets(perm, r['alphabets'])
    pt_str = ''.join(AZ[v] for v in pt_vals)
    print(f"    #{i+1}: order={r['order']} qg/c={r['qg_per_char']:.4f}")
    print(f"          PT: {pt_str}")

# ── Phase 3: Option A (alphabets by output position) ────────────────────
print("\n" + "-" * 50)
print("Phase 3: Option A (alphabets by intermediate position, j%7)")
print("-" * 50)

def get_crib_constraints_optA(order):
    """Option A: alphabet index = intermediate position % 7."""
    _, inv_perm = build_col_perm(order)

    constraints = {c: [] for c in range(WIDTH)}

    for p in CRIB_POS:
        j = inv_perm[p]
        alph_idx = j % WIDTH
        pt_val = IDX[CRIB_DICT[p]]
        ct_val = CT_IDX[j]
        constraints[alph_idx].append((pt_val, ct_val))

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

    return constraints, valid, inv_perm

def decrypt_optA(perm, alphabets):
    """Decrypt with Option A: CT[j] = alpha_{j%7}(PT[perm[j]])."""
    inv_alphas = []
    for alpha in alphabets:
        inv = [0] * 26
        for i in range(26):
            inv[alpha[i]] = i
        inv_alphas.append(inv)

    pt = [0] * N
    for j in range(N):
        pt_pos = perm[j]
        alph_idx = j % WIDTH
        pt[pt_pos] = inv_alphas[alph_idx][CT_IDX[j]]

    return pt

# Test top 100 orderings from Phase 1 with Option A
optA_results = []
t4 = time.time()
optA_valid = 0

for idx, order in enumerate(all_orders):
    order = list(order)
    constraints_a, valid_a, inv_perm_a = get_crib_constraints_optA(order)

    if valid_a:
        optA_valid += 1
        score_a, alphas_a = sa_mixed_alphabets(order, constraints_a, n_iters=20000, T_start=2.0, seed=99999+idx)

        # But decrypt with Option A
        perm, _ = build_col_perm(order)
        pt_vals = decrypt_optA(perm, alphas_a)
        score_actual = score_quadgrams(pt_vals)

        optA_results.append({
            'order': order,
            'score': score_actual,
            'qg_per_char': score_actual / (N - 3),
        })

    if (idx + 1) % 1000 == 0:
        elapsed = time.time() - t4
        best_a = max((r['qg_per_char'] for r in optA_results), default=-999)
        print(f"  {idx+1}/5040, {elapsed:.0f}s, valid={optA_valid}, best_qg/c={best_a:.4f}")

t5 = time.time()
optA_results.sort(key=lambda x: -x['score'])
print(f"\n  Option A: {len(optA_results)} valid orderings, {t5-t4:.1f}s")
print(f"  Top 5:")
for i, r in enumerate(optA_results[:5]):
    print(f"    #{i+1}: order={r['order']} qg/c={r['qg_per_char']:.4f}")


# ── Summary ──────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)

best_b = deep_results[0] if deep_results else None
best_a = optA_results[0] if optA_results else None

if best_b:
    print(f"  Option B (per-column alphabets): best qg/c = {best_b['qg_per_char']:.4f}")
    perm, _ = build_col_perm(best_b['order'])
    pt_vals = decrypt_with_alphabets(perm, best_b['alphabets'])
    pt_str = ''.join(AZ[v] for v in pt_vals)
    print(f"    order={best_b['order']}")
    print(f"    PT: {pt_str}")

if best_a:
    print(f"  Option A (per-position alphabets): best qg/c = {best_a['qg_per_char']:.4f}")
    print(f"    order={best_a['order']}")

# English reference: qg/c ≈ -4.285, random ≈ -10.5
# If SA can find orderings that significantly outperform others, that's signal
ENGLISH_QG = -4.285
RANDOM_QG = -10.5

print(f"\n  Reference: English qg/c ≈ {ENGLISH_QG}, random ≈ {RANDOM_QG}")

# Check if there's variance in top scores (if all orderings give similar scores,
# the approach is underdetermined)
if len(deep_results) >= 10:
    scores = [r['qg_per_char'] for r in deep_results[:10]]
    score_range = max(scores) - min(scores)
    print(f"  Top-10 score range: {score_range:.4f} (small = underdetermined)")

# Verdict
if best_b and best_b['qg_per_char'] > -5.0:
    verdict = "PROMISING — investigate further"
elif best_b and best_b['qg_per_char'] > -6.0:
    verdict = "WEAK — possible underdetermination artifact"
else:
    verdict = "NO SIGNAL — noise level"

print(f"\n  Verdict: {verdict}")

# Save results
output = {
    'experiment': 'E-S-73',
    'description': '7 mixed alphabets + width-7 columnar SA',
    'option_b_best_qgc': best_b['qg_per_char'] if best_b else None,
    'option_b_order': best_b['order'] if best_b else None,
    'option_a_best_qgc': best_a['qg_per_char'] if best_a else None,
    'option_a_order': best_a['order'] if best_a else None,
    'valid_b': valid_count,
    'valid_a': optA_valid,
    'verdict': verdict,
}
os.makedirs("results", exist_ok=True)
with open("results/e_s_73_mixed_alphabet_sa.json", "w") as f:
    json.dump(output, f, indent=2)
print(f"\n  Artifact: results/e_s_73_mixed_alphabet_sa.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_73_mixed_alphabet_sa.py")
