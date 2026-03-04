#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: substitution
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-107: Shifted Keyword-Mixed Alphabets + Width-7 Columnar.

HYPOTHESIS: K4 uses a tableau where each of 7 sub-alphabets is the SAME
keyword-mixed alphabet shifted by different amounts. The "coding charts"
would be 7 versions of this shifted alphabet.

Structure (Model B: trans→sub):
  1. Columnar transposition (width 7, unknown ordering)
  2. Position-dependent substitution: CT[i] = mixed_alph[(mixed_inv[trans(PT)[i]] + shift[i%7]) % 26]

This differs from standard Vigenère in that the ALPHABET is mixed (not standard),
and the shifts are applied WITHIN the mixed alphabet ordering.

Search space per (keyword, ordering):
  - 7 shift values determined by constraint propagation from cribs
  - So it's 370K keywords × 5040 orderings = 1.86B, but constraint prop. is O(24) each

Also test:
  P1: Keyword-mixed shifted alphabets + all w7 orderings (370K × 5040 with constraints)
  P2: Double-shifted: different keyword for trans and for alphabet (keyword_pairs × 5040)
  P3: Affine on mixed alphabet: CT[i] = mixed_alph[(a * mixed_inv[intermediate[i]] + b) % 26]
      for each of 7 residues, (a,b) pair. a must be coprime to 26 (12 values).

Output: results/e_s_107_shifted_mixed_alpha.json
"""
import json
import time
import sys
import os
from itertools import permutations

sys.path.insert(0, "src")
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS, CRIB_POSITIONS,
)

CT_IDX = [ALPH_IDX[c] for c in CT]
PT_AT_CRIB = {p: ALPH_IDX[ch] for p, ch in CRIB_DICT.items()}
CRIB_POS = sorted(CRIB_POSITIONS)
N = CT_LEN
WIDTH = 7

# Column heights for 97 chars
NROWS = N // WIDTH  # 13
EXTRA = N % WIDTH   # 6


def keyword_to_mixed_alphabet(keyword):
    """Generate keyword-mixed alphabet."""
    seen = set()
    mixed = []
    for c in keyword.upper():
        if c in ALPH_IDX and c not in seen:
            seen.add(c)
            mixed.append(c)
    for c in ALPH:
        if c not in seen:
            mixed.append(c)
    return ''.join(mixed)


def keyword_to_order(keyword):
    return sorted(range(len(keyword)), key=lambda i: (keyword[i], i))


def build_columnar_perm(order):
    """perm[output_pos] = input_pos (gather)."""
    w = len(order)
    nf = N // w
    extra = N % w
    heights = [nf + (1 if c < extra else 0) for c in range(w)]
    perm = []
    for rank in range(w):
        col = order[rank]
        for row in range(heights[col]):
            perm.append(row * w + col)
    return perm


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


print("=" * 70)
print("E-S-107: Shifted Keyword-Mixed Alphabets + Width-7 Columnar")
print("=" * 70)
t0 = time.time()

results = {}
best_overall = 0
best_config = ""

# Load wordlist
wordlist_path = "wordlists/english.txt"
if os.path.exists(wordlist_path):
    with open(wordlist_path) as f:
        all_words = [w.strip().upper() for w in f if 3 <= len(w.strip()) <= 15]
    # Filter to unique-enough keywords (at least 4 distinct letters)
    wordlist = []
    seen_alphas = set()
    for w in all_words:
        alpha = keyword_to_mixed_alphabet(w)
        if alpha not in seen_alphas:
            seen_alphas.add(alpha)
            wordlist.append(w)
    print(f"Loaded {len(wordlist)} unique-alphabet keywords from wordlist")
else:
    wordlist = []
    print("WARNING: wordlist not found, using thematic keywords only")

THEMATIC_KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "BERLIN",
    "SANBORN", "MEDUSA", "LUCIFER", "ENIGMA", "INVISIBLE",
    "CLOCK", "EAST", "NORTH", "EGYPT", "CARTER", "PHARAOH",
    "ILLUSION", "IQLUSION", "MAGNETIC", "LANGLEY", "BURIED",
    "DESPARATLY", "WHATSTHEPOINT", "TUTANKHAMUN",
]

# ===========================================================================
# Phase 1: Thematic keywords + all w7 orderings
# For each (keyword, ordering), use constraint propagation from 24 cribs
# ===========================================================================
print("\n--- Phase 1: Thematic keywords + shifted mixed alphabet + all w7 ---")

def test_shifted_mixed(alpha_str, ordering):
    """Test if shifted keyword-mixed alphabet works with this ordering.

    Model B: trans then sub.
    CT[i] = alpha[(alpha_inv[intermediate[i]] + shift[i_orig_col]) % 26]
    where intermediate = trans(PT) via columnar(ordering).

    Actually, for Model B with column-dependent key:
    After transposition, position i in the CT corresponds to some position in
    the transposed text. The substitution key depends on the CT position.

    CT[i] = alpha[(alpha_inv[transposed[i]] + shift[i % 7]) % 26]

    Wait, need to be more careful about what "i % 7" means.
    In the columnar grid, CT position i maps to column col_of(i) where
    col_of depends on the column ordering.

    For Model B with period-7 key:
    shift depends on CT_position mod 7... but CT positions in a columnar
    cipher are grouped by column, NOT interleaved.

    Alternative: shift depends on the ROW in the grid.
    Or: shift depends on the original PT position mod 7.

    Let's test multiple models:
    Model B1: shift depends on CT position (i) mod 7
    Model B2: shift depends on the COLUMN in the original grid that this CT position came from
    """
    alpha_idx = {c: i for i, c in enumerate(alpha_str)}

    # Build the transposition permutation
    perm = build_columnar_perm(ordering)
    # perm[ct_pos] = pt_pos (gather convention)

    # For each crib position pt_pos:
    # Find which CT position it maps to: ct_pos such that perm[ct_pos] = pt_pos
    inv = invert_perm(perm)
    # inv[pt_pos] = ct_pos

    # Under Model B: CT[ct_pos] = sub(PT[pt_pos], key_at_ct_pos)
    # With shifted mixed alpha: sub(x, shift) = alpha[(alpha_idx[x] + shift) % 26]
    # So: alpha_idx[CT[ct_pos]] = (alpha_idx[PT[pt_pos]] + shift) % 26
    # shift = (alpha_idx[CT[ct_pos]] - alpha_idx[PT[pt_pos]]) % 26

    # Model B1: shift depends on ct_pos % 7
    # Model B2: shift depends on pt_pos % 7

    for model_name, residue_func in [("B1", lambda ct_p, pt_p: ct_p % 7),
                                      ("B2", lambda ct_p, pt_p: pt_p % 7)]:
        shifts = {}  # residue → set of required shifts
        consistent = True
        for pt_pos in CRIB_POS:
            ct_pos = inv[pt_pos]
            pt_val = PT_AT_CRIB[pt_pos]
            ct_val = CT_IDX[ct_pos]

            pt_in_alpha = alpha_idx[ALPH[pt_val]]
            ct_in_alpha = alpha_idx[ALPH[ct_val]]
            required_shift = (ct_in_alpha - pt_in_alpha) % 26

            residue = residue_func(ct_pos, pt_pos)
            if residue in shifts:
                if shifts[residue] != required_shift:
                    consistent = False
                    break
            else:
                shifts[residue] = required_shift

        if consistent:
            return True, model_name, shifts

    return False, None, None


best_p1 = 0
survivors_p1 = []
n_tested = 0

for kw in THEMATIC_KEYWORDS:
    alpha = keyword_to_mixed_alphabet(kw)
    n_survive = 0
    for order in permutations(range(WIDTH)):
        order = list(order)
        ok, model, shifts = test_shifted_mixed(alpha, order)
        n_tested += 1
        if ok:
            n_survive += 1
            survivors_p1.append({"keyword": kw, "order": order, "model": model, "shifts": shifts})
    if n_survive > 0:
        print(f"  {kw}: {n_survive} survivors!", flush=True)

print(f"P1: {n_tested} configs tested, {len(survivors_p1)} survivors")
results["P1_thematic"] = {"n_tested": n_tested, "n_survivors": len(survivors_p1)}
if survivors_p1:
    # Show details
    for s in survivors_p1[:20]:
        print(f"  SURVIVOR: kw={s['keyword']}, order={s['order']}, model={s['model']}, shifts={s['shifts']}")
    results["P1_survivors"] = [str(s) for s in survivors_p1[:50]]

# ===========================================================================
# Phase 2: Full wordlist scan (if available)
# ===========================================================================
if wordlist:
    print(f"\n--- Phase 2: Full wordlist ({len(wordlist)} keywords) + all w7 ---")

    survivors_p2 = []
    n_tested_p2 = 0
    batch_size = 1000

    for wi, kw in enumerate(wordlist):
        alpha = keyword_to_mixed_alphabet(kw)
        for order in permutations(range(WIDTH)):
            order = list(order)
            ok, model, shifts = test_shifted_mixed(alpha, order)
            n_tested_p2 += 1
            if ok:
                survivors_p2.append({"keyword": kw, "order": order, "model": model})

        if (wi + 1) % batch_size == 0:
            elapsed_so_far = time.time() - t0
            rate = n_tested_p2 / elapsed_so_far
            remaining = (len(wordlist) - wi - 1) * 5040 / rate
            print(f"  {wi+1}/{len(wordlist)} keywords, {len(survivors_p2)} survivors, "
                  f"rate={rate:.0f}/s, ETA={remaining:.0f}s", flush=True)

            # Early termination if taking too long
            if elapsed_so_far > 600 and wi < len(wordlist) * 0.1:
                print(f"  WARNING: Only {wi+1}/{len(wordlist)} done in {elapsed_so_far:.0f}s, "
                      f"truncating to thematic keywords only")
                break

    print(f"P2: {n_tested_p2} configs tested, {len(survivors_p2)} survivors")
    results["P2_wordlist"] = {"n_tested": n_tested_p2, "n_survivors": len(survivors_p2)}
    if survivors_p2:
        for s in survivors_p2[:20]:
            print(f"  SURVIVOR: kw={s['keyword']}, order={s['order']}, model={s['model']}")
        results["P2_survivors"] = [str(s) for s in survivors_p2[:50]]

# ===========================================================================
# Phase 3: Affine on mixed alphabet (a,b per residue instead of just b)
# Coprime a values: 1,3,5,7,9,11,15,17,19,21,23,25 (12 values)
# ===========================================================================
print("\n--- Phase 3: Affine mixed alphabet (thematic keywords) ---")

COPRIMES = [a for a in range(1, 26) if pow(a, 1, 2) != 0 or a == 1]
# Actually: gcd(a, 26) == 1
import math
COPRIMES = [a for a in range(1, 26) if math.gcd(a, 26) == 1]
print(f"  Coprime values: {COPRIMES} ({len(COPRIMES)} values)")

def test_affine_mixed(alpha_str, ordering):
    """Test affine substitution on mixed alphabet.

    CT[ct_pos] = alpha[(a_r * alpha_inv[PT[pt_pos]] + b_r) % 26]
    where r = pt_pos % 7 (Model B2)

    From two cribs in same residue:
    alpha_inv[CT1] = a * alpha_inv[PT1] + b (mod 26)
    alpha_inv[CT2] = a * alpha_inv[PT2] + b (mod 26)
    => alpha_inv[CT1] - alpha_inv[CT2] = a * (alpha_inv[PT1] - alpha_inv[PT2]) (mod 26)
    => a = (alpha_inv[CT1] - alpha_inv[CT2]) * inv(alpha_inv[PT1] - alpha_inv[PT2]) (mod 26)
    """
    alpha_idx = {c: i for i, c in enumerate(alpha_str)}
    perm = build_columnar_perm(ordering)
    inv = invert_perm(perm)

    # Collect constraints per residue (Model B2: residue = pt_pos % 7)
    residue_constraints = {}  # r → list of (alpha_inv_pt, alpha_inv_ct)
    for pt_pos in CRIB_POS:
        ct_pos = inv[pt_pos]
        pt_val = PT_AT_CRIB[pt_pos]
        ct_val = CT_IDX[ct_pos]
        pt_in_alpha = alpha_idx[ALPH[pt_val]]
        ct_in_alpha = alpha_idx[ALPH[ct_val]]
        r = pt_pos % 7
        if r not in residue_constraints:
            residue_constraints[r] = []
        residue_constraints[r].append((pt_in_alpha, ct_in_alpha))

    # For each residue, check if an (a, b) pair exists
    affine_params = {}
    for r, constraints in residue_constraints.items():
        if len(constraints) < 2:
            # Only 1 constraint: any (a, b) works for this residue (12×26 = 312 options)
            # Can't discriminate, accept
            affine_params[r] = "underdetermined"
            continue

        # Try all coprime a values
        valid_a = set()
        for a in COPRIMES:
            # Check all pairs
            b_val = None
            ok = True
            for (px, cx) in constraints:
                b_needed = (cx - a * px) % 26
                if b_val is None:
                    b_val = b_needed
                elif b_val != b_needed:
                    ok = False
                    break
            if ok:
                valid_a.add((a, b_val))

        if not valid_a:
            return False, None
        affine_params[r] = valid_a

    # Check if there's at least one valid (a_r, b_r) per residue
    all_determined = all(v != "underdetermined" for v in affine_params.values())
    return True, affine_params


survivors_p3 = []
n_tested_p3 = 0

for kw in THEMATIC_KEYWORDS:
    alpha = keyword_to_mixed_alphabet(kw)
    for order in permutations(range(WIDTH)):
        order = list(order)
        ok, params = test_affine_mixed(alpha, order)
        n_tested_p3 += 1
        if ok:
            survivors_p3.append({"keyword": kw, "order": order, "params": str(params)})

print(f"P3: {n_tested_p3} configs tested, {len(survivors_p3)} survivors")
results["P3_affine"] = {"n_tested": n_tested_p3, "n_survivors": len(survivors_p3)}
if survivors_p3:
    # This might have many survivors due to underdetermination
    print(f"  First 5 survivors:")
    for s in survivors_p3[:5]:
        print(f"    kw={s['keyword']}, order={s['order']}")
    results["P3_sample"] = [str(s) for s in survivors_p3[:20]]

# ===========================================================================
# Phase 4: Standard alphabet (no keyword mixing) with shifts per residue
# This is just standard periodic Vig — included as sanity check
# ===========================================================================
print("\n--- Phase 4: Standard alphabet + shifts (sanity = periodic Vig) ---")
survivors_p4 = 0
for order in permutations(range(WIDTH)):
    order = list(order)
    ok, _, _ = test_shifted_mixed(ALPH, order)
    if ok:
        survivors_p4 += 1
print(f"P4 sanity (standard Vig p=7 + w7): {survivors_p4}/5040 survivors")
results["P4_sanity"] = {"survivors": survivors_p4}

# ===========================================================================
# Summary
# ===========================================================================
elapsed = time.time() - t0
print(f"\n{'='*70}")
print(f"E-S-107 COMPLETE — elapsed: {elapsed:.1f}s")
print(f"P1 survivors: {len(survivors_p1)}")
print(f"P3 survivors: {len(survivors_p3)}")
print(f"P4 sanity (should be 0): {survivors_p4}")
print(f"{'='*70}")

results["elapsed_seconds"] = elapsed

os.makedirs("results", exist_ok=True)
with open("results/e_s_107_shifted_mixed_alpha.json", "w") as f:
    json.dump({"experiment": "E-S-107",
               "description": "Shifted keyword-mixed alphabets + w7 columnar",
               "results": results}, f, indent=2, default=str)

print(f"\nResults saved to results/e_s_107_shifted_mixed_alpha.json")
