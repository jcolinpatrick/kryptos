#!/usr/bin/env python3
"""
Investigation 1: Period-13 Mixed-Alphabet Beaufort (Quagmire III/IV style)

Cipher: quagmire_per_residue
Family: analysis
Status: active
Keyspace: ~1.5M keyword combinations + exhaustive short-keyword search
Last run:
Best score:

KEY INSIGHT: All prior periodic sub eliminations used the SAME alphabet at all
residue classes. This investigates per-residue DIFFERENT keyword-mixed alphabets.

Under Beaufort with alphabet alpha_r at residue r = i mod 13:
  K[i] = (alpha_r.index(CT[i]) + alpha_r.index(PT[i])) mod 26

ENE covers all 13 residues exactly once (pos 21-33).
BCL covers 11/13 residues (pos 63-73, missing residues 9, 10).

For the 11 doubly-constrained residues: subtracting the two Beaufort equations gives
  alpha_r.index(CT_ene) - alpha_r.index(CT_bcl) = alpha_r.index(PT_ene) - alpha_r.index(PT_bcl) mod 26

For a keyword-mixed alphabet alpha = keyword_mixed_alphabet(W), this difference
constraint depends on W. We search for keywords that satisfy it at each residue.

If all 11 residues can be satisfied (possibly with same or different keywords),
we have a valid period-13 cipher model. Decrypt all 97 chars and score by quadgrams.
"""

import sys, os, time, json, itertools
from pathlib import Path
from collections import defaultdict
from multiprocessing import Pool, cpu_count

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kryptos.kernel.constants import CT, ALPH, MOD
from kryptos.kernel.alphabet import keyword_mixed_alphabet

t0 = time.time()

# ── Constants ──────────────────────────────────────────────────────────────
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
N = len(CT)
I2N = {c: i for i, c in enumerate(AZ)}
N2L = {i: c for i, c in enumerate(AZ)}

ENE_START, ENE_TEXT = 21, "EASTNORTHEAST"
BCL_START, BCL_TEXT = 63, "BERLINCLOCK"
PERIOD = 13

# Crib positions and key values
CRIB_POS = list(range(ENE_START, ENE_START + len(ENE_TEXT))) + \
           list(range(BCL_START, BCL_START + len(BCL_TEXT)))
PT_AT = {}
for i, ch in enumerate(ENE_TEXT):
    PT_AT[ENE_START + i] = ch
for i, ch in enumerate(BCL_TEXT):
    PT_AT[BCL_START + i] = ch

# Load quadgrams
QUADGRAMS = None
try:
    qg_path = "/home/cpatrick/kryptos/data/english_quadgrams.json"
    if os.path.exists(qg_path):
        with open(qg_path) as f:
            QUADGRAMS = json.load(f)
        QG_FLOOR = min(QUADGRAMS.values()) - 1
except Exception:
    pass

def qg_score(text):
    if QUADGRAMS is None or len(text) < 4:
        return -99.0
    s = sum(QUADGRAMS.get(text[i:i+4], QG_FLOOR) for i in range(len(text) - 3))
    return s / len(text)

# ── Build residue constraints ─────────────────────────────────────────────
# For each residue r (mod 13), identify which crib positions fall in it
residue_positions = defaultdict(list)
for pos in CRIB_POS:
    r = pos % PERIOD
    residue_positions[r].append(pos)

# ENE covers residues 8,9,10,11,12,0,1,2,3,4,5,6,7 (all 13)
# BCL covers residues 11,12,0,1,2,3,4,5,6,7,8 (11/13, missing 9,10)

print("=" * 80)
print("INVESTIGATION 1: Period-13 Mixed-Alphabet Beaufort")
print("=" * 80)
print(f"CT: {CT} ({N} chars)")
print(f"Period: {PERIOD}")
print()

# For each residue with 2 constraints (ENE and BCL):
# alpha.index(CT_ene) - alpha.index(CT_bcl) must = alpha.index(PT_ene) - alpha.index(PT_bcl) mod 26
doubly_constrained = {}  # r -> (ct_ene, pt_ene, ct_bcl, pt_bcl)
for r in range(PERIOD):
    positions = residue_positions[r]
    ene_pos = [p for p in positions if ENE_START <= p <= ENE_START + 12]
    bcl_pos = [p for p in positions if BCL_START <= p <= BCL_START + 10]
    if ene_pos and bcl_pos:
        ep = ene_pos[0]
        bp = bcl_pos[0]
        doubly_constrained[r] = (CT[ep], PT_AT[ep], CT[bp], PT_AT[bp])

print(f"Doubly-constrained residues: {sorted(doubly_constrained.keys())}")
print(f"Singly-constrained residues (ENE only): {sorted(set(range(PERIOD)) - set(doubly_constrained.keys()))}")

# ── Phase 1: Difference constraint for each residue ──────────────────────
print("\n" + "=" * 80)
print("PHASE 1: Difference constraints per residue")
print("=" * 80)

# For each doubly-constrained residue, compute the required difference
# Under Beaufort: K = (alpha.index(CT) + alpha.index(PT)) mod 26
# Two constraints at same residue:
#   alpha.index(CT1) + alpha.index(PT1) = alpha.index(CT2) + alpha.index(PT2) mod 26
#   => alpha.index(CT1) - alpha.index(CT2) = alpha.index(PT2) - alpha.index(PT1) mod 26
# This is the BEAUFORT DIFFERENCE CONSTRAINT for the alphabet at this residue.

# Under standard AZ: index = ord(X) - 65
# Required: (CT1_val - CT2_val) = (PT2_val - PT1_val) mod 26
# If this holds in AZ, it's consistent. If not, we need a mixed alphabet.

for r in sorted(doubly_constrained.keys()):
    ct_ene, pt_ene, ct_bcl, pt_bcl = doubly_constrained[r]
    # Standard AZ check
    az_lhs = (I2N[ct_ene] - I2N[ct_bcl]) % 26
    az_rhs = (I2N[pt_bcl] - I2N[pt_ene]) % 26
    consistent_az = az_lhs == az_rhs

    # Beaufort key values under AZ
    k_ene = (I2N[ct_ene] + I2N[pt_ene]) % 26
    k_bcl = (I2N[ct_bcl] + I2N[pt_bcl]) % 26

    match_str = "MATCH (key={})".format(N2L[k_ene]) if consistent_az else f"CONFLICT (keys: {N2L[k_ene]}, {N2L[k_bcl]})"
    print(f"  r={r:2d}: CT={ct_ene},{ct_bcl}  PT={pt_ene},{pt_bcl}  "
          f"AZ keys: {N2L[k_ene]},{N2L[k_bcl]}  {match_str}")

# ── Phase 2: For each conflicted residue, find keyword alphabets that resolve it
print("\n" + "=" * 80)
print("PHASE 2: Keyword alphabet search per conflicted residue")
print("=" * 80)

# Collect thematic keywords
try:
    with open("/home/cpatrick/kryptos/wordlists/thematic_keywords.txt") as f:
        THEMATIC = [line.strip() for line in f if line.strip() and not line.startswith('#')]
except:
    THEMATIC = []

# Add additional keywords
EXTRA_KW = ['KRYPTOS', 'DEFECTOR', 'KOMPASS', 'ABSCISSA', 'COLOPHON', 'PARALLAX',
            'PALIMPSEST', 'ENIGMA', 'SHADOW', 'SANBORN', 'MEDUSA', 'BERLIN',
            'CLOCK', 'NORTH', 'EAST', 'COMPASS', 'SEVEN', 'FIVE', 'HOROLOGE',
            'CIPHER', 'SECRET', 'BURIED', 'HIDDEN', 'LANGLEY', 'VIRGINIA',
            'TRANSIT', 'MERCURY', 'DYAHR', 'YAR', 'RAY']
for kw in EXTRA_KW:
    if kw not in THEMATIC:
        THEMATIC.append(kw)

# Also generate all 1-4 letter keywords exhaustively
SHORT_KEYWORDS = []
for length in range(1, 5):
    for combo in itertools.product(AZ, repeat=length):
        kw = ''.join(combo)
        SHORT_KEYWORDS.append(kw)

print(f"Thematic keywords: {len(THEMATIC)}")
print(f"Short keywords (1-4 letters): {len(SHORT_KEYWORDS)}")

def check_alphabet_for_residue(alpha_str, r, ct_ene, pt_ene, ct_bcl, pt_bcl):
    """Check if alphabet alpha_str makes residue r consistent under Beaufort."""
    alpha_idx = {c: i for i, c in enumerate(alpha_str)}
    # Beaufort: K = (alpha.index(CT) + alpha.index(PT)) mod 26
    k_ene = (alpha_idx[ct_ene] + alpha_idx[pt_ene]) % 26
    k_bcl = (alpha_idx[ct_bcl] + alpha_idx[pt_bcl]) % 26
    if k_ene == k_bcl:
        return True, k_ene
    return False, None

def check_alphabet_for_residue_vig(alpha_str, r, ct_ene, pt_ene, ct_bcl, pt_bcl):
    """Check if alphabet alpha_str makes residue r consistent under Vigenere."""
    alpha_idx = {c: i for i, c in enumerate(alpha_str)}
    k_ene = (alpha_idx[ct_ene] - alpha_idx[pt_ene]) % 26
    k_bcl = (alpha_idx[ct_bcl] - alpha_idx[pt_bcl]) % 26
    if k_ene == k_bcl:
        return True, k_ene
    return False, None

def check_alphabet_for_residue_vbeau(alpha_str, r, ct_ene, pt_ene, ct_bcl, pt_bcl):
    """Check if alphabet alpha_str makes residue r consistent under Variant Beaufort."""
    alpha_idx = {c: i for i, c in enumerate(alpha_str)}
    k_ene = (alpha_idx[pt_ene] - alpha_idx[ct_ene]) % 26
    k_bcl = (alpha_idx[pt_bcl] - alpha_idx[ct_bcl]) % 26
    if k_ene == k_bcl:
        return True, k_ene
    return False, None

CHECK_FUNCS = {
    'beau': check_alphabet_for_residue,
    'vig': check_alphabet_for_residue_vig,
    'vbeau': check_alphabet_for_residue_vbeau,
}

# For each variant and each conflicted residue, find satisfying keywords
for variant_name, check_func in CHECK_FUNCS.items():
    print(f"\n--- Variant: {variant_name} ---")

    # Identify conflicted residues under this variant
    conflicted = {}
    matching = {}
    for r in sorted(doubly_constrained.keys()):
        ct_ene, pt_ene, ct_bcl, pt_bcl = doubly_constrained[r]
        ok, k = check_func(AZ, r, ct_ene, pt_ene, ct_bcl, pt_bcl)
        if not ok:
            conflicted[r] = doubly_constrained[r]
        else:
            matching[r] = k

    print(f"  Conflicted residues (AZ): {sorted(conflicted.keys())} ({len(conflicted)}/11)")
    print(f"  Matching residues (AZ):   {sorted(matching.keys())} ({len(matching)}/11)")

    if not conflicted:
        print(f"  ALL residues consistent under AZ -- this is standard periodic-{PERIOD} {variant_name}")
        # Decrypt and score
        continue

    # Search thematic keywords for each conflicted residue
    residue_solutions = defaultdict(list)  # r -> [(keyword, key_val)]

    print(f"\n  Searching {len(THEMATIC)} thematic keywords for conflicted residues...")
    for kw in THEMATIC:
        try:
            alpha_str = keyword_mixed_alphabet(kw)
        except:
            continue
        for r, (ct_e, pt_e, ct_b, pt_b) in conflicted.items():
            ok, k = check_func(alpha_str, r, ct_e, pt_e, ct_b, pt_b)
            if ok:
                residue_solutions[r].append((kw, k, alpha_str))

    # Report
    all_solved = True
    for r in sorted(conflicted.keys()):
        sols = residue_solutions[r]
        if sols:
            kw_list = [s[0] for s in sols[:10]]
            print(f"    r={r}: {len(sols)} keyword solutions, e.g.: {kw_list}")
        else:
            print(f"    r={r}: NO thematic keyword solution found")
            all_solved = False

    # Now search short keywords (1-4 letters) for unsolved residues
    unsolved = [r for r in conflicted if not residue_solutions[r]]
    if unsolved:
        print(f"\n  Searching {len(SHORT_KEYWORDS)} short keywords (1-4 letters) for residues: {unsolved}")
        for kw in SHORT_KEYWORDS:
            try:
                alpha_str = keyword_mixed_alphabet(kw)
            except:
                continue
            for r in unsolved:
                ct_e, pt_e, ct_b, pt_b = conflicted[r]
                ok, k = check_func(alpha_str, r, ct_e, pt_e, ct_b, pt_b)
                if ok:
                    residue_solutions[r].append((kw, k, alpha_str))

        for r in unsolved:
            sols = residue_solutions[r]
            if sols:
                print(f"    r={r}: {len(sols)} short-keyword solutions found")
            else:
                print(f"    r={r}: STILL NO solution (mathematically impossible for keyword-mixed alphabets?)")

    # Check if all residues now solved
    total_solved = sum(1 for r in conflicted if residue_solutions[r])
    print(f"\n  Summary: {total_solved}/{len(conflicted)} conflicted residues solvable via keyword alphabets")

    if total_solved == len(conflicted):
        print(f"  ALL conflicts resolvable! Building combined solutions...")

        # For each combination of keyword solutions across residues, decrypt and score
        # Build the product of solutions across residues
        residue_order = sorted(conflicted.keys())
        solution_lists = [residue_solutions[r] for r in residue_order]

        # Limit combinatorial explosion
        MAX_PER_RESIDUE = 50  # Take top 50 per residue
        solution_lists_trimmed = [sl[:MAX_PER_RESIDUE] for sl in solution_lists]

        total_combos = 1
        for sl in solution_lists_trimmed:
            total_combos *= len(sl)
        print(f"  Total combinations: {total_combos} (capped per-residue at {MAX_PER_RESIDUE})")

        if total_combos > 10_000_000:
            print(f"  Too many combinations, reducing per-residue cap...")
            MAX_PER_RESIDUE = 5
            solution_lists_trimmed = [sl[:MAX_PER_RESIDUE] for sl in solution_lists]
            total_combos = 1
            for sl in solution_lists_trimmed:
                total_combos *= len(sl)
            print(f"  Reduced to {total_combos} combinations")

        best_qg = -99.0
        best_combo = None
        best_pt = ""
        tested = 0

        for combo in itertools.product(*solution_lists_trimmed):
            # Build the per-residue alphabets and key values
            # For matching residues, use AZ
            # For conflicted residues, use the combo's keyword alphabet
            alphabets = {}  # r -> alpha_str
            key_vals = {}   # r -> key_val (index in that alphabet)

            # First, matching residues
            for r, k in matching.items():
                alphabets[r] = AZ
                key_vals[r] = k

            # Then, conflicted residues from combo
            for idx, r in enumerate(residue_order):
                kw, k, alpha_str = combo[idx]
                alphabets[r] = alpha_str
                key_vals[r] = k

            # For singly-constrained residues (9 and 10), we need to determine them
            # We have only 1 constraint each (from ENE), so any alphabet works
            # Use AZ for simplicity and compute the key from ENE
            for r in [9, 10]:
                pos = ENE_START + ((r - ENE_START % PERIOD) % PERIOD)
                # Find the ENE position at residue r
                for p in range(ENE_START, ENE_START + 13):
                    if p % PERIOD == r:
                        pos = p
                        break
                alpha_str = AZ
                if variant_name == 'beau':
                    k = (I2N[CT[pos]] + I2N[PT_AT[pos]]) % 26
                elif variant_name == 'vig':
                    k = (I2N[CT[pos]] - I2N[PT_AT[pos]]) % 26
                else:
                    k = (I2N[PT_AT[pos]] - I2N[CT[pos]]) % 26
                alphabets[r] = alpha_str
                key_vals[r] = k

            # Decrypt all 97 characters
            pt = []
            for i in range(N):
                r = i % PERIOD
                alpha_str = alphabets.get(r, AZ)
                alpha_idx = {c: j for j, c in enumerate(alpha_str)}
                k = key_vals.get(r, 0)
                ct_val = alpha_idx[CT[i]]

                if variant_name == 'beau':
                    pt_val = (k - ct_val) % 26
                elif variant_name == 'vig':
                    pt_val = (ct_val - k) % 26
                else:
                    pt_val = (ct_val + k) % 26

                pt.append(alpha_str[pt_val])

            pt_text = ''.join(pt)

            # Verify cribs
            ene_match = sum(1 for j, ch in enumerate(ENE_TEXT) if pt[ENE_START + j] == ch)
            bcl_match = sum(1 for j, ch in enumerate(BCL_TEXT) if pt[BCL_START + j] == ch)

            qg = qg_score(pt_text)
            tested += 1

            if qg > best_qg:
                best_qg = qg
                best_combo = combo
                best_pt = pt_text
                best_ene = ene_match
                best_bcl = bcl_match

            if tested % 100000 == 0:
                print(f"    Tested {tested}/{total_combos}, best qg={best_qg:.4f}")

        print(f"\n  RESULTS ({variant_name}):")
        print(f"    Tested: {tested} combinations")
        print(f"    Best quadgram score: {best_qg:.4f}/char")
        print(f"    Best PT (first 60): {best_pt[:60]}")
        print(f"    ENE match: {best_ene}/13, BCL match: {best_bcl}/11")
        if best_combo:
            print(f"    Keywords per conflicted residue:")
            for idx, r in enumerate(residue_order):
                kw, k, _ = best_combo[idx]
                print(f"      r={r}: keyword={kw}, key_val={k} ({N2L[k]})")
    else:
        print(f"  NOT all conflicts resolvable -- checking if any are mathematically unsolvable...")

        # For each unsolvable residue, test ALL 26! orderings? No, that's too many.
        # Instead, test if ANY permutation of 26 letters satisfies the constraint.
        # The constraint is: alpha.index(CT1) - alpha.index(CT2) = alpha.index(PT1) - alpha.index(PT2) mod 26
        # For Beaufort: alpha.index(CT1) + alpha.index(PT1) = alpha.index(CT2) + alpha.index(PT2) mod 26

        for r in sorted(conflicted.keys()):
            if residue_solutions[r]:
                continue
            ct_e, pt_e, ct_b, pt_b = conflicted[r]
            # Under Beaufort with ANY alphabet alpha:
            # alpha.index(CT_e) + alpha.index(PT_e) = alpha.index(CT_b) + alpha.index(PT_b) mod 26
            # This is 1 equation in 4 unknowns (the alpha positions of 4 specific letters).
            # If the 4 letters are all distinct, there are solutions.
            # If some letters coincide, there may be constraints.
            chars_needed = {ct_e, pt_e, ct_b, pt_b}
            print(f"    r={r}: letters {ct_e},{pt_e},{ct_b},{pt_b} ({len(chars_needed)} distinct)")
            print(f"           Constraint: alpha[{ct_e}]+alpha[{pt_e}] = alpha[{ct_b}]+alpha[{pt_b}] mod 26")

            if len(chars_needed) == 4:
                print(f"           4 distinct letters -> solvable for ANY target difference")
                print(f"           BUG: keyword_mixed_alphabet should find solutions!")
            elif len(chars_needed) == 3:
                # One letter appears twice
                if ct_e == ct_b:
                    # alpha[CT] + alpha[PT_e] = alpha[CT] + alpha[PT_b] => PT_e = PT_b
                    # But PT_e != PT_b (otherwise no conflict). CONTRADICTION.
                    print(f"           CT same ({ct_e}), PT different ({pt_e},{pt_b}) -> IMPOSSIBLE for ANY alphabet")
                elif pt_e == pt_b:
                    print(f"           PT same ({pt_e}), CT different ({ct_e},{ct_b}) -> IMPOSSIBLE for ANY alphabet")
                elif ct_e == pt_b:
                    print(f"           CT_e=PT_b={ct_e}: alpha[{ct_e}]+alpha[{pt_e}] = alpha[{ct_b}]+alpha[{ct_e}]")
                    print(f"           => alpha[{pt_e}] = alpha[{ct_b}] mod 26 => {pt_e}={ct_b}? {'YES' if pt_e == ct_b else 'NO -- IMPOSSIBLE'}")
                elif ct_b == pt_e:
                    print(f"           CT_b=PT_e={ct_b}: alpha[{ct_e}]+alpha[{ct_b}] = alpha[{ct_b}]+alpha[{pt_b}]")
                    print(f"           => alpha[{ct_e}] = alpha[{pt_b}] mod 26 => {ct_e}={pt_b}? {'YES' if ct_e == pt_b else 'NO -- IMPOSSIBLE'}")
                else:
                    print(f"           Complex 3-letter case, testing numerically...")
            elif len(chars_needed) == 2:
                print(f"           2 distinct letters -> analyzing...")

# ── Phase 3: Same-keyword-everywhere model ────────────────────────────────
print("\n" + "=" * 80)
print("PHASE 3: Same keyword alphabet at ALL residues (verify prior result)")
print("=" * 80)

# Quick verification: with a single keyword alphabet for ALL 13 residues
for variant_name, check_func in CHECK_FUNCS.items():
    best_consistent = 0
    best_kw = ""
    best_key = ""
    best_pt_text = ""

    for kw in THEMATIC + ['AZ_STANDARD']:
        if kw == 'AZ_STANDARD':
            alpha_str = AZ
        else:
            try:
                alpha_str = keyword_mixed_alphabet(kw)
            except:
                continue

        alpha_idx = {c: i for i, c in enumerate(alpha_str)}

        # Check period-13 consistency
        residue_keys = defaultdict(set)
        for pos in CRIB_POS:
            r = pos % PERIOD
            ct_idx = alpha_idx[CT[pos]]
            pt_idx = alpha_idx[PT_AT[pos]]
            if variant_name == 'beau':
                k = (ct_idx + pt_idx) % 26
            elif variant_name == 'vig':
                k = (ct_idx - pt_idx) % 26
            else:
                k = (pt_idx - ct_idx) % 26
            residue_keys[r].add(k)

        n_consistent = sum(1 for v in residue_keys.values() if len(v) == 1)
        n_conflict = sum(1 for v in residue_keys.values() if len(v) > 1)

        if n_conflict == 0:
            # Fully consistent! Decrypt and score
            key_str = ''
            key_nums = {}
            for r in range(PERIOD):
                if r in residue_keys and len(residue_keys[r]) == 1:
                    k = list(residue_keys[r])[0]
                    key_nums[r] = k
                    key_str += alpha_str[k]
                else:
                    key_nums[r] = 0
                    key_str += '?'

            pt = []
            for i in range(N):
                r = i % PERIOD
                ct_val = alpha_idx[CT[i]]
                k = key_nums.get(r, 0)
                if variant_name == 'beau':
                    pt_val = (k - ct_val) % 26
                elif variant_name == 'vig':
                    pt_val = (ct_val - k) % 26
                else:
                    pt_val = (ct_val + k) % 26
                pt.append(alpha_str[pt_val])

            pt_text = ''.join(pt)
            qg = qg_score(pt_text)

            print(f"  {variant_name} {kw:20s}: CONSISTENT, key={key_str}, qg={qg:.4f}, PT={pt_text[:50]}")

            if n_consistent > best_consistent or (n_consistent == best_consistent and qg > -90):
                best_consistent = n_consistent
                best_kw = kw
                best_key = key_str
                best_pt_text = pt_text

    if best_consistent == 0:
        print(f"  {variant_name}: NO fully consistent alphabet found among {len(THEMATIC)+1} keywords")

# ── Phase 4: Exhaustive short-keyword search for EACH conflicted residue ──
print("\n" + "=" * 80)
print("PHASE 4: Exhaustive 1-4 letter keyword search (Beaufort variant)")
print("=" * 80)

# Focus on Beaufort (the most promising variant based on prior analysis)
variant_name = 'beau'
check_func = CHECK_FUNCS[variant_name]

# For each conflicted residue, count how many of the ~475K short keywords work
conflicted_beau = {}
matching_beau = {}
for r in sorted(doubly_constrained.keys()):
    ct_e, pt_e, ct_b, pt_b = doubly_constrained[r]
    ok, k = check_func(AZ, r, ct_e, pt_e, ct_b, pt_b)
    if not ok:
        conflicted_beau[r] = doubly_constrained[r]
    else:
        matching_beau[r] = k

print(f"Conflicted residues (Beaufort, AZ): {sorted(conflicted_beau.keys())}")
print(f"Matching residues (Beaufort, AZ):   {sorted(matching_beau.keys())}")

# For EACH conflicted residue, do exhaustive search
residue_kw_solutions = {}
for r in sorted(conflicted_beau.keys()):
    ct_e, pt_e, ct_b, pt_b = conflicted_beau[r]
    solutions = []

    # Test all short keywords
    seen_alphas = set()
    for kw in SHORT_KEYWORDS:
        alpha_str = keyword_mixed_alphabet(kw)
        if alpha_str in seen_alphas:
            continue
        seen_alphas.add(alpha_str)

        ok, k = check_func(alpha_str, r, ct_e, pt_e, ct_b, pt_b)
        if ok:
            solutions.append((kw, k, alpha_str))

    # Also test thematic keywords
    for kw in THEMATIC:
        try:
            alpha_str = keyword_mixed_alphabet(kw)
        except:
            continue
        if alpha_str in seen_alphas:
            continue
        seen_alphas.add(alpha_str)
        ok, k = check_func(alpha_str, r, ct_e, pt_e, ct_b, pt_b)
        if ok:
            solutions.append((kw, k, alpha_str))

    residue_kw_solutions[r] = solutions
    n_sol = len(solutions)
    if n_sol > 0:
        sample = [s[0] for s in solutions[:5]]
        key_vals = sorted(set(s[1] for s in solutions))
        print(f"  r={r}: {n_sol} keyword solutions, key vals={[N2L[k] for k in key_vals]}, "
              f"e.g.: {sample}")
    else:
        print(f"  r={r}: ZERO solutions -- MATHEMATICALLY IMPOSSIBLE under Beaufort")

# Check solvability
all_solved = all(len(residue_kw_solutions.get(r, [])) > 0 for r in conflicted_beau)
if all_solved:
    print(f"\nAll {len(conflicted_beau)} conflicted residues solvable! Building combinations...")

    residue_order = sorted(conflicted_beau.keys())
    # Cap solutions per residue for tractability
    MAX_PER = 100
    solution_lists = [residue_kw_solutions[r][:MAX_PER] for r in residue_order]

    total_combos = 1
    for sl in solution_lists:
        total_combos *= len(sl)
    print(f"Total combinations: {total_combos} (capped at {MAX_PER}/residue)")

    if total_combos > 50_000_000:
        MAX_PER = 10
        solution_lists = [residue_kw_solutions[r][:MAX_PER] for r in residue_order]
        total_combos = 1
        for sl in solution_lists:
            total_combos *= len(sl)
        print(f"Reduced to {total_combos} combinations")

    best_qg = -99.0
    best_combo = None
    best_pt = ""
    tested = 0

    # For residues 9,10 (ENE-only), compute key under AZ
    single_keys = {}
    for r in [9, 10]:
        for p in range(ENE_START, ENE_START + 13):
            if p % PERIOD == r:
                single_keys[r] = (I2N[CT[p]] + I2N[PT_AT[p]]) % 26
                break

    for combo in itertools.product(*solution_lists):
        # Build per-residue alphabet + key
        alpha_map = {}
        key_map = {}

        for r, k in matching_beau.items():
            alpha_map[r] = AZ
            key_map[r] = k

        for idx, r in enumerate(residue_order):
            kw, k, alpha_str = combo[idx]
            alpha_map[r] = alpha_str
            key_map[r] = k

        for r in [9, 10]:
            alpha_map[r] = AZ
            key_map[r] = single_keys[r]

        # Decrypt
        pt = []
        for i in range(N):
            r = i % PERIOD
            a_str = alpha_map[r]
            a_idx = {c: j for j, c in enumerate(a_str)}
            k = key_map[r]
            ct_val = a_idx[CT[i]]
            pt_val = (k - ct_val) % 26
            pt.append(a_str[pt_val])

        pt_text = ''.join(pt)
        qg = qg_score(pt_text)
        tested += 1

        if qg > best_qg:
            best_qg = qg
            best_combo = combo
            best_pt = pt_text

        if tested % 500000 == 0:
            elapsed = time.time() - t0
            print(f"  Tested {tested}/{total_combos} ({100*tested/total_combos:.1f}%), "
                  f"best qg={best_qg:.4f}, elapsed={elapsed:.0f}s")

    # Verify cribs
    ene_match = sum(1 for j, ch in enumerate(ENE_TEXT) if best_pt[ENE_START + j] == ch)
    bcl_match = sum(1 for j, ch in enumerate(BCL_TEXT) if best_pt[BCL_START + j] == ch)

    print(f"\n  FINAL RESULTS (Beaufort, per-residue mixed alphabets, period {PERIOD}):")
    print(f"    Tested: {tested}")
    print(f"    Best quadgram: {best_qg:.4f}/char (English ~ -3.8, random ~ -4.5)")
    print(f"    Best PT: {best_pt}")
    print(f"    ENE match: {ene_match}/13, BCL match: {bcl_match}/11")
    print(f"    Total crib: {ene_match + bcl_match}/24")
    if best_combo:
        print(f"    Keywords per conflicted residue:")
        for idx, r in enumerate(residue_order):
            kw, k, _ = best_combo[idx]
            print(f"      r={r}: keyword={kw}, key={N2L[k]}")
else:
    print(f"\nNOT all conflicts solvable -- some residues are IMPOSSIBLE under keyword-mixed Beaufort")
    impossible_residues = [r for r in conflicted_beau if not residue_kw_solutions.get(r, [])]
    print(f"Impossible residues: {impossible_residues}")
    for r in impossible_residues:
        ct_e, pt_e, ct_b, pt_b = conflicted_beau[r]
        print(f"  r={r}: CT=({ct_e},{ct_b}), PT=({pt_e},{pt_b})")
        # The constraint under Beaufort: alpha.index(CT_e) + alpha.index(PT_e) = alpha.index(CT_b) + alpha.index(PT_b) mod 26
        # If CT_e == CT_b (same CT letter at both positions):
        #   alpha.index(PT_e) = alpha.index(PT_b) mod 26 => PT_e == PT_b (forced)
        #   If PT_e != PT_b, IMPOSSIBLE for any alphabet.
        if ct_e == ct_b and pt_e != pt_b:
            print(f"  PROOF: CT letters identical ({ct_e}), PT letters different ({pt_e},{pt_b})")
            print(f"  => alpha.index({pt_e}) = alpha.index({pt_b}) mod 26 which requires {pt_e}={pt_b}")
            print(f"  => IMPOSSIBLE for ANY permutation alphabet. Period-13 mixed-alphabet Beaufort ELIMINATED.")
        if pt_e == pt_b and ct_e != ct_b:
            print(f"  PROOF: PT letters identical ({pt_e}), CT letters different ({ct_e},{ct_b})")
            print(f"  => alpha.index({ct_e}) = alpha.index({ct_b}) mod 26 which requires {ct_e}={ct_b}")
            print(f"  => IMPOSSIBLE for ANY permutation alphabet. Period-13 mixed-alphabet Beaufort ELIMINATED.")

# ── Phase 5: Also check Vigenere and Variant Beaufort exhaustively ────────
print("\n" + "=" * 80)
print("PHASE 5: Quick impossibility check for Vigenere and VBeau variants")
print("=" * 80)

for variant_name in ['vig', 'vbeau']:
    check_func = CHECK_FUNCS[variant_name]
    conflicted_v = {}
    for r in sorted(doubly_constrained.keys()):
        ct_e, pt_e, ct_b, pt_b = doubly_constrained[r]
        ok, k = check_func(AZ, r, ct_e, pt_e, ct_b, pt_b)
        if not ok:
            conflicted_v[r] = doubly_constrained[r]

    impossible = []
    for r, (ct_e, pt_e, ct_b, pt_b) in conflicted_v.items():
        # Under Vig: alpha.index(CT_e) - alpha.index(PT_e) = alpha.index(CT_b) - alpha.index(PT_b) mod 26
        # => alpha.index(CT_e) - alpha.index(CT_b) = alpha.index(PT_e) - alpha.index(PT_b) mod 26
        # Under VBeau: alpha.index(PT_e) - alpha.index(CT_e) = alpha.index(PT_b) - alpha.index(CT_b) mod 26
        # Same difference constraint
        # Impossible iff same CT => different PT (or vice versa)
        if ct_e == ct_b and pt_e != pt_b:
            impossible.append(r)
        elif pt_e == pt_b and ct_e != ct_b:
            impossible.append(r)

    if impossible:
        print(f"  {variant_name}: {len(impossible)} residues IMPOSSIBLE for ANY alphabet: {impossible}")
        print(f"  => Period-13 mixed-alphabet {variant_name} ELIMINATED.")
    else:
        print(f"  {variant_name}: all conflicted residues potentially solvable, testing...")
        # Do the same exhaustive search as for Beaufort
        # (abbreviated -- just check solvability)
        all_ok = True
        for r, (ct_e, pt_e, ct_b, pt_b) in conflicted_v.items():
            found = False
            for kw in SHORT_KEYWORDS[:10000]:  # Sample
                alpha_str = keyword_mixed_alphabet(kw)
                ok, k = check_func(alpha_str, r, ct_e, pt_e, ct_b, pt_b)
                if ok:
                    found = True
                    break
            if not found:
                all_ok = False
                print(f"    r={r}: no solution found in 10K keywords")
        if all_ok:
            print(f"  All residues solvable (details would require full combinatorial search)")

# ── Summary ───────────────────────────────────────────────────────────────
elapsed = time.time() - t0
print("\n" + "=" * 80)
print(f"INVESTIGATION 1 COMPLETE ({elapsed:.1f}s)")
print("=" * 80)

# Save results
results = {
    'experiment': 'PERIOD13_MIXED_ALPHABET_BEAUFORT',
    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
    'elapsed_seconds': elapsed,
    'period': PERIOD,
    'doubly_constrained_residues': list(doubly_constrained.keys()),
    'singly_constrained_residues': [9, 10],
}

out_path = '/home/cpatrick/kryptos/results/period13_mixed_alphabet_beaufort.json'
with open(out_path, 'w') as f:
    json.dump(results, f, indent=2, default=str)
print(f"Results saved to: {out_path}")
