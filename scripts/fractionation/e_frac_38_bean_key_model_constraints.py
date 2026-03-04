#!/usr/bin/env python3
"""
Cipher: fractionation analysis
Family: fractionation
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-FRAC-38: Bean Constraint Analysis for ALL Key Generation Models

Final FRAC structural analysis. For each key generation model, derive
what Bean constraints imply — which models are eliminated, constrained,
or unconstrained.

This is primarily algebraic analysis with computational verification.
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import BEAN_EQ, BEAN_INEQ, CT

START_TIME = time.time()

CT_VALS = [ord(c) - ord('A') for c in CT]
N = len(CT)  # 97

print("=" * 70)
print("E-FRAC-38: Bean Constraint Analysis for ALL Key Generation Models")
print("=" * 70)

results = {}

# Bean positions
eq_pairs = list(BEAN_EQ)  # [(27, 65)]
ineq_pairs = list(BEAN_INEQ)  # 21 pairs

print(f"\nBean equality: {eq_pairs}")
print(f"Bean inequalities: {len(ineq_pairs)} pairs")
print(f"  Differences: {sorted(set(abs(a-b) for a,b in ineq_pairs))}")

# ================================================================
# Model 1: Periodic key K[i] = key[i % p]
# ================================================================
print(f"\n{'='*70}")
print("MODEL 1: Periodic Key — K[i] = key[i % p]")
print("=" * 70)
print("Already fully analyzed in E-FRAC-35. Results:")
print("  Type 1 eliminated: periods where any ineq pair has a≡b (mod p)")
print("  Type 2 eliminated: periods where eq pair residues match some ineq pair residues")
print("  Eliminated (2-26): {2,3,4,5,6,7,9,10,11,12,14,15,17,18,21,22,25}")
print("  Surviving (2-26): {8,13,16,19,20,23,24,26}")
results['periodic'] = 'See E-FRAC-35. 17/25 periods eliminated.'

# ================================================================
# Model 2: Progressive key K[i] = (base + delta*i) % 26
# ================================================================
print(f"\n{'='*70}")
print("MODEL 2: Progressive Key — K[i] = (base + delta*i) % 26")
print("=" * 70)

# Bean equality: K[27] = K[65]
# (base + 27*delta) % 26 = (base + 65*delta) % 26
# 38*delta ≡ 0 (mod 26)
# Since gcd(38,26) = 2, need delta divisible by 26/gcd(38,26) = 13
# delta ∈ {0, 13}
from math import gcd
g = gcd(38, 26)
valid_deltas = [d for d in range(26) if (38 * d) % 26 == 0]
print(f"  Bean equality: 38*delta ≡ 0 (mod 26)")
print(f"  gcd(38,26) = {g}")
print(f"  Valid deltas: {valid_deltas}")

for delta in valid_deltas:
    if delta == 0:
        print(f"\n  delta=0: Monoalphabetic (constant key). Trivially eliminated by known results.")
        # Check inequalities
        ineq_fails = 0
        for a, b in ineq_pairs:
            ka = (0 + delta * a) % 26
            kb = (0 + delta * b) % 26
            if ka == kb:
                ineq_fails += 1
        print(f"    Inequality violations: {ineq_fails}/21 (all keys identical → all violated)")
    else:
        print(f"\n  delta={delta}: K[i] = (base + 13i) % 26. Alternates between 2 values.")
        # K[i] = base + 13i mod 26. Since 13*2=26≡0, this gives:
        # K[even] = base, K[odd] = base+13
        # This is effectively period 2!
        ineq_violations = []
        for a, b in ineq_pairs:
            ka = (13 * a) % 26
            kb = (13 * b) % 26
            if ka == kb:
                ineq_violations.append((a, b, abs(a - b)))
        print(f"    Inequality violations: {len(ineq_violations)}/21")
        if ineq_violations:
            print(f"    Violated pairs: {ineq_violations[:5]}...")
            print(f"    This is effectively period-2, which is Bean-eliminated (E-FRAC-35)")

print(f"\n  VERDICT: Progressive key is BEAN-ELIMINATED for all delta values.")
print(f"  delta=0 → monoalphabetic (trivially eliminated)")
print(f"  delta=13 → effectively period-2 (Bean-eliminated by E-FRAC-35)")
results['progressive'] = 'ELIMINATED. Only delta in {0,13} passes eq; both trivially eliminated.'

# ================================================================
# Model 3: Quadratic key K[i] = (a*i^2 + b*i + c) % 26
# ================================================================
print(f"\n{'='*70}")
print("MODEL 3: Quadratic Key — K[i] = (a*i² + b*i + c) % 26")
print("=" * 70)

# Bean equality: K[27] = K[65]
# a(27²-65²) + b(27-65) ≡ 0 (mod 26)
# a(729-4225) + b(-38) ≡ 0 (mod 26)
# -3496a - 38b ≡ 0 (mod 26)
# 3496 mod 26 = 3496 - 134*26 = 3496 - 3484 = 12
# 38 mod 26 = 12
# So: -12a - 12b ≡ 0 (mod 26) → 12(a+b) ≡ 0 (mod 26)
# gcd(12,26) = 2, so need (a+b) divisible by 13
# a+b ∈ {0, 13} (mod 26)... wait, 26/gcd(12,26) = 13

eq_constraint = "12(a+b) ≡ 0 (mod 26) → (a+b) ≡ 0 (mod 13)"
print(f"  Bean equality: {eq_constraint}")
print(f"  So a+b must be 0 or 13 (mod 26). c is free.")

# Count valid (a,b) pairs
valid_ab = [(a, b) for a in range(26) for b in range(26) if (a + b) % 13 == 0]
print(f"  Valid (a,b) pairs: {len(valid_ab)}/676 ({100*len(valid_ab)/676:.1f}%)")

# For each valid (a,b), check Bean inequalities
survived_count = 0
eliminated_count = 0
for a, b in valid_ab:
    ineq_ok = True
    for pa, pb in ineq_pairs:
        ka = (a * pa * pa + b * pa) % 26
        kb = (a * pb * pb + b * pb) % 26
        if ka == kb:
            ineq_ok = False
            break
    if ineq_ok:
        survived_count += 1
    else:
        eliminated_count += 1

print(f"  After inequality check: {survived_count} survive, {eliminated_count} eliminated")
print(f"  Survival rate: {100*survived_count/len(valid_ab):.1f}% of eq-passing pairs")
print(f"  Overall survival: {100*survived_count/676:.1f}% of all (a,b) pairs")

# Check: is this better or worse than random?
# For random (a,b), probability of passing eq = 2/26 ≈ 7.7%
# For random that pass eq, probability of passing all 21 ineq ≈ ?
# Each ineq eliminates 1/26 of key space → P(pass 21 ineq) ≈ (25/26)^21 ≈ 44%
# But inequalities are correlated, so this is approximate
import random
random.seed(42)
n_random_pass = 0
for _ in range(100000):
    a, b = random.randint(0, 25), random.randint(0, 25)
    if (a + b) % 13 != 0:
        continue
    ok = True
    for pa, pb in ineq_pairs:
        ka = (a * pa * pa + b * pa) % 26
        kb = (a * pb * pb + b * pb) % 26
        if ka == kb:
            ok = False
            break
    if ok:
        n_random_pass += 1

print(f"  Monte Carlo verification: {n_random_pass}/100000 random (a,b) pass all Bean")
print(f"  (matches {survived_count}/{len(valid_ab)} × {len(valid_ab)}/676 ≈ {survived_count*100000//676}/100000)")

if survived_count > 0:
    print(f"\n  VERDICT: Quadratic key is NOT fully Bean-eliminated.")
    print(f"  {survived_count} (a,b) pairs survive (c is free → {survived_count}×26 = {survived_count*26} total configs)")
    print(f"  But E-FRAC-15 showed quadratic key max = 8/24 = NOISE under direct correspondence.")
    print(f"  With transposition: untested, but quadratic key + transposition is a valid model.")
else:
    print(f"\n  VERDICT: Quadratic key is BEAN-ELIMINATED.")

results['quadratic'] = {
    'eq_surviving_ab': len(valid_ab),
    'full_surviving': survived_count,
    'total_configs': survived_count * 26,
}

# ================================================================
# Model 4: Running key K[i] = source[offset + i]
# ================================================================
print(f"\n{'='*70}")
print("MODEL 4: Running Key — K[i] = source[offset + i]")
print("=" * 70)

# Bean equality: source[offset+27] = source[offset+65]
# This means positions 27 and 65 of the running key text (relative to offset) must be the same letter.
# 65-27 = 38 positions apart in the source text.
# For English text: P(source[x] = source[x+38]) ≈ sum(freq_i^2) ≈ 0.065 (IC of English)
# So ~6.5% of offsets in English text will pass Bean equality.

print(f"  Bean equality: source[offset+27] = source[offset+65]")
print(f"  This means the source text must have the same letter at positions 38 apart.")
print(f"  For English: P ≈ IC(English) ≈ 0.065 (6.5% of offsets pass)")
print(f"  For random: P ≈ 1/26 ≈ 0.038 (3.8% of offsets pass)")

# Bean inequalities: source[offset+a] ≠ source[offset+b] for 21 pairs
# Each pair eliminates ~1/26 of remaining offsets
# P(all 21 pass) ≈ (25/26)^21 ≈ 0.44 for independent pairs (correlated, so approximate)

# Test with a real English text
try:
    with open(os.path.join(os.path.dirname(__file__), '..', 'wordlists', 'english.txt')) as f:
        english_words = f.read().upper()
    # Generate a long English-like text
    english_text = english_words.replace('\n', '')[:10000]
    eq_pass = 0
    full_pass = 0
    total_offsets = len(english_text) - 97
    for offset in range(total_offsets):
        key = [ord(english_text[offset + i]) - ord('A') for i in range(97)]
        eq_ok = True
        for a, b in eq_pairs:
            if key[a] != key[b]:
                eq_ok = False
                break
        if not eq_ok:
            continue
        eq_pass += 1
        ineq_ok = True
        for a, b in ineq_pairs:
            if key[a] == key[b]:
                ineq_ok = False
                break
        if ineq_ok:
            full_pass += 1

    print(f"\n  Empirical test (wordlist as source text, {total_offsets} offsets):")
    print(f"    Bean eq pass: {eq_pass}/{total_offsets} ({100*eq_pass/total_offsets:.1f}%)")
    print(f"    Full Bean pass: {full_pass}/{total_offsets} ({100*full_pass/total_offsets:.1f}%)")
except Exception as e:
    print(f"  (Could not test empirically: {e})")

print(f"\n  VERDICT: Running key is NOT Bean-eliminated.")
print(f"  Bean only constrains ~6.5% of source text offsets (equality).")
print(f"  Running key + transposition remains FULLY OPEN.")
print(f"  E-FRAC-17 tested 8 known texts under direct correspondence → NOISE.")
print(f"  Running key + arbitrary transposition: untested (JTS territory).")

results['running_key'] = 'NOT ELIMINATED. Bean constrains offset selection but does not eliminate.'

# ================================================================
# Model 5: PT-autokey K[0]=seed, K[i]=PT[i-1]
# ================================================================
print(f"\n{'='*70}")
print("MODEL 5: PT-Autokey — K[0]=seed, K[i]=PT[i-1]")
print("=" * 70)

# Bean equality: K[27] = K[65]
# K[27] = PT[26], K[65] = PT[64]
# PT[64] = E (crib at position 64)
# So PT[26] must be E.
print(f"  Bean equality: K[27]=PT[26], K[65]=PT[64]=E (crib)")
print(f"  → PT[26] must be E")
print(f"  → For Vigenère: CT[σ(26)] - PT[25] ≡ 4 (mod 26)")
print(f"  → Constrains relationship between σ(26) and PT[25]")

# Bean inequalities: K[a]=PT[a-1] ≠ K[b]=PT[b-1]
# → PT[a-1] ≠ PT[b-1] for each inequality pair
ineq_pt_positions = [(a-1, b-1) for a, b in ineq_pairs]
print(f"\n  Bean inequalities become plaintext constraints:")
print(f"  PT[a-1] ≠ PT[b-1] for 21 pairs")

# How many of these involve crib positions?
crib_constrained = 0
for pa, pb in ineq_pt_positions:
    crib_a = pa in [21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73]
    crib_b = pb in [21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73]
    if crib_a or crib_b:
        crib_constrained += 1

print(f"  Pairs involving crib-adjacent positions: {crib_constrained}/21")
print(f"\n  E-FRAC-37 showed: PT-autokey CANNOT reach 24/24 with arbitrary transposition")
print(f"  Max achieved: 16/24 (no Bean), 13/24 (Bean=HARD)")
print(f"\n  VERDICT: PT-autokey is COMPUTATIONALLY ELIMINATED (cannot reach 24/24)")

results['pt_autokey'] = 'COMPUTATIONALLY ELIMINATED (E-FRAC-37). Cannot reach 24/24.'

# ================================================================
# Model 6: CT-autokey K[0]=seed, K[i]=CT[σ(i-1)]
# ================================================================
print(f"\n{'='*70}")
print("MODEL 6: CT-Autokey — K[0]=seed, K[i]=CT[σ(i-1)]")
print("=" * 70)

# Bean equality: K[27] = K[65]
# K[27] = CT[σ(26)], K[65] = CT[σ(64)]
# → CT[σ(26)] = CT[σ(64)]
# This means positions σ(26) and σ(64) in CT must have the same letter.

# How many CT letter pairs match?
ct_letter_counts = {}
for i, v in enumerate(CT_VALS):
    ct_letter_counts.setdefault(v, []).append(i)

pair_count = 0
for letter, positions in ct_letter_counts.items():
    n = len(positions)
    pair_count += n * (n - 1)  # ordered pairs

print(f"  Bean equality: CT[σ(26)] = CT[σ(64)]")
print(f"  Need two positions in CT with the same letter.")
print(f"  CT letter distribution: {len(ct_letter_counts)} distinct letters")
print(f"  Ordered pairs with same letter: {pair_count}/{N*(N-1)} = {100*pair_count/(N*(N-1)):.1f}%")
print(f"  (matches 1/26 ≈ 3.85%)")

print(f"\n  E-FRAC-37 showed: CT-autokey reaches max 21/24 (no Bean), 21/24 (Bean=HARD)")
print(f"  CANNOT reach 24/24 in 50 climbs × 5K steps.")
print(f"\n  VERDICT: CT-autokey is COMPUTATIONALLY ELIMINATED (cannot reach 24/24 in tested budget)")
print(f"  Note: not as definitive as PT-autokey — larger budget might push higher.")

results['ct_autokey'] = 'COMPUTATIONALLY ELIMINATED (E-FRAC-37). Max 21/24 in tested budget.'

# ================================================================
# Model 7: Fibonacci/recurrence K[0]=a, K[1]=b, K[i]=(K[i-1]+K[i-2]) % 26
# ================================================================
print(f"\n{'='*70}")
print("MODEL 7: Fibonacci/Recurrence Key")
print("=" * 70)

# For Fibonacci: K[i] depends on K[i-1] and K[i-2]
# The sequence is deterministic from (K[0], K[1]) = (a, b)
# 676 possible (a,b) pairs
# For each: compute K[0..96], check Bean

fib_pass_eq = 0
fib_pass_full = 0
for a in range(26):
    for b in range(26):
        k = [0] * N
        k[0] = a
        k[1] = b
        for i in range(2, N):
            k[i] = (k[i-1] + k[i-2]) % 26
        # Check Bean eq
        eq_ok = all(k[pa] == k[pb] for pa, pb in eq_pairs)
        if not eq_ok:
            continue
        fib_pass_eq += 1
        # Check Bean ineq
        ineq_ok = all(k[pa] != k[pb] for pa, pb in ineq_pairs)
        if ineq_ok:
            fib_pass_full += 1

print(f"  Fibonacci K[i] = (K[i-1]+K[i-2]) % 26")
print(f"  Bean eq pass: {fib_pass_eq}/676 ({100*fib_pass_eq/676:.1f}%)")
print(f"  Bean full pass: {fib_pass_full}/676 ({100*fib_pass_full/676:.1f}%)")
print(f"  E-FRAC-15 showed: Fibonacci max < 6/24 = NOISE")
print(f"\n  VERDICT: Fibonacci is {'NOT Bean-eliminated' if fib_pass_full > 0 else 'BEAN-ELIMINATED'}"
      f" ({fib_pass_full} surviving configs)")

results['fibonacci'] = {
    'eq_pass': fib_pass_eq,
    'full_pass': fib_pass_full,
    'status': 'ELIMINATED by E-FRAC-15 (noise)' if fib_pass_full > 0 else 'BEAN-ELIMINATED',
}

# General recurrence K[i] = (c1*K[i-1] + c2*K[i-2]) % 26
gen_pass_full = 0
gen_pass_eq = 0
for c1 in range(26):
    for c2 in range(26):
        for a in range(26):
            for b in range(26):
                k = [0] * N
                k[0] = a
                k[1] = b
                for i in range(2, N):
                    k[i] = (c1 * k[i-1] + c2 * k[i-2]) % 26
                eq_ok = all(k[pa] == k[pb] for pa, pb in eq_pairs)
                if not eq_ok:
                    continue
                gen_pass_eq += 1
                ineq_ok = all(k[pa] != k[pb] for pa, pb in ineq_pairs)
                if ineq_ok:
                    gen_pass_full += 1

total_gen = 26**4  # 456,976
print(f"\n  General recurrence K[i] = (c1*K[i-1] + c2*K[i-2]) % 26")
print(f"  Total configs: {total_gen}")
print(f"  Bean eq pass: {gen_pass_eq} ({100*gen_pass_eq/total_gen:.2f}%)")
print(f"  Bean full pass: {gen_pass_full} ({100*gen_pass_full/total_gen:.2f}%)")

results['general_recurrence'] = {
    'total': total_gen,
    'eq_pass': gen_pass_eq,
    'full_pass': gen_pass_full,
}

# ================================================================
# Summary
# ================================================================
print(f"\n{'='*70}")
print("COMPREHENSIVE BEAN CONSTRAINT ANALYSIS — ALL KEY MODELS")
print("=" * 70)

models = [
    ("Periodic (period p)", "17/25 periods eliminated (E-FRAC-35)", "MOSTLY ELIMINATED"),
    ("Progressive (linear)", "delta ∈ {0,13} only; both trivially eliminated", "ELIMINATED"),
    ("Quadratic (a*i²+b*i+c)", f"{survived_count}×26 = {survived_count*26} configs survive",
     "CONSTRAINED" if survived_count > 0 else "ELIMINATED"),
    ("Running key", "Only constrains source offset (~6.5% pass)", "OPEN"),
    ("PT-autokey", "Cannot reach 24/24 (E-FRAC-37, max 16)", "COMP. ELIMINATED"),
    ("CT-autokey", "Cannot reach 24/24 (E-FRAC-37, max 21)", "COMP. ELIMINATED"),
    ("Fibonacci", f"{fib_pass_full}/676 survive Bean", "NOISE (E-FRAC-15)"),
    ("General recurrence", f"{gen_pass_full}/{total_gen} survive Bean", "NOISE (E-FRAC-15)"),
]

print(f"\n  {'Model':<25} {'Bean Status':<50} {'Overall':<20}")
print(f"  {'-'*25} {'-'*50} {'-'*20}")
for model, bean_status, overall in models:
    print(f"  {model:<25} {bean_status:<50} {overall:<20}")

print(f"\n  SURVIVING MODELS (for transposition + substitution at K4):")
print(f"  1. Running key — barely constrained by Bean (JTS territory)")
print(f"  2. Periodic at surviving periods ({'{'}8,13,16,19,20,23,24,26{'}'}) — underdetermined")
print(f"  3. Quadratic — {survived_count*26} configs survive Bean but max 8/24 without transposition")
print(f"  4. General recurrence — {gen_pass_full} configs survive but max <8/24 without transposition")
print(f"  5. Position-dependent alphabets (no fixed key schedule) — unconstrained by Bean")
print(f"  6. Non-standard / bespoke key generation — unconstrained by Bean")

print(f"\n  KEY INSIGHT: Bean constraints are most powerful against PERIODIC keying (kills 17/25 periods)")
print(f"  and PROGRESSIVE keying (kills ALL valid deltas). They provide minimal constraint on")
print(f"  running key and no constraint on position-dependent or bespoke models.")

summary = {
    'experiment': 'E-FRAC-38',
    'title': 'Bean Constraint Analysis for ALL Key Generation Models',
    'runtime_seconds': round(time.time() - START_TIME, 1),
    'results': results,
    'verdict': 'STRUCTURAL_ANALYSIS_COMPLETE',
}

os.makedirs('results/frac', exist_ok=True)
outpath = 'results/frac/e_frac_38_bean_key_model_constraints.json'
with open(outpath, 'w') as f:
    json.dump(summary, f, indent=2, default=str)
print(f"\n  Results: {outpath}")
print(f"  Runtime: {summary['runtime_seconds']}s")
print(f"\nRESULT: STRUCTURAL_ANALYSIS_COMPLETE")
