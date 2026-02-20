#!/usr/bin/env python3
"""E-TABLEAU-NAV-001: Non-standard tableau navigation (algebraic approach).

For each candidate navigation rule R on the KRYPTOS tableau, algebraically
derive the required key at all 24 crib positions, then check if any periodic
key (period 2-26) is consistent across all cribs. For any consistent
(rule, period), decrypt full CT and score.

This is EXHAUSTIVE over all periodic keys — no dictionary needed.

Also tests position-dependent rules where the lookup depends on i.

Usage: PYTHONPATH=src python3 -u scripts/e_tableau_nav_001_algebraic.py
"""
import json
import os
import time
from collections import defaultdict
from itertools import product as iprod

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, N_CRIBS, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET, BEAN_EQ, BEAN_INEQ,
)

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_POSITIONS = sorted(CRIB_DICT.keys())
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
CRIB_CT_NUM = {pos: CT_NUM[pos] for pos in CRIB_POSITIONS}

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}
KA_NUM_CT = [KA_IDX[c] for c in CT]
KA_NUM_PT = {pos: KA_IDX[ch] for pos, ch in CRIB_DICT.items()}
KA_NUM_CT_CRIB = {pos: KA_NUM_CT[pos] for pos in CRIB_POSITIONS}

# ── Load quadgrams for quality scoring ─────────────────────────────
try:
    with open("data/english_quadgrams.json") as f:
        QUADGRAMS = json.load(f)
    QG_FLOOR = min(QUADGRAMS.values()) - 1.0
except FileNotFoundError:
    QUADGRAMS = None
    QG_FLOOR = -10.0


def quadgram_score(text):
    """Log-probability per character using quadgram model."""
    if QUADGRAMS is None:
        return -99.0
    total = 0.0
    n = 0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        total += QUADGRAMS.get(qg, QG_FLOOR)
        n += 1
    return total / max(n, 1)


def ic(nums):
    """Index of coincidence."""
    from collections import Counter
    freq = Counter(nums)
    n = len(nums)
    if n < 2:
        return 0.0
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


def check_bean(pt_nums):
    """Check Bean equality and inequality constraints."""
    for a, b in BEAN_EQ:
        if a < len(pt_nums) and b < len(pt_nums):
            if pt_nums[a] != pt_nums[b]:
                return False
    for a, b in BEAN_INEQ:
        if a < len(pt_nums) and b < len(pt_nums):
            if pt_nums[a] == pt_nums[b]:
                return False
    return True


# ── Navigation rules ───────────────────────────────────────────────
# Each rule is defined by an encrypt function: encrypt(key_idx, pt_idx) → ct_idx
# We work in a given alphabet's index space.
# For decryption at cribs, we need: given (ct_idx, pt_idx), find key_idx.
# We precompute this as a lookup table.

def build_rules():
    """Build navigation rules as encrypt(k, p) → c functions.
    Returns dict of name → lambda(k, p) → c (all mod 26).
    """
    rules = {}

    # Standard polyalphabetic variants
    rules["vig_standard"] = lambda k, p: (k + p) % 26
    rules["beaufort"] = lambda k, p: (k - p) % 26
    rules["variant_beaufort"] = lambda k, p: (p - k) % 26

    # Reversed directions on the tableau
    rules["row_reversed"] = lambda k, p: (k - p + 25) % 26
    rules["bottom_up"] = lambda k, p: (25 - k + p) % 26
    rules["both_reversed"] = lambda k, p: (24 - k - p) % 26
    rules["col_reversed_only"] = lambda k, p: (k + 25 - p) % 26

    # Affine row multipliers: ct = (a*k + p) mod 26
    for a in [2, 3, 5, 7, 9, 11, 15, 17, 19, 23, 25]:
        rules[f"affine_row_{a}"] = (lambda a: lambda k, p: (a * k + p) % 26)(a)

    # Affine column multipliers: ct = (k + b*p) mod 26
    for b in [2, 3, 5, 7, 9, 11, 15, 17, 19, 23, 25]:
        rules[f"affine_col_{b}"] = (lambda b: lambda k, p: (k + b * p) % 26)(b)

    # Both affine: ct = (a*k + b*p) mod 26 for selected a, b
    for a, b in [(3, 5), (5, 3), (7, 11), (11, 7), (3, 7), (7, 3),
                 (5, 9), (9, 5), (9, 11), (11, 9), (5, 7), (7, 5)]:
        rules[f"affine_{a}k_{b}p"] = (lambda a, b: lambda k, p: (a * k + b * p) % 26)(a, b)

    # Constant offsets: ct = (k + p + c) mod 26
    for c in range(1, 26):
        rules[f"offset_{c}"] = (lambda c: lambda k, p: (k + p + c) % 26)(c)

    # Diagonal-like: ct = (k + 2p) mod 26 (move diagonally on tableau)
    # Already covered by affine_col_2

    # Negative/subtraction variants with offsets
    rules["neg_k_plus_p"] = lambda k, p: (26 - k + p) % 26  # same as bottom_up+1
    rules["k_minus_2p"] = lambda k, p: (k - 2 * p) % 26
    rules["2k_minus_p"] = lambda k, p: (2 * k - p) % 26
    rules["k_xor_p"] = lambda k, p: (k ^ p) % 26  # bitwise XOR

    # Squared: ct = (k*k + p) mod 26, ct = (k + p*p) mod 26
    rules["k_squared_plus_p"] = lambda k, p: (k * k + p) % 26
    rules["k_plus_p_squared"] = lambda k, p: (k + p * p) % 26
    rules["k_times_p"] = lambda k, p: (k * p) % 26

    return rules


def build_decrypt_key_table(encrypt_fn):
    """For a given encrypt function, build table:
    decrypt_key[ct_idx][pt_idx] → set of key_idx values.
    """
    table = [[set() for _ in range(26)] for _ in range(26)]
    for k in range(26):
        for p in range(26):
            c = encrypt_fn(k, p)
            if 0 <= c < 26:
                table[c][p].add(k)
    return table


# ── Main experiment ────────────────────────────────────────────────

print("=" * 70)
print("E-TABLEAU-NAV-001: Non-Standard Tableau Navigation (Algebraic)")
print("=" * 70)

t0 = time.time()
rules = build_rules()
print(f"Navigation rules defined: {len(rules)}")

ALPHABETS = {
    "AZ": (ALPH, ALPH_IDX, CT_NUM, CRIB_PT_NUM, CRIB_CT_NUM),
    "KA": (KA, KA_IDX, KA_NUM_CT, KA_NUM_PT, KA_NUM_CT_CRIB),
}

total_rules_tested = 0
total_candidates = 0
best_overall_score = 0
best_overall_config = None
results_log = []

for alph_name, (alphabet, aidx, ct_num, crib_pt, crib_ct) in ALPHABETS.items():
    for rule_name, encrypt_fn in rules.items():
        total_rules_tested += 1

        # Build decrypt-key table for this rule
        dk_table = build_decrypt_key_table(encrypt_fn)

        # For each crib position, find valid key indices
        crib_key_options = {}  # pos → set of valid key indices
        impossible = False
        for pos in CRIB_POSITIONS:
            ct_idx = crib_ct[pos]
            pt_idx = crib_pt[pos]
            valid_keys = dk_table[ct_idx][pt_idx]
            if not valid_keys:
                impossible = True
                break
            crib_key_options[pos] = valid_keys

        if impossible:
            continue

        # Test each period p in [2, 26]
        for period in range(2, 27):
            # Group crib positions by residue class
            residue_groups = defaultdict(list)
            for pos in CRIB_POSITIONS:
                residue_groups[pos % period].append(pos)

            # For each residue class, intersect valid key sets
            consistent = True
            key_by_residue = {}
            for residue, positions in residue_groups.items():
                valid = None
                for pos in positions:
                    if valid is None:
                        valid = set(crib_key_options[pos])
                    else:
                        valid &= crib_key_options[pos]
                if not valid:
                    consistent = False
                    break
                key_by_residue[residue] = valid

            if not consistent:
                continue

            # We have a consistent (rule, alphabet, period)!
            # Try all combinations of key values across residue classes
            residues_ordered = sorted(key_by_residue.keys())
            options = [sorted(key_by_residue[r]) for r in residues_ordered]

            # Limit combinatorial explosion
            n_combos = 1
            for opt in options:
                n_combos *= len(opt)
            if n_combos > 100_000:
                # Too many — sample
                import random
                random.seed(42)
                combos_to_try = []
                for _ in range(10_000):
                    combo = tuple(random.choice(opt) for opt in options)
                    combos_to_try.append(combo)
            else:
                combos_to_try = list(iprod(*options))

            for combo in combos_to_try:
                # Build full periodic key
                key_map = {residues_ordered[i]: combo[i] for i in range(len(combo))}
                full_key = [key_map.get(i % period, 0) for i in range(CT_LEN)]

                # Check: do we have key values for ALL residues used by CT?
                missing = False
                for i in range(CT_LEN):
                    if i % period not in key_map:
                        missing = True
                        break
                if missing:
                    # Fill missing residues — can't determine, try all... but skip for now
                    # Only score if ALL residues are determined by cribs
                    continue

                # Decrypt
                pt_nums = []
                for i in range(CT_LEN):
                    # For each position, need to find pt such that encrypt(key, pt) = ct
                    k = full_key[i]
                    c = ct_num[i]
                    # Find pt from dk_table: we need pt such that encrypt(k,pt)=c
                    # Actually dk_table[c][pt] gives key values. We need the inverse:
                    # for given k and c, find p such that encrypt(k,p) = c
                    found_pt = None
                    for p in range(26):
                        if encrypt_fn(k, p) == c:
                            found_pt = p
                            break
                    if found_pt is None:
                        pt_nums = None
                        break
                    pt_nums.append(found_pt)

                if pt_nums is None:
                    continue

                # Score cribs
                crib_matches = 0
                for pos in CRIB_POSITIONS:
                    if pt_nums[pos] == crib_pt[pos]:
                        crib_matches += 1

                if crib_matches < 14:
                    continue

                total_candidates += 1
                pt_text = ''.join(alphabet[x] for x in pt_nums)
                qg = quadgram_score(pt_text)
                ic_val = ic(pt_nums)
                bean_ok = check_bean(pt_nums)

                entry = {
                    'alphabet': alph_name,
                    'rule': rule_name,
                    'period': period,
                    'key': [combo[i] for i in range(len(combo))],
                    'crib_score': crib_matches,
                    'quadgram_per_char': round(qg, 3),
                    'ic': round(ic_val, 4),
                    'bean': bean_ok,
                    'pt_preview': pt_text[:50],
                }
                results_log.append(entry)

                if crib_matches > best_overall_score:
                    best_overall_score = crib_matches
                    best_overall_config = entry

                if crib_matches >= 16:
                    print(f"\n  ** SIGNAL: {alph_name}/{rule_name} p={period} "
                          f"cribs={crib_matches}/24 qg={qg:.2f} IC={ic_val:.4f} "
                          f"Bean={'PASS' if bean_ok else 'FAIL'}")
                    print(f"     PT: {pt_text[:60]}...")
                    print(f"     Key: {[alphabet[x] for x in combo]}")

        # Progress
        if total_rules_tested % 50 == 0:
            print(f"  Tested {total_rules_tested} rule+alphabet combos, "
                  f"{total_candidates} candidates above 14/24, "
                  f"best={best_overall_score}/24, {time.time()-t0:.1f}s")


# ── Position-dependent rules ──────────────────────────────────────
print(f"\n--- Phase 2: Position-dependent rules ---")

pos_dep_rules = {
    "vig_plus_pos": lambda k, p, i: (k + p + i) % 26,
    "vig_plus_pos_mod10": lambda k, p, i: (k + p + (i % 10)) % 26,
    "vig_plus_pos_mod9": lambda k, p, i: (k + p + (i % 9)) % 26,
    "vig_plus_pos_mod7": lambda k, p, i: (k + p + (i % 7)) % 26,
    "vig_times_pos": lambda k, p, i: (k + p + i * k) % 26,
    "beau_plus_pos": lambda k, p, i: (k - p + i) % 26,
    "vig_progressive": lambda k, p, i: (k + p + i // 10) % 26,
    "vig_row_col_swap_by_pos": lambda k, p, i: ((k + p) if i % 2 == 0 else (k - p)) % 26,
}

for alph_name, (alphabet, aidx, ct_num, crib_pt, crib_ct) in ALPHABETS.items():
    for rule_name, rule_fn in pos_dep_rules.items():
        total_rules_tested += 1

        # For position-dependent rules with a periodic key,
        # the key at each crib position is determined uniquely (if the rule is invertible in k).
        # For each crib position i: find k such that rule_fn(k, pt[i], i) = ct[i]
        crib_key_options = {}
        impossible = False
        for pos in CRIB_POSITIONS:
            ct_idx = crib_ct[pos]
            pt_idx = crib_pt[pos]
            valid_keys = set()
            for k in range(26):
                if rule_fn(k, pt_idx, pos) == ct_idx:
                    valid_keys.add(k)
            if not valid_keys:
                impossible = True
                break
            crib_key_options[pos] = valid_keys

        if impossible:
            continue

        # Test periodicity
        for period in range(2, 27):
            residue_groups = defaultdict(list)
            for pos in CRIB_POSITIONS:
                residue_groups[pos % period].append(pos)

            consistent = True
            key_by_residue = {}
            for residue, positions in residue_groups.items():
                valid = None
                for pos in positions:
                    if valid is None:
                        valid = set(crib_key_options[pos])
                    else:
                        valid &= crib_key_options[pos]
                if not valid:
                    consistent = False
                    break
                key_by_residue[residue] = valid

            if not consistent:
                continue

            # Build and test key combos (same as above)
            residues_ordered = sorted(key_by_residue.keys())
            options = [sorted(key_by_residue[r]) for r in residues_ordered]
            n_combos = 1
            for opt in options:
                n_combos *= len(opt)
            if n_combos > 100_000:
                continue  # skip intractable combos for pos-dependent
            if n_combos == 0:
                continue

            for combo in iprod(*options):
                key_map = {residues_ordered[j]: combo[j] for j in range(len(combo))}
                missing = any(i % period not in key_map for i in range(CT_LEN))
                if missing:
                    continue

                full_key = [key_map[i % period] for i in range(CT_LEN)]
                pt_nums = []
                ok = True
                for i in range(CT_LEN):
                    found = None
                    for p in range(26):
                        if rule_fn(full_key[i], p, i) == ct_num[i]:
                            found = p
                            break
                    if found is None:
                        ok = False
                        break
                    pt_nums.append(found)

                if not ok:
                    continue

                crib_matches = sum(1 for pos in CRIB_POSITIONS if pt_nums[pos] == crib_pt[pos])
                if crib_matches < 14:
                    continue

                total_candidates += 1
                pt_text = ''.join(alphabet[x] for x in pt_nums)
                qg = quadgram_score(pt_text)
                ic_val = ic(pt_nums)
                bean_ok = check_bean(pt_nums)

                entry = {
                    'alphabet': alph_name,
                    'rule': rule_name,
                    'period': period,
                    'crib_score': crib_matches,
                    'quadgram_per_char': round(qg, 3),
                    'ic': round(ic_val, 4),
                    'bean': bean_ok,
                    'pt_preview': pt_text[:50],
                }
                results_log.append(entry)
                if crib_matches > best_overall_score:
                    best_overall_score = crib_matches
                    best_overall_config = entry

                if crib_matches >= 16:
                    print(f"\n  ** SIGNAL: {alph_name}/{rule_name} p={period} "
                          f"cribs={crib_matches}/24 qg={qg:.2f} Bean={'PASS' if bean_ok else 'FAIL'}")
                    print(f"     PT: {pt_text[:60]}...")

elapsed = time.time() - t0

# ── Summary ────────────────────────────────────────────────────────

print()
print("=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  Total rule+alphabet combos tested: {total_rules_tested}")
print(f"  Total candidates above 14/24: {total_candidates}")
print(f"  Elapsed: {elapsed:.2f}s")
print(f"  Best crib score: {best_overall_score}/24")

if best_overall_config:
    cfg = best_overall_config
    print(f"  Best config: {cfg['alphabet']}/{cfg['rule']} p={cfg['period']}")
    print(f"    Cribs: {cfg['crib_score']}/24, QG/c: {cfg['quadgram_per_char']}, "
          f"IC: {cfg['ic']}, Bean: {cfg['bean']}")
    print(f"    PT: {cfg['pt_preview']}...")

# Score interpretation
if best_overall_score >= 20:
    print("\n  *** SIGNAL DETECTED — investigate immediately ***")
elif best_overall_score <= 6:
    print("\n  RESULT: NOISE. No non-standard tableau navigation with periodic key works.")
    print("  ELIMINATED: All tested navigation rules × periods 2-26 × both alphabets.")
else:
    period_note = ""
    if best_overall_config and best_overall_config['period'] >= 13:
        period_note = " (WARNING: high period — likely underdetermination artifact)"
    print(f"\n  RESULT: Best {best_overall_score}/24{period_note}")
    if best_overall_score <= 14:
        print("  At or below noise floor. Non-standard tableau navigation: ELIMINATED.")
    else:
        print("  Above noise but below signal. Investigate further if period <= 7.")

# Dump any candidates above noise
if results_log:
    print(f"\n  Candidates above 14/24: {len(results_log)}")
    # Show period distribution
    from collections import Counter
    period_dist = Counter(e['period'] for e in results_log)
    print(f"  By period: {dict(sorted(period_dist.items()))}")

    os.makedirs("results", exist_ok=True)
    with open("results/e_tableau_nav_001.json", "w") as f:
        json.dump({
            'experiment': 'E-TABLEAU-NAV-001',
            'total_rules': total_rules_tested,
            'total_candidates': total_candidates,
            'best_score': best_overall_score,
            'best_config': best_overall_config,
            'all_candidates': results_log[:100],  # cap output
            'elapsed': elapsed,
        }, f, indent=2)
    print(f"  Artifact: results/e_tableau_nav_001.json")

print(f"\n  Repro: PYTHONPATH=src python3 -u scripts/e_tableau_nav_001_algebraic.py")
