#!/usr/bin/env python3
"""
Cipher: autokey
Family: polyalphabetic
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-06: Autokey cipher test for K4.

This is a HIGH-LEVERAGE test because autokey ciphers:
- Are position-dependent (not periodic) ✓
- Are NOT from any linear recurrence ✓
- Can be done by hand ("not mathematical") ✓
- Are fully determined by a short primer
- The known cribs PROPAGATE through the autokey mechanism,
  determining plaintext at positions far from the cribs

Two autokey variants:
1. PLAINTEXT autokey: k[i] = primer[i] for i < p, PT[i-p] for i ≥ p
   → CT[i] = (PT[i] + k[i]) mod 26
2. CIPHERTEXT autokey: k[i] = primer[i] for i < p, CT[i-p] for i ≥ p
   → CT[i] = (PT[i] + k[i]) mod 26

For plaintext autokey, the known cribs at positions 21-33 and 63-73
determine the key at positions (21+p)-(33+p) and (63+p)-(73+p),
which in turn determine more plaintext, which propagates further.

ALGEBRAIC ELIMINATION:
- Ciphertext autokey: can check directly since k[i]=CT[i-p] is fully known
- Plaintext autokey: overlap contradictions eliminate p=1-12 and p=30-52
  Remaining: p ∈ {13..29, 53..96}

Also tests Beaufort and Variant Beaufort autokey variants.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH_IDX, MOD, CRIB_DICT, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
)

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_POS = sorted(CRIB_DICT.keys())


def num_to_char(n):
    return chr(ord('A') + (n % 26))


def score_cribs(pt_nums):
    matches = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(pt_nums) and pt_nums[pos] == ALPH_IDX[ch]:
            matches += 1
    return matches


def check_bean(pt_nums):
    key = [(CT_NUM[i] - pt_nums[i]) % MOD for i in range(len(pt_nums))]
    for a, b in BEAN_EQ:
        if key[a] != key[b]:
            return False
    for a, b in BEAN_INEQ:
        if key[a] == key[b]:
            return False
    return True


def ic(nums):
    """Index of coincidence."""
    n = len(nums)
    if n < 2:
        return 0
    counts = [0] * 26
    for v in nums:
        counts[v] += 1
    return sum(c * (c - 1) for c in counts) / (n * (n - 1))


def english_score(text):
    """Quick English-likeness score (bigram + common word check)."""
    score = 0
    common_bigrams = {'TH', 'HE', 'IN', 'ER', 'AN', 'RE', 'ON', 'AT',
                      'EN', 'ND', 'TI', 'ES', 'OR', 'TE', 'OF', 'ED',
                      'IS', 'IT', 'AL', 'AR', 'ST', 'TO', 'NT', 'NG'}
    for i in range(len(text) - 1):
        if text[i:i+2] in common_bigrams:
            score += 1
    common_words = {'THE', 'AND', 'WAS', 'FOR', 'ARE', 'BUT', 'NOT',
                    'YOU', 'ALL', 'CAN', 'HER', 'ONE', 'OUR', 'OUT',
                    'DAY', 'HAD', 'HAS', 'HIS', 'HOW', 'ITS', 'MAY',
                    'NEW', 'NOW', 'OLD', 'SEE', 'WAY', 'WHO', 'DID',
                    'GET', 'LET', 'SAY', 'SHE', 'TOO', 'USE',
                    'EAST', 'NORTH', 'BERLIN', 'CLOCK', 'TIME', 'WALL',
                    'BETWEEN', 'SLOWLY', 'BURIED', 'SHADOW'}
    for w in common_words:
        if w in text:
            score += 5
    return score


def main():
    print("=" * 80)
    print("E-06: Autokey Cipher Test for K4")
    print("=" * 80)
    sys.stdout.flush()

    results = []

    # ═══════════════════════════════════════════════════════════════════════════
    # TEST 1: CIPHERTEXT AUTOKEY (fully determined, exhaustive)
    # ═══════════════════════════════════════════════════════════════════════════

    print("\n── Test 1: Ciphertext autokey (all primer lengths 1-96) ──")
    print("  k[i] = primer[i] for i < p, CT[i-p] for i ≥ p")
    sys.stdout.flush()

    # For ciphertext autokey, the key at position i ≥ p is CT[i-p], which is known.
    # So for each primer length, we only need to find primer values.
    # At crib positions i ≥ p: k[i] = CT[i-p], and we need k[i] = (CT[i] - PT[i]) mod 26.
    # This constrains nothing about the primer — it's a direct check.

    for variant_name, decrypt_fn in [
        ("Vig", lambda ct, k: (ct - k) % MOD),
        ("Beaufort", lambda ct, k: (k - ct) % MOD),
        ("VarBeau", lambda ct, k: (ct + k) % MOD),
    ]:
        best_for_variant = (0, 0, [])

        for p in range(1, CT_LEN):
            # Check: do the crib positions with i ≥ p have consistent keys?
            crib_consistent = True
            for pos in CRIB_POS:
                if pos >= p:
                    k_val = CT_NUM[pos - p]
                    pt_expected = ALPH_IDX[CRIB_DICT[pos]]
                    pt_computed = decrypt_fn(CT_NUM[pos], k_val)
                    if pt_computed != pt_expected:
                        crib_consistent = False
                        break

            if not crib_consistent:
                continue

            # All cribs with i ≥ p are consistent! Now try all primer values.
            # For cribs with i < p, the key is the primer — we need to find it.
            # The number of primer positions that overlap with cribs is small.
            primer_crib_positions = [pos for pos in CRIB_POS if pos < p]

            if len(primer_crib_positions) == 0:
                # All cribs are in the autokey region and they're consistent!
                # Try a random primer and score
                primer = [0] * p  # dummy primer
                # Compute full key
                key = list(primer) + [CT_NUM[i - p] for i in range(p, CT_LEN)]
                pt = [decrypt_fn(CT_NUM[i], key[i]) for i in range(CT_LEN)]
                score = score_cribs(pt)
                bean = check_bean(pt)

                if score >= N_CRIBS - 1:  # Should be 24/24 since all cribs consistent
                    # Now try to find primer that makes good English
                    # The primer positions (0..p-1) need to be determined
                    # But we have score=24 from cribs!
                    pt_text = ''.join(num_to_char(n) for n in pt)
                    eng = english_score(pt_text)
                    tag = f"CT-autokey p={p} {variant_name}"
                    print(f"  ** {tag}: score={score}/{N_CRIBS} "
                          f"{'BEAN✓' if bean else 'bean✗'} eng={eng}")
                    print(f"     PT: {pt_text}")
                    results.append((score, tag, p, bean, eng))
                    sys.stdout.flush()

            else:
                # Some cribs fall in the primer region.
                # The primer at those positions is determined by the crib.
                primer_constraints = {}
                for pos in primer_crib_positions:
                    pt_expected = ALPH_IDX[CRIB_DICT[pos]]
                    # PT[pos] = decrypt_fn(CT[pos], primer[pos])
                    # For Vig: PT = CT - primer → primer = CT - PT
                    # We need to solve for primer[pos]
                    if variant_name == "Vig":
                        primer_constraints[pos] = (CT_NUM[pos] - pt_expected) % MOD
                    elif variant_name == "Beaufort":
                        # PT = primer - CT → primer = PT + CT
                        primer_constraints[pos] = (pt_expected + CT_NUM[pos]) % MOD
                    else:  # VarBeau
                        # PT = CT + primer → primer = PT - CT
                        primer_constraints[pos] = (pt_expected - CT_NUM[pos]) % MOD

                # Build full key with known constraints
                key = [0] * CT_LEN
                for i in range(p, CT_LEN):
                    key[i] = CT_NUM[i - p]
                for pos, val in primer_constraints.items():
                    key[pos] = val

                pt = [decrypt_fn(CT_NUM[i], key[i]) for i in range(CT_LEN)]
                score = score_cribs(pt)

                if score >= 20:
                    bean = check_bean(pt)
                    pt_text = ''.join(num_to_char(n) for n in pt)
                    eng = english_score(pt_text)
                    tag = f"CT-autokey p={p} {variant_name}"
                    print(f"  ** {tag}: score={score}/{N_CRIBS} "
                          f"{'BEAN✓' if bean else 'bean✗'} eng={eng}")
                    print(f"     PT: {pt_text}")
                    results.append((score, tag, p, bean, eng))
                    sys.stdout.flush()

                if score > best_for_variant[0]:
                    best_for_variant = (score, p, primer_constraints)

        print(f"  {variant_name} CT-autokey best: {best_for_variant[0]}/{N_CRIBS} at p={best_for_variant[1]}")
    sys.stdout.flush()

    # ═══════════════════════════════════════════════════════════════════════════
    # TEST 2: PLAINTEXT AUTOKEY (propagation from cribs)
    # ═══════════════════════════════════════════════════════════════════════════

    print("\n── Test 2: Plaintext autokey (propagation from cribs) ──")
    print("  k[i] = primer[i] for i < p, PT[i-p] for i ≥ p")
    print("  Algebraic check: p=1-12 and p=30-52 have overlap contradictions")
    sys.stdout.flush()

    for variant_name, key_from_ct_pt, pt_from_ct_key in [
        ("Vig",
         lambda ct, pt: (ct - pt) % MOD,     # k = CT - PT
         lambda ct, k: (ct - k) % MOD),       # PT = CT - k
        ("Beaufort",
         lambda ct, pt: (ct + pt) % MOD,      # k = CT + PT (Beaufort)
         lambda ct, k: (k - ct) % MOD),        # PT = k - CT
        ("VarBeau",
         lambda ct, pt: (pt - ct) % MOD,       # k = PT - CT
         lambda ct, k: (ct + k) % MOD),        # PT = CT + k
    ]:
        print(f"\n  === {variant_name} plaintext autokey ===")
        sys.stdout.flush()

        best_for_variant = (0, 0, 0)

        for p in range(1, CT_LEN):
            # Step 1: Check if this primer length creates contradictions
            # at overlap positions (where the autokey chain reaches known cribs)
            contradiction = False

            # Build what we know: at crib positions, PT is known
            known_pt = dict(CRIB_DICT)  # pos → letter
            known_pt_num = {pos: ALPH_IDX[ch] for pos, ch in known_pt.items()}

            # Propagate: for position i ≥ p, k[i] = PT[i-p]
            # If (i-p) has known PT, then k[i] is determined.
            # Then PT[i] = pt_from_ct_key(CT[i], k[i]).
            # If position i also has a known PT (crib), check consistency.

            # First pass: check consistency at crib positions
            for pos in CRIB_POS:
                if pos >= p and (pos - p) in known_pt_num:
                    k_val = known_pt_num[pos - p]
                    pt_computed = pt_from_ct_key(CT_NUM[pos], k_val)
                    pt_expected = ALPH_IDX[CRIB_DICT[pos]]
                    if pt_computed != pt_expected:
                        contradiction = True
                        break

            if contradiction:
                continue

            # Step 2: Full propagation from cribs
            # Start with known PT at crib positions.
            # Propagate forward: if PT[j] is known and j+p < CT_LEN,
            # then k[j+p] = PT[j], so PT[j+p] = pt_from_ct_key(CT[j+p], PT[j])
            # This may chain further.

            pt = [None] * CT_LEN
            for pos, ch in CRIB_DICT.items():
                pt[pos] = ALPH_IDX[ch]

            # Propagate until no more changes
            changed = True
            while changed:
                changed = False
                for i in range(CT_LEN):
                    if pt[i] is not None and i + p < CT_LEN and pt[i + p] is None:
                        k_val = pt[i]
                        pt[i + p] = pt_from_ct_key(CT_NUM[i + p], k_val)
                        changed = True

            # Also propagate backward: if PT[i] is known and i ≥ p,
            # then k[i] = PT[i-p] (if known), but if k[i] is also determinable
            # from CT[i] and PT[i]: k[i] = key_from_ct_pt(CT[i], PT[i])
            # Then PT[i-p] = k[i] (for plaintext autokey)
            changed = True
            while changed:
                changed = False
                for i in range(p, CT_LEN):
                    if pt[i] is not None and pt[i - p] is None:
                        # k[i] must equal PT[i-p]
                        # k[i] = key_from_ct_pt(CT[i], PT[i])
                        k_val = key_from_ct_pt(CT_NUM[i], pt[i])
                        pt[i - p] = k_val
                        changed = True
                # Also forward propagation of newly discovered values
                for i in range(CT_LEN):
                    if pt[i] is not None and i + p < CT_LEN and pt[i + p] is None:
                        k_val = pt[i]
                        pt[i + p] = pt_from_ct_key(CT_NUM[i + p], k_val)
                        changed = True

            # Check consistency: any contradiction with cribs?
            for pos, ch in CRIB_DICT.items():
                if pt[pos] is not None and pt[pos] != ALPH_IDX[ch]:
                    contradiction = True
                    break

            if contradiction:
                continue

            # Count how many positions are determined
            n_determined = sum(1 for v in pt if v is not None)
            score = score_cribs([v if v is not None else -1 for v in pt])

            # Check Bean
            pt_for_bean = [v if v is not None else 0 for v in pt]
            bean = check_bean(pt_for_bean) if n_determined > 80 else False

            # Compute English score for determined positions
            pt_text_full = ''.join(num_to_char(v) if v is not None else '?' for v in pt)
            determined_text = ''.join(num_to_char(v) for v in pt if v is not None)
            eng = english_score(determined_text)
            ic_val = ic([v for v in pt if v is not None]) if n_determined > 10 else 0

            if n_determined >= 50 or eng >= 5 or (bean and score >= 20):
                tag = f"PT-autokey p={p} {variant_name}"
                print(f"  {tag}: determined={n_determined}/{CT_LEN} score={score}/{N_CRIBS} "
                      f"{'BEAN✓' if bean else 'bean✗'} eng={eng} IC={ic_val:.4f}")
                if n_determined >= 80:
                    print(f"     PT: {pt_text_full}")
                results.append((score, tag, p, bean, eng))
                sys.stdout.flush()

            if n_determined > best_for_variant[2]:
                best_for_variant = (score, p, n_determined)

        print(f"  {variant_name} PT-autokey best: score={best_for_variant[0]}/{N_CRIBS}, "
              f"most-determined={best_for_variant[2]}/{CT_LEN} at p={best_for_variant[1]}")
    sys.stdout.flush()

    # ═══════════════════════════════════════════════════════════════════════════
    # TEST 3: AUTOKEY WITH KEYED ALPHABET
    # ═══════════════════════════════════════════════════════════════════════════

    print("\n── Test 3: Autokey with KRYPTOS-keyed alphabet ──")
    sys.stdout.flush()

    # Instead of standard A=0..Z=25, use the KRYPTOS alphabet ordering
    from kryptos.kernel.constants import KRYPTOS_ALPHABET
    KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
    KA_CT = [KA_IDX[c] for c in CT]

    for p in range(1, 30):
        # Plaintext autokey with KRYPTOS alphabet
        known_pt = {pos: KA_IDX.get(ch, ALPH_IDX[ch]) for pos, ch in CRIB_DICT.items()}

        pt_ka = [None] * CT_LEN
        for pos, val in known_pt.items():
            pt_ka[pos] = val

        # Forward propagation
        changed = True
        while changed:
            changed = False
            for i in range(CT_LEN):
                if pt_ka[i] is not None and i + p < CT_LEN and pt_ka[i + p] is None:
                    pt_ka[i + p] = (KA_CT[i + p] - pt_ka[i]) % MOD
                    changed = True
            for i in range(p, CT_LEN):
                if pt_ka[i] is not None and pt_ka[i - p] is None:
                    pt_ka[i - p] = (KA_CT[i] - pt_ka[i]) % MOD
                    changed = True

        n_determined = sum(1 for v in pt_ka if v is not None)
        if n_determined >= 50:
            # Convert back to standard alphabet for scoring
            inv_ka = {i: c for i, c in enumerate(KRYPTOS_ALPHABET)}
            pt_text = ''.join(inv_ka.get(v, '?') if v is not None else '?' for v in pt_ka)
            # Score against standard cribs
            pt_std = [ALPH_IDX.get(c, -1) for c in pt_text]
            score = score_cribs(pt_std)
            eng = english_score(pt_text)
            print(f"  KA-autokey p={p}: det={n_determined} score={score}/{N_CRIBS} eng={eng}")
            if n_determined >= 80:
                print(f"     PT: {pt_text}")
            results.append((score, f"KA-autokey p={p}", p, False, eng))
            sys.stdout.flush()

    # ═══════════════════════════════════════════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════════════════════════════════════════

    print("\n" + "=" * 80)
    print("SUMMARY: Autokey Results")
    print("=" * 80)

    results.sort(key=lambda x: (-x[0], -x[4]))
    for score, tag, p, bean, eng in results[:20]:
        bean_str = "BEAN✓" if bean else "bean✗"
        print(f"  {score}/{N_CRIBS} {bean_str} eng={eng} | {tag}")

    best = results[0] if results else (0, "none", 0, False, 0)
    print(f"\nBest: {best[0]}/{N_CRIBS} | {best[1]}")

    if best[0] >= 17:
        print("SUCCESS: Autokey shows strong signal")
    elif best[0] >= 10:
        print("INTERESTING: Above noise, investigate further")
    else:
        print("FAILURE: Autokey variants at noise floor")

    print("\n[E-06 COMPLETE]")
    return best[0]


if __name__ == "__main__":
    main()
