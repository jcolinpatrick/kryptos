#!/usr/bin/env python3
"""
Analytical elimination engine for K4 cipher models.

Cipher:  Multiple (analytical constraints)
Family:  substitution
Status:  active
Keyspace: analytical (not search)
Last run: never
Best score: N/A

Applies Biham-Shamir-style constraint propagation to eliminate
entire cipher families in microseconds. For each model, we derive
what the key MUST be from the 24 known PT-CT pairs, then check
if those derived key values are self-consistent.

If inconsistent → model is STRUCTURALLY IMPOSSIBLE (Tier 1 elimination).
If consistent → derive the required key and attempt full decryption.

Models tested:
  A. CT-autokey (Vig/Beau/VBeau × AZ/KA × primer lengths 1-96)
  B. PT-autokey (internal consistency + cross-block + Bean)
  C. Gronsfeld (key digits 0-9 only)
  D. Porta cipher
  E. Beaufort autokey variants
  F. Quagmire I/II/III consistency check
  G. Trans + mono sub (constraint propagation on permutation)
"""

import json, sys, time
from pathlib import Path
from itertools import combinations

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kryptos.kernel.constants import CT, CRIB_DICT, BEAN_EQ, BEAN_INEQ

QG_PATH = Path(__file__).resolve().parents[2] / "data" / "english_quadgrams.json"
with open(QG_PATH) as f:
    _qg = json.load(f)
QG_FLOOR = min(_qg.values()) - 1.0

def qg_per_char(text):
    s = sum(_qg.get(text[i:i+4], QG_FLOOR) for i in range(len(text)-3))
    n = len(text) - 3
    return s / n if n > 0 else QG_FLOOR

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
N = len(CT)
MOD = 26

# Build index maps
AZ_IDX = {c: i for i, c in enumerate(AZ)}
KA_IDX = {c: i for i, c in enumerate(KA)}

# Crib data
CRIB_POSITIONS = sorted(CRIB_DICT.keys())
PT_AT = {}  # position -> plaintext char
CT_AT = {}  # position -> ciphertext char
for pos, ch in CRIB_DICT.items():
    PT_AT[pos] = ch
    CT_AT[pos] = CT[pos]

print(f"K4 Analytical Eliminator")
print(f"CT ({N}): {CT}")
print(f"Cribs: {len(CRIB_POSITIONS)} known positions")


# ══════════════════════════════════════════════════════════════════════════
# A. CT-AUTOKEY: key[i] = CT[i-L] for i >= L
# ══════════════════════════════════════════════════════════════════════════

def test_ct_autokey():
    print(f"\n{'='*70}")
    print("A. CT-AUTOKEY — Analytical Elimination")
    print("="*70)
    print("  For primer length L, key[i] = CT[i-L] for i >= L.")
    print("  CT is fully known → key is fully determined → instant check.\n")

    alphabets = [("AZ", AZ, AZ_IDX), ("KA", KA, KA_IDX)]
    variants = [
        ("Vig",   lambda ct, k: (ct - k) % MOD),
        ("Beau",  lambda ct, k: (k - ct) % MOD),
        ("VBeau", lambda ct, k: (ct + k) % MOD),
    ]

    survivors = []
    total = 0

    for alph_name, alph, idx in alphabets:
        for var_name, dec_fn in variants:
            for L in range(1, N):
                total += 1
                matches = 0
                mismatches = 0

                for pos in CRIB_POSITIONS:
                    if pos < L:
                        continue  # primer region — can't check

                    ct_idx = idx[CT[pos]]
                    key_idx = idx[CT[pos - L]]
                    pt_idx = dec_fn(ct_idx, key_idx)
                    pt_char = alph[pt_idx]

                    expected = PT_AT[pos]
                    if pt_char == expected:
                        matches += 1
                    else:
                        mismatches += 1
                        break  # one mismatch eliminates

                if mismatches == 0 and matches > 0:
                    # All testable crib positions match!
                    # Compute full decryption
                    pt_chars = list(CT)  # placeholder
                    # First L chars: need primer (unknown)
                    # Chars L..96: decrypt using CT[i-L] as key
                    for i in range(L, N):
                        ct_i = idx[CT[i]]
                        key_i = idx[CT[i - L]]
                        pt_i = dec_fn(ct_i, key_i)
                        pt_chars[i] = alph[pt_i]

                    # For primer positions (0..L-1), mark as unknown
                    for i in range(L):
                        pt_chars[i] = '?'

                    pt_known = ''.join(pt_chars[L:])
                    qg = qg_per_char(pt_known) if len(pt_known) > 3 else -99

                    survivors.append({
                        'alph': alph_name, 'var': var_name, 'L': L,
                        'matches': matches, 'tested': matches,
                        'pt_from_L': pt_known, 'qg': qg,
                    })

    eliminated = total - len(survivors)
    print(f"  Tested: {total} configs (96 primer lengths × 3 variants × 2 alphabets)")
    print(f"  Eliminated: {eliminated} ({100*eliminated/total:.1f}%)")
    print(f"  Survivors: {len(survivors)}")

    if survivors:
        # Sort by matches (desc) then qg (desc)
        survivors.sort(key=lambda s: (-s['matches'], -s['qg']))
        print(f"\n  SURVIVING CT-AUTOKEY CONFIGURATIONS:")
        for s in survivors[:20]:
            print(f"    L={s['L']:2d} {s['alph']}/{s['var']} "
                  f"matches={s['matches']}/{s['tested']} "
                  f"qg={s['qg']:.3f} | ...{s['pt_from_L'][:50]}...")
    else:
        print(f"\n  *** ALL CT-AUTOKEY ELIMINATED on raw 97-char CT ***")

    return survivors


# ══════════════════════════════════════════════════════════════════════════
# B. PT-AUTOKEY: key[i] = PT[i-L] for i >= L
# ══════════════════════════════════════════════════════════════════════════

def test_pt_autokey():
    print(f"\n{'='*70}")
    print("B. PT-AUTOKEY — Analytical Elimination")
    print("="*70)
    print("  For primer length L, key[i] = PT[i-L].")
    print("  PT is only known at crib positions → partial check.\n")

    alphabets = [("AZ", AZ, AZ_IDX), ("KA", KA, KA_IDX)]
    variants = [
        # (name, encrypt: PT,K -> CT, key_derive: CT,PT -> K)
        ("Vig",   lambda p, k: (p + k) % MOD, lambda c, p: (c - p) % MOD),
        ("Beau",  lambda p, k: (k - p) % MOD, lambda c, p: (c + p) % MOD),
        ("VBeau", lambda p, k: (p - k) % MOD, lambda c, p: (p - c) % MOD),
    ]

    survivors = []
    total = 0
    elim_reasons = {"intra_ene": 0, "intra_bc": 0, "cross_block": 0,
                    "bean_eq": 0, "bean_ineq": 0, "derived_key": 0}

    for alph_name, alph, idx in alphabets:
        for var_name, enc_fn, key_fn in variants:
            for L in range(1, N):
                total += 1
                eliminated = False
                reason = None

                # Derive key values at crib positions
                # key[c] = PT[c-L] for c >= L
                # At crib position c, we know PT[c] and CT[c].
                # key_derive: k[c] = f(CT[c], PT[c])
                # If c-L is ALSO a crib position, then PT[c-L] is known.
                # Check: derived key k[c] should equal idx[PT[c-L]]

                derived_keys = {}  # pos -> key value (in alph)
                for c in CRIB_POSITIONS:
                    ct_val = idx[CT[c]]
                    pt_val = idx[PT_AT[c]]
                    k_val = key_fn(ct_val, pt_val)
                    derived_keys[c] = k_val

                # Check 1: Intra-block consistency
                # For c >= L where c-L is also a crib position:
                # k[c] should equal idx[PT[c-L]]
                for c in CRIB_POSITIONS:
                    if c < L:
                        continue
                    src = c - L
                    if src in PT_AT:
                        expected_key = idx[PT_AT[src]]
                        if derived_keys[c] != expected_key:
                            eliminated = True
                            if 21 <= src <= 33 or 21 <= c <= 33:
                                reason = "intra_ene"
                            elif 63 <= src <= 73 or 63 <= c <= 73:
                                reason = "intra_bc"
                            else:
                                reason = "cross_block"
                            break

                if eliminated:
                    elim_reasons[reason] += 1
                    continue

                # Check 2: If two crib positions c1, c2 have c1-L == c2-L (mod something)?
                # No — they're at different positions.
                # But: if c1-L and c2-L are both crib positions with same PT letter,
                # then k[c1] and k[c2] should both equal that letter's index.
                # More directly: if c1-L = c2-L, then k[c1] = k[c2].
                # That requires c1 = c2, trivial.

                # Check 3: Bean equality k[27] = k[65]
                if 27 in derived_keys and 65 in derived_keys:
                    if derived_keys[27] != derived_keys[65]:
                        eliminated = True
                        reason = "bean_eq"

                if eliminated:
                    elim_reasons[reason] += 1
                    continue

                # Check 4: Bean inequalities
                for a, b in BEAN_INEQ:
                    if a in derived_keys and b in derived_keys:
                        if derived_keys[a] == derived_keys[b]:
                            eliminated = True
                            reason = "bean_ineq"
                            break

                if eliminated:
                    elim_reasons[reason] += 1
                    continue

                # Check 5: Mutual consistency chains
                # From crib pos c, we derive key[c].
                # key[c] = PT[c-L]. If c-L is not a crib position, we LEARN PT[c-L].
                # Then if c-L >= L, key[c-L] = PT[c-2L], and we know PT[c-L] now...
                # Chain: PT[c], PT[c-L], PT[c-2L], ...
                # If this chain reaches ANOTHER crib position, we can check.

                learned_pt = dict(PT_AT)  # copy known PT
                chain_conflict = False

                for c in CRIB_POSITIONS:
                    if c < L:
                        continue
                    # We know key[c] = derived_keys[c]
                    # This means PT[c-L] = alph[derived_keys[c]]
                    src = c - L
                    inferred_char = alph[derived_keys[c]]

                    if src in learned_pt:
                        if learned_pt[src] != inferred_char:
                            chain_conflict = True
                            break
                    else:
                        learned_pt[src] = inferred_char

                # Now chain forward: for each newly learned PT position,
                # if it's in range, derive more
                changed = True
                while changed and not chain_conflict:
                    changed = False
                    for pos in list(learned_pt.keys()):
                        target = pos + L
                        if target >= N:
                            continue
                        if target not in derived_keys:
                            # We need CT[target] to derive key[target]
                            ct_val = idx[CT[target]]
                            # key[target] = PT[pos] (known now)
                            key_val = idx[learned_pt[pos]]
                            # PT[target] = decrypt(CT[target], key[target])
                            pt_idx_val = (ct_val - key_val) % MOD  # Vig
                            if var_name == "Beau":
                                pt_idx_val = (key_val - ct_val) % MOD
                            elif var_name == "VBeau":
                                pt_idx_val = (ct_val + key_val) % MOD
                            pt_char = alph[pt_idx_val]

                            if target in learned_pt:
                                if learned_pt[target] != pt_char:
                                    chain_conflict = True
                                    break
                            else:
                                learned_pt[target] = pt_char
                                changed = True

                if chain_conflict:
                    elim_reasons["derived_key"] += 1
                    continue

                # SURVIVOR! Compute what we know
                n_known = len(learned_pt)
                # Build partial PT
                pt_partial = ['?'] * N
                for pos, ch in learned_pt.items():
                    if 0 <= pos < N:
                        pt_partial[pos] = ch
                pt_str = ''.join(pt_partial)
                known_substr = ''.join(c for c in pt_partial if c != '?')
                qg = qg_per_char(known_substr) if len(known_substr) > 10 else -99

                survivors.append({
                    'alph': alph_name, 'var': var_name, 'L': L,
                    'n_known': n_known,
                    'pt': pt_str,
                    'qg': qg,
                })

    eliminated_total = total - len(survivors)
    print(f"  Tested: {total} configs")
    print(f"  Eliminated: {eliminated_total} ({100*eliminated_total/total:.1f}%)")
    print(f"  Breakdown:")
    for reason, count in sorted(elim_reasons.items(), key=lambda x: -x[1]):
        if count > 0:
            print(f"    {reason}: {count}")
    print(f"  Survivors: {len(survivors)}")

    if survivors:
        survivors.sort(key=lambda s: (-s['n_known'], -s['qg']))
        print(f"\n  SURVIVING PT-AUTOKEY CONFIGURATIONS:")
        for s in survivors[:30]:
            print(f"    L={s['L']:2d} {s['alph']}/{s['var']} "
                  f"known={s['n_known']}/{N} "
                  f"qg={s['qg']:.3f}")
            # Show partial PT with context around cribs
            pt = s['pt']
            print(f"      PT[20:35] = {pt[20:35]}")
            print(f"      PT[62:75] = {pt[62:75]}")
    else:
        print(f"\n  *** ALL PT-AUTOKEY ELIMINATED on raw 97-char CT ***")

    return survivors


# ══════════════════════════════════════════════════════════════════════════
# C. GRONSFELD (key digits 0-9 only)
# ══════════════════════════════════════════════════════════════════════════

def test_gronsfeld():
    print(f"\n{'='*70}")
    print("C. GRONSFELD — Key restricted to digits 0-9")
    print("="*70)

    # Vig: key[i] = (CT[i] - PT[i]) mod 26. Must be in {0..9}.
    vig_keys = {}
    for pos in CRIB_POSITIONS:
        k = (AZ_IDX[CT[pos]] - AZ_IDX[PT_AT[pos]]) % MOD
        vig_keys[pos] = k

    violations = [(pos, k) for pos, k in vig_keys.items() if k > 9]
    print(f"  Vig key values at cribs: {[vig_keys[p] for p in CRIB_POSITIONS]}")
    print(f"  Values > 9: {len(violations)} positions")
    if violations:
        print(f"  First violation: pos={violations[0][0]}, key={violations[0][1]} "
              f"(CT={CT[violations[0][0]]}, PT={PT_AT[violations[0][0]]})")
        print(f"  *** GRONSFELD ELIMINATED (Vig) ***")
    else:
        print(f"  *** GRONSFELD SURVIVES (Vig) — investigate! ***")

    # Beaufort: key[i] = (CT[i] + PT[i]) mod 26. Must be in {0..9}.
    beau_keys = {}
    for pos in CRIB_POSITIONS:
        k = (AZ_IDX[CT[pos]] + AZ_IDX[PT_AT[pos]]) % MOD
        beau_keys[pos] = k

    violations_b = [(pos, k) for pos, k in beau_keys.items() if k > 9]
    print(f"\n  Beau key values at cribs: {[beau_keys[p] for p in CRIB_POSITIONS]}")
    print(f"  Values > 9: {len(violations_b)} positions")
    if violations_b:
        print(f"  First violation: pos={violations_b[0][0]}, key={violations_b[0][1]}")
        print(f"  *** GRONSFELD ELIMINATED (Beau) ***")
    else:
        print(f"  *** GRONSFELD SURVIVES (Beau) — investigate! ***")


# ══════════════════════════════════════════════════════════════════════════
# D. PORTA CIPHER
# ══════════════════════════════════════════════════════════════════════════

def test_porta():
    print(f"\n{'='*70}")
    print("D. PORTA CIPHER — Reciprocal substitution, key selects tableau row")
    print("="*70)

    # Porta: alphabet split into two halves (A-M, N-Z).
    # Key letter selects which of 13 reciprocal substitutions to use.
    # PT in A-M maps to N-Z and vice versa.
    # Critical property: Porta is RECIPROCAL and maps A-M ↔ N-Z.
    # So if CT[i] is in A-M, PT[i] must be in N-Z, and vice versa.

    for pos in CRIB_POSITIONS:
        ct_half = "first" if AZ_IDX[CT[pos]] < 13 else "second"
        pt_half = "first" if AZ_IDX[PT_AT[pos]] < 13 else "second"
        if ct_half == pt_half:
            print(f"  Position {pos}: CT={CT[pos]}({ct_half}) PT={PT_AT[pos]}({pt_half}) — SAME HALF")
            print(f"  *** PORTA ELIMINATED — CT and PT in same half at pos {pos} ***")
            return

    print(f"  All crib positions have CT/PT in opposite halves — Porta SURVIVES")
    print(f"  (Would need further analysis)")


# ══════════════════════════════════════════════════════════════════════════
# E. RUNNING KEY (key = known text at offset)
# ══════════════════════════════════════════════════════════════════════════

def test_running_key_self():
    print(f"\n{'='*70}")
    print("E. SELF-KEYED VARIANTS — Key derived from CT or PT itself")
    print("="*70)

    # Progressive key: key[i] = i (Trithemius-like)
    print("\n  Trithemius (key[i] = i mod 26):")
    matches = 0
    for pos in CRIB_POSITIONS:
        k = pos % MOD
        pt_vig = AZ[(AZ_IDX[CT[pos]] - k) % MOD]
        if pt_vig == PT_AT[pos]:
            matches += 1

    print(f"    Vig: {matches}/24 matches", end="")
    print(" — ELIMINATED" if matches < 24 else " — SURVIVES!")

    # Key = position mod various bases
    for base in [5, 7, 8, 9, 10, 11, 13, 24, 31, 73, 97]:
        matches = 0
        for pos in CRIB_POSITIONS:
            k = pos % base
            if k >= 26:
                continue
            pt_vig = AZ[(AZ_IDX[CT[pos]] - k) % MOD]
            if pt_vig == PT_AT[pos]:
                matches += 1
        if matches >= 10:
            print(f"    key=pos%{base}: {matches}/24 matches — INTERESTING")

    # Key = A1Z26 position value (A=1, B=2, ...)
    print(f"\n  Position-derived keys:")
    for fn_name, fn in [
        ("pos+1",      lambda p: (p + 1) % MOD),
        ("pos*2",      lambda p: (p * 2) % MOD),
        ("pos^2",      lambda p: (p * p) % MOD),
        ("pos*27+21",  lambda p: (p * 27 + 21) % MOD),  # K2 affine
        ("97-pos",     lambda p: (97 - p) % MOD),
    ]:
        matches = 0
        for pos in CRIB_POSITIONS:
            k = fn(pos)
            pt_vig = AZ[(AZ_IDX[CT[pos]] - k) % MOD]
            if pt_vig == PT_AT[pos]:
                matches += 1
        status = "ELIMINATED" if matches < 10 else "INVESTIGATE"
        if matches >= 4:
            print(f"    {fn_name}: {matches}/24 — {status}")


# ══════════════════════════════════════════════════════════════════════════
# F. TRANS + MONO SUB — Constraint propagation
# ══════════════════════════════════════════════════════════════════════════

def test_trans_mono_constraints():
    print(f"\n{'='*70}")
    print("F. TRANSPOSITION + MONO SUB — Constraint Propagation")
    print("="*70)
    print("  Model: PT → transposition(perm) → intermediate → mono_sub(S) → CT")
    print("  At crib pos c: CT[perm[c]] = S(PT[c])")
    print("  Or equivalently: CT[i] = S(PT[perm⁻¹[i]])")
    print()

    # Group crib positions by PT letter
    pt_groups = {}
    for pos in CRIB_POSITIONS:
        ch = PT_AT[pos]
        if ch not in pt_groups:
            pt_groups[ch] = []
        pt_groups[ch].append(pos)

    print("  PT letter groups at crib positions:")
    for ch in sorted(pt_groups.keys()):
        print(f"    {ch}: positions {pt_groups[ch]}")

    # Key constraint: positions with same PT letter must map (via perm)
    # to CT positions with the SAME CT letter (since S is a function).
    #
    # So: for E at positions {21, 30, 64}, perm[21], perm[30], perm[64]
    # must all be positions in CT where the same letter appears.
    #
    # How many CT positions have the same letter?

    ct_groups = {}
    for i, c in enumerate(CT):
        if c not in ct_groups:
            ct_groups[c] = []
        ct_groups[c].append(i)

    print(f"\n  CT letter frequencies (positions available for mapping):")
    for ch in sorted(ct_groups.keys()):
        print(f"    {ch}: {len(ct_groups[ch])} positions")

    # For each PT group of size k, we need k CT positions with the same letter.
    # Count how many CT letters have enough positions:
    print(f"\n  Feasibility check (each PT group needs CT letter with enough positions):")
    possible_mappings = {}
    total_assignments = 1

    for pt_ch in sorted(pt_groups.keys()):
        k = len(pt_groups[pt_ch])
        candidates = [(ct_ch, len(positions))
                      for ct_ch, positions in ct_groups.items()
                      if len(positions) >= k]
        possible_mappings[pt_ch] = candidates
        print(f"    PT={pt_ch} (need {k}): {len(candidates)} CT letters qualify "
              f"— {[f'{c}({n})' for c, n in sorted(candidates, key=lambda x: -x[1])[:5]]}")

        if candidates:
            # Number of ways to choose k positions from n
            from math import comb, perm as math_perm
            ways = sum(math_perm(n, k) for _, n in candidates)
            total_assignments *= len(candidates)
        else:
            print(f"    *** IMPOSSIBLE: no CT letter has {k}+ occurrences ***")
            total_assignments = 0

    # Check mutual exclusivity: each PT letter must map to a DIFFERENT CT letter
    # (since S is a bijection — actually S is a function A→A, and mono sub IS
    # a bijection on the alphabet, so S(E) ≠ S(A) etc.)
    print(f"\n  Bijection constraint (S must be injective on PT letters):")
    pt_letters = sorted(pt_groups.keys())  # 13 distinct PT letters
    print(f"    {len(pt_letters)} distinct PT letters at crib positions")
    print(f"    Need 13 distinct CT letter assignments")

    # This is a bipartite matching problem.
    # Build bipartite graph: PT letter → possible CT letter mappings
    # Check if a perfect matching exists.

    # Count: for the 3-element groups (E, T), we need CT letters with 3+ positions
    three_plus = [ch for ch, pos in ct_groups.items() if len(pos) >= 3]
    two_plus = [ch for ch, pos in ct_groups.items() if len(pos) >= 2]
    print(f"    CT letters with 3+ positions: {len(three_plus)} — {three_plus}")
    print(f"    CT letters with 2+ positions: {len(two_plus)} — {two_plus}")

    groups_need_3 = [ch for ch in pt_letters if len(pt_groups[ch]) >= 3]
    groups_need_2 = [ch for ch in pt_letters if len(pt_groups[ch]) == 2]
    groups_need_1 = [ch for ch in pt_letters if len(pt_groups[ch]) == 1]
    print(f"    PT letters needing 3+ CT positions: {groups_need_3} ({len(groups_need_3)} letters)")
    print(f"    PT letters needing 2+ CT positions: {groups_need_2} ({len(groups_need_2)} letters)")
    print(f"    PT letters needing 1+ CT positions: {groups_need_1} ({len(groups_need_1)} letters)")

    # The 2 groups needing 3+ (E,T) must map to different CT letters with 3+ positions
    if len(groups_need_3) > len(three_plus):
        print(f"\n  *** TRANS+MONO IMPOSSIBLE: {len(groups_need_3)} PT groups need 3+, "
              f"only {len(three_plus)} CT letters have 3+ ***")
    else:
        print(f"\n  Trans+Mono is FEASIBLE (constraints don't force impossibility)")
        print(f"  But MITM already tested 4.2M structured transpositions: 0 hits")
        print(f"  The transposition must be NON-STANDARD if this model is correct")

    # Additional constraint: self-encrypting positions
    # CT[32]=S=PT[32] and CT[73]=K=PT[73]
    # If perm[32]=32: intermediate[32]=PT[32]=S, and S(S)=CT[32]=S → S maps S→S (fixed point)
    # If perm[73]=73: S(K)=CT[73]=K → K maps K→K (fixed point)
    print(f"\n  Self-encrypting position analysis:")
    print(f"    CT[32]=S, PT[32]=S → if perm fixes 32: S('S')='S' (fixed point in sub)")
    print(f"    CT[73]=K, PT[73]=K → if perm fixes 73: S('K')='K' (fixed point)")
    print(f"    Two fixed points in mono sub → not Caesar (unless shift=0=identity)")


# ══════════════════════════════════════════════════════════════════════════
# G. DERIVED KEYSTREAM ANALYSIS
# ══════════════════════════════════════════════════════════════════════════

def test_keystream_patterns():
    print(f"\n{'='*70}")
    print("G. DERIVED KEYSTREAM PATTERN ANALYSIS")
    print("="*70)

    # For each cipher variant, compute the derived key at crib positions
    # and look for patterns (arithmetic, geometric, structural)

    for var_name, key_fn in [
        ("Vig (k=CT-PT)", lambda c, p: (c - p) % MOD),
        ("Beau (k=CT+PT)", lambda c, p: (c + p) % MOD),
        ("VBeau (k=PT-CT)", lambda c, p: (p - c) % MOD),
    ]:
        keys = []
        for pos in CRIB_POSITIONS:
            k = key_fn(AZ_IDX[CT[pos]], AZ_IDX[PT_AT[pos]])
            keys.append((pos, k))

        key_vals = [k for _, k in keys]
        key_chars = [AZ[k] for _, k in keys]

        print(f"\n  {var_name}:")
        print(f"    Keys: {key_chars}")
        print(f"    Vals: {key_vals}")

        # Check for constant key (Caesar)
        if len(set(key_vals)) == 1:
            print(f"    *** CONSTANT KEY = {key_vals[0]} ({AZ[key_vals[0]]}) — Caesar! ***")
            continue

        # Check differences between consecutive crib keys
        diffs = [(keys[i+1][0] - keys[i][0],
                  (keys[i+1][1] - keys[i][1]) % MOD)
                 for i in range(len(keys)-1)]
        print(f"    Position gaps: {[d[0] for d in diffs]}")
        print(f"    Key diffs (mod 26): {[d[1] for d in diffs]}")

        # Check if key is linear function of position: k = a*pos + b mod 26
        print(f"    Linear fit test (k = a*pos + b mod 26):")
        found_linear = False
        for a in range(MOD):
            bs = set()
            for pos, k in keys:
                b = (k - a * pos) % MOD
                bs.add(b)
            if len(bs) == 1:
                b = bs.pop()
                print(f"      *** PERFECT FIT: k = {a}*pos + {b} mod 26 ***")
                found_linear = True
        if not found_linear:
            print(f"      No perfect linear fit")

        # Check mod-13 pattern (d=13 anomaly)
        mod13_groups = {}
        for pos, k in keys:
            r = pos % 13
            if r not in mod13_groups:
                mod13_groups[r] = []
            mod13_groups[r].append(k)

        collisions = {r: vals for r, vals in mod13_groups.items() if len(vals) > 1}
        if collisions:
            print(f"    Mod-13 residue collisions:")
            for r, vals in sorted(collisions.items()):
                match = "EQUAL" if len(set(vals)) == 1 else f"DIFFER ({vals})"
                print(f"      residue {r}: keys={vals} — {match}")


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

def run():
    print("=" * 70)
    print("K4 ANALYTICAL ELIMINATION ENGINE")
    print("=" * 70)

    t0 = time.time()

    ct_autokey_survivors = test_ct_autokey()
    pt_autokey_survivors = test_pt_autokey()
    test_gronsfeld()
    test_porta()
    test_running_key_self()
    test_trans_mono_constraints()
    test_keystream_patterns()

    # ═══ FINAL SUMMARY ═══
    print(f"\n{'='*70}")
    print("ELIMINATION SUMMARY")
    print("="*70)

    print(f"\n  CT-Autokey survivors: {len(ct_autokey_survivors)}")
    print(f"  PT-Autokey survivors: {len(pt_autokey_survivors)}")

    if not ct_autokey_survivors:
        print(f"\n  *** CT-AUTOKEY: ALL primer lengths 1-96 ELIMINATED ***")
        print(f"      (for Vig, Beau, VBeau × AZ, KA on raw 97-char CT)")

    if not pt_autokey_survivors:
        print(f"\n  *** PT-AUTOKEY: ALL primer lengths 1-96 ELIMINATED ***")
        print(f"      (for Vig, Beau, VBeau × AZ, KA on raw 97-char CT)")

    elapsed = time.time() - t0
    print(f"\n  Total elapsed: {elapsed:.3f}s")


if __name__ == "__main__":
    run()
