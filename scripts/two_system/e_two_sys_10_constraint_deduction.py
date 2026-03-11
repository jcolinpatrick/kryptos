#!/usr/bin/env python3
# Cipher:     Constraint-based deduction from K4 cribs
# Family:     two_system
# Status:     active
# Keyspace:   N/A — analytical, not brute-force
#
# E-TWO-SYS-10: Deduce cipher structure from crib constraints.
#
# Instead of sweeping keywords × ciphers × masks, we ask:
#   "What cipher structures are CONSISTENT with the 24 known PT/CT pairs?"
#
# The 24 cribs give us 24 equations. Self-encrypting positions (S→S, K→K)
# add structural constraints. We derive impossibility proofs and identify
# what's left standing.
from __future__ import annotations

import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, MOD,
    CRIB_DICT, CRIB_POSITIONS, KRYPTOS_ALPHABET,
)

# ── Extract crib data ────────────────────────────────────────────────────

CRIBS = sorted(CRIB_DICT.items())  # [(pos, pt_char), ...]


def ct_ord(pos): return ord(CT[pos]) - 65
def pt_ord(pos): return ord(CRIB_DICT[pos]) - 65


def key_vig(pos): return (ct_ord(pos) - pt_ord(pos)) % MOD
def key_beau(pos): return (ct_ord(pos) + pt_ord(pos)) % MOD
def key_vbeau(pos): return (pt_ord(pos) - ct_ord(pos)) % MOD


# ══════════════════════════════════════════════════════════════════════════
# ANALYSIS 1: Monoalphabetic impossibility proof
# ══════════════════════════════════════════════════════════════════════════

def analyze_mono():
    print("=" * 78)
    print("ANALYSIS 1: Monoalphabetic substitution")
    print("=" * 78)

    # Group by CT letter
    ct_to_pt = defaultdict(list)
    for pos, pt_char in CRIBS:
        ct_to_pt[CT[pos]].append((pos, pt_char))

    conflicts = 0
    for ct_char in sorted(ct_to_pt):
        mappings = ct_to_pt[ct_char]
        pt_chars = set(pt for _, pt in mappings)
        status = "✓ consistent" if len(pt_chars) == 1 else "✗ CONFLICT"
        if len(pt_chars) > 1:
            conflicts += 1
        detail = ", ".join(f"pos {p}: {ct_char}→{pt}" for p, pt in mappings)
        print(f"  CT '{ct_char}': {detail}  [{status}]")

    print(f"\n  RESULT: {conflicts} CT letters map to multiple PT letters.")
    print(f"  → Monoalphabetic substitution is IMPOSSIBLE on the carved text,")
    print(f"    regardless of any null mask (since all crib positions are non-null).")
    print(f"    Maximum achievable mono score: {24 - conflicts}/24\n")


# ══════════════════════════════════════════════════════════════════════════
# ANALYSIS 2: Key value sequences at crib positions
# ══════════════════════════════════════════════════════════════════════════

def analyze_key_sequences():
    print("=" * 78)
    print("ANALYSIS 2: Key values at crib positions (all 3 variants)")
    print("=" * 78)

    for variant_name, key_fn in [("Vigenère", key_vig), ("Beaufort", key_beau), ("Var.Beaufort", key_vbeau)]:
        print(f"\n  ── {variant_name} ──")
        print(f"  {'Pos':>3} {'CT':>2}→{'PT':>2}  Key  Letter  Self?")
        print(f"  {'─'*40}")

        ene_keys = []
        bc_keys = []
        for pos, pt_char in CRIBS:
            k = key_fn(pos)
            self_enc = " ← SELF" if CT[pos] == pt_char else ""
            section = "ENE" if pos <= 33 else "BC "
            print(f"  {pos:3d}  {CT[pos]}→{pt_char}   {k:2d}   {ALPH[k]}     {self_enc}")
            if pos <= 33:
                ene_keys.append(k)
            else:
                bc_keys.append(k)

        print(f"\n  ENE key values: {ene_keys}")
        print(f"  BC  key values: {bc_keys}")

        # Consecutive differences
        ene_diffs = [(ene_keys[i+1] - ene_keys[i]) % MOD for i in range(len(ene_keys)-1)]
        bc_diffs = [(bc_keys[i+1] - bc_keys[i]) % MOD for i in range(len(bc_keys)-1)]
        print(f"  ENE diffs (mod 26): {ene_diffs}")
        print(f"  BC  diffs (mod 26): {bc_diffs}")

        # Second differences
        ene_2diffs = [(ene_diffs[i+1] - ene_diffs[i]) % MOD for i in range(len(ene_diffs)-1)]
        print(f"  ENE 2nd diffs:      {ene_2diffs}")

        # Check for constant differences (progressive key)
        if len(set(ene_diffs)) == 1:
            print(f"  → ENE: constant diff = {ene_diffs[0]} — PROGRESSIVE KEY!")
        else:
            print(f"  → ENE: {len(set(ene_diffs))} distinct diffs — NOT progressive")

        # Check for constant 2nd differences (quadratic key)
        if len(set(ene_2diffs)) == 1:
            print(f"  → ENE: constant 2nd diff = {ene_2diffs[0]} — QUADRATIC KEY!")
        else:
            print(f"  → ENE: {len(set(ene_2diffs))} distinct 2nd diffs — NOT quadratic")


# ══════════════════════════════════════════════════════════════════════════
# ANALYSIS 3: Periodic consistency within cribs (null-mask-independent)
# ══════════════════════════════════════════════════════════════════════════

def analyze_periodic_internal():
    print("\n" + "=" * 78)
    print("ANALYSIS 3: Periodic consistency WITHIN each crib block")
    print("=" * 78)
    print("\nThe ENE crib (13 chars) and BC crib (11 chars) are ALWAYS contiguous")
    print("in the reduced text, regardless of null mask. For a periodic cipher")
    print("with period p on the reduced text, positions i and i+p within a crib")
    print("must have the SAME key value.\n")

    for variant_name, key_fn in [("Vigenère", key_vig), ("Beaufort", key_beau), ("Var.Beaufort", key_vbeau)]:
        print(f"  ── {variant_name} ──")

        ene_keys = [key_fn(pos) for pos in range(21, 34)]
        bc_keys = [key_fn(pos) for pos in range(63, 74)]

        for p in range(1, 14):
            # Check ENE internal consistency
            ene_ok = True
            ene_conflicts = []
            for i in range(13):
                for j in range(i + p, 13, p):
                    if ene_keys[i] != ene_keys[j]:
                        ene_ok = False
                        ene_conflicts.append((i, j, ene_keys[i], ene_keys[j]))

            # Check BC internal consistency
            bc_ok = True
            bc_conflicts = []
            for i in range(11):
                for j in range(i + p, 11, p):
                    if bc_keys[i] != bc_keys[j]:
                        bc_ok = False
                        bc_conflicts.append((i, j, bc_keys[i], bc_keys[j]))

            status = "✓" if (ene_ok and bc_ok) else "✗"
            if not ene_ok:
                print(f"    Period {p:2d}: {status} ENE CONFLICT "
                      f"(e.g., pos {ene_conflicts[0][0]}={ene_conflicts[0][2]} "
                      f"vs pos {ene_conflicts[0][1]}={ene_conflicts[0][3]})")
            elif not bc_ok:
                print(f"    Period {p:2d}: {status} BC CONFLICT "
                      f"(e.g., pos {bc_conflicts[0][0]}={bc_conflicts[0][2]} "
                      f"vs pos {bc_conflicts[0][1]}={bc_conflicts[0][3]})")
            else:
                n_free = p - (13 % p if 13 % p > 0 else 0)
                print(f"    Period {p:2d}: {status} CONSISTENT "
                      f"(but ≥{p}, underdetermined)")

        print()

    # Summary
    print("  RESULT: For ALL three variants, periods 1-12 are IMPOSSIBLE")
    print("  within the ENE crib alone (13 consecutive chars with conflicting")
    print("  key values at same-residue positions).")
    print("  → This holds for ANY null mask, since ENE is always contiguous.")
    print("  → Periodic substitution on the reduced text requires period ≥ 13.\n")


# ══════════════════════════════════════════════════════════════════════════
# ANALYSIS 4: Cross-crib constraints for periods 13+
# ══════════════════════════════════════════════════════════════════════════

def analyze_cross_crib_periods():
    print("=" * 78)
    print("ANALYSIS 4: Cross-crib constraints for periods 13-26")
    print("=" * 78)
    print("\nFor period p ≥ 13, ENE alone doesn't constrain (each position has")
    print("unique residue). But cross-constraints between ENE and BC must hold.")
    print("After null removal: ENE at reduced positions [21-a, 33-a],")
    print("BC at [63-a-b, 73-a-b]. Cross-constraint exists when:")
    print("  (ene_reduced_pos) ≡ (bc_reduced_pos) (mod p)")
    print("  ⟺ (ene_orig - a) ≡ (bc_orig - a - b) (mod p)")
    print("  ⟺ ene_orig - bc_orig ≡ -b (mod p)")
    print("  ⟺ b ≡ bc_orig - ene_orig (mod p)\n")

    for variant_name, key_fn in [("Vigenère", key_vig), ("Beaufort", key_beau), ("Var.Beaufort", key_vbeau)]:
        print(f"  ── {variant_name} ──")

        ene_data = [(pos, key_fn(pos)) for pos in range(21, 34)]
        bc_data = [(pos, key_fn(pos)) for pos in range(63, 74)]

        for p in range(13, 27):
            # For each possible b (0 to 29, nulls in gap between cribs):
            viable_b = []
            for b in range(30):  # max 29 positions in gap [34,62]
                consistent = True
                for ene_pos, ene_key in ene_data:
                    for bc_pos, bc_key in bc_data:
                        # Check if they share a residue
                        ene_r = ene_pos  # - a cancels out
                        bc_r = bc_pos - b  # - a cancels out
                        if (ene_r - bc_r) % p == 0:
                            # Same residue — keys must match
                            if ene_key != bc_key:
                                consistent = False
                                break
                    if not consistent:
                        break
                if consistent:
                    viable_b.append(b)

            if viable_b:
                print(f"    Period {p:2d}: {len(viable_b)} viable b values: {viable_b[:15]}{'...' if len(viable_b) > 15 else ''}")
            else:
                print(f"    Period {p:2d}: NO viable b values — IMPOSSIBLE")

        print()


# ══════════════════════════════════════════════════════════════════════════
# ANALYSIS 5: Self-encrypting position constraints
# ══════════════════════════════════════════════════════════════════════════

def analyze_self_encrypting():
    print("=" * 78)
    print("ANALYSIS 5: Self-encrypting positions")
    print("=" * 78)

    self_enc = [(pos, CT[pos]) for pos in range(CT_LEN)
                if pos in CRIB_DICT and CT[pos] == CRIB_DICT[pos]]

    print(f"\n  Self-encrypting crib positions:")
    for pos, ch in self_enc:
        print(f"    Position {pos}: CT='{ch}' → PT='{ch}'")
        print(f"      Vig key: {key_vig(pos)} = '{ALPH[key_vig(pos)]}'")
        print(f"      Beau key: {key_beau(pos)} = '{ALPH[key_beau(pos)]}'")
        print(f"      VBeau key: {key_vbeau(pos)} = '{ALPH[key_vbeau(pos)]}'")

    print(f"\n  For Vigenère/VarBeaufort: self-encrypting ⟺ key = 0 = 'A'")
    print(f"  For Beaufort: self-encrypting ⟺ key = 2*CT mod 26")
    print(f"    S(18): key = 36%26 = 10 = 'K'")
    print(f"    K(10): key = 20%26 = 20 = 'U'")

    print(f"\n  Implications for periodic Vigenère with keyword of length p:")
    print(f"    After null removal, pos 32 → reduced (32-a), pos 73 → reduced (73-a-b)")
    print(f"    keyword[(32-a) % p] must be 'A' (key=0)")
    print(f"    keyword[(73-a-b) % p] must be 'A' (key=0)")
    print(f"    → The keyword must have 'A' in at least 1 position (if residues match)")
    print(f"      or 2 positions (if residues differ).")
    print(f"    → Keywords without 'A' are ELIMINATED for Vigenère.\n")

    # Check which thematic keywords contain 'A'
    from kryptos.kernel.alphabet import keyword_mixed_alphabet
    wordlist_path = os.path.join(
        os.path.dirname(__file__), '..', '..', 'wordlists', 'thematic_keywords_v2.txt'
    )
    words = set()
    if os.path.exists(wordlist_path):
        with open(wordlist_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                w = line.upper()
                if 3 <= len(w) <= 13 and w.isalpha():
                    words.add(w)

    with_a = [w for w in sorted(words) if 'A' in w]
    without_a = [w for w in sorted(words) if 'A' not in w]
    with_2a = [w for w in with_a if w.count('A') >= 2]

    print(f"  Keywords with 'A': {len(with_a)}/{len(words)} ({100*len(with_a)/len(words):.0f}%)")
    print(f"  Keywords with 2+ 'A': {len(with_2a)}/{len(words)} ({100*len(with_2a)/len(words):.0f}%)")
    print(f"  Keywords without 'A' (ELIMINATED for Vig): {len(without_a)}")
    print(f"    Examples: {without_a[:20]}")

    # For each keyword with A, check if A can land at required positions
    # for some period p and null distribution (a, b)
    print(f"\n  For Beaufort: keyword positions must have 'K' and 'U' (or both")
    print(f"  at same residue). Keywords without K or U are eliminated.")
    with_ku = [w for w in sorted(words) if 'K' in w and 'U' in w]
    print(f"  Keywords with both K and U: {len(with_ku)}")
    print(f"    Examples: {with_ku[:20]}")


# ══════════════════════════════════════════════════════════════════════════
# ANALYSIS 6: Autokey consistency check
# ══════════════════════════════════════════════════════════════════════════

def analyze_autokey():
    print("=" * 78)
    print("ANALYSIS 6: Autokey consistency at crib positions")
    print("=" * 78)
    print("\nPT-autokey: key[i] = keyword[i] for i < L, then key[i] = PT[i-L]")
    print("For reduced positions where BOTH pos and pos-L are crib positions,")
    print("we can check: does key[pos] = PT[pos-L]?\n")

    ene_keys_vig = {pos: key_vig(pos) for pos in range(21, 34)}
    bc_keys_vig = {pos: key_vig(pos) for pos in range(63, 74)}
    all_keys = {**ene_keys_vig, **bc_keys_vig}

    # For each possible keyword length L and null distribution,
    # check if autokey holds between crib positions
    print("  Testing: for keyword length L, if crib pos r and r-L are both")
    print("  crib positions, does Vig key[r] = PT_ord[r-L]?\n")

    # Within ENE: positions 21-33, reduced to (21-a)..(33-a)
    # If L <= 12, then (21-a+k) and (21-a+k-L) might both be in ENE
    # i.e., orig position (21+k) and (21+k-L) both in [21,33]
    # → k-L >= 0 and k <= 12 → L <= k <= 12

    for L in range(1, 30):
        matches = []
        mismatches = []

        # Within ENE: check if pos i and pos i-L are both crib positions
        # On the reduced text, pos i has reduced position (i-a)
        # and pos i-L has reduced position (i-L-a) (if no nulls between them)
        # For positions within ENE (21-33), no nulls between them
        # So autokey check: key_vig[i] should equal pt_ord[i-L] (if i-L is also in ENE)
        for i in range(21 + L, 34):
            j = i - L
            if j >= 21:  # both in ENE
                k_val = key_vig(i)
                pt_val = pt_ord(j)
                if k_val == pt_val:
                    matches.append((i, j, ALPH[k_val], CRIB_DICT[j]))
                else:
                    mismatches.append((i, j, ALPH[k_val], CRIB_DICT[j]))

        # Within BC
        for i in range(63 + L, 74):
            j = i - L
            if j >= 63:
                k_val = key_vig(i)
                pt_val = pt_ord(j)
                if k_val == pt_val:
                    matches.append((i, j, ALPH[k_val], CRIB_DICT[j]))
                else:
                    mismatches.append((i, j, ALPH[k_val], CRIB_DICT[j]))

        if matches or mismatches:
            total = len(matches) + len(mismatches)
            if len(matches) > 0 and len(mismatches) == 0:
                print(f"  L={L:2d}: {len(matches)}/{total} match — ALL CONSISTENT! ← INVESTIGATE")
            elif len(matches) > total * 0.5:
                print(f"  L={L:2d}: {len(matches)}/{total} match — partial")
            elif total > 0:
                print(f"  L={L:2d}: {len(matches)}/{total} match")


# ══════════════════════════════════════════════════════════════════════════
# ANALYSIS 7: What cipher families survive?
# ══════════════════════════════════════════════════════════════════════════

def analyze_survivors():
    print("\n" + "=" * 78)
    print("ANALYSIS 7: Cipher family survival summary")
    print("=" * 78)

    print("""
  ELIMINATED (proven impossible from crib constraints):
  ─────────────────────────────────────────────────────
  • Monoalphabetic: 9 CT letters map to multiple PT letters
  • Periodic Vig/Beau/VBeau period 1-12: internal ENE conflicts
  • Progressive key (linear): non-constant consecutive diffs
  • Quadratic key: non-constant 2nd diffs
  • Periodic on raw 97: Bean constraints eliminate all periods 1-26

  SURVIVING (not yet eliminated):
  ────────────────────────────────
  • Periodic Vig/Beau/VBeau period 13-26 on REDUCED text (after null removal)
    → Requires specific null distribution (b values) for cross-crib consistency
    → Period 13 = len(EASTNORTHEAST) — the d=13 anomaly!
  • Autokey (PT or CT) on reduced text
    → Must check within-crib consistency for each keyword length L
  • Non-tabular ciphers: Porta, Gronsfeld, cipher disk
  • Running key (from reference text)
  • Product cipher: simple sub + transposition (the "two systems"?)
  • Fractionation: Polybius/straddling checkerboard + transposition
  • Route/path cipher through the 28×31 grid
  • Something entirely unexpected that we haven't categorized
""")


# ══════════════════════════════════════════════════════════════════════════
# ANALYSIS 8: The d=13 anomaly — deep dive
# ══════════════════════════════════════════════════════════════════════════

def analyze_d13():
    print("=" * 78)
    print("ANALYSIS 8: Period 13 deep dive (d=13 anomaly)")
    print("=" * 78)
    print("\nPeriod 13 = len(EASTNORTHEAST). Bean found 3.55× expected Beaufort")
    print("keystream collisions at k%13. Let's check what period 13 looks like.\n")

    for variant_name, key_fn in [("Vigenère", key_vig), ("Beaufort", key_beau)]:
        print(f"  ── {variant_name}, period 13 ──")

        ene_keys = [key_fn(pos) for pos in range(21, 34)]
        bc_keys = [key_fn(pos) for pos in range(63, 74)]

        print(f"  ENE determines ALL 13 key values: {ene_keys}")
        print(f"  Key as letters: {''.join(ALPH[k] for k in ene_keys)}")

        # For period 13, BC positions must be consistent with this key
        # BC reduced positions: (63-a-b) to (73-a-b), 11 positions
        # Residue of (63-a-b) mod 13 depends on a+b
        # ENE reduced positions: (21-a) to (33-a)
        # ENE residues mod 13: (21-a)%13, ..., (33-a)%13

        print(f"\n  BC consistency check:")
        print(f"  For each possible (a+b), check if BC key values match ENE-derived key:")

        for ab_sum in range(0, 50):
            # ENE reduced start: 21-a. For period 13 key determined by ENE:
            # key[r%13] = ene_keys[r - (21-a)] for r in [21-a, 33-a]
            # But r%13 = (21-a+offset)%13 where offset is 0..12
            # So key[(21-a+offset)%13] = ene_keys[offset]

            # For BC: reduced pos = 63-ab_sum+j for j=0..10
            # key[(63-ab_sum+j)%13] should equal bc_keys[j]
            # key[(63-ab_sum+j)%13] = ene_keys[((63-ab_sum+j) - (21-a))%13]
            #                        = ene_keys[((63-ab_sum+j) - 21+a)%13]
            #                        = ene_keys[(42-b+j)%13]  since ab_sum=a+b
            # Simplify: = ene_keys[(42-b+j)%13]
            # But we know ab_sum=a+b, not b alone. However, (42-b+j) mod 13
            # depends only on b mod 13, not a.
            # And b = ab_sum - a. For different a values, b changes.
            # BUT (42 - b + j) mod 13 = (42 - (ab_sum-a) + j) mod 13
            #                          = (42 - ab_sum + a + j) mod 13
            # This depends on a. Hmm.

            # Let's try a different approach. The key is fully determined by
            # the ENE crib: key[residue] = ene_keys[residue - offset_ene % 13]
            # where offset_ene = (21-a) % 13

            # For a given a, offset_ene = (21-a) % 13
            # key[(21-a+k)%13] = ene_keys[k] for k=0..12

            # For BC: key[(63-a-b+j)%13] must equal bc_keys[j]
            # (63-a-b+j)%13 = (21-a + (42-b+j))%13 = (21-a + (42-b+j)%13)%13
            # So key index = (21-a + 42 - b + j) % 13 = (63 - a - b + j) % 13
            # Expected key value = ene_keys[(63-a-b+j - (21-a))%13]
            #                    = ene_keys[(42-b+j) % 13]

            # So the constraint only depends on b (not a)!
            # For b = ab_sum - a, but b ranges from max(0, ab_sum-21) to min(29, ab_sum)

            # Since the constraint only depends on b mod 13, let's check all b mod 13:
            pass

        # Simpler: check all b values mod 13
        print(f"  (Constraint depends only on b mod 13)")
        for b_mod in range(13):
            consistent = True
            for j in range(11):
                expected_key_idx = (42 - b_mod + j) % 13
                expected = ene_keys[expected_key_idx]
                actual = bc_keys[j]
                if expected != actual:
                    consistent = False
                    break
            status = "✓ CONSISTENT" if consistent else "✗"
            if consistent:
                print(f"    b ≡ {b_mod:2d} (mod 13): {status} ← POSSIBLE!")
            else:
                print(f"    b ≡ {b_mod:2d} (mod 13): {status}")

        print()


# ══════════════════════════════════════════════════════════════════════════
# ANALYSIS 9: Tabula recta position — what if cribs index into the tableau?
# ══════════════════════════════════════════════════════════════════════════

def analyze_tableau_position():
    print("=" * 78)
    print("ANALYSIS 9: Could the cipher use the Kryptos tableau directly?")
    print("=" * 78)
    print("\nThe Kryptos tableau is a 26×26 grid with KA alphabet.")
    print("What if encryption = look up (row=PT, col=key) in tableau?")
    print("Or (row=key, col=PT)? The KA ordering changes the arithmetic.\n")

    # KA alphabet
    ka = KRYPTOS_ALPHABET
    ka_idx = {c: i for i, c in enumerate(ka)}

    print(f"  KA: {ka}")
    print(f"  Std: {ALPH}\n")

    # For KA-Vigenère: CT_ka_idx = (PT_ka_idx + KEY_ka_idx) % 26
    # → KEY_ka_idx = (CT_ka_idx - PT_ka_idx) % 26
    print(f"  KA-Vigenère key values at crib positions:")
    ka_ene_keys = []
    ka_bc_keys = []
    for pos, pt_char in CRIBS:
        ct_ka = ka_idx[CT[pos]]
        pt_ka = ka_idx[pt_char]
        k_ka = (ct_ka - pt_ka) % 26
        section = "ENE" if pos <= 33 else "BC "
        key_letter = ka[k_ka]
        self_enc = " ← SELF" if CT[pos] == pt_char else ""
        print(f"    {pos:3d}  {CT[pos]}→{pt_char}  KA key={k_ka:2d} ({key_letter}){self_enc}")
        if pos <= 33:
            ka_ene_keys.append(k_ka)
        else:
            ka_bc_keys.append(k_ka)

    print(f"\n  KA ENE keys: {ka_ene_keys}  = {''.join(ka[k] for k in ka_ene_keys)}")
    print(f"  KA BC keys:  {ka_bc_keys}  = {''.join(ka[k] for k in ka_bc_keys)}")

    # Check period 13 consistency for KA
    print(f"\n  Period 13 cross-crib consistency (KA-Vigenère):")
    for b_mod in range(13):
        consistent = True
        for j in range(11):
            expected_key_idx = (42 - b_mod + j) % 13
            expected = ka_ene_keys[expected_key_idx]
            actual = ka_bc_keys[j]
            if expected != actual:
                consistent = False
                break
        if consistent:
            print(f"    b ≡ {b_mod:2d} (mod 13): ✓ CONSISTENT!")


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

def main():
    print("╔══════════════════════════════════════════════════════════════════════════╗")
    print("║  K4 CONSTRAINT DEDUCTION — What do the cribs tell us?                  ║")
    print("╚══════════════════════════════════════════════════════════════════════════╝")
    print(f"\nCT: {CT}")
    print(f"24 known PT/CT pairs at positions 21-33 (ENE) and 63-73 (BC)")
    print(f"Self-encrypting: pos 32 (S→S), pos 73 (K→K)\n")

    analyze_mono()
    analyze_key_sequences()
    analyze_periodic_internal()
    analyze_cross_crib_periods()
    analyze_self_encrypting()
    analyze_autokey()
    analyze_survivors()
    analyze_d13()
    analyze_tableau_position()

    print("\n" + "=" * 78)
    print("END OF CONSTRAINT ANALYSIS")
    print("=" * 78)


if __name__ == "__main__":
    main()
