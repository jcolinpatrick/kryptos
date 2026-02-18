#!/usr/bin/env python3
"""E-05: 'LAYER TWO' compound cipher tests for K4.

K2 ends with 'LAYER TWO' — an operational instruction meaning K4 uses
compound encipherment. The extra 'L' on the tableau spells 'HILL' (§B1),
suggesting a Hill cipher component.

Tested compound structures:
1. Hill(2×2) + Vigenère: algebraic approach using cribs
2. Vigenère + Hill(2×2): intermediate from Vig, then Hill
3. Keyed substitution + columnar transposition (ADFGVX-like)
4. Double columnar transposition
5. Bifid cipher (Polybius fractionation)
6. Hill(2×2) only with all block offsets and partial blocks

KEY INSIGHT: For a compound cipher CT = f(g(PT)), the cribs constrain
the composition. We can use the 24 known positions to set up systems
of equations that overconstrain the compound parameters.
"""

import sys
import os
import math
from itertools import permutations, product
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH_IDX, MOD, CRIB_DICT, N_CRIBS,
    BEAN_EQ, BEAN_INEQ, KRYPTOS_ALPHABET,
)

CT_NUM = [ALPH_IDX[c] for c in CT]


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


def mod_inverse(a, m=26):
    if a == 0:
        return None
    g, x, _ = _egcd(a % m, m)
    return x % m if g == 1 else None


def _egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = _egcd(b % a, a)
    return g, y - (b // a) * x, x


def mat2_det(m):
    return (m[0] * m[3] - m[1] * m[2]) % MOD


def mat2_inv(m):
    """Inverse of 2×2 matrix [a,b,c,d] stored flat."""
    det = mat2_det(m)
    di = mod_inverse(det)
    if di is None:
        return None
    return [(di * m[3]) % MOD, (di * (-m[1])) % MOD,
            (di * (-m[2])) % MOD, (di * m[0]) % MOD]


def mat2_mul_vec(m, v0, v1):
    return (m[0] * v0 + m[1] * v1) % MOD, (m[2] * v0 + m[3] * v1) % MOD


def hill2_decrypt_offset(ct_nums, inv_m, offset):
    """Decrypt with 2×2 Hill, blocks starting at `offset`."""
    pt = list(ct_nums)  # copy; non-block positions unchanged
    for i in range(offset, len(ct_nums) - 1, 2):
        pt[i], pt[i + 1] = mat2_mul_vec(inv_m, ct_nums[i], ct_nums[i + 1])
    return pt


# ── Precompute coprime set ───────────────────────────────────────────────────
COPRIME = frozenset(d for d in range(26) if math.gcd(d, 26) == 1)


def main():
    print("=" * 80)
    print("E-05: LAYER TWO Compound Cipher Tests")
    print("=" * 80)
    sys.stdout.flush()

    results = []

    # ═══════════════════════════════════════════════════════════════════════════
    # TEST 1: Exhaustive Hill(2×2) — optimized with early pruning
    # ═══════════════════════════════════════════════════════════════════════════

    print("\n── Test 1: Exhaustive Hill(2×2) with aggressive pruning ──")
    sys.stdout.flush()

    # We check crib positions 21,22 and 63,64 first (4 positions).
    # For a correct Hill matrix, ALL 4 must match — that's a 1/(26^4) chance
    # per matrix, so we expect ~0 false positives out of ~160K invertible matrices.

    crib_check_positions = [
        (21, 22, ALPH_IDX['E'], ALPH_IDX['A']),  # EASTNORTHEAST starts E,A
        (63, 64, ALPH_IDX['B'], ALPH_IDX['E']),  # BERLINCLOCK starts B,E
    ]

    count = 0
    hill_hits = []

    for a in range(26):
        for b in range(26):
            ab_contrib = a * b  # precompute partial
            for c in range(26):
                for d in range(26):
                    det = (a * d - b * c) % 26
                    if det not in COPRIME:
                        continue
                    count += 1

                    inv = mat2_inv([a, b, c, d])
                    if inv is None:
                        continue

                    # Quick prune: check 2 pairs at both offsets
                    for offset in range(2):
                        ok = True
                        for pos1, pos2, pt1, pt2 in crib_check_positions:
                            if (pos1 - offset) % 2 != 0:
                                # This pair doesn't align with this offset
                                ok = False
                                break
                            d1, d2 = mat2_mul_vec(inv, CT_NUM[pos1], CT_NUM[pos1 + 1])
                            if d1 != pt1 or d2 != pt2:
                                ok = False
                                break

                        if not ok:
                            continue

                        # Full decrypt
                        pt = hill2_decrypt_offset(CT_NUM, inv, offset)
                        score = score_cribs(pt)
                        if score >= 8:
                            bean = check_bean(pt)
                            pt_text = ''.join(num_to_char(n) for n in pt)
                            tag = f"Hill2 [{a},{b},{c},{d}] off={offset}"
                            hill_hits.append((score, tag, [a, b, c, d], bean, pt_text))
                            print(f"  ** {tag}: score={score}/{N_CRIBS} "
                                  f"{'BEAN✓' if bean else 'bean✗'}")
                            if score >= 12:
                                print(f"     PT: {pt_text}")
                            sys.stdout.flush()

    print(f"  Tested {count:,} invertible matrices. Hits ≥8: {len(hill_hits)}")
    for score, tag, m, bean, pt_text in sorted(hill_hits, reverse=True)[:5]:
        results.append((score, tag, m, bean))
        print(f"    {score}/{N_CRIBS} {'BEAN✓' if bean else 'bean✗'} | {tag}")
    sys.stdout.flush()

    # ═══════════════════════════════════════════════════════════════════════════
    # TEST 2: Hill(2×2) + periodic Vigenère
    # ═══════════════════════════════════════════════════════════════════════════

    print("\n── Test 2: Hill(2×2) then Vigenère (period 1-7) ──")
    print("  Model: CT = Vig(Hill(PT, M), key)")
    print("  → Hill(PT, M) = Vig⁻¹(CT, key) → PT = Hill⁻¹(intermediate)")
    sys.stdout.flush()

    # For each Vig period, determine key values at crib positions algebraically.
    # Then for each Hill matrix, check if the intermediate decrypts correctly.

    # Strategy: enumerate Vig key residues at crib positions (small for p≤7),
    # compute intermediate = (CT - key) mod 26 at crib positions,
    # then check if a Hill matrix produces the known plaintext from intermediate.

    for period in range(2, 8):
        # Crib positions mod period → residue classes
        residue_to_cribs = {}
        for pos, ch in CRIB_DICT.items():
            r = pos % period
            if r not in residue_to_cribs:
                residue_to_cribs[r] = []
            residue_to_cribs[r].append((pos, ALPH_IDX[ch]))

        # We need key values at residues that cover crib positions
        needed_residues = sorted(residue_to_cribs.keys())
        if len(needed_residues) > 7:
            continue

        # For each key assignment, compute intermediate at ALL crib positions
        # Then check if a 2×2 Hill matrix maps PT → intermediate consistently
        best_for_period = 0
        configs = 0

        for key_combo in product(range(26), repeat=len(needed_residues)):
            configs += 1
            key_at_residue = dict(zip(needed_residues, key_combo))

            # Compute intermediate at crib positions: inter[pos] = (CT[pos] - key[pos%p]) % 26
            inter_at_cribs = {}
            for pos, ch in CRIB_DICT.items():
                k = key_at_residue.get(pos % period, 0)
                inter_at_cribs[pos] = (CT_NUM[pos] - k) % MOD

            # Now we need: Hill(PT) = intermediate
            # For 2×2 Hill with offset 0: [inter[2i], inter[2i+1]] = M * [pt[2i], pt[2i+1]]
            # We need pairs where both positions are cribs
            for offset in range(2):
                pairs = []
                for pos in sorted(CRIB_DICT.keys()):
                    partner = pos + 1 if (pos - offset) % 2 == 0 else pos - 1
                    if partner in CRIB_DICT and pos < partner:
                        block_start = pos if (pos - offset) % 2 == 0 else partner
                        p1 = ALPH_IDX[CRIB_DICT[block_start]]
                        p2 = ALPH_IDX[CRIB_DICT[block_start + 1]]
                        i1 = inter_at_cribs[block_start]
                        i2 = inter_at_cribs[block_start + 1]
                        pairs.append((p1, p2, i1, i2))

                if len(pairs) < 2:
                    continue

                # Solve for M from first 2 pairs: I_mat = M * P_mat → M = I_mat * P_mat⁻¹
                p1a, p2a, i1a, i2a = pairs[0]
                p1b, p2b, i1b, i2b = pairs[1]

                P = [p1a, p1b, p2a, p2b]
                det_P = (p1a * p2b - p1b * p2a) % MOD
                if det_P not in COPRIME:
                    continue
                P_inv = mat2_inv(P)
                if P_inv is None:
                    continue

                # M = I_mat * P_inv
                I_mat = [i1a, i1b, i2a, i2b]
                M = [
                    (I_mat[0] * P_inv[0] + I_mat[1] * P_inv[2]) % MOD,
                    (I_mat[0] * P_inv[1] + I_mat[1] * P_inv[3]) % MOD,
                    (I_mat[2] * P_inv[0] + I_mat[3] * P_inv[2]) % MOD,
                    (I_mat[2] * P_inv[1] + I_mat[3] * P_inv[3]) % MOD,
                ]

                # Verify remaining pairs
                verified = 2
                for idx in range(2, len(pairs)):
                    p1, p2, i1, i2 = pairs[idx]
                    e1, e2 = mat2_mul_vec(M, p1, p2)
                    if e1 == i1 and e2 == i2:
                        verified += 1
                    else:
                        break

                if verified < min(len(pairs), 4):
                    continue

                # M is invertible?
                M_inv = mat2_inv(M)
                if M_inv is None:
                    continue

                # Full decrypt: Vig⁻¹ then Hill⁻¹
                full_key = [key_at_residue.get(i % period, 0) for i in range(CT_LEN)]
                inter = [(CT_NUM[i] - full_key[i]) % MOD for i in range(CT_LEN)]
                pt = hill2_decrypt_offset(inter, M_inv, offset)
                score = score_cribs(pt)

                if score > best_for_period:
                    best_for_period = score

                if score >= 14:
                    bean = check_bean(pt)
                    pt_text = ''.join(num_to_char(n) for n in pt)
                    tag = f"Vig(p={period})+Hill2 M={M} off={offset}"
                    print(f"  ** {tag}: score={score}/{N_CRIBS} "
                          f"{'BEAN✓' if bean else 'bean✗'} verified={verified}")
                    print(f"     key_residues={dict(zip(needed_residues, key_combo))}")
                    print(f"     PT: {pt_text[:60]}...")
                    results.append((score, tag, M, bean))
                    sys.stdout.flush()

        print(f"  Period {period}: {configs:,} key combos, best={best_for_period}/{N_CRIBS}")
        sys.stdout.flush()

    # ═══════════════════════════════════════════════════════════════════════════
    # TEST 3: Double columnar transposition
    # ═══════════════════════════════════════════════════════════════════════════

    print("\n── Test 3: Double columnar transposition ──")
    sys.stdout.flush()

    def columnar_decrypt(ct, perm):
        """Decrypt columnar transposition: undo column-read ordering."""
        width = len(perm)
        n = len(ct)
        n_rows = (n + width - 1) // width
        n_full = n % width or width

        # Compute column lengths
        col_lens = [n_rows if i < n_full else n_rows - 1 for i in range(width)]

        # Read into columns in perm order
        grid = [[] for _ in range(width)]
        idx = 0
        for rank in range(width):
            col = perm.index(rank)  # which column has this rank
            for _ in range(col_lens[col]):
                if idx < n:
                    grid[col].append(ct[idx])
                    idx += 1

        # Read off by rows
        result = []
        for r in range(n_rows):
            for c in range(width):
                if r < len(grid[c]):
                    result.append(grid[c][r])
        return result[:n]

    # Test small widths (3-8) with all permutations for first transposition,
    # then small widths for second
    best_double = 0
    for w1 in range(3, 7):
        for w2 in range(3, 7):
            for perm1 in permutations(range(w1)):
                inter = columnar_decrypt(CT_NUM, list(perm1))
                for perm2 in permutations(range(w2)):
                    pt = columnar_decrypt(inter, list(perm2))
                    score = score_cribs(pt)
                    if score > best_double:
                        best_double = score
                    if score >= 10:
                        bean = check_bean(pt)
                        pt_text = ''.join(num_to_char(n) for n in pt)
                        tag = f"DblCol w1={w1} p1={list(perm1)} w2={w2} p2={list(perm2)}"
                        print(f"  ** {tag}: score={score}/{N_CRIBS} "
                              f"{'BEAN✓' if bean else 'bean✗'}")
                        results.append((score, tag, [], bean))
                        sys.stdout.flush()

    print(f"  Double columnar best: {best_double}/{N_CRIBS}")
    sys.stdout.flush()

    # ═══════════════════════════════════════════════════════════════════════════
    # TEST 4: Bifid cipher with KRYPTOS-keyed Polybius square
    # ═══════════════════════════════════════════════════════════════════════════

    print("\n── Test 4: Bifid cipher (Polybius fractionation) ──")
    sys.stdout.flush()

    def make_polybius(keyword, size=5):
        """Create Polybius square from keyword (5×5, merge I/J)."""
        seen = set()
        square = []
        for c in keyword.upper():
            if c == 'J':
                c = 'I'
            if c not in seen and c.isalpha():
                seen.add(c)
                square.append(c)
        for c in 'ABCDEFGHIKLMNOPQRSTUVWXYZ':  # no J
            if c not in seen:
                seen.add(c)
                square.append(c)
        return square[:25]

    def bifid_decrypt(ct_nums, square, period):
        """Decrypt Bifid cipher with given Polybius square and period."""
        # Build lookup tables
        char_to_pos = {}
        pos_to_char = {}
        for idx, ch_val in enumerate(square):
            r, c = divmod(idx, 5)
            val = ALPH_IDX[ch_val]
            char_to_pos[val] = (r, c)
            pos_to_char[(r, c)] = val

        ct_mapped = []
        for v in ct_nums:
            if v == ALPH_IDX['J']:
                v = ALPH_IDX['I']
            if v in char_to_pos:
                ct_mapped.append(v)
            else:
                ct_mapped.append(v)

        # Bifid decrypt: process in blocks of `period`
        pt = []
        for start in range(0, len(ct_mapped), period):
            block = ct_mapped[start:start + period]
            blen = len(block)

            # Get row, col for each CT letter
            rows = []
            cols = []
            for v in block:
                if v in char_to_pos:
                    r, c = char_to_pos[v]
                else:
                    r, c = 0, 0
                rows.append(r)
                cols.append(c)

            # In Bifid decrypt: the fractionated stream is rows+cols
            # We need to UN-fractionate: interleave to get original coordinates
            combined = rows + cols
            for i in range(blen):
                r = combined[i]
                c = combined[blen + i]
                if (r, c) in pos_to_char:
                    pt.append(pos_to_char[(r, c)])
                else:
                    pt.append(0)

        return pt[:len(ct_nums)]

    keywords_to_test = [
        "KRYPTOS", "PALIMPSEST", "PALIMPCEST", "ABSCISSA", "BERLIN",
        "SANBORN", "SCHEIDT", "HILL", "LAYER", "CLOCK",
        "WELTZEITUHR", "URANIA", "EASTNORTHEAST",
    ]

    best_bifid = 0
    for kw in keywords_to_test:
        square = make_polybius(kw)
        for period in range(3, 20):
            pt = bifid_decrypt(CT_NUM, square, period)
            score = score_cribs(pt)
            if score > best_bifid:
                best_bifid = score
            if score >= 8:
                bean = check_bean(pt)
                tag = f"Bifid kw={kw} p={period}"
                print(f"  ** {tag}: score={score}/{N_CRIBS} "
                      f"{'BEAN✓' if bean else 'bean✗'}")
                results.append((score, tag, [], bean))
                sys.stdout.flush()

    # Also test with standard alphabet
    square_std = list('ABCDEFGHIKLMNOPQRSTUVWXYZ')
    for period in range(3, 20):
        pt = bifid_decrypt(CT_NUM, square_std, period)
        score = score_cribs(pt)
        if score > best_bifid:
            best_bifid = score
        if score >= 8:
            print(f"  ** Bifid std p={period}: score={score}/{N_CRIBS}")
            results.append((score, f"Bifid std p={period}", [], False))

    print(f"  Bifid best: {best_bifid}/{N_CRIBS}")
    sys.stdout.flush()

    # ═══════════════════════════════════════════════════════════════════════════
    # TEST 5: Keyed monoalphabetic substitution + transposition
    # ═══════════════════════════════════════════════════════════════════════════

    print("\n── Test 5: Monoalpha substitution + columnar transposition ──")
    sys.stdout.flush()

    # Test KRYPTOS-alphabet substitution followed by columnar transposition
    # KRYPTOS alphabet: KRYPTOSABCDEFGHIJLMNQUVWXZ
    ka_map = {ALPH_IDX[c]: i for i, c in enumerate(KRYPTOS_ALPHABET)}

    best_mono_trans = 0
    for direction in ["sub_then_trans", "trans_then_sub"]:
        for width in range(3, 10):
            for perm in permutations(range(width)):
                perm_list = list(perm)
                if direction == "sub_then_trans":
                    # Undo: transpose⁻¹ first, then sub⁻¹
                    inter = columnar_decrypt(CT_NUM, perm_list)
                    pt = [ka_map.get(v, v) for v in inter]
                else:
                    # Undo: sub⁻¹ first, then transpose⁻¹
                    inter = [ka_map.get(v, v) for v in CT_NUM]
                    pt = columnar_decrypt(inter, perm_list)

                score = score_cribs(pt)
                if score > best_mono_trans:
                    best_mono_trans = score
                if score >= 10:
                    tag = f"Mono+Trans {direction} w={width} p={perm_list}"
                    print(f"  ** {tag}: score={score}/{N_CRIBS}")
                    results.append((score, tag, [], False))

            # Early exit if width gets too large (permutations explode)
            if width >= 8:
                break

    print(f"  Mono+Trans best: {best_mono_trans}/{N_CRIBS}")
    sys.stdout.flush()

    # ═══════════════════════════════════════════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════════════════════════════════════════

    print("\n" + "=" * 80)
    print("SUMMARY: LAYER TWO Results")
    print("=" * 80)

    results.sort(key=lambda x: (-x[0], -x[3]))
    for score, tag, key, bean in results[:20]:
        bean_str = "BEAN✓" if bean else "bean✗"
        print(f"  {score}/{N_CRIBS} {bean_str} | {tag}")

    best = results[0] if results else (0, "none", [], False)
    print(f"\nBest: {best[0]}/{N_CRIBS}")
    if best[0] >= 17:
        print("SUCCESS: Compound cipher shows strong signal")
    elif best[0] >= 10:
        print("INTERESTING: Above noise, investigate further")
    else:
        print("FAILURE: Tested compound ciphers at noise floor")

    print("\n[E-05 COMPLETE]")
    return best[0]


if __name__ == "__main__":
    main()
