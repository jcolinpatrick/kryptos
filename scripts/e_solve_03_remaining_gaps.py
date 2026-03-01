#!/usr/bin/env python3
"""E-SOLVE-03: Attack remaining open gaps in K4 cipher space.

Targets:
  H11: Quagmire III/IV with KA alphabet — mixed-alphabet Vigenère
  H12: Double-layer different-key encryption (two Vigenère with independent keys)
  H13: Affine running key — K = (a*PT + b) mod 26 with varying a,b
  H14: Reverse crib mapping — what if cribs are at TRANSPOSED positions?
  H15: Short unknown running key exhaustive — keys ≤8 chars, ALL possible texts
"""

import json
import sys
import time
from pathlib import Path

# ── Import from kernel ──────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, KRYPTOS_ALPHABET,
    CRIB_DICT, CRIB_POSITIONS, CRIB_WORDS,
    BEAN_EQ, BEAN_INEQ,
    NOISE_FLOOR, STORE_THRESHOLD,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
)

CT_VALS = [ALPH_IDX[c] for c in CT]
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

def crib_score(pt_vals):
    """Count how many crib positions match."""
    score = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(pt_vals) and pt_vals[pos] == ALPH_IDX[ch]:
            score += 1
    return score

def bean_check(key_vals):
    """Check Bean equality and inequality constraints on keystream."""
    # Equality: k[27] == k[65]
    for a, b in BEAN_EQ:
        if a < len(key_vals) and b < len(key_vals):
            if key_vals[a] != key_vals[b]:
                return False
    # Inequalities
    for a, b in BEAN_INEQ:
        if a < len(key_vals) and b < len(key_vals):
            if key_vals[a] == key_vals[b]:
                return False
    return True


# ====================================================================
# H11: Quagmire III/IV — Mixed-Alphabet Vigenère
# ====================================================================
def make_keyed_alphabet(keyword):
    """Create a keyed alphabet from a keyword."""
    seen = set()
    alpha = []
    for c in keyword.upper():
        if c in ALPH and c not in seen:
            seen.add(c)
            alpha.append(c)
    for c in ALPH:
        if c not in seen:
            seen.add(c)
            alpha.append(c)
    return ''.join(alpha)

def test_quagmire():
    """
    Quagmire III: Both PT and CT alphabets are keyed (same key).
    Quagmire IV: PT and CT alphabets are keyed with DIFFERENT keys.

    CT[i] = CT_alpha[PT_alpha.index(PT[i]) + key_val] where key_val
    comes from a periodic keyword through the PT alphabet.
    """
    print("\n" + "=" * 70)
    print("HYPOTHESIS 11: Quagmire III/IV with KA Alphabet")
    print("=" * 70)

    # Thematic keywords for alphabet construction
    alpha_keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK", "EASTNORTHEAST",
        "SANBORN", "SCHEIDT", "WEBSTER", "SHADOW", "LANGLEY",
        "VIRTUALLY", "INVISIBLE", "DIGETAL", "INTERPRETATU",
        "UNDERGRUUND", "DESPERATELY", "IQLUSION", "SUBTLESHADING",
    ]

    # Periodic keywords for the key
    key_keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "POINT",
        "LIGHT", "BERLIN", "CLOCK", "EAST", "NORTH",
        "SCHEIDT", "WEBSTER", "SANBORN", "LANGLEY", "REMINDER",
    ]

    best_score = 0
    above_noise = 0
    total = 0

    for ak in alpha_keywords:
        ct_alpha = make_keyed_alphabet(ak)
        ct_alpha_idx = {c: i for i, c in enumerate(ct_alpha)}

        for ak2 in alpha_keywords:
            pt_alpha = make_keyed_alphabet(ak2)
            pt_alpha_idx = {c: i for i, c in enumerate(pt_alpha)}

            for kk in key_keywords:
                key_vals_raw = [ALPH_IDX[c] for c in kk]
                period = len(kk)

                # Quagmire III: same CT/PT alphabet, keyword through PT alpha
                # Quagmire IV: different CT/PT alphabets
                for mode in ("III", "IV"):
                    if mode == "III" and ak != ak2:
                        continue  # Quagmire III uses same alphabet
                    if mode == "IV" and ak == ak2:
                        continue  # Quagmire IV uses different alphabets

                    # Decrypt: PT[i] = pt_alpha[(ct_alpha_idx[CT[i]] - key_shift) % 26]
                    # where key_shift = pt_alpha_idx[kk[i % period]]
                    pt_vals = []
                    for i in range(CT_LEN):
                        key_shift = pt_alpha_idx[kk[i % period]]
                        ct_pos = ct_alpha_idx[CT[i]]
                        pt_pos = (ct_pos - key_shift) % 26
                        pt_vals.append(ALPH_IDX[pt_alpha[pt_pos]])

                    score = crib_score(pt_vals)
                    total += 1
                    if score > best_score:
                        best_score = score
                    if score > NOISE_FLOOR:
                        above_noise += 1

                    # Also try with KA as one or both alphabets
                    if mode == "III":
                        # KA as the shared alphabet
                        for i_ka in range(CT_LEN):
                            key_shift = KA_IDX[kk[i_ka % period]]
                            ct_pos = KA_IDX[CT[i_ka]]
                            pt_pos = (ct_pos - key_shift) % 26
                            pt_vals[i_ka] = ALPH_IDX[KA[pt_pos]]

                        score = crib_score(pt_vals)
                        total += 1
                        if score > best_score:
                            best_score = score
                        if score > NOISE_FLOOR:
                            above_noise += 1

    print(f"  Tested {total} Quagmire configs")
    print(f"  Best score: {best_score}/24")
    print(f"  Above-noise: {above_noise}")
    return {"total": total, "best": best_score, "above_noise": above_noise}


# ====================================================================
# H12: Double-Layer Different-Key Encryption
# ====================================================================
def test_double_layer():
    """
    Two sequential Vigenère-family encryptions with DIFFERENT keys.
    PT → Vig(key1) → intermediate → Vig(key2) → CT

    This is equivalent to single Vig with key1+key2 ONLY if both use
    the same variant. If they use DIFFERENT variants (e.g., Vig then Beau),
    it's a genuinely different cipher.

    We test mixed variants: Vig+Beau, Beau+Vig, Beau+VarBeau, etc.
    """
    print("\n" + "=" * 70)
    print("HYPOTHESIS 12: Double-Layer Different-Key/Variant Encryption")
    print("=" * 70)

    keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "POINT",
        "LIGHT", "BERLIN", "CLOCK", "EAST", "NORTH",
        "SCHEIDT", "WEBSTER", "SANBORN", "LANGLEY", "REMINDER",
        "CARTER", "TOMB", "HOWARD", "PHARAOH", "EGYPT",
    ]

    # Cipher operations
    def vig_decrypt(ct_val, key_val):
        return (ct_val - key_val) % 26

    def beau_decrypt(ct_val, key_val):
        return (key_val - ct_val) % 26

    def var_beau_decrypt(ct_val, key_val):
        return (ct_val + key_val) % 26

    variants = [
        ("vig", vig_decrypt),
        ("beau", beau_decrypt),
        ("varbeau", var_beau_decrypt),
    ]

    best_score = 0
    above_noise = 0
    total = 0

    for k1_word in keywords:
        k1_vals = [ALPH_IDX[c] for c in k1_word]
        p1 = len(k1_word)

        for k2_word in keywords:
            if k1_word == k2_word:
                continue
            k2_vals = [ALPH_IDX[c] for c in k2_word]
            p2 = len(k2_word)

            for v1_name, v1_fn in variants:
                for v2_name, v2_fn in variants:
                    # Skip if both same variant AND keys combine additively
                    # (equivalent to single Vig with combined key, already tested)
                    if v1_name == v2_name == "vig":
                        continue

                    # Decrypt: CT → undo layer 2 → undo layer 1 → PT
                    pt_vals = []
                    for i in range(CT_LEN):
                        intermediate = v2_fn(CT_VALS[i], k2_vals[i % p2])
                        pt_val = v1_fn(intermediate, k1_vals[i % p1])
                        pt_vals.append(pt_val)

                    score = crib_score(pt_vals)
                    total += 1
                    if score > best_score:
                        best_score = score
                    if score > NOISE_FLOOR:
                        above_noise += 1

    # Also test with KA alphabet operations
    for k1_word in keywords[:10]:
        k1_vals = [KA_IDX[c] for c in k1_word]
        p1 = len(k1_word)

        for k2_word in keywords[:10]:
            if k1_word == k2_word:
                continue
            k2_vals = [KA_IDX[c] for c in k2_word]
            p2 = len(k2_word)

            # Vig in KA-space layer 1, standard Vig layer 2
            pt_vals = []
            for i in range(CT_LEN):
                ct_ka = KA_IDX[CT[i]]
                inter = (ct_ka - k2_vals[i % p2]) % 26
                inter_std = ALPH_IDX[KA[inter]]
                pt_val = (inter_std - ALPH_IDX[k1_word[i % p1]]) % 26
                pt_vals.append(pt_val)

            score = crib_score(pt_vals)
            total += 1
            if score > best_score:
                best_score = score
            if score > NOISE_FLOOR:
                above_noise += 1

    print(f"  Tested {total} double-layer configs")
    print(f"  Best score: {best_score}/24")
    print(f"  Above-noise: {above_noise}")
    return {"total": total, "best": best_score, "above_noise": above_noise}


# ====================================================================
# H13: Affine Running Key — K = (a*PT + b) mod 26
# ====================================================================
def test_affine_running_key():
    """
    Instead of additive substitution (CT = PT + K mod 26), test
    affine substitution where the running key modifies BOTH the
    multiplier and additive term.

    Model: CT[i] = (a * PT[i] + key[i]) mod 26
    where a is a fixed coprime-to-26 multiplier (12 valid values)
    and key[i] comes from a running key text.

    This is NOT the same as standard affine cipher (which was tested)
    because here the 'b' term varies per position from running key.
    """
    print("\n" + "=" * 70)
    print("HYPOTHESIS 13: Affine + Running Key Hybrid")
    print("=" * 70)

    # Valid multipliers (coprime to 26)
    valid_a = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]

    # Compute modular inverse of a
    def mod_inv(a, m=26):
        for x in range(m):
            if (a * x) % m == 1:
                return x
        return None

    # Running key sources from the sculpture
    running_keys = []

    # KA repeated
    running_keys.append(("KA_repeated", [ALPH_IDX[c] for c in (KA * 4)[:CT_LEN]]))

    # CT itself as running key
    running_keys.append(("CT_self", CT_VALS[:]))

    # CT reversed
    running_keys.append(("CT_reversed", list(reversed(CT_VALS))))

    # Alphabet cycling
    running_keys.append(("alpha_cycle", [i % 26 for i in range(CT_LEN)]))

    # Position values
    running_keys.append(("position", [i % 26 for i in range(CT_LEN)]))

    # Known K1 plaintext running key
    k1_pt = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUABOROFIQLUSIONX"
    k1_vals = [ALPH_IDX[c] for c in k1_pt[:CT_LEN].ljust(CT_LEN, 'A')]
    running_keys.append(("K1_PT", k1_vals))

    # K2 plaintext
    k2_pt = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESTHELANGULOFSEPARATIONWASITSREALLYNECESSARYXWASITABSOLUTELYNECESSARYXTHEYCOULDSEEFROMTHEIRPOSITIONSLIGHTLYTOTHEEASTXTHEKOPTICASTONEISLOCATEDINTHEPARKINGLOTADJACENTTOTHENORTHWESTCORNEROFTHEBUILDINGXITWASDIGITALANDTHEYWEREABLETOGETRIDOFIT"
    k2_vals = [ALPH_IDX.get(c, 0) for c in k2_pt.upper()[:CT_LEN]]
    running_keys.append(("K2_PT", k2_vals))

    # K3 plaintext
    k3_pt = "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBLORISANFILLEDDTHELOWERPARTOFTHEDOORWAYWASBLOCKPLASTEREDANDFLOORSTONESOBVIOUSLYREHIDDENTHEORIGINALENTRANWEGOTWHATAPPARENTLYNOTHINGXBUTNOW"
    k3_vals = [ALPH_IDX.get(c, 0) for c in k3_pt.upper()[:CT_LEN]]
    running_keys.append(("K3_PT", k3_vals))

    best_score = 0
    above_noise = 0
    total = 0

    for a in valid_a:
        a_inv = mod_inv(a)
        if a_inv is None:
            continue

        for rk_name, rk_vals in running_keys:
            # Decrypt: PT[i] = a_inv * (CT[i] - key[i]) mod 26
            pt_vals = [(a_inv * (CT_VALS[i] - rk_vals[i])) % 26 for i in range(CT_LEN)]

            score = crib_score(pt_vals)
            total += 1
            if score > best_score:
                best_score = score
            if score > NOISE_FLOOR:
                above_noise += 1

            # Also: PT[i] = a_inv * CT[i] - key[i] mod 26 (different model)
            pt_vals2 = [(a_inv * CT_VALS[i] - rk_vals[i]) % 26 for i in range(CT_LEN)]

            score2 = crib_score(pt_vals2)
            total += 1
            if score2 > best_score:
                best_score = score2
            if score2 > NOISE_FLOOR:
                above_noise += 1

            # And: CT[i] = a * (PT[i] + key[i]) mod 26
            # So PT[i] = (a_inv * CT[i] - key[i]) mod 26 — same as model 2

            # And: CT[i] = (a * PT[i]) XOR key[i] — non-modular mix
            # Can't really test XOR on mod-26 values meaningfully

    # Additional: double affine a1*PT + a2*key mod 26
    for a1 in valid_a:
        a1_inv = mod_inv(a1)
        for a2 in valid_a:
            for rk_name, rk_vals in running_keys[:3]:  # Limit for speed
                # CT = a1*PT + a2*key mod 26 → PT = a1_inv*(CT - a2*key) mod 26
                pt_vals = [(a1_inv * (CT_VALS[i] - a2 * rk_vals[i])) % 26 for i in range(CT_LEN)]

                score = crib_score(pt_vals)
                total += 1
                if score > best_score:
                    best_score = score
                if score > NOISE_FLOOR:
                    above_noise += 1

    print(f"  Tested {total} affine running key configs")
    print(f"  Best score: {best_score}/24")
    print(f"  Above-noise: {above_noise}")
    return {"total": total, "best": best_score, "above_noise": above_noise}


# ====================================================================
# H14: Reverse Crib Mapping — Cribs at Transposed Positions
# ====================================================================
def test_reverse_crib():
    """
    Standard assumption: CT[i] encrypts PT[i] (direct correspondence).

    What if a transposition σ was applied AFTER substitution?
    Then CT[σ(i)] = encrypt(PT[i]) and the crib positions in CT
    correspond to DIFFERENT positions in PT.

    For each small width (5-13), find which column permutation maps
    the known crib CT positions to consecutive PT positions, then
    check if the implied keystream is structured.
    """
    print("\n" + "=" * 70)
    print("HYPOTHESIS 14: Reverse Crib Mapping (Model B: sub→trans)")
    print("=" * 70)

    from itertools import permutations

    # Under Model B (sub then trans):
    # PT → substitute → IT → columnar_trans → CT
    # So CT = trans(sub(PT)), meaning CT[σ(i)] = sub(PT[i])
    # Equivalently: sub(PT[i]) = CT[σ(i)]
    # And we know PT at crib positions, so:
    # sub(CRIB[j]) = CT[σ(crib_pos[j])]

    # For a periodic substitution with period p:
    # sub(PT[i], key[i % p]) = CT[σ(i)]
    # At crib positions: key[crib_pos % p] = CT[σ(crib_pos)] - PT[crib_pos] mod 26

    crib_positions = sorted(CRIB_DICT.keys())
    crib_pt_vals = [ALPH_IDX[CRIB_DICT[p]] for p in crib_positions]

    best_score = 0
    above_noise = 0
    total = 0
    best_config = None

    for width in range(5, 14):
        n_cols = width
        n_rows = (CT_LEN + n_cols - 1) // n_cols

        # For each column permutation (only do exhaustive for small widths)
        if width <= 8:
            perms = list(permutations(range(n_cols)))
        else:
            # Sample: use keyword-based permutations
            kw_list = [
                "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "BERLIN",
                "CLOCK", "EAST", "NORTH", "SCHEIDT", "WEBSTER",
                "CARTER", "PHARAOH", "SANBORN", "LIGHT", "POINT",
                "DIGETAL", "REMIND", "VIRTUAL", "INVISIBLE", "LANGLEY",
            ]
            perms = set()
            for kw in kw_list:
                # Generate permutation from keyword
                kw_upper = kw.upper()[:width]
                if len(kw_upper) < width:
                    continue
                indexed = sorted(range(len(kw_upper)), key=lambda i: (kw_upper[i], i))
                perms.add(tuple(indexed))
            # Add identity and reverse
            perms.add(tuple(range(n_cols)))
            perms.add(tuple(reversed(range(n_cols))))
            perms = list(perms)

        for perm in perms:
            # Apply inverse transposition: σ^-1 maps CT positions to IT positions
            # IT is arranged in rows of width, read by columns in perm order
            # Build the position mapping
            inv_perm = [0] * n_cols
            for i, p in enumerate(perm):
                inv_perm[p] = i

            # Map each position through columnar transposition
            # In columnar trans: write by rows (width=n_cols), read by columns in perm order
            # Position i in IT → row r = i // n_cols, col c = i % n_cols
            # Read order: for each column in perm order, read top to bottom
            # So CT position for IT position (r, c) = sum of column heights before perm.index(c) + r

            # Build forward map: IT pos → CT pos
            col_heights = [n_rows if col < (CT_LEN % n_cols or n_cols) else n_rows - (1 if CT_LEN % n_cols else 0)
                          for col in range(n_cols)]
            # Actually, let's be precise about short columns
            full_rows = CT_LEN // n_cols
            extra = CT_LEN % n_cols
            col_heights = [full_rows + (1 if col < extra else 0) for col in range(n_cols)]

            sigma = [0] * CT_LEN  # sigma[it_pos] = ct_pos
            ct_pos = 0
            for col_idx in perm:
                for row in range(col_heights[col_idx]):
                    it_pos = row * n_cols + col_idx
                    if it_pos < CT_LEN:
                        sigma[it_pos] = ct_pos
                        ct_pos += 1

            if ct_pos != CT_LEN:
                continue  # Malformed

            # Build inverse: sigma_inv[ct_pos] = it_pos
            sigma_inv = [0] * CT_LEN
            for it_pos, ct_pos_val in enumerate(sigma):
                sigma_inv[ct_pos_val] = it_pos

            # Under Model B: CT[sigma[i]] = sub(PT[i])
            # So sub(PT[i]) = CT[sigma[i]]
            # At crib positions: key[i] = CT[sigma[crib_pos]] - PT[crib_pos] mod 26

            # Check crib consistency
            key_at_cribs = {}
            for cp, pt_ch in zip(crib_positions, crib_pt_vals):
                if cp < CT_LEN:
                    ct_mapped = CT_VALS[sigma[cp]] if cp < len(sigma) else -1
                    if ct_mapped < 0:
                        continue
                    key_val = (ct_mapped - pt_ch) % 26
                    key_at_cribs[cp] = key_val

            # Score: how many cribs map correctly if we assume various periodicities?
            for period in [7, 8, 9, 11, 13]:
                # Group crib positions by residue
                residue_keys = {}
                consistent = True
                for cp, kv in key_at_cribs.items():
                    res = cp % period
                    if res in residue_keys:
                        if residue_keys[res] != kv:
                            consistent = False
                            break
                    else:
                        residue_keys[res] = kv

                total += 1
                if consistent and len(key_at_cribs) >= 20:
                    # All cribs are consistent with this period!
                    # Compute full keystream and decrypt
                    full_key = [0] * CT_LEN
                    for i in range(CT_LEN):
                        res = i % period
                        if res in residue_keys:
                            full_key[i] = residue_keys[res]

                    pt_vals = [(CT_VALS[sigma[i]] - full_key[i]) % 26 for i in range(CT_LEN)]
                    score = crib_score(pt_vals)

                    if score > best_score:
                        best_score = score
                        best_config = f"w={width}, perm={perm}, period={period}"
                    if score > NOISE_FLOOR:
                        above_noise += 1

    print(f"  Tested {total} reverse crib mapping configs")
    print(f"  Best score: {best_score}/24")
    if best_config:
        print(f"  Best config: {best_config}")
    print(f"  Above-noise: {above_noise}")
    return {"total": total, "best": best_score, "above_noise": above_noise}


# ====================================================================
# H15: Short Unknown Running Key — Exhaustive Search
# ====================================================================
def test_short_running_key():
    """
    If the running key is a SHORT repeated phrase (not from a known text),
    exhaustively search all possible short keys.

    At period p, the keystream has p free parameters. For each period,
    use the crib constraints to solve for the key values at covered
    residue classes, then check how many cribs are simultaneously satisfied.

    This is the constraint-propagation approach: given cribs, derive what
    the key MUST be, and check for contradictions.
    """
    print("\n" + "=" * 70)
    print("HYPOTHESIS 15: Constraint-Derived Key Search (all periods)")
    print("=" * 70)

    crib_positions = sorted(CRIB_DICT.keys())
    crib_ct_vals = [CT_VALS[p] for p in crib_positions]
    crib_pt_vals = [ALPH_IDX[CRIB_DICT[p]] for p in crib_positions]

    # For each variant, compute key at each crib position
    variants = {
        "vig": lambda ct, pt: (ct - pt) % 26,
        "beau": lambda ct, pt: (ct + pt) % 26,
        "varbeau": lambda ct, pt: (pt - ct) % 26,
    }

    best_score = 0
    above_noise = 0
    total = 0
    results_by_period = {}

    for var_name, key_fn in variants.items():
        # Compute key at each crib position
        crib_keys = {}
        for i, pos in enumerate(crib_positions):
            crib_keys[pos] = key_fn(crib_ct_vals[i], crib_pt_vals[i])

        for period in range(2, 50):
            # Group crib positions by residue class
            by_residue = {}
            for pos, kv in crib_keys.items():
                res = pos % period
                if res not in by_residue:
                    by_residue[res] = []
                by_residue[res].append(kv)

            # Check consistency: all key values in same residue must agree
            consistent = True
            residue_key = {}
            for res, kvs in by_residue.items():
                unique = set(kvs)
                if len(unique) > 1:
                    consistent = False
                    break
                residue_key[res] = kvs[0]

            total += 1

            # How many residue classes are covered by cribs?
            covered = len(by_residue)

            if consistent:
                # All covered residues are consistent!
                # For uncovered residues, we'd need to brute force (26^uncovered)
                uncovered = period - covered

                if uncovered == 0:
                    # Fully determined! Decrypt and score.
                    key_stream = [residue_key[i % period] for i in range(CT_LEN)]

                    if var_name == "vig":
                        pt_vals = [(CT_VALS[i] - key_stream[i]) % 26 for i in range(CT_LEN)]
                    elif var_name == "beau":
                        pt_vals = [(key_stream[i] - CT_VALS[i]) % 26 for i in range(CT_LEN)]
                    else:  # varbeau
                        pt_vals = [(CT_VALS[i] + key_stream[i]) % 26 for i in range(CT_LEN)]

                    score = crib_score(pt_vals)

                    if score > best_score:
                        best_score = score
                        pt_text = ''.join(ALPH[v] for v in pt_vals)
                        key_text = ''.join(ALPH[v] for v in key_stream[:period])
                        print(f"    {var_name} period={period}: score={score}/24, key={key_text}")
                        if score >= STORE_THRESHOLD:
                            print(f"      PT: {pt_text}")
                    if score > NOISE_FLOOR:
                        above_noise += 1

                    results_by_period[f"{var_name}_p{period}"] = {
                        "consistent": True, "covered": covered,
                        "uncovered": 0, "score": score,
                    }

                elif uncovered <= 3 and period <= 30:
                    # Partially determined — brute force uncovered residues
                    uncovered_residues = [r for r in range(period) if r not in residue_key]

                    best_sub = 0
                    for combo_idx in range(26 ** uncovered):
                        # Decode combo
                        full_key = dict(residue_key)
                        temp = combo_idx
                        for ur in uncovered_residues:
                            full_key[ur] = temp % 26
                            temp //= 26

                        key_stream = [full_key[i % period] for i in range(CT_LEN)]

                        if var_name == "vig":
                            pt_vals = [(CT_VALS[i] - key_stream[i]) % 26 for i in range(CT_LEN)]
                        elif var_name == "beau":
                            pt_vals = [(key_stream[i] - CT_VALS[i]) % 26 for i in range(CT_LEN)]
                        else:
                            pt_vals = [(CT_VALS[i] + key_stream[i]) % 26 for i in range(CT_LEN)]

                        score = crib_score(pt_vals)
                        total += 1

                        if score > best_score:
                            best_score = score
                            pt_text = ''.join(ALPH[v] for v in pt_vals)
                            key_text = ''.join(ALPH[v] for v in key_stream[:period])
                            print(f"    {var_name} period={period}: score={score}/24, key={key_text}")
                            if score >= STORE_THRESHOLD:
                                print(f"      PT: {pt_text}")
                                # Check Bean
                                kv = [(CT_VALS[i] - pt_vals[i]) % 26 for i in range(CT_LEN)]
                                bean = bean_check(kv)
                                print(f"      Bean: {'PASS' if bean else 'FAIL'}")
                        if score > NOISE_FLOOR:
                            above_noise += 1
                            best_sub = max(best_sub, score)

                    results_by_period[f"{var_name}_p{period}"] = {
                        "consistent": True, "covered": covered,
                        "uncovered": uncovered, "best": best_sub,
                    }
                else:
                    results_by_period[f"{var_name}_p{period}"] = {
                        "consistent": True, "covered": covered,
                        "uncovered": uncovered, "note": "too many uncovered",
                    }
            else:
                results_by_period[f"{var_name}_p{period}"] = {"consistent": False}

    # Summary: which periods are crib-consistent?
    consistent_periods = [k for k, v in results_by_period.items() if v.get("consistent")]
    print(f"\n  Crib-consistent period/variant combos: {len(consistent_periods)}")
    for k in sorted(consistent_periods):
        v = results_by_period[k]
        print(f"    {k}: covered={v['covered']}/{k.split('_p')[1] if '_p' in k else '?'}, "
              f"uncovered={v.get('uncovered', '?')}, score={v.get('score', v.get('best', '?'))}")

    print(f"\n  Total configs tested: {total}")
    print(f"  Best score: {best_score}/24")
    print(f"  Above-noise: {above_noise}")
    return {"total": total, "best": best_score, "above_noise": above_noise}


# ====================================================================
# MAIN
# ====================================================================
def main():
    print(f"E-SOLVE-03: Remaining Gap Attacks")
    print(f"CT: {CT[:45]}...")
    print()

    t0 = time.time()
    results = {}

    results["h11_quagmire"] = test_quagmire()
    results["h12_double_layer"] = test_double_layer()
    results["h13_affine_running"] = test_affine_running_key()
    results["h14_reverse_crib"] = test_reverse_crib()
    results["h15_constraint_key"] = test_short_running_key()

    elapsed = time.time() - t0

    print("\n" + "=" * 70)
    print(f"E-SOLVE-03 SUMMARY ({elapsed:.1f}s)")
    print("=" * 70)
    for name, res in results.items():
        print(f"  {name}: {res.get('above_noise', 0)} above-noise results")

    total_an = sum(r.get("above_noise", 0) for r in results.values())
    print(f"\n  OVERALL: {total_an} above-noise results found!")

    out_path = Path("results/e_solve_03_results.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2, default=str))
    print(f"  Results saved to {out_path}")


if __name__ == "__main__":
    main()
