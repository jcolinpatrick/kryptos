#!/usr/bin/env python3
"""
Cipher: cipher family model
Family: cfm
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-CFM-00: DRUSILLA Hypothesis — Webster family name as key material.

[HYPOTHESIS] William H. Webster (CIA Director during Kryptos installation,
the "WW" in K2) had a wife and daughter both named DRUSILLA.
- DRUSILLA = 8 letters; period 8 is Bean-surviving
- Webster served 97 days beyond 4 years as DCI (97 = K4 length)
- Personal connection to the sculpture's addressee

Tests:
  1. DRUSILLA as Vigenere/Beaufort/VBeau key (period 8) — direct correspondence
  2. DRUSILLA as keyword for mixed alphabet + Vigenere with standard key
  3. DRUSILLA as alphabet-mixing keyword + running key model
  4. DRUSILLA-derived permutation as transposition
  5. Expanded name tests: WEBSTER, WILLIAMWEBSTER, DRUSILLWEBSTER, etc.
  6. DRUSILLA as running key characters
"""
import sys
import os
import itertools

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT, N_CRIBS,
    BEAN_EQ, BEAN_INEQ, SELF_ENCRYPTING,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)
from kryptos.kernel.scoring.aggregate import score_candidate, ScoreBreakdown
from kryptos.kernel.constraints.bean import verify_bean, BeanResult
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, vig_decrypt, beau_decrypt, varbeau_decrypt,
    vig_recover_key, beau_recover_key, varbeau_recover_key,
)
from kryptos.kernel.transforms.transposition import (
    apply_perm, invert_perm, validate_perm,
)

DECRYPT_FN = {
    CipherVariant.VIGENERE: vig_decrypt,
    CipherVariant.BEAUFORT: beau_decrypt,
    CipherVariant.VAR_BEAUFORT: varbeau_decrypt,
}

RECOVER_FN = {
    CipherVariant.VIGENERE: vig_recover_key,
    CipherVariant.BEAUFORT: beau_recover_key,
    CipherVariant.VAR_BEAUFORT: varbeau_recover_key,
}

# ── Webster-related keywords ──────────────────────────────────────────────
KEYWORDS = [
    "DRUSILLA",
    "WEBSTER",
    "WILLIAMWEBSTER",
    "WILLIAMHWEBSTER",
    "DRUSILLWEBSTER",
    "DRUSILLAWEBSTER",
    "DRUSILLAWILLIAMWEBSTER",
    "WWDRUSILLA",
    "DRUSILLAWW",
    "JUDGEDRUSILLA",
    # Webster was a judge/FBI director/CIA director
    "JUDGWEBSTER",
    "DIRECTORWEBSTER",
]


def keyword_to_mixed_alphabet(keyword: str) -> str:
    """Generate a mixed alphabet from a keyword."""
    seen = set()
    mixed = []
    for ch in keyword.upper():
        if ch in ALPH and ch not in seen:
            seen.add(ch)
            mixed.append(ch)
    for ch in ALPH:
        if ch not in seen:
            mixed.append(ch)
    return "".join(mixed)


def decrypt_with_key(ct: str, key: str, variant: CipherVariant) -> str:
    """Decrypt ct with repeating key under given variant."""
    dfn = DECRYPT_FN[variant]
    pt = []
    for i, c in enumerate(ct):
        c_idx = ALPH_IDX[c]
        k_idx = ALPH_IDX[key[i % len(key)]]
        p_idx = dfn(c_idx, k_idx)
        pt.append(ALPH[p_idx])
    return "".join(pt)


def recover_keystream(ct: str, pt: str, variant: CipherVariant) -> list:
    """Recover keystream values from known CT-PT pairs."""
    rfn = RECOVER_FN[variant]
    return [rfn(ALPH_IDX[c], ALPH_IDX[p]) for c, p in zip(ct, pt)]


def keyword_to_perm(keyword: str, length: int) -> list:
    """Convert a keyword to a columnar transposition permutation."""
    width = len(keyword)
    if width < 2 or width > length:
        return None
    # Number columns by keyword alphabetical order
    order = sorted(range(width), key=lambda i: (keyword[i], i))
    col_order = [0] * width
    for rank, col in enumerate(order):
        col_order[col] = rank

    nrows = (length + width - 1) // width
    perm = []
    for rank in range(width):
        col = order[rank]
        for row in range(nrows):
            pos = row * width + col
            if pos < length:
                perm.append(pos)
    if len(perm) != length:
        return None
    return perm


def decrypt_sub_alphabet(ct: str, ct_alph: str, pt_alph: str = ALPH) -> str:
    """Decrypt using a monoalphabetic mapping: ct_alph[i] -> pt_alph[i]."""
    mapping = {}
    for c_ch, p_ch in zip(ct_alph, pt_alph):
        mapping[c_ch] = p_ch
    return "".join(mapping.get(c, c) for c in ct)


def main():
    print("=" * 70)
    print("E-CFM-00: DRUSILLA Hypothesis — Webster family key material")
    print("=" * 70)

    best_score = 0
    best_config = ""
    results = []

    # ── Test 1: Periodic key (direct correspondence) ──────────────────────
    print("\n── Test 1: Periodic Vigenere/Beaufort/VBeau with Webster keywords ──")
    for keyword in KEYWORDS:
        for variant in CipherVariant:
            pt = decrypt_with_key(CT, keyword, variant)
            sb = score_candidate(pt)
            if sb.crib_score > best_score:
                best_score = sb.crib_score
                best_config = f"periodic key={keyword} variant={variant.value}"
            if sb.crib_score > 6:  # above noise floor
                print(f"  [!] {keyword} / {variant.value}: {sb.summary}")
                results.append((sb.crib_score, f"periodic {keyword}/{variant.value}"))
    print(f"  Best periodic: {best_score}/24")

    # ── Test 2: Keyword-mixed alphabet as mono layer ──────────────────────
    print("\n── Test 2: Keyword-mixed alphabet + periodic key ──")
    test2_best = 0
    for kw in KEYWORDS:
        mixed = keyword_to_mixed_alphabet(kw)
        # Apply mono: CT -> intermediate via mixed alphabet
        # Try both directions: mixed as CT alphabet and as PT alphabet
        for direction in ["ct_to_std", "std_to_ct"]:
            if direction == "ct_to_std":
                intermediate = decrypt_sub_alphabet(CT, mixed, ALPH)
            else:
                intermediate = decrypt_sub_alphabet(CT, ALPH, mixed)
            # Then try each Kryptos-related periodic key on top
            for key2 in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "DRUSILLA"]:
                for variant in CipherVariant:
                    pt = decrypt_with_key(intermediate, key2, variant)
                    sb = score_candidate(pt)
                    if sb.crib_score > test2_best:
                        test2_best = sb.crib_score
                    if sb.crib_score > 6:
                        cfg = f"mono={kw}({direction}) + key={key2}/{variant.value}"
                        print(f"  [!] {cfg}: {sb.summary}")
                        results.append((sb.crib_score, cfg))
    print(f"  Best mono+periodic: {test2_best}/24")

    # ── Test 3: DRUSILLA as columnar transposition keyword ────────────────
    print("\n── Test 3: Columnar transposition with Webster keywords ──")
    test3_best = 0
    for kw in KEYWORDS:
        perm = keyword_to_perm(kw, CT_LEN)
        if perm is None:
            continue
        inv = invert_perm(perm)
        for p in [perm, inv]:
            transposed = apply_perm(CT, p)
            # Score as-is (pure transposition)
            sb = score_candidate(transposed)
            if sb.crib_score > test3_best:
                test3_best = sb.crib_score
            if sb.crib_score > 6:
                print(f"  [!] trans={kw}: {sb.summary}")
            # Then Vigenere on top with various keys
            for key2 in ["KRYPTOS", "PALIMPSEST", "DRUSILLA"]:
                for variant in CipherVariant:
                    pt = decrypt_with_key(transposed, key2, variant)
                    sb = score_candidate(pt)
                    if sb.crib_score > test3_best:
                        test3_best = sb.crib_score
                    if sb.crib_score > 6:
                        cfg = f"trans={kw} + key={key2}/{variant.value}"
                        print(f"  [!] {cfg}: {sb.summary}")
                        results.append((sb.crib_score, cfg))
    print(f"  Best trans+sub: {test3_best}/24")

    # ── Test 4: DRUSILLA as running key (character-level) ─────────────────
    print("\n── Test 4: Extended Webster phrases as running key ──")
    test4_best = 0
    # Generate extended text from Webster-related phrases
    running_phrases = [
        "DRUSILLA" * 13,  # Repeated to cover 97 chars
        "DRUSILLAWEBSTER" * 7,
        "WILLIAMHWEBSTERDRUSILLA" * 5,
        "DRUSILLACIADIRECTORWEBSTER" * 4,
        "JUDGEWEBSTERDRUSILLA" * 5,
    ]
    for phrase in running_phrases:
        key = phrase[:CT_LEN]
        for variant in CipherVariant:
            pt = decrypt_with_key(CT, key, variant)
            sb = score_candidate(pt)
            if sb.crib_score > test4_best:
                test4_best = sb.crib_score
            if sb.crib_score > 6:
                print(f"  [!] running key={phrase[:20]}... / {variant.value}: {sb.summary}")
                results.append((sb.crib_score, f"running {phrase[:20]}/{variant.value}"))
    print(f"  Best running key: {test4_best}/24")

    # ── Test 5: Bean constraint check for DRUSILLA at period 8 ────────────
    print("\n── Test 5: Bean constraint analysis for DRUSILLA ──")
    for variant in CipherVariant:
        rfn = RECOVER_FN[variant]
        key_vals = [ALPH_IDX[c] for c in "DRUSILLA"]
        keystream = [key_vals[i % 8] for i in range(CT_LEN)]
        bean = verify_bean(keystream)
        print(f"  DRUSILLA / {variant.value}: Bean {'PASS' if bean.passed else 'FAIL'}")
        if not bean.passed:
            print(f"    EQ: {bean.eq_satisfied}/{bean.eq_total}, INEQ: {bean.ineq_satisfied}/{bean.ineq_total}")

    # ── Test 6: DRUSILLA-mixed KA alphabet ────────────────────────────────
    print("\n── Test 6: DRUSILLA-mixed vs KA alphabet cross-products ──")
    test6_best = 0
    dru_alph = keyword_to_mixed_alphabet("DRUSILLA")
    ka_alph = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
    alphabets = {
        "DRUSILLA": dru_alph,
        "KA": ka_alph,
        "AZ": ALPH,
    }
    for name_ct, alph_ct in alphabets.items():
        for name_pt, alph_pt in alphabets.items():
            if name_ct == name_pt:
                continue
            pt = decrypt_sub_alphabet(CT, alph_ct, alph_pt)
            sb = score_candidate(pt)
            if sb.crib_score > test6_best:
                test6_best = sb.crib_score
            if sb.crib_score > 4:
                print(f"  mono CT={name_ct} PT={name_pt}: {sb.summary}")
    print(f"  Best alphabet cross: {test6_best}/24")

    # ── Summary ───────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    overall_best = max([r[0] for r in results]) if results else best_score
    print(f"Overall best score: {overall_best}/24")
    if results:
        results.sort(key=lambda x: -x[0])
        print("Top 5 configs:")
        for score, cfg in results[:5]:
            print(f"  {score}/24: {cfg}")
    else:
        print("No configs above noise floor (6/24)")
    print(f"\nVerdict: {'SIGNAL — investigate!' if overall_best >= 18 else 'NOISE' if overall_best <= 6 else 'STORE — worth logging'}")


if __name__ == "__main__":
    main()
