#!/usr/bin/env python3
"""E-CFM-10: MEDUSA Rule — Cyrillic Projector key derivation applied to Kryptos.

[HYPOTHESIS] Embedded anomaly words on Kryptos, when encrypted through the
KRYPTOS tableau (KRYPTOSABCDEFGHIJLMNQUVWXZ), produce a key that decrypts K4.

Background:
  The Cyrillic side of Antipodes uses a MEDUSA-rule key derivation:
    MEDUSA → МЕДУЗА (Russian transliteration) → standard positions [12,5,4,19,7,0]
    → lookup in ТЕНЬ-keyword-mixed alphabet → ЙБАСГТ (the Vigenere key)
  This is a monoalphabetic substitution through row 0 of the sculpture's own
  Vigenere tableau. The question: does Sanborn use the same pattern on Kryptos?

Method:
  1. Forward pass: ~40 clue words → apply MEDUSA rule (std position → KA lookup)
     → use as repeating Vigenere/Beaufort/VBeau key to decrypt K4
  2. Reverse pass: known keystream fragments → reverse through KA → check if they
     spell recognizable words
  3. Extended derivations: KA reverse, double application, reversed input word,
     encrypt clue word with KRYPTOS key
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT, N_CRIBS,
    KRYPTOS_ALPHABET, BEAN_EQ, BEAN_INEQ,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.constraints.bean import verify_bean, BeanResult
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, vig_decrypt, beau_decrypt, varbeau_decrypt,
    decrypt_text,
)

DECRYPT_FN = {
    CipherVariant.VIGENERE: vig_decrypt,
    CipherVariant.BEAUFORT: beau_decrypt,
    CipherVariant.VAR_BEAUFORT: varbeau_decrypt,
}

# KA lookup tables
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}


# ── MEDUSA derivation functions ──────────────────────────────────────────

def medusa_forward(word):
    """MEDUSA rule: letter → standard position → index into KA.
    Example: S=18 → KA[18]='J', H=7 → KA[7]='A', etc.
    """
    return "".join(KA[ALPH_IDX[c]] for c in word.upper())


def medusa_reverse(word):
    """Reverse MEDUSA: letter → find in KA → output standard position letter.
    Example: K is at KA[0] → ALPH[0]='A', R is at KA[1] → ALPH[1]='B', etc.
    """
    return "".join(ALPH[KA_IDX[c]] for c in word.upper())


def medusa_double(word):
    """Double application: apply MEDUSA forward twice."""
    return medusa_forward(medusa_forward(word))


def medusa_reversed_input(word):
    """Apply MEDUSA forward to the reversed word."""
    return medusa_forward(word[::-1].upper())


def medusa_encrypt_with_kryptos(word):
    """Encrypt clue word with 'KRYPTOS' as Vigenere key, producing derived key.
    C = (P + K) mod 26 where K cycles through KRYPTOS letter values.
    """
    kryptos_key = [ALPH_IDX[c] for c in "KRYPTOS"]
    result = []
    for i, c in enumerate(word.upper()):
        p = ALPH_IDX[c]
        k = kryptos_key[i % len(kryptos_key)]
        result.append(ALPH[(p + k) % MOD])
    return "".join(result)


DERIVATION_RULES = {
    "KA_forward": medusa_forward,
    "KA_reverse": medusa_reverse,
    "KA_double": medusa_double,
    "reversed_input": medusa_reversed_input,
    "vig_KRYPTOS": medusa_encrypt_with_kryptos,
}


# ── Clue word candidates ─────────────────────────────────────────────────

CLUE_WORDS = [
    # Anomaly words from the sculpture
    "YAR", "RAY", "DYARO", "HILL", "LRAY", "HILLRAY",
    # Misspelling clues
    "DESPARATLY", "DESPERATELY", "IQLUSION", "ILLUSION",
    "UNDERGRUUND", "UNDERGROUND", "DIGETAL", "DIGITAL",
    # Sanborn clue phrases (2025)
    "SHADOW", "POINT", "THEPOINT", "WHATSTHEPOINT",
    "CREATIVITY", "DELIVERING", "MESSAGE",
    # Known K1-K3 keywords
    "PALIMPSEST", "ABSCISSA", "KRYPTOS", "PALIMPCEST",
    # Thematic words
    "BERLIN", "CLOCK", "BERLINCLOCK", "WELTZEITUHR",
    "MEDUSA", "ANTIPODES",
    # Names
    "SANBORN", "SCHEIDT", "WEBSTER", "DRUSILLA",
    # K4 crib words
    "EASTNORTHEAST", "EAST", "NORTHEAST",
    # Combined anomalies
    "YARSHADOW", "HILLSHADOW", "YARHILL",
    # Additional thematic
    "EGYPT", "CIA", "LANGLEY", "SCULPTURE",
]


def decrypt_with_numeric_key(ct, key_str, variant):
    """Convert key string to numeric values and decrypt."""
    key_nums = [ALPH_IDX[c] for c in key_str]
    return decrypt_text(ct, key_nums, variant)


def check_bean_for_key(key_str):
    """Check Bean constraints for a repeating key."""
    key_nums = [ALPH_IDX[c] for c in key_str]
    keystream = [key_nums[i % len(key_nums)] for i in range(CT_LEN)]
    return verify_bean(keystream)


def main():
    print("=" * 70)
    print("E-CFM-10: MEDUSA Rule — Cyrillic Projector Derivation on Kryptos")
    print("=" * 70)

    best_score = 0
    best_config = ""
    results = []
    total_configs = 0

    # ── Forward Pass: Derive keys from clue words ─────────────────────────
    print(f"\n── Forward Pass: {len(CLUE_WORDS)} clue words × "
          f"{len(DERIVATION_RULES)} derivations × 3 variants ──")

    for word in CLUE_WORDS:
        for rule_name, rule_fn in DERIVATION_RULES.items():
            derived_key = rule_fn(word)
            for variant in CipherVariant:
                total_configs += 1
                pt = decrypt_with_numeric_key(CT, derived_key, variant)
                sb = score_candidate(pt)

                if sb.crib_score > best_score:
                    best_score = sb.crib_score
                    best_config = (f"word={word} rule={rule_name} "
                                   f"key={derived_key} variant={variant.value}")

                if sb.crib_score > 6:
                    bean = check_bean_for_key(derived_key)
                    print(f"  [!] {word}/{rule_name}/{variant.value}: "
                          f"key={derived_key} → {sb.summary}")
                    if bean.passed:
                        print(f"      *** BEAN PASS ***")
                    results.append((sb.crib_score, bean.passed,
                                    f"{word}/{rule_name}/{variant.value} key={derived_key}"))

    print(f"  Forward pass best: {best_score}/24 ({total_configs} configs)")

    # ── Reverse Pass: What do the known keystream fragments spell? ─────────
    print("\n── Reverse Pass: Known keystream → reverse through KA ──")

    keystreams = {
        "Vigenere_ENE": VIGENERE_KEY_ENE,
        "Vigenere_BC": VIGENERE_KEY_BC,
        "Beaufort_ENE": BEAUFORT_KEY_ENE,
        "Beaufort_BC": BEAUFORT_KEY_BC,
    }

    for name, ks_values in keystreams.items():
        # Convert numeric keystream to letters
        ks_letters = "".join(ALPH[v] for v in ks_values)

        # Apply MEDUSA reverse: find each letter in KA → output std position
        reversed_ka = medusa_reverse(ks_letters)
        # Apply MEDUSA forward: std position → KA lookup
        forward_ka = medusa_forward(ks_letters)

        print(f"  {name}: keystream letters = {ks_letters}")
        print(f"    KA reverse (find in KA → std pos): {reversed_ka}")
        print(f"    KA forward (std pos → KA lookup):  {forward_ka}")

        # Check if any of these look like words
        for label, text in [("reverse", reversed_ka), ("forward", forward_ka)]:
            # Check against a simple vowel ratio heuristic
            vowels = sum(1 for c in text if c in "AEIOU")
            ratio = vowels / len(text) if text else 0
            if ratio > 0.30:
                print(f"    → {label} has {ratio:.0%} vowels (plausible)")

    # ── Combined keystream: concatenate ENE + BC ──────────────────────────
    print("\n── Combined keystream reverse lookup ──")
    for variant_name, ene_ks, bc_ks in [
        ("Vigenere", VIGENERE_KEY_ENE, VIGENERE_KEY_BC),
        ("Beaufort", BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC),
    ]:
        combined = list(ene_ks) + list(bc_ks)
        combined_letters = "".join(ALPH[v] for v in combined)
        rev = medusa_reverse(combined_letters)
        fwd = medusa_forward(combined_letters)
        print(f"  {variant_name} combined (ENE+BC): {combined_letters}")
        print(f"    KA reverse: {rev}")
        print(f"    KA forward: {fwd}")

    # ── Extended: Try full keystream as 97-letter key ─────────────────────
    print("\n── Extended: Full 97-char derived keys from longer words ──")
    # Some words, when repeated to 97 chars, then MEDUSA-derived
    ext_best = 0
    ext_configs = 0
    for word in CLUE_WORDS:
        if len(word) < 3:
            continue
        # Repeat word to cover 97 chars, then apply each derivation
        repeated = (word * ((CT_LEN // len(word)) + 1))[:CT_LEN]
        for rule_name, rule_fn in DERIVATION_RULES.items():
            derived = rule_fn(repeated)
            for variant in CipherVariant:
                ext_configs += 1
                total_configs += 1
                pt = decrypt_with_numeric_key(CT, derived, variant)
                sb = score_candidate(pt)

                if sb.crib_score > ext_best:
                    ext_best = sb.crib_score

                if sb.crib_score > best_score:
                    best_score = sb.crib_score
                    best_config = (f"extended word={word} rule={rule_name} "
                                   f"variant={variant.value}")

                if sb.crib_score > 6:
                    bean_ks = [ALPH_IDX[c] for c in derived]
                    bean = verify_bean(bean_ks)
                    print(f"  [!] ext {word}/{rule_name}/{variant.value}: "
                          f"{sb.summary}")
                    results.append((sb.crib_score, bean.passed,
                                    f"ext {word}/{rule_name}/{variant.value}"))
    print(f"  Extended best: {ext_best}/24 ({ext_configs} configs)")

    # ── KA tableau row keys: each row of the Kryptos tableau as a key ────
    print("\n── KA tableau rows as keys ──")
    tab_best = 0
    tab_configs = 0
    for shift in range(26):
        # Row = cyclic shift of KA
        row = KA[shift:] + KA[:shift]
        row_key = row[:CT_LEN] if len(row) >= CT_LEN else (row * ((CT_LEN // 26) + 1))[:CT_LEN]
        for variant in CipherVariant:
            tab_configs += 1
            total_configs += 1
            pt = decrypt_with_numeric_key(CT, row_key, variant)
            sb = score_candidate(pt)
            if sb.crib_score > tab_best:
                tab_best = sb.crib_score
            if sb.crib_score > best_score:
                best_score = sb.crib_score
                best_config = f"KA_row_{shift}/{variant.value}"
            if sb.crib_score > 6:
                print(f"  [!] KA row {shift}/{variant.value}: {sb.summary}")
                results.append((sb.crib_score, False,
                                f"KA_row_{shift}/{variant.value}"))
    print(f"  Tableau row best: {tab_best}/24 ({tab_configs} configs)")

    # ── Diagonal / offset reads through KA tableau ────────────────────────
    print("\n── KA tableau diagonal reads as keys ──")
    diag_best = 0
    diag_configs = 0
    for start_row in range(26):
        for step in [1, 2, 3, 5, 7, 11, 13]:
            # Read diagonal: row advances by step per column
            key_chars = []
            for col in range(CT_LEN):
                row = (start_row + col * step) % 26
                row_alph = KA[row:] + KA[:row]
                key_chars.append(row_alph[col % 26])
            diag_key = "".join(key_chars)
            for variant in CipherVariant:
                diag_configs += 1
                total_configs += 1
                pt = decrypt_with_numeric_key(CT, diag_key, variant)
                sb = score_candidate(pt)
                if sb.crib_score > diag_best:
                    diag_best = sb.crib_score
                if sb.crib_score > best_score:
                    best_score = sb.crib_score
                    best_config = f"diag start={start_row} step={step}/{variant.value}"
                if sb.crib_score > 6:
                    print(f"  [!] diag start={start_row} step={step}/{variant.value}: "
                          f"{sb.summary}")
                    results.append((sb.crib_score, False,
                                    f"diag start={start_row} step={step}/{variant.value}"))
    print(f"  Diagonal best: {diag_best}/24 ({diag_configs} configs)")

    # ── Summary ───────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("SUMMARY — E-CFM-10: MEDUSA Rule")
    print("=" * 70)
    print(f"Total configs tested: {total_configs}")
    print(f"Overall best score: {best_score}/24")
    print(f"Best config: {best_config}")

    if results:
        results.sort(key=lambda x: (-x[0], -x[1]))
        print(f"\nAbove-noise results ({len(results)}):")
        for score, bean, cfg in results[:10]:
            print(f"  {score}/24 bean={'PASS' if bean else 'FAIL'}: {cfg}")

    bean_passes = [r for r in results if r[1]]
    if bean_passes:
        print(f"\nBean PASS results ({len(bean_passes)}):")
        for score, _, cfg in bean_passes[:5]:
            print(f"  {score}/24: {cfg}")

    # Truth taxonomy classification
    if best_score >= 24:
        verdict = "BREAKTHROUGH — verify immediately!"
        taxonomy = "[INTERNAL RESULT] MEDUSA rule: BREAKTHROUGH"
    elif best_score >= 18:
        verdict = "SIGNAL — investigate further"
        taxonomy = "[INTERNAL RESULT] MEDUSA rule: SIGNAL"
    elif best_score >= 10:
        verdict = "STORE — worth logging, likely noise"
        taxonomy = "[INTERNAL RESULT] MEDUSA rule: STORE"
    else:
        verdict = "NOISE"
        taxonomy = "[INTERNAL RESULT] MEDUSA rule on Kryptos: NOISE"

    print(f"\nVerdict: {verdict}")
    print(f"Classification: {taxonomy}")
    print(f"\n[HYPOTHESIS] MEDUSA-style key derivation through KA tableau "
          f"{'SURVIVES' if best_score >= 18 else 'does NOT produce signal'} "
          f"for K4 decryption.")


if __name__ == "__main__":
    main()
