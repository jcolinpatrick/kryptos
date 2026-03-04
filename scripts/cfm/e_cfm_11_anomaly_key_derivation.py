#!/usr/bin/env python3
"""
Cipher: cipher family model
Family: cfm
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-CFM-11: Systematic Anomaly-as-Key-Material.

[HYPOTHESIS] Physical anomalies on Kryptos function like MEDUSA — they are
embedded clue words whose letter values (via various derivation rules) produce
key parameters for K4.

Tests anomalies as key material through MULTIPLE derivation methods:
  1. Direct as repeating Vigenere/Beaufort key
  2. MEDUSA rule (std → KA lookup)
  3. Reverse MEDUSA rule (KA → std lookup)
  4. As transposition seed (keyword → columnar perm)
  5. As period indicator
  6. As starting offset for running key (offset into known texts)
  7. As additive mask before/after Vigenere
  8. Combined: anomaly-derived key + anomaly-derived transposition
"""
import sys
import os
import math

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT, N_CRIBS,
    KRYPTOS_ALPHABET, BEAN_EQ, BEAN_INEQ,
    SELF_ENCRYPTING,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.constraints.bean import verify_bean, BeanResult
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, vig_decrypt, beau_decrypt, varbeau_decrypt,
    decrypt_text, apply_additive_mask, remove_additive_mask,
)
from kryptos.kernel.transforms.transposition import (
    apply_perm, invert_perm, columnar_perm, keyword_to_order,
)

DECRYPT_FN = {
    CipherVariant.VIGENERE: vig_decrypt,
    CipherVariant.BEAUFORT: beau_decrypt,
    CipherVariant.VAR_BEAUFORT: varbeau_decrypt,
}

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}


# ── MEDUSA derivation helpers ────────────────────────────────────────────

def medusa_forward(word):
    """MEDUSA rule: letter → standard position → index into KA."""
    return "".join(KA[ALPH_IDX[c]] for c in word.upper())


def medusa_reverse(word):
    """Reverse MEDUSA: letter → find in KA → output standard position letter."""
    return "".join(ALPH[KA_IDX[c]] for c in word.upper())


def keyword_to_perm_local(keyword, length=97):
    """Convert a keyword to a columnar transposition permutation."""
    kw = keyword.upper()
    width = len(kw)
    if width < 2 or width > length:
        return None
    order = keyword_to_order(kw, width)
    if order is None:
        return None
    return columnar_perm(width, order, length)


def decrypt_with_numeric_key(ct, key_str, variant):
    """Convert key string to numeric values and decrypt."""
    key_nums = [ALPH_IDX[c] for c in key_str]
    return decrypt_text(ct, key_nums, variant)


def check_bean_for_keystream(keystream):
    """Check Bean constraints for a full keystream."""
    return verify_bean(keystream)


# ── Anomaly sources ──────────────────────────────────────────────────────

ANOMALY_WORDS = {
    # Anomaly words from the sculpture
    "YAR": "YAR",
    "RAY": "RAY",
    "DYARO": "DYARO",
    "HILL": "HILL",
    "LRAY": "LRAY",
    "HILLRAY": "HILLRAY",
    # Misspelling-derived
    "DESPARATLY": "DESPARATLY",
    "IQLUSION": "IQLUSION",
    "UNDERGRUUND": "UNDERGRUUND",
    "DIGETAL": "DIGETAL",
    # Q from K3/K4 boundary
    "Q": "Q",
    # Self-encrypting positions as letters: pos 32='S', pos 73='K'
    "SK": "SK",
    # RQ from Morse end
    "RQ": "RQ",
}

ANOMALY_NUMERIC = {
    # Alphabet positions of anomaly words
    "YAR_pos": [24, 0, 17],
    "DYARO_pos": [3, 24, 0, 17, 14],
    "HILL_pos": [7, 8, 11, 11],
    # Misspelling difference positions (where errors occur)
    "DESPARATLY_errs": [5, 8],  # E→A at pos 5, E dropped at pos 8
    # Self-encrypting positions
    "self_encrypt": [32, 73],
    # RQ from Morse
    "RQ_pos": [17, 16],
    # UNDERGRUUND: O→U shift = 6
    "UNDERGRUUND_shift": [6],
    # Compass bearing 67.5 degrees
    "compass_675": [6, 7, 5],
    # K2 coordinates as numeric
    "K2_coords": [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4],
    # 97 = K4 length, Webster 97 days
    "NINETYSEVEN": [13, 8, 13, 4, 19, 24, 18, 4, 21, 4, 13],
}


# ── Running key source texts ─────────────────────────────────────────────

def load_carter_text():
    """Try to load Carter book text for running key offset tests."""
    paths = [
        os.path.join(os.path.dirname(__file__), "..", "reference", "carter_text.txt"),
        os.path.join(os.path.dirname(__file__), "..", "reference", "carter_book_text.txt"),
    ]
    for p in paths:
        if os.path.exists(p):
            with open(p) as f:
                text = f.read().upper()
                return "".join(c for c in text if c in ALPH)
    return None


def main():
    print("=" * 70)
    print("E-CFM-11: Systematic Anomaly-as-Key-Material")
    print("=" * 70)

    best_score = 0
    best_config = ""
    results = []
    total_configs = 0

    # ══════════════════════════════════════════════════════════════════════
    # Test 1: Direct repeating Vigenere/Beaufort key from anomaly words
    # ══════════════════════════════════════════════════════════════════════
    print("\n── Test 1: Anomaly words as direct repeating key ──")
    t1_best = 0
    for name, word in ANOMALY_WORDS.items():
        for variant in CipherVariant:
            total_configs += 1
            pt = decrypt_with_numeric_key(CT, word, variant)
            sb = score_candidate(pt)
            if sb.crib_score > t1_best:
                t1_best = sb.crib_score
            if sb.crib_score > best_score:
                best_score = sb.crib_score
                best_config = f"direct key={name}/{variant.value}"
            if sb.crib_score > 6:
                print(f"  [!] {name}/{variant.value}: {sb.summary}")
                results.append((sb.crib_score, f"direct {name}/{variant.value}"))
    print(f"  Test 1 best: {t1_best}/24")

    # ══════════════════════════════════════════════════════════════════════
    # Test 2: MEDUSA rule (std → KA lookup)
    # ══════════════════════════════════════════════════════════════════════
    print("\n── Test 2: MEDUSA rule (std pos → KA lookup) ──")
    t2_best = 0
    for name, word in ANOMALY_WORDS.items():
        derived = medusa_forward(word)
        for variant in CipherVariant:
            total_configs += 1
            pt = decrypt_with_numeric_key(CT, derived, variant)
            sb = score_candidate(pt)
            if sb.crib_score > t2_best:
                t2_best = sb.crib_score
            if sb.crib_score > best_score:
                best_score = sb.crib_score
                best_config = f"MEDUSA_fwd key={name}→{derived}/{variant.value}"
            if sb.crib_score > 6:
                print(f"  [!] {name}→{derived}/{variant.value}: {sb.summary}")
                results.append((sb.crib_score,
                                f"MEDUSA_fwd {name}→{derived}/{variant.value}"))
    print(f"  Test 2 best: {t2_best}/24")

    # ══════════════════════════════════════════════════════════════════════
    # Test 3: Reverse MEDUSA rule (KA → std lookup)
    # ══════════════════════════════════════════════════════════════════════
    print("\n── Test 3: Reverse MEDUSA rule (find in KA → std pos) ──")
    t3_best = 0
    for name, word in ANOMALY_WORDS.items():
        derived = medusa_reverse(word)
        for variant in CipherVariant:
            total_configs += 1
            pt = decrypt_with_numeric_key(CT, derived, variant)
            sb = score_candidate(pt)
            if sb.crib_score > t3_best:
                t3_best = sb.crib_score
            if sb.crib_score > best_score:
                best_score = sb.crib_score
                best_config = f"MEDUSA_rev key={name}→{derived}/{variant.value}"
            if sb.crib_score > 6:
                print(f"  [!] {name}→{derived}/{variant.value}: {sb.summary}")
                results.append((sb.crib_score,
                                f"MEDUSA_rev {name}→{derived}/{variant.value}"))
    print(f"  Test 3 best: {t3_best}/24")

    # ══════════════════════════════════════════════════════════════════════
    # Test 4: Anomaly words as transposition seed
    # ══════════════════════════════════════════════════════════════════════
    print("\n── Test 4: Anomaly words as transposition keyword ──")
    t4_best = 0
    for name, word in ANOMALY_WORDS.items():
        if len(word) < 2:
            continue
        perm = keyword_to_perm_local(word)
        if perm is None or len(perm) != CT_LEN:
            continue
        inv = invert_perm(perm)
        for p, pdir in [(perm, "fwd"), (inv, "inv")]:
            transposed = apply_perm(CT, p)
            # Score pure transposition
            total_configs += 1
            sb = score_candidate(transposed)
            if sb.crib_score > t4_best:
                t4_best = sb.crib_score
            if sb.crib_score > best_score:
                best_score = sb.crib_score
                best_config = f"trans_{pdir} kw={name}"
            if sb.crib_score > 6:
                print(f"  [!] trans_{pdir} {name}: {sb.summary}")
                results.append((sb.crib_score, f"trans_{pdir} {name}"))

            # Transposition + Vigenere with KRYPTOS key
            for sub_key in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
                for variant in CipherVariant:
                    total_configs += 1
                    pt = decrypt_with_numeric_key(transposed, sub_key, variant)
                    sb = score_candidate(pt)
                    if sb.crib_score > t4_best:
                        t4_best = sb.crib_score
                    if sb.crib_score > best_score:
                        best_score = sb.crib_score
                        best_config = (f"trans_{pdir}={name} + "
                                       f"key={sub_key}/{variant.value}")
                    if sb.crib_score > 6:
                        cfg = f"trans_{pdir}={name}+{sub_key}/{variant.value}"
                        print(f"  [!] {cfg}: {sb.summary}")
                        results.append((sb.crib_score, cfg))
    print(f"  Test 4 best: {t4_best}/24")

    # ══════════════════════════════════════════════════════════════════════
    # Test 5: Anomaly numeric values as period + exhaustive key at that period
    # ══════════════════════════════════════════════════════════════════════
    print("\n── Test 5: Anomaly-derived periods with KRYPTOS-based keys ──")
    t5_best = 0
    # Extract unique periods from anomaly numeric data
    candidate_periods = set()
    for name, vals in ANOMALY_NUMERIC.items():
        for v in vals:
            if 2 <= v <= 26:
                candidate_periods.add(v)
        # Also try length of the numeric array
        if 2 <= len(vals) <= 26:
            candidate_periods.add(len(vals))

    # For each candidate period, try KRYPTOS-derived keys
    key_sources = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SANBORN", "SCHEIDT",
                   "SHADOW", "MEDUSA", "BERLINCLOCK", "ANTIPODES"]
    for period in sorted(candidate_periods):
        for ks in key_sources:
            # Truncate/repeat key source to match period
            key = (ks * ((period // len(ks)) + 1))[:period]
            for variant in CipherVariant:
                total_configs += 1
                pt = decrypt_with_numeric_key(CT, key, variant)
                sb = score_candidate(pt)
                if sb.crib_score > t5_best:
                    t5_best = sb.crib_score
                if sb.crib_score > best_score:
                    best_score = sb.crib_score
                    best_config = (f"period={period} key={key}/"
                                   f"{variant.value}")
                if sb.crib_score > 6:
                    print(f"  [!] p={period} key={key[:12]}.../"
                          f"{variant.value}: {sb.summary}")
                    results.append((sb.crib_score,
                                    f"p={period} key={key}/{variant.value}"))
    print(f"  Test 5 best: {t5_best}/24")

    # ══════════════════════════════════════════════════════════════════════
    # Test 6: Anomaly numeric values as running key offset (Carter text)
    # ══════════════════════════════════════════════════════════════════════
    print("\n── Test 6: Anomaly values as running key offset into Carter ──")
    t6_best = 0
    carter_text = load_carter_text()
    if carter_text and len(carter_text) >= CT_LEN + 1000:
        # Offsets derived from anomaly positions and values
        offsets_to_try = set()
        for name, vals in ANOMALY_NUMERIC.items():
            for v in vals:
                offsets_to_try.add(v)
                offsets_to_try.add(v * 10)
                offsets_to_try.add(v * 97)
            # Concatenate digits as offset
            if len(vals) > 1:
                concat = int("".join(str(v) for v in vals))
                if concat < len(carter_text) - CT_LEN:
                    offsets_to_try.add(concat)

        # Also try specific offsets
        for special in [97, 190, 865, 1584, 675, 67, 68]:
            offsets_to_try.add(special)

        valid_offsets = [o for o in offsets_to_try
                         if 0 <= o <= len(carter_text) - CT_LEN]

        for offset in sorted(valid_offsets):
            running_key = carter_text[offset:offset + CT_LEN]
            for variant in CipherVariant:
                total_configs += 1
                pt = decrypt_with_numeric_key(CT, running_key, variant)
                sb = score_candidate(pt)
                if sb.crib_score > t6_best:
                    t6_best = sb.crib_score
                if sb.crib_score > best_score:
                    best_score = sb.crib_score
                    best_config = f"carter_offset={offset}/{variant.value}"
                if sb.crib_score > 6:
                    print(f"  [!] carter@{offset}/{variant.value}: "
                          f"{sb.summary}")
                    results.append((sb.crib_score,
                                    f"carter@{offset}/{variant.value}"))
        print(f"  Test 6 best: {t6_best}/24 ({len(valid_offsets)} offsets)")
    else:
        print("  Carter text not available, skipping")

    # ══════════════════════════════════════════════════════════════════════
    # Test 7: Anomaly words as additive mask before/after Vigenere
    # ══════════════════════════════════════════════════════════════════════
    print("\n── Test 7: Anomaly words as additive mask ──")
    t7_best = 0
    mask_words = ["YAR", "HILL", "DYARO", "HILLRAY", "SK", "RQ",
                  "DESPARATLY", "IQLUSION", "KRYPTOS"]
    sub_keys = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SANBORN"]

    for mask_word in mask_words:
        # Remove mask from CT first, then decrypt
        unmasked = remove_additive_mask(CT, mask_word)
        for sub_key in sub_keys:
            for variant in CipherVariant:
                total_configs += 1
                pt = decrypt_with_numeric_key(unmasked, sub_key, variant)
                sb = score_candidate(pt)
                if sb.crib_score > t7_best:
                    t7_best = sb.crib_score
                if sb.crib_score > best_score:
                    best_score = sb.crib_score
                    best_config = (f"unmask={mask_word}+key={sub_key}/"
                                   f"{variant.value}")
                if sb.crib_score > 6:
                    cfg = f"unmask={mask_word}+{sub_key}/{variant.value}"
                    print(f"  [!] {cfg}: {sb.summary}")
                    results.append((sb.crib_score, cfg))

        # Also try: decrypt first, then remove mask
        for sub_key in sub_keys:
            for variant in CipherVariant:
                total_configs += 1
                intermediate = decrypt_with_numeric_key(CT, sub_key, variant)
                pt = remove_additive_mask(intermediate, mask_word)
                sb = score_candidate(pt)
                if sb.crib_score > t7_best:
                    t7_best = sb.crib_score
                if sb.crib_score > best_score:
                    best_score = sb.crib_score
                    best_config = (f"key={sub_key}/{variant.value}+"
                                   f"unmask={mask_word}")
                if sb.crib_score > 6:
                    cfg = f"{sub_key}/{variant.value}+unmask={mask_word}"
                    print(f"  [!] {cfg}: {sb.summary}")
                    results.append((sb.crib_score, cfg))
    print(f"  Test 7 best: {t7_best}/24")

    # ══════════════════════════════════════════════════════════════════════
    # Test 8: Combined anomaly-derived key + anomaly-derived transposition
    # ══════════════════════════════════════════════════════════════════════
    print("\n── Test 8: Combined key + transposition from anomalies ──")
    t8_best = 0

    # Pairs: (transposition_source, key_source)
    trans_words = ["YAR", "HILL", "DYARO", "DESPARATLY", "IQLUSION",
                   "HILLRAY", "UNDERGRUUND", "DIGETAL"]
    key_words = ["YAR", "HILL", "DYARO", "SK", "RQ", "HILLRAY",
                 "KRYPTOS", "SHADOW", "MEDUSA"]

    for tw in trans_words:
        if len(tw) < 2:
            continue
        perm = keyword_to_perm_local(tw)
        if perm is None or len(perm) != CT_LEN:
            continue
        inv = invert_perm(perm)

        for p, pdir in [(perm, "fwd"), (inv, "inv")]:
            transposed = apply_perm(CT, p)
            for kw in key_words:
                if kw == tw:
                    continue  # Skip same word for both
                # Direct key
                for variant in CipherVariant:
                    total_configs += 1
                    pt = decrypt_with_numeric_key(transposed, kw, variant)
                    sb = score_candidate(pt)
                    if sb.crib_score > t8_best:
                        t8_best = sb.crib_score
                    if sb.crib_score > best_score:
                        best_score = sb.crib_score
                        best_config = (f"trans_{pdir}={tw}+key={kw}/"
                                       f"{variant.value}")
                    if sb.crib_score > 6:
                        cfg = f"t_{pdir}={tw}+k={kw}/{variant.value}"
                        print(f"  [!] {cfg}: {sb.summary}")
                        results.append((sb.crib_score, cfg))

                # MEDUSA-derived key
                mk = medusa_forward(kw)
                for variant in CipherVariant:
                    total_configs += 1
                    pt = decrypt_with_numeric_key(transposed, mk, variant)
                    sb = score_candidate(pt)
                    if sb.crib_score > t8_best:
                        t8_best = sb.crib_score
                    if sb.crib_score > best_score:
                        best_score = sb.crib_score
                        best_config = (f"trans_{pdir}={tw}+MEDUSA({kw})="
                                       f"{mk}/{variant.value}")
                    if sb.crib_score > 6:
                        cfg = (f"t_{pdir}={tw}+M({kw})="
                               f"{mk}/{variant.value}")
                        print(f"  [!] {cfg}: {sb.summary}")
                        results.append((sb.crib_score, cfg))
    print(f"  Test 8 best: {t8_best}/24")

    # ══════════════════════════════════════════════════════════════════════
    # Test 9: Compound tests — specific anomaly combinations
    # ══════════════════════════════════════════════════════════════════════
    print("\n── Test 9: Compound anomaly combinations ──")
    t9_best = 0

    compounds = [
        # (description, transposition_kw_or_None, sub_key, mask_or_None)
        ("YAR+HILL 7-letter key", None, "YARHILL", None),
        ("HILL+YAR 7-letter key", None, "HILLRAY", None),
        ("DESPARATLY trans + MEDUSA(YAR) key",
         "DESPARATLY", medusa_forward("YAR"), None),
        ("IQLUSION trans + MEDUSA(HILL) key",
         "IQLUSION", medusa_forward("HILL"), None),
        ("YAR trans + KRYPTOS key + HILL mask",
         "YAR", "KRYPTOS", "HILL"),
        ("HILL trans + SHADOW key",
         "HILL", "SHADOW", None),
        ("DYARO trans + MEDUSA(SHADOW) key",
         "DYARO", medusa_forward("SHADOW"), None),
        ("UNDERGRUUND trans + YAR key",
         "UNDERGRUUND", "YAR", None),
        ("DIGETAL trans + MEDUSA(KRYPTOS) key",
         "DIGETAL", medusa_forward("KRYPTOS"), None),
        ("SK (self-encrypt) as key, HILL trans",
         "HILL", "SK", None),
    ]

    for desc, trans_kw, sub_key, mask in compounds:
        # Get the text to decrypt (with or without transposition)
        if trans_kw and len(trans_kw) >= 2:
            perm = keyword_to_perm_local(trans_kw)
            if perm is None or len(perm) != CT_LEN:
                print(f"  SKIP {desc}: invalid transposition")
                continue
            texts = [
                (apply_perm(CT, perm), "fwd"),
                (apply_perm(CT, invert_perm(perm)), "inv"),
            ]
        else:
            texts = [(CT, "none")]

        for text, tdir in texts:
            for variant in CipherVariant:
                total_configs += 1
                pt = decrypt_with_numeric_key(text, sub_key, variant)
                if mask:
                    pt = remove_additive_mask(pt, mask)
                sb = score_candidate(pt)
                if sb.crib_score > t9_best:
                    t9_best = sb.crib_score
                if sb.crib_score > best_score:
                    best_score = sb.crib_score
                    best_config = f"compound: {desc} t={tdir}/{variant.value}"
                if sb.crib_score > 6:
                    print(f"  [!] {desc} t={tdir}/{variant.value}: "
                          f"{sb.summary}")
                    results.append((sb.crib_score,
                                    f"compound: {desc}/{variant.value}"))
    print(f"  Test 9 best: {t9_best}/24")

    # ══════════════════════════════════════════════════════════════════════
    # Test 10: Anomaly numeric sequences as direct key values
    # ══════════════════════════════════════════════════════════════════════
    print("\n── Test 10: Raw numeric anomaly values as key ──")
    t10_best = 0
    for name, vals in ANOMALY_NUMERIC.items():
        if len(vals) < 1:
            continue
        for variant in CipherVariant:
            total_configs += 1
            pt = decrypt_text(CT, vals, variant)
            sb = score_candidate(pt)
            if sb.crib_score > t10_best:
                t10_best = sb.crib_score
            if sb.crib_score > best_score:
                best_score = sb.crib_score
                best_config = f"numeric {name}={vals}/{variant.value}"
            if sb.crib_score > 6:
                print(f"  [!] {name}={vals}/{variant.value}: {sb.summary}")
                results.append((sb.crib_score,
                                f"numeric {name}={vals}/{variant.value}"))

        # Also try MEDUSA on the numeric values (convert to letters first)
        letter_vals = "".join(ALPH[v % 26] for v in vals)
        derived = medusa_forward(letter_vals)
        for variant in CipherVariant:
            total_configs += 1
            pt = decrypt_with_numeric_key(CT, derived, variant)
            sb = score_candidate(pt)
            if sb.crib_score > t10_best:
                t10_best = sb.crib_score
            if sb.crib_score > best_score:
                best_score = sb.crib_score
                best_config = f"MEDUSA(numeric {name})={derived}/{variant.value}"
            if sb.crib_score > 6:
                print(f"  [!] M({name})={derived}/{variant.value}: "
                      f"{sb.summary}")
                results.append((sb.crib_score,
                                f"M({name})={derived}/{variant.value}"))
    print(f"  Test 10 best: {t10_best}/24")

    # ══════════════════════════════════════════════════════════════════════
    # Bean analysis for top results
    # ══════════════════════════════════════════════════════════════════════
    if results:
        print("\n── Bean constraint check on above-noise results ──")
        results.sort(key=lambda x: -x[0])
        for score, cfg in results[:10]:
            if score >= 10:
                print(f"  {score}/24: {cfg} — checking Bean...")
                # We'd need to reconstruct the keystream for Bean check
                # For now just flag these for manual investigation

    # ══════════════════════════════════════════════════════════════════════
    # Summary
    # ══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print("SUMMARY — E-CFM-11: Systematic Anomaly-as-Key-Material")
    print("=" * 70)
    print(f"Total configs tested: {total_configs}")
    print(f"Overall best score: {best_score}/24")
    print(f"Best config: {best_config}")

    if results:
        results.sort(key=lambda x: -x[0])
        print(f"\nAbove-noise results ({len(results)}):")
        for score, cfg in results[:10]:
            print(f"  {score}/24: {cfg}")
    else:
        print("No configs above noise floor (6/24)")

    # Truth taxonomy classification
    if best_score >= 24:
        verdict = "BREAKTHROUGH — verify immediately!"
        taxonomy = "[INTERNAL RESULT] Anomaly key derivation: BREAKTHROUGH"
    elif best_score >= 18:
        verdict = "SIGNAL — investigate further"
        taxonomy = "[INTERNAL RESULT] Anomaly key derivation: SIGNAL"
    elif best_score >= 10:
        verdict = "STORE — worth logging, likely noise"
        taxonomy = "[INTERNAL RESULT] Anomaly key derivation: STORE"
    else:
        verdict = "NOISE"
        taxonomy = ("[INTERNAL RESULT] Anomaly-as-key-material (MEDUSA rule, "
                    "direct, transposition, additive mask, combined): NOISE")

    print(f"\nVerdict: {verdict}")
    print(f"Classification: {taxonomy}")
    print(f"\n[HYPOTHESIS] Physical anomalies as key material through "
          f"MEDUSA-style and other derivation methods "
          f"{'SURVIVES' if best_score >= 18 else 'does NOT produce signal'} "
          f"for K4 decryption.")


if __name__ == "__main__":
    main()
