#!/usr/bin/env python3
"""E-TEAM-ARTIFACT-KEYS: Test ~500 artifact-derived values as keys for K4.

Tests date keys, coordinate keys, string keywords, YAR-derived keys,
and numeric sequences as Vigenere/Beaufort/VarBeau keys. Also tests
string keywords as columnar transposition keys combined with shift decryption.

Results saved to results/e_team_artifact_keys.json.
"""
import sys, os, json, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, N_CRIBS,
    CRIB_DICT, CRIB_POSITIONS,
    BEAN_EQ, BEAN_INEQ,
    KRYPTOS_ALPHABET,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text,
)
from kryptos.kernel.transforms.transposition import (
    apply_perm, invert_perm, columnar_perm, keyword_to_order,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.constraints.bean import verify_bean

VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]

# ── Key generators ────────────────────────────────────────────────────────

def digits_to_key(digits_str: str) -> list[int]:
    """Convert digit string to key values mod 26."""
    return [int(d) % MOD for d in digits_str]

def string_to_key(s: str) -> list[int]:
    """Convert string to numeric key (A=0, B=1, ...)."""
    return [ALPH_IDX[c] for c in s.upper() if c in ALPH_IDX]

def repeat_key(key: list[int], length: int = CT_LEN) -> list[int]:
    """Repeat/truncate key to specified length."""
    if not key:
        return [0] * length
    return [key[i % len(key)] for i in range(length)]

# ── Date keys ──────────────────────────────────────────────────────────────

DATE_STRINGS = [
    "1986", "1989", "11091989", "03111990", "05261987",
    "08082025", "19870526", "19891109", "19900311", "20250808",
    "1990", "2025", "07041776", "17760704", "19860101",
    "11031990",  # Kryptos dedication Nov 3 1990
]

# ── Coordinate keys ───────────────────────────────────────────────────────

COORD_STRINGS = [
    "389517", "771467", "5252", "13405", "2574", "3260",
    "38955177146752521340525743260",  # all coords concatenated
]

# ── String keywords ───────────────────────────────────────────────────────

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "LAYERTWO", "IDBYROWS",
    "SHADOW", "IQLUSION", "DESPARATLY", "BERLIN", "CLOCK",
    "WELTZEITUHR", "EASTNORTHEAST", "BERLINCLOCK", "SANBORN",
    "SCHEIDT", "WEBSTER", "DRUSILLA", "NORTHEASTEAST", "EGYPT",
    "PHARAOH", "CARTER", "TUTANKHAMUN", "ALEXANDERPLATZ",
    "HIRSHHORN", "ANTIPODES", "SMITHSONIAN", "LANGLEY",
    "LUCIFER", "UNDERGRUUND", "UNDERGROUND", "DIGETAL",
    "VIRTUALLY", "INVISIBLE", "SLOWLY",
    "ILLUSION", "SHADOWFORCES", "BETWEENSUBTLE",
    "XLAYERTWO", "NYPVTT", "DYAHR",
    # Weltzeituhr 24 cities
    "LONDON", "TOKYO", "MOSCOW", "PARIS", "CAIRO",
    "NEWYORK", "DELHI", "ROME", "BEIJING", "ANKARA",
    "ACCRA", "ALGIERS", "DHAKA", "HAVANA", "KABUL",
    "LAGOS", "MONROVIA", "WINDHOEK", "KARACHI", "TEHRAN",
    "TASHKENT", "JAKARTA", "PETROPAVLOVSK", "HONOLULU",
]
# Deduplicate
KEYWORDS = list(dict.fromkeys(KEYWORDS))

# ── YAR-derived ───────────────────────────────────────────────────────────

YAR_KEY = [24, 0, 17]  # Y=24, A=0, R=17

# ── Numeric sequences ─────────────────────────────────────────────────────

def fibonacci_key(length: int = CT_LEN) -> list[int]:
    """Fibonacci sequence mod 26."""
    key = [1, 1]
    while len(key) < length:
        key.append((key[-1] + key[-2]) % MOD)
    return key[:length]

def primes_key(length: int = CT_LEN) -> list[int]:
    """Prime numbers mod 26."""
    actual_primes = []
    result = []
    n = 2
    while len(result) < length:
        if all(n % p != 0 for p in actual_primes if p * p <= n):
            actual_primes.append(n)
            result.append(n % MOD)
        n += 1
    return result

def prime_indices_key(length: int = CT_LEN) -> list[int]:
    """Index of each prime mod 26 (1st prime=0, 2nd=1, etc.)."""
    return [i % MOD for i in range(length)]

# ── Main experiment ───────────────────────────────────────────────────────

def main():
    start_time = time.time()
    results = []
    best_score = 0
    best_result = None
    configs_tested = 0

    def test_key(key_list: list[int], key_name: str, category: str):
        nonlocal best_score, best_result, configs_tested
        key_97 = repeat_key(key_list, CT_LEN)
        bean = verify_bean(key_97)

        for variant in VARIANTS:
            configs_tested += 1
            pt = decrypt_text(CT, key_97, variant)
            sc = score_candidate(pt, bean)
            score = sc.crib_score

            entry = {
                "key_name": key_name,
                "category": category,
                "variant": variant.value,
                "key_len": len(key_list),
                "key_preview": key_list[:20],
                "crib_score": score,
                "bean_passed": sc.bean_passed,
                "ic": round(sc.ic_value, 4),
                "classification": sc.crib_classification,
                "plaintext_preview": pt[:40],
            }

            if score >= 6:
                results.append(entry)
                print(f"  [ABOVE NOISE] {key_name} / {variant.value}: {sc.summary}")

            if score > best_score:
                best_score = score
                best_result = entry
                if score >= 10:
                    print(f"  ** STORE-WORTHY: {key_name} / {variant.value}: {sc.summary}")

    # ── 1. Date keys ──────────────────────────────────────────────────────
    print("=" * 70)
    print("Phase 1: Date keys")
    print("=" * 70)
    for ds in DATE_STRINGS:
        key = digits_to_key(ds)
        test_key(key, f"date_{ds}", "date")

    # ── 2. Coordinate keys ────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("Phase 2: Coordinate keys")
    print("=" * 70)
    for cs in COORD_STRINGS:
        key = digits_to_key(cs)
        test_key(key, f"coord_{cs}", "coordinate")

    # ── 3. String keywords ────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("Phase 3: String keywords as Vigenere keys")
    print("=" * 70)
    for kw in KEYWORDS:
        key = string_to_key(kw)
        test_key(key, f"kw_{kw}", "keyword")

    # ── 3b. Compass / facet / Webster / DESPARATLY keys ─────────────────
    print("\n" + "=" * 70)
    print("Phase 3b: Compass, facet, Webster, DESPARATLY keys")
    print("=" * 70)
    sys.stdout.flush()
    # Compass: 67.5 degrees = ENE direction
    test_key(digits_to_key("675"), "compass_675", "compass")
    test_key(digits_to_key("6750"), "compass_6750", "compass")
    test_key([6, 7, 5], "compass_ints_675", "compass")
    # Facet numbers 0-23 repeated
    test_key(list(range(24)), "facets_0_23", "facet")
    test_key(list(range(23, -1, -1)), "facets_23_0_rev", "facet")
    # Webster: 97 as shift (already 97%26=19), service dates
    test_key([19], "webster_97mod26", "webster")
    test_key([97 % MOD], "const_97", "webster")
    test_key(digits_to_key("97"), "webster_97_digits", "webster")
    test_key(digits_to_key("4"), "webster_4yr_service", "webster")
    test_key(digits_to_key("497"), "webster_4yr_97day", "webster")
    # DESPARATLY: positions 5, 8 as offsets
    test_key([5], "desparatly_pos5", "desparatly")
    test_key([8], "desparatly_pos8", "desparatly")
    test_key([5, 8], "desparatly_58", "desparatly")
    test_key([8, 5], "desparatly_85", "desparatly")

    # ── 4. YAR-derived ────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("Phase 4: YAR-derived keys")
    print("=" * 70)
    test_key(YAR_KEY, "YAR_repeat", "yar")
    # Also try YAR reversed, doubled, etc.
    test_key([17, 0, 24], "RAY_repeat", "yar")
    test_key([24, 0, 17, 17, 0, 24], "YAR_RAY", "yar")
    test_key([24, 0, 17, 24, 0, 17, 24, 0, 17], "YAR_x3", "yar")
    # YAR as offsets into Bean-surviving periods
    for period in [8, 13, 16, 19, 20, 23, 24, 26]:
        yar_period_key = [24, 0, 17] * ((period // 3) + 1)
        yar_period_key = yar_period_key[:period]
        test_key(yar_period_key, f"YAR_period{period}", "yar_period")

    # ── 5. Numeric sequences ──────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("Phase 5: Numeric sequences")
    print("=" * 70)
    test_key([97 % MOD] * CT_LEN, "const_97mod26", "numeric")
    test_key(fibonacci_key(), "fibonacci_mod26", "numeric")
    test_key(primes_key(), "primes_mod26", "numeric")
    test_key(prime_indices_key(), "prime_indices_mod26", "numeric")
    test_key(list(range(CT_LEN)), "sequential_0_96", "numeric")
    test_key(list(range(CT_LEN - 1, -1, -1)), "reverse_sequential", "numeric")
    # Triangular numbers mod 26
    tri = [(n * (n + 1) // 2) % MOD for n in range(CT_LEN)]
    test_key(tri, "triangular_mod26", "numeric")
    # Powers of 2 mod 26
    pow2 = [(2**n) % MOD for n in range(CT_LEN)]
    test_key(pow2, "powers_of_2_mod26", "numeric")

    print(f"  Phase 5 done. Configs so far: {configs_tested}")
    sys.stdout.flush()

    # ── 6. Keyword combinations (concatenated) ────────────────────────────
    print("\n" + "=" * 70)
    print("Phase 6: Keyword combinations")
    print("=" * 70)
    sys.stdout.flush()
    combos = [
        ("KRYPTOS_PALIMPSEST", "KRYPTOS" + "PALIMPSEST"),
        ("KRYPTOS_ABSCISSA", "KRYPTOS" + "ABSCISSA"),
        ("PALIMPSEST_ABSCISSA", "PALIMPSEST" + "ABSCISSA"),
        ("KRYPTOS_SANBORN", "KRYPTOS" + "SANBORN"),
        ("SANBORN_SCHEIDT", "SANBORN" + "SCHEIDT"),
        ("BERLIN_CLOCK", "BERLIN" + "CLOCK"),
        ("EAST_NORTH_EAST", "EAST" + "NORTH" + "EAST"),
        ("SHADOW_FORCES", "SHADOW" + "FORCES"),
        ("KRYPTOS_BERLIN", "KRYPTOS" + "BERLIN"),
        ("KRYPTOS_WEBSTER", "KRYPTOS" + "WEBSTER"),
        ("LANGLEY_KRYPTOS", "LANGLEY" + "KRYPTOS"),
        ("ABSCISSA_LAYERTWO", "ABSCISSA" + "LAYERTWO"),
        ("KRYPTOS_IQLUSION", "KRYPTOS" + "IQLUSION"),
    ]
    for name, combo in combos:
        key = string_to_key(combo)
        test_key(key, f"combo_{name}", "combination")

    print(f"  Phase 6 done. Configs so far: {configs_tested}")
    sys.stdout.flush()

    # ── 7. Kryptos alphabet as key ────────────────────────────────────────
    print("\n" + "=" * 70)
    print("Phase 7: Kryptos alphabet as key")
    print("=" * 70)
    sys.stdout.flush()
    ka_key = string_to_key(KRYPTOS_ALPHABET)
    test_key(ka_key, "KA_alphabet", "alphabet")
    # Standard alphabet
    az_key = list(range(26))
    test_key(az_key, "AZ_alphabet", "alphabet")
    # Reversed KA
    test_key(list(reversed(ka_key)), "KA_reversed", "alphabet")

    print(f"  Phase 7 done. Configs so far: {configs_tested}")
    sys.stdout.flush()

    # ── 8. Columnar transposition + shift decryption ──────────────────────
    print("\n" + "=" * 70)
    print("Phase 8: Keyword columnar transposition + Caesar shifts")
    print("=" * 70)
    sys.stdout.flush()
    trans_results = []
    for kw in KEYWORDS:
        width = len(kw)
        if width < 5 or width > 15:
            continue
        order = keyword_to_order(kw, width)
        if order is None:
            continue
        perm = columnar_perm(width, order, CT_LEN)
        inv = invert_perm(perm)
        intermediate = apply_perm(CT, inv)

        for shift in range(26):
            key_list = [shift] * CT_LEN
            for variant in VARIANTS:
                configs_tested += 1
                pt = decrypt_text(intermediate, key_list, variant)
                sc = score_candidate(pt)
                score = sc.crib_score

                if score >= 6:
                    entry = {
                        "key_name": f"trans_{kw}_shift{shift}",
                        "category": "trans+shift",
                        "variant": variant.value,
                        "width": width,
                        "shift": shift,
                        "keyword": kw,
                        "crib_score": score,
                        "bean_passed": sc.bean_passed,
                        "ic": round(sc.ic_value, 4),
                        "classification": sc.crib_classification,
                        "plaintext_preview": pt[:40],
                    }
                    trans_results.append(entry)
                    results.append(entry)
                    print(f"  [ABOVE NOISE] trans_{kw}_shift{shift}/{variant.value}: {sc.summary}")

                if score > best_score:
                    best_score = score
                    best_result = entry
                    if score >= 10:
                        print(f"  ** STORE-WORTHY: trans_{kw}_shift{shift}/{variant.value}: {sc.summary}")

    print(f"  Phase 8 done. Configs so far: {configs_tested}")
    sys.stdout.flush()

    # ── 9. Keyword columnar transposition + keyword Vigenere ──────────────
    print("\n" + "=" * 70)
    print("Phase 9: Keyword columnar transposition + keyword Vigenere")
    print("=" * 70)
    sys.stdout.flush()
    # Use each keyword as both transposition key and substitution key
    for trans_kw in KEYWORDS:
        t_width = len(trans_kw)
        if t_width < 5 or t_width > 15:
            continue
        t_order = keyword_to_order(trans_kw, t_width)
        if t_order is None:
            continue
        t_perm = columnar_perm(t_width, t_order, CT_LEN)
        t_inv = invert_perm(t_perm)
        intermediate = apply_perm(CT, t_inv)

        for sub_kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SANBORN", "SCHEIDT",
                        "BERLIN", "CLOCK", "WEBSTER", "SHADOW", "LAYERTWO"]:
            sub_key = repeat_key(string_to_key(sub_kw), CT_LEN)
            for variant in VARIANTS:
                configs_tested += 1
                pt = decrypt_text(intermediate, sub_key, variant)
                sc = score_candidate(pt)
                score = sc.crib_score

                if score >= 6:
                    entry = {
                        "key_name": f"trans_{trans_kw}_sub_{sub_kw}",
                        "category": "trans+keyword",
                        "variant": variant.value,
                        "trans_keyword": trans_kw,
                        "sub_keyword": sub_kw,
                        "crib_score": score,
                        "bean_passed": sc.bean_passed,
                        "ic": round(sc.ic_value, 4),
                        "classification": sc.crib_classification,
                        "plaintext_preview": pt[:40],
                    }
                    results.append(entry)
                    print(f"  [ABOVE NOISE] trans_{trans_kw}+{sub_kw}/{variant.value}: {sc.summary}")

                if score > best_score:
                    best_score = score
                    best_result = entry
                    if score >= 10:
                        print(f"  ** STORE-WORTHY: trans_{trans_kw}+{sub_kw}/{variant.value}: {sc.summary}")

    # ── 10. Bean-surviving period testing ─────────────────────────────────
    print("\n" + "=" * 70)
    print("Phase 10: Keywords at Bean-surviving periods {8,13,16,19,20,23,24,26}")
    print("=" * 70)
    sys.stdout.flush()
    BEAN_PERIODS = [8, 13, 16, 19, 20, 23, 24, 26]
    # For each keyword, truncate/pad to each Bean-surviving period length
    test_kws = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "LAYERTWO", "SANBORN",
                 "SCHEIDT", "WEBSTER", "BERLIN", "SHADOW", "CLOCK",
                 "WELTZEITUHR", "DRUSILLA", "IQLUSION", "DESPARATLY",
                 "CARTER", "EGYPT", "PHARAOH", "ANTIPODES",
                 "LONDON", "TOKYO", "MOSCOW", "PARIS", "CAIRO"]
    for kw in test_kws:
        kw_nums = string_to_key(kw)
        for period in BEAN_PERIODS:
            # Truncate or repeat keyword to exactly period length
            key_at_period = repeat_key(kw_nums, period)
            key_97 = repeat_key(key_at_period, CT_LEN)
            bean = verify_bean(key_97)
            for variant in VARIANTS:
                configs_tested += 1
                pt = decrypt_text(CT, key_97, variant)
                sc = score_candidate(pt, bean)
                score = sc.crib_score
                if score >= 6:
                    entry = {
                        "key_name": f"bean_p{period}_{kw}",
                        "category": "bean_period",
                        "variant": variant.value,
                        "period": period,
                        "keyword": kw,
                        "crib_score": score,
                        "bean_passed": sc.bean_passed,
                        "ic": round(sc.ic_value, 4),
                        "classification": sc.crib_classification,
                        "plaintext_preview": pt[:40],
                    }
                    results.append(entry)
                    print(f"  [ABOVE NOISE] bean_p{period}_{kw}/{variant.value}: {sc.summary}")
                if score > best_score:
                    best_score = score
                    best_result = {
                        "key_name": f"bean_p{period}_{kw}",
                        "category": "bean_period",
                        "variant": variant.value,
                        "period": period,
                        "keyword": kw,
                        "crib_score": score,
                        "bean_passed": sc.bean_passed,
                        "ic": round(sc.ic_value, 4),
                        "classification": sc.crib_classification,
                        "plaintext_preview": pt[:40],
                    }
                    if score >= 10:
                        print(f"  ** STORE-WORTHY: bean_p{period}_{kw}/{variant.value}: {sc.summary}")

    print(f"  Phase 10 done. Configs so far: {configs_tested}")
    sys.stdout.flush()

    # ── Summary ───────────────────────────────────────────────────────────
    elapsed = time.time() - start_time
    print("\n" + "=" * 70)
    print(f"FINAL SUMMARY — E-TEAM-ARTIFACT-KEYS")
    print("=" * 70)
    print(f"Configs tested: {configs_tested}")
    print(f"Above noise (>=6): {len(results)}")
    store_worthy = [r for r in results if r['crib_score'] >= 10]
    print(f"Store-worthy (>=10): {len(store_worthy)}")
    signal = [r for r in results if r['crib_score'] >= 18]
    print(f"Signal (>=18): {len(signal)}")
    print(f"Best score: {best_score}/24")
    if best_result:
        print(f"Best config: {best_result['key_name']} / {best_result['variant']}")
        print(f"Best PT preview: {best_result['plaintext_preview']}")
    print(f"Elapsed: {elapsed:.1f}s")

    # ── Save ──────────────────────────────────────────────────────────────
    output = {
        "experiment": "e_team_artifact_keys",
        "configs_tested": configs_tested,
        "above_noise": len(results),
        "store_worthy": len(store_worthy),
        "best_score": best_score,
        "best_result": best_result,
        "elapsed_seconds": round(elapsed, 1),
        "all_above_noise": sorted(results, key=lambda x: -x["crib_score"]),
    }

    out_path = os.path.join(os.path.dirname(__file__), "..", "results", "e_team_artifact_keys.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {out_path}")

    # Verdict
    if best_score >= 18:
        print("\n*** SIGNAL DETECTED — investigate immediately ***")
    elif best_score >= 10:
        print("\n** INTERESTING — worth further analysis **")
    else:
        print("\nVerdict: NOISE — no artifact-derived key produces meaningful crib matches")


if __name__ == "__main__":
    main()
