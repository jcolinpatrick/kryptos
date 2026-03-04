#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-120: Misspelling-derived parameter tests for K4.

Tests all misspelling-derived artifacts as K4 parameters:
  (a) Wrong letters [C,Q,U,A,E] as Vigenère key (period 5)
  (b) Wrong letters [Q,U,A,E,L] (with tableau L) as key (period 5)
  (c) EQUAL as keyword → keyed alphabet or Vigenère key
  (d) Error positions [7,2,10,5,4] as columnar key order
  (e) Error positions as skip/decimation sequence
  (f) DESPARATLY positions 5,8 as grid dimensions
  (g) Combined: misspelling key + w7 columnar
  (h) Cross-section consistency test: do positions encode a single parameter type?

Stage 3 of Progressive Solve Plan.
"""
import json
import itertools
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT, N_CRIBS,
    NOISE_FLOOR, KRYPTOS_ALPHABET,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text,
)
from kryptos.kernel.transforms.transposition import (
    columnar_perm, apply_perm, invert_perm, keyword_to_order,
)
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.scoring.ic import ic


# ── Misspelling Data ────────────────────────────────────────────────────

# Wrong letters (engraved instead of correct)
WRONG_LETTERS_NO_L = "CQUAE"  # C (PALIMPCEST), Q (IQLUSION), U (UNDERGRUUND), A (DESPARATLY), E (DIGETAL)
WRONG_LETTERS_WITH_L = "QUAEL"  # Excluding C, including tableau extra L

# EQUAL anagram of Q,U,A,E,L
EQUAL = "EQUAL"

# Correct letters that should have been there
CORRECT_LETTERS = "SLOEI"  # S, L, O, E, I

# Error positions within respective words (0-indexed within word)
ERROR_POSITIONS = [7, 2, 10, 5, 4]  # PALIMPCEST pos7, IQLUSION pos2, UNDERGRUUND pos10, DESPARATLY pos5, DIGETAL pos4

# DESPARATLY specific: errors at word positions 5 and 8
DESPARATLY_POSITIONS = [5, 8]


def make_key_from_letters(letters):
    """Convert letter string to numeric key (A=0)."""
    return [ALPH_IDX[c] for c in letters.upper()]


def make_keyed_alphabet(keyword):
    """Build keyed alphabet from keyword (standard method)."""
    seen = set()
    alphabet = []
    for c in keyword.upper():
        if c not in seen:
            seen.add(c)
            alphabet.append(c)
    for c in ALPH:
        if c not in seen:
            seen.add(c)
            alphabet.append(c)
    return "".join(alphabet)


def decrypt_with_mixed_alphabet(ct, alphabet, key, variant=CipherVariant.VIGENERE):
    """Decrypt using a mixed alphabet for the substitution tableau."""
    alph_idx = {c: i for i, c in enumerate(alphabet)}
    from kryptos.kernel.transforms.vigenere import DECRYPT_FN
    fn = DECRYPT_FN[variant]
    klen = len(key)
    result = []
    for i, c in enumerate(ct):
        c_idx = alph_idx.get(c, ord(c) - 65)
        p_idx = fn(c_idx, key[i % klen])
        result.append(alphabet[p_idx % 26])
    return "".join(result)


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-S-120: Misspelling-Derived Parameter Tests")
    print("=" * 70)

    results = []
    best_overall = 0
    total_tested = 0

    # ── Test 1: Wrong letters as Vigenère key ────────────────────────────
    print("\n--- Test 1: Wrong letters as Vigenère key ---")
    letter_keys = {
        "CQUAE": make_key_from_letters("CQUAE"),
        "QUAEL": make_key_from_letters("QUAEL"),
        "EQUAL": make_key_from_letters("EQUAL"),
        "SLOEI": make_key_from_letters("SLOEI"),  # Correct letters
        "CQUAE_reversed": make_key_from_letters("EAUQC"),
        "QUAEL_reversed": make_key_from_letters("LEAUQ"),
    }

    for key_name, key in letter_keys.items():
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
            pt = decrypt_text(CT, key, variant)
            sc = score_cribs(pt)
            total_tested += 1
            if sc > best_overall:
                best_overall = sc
            if sc > NOISE_FLOOR:
                results.append({
                    "test": "letters_as_key",
                    "key_name": key_name,
                    "key": key,
                    "variant": variant.value,
                    "score": sc,
                    "pt_snippet": pt[:40],
                })
            print(f"  {key_name} ({variant.value}): {sc}/24")

    # ── Test 2: Error positions as columnar key order ────────────────────
    print("\n--- Test 2: Error positions as parameters ---")

    # Positions [7,2,10,5,4] — need to map to a valid columnar order
    # As a width-5 key order: the positions rank to [3,1,4,2,0] (sorted indices)
    pos_sorted = sorted(range(len(ERROR_POSITIONS)), key=lambda i: ERROR_POSITIONS[i])
    order_from_positions = [0] * len(ERROR_POSITIONS)
    for rank, idx in enumerate(pos_sorted):
        order_from_positions[idx] = rank
    print(f"  Error positions {ERROR_POSITIONS} → columnar order: {order_from_positions}")

    # Test as width-5 columnar
    perm = columnar_perm(5, order_from_positions, CT_LEN)
    inv = invert_perm(perm)
    ct_untrans = apply_perm(CT, inv)
    for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
        for kw_name, kw in [("none", [0]), ("KRYPTOS", make_key_from_letters("KRYPTOS")),
                            ("PALIMPCEST", make_key_from_letters("PALIMPCEST")),
                            ("ABSCISSA", make_key_from_letters("ABSCISSA")),
                            ("EQUAL", make_key_from_letters("EQUAL"))]:
            pt = decrypt_text(ct_untrans, kw, variant)
            sc = score_cribs(pt)
            total_tested += 1
            if sc > best_overall:
                best_overall = sc
            if sc > NOISE_FLOOR:
                results.append({
                    "test": "positions_as_columnar",
                    "col_order": order_from_positions,
                    "keyword": kw_name,
                    "variant": variant.value,
                    "score": sc,
                })
        print(f"  w5 columnar + {variant.value}: tested")

    # Test as width-5 columnar with the raw positions as order
    raw_order = [p % 5 for p in ERROR_POSITIONS]
    print(f"  Raw positions mod 5: {raw_order}")

    # ── Test 3: DESPARATLY positions 5,8 as grid dimensions ──────────────
    print("\n--- Test 3: DESPARATLY positions 5,8 as K4 parameters ---")

    for width in [5, 8]:
        # Test all orderings for this width
        # Width 5: 120 orderings, Width 8: 40320 orderings (sample)
        if width <= 6:
            orderings = list(itertools.permutations(range(width)))
        else:
            # Sample 5040 orderings for width 8
            import random
            random.seed(42)
            orderings = [tuple(random.sample(range(width), width)) for _ in range(5040)]
            # Also include natural order and reverse
            orderings.append(tuple(range(width)))
            orderings.append(tuple(range(width-1, -1, -1)))

        best_for_width = 0
        for col_order in orderings:
            perm = columnar_perm(width, list(col_order), CT_LEN)
            inv = invert_perm(perm)
            ct_untrans = apply_perm(CT, inv)

            # Direct (no substitution)
            sc_direct = score_cribs(ct_untrans)
            total_tested += 1
            if sc_direct > best_for_width:
                best_for_width = sc_direct

            # With keyword substitution
            for kw_name, kw in [("KRYPTOS", make_key_from_letters("KRYPTOS")),
                                ("EQUAL", make_key_from_letters("EQUAL")),
                                ("CQUAE", make_key_from_letters("CQUAE"))]:
                for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                    pt = decrypt_text(ct_untrans, kw, variant)
                    sc = score_cribs(pt)
                    total_tested += 1
                    if sc > best_for_width:
                        best_for_width = sc
                    if sc > NOISE_FLOOR:
                        results.append({
                            "test": f"desparatly_w{width}",
                            "col_order": list(col_order),
                            "keyword": kw_name,
                            "variant": variant.value,
                            "score": sc,
                        })

        if best_for_width > best_overall:
            best_overall = best_for_width
        print(f"  Width {width}: best={best_for_width}/24 ({len(orderings)} orderings tested)")

    # ── Test 4: Misspelling letters as key + w7 columnar ────────────────
    print("\n--- Test 4: Misspelling keys + w7 columnar (sampling) ---")
    import random
    random.seed(117)

    # Sample 1000 w7 orderings
    w7_sample = [tuple(random.sample(range(7), 7)) for _ in range(1000)]
    w7_sample.append(tuple(range(7)))
    w7_sample.append(tuple(range(6, -1, -1)))

    phase4_best = 0
    for key_name, key in letter_keys.items():
        key_best = 0
        for col_order in w7_sample:
            perm = columnar_perm(7, list(col_order), CT_LEN)
            inv = invert_perm(perm)
            ct_untrans = apply_perm(CT, inv)

            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt = decrypt_text(ct_untrans, key, variant)
                sc = score_cribs(pt)
                total_tested += 1
                if sc > key_best:
                    key_best = sc
                if sc > NOISE_FLOOR:
                    results.append({
                        "test": "misspelling_w7",
                        "key_name": key_name,
                        "col_order": list(col_order),
                        "variant": variant.value,
                        "score": sc,
                    })

        if key_best > phase4_best:
            phase4_best = key_best
        print(f"  {key_name}: best={key_best}/24")

    if phase4_best > best_overall:
        best_overall = phase4_best

    # ── Test 5: EQUAL as keyed alphabet ──────────────────────────────────
    print("\n--- Test 5: EQUAL as keyed alphabet ---")
    equal_alphabet = make_keyed_alphabet("EQUAL")
    print(f"  EQUAL-keyed alphabet: {equal_alphabet}")

    # Use EQUAL-keyed alphabet for substitution
    for kw_name, kw in [("KRYPTOS", make_key_from_letters("KRYPTOS")),
                        ("ABSCISSA", make_key_from_letters("ABSCISSA")),
                        ("COORD_MOD26", [v % MOD for v in [38, 57, 6, 5, 77, 8, 44]])]:
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
            pt = decrypt_with_mixed_alphabet(CT, equal_alphabet, kw, variant)
            sc = score_cribs(pt)
            total_tested += 1
            if sc > best_overall:
                best_overall = sc
            if sc > NOISE_FLOOR:
                results.append({
                    "test": "equal_keyed_alphabet",
                    "keyword": kw_name,
                    "variant": variant.value,
                    "score": sc,
                })
            print(f"  EQUAL alphabet + {kw_name} ({variant.value}): {sc}/24")

    # ── Test 6: Cross-section consistency ────────────────────────────────
    print("\n--- Test 6: Cross-section consistency analysis ---")
    print(f"  Error positions in words: {ERROR_POSITIONS}")
    print(f"  Wrong letters: C({ALPH_IDX['C']}), Q({ALPH_IDX['Q']}), U({ALPH_IDX['U']}), A({ALPH_IDX['A']}), E({ALPH_IDX['E']})")
    print(f"  Wrong letter ordinals: {[ALPH_IDX[c] for c in 'CQUAE']}")
    print(f"  Correct letter ordinals: {[ALPH_IDX[c] for c in 'SLOEI']}")
    print(f"  Differences (wrong - correct): {[(ALPH_IDX[w] - ALPH_IDX[c]) % 26 for w, c in zip('CQUAE', 'SLOEI')]}")

    diffs = [(ALPH_IDX[w] - ALPH_IDX[c]) % 26 for w, c in zip('CQUAE', 'SLOEI')]
    print(f"  Shift values: {diffs}")

    # Test shift values as key
    for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
        pt = decrypt_text(CT, diffs, variant)
        sc = score_cribs(pt)
        total_tested += 1
        if sc > best_overall:
            best_overall = sc
        print(f"  Shift-as-key ({variant.value}): {sc}/24")
        if sc > NOISE_FLOOR:
            results.append({
                "test": "shift_values_as_key",
                "key": diffs,
                "variant": variant.value,
                "score": sc,
            })

    # ── Summary ──────────────────────────────────────────────────────────
    elapsed = time.time() - t0
    print(f"\n{'=' * 70}")
    print(f"SUMMARY (elapsed: {elapsed:.1f}s)")
    print(f"{'=' * 70}")
    print(f"Total configs tested: {total_tested}")
    print(f"Global best score: {best_overall}/24")
    print(f"Results above noise: {len(results)}")

    if results:
        print("\nTop results (above noise):")
        for r in sorted(results, key=lambda x: -x["score"])[:10]:
            print(f"  score={r['score']}/24 {r['test']}")

    verdict = "SIGNAL" if best_overall >= 18 else ("STORE" if best_overall > NOISE_FLOOR else "NOISE")
    print(f"\nVERDICT: {verdict}")

    # Write artifacts
    artifact = {
        "experiment_id": "e_s_120",
        "stage": 3,
        "hypothesis": "Misspelling-derived parameters encode K4 key material",
        "parameters_source": "K0-K3 misspellings",
        "total_tested": total_tested,
        "best_score": best_overall,
        "above_noise_count": len(results),
        "above_noise": results[:50],
        "verdict": verdict,
        "runtime_seconds": elapsed,
        "repro_command": "PYTHONPATH=src python3 -u scripts/e_s_120_desparatly_test.py",
    }

    out_path = "artifacts/progressive_solve/stage3/desparatly_test_results.json"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(artifact, f, indent=2, default=str)
    print(f"\nArtifacts written to {out_path}")


if __name__ == "__main__":
    main()
