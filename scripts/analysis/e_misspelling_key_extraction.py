#!/usr/bin/env python3
"""
Cipher: misspelling-derived key
Family: analysis
Status: active
Keyspace: ~50K (primers × extension rules × variants × with/without UNDERGRUUND)
Last run:
Best score:

P-F1-1 / P-F1-2 from docs/procedural_anomaly_recipes.md

Hypothesis: The deliberate misspellings on the Kryptos sculpture are WORKED
EXAMPLES of the encryption operation. Each wrong→correct letter pair is a
(CT, PT) example. Extracting the implied key value under Vig/Beau/VarBeau
gives a primer that, extended by some key-generation rule, produces the K4
keystream.

Misspellings (correct → wrong):
  PALIMPSEST → PALIMPCEST:  S → C
  ILLUSION   → IQLUSION:    L → Q
  UNDERGROUND→ UNDERGRUUND: O → U  (disputed: transcription error)
  DESPERATELY→ DESPARATLY:  E → A
  DIGITAL    → DIGETAL:      I → E

We treat "correct = PT" and "wrong = CT" and extract K under each variant.
"""

import sys
import os
from itertools import product

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, BEAN_EQ, BEAN_INEQ,
)
from kryptos.kernel.scoring.aggregate import score_candidate

# ── Misspelling pairs: (correct_letter, wrong_letter) ──────────────────

# Full set (including disputed UNDERGRUUND)
PAIRS_FULL = [
    ("S", "C"),  # PALIMPCEST
    ("L", "Q"),  # IQLUSION
    ("O", "U"),  # UNDERGRUUND (disputed)
    ("E", "A"),  # DESPARATLY
    ("I", "E"),  # DIGETAL
]

# Without UNDERGRUUND
PAIRS_NO_UG = [
    ("S", "C"),  # PALIMPCEST
    ("L", "Q"),  # IQLUSION
    ("E", "A"),  # DESPARATLY
    ("I", "E"),  # DIGETAL
]

def extract_keys(pairs, variant):
    """Extract key values from misspelling pairs under a cipher variant.

    We treat correct_letter = PT, wrong_letter = CT.

    Vigenère:        CT = (PT + K) mod 26  →  K = (CT - PT) mod 26
    Beaufort:        CT = (K - PT) mod 26  →  K = (CT + PT) mod 26
    Variant Beaufort: CT = (PT - K) mod 26  →  K = (PT - CT) mod 26
    """
    keys = []
    for pt_letter, ct_letter in pairs:
        p = ALPH_IDX[pt_letter]
        c = ALPH_IDX[ct_letter]
        if variant == "vig":
            k = (c - p) % MOD
        elif variant == "beau":
            k = (c + p) % MOD
        elif variant == "vbeau":
            k = (p - c) % MOD
        else:
            raise ValueError(f"Unknown variant: {variant}")
        keys.append(k)
    return keys


# ── Key extension rules ────────────────────────────────────────────────

def extend_repeat(primer, length):
    """Repeat the primer cyclically (periodic key)."""
    return [primer[i % len(primer)] for i in range(length)]


def extend_fibonacci(primer, length, modulus=26):
    """Fibonacci-like: k[i] = (k[i-1] + k[i-2]) mod m."""
    ks = list(primer)
    while len(ks) < length:
        ks.append((ks[-1] + ks[-2]) % modulus)
    return ks[:length]


def extend_chain_add(primer, length, tap=None, modulus=26):
    """Chain addition: k[i] = (k[i-1] + k[i-tap]) mod m.
    Default tap = len(primer) (lagged Fibonacci using full primer width).
    """
    if tap is None:
        tap = len(primer)
    ks = list(primer)
    while len(ks) < length:
        idx = len(ks)
        a = ks[idx - 1]
        b = ks[idx - tap] if idx >= tap else ks[idx - tap + len(primer)]
        ks.append((a + b) % modulus)
    return ks[:length]


def extend_chain_sum(primer, length, modulus=26):
    """Sum of all primer-width previous values: k[i] = sum(k[i-w:i]) mod m."""
    w = len(primer)
    ks = list(primer)
    while len(ks) < length:
        ks.append(sum(ks[-w:]) % modulus)
    return ks[:length]


def extend_autokey_pt(primer, plaintext_nums, length):
    """Autokey with plaintext: k[i] = PT[i - len(primer)] for i >= len(primer)."""
    ks = list(primer)
    while len(ks) < length:
        pt_idx = len(ks) - len(primer)
        if pt_idx < len(plaintext_nums):
            ks.append(plaintext_nums[pt_idx])
        else:
            break
    return ks[:length]


def extend_cumulative(primer, length, modulus=26):
    """Cumulative sum: k[i] = (k[i-1] + k[0] + i) mod m. Ad-hoc progressive."""
    ks = list(primer)
    while len(ks) < length:
        i = len(ks)
        ks.append((ks[-1] + ks[0] + i) % modulus)
    return ks[:length]


def extend_multiplicative(primer, length, modulus=26):
    """k[i] = (k[i-1] * k[i-2]) mod m. Multiplicative chain."""
    ks = list(primer)
    while len(ks) < length:
        ks.append((ks[-1] * ks[-2]) % modulus)
    return ks[:length]


def extend_difference(primer, length, modulus=26):
    """k[i] = (k[i-1] - k[i-2]) mod m. Difference chain."""
    ks = list(primer)
    while len(ks) < length:
        ks.append((ks[-1] - ks[-2]) % modulus)
    return ks[:length]


def extend_alternating_add_sub(primer, length, modulus=26):
    """k[i] = k[i-1] + k[i-2] if i even, k[i-1] - k[i-2] if i odd. mod m."""
    ks = list(primer)
    while len(ks) < length:
        i = len(ks)
        if i % 2 == 0:
            ks.append((ks[-1] + ks[-2]) % modulus)
        else:
            ks.append((ks[-1] - ks[-2]) % modulus)
    return ks[:length]


# ── Decryption ─────────────────────────────────────────────────────────

def decrypt(ct_nums, key, variant):
    """Decrypt ciphertext numbers with key under the given variant."""
    pt = []
    for i, c in enumerate(ct_nums):
        k = key[i] if i < len(key) else 0
        if variant == "vig":
            p = (c - k) % MOD
        elif variant == "beau":
            p = (k - c) % MOD
        elif variant == "vbeau":
            p = (c + k) % MOD
        else:
            raise ValueError(f"Unknown variant: {variant}")
        pt.append(p)
    return pt


def nums_to_text(nums):
    return "".join(ALPH[n % MOD] for n in nums)


def check_bean(key):
    """Check Bean equality and inequality constraints against a keystream."""
    # Bean equality: k[27] == k[65]
    for a, b in BEAN_EQ:
        if a < len(key) and b < len(key):
            if key[a] != key[b]:
                return False, "eq_fail"

    # Bean inequalities
    ineq_pass = 0
    ineq_fail = 0
    for a, b in BEAN_INEQ:
        if a < len(key) and b < len(key):
            if key[a] != key[b]:
                ineq_pass += 1
            else:
                ineq_fail += 1

    if ineq_fail > 0:
        return False, f"ineq_fail({ineq_fail})"
    return True, "pass"


# ── Main sweep ─────────────────────────────────────────────────────────

def main():
    ct_nums = [ALPH_IDX[c] for c in CT]

    variants = ["vig", "beau", "vbeau"]
    pair_sets = [
        ("full_5", PAIRS_FULL),
        ("no_ug_4", PAIRS_NO_UG),
    ]

    # Also try reversed order of pairs and various permutations of the
    # "correct" ordering (maybe the order on the sculpture matters)
    # For now: canonical order, reversed order
    orderings = ["canonical", "reversed"]

    # Extension rules
    extension_rules = [
        ("repeat", lambda p, n: extend_repeat(p, n)),
        ("fib_mod26", lambda p, n: extend_fibonacci(p, n, 26)),
        ("fib_mod10", lambda p, n: extend_fibonacci(p, n, 10)),
        ("fib_mod21", lambda p, n: extend_fibonacci(p, n, 21)),
        ("fib_mod5", lambda p, n: extend_fibonacci(p, n, 5)),
        ("chain_tap2", lambda p, n: extend_chain_add(p, n, tap=2)),
        ("chain_tap3", lambda p, n: extend_chain_add(p, n, tap=3)),
        ("chain_tapW", lambda p, n: extend_chain_add(p, n)),  # tap=primer width
        ("chain_sum", lambda p, n: extend_chain_sum(p, n)),
        ("chain_sum_mod10", lambda p, n: extend_chain_sum(p, n, modulus=10)),
        ("cumulative", lambda p, n: extend_cumulative(p, n)),
        ("multiplicative", lambda p, n: extend_multiplicative(p, n)),
        ("difference", lambda p, n: extend_difference(p, n)),
        ("alt_add_sub", lambda p, n: extend_alternating_add_sub(p, n)),
    ]

    # Additional moduli for chain addition
    for mod in [5, 10, 21]:
        extension_rules.append(
            (f"chain_tapW_mod{mod}",
             lambda p, n, m=mod: extend_chain_add(p, n, modulus=m))
        )

    results = []
    tested = 0

    print("=" * 72)
    print("P-F1: Misspelling-Derived Key Extraction Test")
    print("=" * 72)

    for pair_name, pairs in pair_sets:
        for variant in variants:
            primer = extract_keys(pairs, variant)
            primer_letters = nums_to_text(primer)
            print(f"\n--- Primer: {pair_name} / {variant} = "
                  f"{primer} ({primer_letters}) ---")

            for ordering in orderings:
                if ordering == "reversed":
                    p = list(reversed(primer))
                else:
                    p = list(primer)

                for ext_name, ext_fn in extension_rules:
                    # Generate full keystream
                    try:
                        keystream = ext_fn(p, CT_LEN)
                    except (ZeroDivisionError, IndexError):
                        continue

                    if len(keystream) < CT_LEN:
                        continue

                    tested += 1

                    # Decrypt under the SAME variant used for extraction
                    pt_nums = decrypt(ct_nums, keystream, variant)
                    pt_text = nums_to_text(pt_nums)

                    # Also try decrypting under OTHER variants (the extraction
                    # variant might differ from the encryption variant)
                    for dec_variant in variants:
                        pt_nums_dv = decrypt(ct_nums, keystream, dec_variant)
                        pt_text_dv = nums_to_text(pt_nums_dv)

                        # Score
                        sb = score_candidate(pt_text_dv)

                        if sb.crib_score >= 4:
                            bean_ok, bean_msg = check_bean(keystream)
                            results.append({
                                "pair_set": pair_name,
                                "extract_variant": variant,
                                "decrypt_variant": dec_variant,
                                "ordering": ordering,
                                "extension": ext_name,
                                "primer": p,
                                "crib_score": sb.crib_score,
                                "bean": bean_msg,
                                "pt_preview": pt_text_dv[:40],
                                "ene": sb.ene_score,
                                "bc": sb.bc_score,
                            })

                        if sb.crib_score >= 6:
                            print(f"  ** {ext_name}/{ordering}/{dec_variant}: "
                                  f"crib={sb.crib_score}/24 "
                                  f"(ENE={sb.ene_score} BC={sb.bc_score}) "
                                  f"PT={pt_text_dv[:30]}...")

    # ── Also test: misspelling key values at their SOURCE positions ────
    # What if the key values apply at specific positions in K4, not as a
    # primer? E.g., key position 7 = K (from PALIMPCEST position 7)?
    print("\n" + "=" * 72)
    print("Phase 2: Position-specific key placement")
    print("=" * 72)

    # The misspellings come from specific positions in their source words.
    # PALIMPCEST: S→C at word position 7
    # IQLUSION:   L→Q at word position 2
    # UNDERGRUUND: O→U at word position 9 (or 10, depending on counting)
    # DESPARATLY: E→A at word position 5
    # DIGETAL:    I→E at word position 4
    #
    # Could these word positions be the K4 positions where the key values apply?
    source_positions_full = [7, 2, 9, 5, 4]
    source_positions_no_ug = [7, 2, 5, 4]

    for variant in variants:
        for pair_name, pairs, positions in [
            ("full_5", PAIRS_FULL, source_positions_full),
            ("no_ug_4", PAIRS_NO_UG, source_positions_no_ug),
        ]:
            keys = extract_keys(pairs, variant)
            key_letters = nums_to_text(keys)

            # Try placing these at the source positions and interpolating
            # between them
            print(f"\n  Positional: {pair_name}/{variant} "
                  f"keys={key_letters} at positions={positions}")

            # Create a sparse keystream with known values at these positions
            # then try linear interpolation
            known = dict(zip(positions, keys))

            # Method: fill the keystream by linear interpolation mod 26
            keystream = [0] * CT_LEN
            sorted_pos = sorted(known.keys())
            for i in range(CT_LEN):
                # Find nearest known positions
                if i in known:
                    keystream[i] = known[i]
                else:
                    # Simple repeat of nearest known
                    best_dist = CT_LEN
                    best_val = 0
                    for sp in sorted_pos:
                        if abs(i - sp) < best_dist:
                            best_dist = abs(i - sp)
                            best_val = known[sp]
                    keystream[i] = best_val

            for dec_variant in variants:
                pt_nums = decrypt(ct_nums, keystream, dec_variant)
                pt_text = nums_to_text(pt_nums)
                sb = score_candidate(pt_text)
                if sb.crib_score >= 4:
                    print(f"    {dec_variant}: crib={sb.crib_score}/24 "
                          f"PT={pt_text[:30]}...")

    # ── Phase 3: Use derived key values to CHECK against known keystream ──
    print("\n" + "=" * 72)
    print("Phase 3: Check derived primers against known crib keystream")
    print("=" * 72)

    # Known Beaufort A=0 keystream at crib positions (from constraint_spec.md)
    known_beau_ks = {
        21: 9, 22: 11, 23: 9, 24: 14, 25: 3, 26: 4, 27: 6,
        28: 10, 29: 20, 30: 10, 31: 10, 32: 10, 33: 11,
        63: 14, 64: 2, 65: 6, 66: 6, 67: 1, 68: 6, 69: 14,
        70: 10, 71: 19, 72: 17, 73: 20,
    }

    print("\nFor each primer + extension, checking if the generated keystream")
    print("matches the KNOWN values at crib positions (Beaufort A=0)...")

    best_match = 0
    best_config = None

    for pair_name, pairs in pair_sets:
        for variant in variants:
            primer = extract_keys(pairs, variant)

            for ordering in orderings:
                if ordering == "reversed":
                    p = list(reversed(primer))
                else:
                    p = list(primer)

                for ext_name, ext_fn in extension_rules:
                    try:
                        keystream = ext_fn(p, CT_LEN)
                    except (ZeroDivisionError, IndexError):
                        continue
                    if len(keystream) < CT_LEN:
                        continue

                    # Count matches at known positions
                    # We need to convert the keystream to Beaufort convention
                    # if the extraction was under a different variant
                    matches = 0
                    for pos, expected in known_beau_ks.items():
                        # The keystream values ARE variant-dependent.
                        # known_beau_ks is under Beaufort. If we extracted
                        # under Vigenère, k_vig = (CT-PT)%26 and
                        # k_beau = (CT+PT)%26. They're different numbers.
                        # So we compare against the variant-appropriate known
                        # keystream.
                        #
                        # Actually, the simplest approach: decrypt K4 with this
                        # keystream under each variant, and see if the PT at
                        # crib positions matches.
                        pass

                    # Simpler: count crib matches directly
                    for dec_variant in ["beau"]:  # Just check Beaufort
                        pt_nums = decrypt(ct_nums, keystream, dec_variant)
                        match_count = 0
                        for pos, expected_pt in CRIB_DICT.items():
                            if pos < len(pt_nums):
                                if ALPH[pt_nums[pos]] == expected_pt:
                                    match_count += 1
                        if match_count > best_match:
                            best_match = match_count
                            best_config = (pair_name, variant, ordering,
                                           ext_name, dec_variant, p)
                        if match_count >= 6:
                            print(f"  {pair_name}/{variant}/{ordering}/"
                                  f"{ext_name}/beau: {match_count}/24 "
                                  f"crib matches")

                    # Also check Vig and VBeau decryption
                    for dec_variant in ["vig", "vbeau"]:
                        pt_nums = decrypt(ct_nums, keystream, dec_variant)
                        match_count = 0
                        for pos, expected_pt in CRIB_DICT.items():
                            if pos < len(pt_nums):
                                if ALPH[pt_nums[pos]] == expected_pt:
                                    match_count += 1
                        if match_count > best_match:
                            best_match = match_count
                            best_config = (pair_name, variant, ordering,
                                           ext_name, dec_variant, p)
                        if match_count >= 6:
                            print(f"  {pair_name}/{variant}/{ordering}/"
                                  f"{ext_name}/{dec_variant}: "
                                  f"{match_count}/24 crib matches")

    print(f"\n  Best crib match: {best_match}/24")
    if best_config:
        print(f"  Config: pair_set={best_config[0]}, "
              f"extract={best_config[1]}, order={best_config[2]}, "
              f"ext={best_config[3]}, decrypt={best_config[4]}, "
              f"primer={best_config[5]}")

    # ── Summary ────────────────────────────────────────────────────────
    print("\n" + "=" * 72)
    print(f"SUMMARY: Tested {tested} configurations")
    print(f"Results with crib_score >= 4: {len(results)}")
    print("=" * 72)

    if results:
        results.sort(key=lambda r: r["crib_score"], reverse=True)
        print("\nTop results:")
        for r in results[:20]:
            print(f"  crib={r['crib_score']}/24 (ENE={r['ene']} BC={r['bc']}) "
                  f"bean={r['bean']} | {r['pair_set']}/{r['extract_variant']}/"
                  f"{r['decrypt_variant']}/{r['ordering']}/{r['extension']} "
                  f"| {r['pt_preview']}")
    else:
        print("\nNo results above threshold.")

    # Print all primers for reference
    print("\n" + "=" * 72)
    print("REFERENCE: All derived primers")
    print("=" * 72)
    for pair_name, pairs in pair_sets:
        for variant in variants:
            keys = extract_keys(pairs, variant)
            letters = nums_to_text(keys)
            print(f"  {pair_name:8s} / {variant:5s}: "
                  f"{str(keys):30s} = {letters}")

    # Expected baseline: random 5-value primer, noise floor is ~1/24
    # per position = ~0.92 expected matches. Anything above 3-4 is
    # worth investigating.
    print(f"\nExpected random baseline: ~{24/26:.1f} crib matches")
    print("Score >= 6 would be interesting (p < 0.01)")

    return best_match


if __name__ == "__main__":
    best = main()
    sys.exit(0 if best < 18 else 1)
