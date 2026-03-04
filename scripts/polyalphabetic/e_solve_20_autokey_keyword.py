#!/usr/bin/env python3
"""
Cipher: autokey
Family: polyalphabetic
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-SOLVE-20: Keyword-Mixed Autokey Models

E-FRAC-37 tested PURE autokey (K[i] = CT[i-1] or PT[i-1]) — max 21/24 CT, 16/24 PT.
E-SOLVE-18 tested KEY-feedback arithmetic recurrences (K[i] = f(K[i-1], kw[i%p])).

NEITHER tested keyword-mixed autokey where feedback from CT or PT is combined
with a periodic keyword:
    K[i] = combine(feedback[i-1], kw[i%p])

These models produce non-periodic keystreams from periodic keywords, avoiding
the Bean impossibility proofs that eliminate all purely periodic keys.

Models tested:
  Feedback source: CT[i-1], PT[i-1], K[i-1]
  Combination: add, sub, Beaufort-style
  Cipher variant: Vigenere, Beaufort, Variant Beaufort
  Periods: 2-48

Method: At each crib position i, derive the required kw[i%p] value.
Check consistency: all derivations at the same residue must agree.
Cross-validate between ENE and BC cribs.
"""

import sys
sys.path.insert(0, "src")

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, BEAN_EQ, BEAN_INEQ,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    KRYPTOS_ALPHABET,
)

CT_INT = [ALPH_IDX[c] for c in CT]
CRIB_POS = sorted(CRIB_DICT.keys())  # [21,22,...,33, 63,64,...,73]
CRIB_PT = {pos: ALPH_IDX[CRIB_DICT[pos]] for pos in CRIB_POS}
CRIB_INT = {pos: CT_INT[pos] for pos in CRIB_POS}

# KA alphabet lookup
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}


def get_key_values(variant):
    """Compute key values at all crib positions for a given cipher variant."""
    keys = {}
    for pos in CRIB_POS:
        ct = CT_INT[pos]
        pt = CRIB_PT[pos]
        if variant == "vig":
            keys[pos] = (ct - pt) % MOD
        elif variant == "beau":
            keys[pos] = (ct + pt) % MOD
        elif variant == "varbeau":
            keys[pos] = (pt - ct) % MOD
    return keys


def check_consistency(derivations, period):
    """
    Given a dict of {position: derived_kw_value}, check if all positions
    mapping to the same residue (position % period) give the same value.
    Returns (is_consistent, keyword_dict, num_constraints, num_residues_covered).
    """
    residue_values = {}
    for pos, val in derivations.items():
        r = pos % period
        if r in residue_values:
            if residue_values[r] != val:
                return False, {}, 0, 0
        else:
            residue_values[r] = val

    return True, residue_values, len(derivations), len(residue_values)


def get_feedback_value(feedback_type, pos, keys, variant):
    """
    Get the feedback value at position pos-1 for the given feedback type.
    Returns (value, is_available).
    """
    prev = pos - 1
    if prev < 0:
        return None, False

    if feedback_type == "ct":
        # CT[pos-1] is always known
        return CT_INT[prev], True
    elif feedback_type == "pt":
        # PT[pos-1] is only known at crib positions
        if prev in CRIB_PT:
            return CRIB_PT[prev], True
        return None, False
    elif feedback_type == "key":
        # K[pos-1] is only known at crib positions
        if prev in keys:
            return keys[prev], True
        return None, False
    return None, False


def derive_keyword_value(key_val, feedback_val, combine):
    """
    Given K[i] and feedback[i-1], derive kw[i%p].
    K[i] = combine(feedback[i-1], kw[i%p])
    """
    if combine == "add":
        # K[i] = (feedback + kw) % 26 → kw = (K[i] - feedback) % 26
        return (key_val - feedback_val) % MOD
    elif combine == "sub":
        # K[i] = (feedback - kw) % 26 → kw = (feedback - K[i]) % 26
        return (feedback_val - key_val) % MOD
    elif combine == "beau":
        # K[i] = (kw - feedback) % 26 → kw = (K[i] + feedback) % 26
        return (key_val + feedback_val) % MOD
    return None


def derive_kw_ka(key_val, feedback_val, combine):
    """
    Same as derive_keyword_value but in KA-index space.
    The feedback goes through KA tableau: K[i] = KA[(KA_inv[feedback] + KA_inv[kw]) % 26]
    So KA_inv[K[i]] = KA_inv[feedback] + KA_inv[kw] (mod 26)
    → KA_inv[kw] = KA_inv[K[i]] - KA_inv[feedback] (mod 26)
    """
    # Map AZ-indices to KA-indices
    key_letter = ALPH[key_val]
    feed_letter = ALPH[feedback_val]
    if key_letter not in KA_IDX or feed_letter not in KA_IDX:
        return None

    key_ka = KA_IDX[key_letter]
    feed_ka = KA_IDX[feed_letter]

    if combine == "add":
        return (key_ka - feed_ka) % MOD
    elif combine == "sub":
        return (feed_ka - key_ka) % MOD
    elif combine == "beau":
        return (key_ka + feed_ka) % MOD
    return None


def forward_propagate(keys, keyword, period, feedback_type, combine, variant,
                      use_ka=False):
    """
    Given a keyword and initial seed, forward-propagate the autokey model
    and count how many crib positions match.
    """
    best_matches = 0
    best_seed = -1

    for seed in range(MOD):
        k = [0] * CT_LEN
        k[0] = seed
        matches = 0

        for i in range(1, CT_LEN):
            # Get feedback from position i-1
            if feedback_type == "ct":
                # Need to compute CT for all positions, but we know CT already
                fb = CT_INT[i - 1]
            elif feedback_type == "pt":
                # PT[i-1] = decrypt(CT[i-1], K[i-1])
                if variant == "vig":
                    fb = (CT_INT[i - 1] - k[i - 1]) % MOD
                elif variant == "beau":
                    fb = (k[i - 1] - CT_INT[i - 1]) % MOD
                else:  # varbeau
                    fb = (CT_INT[i - 1] + k[i - 1]) % MOD
            elif feedback_type == "key":
                fb = k[i - 1]
            else:
                fb = 0

            kw_val = keyword.get(i % period)
            if kw_val is None:
                # Unknown keyword position, just propagate with 0
                kw_val = 0

            if use_ka:
                fb_letter = ALPH[fb % MOD]
                fb_ka = KA_IDX.get(fb_letter, 0)
                if combine == "add":
                    k_ka = (fb_ka + kw_val) % MOD
                elif combine == "sub":
                    k_ka = (fb_ka - kw_val) % MOD
                else:
                    k_ka = (kw_val - fb_ka) % MOD
                k_letter = KA[k_ka]
                k[i] = ALPH_IDX[k_letter]
            else:
                if combine == "add":
                    k[i] = (fb + kw_val) % MOD
                elif combine == "sub":
                    k[i] = (fb - kw_val) % MOD
                else:
                    k[i] = (kw_val - fb) % MOD

        # Check crib positions
        for pos in CRIB_POS:
            if pos in keys and k[pos] == keys[pos]:
                matches += 1

        if matches > best_matches:
            best_matches = matches
            best_seed = seed

    return best_matches, best_seed


print("E-SOLVE-20: Keyword-Mixed Autokey Models")
print("=" * 70)
print()

variants = [("vig", "Vigenère"), ("beau", "Beaufort"), ("varbeau", "VarBeaufort")]
feedbacks = ["ct", "pt", "key"]
combines = ["add", "sub", "beau"]
max_period = 48

total_tests = 0
total_consistent = 0
total_cross_valid = 0
best_candidates = []

for variant_code, variant_name in variants:
    keys = get_key_values(variant_code)

    for feedback_type in feedbacks:
        for combine in combines:
            for use_ka in [False, True]:
                space_name = "KA" if use_ka else "AZ"
                model_name = f"{variant_name}/{feedback_type}-autokey/{combine}/{space_name}"

                consistent_periods = []

                for period in range(2, max_period + 1):
                    total_tests += 1

                    # Derive keyword values at each crib position
                    derivations = {}
                    all_available = True

                    for pos in CRIB_POS:
                        fb_val, available = get_feedback_value(
                            feedback_type, pos, keys, variant_code
                        )
                        if not available:
                            continue

                        if use_ka:
                            kw_val = derive_kw_ka(
                                keys[pos], fb_val, combine
                            )
                        else:
                            kw_val = derive_keyword_value(
                                keys[pos], fb_val, combine
                            )

                        if kw_val is not None:
                            derivations[pos] = kw_val

                    if len(derivations) < 4:
                        continue

                    is_consistent, kw_dict, n_constraints, n_residues = \
                        check_consistency(derivations, period)

                    if is_consistent:
                        total_consistent += 1
                        consistent_periods.append(
                            (period, n_constraints, n_residues, kw_dict)
                        )

                # Report results for this model
                if consistent_periods:
                    # Filter: only report periods where we have meaningful
                    # constraint coverage (more constraints than residues)
                    meaningful = [
                        (p, nc, nr, kw) for p, nc, nr, kw in consistent_periods
                        if nc > nr  # overdetermined
                    ]
                    trivial = [
                        (p, nc, nr, kw) for p, nc, nr, kw in consistent_periods
                        if nc <= nr  # underdetermined
                    ]

                    if meaningful:
                        for p, nc, nr, kw in meaningful:
                            total_cross_valid += 1
                            kw_str = "".join(
                                ALPH[kw.get(r, 0)] for r in range(p)
                            )
                            print(f"  *** CONSISTENT (overdetermined): "
                                  f"{model_name} period={p}")
                            print(f"      {nc} constraints, "
                                  f"{nr} residues covered")
                            print(f"      Keyword fragment: {kw_str}")

                            # Forward propagate to verify
                            matches, seed = forward_propagate(
                                keys, kw, p, feedback_type, combine,
                                variant_code, use_ka
                            )
                            print(f"      Forward propagation: "
                                  f"{matches}/24 crib matches "
                                  f"(best seed={seed})")

                            if matches >= 18:
                                print(f"      *** SIGNAL! ***")
                                best_candidates.append(
                                    (model_name, p, kw_str, matches, seed)
                                )
                            elif matches >= 10:
                                print(f"      (above store threshold)")

                    if trivial and not meaningful:
                        pass  # Don't report underdetermined cases

print()
print("=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"Total model × period tests: {total_tests:,}")
print(f"Total algebraically consistent: {total_consistent}")
print(f"Total overdetermined consistent: {total_cross_valid}")
print(f"Total candidates (≥18/24): {len(best_candidates)}")
print()

if best_candidates:
    print("CANDIDATES:")
    for name, p, kw, matches, seed in sorted(
        best_candidates, key=lambda x: -x[3]
    ):
        print(f"  {name} period={p} kw={kw} "
              f"matches={matches}/24 seed={seed}")
elif total_cross_valid > 0:
    print(f"WARNING: {total_cross_valid} overdetermined-consistent cases "
          f"found but none reach signal threshold.")
    print("These may indicate near-miss models worth investigating.")
else:
    print("RESULT: ALL keyword-mixed autokey models produce INCONSISTENT")
    print("keyword derivations at overdetermined periods.")
    print()
    print("Combined with E-FRAC-37 (pure autokey ≤21/24) and E-SOLVE-18")
    print("(arithmetic key recurrences), this ELIMINATES:")
    print("  - CT-autokey + periodic keyword (all combine functions)")
    print("  - PT-autokey + periodic keyword (all combine functions)")
    print("  - K-autokey + periodic keyword (all combine functions)")
    print("  - All of the above in both AZ and KA index spaces")
    print("  - Under Vigenère, Beaufort, and Variant Beaufort")
    print("  - At all periods 2-48")
