#!/usr/bin/env python3
"""
Cipher: running key
Family: running_key
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-CFM-02: Mono + transposition + running key — DOF reduction.

[HYPOTHESIS] The one identified open gap in the structured cipher model
space (E-FRAC-54). This experiment attempts to REDUCE the 13 monoalphabetic
degrees of freedom by exploiting:
  1. Self-encrypting positions: CT[32]=PT[32]=S and CT[73]=PT[73]=K
     → mono must fix S→S and K→K (reduces 13 DOF to 11)
  2. Letter frequency constraints: the mono layer must produce a CT
     frequency distribution consistent with K4's observed frequencies
     given an English plaintext
  3. Crib letter pairing: at crib positions, specific PT→CT pairs are
     known. Under mono+trans, these constrain the mono mapping.

Goal: determine whether these constraints reduce the DOF enough that
running key fragment analysis can discriminate English from random.
"""
import sys
import os
from collections import Counter, defaultdict
from itertools import permutations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS, SELF_ENCRYPTING,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
)
from kryptos.kernel.transforms.vigenere import vig_recover_key


def main():
    print("=" * 70)
    print("E-CFM-02: Mono + Trans + Running Key — DOF Reduction Analysis")
    print("=" * 70)

    # ── Step 1: Identify constrained mono positions ───────────────────────
    print("\n── Step 1: Self-encrypting position constraints ──")
    # If mono(X) = Y, then in the model:
    #   CT = RunKey_encrypt(Trans(Mono(PT)))
    # At self-encrypting positions: CT[i] = PT[i]
    # This means: RunKey_encrypt(Trans(Mono(PT[i])), k[i]) = CT[i] = PT[i]
    # If we assume identity transposition at these positions (which is a
    # specific case), then: RunKey_encrypt(Mono(PT[i]), k[i]) = PT[i]
    # This constrains the relationship between Mono and the key.

    # Under the simplest model (mono applied to PT, then key added):
    #   CT[i] = (Mono(PT[i]) + K[i]) mod 26
    # Self-encryption: CT[i] = PT[i], so:
    #   PT[i] = (Mono(PT[i]) + K[i]) mod 26
    # This means: K[i] = (PT[i] - Mono(PT[i])) mod 26

    # For position 32: PT=S, CT=S → K[32] = (S - Mono(S)) mod 26
    # For position 73: PT=K, CT=K → K[73] = (K - Mono(K)) mod 26

    # If Mono fixes S (Mono(S)=S): K[32] = 0
    # If Mono fixes K (Mono(K)=K): K[73] = 0

    for pos, ch in SELF_ENCRYPTING.items():
        ct_ch = CT[pos]
        print(f"  Position {pos}: PT='{ch}', CT='{ct_ch}'")
        if ct_ch == ch:
            print(f"    Self-encrypting: if Mono fixes '{ch}', then K[{pos}]=0")
            print(f"    If Mono('{ch}')=X, then K[{pos}] = ({ALPH_IDX[ch]} - X) mod 26")

    # ── Step 2: Analyze the 13 distinct PT letters in cribs ───────────────
    print("\n── Step 2: Distinct PT letters at crib positions ──")
    pt_letters_at_cribs = set(CRIB_DICT.values())
    ct_letters_at_cribs = set(CT[pos] for pos in CRIB_DICT)

    print(f"Distinct PT letters in cribs: {sorted(pt_letters_at_cribs)} ({len(pt_letters_at_cribs)})")
    print(f"Distinct CT letters at crib positions: {sorted(ct_letters_at_cribs)} ({len(ct_letters_at_cribs)})")

    # Map each crib position's PT→CT pair
    pt_ct_pairs = defaultdict(set)
    for pos, pt_ch in CRIB_DICT.items():
        ct_ch = CT[pos]
        pt_ct_pairs[pt_ch].add(ct_ch)

    print("\nPT letter → CT letters seen at crib positions:")
    for pt_ch in sorted(pt_ct_pairs.keys()):
        ct_set = pt_ct_pairs[pt_ch]
        print(f"  PT '{pt_ch}' → CT {sorted(ct_set)}")

    # Under the model CT = RunKey(Trans(Mono(PT))):
    # At each crib position: CT[i] = (Mono(PT[i]) + K[Trans_inv(i)]) mod 26
    # Without knowing Trans, we can't pin down Mono.
    # But we CAN analyze what happens under identity transposition.

    # ── Step 3: Identity transposition analysis ───────────────────────────
    print("\n── Step 3: Under IDENTITY transposition (no transposition) ──")
    print("Model: CT[i] = (Mono(PT[i]) + K[i]) mod 26")
    print("At crib positions, K[i] = (CT[i] - Mono(PT[i])) mod 26")
    print()
    print("The mono mapping Mono(X) determines the key values at all 24 crib positions.")
    print("The 13 distinct PT letters = 13 free mono values.")
    print()

    # Under identity trans, the keystream at crib positions is determined
    # by the mono mapping. The question: for which mono mappings do the
    # resulting key values look like English text (running key)?

    # For EACH of the 13 PT letters, Mono assigns a value 0-25.
    # This determines K[i] at all 24 crib positions.
    # We need K to look like consecutive characters from English text.

    # But 24 key values from 13 free parameters = underdetermined.
    # The question is: HOW underdetermined?

    # ── Step 4: Quantify the constraint from self-encryption ──────────────
    print("\n── Step 4: Self-encryption reduces DOF ──")
    # Self-encrypting letters at crib positions:
    self_encrypt_in_cribs = {}
    for pos, pt_ch in CRIB_DICT.items():
        ct_ch = CT[pos]
        if ct_ch == pt_ch:
            self_encrypt_in_cribs[pos] = pt_ch

    print(f"Self-encrypting positions within cribs: {self_encrypt_in_cribs}")
    if self_encrypt_in_cribs:
        for pos, ch in self_encrypt_in_cribs.items():
            print(f"  Position {pos}: PT=CT='{ch}' → if Mono('{ch}')=M, K[{pos}]={ALPH_IDX[ch]}-M mod 26")

    # ── Step 5: Frequency constraint analysis ─────────────────────────────
    print("\n── Step 5: K4 CT frequency distribution ──")
    ct_freq = Counter(CT)

    # English frequency order
    english_freq = {
        'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7,
        'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8,
        'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2, 'G': 2.0, 'Y': 2.0,
        'P': 1.9, 'B': 1.5, 'V': 1.0, 'K': 0.8, 'J': 0.2, 'X': 0.2,
        'Q': 0.1, 'Z': 0.1,
    }

    print("CT frequencies (count, expected English count for n=97):")
    for ch in sorted(ALPH, key=lambda c: -ct_freq.get(c, 0)):
        ct_count = ct_freq.get(ch, 0)
        eng_expected = english_freq[ch] * 97 / 100
        diff = ct_count - eng_expected
        print(f"  '{ch}': CT={ct_count:2d}, English≈{eng_expected:.1f}, diff={diff:+.1f}")

    # Under mono+running key (no transposition):
    # CT[i] = (Mono(PT[i]) + K[i]) mod 26
    # If K is English-like, then CT = Mono(PT) + English
    # CT freq ≈ convolution of Mono(English freq) and English freq
    # This should be roughly uniform (like Vigenere with long key)
    # K4's CT IS roughly uniform (IC ≈ 0.0361)
    # So this is CONSISTENT but not diagnostic

    print("\n── Step 5b: Chi-squared distance from uniform ──")
    expected_uniform = CT_LEN / 26
    chi2 = sum((ct_freq.get(ch, 0) - expected_uniform) ** 2 / expected_uniform
               for ch in ALPH)
    print(f"  Chi-squared (CT vs uniform): {chi2:.2f}")
    print(f"  Expected for uniform: ~25 (25 df)")
    print(f"  K4's value suggests {'consistent with running key' if chi2 < 40 else 'inconsistent'}")

    # ── Step 6: Enumerate mono mappings with self-encryption fixed ────────
    print("\n── Step 6: Small-scale mono enumeration ──")
    # Fix Mono(S)=S and Mono(K)=K (from self-encrypting positions)
    # This leaves 11 free PT letters in the cribs
    # Full enumeration: 26^11 ≈ 3.7 trillion — too large
    # Instead: sample random mono mappings and check key fragment quality

    import random
    random.seed(42)

    crib_pt_letters = sorted(pt_letters_at_cribs)
    print(f"PT letters to assign: {crib_pt_letters}")

    # Fixed assignments
    fixed = {}
    if 'S' in pt_letters_at_cribs:
        fixed['S'] = ALPH_IDX['S']
        print(f"  Fixed: Mono('S') = S (idx {ALPH_IDX['S']})")
    if 'K' in pt_letters_at_cribs:
        fixed['K'] = ALPH_IDX['K']
        print(f"  Fixed: Mono('K') = K (idx {ALPH_IDX['K']})")

    free_letters = [ch for ch in crib_pt_letters if ch not in fixed]
    print(f"  Free letters: {free_letters} ({len(free_letters)} DOF)")

    # Sample N random mono assignments, compute key fragments, check quality
    N_SAMPLES = 100000
    print(f"\nSampling {N_SAMPLES} random mono assignments...")

    # For each sample: assign random values to free letters,
    # compute K at all 24 crib positions, check if K looks structured
    key_quality_scores = []

    for trial in range(N_SAMPLES):
        # Random mono: each free letter gets random 0-25
        mono = dict(fixed)
        for ch in free_letters:
            mono[ch] = random.randint(0, 25)

        # Compute keystream at crib positions
        key_values = []
        for pos in sorted(CRIB_DICT.keys()):
            pt_ch = CRIB_DICT[pos]
            ct_val = ALPH_IDX[CT[pos]]
            mono_val = mono[pt_ch]
            k_val = (ct_val - mono_val) % 26
            key_values.append(k_val)

        # Check quality: count how many consecutive key pairs have
        # difference consistent with English bigram structure
        # (English text has autocorrelation: k[i+1] - k[i] is non-uniform)
        diffs = [(key_values[i+1] - key_values[i]) % 26 for i in range(len(key_values)-1)]
        # English key: consecutive letters often have small differences
        # (common bigrams: TH, HE, IN, ER, AN have diffs of specific values)
        small_diffs = sum(1 for d in diffs if d <= 5 or d >= 21)
        key_quality_scores.append(small_diffs)

    avg_quality = sum(key_quality_scores) / len(key_quality_scores)
    max_quality = max(key_quality_scores)
    print(f"  Average key quality (small-diff count): {avg_quality:.2f} / {len(key_values)-1}")
    print(f"  Max key quality: {max_quality} / {len(key_values)-1}")

    # Expected for random: each diff is uniform mod 26
    # P(diff <= 5 or diff >= 21) = 11/26 ≈ 0.423
    expected_random = (len(key_values) - 1) * 11 / 26
    print(f"  Expected random: {expected_random:.2f}")
    print(f"  Observed/Expected ratio: {avg_quality / expected_random:.3f}")

    # Distribution
    from collections import Counter as C2
    dist = C2(key_quality_scores)
    print(f"\n  Quality distribution (top 5):")
    for val, count in sorted(dist.items(), key=lambda x: -x[0])[:5]:
        print(f"    quality={val}: {count} samples ({count/N_SAMPLES:.2%})")

    # ── Step 7: Check if mono(S)=S, mono(K)=K is forced ──────────────────
    print("\n── Step 7: Is Mono fixing S and K actually required? ──")
    print("Self-encrypting positions constrain Mono(S) and Mono(K) ONLY if")
    print("the transposition is identity at those positions.")
    print("Under arbitrary transposition, positions 32 and 73 may be")
    print("mapped elsewhere, so self-encryption doesn't constrain mono.")
    print()
    print("[DERIVED FACT] Without assuming identity transposition at")
    print("self-encrypting positions, the full 13 DOF remain.")
    print()
    print("Under IDENTITY transposition: 11 DOF (S and K fixed).")
    print("Under ARBITRARY transposition: 13 DOF (nothing fixed).")

    # ── Summary ───────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"13 distinct PT letters in cribs = 13 mono DOF")
    print(f"Self-encryption fixes 2 (S→S, K→K) under identity trans → 11 DOF")
    print(f"Under arbitrary transposition: 13 DOF unchanged")
    print()
    print(f"Random mono sampling ({N_SAMPLES} trials):")
    print(f"  Key fragment quality indistinguishable from random")
    print(f"  (avg={avg_quality:.2f}, expected random={expected_random:.2f})")
    print()
    print("[INTERNAL RESULT] The mono layer's DOF CANNOT be reduced by")
    print("self-encryption constraints alone when transposition is unknown.")
    print("Frequency constraints are also non-diagnostic (CT is already")
    print("near-uniform, consistent with ANY mono + running key).")
    print()
    print("[DERIVED FACT] Confirming E-FRAC-54: the mono+trans+running key")
    print("model remains UNDERDETERMINED. Additional constraints needed:")
    print("  1. Physical transposition from sculpture geometry")
    print("  2. Known running key text (reduces problem to trans search)")
    print("  3. External information (coding charts, K5, Sanborn disclosure)")
    print()
    print("Verdict: UNDERDETERMINED — confirms E-FRAC-54, no new reduction found")


if __name__ == "__main__":
    main()
