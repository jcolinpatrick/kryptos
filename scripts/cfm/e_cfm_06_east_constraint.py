#!/usr/bin/env python3
"""
Cipher: running key
Family: cfm
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-CFM-06: EAST repetition constraint mining for running key identification.

[HYPOTHESIS] The word EAST appears TWICE in the cribs (pos 21-24 and 30-33),
mapping to different CT (FLRV and GKSS). Under any substitution model with a
running key, this creates a DIFFERENTIAL constraint on the source text:

  For Vigenere: source[off+j+9] - source[off+j] ≡ delta_j (mod 26)
  for j in {21, 22, 23, 24} with delta = [1, 25, 1, 23]

Combined with Bean-EQ (source[off+27] = source[off+65], gap-38), this gives
5 simultaneous constraints on the running key source text.

P(all 5 constraints satisfied randomly) ≈ (1/26)^4 × (1/26) ≈ 8.4e-8
For a 100K-char corpus: ~0.008 expected false positives.

This experiment:
1. Derives the exact EAST gap-9 differentials for all 3 cipher variants
2. Scans all available corpus texts for passages matching these constraints
3. Reports any matches (zero matches = further eliminates running key from
   known texts; positive matches = investigate immediately)
4. Quantifies the discriminating power of this constraint
"""
import sys
import os
import glob
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAN_EQ, BEAN_INEQ,
)
from kryptos.kernel.transforms.vigenere import (
    vig_recover_key, beau_recover_key, varbeau_recover_key,
)


def strip_alpha(text: str) -> str:
    """Keep only A-Z uppercase."""
    return "".join(c for c in text.upper() if c in ALPH)


def load_corpus_texts():
    """Load all available corpus texts from reference/ directory."""
    base = os.path.join(os.path.dirname(__file__), "..", "reference")
    texts = {}

    # Running key texts
    rk_dir = os.path.join(base, "running_key_texts")
    if os.path.isdir(rk_dir):
        for f in sorted(os.listdir(rk_dir)):
            path = os.path.join(rk_dir, f)
            if os.path.isfile(path):
                with open(path) as fh:
                    texts[f"running_key/{f}"] = strip_alpha(fh.read())

    # Carter texts
    for name in ["carter_gutenberg.txt", "carter_vol1.txt"]:
        path = os.path.join(base, name)
        if os.path.isfile(path):
            with open(path) as fh:
                texts[name] = strip_alpha(fh.read())

    # Wordlist as a "text" (continuous string of all words)
    wl_path = os.path.join(os.path.dirname(__file__), "..", "wordlists", "english.txt")
    if os.path.isfile(wl_path):
        with open(wl_path) as fh:
            texts["wordlist_continuous"] = strip_alpha(fh.read())

    return texts


def main():
    print("=" * 70)
    print("E-CFM-06: EAST Repetition Constraint Mining")
    print("=" * 70)

    # ── Step 1: Derive key values at all crib positions ─────────────────
    print("\n── Step 1: Key fragments at crib positions (identity trans) ──")

    crib_positions = sorted(CRIB_DICT.keys())
    variants = {
        "vigenere": vig_recover_key,
        "beaufort": beau_recover_key,
        "var_beaufort": varbeau_recover_key,
    }

    key_fragments = {}
    for variant_name, recover_fn in variants.items():
        keys = []
        for pos in crib_positions:
            pt_val = ALPH_IDX[CRIB_DICT[pos]]
            ct_val = ALPH_IDX[CT[pos]]
            k = recover_fn(ct_val, pt_val)
            keys.append(k)
        key_fragments[variant_name] = keys
        key_str = "".join(ALPH[k] for k in keys)
        print(f"  {variant_name:14s}: {key_str}")
        # Show as source text requirement
        print(f"    Positions 21-33: {''.join(ALPH[k] for k in keys[:13])}")
        print(f"    Positions 63-73: {''.join(ALPH[k] for k in keys[13:])}")

    # Verify against known constants
    assert key_fragments["vigenere"][:13] == list(VIGENERE_KEY_ENE)
    assert key_fragments["vigenere"][13:] == list(VIGENERE_KEY_BC)
    print("  (Verified against VIGENERE_KEY_ENE and VIGENERE_KEY_BC)")

    # ── Step 2: EAST gap-9 differential ─────────────────────────────────
    print("\n── Step 2: EAST gap-9 differentials ──")
    print("EAST at pos 21-24 and pos 30-33 → gap = 9")
    print()

    east_diffs = {}
    for variant_name, keys in key_fragments.items():
        # Keys at EAST positions: 21,22,23,24 → indices 0,1,2,3
        # Keys at second EAST: 30,31,32,33 → indices 9,10,11,12
        diffs = []
        for i in range(4):
            d = (keys[9 + i] - keys[i]) % MOD
            diffs.append(d)
        east_diffs[variant_name] = diffs
        print(f"  {variant_name:14s}: Δ = {diffs}")
        # Show as character pairs
        for j in range(4):
            k1 = keys[j]
            k2 = keys[9 + j]
            pos1 = 21 + j
            pos2 = 30 + j
            print(f"    k[{pos2}]-k[{pos1}] = {ALPH[k2]}-{ALPH[k1]} = "
                  f"({k2}-{k1}) mod 26 = {diffs[j]}")

    # Note: Vigenere and Beaufort give the SAME diffs (because PT is the
    # same at both positions, so the diff cancels the variant)
    if east_diffs["vigenere"] == east_diffs["beaufort"]:
        print("\n  [DERIVED FACT] Vigenere and Beaufort give IDENTICAL gap-9 diffs")
        print("  (because PT is the same at both EAST positions)")

    # ── Step 3: Bean-EQ as additional filter ────────────────────────────
    print("\n── Step 3: Bean-EQ constraint on running key ──")
    bean_eq_pos = BEAN_EQ[0]  # (27, 65)
    print(f"  Bean-EQ: k[{bean_eq_pos[0]}] = k[{bean_eq_pos[1]}]")
    print(f"  Gap: {bean_eq_pos[1] - bean_eq_pos[0]}")
    print(f"  For running key: source[off+{bean_eq_pos[0]}] = source[off+{bean_eq_pos[1]}]")
    for variant_name, keys in key_fragments.items():
        # Position 27 is index 6 (27-21=6 in first crib)
        # Position 65 is index 15 (65-63+13=15)
        k27 = keys[6]
        k65 = keys[15]
        print(f"  {variant_name}: k[27]={ALPH[k27]}({k27}), k[65]={ALPH[k65]}({k65}), "
              f"equal={k27 == k65}")

    # ── Step 4: Compute discriminating power ────────────────────────────
    print("\n── Step 4: Discriminating power analysis ──")
    # For random text, P(char[i+9] - char[i] = d) ≈ 1/26 for each d
    # For 4 constraints: (1/26)^4 ≈ 2.19e-6
    # Plus Bean-EQ: (1/26)^5 ≈ 8.4e-8
    p_single = 1.0 / MOD
    p_east_4 = p_single ** 4
    p_all_5 = p_single ** 5

    print(f"  P(single gap-9 diff match) = 1/26 = {p_single:.4f}")
    print(f"  P(all 4 EAST diffs match)  = (1/26)^4 = {p_east_4:.2e}")
    print(f"  P(4 EAST + Bean-EQ match)  = (1/26)^5 = {p_all_5:.2e}")
    print()

    # For English text, the probabilities are slightly non-uniform due to
    # letter frequency correlations, but the same order of magnitude.
    # The key point: for a corpus of N characters, expected false positives
    # = N × P. For Carter vol1 (~350K alpha chars): ~0.77 for EAST alone,
    # ~0.03 for EAST + Bean.

    # ── Step 5: Corpus search ───────────────────────────────────────────
    print("\n── Step 5: Corpus search ──")
    texts = load_corpus_texts()
    print(f"  Loaded {len(texts)} corpus texts")
    for name, text in sorted(texts.items()):
        print(f"    {name}: {len(text)} chars")

    total_matches_east = 0
    total_matches_full = 0

    for variant_name, diffs in east_diffs.items():
        print(f"\n  --- Variant: {variant_name} ---")
        print(f"  EAST diffs: {diffs}")

        keys = key_fragments[variant_name]
        bean_k27 = keys[6]   # k[27]
        bean_k65 = keys[15]  # k[65]

        for corpus_name, text in sorted(texts.items()):
            if len(text) < CT_LEN:
                continue

            max_offset = len(text) - CT_LEN
            east_matches = []
            full_matches = []

            for offset in range(max_offset + 1):
                # Check EAST gap-9 diffs
                # Positions 21,22,23,24 and 30,31,32,33 relative to offset
                match = True
                for j in range(4):
                    pos1 = offset + 21 + j
                    pos2 = offset + 30 + j
                    char_diff = (ALPH_IDX[text[pos2]] - ALPH_IDX[text[pos1]]) % MOD
                    if char_diff != diffs[j]:
                        match = False
                        break
                if not match:
                    continue

                east_matches.append(offset)

                # Check Bean-EQ: source[off+27] = source[off+65]
                if text[offset + 27] != text[offset + 65]:
                    continue

                # Check that the key at crib positions matches
                # (this is the FULL 24-position constraint)
                all_match = True
                for idx, pos in enumerate(crib_positions):
                    expected_k = keys[idx]
                    actual_char = ALPH_IDX[text[offset + pos]]
                    if actual_char != expected_k:
                        all_match = False
                        break

                if all_match:
                    full_matches.append(offset)
                    # This would be a BREAKTHROUGH
                    context = text[offset:offset + CT_LEN]
                    print(f"\n  *** FULL MATCH in {corpus_name} at offset {offset}! ***")
                    print(f"  Source text: {context[:50]}...")
                    # Decrypt
                    pt = []
                    for i in range(CT_LEN):
                        ct_val = ALPH_IDX[CT[i]]
                        k_val = ALPH_IDX[text[offset + i]]
                        if variant_name == "vigenere":
                            pt_val = (ct_val - k_val) % MOD
                        elif variant_name == "beaufort":
                            pt_val = (k_val - ct_val) % MOD
                        else:
                            pt_val = (ct_val + k_val) % MOD
                        pt.append(ALPH[pt_val])
                    pt_str = "".join(pt)
                    print(f"  Decrypted PT: {pt_str}")

            if east_matches:
                total_matches_east += len(east_matches)
                print(f"  {corpus_name}: {len(east_matches)} EAST-diff matches")
                # Show first few
                for off in east_matches[:3]:
                    snippet = text[offset + 21:offset + 34]
                    print(f"    offset {off}: ...{text[off+19:off+36]}...")

            if full_matches:
                total_matches_full += len(full_matches)

        if total_matches_east == 0:
            print(f"  No EAST-diff matches in any corpus for {variant_name}")

    # ── Step 6: Bean inequality filter ──────────────────────────────────
    print("\n── Step 6: Bean inequality statistics ──")
    # For each EAST-diff match, also check Bean inequalities
    # This is done separately for clarity

    for variant_name, diffs in east_diffs.items():
        keys = key_fragments[variant_name]
        print(f"\n  {variant_name} — checking Bean on EAST-diff matches:")
        bean_pass_count = 0
        east_total = 0

        for corpus_name, text in sorted(texts.items()):
            if len(text) < CT_LEN:
                continue

            max_offset = len(text) - CT_LEN
            for offset in range(max_offset + 1):
                # Quick EAST check
                match = True
                for j in range(4):
                    pos1 = offset + 21 + j
                    pos2 = offset + 30 + j
                    if (ALPH_IDX[text[pos2]] - ALPH_IDX[text[pos1]]) % MOD != diffs[j]:
                        match = False
                        break
                if not match:
                    continue

                east_total += 1

                # Check Bean-EQ
                if text[offset + 27] != text[offset + 65]:
                    continue

                # Compute full key at crib positions
                key_vals = {}
                for idx, pos in enumerate(crib_positions):
                    key_vals[pos] = ALPH_IDX[text[offset + pos]]

                # Check Bean inequalities
                ineq_pass = True
                for i, j in BEAN_INEQ:
                    if i in key_vals and j in key_vals:
                        if key_vals[i] == key_vals[j]:
                            ineq_pass = False
                            break

                if ineq_pass:
                    bean_pass_count += 1
                    print(f"    Bean PASS at offset {offset} in {corpus_name}")
                    context = text[offset + 21:offset + 34]
                    context2 = text[offset + 63:offset + 74]
                    print(f"      key@ENE: {context}, key@BC: {context2}")

        print(f"  Total EAST-diff matches: {east_total}, Bean passes: {bean_pass_count}")

    # ── Step 7: English bigram frequency of EAST diffs ──────────────────
    print("\n── Step 7: Expected EAST-diff frequency in English ──")
    # English letter frequency approximation
    eng_freq = {
        'A': .082, 'B': .015, 'C': .028, 'D': .043, 'E': .127,
        'F': .022, 'G': .020, 'H': .061, 'I': .070, 'J': .002,
        'K': .008, 'L': .040, 'M': .024, 'N': .067, 'O': .075,
        'P': .019, 'Q': .001, 'R': .060, 'S': .063, 'T': .091,
        'U': .028, 'V': .010, 'W': .024, 'X': .002, 'Y': .020,
        'Z': .001,
    }

    for variant_name, diffs in east_diffs.items():
        p_all = 1.0
        print(f"\n  {variant_name}: diffs = {diffs}")
        for j, d in enumerate(diffs):
            # P(char2 - char1 = d) = sum_a freq(a) * freq((a+d) % 26)
            p_d = sum(eng_freq[ALPH[a]] * eng_freq[ALPH[(a + d) % MOD]]
                      for a in range(MOD))
            p_all *= p_d
            print(f"    Δ={d:2d}: P={p_d:.5f} (random=0.03846)")
        print(f"    P(all 4 diffs) = {p_all:.2e}")
        print(f"    For 100K-char corpus: ~{100000 * p_all:.4f} expected matches")
        print(f"    For 350K-char corpus: ~{350000 * p_all:.4f} expected matches")

    # ── Step 8: What does the source text LOOK like? ────────────────────
    print("\n── Step 8: Source text profile at crib positions ──")
    for variant_name, keys in key_fragments.items():
        print(f"\n  {variant_name}:")
        src_21_33 = "".join(ALPH[k] for k in keys[:13])
        src_63_73 = "".join(ALPH[k] for k in keys[13:])
        print(f"    Source[off+21..33] must be: {src_21_33}")
        print(f"    Source[off+63..73] must be: {src_63_73}")
        # Check if any substring looks like natural language
        combined = src_21_33 + "." * 29 + src_63_73
        vowels = sum(1 for c in src_21_33 + src_63_73 if c in "AEIOU")
        total = len(src_21_33) + len(src_63_73)
        print(f"    Vowel ratio: {vowels}/{total} = {vowels/total:.1%} "
              f"(English ≈ 40%)")

    # ── Summary ─────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    print(f"EAST gap-9 differentials (variant-independent for Vig/Beau): {east_diffs['vigenere']}")
    print(f"Var Beaufort differentials: {east_diffs['var_beaufort']}")
    print()
    print(f"Corpus search results:")
    print(f"  Total EAST-diff matches: {total_matches_east}")
    print(f"  Full 24-position matches: {total_matches_full}")
    print()

    if total_matches_full > 0:
        print("*** BREAKTHROUGH — full running key match found! ***")
        print("Verdict: SIGNAL")
    elif total_matches_east > 0:
        print(f"EAST-diff matches found ({total_matches_east}) but none pass full constraints.")
        print("This is consistent with random coincidence at the expected rate.")
        print()
        print("[INTERNAL RESULT] Running key from tested corpora: ELIMINATED")
        print("(under identity transposition)")
        print()
        print("[DERIVED FACT] The EAST gap-9 constraint is highly discriminating:")
        print(f"  P(match) ≈ {p_east_4:.2e} per offset position")
        print(f"  Combined with Bean-EQ: P ≈ {p_all_5:.2e} per offset")
        print()
        print("[HYPOTHESIS] The EAST constraint can be used as a fast filter for")
        print("evaluating new candidate running key texts. Any legitimate running")
        print("key source text MUST satisfy all 4 EAST diffs at some offset.")
        print()
        print("Verdict: NOISE (corpora searched), TOOL (constraint validated)")
    else:
        print("Zero EAST-diff matches in all corpora — the constraint is")
        print("extremely discriminating against these texts.")
        print()
        print("[DERIVED FACT] The 4 EAST gap-9 constraints eliminate all tested")
        print("corpus texts as running key sources under identity transposition.")
        print("P(false positive per position) ≈ 2.2e-6, making this a powerful")
        print("filter for evaluating new candidate texts.")
        print()
        print("Verdict: NOISE (corpora), TOOL (constraint validated for future use)")


if __name__ == "__main__":
    main()
