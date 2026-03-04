#!/usr/bin/env python3
"""
Cipher: running key
Family: fractionation
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-FRAC-24: Running Key Language Profile Analysis

Building on E-FRAC-23's finding that no structured non-periodic model produces the
observed Beaufort key values, this experiment analyzes what a running key source text
would need to look like if the cipher is Beaufort with a running key.

The Beaufort key as letters: J L J O D E G K U K K K L  O C G G B G O K T R U
                              ─────ENE──────────────────  ───────BC──────────

Key questions:
1. Is the key letter distribution compatible with English? German? Other languages?
2. The KKK run at positions 30-32: how rare is this in natural language?
3. Can we constrain the source text by looking at digram/trigram statistics?
4. What if the key uses the KRYPTOS alphabet mapping instead of standard?
5. What words/phrases could produce the key fragments?
"""

import json
import math
import random
import time
from collections import Counter
from pathlib import Path

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, MOD, ALPH_IDX, CRIB_DICT,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    KRYPTOS_ALPHABET,
)


# Language frequency tables (approximate, from standard sources)
ENGLISH_FREQ = {
    'A': 0.0817, 'B': 0.0149, 'C': 0.0278, 'D': 0.0425, 'E': 0.1270,
    'F': 0.0223, 'G': 0.0202, 'H': 0.0609, 'I': 0.0697, 'J': 0.0015,
    'K': 0.0077, 'L': 0.0403, 'M': 0.0241, 'N': 0.0675, 'O': 0.0751,
    'P': 0.0193, 'Q': 0.0010, 'R': 0.0599, 'S': 0.0633, 'T': 0.0906,
    'U': 0.0276, 'V': 0.0098, 'W': 0.0236, 'X': 0.0015, 'Y': 0.0197,
    'Z': 0.0007,
}

GERMAN_FREQ = {
    'A': 0.0651, 'B': 0.0189, 'C': 0.0306, 'D': 0.0508, 'E': 0.1740,
    'F': 0.0166, 'G': 0.0301, 'H': 0.0476, 'I': 0.0755, 'J': 0.0027,
    'K': 0.0121, 'L': 0.0344, 'M': 0.0253, 'N': 0.0978, 'O': 0.0251,
    'P': 0.0079, 'Q': 0.0002, 'R': 0.0700, 'S': 0.0727, 'T': 0.0615,
    'U': 0.0435, 'V': 0.0067, 'W': 0.0189, 'X': 0.0003, 'Y': 0.0004,
    'Z': 0.0113,
}

FRENCH_FREQ = {
    'A': 0.0764, 'B': 0.0090, 'C': 0.0326, 'D': 0.0367, 'E': 0.1472,
    'F': 0.0107, 'G': 0.0087, 'H': 0.0074, 'I': 0.0753, 'J': 0.0055,
    'K': 0.0005, 'L': 0.0546, 'M': 0.0297, 'N': 0.0710, 'O': 0.0579,
    'P': 0.0302, 'Q': 0.0136, 'R': 0.0655, 'S': 0.0795, 'T': 0.0724,
    'U': 0.0638, 'V': 0.0163, 'W': 0.0011, 'X': 0.0039, 'Y': 0.0031,
    'Z': 0.0014,
}

LATIN_FREQ = {
    'A': 0.0863, 'B': 0.0145, 'C': 0.0458, 'D': 0.0354, 'E': 0.1228,
    'F': 0.0103, 'G': 0.0127, 'H': 0.0116, 'I': 0.1115, 'J': 0.0001,
    'K': 0.0001, 'L': 0.0310, 'M': 0.0572, 'N': 0.0630, 'O': 0.0519,
    'P': 0.0350, 'Q': 0.0158, 'R': 0.0614, 'S': 0.0735, 'T': 0.0826,
    'U': 0.0847, 'V': 0.0095, 'W': 0.0001, 'X': 0.0045, 'Y': 0.0012,
    'Z': 0.0003,
}


def log_likelihood(text_letters, freq_table):
    """Compute log-likelihood of a letter sequence under a given frequency model."""
    ll = 0
    for ch in text_letters:
        f = freq_table.get(ch, 1e-6)
        ll += math.log(f)
    return ll


def chi_squared_gof(observed_counts, expected_freqs, total):
    """Chi-squared goodness of fit."""
    chi2 = 0
    for ch in ALPH:
        obs = observed_counts.get(ch, 0)
        exp = expected_freqs.get(ch, 1/26) * total
        if exp > 0:
            chi2 += (obs - exp) ** 2 / exp
    return chi2


def main():
    start_time = time.time()
    random.seed(42)
    results = {}

    print("=" * 70)
    print("E-FRAC-24: Running Key Language Profile Analysis")
    print("=" * 70)

    # Build key as letters under standard alphabet
    beau_vals = list(BEAUFORT_KEY_ENE) + list(BEAUFORT_KEY_BC)
    beau_letters = [ALPH[v] for v in beau_vals]
    beau_str = ''.join(beau_letters)

    # Build key as letters under KRYPTOS alphabet
    ka_idx = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
    beau_ka_letters = [KRYPTOS_ALPHABET[v] for v in beau_vals]
    beau_ka_str = ''.join(beau_ka_letters)

    print(f"\nBeaufort key at 24 crib positions:")
    print(f"  Standard alphabet: {beau_str}")
    print(f"  ENE: {beau_str[:13]}  BC: {beau_str[13:]}")
    print(f"  KRYPTOS alphabet:  {beau_ka_str}")
    print(f"  ENE: {beau_ka_str[:13]}  BC: {beau_ka_str[13:]}")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 1: Language Likelihood Analysis
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n" + "=" * 60)
    print("Part 1: Language Log-Likelihood (key as text)")
    print("=" * 60)

    languages = {
        'English': ENGLISH_FREQ,
        'German': GERMAN_FREQ,
        'French': FRENCH_FREQ,
        'Latin': LATIN_FREQ,
        'Uniform': {c: 1/26 for c in ALPH},
    }

    lang_results = {}
    for alpha_name, key_letters in [('Standard', beau_letters), ('KRYPTOS', beau_ka_letters)]:
        print(f"\n  Alphabet: {alpha_name} → key text: {''.join(key_letters)}")
        counts = Counter(key_letters)

        for lang_name, freq in languages.items():
            ll = log_likelihood(key_letters, freq)
            chi2 = chi_squared_gof(counts, freq, 24)
            # df = 25 for chi-squared with 26 categories
            print(f"    {lang_name:8s}: LL={ll:7.2f}  chi2={chi2:7.2f}")
            lang_results[f'{alpha_name}_{lang_name}'] = {'ll': ll, 'chi2': chi2}

    # Monte Carlo: how does the key's LL compare to random 24-char samples from each language?
    print("\n  Monte Carlo: key text LL percentile under each language")
    N_MC = 100_000
    for alpha_name, key_letters in [('Standard', beau_letters), ('KRYPTOS', beau_ka_letters)]:
        actual_lls = {}
        for lang_name, freq in languages.items():
            actual_lls[lang_name] = log_likelihood(key_letters, freq)

        for lang_name, freq in languages.items():
            if lang_name == 'Uniform':
                continue
            # Generate random 24-char samples from this language's distribution
            letters = list(ALPH)
            probs = [freq[c] for c in letters]
            mc_lls = []
            for _ in range(N_MC):
                sample = random.choices(letters, weights=probs, k=24)
                mc_lls.append(log_likelihood(sample, freq))

            pctile = sum(1 for x in mc_lls if x <= actual_lls[lang_name]) / N_MC
            print(f"    {alpha_name} key under {lang_name:8s}: LL={actual_lls[lang_name]:.2f}, "
                  f"percentile={pctile*100:.1f}%")
            lang_results[f'{alpha_name}_{lang_name}_pctile'] = pctile

    results['part1_language'] = lang_results

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 2: Triple Letter Analysis (KKK under standard, DDD under KA)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n" + "=" * 60)
    print("Part 2: Triple Letter Run Analysis")
    print("=" * 60)

    # How rare are triple-letter runs in natural language text?
    # In English, triple letters are essentially nonexistent within words.
    # Between words (e.g., "press secretary" -> ss + s at word boundary? No, that's "ss s", not sss)
    # The only way to get KKK in English is: very rare (Ku Klux Klan, some Finnish/Estonian loanwords)

    for alpha_name, triple_letter in [('Standard', 'K'), ('KRYPTOS', 'D')]:
        freq = ENGLISH_FREQ[triple_letter]
        # Probability of exactly 3 consecutive identical letters in a 24-char random English sample
        # at any position (positions 0-21, 22 possible starting points for a triple)
        p_triple_any = 1 - (1 - freq**3) ** 22  # Approximate (ignoring overlaps)
        p_triple_exact_pos = freq ** 3  # At a specific position

        print(f"\n  {alpha_name} alphabet: triple-letter = {triple_letter}{triple_letter}{triple_letter}")
        print(f"  English freq({triple_letter}) = {freq:.4f}")
        print(f"  P(3 consecutive {triple_letter}'s at specific position) = {p_triple_exact_pos:.6f}")
        print(f"  P(3 consecutive {triple_letter}'s anywhere in 24-char English text) ≈ {p_triple_any:.6f}")

    # How about triple of ANY letter?
    print(f"\n  P(any triple-letter run in 24-char text):")
    for lang_name, freq in [('English', ENGLISH_FREQ), ('German', GERMAN_FREQ), ('Uniform', {c: 1/26 for c in ALPH})]:
        p_no_triple = 1.0
        for pos in range(22):  # 22 possible starting positions for a triple
            p_triple_at_pos = sum(freq[c]**3 for c in ALPH)
            p_no_triple *= (1 - p_triple_at_pos)
        p_any_triple = 1 - p_no_triple
        print(f"    {lang_name:8s}: {p_any_triple:.4f}")

    # MC verification
    print(f"\n  Monte Carlo (100K samples of 24-char English text):")
    mc_triple_count = 0
    mc_kkk_count = 0
    for _ in range(N_MC):
        sample = random.choices(list(ALPH), weights=[ENGLISH_FREQ[c] for c in ALPH], k=24)
        has_triple = False
        has_kkk = False
        for i in range(22):
            if sample[i] == sample[i+1] == sample[i+2]:
                has_triple = True
                if sample[i] == 'K':
                    has_kkk = True
        if has_triple:
            mc_triple_count += 1
        if has_kkk:
            mc_kkk_count += 1

    print(f"    Any triple: {mc_triple_count}/{N_MC} = {mc_triple_count/N_MC*100:.3f}%")
    print(f"    KKK specifically: {mc_kkk_count}/{N_MC} = {mc_kkk_count/N_MC*100:.4f}%")

    results['part2_triple'] = {
        'mc_any_triple': mc_triple_count / N_MC,
        'mc_kkk': mc_kkk_count / N_MC,
    }

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 3: Digram/Trigram Analysis
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n" + "=" * 60)
    print("Part 3: Digram and Trigram Analysis")
    print("=" * 60)

    for alpha_name, key_str in [('Standard', beau_str), ('KRYPTOS', beau_ka_str)]:
        ene = key_str[:13]
        bc = key_str[13:]

        # Digrams
        ene_digrams = [ene[i:i+2] for i in range(len(ene)-1)]
        bc_digrams = [bc[i:i+2] for i in range(len(bc)-1)]

        # Trigrams
        ene_trigrams = [ene[i:i+3] for i in range(len(ene)-2)]
        bc_trigrams = [bc[i:i+3] for i in range(len(bc)-2)]

        print(f"\n  {alpha_name} alphabet:")
        print(f"    ENE digrams: {ene_digrams}")
        print(f"    BC digrams:  {bc_digrams}")
        print(f"    ENE trigrams: {ene_trigrams}")
        print(f"    BC trigrams:  {bc_trigrams}")

        # Count repeated digrams
        all_digrams = ene_digrams + bc_digrams
        di_counts = Counter(all_digrams)
        repeated = {d: c for d, c in di_counts.items() if c > 1}
        if repeated:
            print(f"    Repeated digrams: {repeated}")
        else:
            print(f"    No repeated digrams")

        all_trigrams = ene_trigrams + bc_trigrams
        tri_counts = Counter(all_trigrams)
        tri_repeated = {t: c for t, c in tri_counts.items() if c > 1}
        if tri_repeated:
            print(f"    Repeated trigrams: {tri_repeated}")

    results['part3_ngrams'] = {
        'std_ene_digrams': [beau_str[i:i+2] for i in range(12)],
        'std_bc_digrams': [beau_str[13+i:15+i] for i in range(10)],
    }

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 4: Letter Frequency Comparison with Known K4 Clue Texts
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n" + "=" * 60)
    print("Part 4: Key Distribution vs Known Clue Words")
    print("=" * 60)

    # The key text would be a continuous stretch of text.
    # What Kryptos-related words/phrases contain the letters K, G, O frequently?
    clue_words = [
        "KRYPTOS", "KRYPTOSABCDEFGHIJLMNQUVWXZ",
        "BERLINCLOCK", "EASTNORTHEAST",
        "SHADOW", "SHADOWFORCES", "PALIMPSEST",
        "VIRTUALLYINVISIBLE", "UNDERGRUUND",
        "DESPERATLY", "IQLUSION", "LAYERTWO",
        "DIGETAL", "INTERPRETATU",
    ]

    beau_counts = Counter(beau_str)
    print(f"\n  Key letter frequency: {dict(sorted(beau_counts.items(), key=lambda x:-x[1]))}")

    for word in clue_words:
        word = word.upper()
        word_counts = Counter(word)
        # Compute correlation between key frequency and word frequency
        overlap = sum(min(beau_counts.get(c, 0), word_counts.get(c, 0)) for c in ALPH)
        print(f"    '{word}': overlap={overlap}/{len(word)}")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 5: Beaufort Key as Running Key — What Text Matches?
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n" + "=" * 60)
    print("Part 5: What Running Key Text Would Produce This Key?")
    print("=" * 60)

    # Under Beaufort with running key: key[i] = source_text[i]
    # So the running key text at positions 21-33 would be: JLJODEGKUKKKL
    # and at positions 63-73 would be: OCGGBGOKTRU
    #
    # But if the running key starts at some offset before position 0,
    # then the text fragment at the relevant positions is what we see.

    ene_key = beau_str[:13]  # JLJODEGKUKKKL
    bc_key = beau_str[13:]   # OCGGBGOKTRU

    print(f"\n  If running key under Beaufort (standard alphabet):")
    print(f"    Source text at pos 21-33: {ene_key}")
    print(f"    Source text at pos 63-73: {bc_key}")
    print(f"    Gap (pos 34-62): 29 unknown characters")
    print(f"    Full partial: ...{ene_key}[29 unknown]{bc_key}...")

    print(f"\n  If running key under Beaufort (KRYPTOS alphabet):")
    print(f"    Source text at pos 21-33: {beau_ka_str[:13]}")
    print(f"    Source text at pos 63-73: {beau_ka_str[13:]}")

    # Search for these fragments in reference texts
    print(f"\n  Searching for '{ene_key}' and '{bc_key}' in reference texts...")

    reference_texts_dir = Path("reference")
    if reference_texts_dir.exists():
        for txt_file in sorted(reference_texts_dir.glob("*.txt")):
            try:
                text = txt_file.read_text().upper()
                text_alpha = ''.join(c for c in text if c.isalpha())

                # Search for exact matches
                for fragment, frag_name in [(ene_key, "ENE key"), (bc_key, "BC key")]:
                    idx = text_alpha.find(fragment)
                    if idx >= 0:
                        context = text_alpha[max(0,idx-10):idx+len(fragment)+10]
                        print(f"    FOUND '{fragment}' in {txt_file.name} at pos {idx}: ...{context}...")

                # Search for partial matches (>= 5 consecutive chars)
                for fragment, frag_name in [(ene_key, "ENE"), (bc_key, "BC")]:
                    for sublen in range(min(len(fragment), 8), 4, -1):
                        for start in range(len(fragment) - sublen + 1):
                            sub = fragment[start:start+sublen]
                            idx = text_alpha.find(sub)
                            if idx >= 0:
                                context = text_alpha[max(0,idx-5):idx+sublen+5]
                                print(f"    Partial match ({frag_name}[{start}:{start+sublen}]='{sub}') "
                                      f"in {txt_file.name}: ...{context}...")
                                break
                        else:
                            continue
                        break
            except Exception:
                pass

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 6: Constraint Summary — What Must Be True
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n" + "=" * 60)
    print("Part 6: Constraint Summary for the Key Source")
    print("=" * 60)

    print("""
  UNDER BEAUFORT WITH RUNNING KEY (standard alphabet):
  The key source text would need to contain:
  1. The substring 'KKK' at some position offset by +30 from the text start
     (positions 30-32 relative to K4, mapped to ENE crib)
  2. The letter G at positions 27, 65, 66, 68 (relative to K4)
     → G appears at 4 positions including two pairs distance 1 apart
  3. The letter K at positions 28, 30, 31, 32, 70
     → K appears at 5 positions including KKK run and one 38 positions later
  4. The letter O at positions 24, 63, 69
     → O appears spanning both crib regions

  CONSTRAINTS ON THE SOURCE TEXT:
  - Text[30:33] = 'KKK' → Triple K is virtually impossible in any Indo-European language
  - Text[27] = G and Text[65] = G (Bean equality: same key at distance 38)
  - Text[65] = G and Text[66] = G → 'GG' at positions 65-66
  - Text[28:33] = 'KUKKKL' → bizarre letter sequence for any natural language

  IMPLICATION: If the cipher is Beaufort with a running key from natural text,
  the KKK constraint essentially rules this out. The source text would need to be:
  a) A non-natural-language text (codes, abbreviations, coordinates)
  b) An extremely unusual passage
  c) OR: the Beaufort key is NOT a running key (something else generates it)
  """)

    # What about under KRYPTOS alphabet?
    print(f"  UNDER BEAUFORT WITH KRYPTOS ALPHABET:")
    print(f"  Key at pos 30-32 = D,D,D → still triple letter (DDD)")
    print(f"  This is slightly more plausible than KKK (D is more common)")
    print(f"  P(DDD at specific position in English): {ENGLISH_FREQ['D']**3:.6f}")
    print(f"  P(KKK at specific position in English): {ENGLISH_FREQ['K']**3:.6f}")
    print(f"  DDD is {ENGLISH_FREQ['D']**3/ENGLISH_FREQ['K']**3:.0f}x more likely than KKK")
    print(f"  But still very rare for any natural language")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 7: What if Transposition Exists?
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n" + "=" * 60)
    print("Part 7: Effect of Transposition on Key Interpretation")
    print("=" * 60)

    print("""
  If there is a transposition layer σ, the Beaufort key values we compute
  under direct correspondence are NOT the true key values.

  Apparent key[j] = (CT[j] + PT[j]) mod 26  (what we compute)
  True key[i]     = key at position i in the actual encryption

  If the true cipher is: CT[i] = (true_key[i] - PT[σ⁻¹(i)]) mod 26
  Then: apparent_key[j] = true_key[j] + (PT[j] - PT[σ⁻¹(j)]) mod 26
                        = true_key[j] + plaintext_displacement[j]

  The plaintext displacement depends on σ:
  - If σ(j) = j (no transposition at position j): displacement = 0, apparent = true
  - If σ(j) ≠ j: displacement = PT[j] - PT[σ⁻¹(j)], could be anything

  The low entropy of the apparent Beaufort key could be because:
  1. The true key has low entropy (key itself is structured) — BUT E-FRAC-23 eliminated this
  2. The transposition σ maps crib positions to OTHER crib positions,
     making the displacement terms small/structured
  3. The combination of true_key + displacement happens to have low entropy by chance

  For the KKK run (apparent_key[30]=apparent_key[31]=apparent_key[32]=10):
  true_key[30] + (PT[30] - PT[σ⁻¹(30)]) = 10
  true_key[31] + (PT[31] - PT[σ⁻¹(31)]) = 10
  true_key[32] + (PT[32] - PT[σ⁻¹(32)]) = 10

  PT[30]=E(4), PT[31]=A(0), PT[32]=S(18)

  If true_key is periodic: true_key[30] ≠ true_key[31] ≠ true_key[32] in general
  So the displacement terms must COMPENSATE: different true_key values + different
  displacements all summing to 10. This is much less constraining than requiring
  the source text to literally contain KKK.
  """)

    # Quantify: how often do 3 random (key + displacement) values all equal 10?
    # If key is uniform and displacement is uniform, each value is uniform,
    # so P(all three = 10) = (1/26)³ ≈ 5.7e-5
    # But if key is periodic with period p, and displacements depend on σ:
    # The constraint is: key[30] + d[30] = key[31] + d[31] = key[32] + d[32] = 10
    # i.e., d[30] - d[31] = key[31] - key[30], d[31] - d[32] = key[32] - key[31]
    # For periodic key with period ≤ 7: these are determined by 2 constraints on σ
    # Much less restrictive than KKK in source text

    # Monte Carlo: for random permutation σ and periodic key (period 5-7),
    # how often do apparent keys at 30-32 all have the same value?
    print(f"\n  Monte Carlo: P(apparent_key[30]=apparent_key[31]=apparent_key[32]) under transposition")

    pt_at_cribs = {}
    for pos in range(CT_LEN):
        if pos in CRIB_DICT:
            pt_at_cribs[pos] = ALPH_IDX[CRIB_DICT[pos]]

    N_MC_TRANS = 200_000
    triple_count = 0
    triple_k_count = 0

    for _ in range(N_MC_TRANS):
        # Random permutation
        perm = list(range(CT_LEN))
        random.shuffle(perm)

        # Random periodic key (period 5)
        period = random.randint(5, 7)
        base_key = [random.randint(0, 25) for _ in range(period)]
        true_key = [base_key[i % period] for i in range(CT_LEN)]

        # Compute apparent key at positions 30, 31, 32
        # CT[i] = (true_key[i] - PT[perm_inv[i]]) mod 26
        # apparent_key[j] = (CT[j] + PT[j]) mod 26
        # = (true_key[j] - PT[perm_inv[j]] + PT[j]) mod 26
        perm_inv = [0] * CT_LEN
        for i in range(CT_LEN):
            perm_inv[perm[i]] = i

        apparent_vals = []
        for pos in [30, 31, 32]:
            pt_j = pt_at_cribs.get(pos, random.randint(0, 25))
            pt_sigma = pt_at_cribs.get(perm_inv[pos], random.randint(0, 25))
            app_key = (true_key[pos] - pt_sigma + pt_j) % 26
            apparent_vals.append(app_key)

        if apparent_vals[0] == apparent_vals[1] == apparent_vals[2]:
            triple_count += 1
            if apparent_vals[0] == 10:
                triple_k_count += 1

    print(f"    P(triple match at 30-32): {triple_count/N_MC_TRANS*100:.3f}%")
    print(f"    P(triple = K at 30-32):   {triple_k_count/N_MC_TRANS*100:.4f}%")
    print(f"    Expected (uniform):       {100/26:.3f}% (triple match), {100/26/26:.4f}% (triple K)")

    results['part7_transposition'] = {
        'mc_triple_match': triple_count / N_MC_TRANS,
        'mc_triple_k': triple_k_count / N_MC_TRANS,
        'expected_triple_match': 1 / 26,
        'expected_triple_k': 1 / (26 * 26),
    }

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Summary
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    runtime = time.time() - start_time

    print("\n" + "=" * 70)
    print("SUMMARY: E-FRAC-24 — Running Key Language Profile")
    print("=" * 70)

    print(f"""
1. LANGUAGE COMPATIBILITY:
   The Beaufort key text (standard) = '{beau_str}' is poorly compatible
   with all tested natural languages due to the KKK triple and unusual
   letter distribution (5 K's, 4 G's in 24 chars).

2. TRIPLE LETTER RARITY:
   KKK in English: ~{mc_kkk_count/N_MC*100:.3f}% probability at any position in 24 chars
   Any triple: ~{mc_triple_count/N_MC*100:.3f}% in 24 chars of English
   → KKK effectively rules out English running key under Beaufort

3. IF TRANSPOSITION EXISTS:
   The apparent KKK need not be literal KKK in the source text.
   Under transposition + periodic key, P(triple match) ≈ {triple_count/N_MC_TRANS*100:.1f}%
   vs {100/26:.1f}% expected — {'comparable' if abs(triple_count/N_MC_TRANS - 1/26) < 0.02 else 'different'}.
   Transposition relaxes the constraint from "source text has KKK"
   to "key + displacement values happen to align."

4. IMPLICATIONS:
   - Without transposition: running key from natural text is essentially ruled out
   - With transposition: the KKK pattern is explained as a coincidence of key+displacement
   - This is weak evidence FOR the existence of a transposition layer
   - The Beaufort key structure may be a CONSEQUENCE of transposition, not a
     property of the key generation method itself
""")

    print(f"Runtime: {runtime:.1f}s")
    print(f"RESULT: running_key_natural_text_eliminated={'yes' if mc_kkk_count < 10 else 'no'} "
          f"transposition_explains_pattern={'yes' if abs(triple_count/N_MC_TRANS - 1/26) < 0.02 else 'partially'} "
          f"verdict=RUNNING_KEY_UNLIKELY_WITHOUT_TRANSPOSITION")

    results['summary'] = {
        'verdict': 'RUNNING_KEY_UNLIKELY_WITHOUT_TRANSPOSITION',
        'kkk_probability_english': mc_kkk_count / N_MC,
        'transposition_triple_probability': triple_count / N_MC_TRANS,
        'expected_triple_probability': 1 / 26,
        'runtime': runtime,
    }

    # Save
    out_dir = Path("results/frac")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "e_frac_24_running_key_profile.json"
    with open(out_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nResults saved to {out_path}")


if __name__ == '__main__':
    main()
