#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-152: NATO / Military Protocol Cipher Hypotheses

Tests derived from NATO phonetic alphabet and COMSEC research:

1. NATO word crib drag: CHARLIE, TANGO, CHECKPOINT, etc. at all valid
   positions.  For each placement, compute Vig/Beaufort key segment and
   check whether the combined key (existing cribs + new word) looks
   English-like (quadgram score of key letters).  A high-scoring key
   would indicate a running-key cipher.

2. Running key search under KA (KRYPTOS-keyed) alphabet:
   ALL prior running-key searches used standard A-Z Vigenère.
   If the Vigenère tableau on the sculpture uses the KA alphabet ordering,
   the keystream is different.  This test re-runs the running-key search
   from known texts under KA-Vigenère and KA-Beaufort.

3. VIC-style chain addition key generation:
   Lagged Fibonacci mod 26 with seeds from Kryptos words.
   Each seed generates a 97-char key; test direct decryption.

4. KA keystream analysis:
   Compute keystream at crib positions under KA alphabet.
   Check for statistical anomalies (letter frequency, patterns).
"""

import json, os, sys, time, glob, math
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, CRIB_WORDS,
    KRYPTOS_ALPHABET, ALPH, ALPH_IDX,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)

REPO = Path(__file__).resolve().parents[1]
N = CT_LEN
CT_NUM = [ALPH_IDX[c] for c in CT]

# KA alphabet
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}
KA_NUM = [ALPH_IDX[c] for c in KA]  # standard A=0..Z=25 value of each KA position

# Crib positions and values
CRIB_POS = {}  # pos -> pt letter number (A=0)
for start, word in CRIB_WORDS:
    for i, ch in enumerate(word):
        CRIB_POS[start + i] = ALPH_IDX[ch]

# Known Vigenère key at crib positions (standard AZ)
VIG_KEY_AT = {pos: (CT_NUM[pos] - pt) % 26 for pos, pt in CRIB_POS.items()}
# Known Beaufort key at crib positions (standard AZ)
BEAU_KEY_AT = {pos: (CT_NUM[pos] + pt) % 26 for pos, pt in CRIB_POS.items()}

# ── Quadgram scoring ─────────────────────────────────────────────────────

QUADGRAM_PATH = REPO / 'data' / 'english_quadgrams.json'
QUADGRAMS = {}
QG_FLOOR = -10.0

def load_quadgrams():
    global QUADGRAMS, QG_FLOOR
    with open(QUADGRAM_PATH) as f:
        QUADGRAMS = json.load(f)
    total = sum(10**v for v in QUADGRAMS.values())
    QG_FLOOR = math.log10(0.01 / total)

def quadgram_score(text):
    """Return average log10-probability per character."""
    text = text.upper()
    if len(text) < 4:
        return QG_FLOOR
    s = sum(QUADGRAMS.get(text[i:i+4], QG_FLOOR) for i in range(len(text) - 3))
    return s / len(text)

# ── Helpers ──────────────────────────────────────────────────────────────

def decrypt_vig(ct_num, key_num):
    """Standard Vigenère decrypt: pt = (ct - key) mod 26"""
    return [(c - k) % 26 for c, k in zip(ct_num, key_num)]

def decrypt_beau(ct_num, key_num):
    """Beaufort decrypt: pt = (key - ct) mod 26"""
    return [(k - c) % 26 for c, k in zip(ct_num, key_num)]

def decrypt_ka_vig(ct_num, key_num):
    """KA-Vigenère decrypt: pt = KA[(KA_inv(ct) - KA_inv(key)) mod 26]
    where KA_inv maps letter to its position in KA alphabet."""
    result = []
    for c, k in zip(ct_num, key_num):
        ct_ka = KA_IDX[ALPH[c]]
        key_ka = KA_IDX[ALPH[k]]
        pt_ka = (ct_ka - key_ka) % 26
        result.append(ALPH_IDX[KA[pt_ka]])
    return result

def decrypt_ka_beau(ct_num, key_num):
    """KA-Beaufort decrypt: pt = KA[(KA_inv(key) - KA_inv(ct)) mod 26]"""
    result = []
    for c, k in zip(ct_num, key_num):
        ct_ka = KA_IDX[ALPH[c]]
        key_ka = KA_IDX[ALPH[k]]
        pt_ka = (key_ka - ct_ka) % 26
        result.append(ALPH_IDX[KA[pt_ka]])
    return result

def nums_to_str(nums):
    return ''.join(ALPH[n] for n in nums)

def count_crib_matches(pt_nums):
    """Count how many crib positions match."""
    return sum(1 for pos, expected in CRIB_POS.items() if pt_nums[pos] == expected)

# ══════════════════════════════════════════════════════════════════════════
# TEST 1: NATO Word Crib Drag
# ══════════════════════════════════════════════════════════════════════════

def test_nato_crib_drag():
    print("=" * 70)
    print("TEST 1: NATO Word Crib Drag")
    print("=" * 70)

    NATO_WORDS = [
        "CHARLIE", "TANGO", "FOXTROT", "ALPHA", "BRAVO", "DELTA",
        "ECHO", "HOTEL", "INDIA", "JULIET", "KILO", "LIMA", "MIKE",
        "NOVEMBER", "OSCAR", "PAPA", "QUEBEC", "ROMEO", "SIERRA",
        "UNIFORM", "VICTOR", "WHISKEY", "XRAY", "YANKEE", "ZULU",
        "CHECKPOINT", "POSITION", "CONTACT", "ROGER", "AFFIRM",
        "NEGATIVE", "MAYDAY", "SECRET", "REMINDER", "MESSAGE",
        "DECODED", "TWOCLOCK", "OCLOCK", "CHECKPOINT",
    ]
    # Deduplicate
    NATO_WORDS = list(dict.fromkeys(NATO_WORDS))

    crib_ranges = set()
    for start, word in CRIB_WORDS:
        for i in range(len(word)):
            crib_ranges.add(start + i)

    results = []

    for word in NATO_WORDS:
        wnum = [ALPH_IDX[c] for c in word]
        wlen = len(word)

        for start in range(N - wlen + 1):
            # Skip if overlaps existing cribs
            positions = set(range(start, start + wlen))
            if positions & crib_ranges:
                continue

            # Vigenère key for this placement
            vig_seg = [(CT_NUM[start + i] - wnum[i]) % 26 for i in range(wlen)]
            # Beaufort key
            beau_seg = [(CT_NUM[start + i] + wnum[i]) % 26 for i in range(wlen)]

            for variant, seg in [("Vig", vig_seg), ("Beau", beau_seg)]:
                key_str = nums_to_str(seg)
                qg = quadgram_score(key_str) if wlen >= 4 else -10.0
                results.append({
                    'word': word, 'pos': start, 'variant': variant,
                    'key': key_str, 'qg': qg
                })

    # Sort by quadgram score (higher = more English-like key)
    results.sort(key=lambda r: -r['qg'])

    # English text typically scores around -4.2 to -4.8 per char
    # Random text scores around -5.5 to -6.0 per char
    print(f"\nTotal placements tested: {len(results)}")
    print(f"\nTop 30 placements by key quadgram score (higher = more English-like):")
    print(f"{'Word':12s} {'Pos':>4s} {'Var':5s} {'Key':20s} {'QG/c':>7s}")
    print("-" * 55)
    for r in results[:30]:
        print(f"{r['word']:12s} {r['pos']:4d} {r['variant']:5s} {r['key']:20s} {r['qg']:7.3f}")

    # Check: any key scoring above -5.0 (plausibly English)?
    english_like = [r for r in results if r['qg'] > -5.0]
    print(f"\nPlacements with key QG > -5.0 (plausibly English): {len(english_like)}")
    for r in english_like[:10]:
        print(f"  {r['word']:12s} @ {r['pos']:3d} ({r['variant']}) key={r['key']} QG={r['qg']:.3f}")

    return results

# ══════════════════════════════════════════════════════════════════════════
# TEST 2: Running Key under KA Alphabet
# ══════════════════════════════════════════════════════════════════════════

def test_ka_running_key():
    print("\n" + "=" * 70)
    print("TEST 2: Running Key under KA (KRYPTOS-keyed) Alphabet")
    print("=" * 70)

    # Compute KA-Vigenère keystream at crib positions
    print("\nKA keystream at crib positions:")
    ka_vig_key = {}
    ka_beau_key = {}
    for pos, pt in CRIB_POS.items():
        ct_ka = KA_IDX[ALPH[CT_NUM[pos]]]
        pt_ka = KA_IDX[ALPH[pt]]
        ka_vig_key[pos] = (ct_ka - pt_ka) % 26
        ka_beau_key[pos] = (ct_ka + pt_ka) % 26

    # Print comparison
    print(f"\n{'Pos':>4s} {'CT':>3s} {'PT':>3s} {'AZ-Vig':>7s} {'AZ-Beau':>8s} {'KA-Vig':>7s} {'KA-Beau':>8s}")
    print("-" * 50)
    for pos in sorted(CRIB_POS.keys()):
        az_v = VIG_KEY_AT[pos]
        az_b = BEAU_KEY_AT[pos]
        ka_v = ka_vig_key[pos]
        ka_b = ka_beau_key[pos]
        print(f"{pos:4d}  {ALPH[CT_NUM[pos]]:>2s}  {ALPH[CRIB_POS[pos]]:>2s}   "
              f"{ALPH[az_v]:>2s}({az_v:2d})  {ALPH[az_b]:>2s}({az_b:2d})   "
              f"{KA[ka_v]:>2s}({ka_v:2d})  {KA[ka_b]:>2s}({ka_b:2d})")

    # Analyze KA-Vig key letter frequencies
    ka_vig_letters = [KA[ka_vig_key[p]] for p in sorted(CRIB_POS.keys())]
    ka_beau_letters = [KA[ka_beau_key[p]] for p in sorted(CRIB_POS.keys())]
    print(f"\nKA-Vig key letters (ENE+BC): {''.join(ka_vig_letters)}")
    print(f"KA-Beau key letters (ENE+BC): {''.join(ka_beau_letters)}")

    # Frequency analysis
    for name, letters in [("KA-Vig", ka_vig_letters), ("KA-Beau", ka_beau_letters)]:
        freq = Counter(letters)
        most_common = freq.most_common(5)
        print(f"\n{name} frequency: {dict(freq)}")
        print(f"  Most common: {most_common}")
        # Statistical test: expected = 24/26 ≈ 0.92 per letter
        # If any letter appears 5+ times in 24, binomial(24, 5, 1/26) ≈ 5.7e-5
        for letter, count in most_common:
            if count >= 4:
                # Exact binomial probability
                from math import comb
                p = 1/26
                prob = sum(comb(24, k) * p**k * (1-p)**(24-k) for k in range(count, 25))
                print(f"  {letter} appears {count}x: P(>={count}) = {prob:.6f}")

    # === Running key search under KA alphabet ===
    print("\n--- Running key search under KA alphabet ---")

    # Load known texts
    texts = {}
    # K1-K3 plaintexts
    texts['K1'] = 'BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION'
    texts['K2'] = ('ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETIC'
                   'FIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOAN'
                   'UNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHISXTHEYSHOULDITSBURIED'
                   'OUTTHERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONXONLYWWTHISWASHIS'
                   'LASTMESSAGEXTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVE'
                   'SECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWEST'
                   'XLAYERTWO')
    texts['K3'] = ('SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBABORSWERE'
                   'DISCOVEREDALEADTOTHEDOORWAYWASONLYEXTENDEDLABORUNDERGOROUD'
                   'LEADTOLAROKINGTUTSEPULCHURALSROOM')

    # Load reference texts
    text_dir = REPO / 'reference' / 'running_key_texts'
    if text_dir.exists():
        for fp in text_dir.glob('*.txt'):
            raw = fp.read_text(errors='ignore')
            clean = ''.join(c for c in raw.upper() if c in ALPH)
            if len(clean) >= N:
                texts[fp.stem] = clean

    # Also check main reference dir for larger texts
    ref_dir = REPO / 'reference'
    for fp in ref_dir.glob('*.txt'):
        raw = fp.read_text(errors='ignore')
        clean = ''.join(c for c in raw.upper() if c in ALPH)
        if len(clean) >= N:
            texts[f'ref_{fp.stem}'] = clean

    print(f"Loaded {len(texts)} texts for running key search")

    best_results = []

    for text_name, text in texts.items():
        text_num = [ALPH_IDX[c] for c in text if c in ALPH_IDX]

        # Try all offsets
        for offset in range(len(text_num) - N + 1):
            key_seg = text_num[offset:offset + N]

            # Test 4 variants: AZ-Vig, AZ-Beau, KA-Vig, KA-Beau
            for variant_name, decrypt_fn in [
                ("KA-Vig", decrypt_ka_vig),
                ("KA-Beau", decrypt_ka_beau),
            ]:
                pt_nums = decrypt_fn(CT_NUM, key_seg)
                matches = count_crib_matches(pt_nums)

                if matches >= 8:  # Report threshold
                    pt_str = nums_to_str(pt_nums)
                    qg = quadgram_score(pt_str)
                    best_results.append({
                        'text': text_name, 'offset': offset,
                        'variant': variant_name, 'matches': matches,
                        'qg': qg, 'pt_preview': pt_str[:40]
                    })

    best_results.sort(key=lambda r: (-r['matches'], -r['qg']))
    print(f"\nKA running key results with >= 8 crib matches: {len(best_results)}")
    for r in best_results[:20]:
        print(f"  {r['text']:20s} off={r['offset']:5d} {r['variant']:8s} "
              f"cribs={r['matches']:2d} qg={r['qg']:.3f} pt={r['pt_preview']}")

    # Also test AZ variants for comparison (should match prior results)
    print("\n--- AZ comparison (should match prior results) ---")
    az_results = []
    for text_name, text in texts.items():
        text_num = [ALPH_IDX[c] for c in text if c in ALPH_IDX]
        for offset in range(len(text_num) - N + 1):
            key_seg = text_num[offset:offset + N]
            for variant_name, decrypt_fn in [
                ("AZ-Vig", decrypt_vig),
                ("AZ-Beau", decrypt_beau),
            ]:
                pt_nums = decrypt_fn(CT_NUM, key_seg)
                matches = count_crib_matches(pt_nums)
                if matches >= 8:
                    pt_str = nums_to_str(pt_nums)
                    qg = quadgram_score(pt_str)
                    az_results.append({
                        'text': text_name, 'offset': offset,
                        'variant': variant_name, 'matches': matches,
                        'qg': qg
                    })

    az_results.sort(key=lambda r: (-r['matches'], -r['qg']))
    print(f"AZ running key results with >= 8 crib matches: {len(az_results)}")
    for r in az_results[:10]:
        print(f"  {r['text']:20s} off={r['offset']:5d} {r['variant']:8s} "
              f"cribs={r['matches']:2d} qg={r['qg']:.3f}")

    return best_results

# ══════════════════════════════════════════════════════════════════════════
# TEST 3: VIC-style Chain Addition Key
# ══════════════════════════════════════════════════════════════════════════

def test_chain_addition_keys():
    print("\n" + "=" * 70)
    print("TEST 3: VIC-style Chain Addition Key Generation")
    print("=" * 70)

    def chain_addition(seed, length, modulus=26):
        """Lagged Fibonacci: x[n] = (x[n-lag] + x[n-1]) mod m, lag = len(seed)"""
        lag = len(seed)
        seq = list(seed)
        while len(seq) < length:
            seq.append((seq[-lag] + seq[-1]) % modulus)
        return seq[:length]

    def chain_addition_v2(seed, length, modulus=26):
        """VIC-style: x[n] = (x[n-lag] + x[n-lag+1]) mod m (adjacent pair sum)"""
        lag = len(seed)
        seq = list(seed)
        while len(seq) < length:
            idx = len(seq) - lag
            seq.append((seq[idx] + seq[idx + 1]) % modulus)
        return seq[:length]

    # Seeds from Kryptos-related words
    seeds = {
        'KRYPTOS': [ALPH_IDX[c] for c in 'KRYPTOS'],
        'PALIMPSEST': [ALPH_IDX[c] for c in 'PALIMPSEST'],
        'ABSCISSA': [ALPH_IDX[c] for c in 'ABSCISSA'],
        'BERLIN': [ALPH_IDX[c] for c in 'BERLIN'],
        'CLOCK': [ALPH_IDX[c] for c in 'CLOCK'],
        'BERLINCLOCK': [ALPH_IDX[c] for c in 'BERLINCLOCK'],
        'EASTNORTHEAST': [ALPH_IDX[c] for c in 'EASTNORTHEAST'],
        'SCHEIDT': [ALPH_IDX[c] for c in 'SCHEIDT'],
        'SANBORN': [ALPH_IDX[c] for c in 'SANBORN'],
        'DRYAD': [ALPH_IDX[c] for c in 'DRYAD'],
        'CHARLIE': [ALPH_IDX[c] for c in 'CHARLIE'],
        'TANGO': [ALPH_IDX[c] for c in 'TANGO'],
        'ENE_bearing': [0, 6, 7, 5, 0],  # 067.50 degrees
        'TWO_OCLOCK': [2],  # clock position
        'KA_from_T': [KA_IDX[c] for c in 'KRYPTOSABCDEFGHIJLMNQUVWXZ'[4:]],  # KA starting from T
    }

    results = []

    for seed_name, seed in seeds.items():
        if len(seed) < 2:
            continue

        for gen_name, gen_fn in [("lag_fib", chain_addition), ("vic_adj", chain_addition_v2)]:
            key = gen_fn(seed, N)

            # Test all 4 decrypt variants
            for var_name, dec_fn in [
                ("AZ-Vig", decrypt_vig),
                ("AZ-Beau", decrypt_beau),
                ("KA-Vig", decrypt_ka_vig),
                ("KA-Beau", decrypt_ka_beau),
            ]:
                pt_nums = dec_fn(CT_NUM, key)
                matches = count_crib_matches(pt_nums)
                pt_str = nums_to_str(pt_nums)
                qg = quadgram_score(pt_str)

                results.append({
                    'seed': seed_name, 'gen': gen_name, 'variant': var_name,
                    'matches': matches, 'qg': qg,
                    'key_preview': nums_to_str(key[:15]),
                    'pt_preview': pt_str[:30]
                })

    results.sort(key=lambda r: (-r['matches'], -r['qg']))

    print(f"\nTotal chain keys tested: {len(results)}")
    print(f"\nTop 20 by crib matches:")
    print(f"{'Seed':15s} {'Gen':8s} {'Var':8s} {'Cribs':>5s} {'QG/c':>7s} {'Key':15s} {'PT':30s}")
    print("-" * 95)
    for r in results[:20]:
        print(f"{r['seed']:15s} {r['gen']:8s} {r['variant']:8s} "
              f"{r['matches']:5d} {r['qg']:7.3f} {r['key_preview']:15s} {r['pt_preview']:30s}")

    # Expected random at period ~∞ is ~0-2 matches (since key is pseudorandom, not periodic)
    high = [r for r in results if r['matches'] >= 4]
    print(f"\nResults with >= 4 crib matches: {len(high)}")

    return results

# ══════════════════════════════════════════════════════════════════════════
# TEST 4: KA Keystream Anomaly Analysis
# ══════════════════════════════════════════════════════════════════════════

def test_ka_keystream_anomaly():
    print("\n" + "=" * 70)
    print("TEST 4: KA Keystream Anomaly Analysis")
    print("=" * 70)

    # Compute all 4 keystream variants at crib positions
    variants = {}
    for pos, pt in CRIB_POS.items():
        ct_az = CT_NUM[pos]
        ct_ka = KA_IDX[ALPH[ct_az]]
        pt_ka = KA_IDX[ALPH[pt]]

        variants.setdefault('AZ-Vig', {})[pos] = (ct_az - pt) % 26
        variants.setdefault('AZ-Beau', {})[pos] = (ct_az + pt) % 26
        variants.setdefault('KA-Vig', {})[pos] = (ct_ka - pt_ka) % 26
        variants.setdefault('KA-Beau', {})[pos] = (ct_ka + pt_ka) % 26

    # For each variant, analyze the distribution
    from math import comb
    for var_name, keystream in variants.items():
        values = [keystream[p] for p in sorted(keystream.keys())]
        if var_name.startswith('KA'):
            letters = [KA[v] for v in values]
        else:
            letters = [ALPH[v] for v in values]

        freq = Counter(letters)
        print(f"\n{var_name} keystream: {''.join(letters)}")

        # Chi-squared test against uniform
        expected = len(values) / 26
        chi2 = sum((count - expected)**2 / expected for count in freq.values())
        # Add zero-count letters
        chi2 += (26 - len(freq)) * expected
        print(f"  Chi-squared (uniform): {chi2:.2f} (df=25, critical_0.05=37.65)")

        # Most common
        for letter, count in freq.most_common(3):
            if count >= 3:
                p = 1/26
                prob = sum(comb(24, k) * p**k * (1-p)**(24-k) for k in range(count, 25))
                print(f"  {letter} appears {count}x: P(>={count}|uniform) = {prob:.6f}")

    # Specific check: KA-Vig ENE key has many Z's (= -1 shift in KA space)
    print("\n--- Specific: KA-Vig keystream by crib region ---")
    ene_positions = list(range(21, 34))
    bc_positions = list(range(63, 74))

    for region, positions in [("ENE (21-33)", ene_positions), ("BC (63-73)", bc_positions)]:
        ka_vig = [KA[variants['KA-Vig'][p]] for p in positions]
        print(f"  {region}: {''.join(ka_vig)}")

    # Check: does the KA-Vig key at position 27 equal position 65? (Bean equality)
    p27_ka = variants['KA-Vig'][27]
    p65_ka = variants['KA-Vig'][65]
    print(f"\n  Bean check: KA-Vig key[27] = {KA[p27_ka]}({p27_ka}), "
          f"key[65] = {KA[p65_ka]}({p65_ka}) → {'PASS' if p27_ka == p65_ka else 'FAIL'}")

    # Standard Vig Bean check for comparison
    p27_az = variants['AZ-Vig'][27]
    p65_az = variants['AZ-Vig'][65]
    print(f"  Bean check: AZ-Vig key[27] = {ALPH[p27_az]}({p27_az}), "
          f"key[65] = {ALPH[p65_az]}({p65_az}) → {'PASS' if p27_az == p65_az else 'FAIL'}")

# ══════════════════════════════════════════════════════════════════════════
# TEST 5: DRYAD-like with Vigenère tableau + specific row sequences
# ══════════════════════════════════════════════════════════════════════════

def test_dryad_row_sequences():
    print("\n" + "=" * 70)
    print("TEST 5: DRYAD-like Cipher with Specific Row Sequences")
    print("=" * 70)

    # If the Vigenère tableau on the sculpture IS the "coding chart",
    # and rows are selected by a specific sequence, what row sequences
    # give the best crib match?

    # Under standard Vig tableau: CT[i] = (PT[i] + row[i]) mod 26
    # So row[i] = (CT[i] - PT[i]) mod 26 = the standard Vig key
    # We already know this key is non-periodic.

    # Under KA-keyed tableau: row selection in KA space
    # CT[i] = KA[(KA_inv(PT[i]) + row_ka[i]) mod 26]
    # row_ka[i] = (KA_inv(CT[i]) - KA_inv(PT[i])) mod 26

    # Test specific row-selection sequences that might have been used:

    sequences = {}

    # 1. KA alphabet cycling from T (position 4 in KA)
    t_pos = KA_IDX['T']  # = 4
    sequences['KA_from_T'] = [(t_pos + i) % 26 for i in range(N)]

    # 2. KA alphabet cycling from K (position 0 in KA)
    sequences['KA_from_K'] = [i % 26 for i in range(N)]

    # 3. Reverse KA from T
    sequences['KA_rev_from_T'] = [(t_pos - i) % 26 for i in range(N)]

    # 4. KRYPTOS repeating (period 7)
    kryptos_vals = [KA_IDX[c] for c in 'KRYPTOS']
    sequences['KRYPTOS_p7'] = [kryptos_vals[i % 7] for i in range(N)]

    # 5. PALIMPSEST repeating (period 10)
    palimpsest_vals = [KA_IDX[c] for c in 'PALIMPSEST']
    sequences['PALIMPSEST_p10'] = [palimpsest_vals[i % 10] for i in range(N)]

    # 6. Row number = position (identity)
    sequences['pos_mod26'] = [i % 26 for i in range(N)]

    # 7. Row = CT value (autokey-like)
    sequences['ct_autokey'] = [KA_IDX[ALPH[CT_NUM[i]]] for i in range(N)]

    # 8. Row = previous CT (ciphertext autokey, shift by 1)
    sequences['ct_autokey_lag1'] = [0] + [KA_IDX[ALPH[CT_NUM[i]]] for i in range(N-1)]

    # 9. Fibonacci-like from KRYPTOS seed
    fib_seed = [KA_IDX[c] for c in 'KRYPTOS']
    seq = list(fib_seed)
    while len(seq) < N:
        seq.append((seq[-7] + seq[-1]) % 26)
    sequences['kryptos_fib7'] = seq[:N]

    # 10. Row derived from compass bearing: 67.5° → various interpretations
    sequences['bearing_0675'] = [(0*26 + 6*26 + 7*26 + 5*26) % 26] * N  # constant (not useful but for completeness)

    results = []

    for seq_name, row_seq in sequences.items():
        # Build key in standard A-Z space from KA row sequence
        # If using KA tableau: PT = KA[(KA_inv(CT) - row_ka) mod 26]
        pt_nums = []
        for i in range(N):
            ct_ka = KA_IDX[ALPH[CT_NUM[i]]]
            pt_ka = (ct_ka - row_seq[i]) % 26
            pt_nums.append(ALPH_IDX[KA[pt_ka]])

        matches = count_crib_matches(pt_nums)
        pt_str = nums_to_str(pt_nums)
        qg = quadgram_score(pt_str)

        results.append({
            'sequence': seq_name, 'variant': 'KA-tableau',
            'matches': matches, 'qg': qg,
            'pt_preview': pt_str[:40]
        })

        # Also test with standard AZ tableau
        pt_nums_az = [(CT_NUM[i] - row_seq[i]) % 26 for i in range(N)]
        matches_az = count_crib_matches(pt_nums_az)
        pt_str_az = nums_to_str(pt_nums_az)
        qg_az = quadgram_score(pt_str_az)

        results.append({
            'sequence': seq_name, 'variant': 'AZ-tableau',
            'matches': matches_az, 'qg': qg_az,
            'pt_preview': pt_str_az[:40]
        })

    results.sort(key=lambda r: (-r['matches'], -r['qg']))

    print(f"\nTotal row sequences tested: {len(sequences)} × 2 tableaux = {len(results)}")
    print(f"\nAll results:")
    print(f"{'Sequence':20s} {'Tableau':11s} {'Cribs':>5s} {'QG/c':>7s} {'PT preview':40s}")
    print("-" * 90)
    for r in results:
        print(f"{r['sequence']:20s} {r['variant']:11s} "
              f"{r['matches']:5d} {r['qg']:7.3f} {r['pt_preview']:40s}")

    return results

# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    t0 = time.time()

    load_quadgrams()
    print(f"Quadgrams loaded: {len(QUADGRAMS)} entries")

    r1 = test_nato_crib_drag()
    r2 = test_ka_running_key()
    r3 = test_chain_addition_keys()
    test_ka_keystream_anomaly()
    r5 = test_dryad_row_sequences()

    elapsed = time.time() - t0

    # Save results
    os.makedirs(REPO / 'results', exist_ok=True)
    artifact = {
        'experiment': 'E-S-152',
        'name': 'NATO/Military Protocol Cipher Hypotheses',
        'elapsed_seconds': elapsed,
        'nato_crib_top10': r1[:10] if r1 else [],
        'ka_running_key_top10': r2[:10] if r2 else [],
        'chain_addition_top10': r3[:10] if r3 else [],
        'dryad_sequences': r5,
    }
    artifact_path = REPO / 'results' / 'e_s_152_nato_protocol.json'
    with open(artifact_path, 'w') as f:
        json.dump(artifact, f, indent=2)

    print(f"\n{'=' * 70}")
    print(f"E-S-152 COMPLETE — {elapsed:.1f}s")
    print(f"Artifact: {artifact_path}")
    print(f"{'=' * 70}")
