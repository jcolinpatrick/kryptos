#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-OPGOLD-02: K2-Derived Words + YAR Superscript as K4 Cipher Keys

Tests the progressive-solve hypothesis: understanding K2's meaning (Operation Gold,
a CIA/MI6 Berlin tunnel wiretapping operation) helps crack K4. The YAR superscript
letters at the K3/K4 boundary (Y=24, A=0, R=17 in A=0 numbering) may combine with
K2-derived information to form the K4 key.

Test groups:
1. K2 keywords as Vig/Beaufort keys (repeating)
2. K2 keywords concatenated with YAR / DYAR
3. K2 keywords with YAR values as Caesar shifts (cycling +24, +0, +17)
4. K2 first-letter acronym as running key
5. YAR as offset into K2 plaintext → running key
6. WW + YAR combinations
7. DYAR variant keywords
8. Operation Gold words + YAR
"""

import json, os, sys, time, math
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, CRIB_WORDS,
    KRYPTOS_ALPHABET, ALPH, ALPH_IDX,
)

REPO = Path(__file__).resolve().parents[1]
N = CT_LEN
CT_NUM = [ALPH_IDX[c] for c in CT]

# Crib positions and values
CRIB_POS = {}
for start, word in CRIB_WORDS:
    for i, ch in enumerate(word):
        CRIB_POS[start + i] = ALPH_IDX[ch]

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

def decrypt_vb(ct_num, key_num):
    """Variant Beaufort decrypt: pt = (ct + key) mod 26"""
    return [(c + k) % 26 for c, k in zip(ct_num, key_num)]

def nums_to_str(nums):
    return ''.join(ALPH[n] for n in nums)

def count_crib_matches(pt_nums):
    """Count how many crib positions match."""
    return sum(1 for pos, expected in CRIB_POS.items()
               if pos < len(pt_nums) and pt_nums[pos] == expected)

def make_repeating_key(keyword_str, length):
    """Repeat keyword to fill length."""
    key_nums = [ALPH_IDX[c] for c in keyword_str.upper()]
    return [key_nums[i % len(key_nums)] for i in range(length)]

def test_key(key_nums, label):
    """Test a key against all 3 cipher variants, return list of result dicts."""
    results = []
    for var_name, dec_fn in [("Vig", decrypt_vig), ("Beau", decrypt_beau), ("VB", decrypt_vb)]:
        pt_nums = dec_fn(CT_NUM, key_nums)
        matches = count_crib_matches(pt_nums)
        pt_str = nums_to_str(pt_nums)
        qg = quadgram_score(pt_str)
        results.append({
            'label': label,
            'variant': var_name,
            'matches': matches,
            'qg': qg,
            'pt_preview': pt_str[:50],
            'key_preview': nums_to_str(key_nums[:20]),
        })
    return results


# ── K2 plaintext ─────────────────────────────────────────────────────────

K2_PLAINTEXT = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETIC"
    "FIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOAN"
    "UNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHISXTHEYSHOULDITSBURIED"
    "OUTTHERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONXONLYWWTHISWASHIS"
    "LASTMESSAGEXTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVE"
    "SECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWEST"
    "XLAYERTWO"
)

K2_WORDS = [
    "INVISIBLE", "MAGNETIC", "UNDERGROUND", "TRANSMITTED", "BURIED",
    "LOCATION", "LANGLEY", "MESSAGE", "LAYERTWO", "INFORMATION",
    "GATHERED", "UNKNOWN", "EARTHS", "FIELD", "POSSIBLE",
    "NORTH", "WEST", "EAST", "DEGREES",
]

# Operation Gold related words
OPGOLD_WORDS = [
    "GOLD", "SILVER", "STOPWATCH", "TUNNEL", "WIRETAP",
    "RUDOW", "ALTGLIENICKE", "OPERATION", "OPERATIONGOLD",
]

# ══════════════════════════════════════════════════════════════════════════
# TEST 1: K2 Keywords as repeating Vig/Beaufort keys
# ══════════════════════════════════════════════════════════════════════════

def test_k2_keywords_direct():
    print("=" * 70)
    print("TEST 1: K2 Keywords as Repeating Cipher Keys")
    print("=" * 70)

    keywords = K2_WORDS + OPGOLD_WORDS
    all_results = []

    for kw in keywords:
        key_nums = make_repeating_key(kw, N)
        all_results.extend(test_key(key_nums, f"direct:{kw}"))

    all_results.sort(key=lambda r: (-r['matches'], -r['qg']))
    print(f"\nTested {len(keywords)} keywords × 3 variants = {len(all_results)} configs")
    print_top(all_results, 15)
    return all_results


# ══════════════════════════════════════════════════════════════════════════
# TEST 2: K2 Keywords Concatenated with YAR / DYAR
# ══════════════════════════════════════════════════════════════════════════

def test_k2_keywords_with_yar():
    print("\n" + "=" * 70)
    print("TEST 2: K2 Keywords + YAR/DYAR Concatenations")
    print("=" * 70)

    suffixes = ["YAR", "DYAR"]
    prefixes = ["YAR", "DYAR"]
    keywords = K2_WORDS + OPGOLD_WORDS
    all_results = []

    for kw in keywords:
        for suf in suffixes:
            combined = kw + suf
            key_nums = make_repeating_key(combined, N)
            all_results.extend(test_key(key_nums, f"concat:{kw}+{suf}"))

        for pre in prefixes:
            combined = pre + kw
            key_nums = make_repeating_key(combined, N)
            all_results.extend(test_key(key_nums, f"concat:{pre}+{kw}"))

    all_results.sort(key=lambda r: (-r['matches'], -r['qg']))
    print(f"\nTested {len(all_results)} configs")
    print_top(all_results, 15)
    return all_results


# ══════════════════════════════════════════════════════════════════════════
# TEST 3: K2 Keywords with YAR Values as Caesar Shifts
# ══════════════════════════════════════════════════════════════════════════

def test_k2_keywords_yar_shifted():
    print("\n" + "=" * 70)
    print("TEST 3: K2 Keywords with YAR-value Caesar Shifts")
    print("=" * 70)

    # YAR values: Y=24, A=0, R=17
    yar_shifts = [24, 0, 17]
    # DYAR values: D=3, Y=24, A=0, R=17
    dyar_shifts = [3, 24, 0, 17]

    keywords = K2_WORDS + OPGOLD_WORDS
    all_results = []

    for kw in keywords:
        kw_nums = [ALPH_IDX[c] for c in kw]

        for shift_name, shifts in [("YAR", yar_shifts), ("DYAR", dyar_shifts)]:
            # Apply shifts cyclically to the keyword letters
            shifted_nums = [(kw_nums[i] + shifts[i % len(shifts)]) % 26
                           for i in range(len(kw_nums))]
            shifted_kw = nums_to_str(shifted_nums)
            key_nums = [shifted_nums[i % len(shifted_nums)] for i in range(N)]
            all_results.extend(test_key(key_nums, f"shift:{kw}+{shift_name}={shifted_kw}"))

            # Also try subtractive shifts
            shifted_nums_sub = [(kw_nums[i] - shifts[i % len(shifts)]) % 26
                               for i in range(len(kw_nums))]
            shifted_kw_sub = nums_to_str(shifted_nums_sub)
            key_nums_sub = [shifted_nums_sub[i % len(shifted_nums_sub)] for i in range(N)]
            all_results.extend(test_key(key_nums_sub, f"shift:{kw}-{shift_name}={shifted_kw_sub}"))

    all_results.sort(key=lambda r: (-r['matches'], -r['qg']))
    print(f"\nTested {len(all_results)} configs")
    print_top(all_results, 15)
    return all_results


# ══════════════════════════════════════════════════════════════════════════
# TEST 4: K2 First-Letter Acronym as Running Key
# ══════════════════════════════════════════════════════════════════════════

def test_k2_acronym_running_key():
    print("\n" + "=" * 70)
    print("TEST 4: K2 First-Letter Acronym as Running Key")
    print("=" * 70)

    # K2 words (including X separator)
    k2_words_list = [
        "IT", "WAS", "TOTALLY", "INVISIBLE", "HOWS", "THAT", "POSSIBLE",
        "THEY", "USED", "THE", "EARTHS", "MAGNETIC", "FIELD", "X",
        "THE", "INFORMATION", "WAS", "GATHERED", "AND", "TRANSMITTED",
        "UNDERGRUUND", "TO", "AN", "UNKNOWN", "LOCATION", "X",
        "DOES", "LANGLEY", "KNOW", "ABOUT", "THIS", "X",
        "THEY", "SHOULD", "ITS", "BURIED", "OUT", "THERE", "SOMEWHERE", "X",
        "WHO", "KNOWS", "THE", "EXACT", "LOCATION", "X",
        "ONLY", "WW", "THIS", "WAS", "HIS", "LAST", "MESSAGE", "X",
        "THIRTY", "EIGHT", "DEGREES", "FIFTY", "SEVEN", "MINUTES",
        "SIX", "POINT", "FIVE", "SECONDS", "NORTH",
        "SEVENTY", "SEVEN", "DEGREES", "EIGHT", "MINUTES",
        "FORTY", "FOUR", "SECONDS", "WEST", "X",
        "LAYER", "TWO",
    ]

    # First letters
    first_letters = ''.join(w[0] for w in k2_words_list)
    print(f"K2 first-letter acronym ({len(first_letters)} chars): {first_letters}")

    all_results = []

    # Use as repeating key
    key_nums = make_repeating_key(first_letters, N)
    all_results.extend(test_key(key_nums, f"acronym:K2_first_letters(rep)"))

    # Use as running key (if long enough, try different start offsets)
    fl_nums = [ALPH_IDX[c] for c in first_letters]
    if len(fl_nums) >= N:
        for offset in range(len(fl_nums) - N + 1):
            seg = fl_nums[offset:offset + N]
            all_results.extend(test_key(seg, f"acronym:K2_first_off={offset}"))
    else:
        # Pad by repeating
        padded = fl_nums * ((N // len(fl_nums)) + 2)
        key_nums = padded[:N]
        all_results.extend(test_key(key_nums, f"acronym:K2_first_padded"))

    # Also try: first letter of each K2 sentence (separated by X)
    k2_sentences = K2_PLAINTEXT.split('X')
    sent_first = ''.join(s[0] for s in k2_sentences if s)
    print(f"K2 sentence-initial letters: {sent_first}")
    if len(sent_first) >= 2:
        key_nums = make_repeating_key(sent_first, N)
        all_results.extend(test_key(key_nums, f"acronym:K2_sentence_initials"))

    all_results.sort(key=lambda r: (-r['matches'], -r['qg']))
    print(f"\nTested {len(all_results)} configs")
    print_top(all_results, 10)
    return all_results


# ══════════════════════════════════════════════════════════════════════════
# TEST 5: YAR as Offset into K2 Plaintext → Running Key
# ══════════════════════════════════════════════════════════════════════════

def test_yar_offset_running_key():
    print("\n" + "=" * 70)
    print("TEST 5: YAR as Offset into K2 Plaintext → Running Key")
    print("=" * 70)

    k2_nums = [ALPH_IDX[c] for c in K2_PLAINTEXT]
    k2_len = len(K2_PLAINTEXT)
    print(f"K2 plaintext length: {k2_len}")

    # YAR values: Y=24, A=0, R=17
    offsets_to_test = [
        (24, "Y=24"),
        (0, "A=0"),
        (17, "R=17"),
        (24017, "YAR=24017" if 24017 < k2_len else "YAR=24017(wrap)"),
        (241, "Y*10+A+1=241" if 241 < k2_len else "241(wrap)"),
        (2417, "concat_YAR=2417" if 2417 < k2_len else "2417(wrap)"),
    ]

    # Also: K2 starting from "LAYERTWO" (the end — last 8 chars)
    layertwo_pos = K2_PLAINTEXT.find("LAYERTWO")
    if layertwo_pos >= 0:
        offsets_to_test.append((layertwo_pos, f"LAYERTWO_pos={layertwo_pos}"))

    # K2 starting from "WW"
    ww_pos = K2_PLAINTEXT.find("WW")
    if ww_pos >= 0:
        offsets_to_test.append((ww_pos, f"WW_pos={ww_pos}"))

    # K2 starting from "BERLINCLOCK"-like content (there's no BERLINCLOCK in K2,
    # but LOCATION appears)
    loc_pos = K2_PLAINTEXT.find("LOCATION")
    if loc_pos >= 0:
        offsets_to_test.append((loc_pos, f"LOCATION_pos={loc_pos}"))

    all_results = []

    for offset, desc in offsets_to_test:
        offset = offset % k2_len  # wrap if needed
        # Extract running key starting at offset, wrapping around
        key_nums = []
        for i in range(N):
            key_nums.append(k2_nums[(offset + i) % k2_len])

        key_str = nums_to_str(key_nums)
        all_results.extend(test_key(key_nums, f"K2_offset:{desc}"))

    # Also test: K2 read BACKWARDS from various offsets
    k2_rev_nums = list(reversed(k2_nums))
    for offset, desc in [(0, "rev_start"), (24, "rev_Y=24"), (17, "rev_R=17")]:
        key_nums = []
        for i in range(N):
            key_nums.append(k2_rev_nums[(offset + i) % k2_len])
        all_results.extend(test_key(key_nums, f"K2_rev:{desc}"))

    all_results.sort(key=lambda r: (-r['matches'], -r['qg']))
    print(f"\nTested {len(all_results)} configs")
    print_top(all_results, 15)
    return all_results


# ══════════════════════════════════════════════════════════════════════════
# TEST 6: WW + YAR Combinations
# ══════════════════════════════════════════════════════════════════════════

def test_ww_yar_combinations():
    print("\n" + "=" * 70)
    print("TEST 6: WW + YAR Combinations")
    print("=" * 70)

    combo_keywords = [
        "WWYAR", "YARWW", "WWDYAR", "DYARWW",
        "WW", "WILLIAMWEBSTER", "WEBSTERYAR",
        "YARWEBSTER", "WWLAYERTWO", "LAYERTWOWW",
    ]

    all_results = []

    for kw in combo_keywords:
        key_nums = make_repeating_key(kw, N)
        all_results.extend(test_key(key_nums, f"ww_yar:{kw}"))

    # WW as shift value (W=22): apply constant shift of 22 combined with YAR cycling
    # Key = [22+24, 22+0, 22+17, 22+24, ...] mod 26 = [20, 22, 13, ...]
    yar_vals = [24, 0, 17]
    ww_shift = 22
    ww_yar_key = [(ww_shift + yar_vals[i % 3]) % 26 for i in range(N)]
    all_results.extend(test_key(ww_yar_key, "ww_yar:W22+YAR_cycling"))

    # Subtract version
    ww_yar_key_sub = [(ww_shift - yar_vals[i % 3]) % 26 for i in range(N)]
    all_results.extend(test_key(ww_yar_key_sub, "ww_yar:W22-YAR_cycling"))

    # WW=2222 (two W's numerically) → mod 26 = 2222%26 = 12
    ww_num = 2222 % 26  # = 12
    ww_yar2 = [(ww_num + yar_vals[i % 3]) % 26 for i in range(N)]
    all_results.extend(test_key(ww_yar2, "ww_yar:WW2222+YAR"))

    # Pure YAR cycling (period 3): [24, 0, 17, 24, 0, 17, ...]
    yar_key = [yar_vals[i % 3] for i in range(N)]
    all_results.extend(test_key(yar_key, "pure:YAR_cycle3"))

    # Pure DYAR cycling (period 4): [3, 24, 0, 17, ...]
    dyar_vals = [3, 24, 0, 17]
    dyar_key = [dyar_vals[i % 4] for i in range(N)]
    all_results.extend(test_key(dyar_key, "pure:DYAR_cycle4"))

    # YART cycling (period 4): [24, 0, 17, 19, ...]
    yart_vals = [24, 0, 17, 19]
    yart_key = [yart_vals[i % 4] for i in range(N)]
    all_results.extend(test_key(yart_key, "pure:YART_cycle4"))

    all_results.sort(key=lambda r: (-r['matches'], -r['qg']))
    print(f"\nTested {len(all_results)} configs")
    print_top(all_results, 15)
    return all_results


# ══════════════════════════════════════════════════════════════════════════
# TEST 7: DYAR Variant Keywords
# ══════════════════════════════════════════════════════════════════════════

def test_dyar_variants():
    print("\n" + "=" * 70)
    print("TEST 7: DYAR as Keyword (standalone + combined)")
    print("=" * 70)

    dyar_keywords = [
        "DYAR", "YARD", "DRAY", "RYAD", "ARDY",
        "YARDBIRD", "DYARBIRD",
        "DYARKRYPTOS", "KRYPTOSDYAR",
        "DYARPALIMPSEST", "PALIMPSESTDYAR",
        "DYARABSCISSA", "ABSCISSADYAR",
        "DYARLAYERTWO", "LAYERTWODYAR",
    ]

    all_results = []

    for kw in dyar_keywords:
        key_nums = make_repeating_key(kw, N)
        all_results.extend(test_key(key_nums, f"dyar:{kw}"))

    all_results.sort(key=lambda r: (-r['matches'], -r['qg']))
    print(f"\nTested {len(all_results)} configs")
    print_top(all_results, 15)
    return all_results


# ══════════════════════════════════════════════════════════════════════════
# TEST 8: Operation Gold Words + YAR
# ══════════════════════════════════════════════════════════════════════════

def test_opgold_yar():
    print("\n" + "=" * 70)
    print("TEST 8: Operation Gold Words + YAR Combinations")
    print("=" * 70)

    opgold_keywords = [
        "GOLD", "SILVER", "STOPWATCH",
        "TUNNEL", "BERLIN", "RUDOW", "ALTGLIENICKE",
        "OPERATIONGOLD", "OPERATIONSILVER", "OPERATIONSTOPWATCH",
        "HARVEYSPOINT", "CHARLIECHECK", "CHECKPOINT", "CHECKPOINTCHARLIE",
    ]

    suffixes = ["YAR", "DYAR", "YART"]
    all_results = []

    for kw in opgold_keywords:
        # Direct keyword
        key_nums = make_repeating_key(kw, N)
        all_results.extend(test_key(key_nums, f"opgold:{kw}"))

        # With suffixes/prefixes
        for suf in suffixes:
            for combined in [kw + suf, suf + kw]:
                key_nums = make_repeating_key(combined, N)
                all_results.extend(test_key(key_nums, f"opgold:{combined}"))

    # Special: KRYPTOS + GOLD
    for combo in ["KRYPTOSGOLD", "GOLDKRYPTOS", "KRYPTOSOPERATIONGOLD"]:
        key_nums = make_repeating_key(combo, N)
        all_results.extend(test_key(key_nums, f"opgold:{combo}"))

    all_results.sort(key=lambda r: (-r['matches'], -r['qg']))
    print(f"\nTested {len(all_results)} configs")
    print_top(all_results, 15)
    return all_results


# ══════════════════════════════════════════════════════════════════════════
# TEST 9: K2 Plaintext as Running Key (Full Sweep of All Start Positions)
# ══════════════════════════════════════════════════════════════════════════

def test_k2_full_running_key():
    print("\n" + "=" * 70)
    print("TEST 9: K2 Full Running Key (all start positions)")
    print("=" * 70)

    k2_nums = [ALPH_IDX[c] for c in K2_PLAINTEXT]
    k2_len = len(K2_PLAINTEXT)
    all_results = []

    # Test every starting offset in K2
    for offset in range(k2_len):
        key_nums = []
        for i in range(N):
            key_nums.append(k2_nums[(offset + i) % k2_len])

        for var_name, dec_fn in [("Vig", decrypt_vig), ("Beau", decrypt_beau)]:
            pt_nums = dec_fn(CT_NUM, key_nums)
            matches = count_crib_matches(pt_nums)
            if matches >= 4:  # Only record interesting ones
                pt_str = nums_to_str(pt_nums)
                qg = quadgram_score(pt_str)
                all_results.append({
                    'label': f"K2_run:off={offset}",
                    'variant': var_name,
                    'matches': matches,
                    'qg': qg,
                    'pt_preview': pt_str[:50],
                    'key_preview': nums_to_str(key_nums[:20]),
                })

    all_results.sort(key=lambda r: (-r['matches'], -r['qg']))
    print(f"\nK2 running key: tested {k2_len} offsets × 2 variants")
    print(f"Results with >= 4 crib matches: {len(all_results)}")
    print_top(all_results, 15)
    return all_results


# ══════════════════════════════════════════════════════════════════════════
# TEST 10: YAR-modulated K2 Running Key
# ══════════════════════════════════════════════════════════════════════════

def test_yar_modulated_k2():
    print("\n" + "=" * 70)
    print("TEST 10: YAR-modulated K2 Running Key")
    print("=" * 70)

    k2_nums = [ALPH_IDX[c] for c in K2_PLAINTEXT]
    k2_len = len(K2_PLAINTEXT)
    yar_vals = [24, 0, 17]
    dyar_vals = [3, 24, 0, 17]
    all_results = []

    # For each offset, take K2 running key and add YAR/DYAR shifts cyclically
    for offset in range(0, k2_len, 1):
        base_key = [k2_nums[(offset + i) % k2_len] for i in range(N)]

        for mod_name, mod_vals in [("YAR", yar_vals), ("DYAR", dyar_vals)]:
            # Additive modulation
            modulated = [(base_key[i] + mod_vals[i % len(mod_vals)]) % 26 for i in range(N)]
            for var_name, dec_fn in [("Vig", decrypt_vig), ("Beau", decrypt_beau)]:
                pt_nums = dec_fn(CT_NUM, modulated)
                matches = count_crib_matches(pt_nums)
                if matches >= 5:
                    pt_str = nums_to_str(pt_nums)
                    qg = quadgram_score(pt_str)
                    all_results.append({
                        'label': f"K2+{mod_name}:off={offset}",
                        'variant': var_name,
                        'matches': matches,
                        'qg': qg,
                        'pt_preview': pt_str[:50],
                        'key_preview': nums_to_str(modulated[:20]),
                    })

    all_results.sort(key=lambda r: (-r['matches'], -r['qg']))
    print(f"\nYAR-modulated K2 running key results with >= 5 crib matches: {len(all_results)}")
    print_top(all_results, 15)
    return all_results


# ══════════════════════════════════════════════════════════════════════════
# Utilities
# ══════════════════════════════════════════════════════════════════════════

def print_top(results, n=15):
    """Print top n results."""
    if not results:
        print("  (no results)")
        return
    print(f"\n{'Label':45s} {'Var':5s} {'Cribs':>5s} {'QG/c':>7s} {'PT preview':40s}")
    print("-" * 105)
    for r in results[:n]:
        print(f"{r['label']:45s} {r['variant']:5s} "
              f"{r['matches']:5d} {r['qg']:7.3f} {r['pt_preview']:40s}")

    # Summary stats
    best = results[0]
    print(f"\nBest: {best['matches']}/24 cribs, qg={best['qg']:.3f} [{best['label']} / {best['variant']}]")


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    t0 = time.time()

    load_quadgrams()
    print(f"Quadgrams loaded: {len(QUADGRAMS)} entries")
    print(f"CT: {CT}")
    print(f"CT length: {N}")
    print(f"K2 plaintext length: {len(K2_PLAINTEXT)}")
    print()

    r1 = test_k2_keywords_direct()
    r2 = test_k2_keywords_with_yar()
    r3 = test_k2_keywords_yar_shifted()
    r4 = test_k2_acronym_running_key()
    r5 = test_yar_offset_running_key()
    r6 = test_ww_yar_combinations()
    r7 = test_dyar_variants()
    r8 = test_opgold_yar()
    r9 = test_k2_full_running_key()
    r10 = test_yar_modulated_k2()

    elapsed = time.time() - t0

    # Collect ALL results across tests for global ranking
    all_combined = []
    for label, results in [
        ("T1:K2_direct", r1), ("T2:K2+YAR_concat", r2),
        ("T3:K2+YAR_shift", r3), ("T4:K2_acronym", r4),
        ("T5:K2_offset", r5), ("T6:WW+YAR", r6),
        ("T7:DYAR", r7), ("T8:OpGold+YAR", r8),
        ("T9:K2_running", r9), ("T10:YAR_mod_K2", r10),
    ]:
        if results:
            all_combined.extend(results)

    all_combined.sort(key=lambda r: (-r['matches'], -r['qg']))

    print("\n" + "=" * 70)
    print("GLOBAL TOP 25 ACROSS ALL TESTS")
    print("=" * 70)
    print_top(all_combined, 25)

    # Classification
    best_score = all_combined[0]['matches'] if all_combined else 0
    if best_score >= 18:
        classification = "SIGNAL"
    elif best_score >= 10:
        classification = "INTERESTING"
    elif best_score > 6:
        classification = "BORDERLINE"
    else:
        classification = "NOISE"

    print(f"\n{'=' * 70}")
    print(f"E-OPGOLD-02 COMPLETE — {elapsed:.1f}s — Classification: {classification}")
    print(f"Best score: {best_score}/24 cribs")
    print(f"Total configs tested: {len(all_combined)}")

    # Expected random performance: periodic keys with period ≤7 expect ~8.2/24
    # Running keys (non-periodic) expect ~0-2/24
    # Anything above 6/24 for non-periodic is worth noting
    if best_score <= 6:
        print("Result: ALL NOISE — no K2+YAR combination produces meaningful crib matches")
    else:
        print(f"Result: Best {best_score}/24 — check if period is <= 7 for significance")

    print(f"{'=' * 70}")

    # Save artifact
    os.makedirs(REPO / 'results', exist_ok=True)
    artifact = {
        'experiment': 'E-OPGOLD-02',
        'name': 'K2-Derived Words + YAR Superscript as K4 Cipher Keys',
        'elapsed_seconds': elapsed,
        'classification': classification,
        'best_score': best_score,
        'total_configs': len(all_combined),
        'global_top20': all_combined[:20],
    }
    artifact_path = REPO / 'results' / 'e_opgold_02_progressive.json'
    with open(artifact_path, 'w') as f:
        json.dump(artifact, f, indent=2)
    print(f"Artifact: {artifact_path}")
