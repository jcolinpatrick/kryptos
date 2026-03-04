#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: _uncategorized
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""Comprehensive attack on the new grille-derived CT from corrected 28x31 grid.

Attacks:
1. Basic statistics (length, IC, frequency, letter coverage)
2. Vigenere/Beaufort/VarBeau × known keywords × AZ/KA alphabets
3. All Caesar shifts (period-1)
4. Kasiski analysis (repeated bigrams/trigrams)
5. Period analysis (IC per period 2-25)
6. Brute force all periods 2-12 with frequency-analysis key recovery
7. Check for crib fragments in ALL decryptions
8. Quadgram scoring of top candidates
9. Try substrings of length 97
10. Autokey variants
11. Running key with grille extract itself
"""
import sys, os, json, math, itertools
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# ── Constants ──────────────────────────────────────────────────────────────

NEW_CT = "HJLVKDJQZKIVPCMWSAFOPCKBDLHIFXRYVFIJMXEIOMQFJNXZKILKRDIYSCLMQVZACEIMVSEFHLQKRGILVHNQXWTCDKIKJUFQRXCD"
CARVED_CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK",
    "KRYPTOS" * 2,  # doubled
    "SANBORN", "SCHEIDT", "CIPHER", "ENIGMA",
    "UNDERGROUND", "SOUTHEAST", "NORTHWEST",
    "CLOCK", "BERLIN", "EAST", "NORTH",
    "SHADOW", "ILLUSION", "INVISIBLE",
    "LUCID", "MEMORY", "VIRTUALLY",
    "IQLUSION", "DESPERATLY",  # K3 misspellings
    "DYAHR",  # reversed RHADY
    "MEDUSA", "VENUS", "NYPVTT",
    "OBKRUOXOGHULBSOLIFBBW",  # K4 prefix as key
]

CRIBS = ["EASTNORTHEAST", "BERLINCLOCK", "EAST", "NORTH", "NORTHEAST",
         "BERLIN", "CLOCK", "BETWEEN", "SUBTLE", "SHADING",
         "SHADOW", "IQLUSION", "UNDERGROUND", "VIRTUALLY", "INVISIBLE",
         "SLOWLY", "DESPERATLY", "YES", "WONDERFUL", "THINGS",
         "YESWONDERFULTHINGS", "CANYOUSEEANYTHING",
         "ARCHAEOLOG", "CARTER", "TUTANKHAMUN", "TOMB",
         "LONGITUDE", "LATITUDE", "LANGLEY", "DIGETAL", "INTERPRETATIT"]

# ── Helpers ────────────────────────────────────────────────────────────────

def char_to_idx(c, alph=AZ):
    return alph.index(c)

def idx_to_char(i, alph=AZ):
    return alph[i % 26]

def ic(text):
    n = len(text)
    if n <= 1:
        return 0.0
    freq = Counter(text)
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))

def vig_decrypt(ct, key_nums, alph=AZ):
    klen = len(key_nums)
    result = []
    for i, c in enumerate(ct):
        ci = char_to_idx(c, alph)
        ki = key_nums[i % klen]
        pi = (ci - ki) % 26
        result.append(idx_to_char(pi, alph))
    return ''.join(result)

def beau_decrypt(ct, key_nums, alph=AZ):
    klen = len(key_nums)
    result = []
    for i, c in enumerate(ct):
        ci = char_to_idx(c, alph)
        ki = key_nums[i % klen]
        pi = (ki - ci) % 26
        result.append(idx_to_char(pi, alph))
    return ''.join(result)

def varbeau_decrypt(ct, key_nums, alph=AZ):
    klen = len(key_nums)
    result = []
    for i, c in enumerate(ct):
        ci = char_to_idx(c, alph)
        ki = key_nums[i % klen]
        pi = (ci + ki) % 26
        result.append(idx_to_char(pi, alph))
    return ''.join(result)

def keyword_to_nums(keyword, alph=AZ):
    return [char_to_idx(c, alph) for c in keyword]

def check_cribs(text, cribs=CRIBS):
    """Return list of (crib, position) for all cribs found in text."""
    found = []
    for crib in cribs:
        pos = text.find(crib)
        if pos >= 0:
            found.append((crib, pos))
    return found

def count_common_words(text):
    """Count common English words found in text."""
    common = ["THE", "AND", "FOR", "ARE", "BUT", "NOT", "YOU", "ALL",
              "CAN", "HER", "WAS", "ONE", "OUR", "OUT", "HAS", "HIS",
              "HOW", "ITS", "MAY", "NEW", "NOW", "OLD", "SEE", "WAY",
              "WHO", "DID", "GET", "LET", "SAY", "SHE", "TOO", "USE",
              "THAT", "WITH", "HAVE", "THIS", "WILL", "YOUR", "FROM",
              "THEY", "BEEN", "SAID", "EACH", "MAKE", "LIKE", "LONG",
              "LOOK", "MANY", "SOME", "THAN", "THEM", "THEN", "WHAT",
              "WHEN", "WERE", "INTO", "OVER", "SUCH", "ONLY", "VERY",
              "EAST", "WEST", "NORTH", "SOUTH", "CLOCK", "BERLIN",
              "BETWEEN", "SUBTLE", "SHADOW", "UNDERGROUND", "YES",
              "WONDERFUL", "THINGS", "SLOWLY", "COULD", "WOULD",
              "THERE", "WHERE", "WHICH", "ABOUT", "AFTER", "BEFORE"]
    found = []
    for w in common:
        if w in text:
            found.append(w)
    return found

# ── Load quadgrams ─────────────────────────────────────────────────────────

QUADGRAMS = None
QG_FLOOR = -10.0

def load_quadgrams():
    global QUADGRAMS, QG_FLOOR
    qg_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'english_quadgrams.json')
    if os.path.exists(qg_path):
        with open(qg_path) as f:
            QUADGRAMS = json.load(f)
        # Find floor value
        vals = list(QUADGRAMS.values())
        QG_FLOOR = min(vals) - 1.0
        print(f"  Loaded {len(QUADGRAMS)} quadgrams (floor={QG_FLOOR:.2f})")
    else:
        print("  WARNING: quadgrams file not found, skipping QG scoring")

def qg_score(text):
    if QUADGRAMS is None:
        return -999
    total = 0.0
    count = 0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        total += QUADGRAMS.get(qg, QG_FLOOR)
        count += 1
    return total / count if count > 0 else -999

# ── Autokey ────────────────────────────────────────────────────────────────

def autokey_decrypt_pt(ct, primer, alph=AZ):
    """Autokey using plaintext feedback."""
    key_stream = list(keyword_to_nums(primer, alph))
    pt = []
    for i, c in enumerate(ct):
        ci = char_to_idx(c, alph)
        ki = key_stream[i]
        pi = (ci - ki) % 26
        pt_char = idx_to_char(pi, alph)
        pt.append(pt_char)
        key_stream.append(char_to_idx(pt_char, alph))
    return ''.join(pt)

def autokey_decrypt_ct(ct, primer, alph=AZ):
    """Autokey using ciphertext feedback."""
    key_stream = list(keyword_to_nums(primer, alph))
    pt = []
    for i, c in enumerate(ct):
        ci = char_to_idx(c, alph)
        ki = key_stream[i]
        pi = (ci - ki) % 26
        pt.append(idx_to_char(pi, alph))
        key_stream.append(ci)
    return ''.join(pt)

# ── Kasiski ────────────────────────────────────────────────────────────────

def kasiski(text, min_len=3, max_len=6):
    """Find repeated sequences and their spacings."""
    repeats = {}
    for length in range(min_len, max_len + 1):
        for i in range(len(text) - length + 1):
            seq = text[i:i+length]
            if seq not in repeats:
                repeats[seq] = []
            repeats[seq].append(i)

    spacings = []
    for seq, positions in repeats.items():
        if len(positions) > 1:
            for i in range(len(positions)):
                for j in range(i+1, len(positions)):
                    spacings.append((positions[j] - positions[i], seq, positions[i], positions[j]))
    return spacings

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# ── Period IC analysis ─────────────────────────────────────────────────────

def period_ic(text, period):
    """Average IC across columns for a given period."""
    columns = ['' for _ in range(period)]
    for i, c in enumerate(text):
        columns[i % period] += c
    ics = [ic(col) for col in columns if len(col) > 1]
    return sum(ics) / len(ics) if ics else 0.0

# ── Frequency-based key recovery ──────────────────────────────────────────

ENGLISH_FREQ = {
    'E': 12.7, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97,
    'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25,
    'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36,
    'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29,
    'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10,
    'Z': 0.07,
}
ENG_FREQ_VEC = [ENGLISH_FREQ.get(chr(65+i), 0.0) / 100.0 for i in range(26)]

def chi_squared_shift(col_text, shift, alph=AZ):
    """Chi-squared statistic for a column after applying shift."""
    n = len(col_text)
    if n == 0:
        return 9999
    freq = Counter()
    for c in col_text:
        idx = char_to_idx(c, alph)
        shifted = (idx - shift) % 26
        freq[shifted] += 1

    chi2 = 0.0
    for i in range(26):
        observed = freq.get(i, 0)
        expected = ENG_FREQ_VEC[i] * n
        if expected > 0:
            chi2 += (observed - expected) ** 2 / expected
    return chi2

def best_shift_for_column(col_text, alph=AZ):
    """Find the shift that minimizes chi-squared."""
    best_shift = 0
    best_chi2 = 9999
    for shift in range(26):
        chi2 = chi_squared_shift(col_text, shift, alph)
        if chi2 < best_chi2:
            best_chi2 = chi2
            best_shift = shift
    return best_shift, best_chi2

def frequency_attack(ct, period, alph=AZ):
    """Recover key by frequency analysis for a given period."""
    columns = ['' for _ in range(period)]
    for i, c in enumerate(ct):
        columns[i % period] += c

    key = []
    total_chi2 = 0
    for col in columns:
        shift, chi2 = best_shift_for_column(col, alph)
        key.append(shift)
        total_chi2 += chi2

    pt = vig_decrypt(ct, key, alph)
    return key, pt, total_chi2 / period

# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

def main():
    ct = NEW_CT
    print("=" * 80)
    print("COMPREHENSIVE ATTACK ON NEW GRILLE-DERIVED CT")
    print("=" * 80)

    # ── 1. BASIC STATISTICS ──────────────────────────────────────────────
    print(f"\n{'='*80}")
    print("1. BASIC STATISTICS")
    print(f"{'='*80}")
    print(f"  CT: {ct}")
    print(f"  Length: {len(ct)}")
    print(f"  IC: {ic(ct):.6f}  (English ≈ 0.0667, random ≈ 0.0385)")

    freq = Counter(ct)
    print(f"  Unique letters: {len(freq)}")
    missing = [c for c in AZ if c not in freq]
    print(f"  Missing letters: {missing if missing else 'NONE (all 26 present)'}")

    print(f"\n  Frequency distribution:")
    for c, count in sorted(freq.items(), key=lambda x: -x[1]):
        bar = '#' * count
        print(f"    {c}: {count:3d}  {bar}")

    # Compare to carved CT
    carved_freq = Counter(CARVED_CT)
    print(f"\n  Comparison to carved CT ({len(CARVED_CT)} chars, IC={ic(CARVED_CT):.6f}):")
    print(f"  New CT IC:    {ic(ct):.6f}")
    print(f"  Carved CT IC: {ic(CARVED_CT):.6f}")

    # Letter overlap
    new_set = set(ct)
    carved_set = set(CARVED_CT)
    print(f"  Letters in new CT but not carved: {new_set - carved_set}")
    print(f"  Letters in carved but not new CT: {carved_set - new_set}")

    load_quadgrams()
    print(f"  Quadgram score (raw): {qg_score(ct):.4f} per char")

    # ── 2. KEYWORD DECRYPTION ────────────────────────────────────────────
    print(f"\n{'='*80}")
    print("2. KEYWORD DECRYPTION (Vig/Beau/VarBeau × AZ/KA)")
    print(f"{'='*80}")

    results = []

    for keyword in KEYWORDS:
        for alph_name, alph in [("AZ", AZ), ("KA", KA)]:
            key_nums = keyword_to_nums(keyword, alph)

            for variant_name, decrypt_fn in [("VIG", vig_decrypt), ("BEAU", beau_decrypt), ("VARBEAU", varbeau_decrypt)]:
                pt = decrypt_fn(ct, key_nums, alph)
                score = qg_score(pt)
                cribs_found = check_cribs(pt)
                words = count_common_words(pt)

                results.append((score, keyword, alph_name, variant_name, pt, cribs_found, words))

    # Sort by quadgram score (higher is better / less negative)
    results.sort(key=lambda x: -x[0])

    print(f"\n  Top 30 keyword decryptions by quadgram score:")
    for i, (score, kw, alph_name, var, pt, cribs, words) in enumerate(results[:30]):
        cribs_str = f" CRIBS: {cribs}" if cribs else ""
        words_str = f" WORDS: {words[:5]}" if words else ""
        print(f"  {i+1:3d}. [{score:7.4f}] {var:8s}/{alph_name}/{kw:20s}: {pt[:60]}...{cribs_str}{words_str}")

    # Show ANY with cribs
    crib_results = [(s, kw, an, v, pt, c, w) for s, kw, an, v, pt, c, w in results if c]
    if crib_results:
        print(f"\n  *** CRIB MATCHES FOUND! ***")
        for score, kw, alph_name, var, pt, cribs, words in crib_results:
            print(f"    [{score:.4f}] {var}/{alph_name}/{kw}: {pt}")
            print(f"    Cribs: {cribs}")
    else:
        print(f"\n  No crib matches found in keyword decryptions.")

    # ── 3. CAESAR SHIFTS ─────────────────────────────────────────────────
    print(f"\n{'='*80}")
    print("3. ALL 26 CAESAR SHIFTS")
    print(f"{'='*80}")

    for shift in range(26):
        pt = vig_decrypt(ct, [shift], AZ)
        score = qg_score(pt)
        cribs = check_cribs(pt)
        words = count_common_words(pt)
        marker = " ***" if cribs or len(words) > 3 else ""
        if shift < 26:  # show all
            print(f"  shift={shift:2d} ({AZ[shift]}): {pt[:70]}  qg={score:.3f} w={len(words)}{marker}")

    # ── 4. KASISKI ANALYSIS ──────────────────────────────────────────────
    print(f"\n{'='*80}")
    print("4. KASISKI ANALYSIS")
    print(f"{'='*80}")

    spacings = kasiski(ct, 2, 5)
    if spacings:
        # Group by spacing
        spacing_counts = Counter()
        for dist, seq, p1, p2 in spacings:
            spacing_counts[dist] += 1

        # Find common factors
        all_spacings = [dist for dist, seq, p1, p2 in spacings]
        factor_counts = Counter()
        for s in all_spacings:
            for f in range(2, min(s+1, 30)):
                if s % f == 0:
                    factor_counts[f] += 1

        print(f"  Repeated sequences found: {len(spacings)}")
        # Show repeated trigrams+
        long_repeats = [(d, s, p1, p2) for d, s, p1, p2 in spacings if len(s) >= 3]
        if long_repeats:
            print(f"  Repeated trigrams+:")
            for dist, seq, p1, p2 in sorted(long_repeats, key=lambda x: -len(x[1]))[:15]:
                print(f"    '{seq}' at positions {p1},{p2} (distance={dist}, factors: {[f for f in range(2,dist+1) if dist%f==0][:8]})")

        print(f"\n  Most common period factors:")
        for factor, count in factor_counts.most_common(10):
            print(f"    period={factor}: {count} spacings")
    else:
        print("  No repeated sequences of length >= 2 found.")

    # ── 5. PERIOD IC ANALYSIS ────────────────────────────────────────────
    print(f"\n{'='*80}")
    print("5. PERIOD IC ANALYSIS")
    print(f"{'='*80}")

    print(f"  Period  Avg IC    (English ≈ 0.0667)")
    best_period_ic = []
    for p in range(1, 26):
        pic = period_ic(ct, p)
        bar = '#' * int(pic * 200)
        marker = " <-- PEAK" if pic > 0.055 else ""
        print(f"    {p:3d}    {pic:.5f}  {bar}{marker}")
        best_period_ic.append((pic, p))

    best_period_ic.sort(reverse=True)
    print(f"\n  Top 5 periods by IC: {[(p, f'{v:.4f}') for v, p in best_period_ic[:5]]}")

    # ── 6. FREQUENCY ATTACK ALL PERIODS ──────────────────────────────────
    print(f"\n{'='*80}")
    print("6. FREQUENCY-BASED KEY RECOVERY (periods 2-25)")
    print(f"{'='*80}")

    freq_results = []
    for period in range(2, 26):
        for alph_name, alph in [("AZ", AZ), ("KA", KA)]:
            key, pt, avg_chi2 = frequency_attack(ct, period, alph)
            score = qg_score(pt)
            cribs = check_cribs(pt)
            words = count_common_words(pt)
            key_str = ''.join(idx_to_char(k, alph) for k in key)
            freq_results.append((score, period, alph_name, key_str, pt, cribs, words, avg_chi2))

    freq_results.sort(key=lambda x: -x[0])
    print(f"\n  Top 20 by quadgram score:")
    for i, (score, period, alph_name, key_str, pt, cribs, words, chi2) in enumerate(freq_results[:20]):
        cribs_str = f" CRIBS:{cribs}" if cribs else ""
        print(f"  {i+1:3d}. [{score:7.4f}] p={period:2d}/{alph_name} key={key_str:25s}: {pt[:55]}{cribs_str}")

    # ── 7. AUTOKEY VARIANTS ──────────────────────────────────────────────
    print(f"\n{'='*80}")
    print("7. AUTOKEY DECRYPTION")
    print(f"{'='*80}")

    autokey_results = []
    for keyword in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK", "K", "A", "SANBORN"]:
        for alph_name, alph in [("AZ", AZ), ("KA", KA)]:
            # PT-autokey
            pt = autokey_decrypt_pt(ct, keyword, alph)
            score = qg_score(pt)
            cribs = check_cribs(pt)
            autokey_results.append((score, "PT-AK", keyword, alph_name, pt, cribs))

            # CT-autokey
            pt = autokey_decrypt_ct(ct, keyword, alph)
            score = qg_score(pt)
            cribs = check_cribs(pt)
            autokey_results.append((score, "CT-AK", keyword, alph_name, pt, cribs))

    autokey_results.sort(key=lambda x: -x[0])
    print(f"\n  Top 10 autokey results:")
    for i, (score, mode, kw, alph_name, pt, cribs) in enumerate(autokey_results[:10]):
        cribs_str = f" CRIBS:{cribs}" if cribs else ""
        print(f"  {i+1:3d}. [{score:7.4f}] {mode}/{alph_name}/{kw}: {pt[:60]}{cribs_str}")

    # ── 8. RUNNING KEY WITH GRILLE ITSELF ────────────────────────────────
    print(f"\n{'='*80}")
    print("8. RUNNING KEY (grille as key)")
    print(f"{'='*80}")

    OLD_GRILLE = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"

    # Try using the carved CT as key for the new CT, and vice versa
    running_keys = [
        ("carved CT as key", CARVED_CT),
        ("old grille as key", OLD_GRILLE),
        ("new CT reversed", ct[::-1]),
        ("carved CT reversed", CARVED_CT[::-1]),
    ]

    for rk_name, rk in running_keys:
        rk_nums = keyword_to_nums(rk[:len(ct)], AZ)
        for var_name, fn in [("VIG", vig_decrypt), ("BEAU", beau_decrypt), ("VARBEAU", varbeau_decrypt)]:
            pt = fn(ct, rk_nums, AZ)
            score = qg_score(pt)
            cribs = check_cribs(pt)
            words = count_common_words(pt)
            marker = " ***" if cribs or len(words) > 3 else ""
            print(f"  {var_name}/{rk_name}: {pt[:60]} qg={score:.3f} w={len(words)}{marker}")

    # ── 9. SUBSTRING ANALYSIS (length 97) ────────────────────────────────
    print(f"\n{'='*80}")
    print("9. SUBSTRING ANALYSIS (length-97 substrings)")
    print(f"{'='*80}")

    if len(ct) > 97:
        for start in range(len(ct) - 97 + 1):
            sub = ct[start:start+97]
            sub_ic = ic(sub)
            print(f"  [{start}:{start+97}] IC={sub_ic:.5f} -> {sub[:40]}...")

            # Try top keywords on each substring
            for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
                for alph_name, alph in [("AZ", AZ)]:
                    key_nums = keyword_to_nums(kw, alph)
                    for var_name, fn in [("VIG", vig_decrypt), ("BEAU", beau_decrypt)]:
                        pt = fn(sub, key_nums, alph)
                        score = qg_score(pt)
                        cribs = check_cribs(pt)
                        if cribs or score > -7.5:
                            print(f"    {var_name}/{kw}: {pt[:50]} qg={score:.3f} cribs={cribs}")
    else:
        print(f"  CT is exactly {len(ct)} chars, no substrings to test.")

    # ── 10. COLUMNAR READING OF NEW CT ───────────────────────────────────
    print(f"\n{'='*80}")
    print("10. COLUMNAR/ROUTE READINGS OF NEW CT")
    print(f"{'='*80}")

    for width in [4, 5, 7, 8, 10, 13, 20, 25]:
        if width > len(ct):
            continue
        # Column-major reading
        nrows = math.ceil(len(ct) / width)
        padded = ct + 'X' * (nrows * width - len(ct))

        # Read column by column
        col_read = ''
        for c in range(width):
            for r in range(nrows):
                idx = r * width + c
                if idx < len(ct):
                    col_read += ct[idx]

        col_ic = ic(col_read[:len(ct)])

        # Try Vig/KRYPTOS on column reading
        key_nums = keyword_to_nums("KRYPTOS", AZ)
        pt_vig = vig_decrypt(col_read[:len(ct)], key_nums, AZ)
        pt_beau = beau_decrypt(col_read[:len(ct)], key_nums, AZ)
        score_v = qg_score(pt_vig)
        score_b = qg_score(pt_beau)
        cribs_v = check_cribs(pt_vig)
        cribs_b = check_cribs(pt_beau)

        marker = ""
        if cribs_v or cribs_b:
            marker = " ***CRIB***"
        print(f"  width={width:2d}: col_read IC={col_ic:.5f} VIG/KRYPTOS qg={score_v:.3f} BEAU qg={score_b:.3f}{marker}")
        if cribs_v:
            print(f"    VIG: {pt_vig}")
        if cribs_b:
            print(f"    BEAU: {pt_beau}")

    # ── 11. REVERSE AND OFFSET ATTACKS ───────────────────────────────────
    print(f"\n{'='*80}")
    print("11. REVERSE/OFFSET VARIANTS")
    print(f"{'='*80}")

    variants = [
        ("reversed", ct[::-1]),
        ("every_other_0", ct[0::2]),
        ("every_other_1", ct[1::2]),
        ("interleaved", ct[0::2] + ct[1::2]),
        ("reverse_interleaved", ct[1::2] + ct[0::2]),
    ]

    for var_name, var_ct in variants:
        for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            key_nums = keyword_to_nums(kw, AZ)
            pt_v = vig_decrypt(var_ct, key_nums, AZ)
            pt_b = beau_decrypt(var_ct, key_nums, AZ)
            score_v = qg_score(pt_v)
            score_b = qg_score(pt_b)
            cribs_v = check_cribs(pt_v)
            cribs_b = check_cribs(pt_b)
            best = max(score_v, score_b)
            if best > -8.5 or cribs_v or cribs_b:
                print(f"  {var_name}/{kw}: VIG qg={score_v:.3f} BEAU qg={score_b:.3f}")
                if cribs_v: print(f"    VIG: {pt_v}")
                if cribs_b: print(f"    BEAU: {pt_b}")

        # Also try plain frequency analysis
        for p in [7, 8, 10]:
            if len(var_ct) > p:
                key, pt, chi2 = frequency_attack(var_ct, p, AZ)
                score = qg_score(pt)
                if score > -8.0:
                    key_str = ''.join(idx_to_char(k) for k in key)
                    print(f"  {var_name}/freq p={p}: key={key_str} qg={score:.3f} {pt[:50]}")

    # ── 12. EXHAUSTIVE SHORT KEYWORD SEARCH ──────────────────────────────
    print(f"\n{'='*80}")
    print("12. EXHAUSTIVE SHORT KEYWORD SEARCH (length 1-4)")
    print(f"{'='*80}")

    best_short = []
    for klen in range(1, 5):
        for key_tuple in itertools.product(range(26), repeat=klen):
            key = list(key_tuple)
            pt = vig_decrypt(ct, key, AZ)
            score = qg_score(pt)
            if score > -7.5:
                key_str = ''.join(AZ[k] for k in key)
                cribs = check_cribs(pt)
                best_short.append((score, key_str, pt, cribs))

            pt_b = beau_decrypt(ct, key, AZ)
            score_b = qg_score(pt_b)
            if score_b > -7.5:
                key_str = ''.join(AZ[k] for k in key)
                cribs = check_cribs(pt_b)
                best_short.append((score_b, "B:" + key_str, pt_b, cribs))

    best_short.sort(key=lambda x: -x[0])
    print(f"  Top 20 short-key results (qg > -7.5):")
    for i, (score, key_str, pt, cribs) in enumerate(best_short[:20]):
        cribs_str = f" CRIBS:{cribs}" if cribs else ""
        print(f"  {i+1:3d}. [{score:7.4f}] key={key_str:6s}: {pt[:60]}{cribs_str}")

    if not best_short:
        print("  No results above -7.5 threshold. Showing best from period-3 Vig:")
        best3 = []
        for key_tuple in itertools.product(range(26), repeat=3):
            key = list(key_tuple)
            pt = vig_decrypt(ct, key, AZ)
            score = qg_score(pt)
            best3.append((score, ''.join(AZ[k] for k in key), pt))
        best3.sort(key=lambda x: -x[0])
        for i, (score, ks, pt) in enumerate(best3[:5]):
            print(f"    [{score:.4f}] key={ks}: {pt[:60]}")

    # ── 13. DIFFERENCE ANALYSIS ──────────────────────────────────────────
    print(f"\n{'='*80}")
    print("13. NEW CT vs OLD GRILLE EXTRACT COMPARISON")
    print(f"{'='*80}")

    old = OLD_GRILLE
    new = ct
    print(f"  Old grille: {old} ({len(old)} chars)")
    print(f"  New CT:     {new} ({len(new)} chars)")
    print(f"  Length diff: {len(old) - len(new)}")

    # Character-by-character alignment
    min_len = min(len(old), len(new))
    diffs = []
    for i in range(min_len):
        if old[i] != new[i]:
            diffs.append((i, old[i], new[i]))
    print(f"  Positions differing (first {min_len} chars): {len(diffs)}")
    for pos, o, n in diffs[:30]:
        print(f"    pos {pos:3d}: {o} -> {n}")

    # Letter frequency comparison
    old_freq = Counter(old)
    new_freq = Counter(new)
    print(f"\n  Frequency differences:")
    for c in sorted(set(list(old) + list(new))):
        of = old_freq.get(c, 0)
        nf = new_freq.get(c, 0)
        if of != nf:
            print(f"    {c}: {of} -> {nf} ({nf-of:+d})")

    # ── 14. POLYBIUS / BIFID CHECKS ──────────────────────────────────────
    print(f"\n{'='*80}")
    print("14. SPECIAL CHECKS")
    print(f"{'='*80}")

    # Check if new CT could be a simple substitution of carved CT
    print(f"  Is new CT a permutation of carved CT?")
    new_sorted = ''.join(sorted(ct))
    carved_sorted = ''.join(sorted(CARVED_CT))
    print(f"    New CT sorted:    {new_sorted}")
    print(f"    Carved CT sorted: {carved_sorted}")
    print(f"    Same multiset? {new_sorted == carved_sorted}")

    # Check if same letters with different frequencies
    print(f"\n  Frequency comparison (new vs carved):")
    for c in AZ:
        nc = ct.count(c)
        cc = CARVED_CT.count(c)
        if nc != cc:
            print(f"    {c}: new={nc} carved={cc} diff={nc-cc:+d}")

    # ── 15. XOR / MODULAR DIFFERENCE ─────────────────────────────────────
    print(f"\n{'='*80}")
    print("15. MODULAR DIFFERENCE: new CT - carved CT (mod 26)")
    print(f"{'='*80}")

    # Pad shorter one
    min_l = min(len(ct), len(CARVED_CT))
    diff_seq = []
    for i in range(min_l):
        d = (ord(ct[i]) - ord(CARVED_CT[i])) % 26
        diff_seq.append(d)

    diff_letters = ''.join(AZ[d] for d in diff_seq)
    print(f"  Difference sequence (letters): {diff_letters}")
    print(f"  Difference sequence (numbers): {diff_seq}")
    print(f"  IC of difference: {ic(diff_letters):.5f}")
    cribs_diff = check_cribs(diff_letters)
    if cribs_diff:
        print(f"  *** CRIBS IN DIFFERENCE: {cribs_diff} ***")

    # Also try sum
    sum_seq = [(ord(ct[i]) - 65 + ord(CARVED_CT[i]) - 65) % 26 for i in range(min_l)]
    sum_letters = ''.join(AZ[s] for s in sum_seq)
    print(f"  Sum sequence (letters): {sum_letters}")
    cribs_sum = check_cribs(sum_letters)
    if cribs_sum:
        print(f"  *** CRIBS IN SUM: {cribs_sum} ***")

    # ── FINAL SUMMARY ────────────────────────────────────────────────────
    print(f"\n{'='*80}")
    print("SUMMARY")
    print(f"{'='*80}")
    print(f"  New CT length: {len(ct)}")
    print(f"  IC: {ic(ct):.5f}")
    print(f"  All 26 letters present: {len(set(ct)) == 26}")
    print(f"  Best keyword result shown above")
    print(f"  Check Kasiski and period IC for promising periods")
    print("=" * 80)


if __name__ == '__main__':
    main()
