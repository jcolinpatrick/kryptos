#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: _uncategorized
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""Creative attacks on new grille CT: Porta, mono, grid-offset keys, Gromark."""
import sys, os, json, math, random
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

NEW_CT = "HJLVKDJQZKIVPCMWSAFOPCKBDLHIFXRYVFIJMXEIOMQFJNXZKILKRDIYSCLMQVZACEIMVSEFHLQKRGILVHNQXWTCDKIKJUFQRXCD"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

QUADGRAMS = None
QG_FLOOR = -10.0

def load_quadgrams():
    global QUADGRAMS, QG_FLOOR
    qg_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'english_quadgrams.json')
    with open(qg_path) as f:
        QUADGRAMS = json.load(f)
    QG_FLOOR = min(QUADGRAMS.values()) - 1.0

def qg_score(text):
    if QUADGRAMS is None or len(text) < 4:
        return -999
    total = sum(QUADGRAMS.get(text[i:i+4], QG_FLOOR) for i in range(len(text)-3))
    return total / (len(text) - 3)

def ic(text):
    n = len(text)
    if n <= 1: return 0.0
    freq = Counter(text)
    return sum(f*(f-1) for f in freq.values()) / (n*(n-1))

def ci(c, alph=AZ): return alph.index(c)
def cc(i, alph=AZ): return alph[i % 26]

def vig_d(ct, key, alph=AZ):
    return ''.join(cc((ci(c,alph)-key[i%len(key)])%26,alph) for i,c in enumerate(ct))
def beau_d(ct, key, alph=AZ):
    return ''.join(cc((key[i%len(key)]-ci(c,alph))%26,alph) for i,c in enumerate(ct))

CRIBS = ["EASTNORTHEAST","BERLINCLOCK","EAST","NORTH","NORTHEAST",
         "BERLIN","CLOCK","BETWEEN","SUBTLE","SHADOW","UNDERGROUND",
         "YES","WONDERFUL","THINGS","YESWONDERFULTHINGS",
         "SLOWLY","DESPERATLY","VIRTUALLY","INVISIBLE","LANGLEY",
         "LONGITUDE","LATITUDE","CANYOUSEEANYTHING","TOMB","CARTER"]

def check_cribs(text):
    return [(c,text.find(c)) for c in CRIBS if c in text.upper()]

# ══════════════════════════════════════════════════════════════════════════
# 1. PORTA CIPHER
# ══════════════════════════════════════════════════════════════════════════

def porta_decrypt(ct, keyword):
    """Porta cipher decryption."""
    pt = []
    for i, c in enumerate(ct):
        k = ci(keyword[i % len(keyword)])
        p = ci(c)
        key_half = k // 2  # 0-12

        if p < 13:  # A-M
            pt_idx = (p - key_half) % 13 + 13
        else:  # N-Z
            pt_idx = (p - 13 + key_half) % 13
        pt.append(AZ[pt_idx])
    return ''.join(pt)

# ══════════════════════════════════════════════════════════════════════════
# 2. MONOALPHABETIC FREQUENCY ANALYSIS
# ══════════════════════════════════════════════════════════════════════════

def mono_frequency_decrypt(ct):
    """Decrypt assuming simple substitution based on English frequency."""
    eng_order = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    ct_freq = Counter(ct)
    ct_order = ''.join(c for c, _ in ct_freq.most_common())
    # Pad if needed
    for c in AZ:
        if c not in ct_order:
            ct_order += c

    mapping = {}
    for i, c in enumerate(ct_order):
        if i < len(eng_order):
            mapping[c] = eng_order[i]

    return ''.join(mapping.get(c, '?') for c in ct)

# ══════════════════════════════════════════════════════════════════════════
# 3. GRID OFFSET KEY
# ══════════════════════════════════════════════════════════════════════════

def try_offset_keys(ct):
    """Try keywords at various start offsets (K4 starts at position 768 in full grid)."""
    results = []
    keywords = ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]

    for kw in keywords:
        for offset in range(len(kw)):
            # Key starting at offset
            key = [ci(kw[(offset + i) % len(kw)]) for i in range(len(ct))]
            for var_name, fn in [("VIG", vig_d), ("BEAU", beau_d)]:
                pt = fn(ct, key)
                score = qg_score(pt)
                cribs = check_cribs(pt)
                results.append((score, f"{var_name}/{kw}+off{offset}", pt, cribs))

    # K4 starts at position 768. key_offset = 768 % len(keyword)
    for kw in keywords:
        offset = 768 % len(kw)
        key = [ci(kw[(offset + i) % len(kw)]) for i in range(len(ct))]
        for var_name, fn in [("VIG", vig_d), ("BEAU", beau_d)]:
            pt = fn(ct, key)
            score = qg_score(pt)
            cribs = check_cribs(pt)
            results.append((score, f"{var_name}/{kw}@pos768(off={offset})", pt, cribs))

    return sorted(results, key=lambda x: -x[0])

# ══════════════════════════════════════════════════════════════════════════
# 4. GROMARK / GRONSFELD
# ══════════════════════════════════════════════════════════════════════════

def gronsfeld_decrypt(ct, digits):
    """Gronsfeld (digit-key Vigenère)."""
    return ''.join(cc((ci(c) - digits[i % len(digits)]) % 26) for i, c in enumerate(ct))

# ══════════════════════════════════════════════════════════════════════════
# 5. BIFURCATED ANALYSIS - odds and evens separately
# ══════════════════════════════════════════════════════════════════════════

def analyze_bifurcated(ct):
    """Analyze even-position and odd-position characters separately."""
    evens = ''.join(ct[i] for i in range(0, len(ct), 2))
    odds = ''.join(ct[i] for i in range(1, len(ct), 2))

    results = []
    for name, sub in [("evens", evens), ("odds", odds)]:
        sub_ic = ic(sub)
        results.append((name, sub, sub_ic))

        # Try keywords on each half
        for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            key = [ci(c) for c in kw]
            for var, fn in [("VIG", vig_d), ("BEAU", beau_d)]:
                pt = fn(sub, key)
                score = qg_score(pt)
                cribs = check_cribs(pt)
                if score > -7.0 or cribs:
                    results.append((f"  {name}/{var}/{kw}", pt, score))

    return results

# ══════════════════════════════════════════════════════════════════════════
# 6. TRANSPOSITION FIRST, THEN DECRYPT
# ══════════════════════════════════════════════════════════════════════════

def columnar_transpose(text, width):
    """Read column by column."""
    nrows = math.ceil(len(text) / width)
    padded = text + 'X' * (nrows * width - len(text))
    result = ''
    for c in range(width):
        for r in range(nrows):
            idx = r * width + c
            if idx < len(text):
                result += text[idx]
    return result

def reverse_columnar(text, width):
    """Reverse columnar transposition (scatter into grid row by row, read column by column)."""
    nrows = math.ceil(len(text) / width)
    ncols = width
    # Fill column by column
    grid = [[''] * ncols for _ in range(nrows)]
    idx = 0
    for c in range(ncols):
        for r in range(nrows):
            if idx < len(text):
                grid[r][c] = text[idx]
                idx += 1
    # Read row by row
    return ''.join(grid[r][c] for r in range(nrows) for c in range(ncols) if grid[r][c])

# ══════════════════════════════════════════════════════════════════════════
# 7. NIHILIST CIPHER
# ══════════════════════════════════════════════════════════════════════════

def polybius_5x5(char, key_square):
    """Convert char to Polybius coordinates using a keyed 5x5 square."""
    idx = key_square.index(char)
    return (idx // 5, idx % 5)

# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

def main():
    ct = NEW_CT
    load_quadgrams()

    print("=" * 80)
    print("CREATIVE ATTACKS ON NEW GRILLE CT")
    print("=" * 80)

    # ── 1. PORTA CIPHER ──────────────────────────────────────────────────
    print(f"\n{'='*80}")
    print("1. PORTA CIPHER")
    print(f"{'='*80}")

    porta_results = []
    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK", "SANBORN",
               "CIPHER", "ENIGMA", "SHADOW", "CLOCK", "MEDUSA"]:
        pt = porta_decrypt(ct, kw)
        score = qg_score(pt)
        cribs = check_cribs(pt)
        porta_results.append((score, kw, pt, cribs))

    porta_results.sort(key=lambda x: -x[0])
    for score, kw, pt, cribs in porta_results:
        marker = " ***" if cribs else ""
        print(f"  PORTA/{kw}: {pt[:60]} qg={score:.4f}{marker}")

    # ── 2. MONOALPHABETIC ────────────────────────────────────────────────
    print(f"\n{'='*80}")
    print("2. MONOALPHABETIC FREQUENCY ANALYSIS")
    print(f"{'='*80}")

    mono_pt = mono_frequency_decrypt(ct)
    print(f"  Frequency-based substitution: {mono_pt}")
    print(f"  IC of CT: {ic(ct):.5f} (mono English would be ~0.0667)")
    print(f"  NOTE: IC=0.0416 is too low for mono substitution — this confirms polyalphabetic")

    # ── 3. GRID-OFFSET KEYS ──────────────────────────────────────────────
    print(f"\n{'='*80}")
    print("3. GRID-OFFSET KEY ATTACKS")
    print(f"{'='*80}")

    offset_results = try_offset_keys(ct)
    for i, (score, desc, pt, cribs) in enumerate(offset_results[:15]):
        marker = f" CRIBS:{cribs}" if cribs else ""
        print(f"  {i+1:3d}. [{score:.4f}] {desc}: {pt[:50]}{marker}")

    # ── 4. GRONSFELD (digit keys) ────────────────────────────────────────
    print(f"\n{'='*80}")
    print("4. GRONSFELD CIPHER (digit keys)")
    print(f"{'='*80}")

    # Try significant numbers
    digit_keys = [
        ("K4_start_768", [7, 6, 8]),
        ("97_prime", [9, 7]),
        ("31_width", [3, 1]),
        ("28_height", [2, 8]),
        ("868_total", [8, 6, 8]),
        ("434_half", [4, 3, 4]),
        ("1990", [1, 9, 9, 0]),
        ("2025", [2, 0, 2, 5]),
        ("314159", [3, 1, 4, 1, 5, 9]),
        ("271828", [2, 7, 1, 8, 2, 8]),
        ("row24col27", [2, 4, 2, 7]),
        ("04073", [0, 4, 0, 7, 3]),  # K4 location maybe
        ("1234567", [1, 2, 3, 4, 5, 6, 7]),
        ("7654321", [7, 6, 5, 4, 3, 2, 1]),
        ("8_lines_73", [8, 7, 3]),
    ]

    for name, digits in digit_keys:
        pt = gronsfeld_decrypt(ct, digits)
        score = qg_score(pt)
        cribs = check_cribs(pt)
        marker = " ***" if cribs else ""
        print(f"  [{score:.4f}] {name} ({digits}): {pt[:60]}{marker}")

    # ── 5. BIFURCATED ANALYSIS ───────────────────────────────────────────
    print(f"\n{'='*80}")
    print("5. BIFURCATED (EVEN/ODD) ANALYSIS")
    print(f"{'='*80}")

    evens = ct[0::2]  # 50 chars
    odds = ct[1::2]   # 50 chars
    print(f"  Evens ({len(evens)}): {evens}")
    print(f"  Odds  ({len(odds)}): {odds}")
    print(f"  IC(evens)={ic(evens):.5f}, IC(odds)={ic(odds):.5f}")

    for name, sub in [("evens", evens), ("odds", odds)]:
        for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            key = [ci(c) for c in kw]
            pt_v = vig_d(sub, key)
            pt_b = beau_d(sub, key)
            sv = qg_score(pt_v)
            sb = qg_score(pt_b)
            cv = check_cribs(pt_v)
            cb = check_cribs(pt_b)
            best = max(sv, sb)
            if best > -7.2 or cv or cb:
                print(f"    {name}/VIG/{kw}: qg={sv:.4f} | BEAU: qg={sb:.4f}")

    # ── 6. TRANSPOSITION THEN DECRYPT ────────────────────────────────────
    print(f"\n{'='*80}")
    print("6. TRANSPOSITION THEN DECRYPT")
    print(f"{'='*80}")

    trans_results = []
    for width in [4, 5, 7, 8, 10, 13, 20, 25, 31]:
        for direction in ["col", "rev_col"]:
            if direction == "col":
                trans = columnar_transpose(ct, width)
            else:
                trans = reverse_columnar(ct, width)

            for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
                key = [ci(c) for c in kw]
                for var, fn in [("VIG", vig_d), ("BEAU", beau_d)]:
                    pt = fn(trans, key)
                    score = qg_score(pt)
                    cribs = check_cribs(pt)
                    trans_results.append((score, f"w={width}/{direction}/{var}/{kw}", pt, cribs))

    trans_results.sort(key=lambda x: -x[0])
    print(f"  Top 15 transposition+decrypt:")
    for i, (score, desc, pt, cribs) in enumerate(trans_results[:15]):
        marker = f" CRIBS:{cribs}" if cribs else ""
        print(f"  {i+1:3d}. [{score:.4f}] {desc}: {pt[:50]}{marker}")

    # ── 7. K3 METHOD ON NEW CT ───────────────────────────────────────────
    print(f"\n{'='*80}")
    print("7. K3 DOUBLE COLUMNAR METHOD APPLIED TO NEW CT")
    print(f"{'='*80}")

    # K3 used double columnar with widths 21 and 28 (RTL)
    # But K4 is different length. Try various width pairs.
    for w1 in [4, 5, 7, 8, 10]:
        for w2 in [4, 5, 7, 8, 10, 13, 20, 25]:
            if w1 == w2:
                continue
            # First columnar transposition
            mid = columnar_transpose(ct, w1)
            # Second columnar transposition
            trans = columnar_transpose(mid, w2)

            for kw in ["KRYPTOS"]:
                key = [ci(c) for c in kw]
                pt = vig_d(trans, key)
                score = qg_score(pt)
                cribs = check_cribs(pt)
                if score > -7.0 or cribs:
                    print(f"  double_col({w1},{w2})/VIG/{kw}: qg={score:.4f} {pt[:50]}")

                pt_b = beau_d(trans, key)
                score_b = qg_score(pt_b)
                cribs_b = check_cribs(pt_b)
                if score_b > -7.0 or cribs_b:
                    print(f"  double_col({w1},{w2})/BEAU/{kw}: qg={score_b:.4f} {pt_b[:50]}")

    # ── 8. FIRST 97 vs LAST 97 vs MIDDLE ────────────────────────────────
    print(f"\n{'='*80}")
    print("8. FOCUSED 97-CHAR SUBSETS")
    print(f"{'='*80}")

    subsets = {
        "first_97": ct[:97],
        "last_97": ct[3:],
        "skip_first": ct[1:98],
        "skip_last": ct[0:97],
        "skip_first3": ct[3:],
        "no_last3": ct[:97],
    }

    for sname, sub in subsets.items():
        if len(sub) != 97:
            sub = sub[:97]
        for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            key = [ci(c) for c in kw]
            for var, fn in [("VIG", vig_d), ("BEAU", beau_d)]:
                pt = fn(sub, key)
                score = qg_score(pt)
                cribs = check_cribs(pt)
                if score > -7.0 or cribs:
                    print(f"  {sname}/{var}/{kw}: qg={score:.4f} {pt[:50]}")

    # ── 9. TWO-KEYWORD VIGENERE ──────────────────────────────────────────
    print(f"\n{'='*80}")
    print("9. TWO-KEYWORD COMBINED KEYS")
    print(f"{'='*80}")

    # E.g., key = KRYPTOS XOR PALIMPSEST, or key = KRYPTOS + ABSCISSA mod 26
    keywords = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK"]
    two_kw_results = []

    for kw1 in keywords:
        for kw2 in keywords:
            if kw1 >= kw2:
                continue
            # LCM length key
            lcm_len = len(kw1) * len(kw2) // math.gcd(len(kw1), len(kw2))

            # Sum key
            sum_key = [(ci(kw1[i % len(kw1)]) + ci(kw2[i % len(kw2)])) % 26 for i in range(lcm_len)]
            # Diff key
            diff_key = [(ci(kw1[i % len(kw1)]) - ci(kw2[i % len(kw2)])) % 26 for i in range(lcm_len)]

            for key_name, key in [("sum", sum_key), ("diff", diff_key)]:
                pt = vig_d(ct, key)
                score = qg_score(pt)
                cribs = check_cribs(pt)
                two_kw_results.append((score, f"{kw1}+{kw2}({key_name})", pt, cribs))

    two_kw_results.sort(key=lambda x: -x[0])
    for i, (score, desc, pt, cribs) in enumerate(two_kw_results[:10]):
        marker = f" CRIBS:{cribs}" if cribs else ""
        print(f"  {i+1}. [{score:.4f}] {desc}: {pt[:50]}{marker}")

    # ── 10. PROGRESSIVE KEY / BEAUFORT WITH KA ───────────────────────────
    print(f"\n{'='*80}")
    print("10. BEAUFORT WITH KA ALPHABET (all keywords)")
    print(f"{'='*80}")

    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK", "SANBORN",
               "SCHEIDT", "IQLUSION", "DESPERATLY", "UNDERGROUND"]:
        key = [ci(c, KA) for c in kw if c in KA]
        if not key:
            continue
        pt = beau_d(ct, key, KA)
        score = qg_score(pt)
        cribs = check_cribs(pt)
        marker = f" CRIBS:{cribs}" if cribs else ""
        print(f"  BEAU/KA/{kw}: qg={score:.4f} {pt[:55]}{marker}")

    # ── 11. RAW STATISTICAL SUMMARY ──────────────────────────────────────
    print(f"\n{'='*80}")
    print("11. STATISTICAL SUMMARY")
    print(f"{'='*80}")

    # Bigram IC
    bigrams = [ct[i:i+2] for i in range(len(ct)-1)]
    bigram_ic = ic(''.join(bigrams))
    print(f"  Monogram IC: {ic(ct):.5f}")
    print(f"  Unique bigrams: {len(set(bigrams))} / {len(bigrams)}")

    # Chi-squared against English
    eng_freq = {'A':8.17,'B':1.29,'C':2.78,'D':4.25,'E':12.7,'F':2.23,'G':2.02,'H':6.09,
                'I':6.97,'J':0.15,'K':0.77,'L':4.03,'M':2.41,'N':6.75,'O':7.51,'P':1.93,
                'Q':0.10,'R':5.99,'S':6.33,'T':9.06,'U':2.76,'V':0.98,'W':2.36,'X':0.15,
                'Y':1.97,'Z':0.07}
    freq = Counter(ct)
    chi2 = sum((freq.get(c,0) - eng_freq[c]*len(ct)/100)**2 / (eng_freq[c]*len(ct)/100)
               for c in AZ if eng_freq[c] > 0)
    print(f"  Chi-squared vs English: {chi2:.1f} (lower = more English-like, random ≈ 200-400)")

    # Unicity distance
    print(f"  Unicity distance estimate: ~{int(1.47 * 26)}")  # H(K)/D for 26-letter key
    print(f"  CT length {len(ct)} vs English IC gap: {'SUFFICIENT' if len(ct) > 50 else 'MARGINAL'}")

    # ── 12. LETTER PATTERN ANALYSIS ──────────────────────────────────────
    print(f"\n{'='*80}")
    print("12. NOTABLE PATTERNS")
    print(f"{'='*80}")

    # Check for repeating patterns
    for length in range(3, 8):
        patterns = {}
        for i in range(len(ct) - length + 1):
            s = ct[i:i+length]
            if s in patterns:
                patterns[s].append(i)
            else:
                patterns[s] = [i]
        repeats = {k: v for k, v in patterns.items() if len(v) > 1}
        if repeats:
            for pat, positions in repeats.items():
                distances = [positions[j]-positions[j-1] for j in range(1, len(positions))]
                print(f"  Repeat '{pat}' at positions {positions} (distances: {distances})")

    # Terminal CD CD pattern
    print(f"\n  Last 10 chars: {ct[-10:]}")
    print(f"  First 10 chars: {ct[:10]}")
    print(f"  Note: CT ends with 'QRXCD' and starts with 'HJLVKDJQZK'")

    # Check if last 3 chars = first 3 chars or reverse
    print(f"  Last 3: {ct[-3:]}, First 3: {ct[:3]}, Match: {ct[-3:] == ct[:3]}")
    print(f"  Last 3 reversed: {ct[-3:][::-1]}, First 3: {ct[:3]}, Match: {ct[-3:][::-1] == ct[:3]}")

    print(f"\n{'='*80}")
    print("ANALYSIS COMPLETE")
    print(f"{'='*80}")


if __name__ == '__main__':
    main()
