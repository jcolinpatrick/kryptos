#!/usr/bin/env python3
"""
Cipher: Vigenere/Beaufort
Family: _uncategorized
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""Deep attack on new grille CT: crib-dragging, hill climbing, Beaufort focus."""
import sys, os, json, math, random, itertools
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

NEW_CT = "HJLVKDJQZKIVPCMWSAFOPCKBDLHIFXRYVFIJMXEIOMQFJNXZKILKRDIYSCLMQVZACEIMVSEFHLQKRGILVHNQXWTCDKIKJUFQRXCD"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

# Load quadgrams
QUADGRAMS = None
QG_FLOOR = -10.0

def load_quadgrams():
    global QUADGRAMS, QG_FLOOR
    qg_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'english_quadgrams.json')
    with open(qg_path) as f:
        QUADGRAMS = json.load(f)
    vals = list(QUADGRAMS.values())
    QG_FLOOR = min(vals) - 1.0

def qg_score(text):
    if QUADGRAMS is None or len(text) < 4:
        return -999
    total = 0.0
    count = 0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        total += QUADGRAMS.get(qg, QG_FLOOR)
        count += 1
    return total / count if count > 0 else -999

def char_to_idx(c, alph=AZ):
    return alph.index(c)

def idx_to_char(i, alph=AZ):
    return alph[i % 26]

def vig_decrypt(ct, key_nums, alph=AZ):
    klen = len(key_nums)
    return ''.join(idx_to_char((char_to_idx(c, alph) - key_nums[i % klen]) % 26, alph) for i, c in enumerate(ct))

def beau_decrypt(ct, key_nums, alph=AZ):
    klen = len(key_nums)
    return ''.join(idx_to_char((key_nums[i % klen] - char_to_idx(c, alph)) % 26, alph) for i, c in enumerate(ct))

def varbeau_decrypt(ct, key_nums, alph=AZ):
    klen = len(key_nums)
    return ''.join(idx_to_char((char_to_idx(c, alph) + key_nums[i % klen]) % 26, alph) for i, c in enumerate(ct))

CRIBS = ["EASTNORTHEAST", "BERLINCLOCK", "YESWONDERFULTHINGS",
         "EAST", "NORTH", "NORTHEAST", "BERLIN", "CLOCK",
         "BETWEEN", "SUBTLE", "SHADOW", "UNDERGROUND",
         "SLOWLY", "DESPERATLY", "VIRTUALLY", "INVISIBLE",
         "YES", "WONDERFUL", "THINGS", "Carter", "TOMB",
         "LANGLEY", "LONGITUDE", "LATITUDE", "IQLUSION",
         "CANYOUSEEANYTHING", "INTERPRETATIONS"]

def check_cribs(text):
    found = []
    for crib in CRIBS:
        crib = crib.upper()
        pos = text.find(crib)
        if pos >= 0:
            found.append((crib, pos))
    return found

# ══════════════════════════════════════════════════════════════════════════
# 1. CRIB DRAGGING - place known plaintext at every position
# ══════════════════════════════════════════════════════════════════════════

def crib_drag(ct, crib, alph=AZ):
    """Try placing a crib at every position and recover implied key values."""
    results = []
    for start in range(len(ct) - len(crib) + 1):
        # Recover key values at these positions
        vig_key = []
        beau_key = []
        for i, pt_ch in enumerate(crib):
            ci = char_to_idx(ct[start + i], alph)
            pi = char_to_idx(pt_ch, alph)
            vig_key.append((ci - pi) % 26)
            beau_key.append((ci + pi) % 26)

        results.append((start, vig_key, beau_key))
    return results

def analyze_key_periodicity(key_values, max_period=26):
    """Check if key values show periodic structure."""
    best_period = None
    best_score = -1
    for period in range(1, min(max_period + 1, len(key_values))):
        # Check consistency: do values repeat with this period?
        consistent = 0
        total = 0
        for i in range(len(key_values)):
            for j in range(i + period, len(key_values), period):
                if j < len(key_values):
                    total += 1
                    if key_values[i] == key_values[j]:
                        consistent += 1
        if total > 0:
            score = consistent / total
            if score > best_score:
                best_score = score
                best_period = period
    return best_period, best_score

# ══════════════════════════════════════════════════════════════════════════
# 2. HILL CLIMBING with SA
# ══════════════════════════════════════════════════════════════════════════

def hill_climb_key(ct, period, alph=AZ, variant="vig", iterations=50000, restarts=5):
    """Simulated annealing to find optimal key."""
    best_overall_score = -999
    best_overall_key = None
    best_overall_pt = None

    decrypt_fn = {"vig": vig_decrypt, "beau": beau_decrypt, "varbeau": varbeau_decrypt}[variant]

    for restart in range(restarts):
        # Random initial key
        key = [random.randint(0, 25) for _ in range(period)]

        pt = decrypt_fn(ct, key, alph)
        score = qg_score(pt)
        best_score = score
        best_key = key[:]

        temp = 1.0
        for it in range(iterations):
            # Mutate: change one key position
            new_key = key[:]
            pos = random.randint(0, period - 1)
            new_key[pos] = random.randint(0, 25)

            pt = decrypt_fn(ct, new_key, alph)
            new_score = qg_score(pt)

            delta = new_score - score
            if delta > 0 or random.random() < math.exp(delta / max(temp, 0.001)):
                key = new_key
                score = new_score

                if score > best_score:
                    best_score = score
                    best_key = key[:]

            temp *= 0.9999

        if best_score > best_overall_score:
            best_overall_score = best_score
            best_overall_key = best_key
            best_overall_pt = decrypt_fn(ct, best_key, alph)

    return best_overall_key, best_overall_pt, best_overall_score

# ══════════════════════════════════════════════════════════════════════════
# 3. WORDLIST-BASED KEY SEARCH
# ══════════════════════════════════════════════════════════════════════════

def wordlist_key_search(ct, wordlist_path, alph=AZ, max_len=15):
    """Try every word in wordlist as a Vigenere key."""
    best = []
    try:
        with open(wordlist_path) as f:
            words = [w.strip().upper() for w in f if w.strip().isalpha() and 3 <= len(w.strip()) <= max_len]
    except FileNotFoundError:
        return []

    for word in words:
        key_nums = [char_to_idx(c, alph) for c in word if c in alph]
        if not key_nums:
            continue

        for var_name, fn in [("VIG", vig_decrypt), ("BEAU", beau_decrypt)]:
            pt = fn(ct, key_nums, alph)
            score = qg_score(pt)
            cribs = check_cribs(pt)
            if score > -6.8 or cribs:
                best.append((score, var_name, word, pt, cribs))

    best.sort(key=lambda x: -x[0])
    return best[:50]

# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

def main():
    ct = NEW_CT
    load_quadgrams()

    print("=" * 80)
    print("DEEP ATTACK ON NEW GRILLE CT (100 chars)")
    print("=" * 80)

    # ── 1. CRIB DRAGGING ─────────────────────────────────────────────────
    print(f"\n{'='*80}")
    print("1. CRIB DRAGGING — EASTNORTHEAST (13 chars)")
    print(f"{'='*80}")

    for alph_name, alph in [("AZ", AZ), ("KA", KA)]:
        print(f"\n  Alphabet: {alph_name}")
        results = crib_drag(ct, "EASTNORTHEAST", alph)
        for start, vig_key, beau_key in results:
            vig_str = ''.join(idx_to_char(k, alph) for k in vig_key)
            beau_str = ''.join(idx_to_char(k, alph) for k in beau_key)

            # Check periodicity
            for period in range(1, 14):
                # Vig: check if key repeats with this period
                vig_consistent = True
                for i in range(len(vig_key)):
                    for j in range(i, len(vig_key)):
                        if (j - i) % period == 0 and vig_key[i] != vig_key[j]:
                            vig_consistent = False
                            break
                    if not vig_consistent:
                        break

                if vig_consistent and period <= 10:
                    # This key repeats with period p — extract the key
                    key_cycle = vig_key[:period]
                    key_word = ''.join(idx_to_char(k, alph) for k in key_cycle)
                    # Decrypt full CT with this key
                    full_pt = vig_decrypt(ct, key_cycle, alph)
                    score = qg_score(full_pt)
                    cribs = check_cribs(full_pt)
                    marker = " ***" if cribs else ""
                    print(f"    pos={start:2d} VIG period={period} key={key_word}: {full_pt[:50]} qg={score:.3f}{marker}")

                beau_consistent = True
                for i in range(len(beau_key)):
                    for j in range(i, len(beau_key)):
                        if (j - i) % period == 0 and beau_key[i] != beau_key[j]:
                            beau_consistent = False
                            break
                    if not beau_consistent:
                        break

                if beau_consistent and period <= 10:
                    key_cycle = beau_key[:period]
                    key_word = ''.join(idx_to_char(k, alph) for k in key_cycle)
                    full_pt = beau_decrypt(ct, key_cycle, alph)
                    score = qg_score(full_pt)
                    cribs = check_cribs(full_pt)
                    marker = " ***" if cribs else ""
                    print(f"    pos={start:2d} BEAU period={period} key={key_word}: {full_pt[:50]} qg={score:.3f}{marker}")

        # Just show the raw key values for context
        print(f"\n  Key values at each start position (Vig/{alph_name}):")
        for start, vig_key, beau_key in results[:10]:
            vig_str = ''.join(idx_to_char(k, alph) for k in vig_key)
            print(f"    pos={start:2d}: key_letters={vig_str} nums={vig_key}")

    # Also drag BERLINCLOCK
    print(f"\n{'='*80}")
    print("1b. CRIB DRAGGING — BERLINCLOCK (11 chars)")
    print(f"{'='*80}")

    for alph_name, alph in [("AZ", AZ)]:
        results = crib_drag(ct, "BERLINCLOCK", alph)
        print(f"\n  Key values at each position (Vig/{alph_name}):")
        for start, vig_key, beau_key in results:
            vig_str = ''.join(idx_to_char(k, alph) for k in vig_key)
            # Check for known keywords in key
            for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
                for period in range(1, 12):
                    consistent = True
                    kw_key = [char_to_idx(kw[i % len(kw)], alph) for i in range(11)]
                    # Check if vig_key matches kw_key at positions start..start+10 mod period
                    match = True
                    for i in range(11):
                        expected = char_to_idx(kw[(start + i) % len(kw)], alph)
                        if vig_key[i] != expected:
                            match = False
                            break
                    if match:
                        full_pt = vig_decrypt(ct, [char_to_idx(c, alph) for c in kw], alph)
                        print(f"    *** KEYWORD MATCH: pos={start} VIG/{kw} -> {full_pt[:50]}")

            # Show raw for manual inspection
            if start < 15 or start > len(ct) - 15:
                print(f"    pos={start:2d}: VIG key={vig_str}")

    # ── 2. HILL CLIMBING ─────────────────────────────────────────────────
    print(f"\n{'='*80}")
    print("2. HILL CLIMBING (SA) — Best periods")
    print(f"{'='*80}")

    for period in [7, 8, 10, 12, 13]:
        for alph_name, alph in [("AZ", AZ)]:
            for variant in ["vig", "beau"]:
                key, pt, score = hill_climb_key(ct, period, alph, variant, iterations=100000, restarts=3)
                key_str = ''.join(idx_to_char(k, alph) for k in key)
                cribs = check_cribs(pt)
                marker = " ***CRIBS***" if cribs else ""
                print(f"  p={period:2d} {variant:7s}/{alph_name}: key={key_str:15s} qg={score:.4f} {pt[:55]}{marker}")

    # Also try on 97-char substrings
    print(f"\n  Hill climbing on substring [0:97]:")
    sub = ct[:97]
    for period in [7, 8]:
        for variant in ["vig", "beau"]:
            key, pt, score = hill_climb_key(sub, period, AZ, variant, iterations=100000, restarts=3)
            key_str = ''.join(AZ[k] for k in key)
            cribs = check_cribs(pt)
            print(f"  p={period} {variant}: key={key_str} qg={score:.4f} {pt[:55]}")

    # ── 3. WORDLIST KEY SEARCH ───────────────────────────────────────────
    print(f"\n{'='*80}")
    print("3. WORDLIST KEY SEARCH")
    print(f"{'='*80}")

    wordlist = os.path.join(os.path.dirname(__file__), '..', 'wordlists', 'english.txt')
    results = wordlist_key_search(ct, wordlist, AZ, max_len=12)
    print(f"  Found {len(results)} results above threshold")
    for i, (score, var, word, pt, cribs) in enumerate(results[:25]):
        cribs_str = f" CRIBS:{cribs}" if cribs else ""
        print(f"  {i+1:3d}. [{score:.4f}] {var}/{word:15s}: {pt[:55]}{cribs_str}")

    # Also KA alphabet
    results_ka = wordlist_key_search(ct, wordlist, KA, max_len=12)
    print(f"\n  KA alphabet — Found {len(results_ka)} results above threshold")
    for i, (score, var, word, pt, cribs) in enumerate(results_ka[:15]):
        cribs_str = f" CRIBS:{cribs}" if cribs else ""
        print(f"  {i+1:3d}. [{score:.4f}] {var}/{word:15s}: {pt[:55]}{cribs_str}")

    # ── 4. COMBINED CRIB PLACEMENT ───────────────────────────────────────
    print(f"\n{'='*80}")
    print("4. COMBINED CRIB PLACEMENT (EASTNORTHEAST + BERLINCLOCK)")
    print(f"{'='*80}")

    # Try every combo of positions for both cribs
    best_combos = []
    for east_start in range(len(ct) - 13 + 1):
        for berlin_start in range(len(ct) - 11 + 1):
            # No overlap
            east_end = east_start + 13
            berlin_end = berlin_start + 11
            if east_start < berlin_end and berlin_start < east_end:
                continue

            # Recover key at all crib positions
            key_map = {}
            conflict = False
            for i, ch in enumerate("EASTNORTHEAST"):
                pos = east_start + i
                k = (char_to_idx(ct[pos]) - char_to_idx(ch)) % 26
                if pos in key_map and key_map[pos] != k:
                    conflict = True
                    break
                key_map[pos] = k

            if conflict:
                continue

            for i, ch in enumerate("BERLINCLOCK"):
                pos = berlin_start + i
                k = (char_to_idx(ct[pos]) - char_to_idx(ch)) % 26
                if pos in key_map and key_map[pos] != k:
                    conflict = True
                    break
                key_map[pos] = k

            if conflict:
                continue

            # Check for periodic key
            positions = sorted(key_map.keys())
            key_values = [key_map[p] for p in positions]

            for period in range(1, 14):
                consistent = True
                key_cycle = [None] * period
                for pos, kval in key_map.items():
                    slot = pos % period
                    if key_cycle[slot] is None:
                        key_cycle[slot] = kval
                    elif key_cycle[slot] != kval:
                        consistent = False
                        break

                if consistent and all(k is not None for k in key_cycle):
                    key_word = ''.join(AZ[k] for k in key_cycle)
                    full_pt = vig_decrypt(ct, key_cycle, AZ)
                    score = qg_score(full_pt)
                    if score > -7.0:
                        best_combos.append((score, east_start, berlin_start, period, key_word, full_pt))

    best_combos.sort(key=lambda x: -x[0])
    print(f"  Found {len(best_combos)} consistent period-key combos (qg > -7.0)")
    for i, (score, es, bs, period, key_word, pt) in enumerate(best_combos[:20]):
        cribs = check_cribs(pt)
        marker = " ***" if cribs else ""
        print(f"  {i+1:3d}. [{score:.4f}] EAST@{es} BERLIN@{bs} p={period} key={key_word}: {pt[:50]}{marker}")

    # ── 5. AFFINE / MULTIPLICATIVE SUBSTITUTION ──────────────────────────
    print(f"\n{'='*80}")
    print("5. AFFINE SUBSTITUTION (a*x + b mod 26)")
    print(f"{'='*80}")

    coprimes = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
    affine_results = []
    for a in coprimes:
        for b in range(26):
            pt = ''.join(AZ[(a * char_to_idx(c) + b) % 26] for c in ct)
            score = qg_score(pt)
            cribs = check_cribs(pt)
            if score > -7.0 or cribs:
                affine_results.append((score, a, b, pt, cribs))

    affine_results.sort(key=lambda x: -x[0])
    print(f"  Top 10 affine results:")
    for i, (score, a, b, pt, cribs) in enumerate(affine_results[:10]):
        cribs_str = f" CRIBS:{cribs}" if cribs else ""
        print(f"  {i+1}. [{score:.4f}] a={a} b={b}: {pt[:60]}{cribs_str}")

    # ── 6. DOUBLE ENCRYPTION CHECK ───────────────────────────────────────
    print(f"\n{'='*80}")
    print("6. DOUBLE ENCRYPTION (VIG then VIG, different keys)")
    print(f"{'='*80}")

    double_results = []
    for kw1 in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
        key1 = [char_to_idx(c) for c in kw1]
        mid = vig_decrypt(ct, key1, AZ)
        for kw2 in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK", "SANBORN"]:
            key2 = [char_to_idx(c) for c in kw2]
            pt_vv = vig_decrypt(mid, key2, AZ)
            pt_vb = beau_decrypt(mid, key2, AZ)
            score_vv = qg_score(pt_vv)
            score_vb = qg_score(pt_vb)
            cribs_vv = check_cribs(pt_vv)
            cribs_vb = check_cribs(pt_vb)
            double_results.append((score_vv, f"VIG/{kw1}+VIG/{kw2}", pt_vv, cribs_vv))
            double_results.append((score_vb, f"VIG/{kw1}+BEAU/{kw2}", pt_vb, cribs_vb))

        # Also Beaufort first layer
        mid_b = beau_decrypt(ct, key1, AZ)
        for kw2 in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            key2 = [char_to_idx(c) for c in kw2]
            pt = vig_decrypt(mid_b, key2, AZ)
            score = qg_score(pt)
            cribs = check_cribs(pt)
            double_results.append((score, f"BEAU/{kw1}+VIG/{kw2}", pt, cribs))

    double_results.sort(key=lambda x: -x[0])
    print(f"  Top 10:")
    for i, (score, desc, pt, cribs) in enumerate(double_results[:10]):
        cribs_str = f" CRIBS:{cribs}" if cribs else ""
        print(f"  {i+1}. [{score:.4f}] {desc}: {pt[:55]}{cribs_str}")

    # ── 7. PROGRESSIVE KEY (KRYPTOS starting at different offsets) ──────
    print(f"\n{'='*80}")
    print("7. KEYWORD AT DIFFERENT OFFSETS")
    print(f"{'='*80}")

    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
        for offset in range(len(kw)):
            shifted_kw = kw[offset:] + kw[:offset]
            key_nums = [char_to_idx(c) for c in shifted_kw]
            for var, fn in [("VIG", vig_decrypt), ("BEAU", beau_decrypt)]:
                pt = fn(ct, key_nums, AZ)
                score = qg_score(pt)
                cribs = check_cribs(pt)
                if score > -7.0 or cribs:
                    print(f"  {var}/{shifted_kw} (offset={offset}): qg={score:.4f} {pt[:50]}")

    # ── 8. TRY ON THE CARVED CT TOO ──────────────────────────────────────
    print(f"\n{'='*80}")
    print("8. NEW CT AS KEY FOR CARVED CT (and vice versa)")
    print(f"{'='*80}")

    carved = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
    # Use first 97 chars of new CT as key for carved CT
    new_key = [char_to_idx(c) for c in ct[:97]]
    for var, fn in [("VIG", vig_decrypt), ("BEAU", beau_decrypt), ("VARBEAU", varbeau_decrypt)]:
        pt = fn(carved, new_key, AZ)
        score = qg_score(pt)
        cribs = check_cribs(pt)
        words_found = [w for w in ["THE","AND","FOR","ARE","WAS","BUT","NOT","YOU","HIS","HER",
                                     "HAS","HAD","ONE","OUR","OUT","CAN","HOW","ALL","NEW","OLD",
                                     "BETWEEN","SUBTLE","SHADOW","EAST","NORTH","BERLIN","CLOCK",
                                     "UNDERGROUND","YES","WONDERFUL","THINGS"] if w in pt]
        print(f"  new_CT_key → carved: {var}: {pt[:60]} qg={score:.3f} words={words_found}")
        if cribs:
            print(f"    *** CRIBS: {cribs}")

    # carved CT as key for new CT
    carved_key = [char_to_idx(c) for c in carved]
    for var, fn in [("VIG", vig_decrypt), ("BEAU", beau_decrypt), ("VARBEAU", varbeau_decrypt)]:
        pt = fn(ct[:97], carved_key, AZ)
        score = qg_score(pt)
        cribs = check_cribs(pt)
        words_found = [w for w in ["THE","AND","FOR","ARE","WAS","BUT","NOT","ONE",
                                     "BETWEEN","SUBTLE","SHADOW","EAST","NORTH","BERLIN","CLOCK",
                                     "YES","WONDERFUL","THINGS"] if w in pt]
        print(f"  carved_key → new_CT: {var}: {pt[:60]} qg={score:.3f} words={words_found}")

    # ── 9. DIGRAPHIC / POLYGRAPHIC ANALYSIS ──────────────────────────────
    print(f"\n{'='*80}")
    print("9. BIGRAM FREQUENCY ANALYSIS")
    print(f"{'='*80}")

    bigrams = Counter()
    for i in range(len(ct) - 1):
        bigrams[ct[i:i+2]] += 1

    print(f"  Most common bigrams:")
    for bg, count in bigrams.most_common(15):
        print(f"    {bg}: {count}")

    # ── 10. KNOWN PLAINTEXT EXTENSION ────────────────────────────────────
    print(f"\n{'='*80}")
    print("10. 'YES WONDERFUL THINGS' PLACEMENT TEST")
    print(f"{'='*80}")

    test_pts = [
        "YESWONDERFULTHINGS",
        "YESTHEWONDERFULTHINGS",
        "YESIWONDERFULTHINGS",
    ]

    for test_pt in test_pts:
        for start in range(len(ct) - len(test_pt) + 1):
            vig_key = [(char_to_idx(ct[start + i]) - char_to_idx(test_pt[i])) % 26 for i in range(len(test_pt))]
            key_str = ''.join(AZ[k] for k in vig_key)

            # Check periodicity
            for period in [7, 8, 10]:
                consistent = True
                for i in range(len(vig_key)):
                    for j in range(i + period, len(vig_key), period):
                        if j < len(vig_key) and vig_key[i] != vig_key[j]:
                            consistent = False
                            break
                    if not consistent:
                        break
                if consistent:
                    key_cycle = vig_key[:period]
                    kw = ''.join(AZ[k] for k in key_cycle)
                    full_pt = vig_decrypt(ct, key_cycle, AZ)
                    score = qg_score(full_pt)
                    if score > -7.5:
                        print(f"  '{test_pt}' at pos {start}, VIG period={period} key={kw}: {full_pt[:50]} qg={score:.4f}")

    print("\nDone.")


if __name__ == '__main__':
    main()
