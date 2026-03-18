#!/usr/bin/env python3
"""
Cipher: blind cryptanalysis
Family: k3_continuity
Status: active
Keyspace: ~500K+ configs
Last run:
Best score:
"""
"""E-NDYAHR-BLIND-CRYPTANALYSIS: Blind cryptanalysis of K1+K2+K3 after NDYAHR removal.

CRITICAL POINT: After NDYAHR letter removal, we treat these as COMPLETELY NEW
ciphertexts. We do NOT know the cipher method. We do NOT score against K4 cribs.
We look for ENGLISH PLAINTEXT using quadgram scoring, IC, frequency analysis,
and hill-climbing.

Test texts:
1. K3_edited: K3 CT with N,D,Y,A,H,R removed
2. K123_edited: K1+K2+K3 CT concatenated, with N,D,Y,A,H,R removed
3. K3_corrected_edited: K3 CT with Sanborn corrections, then NDYAHR removed
4. K1K2_edited: K1+K2 CT with NDYAHR removed

Steps:
1. Statistical profiling (IC, frequency, Kasiski, Friedman)
2. Monoalphabetic substitution hill-climbing (50 restarts x 10K steps)
3. Vigenere/Beaufort with all periods 1-30
4. Transposition analysis (columnar, rail fence, route)
5. Combined transposition + substitution
6. Subset analysis (remove subsets of NDYAHR)

Usage: PYTHONPATH=src python3 -u scripts/k3_continuity/e_ndyahr_blind_cryptanalysis.py
"""

import sys
import os
import json
import time
import math
import random
from collections import Counter
from datetime import datetime, timezone
from itertools import permutations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, ALPH, ALPH_IDX, MOD
from kryptos.kernel.scoring.ngram import NgramScorer

# ── Load quadgram scorer ──────────────────────────────────────────────────
QG_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'english_quadgrams.json')
scorer = NgramScorer.from_file(QG_PATH, n=4)

random.seed(42)

# ── K1/K2/K3 Ciphertexts ─────────────────────────────────────────────────

K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"

K2_CT = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLG"
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRR"
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVHDWKBFUFPWNTDFIYCUQZERE"
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZFKZBSFDQVGOGIPUFXHHDRKF"
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
)

K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOE"
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLB"
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"
)

# K3 plaintext (known — K3 is a solved transposition cipher)
K3_PT = ''.join(c for c in (
    "SLOWLY DESPARATLY SLOWLY THE REMAINS OF PASSAGE DEBRIS "
    "THAT ENCUMBERED THE LOWER PART OF THE DOORWAY WAS REMOVED "
    "WITH TREMBLING HANDS I MADE A TINY BREACH IN THE UPPER "
    "LEFT HAND CORNER AND THEN WIDENING THE HOLE A LITTLE "
    "I INSERTED THE CANDLE AND PEERED IN THE HOT AIR ESCAPING "
    "FROM THE CHAMBER CAUSED THE FLAME TO FLICKER BUT PRESENTLY "
    "DETAILS OF THE ROOM WITHIN EMERGED FROM THE MIST "
    "X CAN YOU SEE ANYTHING Q"
).upper() if c.isalpha())

NDYAHR = set('NDYAHR')

# ── Helper functions ──────────────────────────────────────────────────────

def remove_letters(text, letters_to_remove):
    """Remove all occurrences of specified letters from text."""
    return ''.join(c for c in text if c not in letters_to_remove)

def ic(text):
    """Index of coincidence."""
    n = len(text)
    if n <= 1:
        return 0.0
    freq = Counter(text)
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))

def digraph_ic(text):
    """Digraph index of coincidence."""
    n = len(text) - 1
    if n <= 1:
        return 0.0
    digraphs = [text[i:i+2] for i in range(n)]
    freq = Counter(digraphs)
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))

def chi_squared(text, expected_freqs):
    """Chi-squared statistic against expected frequencies."""
    n = len(text)
    freq = Counter(text)
    total = 0.0
    for c in ALPH:
        if c in expected_freqs:
            observed = freq.get(c, 0)
            expected = expected_freqs[c] * n
            if expected > 0:
                total += (observed - expected) ** 2 / expected
    return total

# English letter frequencies (standard)
ENGLISH_FREQ = {
    'A': 0.08167, 'B': 0.01492, 'C': 0.02782, 'D': 0.04253, 'E': 0.12702,
    'F': 0.02228, 'G': 0.02015, 'H': 0.06094, 'I': 0.06966, 'J': 0.00153,
    'K': 0.00772, 'L': 0.04025, 'M': 0.02406, 'N': 0.06749, 'O': 0.07507,
    'P': 0.01929, 'Q': 0.00095, 'R': 0.05987, 'S': 0.06327, 'T': 0.09056,
    'U': 0.02758, 'V': 0.00978, 'W': 0.02360, 'X': 0.00150, 'Y': 0.01974,
    'Z': 0.00074
}

UNIFORM_FREQ = {c: 1.0/26 for c in ALPH}

def kasiski_examination(text, min_len=2, max_len=5):
    """Find repeated n-grams and compute GCD of distances."""
    results = {}
    for n in range(min_len, max_len + 1):
        positions = {}
        for i in range(len(text) - n + 1):
            gram = text[i:i+n]
            if gram not in positions:
                positions[gram] = []
            positions[gram].append(i)
        for gram, pos_list in positions.items():
            if len(pos_list) >= 2:
                distances = []
                for i in range(len(pos_list)):
                    for j in range(i + 1, len(pos_list)):
                        distances.append(pos_list[j] - pos_list[i])
                results[gram] = {'positions': pos_list, 'distances': distances}
    return results

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def gcd_list(lst):
    result = lst[0]
    for x in lst[1:]:
        result = gcd(result, x)
    return result

def friedman_test(text):
    """Estimate key length using Friedman test."""
    n = len(text)
    ic_val = ic(text)
    if ic_val <= 1.0/26:
        return float('inf')
    # Friedman formula: k = (0.0667 - 1/26) / (ic - 1/26) * n / (n-1) approximately
    numerator = 0.0667 - (1.0/26)
    denominator = ic_val - (1.0/26)
    if denominator <= 0:
        return float('inf')
    return numerator / denominator

def vig_decrypt(ct, key):
    """Decrypt ciphertext with Vigenere using key string."""
    pt = []
    for i, c in enumerate(ct):
        k = key[i % len(key)]
        pt.append(ALPH[(ALPH_IDX[c] - ALPH_IDX[k]) % 26])
    return ''.join(pt)

def beau_decrypt(ct, key):
    """Decrypt ciphertext with Beaufort using key string."""
    pt = []
    for i, c in enumerate(ct):
        k = key[i % len(key)]
        pt.append(ALPH[(ALPH_IDX[k] - ALPH_IDX[c]) % 26])
    return ''.join(pt)

def best_key_letter_vig(ct_segment):
    """Find best Vigenere key letter for a segment by frequency analysis."""
    best_score = float('-inf')
    best_key = 'A'
    for k in range(26):
        pt = ''.join(ALPH[(ALPH_IDX[c] - k) % 26] for c in ct_segment)
        s = scorer.score(pt) if len(pt) >= 4 else -999
        if s > best_score:
            best_score = s
            best_key = ALPH[k]
    return best_key, best_score

def best_key_letter_beau(ct_segment):
    """Find best Beaufort key letter for a segment by frequency analysis."""
    best_score = float('-inf')
    best_key = 'A'
    for k in range(26):
        pt = ''.join(ALPH[(k - ALPH_IDX[c]) % 26] for c in ct_segment)
        s = scorer.score(pt) if len(pt) >= 4 else -999
        if s > best_score:
            best_score = s
            best_key = ALPH[k]
    return best_key, best_score

def mono_hill_climb(text, restarts=50, steps=10000):
    """Monoalphabetic substitution hill-climbing."""
    best_score = float('-inf')
    best_pt = ""
    best_key = list(range(26))

    for restart in range(restarts):
        # Random starting key (permutation)
        key = list(range(26))
        random.shuffle(key)

        # Decrypt with current key
        pt = ''.join(ALPH[key[ALPH_IDX[c]]] for c in text)
        current_score = scorer.score(pt)

        for step in range(steps):
            # Swap two random positions in key
            i, j = random.sample(range(26), 2)
            key[i], key[j] = key[j], key[i]

            pt_new = ''.join(ALPH[key[ALPH_IDX[c]]] for c in text)
            new_score = scorer.score(pt_new)

            if new_score > current_score:
                current_score = new_score
                pt = pt_new
            else:
                key[i], key[j] = key[j], key[i]  # Revert

        if current_score > best_score:
            best_score = current_score
            best_pt = pt
            best_key = key[:]

    return best_pt, best_score, best_key

def columnar_decrypt(ct, width, col_order):
    """Decrypt columnar transposition."""
    nrows = math.ceil(len(ct) / width)
    # Fill columns in the given order
    n = len(ct)
    # Compute column lengths
    full_cols = n % width
    if full_cols == 0:
        full_cols = width

    cols = [[] for _ in range(width)]
    idx = 0
    for c in col_order:
        col_len = nrows if c < full_cols else nrows - 1
        cols[c] = list(ct[idx:idx+col_len])
        idx += col_len

    # Read off by rows
    pt = []
    for r in range(nrows):
        for c in range(width):
            if r < len(cols[c]):
                pt.append(cols[c][r])
    return ''.join(pt)

def rail_fence_decrypt(ct, rails):
    """Decrypt rail fence cipher."""
    if rails < 2:
        return ct
    n = len(ct)
    cycle = 2 * (rails - 1)
    # Compute row lengths
    rows = [[] for _ in range(rails)]
    row_lengths = [0] * rails
    for i in range(n):
        r = i % cycle
        if r >= rails:
            r = cycle - r
        row_lengths[r] += 1

    # Fill rows
    idx = 0
    for r in range(rails):
        rows[r] = list(ct[idx:idx+row_lengths[r]])
        idx += row_lengths[r]

    # Read off
    pt = []
    row_idx = [0] * rails
    for i in range(n):
        r = i % cycle
        if r >= rails:
            r = cycle - r
        pt.append(rows[r][row_idx[r]])
        row_idx[r] += 1
    return ''.join(pt)

def keyword_to_col_order(keyword, width):
    """Convert a keyword to column ordering for columnar transposition."""
    # Pad or truncate keyword to width
    kw = keyword[:width] if len(keyword) >= width else keyword + ALPH[:width - len(keyword)]
    # Sort by letter, keeping original positions for ties
    indexed = [(c, i) for i, c in enumerate(kw)]
    indexed.sort(key=lambda x: (x[0], x[1]))
    order = [0] * width
    for rank, (c, orig_idx) in enumerate(indexed):
        order[rank] = orig_idx
    return order

# ── Build test texts ──────────────────────────────────────────────────────

print("=" * 80)
print("NDYAHR BLIND CRYPTANALYSIS")
print("=" * 80)
print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
print()

K1K2_CT = K1_CT + K2_CT
K123_CT = K1_CT + K2_CT + K3_CT

texts = {}
texts['K3_edited'] = remove_letters(K3_CT, NDYAHR)
texts['K123_edited'] = remove_letters(K123_CT, NDYAHR)
texts['K1K2_edited'] = remove_letters(K1K2_CT, NDYAHR)

# K3 "corrected": K3 is a TRANSPOSITION cipher, not substitution.
# The "corrections" Sanborn acknowledged are:
# 1. Q at end = "?" (question mark, stays)
# 2. The DESPARATLY misspelling is in the PLAINTEXT not the CT
# 3. K3 CT has no known corrections (it's the same letters rearranged)
# So K3_corrected_edited = K3_edited (same CT, just transposition)
# But we can also try editing K3 PLAINTEXT with NDYAHR removed
texts['K3_PT_edited'] = remove_letters(K3_PT, NDYAHR)

print("Test texts constructed:")
for name, text in texts.items():
    print(f"  {name}: {len(text)} chars")
print()

# Also build the K3 CT removing only the NDYAHR positions that correspond
# to the 5 physically raised/displaced letters (E, N, D, Y, A, H, R at boundary)
# Actually, NDYAHR are the 6 letters at the K3/K4 boundary that are physically displaced.
# When we remove ALL N,D,Y,A,H,R from K3 CT we get the 218-char residue.

results_data = {
    'timestamp': datetime.now(timezone.utc).isoformat(),
    'method': 'blind_cryptanalysis_ndyahr_removal',
    'texts': {},
    'findings': [],
}

# ═══════════════════════════════════════════════════════════════════════════
# STEP 1: Statistical profiling
# ═══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("STEP 1: STATISTICAL PROFILING")
print("=" * 80)

for name, text in texts.items():
    print(f"\n--- {name} ({len(text)} chars) ---")

    # IC
    ic_val = ic(text)
    print(f"  IC:          {ic_val:.6f}  (random={1/26:.6f}, English={0.0667:.6f})")

    # Digraph IC
    dic_val = digraph_ic(text)
    print(f"  Digraph IC:  {dic_val:.6f}  (random={1/676:.6f}, English~=0.0069)")

    # Frequency distribution
    freq = Counter(text)
    n = len(text)
    sorted_freq = sorted(freq.items(), key=lambda x: -x[1])
    print(f"  Distinct letters: {len(freq)}")
    print(f"  Top 10 letters: {' '.join(f'{c}:{f}({100*f/n:.1f}%)' for c, f in sorted_freq[:10])}")

    # Chi-squared
    chi_eng = chi_squared(text, ENGLISH_FREQ)
    chi_uni = chi_squared(text, UNIFORM_FREQ)
    # For English-with-NDYAHR-removed, compute expected freq
    eng_no_ndyahr = {}
    total_remaining = sum(v for k, v in ENGLISH_FREQ.items() if k not in NDYAHR)
    for c in ALPH:
        if c not in NDYAHR:
            eng_no_ndyahr[c] = ENGLISH_FREQ[c] / total_remaining
    chi_eng_adj = chi_squared(text, eng_no_ndyahr)
    print(f"  Chi-sq vs English:    {chi_eng:.1f}")
    print(f"  Chi-sq vs Eng-noNDY:  {chi_eng_adj:.1f}")
    print(f"  Chi-sq vs uniform:    {chi_uni:.1f}")

    # Friedman test
    friedman_k = friedman_test(text)
    print(f"  Friedman est period:  {friedman_k:.1f}" if friedman_k < 100 else f"  Friedman est period:  >100")

    # Kasiski examination (for longer texts)
    if len(text) >= 50:
        kasiski = kasiski_examination(text, min_len=3, max_len=4)
        # Find repeated trigrams
        repeated_trigrams = {k: v for k, v in kasiski.items() if len(k) == 3 and len(v['positions']) >= 3}
        if repeated_trigrams:
            print(f"  Repeated trigrams (3+ occurrences): {len(repeated_trigrams)}")
            # Compute GCD of all distances
            all_distances = []
            for info in repeated_trigrams.values():
                all_distances.extend(info['distances'])
            if all_distances:
                g = gcd_list(all_distances)
                print(f"  GCD of all trigram distances: {g}")
                # Show factor frequency
                factor_counts = Counter()
                for d in all_distances:
                    for f in range(2, min(31, d+1)):
                        if d % f == 0:
                            factor_counts[f] += 1
                top_factors = factor_counts.most_common(10)
                print(f"  Top distance factors: {' '.join(f'{f}:{c}' for f, c in top_factors)}")

    # Store results
    results_data['texts'][name] = {
        'length': len(text),
        'ic': ic_val,
        'digraph_ic': dic_val,
        'distinct_letters': len(freq),
        'chi_sq_english': chi_eng,
        'chi_sq_eng_adj': chi_eng_adj,
        'chi_sq_uniform': chi_uni,
        'friedman_period': friedman_k if friedman_k < 100 else None,
    }

# ═══════════════════════════════════════════════════════════════════════════
# STEP 2: Monoalphabetic substitution hill-climbing
# ═══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("STEP 2: MONOALPHABETIC SUBSTITUTION HILL-CLIMBING")
print("=" * 80)

mono_results = {}
for name in ['K3_edited', 'K123_edited', 'K1K2_edited', 'K3_PT_edited']:
    text = texts[name]
    print(f"\n--- {name} ({len(text)} chars) ---")
    t0 = time.time()
    pt, score, key = mono_hill_climb(text, restarts=50, steps=12000)
    elapsed = time.time() - t0
    qg_per_char = score / max(1, len(text) - 3)
    print(f"  Best score: {score:.1f} ({qg_per_char:.4f}/char)  [{elapsed:.1f}s]")
    print(f"  Best PT (first 120): {pt[:120]}")
    print(f"  English threshold: qg/char > -4.5 = strong, > -4.0 = very good")
    if qg_per_char > -4.5:
        print(f"  *** POTENTIAL ENGLISH DETECTED ***")
    mono_results[name] = {
        'score': score,
        'qg_per_char': qg_per_char,
        'plaintext_prefix': pt[:200],
        'elapsed': elapsed,
    }
    results_data.setdefault('mono_hill_climb', {})[name] = mono_results[name]

# ═══════════════════════════════════════════════════════════════════════════
# STEP 3: Vigenere/Beaufort with periods 1-30
# ═══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("STEP 3: VIGENERE / BEAUFORT ALL PERIODS 1-30")
print("=" * 80)

vig_results = {}
for name in ['K3_edited', 'K123_edited', 'K1K2_edited']:
    text = texts[name]
    print(f"\n--- {name} ({len(text)} chars) ---")
    best_vig_score = float('-inf')
    best_vig = None
    best_beau_score = float('-inf')
    best_beau = None

    for period in range(1, min(31, len(text))):
        # Build key by best letter per position
        vig_key = ''
        beau_key = ''
        for p in range(period):
            segment = text[p::period]
            vk, _ = best_key_letter_vig(segment)
            bk, _ = best_key_letter_beau(segment)
            vig_key += vk
            beau_key += bk

        vig_pt = vig_decrypt(text, vig_key)
        beau_pt = beau_decrypt(text, beau_key)

        vig_s = scorer.score_per_char(vig_pt)
        beau_s = scorer.score_per_char(beau_pt)

        if vig_s > best_vig_score:
            best_vig_score = vig_s
            best_vig = (period, vig_key, vig_pt)
        if beau_s > best_beau_score:
            best_beau_score = beau_s
            best_beau = (period, beau_key, beau_pt)

    p, k, pt = best_vig
    print(f"  Best Vigenere: period={p}, key={k}, qg/char={best_vig_score:.4f}")
    print(f"    PT: {pt[:100]}")
    p, k, pt = best_beau
    print(f"  Best Beaufort: period={p}, key={k}, qg/char={best_beau_score:.4f}")
    print(f"    PT: {pt[:100]}")

    if best_vig_score > -4.5 or best_beau_score > -4.5:
        print(f"  *** POTENTIAL ENGLISH DETECTED ***")

    vig_results[name] = {
        'best_vig': {'period': best_vig[0], 'key': best_vig[1], 'qg_per_char': best_vig_score, 'pt_prefix': best_vig[2][:200]},
        'best_beau': {'period': best_beau[0], 'key': best_beau[1], 'qg_per_char': best_beau_score, 'pt_prefix': best_beau[2][:200]},
    }
    results_data.setdefault('vig_beau', {})[name] = vig_results[name]

# ═══════════════════════════════════════════════════════════════════════════
# STEP 4: Transposition analysis
# ═══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("STEP 4: TRANSPOSITION ANALYSIS")
print("=" * 80)

THEMATIC_KEYWORDS = ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'DEFECTOR', 'KOMPASS',
                     'COLOPHON', 'PARALLAX', 'SHADOW', 'MEDUSA', 'SANBORN',
                     'BERLINCLOCK', 'ENIGMA']

trans_results = {}
for name in ['K3_edited', 'K123_edited', 'K1K2_edited', 'K3_PT_edited']:
    text = texts[name]
    print(f"\n--- {name} ({len(text)} chars) ---")
    best_trans_score = float('-inf')
    best_trans = None

    # Columnar transposition with widths 2-25
    for width in range(2, 26):
        if width <= 8:
            # Exhaustive for small widths
            for perm in permutations(range(width)):
                pt = columnar_decrypt(text, width, list(perm))
                s = scorer.score_per_char(pt)
                if s > best_trans_score:
                    best_trans_score = s
                    best_trans = ('columnar', width, list(perm), pt)
        else:
            # Keyword-derived orderings
            for kw in THEMATIC_KEYWORDS:
                if len(kw) >= width:
                    col_order = keyword_to_col_order(kw, width)
                    pt = columnar_decrypt(text, width, col_order)
                    s = scorer.score_per_char(pt)
                    if s > best_trans_score:
                        best_trans_score = s
                        best_trans = ('columnar', width, kw, pt)
                    # Also try reversed
                    col_order_rev = list(reversed(col_order))
                    pt = columnar_decrypt(text, width, col_order_rev)
                    s = scorer.score_per_char(pt)
                    if s > best_trans_score:
                        best_trans_score = s
                        best_trans = ('columnar_rev', width, kw, pt)

    # Rail fence with rails 2-10
    for rails in range(2, 11):
        pt = rail_fence_decrypt(text, rails)
        s = scorer.score_per_char(pt)
        if s > best_trans_score:
            best_trans_score = s
            best_trans = ('rail_fence', rails, None, pt)

    ttype, param, detail, pt = best_trans
    print(f"  Best transposition: {ttype} param={param}, detail={str(detail)[:40]}, qg/char={best_trans_score:.4f}")
    print(f"    PT: {pt[:100]}")

    if best_trans_score > -4.5:
        print(f"  *** POTENTIAL ENGLISH DETECTED ***")

    trans_results[name] = {
        'type': ttype,
        'param': param,
        'detail': str(detail)[:100],
        'qg_per_char': best_trans_score,
        'pt_prefix': pt[:200],
    }
    results_data.setdefault('transposition', {})[name] = trans_results[name]

# ═══════════════════════════════════════════════════════════════════════════
# STEP 5: Combined transposition + substitution
# ═══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("STEP 5: COMBINED TRANSPOSITION + SUBSTITUTION")
print("=" * 80)

combined_results = {}
for name in ['K3_edited', 'K123_edited', 'K1K2_edited']:
    text = texts[name]
    print(f"\n--- {name} ({len(text)} chars) ---")

    # Take best transposition result and apply mono hill-climbing
    ttype, param, detail, trans_pt = trans_results[name]['type'], trans_results[name]['param'], trans_results[name]['detail'], None

    # Re-derive the best transposition plaintext
    if 'columnar' in trans_results[name]['type']:
        # We need to re-compute. Use a few promising widths
        best_combined_score = float('-inf')
        best_combined = None

        for width in [7, 8, 9, 14, 24]:
            if width > len(text):
                continue
            for kw in ['KRYPTOS', 'DEFECTOR', 'PALIMPSEST']:
                col_order = keyword_to_col_order(kw, width)
                trans_pt_tmp = columnar_decrypt(text, width, col_order)
                # Now hill-climb mono sub on this
                pt, score, key = mono_hill_climb(trans_pt_tmp, restarts=15, steps=8000)
                qg = score / max(1, len(pt) - 3)
                if qg > best_combined_score:
                    best_combined_score = qg
                    best_combined = (width, kw, pt)

        if best_combined:
            w, kw, pt = best_combined
            print(f"  Best combined (trans+mono): w={w}, kw={kw}, qg/char={best_combined_score:.4f}")
            print(f"    PT: {pt[:100]}")
        else:
            print(f"  No combined result found")
            best_combined_score = float('-inf')
    else:
        best_combined_score = float('-inf')
        print(f"  Best trans was rail fence; trying mono on it...")
        # Get rail fence result
        rails = trans_results[name]['param']
        trans_pt_tmp = rail_fence_decrypt(text, rails)
        pt, score, key = mono_hill_climb(trans_pt_tmp, restarts=15, steps=8000)
        best_combined_score = score / max(1, len(pt) - 3)
        print(f"  Combined (rail_fence+mono): rails={rails}, qg/char={best_combined_score:.4f}")
        print(f"    PT: {pt[:100]}")

    if best_combined_score > -4.5:
        print(f"  *** POTENTIAL ENGLISH DETECTED ***")

    combined_results[name] = {'qg_per_char': best_combined_score}
    results_data.setdefault('combined', {})[name] = combined_results[name]

# ═══════════════════════════════════════════════════════════════════════════
# STEP 6: Vigenere + transposition (best periods on transposed text)
# ═══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("STEP 6: TRANSPOSITION + VIGENERE COMBO")
print("=" * 80)

for name in ['K3_edited', 'K1K2_edited']:
    text = texts[name]
    print(f"\n--- {name} ({len(text)} chars) ---")
    best_combo_score = float('-inf')
    best_combo = None

    for width in [7, 8, 9, 14, 24]:
        if width > len(text):
            continue
        for kw in ['KRYPTOS', 'DEFECTOR']:
            col_order = keyword_to_col_order(kw, width)
            trans_pt_tmp = columnar_decrypt(text, width, col_order)
            # Try vig with periods 1-15
            for period in range(1, 16):
                vig_key = ''
                for p in range(period):
                    segment = trans_pt_tmp[p::period]
                    vk, _ = best_key_letter_vig(segment)
                    vig_key += vk
                vig_pt = vig_decrypt(trans_pt_tmp, vig_key)
                s = scorer.score_per_char(vig_pt)
                if s > best_combo_score:
                    best_combo_score = s
                    best_combo = (width, kw, period, vig_key, vig_pt)

    if best_combo:
        w, kw, p, vk, pt = best_combo
        print(f"  Best trans+vig: w={w}, kw={kw}, period={p}, vkey={vk}, qg/char={best_combo_score:.4f}")
        print(f"    PT: {pt[:100]}")
    if best_combo_score > -4.5:
        print(f"  *** POTENTIAL ENGLISH DETECTED ***")

# ═══════════════════════════════════════════════════════════════════════════
# STEP 7: Subset analysis (subsets of NDYAHR)
# ═══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("STEP 7: SUBSET ANALYSIS (SUBSETS OF NDYAHR)")
print("=" * 80)

ndyahr_letters = list('NDYAHR')
subset_results = []

# Test all subsets of size 3-6
from itertools import combinations as combs

print(f"\nRemoving subsets from K3_CT ({len(K3_CT)} chars) and K123_CT ({len(K123_CT)} chars):")
print(f"{'Subset':<15} {'From K3':>8} {'IC':>8} {'From K123':>8} {'IC':>8} {'Notable?':>10}")
print("-" * 70)

for size in range(1, 7):
    for subset in combs(ndyahr_letters, size):
        subset_set = set(subset)
        k3_res = remove_letters(K3_CT, subset_set)
        k123_res = remove_letters(K123_CT, subset_set)
        ic_k3 = ic(k3_res)
        ic_k123 = ic(k123_res)

        notable = ""
        if len(k3_res) in [73, 97, 24]:
            notable += f"K3={len(k3_res)}!"
        if len(k123_res) in [73, 97, 730, 803]:
            notable += f"K123={len(k123_res)}!"
        if ic_k3 > 0.060:
            notable += f" IC_K3>{ic_k3:.3f}"
        if ic_k123 > 0.050:
            notable += f" IC_K123>{ic_k123:.3f}"

        if notable or size >= 5:
            print(f"  {','.join(subset):<13} {len(k3_res):>8} {ic_k3:>8.5f} {len(k123_res):>8} {ic_k123:>8.5f} {notable:>10}")

        subset_results.append({
            'subset': list(subset),
            'k3_len': len(k3_res),
            'k3_ic': ic_k3,
            'k123_len': len(k123_res),
            'k123_ic': ic_k123,
            'notable': notable,
        })

# Flag any with IC > 0.06 for K3
print("\n--- Subsets with elevated IC (K3) ---")
elevated = [r for r in subset_results if r['k3_ic'] > 0.06]
for r in sorted(elevated, key=lambda x: -x['k3_ic']):
    print(f"  {','.join(r['subset'])}: K3 len={r['k3_len']}, IC={r['k3_ic']:.5f}")

# Flag any with notable lengths
print("\n--- Subsets with notable lengths ---")
notable_len = [r for r in subset_results if '!' in r.get('notable', '')]
for r in notable_len:
    print(f"  {','.join(r['subset'])}: {r['notable']}")

# For DYAHR (5-letter subset, without N)
print("\n--- Special subset: DYAHR (just the raised letters) ---")
dyahr_k3 = remove_letters(K3_CT, set('DYAHR'))
print(f"  K3 residue: {len(dyahr_k3)} chars, IC={ic(dyahr_k3):.5f}")
dyahr_k123 = remove_letters(K123_CT, set('DYAHR'))
print(f"  K123 residue: {len(dyahr_k123)} chars, IC={ic(dyahr_k123):.5f}")

# For YAR (the 3 traditionally raised letters)
print("\n--- Special subset: YAR ---")
yar_k3 = remove_letters(K3_CT, set('YAR'))
print(f"  K3 residue: {len(yar_k3)} chars, IC={ic(yar_k3):.5f}")
yar_k123 = remove_letters(K123_CT, set('YAR'))
print(f"  K123 residue: {len(yar_k123)} chars, IC={ic(yar_k123):.5f}")

# Do quick mono hill-climb on elevated IC subsets
print("\n--- Quick mono hill-climb on most elevated subsets ---")
for r in sorted(elevated, key=lambda x: -x['k3_ic'])[:5]:
    subset_set = set(r['subset'])
    text = remove_letters(K3_CT, subset_set)
    pt, score, _ = mono_hill_climb(text, restarts=20, steps=8000)
    qg = score / max(1, len(pt) - 3)
    print(f"  Remove {','.join(r['subset'])}: len={len(text)}, IC={r['k3_ic']:.5f}, mono qg/char={qg:.4f}")
    print(f"    PT: {pt[:80]}")
    if qg > -4.5:
        print(f"    *** POTENTIAL ENGLISH ***")

results_data['subset_analysis'] = subset_results

# ═══════════════════════════════════════════════════════════════════════════
# STEP 8: K3 is TRANSPOSITION -- the key insight
# ═══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("STEP 8: K3 IS TRANSPOSITION -- ANALYZING K3 PT WITH NDYAHR REMOVED")
print("=" * 80)

# K3 is solved: it's a double columnar transposition.
# K3_CT and K3_PT have the SAME letters (just rearranged).
# So removing NDYAHR from K3_CT is the same multiset as removing from K3_PT.
# The K3 PT residue might be more interesting because we know the English.

k3_pt_ed = texts['K3_PT_edited']
print(f"K3 PT with NDYAHR removed: {len(k3_pt_ed)} chars")
print(f"Text: {k3_pt_ed[:100]}...")
print(f"IC: {ic(k3_pt_ed):.5f}")
print(f"qg/char (direct): {scorer.score_per_char(k3_pt_ed):.4f}")

# What words survive? (spaces removed but original English survives minus NDYAHR)
# Reconstruct with word boundaries
k3_pt_words = (
    "SLOWLY DESPARATLY SLOWLY THE REMAINS OF PASSAGE DEBRIS "
    "THAT ENCUMBERED THE LOWER PART OF THE DOORWAY WAS REMOVED "
    "WITH TREMBLING HANDS I MADE A TINY BREACH IN THE UPPER "
    "LEFT HAND CORNER AND THEN WIDENING THE HOLE A LITTLE "
    "I INSERTED THE CANDLE AND PEERED IN THE HOT AIR ESCAPING "
    "FROM THE CHAMBER CAUSED THE FLAME TO FLICKER BUT PRESENTLY "
    "DETAILS OF THE ROOM WITHIN EMERGED FROM THE MIST "
    "X CAN YOU SEE ANYTHING Q"
)

# Show what K3 PT looks like with NDYAHR removed (preserving word boundaries)
edited_words = []
for word in k3_pt_words.split():
    edited = remove_letters(word.upper(), NDYAHR)
    if edited:
        edited_words.append(edited)
print(f"\nK3 PT words with NDYAHR removed:")
print(' '.join(edited_words))

# ═══════════════════════════════════════════════════════════════════════════
# STEP 9: Quick test of K1 and K2 separately
# ═══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("STEP 9: K1 AND K2 INDIVIDUALLY")
print("=" * 80)

# K1 is Vigenere with key PALIMPSEST
# K2 is Vigenere with key ABSCISSA
# Removing NDYAHR from K1/K2 CT changes the Vigenere alignment

k1_ed = remove_letters(K1_CT, NDYAHR)
k2_ed = remove_letters(K2_CT, NDYAHR)
print(f"K1 edited: {len(k1_ed)} chars (from {len(K1_CT)}), IC={ic(k1_ed):.5f}")
print(f"K2 edited: {len(k2_ed)} chars (from {len(K2_CT)}), IC={ic(k2_ed):.5f}")

# Try Vigenere with known K1/K2 keys on the edited texts
k1_vig_palimpsest = vig_decrypt(k1_ed, 'PALIMPSEST')
print(f"\nK1 edited Vig(PALIMPSEST): qg/char={scorer.score_per_char(k1_vig_palimpsest):.4f}")
print(f"  PT: {k1_vig_palimpsest[:80]}")

k2_vig_abscissa = vig_decrypt(k2_ed, 'ABSCISSA')
print(f"\nK2 edited Vig(ABSCISSA): qg/char={scorer.score_per_char(k2_vig_abscissa):.4f}")
print(f"  PT: {k2_vig_abscissa[:80]}")

# The key alignment is disrupted. Try all periods for edited K1/K2
print("\n--- K1 edited: best Vig period search ---")
best_k1_vig = float('-inf')
best_k1_vig_info = None
for period in range(1, 20):
    key = ''
    for p in range(period):
        segment = k1_ed[p::period]
        vk, _ = best_key_letter_vig(segment)
        key += vk
    pt = vig_decrypt(k1_ed, key)
    s = scorer.score_per_char(pt)
    if s > best_k1_vig:
        best_k1_vig = s
        best_k1_vig_info = (period, key, pt)
if best_k1_vig_info:
    p, k, pt = best_k1_vig_info
    print(f"  Best: period={p}, key={k}, qg/char={best_k1_vig:.4f}")
    print(f"  PT: {pt[:80]}")

print("\n--- K2 edited: best Vig period search ---")
best_k2_vig = float('-inf')
best_k2_vig_info = None
for period in range(1, 20):
    key = ''
    for p in range(period):
        segment = k2_ed[p::period]
        vk, _ = best_key_letter_vig(segment)
        key += vk
    pt = vig_decrypt(k2_ed, key)
    s = scorer.score_per_char(pt)
    if s > best_k2_vig:
        best_k2_vig = s
        best_k2_vig_info = (period, key, pt)
if best_k2_vig_info:
    p, k, pt = best_k2_vig_info
    print(f"  Best: period={p}, key={k}, qg/char={best_k2_vig:.4f}")
    print(f"  PT: {pt[:80]}")

# ═══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("SUMMARY")
print("=" * 80)

print("\nStatistical profile:")
for name, text in texts.items():
    ic_val = ic(text)
    marker = " <<< ELEVATED" if ic_val > 0.06 else ""
    print(f"  {name}: len={len(text)}, IC={ic_val:.5f}{marker}")

print("\nMono hill-climb qg/char:")
for name, r in mono_results.items():
    marker = " <<< ENGLISH" if r['qg_per_char'] > -4.5 else ""
    print(f"  {name}: {r['qg_per_char']:.4f}{marker}")

print("\nBest Vigenere/Beaufort qg/char:")
for name, r in vig_results.items():
    marker = ""
    if r['best_vig']['qg_per_char'] > -4.5 or r['best_beau']['qg_per_char'] > -4.5:
        marker = " <<< ENGLISH"
    print(f"  {name}: vig={r['best_vig']['qg_per_char']:.4f} (p={r['best_vig']['period']}), beau={r['best_beau']['qg_per_char']:.4f} (p={r['best_beau']['period']}){marker}")

print("\nBest transposition qg/char:")
for name, r in trans_results.items():
    marker = " <<< ENGLISH" if r['qg_per_char'] > -4.5 else ""
    print(f"  {name}: {r['qg_per_char']:.4f} ({r['type']} {r['param']}){marker}")

print("\n\nENGLISH DETECTION THRESHOLD: qg/char > -4.5 = strong, > -4.0 = very good")
print("Random text typically scores -6.5 to -7.0")
print("DONE.")

# ── Save results ──────────────────────────────────────────────────────────

results_path = os.path.join(os.path.dirname(__file__), '..', '..', 'results', 'ndyahr_blind_cryptanalysis.json')
os.makedirs(os.path.dirname(results_path), exist_ok=True)
with open(results_path, 'w') as f:
    json.dump(results_data, f, indent=2, default=str)
print(f"\nResults saved to {results_path}")
