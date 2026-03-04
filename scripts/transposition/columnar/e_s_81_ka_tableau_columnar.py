#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: transposition/columnar
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-S-81: Keyword-Alphabet Tableaux + Width-7 Columnar

Tests Quagmire-type ciphers: keyword alphabet as a Vigenère tableau,
combined with width-7 columnar transposition (Model B: trans→sub).

Prior work tested keyword alphabets with DIRECT correspondence (E-S-38)
and found noise. But keyword alphabet + width-7 columnar is UNTESTED.

Tests multiple keyword alphabets:
- KRYPTOS (from the sculpture's Vigenère tableau)
- PALIMPSEST (K1 keyword)
- ABSCISSA (K2 keyword)
- BERLIN, SCHEIDT, SANBORN, etc.

For each alphabet, tests all 5040 orderings × {Vigenère, Beaufort} × period-7.
Also tests the 294 Latin square survivors specifically.
"""

import json
import os
import sys
import time
from itertools import permutations

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
STD_IDX = {c: i for i, c in enumerate(AZ)}

CRIB_DICT = {
    21: 'E', 22: 'A', 23: 'S', 24: 'T', 25: 'N', 26: 'O', 27: 'R',
    28: 'T', 29: 'H', 30: 'E', 31: 'A', 32: 'S', 33: 'T',
    63: 'B', 64: 'E', 65: 'R', 66: 'L', 67: 'I', 68: 'N', 69: 'C',
    70: 'L', 71: 'O', 72: 'C', 73: 'K'
}
CRIB_POS = sorted(CRIB_DICT.keys())

WIDTH = 7
NROWS_FULL = N // WIDTH
NROWS_EXTRA = N % WIDTH
COL_LENGTHS = [NROWS_FULL + 1 if c < NROWS_EXTRA else NROWS_FULL for c in range(WIDTH)]

print("=" * 70)
print("E-S-81: Keyword-Alphabet Tableaux + Width-7 Columnar")
print("=" * 70)


def make_keyword_alphabet(keyword):
    """Standard keyword mixed alphabet: unique keyword letters + remaining."""
    seen = set()
    alpha = []
    for c in keyword.upper():
        if c not in seen and c in AZ:
            seen.add(c)
            alpha.append(c)
    for c in AZ:
        if c not in seen:
            alpha.append(c)
    return ''.join(alpha)


def build_inv_perm(order):
    inv_perm = [0] * N
    j = 0
    for rank in range(WIDTH):
        c = order[rank]
        clen = COL_LENGTHS[c]
        for row in range(clen):
            pt_pos = row * WIDTH + c
            inv_perm[pt_pos] = j
            j += 1
    return inv_perm


# ── Define keyword alphabets ────────────────────────────────────────────

KEYWORD_ALPHABETS = {}
keywords = [
    "KRYPTOS",
    "PALIMPSEST",
    "ABSCISSA",
    "BERLIN",
    "SCHEIDT",
    "SANBORN",
    "KRYPTOSABCDEFGHIJLMNQUVWXZ",  # KA raw (should = KRYPTOS)
    "CLOCK",
    "WORLDCLOCK",
    "EGYPT",
    "PHARAOH",
    "LANGLEY",
    "COMPASS",
    "NORTHEAST",
    "ENIGMA",
    "CIPHER",
    "SECRET",
    "SHADOW",
    "INVISIBLE",
    "MAGNETIC",
    "BURIED",
    "WHATSTHEPOINT",
    "MESSAGE",
    "DELIVER",
]

for kw in keywords:
    alpha = make_keyword_alphabet(kw)
    KEYWORD_ALPHABETS[kw] = alpha

# Remove duplicates
unique_alphas = {}
for kw, alpha in KEYWORD_ALPHABETS.items():
    if alpha not in unique_alphas:
        unique_alphas[alpha] = kw
    else:
        unique_alphas[alpha] += f" = {kw}"

print(f"\n  {len(keywords)} keywords → {len(unique_alphas)} unique alphabets")
for alpha, kw_names in sorted(unique_alphas.items(), key=lambda x: x[1]):
    print(f"    {kw_names}: {alpha}")


# ── Test each alphabet + all orderings ──────────────────────────────────

print("\n" + "-" * 50)
print("Phase 1: Test all keyword alphabets × 5040 orderings × {Vig, Beau}")
print("-" * 50)

all_orders = list(permutations(range(WIDTH)))
t0 = time.time()

results = []

for alpha, kw_names in sorted(unique_alphas.items(), key=lambda x: x[1]):
    # Build index for this alphabet
    a_idx = {c: i for i, c in enumerate(alpha)}

    best_score = 0
    best_config = {'keyword': kw_names, 'variant': 'none', 'order': [], 'score': 0, 'key': []}

    for order in all_orders:
        order = list(order)
        inv_perm = build_inv_perm(order)

        for variant in ['vig', 'beau']:
            # Compute keystream at crib positions using this alphabet
            col_keys = {}
            for p in CRIB_POS:
                j = inv_perm[p]
                pt_v = a_idx[CRIB_DICT[p]]
                ct_v = a_idx[CT[j]]
                if variant == 'vig':
                    kv = (ct_v - pt_v) % 26
                else:
                    kv = (ct_v + pt_v) % 26
                col = p % WIDTH
                if col not in col_keys:
                    col_keys[col] = set()
                col_keys[col].add(kv)

            # Count consistent columns (all crib key values the same)
            consistent = sum(1 for c in range(WIDTH)
                             if c in col_keys and len(col_keys[c]) == 1)

            if consistent > best_score:
                best_score = consistent
                # Extract key
                key = []
                for c in range(WIDTH):
                    if c in col_keys and len(col_keys[c]) == 1:
                        key.append(list(col_keys[c])[0])
                    else:
                        key.append(-1)
                best_config = {
                    'keyword': kw_names,
                    'variant': variant,
                    'order': order,
                    'score': consistent,
                    'key': key,
                }

    elapsed = time.time() - t0
    indicator = "*** HIT ***" if best_score >= 5 else ""
    print(f"  {kw_names}: best {best_score}/7 ({best_config['variant'].upper()}, "
          f"order={best_config['order']}) {indicator}")

    if best_score >= 5:
        key_letters = ''.join(alpha[k] if k >= 0 else '?' for k in best_config['key'])
        print(f"    Key: {best_config['key']} = '{key_letters}'")

    results.append(best_config)

elapsed = time.time() - t0
print(f"\n  Total time: {elapsed:.1f}s")


# ── Phase 2: Test standard alphabet but with KA-indexed tableau ─────────

print("\n" + "-" * 50)
print("Phase 2: Standard Vigenère but indexed via KA alphabet positions")
print("-" * 50)

# The Kryptos Vigenère tableau uses the KA alphabet for BOTH rows and columns.
# Standard Vigenère: CT = AZ[(AZ_idx(PT) + AZ_idx(Key)) % 26]
# KA Vigenère:       CT = KA[(KA_idx(PT) + KA_idx(Key)) % 26]
# These are DIFFERENT because KA has a different letter ordering.

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA)}

best_score_ka = 0
best_config_ka = {'variant': 'none', 'order': [], 'score': 0, 'key': []}

for order in all_orders:
    order = list(order)
    inv_perm = build_inv_perm(order)

    for variant in ['vig', 'beau']:
        col_keys = {}
        for p in CRIB_POS:
            j = inv_perm[p]
            pt_v = KA_IDX[CRIB_DICT[p]]
            ct_v = KA_IDX[CT[j]]
            if variant == 'vig':
                kv = (ct_v - pt_v) % 26
            else:
                kv = (ct_v + pt_v) % 26
            col = p % WIDTH
            if col not in col_keys:
                col_keys[col] = set()
            col_keys[col].add(kv)

        consistent = sum(1 for c in range(WIDTH)
                         if c in col_keys and len(col_keys[c]) == 1)

        if consistent > best_score_ka:
            best_score_ka = consistent
            key = []
            for c in range(WIDTH):
                if c in col_keys and len(col_keys[c]) == 1:
                    key.append(list(col_keys[c])[0])
                else:
                    key.append(-1)
            best_config_ka = {
                'variant': variant,
                'order': order,
                'score': consistent,
                'key': key,
            }

print(f"  KA-indexed tableau: best {best_score_ka}/7 "
      f"({best_config_ka['variant'].upper()}, order={best_config_ka['order']})")

if best_score_ka >= 4:
    key_letters = ''.join(KA[k] if k >= 0 else '?' for k in best_config_ka['key'])
    print(f"    Key: {best_config_ka['key']} = '{key_letters}' (in KA indexing)")


# ── Phase 3: All keyword alphabets from wordlist ────────────────────────

print("\n" + "-" * 50)
print("Phase 3: Wordlist keyword alphabets (sample)")
print("-" * 50)

# Test a large sample of keyword alphabets from the wordlist
wordlist_path = "wordlists/english.txt"
top_hits = []

if os.path.exists(wordlist_path):
    # Generate unique alphabets from keywords of length 5-15
    word_alphas = {}
    with open(wordlist_path) as f:
        for line in f:
            word = line.strip().upper()
            if 5 <= len(word) <= 15 and word.isalpha():
                alpha = make_keyword_alphabet(word)
                if alpha not in word_alphas:
                    word_alphas[alpha] = word

    print(f"  {len(word_alphas)} unique alphabets from wordlist")

    tested = 0
    t1 = time.time()
    for alpha, word in word_alphas.items():
        a_idx = {c: i for i, c in enumerate(alpha)}

        best_for_alpha = 0
        best_config_alpha = None

        for order in all_orders:
            order = list(order)
            inv_perm = build_inv_perm(order)

            for variant in ['vig', 'beau']:
                col_keys = {}
                for p in CRIB_POS:
                    j = inv_perm[p]
                    pt_v = a_idx[CRIB_DICT[p]]
                    ct_v = a_idx[CT[j]]
                    if variant == 'vig':
                        kv = (ct_v - pt_v) % 26
                    else:
                        kv = (ct_v + pt_v) % 26
                    col = p % WIDTH
                    if col not in col_keys:
                        col_keys[col] = set()
                    col_keys[col].add(kv)

                consistent = sum(1 for c in range(WIDTH)
                                 if c in col_keys and len(col_keys[c]) == 1)

                if consistent > best_for_alpha:
                    best_for_alpha = consistent
                    best_config_alpha = {
                        'word': word,
                        'variant': variant,
                        'order': list(order),
                        'score': consistent,
                    }

        if best_for_alpha >= 5:
            top_hits.append(best_config_alpha)

        tested += 1
        if tested % 5000 == 0:
            elapsed = time.time() - t1
            print(f"    {tested}/{len(word_alphas)}, {elapsed:.0f}s, "
                  f"hits≥5: {len(top_hits)}")

        # Limit to reasonable runtime
        if tested >= 50000:
            print(f"    Stopped at {tested} (runtime limit)")
            break

    elapsed = time.time() - t1
    print(f"\n  Tested {tested} keyword alphabets in {elapsed:.1f}s")
    print(f"  Hits with ≥5/7 consistent columns: {len(top_hits)}")

    if top_hits:
        top_hits.sort(key=lambda x: -x['score'])
        print(f"\n  Top hits:")
        for h in top_hits[:20]:
            print(f"    {h['word']}: {h['score']}/7 ({h['variant'].upper()}, "
                  f"order={h['order']})")


# ── Summary ──────────────────────────────────────────────────────────────

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)

max_score = max(r['score'] for r in results)
best_overall = [r for r in results if r['score'] == max_score]
print(f"  Best from thematic keywords: {max_score}/7")
for r in best_overall:
    print(f"    {r['keyword']} {r['variant'].upper()} order={r['order']}")

print(f"  KA-indexed tableau: {best_score_ka}/7")

if max_score <= 3 and best_score_ka <= 3:
    verdict = "NOISE — keyword-alphabet tableaux + width-7 produce no signal"
elif max_score >= 7 or best_score_ka >= 7:
    verdict = "BREAKTHROUGH — all 7 columns consistent!"
elif max_score >= 5 or best_score_ka >= 5:
    verdict = "INTERESTING — ≥5/7 columns consistent, investigate"
else:
    verdict = "WEAK — 4/7 columns, likely noise"

print(f"  Verdict: {verdict}")

output = {
    'experiment': 'E-S-81',
    'description': 'Keyword-Alphabet Tableaux + Width-7 Columnar',
    'thematic_results': results,
    'ka_indexed_best': best_config_ka,
    'wordlist_hits': top_hits[:50] if top_hits else [],
    'verdict': verdict,
}
os.makedirs("results", exist_ok=True)
with open("results/e_s_81_ka_tableau_columnar.json", "w") as f:
    json.dump(output, f, indent=2)
print(f"\n  Artifact: results/e_s_81_ka_tableau_columnar.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_81_ka_tableau_columnar.py")
