#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-S-30: Three-Layer Mask Hypothesis

Scheidt: "I masked the English language so it's more of a challenge now."
Hypothesis: K4 uses K3's method (columnar transposition + Vigenère) PLUS
an additive mask as the outermost layer.

Model: CT[i] = Mask[i] + Columnar(Vig(PT, periodic_key))[i]

Decryption:
1. Unmask: M[i] = (CT[i] - Mask[i]) % 26
2. Untranspose: I[j] = M[σ(j)]
3. Un-Vig: PT[j] = (I[j] - key[j%p]) % 26

Test: for each mask × columnar ordering × period, check crib consistency.

Masks: K1-K3 CT/PT, K1-K3 keywords repeated, KA alphabet sequence, coordinates.
Transpositions: All 5040 width-7 columnar orderings (motivated by lag-7 + K3 method).
Periods: 5-13 (interesting range).

Also test the Beaufort variant (add mask instead of subtract) and reversed masks.
"""

import json
import sys
import os
import time
from itertools import permutations
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD

CT_NUM = [ALPH_IDX[c] for c in CT]
N = CT_LEN
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

# ── Masks ──────────────────────────────────────────────────────────────

K1_CT = 'EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD'
K2_CT = 'VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKSQATQPMFGXIFLAIFQDMHRGWTKRQLXTFSLYEVQALNMFEWFGLFEAMKKSNLCPYSEPQWICETQFHQSVZJLNTIHLLKSQVNIWECQLQOQENMWVLNPEKLSRMSLKLDNQSRMPKHEQIEJFM'
K3_CT = 'ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNETPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOETFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLBTEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEBAECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHEECDMRIPFEIMEHNLSSTTRTVDOHW'
K1_PT = 'BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION'
K2_PT = 'ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHISXTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONXONLYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTXLAYERTWO'
K3_PT = 'SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBABORSWEREDISCOVEREDALEADTOTHEDOORWAYWASONLYEXTENDEDLABORUNDERGOROUDLEADTOLAROKINGTUTSEPULCHURALSROOM'


def pad_to_n(text, n=N):
    """Pad text to length n by repeating."""
    text = text.upper()
    while len(text) < n:
        text += text
    return text[:n]


def text_to_nums(text):
    return [ord(c) - ord('A') for c in text.upper() if c.isalpha()]


# Build mask set
masks = {}
for name, text in [
    ('K1_CT', K1_CT), ('K2_CT', K2_CT), ('K3_CT', K3_CT),
    ('K1_PT', K1_PT), ('K2_PT', K2_PT), ('K3_PT', K3_PT),
    ('K1_CT_rev', K1_CT[::-1]), ('K3_CT_rev', K3_CT[::-1]),
    ('KRYPTOS', 'KRYPTOS'), ('PALIMPSEST', 'PALIMPSEST'),
    ('ABSCISSA', 'ABSCISSA'), ('KRYPTOSABCDEFGHIJLMNQUVWXZ', 'KRYPTOSABCDEFGHIJLMNQUVWXZ'),
]:
    nums = text_to_nums(pad_to_n(text))
    if len(nums) >= N:
        masks[name] = nums[:N]

# Also: concatenated K1+K2+K3 CT (full sculpture sequence before K4)
full_pre_k4 = K1_CT + K2_CT + K3_CT
masks['K123_CT'] = text_to_nums(full_pre_k4)[:N]
# And offset into K3_CT (K4 starts after K3 on the sculpture)
k3_len = len(K3_CT)
masks['K3_CT_tail'] = text_to_nums(K3_CT[k3_len - N:]) if k3_len >= N else text_to_nums(pad_to_n(K3_CT))

# Coordinate-derived masks
# Kryptos: 38°57'6.5"N 77°8'44"W
coord_nums = [3,8,5,7,6,5,7,7,8,4,4]  # digits as letter positions
masks['COORD_digits'] = (coord_nums * ((N // len(coord_nums)) + 1))[:N]

# Year-based: 1986, 1989
years = [1,9,8,6,1,9,8,9]
masks['YEARS'] = (years * ((N // len(years)) + 1))[:N]

print(f"Total masks: {len(masks)}")
for name, nums in masks.items():
    print(f"  {name}: len={len(nums)}, first 10 = {nums[:10]}")


# ── Columnar transposition ─────────────────────────────────────────────

def columnar_decrypt(ct_nums, col_order, width):
    """Undo columnar transposition (read columns in col_order → row-by-row PT)."""
    n = len(ct_nums)
    n_rows = (n + width - 1) // width
    n_long = n % width  # columns with n_rows elements
    if n_long == 0:
        n_long = width

    # Split CT into columns (first n_long columns have n_rows, rest have n_rows-1)
    cols = [[] for _ in range(width)]
    pos = 0
    for ci in col_order:
        col_len = n_rows if ci < n_long else n_rows - 1
        cols[ci] = ct_nums[pos:pos + col_len]
        pos += col_len

    # Read row by row
    result = []
    for row in range(n_rows):
        for col in range(width):
            if row < len(cols[col]):
                result.append(cols[col][row])

    return result


# ── Crib consistency check ─────────────────────────────────────────────

def check_crib_consistency(intermediate_nums, periods):
    """Check if intermediate text at crib positions has consistent periodic key."""
    best_result = None
    best_score = 0

    for period in periods:
        residue_keys = defaultdict(set)
        for pos in CRIB_POS:
            if pos < len(intermediate_nums):
                k = (intermediate_nums[pos] - CRIB_PT[pos]) % MOD
                residue_keys[pos % period].add(k)

        n_consistent = sum(1 for r, ks in residue_keys.items() if len(ks) == 1)
        n_total = len(residue_keys)

        if n_consistent > best_score:
            best_score = n_consistent
            key_vals = {}
            for r, ks in residue_keys.items():
                if len(ks) == 1:
                    key_vals[r] = list(ks)[0]
            best_result = {
                'period': period,
                'score': n_consistent,
                'total': n_total,
                'key_residues': key_vals,
            }

    return best_score, best_result


# ── Main search ────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("E-S-30: Three-Layer Mask Hypothesis")
    print("=" * 60)
    print(f"Model: CT[i] = Mask[i] + Columnar(Vig(PT, periodic_key))[i]")
    print(f"Masks: {len(masks)}, Width: 7, Orderings: 5040")
    print()

    WIDTH = 7
    PERIODS = list(range(3, 14))
    SIGNAL_THRESHOLD = 18
    STORE_THRESHOLD = 14  # Interesting at period 7 (expected ~8.2)

    all_results = []
    t0 = time.time()
    n_configs = 0
    n_hits = 0

    # Generate all width-7 permutations
    orderings = list(permutations(range(WIDTH)))
    total = len(masks) * len(orderings) * 2  # × 2 for sub/add
    print(f"Total configs: {total:,}")

    for mask_name, mask_nums in masks.items():
        mask_hits = 0
        for direction, dir_name in [(-1, 'sub'), (1, 'add')]:
            # Unmask CT
            unmasked = [(CT_NUM[i] + direction * mask_nums[i]) % MOD for i in range(N)]

            for order in orderings:
                # Undo columnar transposition
                intermediate = columnar_decrypt(unmasked, list(order), WIDTH)

                # Check crib consistency
                score, result = check_crib_consistency(intermediate, PERIODS)
                n_configs += 1

                if score >= STORE_THRESHOLD:
                    result['mask'] = mask_name
                    result['direction'] = dir_name
                    result['col_order'] = list(order)
                    all_results.append(result)
                    mask_hits += 1
                    n_hits += 1

                    if score >= SIGNAL_THRESHOLD:
                        key_str = ''.join(chr(v + ord('A')) for v in result['key_residues'].values())
                        print(f"  *** SIGNAL: {mask_name} {dir_name}"
                              f" order={list(order)} p={result['period']}"
                              f" score={score}/{result['total']}"
                              f" key={key_str}")

        if mask_hits > 0 and n_configs % 10000 == 0:
            print(f"  {mask_name}: {mask_hits} hits ≥{STORE_THRESHOLD}")

        # Progress
        elapsed = time.time() - t0
        pct = n_configs / total * 100
        if n_configs % 50000 < len(orderings) * 2:
            print(f"  Progress: {n_configs:,}/{total:,} ({pct:.0f}%)"
                  f"  hits≥{STORE_THRESHOLD}: {n_hits}"
                  f"  elapsed: {elapsed:.0f}s", flush=True)

    elapsed = time.time() - t0

    # Summary
    print(f"\n{'=' * 60}")
    print(f"SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Configs tested: {n_configs:,}")
    print(f"  Time: {elapsed:.1f}s ({elapsed/60:.1f} min)")
    print(f"  Hits ≥ {STORE_THRESHOLD}: {n_hits}")

    if all_results:
        # Sort by score desc
        all_results.sort(key=lambda r: -r['score'])
        print(f"\n  Top 10 results:")
        for i, r in enumerate(all_results[:10]):
            print(f"    {i+1}. {r['mask']} {r['direction']}"
                  f" order={r['col_order']} p={r['period']}"
                  f" score={r['score']}/{r['total']}")

        # Check if any at period ≤ 7 are significant
        p7_results = [r for r in all_results if r['period'] <= 7]
        if p7_results:
            print(f"\n  Period ≤ 7 results ({len(p7_results)}):")
            for r in p7_results[:10]:
                print(f"    {r['mask']} {r['direction']}"
                      f" order={r['col_order']} p={r['period']}"
                      f" score={r['score']}/{r['total']}")
        else:
            print(f"\n  No results at period ≤ 7 above threshold {STORE_THRESHOLD}")
    else:
        print(f"\n  No results above threshold {STORE_THRESHOLD}")
        print(f"  (Expected random at p=7: ~8.2/24)")

    # Verdict
    max_score = max((r['score'] for r in all_results), default=0)
    verdict = "NOISE" if max_score < SIGNAL_THRESHOLD else "SIGNAL"
    print(f"\n  Verdict: {verdict}")

    # Also test without transposition (identity) for completeness
    print(f"\n  Identity transposition check:")
    for mask_name, mask_nums in masks.items():
        for direction, dir_name in [(-1, 'sub'), (1, 'add')]:
            unmasked = [(CT_NUM[i] + direction * mask_nums[i]) % MOD for i in range(N)]
            score, result = check_crib_consistency(unmasked, PERIODS)
            if score >= 10:
                print(f"    {mask_name} {dir_name}: {score}/{result['total']} at p={result['period']}")

    # Save
    os.makedirs("results", exist_ok=True)
    artifact = {
        "experiment": "E-S-30",
        "description": "Three-layer mask hypothesis: CT = Mask + Columnar(Vig(PT, key))",
        "n_masks": len(masks),
        "n_orderings": len(orderings),
        "width": WIDTH,
        "periods_tested": PERIODS,
        "total_configs": n_configs,
        "hits_above_threshold": n_hits,
        "store_threshold": STORE_THRESHOLD,
        "signal_threshold": SIGNAL_THRESHOLD,
        "max_score": max_score,
        "verdict": verdict,
        "top_results": all_results[:20],
        "elapsed_seconds": elapsed,
    }
    with open("results/e_s_30_three_layer_mask.json", "w") as f:
        json.dump(artifact, f, indent=2)

    print(f"\n  Artifact: results/e_s_30_three_layer_mask.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_30_three_layer_mask.py")


if __name__ == "__main__":
    main()
