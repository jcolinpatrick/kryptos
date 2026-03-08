#!/usr/bin/env python3
"""Autokey on permuted CT using campaign's elite permutations.

Cipher: autokey + transposition
Family: grille
Status: active
Keyspace: ~15K configs (elite perms x autokey modes x keywords x alphabets)
Last run: never
Best score: n/a

Motivation: Campaign round 124 Opus insight identified autokey as the critical
untested hypothesis. Periodic DEFENSOR Beaufort produces English morphemes but
not sentences — suggesting "right key, wrong cipher mode."

Autokey on IDENTITY CT is already eliminated (KPA definitive, e_autokey_k4.py).
But autokey on PERMUTED CT has never been tested. This script takes the
campaign's top elite permutations and tests all autokey modes.
"""
from __future__ import annotations

import sys
import os
import json
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_DICT, NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.scoring.aggregate import score_candidate_free
from kryptos.kernel.scoring.ngram import NgramScorer
from kryptos.kernel.scoring.free_crib import score_free_fast

# ── Alphabet setup ────────────────────────────────────────────────────────

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

ALPHABETS = {
    'AZ': (ALPH, ALPH_IDX),
    'KA': (KA, KA_IDX),
}

KEYWORDS = [
    'DEFENSOR', 'DEFECTOR', 'HOROLOGE', 'PARALLAX', 'COLOPHON',
    'KRYPTOS', 'PALIMPSEST', 'ABSCISSA',
]


def to_nums(text, idx_map):
    return [idx_map[c] for c in text]


def to_text(nums, alpha_str):
    return ''.join(alpha_str[n % MOD] for n in nums)


# ── Autokey decrypt functions ─────────────────────────────────────────────

def decrypt_pt_autokey_vig(ct_nums, primer_nums):
    L = len(primer_nums)
    n = len(ct_nums)
    pt = [0] * n
    for i in range(n):
        k = primer_nums[i] if i < L else pt[i - L]
        pt[i] = (ct_nums[i] - k) % MOD
    return pt


def decrypt_ct_autokey_vig(ct_nums, primer_nums):
    L = len(primer_nums)
    n = len(ct_nums)
    pt = [0] * n
    for i in range(n):
        k = primer_nums[i] if i < L else ct_nums[i - L]
        pt[i] = (ct_nums[i] - k) % MOD
    return pt


def decrypt_pt_autokey_beau(ct_nums, primer_nums):
    L = len(primer_nums)
    n = len(ct_nums)
    pt = [0] * n
    for i in range(n):
        k = primer_nums[i] if i < L else pt[i - L]
        pt[i] = (k - ct_nums[i]) % MOD
    return pt


def decrypt_ct_autokey_beau(ct_nums, primer_nums):
    L = len(primer_nums)
    n = len(ct_nums)
    pt = [0] * n
    for i in range(n):
        k = primer_nums[i] if i < L else ct_nums[i - L]
        pt[i] = (k - ct_nums[i]) % MOD
    return pt


def decrypt_pt_autokey_varbeau(ct_nums, primer_nums):
    L = len(primer_nums)
    n = len(ct_nums)
    pt = [0] * n
    for i in range(n):
        k = primer_nums[i] if i < L else pt[i - L]
        pt[i] = (ct_nums[i] + k) % MOD
    return pt


def decrypt_ct_autokey_varbeau(ct_nums, primer_nums):
    L = len(primer_nums)
    n = len(ct_nums)
    pt = [0] * n
    for i in range(n):
        k = primer_nums[i] if i < L else ct_nums[i - L]
        pt[i] = (ct_nums[i] + k) % MOD
    return pt


AUTOKEY_MODES = {
    'pt_vig': decrypt_pt_autokey_vig,
    'ct_vig': decrypt_ct_autokey_vig,
    'pt_beau': decrypt_pt_autokey_beau,
    'ct_beau': decrypt_ct_autokey_beau,
    'pt_varbeau': decrypt_pt_autokey_varbeau,
    'ct_varbeau': decrypt_ct_autokey_varbeau,
}


def apply_perm(text, perm):
    """Apply permutation: output[i] = text[perm[i]]"""
    return ''.join(text[perm[i]] for i in range(len(perm)))


def main():
    t0 = time.time()

    # Load campaign state for elite permutations
    state_path = os.path.join(os.path.dirname(__file__), '..', '..', 'results', 'campaign', 'state.json')
    if not os.path.exists(state_path):
        print("ERROR: Campaign state not found at", state_path)
        return

    with open(state_path) as f:
        state = json.load(f)

    elite = state.get('elite', [])
    print(f"Loaded {len(elite)} elite permutations from campaign")
    print(f"Campaign best: score={state.get('best_ever_score')}, "
          f"hits={state.get('best_ever_crib_hits')}, "
          f"method={state.get('best_ever_method')}")

    # Also include identity permutation for baseline
    identity_perm = list(range(CT_LEN))

    # Collect all permutations to test
    perms_to_test = [('identity', identity_perm)]
    for i, e in enumerate(elite[:50]):  # Top 50 elite
        perm = e.get('perm', e.get('permutation', None))
        if perm and len(perm) == CT_LEN:
            label = e.get('method', f'elite_{i}')
            perms_to_test.append((f'elite{i}_{label}', perm))

    print(f"Testing {len(perms_to_test)} permutations x {len(AUTOKEY_MODES)} modes "
          f"x {len(KEYWORDS)} keywords x {len(ALPHABETS)} alphabets")
    total = len(perms_to_test) * len(AUTOKEY_MODES) * len(KEYWORDS) * len(ALPHABETS)
    print(f"Total configs: {total}")
    print()

    # Load ngram scorer
    ngram_path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'english_quadgrams.json')
    ngram = NgramScorer.from_file(ngram_path) if os.path.exists(ngram_path) else None
    if ngram:
        print(f"Loaded quadgram scorer")
    else:
        print(f"WARNING: No quadgram data at {ngram_path}")

    results = []
    tested = 0
    best_ngram = -999.0
    best_crib = 0
    best_result = None

    THRESHOLD_NGRAM = -380.0  # Campaign elite threshold
    THRESHOLD_CRIB = 6        # Noise floor

    for perm_idx, (perm_label, perm) in enumerate(perms_to_test):
        # Apply permutation to CT
        permuted_ct = apply_perm(CT, perm)
        pct_az = to_nums(permuted_ct, ALPH_IDX)
        pct_ka = to_nums(permuted_ct, KA_IDX)

        for alpha_name, (alpha_str, alpha_idx) in ALPHABETS.items():
            pct_nums = pct_az if alpha_name == 'AZ' else pct_ka

            for kw in KEYWORDS:
                primer_nums = to_nums(kw, alpha_idx)

                for mode_name, decrypt_fn in AUTOKEY_MODES.items():
                    pt_nums = decrypt_fn(pct_nums, primer_nums)
                    pt_text = to_text(pt_nums, alpha_str)

                    # Fast crib check first
                    crib_hits = score_free_fast(pt_text)

                    # Ngram score
                    ng_score = ngram.score(pt_text) if ngram else 0.0

                    tested += 1

                    is_interesting = crib_hits > THRESHOLD_CRIB or ng_score > THRESHOLD_NGRAM

                    if is_interesting:
                        label = f"{mode_name}/{kw}/{alpha_name}/{perm_label}"
                        entry = {
                            'ngram_score': ng_score,
                            'crib_hits': crib_hits,
                            'method': label,
                            'plaintext': pt_text[:60],
                            'perm_label': perm_label,
                        }
                        results.append(entry)
                        if ng_score > best_ngram:
                            best_ngram = ng_score
                            best_result = entry
                        if crib_hits > best_crib:
                            best_crib = crib_hits
                        print(f"  ** ngram={ng_score:.1f} cribs={crib_hits}: {label} | {pt_text[:50]}...")

        if len(perms_to_test) > 10 and (perm_idx + 1) % 10 == 0:
            elapsed = time.time() - t0
            print(f"  ... {tested} configs, {elapsed:.1f}s, "
                  f"best_ngram={best_ngram:.1f} best_crib={best_crib}")

    elapsed = time.time() - t0
    print(f"\n{'='*70}")
    print(f"TOTAL: {tested} configurations tested in {elapsed:.1f}s")
    print(f"{'='*70}")

    if results:
        results.sort(key=lambda x: -x['ngram_score'])
        print(f"\n{len(results)} interesting results:")
        print("\nTop by ngram:")
        for r in results[:10]:
            print(f"  ngram={r['ngram_score']:.1f} cribs={r['crib_hits']}: {r['method']} | {r['plaintext'][:50]}")
        results_by_crib = sorted(results, key=lambda x: -x['crib_hits'])
        print("\nTop by crib hits:")
        for r in results_by_crib[:10]:
            print(f"  cribs={r['crib_hits']} ngram={r['ngram_score']:.1f}: {r['method']} | {r['plaintext'][:50]}")
    else:
        print("\nNo interesting results.")

    if best_result:
        print(f"\nBEST NGRAM: {best_result['ngram_score']:.1f}, method={best_result['method']}")
        print(f"  PT: {best_result['plaintext']}")
    print(f"BEST CRIB HITS: {best_crib}")

    # Save results
    out_path = os.path.join(os.path.dirname(__file__), '..', '..', 'results', 'e_autokey_permuted_05.json')
    with open(out_path, 'w') as f:
        json.dump({
            'experiment': 'e_autokey_permuted_05',
            'total_tested': tested,
            'elapsed': elapsed,
            'best_ngram': best_ngram,
            'best_crib': best_crib,
            'best_result': best_result,
            'above_noise': len(results),
            'top_results': results[:20],
            'perms_tested': len(perms_to_test),
            'keywords': KEYWORDS,
            'modes': list(AUTOKEY_MODES.keys()),
        }, f, indent=2)
    print(f"\nResults saved to {out_path}")
    print("DONE")


if __name__ == '__main__':
    main()
