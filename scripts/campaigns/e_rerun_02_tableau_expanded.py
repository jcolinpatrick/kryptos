#!/usr/bin/env python3
"""
Cipher: multi-vector campaign
Family: campaigns
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-RERUN-02: Expanded Thematic Keywords at Bean-Surviving Periods (K3-Method)

Reruns E-TABLEAU-20 logic with expanded thematic_keywords.txt (~290 words).
Filters keywords by length to match Bean-surviving periods:
  - 8-letter keywords: exhaustive width-8 orderings (40,320)
  - 13-letter keywords: sampled width-13 orderings (50,000)
  - 16-letter keywords: sampled width-16 orderings (50,000)
  - 19/20-letter keywords: sampled orderings (50,000)
Also tests cross-width: 8-letter keywords at width 13, 13-letter at width 8.

Models: A (Sub->Trans) and B (Trans->Sub), Vigenere and Beaufort.
"""

import sys
import os
import json
import time
import random
from itertools import permutations
from math import factorial
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS, BEAN_EQ, BEAN_INEQ,
)

REPO = Path(__file__).resolve().parents[1]
CT_IDX = [ALPH_IDX[c] for c in CT]
CRIB_LIST = [(pos, ALPH_IDX[ch]) for pos, ch in sorted(CRIB_DICT.items())]

# ── Load keywords from expanded thematic_keywords.txt ────────────────────

def load_thematic_keywords():
    path = REPO / "wordlists" / "thematic_keywords.txt"
    keywords = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            word = line.upper()
            if word.isalpha() and len(word) >= 2:
                keywords.append(word)
    return list(dict.fromkeys(keywords))

ALL_KEYWORDS = load_thematic_keywords()

# Bean-surviving periods
BEAN_PERIODS = {8, 13, 16, 19, 20, 23, 24, 26}

# Group keywords by length, only keeping those matching Bean-surviving periods
KEYWORDS_BY_LENGTH = {}
for kw in ALL_KEYWORDS:
    n = len(kw)
    if n in BEAN_PERIODS:
        KEYWORDS_BY_LENGTH.setdefault(n, []).append(kw)


def keyword_to_numeric(keyword):
    return [ALPH_IDX[c] for c in keyword.upper()]


def build_columnar_perm(width, col_order):
    n_full_cols = CT_LEN % width
    base_rows = CT_LEN // width
    col_heights = [base_rows + 1 if c < n_full_cols else base_rows for c in range(width)]
    perm = []
    for col in col_order:
        for row in range(col_heights[col]):
            perm.append(row * width + col)
    assert len(perm) == CT_LEN
    return perm


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def check_crib_score_model_b(inv_perm, key_numeric, period, variant):
    score = 0
    for pos, pt_val in CRIB_LIST:
        j = inv_perm[pos]
        if variant == 'vig':
            derived_pt = (CT_IDX[j] - key_numeric[j % period]) % MOD
        else:
            derived_pt = (key_numeric[j % period] - CT_IDX[j]) % MOD
        if derived_pt == pt_val:
            score += 1
    return score


def check_crib_score_model_a(inv_perm, key_numeric, period, variant):
    score = 0
    for pos, pt_val in CRIB_LIST:
        sub_out_pos = CT_IDX[inv_perm[pos]]
        if variant == 'vig':
            derived_pt = (sub_out_pos - key_numeric[pos % period]) % MOD
        else:
            derived_pt = (key_numeric[pos % period] - sub_out_pos) % MOD
        if derived_pt == pt_val:
            score += 1
    return score


def check_bean(inv_perm, key_numeric, period, variant, model):
    def key_at_pos(i):
        if model == 'B':
            return key_numeric[inv_perm[i] % period]
        else:
            return key_numeric[i % period]

    k27 = key_at_pos(27)
    k65 = key_at_pos(65)
    if k27 != k65:
        return False
    for a, b in BEAN_INEQ:
        if key_at_pos(a) == key_at_pos(b):
            return False
    return True


def derive_plaintext(perm, inv_perm, key_numeric, period, variant, model):
    pt_idx = [0] * CT_LEN
    for pos in range(CT_LEN):
        if model == 'B':
            j = inv_perm[pos]
            if variant == 'vig':
                pt_idx[pos] = (CT_IDX[j] - key_numeric[j % period]) % MOD
            else:
                pt_idx[pos] = (key_numeric[j % period] - CT_IDX[j]) % MOD
        else:
            sub_out = CT_IDX[inv_perm[pos]]
            if variant == 'vig':
                pt_idx[pos] = (sub_out - key_numeric[pos % period]) % MOD
            else:
                pt_idx[pos] = (key_numeric[pos % period] - sub_out) % MOD
    return ''.join(ALPH[v] for v in pt_idx)


def test_keyword_at_width(keyword, width, max_orderings=None):
    period = len(keyword)
    key_numeric = keyword_to_numeric(keyword)

    n_orderings = factorial(width)
    if max_orderings and n_orderings > max_orderings:
        random.seed(42)
        base_list = list(range(width))
        orderings = set()
        while len(orderings) < max_orderings:
            p = tuple(random.sample(base_list, width))
            orderings.add(p)
        orderings = list(orderings)
        sampled = True
    else:
        orderings = list(permutations(range(width)))
        sampled = False

    best_score = 0
    best_configs = []
    bean_pass_count = 0
    bean_pass_best = 0
    score_24_count = 0

    configs = [('B', 'vig'), ('B', 'beau'), ('A', 'vig'), ('A', 'beau')]

    for col_order in orderings:
        perm = build_columnar_perm(width, list(col_order))
        inv_perm = invert_perm(perm)

        for model, variant in configs:
            if model == 'B':
                score = check_crib_score_model_b(inv_perm, key_numeric, period, variant)
            else:
                score = check_crib_score_model_a(inv_perm, key_numeric, period, variant)

            if score >= best_score:
                bean_ok = check_bean(inv_perm, key_numeric, period, variant, model)
                if score > best_score:
                    best_score = score
                    best_configs = []
                best_configs.append({
                    'col_order': list(col_order), 'model': model,
                    'variant': variant, 'score': score, 'bean': bean_ok,
                })
                if bean_ok:
                    bean_pass_count += 1
                    if score > bean_pass_best:
                        bean_pass_best = score
                if score == 24:
                    score_24_count += 1
                    pt = derive_plaintext(perm, inv_perm, key_numeric, period, variant, model)
                    print(f"  *** 24/24 HIT! keyword={keyword} order={list(col_order)} "
                          f"model={model} variant={variant} bean={'PASS' if bean_ok else 'FAIL'}")
                    print(f"      PT: {pt}")

            elif score >= 20:
                bean_ok = check_bean(inv_perm, key_numeric, period, variant, model)
                if bean_ok and score > bean_pass_best:
                    bean_pass_best = score
                if bean_ok:
                    bean_pass_count += 1

    return {
        'keyword': keyword, 'width': width, 'period': period,
        'n_orderings_tested': len(orderings), 'sampled': sampled,
        'best_score': best_score, 'n_best_configs': len(best_configs),
        'best_configs_sample': best_configs[:5],
        'score_24_count': score_24_count,
        'bean_pass_count': bean_pass_count,
        'bean_pass_best_score': bean_pass_best,
    }


def main():
    print("=" * 70)
    print("E-RERUN-02: Expanded Thematic Keywords at Bean-Surviving Periods")
    print("=" * 70)
    print(f"\nSource: wordlists/thematic_keywords.txt ({len(ALL_KEYWORDS)} total)")
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")

    for length, kws in sorted(KEYWORDS_BY_LENGTH.items()):
        print(f"  Period {length}: {len(kws)} keywords")

    all_results = []
    t_global = time.time()

    # ── Phase 1: K3-style specific combos ─────────────────────────────────
    print("\nPHASE 1: K3-style keyword combos (quick check)")
    print("-" * 50)

    def keyword_to_order(keyword):
        indexed = [(c, i) for i, c in enumerate(keyword)]
        sorted_indexed = sorted(indexed, key=lambda x: (x[0], x[1]))
        order = [0] * len(keyword)
        for rank, (_, orig_pos) in enumerate(sorted_indexed):
            order[orig_pos] = rank
        reading_order = [0] * len(keyword)
        for i, r in enumerate(order):
            reading_order[r] = i
        return reading_order

    k3_combos = [
        ("KRYPTOS", 7, "PALIMPSEST"),
        ("KRYPTOS", 7, "ABSCISSA"),
        ("ABSCISSA", 8, "PALIMPSEST"),
        ("ABSCISSA", 8, "ABSCISSA"),
        ("ABSCISSA", 8, "KRYPTOS"),
    ]

    for trans_kw, width, vig_kw in k3_combos:
        col_order = keyword_to_order(trans_kw)
        period = len(vig_kw)
        key_numeric = keyword_to_numeric(vig_kw)
        perm = build_columnar_perm(width, col_order)
        inv_perm = invert_perm(perm)

        for model, variant in [('B', 'vig'), ('B', 'beau'), ('A', 'vig'), ('A', 'beau')]:
            if model == 'B':
                score = check_crib_score_model_b(inv_perm, key_numeric, period, variant)
            else:
                score = check_crib_score_model_a(inv_perm, key_numeric, period, variant)
            bean_ok = check_bean(inv_perm, key_numeric, period, variant, model)
            print(f"  Trans={trans_kw}(w{width}) Vig={vig_kw}(p{period}) "
                  f"model={model} var={variant}: {score}/24 Bean={'PASS' if bean_ok else 'FAIL'}")

    # ── Phase 2: Width-8 exhaustive with all 8-letter keywords ────────────
    kw8 = KEYWORDS_BY_LENGTH.get(8, [])
    if kw8:
        print(f"\nPHASE 2: Width-8 exhaustive (40,320 orderings) x {len(kw8)} period-8 keywords")
        print("-" * 50)
        t0 = time.time()
        for keyword in kw8:
            t_kw = time.time()
            result = test_keyword_at_width(keyword, 8)
            elapsed = time.time() - t_kw
            print(f"  {keyword}: best={result['best_score']}/24, "
                  f"bean_best={result['bean_pass_best_score']}/24, "
                  f"24hits={result['score_24_count']}, time={elapsed:.1f}s")
            all_results.append(result)
        print(f"Phase 2 total: {time.time() - t0:.1f}s")

    # ── Phase 3: Width-13 with 13-letter keywords ─────────────────────────
    kw13 = KEYWORDS_BY_LENGTH.get(13, [])
    if kw13:
        print(f"\nPHASE 3: Width-13 (sampled 50K orderings) x {len(kw13)} period-13 keywords")
        print("-" * 50)
        t0 = time.time()
        for keyword in kw13:
            t_kw = time.time()
            result = test_keyword_at_width(keyword, 13, max_orderings=50000)
            elapsed = time.time() - t_kw
            print(f"  {keyword}: best={result['best_score']}/24, "
                  f"bean_best={result['bean_pass_best_score']}/24, "
                  f"24hits={result['score_24_count']}, time={elapsed:.1f}s")
            all_results.append(result)
        print(f"Phase 3 total: {time.time() - t0:.1f}s")

    # ── Phase 4: Other Bean-surviving lengths (16, 19, 20, 23, 24, 26) ────
    other_lengths = [l for l in sorted(KEYWORDS_BY_LENGTH.keys()) if l not in (8, 13)]
    if other_lengths:
        print(f"\nPHASE 4: Other Bean-surviving lengths: {other_lengths}")
        print("-" * 50)
        t0 = time.time()
        for length in other_lengths:
            kws = KEYWORDS_BY_LENGTH[length]
            max_ord = min(50000, factorial(length))
            for keyword in kws:
                t_kw = time.time()
                result = test_keyword_at_width(keyword, length, max_orderings=50000)
                elapsed = time.time() - t_kw
                print(f"  {keyword}(w{length}): best={result['best_score']}/24, "
                      f"bean_best={result['bean_pass_best_score']}/24, "
                      f"24hits={result['score_24_count']}, time={elapsed:.1f}s")
                all_results.append(result)
        print(f"Phase 4 total: {time.time() - t0:.1f}s")

    # ── Phase 5: Cross-width tests (8-letter keywords at width 13, etc.) ──
    if kw8:
        print(f"\nPHASE 5: Cross-width (top 5 period-8 keywords at width 13)")
        print("-" * 50)
        t0 = time.time()
        for keyword in kw8[:5]:
            t_kw = time.time()
            result = test_keyword_at_width(keyword, 13, max_orderings=50000)
            elapsed = time.time() - t_kw
            print(f"  {keyword}(w13,p8): best={result['best_score']}/24, "
                  f"bean_best={result['bean_pass_best_score']}/24, time={elapsed:.1f}s")
            all_results.append(result)
        print(f"Phase 5 total: {time.time() - t0:.1f}s")

    # ── Summary ──────────────────────────────────────────────────────────
    elapsed_total = time.time() - t_global
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    if all_results:
        total_orderings = sum(r['n_orderings_tested'] for r in all_results)
        total_configs = total_orderings * 4
        global_best = max(r['best_score'] for r in all_results)
        any_24 = any(r['score_24_count'] > 0 for r in all_results)

        print(f"Total orderings tested: {total_orderings:,}")
        print(f"Total configs tested: {total_configs:,}")
        print(f"Keywords tested: {len(all_results)}")
        print(f"Global best score: {global_best}/24")
        print(f"Any 24/24 hits: {'YES!' if any_24 else 'NO'}")

        print("\nPer-keyword results (sorted by best score):")
        for r in sorted(all_results, key=lambda x: -x['best_score'])[:30]:
            flag = " ***" if r['score_24_count'] > 0 else ""
            print(f"  {r['keyword']:20s} w={r['width']:2d} p={r['period']:2d} "
                  f"best={r['best_score']:2d}/24 bean_best={r['bean_pass_best_score']:2d}/24{flag}")

        if any_24:
            verdict = "SIGNAL -- 24/24 hit found! VERIFY IMMEDIATELY."
        elif global_best > 14:
            verdict = "ELEVATED -- above random baseline"
        else:
            verdict = "ELIMINATED -- all expanded keywords produce noise"
    else:
        verdict = "NO KEYWORDS -- no keywords matched Bean-surviving lengths"
        total_configs = 0
        global_best = 0
        any_24 = False

    print(f"\nVERDICT: {verdict}")
    print(f"Elapsed: {elapsed_total:.1f}s")

    os.makedirs(REPO / "results", exist_ok=True)
    output = {
        'experiment': 'E-RERUN-02',
        'description': 'Expanded thematic keywords at Bean-surviving periods (K3 method)',
        'source_wordlist': 'wordlists/thematic_keywords.txt',
        'total_keywords_loaded': len(ALL_KEYWORDS),
        'keywords_by_length': {str(k): len(v) for k, v in KEYWORDS_BY_LENGTH.items()},
        'total_configs': total_configs,
        'global_best': global_best,
        'any_24_hits': any_24,
        'verdict': verdict,
        'elapsed_seconds': elapsed_total,
        'results': all_results,
    }
    artifact_path = REPO / "results" / "e_rerun_02_tableau_expanded.json"
    with open(artifact_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nArtifact: {artifact_path}")
    print(f"Repro: PYTHONPATH=src python3 -u scripts/e_rerun_02_tableau_expanded.py")


if __name__ == '__main__':
    main()
