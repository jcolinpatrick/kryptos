#!/usr/bin/env python3
"""E-S-136: Great Big Story transcript as running key source.

Tests reference/great_big_story_cracking_the_uncrackable_code_2019.txt
(Sanborn's own words from 2019 video interview) as a running key source.

Phase 1: Direct Vigenere/Beaufort (no transposition), mismatch 0/1/2.
Phase 2: Width-7/8/9 columnar transposition + running key (all orderings).

Output: results/e_s_136_great_big_story_rk.json
"""

import json
import os
import sys
import time
from collections import defaultdict
from itertools import permutations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD
from kryptos.kernel.scoring.aggregate import score_candidate

CT_NUM = [ALPH_IDX[c] for c in CT]
N = CT_LEN

CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

ENE_RANGE = list(range(21, 34))
BC_RANGE = list(range(63, 74))


def load_text(path):
    with open(path) as f:
        raw = f.read().strip().upper()
    return [ord(c) - ord('A') for c in raw if c.isalpha()]


def columnar_perm_enc(col_order, width, length):
    n_rows = (length + width - 1) // width
    n_long = length % width
    if n_long == 0:
        n_long = width
    sigma = [0] * length
    ct_pos = 0
    for col in col_order:
        col_len = n_rows if col < n_long else n_rows - 1
        for row in range(col_len):
            inter_pos = row * width + col
            if inter_pos < length:
                sigma[inter_pos] = ct_pos
                ct_pos += 1
    inv = [0] * length
    for i, j in enumerate(sigma):
        inv[j] = i
    return inv, sigma


def direct_scan(text_nums, text_name, max_mismatch=2):
    text_len = len(text_nums)
    max_offset = text_len - N
    if max_offset < 0:
        return []

    vig_req = {pos: (CT_NUM[pos] - CRIB_PT[pos]) % MOD for pos in CRIB_POS}
    beau_req = {pos: (CT_NUM[pos] + CRIB_PT[pos]) % MOD for pos in CRIB_POS}
    results = []

    for vname, required in [("vigenere", vig_req), ("beaufort", beau_req)]:
        for offset in range(max_offset + 1):
            mm = 0
            for pos in CRIB_POS:
                if text_nums[pos + offset] != required[pos]:
                    mm += 1
                    if mm > max_mismatch:
                        break
            if mm <= max_mismatch:
                if vname == "vigenere":
                    pt = [(CT_NUM[i] - text_nums[i + offset]) % MOD for i in range(N)]
                else:
                    pt = [(text_nums[i + offset] - CT_NUM[i]) % MOD for i in range(N)]
                pt_str = ''.join(chr(v + ord('A')) for v in pt)
                sc = score_candidate(pt_str)
                results.append({
                    "variant": vname, "offset": offset, "mismatches": mm,
                    "crib_score": sc.crib_score, "ic": round(sc.ic_value, 5),
                    "plaintext": pt_str, "model": "direct",
                })
                print(f"  {'EXACT' if mm == 0 else f'{mm}-mismatch'}: {vname} off={offset} "
                      f"crib={sc.crib_score}/24 IC={sc.ic_value:.4f}")
    return results


def columnar_scan(text_nums, text_name, width, score_threshold=18):
    text_len = len(text_nums)
    max_offset = text_len - 74
    if max_offset < 0:
        return []

    results = []
    pair_index = defaultdict(list)
    for off in range(max_offset + 1):
        key = (text_nums[21 + off], text_nums[22 + off])
        pair_index[key].append(off)

    checked = 0
    for order_tuple in permutations(range(width)):
        order = list(order_tuple)
        gather, sigma = columnar_perm_enc(order, width, N)

        for variant, sign in [("vig", -1), ("beau", 1)]:
            checked += 1

            # Model A: contiguous key positions
            ene_req = [(CT_NUM[sigma[j]] + sign * CRIB_PT[j]) % MOD for j in ENE_RANGE]
            bc_req = [(CT_NUM[sigma[j]] + sign * CRIB_PT[j]) % MOD for j in BC_RANGE]

            filter_key = (ene_req[0], ene_req[1])
            for off in pair_index.get(filter_key, []):
                ene_ok = all(text_nums[21 + off + k] == ene_req[k] for k in range(2, 13))
                if ene_ok:
                    bc_count = sum(1 for k in range(11) if text_nums[63 + off + k] == bc_req[k])
                    total = 13 + bc_count
                    if total >= score_threshold:
                        pt = []
                        for j in range(N):
                            ct_at = CT_NUM[sigma[j]]
                            kv = text_nums[j + off] if (j + off) < text_len else 0
                            pt.append((ct_at - kv) % MOD if variant == "vig" else (kv - ct_at) % MOD)
                        pt_str = ''.join(chr(v + ord('A')) for v in pt)
                        sc = score_candidate(pt_str)
                        results.append({
                            "variant": variant, "width": width, "order": order,
                            "offset": off, "score": total,
                            "crib_score": sc.crib_score, "ic": round(sc.ic_value, 5),
                            "plaintext": pt_str, "model": "A_columnar",
                        })
                        print(f"  HIT(A): {variant} w={width} off={off} score={total}/24")

            # Model B: scattered key positions
            first_req = (CT_NUM[sigma[21]] + sign * CRIB_PT[21]) % MOD
            max_sigma = max(sigma[j] for j in CRIB_POS)
            max_off_b = text_len - max_sigma - 1

            for off in range(min(max_offset + 1, max_off_b)):
                if text_nums[sigma[21] + off] != first_req:
                    continue
                mc = 1
                for j in CRIB_POS[1:]:
                    tpos = sigma[j] + off
                    if tpos >= text_len:
                        break
                    req = (CT_NUM[sigma[j]] + sign * CRIB_PT[j]) % MOD
                    if text_nums[tpos] == req:
                        mc += 1
                    else:
                        remaining = 24 - CRIB_POS.index(j) - 1
                        if mc + remaining < score_threshold:
                            break
                if mc >= score_threshold:
                    pt = []
                    for j in range(N):
                        tpos = sigma[j] + off
                        kv = text_nums[tpos] if tpos < text_len else 0
                        pt.append((CT_NUM[sigma[j]] - kv) % MOD if variant == "vig" else (kv - CT_NUM[sigma[j]]) % MOD)
                    pt_str = ''.join(chr(v + ord('A')) for v in pt)
                    sc = score_candidate(pt_str)
                    results.append({
                        "variant": variant, "width": width, "order": order,
                        "offset": off, "score": mc,
                        "crib_score": sc.crib_score, "ic": round(sc.ic_value, 5),
                        "plaintext": pt_str, "model": "B_columnar",
                    })
                    print(f"  HIT(B): {variant} w={width} off={off} score={mc}/24")

    return results


def main():
    t0 = time.time()

    print("=" * 70)
    print("E-S-136: Great Big Story Transcript as Running Key Source")
    print("=" * 70)

    path = os.path.join(os.path.dirname(__file__), '..', 'reference',
                        'great_big_story_cracking_the_uncrackable_code_2019.txt')
    text_nums = load_text(path)
    print(f"Text: {len(text_nums)} alpha chars, {max(0, len(text_nums) - N + 1)} offsets")
    print()

    all_results = []

    # Phase 1: Direct
    print("PHASE 1: Direct running key (mismatch <= 2)")
    print("-" * 50)
    hits = direct_scan(text_nums, "great_big_story")
    all_results.extend(hits)
    if not hits:
        print("  No matches at mismatch <= 2")
    print()

    # Phase 2: Columnar widths 7, 8, 9
    for width in [7, 8, 9]:
        n_ord = 1
        for i in range(2, width + 1):
            n_ord *= i
        print(f"PHASE 2: Width-{width} columnar ({n_ord} orderings x 2 variants)")
        print("-" * 50)
        t1 = time.time()
        hits = columnar_scan(text_nums, "great_big_story", width=width)
        all_results.extend(hits)
        if not hits:
            print(f"  No hits >= 18")
        print(f"  Done in {time.time() - t1:.1f}s")
        print()

    t_total = time.time() - t0

    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Text: Great Big Story transcript ({len(text_nums)} alpha chars)")
    print(f"  Total hits: {len(all_results)}")
    print(f"  Total time: {t_total:.1f}s")

    verdict = "ELIMINATED" if not all_results else "SIGNAL"
    print(f"  Verdict: {verdict}")

    if verdict == "ELIMINATED":
        print(f"  -> Great Big Story transcript ELIMINATED as running key source")
        print(f"     under direct Vig/Beau (mismatch<=2) and columnar w7/w8/w9.")

    os.makedirs("results", exist_ok=True)
    artifact = {
        "experiment": "E-S-136",
        "description": "Great Big Story transcript as running key source",
        "text_chars": len(text_nums),
        "phases": {
            "direct": {"max_mismatch": 2, "hits": sum(1 for r in all_results if r["model"] == "direct")},
            "columnar_w7": {"hits": sum(1 for r in all_results if r.get("width") == 7)},
            "columnar_w8": {"hits": sum(1 for r in all_results if r.get("width") == 8)},
            "columnar_w9": {"hits": sum(1 for r in all_results if r.get("width") == 9)},
        },
        "verdict": verdict,
        "elapsed_seconds": round(t_total, 1),
        "top_results": all_results[:20],
    }
    outpath = "results/e_s_136_great_big_story_rk.json"
    with open(outpath, "w") as f:
        json.dump(artifact, f, indent=2)

    print(f"\n  Artifact: {outpath}")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_136_great_big_story_rk.py")
    print(f"\nRESULT: hits={len(all_results)} verdict={verdict}")


if __name__ == "__main__":
    main()
