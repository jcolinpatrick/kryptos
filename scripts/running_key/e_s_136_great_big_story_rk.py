#!/usr/bin/env python3
"""
Cipher: running key
Family: running_key
Status: promising
Keyspace: see implementation
Last run:
Best score:
"""
"""E-S-136: Great Big Story transcript as running key source.

Tests reference/great_big_story_cracking_the_uncrackable_code_2019.txt
(Sanborn's own words from 2019 video interview) as a running key source.

Phase 1: Direct Vigenere/Beaufort (no transposition), mismatch 0/1/2.
Phase 2: Width-7/8/9 columnar transposition + running key (all orderings).

Output: results/e_s_136_great_big_story_rk.json

attack(ciphertext, **params) -> list[tuple[float, str, str]]
    Standard attack interface.
    params: text_path (str), max_mismatch (int, default 2),
            columnar_widths (list[int], default [7,8,9]),
            score_threshold (int, default 18)
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


def _direct_scan(ct_num, ct_len, text_nums, max_mismatch=2):
    """Direct running key scan (no transposition). Returns list of result tuples."""
    text_len = len(text_nums)
    max_offset = text_len - ct_len
    if max_offset < 0:
        return []

    crib_pos = sorted(CRIB_DICT.keys())
    crib_pt = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
    vig_req = {pos: (ct_num[pos] - crib_pt[pos]) % MOD for pos in crib_pos}
    beau_req = {pos: (ct_num[pos] + crib_pt[pos]) % MOD for pos in crib_pos}
    results = []

    for vname, required in [("vigenere", vig_req), ("beaufort", beau_req)]:
        for offset in range(max_offset + 1):
            mm = 0
            for pos in crib_pos:
                if text_nums[pos + offset] != required[pos]:
                    mm += 1
                    if mm > max_mismatch:
                        break
            if mm <= max_mismatch:
                if vname == "vigenere":
                    pt = [(ct_num[i] - text_nums[i + offset]) % MOD for i in range(ct_len)]
                else:
                    pt = [(text_nums[i + offset] - ct_num[i]) % MOD for i in range(ct_len)]
                pt_str = ''.join(chr(v + ord('A')) for v in pt)
                sc = score_candidate(pt_str)
                results.append({
                    "variant": vname, "offset": offset, "mismatches": mm,
                    "crib_score": sc.crib_score, "ic": round(sc.ic_value, 5),
                    "plaintext": pt_str, "model": "direct",
                })
    return results


def _columnar_scan(ct_num, ct_len, text_nums, width, score_threshold=18):
    """Columnar + running key scan for a single width. Returns list of result dicts."""
    text_len = len(text_nums)
    max_offset = text_len - 74
    if max_offset < 0:
        return []

    crib_pos = sorted(CRIB_DICT.keys())
    crib_pt = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

    results = []
    pair_index = defaultdict(list)
    for off in range(max_offset + 1):
        key = (text_nums[21 + off], text_nums[22 + off])
        pair_index[key].append(off)

    for order_tuple in permutations(range(width)):
        order = list(order_tuple)
        gather, sigma = columnar_perm_enc(order, width, ct_len)

        for variant, sign in [("vig", -1), ("beau", 1)]:
            # Model A: contiguous key positions
            ene_req = [(ct_num[sigma[j]] + sign * crib_pt[j]) % MOD for j in ENE_RANGE]
            bc_req = [(ct_num[sigma[j]] + sign * crib_pt[j]) % MOD for j in BC_RANGE]

            filter_key = (ene_req[0], ene_req[1])
            for off in pair_index.get(filter_key, []):
                ene_ok = all(text_nums[21 + off + k] == ene_req[k] for k in range(2, 13))
                if ene_ok:
                    bc_count = sum(1 for k in range(11) if text_nums[63 + off + k] == bc_req[k])
                    total = 13 + bc_count
                    if total >= score_threshold:
                        pt = []
                        for j in range(ct_len):
                            ct_at = ct_num[sigma[j]]
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

            # Model B: scattered key positions
            first_req = (ct_num[sigma[21]] + sign * crib_pt[21]) % MOD
            max_sigma = max(sigma[j] for j in crib_pos)
            max_off_b = text_len - max_sigma - 1

            for off in range(min(max_offset + 1, max_off_b)):
                if text_nums[sigma[21] + off] != first_req:
                    continue
                mc = 1
                for j in crib_pos[1:]:
                    tpos = sigma[j] + off
                    if tpos >= text_len:
                        break
                    req = (ct_num[sigma[j]] + sign * crib_pt[j]) % MOD
                    if text_nums[tpos] == req:
                        mc += 1
                    else:
                        remaining = 24 - crib_pos.index(j) - 1
                        if mc + remaining < score_threshold:
                            break
                if mc >= score_threshold:
                    pt = []
                    for j in range(ct_len):
                        tpos = sigma[j] + off
                        kv = text_nums[tpos] if tpos < text_len else 0
                        pt.append((ct_num[sigma[j]] - kv) % MOD if variant == "vig" else (kv - ct_num[sigma[j]]) % MOD)
                    pt_str = ''.join(chr(v + ord('A')) for v in pt)
                    sc = score_candidate(pt_str)
                    results.append({
                        "variant": variant, "width": width, "order": order,
                        "offset": off, "score": mc,
                        "crib_score": sc.crib_score, "ic": round(sc.ic_value, 5),
                        "plaintext": pt_str, "model": "B_columnar",
                    })

    return results


# -- Standard attack interface --

def attack(ciphertext: str, **params) -> list[tuple[float, str, str]]:
    """Standard attack interface. Returns [(score, plaintext, method_description), ...]"""
    text_path = params.get("text_path",
                           os.path.join(os.path.dirname(__file__), '..', 'reference',
                                        'great_big_story_cracking_the_uncrackable_code_2019.txt'))
    max_mismatch = params.get("max_mismatch", 2)
    columnar_widths = params.get("columnar_widths", [7, 8, 9])
    score_threshold = params.get("score_threshold", 18)

    ct_len = len(ciphertext)
    ct_num = [ALPH_IDX[c] for c in ciphertext]
    text_nums = load_text(text_path)

    results = []

    # Phase 1: Direct running key
    direct_hits = _direct_scan(ct_num, ct_len, text_nums, max_mismatch=max_mismatch)
    for h in direct_hits:
        desc = (f"direct_running_key {h['variant']} "
                f"offset={h['offset']} mismatches={h['mismatches']} "
                f"crib={h['crib_score']}/24 IC={h['ic']}")
        results.append((float(h["crib_score"]), h["plaintext"], desc))

    # Phase 2: Columnar + running key
    for width in columnar_widths:
        col_hits = _columnar_scan(ct_num, ct_len, text_nums, width,
                                  score_threshold=score_threshold)
        for h in col_hits:
            desc = (f"columnar_running_key model={h['model']} "
                    f"{h['variant']} w={h.get('width', width)} "
                    f"order={h.get('order', '?')} offset={h['offset']} "
                    f"score={h['score']}/24 crib={h['crib_score']}/24 IC={h['ic']}")
            results.append((float(h["crib_score"]), h["plaintext"], desc))

    results.sort(key=lambda x: -x[0])
    return results


def direct_scan(text_nums, text_name, max_mismatch=2):
    """Backwards-compatible wrapper for main()."""
    hits = _direct_scan(CT_NUM, N, text_nums, max_mismatch=max_mismatch)
    for h in hits:
        mm = h['mismatches']
        tag = 'EXACT' if mm == 0 else f'{mm}-mismatch'
        print(f"  {tag}: {h['variant']} off={h['offset']} "
              f"crib={h['crib_score']}/24 IC={h['ic']:.4f}")
    return hits


def columnar_scan(text_nums, text_name, width, score_threshold=18):
    """Backwards-compatible wrapper for main()."""
    hits = _columnar_scan(CT_NUM, N, text_nums, width, score_threshold=score_threshold)
    for h in hits:
        model_tag = "A" if h["model"] == "A_columnar" else "B"
        print(f"  HIT({model_tag}): {h['variant']} w={width} off={h['offset']} score={h['score']}/24")
    return hits


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
            "direct": {"max_mismatch": 2, "hits": sum(1 for r in all_results if r.get("model") == "direct")},
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
