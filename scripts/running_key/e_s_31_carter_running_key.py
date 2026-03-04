#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: running_key
Status: active
Keyspace: see implementation
Last run:
Best score:
"""
"""
E-S-31: Carter Book Running Key + Columnar Transposition

The Carter book (Tomb of Tutankhamun Vol 1) is the most thematically
connected running key source for K4:
- K3's plaintext is directly from Carter's account
- Sanborn's 2025 clue mentions a 1986 Egypt trip
- Scheidt's "masking" could be a running key from this text

Model A: CT = sigma(Vig(PT, Text[offset:]))
  -> Text[j+offset] = (CT[sigma(j)] - PT[j]) % 26 for crib position j

For each width-7 columnar ordering sigma:
  Compute 13 required key values for ENE (contiguous at text pos 21+offset to 33+offset)
  Search Carter text for matches (hash-based fast filter)
  If ENE matches, verify BC block (pos 63+offset to 73+offset)

Also: widths 5-10, Beaufort variant, Model B (scattered key positions).

Output: results/e_s_31_carter_running_key.json

attack(ciphertext, **params) -> list[tuple[float, str, str]]
    Standard attack interface.
    params: widths (list[int], default [7,5,6,8,9,10]),
            score_threshold (int, default 18),
            texts (dict[str, list[int]], default loads carter + running_key_texts/)
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

# ENE and BC crib blocks
ENE_RANGE = list(range(21, 34))  # 13 positions
BC_RANGE = list(range(63, 74))   # 11 positions


def load_carter_text():
    path = "reference/carter_vol1.txt"
    with open(path) as f:
        text = f.read().strip().upper()
    # Convert to numbers
    return [ord(c) - ord('A') for c in text if c.isalpha()]


def columnar_perm(col_order, width, length):
    """Return permutation sigma such that CT[i] = M[sigma^-1(i)], i.e., sigma(j)=CT position
    for intermediate position j. This is the "scatter" direction.

    Actually for columnar encryption:
    - Write M row by row into grid of given width
    - Read columns in col_order

    So sigma maps intermediate position j -> CT position i.
    """
    n_rows = (length + width - 1) // width
    n_long = length % width
    if n_long == 0:
        n_long = width

    # Build: for each intermediate position j, which CT position does it go to?
    sigma = [0] * length
    ct_pos = 0
    for col in col_order:
        col_len = n_rows if col < n_long else n_rows - 1
        for row in range(col_len):
            inter_pos = row * width + col
            if inter_pos < length:
                sigma[inter_pos] = ct_pos
                ct_pos += 1

    return sigma


def invert_perm(sigma):
    inv = [0] * len(sigma)
    for i, j in enumerate(sigma):
        inv[j] = i
    return inv


def _load_all_texts():
    """Load carter text and any running key texts from reference/running_key_texts/."""
    carter = load_carter_text()
    all_texts = {"carter_vol1": carter}

    rkt_dir = "reference/running_key_texts"
    if os.path.isdir(rkt_dir):
        for fn in sorted(os.listdir(rkt_dir)):
            if fn.endswith('.txt'):
                path = os.path.join(rkt_dir, fn)
                with open(path) as f:
                    raw = f.read().strip().upper()
                name = fn.replace('.txt', '')
                all_texts[name] = [ord(c) - ord('A') for c in raw if c.isalpha()]

    return all_texts


def _scan_width(ct_num, ct_len, width, all_texts, score_threshold, crib_pos, crib_pt, ene_range, bc_range):
    """Core scanning loop for a single width. Returns list of result dicts."""
    results = []
    n_ct = ct_len

    for text_name, text_nums in all_texts.items():
        text_len = len(text_nums)

        max_offset = text_len - 74
        if max_offset < 0:
            continue

        # Build fast lookup: (v0, v1) at consecutive positions -> list of offsets
        pair_index = defaultdict(list)
        for off in range(max_offset):
            key = (text_nums[21 + off], text_nums[22 + off])
            pair_index[key].append(off)

        for order_tuple in permutations(range(width)):
            order = list(order_tuple)
            sigma = columnar_perm(order, width, n_ct)
            sigma_inv = invert_perm(sigma)

            for variant, sign in [("vig", -1), ("beau", 1)]:
                # Model A: Text[j + offset] = (CT[sigma(j)] + sign * PT[j]) % 26
                ene_required = [(ct_num[sigma[j]] + sign * crib_pt[j]) % MOD for j in ene_range]
                bc_required = [(ct_num[sigma[j]] + sign * crib_pt[j]) % MOD for j in bc_range]

                filter_key = (ene_required[0], ene_required[1])
                candidates = pair_index.get(filter_key, [])

                for off in candidates:
                    ene_match = True
                    for k in range(2, 13):
                        if text_nums[21 + off + k] != ene_required[k]:
                            ene_match = False
                            break

                    if ene_match:
                        bc_count = 0
                        for k in range(11):
                            if text_nums[63 + off + k] == bc_required[k]:
                                bc_count += 1

                        total_match = 13 + bc_count
                        if total_match >= score_threshold:
                            pt = []
                            for j in range(n_ct):
                                ct_at_j = ct_num[sigma[j]]
                                if j + off < text_len:
                                    key_val = text_nums[j + off]
                                else:
                                    key_val = 0
                                if variant == "vig":
                                    pt_val = (ct_at_j - key_val) % MOD
                                else:
                                    pt_val = (key_val - ct_at_j) % MOD
                                pt.append(pt_val)
                            pt_str = ''.join(chr(v + ord('A')) for v in pt)

                            results.append({
                                "text": text_name,
                                "width": width,
                                "order": order,
                                "variant": variant,
                                "offset": off,
                                "score": total_match,
                                "ene_match": 13,
                                "bc_match": bc_count,
                                "plaintext": pt_str,
                                "model": "A",
                            })

                # Model B: scattered key positions
                first_req = (ct_num[sigma[21]] + sign * crib_pt[21]) % MOD
                first_sigma_pos = sigma[21]
                max_sigma = max(sigma[j] for j in crib_pos)
                max_off_b = text_len - max_sigma - 1

                for off in range(min(max_offset, max_off_b)):
                    if text_nums[first_sigma_pos + off] != first_req:
                        continue
                    match_count = 1
                    for j in crib_pos[1:]:
                        tpos = sigma[j] + off
                        if tpos >= text_len:
                            break
                        req = (ct_num[sigma[j]] + sign * crib_pt[j]) % MOD
                        if text_nums[tpos] == req:
                            match_count += 1
                        else:
                            if match_count + (24 - crib_pos.index(j) - 1) < score_threshold:
                                break

                    if match_count >= score_threshold:
                        pt = []
                        for j in range(n_ct):
                            tpos = sigma[j] + off
                            if tpos < text_len:
                                key_val = text_nums[tpos]
                            else:
                                key_val = 0
                            if variant == "vig":
                                pt_val = (ct_num[sigma[j]] - key_val) % MOD
                            else:
                                pt_val = (key_val - ct_num[sigma[j]]) % MOD
                            pt.append(pt_val)
                        pt_str = ''.join(chr(v + ord('A')) for v in pt)

                        results.append({
                            "text": text_name,
                            "width": width,
                            "order": order,
                            "variant": variant,
                            "offset": off,
                            "score": match_count,
                            "model": "B",
                            "plaintext": pt_str,
                        })

    return results


# -- Standard attack interface --

def attack(ciphertext: str, **params) -> list[tuple[float, str, str]]:
    """Standard attack interface. Returns [(score, plaintext, method_description), ...]"""
    widths = params.get("widths", [7, 5, 6, 8, 9, 10])
    score_threshold = params.get("score_threshold", 18)
    texts = params.get("texts", None)

    ct_len = len(ciphertext)
    ct_num = [ALPH_IDX[c] for c in ciphertext]
    crib_pos = sorted(CRIB_DICT.keys())
    crib_pt = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

    if texts is None:
        texts = _load_all_texts()

    all_results = []

    for width in widths:
        hits = _scan_width(ct_num, ct_len, width, texts, score_threshold,
                           crib_pos, crib_pt, ENE_RANGE, BC_RANGE)
        for h in hits:
            desc = (f"running_key text={h['text']} "
                    f"model={h['model']} {h['variant']} "
                    f"w={h['width']} order={h['order']} "
                    f"offset={h['offset']} "
                    f"score={h['score']}/24")
            all_results.append((float(h["score"]), h["plaintext"], desc))

    all_results.sort(key=lambda x: -x[0])
    return all_results


def main():
    print("=" * 60)
    print("E-S-31: Carter Book Running Key + Columnar Transposition")
    print("=" * 60)

    carter = load_carter_text()
    print(f"Carter text: {len(carter)} chars")

    # Also load other running key texts for comparison
    other_texts = {}
    rkt_dir = "reference/running_key_texts"
    if os.path.isdir(rkt_dir):
        for fn in sorted(os.listdir(rkt_dir)):
            if fn.endswith('.txt'):
                path = os.path.join(rkt_dir, fn)
                with open(path) as f:
                    raw = f.read().strip().upper()
                name = fn.replace('.txt', '')
                other_texts[name] = [ord(c) - ord('A') for c in raw if c.isalpha()]
                print(f"  Also loaded: {name} ({len(other_texts[name])} chars)")

    all_texts = {"carter_vol1": carter}
    all_texts.update(other_texts)

    t0 = time.time()
    all_results = []
    total_configs = 0

    for width in [7, 5, 6, 8, 9, 10]:
        n_orderings = 1
        for i in range(2, width + 1):
            n_orderings *= i

        print(f"\n{'=' * 60}")
        print(f"Width {width}: {n_orderings} orderings x {len(all_texts)} texts x 2 variants")
        print(f"{'=' * 60}")

        hits = _scan_width(CT_NUM, N, width, all_texts, 18,
                           CRIB_POS, CRIB_PT, ENE_RANGE, BC_RANGE)
        for h in hits:
            all_results.append(h)
            print(f"  *** HIT{' (B)' if h['model'] == 'B' else ''}: {h['text']} {h['variant']}"
                  f" w={h['width']} order={h['order']}"
                  f" offset={h['offset']}"
                  f" score={h['score']}/24"
                  f" PT={h['plaintext'][:50]}...")

        total_configs += n_orderings * len(all_texts) * 2
        elapsed = time.time() - t0
        print(f"  Width {width} done: {elapsed:.0f}s", flush=True)

    elapsed = time.time() - t0

    # Summary
    print(f"\n{'=' * 60}")
    print(f"SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Total configs: {total_configs:,}")
    print(f"  Time: {elapsed:.1f}s ({elapsed / 60:.1f} min)")
    print(f"  Hits >= 18: {len(all_results)}")

    if all_results:
        all_results.sort(key=lambda r: -r['score'])
        print(f"\n  Top results:")
        for r in all_results[:20]:
            print(f"    {r['text']} {r['variant']} w={r['width']}"
                  f" order={r['order']} offset={r['offset']}"
                  f" score={r['score']}/24 model={r['model']}")
            print(f"      PT: {r['plaintext'][:80]}")
    else:
        print(f"\n  No hits above threshold.")
        print(f"  Expected: with 288K offsets and 13-char filter, random hits ~ 0")

    verdict = "SIGNAL" if any(r['score'] >= 18 for r in all_results) else "NOISE"
    print(f"\n  Verdict: {verdict}")

    # Save
    os.makedirs("results", exist_ok=True)
    artifact = {
        "experiment": "E-S-31",
        "description": "Carter book running key + columnar transposition",
        "texts_tested": list(all_texts.keys()),
        "widths": [7, 5, 6, 8, 9, 10],
        "total_configs": total_configs,
        "hits": len(all_results),
        "verdict": verdict,
        "top_results": all_results[:20],
        "elapsed_seconds": round(elapsed, 1),
    }
    with open("results/e_s_31_carter_running_key.json", "w") as f:
        json.dump(artifact, f, indent=2)

    print(f"\n  Artifact: results/e_s_31_carter_running_key.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_31_carter_running_key.py")


if __name__ == "__main__":
    main()
