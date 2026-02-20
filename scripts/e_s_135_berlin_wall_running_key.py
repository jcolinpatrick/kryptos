#!/usr/bin/env python3
"""E-S-135: Berlin Wall speech texts as running key sources.

Sanborn's 2025 open letter mentions 1989 Berlin Wall. Running key from
unknown text is the only structured key model surviving Bean elimination.

Tests historically relevant Berlin Wall texts:
1. Reagan "Tear down this wall" (June 12, 1987)
2. JFK "Ich bin ein Berliner" (June 26, 1963)
3. CIA Charter, UDHR, NSA Act (already in reference/)

For each text:
- Direct running key (no transposition): slide 97-char window, check
  24 constrained crib positions under Vigenere and Beaufort at mismatch 0, 1, 2.
- Width-7 columnar transposition (5040 orderings x 2 variants x 2 layer directions).

Uses constants from kryptos.kernel.constants. Scores hits with score_candidate().

Output: results/e_s_135_berlin_wall_running_key.json
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

ENE_RANGE = list(range(21, 34))  # 13 positions
BC_RANGE = list(range(63, 74))   # 11 positions


def load_text(path):
    """Load a text file and convert to list of ints [0..25]."""
    with open(path) as f:
        raw = f.read().strip().upper()
    return [ord(c) - ord('A') for c in raw if c.isalpha()]


def columnar_perm_enc(col_order, width, length):
    """Columnar encryption permutation.

    Fill grid row by row, read columns in col_order.
    Returns perm where output[i] = input[perm[i]] (gather convention).
    """
    n_rows = (length + width - 1) // width
    n_long = length % width
    if n_long == 0:
        n_long = width

    # Build scatter: for each intermediate position j, sigma[j] = CT position
    sigma = [0] * length
    ct_pos = 0
    for col in col_order:
        col_len = n_rows if col < n_long else n_rows - 1
        for row in range(col_len):
            inter_pos = row * width + col
            if inter_pos < length:
                sigma[inter_pos] = ct_pos
                ct_pos += 1

    # Invert to get gather perm
    inv = [0] * length
    for i, j in enumerate(sigma):
        inv[j] = i
    return inv, sigma


# ── Phase 1: Direct running key (no transposition) ──────────────────────────

def direct_running_key_scan(text_nums, text_name, max_mismatch=2):
    """Slide a window over the text, check crib positions under Vig/Beaufort.

    For Vigenere: KEY[pos] = (CT[pos] - PT[pos]) mod 26
      → text[pos + offset] must equal KEY[pos]
      → text[pos + offset] = (CT[pos] - PT[pos]) mod 26

    For Beaufort: KEY[pos] = (CT[pos] + PT[pos]) mod 26
      → text[pos + offset] must equal KEY[pos]
      → text[pos + offset] = (CT[pos] + PT[pos]) mod 26
    """
    text_len = len(text_nums)
    max_offset = text_len - N
    if max_offset < 0:
        return []

    # Precompute required key values at crib positions
    vig_required = {}
    beau_required = {}
    for pos in CRIB_POS:
        pt_val = CRIB_PT[pos]
        vig_required[pos] = (CT_NUM[pos] - pt_val) % MOD
        beau_required[pos] = (CT_NUM[pos] + pt_val) % MOD

    results = []

    for variant_name, required in [("vigenere", vig_required), ("beaufort", beau_required)]:
        for offset in range(max_offset + 1):
            mismatches = 0
            for pos in CRIB_POS:
                if text_nums[pos + offset] != required[pos]:
                    mismatches += 1
                    if mismatches > max_mismatch:
                        break

            if mismatches <= max_mismatch:
                # Decrypt full text
                if variant_name == "vigenere":
                    pt = [(CT_NUM[i] - text_nums[i + offset]) % MOD for i in range(N)]
                else:
                    pt = [(text_nums[i + offset] - CT_NUM[i]) % MOD for i in range(N)]
                pt_str = ''.join(chr(v + ord('A')) for v in pt)

                score = score_candidate(pt_str)

                results.append({
                    "text": text_name,
                    "variant": variant_name,
                    "offset": offset,
                    "mismatches": mismatches,
                    "crib_score": score.crib_score,
                    "ic": round(score.ic_value, 5),
                    "bean_passed": score.bean_passed,
                    "plaintext": pt_str,
                    "model": "direct",
                })

                if mismatches == 0:
                    print(f"  EXACT MATCH: {text_name} {variant_name} offset={offset} "
                          f"crib={score.crib_score}/24 IC={score.ic_value:.4f}")
                elif mismatches <= 2:
                    print(f"  NEAR MATCH ({mismatches} mismatch): {text_name} {variant_name} "
                          f"offset={offset} crib={score.crib_score}/24")

    return results


# ── Phase 2: Width-7 columnar + running key ──────────────────────────────────

def columnar_running_key_scan(text_nums, text_name, width=7, score_threshold=18):
    """Test all width-7 columnar orderings with running key from text.

    Model A: CT = σ(Vig(PT, text[offset:]))
      → text[j + offset] = (CT[σ(j)] - PT[j]) mod 26  [Vig]
      → text[j + offset] = (CT[σ(j)] + PT[j]) mod 26  [Beaufort, sign convention]

    Model B: CT = Vig(σ(PT), text[offset:])
      → text[σ(j) + offset] = (CT[σ(j)] - PT[j]) mod 26

    For Model A, ENE/BC key values are contiguous in the text at
    positions 21+offset..33+offset and 63+offset..73+offset.
    """
    text_len = len(text_nums)
    max_offset_needed = text_len - 74  # need up to pos 73
    if max_offset_needed < 0:
        return []

    results = []
    n_orderings = 1
    for i in range(2, width + 1):
        n_orderings *= i

    # Build fast lookup: consecutive pair → list of offsets
    pair_index = defaultdict(list)
    for off in range(max_offset_needed + 1):
        key = (text_nums[21 + off], text_nums[22 + off])
        pair_index[key].append(off)

    checked = 0
    t0 = time.time()

    for order_tuple in permutations(range(width)):
        order = list(order_tuple)
        # Get both gather (inv) and scatter (sigma)
        gather, sigma = columnar_perm_enc(order, width, N)

        for variant, sign in [("vig", -1), ("beau", 1)]:
            checked += 1

            # ── Model A: text positions are contiguous ──
            # Required key values for ENE block under this permutation
            ene_req = [(CT_NUM[sigma[j]] + sign * CRIB_PT[j]) % MOD for j in ENE_RANGE]
            bc_req = [(CT_NUM[sigma[j]] + sign * CRIB_PT[j]) % MOD for j in BC_RANGE]

            # Fast filter on first 2 ENE values
            filter_key = (ene_req[0], ene_req[1])
            candidates = pair_index.get(filter_key, [])

            for off in candidates:
                # Check remaining ENE values
                ene_ok = True
                for k in range(2, 13):
                    if text_nums[21 + off + k] != ene_req[k]:
                        ene_ok = False
                        break

                if ene_ok:
                    bc_count = sum(1 for k in range(11) if text_nums[63 + off + k] == bc_req[k])
                    total_match = 13 + bc_count
                    if total_match >= score_threshold:
                        # Decrypt
                        pt = []
                        for j in range(N):
                            ct_at = CT_NUM[sigma[j]]
                            key_val = text_nums[j + off] if (j + off) < text_len else 0
                            if variant == "vig":
                                pt.append((ct_at - key_val) % MOD)
                            else:
                                pt.append((key_val - ct_at) % MOD)
                        pt_str = ''.join(chr(v + ord('A')) for v in pt)

                        score = score_candidate(pt_str)
                        results.append({
                            "text": text_name,
                            "variant": variant,
                            "width": width,
                            "order": order,
                            "offset": off,
                            "score": total_match,
                            "crib_score": score.crib_score,
                            "ic": round(score.ic_value, 5),
                            "bean_passed": score.bean_passed,
                            "plaintext": pt_str,
                            "model": "A_columnar",
                        })
                        print(f"  *** HIT (A): {text_name} {variant} w={width} "
                              f"order={order} off={off} score={total_match}/24 "
                              f"PT={pt_str[:50]}...")

            # ── Model B: scattered key positions ──
            # text[sigma(j) + offset] = required value for crib position j
            first_req = (CT_NUM[sigma[21]] + sign * CRIB_PT[21]) % MOD
            first_sigma_pos = sigma[21]
            max_sigma = max(sigma[j] for j in CRIB_POS)
            max_off_b = text_len - max_sigma - 1

            for off in range(min(max_offset_needed + 1, max_off_b)):
                if text_nums[first_sigma_pos + off] != first_req:
                    continue
                match_count = 1
                for j in CRIB_POS[1:]:
                    tpos = sigma[j] + off
                    if tpos >= text_len:
                        break
                    req = (CT_NUM[sigma[j]] + sign * CRIB_PT[j]) % MOD
                    if text_nums[tpos] == req:
                        match_count += 1
                    else:
                        remaining = 24 - CRIB_POS.index(j) - 1
                        if match_count + remaining < score_threshold:
                            break

                if match_count >= score_threshold:
                    pt = []
                    for j in range(N):
                        tpos = sigma[j] + off
                        key_val = text_nums[tpos] if tpos < text_len else 0
                        if variant == "vig":
                            pt.append((CT_NUM[sigma[j]] - key_val) % MOD)
                        else:
                            pt.append((key_val - CT_NUM[sigma[j]]) % MOD)
                    pt_str = ''.join(chr(v + ord('A')) for v in pt)

                    score = score_candidate(pt_str)
                    results.append({
                        "text": text_name,
                        "variant": variant,
                        "width": width,
                        "order": order,
                        "offset": off,
                        "score": match_count,
                        "crib_score": score.crib_score,
                        "ic": round(score.ic_value, 5),
                        "bean_passed": score.bean_passed,
                        "plaintext": pt_str,
                        "model": "B_columnar",
                    })
                    print(f"  *** HIT (B): {text_name} {variant} w={width} "
                          f"order={order} off={off} score={match_count}/24 "
                          f"PT={pt_str[:50]}...")

        if (checked % 2000) == 0:
            elapsed = time.time() - t0
            rate = checked / elapsed if elapsed > 0 else 0
            print(f"    [{checked}/{n_orderings*2}] {rate:.0f}/s "
                  f"hits={len(results)}", flush=True)

    return results


def main():
    t_start = time.time()

    print("=" * 70)
    print("E-S-135: Berlin Wall Speech Texts as Running Key Sources")
    print("=" * 70)
    print(f"CT: {CT[:20]}...{CT[-10:]} ({CT_LEN} chars)")
    print(f"Cribs: {len(CRIB_POS)} positions (ENE 21-33, BC 63-73)")
    print()

    # Load all texts
    rkt_dir = os.path.join(os.path.dirname(__file__), '..', 'reference', 'running_key_texts')
    texts = {}
    for fn in sorted(os.listdir(rkt_dir)):
        if fn.endswith('.txt'):
            path = os.path.join(rkt_dir, fn)
            name = fn.replace('.txt', '')
            nums = load_text(path)
            texts[name] = nums
            print(f"  Loaded: {name} ({len(nums)} alpha chars)")

    print()

    all_results = []

    # ── Phase 1: Direct running key (no transposition) ──
    print("=" * 70)
    print("PHASE 1: Direct running key (no transposition)")
    print("  Testing mismatch levels 0, 1, 2 at all 24 crib positions")
    print("=" * 70)
    print()

    for text_name, text_nums in texts.items():
        print(f"  [{text_name}] scanning {len(text_nums)} chars...")
        hits = direct_running_key_scan(text_nums, text_name, max_mismatch=2)
        all_results.extend(hits)
        if not hits:
            print(f"    No matches at mismatch <= 2")
        print()

    phase1_count = len(all_results)

    # ── Phase 2: Width-7 columnar + running key ──
    print("=" * 70)
    print("PHASE 2: Width-7 columnar transposition + running key")
    print("  5040 orderings x 2 variants x 2 models (A, B)")
    print("  Score threshold: >= 18/24")
    print("=" * 70)
    print()

    for text_name, text_nums in texts.items():
        print(f"  [{text_name}] ({len(text_nums)} chars) x 5040 orderings x 2 variants...")
        t0 = time.time()
        hits = columnar_running_key_scan(text_nums, text_name, width=7, score_threshold=18)
        elapsed = time.time() - t0
        all_results.extend(hits)
        if not hits:
            print(f"    No hits >= 18")
        print(f"    Done in {elapsed:.1f}s")
        print()

    phase2_count = len(all_results) - phase1_count

    # ── Summary ──
    t_total = time.time() - t_start
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Texts tested: {list(texts.keys())}")
    print(f"  Phase 1 (direct): {phase1_count} hits at mismatch <= 2")
    print(f"  Phase 2 (w7 columnar): {phase2_count} hits >= 18/24")
    print(f"  Total time: {t_total:.1f}s ({t_total / 60:.1f} min)")

    if all_results:
        all_results.sort(key=lambda r: -(r.get('crib_score', 0) or r.get('score', 0)))
        print(f"\n  Top results:")
        for r in all_results[:20]:
            print(f"    {r['model']} {r['text']} {r['variant']} "
                  f"off={r['offset']} "
                  f"crib={r.get('crib_score', '?')}/24 "
                  f"mismatch={r.get('mismatches', '?')} "
                  f"IC={r.get('ic', '?')}")
            print(f"      PT: {r['plaintext'][:80]}")
    else:
        print(f"\n  No hits found.")

    # Verdict
    has_signal = any(r.get('crib_score', 0) >= 18 for r in all_results)
    has_exact_direct = any(r.get('mismatches', 99) == 0 for r in all_results)

    if has_signal:
        verdict = "SIGNAL"
    elif has_exact_direct:
        verdict = "EXACT_DIRECT_HIT_INVESTIGATE"
    elif phase1_count > 0:
        verdict = "NEAR_MISSES_ONLY"
    else:
        verdict = "ELIMINATED"

    print(f"\n  Verdict: {verdict}")

    if verdict == "ELIMINATED":
        print(f"  → These Berlin Wall speech texts are ELIMINATED as running key sources")
        print(f"    under direct Vigenere/Beaufort (mismatch <= 2)")
        print(f"    and under width-7 columnar transposition (score >= 18).")

    # Save
    os.makedirs("results", exist_ok=True)
    artifact = {
        "experiment": "E-S-135",
        "description": "Berlin Wall speech texts as running key sources",
        "texts_tested": {name: len(nums) for name, nums in texts.items()},
        "phase1": {
            "method": "Direct running key, no transposition",
            "max_mismatch": 2,
            "hits": phase1_count,
        },
        "phase2": {
            "method": "Width-7 columnar transposition + running key",
            "width": 7,
            "n_orderings": 5040,
            "score_threshold": 18,
            "hits": phase2_count,
        },
        "total_hits": len(all_results),
        "verdict": verdict,
        "elapsed_seconds": round(t_total, 1),
        "top_results": all_results[:20],
    }

    outpath = "results/e_s_135_berlin_wall_running_key.json"
    with open(outpath, "w") as f:
        json.dump(artifact, f, indent=2)

    print(f"\n  Artifact: {outpath}")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_135_berlin_wall_running_key.py")
    print(f"\nRESULT: phase1={phase1_count} phase2={phase2_count} verdict={verdict}")


if __name__ == "__main__":
    main()
