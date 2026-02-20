#!/usr/bin/env python3
"""E-S-59: Width-7 Grid + Non-Periodic Substitution Deep Probe.

Given the crib alignment at width 7 (p=0.021, E-S-58 Phase C), test ALL 5040
width-7 columnar orderings with non-periodic substitution analysis.

For each ordering σ, derive the keystream at the 24 crib positions under both
Model A (sub→trans) and Model B (trans→sub). Then analyze the keystream:

1. Sorted by CT/PT position: do key values form readable text fragments?
2. Key quadgram score: does the key look like English text?
3. Key smoothness: are adjacent-position key values similar (suggesting tabular lookup)?
4. Key matching Carter text at various offsets (optimized)
5. Bigram score of key when read as text

Additionally: test if any width-7 ordering produces a keystream that matches
the COMPLEMENT cipher (K4 CT is the running key, and the PT+CT produces
a known text as the key).
"""
import json
import time
import sys
import os
import math
from collections import Counter, defaultdict
from itertools import permutations

sys.path.insert(0, "src")

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_DICT, N_CRIBS, CRIB_POSITIONS,
    BEAN_EQ,
)

CT_IDX = [ALPH_IDX[c] for c in CT]
PT_IDX = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}

CRIB_POS_SORTED = sorted(CRIB_POSITIONS)

# Load quadgram data if available
QUADGRAMS = None
QG_FLOOR = -10.0
try:
    qg_path = "data/english_quadgrams.json"
    if os.path.exists(qg_path):
        import json as _json
        with open(qg_path) as f:
            qg_data = _json.load(f)
        if "logp" in qg_data:
            QUADGRAMS = qg_data["logp"]
        print(f"Loaded quadgrams: {len(QUADGRAMS) if QUADGRAMS else 0} entries")
except Exception as e:
    print(f"Quadgram load failed: {e}")


def quadgram_score(text):
    """Log-probability score of text based on English quadgrams."""
    if not QUADGRAMS or len(text) < 4:
        return 0.0
    score = 0.0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        score += QUADGRAMS.get(qg, QG_FLOOR)
    return score / max(1, len(text) - 3)


def ic_of_values(vals):
    n = len(vals)
    if n < 2:
        return 0.0
    counts = Counter(vals)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def columnar_perm(order, text_len):
    width = len(order)
    n_full_rows = text_len // width
    extra = text_len % width
    col_heights = [n_full_rows + (1 if c < extra else 0) for c in range(width)]
    perm = []
    for read_idx in range(width):
        col = order[read_idx]
        for row in range(col_heights[col]):
            pt_pos = row * width + col
            perm.append(pt_pos)
    return perm


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def keyword_to_order(keyword):
    indexed = sorted(range(len(keyword)), key=lambda i: (keyword[i], i))
    order = [0] * len(keyword)
    for col, rank in enumerate(indexed):
        order[col] = rank
    read_order = [0] * len(keyword)
    for col, rank in enumerate(order):
        read_order[rank] = col
    return read_order


# Load Carter text for running key comparison
CARTER_TEXT = ""
for path in ["reference/carter_vol1_extract.txt", "reference/carter_vol1.txt"]:
    if os.path.exists(path):
        try:
            with open(path) as f:
                text = f.read().upper()
                text = ''.join(c for c in text if c in ALPH)
                if len(text) > len(CARTER_TEXT):
                    CARTER_TEXT = text
        except:
            pass

CARTER_IDX = [ALPH_IDX[c] for c in CARTER_TEXT] if CARTER_TEXT else []
print(f"Carter text: {len(CARTER_TEXT)} chars")


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-S-59: Width-7 Grid + Non-Periodic Substitution Deep Probe")
    print("=" * 70)
    print(f"Testing all 5040 width-7 orderings")
    print(f"Models: A (sub→trans), B (trans→sub)")
    print(f"Variants: Vigenère, Beaufort")
    print()

    results = {
        "experiment": "E-S-59",
        "top_configs": [],
    }

    # For each ordering, analyze keystream quality
    top_results = []  # (composite_score, details)

    n_tested = 0
    n_bean_pass = 0

    for order in permutations(range(7)):
        order = list(order)
        n_tested += 1

        perm = columnar_perm(order, CT_LEN)
        inv_perm = invert_perm(perm)

        for variant in ["vig", "beau"]:
            for model in ["A", "B"]:
                # Derive keystream at crib positions
                key_at_pos = {}  # position → key value

                if model == "B":
                    # Trans then Sub: CT[i] = PT[perm[i]] + k[i]
                    # k[inv_perm[p]] = CT[inv_perm[p]] - PT[p] (Vig)
                    # k[inv_perm[p]] = CT[inv_perm[p]] + PT[p] (Beau)
                    for p in CRIB_POS_SORTED:
                        ct_pos = inv_perm[p]
                        if variant == "vig":
                            key_at_pos[ct_pos] = (CT_IDX[ct_pos] - PT_IDX[p]) % MOD
                        else:
                            key_at_pos[ct_pos] = (CT_IDX[ct_pos] + PT_IDX[p]) % MOD
                else:
                    # Sub then Trans: CT[inv_perm[p]] = PT[p] + k[p]
                    # k[p] = CT[inv_perm[p]] - PT[p] (Vig)
                    # k[p] = CT[inv_perm[p]] + PT[p] (Beau)
                    for p in CRIB_POS_SORTED:
                        ct_pos = inv_perm[p]
                        if variant == "vig":
                            key_at_pos[p] = (CT_IDX[ct_pos] - PT_IDX[p]) % MOD
                        else:
                            key_at_pos[p] = (CT_IDX[ct_pos] + PT_IDX[p]) % MOD

                # Sort key by position
                sorted_positions = sorted(key_at_pos.keys())
                key_sorted = [key_at_pos[pos] for pos in sorted_positions]
                key_text = ''.join(ALPH[v] for v in key_sorted)

                # Bean check: under the relevant model, do k[27] = k[65]?
                # For Model A: k[27] and k[65] are at PT positions 27 and 65
                # For Model B: k[inv_perm[27]] and k[inv_perm[65]] are at CT positions
                bean_pass = False
                if model == "A":
                    if 27 in key_at_pos and 65 in key_at_pos:
                        bean_pass = (key_at_pos[27] == key_at_pos[65])
                else:
                    bp27 = inv_perm[27]
                    bp65 = inv_perm[65]
                    if bp27 in key_at_pos and bp65 in key_at_pos:
                        bean_pass = (key_at_pos[bp27] == key_at_pos[bp65])

                if bean_pass:
                    n_bean_pass += 1

                # Metrics
                ic = ic_of_values(key_sorted)

                # Quadgram score of key text
                qg = quadgram_score(key_text)

                # Smoothness: average absolute difference between adjacent key values
                smoothness = 0.0
                if len(sorted_positions) >= 2:
                    adj_diffs = []
                    for i in range(len(sorted_positions) - 1):
                        d = abs(key_sorted[i] - key_sorted[i+1])
                        d = min(d, 26 - d)  # circular distance
                        adj_diffs.append(d)
                    smoothness = sum(adj_diffs) / len(adj_diffs)

                # Carter running key check (optimized: precompute, check every 100th offset)
                carter_best = 0
                carter_offset = 0
                if CARTER_IDX:
                    max_off = min(len(CARTER_IDX) - max(sorted_positions) - 1, len(CARTER_IDX))
                    step = max(1, max_off // 5000)
                    for off in range(0, max_off, step):
                        matches = 0
                        for pos in sorted_positions:
                            if pos + off < len(CARTER_IDX):
                                if CARTER_IDX[pos + off] == key_at_pos[pos]:
                                    matches += 1
                        if matches > carter_best:
                            carter_best = matches
                            carter_offset = off

                # Composite score: weight IC, quadgram, Bean, carter
                composite = (
                    (1.0 if bean_pass else 0.0) * 5.0 +
                    ic * 100.0 +
                    (qg + 10.0) * 2.0 +  # qg is negative, floor ~-10
                    carter_best * 0.5
                )

                if composite > 8.0 or bean_pass or carter_best >= 7 or qg > -7.0:
                    top_results.append((composite, {
                        "order": order,
                        "model": model,
                        "variant": variant,
                        "key_text": key_text,
                        "ic": round(ic, 4),
                        "qg_score": round(qg, 2),
                        "smoothness": round(smoothness, 2),
                        "carter_best": carter_best,
                        "carter_offset": carter_offset,
                        "bean_pass": bean_pass,
                        "composite": round(composite, 2),
                    }))

        if n_tested % 1000 == 0:
            print(f"  [{n_tested:5d}/5040] top_results={len(top_results)} bean_pass={n_bean_pass} "
                  f"({time.time()-t0:.1f}s)")

    # Sort by composite score
    top_results.sort(key=lambda x: -x[0])

    elapsed = time.time() - t0

    print(f"\n{'='*70}")
    print(f"RESULTS")
    print(f"{'='*70}")
    print(f"  Orderings tested: {n_tested}")
    print(f"  Bean-passing configs: {n_bean_pass}")
    print(f"  Saved results: {len(top_results)}")
    print(f"  Time: {elapsed:.1f}s")

    # Show top 20
    print(f"\n  Top 20 by composite score:")
    for i, (comp, d) in enumerate(top_results[:20]):
        bean_flag = "✓" if d["bean_pass"] else " "
        print(f"  {i+1:3d}. comp={comp:6.2f} bean={bean_flag} "
              f"{d['model']}_{d['variant']} order={d['order']} "
              f"IC={d['ic']:.4f} qg={d['qg_score']:.2f} "
              f"smooth={d['smoothness']:.1f} carter={d['carter_best']} "
              f"key={d['key_text']}")

    # Show all Bean-passing configs
    bean_configs = [(comp, d) for comp, d in top_results if d["bean_pass"]]
    if bean_configs:
        print(f"\n  All Bean-passing configs ({len(bean_configs)}):")
        for comp, d in bean_configs[:30]:
            print(f"    comp={comp:6.2f} {d['model']}_{d['variant']} "
                  f"order={d['order']} key={d['key_text']} "
                  f"IC={d['ic']:.4f} qg={d['qg_score']:.2f}")

    # Show configs with Carter match >= 6
    carter_hits = [(comp, d) for comp, d in top_results if d["carter_best"] >= 6]
    if carter_hits:
        print(f"\n  Carter matches ≥ 6 ({len(carter_hits)}):")
        for comp, d in carter_hits[:20]:
            print(f"    carter={d['carter_best']} offset={d['carter_offset']} "
                  f"{d['model']}_{d['variant']} order={d['order']} "
                  f"key={d['key_text']}")

    # Quadgram distribution
    qg_scores = [d["qg_score"] for _, d in top_results]
    if qg_scores:
        print(f"\n  Quadgram score distribution:")
        print(f"    Best: {max(qg_scores):.2f}")
        print(f"    Median: {sorted(qg_scores)[len(qg_scores)//2]:.2f}")
        for thresh in [-6.0, -7.0, -8.0]:
            count = sum(1 for s in qg_scores if s > thresh)
            print(f"    qg > {thresh}: {count} configs")

    # Verdict
    has_signal = any(d["bean_pass"] and d["carter_best"] >= 8 for _, d in top_results)
    if has_signal:
        verdict = "SIGNAL — Bean-passing config with Carter match"
    elif bean_configs:
        verdict = f"INTERESTING — {len(bean_configs)} Bean-passing configs, investigate"
    else:
        verdict = "NO SIGNAL — no Bean-passing or high-scoring configs"

    print(f"\n  Verdict: {verdict}")

    results["n_tested"] = n_tested
    results["n_bean_pass"] = n_bean_pass
    results["elapsed_seconds"] = elapsed
    results["verdict"] = verdict
    results["top_configs"] = [d for _, d in top_results[:100]]

    os.makedirs("results", exist_ok=True)
    with open("results/e_s_59_width7_nonperiodic.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n  Artifact: results/e_s_59_width7_nonperiodic.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_59_width7_nonperiodic.py")


if __name__ == "__main__":
    main()
