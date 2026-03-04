#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: transposition/columnar
Status: active
Keyspace: see implementation
Last run:
Best score:
"""
"""E-RERUN-03: Expanded Keyword Columnar + Myszkowski Sweep

Reruns E-S-53 logic with expanded thematic_keywords.txt (~290 words vs 120).
For each keyword:
  - Derive standard columnar ordering from keyword
  - Also test Myszkowski variant (tied columns)
  - Apply transposition both directions (Sub->Trans and Trans->Sub)
  - Test Vigenere/Beaufort/VarBeau at periods 2-14
  - Check crib matches and Bean constraint

attack(ciphertext, **params) -> list[tuple[float, str, str]]
    Standard attack interface.
    params: keywords (list[str], default from thematic_keywords.txt),
            threshold (int, default STORE_THRESHOLD)
"""

import json
import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS, CRIB_POSITIONS,
    BEAN_EQ, BEAN_INEQ,
    NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.transforms.transposition import (
    columnar_perm, myszkowski_perm, keyword_to_order,
    invert_perm, apply_perm, validate_perm,
)

REPO = Path(__file__).resolve().parents[1]

# -- Load keywords from expanded thematic_keywords.txt --

def load_thematic_keywords():
    path = REPO / "wordlists" / "thematic_keywords.txt"
    keywords = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            word = line.upper()
            if word.isalpha() and len(word) >= 3:
                keywords.append(word)
    return list(dict.fromkeys(keywords))

UNIQUE_KEYWORDS = load_thematic_keywords()

CT_IDX = [ALPH_IDX[c] for c in CT]


def derive_key_at_crib(ct_idx, pt_idx, variant):
    if variant == "vig":
        return (ct_idx - pt_idx) % MOD
    elif variant == "beau":
        return (ct_idx + pt_idx) % MOD
    elif variant == "varbeau":
        return (pt_idx - ct_idx) % MOD
    else:
        raise ValueError(f"Unknown variant: {variant}")


def check_period_consistency(key_vals, period):
    residue_vals = {}
    matches = 0
    for pos, kv in key_vals:
        r = pos % period
        if r in residue_vals:
            if residue_vals[r] == kv:
                matches += 1
        else:
            residue_vals[r] = kv
            matches += 1
    return matches


def check_bean(key_vals_dict, variant):
    if 27 in key_vals_dict and 65 in key_vals_dict:
        if key_vals_dict[27] != key_vals_dict[65]:
            return False
    for p1, p2 in BEAN_INEQ:
        if p1 in key_vals_dict and p2 in key_vals_dict:
            if key_vals_dict[p1] == key_vals_dict[p2]:
                return False
    return True


def _test_transposition_collect(perm, label, ct_idx, ct_len, threshold):
    """Core transposition test that returns results as list of dicts."""
    inv_perm = invert_perm(perm)
    collected = []

    for direction in [1, 2]:
        for variant in ["vig", "beau", "varbeau"]:
            key_vals = []
            key_dict = {}

            if direction == 1:
                # Sub then Trans: KEY[p] = derive(CT[inv_perm[p]], PT[p])
                for p, pt_ch in CRIB_DICT.items():
                    ct_pos = inv_perm[p]
                    ct_val = ct_idx[ct_pos]
                    pt_val = ALPH_IDX[pt_ch]
                    kv = derive_key_at_crib(ct_val, pt_val, variant)
                    key_vals.append((p, kv))
                    key_dict[p] = kv
            else:
                # Trans then Sub: KEY[i] = derive(CT[i], PT[perm[i]])
                for i in range(ct_len):
                    pt_pos = perm[i]
                    if pt_pos in CRIB_DICT:
                        pt_val = ALPH_IDX[CRIB_DICT[pt_pos]]
                        ct_val = ct_idx[i]
                        kv = derive_key_at_crib(ct_val, pt_val, variant)
                        key_vals.append((i, kv))
                        key_dict[i] = kv

            for period in range(2, 15):
                score = check_period_consistency(key_vals, period)
                if score >= threshold:
                    bean_ok = check_bean(key_dict, variant)
                    collected.append({
                        "keyword": label,
                        "type": label.split(":")[0],
                        "direction": direction,
                        "variant": variant,
                        "period": period,
                        "score": score,
                        "bean": bean_ok,
                    })

    return collected


def test_transposition(perm, label, results):
    """Original interface: appends to results list in-place."""
    collected = _test_transposition_collect(perm, label, CT_IDX, CT_LEN, STORE_THRESHOLD)
    results.extend(collected)


# -- Standard attack interface --

def attack(ciphertext: str, **params) -> list[tuple[float, str, str]]:
    """Standard attack interface. Returns [(score, plaintext, method_description), ...]"""
    keywords = params.get("keywords", UNIQUE_KEYWORDS)
    threshold = params.get("threshold", STORE_THRESHOLD)

    ct_len = len(ciphertext)
    ct_idx = [ALPH_IDX[c] for c in ciphertext]

    results = []

    for kw in keywords:
        width = len(kw)

        # Standard columnar
        order = keyword_to_order(kw, width)
        if order is not None:
            perm = columnar_perm(width, order, ct_len)
            if validate_perm(perm, ct_len):
                hits = _test_transposition_collect(perm, f"col:{kw}", ct_idx, ct_len, threshold)
                for h in hits:
                    bean_str = "BEAN_OK" if h["bean"] else "bean_fail"
                    desc = (f"columnar kw={h['keyword']} "
                            f"d={h['direction']} {h['variant']} "
                            f"p={h['period']} {bean_str}")
                    results.append((float(h["score"]), "", desc))

        # Myszkowski (only different if keyword has repeated letters)
        has_repeats = len(set(kw)) < len(kw)
        if has_repeats:
            perm_m = myszkowski_perm(kw, ct_len)
            if validate_perm(perm_m, ct_len):
                hits = _test_transposition_collect(perm_m, f"mysz:{kw}", ct_idx, ct_len, threshold)
                for h in hits:
                    bean_str = "BEAN_OK" if h["bean"] else "bean_fail"
                    desc = (f"myszkowski kw={h['keyword']} "
                            f"d={h['direction']} {h['variant']} "
                            f"p={h['period']} {bean_str}")
                    results.append((float(h["score"]), "", desc))

    results.sort(key=lambda x: -x[0])
    return results


def main():
    print("=" * 70)
    print("E-RERUN-03: Expanded Keyword Columnar + Myszkowski Sweep")
    print("=" * 70)
    print(f"Source: wordlists/thematic_keywords.txt")
    print(f"Keywords: {len(UNIQUE_KEYWORDS)}")
    print(f"Width range: {min(len(k) for k in UNIQUE_KEYWORDS)}-{max(len(k) for k in UNIQUE_KEYWORDS)}")
    print()

    t0 = time.time()
    results = []
    total_configs = 0

    for ki, kw in enumerate(UNIQUE_KEYWORDS):
        width = len(kw)

        # Standard columnar
        order = keyword_to_order(kw, width)
        if order is not None:
            perm = columnar_perm(width, order, CT_LEN)
            if validate_perm(perm, CT_LEN):
                test_transposition(perm, f"col:{kw}", results)
                total_configs += 2 * 3 * 13

        # Myszkowski (only different if keyword has repeated letters)
        has_repeats = len(set(kw)) < len(kw)
        if has_repeats:
            perm_m = myszkowski_perm(kw, CT_LEN)
            if validate_perm(perm_m, CT_LEN):
                test_transposition(perm_m, f"mysz:{kw}", results)
                total_configs += 2 * 3 * 13

        if (ki + 1) % 50 == 0:
            cur_best = max((r["score"] for r in results), default=0)
            print(f"  Keyword {ki+1}/{len(UNIQUE_KEYWORDS)}: configs={total_configs} "
                  f"hits(>={STORE_THRESHOLD})={len(results)} best={cur_best}/24 [{time.time()-t0:.1f}s]")

    elapsed = time.time() - t0
    results.sort(key=lambda r: (-r["score"], -r["bean"]))

    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Keywords: {len(UNIQUE_KEYWORDS)}")
    print(f"  Total configs: {total_configs}")
    print(f"  Hits >={STORE_THRESHOLD}: {len(results)}")
    print(f"  Time: {elapsed:.1f}s")
    print()

    best_score = 0
    if results:
        print(f"  Top 20 results:")
        for r in results[:20]:
            bean_str = "BEAN_OK" if r["bean"] else "bean_fail"
            print(f"    {r['score']}/24 p={r['period']} d={r['direction']} "
                  f"{r['variant']} {r['keyword']} {bean_str}")
        best_config = results[0]
        best_score = best_config["score"]
    else:
        print("  No results above threshold!")

    print(f"\n  Best score: {best_score}/24")

    if best_score <= NOISE_FLOOR:
        verdict = "ELIMINATED -- all at noise floor"
    elif best_score <= 14:
        verdict = f"WEAK -- best {best_score}/24, likely noise"
    else:
        verdict = f"INVESTIGATE -- best {best_score}/24"

    print(f"  Verdict: {verdict}")

    if results:
        from collections import Counter
        width_dist = Counter()
        period_dist = Counter()
        for r in results:
            kw = r["keyword"].split(":", 1)[1] if ":" in r["keyword"] else r["keyword"]
            width_dist[len(kw)] += 1
            period_dist[r["period"]] += 1
        print(f"\n  Width distribution of hits: {dict(sorted(width_dist.items()))}")
        print(f"  Period distribution of hits: {dict(sorted(period_dist.items()))}")

    # Compare with original E-S-53
    print(f"\n  Comparison with original E-S-53:")
    print(f"    Original keywords: ~120")
    print(f"    Expanded keywords: {len(UNIQUE_KEYWORDS)}")
    print(f"    New keywords tested: ~{len(UNIQUE_KEYWORDS) - 120}")

    artifact = {
        "experiment": "E-RERUN-03",
        "description": "Expanded keyword columnar + Myszkowski sweep",
        "source_wordlist": "wordlists/thematic_keywords.txt",
        "n_keywords": len(UNIQUE_KEYWORDS),
        "total_configs": total_configs,
        "n_hits": len(results),
        "best_score": best_score,
        "best_config": results[0] if results else None,
        "verdict": verdict,
        "elapsed_seconds": elapsed,
        "top_20": results[:20],
    }

    import os
    os.makedirs(REPO / "results", exist_ok=True)
    with open(REPO / "results" / "e_rerun_03_columnar_expanded.json", "w") as f:
        json.dump(artifact, f, indent=2)

    print(f"\n  Artifact: results/e_rerun_03_columnar_expanded.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_rerun_03_columnar_expanded.py")


if __name__ == "__main__":
    main()
