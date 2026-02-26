#!/usr/bin/env python3
"""E-RERUN-01: Expanded Thematic Keywords as Cipher Keys + Bean-Width Columnar

Reruns E-OPGOLD-01 logic with the expanded thematic_keywords.txt (~290 words
vs original 19). Tests each keyword as a periodic Vigenere/Beaufort/VarBeau key
combined with columnar transposition at Bean-compatible widths.

Width 8: exhaustive orderings (40,320).
Widths >8: identity, reverse, cyclic shifts (~2*width orderings each).
"""

import itertools
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_WORDS, N_CRIBS,
    NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.constraints.bean import verify_bean
from kryptos.kernel.transforms.transposition import (
    columnar_perm, invert_perm, apply_perm,
)

REPO = Path(__file__).resolve().parents[1]
N = CT_LEN
CT_NUM = [ALPH_IDX[c] for c in CT]

# ── Load keywords from expanded thematic_keywords.txt ────────────────────

def load_thematic_keywords():
    """Load keywords from thematic_keywords.txt, skipping comments and blanks."""
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
    return list(dict.fromkeys(keywords))  # deduplicate preserving order

KEYWORDS = load_thematic_keywords()

BEAN_WIDTHS = [8, 13, 16, 19, 20, 23, 24, 26]

# ── Helpers ───────────────────────────────────────────────────────────────

def keyword_to_key(keyword: str, length: int = N) -> list[int]:
    kw_num = [ALPH_IDX[c] for c in keyword.upper()]
    return [kw_num[i % len(kw_num)] for i in range(length)]


def decrypt_vig(ct_num, key):
    return "".join(ALPH[(c - k) % MOD] for c, k in zip(ct_num, key))

def decrypt_beau(ct_num, key):
    return "".join(ALPH[(k - c) % MOD] for c, k in zip(ct_num, key))

def decrypt_varbeau(ct_num, key):
    return "".join(ALPH[(c + k) % MOD] for c, k in zip(ct_num, key))

VARIANTS = [
    ("Vigenere", decrypt_vig),
    ("Beaufort", decrypt_beau),
    ("VarBeau", decrypt_varbeau),
]

def count_crib_matches(pt):
    return sum(1 for pos, ch in CRIB_DICT.items() if pos < len(pt) and pt[pos] == ch)

def compute_keystream(ct_num, pt, variant):
    ks = []
    for i in range(len(pt)):
        c = ct_num[i]
        p = ALPH_IDX[pt[i]]
        if variant == "Vigenere":
            ks.append((c - p) % MOD)
        elif variant == "Beaufort":
            ks.append((c + p) % MOD)
        else:
            ks.append((p - c) % MOD)
    return ks


def generate_orderings_for_width(width):
    if width <= 8:
        yield from itertools.permutations(range(width))
    else:
        yield tuple(range(width))
        yield tuple(range(width - 1, -1, -1))
        for shift in range(1, width):
            yield tuple((i + shift) % width for i in range(width))
        base = list(range(width - 1, -1, -1))
        for shift in range(1, width):
            yield tuple(base[(i + shift) % width] for i in range(width))


# ── Test 1: Direct polyalphabetic substitution ────────────────────────────

def test_direct_substitution():
    print("=" * 70)
    print("TEST 1: Direct Polyalphabetic Substitution (keyword repeated)")
    print(f"Keywords: {len(KEYWORDS)}")
    print("=" * 70)

    results = []
    for kw in KEYWORDS:
        key = keyword_to_key(kw)
        period = len(kw)
        for var_name, dec_fn in VARIANTS:
            pt = dec_fn(CT_NUM, key)
            cribs = count_crib_matches(pt)
            ks = compute_keystream(CT_NUM, pt, var_name)
            bean = verify_bean(ks)
            results.append({
                "keyword": kw, "variant": var_name, "period": period,
                "cribs": cribs, "bean_pass": bean.passed, "pt_preview": pt[:40],
            })
            if cribs > NOISE_FLOOR:
                print(f"  [ABOVE NOISE] {kw:22s} {var_name:10s} "
                      f"cribs={cribs:2d}/{N_CRIBS} bean={'PASS' if bean.passed else 'FAIL'}")

    results.sort(key=lambda r: -r["cribs"])
    print(f"\nTotal direct configs: {len(results)}")
    print(f"\nTop 15 by crib score:")
    print(f"{'Keyword':22s} {'Variant':10s} {'Per':>3s} {'Cribs':>5s} {'Bean':>5s}")
    print("-" * 55)
    for r in results[:15]:
        print(f"{r['keyword']:22s} {r['variant']:10s} {r['period']:3d} "
              f"{r['cribs']:5d} {'PASS' if r['bean_pass'] else 'FAIL':>5s}")
    return results


# ── Test 2: Transposition + Substitution ──────────────────────────────────

def test_transposition_substitution():
    print("\n" + "=" * 70)
    print("TEST 2: Columnar Transposition + Polyalphabetic Substitution")
    print(f"Keywords: {len(KEYWORDS)}, Bean widths: {BEAN_WIDTHS}")
    print("=" * 70)

    results = []
    total_configs = 0
    best_score = 0

    for width in BEAN_WIDTHS:
        orderings = list(generate_orderings_for_width(width))
        n_orderings = len(orderings)
        print(f"\n  Width {width:2d}: {n_orderings:,} orderings x {len(KEYWORDS)} keywords x 3 variants")

        width_best = 0
        width_t0 = time.time()

        for col_order in orderings:
            perm = columnar_perm(width, col_order, N)
            inv = invert_perm(perm)
            intermediate = apply_perm(CT, inv)
            int_num = [ALPH_IDX[c] for c in intermediate]

            for kw in KEYWORDS:
                key = keyword_to_key(kw)
                for var_name, dec_fn in VARIANTS:
                    pt = dec_fn(int_num, key)
                    cribs = count_crib_matches(pt)
                    total_configs += 1

                    if cribs > width_best:
                        width_best = cribs
                    if cribs > best_score:
                        best_score = cribs

                    if cribs >= STORE_THRESHOLD:
                        ks = compute_keystream(int_num, pt, var_name)
                        bean = verify_bean(ks)
                        sb = score_candidate(pt, bean_result=bean)
                        results.append({
                            "keyword": kw, "variant": var_name, "width": width,
                            "col_order": list(col_order), "cribs": cribs,
                            "bean_pass": bean.passed, "score_summary": sb.summary,
                            "pt_preview": pt[:50],
                        })
                        print(f"    [STORE] w={width} {kw:22s} {var_name:10s} "
                              f"cribs={cribs:2d} {sb.summary}")
                    elif cribs > NOISE_FLOOR:
                        results.append({
                            "keyword": kw, "variant": var_name, "width": width,
                            "col_order": list(col_order), "cribs": cribs,
                            "bean_pass": None, "score_summary": None,
                            "pt_preview": pt[:50],
                        })

        elapsed_w = time.time() - width_t0
        print(f"  Width {width:2d} done in {elapsed_w:.1f}s -- best cribs: {width_best}")

    results.sort(key=lambda r: -r["cribs"])
    print(f"\nTotal transposition configs tested: {total_configs:,}")
    print(f"Results above noise: {len(results)}")
    print(f"Best crib score: {best_score}")

    if results:
        print(f"\nTop 20 by crib score:")
        print(f"{'Keyword':22s} {'Var':10s} {'W':>3s} {'Cribs':>5s} {'Bean':>5s} {'Summary'}")
        print("-" * 90)
        for r in results[:20]:
            bean_str = "PASS" if r["bean_pass"] else ("FAIL" if r["bean_pass"] is not None else "?")
            summary = r["score_summary"] or ""
            print(f"{r['keyword']:22s} {r['variant']:10s} {r['width']:3d} "
                  f"{r['cribs']:5d} {bean_str:>5s} {summary}")
    return results


# ── Main ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    t0 = time.time()
    print("E-RERUN-01: Expanded Thematic Keywords (opgold_01 method)")
    print(f"Source: wordlists/thematic_keywords.txt")
    print(f"Keywords loaded: {len(KEYWORDS)}")
    print(f"Variants: {[v[0] for v in VARIANTS]}")
    print(f"Bean widths: {BEAN_WIDTHS}")
    print()

    r1 = test_direct_substitution()
    r2 = test_transposition_substitution()

    elapsed = time.time() - t0

    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)

    all_results = r1 + r2
    all_results.sort(key=lambda r: -r["cribs"])

    best = all_results[0] if all_results else None
    if best:
        print(f"Best overall: cribs={best['cribs']}/{N_CRIBS} -- "
              f"{best['keyword']} / {best['variant']}")
        if best.get("width"):
            print(f"  Width: {best['width']}, Col order: {best.get('col_order', 'N/A')}")
        print(f"  PT preview: {best['pt_preview']}")

    above_noise = [r for r in all_results if r["cribs"] > NOISE_FLOOR]
    store_level = [r for r in all_results if r["cribs"] >= STORE_THRESHOLD]
    print(f"\nAbove noise (>{NOISE_FLOOR}): {len(above_noise)}")
    print(f"Store level (>={STORE_THRESHOLD}): {len(store_level)}")
    print(f"Elapsed: {elapsed:.1f}s")

    if best and best["cribs"] >= 18:
        classification = "SIGNAL"
    elif best and best["cribs"] >= 10:
        classification = "STORE"
    elif best and best["cribs"] > 6:
        classification = "ABOVE_NOISE"
    else:
        classification = "NOISE"

    print(f"Classification: {classification}")

    os.makedirs(REPO / "results", exist_ok=True)
    artifact = {
        "experiment": "E-RERUN-01",
        "name": "Expanded Thematic Keywords (opgold_01 method)",
        "source_wordlist": "wordlists/thematic_keywords.txt",
        "elapsed_seconds": elapsed,
        "total_keywords": len(KEYWORDS),
        "classification": classification,
        "best_score": best["cribs"] if best else 0,
        "best_config": best if best else None,
        "direct_top10": r1[:10],
        "transposition_top20": r2[:20],
    }
    artifact_path = REPO / "results" / "e_rerun_01_opgold_expanded.json"
    with open(artifact_path, "w") as f:
        json.dump(artifact, f, indent=2, default=str)

    print(f"\nArtifact: {artifact_path}")
    print(f"\n{'=' * 70}")
    print(f"E-RERUN-01 COMPLETE -- {elapsed:.1f}s -- {classification}")
    print(f"{'=' * 70}")
