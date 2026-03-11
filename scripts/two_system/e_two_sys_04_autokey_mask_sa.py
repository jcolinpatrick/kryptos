#!/usr/bin/env python3
# Cipher:     Two-system Model A (null removal + autokey)
# Family:     two_system
# Status:     active
# Keyspace:   ~340 keywords x 12 cipher combos x 4 restarts x 50K SA iters = ~816M evals
# Last run:
# Best score:
#
# E-TWO-SYS-04: Autokey + null mask SA.
#
# Model A + autokey (NOT periodic) on 73-char reduced text.
# SA searches for null masks while free-crib scoring detects signal.
#
# For each keyword × {PT-autokey, CT-autokey} × {Vig, Beau, VBeau} × {AZ, KA}:
#   SA over null-mask space (24 of 73 non-crib positions):
#     Each SA step: remove nulls → autokey decrypt 73 chars → free crib score
#
# This is the strongest untested combination: autokey is historically plausible
# (Scheidt era), and SA with free-crib scoring catches cribs at ANY position.
from __future__ import annotations

import math
import os
import random
import sys
import time
import multiprocessing as mp

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, KRYPTOS_ALPHABET,
)

# ── Constants ─────────────────────────────────────────────────────────────

REDUCED_LEN = 73
N_NULLS = 24

CRIB_ENE = "EASTNORTHEAST"
CRIB_BC = "BERLINCLOCK"
CRIB_LIST = sorted(CRIB_DICT.items())

# SA parameters
SA_ITERATIONS = 50_000
SA_RESTARTS = 4
SA_T_INIT = 2.0
SA_T_MIN = 0.01
SA_COOLING = 0.99993   # tuned for 50K iterations

REPORT_THRESHOLD = 6
N_WORKERS = min(28, os.cpu_count() or 4)

# Alphabets
ALPHABETS = {
    "AZ": (ALPH, {c: i for i, c in enumerate(ALPH)}),
    "KA": (KRYPTOS_ALPHABET, {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}),
}

# Cipher variants
def vig_dec(c, k): return (c - k) % MOD
def beau_dec(c, k): return (k - c) % MOD
def vbeau_dec(c, k): return (c + k) % MOD

CIPHERS = {
    "Vig": vig_dec,
    "Beau": beau_dec,
    "VBeau": vbeau_dec,
}

# Keywords: thematic set expanded to ~340
THEMATIC_KEYWORDS_FILE = os.path.join(
    os.path.dirname(__file__), '..', '..', 'wordlists', 'thematic_keywords.txt'
)

PRIORITY_KEYWORDS = [
    "KRYPTOS", "KOMPASS", "DEFECTOR", "COLOPHON", "ABSCISSA",
    "SHADOW", "CIPHER", "SECRET", "BERLIN", "CLOCK",
    "PALIMPSEST", "QUAGMIRE", "COMPASS", "LODESTONE",
    "MAGNETIC", "BURIED", "HIDDEN", "LANGLEY", "SCULPTURE",
    "ENIGMA", "SANBORN", "SCHEIDT",
]


def load_keywords() -> list:
    """Load thematic keywords, falling back to priority list."""
    keywords = set(PRIORITY_KEYWORDS)
    if os.path.exists(THEMATIC_KEYWORDS_FILE):
        with open(THEMATIC_KEYWORDS_FILE) as f:
            for line in f:
                w = line.strip().upper()
                if 3 <= len(w) <= 20 and w.isalpha():
                    keywords.add(w)
    return sorted(keywords)


# ── Autokey decryption (fast, numeric) ────────────────────────────────────

def decrypt_pt_autokey_fast(ct_ords: list, kw_indices: list, dec_fn, alph_str: str) -> str:
    """PT-autokey decryption returning string."""
    klen = len(kw_indices)
    key = list(kw_indices)
    result = []
    for i in range(len(ct_ords)):
        p = dec_fn(ct_ords[i], key[i])
        result.append(alph_str[p])
        key.append(p)
    return "".join(result)


def decrypt_ct_autokey_fast(ct_ords: list, kw_indices: list, dec_fn, alph_str: str) -> str:
    """CT-autokey decryption returning string."""
    klen = len(kw_indices)
    result = []
    key = list(kw_indices)
    for i in range(len(ct_ords)):
        if i >= klen:
            key.append(ct_ords[i - klen])
        p = dec_fn(ct_ords[i], key[i])
        result.append(alph_str[p])
    return "".join(result)


# ── Scoring ───────────────────────────────────────────────────────────────

def score_combined(pt: str, orig_to_reduced: dict) -> float:
    """Combined score: mapped crib hits + free crib bonus.

    Returns float score where:
      - Each mapped crib hit = 1.0
      - Full ENE found anywhere = 13.0 bonus
      - Full BC found anywhere = 11.0 bonus
      - Partial crib (best sliding window) = 0.1 per char
    """
    # Mapped crib hits
    mapped = 0
    for orig_pos, expected in CRIB_LIST:
        if orig_pos in orig_to_reduced:
            rpos = orig_to_reduced[orig_pos]
            if rpos < len(pt) and pt[rpos] == expected:
                mapped += 1

    # Free crib search
    free = 0
    if CRIB_ENE in pt:
        free += 13
    if CRIB_BC in pt:
        free += 11

    return max(mapped, free)


def score_fast_autokey(null_sorted: list, ct_full: str, keyword: str,
                       kw_indices: list, c2i: dict, alph_str: str,
                       dec_fn, autokey_mode: str) -> float:
    """Fast SA scoring for autokey: remove nulls, decrypt, score.

    Returns combined score (crib hits or free crib).
    """
    # Build reduced CT
    null_set = set(null_sorted)
    reduced_ct_ords = []
    orig_to_reduced = {}
    ridx = 0
    for i in range(CT_LEN):
        if i not in null_set:
            reduced_ct_ords.append(c2i[ct_full[i]])
            orig_to_reduced[i] = ridx
            ridx += 1

    # Decrypt with autokey
    if autokey_mode == "pt":
        pt = decrypt_pt_autokey_fast(reduced_ct_ords, kw_indices, dec_fn, alph_str)
    else:
        pt = decrypt_ct_autokey_fast(reduced_ct_ords, kw_indices, dec_fn, alph_str)

    return score_combined(pt, orig_to_reduced), pt


# ── SA search ─────────────────────────────────────────────────────────────

def sa_search(args: dict) -> list:
    """SA search for null mask optimizing autokey + crib score."""
    keyword = args["keyword"]
    cipher_name = args["cipher_name"]
    alph_name = args["alph_name"]
    autokey_mode = args["autokey_mode"]
    rng_seed = args["rng_seed"]

    alph_str, c2i = ALPHABETS[alph_name]
    dec_fn = CIPHERS[cipher_name]

    try:
        kw_indices = [c2i[c] for c in keyword]
    except KeyError:
        return []

    rng = random.Random(rng_seed)
    results = []

    # Available positions for nulls (non-crib only)
    available = sorted(set(range(CT_LEN)) - CRIB_POSITIONS)

    best_overall_score = -1
    best_overall = None

    for restart in range(SA_RESTARTS):
        # Initialize random null mask
        free_nulls = rng.sample(available, N_NULLS)
        free_null_set = set(free_nulls)
        non_null_list = [p for p in available if p not in free_null_set]

        null_sorted = sorted(free_nulls)
        current_score, current_pt = score_fast_autokey(
            null_sorted, CT, keyword, kw_indices, c2i, alph_str,
            dec_fn, autokey_mode
        )

        best_score = current_score
        best_nulls = list(free_nulls)
        best_pt = current_pt

        temp = SA_T_INIT
        for iteration in range(SA_ITERATIONS):
            # Swap: remove one null, add one non-null
            ri = rng.randrange(N_NULLS)
            ai = rng.randrange(len(non_null_list))
            remove_pos = free_nulls[ri]
            add_pos = non_null_list[ai]

            free_nulls[ri] = add_pos
            non_null_list[ai] = remove_pos

            null_sorted = sorted(free_nulls)
            new_score, new_pt = score_fast_autokey(
                null_sorted, CT, keyword, kw_indices, c2i, alph_str,
                dec_fn, autokey_mode
            )

            delta = new_score - current_score
            if delta > 0 or (delta == 0 and rng.random() < 0.5):
                current_score = new_score
                current_pt = new_pt
                if current_score > best_score:
                    best_score = current_score
                    best_nulls = list(free_nulls)
                    best_pt = current_pt
            elif temp > SA_T_MIN and rng.random() < math.exp(delta / temp):
                current_score = new_score
                current_pt = new_pt
            else:
                free_nulls[ri] = remove_pos
                non_null_list[ai] = add_pos

            temp *= SA_COOLING

        if best_score >= REPORT_THRESHOLD:
            results.append({
                "keyword": keyword,
                "cipher": cipher_name,
                "alphabet": alph_name,
                "autokey_mode": autokey_mode,
                "null_positions": sorted(best_nulls),
                "score": best_score,
                "plaintext": best_pt,
                "restart": restart,
            })

        if best_score > best_overall_score:
            best_overall_score = best_score
            best_overall = {
                "keyword": keyword,
                "cipher": cipher_name,
                "alphabet": alph_name,
                "autokey_mode": autokey_mode,
                "null_positions": sorted(best_nulls),
                "score": best_score,
                "plaintext": best_pt,
                "restart": restart,
            }

    # Always include best from all restarts
    if best_overall and best_overall not in results:
        results.append(best_overall)

    return results


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    t0 = time.time()
    keywords = load_keywords()

    print("=" * 78)
    print("E-TWO-SYS-04: Autokey + null mask SA")
    print("=" * 78)
    print(f"\nCT ({CT_LEN} chars): {CT}")
    print(f"Keywords: {len(keywords)}")
    print(f"Autokey modes: PT-autokey, CT-autokey")
    print(f"Ciphers: {', '.join(CIPHERS.keys())}")
    print(f"Alphabets: {', '.join(ALPHABETS.keys())}")
    print(f"SA: {SA_ITERATIONS:,} iterations × {SA_RESTARTS} restarts per config")
    print(f"Report threshold: {REPORT_THRESHOLD}")
    print(f"Workers: {N_WORKERS}")

    total_configs = len(keywords) * 2 * len(CIPHERS) * len(ALPHABETS)
    total_sa_evals = total_configs * SA_RESTARTS * SA_ITERATIONS
    print(f"Total configs: {total_configs:,}")
    print(f"Total SA evaluations: {total_sa_evals:,}")
    print()
    sys.stdout.flush()

    # Build work items
    tasks = []
    task_id = 0
    for keyword in keywords:
        for autokey_mode in ["pt", "ct"]:
            for cipher_name in CIPHERS:
                for alph_name in ALPHABETS:
                    tasks.append({
                        "keyword": keyword,
                        "cipher_name": cipher_name,
                        "alph_name": alph_name,
                        "autokey_mode": autokey_mode,
                        "rng_seed": 42 + task_id,
                    })
                    task_id += 1

    all_results = []
    completed = 0
    batch_size = N_WORKERS * 2

    with mp.Pool(N_WORKERS) as pool:
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            batch_results = pool.map(sa_search, batch)
            for res_list in batch_results:
                all_results.extend(res_list)
            completed += len(batch)
            elapsed = time.time() - t0
            rate = completed / elapsed if elapsed > 0 else 0
            hits = len([r for r in all_results if r["score"] >= REPORT_THRESHOLD])
            print(f"  Progress: {completed}/{len(tasks)} configs "
                  f"({elapsed:.0f}s, {rate:.1f}/s), "
                  f"hits >= {REPORT_THRESHOLD}: {hits}")
            sys.stdout.flush()

    elapsed = time.time() - t0

    # ── Results ───────────────────────────────────────────────────────────
    print(f"\n{'=' * 78}")
    print(f"RESULTS")
    print(f"{'=' * 78}")
    print(f"Elapsed: {elapsed:.1f}s ({elapsed/3600:.2f}h)")
    print(f"Total configs: {len(tasks)}")

    reportable = [r for r in all_results if r["score"] >= REPORT_THRESHOLD]
    all_best = sorted(all_results, key=lambda r: -r["score"])

    print(f"Results with score >= {REPORT_THRESHOLD}: {len(reportable)}")

    if reportable:
        reportable.sort(key=lambda r: -r["score"])
        for i, r in enumerate(reportable[:50]):
            print(f"\n  #{i+1}: score={r['score']:.1f} | "
                  f"{r['keyword']}/{r['cipher']}/{r['alphabet']} ({r['autokey_mode']}_autokey)")
            print(f"    Null positions: {r['null_positions']}")
            print(f"    PT: {r['plaintext']}")
    else:
        print("  (none)")

    # Top 10 overall
    print(f"\n{'─' * 78}")
    print(f"TOP 10 OVERALL:")
    for i, r in enumerate(all_best[:10]):
        print(f"  #{i+1}: score={r['score']:.1f} | "
              f"{r['keyword']}/{r['cipher']}/{r['alphabet']} ({r['autokey_mode']}_autokey)")
        print(f"       PT: {r['plaintext'][:60]}...")

    best_score = max((r["score"] for r in all_results), default=0)
    print(f"\n{'=' * 78}")
    if best_score >= 18:
        print(f"*** SIGNAL (best={best_score}) — investigate ***")
    elif best_score >= REPORT_THRESHOLD:
        print(f"Above noise (best={best_score}) but below signal")
    else:
        print(f"NOISE — Autokey + Model A null mask: no signal")
    print(f"Best score: {best_score}")
    print(f"{'=' * 78}")


if __name__ == "__main__":
    main()
