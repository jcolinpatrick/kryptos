#!/usr/bin/env python3
# Cipher:     Multi-layer (null insertion + substitution)
# Family:     team
# Status:     active
# Keyspace:   SA over C(97,24) null positions x 6 keywords x 2 ciphers x 2 alphabets
# Last run:
# Best score:
#
# E-NULL-MASK-CRIB-ONLY: SA search for 24 null positions using CRIB-ONLY scoring.
#
# The 73-char null hypothesis says K4 has 24 null characters inserted. Previous
# searches (1.66M configs) used quadgram scoring and found nothing. But if the
# plaintext contains intelligence acronyms (CIA, KGB, etc.), quadgram scoring
# would reject correct results.
#
# This script uses CRIB-ONLY scoring: after removing 24 nulls and decrypting,
# count how many crib characters match at their mapped positions, plus search
# for cribs anywhere in the decrypted text. Intelligence jargon found in the
# decrypted text contributes a bonus.
#
# Two modes:
#   1. Unconstrained SA: 24 null positions chosen freely from non-crib positions
#   2. W-constrained SA: positions 20,36,48,58,74 fixed as nulls, SA over 19 more
#
# Uses multiprocessing across all cores.
from __future__ import annotations

import math
import os
import random
import sys
import time
from multiprocessing import Pool, cpu_count

# ── Setup path ────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    KRYPTOS_ALPHABET, NOISE_FLOOR,
)
from kryptos.kernel.alphabet import AZ, KA, Alphabet

# ── Constants ─────────────────────────────────────────────────────────────

REDUCED_LEN = 73
N_NULLS = 24

# Crib data: positions and characters in the ORIGINAL 97-char text
CRIB_ENE_START = 21
CRIB_ENE = "EASTNORTHEAST"
CRIB_BC_START = 63
CRIB_BC = "BERLINCLOCK"

# All original crib positions (0-indexed in the 97-char text)
ORIG_CRIB_POSITIONS = sorted(CRIB_POSITIONS)

# Keywords to test
KEYWORDS = ["KRYPTOS", "DEFECTOR", "PARALLAX", "COLOPHON", "ABSCISSA", "SHADOW"]

# Alphabets
ALPHABETS = {
    "AZ": ALPH,
    "KA": KRYPTOS_ALPHABET,
}

# Cipher variants: (name, decrypt_fn)
# Vigenere: P = (C - K) mod 26
# Beaufort: P = (K - C) mod 26
def vig_decrypt_char(c_idx: int, k_idx: int) -> int:
    return (c_idx - k_idx) % MOD

def beau_decrypt_char(c_idx: int, k_idx: int) -> int:
    return (k_idx - c_idx) % MOD

CIPHERS = {
    "Vig": vig_decrypt_char,
    "Beau": beau_decrypt_char,
}

# Intelligence jargon to search for
JARGON = [
    "CIA", "KGB", "NSA", "FBI", "DCI", "NRO", "GRU",
    "DEAD", "DROP", "ASSET", "AGENT", "MOLE", "OPS",
    "SIGINT", "HUMINT", "LANGLEY", "MOSCOW", "BERLIN",
    "SECRET", "BURIED", "HIDDEN", "MARKER",
]

# W positions (0-indexed in 97-char text) — hypothesized nulls
W_POSITIONS = frozenset([20, 36, 48, 58, 74])

# SA parameters
SA_ITERATIONS = 100_000
SA_RESTARTS = 4        # per worker task
SA_T_INIT = 2.0
SA_T_MIN = 0.01
SA_COOLING = 0.99997   # tuned for 100K iterations

# Reporting threshold
REPORT_THRESHOLD = 6

N_WORKERS = min(28, cpu_count() or 4)


# ── Core Functions ────────────────────────────────────────────────────────

def build_index_tables(alph_str: str):
    """Build char->index and index->char tables for an alphabet."""
    c2i = [0] * 26  # indexed by ord(ch) - 65
    for i, ch in enumerate(alph_str):
        c2i[ord(ch) - 65] = i
    return c2i, alph_str


def remove_nulls(ct: str, null_positions: frozenset) -> tuple:
    """Remove null positions from CT, returning (reduced_ct, orig_to_reduced_map).

    orig_to_reduced_map[orig_pos] = reduced_pos for non-null positions.
    """
    reduced = []
    orig_to_reduced = {}
    reduced_idx = 0
    for i, ch in enumerate(ct):
        if i not in null_positions:
            reduced.append(ch)
            orig_to_reduced[i] = reduced_idx
            reduced_idx += 1
    return "".join(reduced), orig_to_reduced


def decrypt_reduced(reduced_ct: str, keyword: str, c2i, alph_str, decrypt_fn) -> str:
    """Decrypt reduced CT with keyword using given cipher and alphabet."""
    kw_indices = [c2i[ord(ch) - 65] for ch in keyword]
    kw_len = len(kw_indices)
    result = []
    for i, ch in enumerate(reduced_ct):
        c_idx = c2i[ord(ch) - 65]
        k_idx = kw_indices[i % kw_len]
        p_idx = decrypt_fn(c_idx, k_idx)
        result.append(alph_str[p_idx])
    return "".join(result)


def score_crib_mapped(plaintext: str, orig_to_reduced: dict) -> int:
    """Score by checking if crib characters appear at their mapped positions.

    Original crib positions (in 97-char text) are mapped to positions in
    the reduced 73-char text. We check if the decrypted character at the
    mapped position matches the expected crib character.
    """
    hits = 0
    for orig_pos, expected_char in CRIB_DICT.items():
        if orig_pos in orig_to_reduced:
            reduced_pos = orig_to_reduced[orig_pos]
            if reduced_pos < len(plaintext) and plaintext[reduced_pos] == expected_char:
                hits += 1
    return hits


def score_crib_free(plaintext: str) -> int:
    """Score by searching for full cribs anywhere in the plaintext.

    Returns 13 for ENE found, 11 for BC found, 24 for both.
    """
    s = 0
    if CRIB_ENE in plaintext:
        s += len(CRIB_ENE)
    if CRIB_BC in plaintext:
        s += len(CRIB_BC)
    return s


def score_crib_partial_free(plaintext: str) -> int:
    """Count how many characters of each crib appear at the best offset.

    Slide each crib across the plaintext and find the position with the most
    character matches. Return total character hits across both cribs.
    """
    total = 0
    for crib in [CRIB_ENE, CRIB_BC]:
        best = 0
        crib_len = len(crib)
        for start in range(len(plaintext) - crib_len + 1):
            hits = sum(1 for j in range(crib_len) if plaintext[start + j] == crib[j])
            if hits > best:
                best = hits
        total += best
    return total


def score_jargon(plaintext: str) -> float:
    """Score bonus for intelligence jargon found in plaintext."""
    bonus = 0.0
    for term in JARGON:
        if term in plaintext:
            bonus += len(term) * 0.5  # 0.5 per character of jargon found
    return bonus


def score_candidate_full(plaintext: str, orig_to_reduced: dict) -> tuple:
    """Combined scoring: mapped crib hits + free crib search + jargon bonus.

    Returns (total_score, crib_mapped, crib_free, partial_free, jargon_bonus, jargon_terms).
    """
    crib_mapped = score_crib_mapped(plaintext, orig_to_reduced)
    crib_free = score_crib_free(plaintext)
    partial_free = score_crib_partial_free(plaintext)
    jargon_bonus = score_jargon(plaintext)
    jargon_found = [t for t in JARGON if t in plaintext]

    # Primary score = max of mapped crib hits and free crib hits
    # Add partial free as tiebreaker (scaled down to not dominate)
    primary = max(crib_mapped, crib_free)
    total = primary + jargon_bonus + partial_free * 0.1

    return (total, crib_mapped, crib_free, partial_free, jargon_bonus, jargon_found)


def score_fast(null_set: set, fixed_nulls: frozenset,
               ct_chars: list, keyword_indices: list, kw_len: int,
               c2i: list, alph_str: str, decrypt_fn,
               crib_entries: list) -> int:
    """Fast SA inner-loop scoring: mapped crib hits only.

    Avoids building strings/dicts; works directly with lists and indices.
    Returns crib character match count (0-24).
    """
    all_nulls = null_set | fixed_nulls
    # Build reduced CT indices and position mapping in one pass
    reduced_idx = 0
    # We only need to check crib positions, so track where they land
    hits = 0
    for orig_pos, expected_char in crib_entries:
        if orig_pos in all_nulls:
            continue
        # Count how many non-null positions are before orig_pos
        # (This is the reduced position)
        r_idx = orig_pos
        for np in all_nulls:
            if np < orig_pos:
                r_idx -= 1
        # Decrypt at reduced position
        c_idx = c2i[ct_chars[orig_pos]]
        k_idx = keyword_indices[r_idx % kw_len]
        p_idx = decrypt_fn(c_idx, k_idx)
        if alph_str[p_idx] == expected_char:
            hits += 1
    return hits


def score_fast_v2(null_sorted: list, fixed_nulls_sorted: list,
                  ct_ords: list, keyword_indices: list, kw_len: int,
                  c2i: list, alph_str: str, decrypt_fn,
                  crib_entries: list) -> int:
    """Faster SA scoring using precomputed null count prefix array.

    null_sorted: sorted list of all null positions (free + fixed combined).
    Returns crib character match count (0-24).
    """
    # Build a quick lookup: for each crib position, how many nulls precede it?
    # null_sorted is sorted, so we can binary search.
    hits = 0
    null_set_len = len(null_sorted)
    ni = 0  # index into null_sorted
    for orig_pos, expected_char in crib_entries:
        # Check if this crib position is itself a null
        # Binary search in null_sorted
        lo, hi = 0, null_set_len
        is_null = False
        count_before = 0
        while lo < hi:
            mid = (lo + hi) // 2
            if null_sorted[mid] < orig_pos:
                lo = mid + 1
            elif null_sorted[mid] == orig_pos:
                is_null = True
                break
            else:
                hi = mid
        if is_null:
            continue
        count_before = lo  # number of nulls strictly before orig_pos
        r_idx = orig_pos - count_before
        c_idx = c2i[ct_ords[orig_pos]]
        k_idx = keyword_indices[r_idx % kw_len]
        p_idx = decrypt_fn(c_idx, k_idx)
        if alph_str[p_idx] == expected_char:
            hits += 1
    return hits


def sa_search(
    keyword: str,
    cipher_name: str,
    alph_name: str,
    decrypt_fn,
    c2i,
    alph_str: str,
    fixed_nulls: frozenset,
    rng_seed: int,
    n_restarts: int = SA_RESTARTS,
) -> list:
    """Simulated annealing search for optimal null positions.

    Args:
        fixed_nulls: positions that MUST be nulls (e.g., W positions).
                     The remaining nulls are searched via SA.

    Returns:
        List of result dicts for candidates scoring >= REPORT_THRESHOLD.
    """
    rng = random.Random(rng_seed)
    results = []
    n_fixed = len(fixed_nulls)
    n_free = N_NULLS - n_fixed

    available_positions = sorted(set(range(CT_LEN)) - fixed_nulls)

    if n_free > len(available_positions):
        return results

    # Precompute for fast scoring
    ct_ords = [ord(ch) - 65 for ch in CT]
    keyword_indices = [c2i[ord(ch) - 65] for ch in keyword]
    kw_len = len(keyword_indices)
    crib_entries = sorted(CRIB_DICT.items())  # sorted by position
    fixed_nulls_sorted = sorted(fixed_nulls)

    best_overall_score = -1
    best_overall = None

    for restart in range(n_restarts):
        # Initialize: use lists for O(1) random access
        free_null_list = rng.sample(available_positions, n_free)
        free_null_set = set(free_null_list)
        non_null_list = [p for p in available_positions if p not in free_null_set]

        # Compute initial score using fast scorer
        all_null_sorted = sorted(free_null_list + fixed_nulls_sorted)
        current_score = score_fast_v2(
            all_null_sorted, fixed_nulls_sorted,
            ct_ords, keyword_indices, kw_len,
            c2i, alph_str, decrypt_fn, crib_entries
        )

        best_score = current_score
        best_free_nulls = list(free_null_list)

        temp = SA_T_INIT
        randrange = rng.randrange
        random_fn = rng.random
        exp_fn = math.exp

        for iteration in range(SA_ITERATIONS):
            # Pick random null to remove and random non-null to add
            ri = randrange(n_free)
            ai = randrange(len(non_null_list))
            remove_pos = free_null_list[ri]
            add_pos = non_null_list[ai]

            # Swap in lists
            free_null_list[ri] = add_pos
            non_null_list[ai] = remove_pos

            # Recompute sorted null list (insertion sort would be faster
            # but sorted() on 24 elements is already fast)
            all_null_sorted = sorted(free_null_list + fixed_nulls_sorted)

            new_score = score_fast_v2(
                all_null_sorted, fixed_nulls_sorted,
                ct_ords, keyword_indices, kw_len,
                c2i, alph_str, decrypt_fn, crib_entries
            )

            # Accept or reject
            delta = new_score - current_score
            if delta > 0 or (delta == 0 and random_fn() < 0.5):
                current_score = new_score
                if current_score > best_score:
                    best_score = current_score
                    best_free_nulls = list(free_null_list)
            elif temp > SA_T_MIN and random_fn() < exp_fn(delta / temp):
                current_score = new_score
            else:
                # Revert swap
                free_null_list[ri] = remove_pos
                non_null_list[ai] = add_pos

            temp *= SA_COOLING

        # Full evaluation of best from this restart
        all_nulls_best = frozenset(best_free_nulls) | fixed_nulls
        reduced_ct_best, orig_to_reduced_best = remove_nulls(CT, all_nulls_best)
        pt_best = decrypt_reduced(reduced_ct_best, keyword, c2i, alph_str, decrypt_fn)
        full_score = score_candidate_full(pt_best, orig_to_reduced_best)
        total, crib_mapped, crib_free, partial_free, jargon_bonus, jargon_found = full_score

        if crib_mapped >= REPORT_THRESHOLD or crib_free >= 11:
            results.append({
                "keyword": keyword,
                "cipher": cipher_name,
                "alphabet": alph_name,
                "mode": "W-constrained" if fixed_nulls else "unconstrained",
                "null_positions": sorted(all_nulls_best),
                "crib_mapped": crib_mapped,
                "crib_free": crib_free,
                "partial_free": partial_free,
                "jargon_bonus": jargon_bonus,
                "jargon_found": jargon_found,
                "total_score": round(total, 2),
                "plaintext": pt_best,
                "reduced_ct": reduced_ct_best,
                "restart": restart,
            })

        if total > best_overall_score:
            best_overall_score = total
            best_overall = {
                "keyword": keyword,
                "cipher": cipher_name,
                "alphabet": alph_name,
                "mode": "W-constrained" if fixed_nulls else "unconstrained",
                "null_positions": sorted(all_nulls_best),
                "crib_mapped": crib_mapped,
                "crib_free": crib_free,
                "partial_free": partial_free,
                "jargon_bonus": jargon_bonus,
                "jargon_found": jargon_found,
                "total_score": round(total, 2),
                "plaintext": pt_best,
                "reduced_ct": reduced_ct_best,
                "restart": restart,
            }

    # Always include the best from all restarts (even below threshold)
    if best_overall and best_overall not in results:
        results.append(best_overall)

    return results


def worker_task(args: dict) -> list:
    """Worker function for multiprocessing. Runs SA for one configuration."""
    keyword = args["keyword"]
    cipher_name = args["cipher_name"]
    alph_name = args["alph_name"]
    decrypt_fn_name = args["decrypt_fn_name"]
    fixed_nulls = frozenset(args["fixed_nulls"])
    rng_seed = args["rng_seed"]

    # Reconstruct objects from serializable args
    alph_str = ALPHABETS[alph_name]
    c2i, _ = build_index_tables(alph_str)
    decrypt_fn = CIPHERS[decrypt_fn_name]

    return sa_search(
        keyword=keyword,
        cipher_name=cipher_name,
        alph_name=alph_name,
        decrypt_fn=decrypt_fn,
        c2i=c2i,
        alph_str=alph_str,
        fixed_nulls=fixed_nulls,
        rng_seed=rng_seed,
    )


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    t0 = time.time()
    print("=" * 78)
    print("E-NULL-MASK-CRIB-ONLY: SA search for 24 null positions (CRIB-ONLY scoring)")
    print("=" * 78)
    print(f"\nCT ({CT_LEN} chars): {CT}")
    print(f"Remove {N_NULLS} nulls -> {REDUCED_LEN} chars")
    print(f"Cribs: EASTNORTHEAST@21-33, BERLINCLOCK@63-73 (in 97-char original)")
    print(f"Keywords: {', '.join(KEYWORDS)}")
    print(f"Ciphers: Vig, Beau × AZ, KA")
    print(f"SA: {SA_ITERATIONS:,} iterations × {SA_RESTARTS} restarts per config")
    print(f"W-constrained positions: {sorted(W_POSITIONS)}")
    print(f"Workers: {N_WORKERS}")
    print(f"Jargon terms: {len(JARGON)}")
    print(f"Report threshold: crib_mapped >= {REPORT_THRESHOLD} OR full crib found")
    print()

    # Build all task configurations
    tasks = []
    task_id = 0
    for keyword in KEYWORDS:
        for cipher_name, _ in CIPHERS.items():
            for alph_name in ALPHABETS:
                # Mode 1: Unconstrained (no fixed nulls)
                tasks.append({
                    "keyword": keyword,
                    "cipher_name": cipher_name,
                    "alph_name": alph_name,
                    "decrypt_fn_name": cipher_name,
                    "fixed_nulls": [],
                    "rng_seed": 42 + task_id,
                })
                task_id += 1

                # Mode 2: W-constrained (5 W positions fixed as nulls)
                tasks.append({
                    "keyword": keyword,
                    "cipher_name": cipher_name,
                    "alph_name": alph_name,
                    "decrypt_fn_name": cipher_name,
                    "fixed_nulls": sorted(W_POSITIONS),
                    "rng_seed": 10007 + task_id,
                })
                task_id += 1

    total_tasks = len(tasks)
    total_sa_runs = total_tasks * SA_RESTARTS
    total_iterations = total_sa_runs * SA_ITERATIONS
    print(f"Total tasks: {total_tasks}")
    print(f"Total SA runs: {total_sa_runs:,}")
    print(f"Total SA iterations: {total_iterations:,}")
    print(f"\nStarting SA search...\n")
    sys.stdout.flush()

    # Run with multiprocessing
    all_results = []
    completed = 0
    batch_size = N_WORKERS * 2  # process in batches for progress reporting

    with Pool(N_WORKERS) as pool:
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            batch_results = pool.map(worker_task, batch)
            for res_list in batch_results:
                all_results.extend(res_list)
            completed += len(batch)
            elapsed = time.time() - t0
            rate = completed / elapsed if elapsed > 0 else 0
            print(f"  Progress: {completed}/{total_tasks} tasks "
                  f"({completed * SA_RESTARTS * SA_ITERATIONS:,} iterations), "
                  f"{elapsed:.1f}s, {rate:.1f} tasks/s, "
                  f"hits so far: {len([r for r in all_results if r.get('crib_mapped', 0) >= REPORT_THRESHOLD or r.get('crib_free', 0) >= 11])}")
            sys.stdout.flush()

    elapsed = time.time() - t0

    # ── Report Results ────────────────────────────────────────────────────
    print(f"\n{'=' * 78}")
    print(f"RESULTS")
    print(f"{'=' * 78}")
    print(f"Elapsed: {elapsed:.1f}s")
    print(f"Total tasks: {total_tasks}")
    print(f"Total SA iterations: {total_iterations:,}")

    # Filter and sort results
    reportable = [r for r in all_results
                  if r.get("crib_mapped", 0) >= REPORT_THRESHOLD
                  or r.get("crib_free", 0) >= 11]

    # Also collect overall best per config (even below threshold)
    all_best = sorted(all_results, key=lambda r: -r.get("total_score", 0))

    print(f"\nResults with crib_mapped >= {REPORT_THRESHOLD} or full crib found: {len(reportable)}")

    if reportable:
        reportable.sort(key=lambda r: -r.get("total_score", 0))
        print(f"\n{'─' * 78}")
        for i, r in enumerate(reportable[:50]):  # cap at top 50
            print(f"\n  #{i+1}: {r['keyword']}/{r['cipher']}/{r['alphabet']} ({r['mode']})")
            print(f"    Crib mapped: {r['crib_mapped']}/24, "
                  f"Crib free: {r['crib_free']}/24, "
                  f"Partial free: {r['partial_free']}/24")
            print(f"    Jargon bonus: {r['jargon_bonus']:.1f} {r['jargon_found']}")
            print(f"    Total score: {r['total_score']}")
            print(f"    Null positions: {r['null_positions']}")
            print(f"    Reduced CT: {r['reduced_ct']}")
            print(f"    Plaintext:  {r['plaintext']}")
    else:
        print("  (none)")

    # Always show top 10 overall for diagnostics
    print(f"\n{'─' * 78}")
    print(f"TOP 10 OVERALL (any score):")
    for i, r in enumerate(all_best[:10]):
        print(f"  #{i+1}: score={r['total_score']:.2f} "
              f"mapped={r.get('crib_mapped', '?')}/24 "
              f"free={r.get('crib_free', '?')}/24 "
              f"partial={r.get('partial_free', '?')}/24 "
              f"jargon={r.get('jargon_bonus', 0):.1f} "
              f"{r['keyword']}/{r['cipher']}/{r['alphabet']} ({r['mode']})")
        if r.get('jargon_found'):
            print(f"       jargon: {r['jargon_found']}")
        print(f"       PT: {r['plaintext'][:60]}...")

    print(f"\n{'=' * 78}")
    print(f"DONE. {elapsed:.1f}s, {total_iterations:,} SA iterations, "
          f"{len(reportable)} results >= threshold")
    print(f"{'=' * 78}")

    return reportable


if __name__ == "__main__":
    main()
