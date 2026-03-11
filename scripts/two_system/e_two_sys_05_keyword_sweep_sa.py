#!/usr/bin/env python3
# Cipher:     Two-system Model A (null removal + periodic Vig/Beau)
# Family:     two_system
# Status:     active
# Keyspace:   ~840K keywords x 6 variants x 4 restarts x 50K SA iters = ~1.0T evals
# Last run:
# Best score:
#
# E-TWO-SYS-05: Full English wordlist keyword sweep + null mask SA.
#
# THE BIG RUN. Model A + periodic Vig/Beau on 73-char text. Full English wordlist
# (~840K keywords, lengths 3-13). For each keyword, SA searches for null masks
# optimizing free-crib score.
#
# Features:
#   - Checkpoint/resume: saves progress per shard, restarts skip completed words
#   - 28-core parallel: wordlist split into shards, one per core
#   - Fast inner loop: score_fast_v2 for mapped crib hits
#   - Final validation: free crib search on top candidates
#
# Runtime: ~8-9 days on 28 cores.
from __future__ import annotations

import json
import math
import os
import random
import sys
import time
import multiprocessing as mp
from pathlib import Path

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
SA_ITERATIONS = 100_000
SA_RESTARTS = 8
SA_T_INIT = 2.0
SA_T_MIN = 0.01
SA_COOLING = 0.99997   # tuned for 100K iterations

REPORT_THRESHOLD = 8  # higher threshold for the big run
N_WORKERS = min(28, os.cpu_count() or 4)

# Checkpoint directory
CHECKPOINT_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'checkpoints', 'two_sys_05')

# Max keyword length (longer keywords are less constrained)
MAX_KW_LEN = 13

# Alphabets
ALPH_TABLE = {
    "AZ": (ALPH, {c: i for i, c in enumerate(ALPH)}),
    "KA": (KRYPTOS_ALPHABET, {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}),
}

# Ciphers
def vig_dec(c, k): return (c - k) % MOD
def beau_dec(c, k): return (k - c) % MOD
def vbeau_dec(c, k): return (c + k) % MOD

CIPHER_TABLE = {
    "Vig": vig_dec,
    "Beau": beau_dec,
    "VBeau": vbeau_dec,
}


# ── Fast scoring (adapted from e_null_mask_crib_only.py) ─────────────────

def score_fast_v2(null_sorted: list, ct_ords: list, keyword_indices: list,
                  kw_len: int, c2i: list, alph_str: str, decrypt_fn,
                  crib_entries: list) -> int:
    """Fast SA scoring: mapped crib hits only.

    null_sorted: sorted list of all null positions.
    Returns crib character match count (0-24).
    """
    hits = 0
    null_set_len = len(null_sorted)
    for orig_pos, expected_char in crib_entries:
        lo, hi = 0, null_set_len
        is_null = False
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
        count_before = lo
        r_idx = orig_pos - count_before
        c_idx = c2i[ct_ords[orig_pos]]
        k_idx = keyword_indices[r_idx % kw_len]
        p_idx = decrypt_fn(c_idx, k_idx)
        if alph_str[p_idx] == expected_char:
            hits += 1
    return hits


def score_free_crib(null_sorted: list, ct_str: str, keyword_indices: list,
                    kw_len: int, c2i: list, alph_str: str, decrypt_fn) -> tuple:
    """Full decryption + free crib search. Returns (score, plaintext)."""
    null_set = set(null_sorted)
    reduced = []
    for i in range(CT_LEN):
        if i not in null_set:
            reduced.append(ct_str[i])
    reduced_ct = "".join(reduced)

    # Decrypt
    result = []
    for i, ch in enumerate(reduced_ct):
        c_idx = c2i[ord(ch) - 65]
        k_idx = keyword_indices[i % kw_len]
        p_idx = decrypt_fn(c_idx, k_idx)
        result.append(alph_str[p_idx])
    pt = "".join(result)

    score = 0
    if CRIB_ENE in pt:
        score += 13
    if CRIB_BC in pt:
        score += 11

    return score, pt


# ── SA search for a single keyword+cipher+alphabet ───────────────────────

def sa_search_keyword(keyword: str, cipher_name: str, alph_name: str,
                      rng_seed: int) -> dict:
    """Run SA search for a single keyword configuration.

    Returns dict with best result.
    """
    import bisect

    alph_str, c2i_dict = ALPH_TABLE[alph_name]
    decrypt_fn = CIPHER_TABLE[cipher_name]

    # Build fast lookup table (indexed by ord-65)
    c2i = [0] * 26
    for ch, idx in c2i_dict.items():
        c2i[ord(ch) - 65] = idx

    try:
        kw_indices = [c2i_dict[c] for c in keyword]
    except KeyError:
        return {"mapped_score": -1, "free_score": 0, "keyword": keyword,
                "cipher": cipher_name, "alphabet": alph_name,
                "null_positions": [], "plaintext": ""}

    kw_len = len(kw_indices)
    rng = random.Random(rng_seed)

    ct_ords = [ord(ch) - 65 for ch in CT]
    crib_entries = CRIB_LIST
    available = sorted(set(range(CT_LEN)) - CRIB_POSITIONS)

    best_overall_score = -1
    best_overall_nulls = None
    best_overall_pt = None

    for restart in range(SA_RESTARTS):
        free_nulls = rng.sample(available, N_NULLS)
        non_null_list = [p for p in available if p not in set(free_nulls)]

        # Maintain a sorted list with bisect instead of sorting every iteration
        null_sorted = sorted(free_nulls)
        current_score = score_fast_v2(
            null_sorted, ct_ords, kw_indices, kw_len,
            c2i, alph_str, decrypt_fn, crib_entries
        )

        best_score = current_score
        best_nulls = list(free_nulls)

        temp = SA_T_INIT
        _randrange = rng.randrange
        _random = rng.random
        _exp = math.exp
        _bisect_left = bisect.bisect_left
        _insort = bisect.insort

        for _ in range(SA_ITERATIONS):
            ri = _randrange(N_NULLS)
            ai = _randrange(len(non_null_list))
            remove_pos = free_nulls[ri]
            add_pos = non_null_list[ai]

            free_nulls[ri] = add_pos
            non_null_list[ai] = remove_pos

            # Update sorted list: remove old, insert new (O(n) shift but no full sort)
            rm_idx = _bisect_left(null_sorted, remove_pos)
            del null_sorted[rm_idx]
            _insort(null_sorted, add_pos)

            new_score = score_fast_v2(
                null_sorted, ct_ords, kw_indices, kw_len,
                c2i, alph_str, decrypt_fn, crib_entries
            )

            delta = new_score - current_score
            if delta > 0 or (delta == 0 and _random() < 0.5):
                current_score = new_score
                if current_score > best_score:
                    best_score = current_score
                    best_nulls = list(free_nulls)
            elif temp > SA_T_MIN and _random() < _exp(delta / temp):
                current_score = new_score
            else:
                free_nulls[ri] = remove_pos
                non_null_list[ai] = add_pos
                # Revert sorted list
                rv_idx = _bisect_left(null_sorted, add_pos)
                del null_sorted[rv_idx]
                _insort(null_sorted, remove_pos)

            temp *= SA_COOLING

        if best_score > best_overall_score:
            best_overall_score = best_score
            best_overall_nulls = sorted(best_nulls)

    # Free crib validation on best result
    free_score = 0
    pt = ""
    if best_overall_score >= REPORT_THRESHOLD - 2:
        # Only do expensive free-crib check on promising candidates
        c2i_list = [0] * 26
        for ch, idx in c2i_dict.items():
            c2i_list[ord(ch) - 65] = idx
        free_score, pt = score_free_crib(
            best_overall_nulls, CT, kw_indices, kw_len,
            c2i_list, alph_str, decrypt_fn
        )

    return {
        "keyword": keyword,
        "cipher": cipher_name,
        "alphabet": alph_name,
        "mapped_score": best_overall_score,
        "free_score": free_score,
        "null_positions": best_overall_nulls,
        "plaintext": pt if pt else "",
    }


# ── Single-keyword worker ─────────────────────────────────────────────────

def process_one_keyword(keyword: str) -> list:
    """Process one keyword across all 6 cipher/alphabet combos."""
    results = []
    for cipher_name in CIPHER_TABLE:
        for alph_name in ALPH_TABLE:
            seed = hash((keyword, cipher_name, alph_name)) & 0xFFFFFFFF
            result = sa_search_keyword(keyword, cipher_name, alph_name, seed)
            if result["mapped_score"] >= REPORT_THRESHOLD or result["free_score"] >= 11:
                results.append(result)
    return results


# ── Checkpoint management ─────────────────────────────────────────────────

def load_checkpoint(shard_id: int) -> set:
    """Load completed keywords for a shard."""
    ckpt_path = os.path.join(CHECKPOINT_DIR, f"shard_{shard_id:03d}.json")
    if os.path.exists(ckpt_path):
        with open(ckpt_path) as f:
            data = json.load(f)
        return set(data.get("completed", []))
    return set()


def save_checkpoint(shard_id: int, completed: set, results: list):
    """Save checkpoint for a shard."""
    os.makedirs(CHECKPOINT_DIR, exist_ok=True)
    ckpt_path = os.path.join(CHECKPOINT_DIR, f"shard_{shard_id:03d}.json")
    with open(ckpt_path, "w") as f:
        json.dump({
            "shard_id": shard_id,
            "completed": sorted(completed),
            "n_completed": len(completed),
            "results": results[-100:],  # keep last 100 results per shard
        }, f)


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    t0 = time.time()

    print("=" * 78)
    print("E-TWO-SYS-05: Thematic keyword sweep + null mask SA")
    print("=" * 78)
    print(f"\nCT ({CT_LEN} chars): {CT}")
    print(f"SA: {SA_ITERATIONS:,} iters × {SA_RESTARTS} restarts")
    print(f"Report threshold: {REPORT_THRESHOLD}")
    print(f"Workers: {N_WORKERS}")
    print()
    sys.stdout.flush()

    # Load thematic wordlist (rigorous, ~700 words)
    wordlist_path = os.path.join(os.path.dirname(__file__), '..', '..', 'wordlists', 'thematic_keywords_v2.txt')
    words = []
    with open(wordlist_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            w = line.upper()
            if 3 <= len(w) <= MAX_KW_LEN and w.isalpha():
                words.append(w)
    words = sorted(set(words))
    print(f"Loaded {len(words):,} unique keywords (length 3-{MAX_KW_LEN})")

    total_configs = len(words) * len(CIPHER_TABLE) * len(ALPH_TABLE)
    total_sa_evals = total_configs * SA_RESTARTS * SA_ITERATIONS
    print(f"Total configs: {total_configs:,}")
    print(f"Total SA evaluations: {total_sa_evals:,}")

    # Split into shards for checkpointing
    shard_size = max(1, len(words) // N_WORKERS)
    shards = []
    for i in range(0, len(words), shard_size):
        shard_words = words[i:i + shard_size]
        shard_id = len(shards)

        # Check checkpoint — remove already-completed words
        completed = load_checkpoint(shard_id)
        remaining = [w for w in shard_words if w not in completed]

        if remaining:
            shards.append((remaining, shard_id))
        else:
            print(f"  Shard {shard_id}: fully completed ({len(completed)} words), skipping")

    total_remaining = sum(len(s[0]) for s in shards)
    print(f"\nShards: {len(shards)} (with {total_remaining:,} remaining keywords)")
    print(f"Checkpoint dir: {CHECKPOINT_DIR}")
    print()
    sys.stdout.flush()

    if not shards:
        print("All shards complete! Nothing to do.")
        return

    # Flatten all remaining keywords into one list
    all_words = []
    for shard_words, shard_id in shards:
        all_words.extend(shard_words)

    all_results = []
    completed_words = 0
    total_words = len(all_words)
    n_hits = 0

    print(f"Total keywords to process: {total_words:,}")
    print(f"Each keyword: 6 cipher/alphabet combos × {SA_RESTARTS} restarts × {SA_ITERATIONS:,} SA iters")
    print(f"\nStarting sweep...\n")
    sys.stdout.flush()

    # One keyword per work unit — gives progress every ~16s per completed word
    REPORT_EVERY = 100  # print progress every N keywords

    with mp.Pool(N_WORKERS) as pool:
        for word_idx, result_list in enumerate(
            pool.imap_unordered(process_one_keyword, all_words, chunksize=1)
        ):
            all_results.extend(result_list)
            completed_words += 1
            n_hits += len(result_list)

            # Print any hits immediately
            for r in result_list:
                print(f"    *** HIT: {r['keyword']}/{r['cipher']}/{r['alphabet']} "
                      f"mapped={r['mapped_score']} free={r['free_score']}")
                if r["plaintext"]:
                    print(f"        PT: {r['plaintext'][:60]}...")
                sys.stdout.flush()

            # Progress report every N keywords
            if completed_words % REPORT_EVERY == 0 or completed_words == total_words:
                elapsed = time.time() - t0
                rate = completed_words / elapsed if elapsed > 0 else 0
                eta_s = (total_words - completed_words) / rate if rate > 0 else 0
                eta_h = eta_s / 3600

                print(f"  [{completed_words:,}/{total_words:,} words] "
                      f"{elapsed/3600:.2f}h elapsed, {rate:.1f} words/s, "
                      f"ETA {eta_h:.1f}h | hits: {n_hits}")
                sys.stdout.flush()

            # Save checkpoint periodically (every 1000 words)
            if completed_words % 1000 == 0:
                results_path = os.path.join(CHECKPOINT_DIR, "results_partial.json")
                os.makedirs(CHECKPOINT_DIR, exist_ok=True)
                with open(results_path, "w") as f:
                    json.dump({
                        "completed_words": completed_words,
                        "total_words": total_words,
                        "elapsed_hours": elapsed / 3600,
                        "results": all_results[-500:],
                    }, f, indent=2)

    elapsed = time.time() - t0

    # ── Final Results ─────────────────────────────────────────────────────
    print(f"\n{'=' * 78}")
    print(f"FINAL RESULTS")
    print(f"{'=' * 78}")
    print(f"Elapsed: {elapsed:.1f}s ({elapsed/3600:.1f}h)")
    print(f"Keywords tested: {total_words:,}")

    reportable = [r for r in all_results
                  if r["mapped_score"] >= REPORT_THRESHOLD or r["free_score"] >= 11]

    print(f"Results above threshold: {len(reportable)}")

    if reportable:
        reportable.sort(key=lambda r: -(max(r["mapped_score"], r["free_score"])))
        print(f"\nTop results:")
        for i, r in enumerate(reportable[:100]):
            print(f"  #{i+1}: mapped={r['mapped_score']} free={r['free_score']} | "
                  f"{r['keyword']}/{r['cipher']}/{r['alphabet']}")
            if r["plaintext"]:
                print(f"       PT: {r['plaintext'][:70]}...")

    # Save final results
    final_path = os.path.join(CHECKPOINT_DIR, "results_final.json")
    os.makedirs(CHECKPOINT_DIR, exist_ok=True)
    with open(final_path, "w") as f:
        json.dump({
            "experiment": "e_two_sys_05_keyword_sweep_sa",
            "total_keywords": total_words,
            "elapsed_hours": elapsed / 3600,
            "sa_iterations": SA_ITERATIONS,
            "sa_restarts": SA_RESTARTS,
            "report_threshold": REPORT_THRESHOLD,
            "total_results": len(reportable),
            "results": reportable,
        }, f, indent=2)
    print(f"\nResults saved to {final_path}")

    best = max((max(r["mapped_score"], r["free_score"]) for r in all_results), default=0)
    print(f"\n{'=' * 78}")
    if best >= 18:
        print(f"*** SIGNAL (best={best}) — INVESTIGATE ***")
    elif best >= REPORT_THRESHOLD:
        print(f"Above noise (best={best}) — review")
    else:
        print(f"NOISE — Full keyword sweep: no signal (best={best})")
    print(f"{'=' * 78}")


if __name__ == "__main__":
    main()
