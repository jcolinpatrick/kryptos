#!/usr/bin/env python3
"""
Cipher: Keyed alphabet sweep — full English wordlist as alphabet keywords
Family: novel
Status: active
Keyspace: ~1M words × 6 configs (deduped to ~200K-500K unique alphabets)
Last run: 2026-04-05
Best score: 0.0 (key_word_coverage)
Credit: community contribution — generate keyed alphabets from full wordlist,
        recover key at crib positions, check if key fragment is English
"""
import sys
import os
import re
import time
from multiprocessing import Pool, cpu_count
from collections import defaultdict

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from kryptos.kernel.constants import (
    CT, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_DICT, BEAN_EQ,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)
from kryptos.kernel.alphabet import keyword_mixed_alphabet

# ── Key recovery functions (inlined for speed in workers) ──────────────────

def _vig_key(c, p):
    return (c - p) % MOD

def _beau_key(c, p):
    return (c + p) % MOD

def _varbeau_key(c, p):
    return (p - c) % MOD

KEY_FNS = {
    "vigenere": _vig_key,
    "beaufort": _beau_key,
    "var_beaufort": _varbeau_key,
}

# Pre-compute CT and PT numeric values at crib positions
CRIB_POSITIONS_SORTED = sorted(CRIB_DICT.keys())
CT_NUMS_AT_CRIBS = [ALPH_IDX[CT[p]] for p in CRIB_POSITIONS_SORTED]
PT_NUMS_AT_CRIBS = [ALPH_IDX[CRIB_DICT[p]] for p in CRIB_POSITIONS_SORTED]

# Bean equality positions (0-indexed into CRIB_POSITIONS_SORTED)
BEAN_EQ_PAIR = BEAN_EQ[0]  # (27, 65)
BEAN_IDX_A = CRIB_POSITIONS_SORTED.index(BEAN_EQ_PAIR[0])
BEAN_IDX_B = CRIB_POSITIONS_SORTED.index(BEAN_EQ_PAIR[1])

# ENE group: positions 21-33 (indices 0..12 in sorted crib positions)
# BC group: positions 63-73 (indices 13..23)
ENE_SLICE = slice(0, 13)
BC_SLICE = slice(13, 24)

# ── Self-test ──────────────────────────────────────────────────────────────

def _self_test():
    """Verify key recovery with identity alphabet reproduces known keystream."""
    identity_idx = list(range(26))  # AZ index table
    for variant, (expected_ene, expected_bc) in [
        ("vigenere", (VIGENERE_KEY_ENE, VIGENERE_KEY_BC)),
        ("beaufort", (BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC)),
    ]:
        fn = KEY_FNS[variant]
        recovered = []
        for ct_n, pt_n in zip(CT_NUMS_AT_CRIBS, PT_NUMS_AT_CRIBS):
            recovered.append(fn(ct_n, pt_n))
        got_ene = tuple(recovered[:13])
        got_bc = tuple(recovered[13:])
        assert got_ene == expected_ene, f"{variant} ENE mismatch: {got_ene} != {expected_ene}"
        assert got_bc == expected_bc, f"{variant} BC mismatch: {got_bc} != {got_bc}"

_self_test()


# ── Alphabet generation and deduplication ──────────────────────────────────

def load_and_dedup_alphabets(wordlist_path):
    """Load words, generate keyed alphabets, deduplicate by sequence."""
    az_only = re.compile(r'^[A-Z]+$')
    # Map: alphabet_sequence -> list of source words (for reporting)
    alph_to_words = defaultdict(list)

    with open(wordlist_path) as f:
        for line in f:
            w = line.strip().upper()
            if len(w) < 2 or not az_only.match(w):
                continue
            # Generate keyed alphabet using AZ as base
            seq = keyword_mixed_alphabet(w, ALPH)
            if len(alph_to_words[seq]) < 3:  # Keep up to 3 example words per alphabet
                alph_to_words[seq].append(w)

    # Also generate with KA as base
    ka_alph_to_words = defaultdict(list)
    with open(wordlist_path) as f:
        for line in f:
            w = line.strip().upper()
            if len(w) < 2 or not az_only.match(w):
                continue
            seq = keyword_mixed_alphabet(w, KRYPTOS_ALPHABET)
            if len(ka_alph_to_words[seq]) < 3:
                ka_alph_to_words[seq].append(w)

    return alph_to_words, ka_alph_to_words


# ── Worker function ────────────────────────────────────────────────────────

# These will be set in init_worker
_worker_words = None
_worker_min_word_len = None
_worker_max_word_len = None
_worker_prefixes = None


def init_worker(words_path, min_word_len):
    """Initialize word set in each worker process."""
    global _worker_words, _worker_min_word_len, _worker_max_word_len, _worker_prefixes
    _worker_min_word_len = min_word_len
    _worker_words = set()
    _worker_prefixes = set()
    az_only = re.compile(r'^[A-Z]+$')
    with open(words_path) as f:
        for line in f:
            w = line.strip().upper()
            if len(w) >= min_word_len and az_only.match(w):
                _worker_words.add(w)
                for i in range(1, len(w) + 1):
                    _worker_prefixes.add(w[:i])
    _worker_max_word_len = max((len(w) for w in _worker_words), default=0)


def quick_coverage(text):
    """Fast DP word coverage (0.0-1.0) using worker's word set."""
    text = text.upper()
    n = len(text)
    if n == 0:
        return 0.0
    dp = [0] * (n + 1)
    for i in range(1, n + 1):
        dp[i] = dp[i - 1]
        mx = min(i, _worker_max_word_len)
        for wlen in range(_worker_min_word_len, mx + 1):
            start = i - wlen
            candidate = text[start:i]
            if candidate in _worker_words:
                new = dp[start] + wlen
                if new > dp[i]:
                    dp[i] = new
    return dp[n] / n


def find_words(text):
    """Find English words in text using DP segmentation."""
    text = text.upper()
    n = len(text)
    if n == 0:
        return [], 0.0
    dp = [0] * (n + 1)
    back = [(-1, 0)] * (n + 1)
    for i in range(1, n + 1):
        dp[i] = dp[i - 1]
        back[i] = (i - 1, 0)
        mx = min(i, _worker_max_word_len)
        for wlen in range(_worker_min_word_len, mx + 1):
            start = i - wlen
            candidate = text[start:i]
            if candidate in _worker_words:
                new = dp[start] + wlen
                if new > dp[i]:
                    dp[i] = new
                    back[i] = (start, wlen)
    # Reconstruct
    words = []
    pos = n
    while pos > 0:
        prev, wl = back[pos]
        if wl > 0:
            words.append(text[prev:pos])
        pos = prev
    words.reverse()
    return words, dp[n] / n


def process_chunk(chunk):
    """Process a chunk of (alph_seq, example_words, base_label) tuples."""
    hits = []
    count = 0

    for alph_seq, example_words, base_label in chunk:
        # Build index table for the keyed alphabet (CA role)
        ca_idx = [0] * 26
        for i, ch in enumerate(alph_seq):
            ca_idx[ord(ch) - 65] = i

        for variant_name, key_fn in KEY_FNS.items():
            count += 1
            # Recover key at all 24 crib positions
            key_vals = []
            for ct_n, pt_n in zip(CT_NUMS_AT_CRIBS, PT_NUMS_AT_CRIBS):
                c = ca_idx[ct_n]  # CT char's index in keyed alphabet
                p = pt_n          # PT char's index in AZ (pa=AZ)
                key_vals.append(key_fn(c, p))

            # Bean equality check
            if key_vals[BEAN_IDX_A] != key_vals[BEAN_IDX_B]:
                continue

            # Convert key values to letters (through AZ)
            key_ene = "".join(ALPH[v] for v in key_vals[ENE_SLICE])
            key_bc = "".join(ALPH[v] for v in key_vals[BC_SLICE])
            key_24 = key_ene + key_bc

            # Quick coverage check
            cov_ene = quick_coverage(key_ene)
            cov_bc = quick_coverage(key_bc)

            if cov_ene >= 0.30 or cov_bc >= 0.30:
                words_ene, _ = find_words(key_ene)
                words_bc, _ = find_words(key_bc)
                words_24, cov_24 = find_words(key_24)

                best_cov = max(cov_ene, cov_bc, cov_24)
                longest = max((len(w) for w in words_ene + words_bc), default=0)

                hits.append((
                    best_cov,
                    longest,
                    key_24,
                    f"keyed_alph({','.join(example_words[:2])}|base={base_label})/"
                    f"{variant_name} "
                    f"ene={key_ene}({cov_ene:.2f},{words_ene}) "
                    f"bc={key_bc}({cov_bc:.2f},{words_bc}) "
                    f"alph={alph_seq[:10]}..."
                ))

            # Also convert through the keyed alphabet itself
            key_ene_ka = "".join(alph_seq[v] for v in key_vals[ENE_SLICE])
            key_bc_ka = "".join(alph_seq[v] for v in key_vals[BC_SLICE])

            cov_ene_ka = quick_coverage(key_ene_ka)
            cov_bc_ka = quick_coverage(key_bc_ka)

            if cov_ene_ka >= 0.30 or cov_bc_ka >= 0.30:
                key_24_ka = key_ene_ka + key_bc_ka
                words_ene_ka, _ = find_words(key_ene_ka)
                words_bc_ka, _ = find_words(key_bc_ka)
                words_24_ka, cov_24_ka = find_words(key_24_ka)

                best_cov = max(cov_ene_ka, cov_bc_ka, cov_24_ka)
                longest = max((len(w) for w in words_ene_ka + words_bc_ka), default=0)

                hits.append((
                    best_cov,
                    longest,
                    key_24_ka,
                    f"keyed_alph({','.join(example_words[:2])}|base={base_label})/"
                    f"{variant_name}/out=CA "
                    f"ene={key_ene_ka}({cov_ene_ka:.2f},{words_ene_ka}) "
                    f"bc={key_bc_ka}({cov_bc_ka:.2f},{words_bc_ka}) "
                    f"alph={alph_seq[:10]}..."
                ))

    return hits, count


def attack(ciphertext: str = CT, **params):
    """Full-wordlist keyed alphabet sweep with English key detection."""
    wordlist = params.get("wordlist",
                          os.path.join(_ROOT, "wordlists", "english.txt"))
    n_workers = params.get("workers", max(1, cpu_count() - 2))
    min_word_len = params.get("min_word_len", 4)

    print(f"Loading and deduplicating alphabets from {wordlist}...")
    t0 = time.time()
    az_alphs, ka_alphs = load_and_dedup_alphabets(wordlist)
    t1 = time.time()
    print(f"  AZ-base: {len(az_alphs):,} unique alphabets")
    print(f"  KA-base: {len(ka_alphs):,} unique alphabets")
    print(f"  Dedup time: {t1 - t0:.1f}s")

    # Build work items
    work = []
    for seq, words in az_alphs.items():
        work.append((seq, words, "AZ"))
    for seq, words in ka_alphs.items():
        work.append((seq, words, "KA"))

    total_alphs = len(work)
    print(f"\nTotal unique alphabets: {total_alphs:,}")
    print(f"Configs per alphabet: 3 variants × 2 output alphabets = 6")
    print(f"Total evaluations: ~{total_alphs * 3:,}")
    print(f"Workers: {n_workers}")

    # Chunk work for multiprocessing
    chunk_size = max(1, total_alphs // (n_workers * 4))
    chunks = [work[i:i + chunk_size] for i in range(0, len(work), chunk_size)]
    print(f"Chunks: {len(chunks)} (size ~{chunk_size})")

    print("\nRunning sweep...")
    t2 = time.time()

    all_hits = []
    total_tested = 0

    with Pool(n_workers, initializer=init_worker,
              initargs=(wordlist, min_word_len)) as pool:
        for i, (hits, count) in enumerate(pool.imap_unordered(process_chunk, chunks)):
            all_hits.extend(hits)
            total_tested += count
            if (i + 1) % 50 == 0:
                elapsed = time.time() - t2
                print(f"  Progress: {i+1}/{len(chunks)} chunks, "
                      f"{total_tested:,} configs, "
                      f"{len(all_hits)} hits, "
                      f"{elapsed:.1f}s")

    t3 = time.time()
    print(f"\nSweep complete: {total_tested:,} configs in {t3 - t2:.1f}s")
    print(f"Hits above threshold: {len(all_hits)}")

    # Sort by (coverage desc, longest_word desc)
    all_hits.sort(key=lambda h: (h[0], h[1]), reverse=True)

    # Convert to standard attack() format
    results = [(h[0], h[2], h[3]) for h in all_hits]
    return results


def main():
    print("=" * 70)
    print("KEYED ALPHABET SWEEP — Full English wordlist as alphabet keywords")
    print("Credit: community contribution")
    print("=" * 70)

    results = attack()

    print(f"\nTotal results: {len(results)}")
    if results:
        print("\nTop 50 results (by key fragment English coverage):")
        print("-" * 70)
        for i, (score, key_text, desc) in enumerate(results[:50]):
            print(f"  [{i+1:2d}] coverage={score:.2f}  {desc}")

    print("\n" + "=" * 70)
    signal = [r for r in results if r[0] >= 0.50]
    if signal:
        print(f"SIGNAL: {len(signal)} results with coverage >= 0.50")
    else:
        print("VERDICT: No signal (no key fragments with >= 50% English coverage)")
    print("=" * 70)


if __name__ == "__main__":
    main()
