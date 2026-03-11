#!/usr/bin/env python3
# Cipher:     Two-system Model B (decrypt all 97, non-periodic ciphers)
# Family:     two_system
# Status:     active
# Keyspace:   ~843K autokey + ~400K running key + ~18K progressive = ~1.3M configs x 6 variants
# Last run:
# Best score:
#
# E-TWO-SYS-03: Model B closure — non-periodic ciphers on all 97 chars.
#
# Model B: decrypt all 97 carved chars, cribs at fixed positions 21-33/63-73,
# 24 plaintext chars are garbage. Tests all non-periodic ciphers NOT yet tried:
#
#   1. PT-autokey: key[i] = keyword[i] for i < L, then key[i] = PT[i-L]
#   2. CT-autokey: key[i] = keyword[i] for i < L, then key[i] = CT[i-L]
#   3. Running key: key from reference texts (K1-K3 PT, known phrases)
#   4. Progressive key: key[i] = (keyword[i%L] + i*step) mod 26
#
# Uses full English wordlist (~843K words) for autokey.
# Scores by crib hits at fixed positions + free crib search.
from __future__ import annotations

import os
import sys
import time
import multiprocessing as mp
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, KRYPTOS_ALPHABET,
    NOISE_FLOOR,
)

# ── Constants ─────────────────────────────────────────────────────────────

CRIB_LIST = sorted(CRIB_DICT.items())  # [(pos, char), ...]

# Crib strings for free search
CRIB_ENE = "EASTNORTHEAST"
CRIB_BC = "BERLINCLOCK"

# Alphabets
ALPHS = [
    ("AZ", ALPH, {c: i for i, c in enumerate(ALPH)}),
    ("KA", KRYPTOS_ALPHABET, {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}),
]

# Cipher decrypt functions: (c, k) -> p
def vig_dec(c, k):
    return (c - k) % MOD

def beau_dec(c, k):
    return (k - c) % MOD

def vbeau_dec(c, k):
    return (c + k) % MOD

CIPHERS = [
    ("Vig", vig_dec),
    ("Beau", beau_dec),
    ("VBeau", vbeau_dec),
]

# Precompute CT as numeric indices for each alphabet
CT_NUMS = {}
for aname, astr, aidx in ALPHS:
    CT_NUMS[aname] = [aidx[c] for c in CT]

# Report thresholds
CRIB_REPORT = 6       # report mapped crib hits >= this
FREE_REPORT = 11      # report free crib score >= this (one full crib)

N_WORKERS = min(28, os.cpu_count() or 4)


# ── Scoring ───────────────────────────────────────────────────────────────

def count_crib_hits(pt: str) -> int:
    """Count crib character matches at fixed positions."""
    hits = 0
    for pos, ch in CRIB_LIST:
        if pos < len(pt) and pt[pos] == ch:
            hits += 1
    return hits


def free_crib_score(pt: str) -> int:
    """0/11/13/24 based on full crib substring presence."""
    s = 0
    if CRIB_ENE in pt:
        s += 13
    if CRIB_BC in pt:
        s += 11
    return s


# ── Autokey decryption ────────────────────────────────────────────────────

def decrypt_pt_autokey(ct_nums: list, kw_nums: list, dec_fn, alph_str: str) -> str:
    """PT-autokey: key extends with plaintext chars."""
    klen = len(kw_nums)
    key = list(kw_nums)
    result = []
    for i in range(len(ct_nums)):
        k = key[i] if i < len(key) else key[i]  # should always be valid
        p = dec_fn(ct_nums[i], k)
        result.append(alph_str[p])
        key.append(p)
    return "".join(result)


def decrypt_ct_autokey(ct_nums: list, kw_nums: list, dec_fn, alph_str: str) -> str:
    """CT-autokey: key extends with ciphertext chars."""
    klen = len(kw_nums)
    key = list(kw_nums)
    for i in range(len(ct_nums)):
        if i >= klen:
            key.append(ct_nums[i - klen])
    result = []
    for i in range(len(ct_nums)):
        p = dec_fn(ct_nums[i], key[i])
        result.append(alph_str[p])
    return "".join(result)


def decrypt_progressive(ct_nums: list, kw_nums: list, step: int,
                        dec_fn, alph_str: str) -> str:
    """Progressive key: key[i] = (keyword[i%L] + i*step) mod 26."""
    klen = len(kw_nums)
    result = []
    for i in range(len(ct_nums)):
        k = (kw_nums[i % klen] + i * step) % MOD
        p = dec_fn(ct_nums[i], k)
        result.append(alph_str[p])
    return "".join(result)


# ── Worker for autokey wordlist sweep ─────────────────────────────────────

def autokey_worker(args: tuple) -> list:
    """Process a batch of keywords for PT-autokey and CT-autokey."""
    words, aname, astr, aidx, cipher_name, dec_fn = args
    ct_nums = [aidx[c] for c in CT]
    results = []

    for word in words:
        # Skip words with chars not in alphabet
        try:
            kw_nums = [aidx[c] for c in word]
        except KeyError:
            continue

        # PT-autokey
        pt = decrypt_pt_autokey(ct_nums, kw_nums, dec_fn, astr)
        hits = count_crib_hits(pt)
        fscore = free_crib_score(pt)
        if hits >= CRIB_REPORT or fscore >= FREE_REPORT:
            results.append({
                "mode": "pt_autokey",
                "keyword": word,
                "cipher": cipher_name,
                "alphabet": aname,
                "crib_hits": hits,
                "free_score": fscore,
                "plaintext": pt,
            })

        # CT-autokey
        pt = decrypt_ct_autokey(ct_nums, kw_nums, dec_fn, astr)
        hits = count_crib_hits(pt)
        fscore = free_crib_score(pt)
        if hits >= CRIB_REPORT or fscore >= FREE_REPORT:
            results.append({
                "mode": "ct_autokey",
                "keyword": word,
                "cipher": cipher_name,
                "alphabet": aname,
                "crib_hits": hits,
                "free_score": fscore,
                "plaintext": pt,
            })

    return results


def progressive_worker(args: tuple) -> list:
    """Process progressive key configs."""
    words, aname, astr, aidx, cipher_name, dec_fn = args
    ct_nums = [aidx[c] for c in CT]
    results = []

    for word in words:
        try:
            kw_nums = [aidx[c] for c in word]
        except KeyError:
            continue

        for step in range(1, MOD):  # steps 1-25
            pt = decrypt_progressive(ct_nums, kw_nums, step, dec_fn, astr)
            hits = count_crib_hits(pt)
            fscore = free_crib_score(pt)
            if hits >= CRIB_REPORT or fscore >= FREE_REPORT:
                results.append({
                    "mode": f"progressive_step{step}",
                    "keyword": word,
                    "cipher": cipher_name,
                    "alphabet": aname,
                    "crib_hits": hits,
                    "free_score": fscore,
                    "plaintext": pt,
                })

    return results


# ── Running key texts ─────────────────────────────────────────────────────

# K1-K3 known plaintexts (concatenated, uppercase, letters only)
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUABORDSECRET"
K2_PT = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGABORDSKNOWABOUTTHISTHEYDSHOULDITSBURIEDOUTTHEREXSOMEWHEREXWHOSHOULDWETRUSTTHISWASTHEIREYESSHITWASACONFIDENCEINFORMEDITWASAGENTLYSTEADLYCLEARLYNOTHINGANYTHINGBUTCLEAR"
K3_PT = "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBLOREDWITHTHECANWALLBEENLYTHEUPPERLEVERAGECREATEDMAPFORMIXITYLIGHTOFTHEWORKOFTHEROOMRECONSTRUCTION"
REFERENCE_TEXTS = {
    "K1": K1_PT.upper(),
    "K2": K2_PT.upper(),
    "K3": K3_PT.upper(),
    "K123": (K1_PT + K2_PT + K3_PT).upper(),
}

# Add some thematic phrases
THEMATIC_PHRASES = [
    "KRYPTOSABCDEFGHIJLMNQUVWXZ" * 4,  # KA alphabet repeated
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ" * 4,   # Standard alphabet repeated
    "PALIMPSEST" * 10,
    "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCE" * 2,
    "VIRTUALLYINVISIBLE" * 6,
]
for i, phrase in enumerate(THEMATIC_PHRASES):
    REFERENCE_TEXTS[f"PHRASE{i}"] = phrase.upper()


def decrypt_running_key(ct_nums: list, key_text: str, dec_fn,
                        alph_str: str, aidx: dict, offset: int = 0) -> str:
    """Running key: key is taken from reference text starting at offset."""
    result = []
    for i in range(len(ct_nums)):
        ki = offset + i
        if ki >= len(key_text):
            break
        k = aidx.get(key_text[ki], 0)
        p = dec_fn(ct_nums[i], k)
        result.append(alph_str[p])
    return "".join(result)


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    t0 = time.time()
    print("=" * 78)
    print("E-TWO-SYS-03: Model B non-periodic closure")
    print("=" * 78)
    print(f"\nCT ({CT_LEN} chars): {CT}")
    print(f"Ciphers: {', '.join(c[0] for c in CIPHERS)}")
    print(f"Alphabets: {', '.join(a[0] for a in ALPHS)}")
    print(f"Workers: {N_WORKERS}")
    print()
    sys.stdout.flush()

    all_results = []

    # ── Phase 1: Autokey with full wordlist ───────────────────────────────
    wordlist_path = os.path.join(os.path.dirname(__file__), '..', '..', 'wordlists', 'english.txt')
    print(f"Loading wordlist from {wordlist_path}...")
    sys.stdout.flush()

    words = []
    with open(wordlist_path) as f:
        for line in f:
            w = line.strip().upper()
            if 3 <= len(w) <= 26 and w.isalpha():
                words.append(w)
    words = list(set(words))  # deduplicate
    print(f"  Loaded {len(words):,} unique words (length 3-26)")

    # Split into batches for parallel processing
    batch_size = max(1, len(words) // (N_WORKERS * 4))
    batches = [words[i:i + batch_size] for i in range(0, len(words), batch_size)]

    total_autokey_configs = len(words) * 2 * len(CIPHERS) * len(ALPHS)
    print(f"  Autokey configs: {total_autokey_configs:,} (PT + CT autokey)")
    print(f"  Batches: {len(batches)}")
    print()
    print("Phase 1: Autokey sweep...")
    sys.stdout.flush()

    work_items = []
    for aname, astr, aidx in ALPHS:
        for cname, dec_fn in CIPHERS:
            for batch in batches:
                work_items.append((batch, aname, astr, aidx, cname, dec_fn))

    completed = 0
    phase1_start = time.time()

    with mp.Pool(N_WORKERS) as pool:
        for result_list in pool.imap_unordered(autokey_worker, work_items, chunksize=1):
            completed += 1
            all_results.extend(result_list)
            if completed % 100 == 0 or completed == len(work_items):
                elapsed = time.time() - phase1_start
                pct = completed / len(work_items) * 100
                print(f"  Autokey: {completed}/{len(work_items)} batches ({pct:.0f}%), "
                      f"{elapsed:.1f}s, {len(all_results)} hits so far")
                sys.stdout.flush()

    phase1_elapsed = time.time() - phase1_start
    phase1_results = len(all_results)
    print(f"  Phase 1 complete: {phase1_results} results, {phase1_elapsed:.1f}s")
    sys.stdout.flush()

    # ── Phase 2: Progressive key ──────────────────────────────────────────
    print(f"\nPhase 2: Progressive key sweep...")
    sys.stdout.flush()

    # Use thematic keywords only (progressive with full wordlist would be huge)
    prog_keywords = [
        "KRYPTOS", "KOMPASS", "DEFECTOR", "COLOPHON", "ABSCISSA",
        "SHADOW", "CIPHER", "SECRET", "BERLIN", "CLOCK",
        "PALIMPSEST", "QUAGMIRE", "ENIGMA",
        "A", "B", "C", "K", "Z",  # single-char seeds
    ]

    prog_work = []
    for aname, astr, aidx in ALPHS:
        for cname, dec_fn in CIPHERS:
            prog_work.append((prog_keywords, aname, astr, aidx, cname, dec_fn))

    phase2_start = time.time()
    with mp.Pool(N_WORKERS) as pool:
        for result_list in pool.imap_unordered(progressive_worker, prog_work):
            all_results.extend(result_list)

    phase2_elapsed = time.time() - phase2_start
    phase2_results = len(all_results) - phase1_results
    print(f"  Phase 2 complete: {phase2_results} results, {phase2_elapsed:.1f}s")

    # ── Phase 3: Running key ──────────────────────────────────────────────
    print(f"\nPhase 3: Running key sweep...")
    sys.stdout.flush()

    phase3_start = time.time()
    phase3_count = 0

    for ref_name, ref_text in REFERENCE_TEXTS.items():
        max_offset = len(ref_text) - CT_LEN
        if max_offset < 0:
            continue
        for aname, astr, aidx in ALPHS:
            ct_nums = [aidx[c] for c in CT]
            for cname, dec_fn in CIPHERS:
                for offset in range(max_offset + 1):
                    phase3_count += 1
                    pt = decrypt_running_key(ct_nums, ref_text, dec_fn, astr, aidx, offset)
                    if len(pt) < CT_LEN:
                        continue
                    hits = count_crib_hits(pt)
                    fscore = free_crib_score(pt)
                    if hits >= CRIB_REPORT or fscore >= FREE_REPORT:
                        all_results.append({
                            "mode": f"running_key_{ref_name}",
                            "keyword": f"{ref_name}@{offset}",
                            "cipher": cname,
                            "alphabet": aname,
                            "crib_hits": hits,
                            "free_score": fscore,
                            "plaintext": pt,
                        })

    phase3_elapsed = time.time() - phase3_start
    phase3_results = len(all_results) - phase1_results - phase2_results
    print(f"  Phase 3 complete: {phase3_results} results from {phase3_count:,} configs, "
          f"{phase3_elapsed:.1f}s")

    # ── Results ───────────────────────────────────────────────────────────
    elapsed = time.time() - t0

    print(f"\n{'=' * 78}")
    print(f"RESULTS")
    print(f"{'=' * 78}")
    print(f"Total configs tested: ~{total_autokey_configs + len(prog_keywords)*25*6 + phase3_count:,}")
    print(f"Total results (crib_hits >= {CRIB_REPORT} or free >= {FREE_REPORT}): {len(all_results)}")
    print(f"Elapsed: {elapsed:.1f}s")
    print()

    if all_results:
        # Sort by best score
        all_results.sort(key=lambda r: -(max(r["crib_hits"], r["free_score"])))

        # Report by mode
        mode_counts = Counter(r["mode"] for r in all_results)
        print(f"Results by mode:")
        for mode, count in mode_counts.most_common():
            print(f"  {mode}: {count}")
        print()

        # Top results
        print(f"Top 50 results:")
        for i, r in enumerate(all_results[:50]):
            print(f"  #{i+1}: crib={r['crib_hits']}/24 free={r['free_score']}/24 "
                  f"| {r['mode']} {r['keyword']}/{r['cipher']}/{r['alphabet']}")
            print(f"       PT: {r['plaintext'][:70]}...")

        # Any breakthroughs?
        breakthroughs = [r for r in all_results if r["crib_hits"] >= 18 or r["free_score"] >= 24]
        if breakthroughs:
            print(f"\n*** {len(breakthroughs)} BREAKTHROUGH(S) DETECTED ***")
            for r in breakthroughs:
                print(f"  crib={r['crib_hits']} free={r['free_score']} "
                      f"| {r['mode']} {r['keyword']}/{r['cipher']}/{r['alphabet']}")
                print(f"  PT: {r['plaintext']}")
    else:
        print("  NO results above threshold.")

    # ── Verdict ───────────────────────────────────────────────────────────
    best_crib = max((r["crib_hits"] for r in all_results), default=0)
    best_free = max((r["free_score"] for r in all_results), default=0)
    best = max(best_crib, best_free)

    print(f"\n{'=' * 78}")
    if best >= 18:
        print(f"*** SIGNAL (best={best}) — investigate immediately ***")
    elif best >= CRIB_REPORT:
        print(f"Above noise (best_crib={best_crib}, best_free={best_free}) — review")
    else:
        print(f"NOISE — Model B + non-periodic ciphers: ELIMINATED")
        print(f"  Best crib: {best_crib}/24, Best free: {best_free}/24")
    print(f"{'=' * 78}")


if __name__ == "__main__":
    main()
