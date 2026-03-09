#!/usr/bin/env python3
"""
Cipher: crib-only keyword sweep
Family: team
Status: active
Keyspace: 12 keywords x 6 variants x 200K hill-climb iterations x num_workers restarts
Last run:
Best score:
"""
"""E-CRIB-ONLY-KEYWORD-SWEEP: Priority keyword search ranked by CRIB HITS ONLY.

Motivation: If K4 plaintext contains intelligence acronyms (CIA, KGB, NSA, etc.),
quadgram scoring would reject correct decryptions as noise. This script finds
results with high crib hits regardless of quadgram quality.

For each keyword x cipher variant x alphabet:
  1. Decrypt K4 directly (identity permutation) and count crib hits
  2. Search for cribs at ANY position (free crib search)
  3. Check for intelligence jargon substrings
  4. Hill-climb permutations scored by crib hits only (not quadgrams):
     - Start from identity permutation
     - For 200K iterations: swap two positions, keep if crib_hits increases or stays equal
     - Run num_workers parallel restarts per combo

Reports ALL results with crib_hits >= 8 and any results containing intel jargon.
"""
import sys
import os
import json
import time
import random
import multiprocessing as mp
from typing import List, Tuple, Dict, Optional

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, N_CRIBS,
    CRIB_DICT, CRIB_POSITIONS, CRIB_WORDS,
    KRYPTOS_ALPHABET,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text, DECRYPT_FN,
)
from kryptos.kernel.transforms.transposition import apply_perm, invert_perm
from kryptos.kernel.alphabet import Alphabet, AZ, KA
from kryptos.kernel.scoring.crib_score import score_cribs, score_cribs_detailed
from kryptos.kernel.scoring.free_crib import score_free, score_free_fast

# ── Configuration ────────────────────────────────────────────────────────

KEYWORDS = [
    "KRYPTOS", "DEFECTOR", "PARALLAX", "COLOPHON", "ABSCISSA",
    "PEDESTAL", "MONOLITH", "SPYPLANE", "TOPOLOGY", "SHADOW",
    "PALIMPSEST", "VERDIGRIS",
]

VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]
ALPHABETS = [("AZ", AZ), ("KA", KA)]

# Intelligence jargon terms to scan for
INTEL_JARGON = [
    "CIA", "KGB", "NSA", "FBI", "DCI", "NRO", "GRU",
    "DEAD", "DROP", "ASSET", "AGENT", "MOLE", "DEFECT",
    "OPS", "SIGINT", "HUMINT", "LANGLEY", "MOSCOW", "BERLIN",
    "SECRET", "BURIED", "HIDDEN", "MARKER",
]

HILL_CLIMB_ITERS = 200_000
CRIB_HIT_THRESHOLD = 8

# ── Crib positions as a fast lookup ──────────────────────────────────────

# Build sorted list of (position, expected_char) for fast scoring
CRIB_LIST = sorted(CRIB_DICT.items())


# ── Core functions ───────────────────────────────────────────────────────

def keyword_to_numeric_key(keyword: str, alphabet: Alphabet) -> List[int]:
    """Convert a keyword string to a repeating numeric key using the given alphabet."""
    return alphabet.encode(keyword)


def decrypt_with_keyword(
    ct: str,
    keyword: str,
    variant: CipherVariant,
    alphabet: Alphabet,
) -> str:
    """Decrypt ciphertext with a keyword under a given cipher variant and alphabet.

    The alphabet determines how characters map to numbers.
    The keyword is repeated to cover the full ciphertext length.
    """
    key_nums = alphabet.encode(keyword)
    klen = len(key_nums)
    decrypt_fn = DECRYPT_FN[variant]
    idx_table = alphabet.index_table

    result = []
    for i, c in enumerate(ct):
        c_num = idx_table[ord(c) - 65]
        k_num = key_nums[i % klen]
        p_num = decrypt_fn(c_num, k_num)
        result.append(alphabet.idx_to_char(p_num))
    return "".join(result)


def count_crib_hits(text: str) -> int:
    """Count how many crib positions match in the text. Fast, no allocations."""
    hits = 0
    for pos, ch in CRIB_LIST:
        if pos < len(text) and text[pos] == ch:
            hits += 1
    return hits


def find_intel_jargon(text: str) -> List[str]:
    """Find all intelligence jargon terms present as substrings."""
    found = []
    upper = text.upper()
    for term in INTEL_JARGON:
        if term in upper:
            found.append(term)
    return found


def decrypt_permuted(
    ct: str,
    perm: List[int],
    keyword: str,
    variant: CipherVariant,
    alphabet: Alphabet,
) -> str:
    """Apply permutation to CT, then decrypt with keyword."""
    permuted_ct = apply_perm(ct, perm)
    return decrypt_with_keyword(permuted_ct, keyword, variant, alphabet)


# ── Hill climber (crib-only scoring) ─────────────────────────────────────

def hill_climb_worker(args: Tuple) -> Dict:
    """Single hill-climb restart. Scored by crib hits ONLY.

    Returns the best result found in this restart.
    """
    (keyword, variant_name, alph_name, seed, iters) = args

    variant = CipherVariant(variant_name)
    alphabet = AZ if alph_name == "AZ" else KA

    rng = random.Random(seed)

    # Start from identity permutation
    perm = list(range(CT_LEN))
    pt = decrypt_permuted(CT, perm, keyword, variant, alphabet)
    best_hits = count_crib_hits(pt)
    best_perm = list(perm)
    best_pt = pt

    for _ in range(iters):
        # Pick two random positions to swap
        i = rng.randint(0, CT_LEN - 1)
        j = rng.randint(0, CT_LEN - 1)
        if i == j:
            continue

        # Swap
        perm[i], perm[j] = perm[j], perm[i]

        pt = decrypt_permuted(CT, perm, keyword, variant, alphabet)
        hits = count_crib_hits(pt)

        if hits >= best_hits:
            # Keep the swap (accept equal or better)
            best_hits = hits
            best_perm = list(perm)
            best_pt = pt
        else:
            # Revert the swap
            perm[i], perm[j] = perm[j], perm[i]

    # Also do free crib search on best result
    free_score = score_free_fast(best_pt)
    jargon = find_intel_jargon(best_pt)

    return {
        "keyword": keyword,
        "variant": variant_name,
        "alphabet": alph_name,
        "seed": seed,
        "crib_hits": best_hits,
        "free_crib_score": free_score,
        "jargon_found": jargon,
        "plaintext": best_pt,
        "perm_preview": best_perm[:20],
    }


# ── Phase 1: Direct decryption (identity permutation) ───────────────────

def run_direct_decryptions() -> Tuple[List[Dict], List[Dict]]:
    """Test all keyword x variant x alphabet combos with identity permutation.

    Returns (high_crib_results, jargon_results).
    """
    high_crib = []
    jargon_results = []
    configs_tested = 0

    for keyword in KEYWORDS:
        for alph_name, alphabet in ALPHABETS:
            for variant in VARIANTS:
                configs_tested += 1
                pt = decrypt_with_keyword(CT, keyword, variant, alphabet)

                # Anchored crib scoring
                hits = count_crib_hits(pt)
                detail = score_cribs_detailed(pt)

                # Free crib search
                free_score = score_free_fast(pt)

                # Intel jargon scan
                jargon = find_intel_jargon(pt)

                entry = {
                    "keyword": keyword,
                    "variant": variant.value,
                    "alphabet": alph_name,
                    "crib_hits": hits,
                    "ene_hits": detail["ene_score"],
                    "bc_hits": detail["bc_score"],
                    "free_crib_score": free_score,
                    "jargon_found": jargon,
                    "plaintext": pt,
                    "phase": "direct",
                }

                if hits >= CRIB_HIT_THRESHOLD:
                    high_crib.append(entry)
                    print(f"  [CRIB HIT {hits}/24] {keyword}/{variant.value}/{alph_name}: "
                          f"ENE={detail['ene_score']}/13 BC={detail['bc_score']}/11 "
                          f"free={free_score}")
                    print(f"    PT: {pt}")

                if jargon:
                    jargon_results.append(entry)
                    print(f"  [JARGON] {keyword}/{variant.value}/{alph_name}: "
                          f"{jargon} (crib_hits={hits})")
                    print(f"    PT: {pt}")

                if free_score >= 11:
                    print(f"  [FREE CRIB {free_score}] {keyword}/{variant.value}/{alph_name}")
                    print(f"    PT: {pt}")

    print(f"  Direct decryptions tested: {configs_tested}")
    return high_crib, jargon_results


# ── Phase 2: Hill-climb with crib-only scoring ───────────────────────────

def run_hill_climb(num_workers: int) -> Tuple[List[Dict], List[Dict]]:
    """Run parallel hill-climb restarts for all combos.

    Returns (high_crib_results, jargon_results).
    """
    # Build work items: one per keyword x variant x alphabet x restart
    # Use fewer restarts per combo to keep total runtime reasonable
    restarts_per_combo = max(1, num_workers // 2)
    work_items = []

    for keyword in KEYWORDS:
        for alph_name, _ in ALPHABETS:
            for variant in VARIANTS:
                for restart in range(restarts_per_combo):
                    seed = hash((keyword, variant.value, alph_name, restart)) & 0xFFFFFFFF
                    work_items.append((
                        keyword,
                        variant.value,
                        alph_name,
                        seed,
                        HILL_CLIMB_ITERS,
                    ))

    total_combos = len(KEYWORDS) * len(ALPHABETS) * len(VARIANTS)
    total_tasks = len(work_items)
    print(f"  Total combos: {total_combos}")
    print(f"  Restarts per combo: {restarts_per_combo}")
    print(f"  Total hill-climb tasks: {total_tasks}")
    print(f"  Iterations per task: {HILL_CLIMB_ITERS:,}")
    print(f"  Workers: {num_workers}")
    sys.stdout.flush()

    high_crib = []
    jargon_results = []
    completed = 0
    start = time.time()

    with mp.Pool(num_workers) as pool:
        for result in pool.imap_unordered(hill_climb_worker, work_items):
            completed += 1

            if result["crib_hits"] >= CRIB_HIT_THRESHOLD:
                high_crib.append(result)
                print(f"  [CRIB HIT {result['crib_hits']}/24] "
                      f"{result['keyword']}/{result['variant']}/{result['alphabet']} "
                      f"(seed={result['seed']}) free={result['free_crib_score']}")
                print(f"    PT: {result['plaintext']}")
                sys.stdout.flush()

            if result["jargon_found"]:
                jargon_results.append(result)
                if result["crib_hits"] < CRIB_HIT_THRESHOLD:
                    print(f"  [JARGON] {result['keyword']}/{result['variant']}/{result['alphabet']}: "
                          f"{result['jargon_found']} (crib_hits={result['crib_hits']})")
                    sys.stdout.flush()

            if completed % 50 == 0 or completed == total_tasks:
                elapsed = time.time() - start
                rate = completed / elapsed if elapsed > 0 else 0
                eta = (total_tasks - completed) / rate if rate > 0 else 0
                print(f"  Progress: {completed}/{total_tasks} ({rate:.1f}/s, ETA {eta:.0f}s)")
                sys.stdout.flush()

    return high_crib, jargon_results


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    start_time = time.time()
    num_workers = min(os.cpu_count() or 4, 24)

    print("=" * 78)
    print("E-CRIB-ONLY-KEYWORD-SWEEP")
    print("Crib-hit-only scoring (ignoring quadgrams)")
    print("=" * 78)
    print(f"Keywords: {KEYWORDS}")
    print(f"Variants: Vigenere, Beaufort, Variant Beaufort")
    print(f"Alphabets: AZ, KA")
    print(f"Hill-climb iterations: {HILL_CLIMB_ITERS:,}")
    print(f"Crib hit threshold: {CRIB_HIT_THRESHOLD}/24")
    print(f"Workers: {num_workers}")
    print(f"Intel jargon terms: {len(INTEL_JARGON)}")
    print()
    sys.stdout.flush()

    all_high_crib = []
    all_jargon = []

    # ── Phase 1: Direct decryption ───────────────────────────────────────
    print("=" * 78)
    print("PHASE 1: Direct decryptions (identity permutation)")
    print("=" * 78)
    sys.stdout.flush()

    direct_crib, direct_jargon = run_direct_decryptions()
    all_high_crib.extend(direct_crib)
    all_jargon.extend(direct_jargon)

    print(f"\n  Phase 1 complete: {len(direct_crib)} high-crib, {len(direct_jargon)} jargon")
    sys.stdout.flush()

    # ── Phase 2: Hill-climb ──────────────────────────────────────────────
    print()
    print("=" * 78)
    print("PHASE 2: Hill-climb permutation search (crib-only scoring)")
    print("=" * 78)
    sys.stdout.flush()

    climb_crib, climb_jargon = run_hill_climb(num_workers)
    all_high_crib.extend(climb_crib)
    all_jargon.extend(climb_jargon)

    print(f"\n  Phase 2 complete: {len(climb_crib)} high-crib, {len(climb_jargon)} jargon")
    sys.stdout.flush()

    # ── Summary ──────────────────────────────────────────────────────────
    elapsed = time.time() - start_time

    print()
    print("=" * 78)
    print("FINAL SUMMARY")
    print("=" * 78)

    # Sort high crib results by score descending
    all_high_crib.sort(key=lambda x: -x["crib_hits"])

    print(f"\nTotal results with crib_hits >= {CRIB_HIT_THRESHOLD}: {len(all_high_crib)}")

    if all_high_crib:
        print(f"\nTop crib-hit results (ranked by crib hits only, quadgrams IGNORED):")
        for i, r in enumerate(all_high_crib[:30]):
            phase = r.get("phase", "hill-climb")
            ene = r.get("ene_hits", "?")
            bc = r.get("bc_hits", "?")
            print(f"  #{i+1}: {r['crib_hits']}/24 | {r['keyword']}/{r['variant']}/{r['alphabet']} "
                  f"| ENE={ene} BC={bc} | free={r.get('free_crib_score', '?')} "
                  f"| phase={phase}")
            print(f"       PT: {r['plaintext'][:60]}...")

    # Deduplicate jargon results by plaintext
    seen_pt = set()
    unique_jargon = []
    for r in all_jargon:
        if r["plaintext"] not in seen_pt:
            seen_pt.add(r["plaintext"])
            unique_jargon.append(r)

    print(f"\nTotal results with intel jargon: {len(unique_jargon)}")
    if unique_jargon:
        # Sort by number of jargon terms found, then by crib_hits
        unique_jargon.sort(key=lambda x: (-len(x["jargon_found"]), -x["crib_hits"]))
        print(f"\nJargon results:")
        for i, r in enumerate(unique_jargon[:30]):
            print(f"  #{i+1}: jargon={r['jargon_found']} | crib_hits={r['crib_hits']}/24 "
                  f"| {r['keyword']}/{r['variant']}/{r['alphabet']}")
            print(f"       PT: {r['plaintext'][:60]}...")

    best_score = max((r["crib_hits"] for r in all_high_crib), default=0)
    print(f"\nBest crib score: {best_score}/24")
    print(f"Elapsed: {elapsed:.1f}s")
    sys.stdout.flush()

    # ── Save results ─────────────────────────────────────────────────────
    # Remove full perm from saved data to keep file size reasonable
    def clean_for_json(r):
        out = dict(r)
        out.pop("perm_preview", None)
        return out

    output = {
        "experiment": "e_crib_only_keyword_sweep",
        "description": "Crib-hit-only keyword sweep (quadgrams ignored)",
        "keywords": KEYWORDS,
        "variants": ["vigenere", "beaufort", "var_beaufort"],
        "alphabets": ["AZ", "KA"],
        "hill_climb_iters": HILL_CLIMB_ITERS,
        "crib_hit_threshold": CRIB_HIT_THRESHOLD,
        "intel_jargon_terms": INTEL_JARGON,
        "total_high_crib": len(all_high_crib),
        "total_jargon": len(unique_jargon),
        "best_crib_score": best_score,
        "elapsed_seconds": round(elapsed, 1),
        "high_crib_results": [clean_for_json(r) for r in all_high_crib[:100]],
        "jargon_results": [clean_for_json(r) for r in unique_jargon[:100]],
    }

    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "results")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "e_crib_only_keyword_sweep.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {out_path}")

    # Verdict
    if best_score >= 18:
        print("\n*** SIGNAL DETECTED — investigate immediately ***")
    elif best_score >= 10:
        print("\n** INTERESTING — worth further analysis **")
    elif best_score >= CRIB_HIT_THRESHOLD:
        print(f"\nAbove threshold ({CRIB_HIT_THRESHOLD}) but below signal — review jargon hits")
    else:
        print(f"\nVerdict: NOISE — no config reached {CRIB_HIT_THRESHOLD}/24 crib hits")


if __name__ == "__main__":
    main()
