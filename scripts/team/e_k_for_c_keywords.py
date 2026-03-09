#!/usr/bin/env python3
"""
Cipher: K-for-C keyword candidates (Greek/German K substitution)
Family: team
Status: active
Keyspace: 11 keywords x 6 variants x (direct + 200K hill-climb iters x num_workers restarts) + KOMPASS extended modes + 73-char null hypothesis
Last run:
Best score:
"""
"""E-K-FOR-C-KEYWORDS: Test thematic keywords following the Greek K-for-C pattern.

KRYPTOS uses Greek K where English uses C (Crypto -> Krypto). Other thematic
words may follow this pattern: KOMPASS (German compass), KOLOPHON (Greek colophon),
KRYPTA (German/Greek crypt), etc.

For each keyword:
  1. Direct decryption (identity perm) - Vig/Beau/VBeau x AZ/KA
  2. Count crib hits at positions 21-33 and 63-73
  3. Check for intelligence jargon substrings
  4. Hill-climb permutations (200K iters, crib-hit scoring only)
  5. Bean constraint check: k[27]==k[65] and 21 inequalities
  6. Quadgram score for reference (NOT used for ranking)

For KOMPASS specifically:
  - Periods 1-26 (keyword repeated/truncated)
  - Autokey mode
  - Running key (plaintext feedback)

Also tests 73-char null hypothesis: remove 24 chars from non-crib positions,
decrypt remainder with each keyword/cipher/alphabet.
"""
import sys
import os
import json
import time
import random
import multiprocessing as mp
from typing import List, Tuple, Dict, Optional
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, N_CRIBS,
    CRIB_DICT, CRIB_POSITIONS, CRIB_WORDS,
    KRYPTOS_ALPHABET,
    BEAN_EQ, BEAN_INEQ,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text, DECRYPT_FN, KEY_RECOVERY,
)
from kryptos.kernel.transforms.transposition import apply_perm, invert_perm
from kryptos.kernel.alphabet import Alphabet, AZ, KA
from kryptos.kernel.scoring.crib_score import score_cribs, score_cribs_detailed
from kryptos.kernel.scoring.free_crib import score_free, score_free_fast
from kryptos.kernel.scoring.ic import ic
from kryptos.kernel.constraints.bean import verify_bean, verify_bean_simple, BeanResult

# ── Configuration ────────────────────────────────────────────────────────

# K-for-C keywords in priority order
KEYWORDS = [
    "KOMPASS",     # 5/6 survival, German compass, lodestone theme
    "KOLOPHON",    # 3/6, Greek colophon, final inscription
    "KRYPTA",      # 3/6, German/Greek crypt
    "KIPHER",      # 3/6, K-for-C cipher
    "KRYPTEIA",    # 2/6, Spartan secret police
    "KLEPSYDRA",   # 2/6, Greek water clock
    "KODEX",       # 2/6, Greek/Latin codex
    "KYKLOS",      # 2/6, Greek cycle
    "KOSMOS",      # 2/6, Greek cosmos
    "KOLONNE",     # 2/6, German column
    "KENTRON",     # 1/6, Greek center
]

VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]
ALPHABETS = [("AZ", AZ), ("KA", KA)]

# Intelligence jargon terms to scan for
INTEL_JARGON = [
    "CIA", "KGB", "NSA", "DDR", "STASI",
    "DEAD", "DROP", "ASSET", "AGENT", "SECRET",
    "BURIED", "HIDDEN", "LANGLEY", "MOSCOW", "BERLIN",
]

HILL_CLIMB_ITERS = 200_000
CRIB_HIT_THRESHOLD = 5
NULL_MASKS_PER_KEYWORD = 1000

# ── Crib positions as a fast lookup ──────────────────────────────────────

CRIB_LIST = sorted(CRIB_DICT.items())


# ── Core functions ───────────────────────────────────────────────────────

def decrypt_with_keyword(
    ct: str,
    keyword: str,
    variant: CipherVariant,
    alphabet: Alphabet,
) -> str:
    """Decrypt ciphertext with a keyword under a given cipher variant and alphabet."""
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


def decrypt_with_numeric_key(
    ct: str,
    key_nums: List[int],
    variant: CipherVariant,
    alphabet: Alphabet,
) -> str:
    """Decrypt ciphertext with a numeric key (possibly longer than keyword)."""
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


def decrypt_autokey(
    ct: str,
    keyword: str,
    variant: CipherVariant,
    alphabet: Alphabet,
) -> str:
    """Autokey mode: key = keyword, then each plaintext char feeds into key.

    K[i] = keyword[i] for i < len(keyword)
    K[i] = P[i - len(keyword)] for i >= len(keyword)
    """
    key_seed = alphabet.encode(keyword)
    klen = len(key_seed)
    decrypt_fn = DECRYPT_FN[variant]
    idx_table = alphabet.index_table

    running_key = list(key_seed)
    result = []
    for i, c in enumerate(ct):
        c_num = idx_table[ord(c) - 65]
        k_num = running_key[i] if i < len(running_key) else running_key[i]
        p_num = decrypt_fn(c_num, k_num)
        result.append(alphabet.idx_to_char(p_num))
        # Feed plaintext back as key
        running_key.append(p_num)
    return "".join(result)


def decrypt_running_key(
    ct: str,
    keyword: str,
    variant: CipherVariant,
    alphabet: Alphabet,
) -> str:
    """Running key mode: key repeats but each PT char XORs with next key position.

    Specifically: K[i] = (keyword_nums[i % klen] + P[i-1]) mod 26 for i > 0
    K[0] = keyword_nums[0]
    """
    key_seed = alphabet.encode(keyword)
    klen = len(key_seed)
    decrypt_fn = DECRYPT_FN[variant]
    idx_table = alphabet.index_table

    result = []
    prev_p = 0
    for i, c in enumerate(ct):
        c_num = idx_table[ord(c) - 65]
        k_num = (key_seed[i % klen] + prev_p) % MOD
        p_num = decrypt_fn(c_num, k_num)
        result.append(alphabet.idx_to_char(p_num))
        prev_p = p_num
    return "".join(result)


def count_crib_hits(text: str) -> int:
    """Count how many crib positions match. Fast, no allocations."""
    hits = 0
    for pos, ch in CRIB_LIST:
        if pos < len(text) and text[pos] == ch:
            hits += 1
    return hits


def count_crib_hits_mapped(text: str, position_map: List[int]) -> int:
    """Count crib hits for a reduced text with position mapping.

    position_map[i] = original position that maps to text[i].
    For each crib position, find if it's in position_map and check the char.
    """
    # Build reverse map: original_pos -> new_index
    reverse = {}
    for new_idx, orig_pos in enumerate(position_map):
        reverse[orig_pos] = new_idx
    hits = 0
    for pos, ch in CRIB_LIST:
        if pos in reverse:
            new_idx = reverse[pos]
            if new_idx < len(text) and text[new_idx] == ch:
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


def compute_bean_for_keyword(
    ct: str,
    keyword: str,
    variant: CipherVariant,
    alphabet: Alphabet,
) -> BeanResult:
    """Compute Bean constraints for a keyword decryption.

    Derives the keystream at all positions and checks Bean eq/ineq.
    """
    key_nums = alphabet.encode(keyword)
    klen = len(key_nums)
    # The effective keystream is the repeating keyword
    keystream = [key_nums[i % klen] for i in range(CT_LEN)]
    return verify_bean(keystream)


def compute_quadgram_score(text: str) -> Optional[float]:
    """Compute quadgram score for reference. Returns per-char score or None."""
    try:
        from kryptos.kernel.scoring.ngram import NgramScorer
        scorer = NgramScorer.from_file(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "english_quadgrams.json")
        )
        return scorer.score_per_char(text)
    except Exception:
        return None


# Load quadgram scorer once at module level (if available)
_NGRAM_SCORER = None
def get_ngram_scorer():
    global _NGRAM_SCORER
    if _NGRAM_SCORER is None:
        try:
            from kryptos.kernel.scoring.ngram import NgramScorer
            _NGRAM_SCORER = NgramScorer.from_file(
                os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "english_quadgrams.json")
            )
        except Exception:
            pass
    return _NGRAM_SCORER


# ── Hill climber (crib-only scoring) ─────────────────────────────────────

def hill_climb_worker(args: Tuple) -> Dict:
    """Single hill-climb restart. Scored by crib hits ONLY."""
    (keyword, variant_name, alph_name, seed, iters) = args

    variant = CipherVariant(variant_name)
    alphabet = AZ if alph_name == "AZ" else KA

    rng = random.Random(seed)

    # Start from identity permutation
    perm = list(range(CT_LEN))
    permuted_ct = apply_perm(CT, perm)
    pt = decrypt_with_keyword(permuted_ct, keyword, variant, alphabet)
    best_hits = count_crib_hits(pt)
    best_perm = list(perm)
    best_pt = pt

    for _ in range(iters):
        i = rng.randint(0, CT_LEN - 1)
        j = rng.randint(0, CT_LEN - 1)
        if i == j:
            continue

        perm[i], perm[j] = perm[j], perm[i]
        permuted_ct = apply_perm(CT, perm)
        pt = decrypt_with_keyword(permuted_ct, keyword, variant, alphabet)
        hits = count_crib_hits(pt)

        if hits >= best_hits:
            best_hits = hits
            best_perm = list(perm)
            best_pt = pt
        else:
            perm[i], perm[j] = perm[j], perm[i]

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


# ── 73-char null hypothesis worker ──────────────────────────────────────

def null_mask_worker(args: Tuple) -> Dict:
    """Test a random null mask: remove 24 non-crib chars, decrypt 73 remainder."""
    (keyword, variant_name, alph_name, seed) = args

    variant = CipherVariant(variant_name)
    alphabet = AZ if alph_name == "AZ" else KA
    rng = random.Random(seed)

    # Non-crib positions that can be nulls
    non_crib = [i for i in range(CT_LEN) if i not in CRIB_POSITIONS]
    # Need to remove 24 positions from non-crib (there are 97-24=73 non-crib positions)
    # But we must keep all 24 crib positions, so we remove 24 from the 73 non-crib
    nulls = set(rng.sample(non_crib, 24))

    # Build the 73-char reduced CT and position map
    reduced_ct = []
    position_map = []
    for i in range(CT_LEN):
        if i not in nulls:
            reduced_ct.append(CT[i])
            position_map.append(i)
    reduced_ct_str = "".join(reduced_ct)

    # Decrypt with keyword
    pt = decrypt_with_keyword(reduced_ct_str, keyword, variant, alphabet)

    # Score: count crib hits at mapped positions
    hits = count_crib_hits_mapped(pt, position_map)

    # Also check for jargon
    jargon = find_intel_jargon(pt)

    # Free crib search (cribs may appear at any position in the 73-char text)
    free_score = score_free_fast(pt)

    best_result = {
        "keyword": keyword,
        "variant": variant_name,
        "alphabet": alph_name,
        "seed": seed,
        "crib_hits": hits,
        "free_crib_score": free_score,
        "jargon_found": jargon,
        "plaintext": pt,
        "null_positions": sorted(nulls),
    }

    return best_result


# ── Phase 1: Direct decryption ───────────────────────────────────────────

def run_direct_decryptions() -> Tuple[List[Dict], List[Dict]]:
    """Test all keyword x variant x alphabet combos with identity permutation."""
    high_crib = []
    jargon_results = []
    all_results = []
    configs_tested = 0

    for keyword in KEYWORDS:
        for alph_name, alphabet in ALPHABETS:
            for variant in VARIANTS:
                configs_tested += 1
                pt = decrypt_with_keyword(CT, keyword, variant, alphabet)

                hits = count_crib_hits(pt)
                detail = score_cribs_detailed(pt)
                free_score = score_free_fast(pt)
                jargon = find_intel_jargon(pt)
                bean = compute_bean_for_keyword(CT, keyword, variant, alphabet)
                ic_val = ic(pt)

                # Quadgram for reference
                scorer = get_ngram_scorer()
                qg = scorer.score_per_char(pt) if scorer else None

                entry = {
                    "keyword": keyword,
                    "variant": variant.value,
                    "alphabet": alph_name,
                    "crib_hits": hits,
                    "ene_hits": detail["ene_score"],
                    "bc_hits": detail["bc_score"],
                    "free_crib_score": free_score,
                    "jargon_found": jargon,
                    "bean_passed": bean.passed,
                    "bean_eq": bean.eq_satisfied,
                    "bean_ineq": f"{bean.ineq_satisfied}/{bean.ineq_total}",
                    "ic": round(ic_val, 4),
                    "quadgram_pc": round(qg, 3) if qg is not None else None,
                    "plaintext": pt,
                    "phase": "direct",
                }

                all_results.append(entry)

                if hits >= CRIB_HIT_THRESHOLD:
                    high_crib.append(entry)
                    print(f"  [CRIB HIT {hits}/24] {keyword}/{variant.value}/{alph_name}: "
                          f"ENE={detail['ene_score']}/13 BC={detail['bc_score']}/11 "
                          f"free={free_score} bean={'PASS' if bean.passed else 'FAIL'} "
                          f"IC={ic_val:.4f}")
                    print(f"    PT: {pt}")

                if jargon:
                    jargon_results.append(entry)
                    print(f"  [JARGON] {keyword}/{variant.value}/{alph_name}: "
                          f"{jargon} (crib_hits={hits})")
                    print(f"    PT: {pt}")

                if free_score >= 11:
                    print(f"  [FREE CRIB {free_score}] {keyword}/{variant.value}/{alph_name}")
                    print(f"    PT: {pt}")

    # Print all direct results sorted by crib hits
    print(f"\n  Direct decryptions tested: {configs_tested}")
    print(f"\n  All direct results (sorted by crib_hits desc):")
    all_results.sort(key=lambda x: (-x["crib_hits"], x["keyword"]))
    for r in all_results[:30]:
        bean_tag = "PASS" if r["bean_passed"] else "FAIL"
        qg_str = f"qg={r['quadgram_pc']:.3f}" if r["quadgram_pc"] is not None else "qg=N/A"
        print(f"    {r['crib_hits']:2d}/24 | {r['keyword']:12s}/{r['variant']:12s}/{r['alphabet']} | "
              f"ENE={r['ene_hits']:2d}/13 BC={r['bc_hits']:2d}/11 | "
              f"bean={bean_tag} ({r['bean_ineq']}) | IC={r['ic']:.4f} | {qg_str}")

    return high_crib, jargon_results


# ── Phase 2: KOMPASS extended modes ──────────────────────────────────────

def run_kompass_extended() -> Tuple[List[Dict], List[Dict]]:
    """KOMPASS-specific extended testing: periods 1-26, autokey, running key."""
    keyword = "KOMPASS"
    high_crib = []
    jargon_results = []
    configs_tested = 0

    print(f"\n  Testing KOMPASS at periods 1-26...")
    for period in range(1, 27):
        # Truncate or repeat keyword to given period
        key_full = keyword * ((period // len(keyword)) + 1)
        key_at_period = key_full[:period]

        for alph_name, alphabet in ALPHABETS:
            for variant in VARIANTS:
                configs_tested += 1
                pt = decrypt_with_keyword(CT, key_at_period, variant, alphabet)

                hits = count_crib_hits(pt)
                detail = score_cribs_detailed(pt)
                free_score = score_free_fast(pt)
                jargon = find_intel_jargon(pt)
                bean_ks = [alphabet.encode(key_at_period)[i % period] for i in range(CT_LEN)]
                bean = verify_bean(bean_ks)
                ic_val = ic(pt)

                entry = {
                    "keyword": f"KOMPASS(p={period},key={key_at_period})",
                    "variant": variant.value,
                    "alphabet": alph_name,
                    "crib_hits": hits,
                    "ene_hits": detail["ene_score"],
                    "bc_hits": detail["bc_score"],
                    "free_crib_score": free_score,
                    "jargon_found": jargon,
                    "bean_passed": bean.passed,
                    "bean_ineq": f"{bean.ineq_satisfied}/{bean.ineq_total}",
                    "ic": round(ic_val, 4),
                    "plaintext": pt,
                    "phase": "kompass_period",
                    "period": period,
                }

                if hits >= CRIB_HIT_THRESHOLD:
                    high_crib.append(entry)
                    print(f"  [CRIB HIT {hits}/24] KOMPASS p={period} key={key_at_period} "
                          f"{variant.value}/{alph_name}: "
                          f"ENE={detail['ene_score']}/13 BC={detail['bc_score']}/11 "
                          f"bean={'PASS' if bean.passed else 'FAIL'}")
                    print(f"    PT: {pt}")

                if jargon:
                    jargon_results.append(entry)
                    print(f"  [JARGON] KOMPASS p={period} {variant.value}/{alph_name}: {jargon}")

    print(f"\n  Testing KOMPASS autokey mode...")
    for alph_name, alphabet in ALPHABETS:
        for variant in VARIANTS:
            configs_tested += 1
            pt = decrypt_autokey(CT, keyword, variant, alphabet)

            hits = count_crib_hits(pt)
            detail = score_cribs_detailed(pt)
            free_score = score_free_fast(pt)
            jargon = find_intel_jargon(pt)
            ic_val = ic(pt)

            entry = {
                "keyword": "KOMPASS(autokey)",
                "variant": variant.value,
                "alphabet": alph_name,
                "crib_hits": hits,
                "ene_hits": detail["ene_score"],
                "bc_hits": detail["bc_score"],
                "free_crib_score": free_score,
                "jargon_found": jargon,
                "bean_passed": False,  # autokey has no simple periodic Bean check
                "ic": round(ic_val, 4),
                "plaintext": pt,
                "phase": "kompass_autokey",
            }

            if hits >= CRIB_HIT_THRESHOLD:
                high_crib.append(entry)
                print(f"  [CRIB HIT {hits}/24] KOMPASS autokey {variant.value}/{alph_name}: "
                      f"ENE={detail['ene_score']}/13 BC={detail['bc_score']}/11")
                print(f"    PT: {pt}")

            if jargon:
                jargon_results.append(entry)
                print(f"  [JARGON] KOMPASS autokey {variant.value}/{alph_name}: {jargon}")
                print(f"    PT: {pt}")

    print(f"\n  Testing KOMPASS running key mode (PT feedback)...")
    for alph_name, alphabet in ALPHABETS:
        for variant in VARIANTS:
            configs_tested += 1
            pt = decrypt_running_key(CT, keyword, variant, alphabet)

            hits = count_crib_hits(pt)
            detail = score_cribs_detailed(pt)
            free_score = score_free_fast(pt)
            jargon = find_intel_jargon(pt)
            ic_val = ic(pt)

            entry = {
                "keyword": "KOMPASS(running_key)",
                "variant": variant.value,
                "alphabet": alph_name,
                "crib_hits": hits,
                "ene_hits": detail["ene_score"],
                "bc_hits": detail["bc_score"],
                "free_crib_score": free_score,
                "jargon_found": jargon,
                "bean_passed": False,
                "ic": round(ic_val, 4),
                "plaintext": pt,
                "phase": "kompass_running_key",
            }

            if hits >= CRIB_HIT_THRESHOLD:
                high_crib.append(entry)
                print(f"  [CRIB HIT {hits}/24] KOMPASS running_key {variant.value}/{alph_name}: "
                      f"ENE={detail['ene_score']}/13 BC={detail['bc_score']}/11")
                print(f"    PT: {pt}")

            if jargon:
                jargon_results.append(entry)
                print(f"  [JARGON] KOMPASS running_key {variant.value}/{alph_name}: {jargon}")
                print(f"    PT: {pt}")

    print(f"  KOMPASS extended configs tested: {configs_tested}")
    return high_crib, jargon_results


# ── Phase 3: Hill-climb ──────────────────────────────────────────────────

def run_hill_climb(num_workers: int) -> Tuple[List[Dict], List[Dict]]:
    """Run parallel hill-climb restarts for all combos."""
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


# ── Phase 4: 73-char null hypothesis ─────────────────────────────────────

def run_null_hypothesis(num_workers: int) -> Tuple[List[Dict], List[Dict]]:
    """Test 73-char null hypothesis: remove 24 chars from non-crib positions."""
    work_items = []
    base_seed = 42

    for keyword in KEYWORDS:
        for alph_name, _ in ALPHABETS:
            for variant in VARIANTS:
                for mask_idx in range(NULL_MASKS_PER_KEYWORD):
                    seed = hash((keyword, variant.value, alph_name, base_seed, mask_idx)) & 0xFFFFFFFF
                    work_items.append((keyword, variant.value, alph_name, seed))

    total_tasks = len(work_items)
    print(f"  Total null-mask tasks: {total_tasks}")
    print(f"  Masks per keyword x variant x alphabet: {NULL_MASKS_PER_KEYWORD}")
    print(f"  Workers: {num_workers}")
    sys.stdout.flush()

    high_crib = []
    jargon_results = []
    completed = 0
    start = time.time()

    with mp.Pool(num_workers) as pool:
        for result in pool.imap_unordered(null_mask_worker, work_items, chunksize=100):
            completed += 1

            if result["crib_hits"] >= CRIB_HIT_THRESHOLD:
                high_crib.append(result)
                print(f"  [NULL CRIB HIT {result['crib_hits']}/24] "
                      f"{result['keyword']}/{result['variant']}/{result['alphabet']} "
                      f"free={result['free_crib_score']}")
                print(f"    PT: {result['plaintext']}")
                sys.stdout.flush()

            if result["jargon_found"]:
                jargon_results.append(result)
                if result["crib_hits"] < CRIB_HIT_THRESHOLD:
                    pass  # Too many to print individually

            if completed % 5000 == 0 or completed == total_tasks:
                elapsed = time.time() - start
                rate = completed / elapsed if elapsed > 0 else 0
                eta = (total_tasks - completed) / rate if rate > 0 else 0
                print(f"  Null progress: {completed}/{total_tasks} ({rate:.1f}/s, ETA {eta:.0f}s)")
                sys.stdout.flush()

    return high_crib, jargon_results


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    start_time = time.time()
    num_workers = min(os.cpu_count() or 4, 24)

    print("=" * 78)
    print("E-K-FOR-C-KEYWORDS: K-for-C thematic keyword candidates")
    print("Greek/German K substitution pattern (Crypto -> Krypto)")
    print("=" * 78)
    print(f"Keywords: {KEYWORDS}")
    print(f"Priority lead: KOMPASS (5/6 pigeonhole survival, German compass)")
    print(f"Variants: Vigenere, Beaufort, Variant Beaufort")
    print(f"Alphabets: AZ, KA")
    print(f"Hill-climb iterations: {HILL_CLIMB_ITERS:,}")
    print(f"Crib hit threshold: {CRIB_HIT_THRESHOLD}/24")
    print(f"Null masks per combo: {NULL_MASKS_PER_KEYWORD}")
    print(f"Workers: {num_workers}")
    print(f"Intel jargon terms: {len(INTEL_JARGON)}")
    print(f"CT: {CT}")
    print(f"CT len: {CT_LEN}")
    print()
    sys.stdout.flush()

    all_high_crib = []
    all_jargon = []

    # ── Phase 1: Direct decryption ───────────────────────────────────────
    print("=" * 78)
    print("PHASE 1: Direct decryptions (identity permutation, all keywords)")
    print("=" * 78)
    sys.stdout.flush()

    direct_crib, direct_jargon = run_direct_decryptions()
    all_high_crib.extend(direct_crib)
    all_jargon.extend(direct_jargon)

    print(f"\n  Phase 1 complete: {len(direct_crib)} high-crib, {len(direct_jargon)} jargon")
    sys.stdout.flush()

    # ── Phase 2: KOMPASS extended ─────────────────────────────────────────
    print()
    print("=" * 78)
    print("PHASE 2: KOMPASS extended modes (periods, autokey, running key)")
    print("=" * 78)
    sys.stdout.flush()

    kompass_crib, kompass_jargon = run_kompass_extended()
    all_high_crib.extend(kompass_crib)
    all_jargon.extend(kompass_jargon)

    print(f"\n  Phase 2 complete: {len(kompass_crib)} high-crib, {len(kompass_jargon)} jargon")
    sys.stdout.flush()

    # ── Phase 3: Hill-climb ──────────────────────────────────────────────
    print()
    print("=" * 78)
    print("PHASE 3: Hill-climb permutation search (crib-only scoring)")
    print("=" * 78)
    sys.stdout.flush()

    climb_crib, climb_jargon = run_hill_climb(num_workers)
    all_high_crib.extend(climb_crib)
    all_jargon.extend(climb_jargon)

    print(f"\n  Phase 3 complete: {len(climb_crib)} high-crib, {len(climb_jargon)} jargon")
    sys.stdout.flush()

    # ── Phase 4: 73-char null hypothesis ──────────────────────────────────
    print()
    print("=" * 78)
    print("PHASE 4: 73-char null hypothesis (remove 24 non-crib chars)")
    print("=" * 78)
    sys.stdout.flush()

    null_crib, null_jargon = run_null_hypothesis(num_workers)
    all_high_crib.extend(null_crib)
    all_jargon.extend(null_jargon)

    print(f"\n  Phase 4 complete: {len(null_crib)} high-crib, {len(null_jargon)} jargon")
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
        print(f"\nTop crib-hit results (ranked by crib hits, quadgrams IGNORED):")
        for i, r in enumerate(all_high_crib[:50]):
            phase = r.get("phase", "hill-climb")
            ene = r.get("ene_hits", "?")
            bc = r.get("bc_hits", "?")
            bean_str = ""
            if "bean_passed" in r:
                bean_str = f" bean={'PASS' if r['bean_passed'] else 'FAIL'}"
            print(f"  #{i+1}: {r['crib_hits']}/24 | {r['keyword']}/{r['variant']}/{r['alphabet']} "
                  f"| ENE={ene} BC={bc} | free={r.get('free_crib_score', '?')} "
                  f"|{bean_str} | phase={phase}")
            print(f"       PT: {r['plaintext'][:70]}...")

    # Deduplicate jargon results by plaintext
    seen_pt = set()
    unique_jargon = []
    for r in all_jargon:
        if r["plaintext"] not in seen_pt:
            seen_pt.add(r["plaintext"])
            unique_jargon.append(r)

    print(f"\nTotal results with intel jargon: {len(unique_jargon)}")
    if unique_jargon:
        unique_jargon.sort(key=lambda x: (-len(x["jargon_found"]), -x["crib_hits"]))
        print(f"\nJargon results (top 30):")
        for i, r in enumerate(unique_jargon[:30]):
            print(f"  #{i+1}: jargon={r['jargon_found']} | crib_hits={r['crib_hits']}/24 "
                  f"| {r['keyword']}/{r['variant']}/{r['alphabet']}")
            print(f"       PT: {r['plaintext'][:70]}...")

    # KOMPASS-specific summary
    print()
    print("=" * 78)
    print("KOMPASS-SPECIFIC RESULTS")
    print("=" * 78)
    kompass_results = [r for r in all_high_crib if "KOMPASS" in str(r.get("keyword", ""))]
    if kompass_results:
        print(f"  KOMPASS results with crib_hits >= {CRIB_HIT_THRESHOLD}: {len(kompass_results)}")
        for i, r in enumerate(kompass_results[:20]):
            print(f"  #{i+1}: {r['crib_hits']}/24 | {r['keyword']}/{r['variant']}/{r['alphabet']} "
                  f"| phase={r.get('phase', '?')}")
            print(f"       PT: {r['plaintext'][:70]}...")
    else:
        print(f"  No KOMPASS results reached {CRIB_HIT_THRESHOLD}/24 crib hits")

    kompass_jargon = [r for r in unique_jargon if "KOMPASS" in str(r.get("keyword", ""))]
    if kompass_jargon:
        print(f"\n  KOMPASS jargon results: {len(kompass_jargon)}")
        for r in kompass_jargon[:10]:
            print(f"    jargon={r['jargon_found']} | {r['keyword']}/{r['variant']}/{r['alphabet']} "
                  f"| crib_hits={r['crib_hits']}")

    best_score = max((r["crib_hits"] for r in all_high_crib), default=0)
    print(f"\nBest overall crib score: {best_score}/24")
    print(f"Elapsed: {elapsed:.1f}s")
    sys.stdout.flush()

    # ── Save results ─────────────────────────────────────────────────────
    def clean_for_json(r):
        out = dict(r)
        out.pop("perm_preview", None)
        # Convert sets to lists for JSON
        if "null_positions" in out and isinstance(out["null_positions"], set):
            out["null_positions"] = sorted(out["null_positions"])
        return out

    output = {
        "experiment": "e_k_for_c_keywords",
        "description": "K-for-C thematic keyword candidates (Greek/German K substitution)",
        "keywords": KEYWORDS,
        "variants": ["vigenere", "beaufort", "var_beaufort"],
        "alphabets": ["AZ", "KA"],
        "hill_climb_iters": HILL_CLIMB_ITERS,
        "crib_hit_threshold": CRIB_HIT_THRESHOLD,
        "null_masks_per_keyword": NULL_MASKS_PER_KEYWORD,
        "intel_jargon_terms": INTEL_JARGON,
        "total_high_crib": len(all_high_crib),
        "total_jargon": len(unique_jargon),
        "best_crib_score": best_score,
        "elapsed_seconds": round(elapsed, 1),
        "high_crib_results": [clean_for_json(r) for r in all_high_crib[:200]],
        "jargon_results": [clean_for_json(r) for r in unique_jargon[:100]],
    }

    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "results")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "e_k_for_c_keywords.json")
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
