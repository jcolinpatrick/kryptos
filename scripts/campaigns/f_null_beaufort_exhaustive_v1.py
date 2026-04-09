#!/usr/bin/env python3 -u
"""
=================================================================
EXHAUSTIVE NULL-MASK + BEAUFORT CAMPAIGN v1
=================================================================
Cipher:     Null masking (stego) + Beaufort A=0
Family:     null_mask_beaufort
Status:     exhausted
Keyspace:   Phase1: C(56,7)=232M masks; Phase2: 26^1..26^8 keys;
            Phase3: ~425 thematic + ~1M English keywords; Phase4: ~200 anomaly masks
Last run:   2026-04-08
Best score: 0.0 (Phase 2 formally UNSAT, all 44,400 CSPs unsatisfiable;
            certificate at results/admissibility_elimination_v1/null_beaufort_phase2.json)

HYPOTHESIS
----------
Jim Sanborn wrote "Beaufort Cipher" in his notebook (Archives of American Art,
IMG_1569/1571). K4's 97 characters contain 24 nulls; removing them yields 73
"real" CT characters. The 73-char text decrypts via Beaufort A=0 (supported by
BCL keystream palette enrichment, p=0.000627).

"Compass Cipher" = CIA lodestone deflects compass to 73 deg (ENE) = PT length.
"Morse code" / "alphabet code" = instructions for identifying null positions.

PHASES
------
1. Consensus-extended mask enumeration: 17 known + enumerate 7 more from 56
2. Key-first periodic Beaufort sweep: periods 1-8 exhaustive
3. Keyword-mixed alphabet sweep: thematic + English words + Weltzeituhr cities
4. Anomaly-guided mask construction: mod-5, width-21, interval-4, etc.
5. Reverse validation for any hit >= 18/24
=================================================================
"""

import sys
import os
import json
import time
import argparse
from itertools import combinations, product
from multiprocessing import Pool, cpu_count
from math import comb

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, 'src')):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CONSENSUS_NULL_POSITIONS, CRIB_WORDS, CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD, BREAKTHROUGH_THRESHOLD,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)
from kryptos.kernel.transforms.vigenere import beau_recover_key, beau_decrypt
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free
from kryptos.kernel.alphabet import keyword_mixed_alphabet

# ── Configuration ─────────────────────────────────────────────────

WORKERS = max(1, cpu_count() - 2)
PHASE1_REPORT_INTERVAL = 1_000_000
PHASE2_REPORT_INTERVAL = 500_000

ENE_WORD = "EASTNORTHEAST"
BCL_WORD = "BERLINCLOCK"
ENE_START = 21  # 0-indexed position in 97-char CT
BCL_START = 63

CT_INTS = [ord(c) - 65 for c in CT]

RESULTS_PATH = os.path.join(_ROOT, "results", "null_beaufort_exhaustive_v1.json")
CHECKPOINT_PATH = os.path.join(_ROOT, "checkpoints", "f_null_beaufort_exhaustive_v1.json")

# BCL palette constraint: key values at BCL positions should be these
PALETTE_VALUES = frozenset({1, 6, 8, 10, 14, 22, 25})  # B,G,I,K,O,W,Z

# Weltzeituhr Facet 6 (73 deg) city names - 1989 versions
WELTZEITUHR_KEYWORDS = [
    "OMSK", "ALMATA", "ALMAATA", "TASCHKENT", "TASHKENT",
    "NOWOSIBIRSK", "NOVOSIBIRSK", "RANGUN", "RANGOON", "DHAKA", "DACCA",
    "BERLIN", "ALEXANDERPLATZ", "URANIA", "WELTZEITUHR",
    "OATNRD",  # facet 6 city initials
    "ECLIPSE",  # Sanborn notebook (IMG_1569/1571)
]

# ── Crib helpers ──────────────────────────────────────────────────

# Pre-compute crib entries as (original_pos, pt_char, pt_int)
CRIB_ENTRIES = []
for start, word in CRIB_WORDS:
    for i, ch in enumerate(word):
        CRIB_ENTRIES.append((start + i, ch, ord(ch) - 65))


def adjust_crib_positions(null_positions):
    """Given null positions (set), compute where each crib lands in the
    extracted 73-char text. Returns list of (new_pos, pt_int) tuples."""
    null_sorted = sorted(null_positions)
    adjusted = []
    for orig_pos, _, pt_int in CRIB_ENTRIES:
        # Count how many nulls are before this position
        shift = sum(1 for n in null_sorted if n < orig_pos)
        new_pos = orig_pos - shift
        adjusted.append((new_pos, pt_int))
    return adjusted


def check_periodicity(key_values, max_period=36):
    """Given list of (position, key_value) pairs, find all consistent periods.
    Returns list of (period, full_key) tuples."""
    if not key_values:
        return []

    results = []
    for p in range(1, max_period + 1):
        # Group by residue class
        residues = {}
        consistent = True
        for pos, kval in key_values:
            r = pos % p
            if r in residues:
                if residues[r] != kval:
                    consistent = False
                    break
            else:
                residues[r] = kval
        if consistent and len(residues) == p:
            # All residue classes filled — we have a complete key
            full_key = [residues[r] for r in range(p)]
            results.append((p, full_key))
    return results


# ── Phase 1: Consensus-extended mask enumeration ──────────────────

def _init_phase1():
    """Worker init — pre-compute constants in each process."""
    global _CT_INTS, _CRIB_ENTRIES_GLOBAL
    _CT_INTS = CT_INTS
    _CRIB_ENTRIES_GLOBAL = CRIB_ENTRIES


def worker_phase1(extra7):
    """Process one 24-position null mask (17 consensus + 7 extra).
    Returns list of (score, plaintext, method_desc, mask, key, period) or empty list."""
    mask = set(CONSENSUS_NULL_POSITIONS) | set(extra7)
    assert len(mask) == 24

    # Extract 73-char CT
    ct73_ints = [_CT_INTS[i] for i in range(CT_LEN) if i not in mask]
    if len(ct73_ints) != 73:
        return []

    # Compute adjusted crib positions and recover key
    null_sorted = sorted(mask)
    key_at_cribs = []
    for orig_pos, _, pt_int in _CRIB_ENTRIES_GLOBAL:
        shift = sum(1 for n in null_sorted if n < orig_pos)
        new_pos = orig_pos - shift
        if new_pos < 73:
            k = (ct73_ints[new_pos] + pt_int) % MOD
            key_at_cribs.append((new_pos, k))

    if len(key_at_cribs) != N_CRIBS:
        return []

    # Check periodicity of recovered key
    periods = check_periodicity(key_at_cribs, max_period=36)
    if not periods:
        return []

    results = []
    ct73 = ''.join(chr(v + 65) for v in ct73_ints)

    for period, full_key in periods:
        # Decrypt full 73 chars with this periodic key
        pt_chars = []
        for i, c_int in enumerate(ct73_ints):
            k = full_key[i % period]
            pt_chars.append(chr(beau_decrypt(c_int, k) + 65))
        plaintext = ''.join(pt_chars)

        # Score
        sb = score_candidate(plaintext)
        score = sb.crib_score

        if score >= STORE_THRESHOLD:
            mask_list = sorted(mask)
            method = f"phase1:consensus+7|period={period}|key={''.join(chr(k+65) for k in full_key)}"
            results.append((score, plaintext, method, mask_list, full_key, period))

    return results


def run_phase1(smoke=False):
    """Enumerate all C(56,7) mask completions."""
    available = sorted(set(range(CT_LEN)) - CRIB_POSITIONS - CONSENSUS_NULL_POSITIONS)
    total = comb(len(available), 7)

    print(f"\n{'='*70}")
    print(f"PHASE 1: Consensus-Extended Mask Enumeration")
    print(f"  Consensus nulls: {sorted(CONSENSUS_NULL_POSITIONS)}")
    print(f"  Available positions: {len(available)}")
    print(f"  Combinations C({len(available)},7) = {total:,}")
    print(f"  Workers: {WORKERS}")
    print(f"{'='*70}")
    sys.stdout.flush()

    def gen():
        for i, extra7 in enumerate(combinations(available, 7)):
            if smoke and i >= 1000:
                break
            yield extra7

    start = time.time()
    hits = []
    count = 0
    best_score = 0

    with Pool(WORKERS, initializer=_init_phase1) as pool:
        for result_list in pool.imap_unordered(worker_phase1, gen(), chunksize=256):
            count += 1
            if result_list:
                for r in result_list:
                    hits.append(r)
                    if r[0] > best_score:
                        best_score = r[0]
                        print(f"  NEW BEST: score={r[0]}/24 period={r[5]} "
                              f"key={''.join(chr(k+65) for k in r[4])} "
                              f"pt={r[1][:40]}...")
                        sys.stdout.flush()
                    if r[0] >= SIGNAL_THRESHOLD:
                        print(f"\n  *** SIGNAL *** score={r[0]}/24")
                        print(f"  PT: {r[1]}")
                        print(f"  Method: {r[2]}")
                        print(f"  Mask: {r[3]}")
                        sys.stdout.flush()
            if count % PHASE1_REPORT_INTERVAL == 0:
                elapsed = time.time() - start
                rate = count / elapsed
                est_remain = (total - count) / rate if rate > 0 else 0
                print(f"  [{count:,}/{total:,}] {count/total*100:.1f}% | "
                      f"{rate:,.0f} masks/s | best={best_score}/24 | "
                      f"ETA {est_remain:.0f}s | hits={len(hits)}")
                sys.stdout.flush()

    elapsed = time.time() - start
    print(f"\n  Phase 1 complete: {count:,} masks in {elapsed:.1f}s "
          f"({count/elapsed:,.0f}/s) | {len(hits)} hits | best={best_score}/24")
    return hits


# ── Phase 2: Key-first periodic Beaufort sweep ───────────────────

def worker_phase2(key_tuple):
    """Try one periodic Beaufort key on all 97 chars. Check for crib substrings.
    Returns (score, plaintext, method, mask, key, period) or None."""
    key = list(key_tuple)
    period = len(key)

    # Decrypt all 97 chars
    pt_chars = []
    for i in range(CT_LEN):
        k = key[i % period]
        pt_chars.append(chr(beau_decrypt(CT_INTS[i], k) + 65))
    pt97 = ''.join(pt_chars)

    # Search for both cribs as substrings
    ene_pos = pt97.find(ENE_WORD)
    bcl_pos = pt97.find(BCL_WORD)

    if ene_pos == -1 or bcl_pos == -1:
        return None

    # Both cribs found! Determine null positions
    # Non-crib positions in the 97-char text are null candidates
    crib_range_ene = set(range(ene_pos, ene_pos + len(ENE_WORD)))
    crib_range_bcl = set(range(bcl_pos, bcl_pos + len(BCL_WORD)))
    crib_range = crib_range_ene | crib_range_bcl

    # The remaining positions are potential nulls
    non_crib = set(range(CT_LEN)) - crib_range
    pt_len = CT_LEN - len(non_crib)  # = len(crib_range) if all non-crib are null
    # We need exactly 24 nulls
    if len(non_crib) != 24:
        # The plaintext is 73 chars. Some non-crib positions have real PT too.
        # We can't determine nulls from substrings alone without knowing the full PT.
        # But if both cribs are present, that's still a strong signal.
        pass

    # Score using free scoring (position-independent)
    sb = score_candidate_free(pt97)
    score = sb.crib_score

    if score >= STORE_THRESHOLD:
        key_str = ''.join(chr(k + 65) for k in key)
        method = f"phase2:periodic|period={period}|key={key_str}|ene@{ene_pos}|bcl@{bcl_pos}"
        return (score, pt97, method, [], key, period)
    return None


def key_generator_period(period, use_palette=False):
    """Generate all keys of given period. If use_palette, constrain BCL-covered positions."""
    if use_palette:
        # Determine which key positions are covered by BCL (pos 63-70)
        bcl_residues = set((63 + i) % period for i in range(8))
        palette_list = sorted(PALETTE_VALUES)
        ranges = []
        for r in range(period):
            if r in bcl_residues:
                ranges.append(palette_list)
            else:
                ranges.append(range(MOD))
        for combo in product(*ranges):
            yield combo
    else:
        for combo in product(range(MOD), repeat=period):
            yield combo


def run_phase2(smoke=False, max_period=8):
    """Exhaustive periodic key sweep."""
    print(f"\n{'='*70}")
    print(f"PHASE 2: Key-First Periodic Beaufort Sweep")
    print(f"  Periods: 1 to {max_period}")
    print(f"  Workers: {WORKERS}")
    print(f"{'='*70}")
    sys.stdout.flush()

    all_hits = []

    for period in range(1, max_period + 1):
        use_palette = period >= 9
        total = (len(PALETTE_VALUES) ** min(8, period)) * (MOD ** max(0, period - 8)) if use_palette else MOD ** period

        print(f"\n  Period {period}: {total:,} keys" +
              (" (palette-constrained)" if use_palette else ""))
        sys.stdout.flush()

        if smoke and total > 10000:
            print(f"    [SMOKE] Skipping (too large)")
            continue

        start = time.time()
        hits = []
        count = 0
        best_score = 0

        with Pool(WORKERS) as pool:
            gen = key_generator_period(period, use_palette=use_palette)
            for result in pool.imap_unordered(worker_phase2, gen, chunksize=1024):
                count += 1
                if result is not None:
                    hits.append(result)
                    if result[0] > best_score:
                        best_score = result[0]
                        print(f"    NEW BEST: score={result[0]}/24 key={result[2]}")
                        sys.stdout.flush()
                    if result[0] >= SIGNAL_THRESHOLD:
                        print(f"\n    *** SIGNAL *** score={result[0]}/24")
                        print(f"    PT: {result[1][:80]}...")
                        print(f"    Method: {result[2]}")
                        sys.stdout.flush()
                if count % PHASE2_REPORT_INTERVAL == 0:
                    elapsed = time.time() - start
                    rate = count / elapsed if elapsed > 0 else 0
                    est = (total - count) / rate if rate > 0 else 0
                    print(f"    [{count:,}/{total:,}] {count/total*100:.1f}% | "
                          f"{rate:,.0f} keys/s | best={best_score}/24 | ETA {est:.0f}s")
                    sys.stdout.flush()

        elapsed = time.time() - start
        print(f"    Period {period} done: {count:,} keys in {elapsed:.1f}s | "
              f"{len(hits)} hits | best={best_score}/24")
        all_hits.extend(hits)

    return all_hits


# ── Phase 3: Keyword-mixed alphabet sweep ─────────────────────────

def _init_phase3():
    """Worker init for Phase 3."""
    pass


def worker_phase3(args):
    """Try keyword-mixed Beaufort on 97-char CT.
    args = (alphabet_keyword, period_keyword, base_alphabet_name)
    Returns hit or None."""
    alpha_kw, period_kw, base_name = args

    # Build cipher alphabet
    base = ALPH if base_name == "AZ" else "KRYPTOSABCDEFGHIJLMNQUVWXZ"
    try:
        ca = keyword_mixed_alphabet(alpha_kw, base)
    except Exception:
        return None

    ca_idx = {c: i for i, c in enumerate(ca)}

    # Build key from period keyword using cipher alphabet
    key = [ca_idx.get(c, 0) for c in period_kw]
    if not key:
        return None
    period = len(key)

    # Decrypt all 97 chars using Beaufort with mixed alphabet
    # C = (K - P) mod 26 with cipher alphabet indexing
    # P = alphabet[K - ca_idx[CT[i]]] mod 26
    pt_chars = []
    for i in range(CT_LEN):
        c_idx = ca_idx.get(CT[i], ord(CT[i]) - 65)
        k = key[i % period]
        p_idx = (k - c_idx) % MOD
        pt_chars.append(ALPH[p_idx])
    pt97 = ''.join(pt_chars)

    # Check for crib substrings
    sb = score_candidate_free(pt97)
    score = sb.crib_score

    if score >= STORE_THRESHOLD:
        method = (f"phase3:mixed_alpha|alpha_kw={alpha_kw}|period_kw={period_kw}|"
                  f"base={base_name}")
        return (score, pt97, method, [], key, period)
    return None


def run_phase3(smoke=False):
    """Keyword-mixed alphabet sweep."""
    print(f"\n{'='*70}")
    print(f"PHASE 3: Keyword-Mixed Alphabet Sweep")
    print(f"  Workers: {WORKERS}")
    print(f"{'='*70}")
    sys.stdout.flush()

    # Load wordlists
    thematic_path = os.path.join(_ROOT, "wordlists", "thematic_keywords.txt")
    english_path = os.path.join(_ROOT, "wordlists", "english.txt")

    alpha_keywords = set()
    period_keywords = set()

    # Thematic keywords for both alphabet and period
    if os.path.exists(thematic_path):
        with open(thematic_path) as f:
            for line in f:
                w = line.strip().upper()
                if w and w.isalpha():
                    alpha_keywords.add(w)
                    period_keywords.add(w)

    # Weltzeituhr city names
    for w in WELTZEITUHR_KEYWORDS:
        alpha_keywords.add(w)
        period_keywords.add(w)

    # English words (period keywords only, lengths 1-12)
    if os.path.exists(english_path) and not smoke:
        with open(english_path) as f:
            for line in f:
                w = line.strip().upper()
                if w and w.isalpha() and 1 <= len(w) <= 12:
                    period_keywords.add(w)

    if smoke:
        # Limit for smoke test
        period_keywords = set(list(period_keywords)[:100])

    alpha_list = sorted(alpha_keywords)
    period_list = sorted(period_keywords)

    print(f"  Alphabet keywords: {len(alpha_list)}")
    print(f"  Period keywords: {len(period_list)}")
    print(f"  Bases: AZ, KA")

    total = len(alpha_list) * len(period_list) * 2
    print(f"  Total configs: {total:,}")
    sys.stdout.flush()

    def gen():
        for base_name in ["AZ", "KA"]:
            for alpha_kw in alpha_list:
                for period_kw in period_list:
                    yield (alpha_kw, period_kw, base_name)

    start = time.time()
    hits = []
    count = 0
    best_score = 0

    with Pool(WORKERS) as pool:
        for result in pool.imap_unordered(worker_phase3, gen(), chunksize=512):
            count += 1
            if result is not None:
                hits.append(result)
                if result[0] > best_score:
                    best_score = result[0]
                    print(f"  NEW BEST: score={result[0]}/24 {result[2]}")
                    sys.stdout.flush()
            if count % 500_000 == 0:
                elapsed = time.time() - start
                rate = count / elapsed if elapsed > 0 else 0
                print(f"  [{count:,}/{total:,}] {count/total*100:.1f}% | "
                      f"{rate:,.0f} configs/s | best={best_score}/24 | hits={len(hits)}")
                sys.stdout.flush()

    elapsed = time.time() - start
    print(f"\n  Phase 3 complete: {count:,} configs in {elapsed:.1f}s | "
          f"{len(hits)} hits | best={best_score}/24")
    return hits


# ── Phase 4: Anomaly-guided mask construction ─────────────────────

def test_mask_with_beaufort(mask, label, results):
    """Test a specific null mask: extract CT, recover key, check periods, score."""
    if len(mask) != 24:
        return
    if mask & CRIB_POSITIONS:
        return  # Invalid: mask overlaps cribs

    ct73_ints = [CT_INTS[i] for i in range(CT_LEN) if i not in mask]
    if len(ct73_ints) != 73:
        return

    null_sorted = sorted(mask)
    key_at_cribs = []
    for orig_pos, _, pt_int in CRIB_ENTRIES:
        shift = sum(1 for n in null_sorted if n < orig_pos)
        new_pos = orig_pos - shift
        if 0 <= new_pos < 73:
            k = (ct73_ints[new_pos] + pt_int) % MOD
            key_at_cribs.append((new_pos, k))

    if len(key_at_cribs) != N_CRIBS:
        return

    periods = check_periodicity(key_at_cribs, max_period=36)
    ct73 = ''.join(chr(v + 65) for v in ct73_ints)

    for period, full_key in periods:
        pt_chars = []
        for i, c_int in enumerate(ct73_ints):
            k = full_key[i % period]
            pt_chars.append(chr(beau_decrypt(c_int, k) + 65))
        plaintext = ''.join(pt_chars)

        sb = score_candidate(plaintext)
        score = sb.crib_score

        if score >= STORE_THRESHOLD:
            key_str = ''.join(chr(k + 65) for k in full_key)
            method = f"phase4:{label}|period={period}|key={key_str}"
            results.append((score, plaintext, method, sorted(mask), full_key, period))
            if score >= SIGNAL_THRESHOLD:
                print(f"    *** SIGNAL *** {label} score={score}/24 period={period}")
                print(f"    PT: {plaintext}")
                sys.stdout.flush()


def run_phase4():
    """Test anomaly-guided masks."""
    print(f"\n{'='*70}")
    print(f"PHASE 4: Anomaly-Guided Mask Construction")
    print(f"{'='*70}")
    sys.stdout.flush()

    results = []
    available = set(range(CT_LEN)) - CRIB_POSITIONS

    # 4a: Mod-5 positional rules (Mengenlehreuhr base-5)
    print("  4a: Mod-5 positional rules...")
    for k in range(5):
        for size in [1, 2]:
            for residues in combinations(range(5), size):
                mask_candidates = {p for p in available if p % 5 in residues}
                if len(mask_candidates) == 24:
                    test_mask_with_beaufort(mask_candidates, f"mod5_r{''.join(str(r) for r in residues)}", results)
                elif len(mask_candidates) > 24:
                    # Try subsets using consensus as seed
                    consensus_in = mask_candidates & CONSENSUS_NULL_POSITIONS
                    if len(consensus_in) <= 24:
                        needed = 24 - len(consensus_in)
                        remaining = sorted(mask_candidates - consensus_in)
                        if needed <= len(remaining) and needed <= 10:
                            for extra in combinations(remaining, needed):
                                mask = consensus_in | set(extra)
                                if len(mask) == 24:
                                    test_mask_with_beaufort(mask, f"mod5_r{''.join(str(r) for r in residues)}_consensus", results)
                                    break  # Just test first one as representative

    # 4b: Width-21 column masks
    print("  4b: Width-21 column masks...")
    for col in range(21):
        mask_candidates = {p for p in available if p % 21 == col}
        if len(mask_candidates) >= 4:
            # Try consensus + column positions
            combined = CONSENSUS_NULL_POSITIONS | mask_candidates
            combined = combined & available  # Remove any crib overlaps
            if len(combined) >= 24:
                test_mask = set(sorted(combined)[:24])
                test_mask_with_beaufort(test_mask, f"width21_col{col}", results)

    # 4c: Interval-4 masks (Stehle connection)
    print("  4c: Interval-4 masks (Stehle)...")
    for residue in range(4):
        mask_candidates = {p for p in available if p % 4 == residue}
        if len(mask_candidates) >= 24:
            test_mask = set(sorted(mask_candidates)[:24])
            test_mask_with_beaufort(test_mask, f"interval4_r{residue}", results)

    # 4d: Weltzeituhr-24 mask (one null per "facet")
    print("  4d: Weltzeituhr-24 mask (one per facet)...")
    group_size = CT_LEN // 24  # ~4 positions per group
    for trial in range(min(100, 2**24)):
        # Deterministic: take the first available position from each group
        mask = set()
        for g in range(24):
            start = g * group_size
            end = min(start + group_size, CT_LEN)
            for p in range(start, end):
                if p in available and p not in mask:
                    mask.add(p)
                    break
        if len(mask) == 24:
            test_mask_with_beaufort(mask, "weltzeituhr24", results)
        break  # Only one deterministic version

    # 4e: Positions where CT letter is in NULL_PALETTE
    print("  4e: CT-palette position masks...")
    palette_letters = frozenset("BGIKOWZ")
    palette_positions = {i for i in available if CT[i] in palette_letters}
    print(f"    Palette positions in available: {len(palette_positions)}")
    if len(palette_positions) >= 24:
        # Take first 24
        test_mask = set(sorted(palette_positions)[:24])
        test_mask_with_beaufort(test_mask, "ct_palette_first24", results)
        # Take last 24
        test_mask = set(sorted(palette_positions)[-24:])
        test_mask_with_beaufort(test_mask, "ct_palette_last24", results)

    print(f"\n  Phase 4 complete: {len(results)} hits")
    return results


# ── Phase 5: Reverse validation ───────────────────────────────────

def validate_hit(hit):
    """Full validation for a high-scoring hit."""
    score, plaintext, method, mask, key, period = hit
    print(f"\n{'#'*70}")
    print(f"VALIDATION: score={score}/24 period={period}")
    print(f"{'#'*70}")
    print(f"  Method:    {method}")
    print(f"  Plaintext: {plaintext}")
    print(f"  Key:       {''.join(chr(k+65) for k in key)} (len={len(key)})")
    if mask:
        print(f"  Mask:      {mask}")
        print(f"  Mask size: {len(mask)}")

    # Re-score from scratch
    sb = score_candidate(plaintext)
    print(f"\n  Re-scored: {sb.crib_score}/24 (ENE={sb.ene_score}/13, BC={sb.bc_score}/11)")
    print(f"  IC:        {sb.ic_value:.4f}")
    print(f"  Class:     {sb.crib_classification}")

    # Free scoring
    sbf = score_candidate_free(plaintext)
    print(f"  Free score: {sbf.crib_score}/24")

    # Bean constraints (on the key at crib positions in 97-char space)
    # We need the keystream at the ORIGINAL crib positions
    if mask and len(key) > 0:
        from kryptos.kernel.constraints.bean import verify_bean_from_implied
        # Map original crib positions to key values
        implied = {}
        null_sorted = sorted(mask)
        for orig_pos, _, pt_int in CRIB_ENTRIES:
            shift = sum(1 for n in null_sorted if n < orig_pos)
            new_pos = orig_pos - shift
            k = key[new_pos % period]
            implied[orig_pos] = k
        bean_result = verify_bean_from_implied(implied)
        print(f"  Bean:      {'PASS' if bean_result else 'FAIL'}")

    # Check if key looks like a keyword
    key_str = ''.join(chr(k + 65) for k in key)
    print(f"  Key word:  {key_str}")

    print(f"{'#'*70}\n")
    sys.stdout.flush()


# ── Main harness ──────────────────────────────────────────────────

def save_results(all_hits, elapsed):
    """Save results to JSON."""
    os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)
    output = {
        "experiment": "f_null_beaufort_exhaustive_v1",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "elapsed_seconds": round(elapsed, 1),
        "total_hits": len(all_hits),
        "hits": [
            {
                "score": h[0],
                "plaintext": h[1],
                "method": h[2],
                "mask": h[3] if h[3] else None,
                "key": [chr(k + 65) for k in h[4]] if h[4] else None,
                "period": h[5],
            }
            for h in sorted(all_hits, key=lambda x: -x[0])[:200]  # Top 200
        ],
    }
    with open(RESULTS_PATH, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {RESULTS_PATH}")


def attack(ciphertext=None, **params):
    """Standard attack contract."""
    smoke = params.get("smoke", False)
    all_hits = []
    all_hits.extend(run_phase1(smoke=smoke))
    all_hits.extend(run_phase2(smoke=smoke))
    all_hits.extend(run_phase3(smoke=smoke))
    all_hits.extend(run_phase4())
    return [(h[0], h[1], h[2]) for h in sorted(all_hits, key=lambda x: -x[0])]


def main():
    parser = argparse.ArgumentParser(description="Exhaustive Null-Mask + Beaufort Campaign")
    parser.add_argument("--smoke", action="store_true", help="Quick smoke test (limited search)")
    parser.add_argument("--phase", type=int, choices=[1, 2, 3, 4], help="Run single phase")
    parser.add_argument("--max-period", type=int, default=8, help="Max period for Phase 2 (default: 8)")
    args = parser.parse_args()

    print(f"Exhaustive Null-Mask + Beaufort Campaign v1")
    print(f"  CT: {CT[:50]}...")
    print(f"  CT length: {CT_LEN}")
    print(f"  Consensus nulls: {len(CONSENSUS_NULL_POSITIONS)}")
    print(f"  Crib positions: {N_CRIBS}")
    print(f"  Workers: {WORKERS}")
    if args.smoke:
        print(f"  MODE: SMOKE TEST")
    print()
    sys.stdout.flush()

    start = time.time()
    all_hits = []

    phases = [args.phase] if args.phase else [1, 2, 3, 4]

    if 1 in phases:
        all_hits.extend(run_phase1(smoke=args.smoke))
    if 2 in phases:
        all_hits.extend(run_phase2(smoke=args.smoke, max_period=args.max_period))
    if 3 in phases:
        all_hits.extend(run_phase3(smoke=args.smoke))
    if 4 in phases:
        all_hits.extend(run_phase4())

    elapsed = time.time() - start

    # Phase 5: Validate high-scoring hits
    signals = [h for h in all_hits if h[0] >= SIGNAL_THRESHOLD]
    if signals:
        print(f"\n{'='*70}")
        print(f"PHASE 5: Validating {len(signals)} signal-level hits")
        print(f"{'='*70}")
        for h in sorted(signals, key=lambda x: -x[0]):
            validate_hit(h)

    # Summary
    print(f"\n{'='*70}")
    print(f"CAMPAIGN SUMMARY")
    print(f"{'='*70}")
    print(f"  Total time:   {elapsed:.1f}s")
    print(f"  Total hits:   {len(all_hits)}")
    print(f"  Signals:      {len(signals)}")
    if all_hits:
        best = max(all_hits, key=lambda x: x[0])
        print(f"  Best score:   {best[0]}/24")
        print(f"  Best method:  {best[2]}")
        print(f"  Best PT:      {best[1][:60]}...")
    else:
        print(f"  Best score:   0/24 (no hits)")

    save_results(all_hits, elapsed)

    # Update exhaustion log
    try:
        sys.path.insert(0, os.path.join(_ROOT, "scripts", "lib"))
        from exhaustion import update
        best_score = max((h[0] for h in all_hits), default=0)
        update("f_null_beaufort_exhaustive_v1",
               status="exhausted" if not args.smoke else "active",
               best=float(best_score),
               family="null_mask_beaufort",
               keyspace=f"P1:C(56,7)=232M|P2:26^1..26^{args.max_period}|P3:~425+1M keywords|P4:~200 masks",
               last_run=time.strftime("%Y-%m-%d"))
    except Exception as e:
        print(f"  Warning: could not update exhaustion log: {e}")

    print(f"\nDone.")


if __name__ == "__main__":
    main()
