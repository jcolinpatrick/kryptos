#!/usr/bin/env python3
# Cipher: Null mask + substitution
# Family: grille
# Status: active
# Keyspace: ~10^17 (C(73,24) masks x 26! substitutions)
# Last run:
# Best score:
"""E-MASK-IC-HILLCLIMB: Method-agnostic null mask scoring pipeline for K4.

Hypothesis: 24 of 97 carved positions are nulls. Removing them yields 73
real ciphertext characters. The correct 73-char extract, when decrypted
with the right cipher, produces the K4 plaintext.

Three-phase pipeline:
  Phase 1: IC-based mask screening (structured + random generation)
  Phase 2: Hill-climbing monoalphabetic substitution on top IC masks
  Phase 3: Vigenere/Beaufort sweep with chi-squared key recovery

Crib constraint: the 24 known crib positions (21-33, 63-73) are almost
certainly real CT, so they MUST survive null removal. We choose 24 nulls
from the 73 non-crib positions (0-20, 34-62, 74-96).

Usage: cd /home/cpatrick/kryptos && PYTHONPATH=src python3 -u scripts/grille/e_mask_ic_hillclimb.py
"""
from __future__ import annotations

import json
import math
import os
import random
import sys
import time
from collections import Counter
from itertools import combinations
from typing import Dict, List, Optional, Set, Tuple

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_POSITIONS, ALPH, ALPH_IDX, MOD,
    IC_RANDOM, IC_ENGLISH,
)
from kryptos.kernel.scoring.ic import ic
from kryptos.kernel.scoring.free_crib import score_free_fast, score_free

# ── Experiment config ────────────────────────────────────────────────────────

EXPERIMENT_ID = "E-MASK-IC-HILLCLIMB"
SEED = 42
random.seed(SEED)

# The 73 non-crib positions (candidates for null removal)
ALL_POSITIONS = set(range(CT_LEN))
NON_CRIB = sorted(ALL_POSITIONS - CRIB_POSITIONS)
assert len(NON_CRIB) == 73, f"Expected 73 non-crib positions, got {len(NON_CRIB)}"
assert len(CRIB_POSITIONS) == 24

# Number of nulls to select from the 73 non-crib positions
N_NULLS = 24
N_REAL = 73  # 97 - 24

# W positions in the carved text
W_POSITIONS = [20, 36, 48, 58, 74]
# Which W positions are in non-crib set?
W_IN_NONCRIB = [p for p in W_POSITIONS if p in NON_CRIB]

# ── Load quadgrams ──────────────────────────────────────────────────────────

QUADGRAM_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "data", "english_quadgrams.json")
QUADGRAM_PATH = os.path.normpath(QUADGRAM_PATH)

print(f"[{EXPERIMENT_ID}] Loading quadgrams from {QUADGRAM_PATH} ...")
with open(QUADGRAM_PATH, "r") as f:
    QUADGRAMS: Dict[str, float] = json.load(f)

# Floor value for unknown quadgrams
QG_FLOOR = min(QUADGRAMS.values()) - 1.0
print(f"  Loaded {len(QUADGRAMS)} quadgrams. Floor = {QG_FLOOR:.4f}")


def quadgram_score(text: str) -> float:
    """Log-probability score of text based on English quadgram frequencies."""
    text = text.upper()
    if len(text) < 4:
        return QG_FLOOR * max(1, len(text))
    total = 0.0
    for i in range(len(text) - 3):
        qg = text[i:i + 4]
        total += QUADGRAMS.get(qg, QG_FLOOR)
    return total


def quadgram_score_per_char(text: str) -> float:
    """Normalized quadgram score per character."""
    n = len(text)
    if n < 4:
        return QG_FLOOR
    return quadgram_score(text) / (n - 3)


# ── Mask utilities ──────────────────────────────────────────────────────────

def extract_real_chars(null_positions: Set[int]) -> str:
    """Given a set of null positions, extract the 73 'real' characters."""
    return "".join(CT[i] for i in range(CT_LEN) if i not in null_positions)


def mask_ic(null_positions: Set[int]) -> float:
    """Compute IC of the 73-char extract after removing nulls."""
    text = extract_real_chars(null_positions)
    return ic(text)


# ── Phase 1: Mask generation strategies ─────────────────────────────────────

def generate_token_binary_masks() -> List[Set[int]]:
    """Token binary masks: take every k-th non-crib position as null.

    For offsets and steps that yield exactly 24 nulls from the 73 non-crib positions.
    """
    masks = []
    # Try various step sizes and offsets
    for step in range(2, 20):
        for offset in range(step):
            nulls_idx = [NON_CRIB[i] for i in range(offset, len(NON_CRIB), step)]
            if len(nulls_idx) == N_NULLS:
                masks.append(set(nulls_idx))
            # Also try taking exactly 24 from the evenly-spaced positions
            elif len(nulls_idx) > N_NULLS:
                # Take first 24
                masks.append(set(nulls_idx[:N_NULLS]))
                # Take last 24
                masks.append(set(nulls_idx[-N_NULLS:]))
                # Take evenly spread from the candidates
                spread = [nulls_idx[i * len(nulls_idx) // N_NULLS] for i in range(N_NULLS)]
                masks.append(set(spread))
    return masks


def generate_w_position_masks(n_samples: int = 50000) -> List[Set[int]]:
    """W-position masks: W's at positions 20,36,48,58,74 as nulls, plus 19 more."""
    masks = []
    w_nulls = set(W_IN_NONCRIB)
    n_w = len(w_nulls)
    remaining_needed = N_NULLS - n_w
    remaining_pool = [p for p in NON_CRIB if p not in w_nulls]

    if remaining_needed <= 0 or remaining_needed > len(remaining_pool):
        print(f"  W-mask: {n_w} W's in non-crib, need {remaining_needed} more from {len(remaining_pool)} pool")
        return masks

    for _ in range(n_samples):
        extra = set(random.sample(remaining_pool, remaining_needed))
        masks.append(w_nulls | extra)
    return masks


def generate_periodic_null_masks() -> List[Set[int]]:
    """Periodic null patterns: every k-th position in the full 97 is null.

    Intersect with non-crib positions and adjust to get exactly 24.
    """
    masks = []
    for period in range(2, 25):
        for offset in range(period):
            null_candidates = set(range(offset, CT_LEN, period)) & set(NON_CRIB)
            if len(null_candidates) == N_NULLS:
                masks.append(null_candidates)
            elif len(null_candidates) > N_NULLS:
                # Take first 24 (by position)
                sorted_cands = sorted(null_candidates)
                masks.append(set(sorted_cands[:N_NULLS]))
                masks.append(set(sorted_cands[-N_NULLS:]))
                # Evenly spaced subset
                spread = [sorted_cands[i * len(sorted_cands) // N_NULLS] for i in range(N_NULLS)]
                if len(set(spread)) == N_NULLS:
                    masks.append(set(spread))
            elif len(null_candidates) >= N_NULLS - 5:
                # Close enough: pad with random
                shortfall = N_NULLS - len(null_candidates)
                pool = [p for p in NON_CRIB if p not in null_candidates]
                if len(pool) >= shortfall:
                    for _ in range(min(10, len(pool))):
                        extra = set(random.sample(pool, shortfall))
                        masks.append(null_candidates | extra)
    return masks


def generate_morse_derived_masks() -> List[Set[int]]:
    """Morse-derived: use Morse code patterns for letters in potential keywords."""
    MORSE = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
        'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
        'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
        'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
        'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
        'Z': '--..',
    }
    keywords = [
        "KRYPTOS", "KOMPASS", "DEFECTOR", "COLOPHON", "ABSCISSA",
        "BERLINCLOCK", "EASTNORTHEAST", "SHADOW", "PALIMPSEST",
        "CLOCK", "NORTH", "FIVE", "LAYER",
    ]
    masks = []
    for kw in keywords:
        # Generate bit pattern from Morse
        bits = ""
        for ch in kw:
            morse = MORSE.get(ch, "")
            for sym in morse:
                bits += "1" if sym == "-" else "0"
        # Extend/repeat pattern to length 73
        if not bits:
            continue
        extended = (bits * (73 // len(bits) + 1))[:73]
        # Method 1: 1s are nulls
        null_indices = [NON_CRIB[i] for i in range(73) if extended[i] == "1"]
        if len(null_indices) == N_NULLS:
            masks.append(set(null_indices))
        elif len(null_indices) > N_NULLS:
            masks.append(set(null_indices[:N_NULLS]))
            masks.append(set(null_indices[-N_NULLS:]))
        # Method 2: 0s are nulls
        null_indices_0 = [NON_CRIB[i] for i in range(73) if extended[i] == "0"]
        if len(null_indices_0) == N_NULLS:
            masks.append(set(null_indices_0))
        elif len(null_indices_0) > N_NULLS:
            masks.append(set(null_indices_0[:N_NULLS]))
            masks.append(set(null_indices_0[-N_NULLS:]))

    return masks


def generate_random_masks(n_samples: int = 50000) -> List[Set[int]]:
    """Pure random: choose 24 random non-crib positions as nulls."""
    masks = []
    for _ in range(n_samples):
        nulls = set(random.sample(NON_CRIB, N_NULLS))
        masks.append(nulls)
    return masks


def generate_block_masks() -> List[Set[int]]:
    """Block-based masks: contiguous blocks of nulls in non-crib positions."""
    masks = []
    # Single block of 24 consecutive non-crib positions
    for start_idx in range(len(NON_CRIB) - N_NULLS + 1):
        nulls = set(NON_CRIB[start_idx:start_idx + N_NULLS])
        masks.append(nulls)
    # Two blocks of 12
    for s1 in range(0, len(NON_CRIB) - 12, 6):
        for s2 in range(s1 + 12, len(NON_CRIB) - 12 + 1, 6):
            block1 = NON_CRIB[s1:s1 + 12]
            block2 = NON_CRIB[s2:s2 + 12]
            if len(set(block1) | set(block2)) == N_NULLS:
                masks.append(set(block1) | set(block2))
    # Three blocks of 8
    for s1 in range(0, len(NON_CRIB) - 8, 8):
        for s2 in range(s1 + 8, len(NON_CRIB) - 8, 8):
            for s3 in range(s2 + 8, len(NON_CRIB) - 8 + 1, 8):
                block1 = NON_CRIB[s1:s1 + 8]
                block2 = NON_CRIB[s2:s2 + 8]
                block3 = NON_CRIB[s3:s3 + 8]
                combined = set(block1) | set(block2) | set(block3)
                if len(combined) == N_NULLS:
                    masks.append(combined)
    # Four blocks of 6
    for s1 in range(0, len(NON_CRIB) - 6, 8):
        for s2 in range(s1 + 6, len(NON_CRIB) - 6, 8):
            for s3 in range(s2 + 6, len(NON_CRIB) - 6, 8):
                for s4 in range(s3 + 6, len(NON_CRIB) - 6 + 1, 8):
                    blocks = (NON_CRIB[s1:s1+6] + NON_CRIB[s2:s2+6] +
                              NON_CRIB[s3:s3+6] + NON_CRIB[s4:s4+6])
                    if len(set(blocks)) == N_NULLS:
                        masks.append(set(blocks))
    return masks


# ── Phase 1 main: screen masks by IC ───────────────────────────────────────

def phase1_screen_masks() -> List[Tuple[float, Set[int], str]]:
    """Generate masks from all strategies, score by IC deviation from random."""
    print(f"\n{'='*72}")
    print(f"PHASE 1: IC-based mask screening")
    print(f"{'='*72}")

    # Compute baseline IC of full 97-char CT
    baseline_ic = ic(CT)
    print(f"  Baseline IC (full 97 chars): {baseline_ic:.6f}")
    print(f"  Random IC:                   {IC_RANDOM:.6f}")
    print(f"  English IC:                  {IC_ENGLISH:.6f}")
    print(f"  Non-crib positions: {len(NON_CRIB)}")
    print(f"  Nulls to choose:   {N_NULLS}")
    print(f"  W in non-crib:     {W_IN_NONCRIB}")
    print()

    all_results: List[Tuple[float, Set[int], str]] = []
    seen_masks: Set[frozenset] = set()

    def add_masks(masks: List[Set[int]], strategy: str):
        """Deduplicate and score masks."""
        added = 0
        for m in masks:
            key = frozenset(m)
            if key in seen_masks:
                continue
            if len(m) != N_NULLS:
                continue
            # Verify all nulls are in non-crib positions
            if not m.issubset(set(NON_CRIB)):
                continue
            seen_masks.add(key)
            added += 1
            extract = extract_real_chars(m)
            assert len(extract) == N_REAL, f"Extract length {len(extract)} != {N_REAL}"
            ic_val = ic(extract)
            # Score: higher IC deviation from random = more interesting
            # (could be English-like or structured)
            ic_dev = abs(ic_val - IC_RANDOM)
            all_results.append((ic_dev, m, strategy))
        return added

    # Strategy 1: Token binary
    t0 = time.time()
    token_masks = generate_token_binary_masks()
    n = add_masks(token_masks, "token_binary")
    print(f"  [1] Token binary:    {n:>7d} unique masks ({time.time()-t0:.1f}s)")

    # Strategy 2: W-position
    t0 = time.time()
    w_masks = generate_w_position_masks(50000)
    n = add_masks(w_masks, "w_position")
    print(f"  [2] W-position:      {n:>7d} unique masks ({time.time()-t0:.1f}s)")

    # Strategy 3: Periodic null
    t0 = time.time()
    periodic_masks = generate_periodic_null_masks()
    n = add_masks(periodic_masks, "periodic_null")
    print(f"  [3] Periodic null:   {n:>7d} unique masks ({time.time()-t0:.1f}s)")

    # Strategy 4: Morse-derived
    t0 = time.time()
    morse_masks = generate_morse_derived_masks()
    n = add_masks(morse_masks, "morse_derived")
    print(f"  [4] Morse-derived:   {n:>7d} unique masks ({time.time()-t0:.1f}s)")

    # Strategy 5: Block-based
    t0 = time.time()
    block_masks = generate_block_masks()
    n = add_masks(block_masks, "block")
    print(f"  [5] Block-based:     {n:>7d} unique masks ({time.time()-t0:.1f}s)")

    # Strategy 6: Random baseline
    t0 = time.time()
    random_masks = generate_random_masks(50000)
    n = add_masks(random_masks, "random")
    print(f"  [6] Random:          {n:>7d} unique masks ({time.time()-t0:.1f}s)")

    total = len(all_results)
    print(f"\n  Total unique masks screened: {total}")

    # Sort by IC deviation (highest first)
    all_results.sort(key=lambda x: -x[0])

    # IC statistics
    ic_values = [r[0] + IC_RANDOM for r in all_results]  # Reconstruct actual IC
    if ic_values:
        print(f"\n  IC distribution of 73-char extracts:")
        print(f"    Min:    {min(ic_values):.6f}")
        print(f"    Max:    {max(ic_values):.6f}")
        print(f"    Mean:   {sum(ic_values)/len(ic_values):.6f}")
        print(f"    Median: {sorted(ic_values)[len(ic_values)//2]:.6f}")

    # Show top 20 by IC deviation
    print(f"\n  Top 20 masks by IC deviation from random ({IC_RANDOM:.6f}):")
    print(f"  {'Rank':>4s} {'IC':>8s} {'Dev':>8s} {'Strategy':<15s} {'Nulls (sorted)'}")
    for i, (dev, mask, strat) in enumerate(all_results[:20]):
        actual_ic = ic(extract_real_chars(mask))
        sorted_nulls = sorted(mask)
        nulls_str = str(sorted_nulls[:10]) + ("..." if len(sorted_nulls) > 10 else "")
        print(f"  {i+1:>4d} {actual_ic:>8.6f} {dev:>8.6f} {strat:<15s} {nulls_str}")

    return all_results


# ── Phase 2: Hill-climbing monoalphabetic substitution ─────────────────────

def hillclimb_mono(ciphertext: str, n_restarts: int = 5) -> Tuple[float, str, List[int]]:
    """Hill-climbing monoalphabetic substitution solver.

    Returns (best_score, best_plaintext, best_key_mapping).
    Key: key[i] = plaintext letter index for ciphertext letter index i.
    """
    n = len(ciphertext)
    ct_nums = [ord(c) - 65 for c in ciphertext]

    best_score = -float("inf")
    best_pt = ""
    best_key = list(range(26))

    for restart in range(n_restarts):
        # Random initial permutation
        key = list(range(26))
        random.shuffle(key)

        # Decrypt with current key
        pt = "".join(chr(key[c] + 65) for c in ct_nums)
        score = quadgram_score(pt)

        improved = True
        while improved:
            improved = False
            for i in range(26):
                for j in range(i + 1, 26):
                    # Swap key[i] and key[j]
                    key[i], key[j] = key[j], key[i]
                    new_pt = "".join(chr(key[c] + 65) for c in ct_nums)
                    new_score = quadgram_score(new_pt)

                    if new_score > score:
                        score = new_score
                        pt = new_pt
                        improved = True
                    else:
                        # Undo swap
                        key[i], key[j] = key[j], key[i]

        if score > best_score:
            best_score = score
            best_pt = pt
            best_key = key[:]

    return best_score, best_pt, best_key


def phase2_hillclimb(top_masks: List[Tuple[float, Set[int], str]], n_top: int = 500) -> List[Tuple[float, str, str, float, Set[int]]]:
    """Phase 2: run hill-climbing substitution solver on top masks.

    Returns list of (qg_score, plaintext, strategy, ic_dev, mask).
    """
    print(f"\n{'='*72}")
    print(f"PHASE 2: Hill-climbing monoalphabetic substitution (top {n_top} masks)")
    print(f"{'='*72}")

    results: List[Tuple[float, str, str, float, Set[int]]] = []
    t0 = time.time()

    for idx, (ic_dev, mask, strategy) in enumerate(top_masks[:n_top]):
        extract = extract_real_chars(mask)

        qg_score, pt, key = hillclimb_mono(extract, n_restarts=5)
        qg_per_char = qg_score / max(1, len(pt) - 3)

        # Check for crib hits
        crib_score = score_free_fast(pt)

        results.append((qg_score, pt, strategy, ic_dev, mask))

        if crib_score > 0:
            print(f"\n  *** CRIB HIT at mask #{idx+1} (strategy={strategy}) ***")
            print(f"      Crib score: {crib_score}")
            print(f"      QG score:   {qg_score:.2f} ({qg_per_char:.4f}/char)")
            print(f"      Plaintext:  {pt}")
            full_result = score_free(pt)
            print(f"      Detail:     {full_result.summary}")
            print(f"      Nulls:      {sorted(mask)}")

        # Also check for partial crib fragments (>= 5 chars)
        for crib_word in ["EASTNORTHEAST", "BERLINCLOCK"]:
            for flen in range(min(8, len(crib_word)), 4, -1):
                for start_in_crib in range(len(crib_word) - flen + 1):
                    frag = crib_word[start_in_crib:start_in_crib + flen]
                    if frag in pt:
                        print(f"  ** Fragment '{frag}' found in mask #{idx+1} (strategy={strategy})")
                        print(f"     QG: {qg_score:.2f}, PT: {pt}")
                        break

        if (idx + 1) % 50 == 0:
            elapsed = time.time() - t0
            rate = (idx + 1) / elapsed
            print(f"  Progress: {idx+1}/{min(n_top, len(top_masks))} masks "
                  f"({elapsed:.1f}s, {rate:.1f} masks/s)")

    elapsed = time.time() - t0
    print(f"\n  Phase 2 complete: {len(results)} masks processed in {elapsed:.1f}s")

    # Sort by QG score (best first)
    results.sort(key=lambda x: -x[0])

    # Show top 20
    print(f"\n  Top 20 by quadgram score:")
    print(f"  {'Rank':>4s} {'QG':>10s} {'QG/ch':>8s} {'Strategy':<15s} {'Plaintext (first 60 chars)'}")
    for i, (qg, pt, strat, ic_dev, mask) in enumerate(results[:20]):
        qg_pc = qg / max(1, len(pt) - 3)
        print(f"  {i+1:>4d} {qg:>10.2f} {qg_pc:>8.4f} {strat:<15s} {pt[:60]}")

    return results


# ── Phase 3: Vigenere/Beaufort sweep ───────────────────────────────────────

def chi_squared_key(ciphertext_nums: List[int], period: int) -> List[int]:
    """Find optimal key for each position using chi-squared against English frequencies.

    Returns list of key values (length = period).
    """
    ENGLISH_FREQ = [
        0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
        0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
        0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
        0.00978, 0.02360, 0.00150, 0.01974, 0.00074
    ]

    key = []
    for pos in range(period):
        # Gather all ciphertext values at this residue
        group = [ciphertext_nums[i] for i in range(pos, len(ciphertext_nums), period)]
        if not group:
            key.append(0)
            continue

        n = len(group)
        freq = Counter(group)

        best_shift = 0
        best_chi2 = float("inf")

        for shift in range(26):
            chi2 = 0.0
            for letter in range(26):
                observed = freq.get((letter + shift) % 26, 0)
                expected = ENGLISH_FREQ[letter] * n
                if expected > 0:
                    chi2 += (observed - expected) ** 2 / expected
            if chi2 < best_chi2:
                best_chi2 = chi2
                best_shift = shift
        key.append(best_shift)

    return key


def decrypt_vig(ct_nums: List[int], key: List[int]) -> str:
    """Vigenere decrypt: P = (C - K) mod 26."""
    klen = len(key)
    return "".join(chr((ct_nums[i] - key[i % klen]) % 26 + 65) for i in range(len(ct_nums)))


def decrypt_beau(ct_nums: List[int], key: List[int]) -> str:
    """Beaufort decrypt: P = (K - C) mod 26."""
    klen = len(key)
    return "".join(chr((key[i % klen] - ct_nums[i]) % 26 + 65) for i in range(len(ct_nums)))


def decrypt_varbeau(ct_nums: List[int], key: List[int]) -> str:
    """Variant Beaufort decrypt: P = (C + K) mod 26."""
    klen = len(key)
    return "".join(chr((ct_nums[i] + key[i % klen]) % 26 + 65) for i in range(len(ct_nums)))


def phase3_vig_beau_sweep(top_masks: List[Tuple[float, Set[int], str]], n_top: int = 200) -> List[Tuple[float, str, str, str, int, Set[int]]]:
    """Phase 3: Vigenere/Beaufort/VarBeau sweep on top masks.

    Returns list of (qg_score, plaintext, cipher_name, strategy, period, mask).
    """
    print(f"\n{'='*72}")
    print(f"PHASE 3: Vigenere/Beaufort sweep (top {n_top} masks, periods 3-13)")
    print(f"{'='*72}")

    CIPHER_FUNCS = [
        ("Vigenere", decrypt_vig),
        ("Beaufort", decrypt_beau),
        ("VarBeau", decrypt_varbeau),
    ]
    PERIODS = list(range(3, 14))

    results: List[Tuple[float, str, str, str, int, Set[int]]] = []
    t0 = time.time()

    for idx, (ic_dev, mask, strategy) in enumerate(top_masks[:n_top]):
        extract = extract_real_chars(mask)
        ct_nums = [ord(c) - 65 for c in extract]

        for cipher_name, decrypt_fn in CIPHER_FUNCS:
            for period in PERIODS:
                # For Vigenere: chi-squared finds the shift directly
                key = chi_squared_key(ct_nums, period)
                pt = decrypt_fn(ct_nums, key)

                qg = quadgram_score(pt)

                # Check cribs
                crib_score = score_free_fast(pt)

                results.append((qg, pt, cipher_name, strategy, period, mask))

                if crib_score > 0:
                    print(f"\n  *** CRIB HIT: mask #{idx+1}, {cipher_name} p={period}, strategy={strategy} ***")
                    print(f"      Crib score: {crib_score}")
                    print(f"      QG score:   {qg:.2f}")
                    print(f"      Key:        {key}")
                    print(f"      Plaintext:  {pt}")
                    full_result = score_free(pt)
                    print(f"      Detail:     {full_result.summary}")

                # Check fragments
                for crib_word in ["EASTNORTHEAST", "BERLINCLOCK"]:
                    for flen in range(min(8, len(crib_word)), 4, -1):
                        for start_in_crib in range(len(crib_word) - flen + 1):
                            frag = crib_word[start_in_crib:start_in_crib + flen]
                            if frag in pt:
                                print(f"  ** Fragment '{frag}': mask #{idx+1}, {cipher_name} p={period}")
                                print(f"     PT: {pt}")
                                break

        if (idx + 1) % 25 == 0:
            elapsed = time.time() - t0
            rate = (idx + 1) / elapsed
            print(f"  Progress: {idx+1}/{min(n_top, len(top_masks))} masks "
                  f"({elapsed:.1f}s, {rate:.1f} masks/s)")

    elapsed = time.time() - t0
    print(f"\n  Phase 3 complete: {len(results)} decryptions in {elapsed:.1f}s")

    # Sort by QG score
    results.sort(key=lambda x: -x[0])

    # Show top 20
    print(f"\n  Top 20 by quadgram score:")
    print(f"  {'Rank':>4s} {'QG':>10s} {'QG/ch':>8s} {'Cipher':<10s} {'Per':>3s} {'Strategy':<15s} {'Plaintext (first 60 chars)'}")
    for i, (qg, pt, cipher, strat, period, mask) in enumerate(results[:20]):
        qg_pc = qg / max(1, len(pt) - 3)
        print(f"  {i+1:>4d} {qg:>10.2f} {qg_pc:>8.4f} {cipher:<10s} {period:>3d} {strat:<15s} {pt[:60]}")

    return results


# ── Main entry point ────────────────────────────────────────────────────────

def main():
    print(f"{'='*72}")
    print(f"  {EXPERIMENT_ID}: Method-agnostic null mask scoring pipeline")
    print(f"{'='*72}")
    print(f"  CT:     {CT}")
    print(f"  Length: {CT_LEN}")
    print(f"  Cribs:  21-33=EASTNORTHEAST, 63-73=BERLINCLOCK (24 positions)")
    print(f"  Non-crib positions ({len(NON_CRIB)}): {NON_CRIB}")
    print(f"  W in non-crib: {W_IN_NONCRIB}")
    print()

    overall_start = time.time()

    # Phase 1: IC screening
    phase1_results = phase1_screen_masks()
    print(f"\n  Phase 1 total masks: {len(phase1_results)}")

    # Phase 2: Hill-climbing on top 500
    phase2_results = phase2_hillclimb(phase1_results, n_top=500)

    # Phase 3: Vig/Beau sweep on top 200
    phase3_results = phase3_vig_beau_sweep(phase1_results, n_top=200)

    # ── Final summary ───────────────────────────────────────────────────────

    total_time = time.time() - overall_start
    print(f"\n{'='*72}")
    print(f"  FINAL SUMMARY")
    print(f"{'='*72}")
    print(f"  Total time: {total_time:.1f}s")
    print(f"  Phase 1 masks screened:     {len(phase1_results)}")
    print(f"  Phase 2 substitution tests: {len(phase2_results)}")
    print(f"  Phase 3 Vig/Beau tests:     {len(phase3_results)}")

    # Count crib hits across all phases
    crib_hits_p2 = sum(1 for qg, pt, *_ in phase2_results if score_free_fast(pt) > 0)
    crib_hits_p3 = sum(1 for qg, pt, *_ in phase3_results if score_free_fast(pt) > 0)

    print(f"\n  Crib hits (Phase 2 hill-climb):  {crib_hits_p2}")
    print(f"  Crib hits (Phase 3 Vig/Beau):   {crib_hits_p3}")

    # Best overall results
    print(f"\n  === Best Phase 2 (monoalphabetic substitution) ===")
    for i, (qg, pt, strat, ic_dev, mask) in enumerate(phase2_results[:5]):
        qg_pc = qg / max(1, len(pt) - 3)
        crib = score_free_fast(pt)
        print(f"  #{i+1}: QG={qg:.2f} ({qg_pc:.4f}/ch) crib={crib} strat={strat}")
        print(f"       PT: {pt[:73]}")

    print(f"\n  === Best Phase 3 (periodic substitution) ===")
    for i, (qg, pt, cipher, strat, period, mask) in enumerate(phase3_results[:5]):
        qg_pc = qg / max(1, len(pt) - 3)
        crib = score_free_fast(pt)
        print(f"  #{i+1}: QG={qg:.2f} ({qg_pc:.4f}/ch) crib={crib} {cipher} p={period} strat={strat}")
        print(f"       PT: {pt[:73]}")

    print(f"\n  {EXPERIMENT_ID} complete.")


if __name__ == "__main__":
    main()
