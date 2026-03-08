#!/usr/bin/env python3
"""
Cipher: infrastructure
Family: _infra
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""K4 Reverse Engineering Engine — Plaintext-First Cryptanalysis.

Instead of searching cipher parameter space (669B configs, all noise),
this inverts the paradigm: search PLAINTEXT space and check if implied
keystreams have structure. Also tests the bifurcated message hypothesis.

Three phases:
  Phase 1: Dictionary word placement sweep (~55M checks)
  Phase 2: Exhaustive 2-word dictionary region fill (3 stages, ~56B combos)
  Phase 3: Bifurcated message statistical test (~225 masks)

Usage:
  PYTHONPATH=src python3 -u scripts/k4_reverse_engine.py --workers 28
  PYTHONPATH=src python3 -u scripts/k4_reverse_engine.py --phase 2 --workers 28
  PYTHONPATH=src python3 -u scripts/k4_reverse_engine.py --phase 2 --workers 28 --resume
"""
from __future__ import annotations

import argparse
import heapq
import itertools
import json
import math
import os
import random
import statistics
import sys
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── Kernel imports ───────────────────────────────────────────────────────────
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
    NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD,
)
from kryptos.kernel.transforms.vigenere import (
    vig_recover_key, beau_recover_key, varbeau_recover_key,
)
from kryptos.kernel.scoring.ic import ic, ic_by_position
from kryptos.kernel.scoring.ngram import NgramScorer
from kryptos.kernel.constraints.bean import verify_bean_simple

# ── Global constants ─────────────────────────────────────────────────────────
CT_NUM = [ord(c) - 65 for c in CT]  # Numeric ciphertext

# Known plaintexts for K1, K2, K3 (from public sources)
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K2_PT = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHS"
    "MAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTED"
    "UNDERGRUUNDTOANOTHERAGENCYWHICHISAYINGTODAY"
    # Note: K2 as solved, ~369 chars total, truncated portion below
)
K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRIS"
    "THATENCUMBEREDTHELOWERPARTOFTHEDOORWAYWAREMOVED"
    "WITHTREMBLING"
    "HANDSIMADEATINYBREACHINTHEUPP"
    "ERLEFTHANDCORNERANDTHENWIDENI"
    "NGTHEHOLEALITTLEINSERTEDACANDLEANDPEEREDIN"
)

# Crib regions (0-indexed): positions NOT covered by known cribs
UNKNOWN_REGIONS = [
    (0, 20),    # Region A: 21 chars
    (34, 62),   # Region B: 29 chars
    (74, 96),   # Region C: 23 chars
]

# Key recovery function triplet: (name, func)
KEY_VARIANTS = [
    ("vig", vig_recover_key),
    ("beau", beau_recover_key),
    ("varbeau", varbeau_recover_key),
]

RESULTS_DIR = Path("results/k4_reverse_engine")

# ── Utility functions ────────────────────────────────────────────────────────

def ensure_results_dir():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def text_to_num(text: str) -> List[int]:
    return [ord(c) - 65 for c in text.upper() if c.isalpha()]


def num_to_text(nums: List[int]) -> str:
    return "".join(chr((n % 26) + 65) for n in nums)


def load_reference_texts() -> Dict[str, List[int]]:
    """Load all reference texts for running-key matching."""
    refs: Dict[str, List[int]] = {}

    # K1-K3 plaintexts
    refs["K1_PT"] = text_to_num(K1_PT)
    refs["K2_PT"] = text_to_num(K2_PT)
    refs["K3_PT"] = text_to_num(K3_PT)

    # Full CT as reference
    refs["K4_CT"] = CT_NUM[:]

    # Carter texts
    for name, path in [
        ("carter_gutenberg", "reference/carter_gutenberg.txt"),
        ("carter_vol1", "reference/carter_vol1.txt"),
    ]:
        p = Path(path)
        if p.exists():
            raw = p.read_text(errors="ignore")
            nums = text_to_num(raw)
            if len(nums) > 0:
                refs[name] = nums

    # Running key texts
    rkt_dir = Path("reference/running_key_texts")
    if rkt_dir.is_dir():
        for f in sorted(rkt_dir.glob("*.txt")):
            raw = f.read_text(errors="ignore")
            nums = text_to_num(raw)
            if len(nums) > 0:
                refs[f.stem] = nums

    # Kryptos tableau row-by-row (KA alphabet cyclic shifts)
    from kryptos.kernel.constants import KRYPTOS_ALPHABET
    tableau_stream = []
    for shift in range(26):
        for j in range(26):
            tableau_stream.append(
                ALPH_IDX[KRYPTOS_ALPHABET[(j + shift) % 26]]
            )
    refs["ka_tableau"] = tableau_stream

    return refs


def load_dictionary(min_len: int = 4, max_len: int = 21) -> List[str]:
    """Load English dictionary, filtered by length."""
    p = Path("wordlists/english.txt")
    words = []
    with open(p) as f:
        for line in f:
            w = line.strip().upper()
            if w.isalpha() and min_len <= len(w) <= max_len:
                words.append(w)
    return words


def load_ngram_scorer() -> Optional[NgramScorer]:
    """Load the quadgram scorer."""
    for path in [
        Path("data/english_quadgrams.json"),
        Path("results/anneal_step7_start8/english_quadgrams.json"),
    ]:
        if path.exists():
            return NgramScorer.from_file(path)
    return None


def load_plaintext_candidates(path: str = "scripts/k4_plaintext_candidates.txt") -> List[str]:
    """Load user-supplied plaintext candidates.

    Candidates are padded with X to 97 chars or truncated if too long.
    Cribs are force-inserted at the correct positions.
    """
    p = Path(path)
    if not p.exists():
        return []
    candidates = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Normalize: uppercase, strip non-alpha
        clean = "".join(c for c in line.upper() if c.isalpha())
        if len(clean) < 50:  # too short to be useful
            continue
        # Pad or truncate to 97
        if len(clean) < CT_LEN:
            clean = clean + "X" * (CT_LEN - len(clean))
        elif len(clean) > CT_LEN:
            clean = clean[:CT_LEN]
        # Force-insert cribs at correct positions
        pt = list(clean)
        for pos, ch in CRIB_DICT.items():
            pt[pos] = ch
        candidates.append("".join(pt))
    return list(dict.fromkeys(candidates))  # deduplicate


# ── Keystream analysis battery ───────────────────────────────────────────────

def recover_keystream(pt_positions: Dict[int, int], ct_num: List[int],
                      recover_fn) -> Dict[int, int]:
    """Recover keystream values at known positions."""
    ks = {}
    for pos, pt_val in pt_positions.items():
        if 0 <= pos < len(ct_num):
            ks[pos] = recover_fn(ct_num[pos], pt_val)
    return ks


def check_periodicity(ks: Dict[int, int], max_period: int = 26,
                      z_threshold: float = 4.0) -> List[Dict]:
    """Check if keystream values are consistent with periodic key."""
    flags = []
    positions = sorted(ks.keys())
    n = len(positions)
    if n < 4:
        return flags

    for period in range(2, min(max_period + 1, n)):
        # Group by position mod period
        groups: Dict[int, List[int]] = {}
        for pos in positions:
            r = pos % period
            groups.setdefault(r, []).append(ks[pos])

        # Count agreements within each group
        total_pairs = 0
        agreeing_pairs = 0
        for vals in groups.values():
            nv = len(vals)
            for i in range(nv):
                for j in range(i + 1, nv):
                    total_pairs += 1
                    if vals[i] == vals[j]:
                        agreeing_pairs += 1

        if total_pairs == 0:
            continue

        # Expected random: 1/26 of pairs agree
        observed_rate = agreeing_pairs / total_pairs
        expected_rate = 1.0 / 26
        if total_pairs >= 3:
            se = math.sqrt(expected_rate * (1 - expected_rate) / total_pairs)
            if se > 0:
                z = (observed_rate - expected_rate) / se
                if z > z_threshold:
                    flags.append({
                        "test": "periodicity",
                        "period": period,
                        "agreeing_pairs": agreeing_pairs,
                        "total_pairs": total_pairs,
                        "rate": round(observed_rate, 4),
                        "z_score": round(z, 2),
                    })
    return flags


def build_ref_text_indices(ref_texts: Dict[str, List[int]]) -> Dict[str, Dict[int, List[int]]]:
    """Precompute value→positions index for each reference text."""
    indices = {}
    for name, nums in ref_texts.items():
        idx: Dict[int, List[int]] = {}
        for i, v in enumerate(nums):
            idx.setdefault(v, []).append(i)
        indices[name] = idx
    return indices


def check_running_key_match(ks: Dict[int, int],
                            ref_texts: Dict[str, List[int]],
                            ref_indices: Dict[str, Dict[int, List[int]]],
                            min_consecutive: int = 8) -> List[Dict]:
    """Check if keystream matches any reference text at some offset.

    Uses multi-anchor filtering: finds offsets where the first N known
    keystream positions all match, then validates the full match.
    With 3 anchors and ~1/26 match rate each, candidate offsets ≈ ref_len/26^3.
    For 300K text: ~17 candidates. Very fast.
    """
    flags = []
    positions = sorted(ks.keys())
    n_pos = len(positions)
    if n_pos < 6:
        return flags

    # Use first 4 positions as anchors
    n_anchors = min(4, n_pos)
    anchors = [(positions[i], ks[positions[i]]) for i in range(n_anchors)]

    for ref_name, ref_nums in ref_texts.items():
        ref_len = len(ref_nums)
        if ref_len < 10:
            continue

        idx_map = ref_indices.get(ref_name, {})

        # Pick the anchor with the FEWEST occurrences in the ref text
        # to minimise the initial set size
        anchors_with_count = [
            (len(idx_map.get(a_val, [])), a_pos, a_val)
            for a_pos, a_val in anchors
        ]
        anchors_with_count.sort()  # fewest occurrences first

        # Start with the rarest anchor
        _, start_pos, start_val = anchors_with_count[0]
        candidate_offsets = set()
        for ref_idx in idx_map.get(start_val, []):
            offset = ref_idx - start_pos
            if 0 <= offset and offset + positions[-1] < ref_len:
                candidate_offsets.add(offset)

        # Intersect with remaining anchors (rarest first for early pruning)
        for _, a_pos, a_val in anchors_with_count[1:]:
            next_offsets = set()
            for ref_idx in idx_map.get(a_val, []):
                offset = ref_idx - a_pos
                if offset in candidate_offsets:
                    next_offsets.add(offset)
            candidate_offsets = next_offsets
            if not candidate_offsets:
                break

        best_match = 0
        best_offset = 0

        for offset in candidate_offsets:
            matches = 0
            consecutive = 0
            max_consecutive = 0
            prev_pos = -2

            for pos in positions:
                ref_idx = pos + offset
                if ref_idx < 0 or ref_idx >= ref_len:
                    continue
                if ks[pos] == ref_nums[ref_idx]:
                    matches += 1
                    if pos == prev_pos + 1:
                        consecutive += 1
                    else:
                        consecutive = 1
                    max_consecutive = max(max_consecutive, consecutive)
                else:
                    consecutive = 0
                prev_pos = pos

            if max_consecutive >= min_consecutive:
                flags.append({
                    "test": "running_key_match",
                    "ref": ref_name,
                    "offset": offset,
                    "consecutive": max_consecutive,
                    "total_matches": matches,
                    "total_positions": n_pos,
                })

            if matches > best_match:
                best_match = matches
                best_offset = offset

        # Also flag if total match rate is very high (>60%)
        if best_match > 0.6 * n_pos and n_pos >= 10:
            flags.append({
                "test": "running_key_high_rate",
                "ref": ref_name,
                "offset": best_offset,
                "matches": best_match,
                "total": n_pos,
                "rate": round(best_match / n_pos, 3),
            })

    return flags


def check_keystream_as_text(ks: Dict[int, int],
                            scorer: Optional[NgramScorer],
                            threshold: float = -4.5) -> List[Dict]:
    """Score keystream-as-letters using quadgrams."""
    flags = []
    if scorer is None:
        return flags

    positions = sorted(ks.keys())
    if len(positions) < 8:
        return flags

    # Build keystream text (only contiguous or near-contiguous runs)
    ks_text = num_to_text([ks[p] for p in positions])

    spc = scorer.score_per_char(ks_text)
    if spc > threshold:
        flags.append({
            "test": "keystream_text_quality",
            "score_per_char": round(spc, 4),
            "threshold": threshold,
            "text_sample": ks_text[:40],
        })

    return flags


def check_bean(ks: Dict[int, int]) -> List[Dict]:
    """Check Bean equality constraint: k[27] == k[65]."""
    flags = []
    if 27 in ks and 65 in ks:
        if ks[27] == ks[65]:
            flags.append({
                "test": "bean_eq_pass",
                "k27": ks[27],
                "k65": ks[65],
            })
    return flags


def check_bean_full(ks: Dict[int, int]) -> Tuple[bool, int]:
    """Full Bean check on partial keystream. Returns (eq_pass, ineq_pass_count)."""
    eq_pass = True
    for a, b in BEAN_EQ:
        if a in ks and b in ks:
            if ks[a] != ks[b]:
                eq_pass = False

    ineq_pass = 0
    ineq_total = 0
    for a, b in BEAN_INEQ:
        if a in ks and b in ks:
            ineq_total += 1
            if ks[a] != ks[b]:
                ineq_pass += 1

    return eq_pass, ineq_pass


def check_low_entropy(ks: Dict[int, int], min_positions: int = 30,
                      max_distinct: int = 10) -> List[Dict]:
    """Flag if keystream has very few distinct values."""
    flags = []
    if len(ks) < min_positions:
        return flags
    distinct = len(set(ks.values()))
    if distinct <= max_distinct:
        flags.append({
            "test": "low_entropy",
            "distinct_values": distinct,
            "total_positions": len(ks),
        })
    return flags


def check_autocorrelation(ks: Dict[int, int], max_lag: int = 20,
                          threshold: float = 0.5,
                          min_count: int = 5) -> List[Dict]:
    """Lag-k autocorrelation of keystream values."""
    flags = []
    positions = sorted(ks.keys())
    vals = [ks[p] for p in positions]
    n = len(vals)
    if n < 10:
        return flags

    mean = statistics.mean(vals)
    var = statistics.variance(vals) if n > 1 else 0
    if var < 0.01:
        return flags

    for lag in range(1, min(max_lag + 1, n)):
        cov = 0.0
        count = 0
        for i in range(n - lag):
            # Only count if positions are actually `lag` apart
            if positions[i + lag] - positions[i] == lag:
                cov += (vals[i] - mean) * (vals[i + lag] - mean)
                count += 1
        if count >= min_count:
            r = cov / (count * var)
            if abs(r) > threshold:
                flags.append({
                    "test": "autocorrelation",
                    "lag": lag,
                    "r": round(r, 4),
                    "count": count,
                })
    return flags


def check_linear_fit(ks: Dict[int, int]) -> List[Dict]:
    """Test if k[i] = (a*i + b) mod 26 for some (a, b).

    Uses algebraic approach: for each pair of positions (p1, p2), derive
    the unique (a, b) and check all positions, instead of brute-forcing 676.
    """
    flags = []
    positions = sorted(ks.keys())
    n = len(positions)
    if n < 6:
        return flags

    best_match = 0
    best_a = 0
    best_b = 0
    seen_ab = set()

    # Sample pairs to derive candidate (a, b) values
    # For each pair (p1, p2): a = (k2 - k1) * inverse(p2 - p1) mod 26
    sample = positions[:min(10, n)]  # Use first 10 positions for pair generation
    for i in range(len(sample)):
        for j in range(i + 1, len(sample)):
            p1, p2 = sample[i], sample[j]
            dp = (p2 - p1) % 26
            dk = (ks[p2] - ks[p1]) % 26
            # Need modular inverse of dp mod 26
            # Only exists when gcd(dp, 26) divides dk
            if dp == 0:
                continue
            for a in range(26):
                if (a * dp) % 26 == dk:
                    b = (ks[p1] - a * p1) % 26
                    if (a, b) not in seen_ab:
                        seen_ab.add((a, b))
                        match = sum(1 for p in positions if (a * p + b) % 26 == ks[p])
                        if match > best_match:
                            best_match = match
                            best_a = a
                            best_b = b

    if best_match == n and n >= 6:
        flags.append({
            "test": "linear_fit_exact",
            "a": best_a,
            "b": best_b,
            "matching": best_match,
            "total": n,
        })
    elif best_match >= 0.9 * n and n >= 10:
        flags.append({
            "test": "linear_fit_near",
            "a": best_a,
            "b": best_b,
            "matching": best_match,
            "total": n,
            "rate": round(best_match / n, 3),
        })

    return flags


def run_keystream_battery(ks: Dict[int, int],
                          ref_texts: Dict[str, List[int]],
                          ref_indices: Dict[str, Dict[int, List[int]]],
                          scorer: Optional[NgramScorer],
                          full: bool = False) -> List[Dict]:
    """Run keystream analysis tests.

    Args:
        full: If True, run all tests including large refs (Phase 2).
              If False, run fast subset with small refs only (Phase 1).
    """
    flags = []
    # Phase 1: only meaningful periods ≤7 (higher periods underdetermined)
    # Phase 2: check all periods up to 26
    flags.extend(check_periodicity(ks,
                                   max_period=26 if full else 7,
                                   z_threshold=3.5 if full else 4.0))

    # Running key: in Phase 1, only check small refs (< 15K chars) for speed
    if full:
        rk_refs = ref_texts
        rk_idx = ref_indices
    else:
        rk_refs = {k: v for k, v in ref_texts.items() if len(v) < 15000}
        rk_idx = {k: v for k, v in ref_indices.items() if k in rk_refs}
    flags.extend(check_running_key_match(ks, rk_refs, rk_idx))

    if full:
        flags.extend(check_keystream_as_text(ks, scorer))
    flags.extend(check_low_entropy(ks))
    # Phase 1: strict autocorrelation (0.8, min 12) to avoid crib-gap artifacts
    # Phase 2: relaxed (0.5, min 5) since we have full 97-position keystreams
    flags.extend(check_autocorrelation(ks, threshold=0.5 if full else 0.8,
                                       min_count=5 if full else 12))
    flags.extend(check_linear_fit(ks))
    return flags


# ── Phase 1: Dictionary Word Placement ───────────────────────────────────────

def _compute_baseline_periodicity() -> Dict[str, Dict[int, float]]:
    """Compute baseline periodicity z-scores from cribs alone for each variant."""
    crib_num = {pos: ord(ch) - 65 for pos, ch in CRIB_DICT.items()}
    baselines = {}
    for vname, fn in KEY_VARIANTS:
        ks = recover_keystream(crib_num, CT_NUM, fn)
        flags = check_periodicity(ks, max_period=7, z_threshold=-999)
        baselines[vname] = {fl["period"]: fl["z_score"] for fl in flags}
    return baselines

# Module-level baseline (computed once at import)
_PERIODICITY_BASELINES: Optional[Dict[str, Dict[int, float]]] = None


def _get_baselines() -> Dict[str, Dict[int, float]]:
    global _PERIODICITY_BASELINES
    if _PERIODICITY_BASELINES is None:
        _PERIODICITY_BASELINES = _compute_baseline_periodicity()
    return _PERIODICITY_BASELINES


def phase1_process_batch(args: Tuple) -> List[Dict]:
    """Process a batch of words for Phase 1 (worker function)."""
    words, ref_texts_serial, scorer_path = args

    # Reconstruct scorer in subprocess
    scorer = None
    if scorer_path:
        try:
            scorer = NgramScorer.from_file(scorer_path)
        except Exception:
            pass

    # Reconstruct reference texts (passed as serializable dict)
    ref_texts = ref_texts_serial

    # Precompute reference text indices (once per worker)
    ref_indices = build_ref_text_indices(ref_texts)

    # Compute baselines (once per worker)
    baselines = _get_baselines()

    # Crib positions as numeric
    crib_num = {pos: ord(ch) - 65 for pos, ch in CRIB_DICT.items()}

    hits = []

    for word in words:
        word_num = text_to_num(word)
        wlen = len(word_num)

        # Try each valid starting position in unknown regions
        for region_start, region_end in UNKNOWN_REGIONS:
            max_start = region_end - wlen + 1
            for start_pos in range(region_start, max_start + 1):
                # Check word doesn't overlap crib positions
                word_positions = range(start_pos, start_pos + wlen)
                if any(p in CRIB_POSITIONS for p in word_positions):
                    continue

                # Build partial plaintext: cribs + this word
                pt_positions = dict(crib_num)
                for i, val in enumerate(word_num):
                    pt_positions[start_pos + i] = val

                # Test all three variants
                for variant_name, recover_fn in KEY_VARIANTS:
                    ks = recover_keystream(pt_positions, CT_NUM, recover_fn)

                    # Quick prefilter: Bean equality
                    bean_eq = True
                    if 27 in ks and 65 in ks:
                        bean_eq = (ks[27] == ks[65])
                    if not bean_eq:
                        continue

                    # Fast battery (no quadgram scoring, tighter thresholds)
                    flags = run_keystream_battery(ks, ref_texts, ref_indices,
                                                 scorer, full=False)

                    # Subtract baseline periodicity: only keep flags where
                    # z-score exceeds baseline by ≥2.0 (word adds real signal)
                    base = baselines.get(variant_name, {})
                    significant_flags = []
                    for fl in flags:
                        if fl["test"] == "periodicity":
                            base_z = base.get(fl["period"], 0)
                            delta_z = fl["z_score"] - base_z
                            if delta_z >= 2.0:
                                fl["delta_z"] = round(delta_z, 2)
                                fl["baseline_z"] = base_z
                                significant_flags.append(fl)
                        else:
                            significant_flags.append(fl)

                    if len(significant_flags) >= 2:
                        hits.append({
                            "word": word,
                            "position": start_pos,
                            "variant": variant_name,
                            "n_known": len(ks),
                            "bean_eq": bean_eq,
                            "flags": significant_flags,
                            "n_flags": len(significant_flags),
                        })

    return hits


def run_phase1(workers: int = 8, batch_size: int = 500):
    """Phase 1: Dictionary word placement sweep."""
    print("=" * 70)
    print("PHASE 1: Dictionary Word Placement Sweep")
    print("=" * 70)

    t0 = time.time()

    print("Loading dictionary...")
    words = load_dictionary(min_len=4, max_len=21)
    print(f"  {len(words)} words (4-21 chars)")

    print("Loading reference texts...")
    ref_texts = load_reference_texts()
    print(f"  {len(ref_texts)} reference texts loaded")
    for name, nums in ref_texts.items():
        print(f"    {name}: {len(nums)} chars")

    # Find quadgram file path for workers
    scorer_path = None
    for p in [Path("data/english_quadgrams.json"),
              Path("results/anneal_step7_start8/english_quadgrams.json")]:
        if p.exists():
            scorer_path = str(p)
            break

    # Estimate total checks
    total_placements = 0
    for word in words:
        wlen = len(word)
        for rs, re_ in UNKNOWN_REGIONS:
            span = re_ - rs + 1
            if span >= wlen:
                total_placements += span - wlen + 1
    total_checks = total_placements * 3  # 3 variants
    print(f"  Estimated: {total_placements:,} placements × 3 variants = {total_checks:,} checks")

    # Split into batches
    batches = []
    for i in range(0, len(words), batch_size):
        chunk = words[i:i + batch_size]
        batches.append((chunk, ref_texts, scorer_path))

    print(f"  {len(batches)} batches of ~{batch_size} words, {workers} workers")
    print()

    all_hits: List[Dict] = []
    done = 0

    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(phase1_process_batch, b): i
                   for i, b in enumerate(batches)}
        for future in as_completed(futures):
            batch_hits = future.result()
            all_hits.extend(batch_hits)
            done += 1
            if done % 20 == 0 or done == len(batches):
                elapsed = time.time() - t0
                print(f"  [{done}/{len(batches)}] {elapsed:.1f}s, {len(all_hits)} hits so far")

    elapsed = time.time() - t0
    print(f"\nPhase 1 complete: {elapsed:.1f}s, {len(all_hits)} total hits")

    # Sort by number of flags (most interesting first)
    all_hits.sort(key=lambda h: h["n_flags"], reverse=True)

    # Save results
    ensure_results_dir()
    out_path = RESULTS_DIR / "phase1_hits.json"
    with open(out_path, "w") as f:
        json.dump({
            "phase": 1,
            "total_words": len(words),
            "total_checks_est": total_checks,
            "elapsed_seconds": round(elapsed, 1),
            "total_hits": len(all_hits),
            "hits": all_hits,
        }, f, indent=2)
    print(f"  Results: {out_path}")

    # Print top hits
    if all_hits:
        print(f"\n  Top 20 hits (by flag count):")
        for h in all_hits[:20]:
            print(f"    {h['word']:20s} @{h['position']:2d} [{h['variant']:8s}] "
                  f"flags={h['n_flags']} known={h['n_known']}")
            for fl in h["flags"][:3]:
                print(f"      {fl['test']}: {_flag_summary(fl)}")
    else:
        print("  No hits with flagged keystream structure.")

    return all_hits


def _flag_summary(fl: Dict) -> str:
    """One-line summary of a flag."""
    t = fl["test"]
    if t == "periodicity":
        return f"period={fl['period']} z={fl['z_score']}"
    elif t == "running_key_match":
        return f"ref={fl['ref']} offset={fl['offset']} consec={fl['consecutive']}"
    elif t == "running_key_high_rate":
        return f"ref={fl['ref']} rate={fl['rate']}"
    elif t == "keystream_text_quality":
        return f"spc={fl['score_per_char']} sample={fl['text_sample']}"
    elif t == "bean_eq_pass":
        return f"k27=k65={fl['k27']}"
    elif t == "low_entropy":
        return f"distinct={fl['distinct_values']}/{fl['total_positions']}"
    elif t == "autocorrelation":
        return f"lag={fl['lag']} r={fl['r']}"
    elif t.startswith("linear_fit"):
        return f"a={fl['a']} b={fl['b']} match={fl['matching']}/{fl['total']}"
    return str(fl)


# ── Phase 2: Exhaustive 2-Word Dictionary Region Fill ────────────────────
#
# Three stages:
#   Stage 1: Independently sweep all 2-word fills per region (~56B combos)
#   Stage 2: Cross-combine top fills from each region (~600M combos)
#   Stage 3: Full keystream battery on best complete candidates
#
# Key insight: regions are independent. Each region's keystream depends only
# on its own plaintext characters and the fixed ciphertext. We score each
# region's fills independently (Stage 1), then cross-combine only the top
# scorers (Stage 2), then run the full battery on the best (Stage 3).

STAGE1_TOP_K = 10_000
STAGE2_TOP_K = 10_000
MIN_FILL_WORD_LEN = 4
STAGE1_BATCH_SIZE = 500

# Region definitions: the 3 unknown gaps between/around cribs
_REGION_DEFS = {
    "A": {"start": 0, "end": 20, "length": 21,
           "crib_prefix_pos": [],
           "crib_suffix_pos": list(range(21, 34))},
    "B": {"start": 34, "end": 62, "length": 29,
           "crib_prefix_pos": list(range(21, 34)),
           "crib_suffix_pos": list(range(63, 74))},
    "C": {"start": 74, "end": 96, "length": 23,
           "crib_prefix_pos": list(range(63, 74)),
           "crib_suffix_pos": []},
}


def _build_ks_char_table(region_start, region_length, recover_fn):
    """Lookup table: table[offset] is a 26-char string, indexed by pt_val.

    Usage: table[offset][pt_val] -> single key character.
    """
    return [
        ''.join(chr(recover_fn(CT_NUM[region_start + off], pv) + 65)
                for pv in range(26))
        for off in range(region_length)
    ]


def _build_crib_ks(positions, recover_fn):
    """Keystream string for crib positions (constant per variant)."""
    return ''.join(
        chr(recover_fn(CT_NUM[p], ord(CRIB_DICT[p]) - 65) + 65)
        for p in positions
    )


def _fill_ks_from_words(w1, w2, ks_table):
    """Keystream string for a 2-word fill starting at offset 0 in the region."""
    l1 = len(w1)
    parts = []
    for i, ch in enumerate(w1):
        parts.append(ks_table[i][ord(ch) - 65])
    for i, ch in enumerate(w2):
        parts.append(ks_table[l1 + i][ord(ch) - 65])
    return ''.join(parts)


def _stage1_worker(args):
    """Score all (w1, w2) combos for one batch of word1 candidates.

    Returns: (top_entries, n_combos)
        top_entries: list of (score, w1, w2) sorted best-first
        n_combos: total combinations scored
    """
    (w1_words, w2_words, ks_char_table, l1,
     crib_prefix_ks, crib_suffix_ks, scorer_path, top_k) = args

    scorer = NgramScorer.from_file(scorer_path)

    # Precompute keystream strings for all w2 (at offset l1 within region)
    w2_ks = [''.join(ks_char_table[l1 + i][ord(ch) - 65]
                     for i, ch in enumerate(w))
             for w in w2_words]

    # Append crib suffix to w2 ks (one fewer concat in inner loop)
    if crib_suffix_ks:
        w2_ks_full = [ks + crib_suffix_ks for ks in w2_ks]
    else:
        w2_ks_full = w2_ks

    heap = []  # min-heap of (score, counter, w1, w2)
    counter = 0
    n_w2 = len(w2_words)

    for w1 in w1_words:
        w1_ks = ''.join(ks_char_table[i][ord(ch) - 65]
                        for i, ch in enumerate(w1))
        w1_full = (crib_prefix_ks + w1_ks) if crib_prefix_ks else w1_ks

        for j in range(n_w2):
            ks_text = w1_full + w2_ks_full[j]
            score = scorer.score_per_char(ks_text)
            counter += 1

            if len(heap) < top_k:
                heapq.heappush(heap, (score, counter, w1, w2_words[j]))
            elif score > heap[0][0]:
                heapq.heappushpop(heap, (score, counter, w1, w2_words[j]))

    results = [(s, w1, w2) for s, _, w1, w2 in sorted(heap, reverse=True)]
    return results, counter


def _stage2_worker(args):
    """Cross-combine two sets of (ks_string, data) entries.

    Generic worker for both Stage 2a (A x B) and Stage 2b (AB x C).
    Each entry in batch_a / all_b is (ks_string, data_tuple).
    Returns: (top_entries, n_combos)
    """
    (batch_a, all_b, scorer_path, top_k) = args

    scorer = NgramScorer.from_file(scorer_path)

    heap = []
    counter = 0

    for a_ks, a_data in batch_a:
        for b_ks, b_data in all_b:
            ks_text = a_ks + b_ks
            score = scorer.score_per_char(ks_text)
            counter += 1

            if len(heap) < top_k:
                heapq.heappush(heap, (score, counter, a_data, b_data))
            elif score > heap[0][0]:
                heapq.heappushpop(heap, (score, counter, a_data, b_data))

    results = [(s, ad, bd) for s, _, ad, bd in sorted(heap, reverse=True)]
    return results, counter


def check_column_reading(ks_list: List[int], ref_texts: Dict[str, List[int]],
                         max_width: int = 15) -> List[Dict]:
    """Check if keystream is a column-reading of a reference text at some width.

    Only checks short reference texts (< 2000 chars) to keep runtime bounded.
    For large texts like Carter, the column-reading space is too vast.
    """
    flags = []
    n = len(ks_list)
    for ref_name, ref_nums in ref_texts.items():
        ref_len = len(ref_nums)
        if ref_len > 2000 or ref_len < 20:
            continue
        for width in range(5, min(max_width + 1, ref_len)):
            n_rows = (ref_len + width - 1) // width
            col_read = []
            for col in range(width):
                for row in range(n_rows):
                    idx = row * width + col
                    if idx < ref_len:
                        col_read.append(ref_nums[idx])
            # Check match at offset 0 only (column-reading is position-specific)
            for offset in range(min(20, max(1, len(col_read) - n))):
                match = sum(1 for i in range(n)
                            if offset + i < len(col_read)
                            and ks_list[i] == col_read[offset + i])
                if match > 0.7 * n:
                    flags.append({
                        "test": "column_reading",
                        "ref": ref_name,
                        "width": width,
                        "offset": offset,
                        "match": match,
                        "total": n,
                        "rate": round(match / n, 3),
                    })
                    break
    return flags


def _composite_score(bean_pass: bool, pt_ic: float,
                     pt_ngram: Optional[float], ks_ic: float,
                     ks_ngram: Optional[float], n_flags: int) -> float:
    """Composite score for ranking Phase 2 candidates.

    Note: Bean is tautologically satisfied for full plaintexts with
    correct cribs, so it gets no bonus points here.
    """
    score = 0.0
    # PT quality (English-like plaintext)
    if pt_ic > 0.060:
        score += 8.0
    elif pt_ic > 0.055:
        score += 5.0
    elif pt_ic > 0.045:
        score += 2.0
    if pt_ngram and pt_ngram > -4.5:
        score += 8.0
    elif pt_ngram and pt_ngram > -4.84:
        score += 5.0
    elif pt_ngram and pt_ngram > -5.0:
        score += 2.0
    # KS quality (English running key indicator)
    if ks_ngram and ks_ngram > -4.5:
        score += 15.0  # Strong signal: keystream reads as English
    elif ks_ngram and ks_ngram > -5.0:
        score += 5.0
    if ks_ic > 0.060:
        score += 8.0
    elif ks_ic > 0.055:
        score += 5.0
    # Structural flags (each is valuable)
    score += n_flags * 5.0
    return score


def _run_stage1(workers, scorer_path, words_by_len, resume):
    """Stage 1: Independent region sweeps (~56B combos at all cores ~5.5h).

    For each region × variant, enumerate all 2-word dictionary fills and
    score the implied keystream (including adjacent crib keystream) with
    quadgrams.  Maintain top-K per (region, variant).
    """
    print("\n── STAGE 1: Independent Region Sweeps ──")

    results = {}
    checkpoint_path = RESULTS_DIR / "stage1_checkpoint.json"
    completed = set()
    if resume and checkpoint_path.exists():
        with open(checkpoint_path) as f:
            completed = set(
                tuple(x) for x in json.load(f).get("completed", [])
            )
        print(f"  Resuming: {len(completed)} (region, variant) pairs already done")

    total_combos_all = 0
    t0 = time.time()

    for region_name in ["A", "B", "C"]:
        rdef = _REGION_DEFS[region_name]
        rlen = rdef["length"]

        for var_name, recover_fn in KEY_VARIANTS:
            key = (region_name, var_name)
            result_file = RESULTS_DIR / f"stage1_{region_name}_{var_name}.json"

            # Resume: load cached results if available
            if key in completed or (resume and result_file.exists()):
                print(f"  [{region_name}/{var_name}] Loading cached results...")
                with open(result_file) as f:
                    data = json.load(f)
                results[key] = [
                    (e["score"], e["w1"], e["w2"]) for e in data["entries"]
                ]
                completed.add(key)
                continue

            print(f"\n  [{region_name}/{var_name}] Sweeping region {region_name} "
                  f"(len={rlen})...")

            # Build lookup tables for this (region, variant)
            ks_table = _build_ks_char_table(
                rdef["start"], rlen, recover_fn)
            crib_prefix = _build_crib_ks(rdef["crib_prefix_pos"], recover_fn)
            crib_suffix = _build_crib_ks(rdef["crib_suffix_pos"], recover_fn)

            # Generate work units: for each (l1, l2) split, batch word1s
            work_units = []
            total_combos = 0
            for l1 in range(MIN_FILL_WORD_LEN,
                            rlen - MIN_FILL_WORD_LEN + 1):
                l2 = rlen - l1
                w1s = words_by_len.get(l1, [])
                w2s = words_by_len.get(l2, [])
                if not w1s or not w2s:
                    continue

                n_combos = len(w1s) * len(w2s)
                total_combos += n_combos

                # Batch w1s into chunks
                for bi in range(0, len(w1s), STAGE1_BATCH_SIZE):
                    batch = w1s[bi:bi + STAGE1_BATCH_SIZE]
                    work_units.append((
                        batch, w2s, ks_table, l1,
                        crib_prefix, crib_suffix, scorer_path,
                        STAGE1_TOP_K,
                    ))

            if not work_units:
                print(f"    No valid word splits for region {region_name}")
                results[key] = []
                continue

            print(f"    {total_combos:,.0f} combos across "
                  f"{len(work_units)} work units")
            total_combos_all += total_combos

            # Submit work units to pool
            master_heap = []
            master_counter = 0
            done = 0
            combos_done = 0
            t_region = time.time()
            last_print = t_region

            with ProcessPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(_stage1_worker, wu): i
                    for i, wu in enumerate(work_units)
                }
                for future in as_completed(futures):
                    top_entries, n_combos = future.result()
                    combos_done += n_combos
                    done += 1

                    # Merge into master heap
                    for score, w1, w2 in top_entries:
                        master_counter += 1
                        entry = (score, master_counter, w1, w2)
                        if len(master_heap) < STAGE1_TOP_K:
                            heapq.heappush(master_heap, entry)
                        elif score > master_heap[0][0]:
                            heapq.heappushpop(master_heap, entry)

                    now = time.time()
                    if now - last_print >= 30 or done == len(work_units):
                        elapsed = now - t_region
                        rate = combos_done / elapsed if elapsed > 0 else 0
                        pct = (100 * combos_done / total_combos
                               if total_combos > 0 else 0)
                        eta_h = ((total_combos - combos_done) / rate / 3600
                                 if rate > 0 else 0)
                        heap_min = (master_heap[0][0]
                                    if master_heap else float('-inf'))
                        print(f"    [{done}/{len(work_units)}] {pct:.1f}% "
                              f"{elapsed:.0f}s {rate/1e6:.1f}M/s "
                              f"ETA {eta_h:.1f}h "
                              f"heap_min={heap_min:.4f}")
                        last_print = now

            # Extract top-K sorted best-first
            top_k_list = [
                (s, w1, w2)
                for s, _, w1, w2 in sorted(master_heap, reverse=True)
            ]
            results[key] = top_k_list

            # Save results
            elapsed_region = time.time() - t_region
            with open(result_file, 'w') as f:
                json.dump({
                    "region": region_name,
                    "variant": var_name,
                    "total_combos": total_combos,
                    "elapsed_seconds": round(elapsed_region, 1),
                    "top_k": len(top_k_list),
                    "entries": [
                        {"score": round(s, 6), "w1": w1, "w2": w2}
                        for s, w1, w2 in top_k_list
                    ],
                }, f, indent=2)

            # Update checkpoint
            completed.add(key)
            with open(checkpoint_path, 'w') as f:
                json.dump({
                    "completed": [list(k) for k in completed]
                }, f)

            if top_k_list:
                print(f"    Done: {elapsed_region:.1f}s, "
                      f"best={top_k_list[0][0]:.4f} "
                      f"worst_in_top={top_k_list[-1][0]:.4f}")
            else:
                print(f"    Done: {elapsed_region:.1f}s, no results")

    elapsed_total = time.time() - t0
    print(f"\n  Stage 1 complete: {elapsed_total:.1f}s "
          f"({elapsed_total/3600:.1f}h), "
          f"{total_combos_all:,.0f} total combos")
    return results


def _run_stage2(stage1_results, workers, scorer_path):
    """Stage 2: Cross-combine top fills hierarchically (~15 min).

    Stage 2a: A x B -> top 10K combined (positions 0-73)
    Stage 2b: AB x C -> top 10K full candidates (positions 0-96)
    """
    print("\n── STAGE 2: Cross-Combine Top Fills ──")

    final_results = {}
    stage2_batch_size = 100  # A/AB entries per work unit

    for var_name, recover_fn in KEY_VARIANTS:
        print(f"\n  [{var_name}] Cross-combining...")

        key_a = ("A", var_name)
        key_b = ("B", var_name)
        key_c = ("C", var_name)

        top_a = stage1_results.get(key_a, [])
        top_b = stage1_results.get(key_b, [])
        top_c = stage1_results.get(key_c, [])

        if not top_a or not top_b or not top_c:
            print(f"    Skipping: missing results for one or more regions")
            final_results[var_name] = []
            continue

        # Build ks tables for reconstructing fill keystreams
        ks_table_a = _build_ks_char_table(
            _REGION_DEFS["A"]["start"],
            _REGION_DEFS["A"]["length"], recover_fn)
        ks_table_b = _build_ks_char_table(
            _REGION_DEFS["B"]["start"],
            _REGION_DEFS["B"]["length"], recover_fn)
        ks_table_c = _build_ks_char_table(
            _REGION_DEFS["C"]["start"],
            _REGION_DEFS["C"]["length"], recover_fn)

        ene_ks = _build_crib_ks(list(range(21, 34)), recover_fn)
        bc_ks = _build_crib_ks(list(range(63, 74)), recover_fn)

        # ── Stage 2a: A x B ──
        n_ab = len(top_a) * len(top_b)
        print(f"    Stage 2a: {len(top_a)} x {len(top_b)} = {n_ab:,} combos")
        t_2a = time.time()

        # Prepare A entries: (a_ks_with_ene, (w1, w2))
        # a_ks_with_ene covers positions 0-33 (fill + ENE crib)
        a_entries = []
        for _, w1, w2 in top_a:
            fill_ks = _fill_ks_from_words(w1, w2, ks_table_a)
            a_entries.append((fill_ks + ene_ks, (w1, w2)))

        # Prepare B entries: (b_ks_with_bc, (w1, w2))
        # b_ks_with_bc covers positions 34-73 (fill + BC crib)
        b_entries = []
        for _, w1, w2 in top_b:
            fill_ks = _fill_ks_from_words(w1, w2, ks_table_b)
            b_entries.append((fill_ks + bc_ks, (w1, w2)))

        # Batch A entries and cross with all B
        ab_work = []
        for bi in range(0, len(a_entries), stage2_batch_size):
            batch = a_entries[bi:bi + stage2_batch_size]
            ab_work.append((batch, b_entries, scorer_path, STAGE2_TOP_K))

        ab_heap = []
        ab_counter = 0
        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(_stage2_worker, wu): i
                for i, wu in enumerate(ab_work)
            }
            done = 0
            for future in as_completed(futures):
                top_entries, n = future.result()
                done += 1
                for score, a_data, b_data in top_entries:
                    ab_counter += 1
                    entry = (score, ab_counter, a_data, b_data)
                    if len(ab_heap) < STAGE2_TOP_K:
                        heapq.heappush(ab_heap, entry)
                    elif score > ab_heap[0][0]:
                        heapq.heappushpop(ab_heap, entry)
                if done % 20 == 0 or done == len(ab_work):
                    print(f"      2a: [{done}/{len(ab_work)}]")

        top_ab = [
            (s, ad, bd)
            for s, _, ad, bd in sorted(ab_heap, reverse=True)
        ]
        elapsed_2a = time.time() - t_2a
        print(f"    Stage 2a done: {elapsed_2a:.1f}s, "
              f"best={top_ab[0][0]:.4f}" if top_ab else
              f"    Stage 2a done: {elapsed_2a:.1f}s, no results")

        if not top_ab:
            final_results[var_name] = []
            continue

        # ── Stage 2b: AB x C ──
        n_abc = len(top_ab) * len(top_c)
        print(f"    Stage 2b: {len(top_ab)} x {len(top_c)} = "
              f"{n_abc:,} combos")
        t_2b = time.time()

        # Prepare AB entries: (ab_ks, (a_w1, a_w2, b_w1, b_w2))
        # ab_ks covers positions 0-73 (74 chars)
        ab_entries = []
        for _, a_data, b_data in top_ab:
            a_fill = _fill_ks_from_words(a_data[0], a_data[1], ks_table_a)
            b_fill = _fill_ks_from_words(b_data[0], b_data[1], ks_table_b)
            ab_ks = a_fill + ene_ks + b_fill + bc_ks
            ab_entries.append((ab_ks, a_data + b_data))

        # Prepare C entries: (c_fill_ks, (w1, w2))
        c_entries = []
        for _, w1, w2 in top_c:
            fill_ks = _fill_ks_from_words(w1, w2, ks_table_c)
            c_entries.append((fill_ks, (w1, w2)))

        # Batch AB entries and cross with all C
        abc_work = []
        for bi in range(0, len(ab_entries), stage2_batch_size):
            batch = ab_entries[bi:bi + stage2_batch_size]
            abc_work.append((batch, c_entries, scorer_path, STAGE2_TOP_K))

        abc_heap = []
        abc_counter = 0
        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(_stage2_worker, wu): i
                for i, wu in enumerate(abc_work)
            }
            done = 0
            for future in as_completed(futures):
                top_entries, n = future.result()
                done += 1
                for score, ab_data, c_data in top_entries:
                    abc_counter += 1
                    entry = (score, abc_counter, ab_data, c_data)
                    if len(abc_heap) < STAGE2_TOP_K:
                        heapq.heappush(abc_heap, entry)
                    elif score > abc_heap[0][0]:
                        heapq.heappushpop(abc_heap, entry)
                if done % 20 == 0 or done == len(abc_work):
                    print(f"      2b: [{done}/{len(abc_work)}]")

        # Build final entries with full ks text and plaintext
        top_abc = []
        for s, _, ab_data, c_data in sorted(abc_heap, reverse=True):
            a_w1, a_w2, b_w1, b_w2 = ab_data
            c_w1, c_w2 = c_data
            a_fill = _fill_ks_from_words(a_w1, a_w2, ks_table_a)
            b_fill = _fill_ks_from_words(b_w1, b_w2, ks_table_b)
            c_fill = _fill_ks_from_words(c_w1, c_w2, ks_table_c)
            ks_text = a_fill + ene_ks + b_fill + bc_ks + c_fill
            pt = (a_w1 + a_w2 + "EASTNORTHEAST" +
                  b_w1 + b_w2 + "BERLINCLOCK" +
                  c_w1 + c_w2)
            top_abc.append({
                "score": round(s, 6),
                "variant": var_name,
                "a_w1": a_w1, "a_w2": a_w2,
                "b_w1": b_w1, "b_w2": b_w2,
                "c_w1": c_w1, "c_w2": c_w2,
                "ks_text": ks_text,
                "plaintext": pt,
            })

        final_results[var_name] = top_abc
        elapsed_2b = time.time() - t_2b
        if top_abc:
            print(f"    Stage 2b done: {elapsed_2b:.1f}s, "
                  f"best={top_abc[0]['score']:.4f}")
        else:
            print(f"    Stage 2b done: {elapsed_2b:.1f}s, no results")

        # Save per-variant results
        with open(RESULTS_DIR / f"stage2_full_{var_name}.json", 'w') as f:
            json.dump({
                "variant": var_name,
                "n_entries": len(top_abc),
                "entries": top_abc,
            }, f, indent=2)

    return final_results


def _run_stage3(stage2_results, ref_texts, ref_indices, scorer):
    """Stage 3: Full keystream battery on top candidates (~seconds)."""
    print("\n── STAGE 3: Full Battery ──")

    all_candidates = []
    for var_name, entries in stage2_results.items():
        for entry in entries:
            all_candidates.append(entry)

    print(f"  {len(all_candidates)} candidates to evaluate")
    t0 = time.time()

    final = []
    for entry in all_candidates:
        pt = entry["plaintext"]
        var_name = entry["variant"]
        ks_text_cached = entry["ks_text"]

        # Find recover function for this variant
        recover_fn = None
        for vn, fn in KEY_VARIANTS:
            if vn == var_name:
                recover_fn = fn
                break

        pt_num = text_to_num(pt)
        pt_positions = {i: v for i, v in enumerate(pt_num)}
        ks = recover_keystream(pt_positions, CT_NUM, recover_fn)

        # Full Bean check
        ks_list = [ks.get(i, 0) for i in range(CT_LEN)]
        bean_pass = verify_bean_simple(ks_list)
        bean_eq, bean_ineq = check_bean_full(ks)

        # Full keystream battery
        flags = run_keystream_battery(
            ks, ref_texts, ref_indices, scorer, full=True)

        # Column reading check
        col_flags = check_column_reading(ks_list, ref_texts)
        flags.extend(col_flags)

        # Quality metrics
        pt_ic_val = ic(pt)
        pt_ngram = scorer.score_per_char(pt) if scorer else None
        ks_ic_val = ic(ks_text_cached)
        ks_ngram = scorer.score_per_char(ks_text_cached) if scorer else None

        composite = _composite_score(
            bean_pass, pt_ic_val, pt_ngram,
            ks_ic_val, ks_ngram, len(flags))

        final.append({
            **entry,
            "bean_pass": bean_pass,
            "bean_eq": bean_eq,
            "bean_ineq_pass": bean_ineq,
            "pt_ic": round(pt_ic_val, 5),
            "pt_ngram": round(pt_ngram, 4) if pt_ngram else None,
            "ks_ic": round(ks_ic_val, 5),
            "ks_ngram": round(ks_ngram, 4) if ks_ngram else None,
            "flags": flags,
            "n_flags": len(flags),
            "composite": composite,
        })

    final.sort(key=lambda r: r["composite"], reverse=True)
    elapsed = time.time() - t0
    print(f"  Stage 3 done: {elapsed:.1f}s")

    return final


def run_phase2(workers: int = 8, resume: bool = False,
               max_words: int = 0):
    """Phase 2: Exhaustive 2-word dictionary region fill (3 stages).

    Stage 1: Sweep all 2-word fills per region independently (~56B combos)
    Stage 2: Cross-combine top fills across regions (~600M combos)
    Stage 3: Full keystream battery on best complete candidates
    """
    print("=" * 70)
    print("PHASE 2: Exhaustive 2-Word Dictionary Region Fill")
    print("=" * 70)

    t0 = time.time()
    ensure_results_dir()

    # Load dictionary
    max_region = max(r["length"] for r in _REGION_DEFS.values())
    print("Loading dictionary...")
    all_words = load_dictionary(
        min_len=MIN_FILL_WORD_LEN,
        max_len=max_region - MIN_FILL_WORD_LEN)
    if max_words > 0:
        all_words = all_words[:max_words]
        print(f"  (--max-words {max_words}: using {len(all_words)} words)")

    words_by_len: Dict[int, List[str]] = {}
    for w in all_words:
        words_by_len.setdefault(len(w), []).append(w)

    total_words = len(all_words)
    len_dist = {k: len(v) for k, v in sorted(words_by_len.items())}
    print(f"  {total_words:,} words across lengths {min(len_dist)}–"
          f"{max(len_dist)}")

    # Estimate combos
    total_combos = 0
    for rname, rdef in _REGION_DEFS.items():
        rlen = rdef["length"]
        region_combos = 0
        for l1 in range(MIN_FILL_WORD_LEN,
                        rlen - MIN_FILL_WORD_LEN + 1):
            l2 = rlen - l1
            n1 = len(words_by_len.get(l1, []))
            n2 = len(words_by_len.get(l2, []))
            region_combos += n1 * n2
        print(f"  Region {rname} (len={rlen}): "
              f"{region_combos:,.0f} 2-word combos")
        total_combos += region_combos
    total_combos_3v = total_combos * 3
    print(f"  Total (3 variants): {total_combos_3v:,.0f} combos")

    # Find scorer path
    scorer_path = None
    for p in [Path("data/english_quadgrams.json"),
              Path("results/anneal_step7_start8/english_quadgrams.json")]:
        if p.exists():
            scorer_path = str(p)
            break
    if not scorer_path:
        print("ERROR: No quadgram scorer found!")
        return []

    # ── Stage 1 ──
    stage1_results = _run_stage1(
        workers, scorer_path, words_by_len, resume)

    # ── Stage 2 ──
    stage2_results = _run_stage2(
        stage1_results, workers, scorer_path)

    # ── Stage 3 ──
    print("\nLoading reference texts for Stage 3...")
    ref_texts = load_reference_texts()
    ref_indices = build_ref_text_indices(ref_texts)
    scorer = load_ngram_scorer()

    final = _run_stage3(stage2_results, ref_texts, ref_indices, scorer)

    elapsed = time.time() - t0

    # Save results
    with open(RESULTS_DIR / "phase2_final.json", 'w') as f:
        json.dump({
            "phase": 2,
            "total_combos": total_combos_3v,
            "elapsed_seconds": round(elapsed, 1),
            "total_candidates": len(final),
            "top_100": final[:100],
        }, f, indent=2)

    with open(RESULTS_DIR / "phase2_summary.json", 'w') as f:
        json.dump({
            "total_combos": total_combos_3v,
            "elapsed_seconds": round(elapsed, 1),
            "n_stage1_results": {
                f"{r}_{v}": len(stage1_results.get((r, v), []))
                for r in _REGION_DEFS for v, _ in KEY_VARIANTS
            },
            "n_stage2_results": {
                v: len(entries)
                for v, entries in stage2_results.items()
            },
            "n_final": len(final),
            "top_score": final[0]["composite"] if final else 0,
        }, f, indent=2)

    # Print top results
    print(f"\nPhase 2 complete: {elapsed:.1f}s ({elapsed/3600:.1f}h)")
    print(f"  Total combos scored: {total_combos_3v:,.0f}")

    if final:
        print(f"\n  Top 20 candidates (by composite score):")
        for r in final[:20]:
            print(f"    score={r['composite']:5.1f} [{r['variant']:8s}] "
                  f"bean={'PASS' if r['bean_pass'] else 'FAIL'} "
                  f"pt_ngram={r['pt_ngram']} ks_ngram={r['ks_ngram']} "
                  f"flags={r['n_flags']}")
            print(f"      PT: {r['plaintext'][:50]}...")
            print(f"      KS: {r['ks_text'][:50]}...")
    else:
        print("  No candidates produced.")

    return final


# ── Phase 3: Bifurcated Message Test ────────────────────────────────────────

def generate_split_masks() -> List[Tuple[str, List[int]]]:
    """Generate deterministic + random split masks."""
    masks: List[Tuple[str, List[int]]] = []

    # Parity: even/odd positions
    masks.append(("even", [i for i in range(CT_LEN) if i % 2 == 0]))
    masks.append(("odd", [i for i in range(CT_LEN) if i % 2 == 1]))

    # Modular splits
    for mod in [3, 4, 5, 7]:
        for residue in range(mod):
            masks.append((f"mod{mod}_r{residue}",
                          [i for i in range(CT_LEN) if i % mod == residue]))

    # Halves
    masks.append(("first48", list(range(48))))
    masks.append(("last49", list(range(48, CT_LEN))))

    # Thirds
    masks.append(("third_0_31", list(range(32))))
    masks.append(("third_32_64", list(range(32, 65))))
    masks.append(("third_65_96", list(range(65, CT_LEN))))

    # Crib-based
    masks.append(("crib_positions", sorted(CRIB_POSITIONS)))
    masks.append(("non_crib", [i for i in range(CT_LEN) if i not in CRIB_POSITIONS]))

    # Letter-based: CT vowel vs consonant positions
    vowels = set("AEIOU")
    masks.append(("ct_vowel", [i for i in range(CT_LEN) if CT[i] in vowels]))
    masks.append(("ct_consonant", [i for i in range(CT_LEN) if CT[i] not in vowels]))

    # Frequency-based: above/below median frequency
    freq = Counter(CT)
    median_freq = sorted(freq.values())[len(freq) // 2]
    high_freq_letters = {ch for ch, f in freq.items() if f >= median_freq}
    masks.append(("ct_high_freq", [i for i in range(CT_LEN) if CT[i] in high_freq_letters]))
    masks.append(("ct_low_freq", [i for i in range(CT_LEN) if CT[i] not in high_freq_letters]))

    # Random masks for null distribution (100 random 50/50 splits)
    rng = random.Random(42)  # Deterministic seed
    for j in range(100):
        indices = list(range(CT_LEN))
        rng.shuffle(indices)
        half = CT_LEN // 2
        masks.append((f"random_{j:03d}", sorted(indices[:half])))

    return masks


def subsequence_statistics(ct_text: str, positions: List[int]) -> Dict[str, Any]:
    """Compute statistical battery for a subsequence."""
    if not positions:
        return {"empty": True}

    subseq = "".join(ct_text[i] for i in positions)
    n = len(subseq)

    # IC
    sub_ic = ic(subseq)

    # Frequency chi-squared against English
    english_freq = {
        'A': 0.08167, 'B': 0.01492, 'C': 0.02782, 'D': 0.04253,
        'E': 0.12702, 'F': 0.02228, 'G': 0.02015, 'H': 0.06094,
        'I': 0.06966, 'J': 0.00153, 'K': 0.00772, 'L': 0.04025,
        'M': 0.02406, 'N': 0.06749, 'O': 0.07507, 'P': 0.01929,
        'Q': 0.00095, 'R': 0.05987, 'S': 0.06327, 'T': 0.09056,
        'U': 0.02758, 'V': 0.00978, 'W': 0.02360, 'X': 0.00150,
        'Y': 0.01974, 'Z': 0.00074,
    }
    observed = Counter(subseq)
    chi2 = sum(
        (observed.get(ch, 0) - n * ef) ** 2 / (n * ef)
        for ch, ef in english_freq.items()
    )

    # Best Caesar shift score (IC after shifting)
    best_caesar_ic = 0.0
    best_shift = 0
    for shift in range(26):
        shifted = "".join(chr((ord(c) - 65 + shift) % 26 + 65) for c in subseq)
        s_ic = ic(shifted)
        if s_ic > best_caesar_ic:
            best_caesar_ic = s_ic
            best_shift = shift

    # IC by period for periods 2-7
    ic_by_period_vals = {}
    for period in range(2, 8):
        ics = ic_by_position(subseq, period)
        ic_by_period_vals[period] = {
            "mean": round(statistics.mean(ics), 5) if ics else 0,
            "max": round(max(ics), 5) if ics else 0,
        }

    # Autocorrelation at lags 1-10
    nums = [ord(c) - 65 for c in subseq]
    mean_val = statistics.mean(nums) if nums else 0
    var_val = statistics.variance(nums) if len(nums) > 1 else 0
    autocorr = {}
    for lag in range(1, min(11, n)):
        if var_val > 0.01:
            cov = sum((nums[i] - mean_val) * (nums[i + lag] - mean_val)
                      for i in range(n - lag))
            autocorr[lag] = round(cov / ((n - lag) * var_val), 4)
        else:
            autocorr[lag] = 0.0

    # Quadgram score (load in-process to avoid pickling issues)
    qg_spc = None
    try:
        for p in [Path("data/english_quadgrams.json"),
                  Path("results/anneal_step7_start8/english_quadgrams.json")]:
            if p.exists():
                scorer = NgramScorer.from_file(p)
                if n >= 4:
                    qg_spc = round(scorer.score_per_char(subseq), 4)
                break
    except Exception:
        pass

    return {
        "n": n,
        "ic": round(sub_ic, 5),
        "chi2_english": round(chi2, 2),
        "best_caesar_ic": round(best_caesar_ic, 5),
        "best_caesar_shift": best_shift,
        "ic_by_period": ic_by_period_vals,
        "autocorrelation": autocorr,
        "quadgram_spc": qg_spc,
        "subsequence": subseq,
    }


def run_phase3():
    """Phase 3: Bifurcated message test."""
    print("=" * 70)
    print("PHASE 3: Bifurcated Message Test")
    print("=" * 70)

    t0 = time.time()

    print("Generating split masks...")
    masks = generate_split_masks()
    n_deterministic = sum(1 for name, _ in masks if not name.startswith("random_"))
    n_random = sum(1 for name, _ in masks if name.startswith("random_"))
    print(f"  {n_deterministic} deterministic + {n_random} random = {len(masks)} total masks")

    print("Computing statistics...\n")

    results = []
    for mask_name, positions in masks:
        complement = sorted(set(range(CT_LEN)) - set(positions))

        stats_a = subsequence_statistics(CT, positions)
        stats_b = subsequence_statistics(CT, complement)

        results.append({
            "mask": mask_name,
            "n_a": len(positions),
            "n_b": len(complement),
            "stats_a": stats_a,
            "stats_b": stats_b,
        })

    # Separate deterministic and random results
    det_results = [r for r in results if not r["mask"].startswith("random_")]
    rnd_results = [r for r in results if r["mask"].startswith("random_")]

    # Build null distribution from random masks
    null_ic_a = [r["stats_a"]["ic"] for r in rnd_results if not r["stats_a"].get("empty")]
    null_ic_b = [r["stats_b"]["ic"] for r in rnd_results if not r["stats_b"].get("empty")]
    null_chi2_a = [r["stats_a"]["chi2_english"] for r in rnd_results if not r["stats_a"].get("empty")]
    null_chi2_b = [r["stats_b"]["chi2_english"] for r in rnd_results if not r["stats_b"].get("empty")]
    null_qg_a = [r["stats_a"]["quadgram_spc"] for r in rnd_results
                 if r["stats_a"].get("quadgram_spc") is not None]
    null_qg_b = [r["stats_b"]["quadgram_spc"] for r in rnd_results
                 if r["stats_b"].get("quadgram_spc") is not None]

    def safe_z(value: float, dist: List[float]) -> float:
        if len(dist) < 3:
            return 0.0
        m = statistics.mean(dist)
        s = statistics.stdev(dist)
        if s < 1e-10:
            return 0.0
        return (value - m) / s

    # Compute z-scores for deterministic masks
    flagged = []
    print(f"{'Mask':<20s} {'n_a':>4s} {'IC_a':>7s} {'z_IC_a':>7s} "
          f"{'IC_b':>7s} {'z_IC_b':>7s} {'QG_a':>7s} {'QG_b':>7s} {'FLAG':>5s}")
    print("-" * 90)

    for r in det_results:
        sa = r["stats_a"]
        sb = r["stats_b"]
        if sa.get("empty") or sb.get("empty"):
            continue

        z_ic_a = safe_z(sa["ic"], null_ic_a)
        z_ic_b = safe_z(sb["ic"], null_ic_b)
        z_chi2_a = safe_z(sa["chi2_english"], null_chi2_a)
        z_chi2_b = safe_z(sb["chi2_english"], null_chi2_b)

        # Flag if BOTH subsequences show signal (z > 2.5 on any metric,
        # where higher IC or lower chi2 = more English-like)
        flag = False
        if z_ic_a > 2.5 and z_ic_b > 2.5:
            flag = True
        if z_chi2_a < -2.5 and z_chi2_b < -2.5:
            flag = True

        qg_a = sa.get("quadgram_spc", "")
        qg_b = sb.get("quadgram_spc", "")
        qg_a_str = f"{qg_a:7.4f}" if isinstance(qg_a, (int, float)) else f"{'N/A':>7s}"
        qg_b_str = f"{qg_b:7.4f}" if isinstance(qg_b, (int, float)) else f"{'N/A':>7s}"

        print(f"{r['mask']:<20s} {r['n_a']:4d} {sa['ic']:7.5f} {z_ic_a:7.2f} "
              f"{sb['ic']:7.5f} {z_ic_b:7.2f} {qg_a_str} {qg_b_str} "
              f"{'***' if flag else '':>5s}")

        r["z_ic_a"] = round(z_ic_a, 3)
        r["z_ic_b"] = round(z_ic_b, 3)
        r["z_chi2_a"] = round(z_chi2_a, 3)
        r["z_chi2_b"] = round(z_chi2_b, 3)
        r["flagged"] = flag

        if flag:
            flagged.append(r)

    elapsed = time.time() - t0
    print(f"\nPhase 3 complete: {elapsed:.1f}s")

    # Null distribution summary
    print(f"\nNull distribution (from {len(rnd_results)} random masks):")
    if null_ic_a:
        print(f"  IC_a: mean={statistics.mean(null_ic_a):.5f} "
              f"std={statistics.stdev(null_ic_a):.5f}")
    if null_ic_b:
        print(f"  IC_b: mean={statistics.mean(null_ic_b):.5f} "
              f"std={statistics.stdev(null_ic_b):.5f}")
    if null_qg_a:
        print(f"  QG_a: mean={statistics.mean(null_qg_a):.4f} "
              f"std={statistics.stdev(null_qg_a):.4f}")

    if flagged:
        print(f"\n*** {len(flagged)} FLAGGED MASKS (both halves z > 2.5): ***")
        for r in flagged:
            print(f"  {r['mask']}: IC_a z={r['z_ic_a']}, IC_b z={r['z_ic_b']}")
    else:
        print("\nNo masks flagged — bifurcation hypothesis not supported by IC/chi2.")

    # Save results
    ensure_results_dir()
    out_path = RESULTS_DIR / "phase3_results.json"
    with open(out_path, "w") as f:
        json.dump({
            "phase": 3,
            "n_deterministic": n_deterministic,
            "n_random": n_random,
            "elapsed_seconds": round(elapsed, 1),
            "n_flagged": len(flagged),
            "null_ic_a_mean": round(statistics.mean(null_ic_a), 5) if null_ic_a else None,
            "null_ic_a_std": round(statistics.stdev(null_ic_a), 5) if null_ic_a else None,
            "null_ic_b_mean": round(statistics.mean(null_ic_b), 5) if null_ic_b else None,
            "null_ic_b_std": round(statistics.stdev(null_ic_b), 5) if null_ic_b else None,
            "deterministic_results": det_results,
            "flagged": flagged,
        }, f, indent=2)
    print(f"  Results: {out_path}")

    return det_results, flagged


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="K4 Reverse Engineering Engine — Plaintext-First Cryptanalysis"
    )
    parser.add_argument("--phase", type=int, choices=[1, 2, 3], default=None,
                        help="Run a specific phase (default: all)")
    parser.add_argument("--workers", type=int, default=8,
                        help="Number of parallel workers (default: 8)")
    parser.add_argument("--batch-size", type=int, default=500,
                        help="Batch size for Phase 1 word batches (default: 500)")
    parser.add_argument("--resume", action="store_true",
                        help="Resume Phase 2 from checkpoint")
    parser.add_argument("--max-words", type=int, default=0,
                        help="Limit dictionary size (for testing, 0=all)")
    args = parser.parse_args()

    print("K4 Reverse Engineering Engine")
    print(f"  CT: {CT[:30]}...{CT[-10:]}")
    print(f"  CT length: {CT_LEN}")
    print(f"  Known positions: {N_CRIBS}/97")
    print(f"  Workers: {args.workers}")
    print(f"  Phase: {args.phase or 'all'}")
    print()

    t_start = time.time()
    results_summary = {}

    if args.phase is None or args.phase == 3:
        det, flagged = run_phase3()
        results_summary["phase3"] = {
            "n_deterministic": len(det),
            "n_flagged": len(flagged),
        }
        print()

    if args.phase is None or args.phase == 1:
        hits1 = run_phase1(workers=args.workers, batch_size=args.batch_size)
        results_summary["phase1"] = {
            "total_hits": len(hits1),
            "top_word": hits1[0]["word"] if hits1 else None,
        }
        print()

    if args.phase is None or args.phase == 2:
        hits2 = run_phase2(workers=args.workers, resume=args.resume,
                           max_words=args.max_words)
        results_summary["phase2"] = {
            "total_hits": len(hits2),
            "top_score": hits2[0]["composite"] if hits2 else 0,
        }
        print()

    total_elapsed = time.time() - t_start
    print("=" * 70)
    print(f"ALL PHASES COMPLETE: {total_elapsed:.1f}s")
    print(f"  Summary: {json.dumps(results_summary, indent=2)}")
    print(f"  Results directory: {RESULTS_DIR}")
    print("=" * 70)

    # Save overall summary
    ensure_results_dir()
    with open(RESULTS_DIR / "summary.json", "w") as f:
        json.dump({
            "total_elapsed_seconds": round(total_elapsed, 1),
            "phases_run": args.phase or "all",
            "workers": args.workers,
            **results_summary,
        }, f, indent=2)


if __name__ == "__main__":
    main()
