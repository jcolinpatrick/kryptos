#!/usr/bin/env python3
"""
Bean-Constrained Keystream Constructor
=======================================
Cipher:   polyalphabetic (Vig / Beau / VarBeau) x (AZ / KA) — running key
Family:   grille
Status:   active
Keyspace: 6 variants x multiple interpolation strategies x hill-climbing
Last run: never
Best score: n/a

HYPOTHESIS: K4 uses a running key (not periodic) for one-to-one substitution
with NO transposition. Bean 2021 provides strong statistical constraints on
the keystream:
  1. k[27] = k[65] (equality)
  2. 21 inequality pairs
  3. Key changes SLOWLY (mean adjacent delta ~3.6)
  4. Width-21 structure (11 repeated vertical bigrams)
  5. Under reversed-KA numbering, 13/24 key values are multiples of 5
  6. Cipher alphabet near-standard (mean 2.1 KA-proximity)

This script:
  1. Computes known key values at 24 crib positions for 6 cipher variants
  2. Analyzes which variants show the most structure (mod-5, low variation, etc.)
  3. Interpolates unknown positions using multiple methods:
     a. Linear interpolation (slow-change assumption)
     b. Mod-5 constrained interpolation
     c. Width-21 mirroring
     d. Fibonacci-like recurrences (bases 2-26)
     e. LFSR sequences through known points
     f. Polynomial interpolation mod 26
  4. For each full keystream: decrypt and score with quadgrams
  5. Hill-climbing with constraint satisfaction for the best variants

Usage:
    PYTHONPATH=src python3 -u scripts/grille/e_bean_keystream_construct.py [--workers N]

Output:
    results/bean_keystream/
"""

from __future__ import annotations

import itertools
import json
import math
import os
import random
import sys
import time
from collections import Counter, defaultdict
from multiprocessing import Pool, cpu_count
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── Kryptos kernel imports ────────────────────────────────────────────────
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, KRYPTOS_ALPHABET, MOD,
    CRIB_WORDS, CRIB_DICT, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)
from kryptos.kernel.constraints.bean import verify_bean_simple
from kryptos.kernel.scoring.ngram import NgramScorer

# ── Parse CLI args ────────────────────────────────────────────────────────
NUM_WORKERS = cpu_count()
for i, arg in enumerate(sys.argv[1:], 1):
    if arg == "--workers" and i < len(sys.argv) - 1:
        NUM_WORKERS = int(sys.argv[i + 1])

# ── Constants ─────────────────────────────────────────────────────────────
AZ = ALPH
KA = KRYPTOS_ALPHABET
CRIBS = CRIB_WORDS

RESULTS_DIR = Path("results/bean_keystream")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# AZ and KA index tables
AZ_IDX = {c: i for i, c in enumerate(AZ)}
KA_IDX = {c: i for i, c in enumerate(KA)}

# Crib positions with their PT characters
CRIB_POSITIONS: Dict[int, str] = dict(CRIB_DICT)

# ── Quadgram scorer ──────────────────────────────────────────────────────
QG_PATH = Path("data/english_quadgrams.json")
_scorer: Optional[NgramScorer] = None

def get_scorer() -> NgramScorer:
    global _scorer
    if _scorer is None:
        _scorer = NgramScorer.from_file(QG_PATH)
    return _scorer


# ══════════════════════════════════════════════════════════════════════════
# PART 1: Compute known key values for all 6 cipher variants
# ══════════════════════════════════════════════════════════════════════════

def compute_key_values(variant: str, alpha_name: str) -> Dict[int, int]:
    """Compute key values at all 24 crib positions for a cipher variant.

    variant: 'vig', 'beau', 'varbeau'
    alpha_name: 'AZ' or 'KA'

    Returns {position: key_value} for positions 21-33 and 63-73.
    """
    alpha = AZ if alpha_name == "AZ" else KA
    idx = AZ_IDX if alpha_name == "AZ" else KA_IDX

    keys = {}
    for pos, pt_char in CRIB_POSITIONS.items():
        ct_char = CT[pos]
        ci = idx[ct_char]
        pi = idx[pt_char]

        if variant == "vig":
            # CT = (PT + K) mod 26  =>  K = (CT - PT) mod 26
            k = (ci - pi) % MOD
        elif variant == "beau":
            # CT = (K - PT) mod 26  =>  K = (CT + PT) mod 26
            k = (ci + pi) % MOD
        elif variant == "varbeau":
            # CT = (PT - K) mod 26  =>  K = (PT - CT) mod 26
            k = (pi - ci) % MOD
        else:
            raise ValueError(f"Unknown variant: {variant}")

        keys[pos] = k

    return keys


def decrypt_with_keystream(keystream: List[int], variant: str, alpha_name: str) -> str:
    """Decrypt CT using a full keystream."""
    alpha = AZ if alpha_name == "AZ" else KA
    idx = AZ_IDX if alpha_name == "AZ" else KA_IDX

    out = []
    for i, ct_char in enumerate(CT):
        ci = idx[ct_char]
        k = keystream[i]

        if variant == "vig":
            pi = (ci - k) % MOD
        elif variant == "beau":
            pi = (k - ci) % MOD
        elif variant == "varbeau":
            pi = (ci + k) % MOD
        else:
            raise ValueError(f"Unknown variant: {variant}")

        out.append(alpha[pi])

    return "".join(out)


def score_plaintext(text: str) -> float:
    """Score plaintext with quadgrams (per-char)."""
    scorer = get_scorer()
    return scorer.score_per_char(text)


# ══════════════════════════════════════════════════════════════════════════
# PART 2: Analyze variant structural properties
# ══════════════════════════════════════════════════════════════════════════

def analyze_variant(variant: str, alpha_name: str) -> dict:
    """Analyze structural properties of a variant's known key values."""
    keys = compute_key_values(variant, alpha_name)
    positions = sorted(keys.keys())
    values = [keys[p] for p in positions]

    # 1. Count mod-5 values
    mod5_count = sum(1 for v in values if v % 5 == 0)

    # 2. Variation (standard deviation)
    mean_val = sum(values) / len(values)
    variance = sum((v - mean_val) ** 2 for v in values) / len(values)
    std_dev = variance ** 0.5

    # 3. Adjacent differences (within each crib block)
    diffs = []
    for i in range(len(positions) - 1):
        if positions[i + 1] == positions[i] + 1:  # Adjacent positions
            diffs.append(abs(values[i + 1] - values[i]))
    mean_diff = sum(diffs) / len(diffs) if diffs else float('inf')

    # 4. Width-21 matches: check k[i] == k[i+21] for pairs in cribs
    w21_matches = 0
    w21_total = 0
    for p in positions:
        if p + 21 in keys:
            w21_total += 1
            if keys[p] == keys[p + 21]:
                w21_matches += 1
        if p - 21 in keys:
            w21_total += 1
            if keys[p] == keys[p - 21]:
                w21_matches += 1
    # Deduplicate
    w21_total //= 2 if w21_total > 0 else 1
    w21_matches //= 2 if w21_matches > 0 else 1

    # 5. Bean constraint satisfaction
    bean_eq_ok = True
    for a, b in BEAN_EQ:
        if a in keys and b in keys:
            if keys[a] != keys[b]:
                bean_eq_ok = False

    bean_ineq_ok = 0
    bean_ineq_total = 0
    for a, b in BEAN_INEQ:
        if a in keys and b in keys:
            bean_ineq_total += 1
            if keys[a] != keys[b]:
                bean_ineq_ok += 1

    # 6. Reversed-KA numbering: check mod-5
    ka_rev = {c: (25 - i) for i, c in enumerate(KA)}
    rev_ka_values = []
    for p in positions:
        ct_char = CT[p]
        pt_char = CRIB_POSITIONS[p]
        # Recompute key in reversed KA index space
        ci_rev = ka_rev[ct_char]
        pi_rev = ka_rev[pt_char]
        if variant == "vig":
            k_rev = (ci_rev - pi_rev) % MOD
        elif variant == "beau":
            k_rev = (ci_rev + pi_rev) % MOD
        elif variant == "varbeau":
            k_rev = (pi_rev - ci_rev) % MOD
        rev_ka_values.append(k_rev)
    mod5_rev_count = sum(1 for v in rev_ka_values if v % 5 == 0)

    # 7. Range of values
    val_range = max(values) - min(values) if values else 0
    unique_vals = len(set(values))

    return {
        "variant": variant,
        "alpha": alpha_name,
        "name": f"{variant}_{alpha_name}",
        "keys": keys,
        "values": values,
        "positions": positions,
        "mod5_count": mod5_count,
        "mod5_frac": mod5_count / len(values),
        "mod5_rev_ka": mod5_rev_count,
        "mod5_rev_ka_frac": mod5_rev_count / len(values),
        "std_dev": std_dev,
        "mean_diff": mean_diff,
        "val_range": val_range,
        "unique_vals": unique_vals,
        "w21_matches": w21_matches,
        "w21_total": w21_total,
        "bean_eq_ok": bean_eq_ok,
        "bean_ineq_ok": bean_ineq_ok,
        "bean_ineq_total": bean_ineq_total,
        "mean_val": mean_val,
    }


# ══════════════════════════════════════════════════════════════════════════
# PART 3: Interpolation Methods
# ══════════════════════════════════════════════════════════════════════════

def linear_interpolate(known: Dict[int, int], length: int) -> List[int]:
    """Linear interpolation between known key values.

    For positions before the first known or after the last known, extrapolate
    using the nearest known value.
    """
    keystream = [0] * length
    positions = sorted(known.keys())

    # Set known values
    for p, v in known.items():
        keystream[p] = v

    # Interpolate between consecutive known positions
    for i in range(len(positions) - 1):
        p1, p2 = positions[i], positions[i + 1]
        v1, v2 = known[p1], known[p2]
        gap = p2 - p1
        for j in range(1, gap):
            # Linear interpolation, round to nearest integer, mod 26
            frac = j / gap
            val = v1 + (v2 - v1) * frac
            keystream[p1 + j] = round(val) % MOD

    # Extrapolate before first known
    first_p = positions[0]
    first_v = known[first_p]
    for p in range(first_p):
        keystream[p] = first_v  # Constant extrapolation

    # Extrapolate after last known
    last_p = positions[-1]
    last_v = known[last_p]
    for p in range(last_p + 1, length):
        keystream[p] = last_v  # Constant extrapolation

    return keystream


def mod5_interpolate(known: Dict[int, int], length: int) -> List[int]:
    """Interpolate forcing values to nearest multiple of 5 (mod 26)."""
    base = linear_interpolate(known, length)
    mod5_vals = [0, 5, 10, 15, 20, 25]

    for i in range(length):
        if i not in known:
            # Snap to nearest mod-5 value
            v = base[i]
            best = min(mod5_vals, key=lambda m: min(abs(v - m), 26 - abs(v - m)))
            base[i] = best

    return base


def width21_interpolate(known: Dict[int, int], length: int) -> List[int]:
    """Use width-21 periodicity: k[i] ≈ k[i+21] or k[i-21]."""
    keystream = linear_interpolate(known, length)

    # Propagate known values with period 21
    extended_known = dict(known)
    for _ in range(5):  # Multiple passes
        new_known = dict(extended_known)
        for p, v in extended_known.items():
            for offset in [21, -21, 42, -42, 63, -63, 84, -84]:
                target = p + offset
                if 0 <= target < length and target not in new_known:
                    new_known[target] = v
        extended_known = new_known

    for p, v in extended_known.items():
        keystream[p] = v

    # Fill remaining with linear interpolation from extended known
    return linear_interpolate(extended_known, length)


def constant_key_streams(known: Dict[int, int], length: int) -> List[List[int]]:
    """Try each of the 26 possible constant keystreams."""
    streams = []
    for k in range(MOD):
        ks = [k] * length
        # Override with known values
        for p, v in known.items():
            ks[p] = v
        streams.append(ks)
    return streams


def fibonacci_keystreams(known: Dict[int, int], length: int) -> List[List[int]]:
    """Generate Fibonacci-like recurrences with various bases.

    k[i] = (a * k[i-1] + b * k[i-2]) mod 26 for different (a, b) pairs.
    Seed from known positions and propagate forward/backward.
    """
    results = []
    positions = sorted(known.keys())

    # For each pair of adjacent known positions, try to find recurrence
    for base_a in range(1, 6):  # a = 1..5
        for base_b in range(1, 6):  # b = 1..5
            # Forward from first two known positions
            if len(positions) >= 2:
                p0, p1 = positions[0], positions[1]
                v0, v1 = known[p0], known[p1]

                ks = [0] * length
                ks[p0] = v0
                ks[p1] = v1

                # Forward fill from p1
                prev2, prev1 = v0, v1
                for i in range(p1 + 1, length):
                    val = (base_a * prev1 + base_b * prev2) % MOD
                    if i in known:
                        val = known[i]
                    ks[i] = val
                    prev2, prev1 = prev1, val

                # Backward fill from p0
                next1, next2 = v0, v1
                for i in range(p0 - 1, -1, -1):
                    # Invert: k[i] from k[i+1] and k[i+2]
                    # k[i+2] = (a * k[i+1] + b * k[i]) mod 26
                    # b * k[i] = (k[i+2] - a * k[i+1]) mod 26
                    # k[i] = (k[i+2] - a * k[i+1]) * b_inv mod 26
                    if math.gcd(base_b, MOD) == 1:
                        b_inv = pow(base_b, -1, MOD)
                        val = (next2 - base_a * next1) * b_inv % MOD
                    else:
                        val = next1  # Fallback
                    if i in known:
                        val = known[i]
                    ks[i] = val
                    next2, next1 = next1, val

                results.append(ks)

    return results


def lfsr_keystreams(known: Dict[int, int], length: int) -> List[List[int]]:
    """Try LFSR-like sequences: k[i] = (c1*k[i-1] + c2*k[i-2] + c3) mod 26.

    Enumerate small coefficient sets and seed from known positions.
    """
    results = []
    positions = sorted(known.keys())
    if len(positions) < 2:
        return results

    # Sample a subset of coefficient triples
    for c1 in range(MOD):
        for c2 in [0, 1, 2, 5, 10, 13, 25]:
            for c3 in [0, 1, 5, 13]:
                p0, p1 = positions[0], positions[1]
                v0, v1 = known[p0], known[p1]

                ks = [0] * length
                ks[p0] = v0
                ks[p1] = v1

                # Forward from p1
                prev2, prev1 = v0, v1
                ok = True
                for i in range(p1 + 1, length):
                    val = (c1 * prev1 + c2 * prev2 + c3) % MOD
                    if i in known:
                        # Check consistency
                        if val != known[i]:
                            ok = False
                            break
                    ks[i] = val
                    prev2, prev1 = prev1, val

                if not ok:
                    continue

                # Backward from p0
                next1, next2 = v0, v1
                for i in range(p0 - 1, -1, -1):
                    if math.gcd(c2 if c2 != 0 else 1, MOD) == 1 and c2 != 0:
                        c2_inv = pow(c2, -1, MOD)
                        val = ((ks[i + 2] if i + 2 < length else 0) - c1 * next1 - c3) * c2_inv % MOD
                    else:
                        val = next1
                    ks[i] = val
                    next2, next1 = next1, val

                # Check all known values match
                all_match = all(ks[p] == known[p] for p in known)
                if all_match:
                    results.append(ks)

                    if len(results) >= 500:
                        return results

    return results


def polynomial_keystreams(known: Dict[int, int], length: int) -> List[List[int]]:
    """Polynomial interpolation mod 26 through subsets of known points.

    For degree d, fit polynomial through d+1 known points, evaluate at all positions.
    Uses Lagrange interpolation mod 26.
    """
    results = []
    positions = sorted(known.keys())
    values = [known[p] for p in positions]

    # Try polynomials of degree 1 through 5
    for degree in range(1, min(6, len(positions))):
        # Take d+1 evenly spaced points from the known set
        n_points = degree + 1
        step = max(1, len(positions) // n_points)
        selected_idx = list(range(0, len(positions), step))[:n_points]
        if len(selected_idx) < n_points:
            continue

        sel_pos = [positions[i] for i in selected_idx]
        sel_val = [values[i] for i in selected_idx]

        # Lagrange interpolation mod 26
        ks = [0] * length
        valid = True

        for x in range(length):
            total = 0
            for j in range(n_points):
                # Lagrange basis polynomial L_j(x)
                num = 1
                den = 1
                for m in range(n_points):
                    if m != j:
                        num = (num * (x - sel_pos[m])) % MOD
                        den = (den * (sel_pos[j] - sel_pos[m])) % MOD

                if den % MOD == 0:
                    valid = False
                    break

                # Modular inverse of denominator
                if math.gcd(den % MOD, MOD) != 1:
                    valid = False
                    break

                den_inv = pow(den % MOD, -1, MOD)
                total = (total + sel_val[j] * num * den_inv) % MOD

            if not valid:
                break
            ks[x] = total % MOD

        if valid:
            # Verify known positions match
            matches = sum(1 for p in known if ks[p] == known[p])
            if matches >= len(known) * 0.8:  # Allow some slack
                results.append(ks)

    return results


# ══════════════════════════════════════════════════════════════════════════
# PART 4: Hill-Climbing with Constraint Satisfaction
# ══════════════════════════════════════════════════════════════════════════

# Global scorer for multiprocessing
_global_scorer = None

def _init_scorer():
    global _global_scorer
    _global_scorer = NgramScorer.from_file(QG_PATH)


def hill_climb_keystream(args) -> Tuple[float, str, str, List[int]]:
    """Hill-climb a keystream, keeping known positions fixed.

    args: (known_keys, variant, alpha_name, seed_keystream, max_iters, bean_weight, slow_weight)
    """
    known, variant, alpha_name, seed, max_iters, bean_weight, slow_weight = args

    global _global_scorer
    if _global_scorer is None:
        _global_scorer = NgramScorer.from_file(QG_PATH)
    scorer = _global_scorer

    alpha = AZ if alpha_name == "AZ" else KA
    idx = AZ_IDX if alpha_name == "AZ" else KA_IDX

    rng = random.Random()

    ks = list(seed)
    # Enforce known positions
    for p, v in known.items():
        ks[p] = v

    # Identify mutable positions
    mutable = [i for i in range(CT_LEN) if i not in known]

    def _decrypt(keystream):
        out = []
        for i, ct_char in enumerate(CT):
            ci = idx[ct_char]
            k = keystream[i]
            if variant == "vig":
                pi = (ci - k) % MOD
            elif variant == "beau":
                pi = (k - ci) % MOD
            elif variant == "varbeau":
                pi = (ci + k) % MOD
            out.append(alpha[pi])
        return "".join(out)

    def _slow_penalty(keystream):
        """Penalize large adjacent jumps."""
        penalty = 0.0
        for i in range(len(keystream) - 1):
            d = abs(keystream[i + 1] - keystream[i])
            d = min(d, MOD - d)  # Circular distance
            if d > 5:
                penalty += (d - 5) * 0.01
        return penalty

    def _w21_bonus(keystream):
        """Reward width-21 repetition."""
        bonus = 0.0
        for i in range(len(keystream) - 21):
            if keystream[i] == keystream[i + 21]:
                bonus += 0.005
        return bonus

    def _evaluate(keystream):
        pt = _decrypt(keystream)
        qg = scorer.score_per_char(pt)
        penalty = slow_weight * _slow_penalty(keystream)
        bonus = _w21_bonus(keystream)
        return qg - penalty + bonus

    best_ks = list(ks)
    best_score = _evaluate(ks)
    best_pt = _decrypt(ks)

    # SA temperature schedule
    temp = 2.0
    cool = 0.99995

    for iteration in range(max_iters):
        # Pick a random mutable position
        pos = rng.choice(mutable)
        old_val = ks[pos]

        # Choose mutation: small delta (80%) or random (20%)
        if rng.random() < 0.8:
            delta = rng.choice([-3, -2, -1, 1, 2, 3])
            new_val = (old_val + delta) % MOD
        else:
            new_val = rng.randint(0, MOD - 1)

        ks[pos] = new_val
        new_score = _evaluate(ks)

        # SA acceptance
        diff = new_score - best_score
        if diff > 0 or rng.random() < math.exp(diff / max(temp, 0.001)):
            if new_score > best_score:
                best_score = new_score
                best_ks = list(ks)
                best_pt = _decrypt(ks)
        else:
            ks[pos] = old_val  # Revert

        temp *= cool

    return best_score, best_pt, f"{variant}_{alpha_name}_hillclimb", best_ks


def hill_climb_constrained(args) -> Tuple[float, str, str, List[int]]:
    """Hill-climb with stricter Bean-inspired constraints.

    - Adjacent values differ by at most 5 (circular)
    - Width-21 values are equal when possible
    - Mod-5 preference for many positions
    """
    known, variant, alpha_name, seed, max_iters = args

    global _global_scorer
    if _global_scorer is None:
        _global_scorer = NgramScorer.from_file(QG_PATH)
    scorer = _global_scorer

    alpha = AZ if alpha_name == "AZ" else KA
    idx = AZ_IDX if alpha_name == "AZ" else KA_IDX

    rng = random.Random()

    ks = list(seed)
    for p, v in known.items():
        ks[p] = v

    mutable = [i for i in range(CT_LEN) if i not in known]

    def _decrypt(keystream):
        out = []
        for i, ct_char in enumerate(CT):
            ci = idx[ct_char]
            k = keystream[i]
            if variant == "vig":
                pi = (ci - k) % MOD
            elif variant == "beau":
                pi = (k - ci) % MOD
            elif variant == "varbeau":
                pi = (ci + k) % MOD
            out.append(alpha[pi])
        return "".join(out)

    def _constraint_score(keystream):
        """Score how well keystream satisfies Bean constraints."""
        score = 0.0

        # Bean equality
        for a, b in BEAN_EQ:
            if keystream[a] == keystream[b]:
                score += 1.0

        # Bean inequalities
        for a, b in BEAN_INEQ:
            if keystream[a] != keystream[b]:
                score += 0.1

        # Slow change
        for i in range(len(keystream) - 1):
            d = abs(keystream[i + 1] - keystream[i])
            d = min(d, MOD - d)
            if d <= 3:
                score += 0.02
            elif d <= 5:
                score += 0.01

        # Width-21 periodicity
        for i in range(len(keystream) - 21):
            if keystream[i] == keystream[i + 21]:
                score += 0.05

        # Mod-5 preference
        for v in keystream:
            if v % 5 == 0:
                score += 0.005

        return score

    def _evaluate(keystream):
        pt = _decrypt(keystream)
        qg = scorer.score_per_char(pt)
        cs = _constraint_score(keystream)
        return qg + 0.3 * cs  # Weight constraint satisfaction

    best_ks = list(ks)
    best_score = _evaluate(ks)
    best_pt = _decrypt(ks)

    temp = 2.0
    cool = 0.99995

    for iteration in range(max_iters):
        pos = rng.choice(mutable)
        old_val = ks[pos]

        # Constrained mutation
        r = rng.random()
        if r < 0.5:
            # Small delta
            delta = rng.choice([-2, -1, 1, 2])
            new_val = (old_val + delta) % MOD
        elif r < 0.7:
            # Copy from width-21 neighbor
            neighbor = pos + 21 if pos + 21 < CT_LEN else pos - 21
            if 0 <= neighbor < CT_LEN:
                new_val = ks[neighbor]
            else:
                new_val = rng.randint(0, MOD - 1)
        elif r < 0.85:
            # Snap to mod-5
            new_val = rng.choice([0, 5, 10, 15, 20, 25])
        else:
            # Random
            new_val = rng.randint(0, MOD - 1)

        ks[pos] = new_val
        new_score = _evaluate(ks)

        diff = new_score - best_score
        if diff > 0 or rng.random() < math.exp(diff / max(temp, 0.001)):
            if new_score > best_score:
                best_score = new_score
                best_ks = list(ks)
                best_pt = _decrypt(ks)
        else:
            ks[pos] = old_val

        temp *= cool

    return best_score, best_pt, f"{variant}_{alpha_name}_constrained_hc", best_ks


# ══════════════════════════════════════════════════════════════════════════
# PART 5: Block-Interpolation Strategy
# ══════════════════════════════════════════════════════════════════════════

def block_interpolation_keystreams(known: Dict[int, int], length: int) -> List[List[int]]:
    """Generate keystreams by interpolating blocks between known regions.

    The known positions are 21-33 and 63-73. This leaves three gaps:
    0-20, 34-62, 74-96. For each gap, try several strategies:
    - Constant (nearest known value)
    - Linear ramp between bounding known values
    - Smooth (repeat pattern from known blocks)
    """
    results = []
    positions = sorted(known.keys())

    # Gap 1: 0-20 (before first crib)
    # Gap 2: 34-62 (between cribs)
    # Gap 3: 74-96 (after second crib)

    gap1_end = min(positions)  # 21
    gap2_start = max(p for p in positions if p <= 33) + 1  # 34
    gap2_end = min(p for p in positions if p >= 63)  # 63
    gap3_start = max(positions) + 1  # 74

    v_left = known[positions[0]]    # k[21]
    v_mid_left = known[positions[12]]  # k[33]
    v_mid_right = known[positions[13]]  # k[63]
    v_right = known[positions[-1]]  # k[73]

    # Strategies for each gap
    gap_strategies = {
        "const_nearest": lambda start, end, v_before, v_after: [v_before if (start + i) < (start + end) // 2 else v_after for i in range(end - start)],
        "const_left": lambda start, end, v_before, v_after: [v_before] * (end - start),
        "const_right": lambda start, end, v_before, v_after: [v_after] * (end - start),
        "linear": lambda start, end, v_before, v_after: [round(v_before + (v_after - v_before) * i / max(end - start - 1, 1)) % MOD for i in range(end - start)],
    }

    # Generate combinations
    for name1, strat1 in gap_strategies.items():
        for name2, strat2 in gap_strategies.items():
            for name3, strat3 in gap_strategies.items():
                ks = [0] * length

                # Fill known
                for p, v in known.items():
                    ks[p] = v

                # Gap 1: 0-20, bounded by ??? on left and k[21] on right
                gap1_vals = strat1(0, gap1_end, v_left, v_left)  # Only right bound available
                for i, v in enumerate(gap1_vals):
                    ks[i] = v % MOD

                # Gap 2: 34-62, bounded by k[33] and k[63]
                gap2_vals = strat2(gap2_start, gap2_end, v_mid_left, v_mid_right)
                for i, v in enumerate(gap2_vals):
                    ks[gap2_start + i] = v % MOD

                # Gap 3: 74-96, bounded by k[73] and ??? on right
                gap3_vals = strat3(gap3_start, length, v_right, v_right)
                for i, v in enumerate(gap3_vals):
                    ks[gap3_start + i] = v % MOD

                results.append(ks)

    return results


# ══════════════════════════════════════════════════════════════════════════
# PART 6: Thematic Running Key Search
# ══════════════════════════════════════════════════════════════════════════

def thematic_running_keys(known: Dict[int, int], variant: str, alpha_name: str,
                          length: int) -> List[Tuple[List[int], str]]:
    """Try running keys derived from thematic keywords repeated/extended.

    Known Kryptos keywords: KRYPTOS, PALIMPSEST, ABSCISSA, etc.
    Also try famous phrases, dictionary entries.
    """
    idx = AZ_IDX if alpha_name == "AZ" else KA_IDX

    keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SANBORN", "SCHEIDT",
        "BERLINCLOCK", "EASTNORTHEAST", "SHADOWFORCES",
        "KRYPTOSABCDEFGHIJLMNQUVWXZ",
        "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHETHENUI",
        "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDX",
        "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATLITTEREDTHE",
        "WHOKNOWSTHEEXACTLOCATIONONLYWW",
        "THETEMPERATUREDROPPEDSUFFICIENTLY",
        "VIRTUALLYINVISIBLE",
        "DIGETAL", "INTERPRETATIU",
        "VERDIGRIS", "OUBLIETTE", "CENOTAPH",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    ]

    results = []
    for kw in keywords:
        # Repeat keyword to fill length
        repeated = (kw * (length // len(kw) + 1))[:length]
        ks = [idx[c] for c in repeated]
        results.append((ks, f"repeated_{kw[:20]}"))

        # Try shifted versions
        for shift in range(min(len(kw), 20)):
            shifted = kw[shift:] + kw[:shift]
            repeated = (shifted * (length // len(shifted) + 1))[:length]
            ks = [idx[c] for c in repeated]
            results.append((ks, f"shifted_{shift}_{kw[:15]}"))

    return results


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

def main():
    t0 = time.time()
    print("=" * 80)
    print("Bean-Constrained Keystream Constructor")
    print("=" * 80)
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"Workers: {NUM_WORKERS}")
    print()

    # ── Step 1: Compute and analyze all 6 variants ────────────────────────
    print("=" * 80)
    print("STEP 1: Analyzing 6 cipher variants at crib positions")
    print("=" * 80)

    variants = ["vig", "beau", "varbeau"]
    alphas = ["AZ", "KA"]

    analyses = []
    for variant in variants:
        for alpha_name in alphas:
            info = analyze_variant(variant, alpha_name)
            analyses.append(info)

            print(f"\n--- {variant.upper()} / {alpha_name} ---")
            print(f"  Key values: {info['values']}")
            print(f"  Mod-5 count: {info['mod5_count']}/{N_CRIBS} ({info['mod5_frac']:.1%})")
            print(f"  Mod-5 (rev-KA): {info['mod5_rev_ka']}/{N_CRIBS} ({info['mod5_rev_ka_frac']:.1%})")
            print(f"  Std dev: {info['std_dev']:.2f}")
            print(f"  Mean adjacent diff: {info['mean_diff']:.2f}")
            print(f"  Value range: {info['val_range']}")
            print(f"  Unique values: {info['unique_vals']}")
            print(f"  Width-21 matches: {info['w21_matches']}/{info['w21_total']}")
            print(f"  Bean EQ: {'OK' if info['bean_eq_ok'] else 'FAIL'}")
            print(f"  Bean INEQ: {info['bean_ineq_ok']}/{info['bean_ineq_total']}")

    # Cross-verify with stored constants
    print("\n\n--- Cross-verification with stored key constants ---")
    vig_az_keys = compute_key_values("vig", "AZ")
    vig_ene_computed = tuple(vig_az_keys[21 + i] for i in range(13))
    vig_bc_computed = tuple(vig_az_keys[63 + i] for i in range(11))
    print(f"  VIG/AZ ENE computed: {vig_ene_computed}")
    print(f"  VIG/AZ ENE stored:   {VIGENERE_KEY_ENE}")
    print(f"  Match: {vig_ene_computed == VIGENERE_KEY_ENE}")
    print(f"  VIG/AZ BC computed:  {vig_bc_computed}")
    print(f"  VIG/AZ BC stored:    {VIGENERE_KEY_BC}")
    print(f"  Match: {vig_bc_computed == VIGENERE_KEY_BC}")

    beau_az_keys = compute_key_values("beau", "AZ")
    beau_ene_computed = tuple(beau_az_keys[21 + i] for i in range(13))
    beau_bc_computed = tuple(beau_az_keys[63 + i] for i in range(11))
    print(f"  BEAU/AZ ENE computed: {beau_ene_computed}")
    print(f"  BEAU/AZ ENE stored:   {BEAUFORT_KEY_ENE}")
    print(f"  Match: {beau_ene_computed == BEAUFORT_KEY_ENE}")
    print(f"  BEAU/AZ BC computed:  {beau_bc_computed}")
    print(f"  BEAU/AZ BC stored:    {BEAUFORT_KEY_BC}")
    print(f"  Match: {beau_bc_computed == BEAUFORT_KEY_BC}")

    # ── Step 2: Rank variants by structural promise ───────────────────────
    print("\n" + "=" * 80)
    print("STEP 2: Ranking variants by structural promise")
    print("=" * 80)

    def variant_score(info):
        """Higher is better."""
        score = 0.0
        # Mod-5 count (Bean's finding: 13/24 are mod-5)
        score += info["mod5_count"] * 2.0
        score += info["mod5_rev_ka"] * 2.0
        # Low variation (slow-change assumption)
        score -= info["std_dev"] * 0.5
        # Low mean diff
        score -= info["mean_diff"] * 1.0
        # Width-21 matches
        score += info["w21_matches"] * 3.0
        # Bean satisfaction
        score += 5.0 if info["bean_eq_ok"] else 0.0
        score += info["bean_ineq_ok"] * 0.5
        return score

    analyses.sort(key=variant_score, reverse=True)

    print("\nRanked variants (most promising first):")
    for rank, info in enumerate(analyses, 1):
        print(f"  {rank}. {info['name']:15s} score={variant_score(info):.2f}  "
              f"mod5={info['mod5_count']}  mod5rev={info['mod5_rev_ka']}  "
              f"std={info['std_dev']:.1f}  diff={info['mean_diff']:.1f}  "
              f"w21={info['w21_matches']}/{info['w21_total']}  "
              f"bean_eq={'OK' if info['bean_eq_ok'] else 'FAIL'}")

    # Use top 4 variants for interpolation + all 6 for hill-climbing
    top_variants = analyses[:4]

    # ── Step 3: Deterministic interpolation methods ───────────────────────
    print("\n" + "=" * 80)
    print("STEP 3: Deterministic interpolation methods")
    print("=" * 80)

    scorer = get_scorer()
    all_results = []  # (score, plaintext, method, variant_name)

    for info in analyses:  # All 6 variants
        known = info["keys"]
        variant = info["variant"]
        alpha_name = info["alpha"]
        name = info["name"]

        print(f"\n--- {name} ---")

        # Method A: Linear interpolation
        ks = linear_interpolate(known, CT_LEN)
        pt = decrypt_with_keystream(ks, variant, alpha_name)
        sc = score_plaintext(pt)
        bean_ok = verify_bean_simple(ks)
        all_results.append((sc, pt, f"linear_{name}", ks))
        print(f"  Linear:     {sc:.4f}  bean={bean_ok}  {pt[:40]}...")

        # Method B: Mod-5 interpolation
        ks = mod5_interpolate(known, CT_LEN)
        pt = decrypt_with_keystream(ks, variant, alpha_name)
        sc = score_plaintext(pt)
        bean_ok = verify_bean_simple(ks)
        all_results.append((sc, pt, f"mod5_{name}", ks))
        print(f"  Mod-5:      {sc:.4f}  bean={bean_ok}  {pt[:40]}...")

        # Method C: Width-21 interpolation
        ks = width21_interpolate(known, CT_LEN)
        pt = decrypt_with_keystream(ks, variant, alpha_name)
        sc = score_plaintext(pt)
        bean_ok = verify_bean_simple(ks)
        all_results.append((sc, pt, f"width21_{name}", ks))
        print(f"  Width-21:   {sc:.4f}  bean={bean_ok}  {pt[:40]}...")

        # Method D: Block interpolation (4^3 = 64 combos per variant)
        block_streams = block_interpolation_keystreams(known, CT_LEN)
        best_block = None
        best_block_sc = -999.0
        for bks in block_streams:
            pt = decrypt_with_keystream(bks, variant, alpha_name)
            sc = score_plaintext(pt)
            if sc > best_block_sc:
                best_block_sc = sc
                best_block = (sc, pt, f"block_{name}", bks)
        if best_block:
            all_results.append(best_block)
            print(f"  Block best: {best_block_sc:.4f}  {best_block[1][:40]}...")

    # ── Step 4: Fibonacci-like recurrences ────────────────────────────────
    print("\n" + "=" * 80)
    print("STEP 4: Fibonacci-like recurrences")
    print("=" * 80)

    for info in top_variants:
        known = info["keys"]
        variant = info["variant"]
        alpha_name = info["alpha"]
        name = info["name"]

        fib_streams = fibonacci_keystreams(known, CT_LEN)
        best_fib_sc = -999.0
        best_fib = None
        for fks in fib_streams:
            pt = decrypt_with_keystream(fks, variant, alpha_name)
            sc = score_plaintext(pt)
            if sc > best_fib_sc:
                best_fib_sc = sc
                best_fib = (sc, pt, f"fibonacci_{name}", fks)

        if best_fib:
            all_results.append(best_fib)
            print(f"  {name}: best={best_fib_sc:.4f}  {best_fib[1][:40]}...")
        else:
            print(f"  {name}: no valid Fibonacci streams found")

    # ── Step 5: LFSR sequences ────────────────────────────────────────────
    print("\n" + "=" * 80)
    print("STEP 5: LFSR sequences (through known points)")
    print("=" * 80)

    for info in top_variants[:2]:  # Only top 2 (LFSR is expensive)
        known = info["keys"]
        variant = info["variant"]
        alpha_name = info["alpha"]
        name = info["name"]

        print(f"  {name}: generating LFSR streams...", end=" ", flush=True)
        lfsr_streams = lfsr_keystreams(known, CT_LEN)
        print(f"found {len(lfsr_streams)} consistent streams")

        best_lfsr_sc = -999.0
        best_lfsr = None
        for lks in lfsr_streams:
            pt = decrypt_with_keystream(lks, variant, alpha_name)
            sc = score_plaintext(pt)
            if sc > best_lfsr_sc:
                best_lfsr_sc = sc
                best_lfsr = (sc, pt, f"lfsr_{name}", lks)

        if best_lfsr:
            all_results.append(best_lfsr)
            print(f"    best={best_lfsr_sc:.4f}  {best_lfsr[1][:40]}...")
        else:
            print(f"    no LFSR streams found")

    # ── Step 6: Polynomial interpolation ──────────────────────────────────
    print("\n" + "=" * 80)
    print("STEP 6: Polynomial interpolation mod 26")
    print("=" * 80)

    for info in top_variants:
        known = info["keys"]
        variant = info["variant"]
        alpha_name = info["alpha"]
        name = info["name"]

        poly_streams = polynomial_keystreams(known, CT_LEN)
        best_poly_sc = -999.0
        best_poly = None
        for pks in poly_streams:
            pt = decrypt_with_keystream(pks, variant, alpha_name)
            sc = score_plaintext(pt)
            if sc > best_poly_sc:
                best_poly_sc = sc
                best_poly = (sc, pt, f"polynomial_{name}", pks)

        if best_poly:
            all_results.append(best_poly)
            print(f"  {name}: best={best_poly_sc:.4f} ({len(poly_streams)} polys)  {best_poly[1][:40]}...")
        else:
            print(f"  {name}: no valid polynomial interpolations")

    # ── Step 7: Thematic running keys ─────────────────────────────────────
    print("\n" + "=" * 80)
    print("STEP 7: Thematic running keys")
    print("=" * 80)

    for info in analyses:
        known = info["keys"]
        variant = info["variant"]
        alpha_name = info["alpha"]
        name = info["name"]

        theme_streams = thematic_running_keys(known, variant, alpha_name, CT_LEN)
        best_theme_sc = -999.0
        best_theme = None
        for tks, tname in theme_streams:
            pt = decrypt_with_keystream(tks, variant, alpha_name)
            sc = score_plaintext(pt)
            if sc > best_theme_sc:
                best_theme_sc = sc
                best_theme = (sc, pt, f"theme_{tname}_{name}", tks)

        if best_theme:
            all_results.append(best_theme)
            print(f"  {name}: best={best_theme_sc:.4f}  {best_theme[1][:40]}...")

    # ── Step 8: Hill-climbing with multiprocessing ────────────────────────
    print("\n" + "=" * 80)
    print("STEP 8: Hill-climbing (simulated annealing)")
    print("=" * 80)

    # Generate diverse seeds for hill climbing
    hc_args = []
    HC_ITERS = 500_000

    for info in analyses:
        known = info["keys"]
        variant = info["variant"]
        alpha_name = info["alpha"]

        # Seed 1: Linear interpolation
        seed_lin = linear_interpolate(known, CT_LEN)
        hc_args.append((known, variant, alpha_name, seed_lin, HC_ITERS, 0.5, 0.3))

        # Seed 2: Mod-5 interpolation
        seed_mod5 = mod5_interpolate(known, CT_LEN)
        hc_args.append((known, variant, alpha_name, seed_mod5, HC_ITERS, 0.5, 0.3))

        # Seed 3: Width-21 interpolation
        seed_w21 = width21_interpolate(known, CT_LEN)
        hc_args.append((known, variant, alpha_name, seed_w21, HC_ITERS, 0.5, 0.3))

        # Seed 4: Random seed with known values
        rng = random.Random(42)
        seed_rand = [rng.randint(0, MOD - 1) for _ in range(CT_LEN)]
        for p, v in known.items():
            seed_rand[p] = v
        hc_args.append((known, variant, alpha_name, seed_rand, HC_ITERS, 0.5, 0.3))

        # Seed 5: Constant-0 with known values
        seed_zero = [0] * CT_LEN
        for p, v in known.items():
            seed_zero[p] = v
        hc_args.append((known, variant, alpha_name, seed_zero, HC_ITERS, 0.5, 0.3))

    # Constrained hill-climbing for top variants
    CHC_ITERS = 800_000
    for info in top_variants:
        known = info["keys"]
        variant = info["variant"]
        alpha_name = info["alpha"]

        for seed_fn in [linear_interpolate, mod5_interpolate, width21_interpolate]:
            seed = seed_fn(known, CT_LEN)
            hc_args.append((known, variant, alpha_name, seed, CHC_ITERS))  # 5 args = constrained

    print(f"  Launching {len(hc_args)} hill-climb jobs on {NUM_WORKERS} workers...")
    print(f"  ({sum(a[4] for a in hc_args):,} total iterations)")

    hc_results = []
    with Pool(NUM_WORKERS, initializer=_init_scorer) as pool:
        # Separate constrained and unconstrained by arg count
        unconstrained = [(i, a) for i, a in enumerate(hc_args) if len(a) == 7]
        constrained = [(i, a) for i, a in enumerate(hc_args) if len(a) == 5]

        futures = {}
        for i, a in unconstrained:
            futures[i] = pool.apply_async(hill_climb_keystream, (a,))
        for i, a in constrained:
            futures[i] = pool.apply_async(hill_climb_constrained, (a,))

        for i in sorted(futures.keys()):
            try:
                result = futures[i].get(timeout=600)
                hc_results.append(result)
                sc, pt, method, ks = result
                bean_ok = verify_bean_simple(ks)
                if sc > -6.5:
                    print(f"    [{i:3d}] {method:35s} score={sc:.4f} bean={bean_ok} {pt[:35]}...")
            except Exception as e:
                print(f"    [{i:3d}] ERROR: {e}")

    all_results.extend(hc_results)

    # ── Step 9: Sort and report ───────────────────────────────────────────
    print("\n" + "=" * 80)
    print("RESULTS SUMMARY")
    print("=" * 80)

    all_results.sort(key=lambda x: x[0], reverse=True)

    # Top 50
    print(f"\nTotal candidates evaluated: {len(all_results)}")
    print(f"\nTop 50 results:")
    print(f"{'Rank':>4}  {'Score':>8}  {'Bean':>5}  {'Method':40s}  {'Plaintext'}")
    print("-" * 120)

    for rank, (sc, pt, method, ks) in enumerate(all_results[:50], 1):
        bean_ok = verify_bean_simple(ks)
        print(f"{rank:4d}  {sc:8.4f}  {'PASS' if bean_ok else 'fail':>5}  {method:40s}  {pt[:50]}")

    # ── Step 10: Save results ─────────────────────────────────────────────
    output_file = RESULTS_DIR / "results.json"
    output_data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "ct": CT,
        "num_candidates": len(all_results),
        "top_results": [],
        "variant_analysis": [],
    }

    for sc, pt, method, ks in all_results[:200]:
        bean_ok = verify_bean_simple(ks)
        output_data["top_results"].append({
            "score": round(sc, 6),
            "plaintext": pt,
            "method": method,
            "keystream": ks,
            "bean_pass": bean_ok,
        })

    for info in analyses:
        output_data["variant_analysis"].append({
            "name": info["name"],
            "mod5_count": info["mod5_count"],
            "mod5_rev_ka": info["mod5_rev_ka"],
            "std_dev": round(info["std_dev"], 4),
            "mean_diff": round(info["mean_diff"], 4),
            "w21_matches": info["w21_matches"],
            "w21_total": info["w21_total"],
            "bean_eq_ok": info["bean_eq_ok"],
            "bean_ineq_ok": info["bean_ineq_ok"],
            "key_values": info["values"],
        })

    with open(output_file, "w") as f:
        json.dump(output_data, f, indent=2)
    print(f"\nResults saved to {output_file}")

    # Save top plaintext candidates
    top_file = RESULTS_DIR / "top_candidates.txt"
    with open(top_file, "w") as f:
        f.write("Bean-Constrained Keystream Constructor — Top Candidates\n")
        f.write("=" * 80 + "\n\n")
        for rank, (sc, pt, method, ks) in enumerate(all_results[:100], 1):
            bean_ok = verify_bean_simple(ks)
            f.write(f"#{rank:3d}  score={sc:.4f}  bean={'PASS' if bean_ok else 'fail'}\n")
            f.write(f"  method: {method}\n")
            f.write(f"  PT: {pt}\n")
            f.write(f"  KS: {ks}\n\n")
    print(f"Top candidates saved to {top_file}")

    # Check for breakthroughs
    breakthroughs = [(sc, pt, method, ks) for sc, pt, method, ks in all_results
                     if sc > -4.5 and verify_bean_simple(ks)]
    if breakthroughs:
        print(f"\n*** {len(breakthroughs)} POTENTIAL BREAKTHROUGH(S) ***")
        for sc, pt, method, ks in breakthroughs:
            print(f"  score={sc:.4f} method={method}")
            print(f"  PT: {pt}")
            print(f"  KS: {ks}")

    elapsed = time.time() - t0
    print(f"\nTotal time: {elapsed:.1f}s")
    print("Done.")


if __name__ == "__main__":
    main()
