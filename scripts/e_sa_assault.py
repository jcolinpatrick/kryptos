#!/usr/bin/env python3
"""Simulated Annealing solver for K4: joint transposition + substitution.

KEY INSIGHT: With a free 97-element key + free permutation, achieving 24/24
crib matches is trivial (just set key values at crib-mapped positions). The
real challenge is finding a configuration where the ENTIRE plaintext reads
as coherent English while satisfying cribs + Bean.

Strategy:
  - Phase 1 "Quadgram SA": Optimize permutation + key purely for English
    quality (quadgram score), ignoring cribs initially. This finds the best
    English-like rearrangement of the ciphertext.
  - Phase 2 "Crib-locking SA": Starting from a high-quadgram state, gradually
    increase the weight on crib matching while maintaining English quality.
  - Both phases check Bean constraints throughout.

Model:
  CT[i] = (PT[sigma[i]] + K[i]) mod 26
  PT[j] = (CT[sigma_inv[j]] - K[sigma_inv[j]]) mod 26

Uses numpy for speed, multiprocessing for parallelism across restarts.
"""

import json
import math
import os
import sys
import time
import multiprocessing as mp
from pathlib import Path
from typing import Tuple, Optional

import numpy as np

# ── Import K4 constants ──────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, N_CRIBS,
    BEAN_EQ, BEAN_INEQ, ALPH_IDX,
)

# ── Global constants ─────────────────────────────────────────────────────────
N = CT_LEN  # 97
CT_INT = np.array([ALPH_IDX[c] for c in CT], dtype=np.int8)

# Crib arrays for fast matching
CRIB_POS = np.array(sorted(CRIB_DICT.keys()), dtype=np.int32)
CRIB_VAL = np.array([ALPH_IDX[CRIB_DICT[p]] for p in sorted(CRIB_DICT.keys())], dtype=np.int8)

# Bean constraints as arrays
BEAN_EQ_A = np.array([a for a, b in BEAN_EQ], dtype=np.int32)
BEAN_EQ_B = np.array([b for a, b in BEAN_EQ], dtype=np.int32)
BEAN_INEQ_A = np.array([a for a, b in BEAN_INEQ], dtype=np.int32)
BEAN_INEQ_B = np.array([b for a, b in BEAN_INEQ], dtype=np.int32)

# ── Quadgram scoring ─────────────────────────────────────────────────────────
QUADGRAM_LUT = None


def load_quadgrams():
    """Load quadgrams into a 26^4 numpy lookup table."""
    global QUADGRAM_LUT
    qpath = os.path.join(os.path.dirname(__file__), '..', 'data', 'english_quadgrams.json')
    with open(qpath, 'r') as f:
        qdata = json.load(f)
    floor_val = min(qdata.values()) - 1.0
    QUADGRAM_LUT = np.full(26 ** 4, floor_val, dtype=np.float32)
    for qgram, logp in qdata.items():
        if len(qgram) == 4 and qgram.isalpha():
            idx = (ALPH_IDX[qgram[0]] * 17576 +
                   ALPH_IDX[qgram[1]] * 676 +
                   ALPH_IDX[qgram[2]] * 26 +
                   ALPH_IDX[qgram[3]])
            QUADGRAM_LUT[idx] = logp


def quadgram_score_fast(pt_int: np.ndarray) -> float:
    """Vectorized quadgram scoring."""
    p = pt_int.astype(np.int32)
    indices = p[:-3] * 17576 + p[1:-2] * 676 + p[2:-1] * 26 + p[3:]
    return float(np.sum(QUADGRAM_LUT[indices]))


# ── Dictionary words ─────────────────────────────────────────────────────────
LONG_WORDS = None


def load_dictionary():
    """Load 7+ char English words."""
    global LONG_WORDS
    wpath = os.path.join(os.path.dirname(__file__), '..', 'wordlists', 'english.txt')
    LONG_WORDS = set()
    with open(wpath, 'r') as f:
        for line in f:
            w = line.strip().upper()
            if len(w) >= 7:
                LONG_WORDS.add(w)


def count_dict_words(pt_str: str) -> int:
    """Count distinct 7+ char dictionary words found in plaintext."""
    found = set()
    for wlen in range(7, min(20, len(pt_str) + 1)):
        for i in range(len(pt_str) - wlen + 1):
            sub = pt_str[i:i + wlen]
            if sub in LONG_WORDS:
                found.add(sub)
    return len(found)


# ── IC calculation ───────────────────────────────────────────────────────────
def calc_ic(pt_int: np.ndarray) -> float:
    n = len(pt_int)
    if n < 2:
        return 0.0
    counts = np.bincount(pt_int, minlength=26)
    return float(np.sum(counts * (counts - 1))) / (n * (n - 1))


# ── Core decrypt ─────────────────────────────────────────────────────────────
def decrypt(sigma_inv: np.ndarray, key: np.ndarray) -> np.ndarray:
    """PT[j] = (CT[sigma_inv[j]] - K[sigma_inv[j]]) mod 26."""
    ct_reordered = CT_INT[sigma_inv]
    k_reordered = key[sigma_inv]
    return (ct_reordered - k_reordered) % 26


def crib_score(pt_int: np.ndarray) -> int:
    return int(np.sum(pt_int[CRIB_POS] == CRIB_VAL))


def bean_check(key: np.ndarray) -> Tuple[bool, int]:
    eq_ok = bool(np.all(key[BEAN_EQ_A] == key[BEAN_EQ_B]))
    ineq_violations = int(np.sum(key[BEAN_INEQ_A] == key[BEAN_INEQ_B]))
    return eq_ok and (ineq_violations == 0), (0 if eq_ok else 1) + ineq_violations


# ── Incremental quadgram update ──────────────────────────────────────────────
def quadgram_delta_swap(pt_int: np.ndarray, i: int, j: int) -> float:
    """Compute the change in quadgram score from swapping PT positions i and j.

    Only quadgrams overlapping positions i or j are affected.
    Returns delta = new_score - old_score (approximately).
    """
    n = len(pt_int)
    # Affected quadgram start positions: max(0, pos-3) .. pos for each of i, j
    affected = set()
    for pos in (i, j):
        for s in range(max(0, pos - 3), min(n - 3, pos + 1)):
            affected.add(s)

    # Old contribution
    old_sum = 0.0
    for s in affected:
        idx = (int(pt_int[s]) * 17576 + int(pt_int[s+1]) * 676 +
               int(pt_int[s+2]) * 26 + int(pt_int[s+3]))
        old_sum += QUADGRAM_LUT[idx]

    # Swap
    pt_int[i], pt_int[j] = pt_int[j], pt_int[i]

    # New contribution
    new_sum = 0.0
    for s in affected:
        idx = (int(pt_int[s]) * 17576 + int(pt_int[s+1]) * 676 +
               int(pt_int[s+2]) * 26 + int(pt_int[s+3]))
        new_sum += QUADGRAM_LUT[idx]

    # Swap back
    pt_int[i], pt_int[j] = pt_int[j], pt_int[i]

    return new_sum - old_sum


# ── SA Worker: Phase 1 (English quality) then Phase 2 (crib locking) ────────
def sa_worker_phased(args) -> dict:
    """Run a phased SA restart."""
    restart_id, seed, n_iters_p1, n_iters_p2, t_start, t_end, verbose = args

    if QUADGRAM_LUT is None:
        load_quadgrams()
    if LONG_WORDS is None:
        load_dictionary()

    rng = np.random.RandomState(seed)

    # ── Initialize: random permutation + random key ──────────────────────
    sigma_inv = rng.permutation(N).astype(np.int32)
    key = rng.randint(0, 26, size=N, dtype=np.int8)

    # Force Bean equality from start
    key[27] = key[65]

    pt_int = decrypt(sigma_inv, key)
    qg = quadgram_score_fast(pt_int)
    cs = crib_score(pt_int)
    bean_ok, bean_viol = bean_check(key)
    ic_val = calc_ic(pt_int)

    # ── PHASE 1: Optimize for English quality ────────────────────────────
    # Objective: quadgram score + mild Bean bonus
    best_qg = qg
    best_sigma_inv = sigma_inv.copy()
    best_key = key.copy()
    best_pt = pt_int.copy()
    best_cs = cs
    best_bean_ok = bean_ok
    best_ic = ic_val

    current_qg = qg
    cooling_p1 = (t_end / t_start) ** (1.0 / n_iters_p1) if n_iters_p1 > 0 else 1.0
    temp = t_start
    accepted_p1 = 0

    breakthrough_reported = False

    for it in range(n_iters_p1):
        r = rng.random()

        if r < 0.50:
            # Swap two positions in sigma_inv (transposition change)
            i, j = rng.randint(0, N, size=2)
            while i == j:
                j = rng.randint(0, N)

            # Compute new PT after swap
            sigma_inv[i], sigma_inv[j] = sigma_inv[j], sigma_inv[i]
            new_pt = decrypt(sigma_inv, key)
            new_qg = quadgram_score_fast(new_pt)

            delta = new_qg - current_qg
            if delta > 0 or rng.random() < math.exp(delta / max(temp, 1e-10)):
                pt_int = new_pt
                current_qg = new_qg
                accepted_p1 += 1
                if new_qg > best_qg:
                    best_qg = new_qg
                    best_sigma_inv = sigma_inv.copy()
                    best_key = key.copy()
                    best_pt = new_pt.copy()
                    best_cs = crib_score(new_pt)
                    best_bean_ok, _ = bean_check(key)
                    best_ic = calc_ic(new_pt)
            else:
                sigma_inv[i], sigma_inv[j] = sigma_inv[j], sigma_inv[i]

        elif r < 0.80:
            # Change one key value (substitution change)
            pos = rng.randint(0, N)
            old_val = int(key[pos])
            new_val = rng.randint(0, 26)
            while new_val == old_val:
                new_val = rng.randint(0, 26)

            key[pos] = new_val
            # Maintain Bean equality: if we changed pos 27 or 65, sync the other
            if pos == 27:
                key[65] = new_val
            elif pos == 65:
                key[27] = new_val

            new_pt = decrypt(sigma_inv, key)
            new_qg = quadgram_score_fast(new_pt)

            delta = new_qg - current_qg
            if delta > 0 or rng.random() < math.exp(delta / max(temp, 1e-10)):
                pt_int = new_pt
                current_qg = new_qg
                accepted_p1 += 1
                if new_qg > best_qg:
                    best_qg = new_qg
                    best_sigma_inv = sigma_inv.copy()
                    best_key = key.copy()
                    best_pt = new_pt.copy()
                    best_cs = crib_score(new_pt)
                    best_bean_ok, _ = bean_check(key)
                    best_ic = calc_ic(new_pt)
            else:
                key[pos] = old_val
                if pos == 27:
                    key[65] = old_val
                elif pos == 65:
                    key[27] = old_val

        else:
            # Reverse a segment of sigma_inv
            i = rng.randint(0, N - 1)
            seg_len = rng.randint(2, min(15, N - i + 1))
            j = i + seg_len
            sigma_inv[i:j] = sigma_inv[i:j][::-1]
            new_pt = decrypt(sigma_inv, key)
            new_qg = quadgram_score_fast(new_pt)

            delta = new_qg - current_qg
            if delta > 0 or rng.random() < math.exp(delta / max(temp, 1e-10)):
                pt_int = new_pt
                current_qg = new_qg
                accepted_p1 += 1
                if new_qg > best_qg:
                    best_qg = new_qg
                    best_sigma_inv = sigma_inv.copy()
                    best_key = key.copy()
                    best_pt = new_pt.copy()
                    best_cs = crib_score(new_pt)
                    best_bean_ok, _ = bean_check(key)
                    best_ic = calc_ic(new_pt)
            else:
                sigma_inv[i:j] = sigma_inv[i:j][::-1]

        temp *= cooling_p1

        if verbose and (it + 1) % 100000 == 0:
            pt_str_preview = ''.join(chr(c + 65) for c in best_pt[:50])
            print(f"  P1 R{restart_id:04d} it={it+1:>7d} T={temp:.4f} "
                  f"qg/c={best_qg/N:.3f} crib={best_cs}/24 "
                  f"bean={'Y' if best_bean_ok else 'N'} ic={best_ic:.4f} "
                  f"acc={accepted_p1/(it+1):.1%} PT={pt_str_preview}...",
                  flush=True)

    # ── PHASE 2: Lock in cribs while preserving quality ──────────────────
    # Restore best from phase 1
    sigma_inv = best_sigma_inv.copy()
    key = best_key.copy()
    pt_int = best_pt.copy()
    current_qg = best_qg

    # Phase 2 objective: weighted combination of quadgram + crib
    # Start with low crib weight, ramp up
    cooling_p2 = (0.01 / 2.0) ** (1.0 / max(n_iters_p2, 1))
    temp = 2.0
    accepted_p2 = 0

    p2_best_obj = -1e9
    p2_best_pt = pt_int.copy()
    p2_best_sigma = sigma_inv.copy()
    p2_best_key = key.copy()
    p2_best_cs = crib_score(pt_int)
    p2_best_qg = current_qg
    p2_best_bean = bean_ok
    p2_best_ic = calc_ic(pt_int)

    def p2_objective(qg_val, cs_val, bean_ok_val, crib_weight):
        """Phase 2 composite objective."""
        return (qg_val / N +  # quadgram per char (around -4 to -3)
                cs_val * crib_weight +  # crib bonus (ramps up)
                (0.5 if bean_ok_val else 0.0))

    for it in range(n_iters_p2):
        # Ramp crib weight from 0.1 to 5.0 over the phase
        progress = it / max(n_iters_p2 - 1, 1)
        crib_weight = 0.1 + 4.9 * progress

        current_cs = crib_score(pt_int)
        current_bean, _ = bean_check(key)
        current_obj = p2_objective(current_qg, current_cs, current_bean, crib_weight)

        r = rng.random()

        if r < 0.50:
            i, j = rng.randint(0, N, size=2)
            while i == j:
                j = rng.randint(0, N)
            sigma_inv[i], sigma_inv[j] = sigma_inv[j], sigma_inv[i]
            new_pt = decrypt(sigma_inv, key)
            new_qg = quadgram_score_fast(new_pt)
            new_cs = crib_score(new_pt)
            new_bean, _ = bean_check(key)
            new_obj = p2_objective(new_qg, new_cs, new_bean, crib_weight)

            delta = new_obj - current_obj
            if delta > 0 or rng.random() < math.exp(delta / max(temp, 1e-10)):
                pt_int = new_pt
                current_qg = new_qg
                accepted_p2 += 1
                if new_obj > p2_best_obj:
                    p2_best_obj = new_obj
                    p2_best_pt = new_pt.copy()
                    p2_best_sigma = sigma_inv.copy()
                    p2_best_key = key.copy()
                    p2_best_cs = new_cs
                    p2_best_qg = new_qg
                    p2_best_bean = new_bean
                    p2_best_ic = calc_ic(new_pt)
            else:
                sigma_inv[i], sigma_inv[j] = sigma_inv[j], sigma_inv[i]

        elif r < 0.80:
            pos = rng.randint(0, N)
            old_val = int(key[pos])
            new_val = rng.randint(0, 26)
            while new_val == old_val:
                new_val = rng.randint(0, 26)
            key[pos] = new_val
            if pos == 27:
                key[65] = new_val
            elif pos == 65:
                key[27] = new_val

            new_pt = decrypt(sigma_inv, key)
            new_qg = quadgram_score_fast(new_pt)
            new_cs = crib_score(new_pt)
            new_bean, _ = bean_check(key)
            new_obj = p2_objective(new_qg, new_cs, new_bean, crib_weight)

            delta = new_obj - current_obj
            if delta > 0 or rng.random() < math.exp(delta / max(temp, 1e-10)):
                pt_int = new_pt
                current_qg = new_qg
                accepted_p2 += 1
                if new_obj > p2_best_obj:
                    p2_best_obj = new_obj
                    p2_best_pt = new_pt.copy()
                    p2_best_sigma = sigma_inv.copy()
                    p2_best_key = key.copy()
                    p2_best_cs = new_cs
                    p2_best_qg = new_qg
                    p2_best_bean = new_bean
                    p2_best_ic = calc_ic(new_pt)
            else:
                key[pos] = old_val
                if pos == 27:
                    key[65] = old_val
                elif pos == 65:
                    key[27] = old_val

        else:
            i = rng.randint(0, N - 1)
            seg_len = rng.randint(2, min(15, N - i + 1))
            j = i + seg_len
            sigma_inv[i:j] = sigma_inv[i:j][::-1]
            new_pt = decrypt(sigma_inv, key)
            new_qg = quadgram_score_fast(new_pt)
            new_cs = crib_score(new_pt)
            new_bean, _ = bean_check(key)
            new_obj = p2_objective(new_qg, new_cs, new_bean, crib_weight)

            delta = new_obj - current_obj
            if delta > 0 or rng.random() < math.exp(delta / max(temp, 1e-10)):
                pt_int = new_pt
                current_qg = new_qg
                accepted_p2 += 1
                if new_obj > p2_best_obj:
                    p2_best_obj = new_obj
                    p2_best_pt = new_pt.copy()
                    p2_best_sigma = sigma_inv.copy()
                    p2_best_key = key.copy()
                    p2_best_cs = new_cs
                    p2_best_qg = new_qg
                    p2_best_bean = new_bean
                    p2_best_ic = calc_ic(new_pt)
            else:
                sigma_inv[i:j] = sigma_inv[i:j][::-1]

        temp *= cooling_p2

        # Breakthrough detection (only report once)
        # TRUE English scores ~-3.3/char; SA gibberish ~-4.2 to -4.8.
        # Use -3.8 as a REAL breakthrough threshold.
        if (not breakthrough_reported and p2_best_cs == 24 and p2_best_bean
                and p2_best_qg / N > -3.8):
            breakthrough_reported = True
            pt_str = ''.join(chr(c + 65) for c in p2_best_pt)
            print(f"\n{'='*80}", flush=True)
            print(f"!!! REAL BREAKTHROUGH R{restart_id} iter P2:{it} !!!", flush=True)
            print(f"PT: {pt_str}", flush=True)
            print(f"crib={p2_best_cs}/24 bean=PASS qg/c={p2_best_qg/N:.3f} "
                  f"ic={p2_best_ic:.4f}", flush=True)
            print(f"{'='*80}\n", flush=True)

        if verbose and (it + 1) % 100000 == 0:
            pt_str_preview = ''.join(chr(c + 65) for c in p2_best_pt[:50])
            print(f"  P2 R{restart_id:04d} it={it+1:>7d} T={temp:.4f} cw={crib_weight:.1f} "
                  f"qg/c={p2_best_qg/N:.3f} crib={p2_best_cs}/24 "
                  f"bean={'Y' if p2_best_bean else 'N'} ic={p2_best_ic:.4f} "
                  f"acc={accepted_p2/(it+1):.1%} PT={pt_str_preview}...",
                  flush=True)

    # ── Final evaluation ─────────────────────────────────────────────────
    # Pick the overall best: compare P1 (pure English) vs P2 (crib-locked)
    # Use P2 result as primary
    final_pt = p2_best_pt
    final_sigma = p2_best_sigma
    final_key = p2_best_key
    final_cs = p2_best_cs
    final_qg = p2_best_qg
    final_bean = p2_best_bean
    final_ic = p2_best_ic

    pt_str = ''.join(chr(c + 65) for c in final_pt)
    dw = count_dict_words(pt_str)

    # Also save P1 best for reference
    p1_pt_str = ''.join(chr(c + 65) for c in best_pt)
    p1_dw = count_dict_words(p1_pt_str)

    return {
        'restart_id': restart_id,
        # Phase 2 (primary) result
        'plaintext': pt_str,
        'crib': final_cs,
        'bean_ok': bool(final_bean),
        'qg_per_char': final_qg / N,
        'ic': final_ic,
        'dict_words': dw,
        'sigma_inv': final_sigma.tolist(),
        'key': final_key.tolist(),
        # Phase 1 (English-only) result
        'p1_plaintext': p1_pt_str,
        'p1_qg_per_char': best_qg / N,
        'p1_crib': best_cs,
        'p1_bean_ok': bool(best_bean_ok),
        'p1_ic': best_ic,
        'p1_dict_words': p1_dw,
        # Stats
        'accepted_p1': accepted_p1,
        'accepted_p2': accepted_p2,
        'iters_p1': n_iters_p1,
        'iters_p2': n_iters_p2,
    }


# ── SA Worker: Pure transposition (identity key) ────────────────────────────
def sa_worker_pure_transposition(args) -> dict:
    """SA optimizing only the permutation, with key derived to satisfy cribs.

    Here we try a different decomposition:
    - Fix key = 0 everywhere (pure transposition)
    - Optimize sigma to maximize quadgram score
    - This searches for: is there a permutation of CT that reads as English?
    """
    restart_id, seed, n_iters, t_start, t_end, verbose = args

    if QUADGRAM_LUT is None:
        load_quadgrams()
    if LONG_WORDS is None:
        load_dictionary()

    rng = np.random.RandomState(seed)

    # Pure transposition: PT[j] = CT[sigma_inv[j]]
    sigma_inv = rng.permutation(N).astype(np.int32)
    pt_int = CT_INT[sigma_inv].copy()
    qg = quadgram_score_fast(pt_int)

    best_qg = qg
    best_sigma = sigma_inv.copy()
    best_pt = pt_int.copy()

    cooling = (t_end / t_start) ** (1.0 / n_iters)
    temp = t_start
    accepted = 0

    for it in range(n_iters):
        r = rng.random()

        if r < 0.70:
            # Swap two positions
            i, j = rng.randint(0, N, size=2)
            while i == j:
                j = rng.randint(0, N)

            # Incremental update
            delta = quadgram_delta_swap(pt_int, i, j)

            if delta > 0 or rng.random() < math.exp(delta / max(temp, 1e-10)):
                pt_int[i], pt_int[j] = pt_int[j], pt_int[i]
                sigma_inv[i], sigma_inv[j] = sigma_inv[j], sigma_inv[i]
                qg += delta
                accepted += 1
                if qg > best_qg:
                    best_qg = qg
                    best_sigma = sigma_inv.copy()
                    best_pt = pt_int.copy()
            # else: no change needed (we didn't modify pt_int in quadgram_delta_swap)

        else:
            # Reverse segment
            i = rng.randint(0, N - 1)
            seg_len = rng.randint(2, min(15, N - i + 1))
            j = i + seg_len

            pt_int[i:j] = pt_int[i:j][::-1]
            sigma_inv[i:j] = sigma_inv[i:j][::-1]
            new_qg = quadgram_score_fast(pt_int)

            delta = new_qg - qg
            if delta > 0 or rng.random() < math.exp(delta / max(temp, 1e-10)):
                qg = new_qg
                accepted += 1
                if qg > best_qg:
                    best_qg = qg
                    best_sigma = sigma_inv.copy()
                    best_pt = pt_int.copy()
            else:
                pt_int[i:j] = pt_int[i:j][::-1]
                sigma_inv[i:j] = sigma_inv[i:j][::-1]

        temp *= cooling

        if verbose and (it + 1) % 100000 == 0:
            cs = crib_score(best_pt)
            ic_val = calc_ic(best_pt)
            pt_str_preview = ''.join(chr(c + 65) for c in best_pt[:50])
            print(f"  PT R{restart_id:04d} it={it+1:>7d} T={temp:.4f} "
                  f"qg/c={best_qg/N:.3f} crib={cs}/24 ic={ic_val:.4f} "
                  f"acc={accepted/(it+1):.1%} PT={pt_str_preview}...",
                  flush=True)

    # Final eval
    pt_str = ''.join(chr(c + 65) for c in best_pt)
    cs = crib_score(best_pt)
    ic_val = calc_ic(best_pt)
    dw = count_dict_words(pt_str)

    return {
        'restart_id': restart_id,
        'mode': 'pure_transposition',
        'plaintext': pt_str,
        'crib': cs,
        'bean_ok': False,  # No key to check
        'qg_per_char': best_qg / N,
        'ic': ic_val,
        'dict_words': dw,
        'sigma_inv': best_sigma.tolist(),
        'key': [0] * N,
        'accepted': accepted,
        'iters': n_iters,
    }


# ── Incremental quadgram for pure transposition ─────────────────────────────
def quadgram_delta_swap(pt_int: np.ndarray, i: int, j: int) -> float:
    """Compute change in quadgram score from swapping PT[i] and PT[j]."""
    n = len(pt_int)
    affected = set()
    for pos in (i, j):
        for s in range(max(0, pos - 3), min(n - 3, pos + 1)):
            affected.add(s)

    old_sum = 0.0
    for s in affected:
        idx = (int(pt_int[s]) * 17576 + int(pt_int[s+1]) * 676 +
               int(pt_int[s+2]) * 26 + int(pt_int[s+3]))
        old_sum += QUADGRAM_LUT[idx]

    pt_int[i], pt_int[j] = pt_int[j], pt_int[i]
    new_sum = 0.0
    for s in affected:
        idx = (int(pt_int[s]) * 17576 + int(pt_int[s+1]) * 676 +
               int(pt_int[s+2]) * 26 + int(pt_int[s+3]))
        new_sum += QUADGRAM_LUT[idx]
    pt_int[i], pt_int[j] = pt_int[j], pt_int[i]

    return new_sum - old_sum


# ── Main orchestrator ────────────────────────────────────────────────────────
def main():
    print("=" * 80, flush=True)
    print("K4 Simulated Annealing Assault — Phased Approach", flush=True)
    print(f"CT: {CT}", flush=True)
    print(f"CT length: {N}", flush=True)
    print(f"Available cores: {mp.cpu_count()}", flush=True)
    print("=" * 80, flush=True)

    N_WORKERS = min(12, mp.cpu_count() - 2)
    ITERS_P1 = 400_000     # Phase 1: English quality
    ITERS_P2 = 300_000     # Phase 2: Crib locking
    ITERS_PT = 500_000     # Pure transposition iters
    T_START = 5.0
    T_END = 0.001
    N_RESTARTS_PHASED = 300
    N_RESTARTS_PURE = 300
    BATCH_SIZE = N_WORKERS

    print(f"\nConfig: {N_WORKERS} workers", flush=True)
    print(f"Phased SA: {N_RESTARTS_PHASED} restarts, P1={ITERS_P1} + P2={ITERS_P2} iters", flush=True)
    print(f"Pure transposition SA: {N_RESTARTS_PURE} restarts, {ITERS_PT} iters", flush=True)

    # Load data
    print("\nLoading quadgrams...", flush=True)
    load_quadgrams()
    print(f"  Loaded ({len(QUADGRAM_LUT)} entries)", flush=True)
    print("Loading dictionary...", flush=True)
    load_dictionary()
    print(f"  Loaded ({len(LONG_WORDS)} words of 7+ chars)\n", flush=True)

    results_dir = Path(__file__).parent.parent / 'results' / 'sa_assault'
    results_dir.mkdir(parents=True, exist_ok=True)

    all_results = []
    signal_results = []
    start_time = time.time()

    # ── Run 1: Pure Transposition SA ─────────────────────────────────────
    print("=" * 60, flush=True)
    print("STAGE 1: Pure Transposition SA (no key, rearrange CT)", flush=True)
    print("=" * 60, flush=True)

    done = 0
    batch_num = 0
    pt_top = []

    while done < N_RESTARTS_PURE:
        batch_sz = min(BATCH_SIZE, N_RESTARTS_PURE - done)
        tasks = []
        for i in range(batch_sz):
            rid = done + i
            seed = 1000000 + rid * 7919
            verbose = (rid % N_WORKERS == 0)
            tasks.append((rid, seed, ITERS_PT, T_START, T_END, verbose))

        with mp.Pool(N_WORKERS) as pool:
            batch_results = pool.map(sa_worker_pure_transposition, tasks)

        for res in batch_results:
            all_results.append(res)
            pt_top.append(res)
            pt_top.sort(key=lambda x: x['qg_per_char'], reverse=True)
            pt_top = pt_top[:20]

        done += batch_sz
        batch_num += 1
        elapsed = time.time() - start_time

        best = pt_top[0] if pt_top else None
        if best and batch_num % 3 == 0:
            print(f"\n  PT batch {batch_num}: {done}/{N_RESTARTS_PURE} done, "
                  f"{elapsed:.0f}s elapsed", flush=True)
            print(f"  Best: qg/c={best['qg_per_char']:.3f} "
                  f"crib={best['crib']}/24 ic={best['ic']:.4f} "
                  f"words={best['dict_words']}", flush=True)
            print(f"  PT: {best['plaintext'][:70]}...", flush=True)

    print(f"\nPure Transposition complete: {done} restarts", flush=True)
    print(f"Top-5 by quadgram quality:", flush=True)
    for i, r in enumerate(pt_top[:5]):
        print(f"  #{i+1}: qg/c={r['qg_per_char']:.3f} crib={r['crib']}/24 "
              f"ic={r['ic']:.4f} words={r['dict_words']}", flush=True)
        print(f"       PT: {r['plaintext'][:70]}...", flush=True)

    # ── Run 2: Phased SA (transposition + substitution) ──────────────────
    print(f"\n{'='*60}", flush=True)
    print("STAGE 2: Phased SA (transposition + substitution)", flush=True)
    print(f"  Phase 1: {ITERS_P1} iters, English quality only", flush=True)
    print(f"  Phase 2: {ITERS_P2} iters, crib locking with quality", flush=True)
    print(f"{'='*60}\n", flush=True)

    done = 0
    batch_num = 0
    phased_top = []

    while done < N_RESTARTS_PHASED:
        batch_sz = min(BATCH_SIZE, N_RESTARTS_PHASED - done)
        tasks = []
        for i in range(batch_sz):
            rid = 10000 + done + i
            seed = 2000000 + (done + i) * 7919
            verbose = ((done + i) % N_WORKERS == 0)
            tasks.append((rid, seed, ITERS_P1, ITERS_P2, T_START, T_END, verbose))

        with mp.Pool(N_WORKERS) as pool:
            batch_results = pool.map(sa_worker_phased, tasks)

        for res in batch_results:
            all_results.append(res)
            phased_top.append(res)
            phased_top.sort(key=lambda x: x['qg_per_char'], reverse=True)
            phased_top = phased_top[:20]

            # Signal detection: high crib + high quadgram + Bean
            # qg/c > -4.0 is genuinely interesting (real English ~-3.3)
            # qg/c > -4.5 with 24 cribs is still worth logging
            if (res['crib'] >= 22 and res['bean_ok'] and
                    res['qg_per_char'] > -4.0):
                signal_results.append(res)
                print(f"\n*** SIGNAL R{res['restart_id']}: "
                      f"crib={res['crib']}/24 bean=PASS "
                      f"qg/c={res['qg_per_char']:.3f} ic={res['ic']:.4f} "
                      f"words={res['dict_words']}", flush=True)
                print(f"    PT: {res['plaintext']}", flush=True)

        done += batch_sz
        batch_num += 1
        elapsed = time.time() - start_time

        best = phased_top[0] if phased_top else None
        if best and batch_num % 3 == 0:
            print(f"\n  Phased batch {batch_num}: {done}/{N_RESTARTS_PHASED} done, "
                  f"{elapsed:.0f}s elapsed", flush=True)
            print(f"  Best P2: qg/c={best['qg_per_char']:.3f} "
                  f"crib={best['crib']}/24 "
                  f"bean={'Y' if best['bean_ok'] else 'N'} "
                  f"ic={best['ic']:.4f} words={best['dict_words']}", flush=True)
            print(f"  PT: {best['plaintext'][:70]}...", flush=True)
            if 'p1_qg_per_char' in best:
                print(f"  P1: qg/c={best['p1_qg_per_char']:.3f} "
                      f"crib={best['p1_crib']}/24", flush=True)

    # ── Final results ────────────────────────────────────────────────────
    total_elapsed = time.time() - start_time

    # Save all results
    output = {
        'experiment': 'sa_assault',
        'total_restarts': len(all_results),
        'elapsed_seconds': total_elapsed,
        'pure_transposition_top20': pt_top[:20],
        'phased_top20': phased_top[:20],
        'signals': signal_results,
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
    }
    outpath = results_dir / 'sa_results.json'
    with open(outpath, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nResults saved to {outpath}", flush=True)

    # Final summary
    print(f"\n{'='*80}", flush=True)
    print("FINAL SUMMARY", flush=True)
    print(f"Total restarts: {len(all_results)} ({total_elapsed:.0f}s = "
          f"{total_elapsed/60:.1f}min)", flush=True)
    print(f"Signals (crib>=20 + Bean + qg>-4.84): {len(signal_results)}", flush=True)

    print(f"\n--- Pure Transposition Top-5 ---", flush=True)
    for i, r in enumerate(pt_top[:5]):
        print(f"  #{i+1}: qg/c={r['qg_per_char']:.3f} crib={r['crib']}/24 "
              f"ic={r['ic']:.4f} words={r['dict_words']}", flush=True)
        print(f"       PT: {r['plaintext']}", flush=True)

    print(f"\n--- Phased SA Top-5 ---", flush=True)
    for i, r in enumerate(phased_top[:5]):
        print(f"  #{i+1}: qg/c={r['qg_per_char']:.3f} crib={r['crib']}/24 "
              f"bean={'PASS' if r['bean_ok'] else 'FAIL'} "
              f"ic={r['ic']:.4f} words={r['dict_words']}", flush=True)
        print(f"       PT: {r['plaintext']}", flush=True)

    # Crib score distribution for phased results
    phased_results = [r for r in all_results if 'p1_crib' in r]
    if phased_results:
        print(f"\n--- Phased: P2 Crib Score Distribution ---", flush=True)
        cs_vals = [r['crib'] for r in phased_results]
        for s in sorted(set(cs_vals)):
            count = cs_vals.count(s)
            print(f"  {s:2d}/24: {count:4d} ({count/len(cs_vals):.1%})", flush=True)

    print(f"\n{'='*80}", flush=True)
    print("Done.", flush=True)


if __name__ == '__main__':
    main()
