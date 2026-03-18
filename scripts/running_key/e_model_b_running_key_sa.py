#!/usr/bin/env python3
"""
Cipher: running_key
Family: running_key
Status: active
Keyspace: 26^73 (SA sampling)
Last run:
Best score:
"""
"""
Model B Running Key SA: Generate the most English-like 97-char key text
subject to 24 pinned crib constraints.

Under Model B (Beaufort on raw CT97, no transposition, no null extraction):
  KEY[i] = (CT[i] + PT[i]) mod 26
At 24 crib positions, KEY is KNOWN. At 73 other positions, KEY is free.

If the key is English running text, SA can find it by optimizing the 73
unknown key values for English quality (quadgram log-probability).

Six SA variants:
  1. Optimize KEY TEXT quadgrams (AZ Beaufort)
  2. Optimize PLAINTEXT quadgrams (AZ Beaufort)
  3. Optimize JOINT key+plaintext (AZ Beaufort)
  4-6. Same three with KA alphabet Beaufort

Each: 200 restarts x 50K steps, parallelized across 28 cores.

Output: results/e_model_b_running_key_sa.json
"""

import json
import sys
import os
import time
import math
import random
from multiprocessing import Pool, cpu_count
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'src'))
from kryptos.kernel.constants import CT

# ── Constants ──────────────────────────────────────────────────────────────
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
N = len(CT)  # 97

AZ_I = {c: i for i, c in enumerate(AZ)}
KA_I = {c: i for i, c in enumerate(KA)}

ENE_START, ENE_TEXT = 21, "EASTNORTHEAST"
BCL_START, BCL_TEXT = 63, "BERLINCLOCK"

# ── Load quadgrams ─────────────────────────────────────────────────────────
QG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'data', 'english_quadgrams.json')
print(f"Loading quadgrams from {QG_PATH}...", flush=True)
with open(QG_PATH) as f:
    QG_RAW = json.load(f)
print(f"  Loaded {len(QG_RAW)} quadgrams", flush=True)

# Convert to numeric lookup: (a,b,c,d) -> log_prob
# Use a flat array for speed: index = a*26^3 + b*26^2 + c*26 + d
QG_SIZE = 26 * 26 * 26 * 26  # 456,976
QG_FLOOR = min(QG_RAW.values()) - 1.0  # floor for missing quadgrams
QG_TABLE = [QG_FLOOR] * QG_SIZE
for gram, logp in QG_RAW.items():
    if len(gram) == 4:
        a, b, c, d = [ord(ch) - 65 for ch in gram]
        idx = a * 17576 + b * 676 + c * 26 + d
        QG_TABLE[idx] = logp

del QG_RAW  # free memory


def qg_score_arr(arr):
    """Quadgram log-probability score for an array of ints (0-25). Returns total and per-char."""
    n = len(arr)
    if n < 4:
        return QG_FLOOR * max(1, n - 3), QG_FLOOR
    total = 0.0
    for i in range(n - 3):
        idx = arr[i] * 17576 + arr[i+1] * 676 + arr[i+2] * 26 + arr[i+3]
        total += QG_TABLE[idx]
    per_char = total / (n - 3)
    return total, per_char


def ic_from_arr(arr):
    """Index of coincidence."""
    n = len(arr)
    if n < 2:
        return 0.0
    counts = Counter(arr)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def arr_to_str(arr):
    """Convert int array to letter string (AZ)."""
    return ''.join(AZ[v] for v in arr)


# ── Build pinned positions for both alphabets ──────────────────────────────

def build_pinned(alph_idx):
    """
    Build pinned key values under Beaufort: KEY[i] = (alph_idx[CT[i]] + alph_idx[PT[i]]) % 26
    Returns: dict {position: key_value}
    """
    ct_vals = [alph_idx[c] for c in CT]
    pinned = {}
    for j, ch in enumerate(ENE_TEXT):
        pos = ENE_START + j
        pinned[pos] = (ct_vals[pos] + alph_idx[ch]) % 26
    for j, ch in enumerate(BCL_TEXT):
        pos = BCL_START + j
        pinned[pos] = (ct_vals[pos] + alph_idx[ch]) % 26
    return pinned, ct_vals


PINNED_AZ, CT_AZ = build_pinned(AZ_I)
PINNED_KA, CT_KA = build_pinned(KA_I)

# Verify
print(f"\nAZ Beaufort pinned key at crib positions:", flush=True)
for pos in sorted(PINNED_AZ):
    print(f"  pos {pos:2d}: CT={CT[pos]} -> KEY={AZ[PINNED_AZ[pos]]} ({PINNED_AZ[pos]})", flush=True)

# Free positions (not pinned)
FREE_POS_AZ = sorted(set(range(N)) - set(PINNED_AZ))
FREE_POS_KA = sorted(set(range(N)) - set(PINNED_KA))
print(f"\n  {len(FREE_POS_AZ)} free positions (AZ), {len(FREE_POS_KA)} free (KA)", flush=True)

# AZ Beaufort key string at pinned positions
az_key_str = ''.join(AZ[PINNED_AZ[p]] for p in sorted(PINNED_AZ))
print(f"  AZ Beaufort pinned key chars: {az_key_str}", flush=True)

ka_key_str = ''.join(KA[PINNED_KA[p]] for p in sorted(PINNED_KA))
print(f"  KA Beaufort pinned key chars: {ka_key_str}", flush=True)


# ── Plaintext from key (Beaufort: PT[i] = (KEY[i] - CT[i]) mod 26 in alphabet) ──

def key_to_pt_az(key_arr):
    """Given key array (AZ-indexed), return plaintext array (AZ-indexed)."""
    return [(key_arr[i] - CT_AZ[i]) % 26 for i in range(N)]


def key_to_pt_ka(key_arr):
    """Given key array (KA-indexed), return plaintext array (KA-indexed)."""
    return [(key_arr[i] - CT_KA[i]) % 26 for i in range(N)]


# ── SA Worker Functions ────────────────────────────────────────────────────

def sa_worker_key_text(args):
    """SA optimizing KEY TEXT quadgrams. Returns best key, score, pt."""
    restart_id, seed, pinned, ct_vals, free_pos, n_steps, alph_name = args
    rng = random.Random(seed)

    # Initialize key: pinned + random free
    key = [0] * N
    for pos, val in pinned.items():
        key[pos] = val
    for pos in free_pos:
        key[pos] = rng.randint(0, 25)

    # Score
    best_key = key[:]
    _, best_qg = qg_score_arr(key)
    cur_qg = best_qg

    T_start = 2.0
    T_end = 0.001
    log_ratio = math.log(T_end / T_start)

    for step in range(n_steps):
        T = T_start * math.exp(log_ratio * step / n_steps)

        # Pick random free position, try random new value
        pos = free_pos[rng.randint(0, len(free_pos) - 1)]
        old_val = key[pos]
        new_val = rng.randint(0, 25)
        if new_val == old_val:
            new_val = (old_val + rng.randint(1, 25)) % 26

        key[pos] = new_val
        _, new_qg = qg_score_arr(key)

        delta = new_qg - cur_qg
        if delta > 0 or rng.random() < math.exp(delta / T):
            cur_qg = new_qg
            if new_qg > best_qg:
                best_qg = new_qg
                best_key = key[:]
        else:
            key[pos] = old_val

    # Compute PT from best key
    if alph_name == 'AZ':
        pt = key_to_pt_az(best_key)
    else:
        pt = key_to_pt_ka(best_key)

    _, pt_qg = qg_score_arr(pt)

    return {
        'restart': restart_id,
        'key_qg': best_qg,
        'pt_qg': pt_qg,
        'key_ic': ic_from_arr(best_key),
        'pt_ic': ic_from_arr(pt),
        'key_text': arr_to_str(best_key),
        'pt_text': arr_to_str(pt) if alph_name == 'AZ' else ''.join(KA[v] for v in pt),
        'alph': alph_name,
        'mode': 'key_text',
    }


def sa_worker_plaintext(args):
    """SA optimizing PLAINTEXT quadgrams. Returns best key, score, pt."""
    restart_id, seed, pinned, ct_vals, free_pos, n_steps, alph_name = args
    rng = random.Random(seed)

    # Initialize key: pinned + random free
    key = [0] * N
    for pos, val in pinned.items():
        key[pos] = val
    for pos in free_pos:
        key[pos] = rng.randint(0, 25)

    # Score based on plaintext
    if alph_name == 'AZ':
        pt = key_to_pt_az(key)
    else:
        pt = key_to_pt_ka(key)

    _, best_pt_qg = qg_score_arr(pt)
    cur_pt_qg = best_pt_qg
    best_key = key[:]

    T_start = 2.0
    T_end = 0.001
    log_ratio = math.log(T_end / T_start)

    for step in range(n_steps):
        T = T_start * math.exp(log_ratio * step / n_steps)

        pos = free_pos[rng.randint(0, len(free_pos) - 1)]
        old_val = key[pos]
        new_val = rng.randint(0, 25)
        if new_val == old_val:
            new_val = (old_val + rng.randint(1, 25)) % 26

        key[pos] = new_val

        if alph_name == 'AZ':
            pt = key_to_pt_az(key)
        else:
            pt = key_to_pt_ka(key)
        _, new_pt_qg = qg_score_arr(pt)

        delta = new_pt_qg - cur_pt_qg
        if delta > 0 or rng.random() < math.exp(delta / T):
            cur_pt_qg = new_pt_qg
            if new_pt_qg > best_pt_qg:
                best_pt_qg = new_pt_qg
                best_key = key[:]
        else:
            key[pos] = old_val

    # Compute final scores
    if alph_name == 'AZ':
        pt = key_to_pt_az(best_key)
    else:
        pt = key_to_pt_ka(best_key)
    _, key_qg = qg_score_arr(best_key)
    _, pt_qg = qg_score_arr(pt)

    return {
        'restart': restart_id,
        'key_qg': key_qg,
        'pt_qg': pt_qg,
        'key_ic': ic_from_arr(best_key),
        'pt_ic': ic_from_arr(pt),
        'key_text': arr_to_str(best_key),
        'pt_text': arr_to_str(pt) if alph_name == 'AZ' else ''.join(KA[v] for v in pt),
        'alph': alph_name,
        'mode': 'plaintext',
    }


def sa_worker_joint(args):
    """SA optimizing JOINT key+plaintext quadgrams. Returns best key, score, pt."""
    restart_id, seed, pinned, ct_vals, free_pos, n_steps, alph_name, alpha, beta = args
    rng = random.Random(seed)

    # Initialize key: pinned + random free
    key = [0] * N
    for pos, val in pinned.items():
        key[pos] = val
    for pos in free_pos:
        key[pos] = rng.randint(0, 25)

    # Score
    _, key_qg = qg_score_arr(key)
    if alph_name == 'AZ':
        pt = key_to_pt_az(key)
    else:
        pt = key_to_pt_ka(key)
    _, pt_qg = qg_score_arr(pt)
    cur_score = alpha * key_qg + beta * pt_qg
    best_score = cur_score
    best_key = key[:]

    T_start = 2.0
    T_end = 0.001
    log_ratio = math.log(T_end / T_start)

    for step in range(n_steps):
        T = T_start * math.exp(log_ratio * step / n_steps)

        pos = free_pos[rng.randint(0, len(free_pos) - 1)]
        old_val = key[pos]
        new_val = rng.randint(0, 25)
        if new_val == old_val:
            new_val = (old_val + rng.randint(1, 25)) % 26

        key[pos] = new_val

        _, new_key_qg = qg_score_arr(key)
        if alph_name == 'AZ':
            pt = key_to_pt_az(key)
        else:
            pt = key_to_pt_ka(key)
        _, new_pt_qg = qg_score_arr(pt)
        new_score = alpha * new_key_qg + beta * new_pt_qg

        delta = new_score - cur_score
        if delta > 0 or rng.random() < math.exp(delta / T):
            cur_score = new_score
            if new_score > best_score:
                best_score = new_score
                best_key = key[:]
        else:
            key[pos] = old_val

    # Compute final scores
    _, key_qg = qg_score_arr(best_key)
    if alph_name == 'AZ':
        pt = key_to_pt_az(best_key)
    else:
        pt = key_to_pt_ka(best_key)
    _, pt_qg = qg_score_arr(pt)

    return {
        'restart': restart_id,
        'key_qg': key_qg,
        'pt_qg': pt_qg,
        'joint_score': alpha * key_qg + beta * pt_qg,
        'key_ic': ic_from_arr(best_key),
        'pt_ic': ic_from_arr(pt),
        'key_text': arr_to_str(best_key),
        'pt_text': arr_to_str(pt) if alph_name == 'AZ' else ''.join(KA[v] for v in pt),
        'alph': alph_name,
        'mode': 'joint',
    }


def verify_cribs(result, pinned, alph_idx, alph_str):
    """Verify that all 24 pinned positions produce correct plaintext."""
    ct_arr = [alph_idx[c] for c in CT]
    key_text = result['key_text']
    errors = []
    # Check ENE
    for j, ch in enumerate(ENE_TEXT):
        pos = ENE_START + j
        key_val = alph_idx[key_text[pos]]
        pt_val = (key_val - ct_arr[pos]) % 26
        pt_ch = alph_str[pt_val]
        if pt_ch != ch:
            errors.append(f"pos {pos}: expected PT={ch}, got PT={pt_ch}")
    # Check BCL
    for j, ch in enumerate(BCL_TEXT):
        pos = BCL_START + j
        key_val = alph_idx[key_text[pos]]
        pt_val = (key_val - ct_arr[pos]) % 26
        pt_ch = alph_str[pt_val]
        if pt_ch != ch:
            errors.append(f"pos {pos}: expected PT={ch}, got PT={pt_ch}")
    return errors


def find_words(text, min_len=4):
    """Find English words of length >= min_len in text."""
    # Load a small word set for checking
    wl_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'wordlists', 'english.txt')
    words = set()
    try:
        with open(wl_path) as f:
            for line in f:
                w = line.strip().upper()
                if len(w) >= min_len:
                    words.add(w)
    except FileNotFoundError:
        return []

    found = []
    text = text.upper()
    for wlen in range(min_len, min(len(text), 15) + 1):
        for i in range(len(text) - wlen + 1):
            substr = text[i:i+wlen]
            if substr in words:
                found.append((i, substr))
    # Deduplicate: keep longest at each position
    found.sort(key=lambda x: (-len(x[1]), x[0]))
    seen_pos = set()
    deduped = []
    for pos, w in found:
        if pos not in seen_pos:
            deduped.append((pos, w))
            seen_pos.add(pos)
    return deduped[:20]  # top 20


def detect_periodicity(arr, max_period=30):
    """Check for periodic patterns in array. Returns (period, correlation) for best period."""
    n = len(arr)
    best_corr = 0.0
    best_p = 0
    for p in range(1, min(max_period + 1, n // 2)):
        matches = sum(1 for i in range(n - p) if arr[i] == arr[i + p])
        corr = matches / (n - p)
        if corr > best_corr:
            best_corr = corr
            best_p = p
    return best_p, best_corr


def run_variant(variant_name, worker_fn, tasks, n_workers):
    """Run one SA variant across all restarts."""
    print(f"\n{'='*70}", flush=True)
    print(f"  VARIANT: {variant_name}", flush=True)
    print(f"  {len(tasks)} restarts, {n_workers} workers", flush=True)
    print(f"{'='*70}", flush=True)

    t0 = time.time()
    with Pool(n_workers) as pool:
        results = pool.map(worker_fn, tasks)
    elapsed = time.time() - t0

    # Sort by key_qg descending
    results.sort(key=lambda r: r['key_qg'], reverse=True)

    print(f"\n  Completed in {elapsed:.1f}s", flush=True)
    print(f"\n  Top 5 by KEY TEXT quality:", flush=True)
    for i, r in enumerate(results[:5]):
        print(f"    #{i+1}: key_qg={r['key_qg']:.4f}/char, pt_qg={r['pt_qg']:.4f}/char, "
              f"key_IC={r['key_ic']:.4f}, pt_IC={r['pt_ic']:.4f}", flush=True)
        print(f"         KEY: {r['key_text'][:50]}...", flush=True)
        print(f"          PT: {r['pt_text'][:50]}...", flush=True)

    # Also sort by pt_qg
    by_pt = sorted(results, key=lambda r: r['pt_qg'], reverse=True)
    print(f"\n  Top 5 by PLAINTEXT quality:", flush=True)
    for i, r in enumerate(by_pt[:5]):
        print(f"    #{i+1}: pt_qg={r['pt_qg']:.4f}/char, key_qg={r['key_qg']:.4f}/char, "
              f"pt_IC={r['pt_ic']:.4f}, key_IC={r['key_ic']:.4f}", flush=True)
        print(f"          PT: {r['pt_text'][:50]}...", flush=True)
        print(f"         KEY: {r['key_text'][:50]}...", flush=True)

    # Statistics
    key_qgs = [r['key_qg'] for r in results]
    pt_qgs = [r['pt_qg'] for r in results]
    print(f"\n  KEY QG stats: mean={sum(key_qgs)/len(key_qgs):.4f}, "
          f"max={max(key_qgs):.4f}, min={min(key_qgs):.4f}", flush=True)
    print(f"  PT  QG stats: mean={sum(pt_qgs)/len(pt_qgs):.4f}, "
          f"max={max(pt_qgs):.4f}, min={min(pt_qgs):.4f}", flush=True)

    return results, elapsed


def main():
    t_start = time.time()
    n_workers = min(cpu_count(), 28)
    n_restarts = 200
    n_steps = 50000
    n_restarts_ka = 100
    n_restarts_joint = 100

    all_results = {}

    # ── Variant 1: AZ Beaufort, optimize KEY TEXT ──────────────────────────
    tasks_1 = [
        (i, 1000 + i, PINNED_AZ, CT_AZ, FREE_POS_AZ, n_steps, 'AZ')
        for i in range(n_restarts)
    ]
    results_1, t1 = run_variant("AZ Beaufort - KEY TEXT quadgrams", sa_worker_key_text, tasks_1, n_workers)
    all_results['az_beau_key_text'] = {'results': results_1[:10], 'elapsed': t1, 'n_restarts': n_restarts}

    # ── Variant 2: AZ Beaufort, optimize PLAINTEXT ─────────────────────────
    tasks_2 = [
        (i, 2000 + i, PINNED_AZ, CT_AZ, FREE_POS_AZ, n_steps, 'AZ')
        for i in range(n_restarts)
    ]
    results_2, t2 = run_variant("AZ Beaufort - PLAINTEXT quadgrams", sa_worker_plaintext, tasks_2, n_workers)
    all_results['az_beau_plaintext'] = {'results': results_2[:10], 'elapsed': t2, 'n_restarts': n_restarts}

    # ── Variant 3: AZ Beaufort, optimize JOINT ─────────────────────────────
    tasks_3 = [
        (i, 3000 + i, PINNED_AZ, CT_AZ, FREE_POS_AZ, n_steps, 'AZ', 1.0, 1.0)
        for i in range(n_restarts_joint)
    ]
    results_3, t3 = run_variant("AZ Beaufort - JOINT key+plaintext", sa_worker_joint, tasks_3, n_workers)
    all_results['az_beau_joint'] = {'results': results_3[:10], 'elapsed': t3, 'n_restarts': n_restarts_joint}

    # ── Variant 4: KA Beaufort, optimize KEY TEXT ──────────────────────────
    tasks_4 = [
        (i, 4000 + i, PINNED_KA, CT_KA, FREE_POS_KA, n_steps, 'KA')
        for i in range(n_restarts_ka)
    ]
    results_4, t4 = run_variant("KA Beaufort - KEY TEXT quadgrams", sa_worker_key_text, tasks_4, n_workers)
    all_results['ka_beau_key_text'] = {'results': results_4[:10], 'elapsed': t4, 'n_restarts': n_restarts_ka}

    # ── Variant 5: KA Beaufort, optimize PLAINTEXT ─────────────────────────
    tasks_5 = [
        (i, 5000 + i, PINNED_KA, CT_KA, FREE_POS_KA, n_steps, 'KA')
        for i in range(n_restarts_ka)
    ]
    results_5, t5 = run_variant("KA Beaufort - PLAINTEXT quadgrams", sa_worker_plaintext, tasks_5, n_workers)
    all_results['ka_beau_plaintext'] = {'results': results_5[:10], 'elapsed': t5, 'n_restarts': n_restarts_ka}

    # ── Variant 6: KA Beaufort, optimize JOINT ─────────────────────────────
    tasks_6 = [
        (i, 6000 + i, PINNED_KA, CT_KA, FREE_POS_KA, n_steps, 'KA', 1.0, 1.0)
        for i in range(n_restarts_ka)
    ]
    results_6, t6 = run_variant("KA Beaufort - JOINT key+plaintext", sa_worker_joint, tasks_6, n_workers)
    all_results['ka_beau_joint'] = {'results': results_6[:10], 'elapsed': t6, 'n_restarts': n_restarts_ka}

    # ── Verification & Analysis ────────────────────────────────────────────
    print(f"\n{'='*70}", flush=True)
    print(f"  VERIFICATION & ANALYSIS", flush=True)
    print(f"{'='*70}", flush=True)

    # Verify cribs on best of each variant
    for vname, vdata in all_results.items():
        best = vdata['results'][0]
        if 'az' in vname:
            errors = verify_cribs(best, PINNED_AZ, AZ_I, AZ)
        else:
            errors = verify_cribs(best, PINNED_KA, KA_I, KA)
        if errors:
            print(f"\n  *** CRIB VERIFICATION FAILED for {vname}:", flush=True)
            for e in errors:
                print(f"      {e}", flush=True)
        else:
            print(f"  {vname}: CRIB VERIFIED (24/24 correct)", flush=True)

    # Find words in best results
    print(f"\n  English words found in top results:", flush=True)
    try:
        wl_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'wordlists', 'english.txt')
        word_set = set()
        with open(wl_path) as f:
            for line in f:
                w = line.strip().upper()
                if 4 <= len(w) <= 15:
                    word_set.add(w)
        print(f"  Loaded {len(word_set)} words for word search", flush=True)

        for vname, vdata in all_results.items():
            best = vdata['results'][0]
            for label, text in [('KEY', best['key_text']), ('PT', best['pt_text'])]:
                found = []
                for wlen in range(15, 3, -1):
                    for i in range(len(text) - wlen + 1):
                        substr = text[i:i+wlen]
                        if substr in word_set:
                            found.append((i, substr))
                if found:
                    # Deduplicate: keep longest at each start position
                    seen = set()
                    deduped = []
                    for pos, w in sorted(found, key=lambda x: (-len(x[1]), x[0])):
                        if pos not in seen:
                            deduped.append((pos, w))
                            seen.add(pos)
                    print(f"  {vname} {label}: {deduped[:10]}", flush=True)
    except FileNotFoundError:
        print("  (wordlist not found, skipping word search)", flush=True)

    # Periodicity check on best key texts
    print(f"\n  Periodicity analysis:", flush=True)
    for vname, vdata in all_results.items():
        best = vdata['results'][0]
        key_arr = [AZ_I.get(c, 0) for c in best['key_text']]
        p, corr = detect_periodicity(key_arr)
        print(f"  {vname}: best_period={p}, correlation={corr:.3f}", flush=True)

    # AP presence check (G=6, K=10, O=14 at known positions)
    print("  AP {G=6,K=10,O=14} presence at known positions:", flush=True)
    for vname, vdata in all_results.items():
        if 'az' not in vname:
            continue
        best = vdata['results'][0]
        key_arr = [AZ_I[c] for c in best['key_text']]
        ap_count = sum(1 for v in key_arr if v in (6, 10, 14))
        print(f"  {vname}: {ap_count}/97 positions in {{G,K,O}} AP", flush=True)

    # ── Save results ───────────────────────────────────────────────────────
    total_time = time.time() - t_start
    output = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'script': 'e_model_b_running_key_sa.py',
        'model': 'Model B Beaufort (raw 97, no transposition, no null extraction)',
        'n_restarts_az': n_restarts,
        'n_restarts_ka': n_restarts_ka,
        'n_restarts_joint': n_restarts_joint,
        'n_steps': n_steps,
        'total_time_s': total_time,
        'variants': {},
    }

    for vname, vdata in all_results.items():
        output['variants'][vname] = {
            'elapsed_s': vdata['elapsed'],
            'n_restarts': vdata['n_restarts'],
            'best_key_qg': vdata['results'][0]['key_qg'],
            'best_pt_qg': max(r['pt_qg'] for r in vdata['results']),
            'best_key_text': vdata['results'][0]['key_text'],
            'best_pt_text': sorted(vdata['results'], key=lambda r: r['pt_qg'], reverse=True)[0]['pt_text'],
            'best_key_ic': vdata['results'][0]['key_ic'],
            'best_pt_ic': sorted(vdata['results'], key=lambda r: r['pt_qg'], reverse=True)[0]['pt_ic'],
            'top_10': vdata['results'][:10],
        }

    # Thresholds for assessment
    english_qg = -4.2  # typical English
    random_qg = -6.5   # random text

    print(f"\n{'='*70}", flush=True)
    print(f"  FINAL ASSESSMENT", flush=True)
    print(f"{'='*70}", flush=True)
    print(f"  English qg/char: ~{english_qg}", flush=True)
    print(f"  Random qg/char:  ~{random_qg}", flush=True)

    any_signal = False
    for vname, vdata in output['variants'].items():
        key_qg = vdata['best_key_qg']
        pt_qg = vdata['best_pt_qg']
        key_gap = key_qg - english_qg
        pt_gap = pt_qg - english_qg

        status = "NOISE"
        if key_qg > -4.5 or pt_qg > -4.5:
            status = "SIGNAL"
            any_signal = True
        elif key_qg > -5.0 or pt_qg > -5.0:
            status = "INTERESTING"

        print(f"\n  {vname}:", flush=True)
        print(f"    Key text: {key_qg:.4f}/char (gap from English: {key_gap:+.2f})", flush=True)
        print(f"    PT:       {pt_qg:.4f}/char (gap from English: {pt_gap:+.2f})", flush=True)
        print(f"    Status:   {status}", flush=True)

    output['any_signal'] = any_signal
    output['verdict'] = 'SIGNAL' if any_signal else 'NOISE'

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'results', 'e_model_b_running_key_sa.json')
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\n  Results saved to: {out_path}", flush=True)
    print(f"  Total time: {total_time:.1f}s ({total_time/60:.1f}m)", flush=True)


if __name__ == '__main__':
    main()
