#!/usr/bin/env python3
"""
Cipher: polyalphabetic (periodic + long-key)
Family: analysis
Status: active
Keyspace: SA sampling (26^P periodic, 26^73 long-key, 2^73 mask)
Last run: never
Best score: n/a
"""
"""
Fresh quadgram-guided MCMC/SA attack on K4.

APPROACH: Use ENGLISH QUALITY (quadgram log-probability) as the SOLE
objective. If the cipher is correct, quadgram optimization should find
plaintext that reads as English AND contains the cribs naturally.

Five phases:
  Phase 1: Extract CT73 using consensus nulls
  Phase 2: Quadgram SA -- periodic polyalphabetic (periods 2-20)
  Phase 3: Quadgram SA -- long key (73 letters, running-key-like)
  Phase 4: Joint mask + key optimization (simultaneous)
  Phase 5: Known-plaintext anchored quadgram extension

All phases try Beaufort, Vigenere, and Variant Beaufort, with and
without col7/col6 transposition.

Output: results/fresh_mcmc_attack.json
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
from kryptos.kernel.constants import CT, CRIB_POSITIONS

# ── Constants ──────────────────────────────────────────────────────────────
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
N97 = len(CT)  # 97

AZ_I = {c: i for i, c in enumerate(AZ)}

ENE_START, ENE_TEXT = 21, "EASTNORTHEAST"
BCL_START, BCL_TEXT = 63, "BERLINCLOCK"

CONSENSUS_17 = sorted([0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85])

# Palette positions (B,G,I,K,O,W,Z in CT97)
PALETTE = frozenset('BGIKOWZ')
PALETTE_POSITIONS = sorted(i for i in range(N97) if CT[i] in PALETTE)
# Non-consensus palette positions (candidates for remaining 7 nulls)
PALETTE_NON_CONSENSUS = sorted(set(PALETTE_POSITIONS) - set(CONSENSUS_17) - CRIB_POSITIONS)

N_WORKERS = 24  # Leave 4 cores free

# ── Load quadgrams ─────────────────────────────────────────────────────────
QG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'data', 'english_quadgrams.json')
print(f"Loading quadgrams from {QG_PATH}...", flush=True)
with open(QG_PATH) as f:
    QG_RAW = json.load(f)
print(f"  Loaded {len(QG_RAW)} quadgrams", flush=True)

QG_SIZE = 26 * 26 * 26 * 26
QG_FLOOR = min(QG_RAW.values()) - 1.0
QG_TABLE = [QG_FLOOR] * QG_SIZE
for gram, logp in QG_RAW.items():
    if len(gram) == 4:
        a, b, c, d = [ord(ch) - 65 for ch in gram]
        QG_TABLE[a * 17576 + b * 676 + c * 26 + d] = logp
del QG_RAW


def qg_score_arr(arr):
    """Quadgram log-probability score. Returns (total, per_char)."""
    n = len(arr)
    if n < 4:
        return QG_FLOOR, QG_FLOOR
    total = 0.0
    for i in range(n - 3):
        total += QG_TABLE[arr[i] * 17576 + arr[i+1] * 676 + arr[i+2] * 26 + arr[i+3]]
    return total, total / (n - 3)


def ic_from_arr(arr):
    n = len(arr)
    if n < 2:
        return 0.0
    counts = Counter(arr)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def arr_to_str(arr):
    return ''.join(AZ[v] for v in arr)


# ── Columnar transposition ─────────────────────────────────────────────────
def columnar_perm(n, width):
    """Build columnar transposition permutation (gather convention)."""
    n_rows = (n + width - 1) // width
    perm = []
    for col in range(width):
        for row in range(n_rows):
            idx = row * width + col
            if idx < n:
                perm.append(idx)
    return perm


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


# Pre-build columnar permutations for CT73
PERM_COL7 = invert_perm(columnar_perm(73, 7))
PERM_COL6 = invert_perm(columnar_perm(73, 6))


# ── Cipher operations ──────────────────────────────────────────────────────
def decrypt_beaufort(ct_arr, key_arr):
    """Beaufort: PT = (KEY - CT) mod 26"""
    return [(key_arr[i % len(key_arr)] - ct_arr[i]) % 26 for i in range(len(ct_arr))]


def decrypt_vigenere(ct_arr, key_arr):
    """Vigenere: PT = (CT - KEY) mod 26"""
    return [(ct_arr[i] - key_arr[i % len(key_arr)]) % 26 for i in range(len(ct_arr))]


def decrypt_varbeau(ct_arr, key_arr):
    """Variant Beaufort: PT = (CT + KEY) mod 26"""
    return [(ct_arr[i] + key_arr[i % len(key_arr)]) % 26 for i in range(len(ct_arr))]


DECRYPT_FNS = {
    'beau': decrypt_beaufort,
    'vig': decrypt_vigenere,
    'vbeau': decrypt_varbeau,
}


# ── Null mask operations ──────────────────────────────────────────────────
def extract_ct73(null_positions):
    """Extract 73-char CT from 97-char CT by removing null positions."""
    null_set = set(null_positions)
    chars = [AZ_I[CT[i]] for i in range(N97) if i not in null_set]
    return chars


def apply_trans(ct73, perm):
    """Apply transposition permutation."""
    return [ct73[perm[i]] for i in range(len(ct73))]


def shifted_crib_positions(null_positions):
    """Compute crib positions in CT73 space after null removal."""
    null_set = set(null_positions)
    # Count nulls before each crib position
    n_before = {}
    for pos in sorted(CRIB_POSITIONS):
        n_before[pos] = sum(1 for n in null_positions if n < pos)

    ene_positions = [(ENE_START + i - n_before[ENE_START + i], ENE_TEXT[i])
                     for i in range(len(ENE_TEXT))]
    bcl_positions = [(BCL_START + i - n_before[BCL_START + i], BCL_TEXT[i])
                     for i in range(len(BCL_TEXT))]
    return ene_positions + bcl_positions


def check_cribs_in_pt(pt_arr, ene_text=ENE_TEXT, bcl_text=BCL_TEXT):
    """Search for cribs ANYWHERE in plaintext (free search)."""
    pt_str = arr_to_str(pt_arr)
    ene_pos = pt_str.find(ene_text)
    bcl_pos = pt_str.find(bcl_text)
    ene_score = len(ene_text) if ene_pos >= 0 else 0
    bcl_score = len(bcl_text) if bcl_pos >= 0 else 0

    # Also check partial matches at expected positions
    # (after null removal, cribs should be near their original positions)
    return ene_score + bcl_score, ene_pos, bcl_pos


def check_cribs_at_positions(pt_arr, shifted_cribs):
    """Check crib matches at shifted positions."""
    hits = 0
    for pos, ch in shifted_cribs:
        if 0 <= pos < len(pt_arr) and pt_arr[pos] == AZ_I[ch]:
            hits += 1
    return hits


# ── Generate 24-null masks ───────────────────────────────────────────────
def random_mask_24(rng, consensus=CONSENSUS_17):
    """Generate a random 24-null mask containing the 17 consensus nulls."""
    available = sorted(set(range(N97)) - set(consensus) - CRIB_POSITIONS)
    extra = rng.sample(available, 7)
    return sorted(set(consensus) | set(extra))


def palette_mask_24(rng, consensus=CONSENSUS_17):
    """Generate 24-null mask, preferring palette positions for the extra 7."""
    # Try palette first, fill rest randomly
    available_palette = sorted(set(PALETTE_NON_CONSENSUS) - CRIB_POSITIONS)
    available_other = sorted(set(range(N97)) - set(consensus) - CRIB_POSITIONS - set(available_palette))

    n_palette = min(len(available_palette), 7)
    if n_palette >= 7:
        extra = rng.sample(available_palette, 7)
    else:
        extra = available_palette[:] + rng.sample(available_other, 7 - n_palette)
    return sorted(set(consensus) | set(extra))


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 2: Periodic SA
# ═══════════════════════════════════════════════════════════════════════════
def phase2_worker(args):
    """SA worker for periodic key on CT73."""
    (restart_id, period, variant, trans_name, null_mask, n_steps, seed) = args
    rng = random.Random(seed)

    ct73 = extract_ct73(null_mask)
    if trans_name == 'col7':
        ct73 = apply_trans(ct73, PERM_COL7)
    elif trans_name == 'col6':
        ct73 = apply_trans(ct73, PERM_COL6)

    decrypt_fn = DECRYPT_FNS[variant]
    n = len(ct73)

    # Initialize random key
    key = [rng.randint(0, 25) for _ in range(period)]
    pt = decrypt_fn(ct73, key)
    _, best_qg = qg_score_arr(pt)
    cur_qg = best_qg
    best_key = key[:]
    best_pt = pt[:]

    T_start = 2.0
    T_end = 0.0005
    log_ratio = math.log(T_end / T_start)

    for step in range(n_steps):
        T = T_start * math.exp(log_ratio * step / n_steps)

        # Mutate one key position
        pos = rng.randint(0, period - 1)
        old_val = key[pos]
        new_val = (old_val + rng.randint(1, 25)) % 26
        key[pos] = new_val

        pt = decrypt_fn(ct73, key)
        _, new_qg = qg_score_arr(pt)

        delta = new_qg - cur_qg
        if delta > 0 or rng.random() < math.exp(delta / T):
            cur_qg = new_qg
            if new_qg > best_qg:
                best_qg = new_qg
                best_key = key[:]
                best_pt = pt[:]
        else:
            key[pos] = old_val

    pt_str = arr_to_str(best_pt)
    crib_free, ene_pos, bcl_pos = check_cribs_in_pt(best_pt)

    return {
        'phase': 2,
        'restart': restart_id,
        'period': period,
        'variant': variant,
        'trans': trans_name,
        'qg_per_char': best_qg,
        'ic': ic_from_arr(best_pt),
        'pt': pt_str[:40] + '...',
        'key': arr_to_str(best_key),
        'crib_free': crib_free,
        'ene_pos': ene_pos,
        'bcl_pos': bcl_pos,
    }


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 3: Long-key SA (73 letters)
# ═══════════════════════════════════════════════════════════════════════════
def phase3_worker(args):
    """SA worker for long (73-letter) key on CT73."""
    (restart_id, variant, trans_name, null_mask, n_steps, seed) = args
    rng = random.Random(seed)

    ct73 = extract_ct73(null_mask)
    if trans_name == 'col7':
        ct73 = apply_trans(ct73, PERM_COL7)
    elif trans_name == 'col6':
        ct73 = apply_trans(ct73, PERM_COL6)

    decrypt_fn = DECRYPT_FNS[variant]
    n = len(ct73)

    # Initialize random 73-letter key
    key = [rng.randint(0, 25) for _ in range(n)]
    pt = decrypt_fn(ct73, key)
    _, best_qg = qg_score_arr(pt)
    cur_qg = best_qg
    best_key = key[:]
    best_pt = pt[:]

    T_start = 2.5
    T_end = 0.0005
    log_ratio = math.log(T_end / T_start)

    for step in range(n_steps):
        T = T_start * math.exp(log_ratio * step / n_steps)

        pos = rng.randint(0, n - 1)
        old_val = key[pos]
        new_val = (old_val + rng.randint(1, 25)) % 26
        key[pos] = new_val

        pt = decrypt_fn(ct73, key)
        _, new_qg = qg_score_arr(pt)

        delta = new_qg - cur_qg
        if delta > 0 or rng.random() < math.exp(delta / T):
            cur_qg = new_qg
            if new_qg > best_qg:
                best_qg = new_qg
                best_key = key[:]
                best_pt = pt[:]
        else:
            key[pos] = old_val

    pt_str = arr_to_str(best_pt)
    crib_free, ene_pos, bcl_pos = check_cribs_in_pt(best_pt)

    return {
        'phase': 3,
        'restart': restart_id,
        'variant': variant,
        'trans': trans_name,
        'qg_per_char': best_qg,
        'ic': ic_from_arr(best_pt),
        'pt': pt_str[:50] + '...',
        'key': arr_to_str(best_key)[:30] + '...',
        'crib_free': crib_free,
        'ene_pos': ene_pos,
        'bcl_pos': bcl_pos,
    }


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 4: Joint mask + key SA
# ═══════════════════════════════════════════════════════════════════════════
def phase4_worker(args):
    """SA worker: jointly optimize null mask AND cipher key."""
    (restart_id, period, variant, trans_name, n_steps, seed) = args
    rng = random.Random(seed)

    # Initialize mask: 17 consensus + 7 random
    null_mask = random_mask_24(rng)

    ct73 = extract_ct73(null_mask)
    if trans_name == 'col7':
        ct73 = apply_trans(ct73, PERM_COL7)
    elif trans_name == 'col6':
        ct73 = apply_trans(ct73, PERM_COL6)

    decrypt_fn = DECRYPT_FNS[variant]

    # Initialize key
    if period == 73:
        key = [rng.randint(0, 25) for _ in range(73)]
    else:
        key = [rng.randint(0, 25) for _ in range(period)]

    pt = decrypt_fn(ct73, key)
    _, best_qg = qg_score_arr(pt)
    cur_qg = best_qg
    best_key = key[:]
    best_mask = null_mask[:]
    best_pt = pt[:]
    best_ct73 = ct73[:]

    # Available positions for mask swaps (not consensus, not crib)
    available = sorted(set(range(N97)) - set(CONSENSUS_17) - CRIB_POSITIONS)

    T_start = 3.0
    T_end = 0.0005
    log_ratio = math.log(T_end / T_start)

    for step in range(n_steps):
        T = T_start * math.exp(log_ratio * step / n_steps)

        # 30% chance: flip a null position; 70%: change a key letter
        if rng.random() < 0.3:
            # Mask move: swap a null out and a non-null in
            current_extra = sorted(set(null_mask) - set(CONSENSUS_17))
            current_non_null = sorted(set(available) - set(current_extra))

            if not current_extra or not current_non_null:
                continue

            old_null = rng.choice(current_extra)
            new_null = rng.choice(current_non_null)

            new_mask = sorted((set(null_mask) - {old_null}) | {new_null})
            new_ct73 = extract_ct73(new_mask)
            if trans_name == 'col7':
                new_ct73 = apply_trans(new_ct73, PERM_COL7)
            elif trans_name == 'col6':
                new_ct73 = apply_trans(new_ct73, PERM_COL6)

            pt = decrypt_fn(new_ct73, key)
            _, new_qg = qg_score_arr(pt)

            delta = new_qg - cur_qg
            if delta > 0 or rng.random() < math.exp(delta / T):
                null_mask = new_mask
                ct73 = new_ct73
                cur_qg = new_qg
                if new_qg > best_qg:
                    best_qg = new_qg
                    best_key = key[:]
                    best_mask = null_mask[:]
                    best_pt = pt[:]
                    best_ct73 = ct73[:]
        else:
            # Key move
            klen = len(key)
            pos = rng.randint(0, klen - 1)
            old_val = key[pos]
            new_val = (old_val + rng.randint(1, 25)) % 26
            key[pos] = new_val

            pt = decrypt_fn(ct73, key)
            _, new_qg = qg_score_arr(pt)

            delta = new_qg - cur_qg
            if delta > 0 or rng.random() < math.exp(delta / T):
                cur_qg = new_qg
                if new_qg > best_qg:
                    best_qg = new_qg
                    best_key = key[:]
                    best_mask = null_mask[:]
                    best_pt = pt[:]
                    best_ct73 = ct73[:]
            else:
                key[pos] = old_val

    pt_str = arr_to_str(best_pt)
    crib_free, ene_pos, bcl_pos = check_cribs_in_pt(best_pt)
    shifted = shifted_crib_positions(best_mask)
    crib_at_pos = check_cribs_at_positions(best_pt, shifted)

    return {
        'phase': 4,
        'restart': restart_id,
        'period': period,
        'variant': variant,
        'trans': trans_name,
        'qg_per_char': best_qg,
        'ic': ic_from_arr(best_pt),
        'pt': pt_str[:50] + '...',
        'key': arr_to_str(best_key)[:30] + ('...' if len(best_key) > 30 else ''),
        'mask_extra': sorted(set(best_mask) - set(CONSENSUS_17)),
        'crib_free': crib_free,
        'crib_at_pos': crib_at_pos,
        'ene_pos': ene_pos,
        'bcl_pos': bcl_pos,
    }


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 5: Known-plaintext anchored quadgram extension
# ═══════════════════════════════════════════════════════════════════════════
def phase5_worker(args):
    """SA that fixes key at crib positions and optimizes the rest for English PT."""
    (restart_id, variant, trans_name, null_mask, n_steps, seed) = args
    rng = random.Random(seed)

    ct73 = extract_ct73(null_mask)
    shifted = shifted_crib_positions(null_mask)

    if trans_name == 'col7':
        ct73_t = apply_trans(ct73, PERM_COL7)
        # Need to map shifted crib positions through col7
        inv_col7 = invert_perm(PERM_COL7)
        shifted_t = [(inv_col7[pos], ch) for pos, ch in shifted if pos < 73]
    elif trans_name == 'col6':
        ct73_t = apply_trans(ct73, PERM_COL6)
        inv_col6 = invert_perm(PERM_COL6)
        shifted_t = [(inv_col6[pos], ch) for pos, ch in shifted if pos < 73]
    else:
        ct73_t = ct73[:]
        shifted_t = [(pos, ch) for pos, ch in shifted if pos < 73]

    n = len(ct73_t)

    # Compute pinned key values at crib positions
    pinned = {}
    for pos, ch in shifted_t:
        if 0 <= pos < n:
            pt_val = AZ_I[ch]
            ct_val = ct73_t[pos]
            if variant == 'beau':
                # PT = (KEY - CT) mod 26 => KEY = (PT + CT) mod 26
                pinned[pos] = (pt_val + ct_val) % 26
            elif variant == 'vig':
                # PT = (CT - KEY) mod 26 => KEY = (CT - PT) mod 26
                pinned[pos] = (ct_val - pt_val) % 26
            else:  # vbeau
                # PT = (CT + KEY) mod 26 => KEY = (PT - CT) mod 26
                pinned[pos] = (pt_val - ct_val) % 26

    free_pos = sorted(set(range(n)) - set(pinned.keys()))

    # Initialize key
    key = [0] * n
    for pos, val in pinned.items():
        key[pos] = val
    for pos in free_pos:
        key[pos] = rng.randint(0, 25)

    decrypt_fn = DECRYPT_FNS[variant]
    pt = decrypt_fn(ct73_t, key)
    _, best_qg = qg_score_arr(pt)
    cur_qg = best_qg
    best_key = key[:]
    best_pt = pt[:]

    T_start = 2.0
    T_end = 0.001
    log_ratio = math.log(T_end / T_start)

    for step in range(n_steps):
        T = T_start * math.exp(log_ratio * step / n_steps)

        # Only mutate free positions
        pos = free_pos[rng.randint(0, len(free_pos) - 1)]
        old_val = key[pos]
        new_val = (old_val + rng.randint(1, 25)) % 26
        key[pos] = new_val

        pt = decrypt_fn(ct73_t, key)
        _, new_qg = qg_score_arr(pt)

        delta = new_qg - cur_qg
        if delta > 0 or rng.random() < math.exp(delta / T):
            cur_qg = new_qg
            if new_qg > best_qg:
                best_qg = new_qg
                best_key = key[:]
                best_pt = pt[:]
        else:
            key[pos] = old_val

    pt_str = arr_to_str(best_pt)
    key_str = arr_to_str(best_key)
    crib_free, ene_pos, bcl_pos = check_cribs_in_pt(best_pt)
    crib_at_pos = check_cribs_at_positions(best_pt, shifted_t)

    # Check key for periodic structure
    key_ic = ic_from_arr(best_key)
    _, key_qg = qg_score_arr(best_key)

    return {
        'phase': 5,
        'restart': restart_id,
        'variant': variant,
        'trans': trans_name,
        'pt_qg_per_char': best_qg,
        'key_qg_per_char': key_qg,
        'pt_ic': ic_from_arr(best_pt),
        'key_ic': key_ic,
        'pt': pt_str[:50] + '...',
        'key': key_str[:50] + '...',
        'n_pinned': len(pinned),
        'n_free': len(free_pos),
        'crib_free': crib_free,
        'crib_at_pos': crib_at_pos,
        'ene_pos': ene_pos,
        'bcl_pos': bcl_pos,
    }


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════
def main():
    t0 = time.time()
    results = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'ct97': CT,
        'consensus_17': CONSENSUS_17,
        'phases': {},
    }

    # ── PHASE 1: Validate CT73 extraction ───────────────────────────────
    print("=" * 70, flush=True)
    print("PHASE 1: CT73 extraction validation", flush=True)
    print("=" * 70, flush=True)

    ct73_consensus = extract_ct73(CONSENSUS_17)
    ct73_str = arr_to_str(ct73_consensus)
    print(f"  CT73 (consensus 17 nulls removed): {ct73_str}", flush=True)
    print(f"  Length: {len(ct73_consensus)}", flush=True)
    print(f"  IC: {ic_from_arr(ct73_consensus):.4f}", flush=True)

    shifted = shifted_crib_positions(CONSENSUS_17)
    ene_shifted = [(p, c) for p, c in shifted if c in ENE_TEXT]
    bcl_shifted = [(p, c) for p, c in shifted if c in BCL_TEXT]
    print(f"  ENE shifted start: {ene_shifted[0][0]} (from {ENE_START})", flush=True)
    print(f"  BCL shifted start: {bcl_shifted[0][0]} (from {BCL_START})", flush=True)

    results['phases']['phase1'] = {
        'ct73': ct73_str,
        'ct73_len': len(ct73_consensus),
        'ct73_ic': ic_from_arr(ct73_consensus),
        'ene_shifted_start': ene_shifted[0][0],
        'bcl_shifted_start': bcl_shifted[0][0],
    }

    # ── PHASE 2: Periodic SA ────────────────────────────────────────────
    print("\n" + "=" * 70, flush=True)
    print("PHASE 2: Periodic polyalphabetic SA (quadgram objective)", flush=True)
    print("=" * 70, flush=True)

    # Generate a default mask for phases 2, 3, 5
    base_rng = random.Random(42)
    default_mask = random_mask_24(base_rng)
    print(f"  Default 24-null mask: {default_mask}", flush=True)
    print(f"  Extra 7: {sorted(set(default_mask) - set(CONSENSUS_17))}", flush=True)

    # Build task list: periods 2-20 x 3 variants x 3 transpositions x N restarts
    N_RESTARTS_P2 = 30  # Per (period, variant, trans) combo
    N_STEPS_P2 = 80000

    # Use 3 different masks per restart batch to reduce mask dependency
    masks_p2 = [default_mask]
    for i in range(2):
        masks_p2.append(random_mask_24(random.Random(100 + i)))

    tasks_p2 = []
    for period in range(2, 21):
        for variant in ['beau', 'vig', 'vbeau']:
            for trans_name in ['none', 'col7', 'col6']:
                for r in range(N_RESTARTS_P2):
                    mask = masks_p2[r % len(masks_p2)]
                    seed = period * 100000 + hash((variant, trans_name)) % 10000 + r
                    tasks_p2.append((r, period, variant, trans_name, mask, N_STEPS_P2, seed))

    print(f"  Phase 2 tasks: {len(tasks_p2)} "
          f"(periods 2-20 x 3 variants x 3 trans x {N_RESTARTS_P2} restarts)", flush=True)
    print(f"  Steps per restart: {N_STEPS_P2}", flush=True)

    t2 = time.time()
    with Pool(N_WORKERS) as pool:
        p2_results = pool.map(phase2_worker, tasks_p2)
    t2_elapsed = time.time() - t2

    # Analyze phase 2
    p2_by_config = {}
    for r in p2_results:
        config_key = f"p{r['period']}:{r['variant']}:{r['trans']}"
        if config_key not in p2_by_config:
            p2_by_config[config_key] = []
        p2_by_config[config_key].append(r)

    # Sort by best qg per config
    p2_sorted = sorted(p2_by_config.items(), key=lambda x: max(r['qg_per_char'] for r in x[1]), reverse=True)

    print(f"\n  Phase 2 completed in {t2_elapsed:.1f}s", flush=True)
    print(f"  Top 20 configurations by best qg/char:", flush=True)
    p2_top = []
    for config, runs in p2_sorted[:20]:
        best_run = max(runs, key=lambda r: r['qg_per_char'])
        avg_qg = sum(r['qg_per_char'] for r in runs) / len(runs)
        any_cribs = any(r['crib_free'] > 0 for r in runs)
        print(f"    {config}: best={best_run['qg_per_char']:.3f} "
              f"avg={avg_qg:.3f} IC={best_run['ic']:.4f} "
              f"cribs={best_run['crib_free']} key={best_run['key'][:20]}... "
              f"PT={best_run['pt'][:30]}...", flush=True)
        p2_top.append({
            'config': config,
            'best_qg': best_run['qg_per_char'],
            'avg_qg': avg_qg,
            'best_ic': best_run['ic'],
            'best_pt': best_run['pt'],
            'best_key': best_run['key'],
            'crib_free': best_run['crib_free'],
            'any_cribs_found': any_cribs,
        })

    # Check for any crib hits
    p2_crib_hits = [r for r in p2_results if r['crib_free'] > 0]
    if p2_crib_hits:
        print(f"\n  *** CRIB HITS IN PHASE 2: {len(p2_crib_hits)} ***", flush=True)
        for r in p2_crib_hits[:10]:
            print(f"    {r}", flush=True)
    else:
        print(f"\n  No crib hits in phase 2.", flush=True)

    results['phases']['phase2'] = {
        'n_tasks': len(tasks_p2),
        'elapsed_s': t2_elapsed,
        'top_configs': p2_top,
        'n_crib_hits': len(p2_crib_hits),
        'crib_hits': p2_crib_hits[:20] if p2_crib_hits else [],
        'global_best_qg': p2_sorted[0][1][0]['qg_per_char'] if p2_sorted else None,
    }

    # ── PHASE 3: Long-key SA ───────────────────────────────────────────
    print("\n" + "=" * 70, flush=True)
    print("PHASE 3: Long-key SA (73-letter key, quadgram objective)", flush=True)
    print("=" * 70, flush=True)

    N_RESTARTS_P3 = 30
    N_STEPS_P3 = 200000  # More steps because 73 DOF

    tasks_p3 = []
    for variant in ['beau', 'vig', 'vbeau']:
        for trans_name in ['none', 'col7', 'col6']:
            for r in range(N_RESTARTS_P3):
                mask = masks_p2[r % len(masks_p2)]
                seed = 300000 + hash((variant, trans_name)) % 10000 + r * 17
                tasks_p3.append((r, variant, trans_name, mask, N_STEPS_P3, seed))

    print(f"  Phase 3 tasks: {len(tasks_p3)} "
          f"(3 variants x 3 trans x {N_RESTARTS_P3} restarts)", flush=True)
    print(f"  Steps per restart: {N_STEPS_P3}", flush=True)

    t3 = time.time()
    with Pool(N_WORKERS) as pool:
        p3_results = pool.map(phase3_worker, tasks_p3)
    t3_elapsed = time.time() - t3

    p3_by_config = {}
    for r in p3_results:
        config_key = f"73key:{r['variant']}:{r['trans']}"
        if config_key not in p3_by_config:
            p3_by_config[config_key] = []
        p3_by_config[config_key].append(r)

    p3_sorted = sorted(p3_by_config.items(), key=lambda x: max(r['qg_per_char'] for r in x[1]), reverse=True)

    print(f"\n  Phase 3 completed in {t3_elapsed:.1f}s", flush=True)
    print(f"  All configurations by best qg/char:", flush=True)
    p3_top = []
    for config, runs in p3_sorted:
        best_run = max(runs, key=lambda r: r['qg_per_char'])
        avg_qg = sum(r['qg_per_char'] for r in runs) / len(runs)
        any_cribs = any(r['crib_free'] > 0 for r in runs)
        print(f"    {config}: best={best_run['qg_per_char']:.3f} "
              f"avg={avg_qg:.3f} IC={best_run['ic']:.4f} "
              f"cribs={best_run['crib_free']} "
              f"PT={best_run['pt'][:30]}...", flush=True)
        p3_top.append({
            'config': config,
            'best_qg': best_run['qg_per_char'],
            'avg_qg': avg_qg,
            'best_ic': best_run['ic'],
            'best_pt': best_run['pt'],
            'best_key': best_run['key'],
            'crib_free': best_run['crib_free'],
            'any_cribs_found': any_cribs,
        })

    p3_crib_hits = [r for r in p3_results if r['crib_free'] > 0]
    if p3_crib_hits:
        print(f"\n  *** CRIB HITS IN PHASE 3: {len(p3_crib_hits)} ***", flush=True)
        for r in p3_crib_hits[:10]:
            print(f"    {r}", flush=True)
    else:
        print(f"\n  No crib hits in phase 3.", flush=True)

    results['phases']['phase3'] = {
        'n_tasks': len(tasks_p3),
        'elapsed_s': t3_elapsed,
        'top_configs': p3_top,
        'n_crib_hits': len(p3_crib_hits),
        'crib_hits': p3_crib_hits[:20] if p3_crib_hits else [],
    }

    # ── PHASE 4: Joint mask + key SA ───────────────────────────────────
    print("\n" + "=" * 70, flush=True)
    print("PHASE 4: Joint mask + key SA", flush=True)
    print("=" * 70, flush=True)

    N_RESTARTS_P4 = 50
    N_STEPS_P4 = 200000

    # Focus on promising periods + long key
    p4_periods = [7, 8, 13, 73]

    tasks_p4 = []
    for period in p4_periods:
        for variant in ['beau', 'vig']:  # Skip vbeau to save time
            for trans_name in ['col7', 'none']:  # Focus on col7 and none
                for r in range(N_RESTARTS_P4):
                    seed = 400000 + period * 1000 + hash((variant, trans_name)) % 1000 + r
                    tasks_p4.append((r, period, variant, trans_name, N_STEPS_P4, seed))

    print(f"  Phase 4 tasks: {len(tasks_p4)} "
          f"(periods {p4_periods} x 2 variants x 2 trans x {N_RESTARTS_P4} restarts)", flush=True)
    print(f"  Steps per restart: {N_STEPS_P4}", flush=True)

    t4 = time.time()
    with Pool(N_WORKERS) as pool:
        p4_results = pool.map(phase4_worker, tasks_p4)
    t4_elapsed = time.time() - t4

    p4_by_config = {}
    for r in p4_results:
        config_key = f"joint_p{r['period']}:{r['variant']}:{r['trans']}"
        if config_key not in p4_by_config:
            p4_by_config[config_key] = []
        p4_by_config[config_key].append(r)

    p4_sorted = sorted(p4_by_config.items(), key=lambda x: max(r['qg_per_char'] for r in x[1]), reverse=True)

    print(f"\n  Phase 4 completed in {t4_elapsed:.1f}s", flush=True)
    print(f"  Top configurations by best qg/char:", flush=True)
    p4_top = []
    for config, runs in p4_sorted[:20]:
        best_run = max(runs, key=lambda r: r['qg_per_char'])
        avg_qg = sum(r['qg_per_char'] for r in runs) / len(runs)
        any_cribs = any(r['crib_free'] > 0 or r['crib_at_pos'] > 10 for r in runs)
        print(f"    {config}: best={best_run['qg_per_char']:.3f} "
              f"avg={avg_qg:.3f} IC={best_run['ic']:.4f} "
              f"crib_free={best_run['crib_free']} crib_pos={best_run['crib_at_pos']} "
              f"PT={best_run['pt'][:30]}...", flush=True)
        p4_top.append({
            'config': config,
            'best_qg': best_run['qg_per_char'],
            'avg_qg': avg_qg,
            'best_ic': best_run['ic'],
            'best_pt': best_run['pt'],
            'best_key': best_run['key'],
            'best_mask_extra': best_run['mask_extra'],
            'crib_free': best_run['crib_free'],
            'crib_at_pos': best_run['crib_at_pos'],
            'any_cribs_found': any_cribs,
        })

    p4_crib_hits = [r for r in p4_results if r['crib_free'] > 0 or r.get('crib_at_pos', 0) > 15]
    if p4_crib_hits:
        print(f"\n  *** HIGH CRIB SCORES IN PHASE 4: {len(p4_crib_hits)} ***", flush=True)
        for r in sorted(p4_crib_hits, key=lambda x: x.get('crib_at_pos', 0) + x['crib_free'], reverse=True)[:10]:
            print(f"    {r}", flush=True)
    else:
        print(f"\n  No crib hits in phase 4.", flush=True)

    results['phases']['phase4'] = {
        'n_tasks': len(tasks_p4),
        'elapsed_s': t4_elapsed,
        'top_configs': p4_top,
        'n_crib_hits': len(p4_crib_hits),
        'crib_hits': [r for r in sorted(p4_crib_hits, key=lambda x: x.get('crib_at_pos', 0), reverse=True)[:20]] if p4_crib_hits else [],
    }

    # ── PHASE 5: Anchored quadgram extension ───────────────────────────
    print("\n" + "=" * 70, flush=True)
    print("PHASE 5: Known-plaintext anchored quadgram extension", flush=True)
    print("=" * 70, flush=True)

    N_RESTARTS_P5 = 50
    N_STEPS_P5 = 150000

    # Use 5 different masks
    masks_p5 = [default_mask]
    for i in range(4):
        masks_p5.append(random_mask_24(random.Random(500 + i)))

    tasks_p5 = []
    for variant in ['beau', 'vig', 'vbeau']:
        for trans_name in ['none', 'col7', 'col6']:
            for r in range(N_RESTARTS_P5):
                mask = masks_p5[r % len(masks_p5)]
                seed = 500000 + hash((variant, trans_name)) % 10000 + r * 31
                tasks_p5.append((r, variant, trans_name, mask, N_STEPS_P5, seed))

    print(f"  Phase 5 tasks: {len(tasks_p5)} "
          f"(3 variants x 3 trans x {N_RESTARTS_P5} restarts)", flush=True)
    print(f"  Steps per restart: {N_STEPS_P5}", flush=True)

    t5 = time.time()
    with Pool(N_WORKERS) as pool:
        p5_results = pool.map(phase5_worker, tasks_p5)
    t5_elapsed = time.time() - t5

    p5_by_config = {}
    for r in p5_results:
        config_key = f"anchored:{r['variant']}:{r['trans']}"
        if config_key not in p5_by_config:
            p5_by_config[config_key] = []
        p5_by_config[config_key].append(r)

    p5_sorted = sorted(p5_by_config.items(), key=lambda x: max(r['pt_qg_per_char'] for r in x[1]), reverse=True)

    print(f"\n  Phase 5 completed in {t5_elapsed:.1f}s", flush=True)
    print(f"  All configurations by best PT qg/char:", flush=True)
    p5_top = []
    for config, runs in p5_sorted:
        best_run = max(runs, key=lambda r: r['pt_qg_per_char'])
        avg_qg = sum(r['pt_qg_per_char'] for r in runs) / len(runs)
        avg_key_qg = sum(r['key_qg_per_char'] for r in runs) / len(runs)
        any_cribs = any(r['crib_free'] > 0 for r in runs)
        print(f"    {config}: best_pt={best_run['pt_qg_per_char']:.3f} "
              f"avg_pt={avg_qg:.3f} best_key={best_run['key_qg_per_char']:.3f} "
              f"avg_key={avg_key_qg:.3f} "
              f"IC_pt={best_run['pt_ic']:.4f} IC_key={best_run['key_ic']:.4f} "
              f"crib_pos={best_run['crib_at_pos']}/{best_run['n_pinned']} "
              f"PT={best_run['pt'][:30]}...", flush=True)
        p5_top.append({
            'config': config,
            'best_pt_qg': best_run['pt_qg_per_char'],
            'avg_pt_qg': avg_qg,
            'best_key_qg': best_run['key_qg_per_char'],
            'avg_key_qg': avg_key_qg,
            'best_pt_ic': best_run['pt_ic'],
            'best_key_ic': best_run['key_ic'],
            'best_pt': best_run['pt'],
            'best_key': best_run['key'],
            'n_pinned': best_run['n_pinned'],
            'crib_free': best_run['crib_free'],
            'crib_at_pos': best_run['crib_at_pos'],
            'any_cribs_found': any_cribs,
        })

    # Analyze anti-correlation
    print(f"\n  Anti-correlation analysis (key qg vs pt qg):", flush=True)
    for config, runs in p5_sorted[:5]:
        pt_qgs = [r['pt_qg_per_char'] for r in runs]
        key_qgs = [r['key_qg_per_char'] for r in runs]
        n = len(pt_qgs)
        mean_pt = sum(pt_qgs) / n
        mean_key = sum(key_qgs) / n
        cov = sum((p - mean_pt) * (k - mean_key) for p, k in zip(pt_qgs, key_qgs)) / n
        std_pt = (sum((p - mean_pt)**2 for p in pt_qgs) / n) ** 0.5
        std_key = (sum((k - mean_key)**2 for k in key_qgs) / n) ** 0.5
        corr = cov / (std_pt * std_key + 1e-12)
        print(f"    {config}: corr(pt_qg, key_qg) = {corr:.3f} "
              f"(positive = running key possible, negative = anti-correlation)", flush=True)

    p5_crib_hits = [r for r in p5_results if r['crib_free'] > 0]

    results['phases']['phase5'] = {
        'n_tasks': len(tasks_p5),
        'elapsed_s': t5_elapsed,
        'top_configs': p5_top,
        'n_crib_hits': len(p5_crib_hits),
        'crib_hits': p5_crib_hits[:20] if p5_crib_hits else [],
    }

    # ── SUMMARY ────────────────────────────────────────────────────────
    total_elapsed = time.time() - t0
    total_tasks = len(tasks_p2) + len(tasks_p3) + len(tasks_p4) + len(tasks_p5)

    print("\n" + "=" * 70, flush=True)
    print("SUMMARY", flush=True)
    print("=" * 70, flush=True)
    print(f"  Total tasks: {total_tasks}", flush=True)
    print(f"  Total time: {total_elapsed:.1f}s ({total_elapsed/60:.1f} min)", flush=True)
    print(f"  Phase 2 (periodic): {t2_elapsed:.1f}s, {len(tasks_p2)} tasks, "
          f"best qg={p2_sorted[0][1][0]['qg_per_char']:.3f}" if p2_sorted else "", flush=True)
    print(f"  Phase 3 (long key): {t3_elapsed:.1f}s, {len(tasks_p3)} tasks, "
          f"best qg={p3_sorted[0][1][0]['qg_per_char']:.3f}" if p3_sorted else "", flush=True)
    print(f"  Phase 4 (joint):    {t4_elapsed:.1f}s, {len(tasks_p4)} tasks", flush=True)
    print(f"  Phase 5 (anchored): {t5_elapsed:.1f}s, {len(tasks_p5)} tasks", flush=True)

    # Find global best across all phases
    all_results = p2_results + p3_results + p4_results + p5_results
    qg_key = lambda r: r.get('qg_per_char', r.get('pt_qg_per_char', -99))
    global_best = max(all_results, key=qg_key)
    print(f"\n  Global best qg/char: {qg_key(global_best):.3f}", flush=True)
    print(f"  From phase {global_best['phase']}", flush=True)
    print(f"  Details: {global_best}", flush=True)

    # Count all crib hits
    total_crib_hits = sum(1 for r in all_results if r.get('crib_free', 0) > 0)
    print(f"\n  Total tasks with free crib matches: {total_crib_hits}/{total_tasks}", flush=True)

    # Verdict
    english_threshold = -4.5
    best_qg = qg_key(global_best)
    if best_qg > english_threshold:
        print(f"\n  *** ABOVE ENGLISH THRESHOLD ({english_threshold}) -- INVESTIGATE ***", flush=True)
        results['verdict'] = 'INVESTIGATE'
    elif best_qg > -5.0:
        print(f"\n  Near-English range ({best_qg:.3f}). Worth examining but likely false positive.", flush=True)
        results['verdict'] = 'MARGINAL'
    else:
        print(f"\n  Below threshold ({best_qg:.3f} < {english_threshold}). "
              f"Consistent with noise.", flush=True)
        results['verdict'] = 'NOISE'

    results['total_elapsed_s'] = total_elapsed
    results['total_tasks'] = total_tasks
    results['global_best_qg'] = best_qg
    results['global_best'] = {k: v for k, v in global_best.items() if not isinstance(v, list) or len(v) < 50}

    # Save results
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'results', 'fresh_mcmc_attack.json')
    with open(out_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n  Results saved to {out_path}", flush=True)

    return results


if __name__ == '__main__':
    main()
