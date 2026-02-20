#!/usr/bin/env python3
"""E-S-146: Anomaly-derived width-7 transposition keys with running key SA.

Tests the hypothesis that deliberate anomalies in K0/K1 encode a width-7
columnar transposition key. Missing letters from misspellings:
  DIGETAL (missing I), INTERPRETATIT (missing O,N), WHAT→T IS YOUR POSITION
  (missing W,H,A), IQLUSION (missing L)

Missing letters in phrase order: I,O,N,W,H,A,L → numeric: 8,14,13,22,7,0,11
Ranked: [2,5,4,6,1,0,3]

Three orderings produce different permutations:
  1. DIGETAL, INTERPRETATIT, WHAT, IQLUSION: [2,5,4,6,1,0,3]
  2. WHAT, DIGETAL, INTERPRETATIT, IQLUSION: [6,1,0,2,5,4,3]
  3. IQLUSION, DIGETAL, INTERPRETATIT, WHAT: [3,2,5,4,6,1,0]

For each ordering + its inverse (6 keys total), test:
  - Width-7 columnar transposition applied to CT
  - SA-optimized running key under Vigenere/Beaufort/Variant Beaufort
  - 500K SA iterations, 3 restarts per config

Width-7 is Bean-IMPOSSIBLE with periodic key, but compatible with running key.

Output: artifacts/e_s_146/
Repro: PYTHONPATH=src python3 -u scripts/e_s_146_anomaly_w7_transposition.py
"""

import json
import math
import os
import random
import sys
import time
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_ENTRIES, CRIB_DICT, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
    NOISE_FLOOR, SIGNAL_THRESHOLD,
)

# ── Constants ────────────────────────────────────────────────────────────────

CT_NUM = [ALPH_IDX[c] for c in CT]
N = CT_LEN  # 97
WIDTH = 7
NROWS = math.ceil(N / WIDTH)  # 14
FULL_COLS = N % WIDTH  # 97 % 7 = 6 (last row has 6 cols filled)

# Load quadgrams
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QG_PATH = os.path.join(REPO_ROOT, "data", "english_quadgrams.json")
with open(QG_PATH) as f:
    QUADGRAMS = json.load(f)
QG_FLOOR = min(QUADGRAMS.values())

# Cribs as dict {pos: pt_char_index}
EXISTING_CRIBS = {pos: ALPH_IDX[ch] for pos, ch in CRIB_ENTRIES}

# Bean constraints
BEAN_EQ_POS = BEAN_EQ[0]  # (27, 65)

# SA parameters
SA_ITERATIONS = 500_000
SA_RESTARTS = 3
T_START = 2.0
T_END = 0.005
SEED_BASE = 20260220

# ── Transposition Keys ──────────────────────────────────────────────────────

# The three orderings of the anomaly-derived letters
ORDERINGS = {
    "anomaly_order_1": {
        "description": "DIGETAL,INTERPRETATIT,WHAT,IQLUSION → I,O,N,W,H,A,L",
        "col_order": [2, 5, 4, 6, 1, 0, 3],
    },
    "anomaly_order_2": {
        "description": "WHAT,DIGETAL,INTERPRETATIT,IQLUSION → W,H,A,I,O,N,L",
        "col_order": [6, 1, 0, 2, 5, 4, 3],
    },
    "anomaly_order_3": {
        "description": "IQLUSION,DIGETAL,INTERPRETATIT,WHAT → L,I,O,N,W,H,A",
        "col_order": [3, 2, 5, 4, 6, 1, 0],
    },
}


def columnar_transposition_perm(width, col_order, length):
    """Build columnar transposition permutation.

    Write plaintext into rows of `width`, read off columns in `col_order`.
    Returns perm where output[i] = input[perm[i]] (gather convention).

    col_order[c] = rank of column c (0 = first column read out).
    """
    nrows = math.ceil(length / width)
    full_cols = length % width  # number of columns that have nrows entries
    if full_cols == 0:
        full_cols = width  # all columns full

    # Build columns: col c contains positions c, c+width, c+2*width, ...
    cols = defaultdict(list)
    for pos in range(length):
        r, c = divmod(pos, width)
        cols[c].append(pos)

    # Read off in column order (rank 0 first, rank 1 next, ...)
    perm = []
    for rank in range(width):
        # Find which column has this rank
        col_idx = col_order.index(rank)
        perm.extend(cols[col_idx])

    assert len(perm) == length, f"Perm length {len(perm)} != {length}"
    assert set(perm) == set(range(length)), "Invalid permutation"
    return perm


def invert_perm(perm):
    """Compute inverse permutation."""
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def apply_perm(text, perm):
    """Apply permutation: output[i] = text[perm[i]]."""
    return "".join(text[p] for p in perm)


def qg_score_text(text):
    """Quadgram score for a text string."""
    score = 0.0
    for i in range(len(text) - 3):
        qg = text[i:i + 4]
        score += QUADGRAMS.get(qg, QG_FLOOR)
    return score


def nums_to_text(nums):
    return ''.join(ALPH[n % 26] for n in nums)


# ── Cipher variant operations ───────────────────────────────────────────────

def decrypt_vig(c, k):
    """Vigenere decrypt: P = (C - K) mod 26"""
    return (c - k) % MOD

def decrypt_beau(c, k):
    """Beaufort decrypt: P = (K - C) mod 26"""
    return (k - c) % MOD

def decrypt_varbeau(c, k):
    """Variant Beaufort decrypt: P = (C + K) mod 26"""
    return (c + k) % MOD

def recover_vig(c, p):
    """Vigenere key recovery: K = (C - P) mod 26"""
    return (c - p) % MOD

def recover_beau(c, p):
    """Beaufort key recovery: K = (C + P) mod 26"""
    return (c + p) % MOD

def recover_varbeau(c, p):
    """Variant Beaufort key recovery: K = (P - C) mod 26"""
    return (p - c) % MOD


VARIANTS = {
    "vigenere": (decrypt_vig, recover_vig),
    "beaufort": (decrypt_beau, recover_beau),
    "var_beaufort": (decrypt_varbeau, recover_varbeau),
}


# ── SA: Running Key Search ──────────────────────────────────────────────────

def sa_running_key(transposed_ct_num, crib_map, variant_name, seed):
    """SA to find a running key that decrypts transposed_ct to English.

    Args:
        transposed_ct_num: list of ints, the transposed ciphertext (numeric)
        crib_map: dict {position_in_transposed_ct: plaintext_char_index}
                  These are the crib constraints AFTER transposition.
        variant_name: 'vigenere', 'beaufort', or 'var_beaufort'
        seed: random seed

    Returns: dict with best results
    """
    random.seed(seed)
    decrypt_fn, recover_fn = VARIANTS[variant_name]

    n = len(transposed_ct_num)
    fixed_positions = set(crib_map.keys())
    free_positions = sorted(set(range(n)) - fixed_positions)

    # Initialize key: at crib positions, key is determined
    key = [0] * n
    for pos, pt_val in crib_map.items():
        key[pos] = recover_fn(transposed_ct_num[pos], pt_val)

    # At free positions, start with random key
    for pos in free_positions:
        key[pos] = random.randint(0, 25)

    # Compute initial plaintext
    pt = [decrypt_fn(transposed_ct_num[i], key[i]) for i in range(n)]
    pt_text = nums_to_text(pt)
    current_score = qg_score_text(pt_text)

    best_score = current_score
    best_key = key[:]
    best_pt = pt_text
    accepted = 0

    for step in range(SA_ITERATIONS):
        T = T_START * (T_END / T_START) ** (step / SA_ITERATIONS)

        # Mutate: change one free position's key value
        pos = random.choice(free_positions)
        old_key_val = key[pos]
        new_key_val = (old_key_val + random.randint(1, 25)) % 26
        key[pos] = new_key_val

        # Compute new plaintext at this position
        old_pt_val = pt[pos]
        new_pt_val = decrypt_fn(transposed_ct_num[pos], new_key_val)
        pt[pos] = new_pt_val

        # Incremental quadgram score update
        # Only quadgrams overlapping position `pos` change
        # Positions affected: max(0, pos-3) to min(n-4, pos)
        lo = max(0, pos - 3)
        hi = min(n - 4, pos)

        old_delta = 0.0
        new_delta = 0.0
        pt_text_list = list(pt_text)
        new_ch = ALPH[new_pt_val]

        for i in range(lo, hi + 1):
            old_qg = pt_text[i:i + 4]
            old_delta += QUADGRAMS.get(old_qg, QG_FLOOR)

        pt_text_list[pos] = new_ch
        new_pt_text = ''.join(pt_text_list)

        for i in range(lo, hi + 1):
            new_qg = new_pt_text[i:i + 4]
            new_delta += QUADGRAMS.get(new_qg, QG_FLOOR)

        delta = new_delta - old_delta

        if delta > 0 or (T > 0 and random.random() < math.exp(delta / T)):
            current_score += delta
            pt_text = new_pt_text
            accepted += 1
            if current_score > best_score:
                best_score = current_score
                best_key = key[:]
                best_pt = pt_text
        else:
            # Revert
            key[pos] = old_key_val
            pt[pos] = old_pt_val

    # Verify crib satisfaction
    crib_matches = 0
    for pos, expected_pt in crib_map.items():
        actual_pt = decrypt_fn(transposed_ct_num[pos], best_key[pos])
        if actual_pt == expected_pt:
            crib_matches += 1

    return {
        'best_score': best_score,
        'best_qg_per_char': best_score / max(n - 3, 1),
        'best_pt': best_pt,
        'best_key': nums_to_text(best_key),
        'crib_matches': crib_matches,
        'crib_total': len(crib_map),
        'accepted_rate': accepted / SA_ITERATIONS,
    }


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    t0 = time.time()

    print("=" * 70)
    print("E-S-146: Anomaly-derived Width-7 Transposition Keys + Running Key SA")
    print("=" * 70)
    print(f"CT: {CT}")
    print(f"Length: {N}, Width: {WIDTH}, Rows: {NROWS}")
    print(f"SA: {SA_ITERATIONS:,} iterations x {SA_RESTARTS} restarts, T={T_START}->{T_END}")
    print(f"Seed base: {SEED_BASE}")
    print()

    # Create output directory
    os.makedirs(os.path.join(REPO_ROOT, "artifacts", "e_s_146"), exist_ok=True)

    # ── Phase 1: Build transposition permutations ────────────────────────────

    all_keys = {}
    for name, info in ORDERINGS.items():
        col_order = info["col_order"]
        perm = columnar_transposition_perm(WIDTH, col_order, N)
        inv = invert_perm(perm)

        all_keys[name] = {
            "description": info["description"],
            "col_order": col_order,
            "perm": perm,
            "direction": "forward",
        }
        all_keys[name + "_inv"] = {
            "description": info["description"] + " (inverse)",
            "col_order": col_order,
            "perm": inv,
            "direction": "inverse",
        }

    print(f"Testing {len(all_keys)} transposition keys x {len(VARIANTS)} cipher variants "
          f"= {len(all_keys) * len(VARIANTS)} configurations\n")

    # ── Phase 2: For each key, apply transposition and run SA ────────────────

    all_results = {}
    global_best_score = float('-inf')
    global_best_config = None

    for key_name, key_info in all_keys.items():
        perm = key_info["perm"]
        direction = key_info["direction"]

        # Apply transposition to CT
        transposed_ct = apply_perm(CT, perm)
        transposed_ct_num = [ALPH_IDX[c] for c in transposed_ct]

        # Map crib positions through the permutation
        # If perm is the encryption permutation (CT = apply_perm(intermediate, perm)),
        # then to reverse: intermediate[perm[i]] = CT[i], or intermediate = apply_perm(CT, inv(perm))
        #
        # Model: Sanborn wrote plaintext, applied transposition to get intermediate,
        # then applied substitution to get CT.
        # CT[i] = Encrypt(intermediate[i], key[i])
        # intermediate = apply_perm(plaintext, sigma)  i.e. intermediate[i] = plaintext[sigma[i]]
        #
        # To decrypt: intermediate[i] = Decrypt(CT[i], key[i])
        #             plaintext[sigma[i]] = intermediate[i]
        #             plaintext = apply_perm(intermediate, inv(sigma))
        #
        # But we're searching for the key. We apply inv(sigma) to CT first:
        # apply_perm(CT, inv(sigma))[i] = CT[inv(sigma)[i]]
        # Then decrypt this with the key...
        #
        # Actually, let's think about this more carefully.
        #
        # Encryption: PT -> transposition sigma -> intermediate -> substitution with key -> CT
        # intermediate[i] = PT[sigma[i]]
        # CT[i] = Enc(intermediate[i], K[i]) = Enc(PT[sigma[i]], K[i])
        #
        # Decryption: CT -> substitution decrypt with key -> intermediate -> inv(sigma) -> PT
        # intermediate[i] = Dec(CT[i], K[i])
        # PT[sigma[i]] = intermediate[i]
        # PT[j] = intermediate[sigma_inv[j]]
        #
        # Our cribs say PT[21]='E', PT[22]='A', etc.
        # So: intermediate[sigma_inv[21]] = Dec(CT[sigma_inv[21]], K[sigma_inv[21]]) must decrypt to 'E'
        #
        # Alternative model: substitution first, then transposition
        # encrypted_sub[i] = Enc(PT[i], K[i])
        # CT[sigma[i]] = encrypted_sub[i]
        # CT = apply_perm(encrypted_sub, sigma)  -- but this uses scatter convention
        #
        # With gather: CT[i] = encrypted_sub[sigma_inv[i]]
        # So: encrypted_sub[j] = CT[sigma[j]]
        # And: Enc(PT[j], K[j]) = CT[sigma[j]]
        # So: PT[j] = Dec(CT[sigma[j]], K[j])
        #
        # For our approach, we test BOTH models:
        # Model A: transposition then substitution (trans-sub)
        #   CT[i] = Enc(PT[sigma[i]], K[i])
        #   Cribs: PT[p] is known → CT[sigma_inv[p]] = Enc(PT[p], K[sigma_inv[p]])
        #   So at position sigma_inv[p] in CT, we know the plaintext is PT[p]
        #   After applying the transposition perm to CT: transposed[i] = CT[perm[i]]
        #   ... this doesn't directly give us PT.
        #
        # Model B: substitution then transposition (sub-trans)
        #   Enc(PT[j], K[j]) = CT[sigma[j]]  (using gather on CT gives encrypted_sub)
        #   PT[j] = Dec(CT[sigma[j]], K[j])
        #   Cribs: PT[p] is known, so K[p] = Recover(CT[sigma[p]], PT[p])
        #   This is simpler! Rearrange CT with sigma, then decrypt position-by-position.
        #
        # Let's use Model B (sub then trans), which means:
        # rearranged_ct[j] = CT[sigma[j]] = apply_perm(CT, sigma)
        # PT[j] = Dec(rearranged_ct[j], K[j])
        # Cribs at positions p: K[p] = Recover(rearranged_ct[p], PT[p])

        # For Model B: rearranged CT using this perm
        # We already computed transposed_ct = apply_perm(CT, perm)
        # Cribs map directly: position p in plaintext → position p in rearranged CT

        # Build crib map for the rearranged CT (same positions as original cribs)
        crib_map_direct = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

        print(f"\n{'='*70}")
        print(f"Key: {key_name} ({direction})")
        print(f"  {key_info['description']}")
        print(f"  Col order: {key_info['col_order']}")
        print(f"  Transposed CT: {transposed_ct[:30]}...{transposed_ct[-20:]}")

        # Quick check: how many original cribs survive after transposition?
        # (i.e., does transposed_ct[p] == CT[p] for crib positions?)
        direct_matches = sum(1 for p in CRIB_DICT if transposed_ct[p] == CT[p])
        print(f"  CT positions unchanged at crib sites: {direct_matches}/{N_CRIBS}")

        key_results = {}

        for variant_name in VARIANTS:
            print(f"\n  --- {variant_name} ---")
            variant_results = []
            best_for_variant = float('-inf')
            best_pt_for_variant = None
            best_key_for_variant = None

            for restart in range(SA_RESTARTS):
                seed = SEED_BASE + hash(key_name) % 100000 + hash(variant_name) % 10000 + restart * 137

                result = sa_running_key(
                    transposed_ct_num, crib_map_direct, variant_name, seed
                )

                variant_results.append({
                    'restart': restart + 1,
                    'score': result['best_score'],
                    'qg_per_char': result['best_qg_per_char'],
                    'crib_matches': result['crib_matches'],
                    'accepted_rate': result['accepted_rate'],
                })

                if result['best_score'] > best_for_variant:
                    best_for_variant = result['best_score']
                    best_pt_for_variant = result['best_pt']
                    best_key_for_variant = result['best_key']

                print(f"    Restart {restart+1}: qg/c={result['best_qg_per_char']:.3f} "
                      f"cribs={result['crib_matches']}/{result['crib_total']} "
                      f"accept={result['accepted_rate']:.1%}")

            best_r = max(variant_results, key=lambda r: r['score'])
            print(f"    BEST: qg/c={best_r['qg_per_char']:.3f} "
                  f"cribs={best_r['crib_matches']}/{N_CRIBS}")

            if best_for_variant > -5.5 * (N - 3):
                # Show plaintext for interesting results
                print(f"    PT: {best_pt_for_variant}")

            key_results[variant_name] = {
                'best_score': best_r['score'],
                'best_qg_per_char': best_r['qg_per_char'],
                'best_crib_matches': best_r['crib_matches'],
                'best_pt': best_pt_for_variant,
                'best_key': best_key_for_variant,
                'restarts': variant_results,
            }

            if best_for_variant > global_best_score:
                global_best_score = best_for_variant
                global_best_config = f"{key_name}/{variant_name}"

        all_results[key_name] = {
            'description': key_info['description'],
            'col_order': key_info['col_order'],
            'direction': direction,
            'variants': key_results,
        }

    elapsed = time.time() - t0

    # ── Phase 3: Summary ────────────────────────────────────────────────────

    print(f"\n{'='*70}")
    print("SUMMARY: All Configurations")
    print(f"{'='*70}")
    print(f"{'Key':<28s} {'Variant':<14s} {'QG/char':>8s} {'Cribs':>6s}")
    print("-" * 60)

    for key_name, key_data in all_results.items():
        for variant_name, variant_data in key_data['variants'].items():
            qgc = variant_data['best_qg_per_char']
            cribs = variant_data['best_crib_matches']
            marker = " ***" if cribs >= SIGNAL_THRESHOLD else ""
            print(f"{key_name:<28s} {variant_name:<14s} {qgc:>8.3f} {cribs:>4d}/24{marker}")

    print(f"\nGlobal best: {global_best_config} (qg/c={global_best_score / max(N-3, 1):.3f})")
    print(f"Elapsed: {elapsed:.1f}s")

    # ── Interpretation ──────────────────────────────────────────────────────

    print(f"\nINTERPRETATION:")
    print(f"Baseline SA with 500K iterations on 97-char text typically achieves")
    print(f"qg/c around -6.0 to -6.5 (random-key territory). Values better than")
    print(f"-5.0 would be noteworthy. Crib satisfaction is guaranteed by construction")
    print(f"(crib positions have fixed keys), so crib_matches should always be 24/24.")
    print(f"The key discriminator is quadgram quality at NON-crib positions.")
    print(f"Only a result with qg/c > -4.84 AND semantic coherence would be a signal.")

    # Check if any result beats the noise threshold on qg/c
    any_signal = False
    for key_name, key_data in all_results.items():
        for variant_name, variant_data in key_data['variants'].items():
            if variant_data['best_qg_per_char'] > -5.0:
                any_signal = True
                print(f"\n  NOTABLE: {key_name}/{variant_name} achieved qg/c="
                      f"{variant_data['best_qg_per_char']:.3f}")
                print(f"  PT: {variant_data['best_pt']}")

    if not any_signal:
        print(f"\nNo configuration achieved qg/c > -5.0. All results are in the")
        print(f"noise range expected for SA with fixed cribs and random key.")
        print(f"VERDICT: Anomaly-derived width-7 keys show NO signal under running key SA.")

    # ── Save artifacts ──────────────────────────────────────────────────────

    artifact_dir = os.path.join(REPO_ROOT, "artifacts", "e_s_146")
    os.makedirs(artifact_dir, exist_ok=True)

    # Save detailed results (without full plaintext/key for compactness)
    summary_results = {}
    for key_name, key_data in all_results.items():
        summary_results[key_name] = {
            'description': key_data['description'],
            'col_order': key_data['col_order'],
            'direction': key_data['direction'],
            'variants': {},
        }
        for variant_name, variant_data in key_data['variants'].items():
            summary_results[key_name]['variants'][variant_name] = {
                'best_qg_per_char': variant_data['best_qg_per_char'],
                'best_crib_matches': variant_data['best_crib_matches'],
                'best_pt': variant_data['best_pt'],
                'restarts': variant_data['restarts'],
            }

    artifact = {
        "experiment_id": "e_s_146",
        "title": "Anomaly-derived width-7 transposition keys + running key SA",
        "sa_params": {
            "iterations": SA_ITERATIONS,
            "restarts": SA_RESTARTS,
            "t_start": T_START,
            "t_end": T_END,
            "seed_base": SEED_BASE,
        },
        "keys_tested": len(all_keys),
        "variants_tested": len(VARIANTS),
        "total_configs": len(all_keys) * len(VARIANTS),
        "global_best_config": global_best_config,
        "global_best_qg_per_char": global_best_score / max(N - 3, 1),
        "results": summary_results,
        "elapsed_seconds": elapsed,
        "verdict": "NOISE" if not any_signal else "INVESTIGATE",
        "repro_command": "PYTHONPATH=src python3 -u scripts/e_s_146_anomaly_w7_transposition.py",
    }

    out_path = os.path.join(artifact_dir, "e_s_146_results.json")
    with open(out_path, "w") as f:
        json.dump(artifact, f, indent=2, default=str)
    print(f"\nArtifact saved: {out_path}")


if __name__ == "__main__":
    main()
