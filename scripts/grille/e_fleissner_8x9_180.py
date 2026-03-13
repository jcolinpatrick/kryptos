#!/usr/bin/env python3
"""
Cipher: Fleissner 8x9 turning grille (180-degree)
Family: grille
Status: active
Keyspace: 2^36 grille × C(72,24) null masks (sampled)
Last run:
Best score:
"""
"""
E-FLEISSNER-8x9-180: Fleissner Turning Grille on 8×9 Grid

HYPOTHESIS: K4's plaintext is 72 characters (8 lines × 9 chars) + 1 terminal
marker. Either the first O or last R of the 97 carved chars is a delimiter
(like K3's terminal Q). Removing it leaves 96 chars. Removing 24 nulls
gives 72 = 8×9 — a clean rectangle for a 180° turning grille.

Model: PT(72) → Fleissner(8×9,180°) → intermediate(72) → substitution → 72-char CT
       → insert 24 nulls → 96 chars → add delimiter → 97 carved chars

The 180° turning grille on 8×9 has 36 position pairs: (r,c) ↔ (7-r, 8-c).
Each pair has a binary choice → 2^36 ≈ 68.7B configurations.

KEY INSIGHT: Crib-derived key values at carved positions are FIXED regardless
of the Fleissner. But the NULL MASK determines which residue class each crib
falls into in the 72-char text, potentially enabling periodic substitution
that was impossible on raw 97.

PHASES:
  P0: Grid mechanics and impossibility analysis
  P1: Null mask + periodic sub consistency search (SA)
  P2: Fleissner + keyword sub SA (quadgram optimization)
  P3: Joint null mask + Fleissner + sub SA
"""

import json
import math
import os
import random
import sys
import time
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, KRYPTOS_ALPHABET,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
)

# ── Quadgram loading ─────────────────────────────────────────────────────
QG_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'english_quadgrams.json')
print("Loading quadgrams...", flush=True)
with open(QG_PATH) as f:
    _qg_raw = json.load(f)
QG_FLOOR = -10.0
QG = {}
for quad, score in _qg_raw.items():
    if len(quad) == 4:
        QG[(ord(quad[0])-65, ord(quad[1])-65, ord(quad[2])-65, ord(quad[3])-65)] = score
del _qg_raw

def qg_score(nums):
    if len(nums) < 4:
        return QG_FLOOR
    total = sum(QG.get((nums[i], nums[i+1], nums[i+2], nums[i+3]), QG_FLOOR)
                for i in range(len(nums) - 3))
    return total / (len(nums) - 3)

# ── Constants ────────────────────────────────────────────────────────────
AZ = ALPH
AZ_IDX = ALPH_IDX
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}
CT_AZ = [AZ_IDX[c] for c in CT]
CRIB_AZ = {p: AZ_IDX[c] for p, c in CRIB_DICT.items()}
CRIB_SORTED = sorted(CRIB_DICT.keys())

# W positions in 97-char carved text
W_POSITIONS_97 = [i for i, c in enumerate(CT) if c == 'W']

# ── Delimiter models ─────────────────────────────────────────────────────
def make_model(name, ct_96, crib_shift):
    """Build a delimiter model: 96-char CT with shifted crib positions."""
    crib_map = {}  # carved position → crib letter (AZ index)
    for p, ch in CRIB_DICT.items():
        new_p = p + crib_shift
        if 0 <= new_p < 96:
            crib_map[new_p] = AZ_IDX[ch]
    ct_nums = [AZ_IDX[c] for c in ct_96]
    return {
        'name': name,
        'ct_96': ct_96,
        'ct_nums': ct_nums,
        'crib_map': crib_map,  # position in 96-char text → AZ index of PT
        'crib_positions': sorted(crib_map.keys()),
    }

MODEL_B = make_model("Remove last R", CT[:96], 0)      # cribs stay at 21-33, 63-73
MODEL_A = make_model("Remove first O", CT[1:97], -1)    # cribs shift to 20-32, 62-72

# ── 8×9 Fleissner mechanics ─────────────────────────────────────────────
ROWS, COLS = 8, 9
GRID_SIZE = ROWS * COLS  # 72

def build_pairs():
    """Build 36 rotation pairs for 180° turn on 8×9 grid."""
    pairs = []
    visited = set()
    for r in range(ROWS):
        for c in range(COLS):
            if (r, c) not in visited:
                partner = (7 - r, 8 - c)
                pairs.append(((r, c), partner))
                visited.add((r, c))
                visited.add(partner)
    return pairs

PAIRS = build_pairs()
N_PAIRS = len(PAIRS)
assert N_PAIRS == 36, f"Expected 36 pairs, got {N_PAIRS}"

# Precompute linear indices for pairs
PAIR_LINEAR = [
    (a[0] * COLS + a[1], b[0] * COLS + b[1])
    for a, b in PAIRS
]

def fleissner_perm(choices):
    """Build permutation from 36 binary choices.
    choices[i] = 0: hole at pair[i][0] in pass 0, pair[i][1] in pass 1
    choices[i] = 1: hole at pair[i][1] in pass 0, pair[i][0] in pass 1
    Returns: list of 72 linear indices in reading order.
    """
    pass0 = []
    pass1 = []
    for i in range(N_PAIRS):
        a, b = PAIR_LINEAR[i]
        if choices[i] == 0:
            pass0.append(a)
            pass1.append(b)
        else:
            pass0.append(b)
            pass1.append(a)
    pass0.sort()  # row-major reading order
    pass1.sort()
    return pass0 + pass1

def apply_perm(text_72, perm):
    """Apply Fleissner permutation: PT[i] = text_72[perm[i]]."""
    return [text_72[perm[i]] for i in range(72)]

def invert_perm(perm):
    """Compute inverse permutation."""
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

# ── Null mask utilities ──────────────────────────────────────────────────
def extract_real_ct(ct_96_nums, null_positions):
    """Remove null positions from 96-char CT to get 72 real chars."""
    null_set = set(null_positions)
    return [ct_96_nums[i] for i in range(96) if i not in null_set]

def map_crib_to_extract(crib_positions_96, null_positions):
    """Map crib positions in 96-char text to positions in 72-char extract."""
    null_set = set(null_positions)
    # Build position mapping: 96-position → 72-position
    rank = {}
    r = 0
    for i in range(96):
        if i not in null_set:
            rank[i] = r
            r += 1
    # Map each crib position
    result = {}
    for p in crib_positions_96:
        if p not in null_set:
            result[p] = rank[p]
    return result

def derive_key_values(model, null_positions, variant='vig'):
    """Derive key values at crib positions in the 72-char extract.
    Returns: dict mapping 72-char position → key value.
    """
    crib_map = model['crib_map']
    ct_nums = model['ct_nums']
    null_set = set(null_positions)

    # Map crib positions to extract positions
    rank_map = map_crib_to_extract(list(crib_map.keys()), null_positions)

    key_at_rank = {}
    for p96, rank72 in rank_map.items():
        ct_val = ct_nums[p96]
        pt_val = crib_map[p96]
        if variant == 'vig':
            k = (ct_val - pt_val) % 26
        elif variant == 'beau':
            k = (ct_val + pt_val) % 26
        else:  # vbeau
            k = (pt_val - ct_val) % 26
        key_at_rank[rank72] = k
    return key_at_rank

def check_periodic_consistency(key_at_rank, period):
    """Check if key values are consistent with a periodic key.
    Returns (n_consistent, n_total) where n_consistent = number of residue
    classes with no conflicts.
    """
    residues = {}  # residue → set of key values
    for rank, k in key_at_rank.items():
        r = rank % period
        if r not in residues:
            residues[r] = set()
        residues[r].add(k)

    n_consistent = sum(1 for vals in residues.values() if len(vals) == 1)
    n_total = len(residues)
    n_conflicts = sum(1 for vals in residues.values() if len(vals) > 1)
    return n_consistent, n_total, n_conflicts

def random_null_mask(model, rng):
    """Generate random null mask: 24 positions from 96, excluding crib positions."""
    crib_set = set(model['crib_positions'])
    non_crib = [i for i in range(96) if i not in crib_set]
    return sorted(rng.sample(non_crib, 24))

# ── Key derivation fixed values (for impossibility analysis) ─────────────
def print_key_analysis(model):
    """Analyze fixed key values at crib positions."""
    ct_nums = model['ct_nums']
    crib_map = model['crib_map']
    print(f"\n  Key values at crib positions ({model['name']}):")
    for variant in ('vig', 'beau', 'vbeau'):
        values = {}
        for p in sorted(crib_map.keys()):
            ct_v = ct_nums[p]
            pt_v = crib_map[p]
            if variant == 'vig':
                k = (ct_v - pt_v) % 26
            elif variant == 'beau':
                k = (ct_v + pt_v) % 26
            else:
                k = (pt_v - ct_v) % 26
            values[p] = k
        distinct = len(set(values.values()))
        print(f"    {variant}: {distinct} distinct values → min period = {distinct}")
        if distinct <= 13:
            print(f"      Values: {[values[p] for p in sorted(values.keys())]}")

# ══════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ══════════════════════════════════════════════════════════════════════════

def main():
    t_start = time.time()
    results = {}

    print("=" * 70)
    print("E-FLEISSNER-8x9-180: Fleissner Turning Grille on 8×9 Grid")
    print(f"  Grid: {ROWS}×{COLS} = {GRID_SIZE} cells")
    print(f"  Pairs: {N_PAIRS} (180° rotation)")
    print(f"  Fleissner configs: 2^{N_PAIRS} = {2**N_PAIRS:,.0f}")
    print(f"  CT: {CT[:30]}... (len={CT_LEN})")
    print(f"  W positions in CT: {W_POSITIONS_97}")
    print("=" * 70, flush=True)

    # ── P0: Grid mechanics verification ──────────────────────────────────
    print("\n--- P0: Grid mechanics and key analysis ---")

    # Verify pairs cover all cells
    all_cells = set()
    for a, b in PAIR_LINEAR:
        all_cells.add(a)
        all_cells.add(b)
    assert len(all_cells) == 72, f"Pairs cover {len(all_cells)} cells, expected 72"
    assert all_cells == set(range(72)), "Pairs don't cover all cells 0-71"
    print(f"  ✓ 36 pairs cover all 72 cells")

    # Verify permutation is valid
    test_perm = fleissner_perm([0] * 36)
    assert sorted(test_perm) == list(range(72)), "Permutation not bijective"
    print(f"  ✓ Fleissner permutation is bijective")

    # Key value analysis for both models
    for model in [MODEL_B, MODEL_A]:
        print_key_analysis(model)

    # ── P1: Null mask + periodic sub consistency (fast proof) ─────────────
    print("\n--- P1: Null mask + periodic sub impossibility proof ---")
    print("  Key values at crib positions are FIXED regardless of null mask.")
    print("  The null mask only changes which RESIDUE CLASS each crib falls into.")
    print("  Checking if ANY null mask can make key values periodic...")

    for model in [MODEL_B, MODEL_A]:
        print(f"\n  === {model['name']} ===")

        for variant in ('vig', 'beau', 'vbeau'):
            # Compute fixed key values at each crib position
            ct_nums = model['ct_nums']
            crib_map = model['crib_map']
            key_values = []
            for p in sorted(crib_map.keys()):
                ct_v = ct_nums[p]
                pt_v = crib_map[p]
                if variant == 'vig':
                    k = (ct_v - pt_v) % 26
                elif variant == 'beau':
                    k = (ct_v + pt_v) % 26
                else:
                    k = (pt_v - ct_v) % 26
                key_values.append(k)

            n_distinct = len(set(key_values))

            # Quick MC: try 100K random null masks per period
            rng = random.Random(42 + hash(variant + model['name']))
            best_by_period = {}

            for period in range(1, 14):
                best_conflicts = 999
                for _ in range(100_000):
                    mask = random_null_mask(model, rng)
                    kv = derive_key_values(model, mask, variant)
                    _, _, conflicts = check_periodic_consistency(kv, period)
                    if conflicts < best_conflicts:
                        best_conflicts = conflicts
                    if conflicts == 0:
                        break
                best_by_period[period] = best_conflicts

            summary = [f"p{p}:{c}" for p, c in sorted(best_by_period.items())]
            consistent = [p for p, c in best_by_period.items() if c == 0]
            print(f"    {variant} ({n_distinct} distinct): {' '.join(summary)}")
            if consistent:
                print(f"    *** PERIODS {consistent} CONSISTENT! ***")
            results[f"P1_{model['name']}_{variant}"] = best_by_period

    # ── P2: Fleissner-only SA (fixed null mask, quadgram scoring) ────────
    print("\n--- P2: Fleissner SA with fixed keyword keys (quadgram scoring) ---")
    print("  For each keyword + random null mask, SA over Fleissner only.")

    KEYWORDS = ["KRYPTOS", "KOMPASS", "DEFECTOR", "COLOPHON", "ABSCISSA",
                "PALIMPSEST", "BERLIN", "SHADOW"]

    model = MODEL_B  # Focus on remove-last-R
    print(f"\n  === {model['name']} ===")

    for keyword in KEYWORDS:
        kw_nums = [AZ_IDX[c] for c in keyword]
        kw_len = len(keyword)
        key_stream = [kw_nums[i % kw_len] for i in range(72)]

        for variant in ('vig', 'beau'):
            rng = random.Random(hash(keyword + variant) % 2**31)
            best_qg = -999.0
            best_pt = ""

            for restart in range(20):
                # Random null mask
                mask = random_null_mask(model, rng)
                real_ct = extract_real_ct(model['ct_nums'], mask)

                # Decrypt sub layer (fixed key)
                if variant == 'vig':
                    intermediate = [(real_ct[i] - key_stream[i]) % 26 for i in range(72)]
                else:
                    intermediate = [(key_stream[i] - real_ct[i]) % 26 for i in range(72)]

                # SA over Fleissner only (fast — only perm changes)
                choices = [rng.randint(0, 1) for _ in range(36)]
                perm = fleissner_perm(choices)
                inv = invert_perm(perm)
                final_pt = [intermediate[inv[i]] for i in range(72)]
                cur_qg = qg_score(final_pt)

                T = 1.5
                for step in range(100_000):
                    idx = rng.randint(0, 35)
                    choices[idx] ^= 1
                    perm = fleissner_perm(choices)
                    inv = invert_perm(perm)
                    final_pt = [intermediate[inv[i]] for i in range(72)]
                    new_qg = qg_score(final_pt)

                    if new_qg > cur_qg or rng.random() < math.exp((new_qg - cur_qg) / max(T, 0.001)):
                        cur_qg = new_qg
                    else:
                        choices[idx] ^= 1
                    T *= 0.99995

                if cur_qg > best_qg:
                    best_qg = cur_qg
                    perm = fleissner_perm(choices)
                    inv = invert_perm(perm)
                    best_pt = ''.join(AZ[intermediate[inv[i]]] for i in range(72))

            print(f"    {variant}-{keyword}: qg={best_qg:.3f} pt={best_pt[:40]}...")
            results[f"P2_{variant}_{keyword}"] = {
                'best_qg': best_qg,
                'best_pt': best_pt[:72],
            }

    # ── P3: Pure Fleissner (no sub) MC baseline ──────────────────────────
    print("\n--- P3: MC baseline — random null mask + random Fleissner (no sub) ---")

    N_MC = 500_000
    mc_best_crib = 0
    mc_hist = Counter()
    rng = random.Random(12345)
    t_mc = time.time()

    model = MODEL_B
    print(f"  {model['name']}: {N_MC:,} random trials (pure transposition)...")

    for trial in range(N_MC):
        mask = random_null_mask(model, rng)
        choices = [rng.randint(0, 1) for _ in range(36)]

        real_ct = extract_real_ct(model['ct_nums'], mask)
        perm = fleissner_perm(choices)
        inv = invert_perm(perm)

        # Pure transposition: intermediate = real_ct, undo Fleissner
        # Count crib matches: CT[p96] should appear at the right position
        rank_map = map_crib_to_extract(model['crib_positions'], mask)
        crib_matches = 0
        for p96, rank72 in rank_map.items():
            if rank72 < 72 and inv[rank72] < 72:
                if real_ct[inv[rank72]] == model['crib_map'][p96]:
                    crib_matches += 1

        mc_hist[crib_matches] += 1
        if crib_matches > mc_best_crib:
            mc_best_crib = crib_matches
            final_pt = [real_ct[inv[i]] for i in range(72)]
            pt_text = ''.join(AZ[n] for n in final_pt)
            print(f"    Trial {trial:,}: {crib_matches}/24 cribs — {pt_text[:40]}...")

        if trial % 100_000 == 0 and trial > 0:
            print(f"    {trial:,} trials, best={mc_best_crib}, {time.time()-t_mc:.1f}s")

    print(f"  MC: best={mc_best_crib}/24 from {N_MC:,} trials")
    print(f"  Distribution: {dict(sorted(mc_hist.items()))}")

    results['mc_baseline'] = {'best_crib': mc_best_crib, 'n_trials': N_MC}

    # ── Summary ──────────────────────────────────────────────────────────
    total_time = time.time() - t_start

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Grid: {ROWS}×{COLS} = {GRID_SIZE} cells (180° turn, 36 pairs)")
    print(f"  Delimiter models tested: Remove-last-R, Remove-first-O")
    print(f"  Total time: {total_time:.1f}s")

    for key, val in sorted(results.items()):
        if isinstance(val, dict) and 'conflicts' in val and val['conflicts'] == 0:
            print(f"  *** {key}: PERIODIC CONSISTENT — key={val.get('key','?')}, qg={val.get('best_qg','?')}")
        elif isinstance(val, dict) and 'best_qg' in val and val['best_qg'] > -5.0:
            print(f"  {key}: qg={val['best_qg']:.3f}")

    # Save results
    os.makedirs("results", exist_ok=True)
    output = {
        'experiment': 'E-FLEISSNER-8x9-180',
        'description': 'Fleissner 8x9 turning grille with delimiter + null mask + periodic sub',
        'grid': f'{ROWS}x{COLS}',
        'pairs': N_PAIRS,
        'elapsed': total_time,
        'results': {k: str(v) for k, v in results.items()},
    }
    outfile = "results/e_fleissner_8x9_180.json"
    with open(outfile, "w") as f:
        json.dump(output, f, indent=2, default=str)

    print(f"\n  Artifact: {outfile}")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/grille/e_fleissner_8x9_180.py")


if __name__ == '__main__':
    main()
