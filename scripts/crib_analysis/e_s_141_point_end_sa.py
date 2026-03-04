#!/usr/bin/env python3
"""
Cipher: crib-based constraint
Family: crib_analysis
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-141: SA optimization for POINT-family at END of plaintext (pos 74-96).

Hypothesis: POINT appears near the end as a concluding rhetorical device:
"...that is the point" or "what's the point"

Tests placements in the 23-char post-BERLINCLOCK segment (74-96),
plus combined placements with SECRET/REMINDER in the middle segment.

Output: results/e_s_141_point_end_sa.json
"""

import json
import math
import os
import random
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_ENTRIES,
    BEAN_EQ, BEAN_INEQ,
)

CT_NUM = [ALPH_IDX[c] for c in CT]
N = CT_LEN

EXISTING_CRIBS = {pos: ALPH_IDX[ch] for pos, ch in CRIB_ENTRIES}
EXISTING_CRIB_POS = set(EXISTING_CRIBS.keys())
BEAN_EQ_POS = BEAN_EQ[0]
BEAN_INEQ_PAIRS = list(BEAN_INEQ)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(REPO_ROOT, "data", "english_quadgrams.json")) as f:
    QUADGRAMS = json.load(f)
QG_FLOOR = -10.0

RESTARTS = 5
STEPS = 50_000
T_START = 2.0
T_END = 0.01
SEED_BASE = 20260221


def qg_score(text):
    s = 0.0
    for i in range(len(text) - 3):
        s += QUADGRAMS.get(text[i:i+4], QG_FLOOR)
    return s


def nums_to_text(nums):
    return ''.join(ALPH[n] for n in nums)


def build_fixed(extra_words):
    """Build fixed positions dict. extra_words = [(word, start_pos), ...]"""
    fixed = dict(EXISTING_CRIBS)
    for word, start in extra_words:
        for i, ch in enumerate(word):
            pos = start + i
            val = ALPH_IDX[ch]
            if pos in fixed and fixed[pos] != val:
                return None  # Conflict
            fixed[pos] = val
    return fixed


def sa_run(fixed, seed):
    """Run SA optimizing free plaintext positions. Returns best result or None."""
    rng = random.Random(seed)
    fixed_positions = set(fixed.keys())
    free_pos = sorted(set(range(N)) - fixed_positions)
    eq_a, eq_b = BEAN_EQ_POS

    pt = [0] * N
    for pos, val in fixed.items():
        pt[pos] = val
    for pos in free_pos:
        pt[pos] = rng.randint(0, 25)

    # Enforce Bean EQ
    bean_a_free = eq_a not in fixed_positions
    bean_b_free = eq_b not in fixed_positions

    if eq_a in fixed_positions and eq_b in fixed_positions:
        ka = (CT_NUM[eq_a] - pt[eq_a]) % MOD
        kb = (CT_NUM[eq_b] - pt[eq_b]) % MOD
        if ka != kb:
            return None
    elif eq_a in fixed_positions:
        ka = (CT_NUM[eq_a] - pt[eq_a]) % MOD
        pt[eq_b] = (CT_NUM[eq_b] - ka) % MOD
    elif eq_b in fixed_positions:
        kb = (CT_NUM[eq_b] - pt[eq_b]) % MOD
        pt[eq_a] = (CT_NUM[eq_a] - kb) % MOD
    else:
        ka = (CT_NUM[eq_a] - pt[eq_a]) % MOD
        pt[eq_b] = (CT_NUM[eq_b] - ka) % MOD

    def score(pt_arr):
        text = nums_to_text(pt_arr)
        s = qg_score(text)
        ka = (CT_NUM[eq_a] - pt_arr[eq_a]) % MOD
        kb = (CT_NUM[eq_b] - pt_arr[eq_b]) % MOD
        if ka != kb:
            s -= 100.0
        for ia, ib in BEAN_INEQ_PAIRS:
            kia = (CT_NUM[ia] - pt_arr[ia]) % MOD
            kib = (CT_NUM[ib] - pt_arr[ib]) % MOD
            if kia == kib:
                s -= 10.0
        return s

    current_score = score(pt)
    best_score = current_score
    best_pt = pt[:]
    accepted = 0

    for step in range(STEPS):
        T = T_START * (T_END / T_START) ** (step / STEPS)
        pos = rng.choice(free_pos)
        old_val = pt[pos]
        new_val = (old_val + rng.randint(1, 25)) % 26
        pt[pos] = new_val

        old_bean_val = None
        if pos == eq_a and bean_a_free:
            old_bean_val = pt[eq_b]
            ka_new = (CT_NUM[eq_a] - new_val) % MOD
            pt[eq_b] = (CT_NUM[eq_b] - ka_new) % MOD
        elif pos == eq_b and bean_b_free:
            old_bean_val = pt[eq_b]
            ka = (CT_NUM[eq_a] - pt[eq_a]) % MOD
            pt[eq_b] = (CT_NUM[eq_b] - ka) % MOD
            new_val = pt[eq_b]

        new_score = score(pt)
        delta = new_score - current_score

        if delta > 0 or (T > 0 and rng.random() < math.exp(delta / T)):
            current_score = new_score
            accepted += 1
            if current_score > best_score:
                best_score = current_score
                best_pt = pt[:]
        else:
            pt[pos] = old_val
            if old_bean_val is not None:
                pt[eq_b] = old_bean_val

    return {
        'score': best_score,
        'pt': best_pt,
        'qg_per_char': qg_score(nums_to_text(best_pt)) / (N - 3),
        'accept_rate': accepted / STEPS,
    }


def run_config(label, extra_words):
    """Run SA for a given placement configuration."""
    fixed = build_fixed(extra_words)
    if fixed is None:
        print(f"  {label}: CONFLICT — skipped")
        return None

    n_fixed = len(fixed)
    n_free = N - n_fixed
    n_new = n_fixed - len(EXISTING_CRIBS)

    # Check Bean compatibility
    eq_a, eq_b = BEAN_EQ_POS
    if eq_a in fixed and eq_b in fixed:
        ka = (CT_NUM[eq_a] - fixed[eq_a]) % MOD
        kb = (CT_NUM[eq_b] - fixed[eq_b]) % MOD
        if ka != kb:
            print(f"  {label}: Bean EQ FAIL — skipped")
            return None

    best = None
    scores = []
    for r in range(RESTARTS):
        seed = SEED_BASE + hash(label) % 10000 + r * 137
        result = sa_run(fixed, seed)
        if result is None:
            continue
        scores.append(result['qg_per_char'])
        if best is None or result['score'] > best['score']:
            best = result

    if not best:
        print(f"  {label}: all restarts failed")
        return None

    pt_text = nums_to_text(best['pt'])
    avg_qg = sum(scores) / len(scores) if scores else 0

    print(f"  {label} (fixed={n_fixed}, +{n_new} new, free={n_free})")
    print(f"    Best: qg/c={best['qg_per_char']:.3f} avg={avg_qg:.3f}")
    print(f"    PT: {pt_text}")
    print(f"    Segments: [{pt_text[:21]}][{pt_text[21:34]}][{pt_text[34:63]}]"
          f"[{pt_text[63:74]}][{pt_text[74:]}]")

    return {
        'label': label,
        'n_fixed': n_fixed,
        'n_new': n_new,
        'n_free': n_free,
        'best_qg': best['qg_per_char'],
        'avg_qg': avg_qg,
        'best_pt': pt_text,
        'all_qg': scores,
    }


def main():
    print("=" * 70)
    print("E-S-141: POINT at END of Plaintext — SA Optimization")
    print("=" * 70)
    print(f"SA: {RESTARTS} restarts x {STEPS:,} steps, T={T_START}->{T_END}")
    print()

    t0 = time.time()
    results = {}

    # ── Baseline ─────────────────────────────────────────────────────────────
    print("--- BASELINE (24 cribs only) ---")
    results['BASELINE'] = run_config('BASELINE', [])

    # ── POINT@16 (from E-S-138 for comparison) ─────────────────────────────
    print("\n--- POINT@16 (E-S-138 reference) ---")
    results['POINT@16'] = run_config('POINT@16', [('POINT', 16)])

    # ── END-segment placements ───────────────────────────────────────────────
    print("\n--- END SEGMENT PLACEMENTS ---")

    configs = [
        ('POINT@92', [('POINT', 92)]),
        ('POINT@89', [('POINT', 89)]),
        ('THEPOINT@89', [('THEPOINT', 89)]),
        ('THEPOINT@85', [('THEPOINT', 85)]),
        ('WHATSTHEPOINT@84', [('WHATSTHEPOINT', 84)]),
        ('ISTHEPOINT@87', [('ISTHEPOINT', 87)]),
        ('THATSTHEPOINT@84', [('THATSTHEPOINT', 84)]),
    ]

    for label, words in configs:
        # Bounds check
        for w, s in words:
            if s + len(w) > N:
                print(f"  {label}: OUT OF BOUNDS ({s}+{len(w)}={s+len(w)} > {N}) — skipped")
                results[label] = None
                break
        else:
            results[label] = run_config(label, words)

    # ── Combined: POINT@92 + SECRET/REMINDER in middle ──────────────────────
    print("\n--- COMBINED PLACEMENTS ---")

    combo_configs = [
        ('POINT@92+SECRET@40', [('POINT', 92), ('SECRET', 40)]),
        ('POINT@92+SECRET@45', [('POINT', 92), ('SECRET', 45)]),
        ('POINT@92+SECRET@50', [('POINT', 92), ('SECRET', 50)]),
        ('POINT@92+SECRET@55', [('POINT', 92), ('SECRET', 55)]),
        ('POINT@92+REMINDER@40', [('POINT', 92), ('REMINDER', 40)]),
        ('POINT@92+REMINDER@50', [('POINT', 92), ('REMINDER', 50)]),
        ('POINT@92+REMINDER@74', [('POINT', 92), ('REMINDER', 74)]),
        ('THEPOINT@89+SECRET@40', [('THEPOINT', 89), ('SECRET', 40)]),
        ('THEPOINT@89+SECRET@50', [('THEPOINT', 89), ('SECRET', 50)]),
        ('THEPOINT@89+REMEMBER@40', [('THEPOINT', 89), ('REMEMBER', 40)]),
        ('THEPOINT@89+REMEMBER@50', [('THEPOINT', 89), ('REMEMBER', 50)]),
    ]

    for label, words in combo_configs:
        # Bounds check
        valid = True
        for w, s in words:
            if s + len(w) > N:
                print(f"  {label}: OUT OF BOUNDS — skipped")
                results[label] = None
                valid = False
                break
        if valid:
            results[label] = run_config(label, words)

    elapsed = time.time() - t0

    # ── Summary table ────────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print("SUMMARY TABLE")
    print(f"{'='*70}")
    print(f"{'Label':<35s} {'Fixed':>5s} {'Free':>5s} {'BestQG':>7s} {'AvgQG':>7s} {'Delta':>7s}")
    print("-" * 70)

    baseline_qg = results.get('BASELINE', {})
    bl_best = baseline_qg['best_qg'] if baseline_qg else -999

    for label, data in results.items():
        if data is None:
            print(f"{label:<35s} {'---':>5s} {'---':>5s} {'---':>7s} {'---':>7s} {'---':>7s}")
            continue
        delta = data['best_qg'] - bl_best
        print(f"{label:<35s} {data['n_fixed']:>5d} {data['n_free']:>5d} "
              f"{data['best_qg']:>7.3f} {data['avg_qg']:>7.3f} {delta:>+7.3f}")

    # ── Ranking by best quadgram ─────────────────────────────────────────────
    print(f"\n{'='*70}")
    print("RANKED BY BEST QUADGRAM/CHAR (closest to 0 = most English-like)")
    print(f"{'='*70}")
    ranked = [(label, data) for label, data in results.items() if data is not None]
    ranked.sort(key=lambda x: -x[1]['best_qg'])
    for i, (label, data) in enumerate(ranked):
        delta = data['best_qg'] - bl_best
        marker = " <-- BASELINE" if label == "BASELINE" else ""
        print(f"  {i+1:2d}. {label:<35s} qg/c={data['best_qg']:.3f} (delta={delta:+.3f}){marker}")

    print(f"\nElapsed: {elapsed:.1f}s")
    print(f"\nINTERPRETATION:")
    print(f"Placements that score ABOVE baseline suggest the fixed word is")
    print(f"compatible with English plaintext. Placements below are penalized")
    print(f"by over-constraint. All deltas < 0.2 are within SA noise.")

    # Save
    os.makedirs("results", exist_ok=True)
    artifact = {
        "experiment_id": "e_s_141",
        "description": "POINT at end of plaintext, SA optimization",
        "sa_params": {"restarts": RESTARTS, "steps": STEPS},
        "results": {k: v for k, v in results.items() if v is not None},
        "elapsed_seconds": elapsed,
        "repro_command": "PYTHONPATH=src python3 -u scripts/e_s_141_point_end_sa.py",
    }
    with open("results/e_s_141_point_end_sa.json", "w") as f:
        json.dump(artifact, f, indent=2, default=str)
    print(f"\nArtifact: results/e_s_141_point_end_sa.json")


if __name__ == "__main__":
    main()
