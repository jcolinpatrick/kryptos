#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-23: Lag-7 Constrained SA over Transpositions

Key insight: the lag-7 autocorrelation (z=3.036) is the strongest
unexplained structural feature of K4 CT. 9 matching pairs at lag 7
vs 3.46 expected.

This experiment uses SA to search for transpositions that:
1. Satisfy 24/24 crib constraints (start on the valid manifold)
2. Maximize quadgram fitness
3. PRESERVE the lag-7 autocorrelation in the pre-transposition text

If the lag-7 comes from the substitution cipher (e.g., period-7 Vigenère),
then the transposition should map the 9 lag-7 matching pairs in CT
to positions that are also related by the same period in PT.

Alternatively, if the lag-7 comes from the plaintext structure
(English text has bigram correlations), the transposition should
map lag-7 CT pairs to nearby PT positions.

We test both hypotheses.

Output: results/e_s_23_lag7_constrained.json
"""
import json
import math
import random
import sys
import time
from collections import defaultdict

sys.path.insert(0, "src")
from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD,
    BEAN_EQ, BEAN_INEQ,
)

CT_NUM = [ALPH_IDX[c] for c in CT]
ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
N = CT_LEN
NON_CRIB_POS = [i for i in range(N) if i not in CRIB_DICT]

# CT position index by letter value
CT_POS_BY_VAL = defaultdict(list)
for i, v in enumerate(CT_NUM):
    CT_POS_BY_VAL[v].append(i)


# ── Lag-7 analysis ──────────────────────────────────────────────────────

def compute_lag_matches(text_nums, lag):
    """Count positions where text[i] == text[i + lag]."""
    matches = []
    for i in range(len(text_nums) - lag):
        if text_nums[i] == text_nums[i + lag]:
            matches.append(i)
    return matches

LAG7_CT_MATCHES = compute_lag_matches(CT_NUM, 7)
print(f"CT lag-7 matches: {len(LAG7_CT_MATCHES)} at positions {LAG7_CT_MATCHES}")
print(f"Expected: {(N-7)/26:.2f}")

# The matching CT pairs at lag 7
LAG7_PAIRS = [(i, i+7) for i in LAG7_CT_MATCHES]
print(f"Lag-7 pairs: {LAG7_PAIRS}")


# ── Quadgram scorer ─────────────────────────────────────────────────────

def load_quadgrams():
    with open("data/english_quadgrams.json") as f:
        data = json.load(f)
    qg = {}
    floor = -10.0
    for gram, val in data.items():
        if len(gram) == 4 and gram.isalpha():
            idx = 0
            for ch in gram.upper():
                idx = idx * 26 + (ord(ch) - ord('A'))
            qg[idx] = val
            if val < floor:
                floor = val
    return qg, floor

QG, QG_FLOOR = load_quadgrams()
print(f"Quadgram scorer: {len(QG)} entries, floor={QG_FLOOR:.3f}")


def quadgram_score(text_nums):
    score = 0.0
    n = len(text_nums)
    for i in range(n - 3):
        idx = text_nums[i] * 17576 + text_nums[i+1] * 676 + text_nums[i+2] * 26 + text_nums[i+3]
        score += QG.get(idx, QG_FLOOR)
    return score


# ── Lag-7 preservation score ────────────────────────────────────────────

def lag7_preservation_score(sigma_inv, period):
    """Score how well the transposition preserves lag-7 relationships.

    For each lag-7 matching pair (i, i+7) in CT:
    - sigma_inv maps PT positions to CT positions
    - If sigma_inv[a] = i and sigma_inv[b] = i+7, then PT positions a,b
      both receive the same CT value.
    - Under period-p Vigenère, if a ≡ b (mod p), then same key is used
      and same CT value implies same PT value.
    - So we want: for each lag-7 CT pair, the corresponding PT positions
      should be in the same residue class mod period.

    Returns: count of lag-7 pairs where PT positions share residue.
    """
    # Build inverse: ct_pos → pt_pos
    sigma = {}
    for pt_pos, ct_pos in sigma_inv.items():
        sigma[ct_pos] = pt_pos

    count = 0
    for ct_i, ct_j in LAG7_PAIRS:
        if ct_i in sigma and ct_j in sigma:
            pt_a = sigma[ct_i]
            pt_b = sigma[ct_j]
            if pt_a % period == pt_b % period:
                count += 1

    return count


# ── Valid assignment generation (from E-S-21) ───────────────────────────

def generate_valid_assignment(period, variant="vig"):
    """Generate a random valid partial assignment for crib positions."""
    residue_groups = defaultdict(list)
    for j in CRIB_POS:
        residue_groups[j % period].append(j)

    sigma_inv_partial = {}
    key = [None] * period
    used_ct_positions = set()

    residues = list(residue_groups.keys())
    random.shuffle(residues)

    for res in residues:
        group = residue_groups[res]
        j0 = group[0]
        pt0 = CRIB_PT_NUM[j0]

        attempts = list(range(MOD))
        random.shuffle(attempts)

        found = False
        for a in attempts:
            if variant == "vig":
                key_val = (a - pt0) % MOD
                required = [(key_val + CRIB_PT_NUM[j]) % MOD for j in group]
            else:
                key_val = (a + pt0) % MOD
                required = [(key_val - CRIB_PT_NUM[j]) % MOD for j in group]

            pos_options = []
            ok = True
            for req in required:
                available = [p for p in CT_POS_BY_VAL[req] if p not in used_ct_positions]
                if not available:
                    ok = False
                    break
                pos_options.append(available)

            if not ok:
                continue

            assigned = {}
            temp_used = set()
            assign_ok = True
            for i, opts in enumerate(pos_options):
                opts_filtered = [p for p in opts if p not in temp_used]
                if not opts_filtered:
                    assign_ok = False
                    break
                chosen = random.choice(opts_filtered)
                assigned[group[i]] = chosen
                temp_used.add(chosen)

            if assign_ok:
                sigma_inv_partial.update(assigned)
                used_ct_positions.update(temp_used)
                key[res] = key_val
                found = True
                break

        if not found:
            return None, None

    return sigma_inv_partial, key


def build_full_transposition(sigma_inv_partial):
    """Build a full transposition from a partial assignment."""
    used_ct = set(sigma_inv_partial.values())
    free_ct = [i for i in range(N) if i not in used_ct]
    free_pt = [i for i in range(N) if i not in sigma_inv_partial]

    random.shuffle(free_ct)
    sigma_inv = dict(sigma_inv_partial)
    for pt_pos, ct_pos in zip(free_pt, free_ct):
        sigma_inv[pt_pos] = ct_pos

    return sigma_inv


def decrypt_with_transposition(sigma_inv, key, period, variant="vig"):
    """Decrypt: PT[j] = vig_decrypt(CT[sigma_inv[j]], key[j % period])."""
    pt = [0] * N
    for j in range(N):
        ct_val = CT_NUM[sigma_inv[j]]
        k = key[j % period]
        if variant == "vig":
            pt[j] = (ct_val - k) % MOD
        else:
            pt[j] = (k - ct_val) % MOD
    return pt


def check_bean(key, period):
    for pos_a, pos_b in BEAN_EQ:
        if key[pos_a % period] != key[pos_b % period]:
            return False
    for pos_a, pos_b in BEAN_INEQ:
        if key[pos_a % period] == key[pos_b % period]:
            return False
    return True


# ── SA with lag-7 constraint ────────────────────────────────────────────

def sa_lag7_search(period, variant, n_restarts, n_steps, lag7_weight, seed=None):
    """SA that optimizes quadgram + lag-7 preservation jointly."""
    if seed is not None:
        random.seed(seed)

    best_score = -1e18
    best_pt = None
    best_key = None
    best_lag7 = 0
    best_qg = -1e18
    scores_history = []

    for restart in range(n_restarts):
        # Generate a valid starting point
        for _ in range(100):
            sigma_inv_partial, key = generate_valid_assignment(period, variant)
            if sigma_inv_partial is not None:
                break
        else:
            continue

        bean_ok = check_bean(key, period)
        sigma_inv = build_full_transposition(sigma_inv_partial)
        pt = decrypt_with_transposition(sigma_inv, key, period, variant)

        qg_score = quadgram_score(pt)
        lag7_score = lag7_preservation_score(sigma_inv, period)
        current_score = qg_score + lag7_weight * lag7_score

        local_best_score = current_score
        local_best_pt = list(pt)
        local_best_key = list(key)
        local_best_lag7 = lag7_score
        local_best_qg = qg_score

        # Temperature schedule
        T_start = 2.0
        T_end = 0.01
        T_factor = (T_end / T_start) ** (1.0 / max(n_steps, 1))
        T = T_start

        accepted = 0
        crib_set = set(CRIB_DICT.keys())

        for step in range(n_steps):
            # Swap two non-crib positions
            i1, i2 = random.sample(NON_CRIB_POS, 2)

            # Compute new PT values
            new_ct_at_i1 = CT_NUM[sigma_inv[i2]]
            new_ct_at_i2 = CT_NUM[sigma_inv[i1]]

            if variant == "vig":
                new_pt_i1 = (new_ct_at_i1 - key[i1 % period]) % MOD
                new_pt_i2 = (new_ct_at_i2 - key[i2 % period]) % MOD
            else:
                new_pt_i1 = (key[i1 % period] - new_ct_at_i1) % MOD
                new_pt_i2 = (key[i2 % period] - new_ct_at_i2) % MOD

            old_pt_i1 = pt[i1]
            old_pt_i2 = pt[i2]

            # Collect all unique affected quadgram start positions
            affected_starts = set()
            for pos in [i1, i2]:
                for start in range(max(0, pos - 3), min(N - 3, pos + 1)):
                    affected_starts.add(start)

            # Old sum (before changes)
            old_qg = 0.0
            for start in affected_starts:
                vals = [pt[start + j] for j in range(4)]
                idx = vals[0] * 17576 + vals[1] * 676 + vals[2] * 26 + vals[3]
                old_qg += QG.get(idx, QG_FLOOR)

            # Apply changes temporarily
            pt[i1] = new_pt_i1
            pt[i2] = new_pt_i2

            # New sum (after changes)
            new_qg = 0.0
            for start in affected_starts:
                vals = [pt[start + j] for j in range(4)]
                idx = vals[0] * 17576 + vals[1] * 676 + vals[2] * 26 + vals[3]
                new_qg += QG.get(idx, QG_FLOOR)

            qg_delta = new_qg - old_qg

            # Compute lag-7 delta
            old_lag7 = lag7_score
            # Update sigma_inv temporarily
            sigma_inv[i1], sigma_inv[i2] = sigma_inv[i2], sigma_inv[i1]
            new_lag7 = lag7_preservation_score(sigma_inv, period)
            lag7_delta = (new_lag7 - old_lag7) * lag7_weight

            total_delta = qg_delta + lag7_delta
            new_total = current_score + total_delta

            if total_delta > 0 or random.random() < math.exp(total_delta / T):
                # Accept
                current_score = new_total
                qg_score += qg_delta
                lag7_score = new_lag7
                accepted += 1

                if current_score > local_best_score:
                    local_best_score = current_score
                    local_best_pt = list(pt)
                    local_best_key = list(key)
                    local_best_lag7 = lag7_score
                    local_best_qg = qg_score
            else:
                # Reject — undo
                pt[i1] = old_pt_i1
                pt[i2] = old_pt_i2
                sigma_inv[i1], sigma_inv[i2] = sigma_inv[i2], sigma_inv[i1]

            T *= T_factor

            # Periodic recalibration to prevent score drift
            if step > 0 and step % 50_000 == 0:
                qg_score = quadgram_score(pt)
                lag7_score = lag7_preservation_score(sigma_inv, period)
                current_score = qg_score + lag7_weight * lag7_score

        # Final recalibration before recording
        qg_score = quadgram_score(local_best_pt)

        # Record
        if local_best_score > best_score:
            best_score = local_best_score
            best_pt = local_best_pt
            best_key = local_best_key
            best_lag7 = local_best_lag7
            best_qg = local_best_qg

        qg_per_char = local_best_qg / (N - 3)
        pt_str = "".join(ALPH[v] for v in local_best_pt)

        scores_history.append({
            "restart": restart,
            "total_score": local_best_score,
            "qg_per_char": qg_per_char,
            "lag7": local_best_lag7,
            "bean": bean_ok,
            "accept_rate": accepted / max(n_steps, 1),
        })

        if (restart + 1) % max(1, n_restarts // 10) == 0 or restart == 0:
            print(f"  [{restart+1:>4}/{n_restarts}] qg/c={qg_per_char:.3f}"
                  f"  lag7={local_best_lag7}/{len(LAG7_PAIRS)}"
                  f"  bean={'Y' if bean_ok else 'N'}"
                  f"  accept={accepted/max(n_steps,1):.2f}"
                  f"  PT={pt_str[:40]}...", flush=True)

    return best_score, best_pt, best_key, best_lag7, best_qg, scores_history


def main():
    print("=" * 60)
    print("E-S-23: Lag-7 Constrained SA")
    print("=" * 60)
    print(f"Model: CT = σ(Vig(PT, period_key))")
    print(f"Fitness: quadgram + lag7_weight × lag7_preservation")
    print(f"Starting on 24/24 crib-consistent manifold")
    print()

    SEED = 20260218
    N_RESTARTS = 30
    N_STEPS = 300_000

    t0 = time.time()
    all_results = {}

    # Test different lag-7 weights
    for lag7_weight in [0.0, 5.0, 20.0, 50.0]:
        for period in [7]:
            for variant in ["vig", "beau"]:
                config_name = f"p{period}_{variant}_w{lag7_weight:.0f}"
                print(f"\n{'='*60}")
                print(f"  {config_name} — {N_RESTARTS} restarts × {N_STEPS:,} steps")
                print(f"{'='*60}")

                best_score, best_pt, best_key, best_lag7, best_qg, history = sa_lag7_search(
                    period, variant, N_RESTARTS, N_STEPS, lag7_weight,
                    seed=SEED + int(lag7_weight) * 1000 + (0 if variant == "vig" else 50)
                )

                qg_per_char = best_qg / (N - 3)
                pt_str = "".join(ALPH[v] for v in best_pt)
                key_str = "".join(ALPH[v] for v in best_key)
                bean_ok = check_bean(best_key, period)

                print(f"\n  Best: qg/c={qg_per_char:.3f}  lag7={best_lag7}/{len(LAG7_PAIRS)}"
                      f"  bean={'PASS' if bean_ok else 'FAIL'}")
                print(f"  Key: {best_key} ({key_str})")
                print(f"  PT: {pt_str}")

                # Crib verify
                crib_check = sum(1 for j in CRIB_POS if best_pt[j] == CRIB_PT_NUM[j])
                print(f"  Crib verify: {crib_check}/24")

                all_results[config_name] = {
                    "period": period,
                    "variant": variant,
                    "lag7_weight": lag7_weight,
                    "best_qg_per_char": qg_per_char,
                    "best_lag7": best_lag7,
                    "best_total": best_score,
                    "key_str": key_str,
                    "best_pt": pt_str,
                    "bean_pass": bean_ok,
                    "crib_verify": crib_check,
                    "n_restarts": N_RESTARTS,
                    "n_steps": N_STEPS,
                }

    elapsed = time.time() - t0

    # Summary
    print(f"\n{'='*60}")
    print(f"  SUMMARY")
    print(f"{'='*60}")
    print(f"  Time: {elapsed:.0f}s ({elapsed/60:.1f} min)")
    print(f"  CT lag-7 matches: {len(LAG7_CT_MATCHES)}")
    print(f"  Reference: English qg/c ≈ -4.285")
    print()

    # Compare lag-7 weights
    print(f"  {'Config':<30} {'qg/c':>8} {'lag7':>5} {'bean':>5} {'cribs':>6}")
    print(f"  {'-'*60}")
    for config, result in sorted(all_results.items()):
        print(f"  {config:<30} {result['best_qg_per_char']:>8.3f}"
              f" {result['best_lag7']:>5}/{len(LAG7_PAIRS)}"
              f" {'Y' if result['bean_pass'] else 'N':>5}"
              f" {result['crib_verify']:>6}/24")

    print(f"\n  KEY QUESTION: Does increasing lag7_weight improve qg/c?")
    print(f"  If yes: lag-7 is structurally compatible with English PT.")
    print(f"  If no: lag-7 is independent of / opposed to English structure.")

    # Save
    with open("results/e_s_23_lag7_constrained.json", "w") as f:
        json.dump(all_results, f, indent=2, default=str)

    print(f"\n  Artifact: results/e_s_23_lag7_constrained.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_23_lag7_constrained.py")


if __name__ == "__main__":
    main()
