#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-21: SA on the 24/24 Crib-Consistent Transposition Manifold

Key insight from E-S-20: there are ~3×10^23 valid partial transpositions at
period 7 that achieve 24/24 crib consistency. Instead of searching FOR such
transpositions, this experiment starts ON the valid manifold and does SA
within it, using quadgram fitness to find English-like plaintext.

Model: CT = σ(Vig(PT, period_key))

For a given valid partial assignment:
- The 7-letter key is DETERMINED by the crib constraint
- The 24 crib positions in the transposition are FIXED
- The 73 remaining positions are FREE to permute

SA moves:
1. Swap two non-crib positions in σ^(-1) (preserves 24/24, changes 2 PT chars)
2. Re-assign one crib position to a different valid CT position (changes key)

Output: results/e_s_21_manifold_sa.json
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
N_CRIB = len(CRIB_POS)
NON_CRIB_POS = [i for i in range(CT_LEN) if i not in CRIB_DICT]

# CT position index by letter value
CT_POS_BY_VAL = defaultdict(list)
for i, v in enumerate(CT_NUM):
    CT_POS_BY_VAL[v].append(i)


# ─── Quadgram scorer ────────────────────────────────────────────────────

def load_quadgrams():
    with open("data/english_quadgrams.json") as f:
        data = json.load(f)
    # Flat dict: {"THAN": -3.77, ...}
    # Build fast lookup: qg[a*26^3 + b*26^2 + c*26 + d] = log_prob
    qg = {}
    floor = -10.0  # Floor for unknown quadgrams
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
    """Score a numeric text (list of 0-25 values) using quadgram log-probs."""
    score = 0.0
    n = len(text_nums)
    for i in range(n - 3):
        idx = text_nums[i] * 17576 + text_nums[i+1] * 676 + text_nums[i+2] * 26 + text_nums[i+3]
        score += QG.get(idx, QG_FLOOR)
    return score


def quadgram_delta(text_nums, pos, old_val, new_val):
    """Compute the change in quadgram score when text_nums[pos] changes.
    Only the 7 quadgrams overlapping position pos are affected.
    """
    n = len(text_nums)
    delta = 0.0

    # Temporarily compute affected quadgrams
    for start in range(max(0, pos - 3), min(n - 3, pos + 1)):
        # Old quadgram
        vals = [text_nums[start + j] for j in range(4)]
        old_idx = vals[0] * 17576 + vals[1] * 676 + vals[2] * 26 + vals[3]
        delta -= QG.get(old_idx, QG_FLOOR)

        # New quadgram (substitute the changed position)
        vals[pos - start] = new_val
        new_idx = vals[0] * 17576 + vals[1] * 676 + vals[2] * 26 + vals[3]
        delta += QG.get(new_idx, QG_FLOOR)

    return delta


# ─── Valid partial assignment generation ────────────────────────────────

def generate_valid_assignment(period, variant="vig"):
    """Generate a random valid partial assignment for the given period and variant.

    Returns: (sigma_inv_partial, key) where
    - sigma_inv_partial: dict {pt_pos: ct_pos} for the 24 crib positions
    - key: list of period key values
    """
    residue_groups = defaultdict(list)
    for j in CRIB_POS:
        residue_groups[j % period].append(j)

    sigma_inv_partial = {}
    key = [None] * period
    used_ct_positions = set()

    # Process residue classes in random order
    residues = list(residue_groups.keys())
    random.shuffle(residues)

    for res in residues:
        group = residue_groups[res]
        j0 = group[0]
        pt0 = CRIB_PT_NUM[j0]

        # Try random key values until we find one that works
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

            # Find available CT positions for each required value
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

            # Greedily assign positions (random from available)
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
            return None, None  # Failed — retry

    return sigma_inv_partial, key


def build_full_transposition(sigma_inv_partial):
    """Build a full transposition from a partial assignment.
    sigma_inv maps PT positions to CT positions.
    """
    used_ct = set(sigma_inv_partial.values())
    free_ct = [i for i in range(CT_LEN) if i not in used_ct]
    free_pt = [i for i in range(CT_LEN) if i not in sigma_inv_partial]

    random.shuffle(free_ct)
    sigma_inv = dict(sigma_inv_partial)
    for pt_pos, ct_pos in zip(free_pt, free_ct):
        sigma_inv[pt_pos] = ct_pos

    return sigma_inv


def decrypt_with_transposition(sigma_inv, key, period, variant="vig"):
    """Decrypt: PT[j] = vig_decrypt(CT[sigma_inv[j]], key[j % period])."""
    pt = [0] * CT_LEN
    for j in range(CT_LEN):
        ct_val = CT_NUM[sigma_inv[j]]
        k = key[j % period]
        if variant == "vig":
            pt[j] = (ct_val - k) % MOD
        else:  # beaufort: CT = (K - PT) mod 26 → PT = (K - CT) mod 26
            pt[j] = (k - ct_val) % MOD
    return pt


def check_bean(key, period):
    """Check Bean equality and inequalities."""
    for pos_a, pos_b in BEAN_EQ:
        if key[pos_a % period] != key[pos_b % period]:
            return False

    for pos_a, pos_b in BEAN_INEQ:
        if key[pos_a % period] == key[pos_b % period]:
            return False

    return True


def sa_search(period, variant, n_restarts, n_steps, seed=None):
    """SA search on the valid manifold."""
    if seed is not None:
        random.seed(seed)

    best_score = -1e18
    best_pt = None
    best_key = None
    best_sigma_inv = None
    scores_history = []

    for restart in range(n_restarts):
        # Generate a valid starting point
        for _ in range(100):
            sigma_inv_partial, key = generate_valid_assignment(period, variant)
            if sigma_inv_partial is not None:
                break
        else:
            continue

        # Check Bean constraint (optional — skip if not satisfied)
        bean_ok = check_bean(key, period)

        sigma_inv = build_full_transposition(sigma_inv_partial)
        pt = decrypt_with_transposition(sigma_inv, key, period, variant)
        current_score = quadgram_score(pt)

        local_best_score = current_score
        local_best_pt = list(pt)
        local_best_key = list(key)

        # Temperature schedule
        T_start = 2.0
        T_end = 0.01
        T_factor = (T_end / T_start) ** (1.0 / max(n_steps, 1))
        T = T_start

        accepted = 0
        for step in range(n_steps):
            # Move type: swap two non-crib positions in sigma_inv
            i1, i2 = random.sample(NON_CRIB_POS, 2)

            # Compute the PT values that would change
            old_pt_i1 = pt[i1]
            old_pt_i2 = pt[i2]

            # After swap: sigma_inv[i1], sigma_inv[i2] = sigma_inv[i2], sigma_inv[i1]
            new_ct_at_i1 = CT_NUM[sigma_inv[i2]]
            new_ct_at_i2 = CT_NUM[sigma_inv[i1]]

            if variant == "vig":
                new_pt_i1 = (new_ct_at_i1 - key[i1 % period]) % MOD
                new_pt_i2 = (new_ct_at_i2 - key[i2 % period]) % MOD
            else:
                new_pt_i1 = (key[i1 % period] - new_ct_at_i1) % MOD
                new_pt_i2 = (key[i2 % period] - new_ct_at_i2) % MOD

            # Compute quadgram delta for both changes
            delta = quadgram_delta(pt, i1, old_pt_i1, new_pt_i1)
            # Apply the first change temporarily
            pt[i1] = new_pt_i1
            delta += quadgram_delta(pt, i2, old_pt_i2, new_pt_i2)

            # Accept/reject
            new_score = current_score + delta

            if delta > 0 or random.random() < math.exp(delta / T):
                # Accept
                pt[i2] = new_pt_i2
                sigma_inv[i1], sigma_inv[i2] = sigma_inv[i2], sigma_inv[i1]
                current_score = new_score
                accepted += 1

                if current_score > local_best_score:
                    local_best_score = current_score
                    local_best_pt = list(pt)
                    local_best_key = list(key)
            else:
                # Reject — undo
                pt[i1] = old_pt_i1

            T *= T_factor

        # Record
        if local_best_score > best_score:
            best_score = local_best_score
            best_pt = local_best_pt
            best_key = local_best_key
            best_sigma_inv = dict(sigma_inv)

        qg_per_char = local_best_score / (CT_LEN - 3)
        pt_str = "".join(ALPH[v] for v in local_best_pt)

        scores_history.append({
            "restart": restart,
            "score": local_best_score,
            "qg_per_char": qg_per_char,
            "bean": bean_ok,
            "accept_rate": accepted / max(n_steps, 1),
            "pt_prefix": pt_str[:50],
        })

        if (restart + 1) % max(1, n_restarts // 10) == 0 or restart == 0:
            print(f"  [{restart+1:>4}/{n_restarts}] qg/c={qg_per_char:.3f}"
                  f"  bean={'Y' if bean_ok else 'N'}"
                  f"  accept={accepted/max(n_steps,1):.2f}"
                  f"  PT={pt_str[:40]}...", flush=True)

    return best_score, best_pt, best_key, best_sigma_inv, scores_history


def main():
    print("=" * 60)
    print("E-S-21: SA on 24/24 Crib-Consistent Transposition Manifold")
    print("=" * 60)
    print(f"Model: CT = σ(Vig(PT, period_key))")
    print(f"24 crib positions are pre-satisfied; SA optimizes remaining 73")
    print()

    SEED = 20260218
    N_RESTARTS = 50
    N_STEPS = 500_000

    t0 = time.time()
    all_results = {}

    for period in [7, 5, 6]:
        for variant in ["vig", "beau"]:
            print(f"\n{'='*60}")
            print(f"  Period {period}, {variant} — {N_RESTARTS} restarts × {N_STEPS:,} steps")
            print(f"{'='*60}")

            best_score, best_pt, best_key, best_sigma, history = sa_search(
                period, variant, N_RESTARTS, N_STEPS,
                seed=SEED + period * 100 + (0 if variant == "vig" else 50)
            )

            qg_per_char = best_score / (CT_LEN - 3)
            pt_str = "".join(ALPH[v] for v in best_pt)
            key_str = "".join(ALPH[v] for v in best_key)

            bean_ok = check_bean(best_key, period)

            print(f"\n  Best: qg/c={qg_per_char:.3f}  bean={'PASS' if bean_ok else 'FAIL'}")
            print(f"  Key: {best_key} ({key_str})")
            print(f"  PT: {pt_str}")

            # Score distribution
            scores = [h["qg_per_char"] for h in history]
            print(f"  Score range: [{min(scores):.3f}, {max(scores):.3f}]")
            print(f"  Bean pass rate: {sum(1 for h in history if h['bean'])/len(history)*100:.0f}%")

            # Check: do the crib positions decrypt correctly?
            crib_check = sum(1 for j in CRIB_POS if best_pt[j] == CRIB_PT_NUM[j])
            print(f"  Crib verify: {crib_check}/24")

            all_results[f"p{period}_{variant}"] = {
                "period": period,
                "variant": variant,
                "best_qg_per_char": qg_per_char,
                "best_score": best_score,
                "best_key": best_key,
                "key_str": key_str,
                "best_pt": pt_str,
                "bean_pass": bean_ok,
                "crib_verify": crib_check,
                "n_restarts": N_RESTARTS,
                "n_steps": N_STEPS,
                "scores": scores,
            }

    elapsed = time.time() - t0

    # Summary
    print(f"\n{'='*60}")
    print(f"  SUMMARY")
    print(f"{'='*60}")
    print(f"  Time: {elapsed:.0f}s ({elapsed/60:.1f} min)")
    print(f"  Reference: English qg/c ≈ -4.285, Random qg/c ≈ -7.489")

    for config, result in sorted(all_results.items()):
        print(f"  {config}: qg/c={result['best_qg_per_char']:.3f}"
              f"  bean={'Y' if result['bean_pass'] else 'N'}"
              f"  cribs={result['crib_verify']}/24")

    # Expected result analysis
    # With 73 free positions and 24 fixed as English (cribs), SA should achieve
    # qg/c near English (~-4.3) since the 73 free positions can be shuffled freely.
    # The question is: does any configuration produce COHERENT English?
    print(f"\n  NOTE: With 73 free transposition positions, SA should trivially")
    print(f"  achieve qg/c ≈ -4.3 (English-like fragments, not coherent text).")
    print(f"  A REAL solution would show COHERENT English + meaningful key.")

    # Save
    with open("results/e_s_21_manifold_sa.json", "w") as f:
        json.dump(all_results, f, indent=2, default=str)

    print(f"\n  Artifacts: results/e_s_21_manifold_sa.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_21_manifold_sa.py")


if __name__ == "__main__":
    main()
