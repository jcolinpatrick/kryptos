#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-26: Bean-Constrained Manifold SA

Key insight from E-S-21: 0% of random 24/24 crib-consistent assignments
pass Bean at period 7. This means Bean + cribs together are extremely
constraining. This experiment generates assignments that satisfy BOTH
24/24 cribs AND Bean, then does SA to optimize quadgrams.

Bean equality at period 7: key[6] = key[2] (since 27%7=6, 65%7=2).
Bean inequalities: 21 constraints on key value pairs.

To generate Bean-passing assignments:
1. Merge residue classes 2 and 6 (forced to share key value)
2. Process this merged class first
3. Process remaining classes independently
4. Check all 21 Bean inequalities

Output: results/e_s_26_bean_manifold_sa.json
"""
import json
import math
import random
import sys
import time
from collections import defaultdict, Counter

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

CT_POS_BY_VAL = defaultdict(list)
for i, v in enumerate(CT_NUM):
    CT_POS_BY_VAL[v].append(i)


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


# ── Bean-aware valid assignment generation ───────────────────────────────

def generate_bean_valid_assignment(period, variant="vig", max_attempts=1000):
    """Generate a valid partial assignment that satisfies BOTH cribs AND Bean.

    Key strategy: merge residue classes linked by Bean equality,
    then check Bean inequalities after assigning all classes.
    """
    # Build residue groups
    residue_groups = defaultdict(list)
    for j in CRIB_POS:
        residue_groups[j % period].append(j)

    # Merge residue classes linked by Bean equality
    merged = {}  # residue -> merged_group_id
    merged_groups = {}
    group_id = 0
    for pos_a, pos_b in BEAN_EQ:
        ra, rb = pos_a % period, pos_b % period
        ga = merged.get(ra)
        gb = merged.get(rb)
        if ga is None and gb is None:
            merged[ra] = group_id
            merged[rb] = group_id
            merged_groups[group_id] = {ra, rb}
            group_id += 1
        elif ga is not None and gb is None:
            merged[rb] = ga
            merged_groups[ga].add(rb)
        elif ga is None and gb is not None:
            merged[ra] = gb
            merged_groups[gb].add(ra)
        elif ga != gb:
            # Merge two existing groups
            for r in merged_groups[gb]:
                merged[r] = ga
            merged_groups[ga].update(merged_groups[gb])
            del merged_groups[gb]

    # Add ungrouped residues
    for res in residue_groups:
        if res not in merged:
            merged[res] = group_id
            merged_groups[group_id] = {res}
            group_id += 1

    # Build Bean inequality lookup
    ineq_pairs = set()
    for pos_a, pos_b in BEAN_INEQ:
        ra, rb = pos_a % period, pos_b % period
        if ra != rb:
            ineq_pairs.add((min(ra, rb), max(ra, rb)))

    for attempt in range(max_attempts):
        sigma_inv_partial = {}
        key = [None] * period
        used_ct = set()
        success = True

        # Process merged groups in random order
        mg_ids = list(merged_groups.keys())
        random.shuffle(mg_ids)

        for mg_id in mg_ids:
            residues_in_group = sorted(merged_groups[mg_id])

            # Collect ALL crib positions across merged residues
            all_positions = []
            for res in residues_in_group:
                all_positions.extend(residue_groups.get(res, []))

            if not all_positions:
                continue

            # Try random key values
            key_attempts = list(range(MOD))
            random.shuffle(key_attempts)

            found = False
            for key_val in key_attempts:
                # Compute required CT values for all positions
                required = []
                for j in all_positions:
                    pt_val = CRIB_PT_NUM[j]
                    if variant == "vig":
                        req = (key_val + pt_val) % MOD
                    else:
                        req = (key_val - pt_val) % MOD
                    required.append(req)

                # Check if enough CT positions are available
                pos_options = []
                ok = True
                for req in required:
                    available = [p for p in CT_POS_BY_VAL[req] if p not in used_ct]
                    if not available:
                        ok = False
                        break
                    pos_options.append(available)

                if not ok:
                    continue

                # Greedily assign positions
                assigned = {}
                temp_used = set()
                assign_ok = True
                for i, opts in enumerate(pos_options):
                    filtered = [p for p in opts if p not in temp_used]
                    if not filtered:
                        assign_ok = False
                        break
                    chosen = random.choice(filtered)
                    assigned[all_positions[i]] = chosen
                    temp_used.add(chosen)

                if assign_ok:
                    # Check Bean inequalities for this key value
                    # against already-assigned residues
                    ineq_ok = True
                    for res in residues_in_group:
                        for other_res in range(period):
                            if key[other_res] is not None:
                                pair = (min(res, other_res), max(res, other_res))
                                if pair in ineq_pairs and key_val == key[other_res]:
                                    ineq_ok = False
                                    break
                        if not ineq_ok:
                            break

                    if ineq_ok:
                        sigma_inv_partial.update(assigned)
                        used_ct.update(temp_used)
                        for res in residues_in_group:
                            key[res] = key_val
                        found = True
                        break

            if not found:
                success = False
                break

        if success:
            # Final Bean check
            bean_ok = True
            for pos_a, pos_b in BEAN_EQ:
                if key[pos_a % period] != key[pos_b % period]:
                    bean_ok = False
                    break
            if bean_ok:
                for pos_a, pos_b in BEAN_INEQ:
                    if key[pos_a % period] == key[pos_b % period]:
                        bean_ok = False
                        break
            if bean_ok:
                return sigma_inv_partial, key

    return None, None


def build_full_transposition(sigma_inv_partial):
    used_ct = set(sigma_inv_partial.values())
    free_ct = [i for i in range(N) if i not in used_ct]
    free_pt = [i for i in range(N) if i not in sigma_inv_partial]
    random.shuffle(free_ct)
    sigma_inv = dict(sigma_inv_partial)
    for pt_pos, ct_pos in zip(free_pt, free_ct):
        sigma_inv[pt_pos] = ct_pos
    return sigma_inv


def decrypt_with_transposition(sigma_inv, key, period, variant="vig"):
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
    for a, b in BEAN_EQ:
        if key[a % period] != key[b % period]:
            return False
    for a, b in BEAN_INEQ:
        if key[a % period] == key[b % period]:
            return False
    return True


# ── SA search ───────────────────────────────────────────────────────────

def sa_bean_search(period, variant, n_restarts, n_steps, seed=None):
    """SA on the Bean + crib-consistent manifold."""
    if seed is not None:
        random.seed(seed)

    best_score = -1e18
    best_pt = None
    best_key = None
    n_generated = 0
    n_failed = 0
    scores_history = []

    t0 = time.time()

    for restart in range(n_restarts):
        # Generate Bean-passing valid assignment
        sigma_inv_partial, key = generate_bean_valid_assignment(period, variant)
        if sigma_inv_partial is None:
            n_failed += 1
            continue
        n_generated += 1

        sigma_inv = build_full_transposition(sigma_inv_partial)
        pt = decrypt_with_transposition(sigma_inv, key, period, variant)
        current_score = quadgram_score(pt)

        local_best_score = current_score
        local_best_pt = list(pt)
        local_best_key = list(key)

        T_start = 2.0
        T_end = 0.01
        T_factor = (T_end / T_start) ** (1.0 / max(n_steps, 1))
        T = T_start

        accepted = 0
        for step in range(n_steps):
            i1, i2 = random.sample(NON_CRIB_POS, 2)

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

            # Compute quadgram delta (deduplicated)
            affected = set()
            for pos in [i1, i2]:
                for start in range(max(0, pos - 3), min(N - 3, pos + 1)):
                    affected.add(start)

            old_qg = 0.0
            for start in affected:
                vals = [pt[start + j] for j in range(4)]
                idx = vals[0] * 17576 + vals[1] * 676 + vals[2] * 26 + vals[3]
                old_qg += QG.get(idx, QG_FLOOR)

            pt[i1] = new_pt_i1
            pt[i2] = new_pt_i2

            new_qg = 0.0
            for start in affected:
                vals = [pt[start + j] for j in range(4)]
                idx = vals[0] * 17576 + vals[1] * 676 + vals[2] * 26 + vals[3]
                new_qg += QG.get(idx, QG_FLOOR)

            delta = new_qg - old_qg
            new_score = current_score + delta

            if delta > 0 or random.random() < math.exp(delta / T):
                sigma_inv[i1], sigma_inv[i2] = sigma_inv[i2], sigma_inv[i1]
                current_score = new_score
                accepted += 1
                if current_score > local_best_score:
                    local_best_score = current_score
                    local_best_pt = list(pt)
                    local_best_key = list(key)
            else:
                pt[i1] = old_pt_i1
                pt[i2] = old_pt_i2

            T *= T_factor

            if step > 0 and step % 50_000 == 0:
                current_score = quadgram_score(pt)

        # Final recalibration
        local_best_qg = quadgram_score(local_best_pt)
        local_best_score = local_best_qg

        if local_best_score > best_score:
            best_score = local_best_score
            best_pt = local_best_pt
            best_key = local_best_key

        qg_per_char = local_best_score / (N - 3)
        pt_str = "".join(ALPH[v] for v in local_best_pt)

        scores_history.append({
            "restart": restart,
            "qg_per_char": qg_per_char,
            "accept_rate": accepted / max(n_steps, 1),
        })

        elapsed = time.time() - t0
        if (restart + 1) % max(1, n_restarts // 20) == 0 or restart == 0:
            print(f"  [{restart+1:>4}/{n_restarts}] qg/c={qg_per_char:.3f}"
                  f"  accept={accepted/max(n_steps,1):.2f}"
                  f"  gen={n_generated} fail={n_failed}"
                  f"  PT={pt_str[:40]}..."
                  f"  ({elapsed:.0f}s)", flush=True)

    return best_score, best_pt, best_key, n_generated, n_failed, scores_history


def main():
    print("=" * 60)
    print("E-S-26: Bean-Constrained Manifold SA")
    print("=" * 60)
    print(f"Model: CT = σ(Vig(PT, period_key))")
    print(f"Constraint: 24/24 cribs AND Bean equality+inequalities")
    print(f"This manifold is MUCH smaller than the crib-only manifold")
    print()

    SEED = 20260218
    N_RESTARTS = 100
    N_STEPS = 500_000

    # First, measure Bean generation success rate
    print("Phase 0: Measuring Bean generation rate...")
    random.seed(SEED)
    n_attempts = 1000
    n_success = 0
    for _ in range(n_attempts):
        s, k = generate_bean_valid_assignment(7, "vig")
        if s is not None:
            n_success += 1
    bean_rate = n_success / n_attempts
    print(f"  Bean+crib generation rate (p=7 vig): {n_success}/{n_attempts} = {bean_rate*100:.1f}%")

    random.seed(SEED + 1)
    n_success_b = 0
    for _ in range(n_attempts):
        s, k = generate_bean_valid_assignment(7, "beau")
        if s is not None:
            n_success_b += 1
    bean_rate_b = n_success_b / n_attempts
    print(f"  Bean+crib generation rate (p=7 beau): {n_success_b}/{n_attempts} = {bean_rate_b*100:.1f}%")

    t0 = time.time()
    all_results = {}

    for variant in ["vig", "beau"]:
        for period in [7]:
            config_name = f"p{period}_{variant}"
            print(f"\n{'='*60}")
            print(f"  {config_name} — {N_RESTARTS} restarts × {N_STEPS:,} steps")
            print(f"  (Bean+crib constrained)")
            print(f"{'='*60}")

            best_score, best_pt, best_key, n_gen, n_fail, history = sa_bean_search(
                period, variant, N_RESTARTS, N_STEPS,
                seed=SEED + (0 if variant == "vig" else 50)
            )

            if best_pt is None:
                print(f"  FAILED to generate any Bean-passing assignments!")
                all_results[config_name] = {"status": "FAILED", "n_generated": n_gen, "n_failed": n_fail}
                continue

            qg_per_char = best_score / (N - 3)
            pt_str = "".join(ALPH[v] for v in best_pt)
            key_str = "".join(ALPH[v] for v in best_key)

            # Crib verify
            crib_check = sum(1 for j in CRIB_POS if best_pt[j] == CRIB_PT_NUM[j])

            print(f"\n  Best: qg/c={qg_per_char:.3f}")
            print(f"  Key: {best_key} ({key_str})")
            print(f"  PT: {pt_str}")
            print(f"  Crib verify: {crib_check}/24")
            print(f"  Bean: PASS (by construction)")
            print(f"  Generated: {n_gen}, Failed: {n_fail}")

            scores = [h["qg_per_char"] for h in history]
            if scores:
                print(f"  Score range: [{min(scores):.3f}, {max(scores):.3f}]")

            all_results[config_name] = {
                "period": period,
                "variant": variant,
                "best_qg_per_char": qg_per_char,
                "best_score": best_score,
                "best_key": best_key,
                "key_str": key_str,
                "best_pt": pt_str,
                "bean_pass": True,
                "crib_verify": crib_check,
                "n_generated": n_gen,
                "n_failed": n_fail,
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
    print(f"  Reference: E-S-21 (no Bean): qg/c ≈ -3.77 (BETTER than English)")
    print(f"  Question: Does Bean constraint push qg/c WORSE?")
    print()

    for config, result in sorted(all_results.items()):
        if result.get("status") == "FAILED":
            print(f"  {config}: FAILED (couldn't generate Bean-passing assignments)")
        else:
            print(f"  {config}: qg/c={result['best_qg_per_char']:.3f}"
                  f"  gen={result['n_generated']} fail={result['n_failed']}"
                  f"  cribs={result['crib_verify']}/24")

    print(f"\n  If qg/c is MUCH WORSE with Bean, then Bean significantly")
    print(f"  constrains the transposition space (useful discriminator).")
    print(f"  If similar, Bean doesn't add much beyond cribs alone.")

    # Save
    with open("results/e_s_26_bean_manifold_sa.json", "w") as f:
        json.dump(all_results, f, indent=2, default=str)

    print(f"\n  Artifact: results/e_s_26_bean_manifold_sa.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_26_bean_manifold_sa.py")


if __name__ == "__main__":
    main()
