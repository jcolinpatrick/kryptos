#!/usr/bin/env python3
"""
Cipher: Compass group-rotation (base rate test)
Family: analysis
Status: active
Keyspace: 1M random partitions × 4096 keys (Monte Carlo)
Last run: never
Best score: n/a

BASE RATE TEST for Kimmo's "compass cipher" hypothesis:
  - Partition 26 letters into 4 ordered groups (~compass directions N/E/S/W)
  - Repeating key of length P from {0,1,2,3} where:
      0 = same group, 1 = next group, 2 = opposite, 3 = previous
  - For each (CT[i], PT[i]) crib pair: group(PT[i]) ≡ group(CT[i]) + key[i%P] (mod 4)

Kimmo found that key ADDABA (period 6, values [0,3,3,0,1,0]) with groups
{ACKRXYZ, BDHMPU, EILNOQT, FGJSVW} satisfies all 24 crib positions.

This script tests: how often does a RANDOM 4-partition admit ANY period-P key
that satisfies all 24 crib constraints? If the answer is "frequently", the
finding is noise. If "rarely", it's worth investigating further.

Tests periods 4-8 (Kimmo found period 6).

Phase 2: For partitions that DO satisfy both cribs, also attempt full
decryption (trying all within-group selection rules) and score with
score_candidate().

Usage: PYTHONPATH=src python3 -u scripts/analysis/e_compass_group_rotation_baserate.py
"""

import sys
import os
import random
import time
from collections import defaultdict
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Robust fallback: if the 2-level dirname chain didn't land on repo root, walk up until we find src/
while not os.path.exists(os.path.join(_ROOT, "src")):
    _parent = os.path.dirname(_ROOT)
    if _parent == _ROOT:
        raise RuntimeError("Could not locate kryptos repo root from compass script bootstrap")
    _ROOT = _parent
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, CRIB_DICT, N_CRIBS
from kryptos.kernel.scoring.aggregate import score_candidate

# ── Crib setup ───────────────────────────────────────────────────────────

# For each crib position, we have (ct_letter, pt_letter)
CRIB_PAIRS = []
for pos, pt_ch in sorted(CRIB_DICT.items()):
    ct_ch = CT[pos]
    CRIB_PAIRS.append((pos, ct_ch, pt_ch))

# Group crib positions by residue mod P
def crib_by_residue(period):
    """Group crib (pos, ct_char, pt_char) by pos % period."""
    residues = defaultdict(list)
    for pos, ct_ch, pt_ch in CRIB_PAIRS:
        residues[pos % period].append((pos, ct_ch, pt_ch))
    return dict(residues)


# ── Partition generation ─────────────────────────────────────────────────

def random_partition_4():
    """Generate a random partition of 26 letters into 4 ordered groups.

    Uses sizes (7, 6, 7, 6) to match Kimmo's finding, but also test
    (7, 7, 6, 6) for comparison.
    """
    letters = list(ALPH)
    random.shuffle(letters)
    # Random sizes summing to 26, each >= 5 (reasonable group size)
    # But to match Kimmo exactly: 7,6,7,6
    groups = [
        set(letters[0:7]),
        set(letters[7:13]),
        set(letters[13:20]),
        set(letters[20:26]),
    ]
    return groups


def random_partition_4_any_sizes():
    """Generate random partition with any sizes (min 4 per group)."""
    letters = list(ALPH)
    random.shuffle(letters)
    # Random split points ensuring min size 4
    while True:
        cuts = sorted(random.sample(range(4, 23), 3))
        sizes = [cuts[0], cuts[1]-cuts[0], cuts[2]-cuts[1], 26-cuts[2]]
        if all(s >= 4 for s in sizes):
            break
    groups = []
    idx = 0
    for s in sizes:
        groups.append(set(letters[idx:idx+s]))
        idx += s
    return groups


def letter_to_group(groups, ch):
    """Return group index (0-3) for a letter."""
    for i, g in enumerate(groups):
        if ch in g:
            return i
    return -1  # should never happen


# ── Constraint check ─────────────────────────────────────────────────────

def check_partition_period(groups, period):
    """Check if this partition admits any period-P key satisfying all cribs.

    For each residue r (mod period), all crib positions with pos%P == r
    must agree on: key[r] ≡ group(PT) - group(CT) (mod 4).

    Returns: (valid, key_if_valid)
    """
    residue_groups = crib_by_residue(period)

    key = [None] * period

    for r in range(period):
        if r not in residue_groups:
            # No constraint on this residue — any value works
            key[r] = 0  # arbitrary
            continue

        required = None
        for pos, ct_ch, pt_ch in residue_groups[r]:
            ct_grp = letter_to_group(groups, ct_ch)
            pt_grp = letter_to_group(groups, pt_ch)
            shift = (pt_grp - ct_grp) % 4

            if required is None:
                required = shift
            elif required != shift:
                return False, None

        key[r] = required

    return True, key


# ── Monte Carlo worker ───────────────────────────────────────────────────

def worker_baserate(args):
    """Test n_trials random partitions for periods 4-8.

    Returns dict: {period: count_of_valid_partitions}
    """
    n_trials, seed, size_mode = args
    rng = random.Random(seed)

    # Override module-level random with seeded instance
    counts = {p: 0 for p in range(4, 9)}

    for _ in range(n_trials):
        letters = list(ALPH)
        rng.shuffle(letters)

        if size_mode == "7676":
            groups = [
                set(letters[0:7]),
                set(letters[7:13]),
                set(letters[13:20]),
                set(letters[20:26]),
            ]
        else:  # "any"
            while True:
                cuts = sorted(rng.sample(range(4, 23), 3))
                sizes = [cuts[0], cuts[1]-cuts[0], cuts[2]-cuts[1], 26-cuts[2]]
                if all(s >= 4 for s in sizes):
                    break
            groups = []
            idx = 0
            for s in sizes:
                groups.append(set(letters[idx:idx+s]))
                idx += s

        for period in range(4, 9):
            valid, key = check_partition_period(groups, period)
            if valid:
                counts[period] += 1

    return counts


# ── Phase 2: Full decryption with within-group selection ────────────────

def decrypt_with_group_rotation(groups, key, ct, selection_mode="positional"):
    """Attempt full decryption using compass group-rotation.

    groups: list of 4 sets of letters
    key: list of ints (0-3), length = period
    ct: ciphertext string
    selection_mode: how to pick the specific letter within the target group

    For 'positional': the index of CT letter within its source group
    determines the index within the target group (mod target group size).
    Groups are sorted alphabetically for stable indexing.
    """
    # Convert sets to sorted lists for indexing
    sorted_groups = [sorted(g) for g in groups]

    # Build lookup: letter -> (group_idx, position_within_group)
    letter_info = {}
    for gi, grp in enumerate(sorted_groups):
        for pi, ch in enumerate(grp):
            letter_info[ch] = (gi, pi)

    pt_chars = []
    for i, c in enumerate(ct):
        ct_gi, ct_pi = letter_info[c]
        shift = key[i % len(key)]
        target_gi = (ct_gi + shift) % 4
        target_grp = sorted_groups[target_gi]

        if selection_mode == "positional":
            # Same position index, mod target group size
            target_pi = ct_pi % len(target_grp)
            pt_chars.append(target_grp[target_pi])
        elif selection_mode == "reverse":
            # Reverse position
            target_pi = (len(target_grp) - 1 - ct_pi) % len(target_grp)
            pt_chars.append(target_grp[target_pi])
        elif selection_mode == "offset":
            # Try all offsets within group (handled by caller)
            pt_chars.append(target_grp[ct_pi % len(target_grp)])

    return "".join(pt_chars)


def worker_decrypt(args):
    """For each valid partition+key, try decryption with various selection rules."""
    n_trials, seed = args
    rng = random.Random(seed)

    results = []

    for _ in range(n_trials):
        letters = list(ALPH)
        rng.shuffle(letters)
        groups = [
            set(letters[0:7]),
            set(letters[7:13]),
            set(letters[13:20]),
            set(letters[20:26]),
        ]

        for period in range(4, 9):
            valid, key = check_partition_period(groups, period)
            if not valid:
                continue

            # Try positional and reverse selection modes
            for mode in ("positional", "reverse"):
                pt = decrypt_with_group_rotation(groups, key, CT, mode)
                score_bd = score_candidate(pt)
                score = score_bd.crib_score

                if score >= 10:
                    results.append({
                        "period": period,
                        "key": key,
                        "groups": [sorted(g) for g in groups],
                        "mode": mode,
                        "score": score,
                        "pt_snippet": pt[:40],
                        "bean": score_bd.bean_passed,
                    })

    return results


# ── Kimmo verification ───────────────────────────────────────────────────

def verify_kimmo():
    """Verify Kimmo's specific finding: key ADDABA with his groups."""
    # Kimmo's groups (from image)
    groups = [
        set("ACKRXYZ"),   # Group 1
        set("BDHMPU"),    # Group 2
        set("EILNOQT"),   # Group 3
        set("FGJSVW"),    # Group 4
    ]

    # ADDABA: A=+1, D=0, so key = ?
    # From Kimmo's notation: A=next(+1), B=opposite(+2), C=prev(+3/-1), D=same(0)
    key_map = {"A": 1, "B": 2, "C": 3, "D": 0}
    kimmo_key_str = "ADDABA"
    key = [key_map[c] for c in kimmo_key_str]

    print("=" * 70)
    print("KIMMO VERIFICATION")
    print("=" * 70)
    print(f"Key: {kimmo_key_str} = {key}")
    print(f"Groups: {[sorted(g) for g in groups]}")
    print(f"Sizes: {[len(g) for g in groups]}")
    print()

    # Check each crib position
    all_ok = True
    for pos, ct_ch, pt_ch in CRIB_PAIRS:
        ct_gi = letter_to_group(groups, ct_ch)
        pt_gi = letter_to_group(groups, pt_ch)
        shift = key[pos % 6]
        expected_pt_gi = (ct_gi + shift) % 4
        ok = expected_pt_gi == pt_gi
        if not ok:
            all_ok = False
        label = "OK" if ok else "FAIL"
        print(f"  pos {pos:2d}: CT={ct_ch} (grp {ct_gi}) + shift {shift} -> "
              f"grp {expected_pt_gi}, PT={pt_ch} (grp {pt_gi}) [{label}]")

    print(f"\nAll crib constraints satisfied: {all_ok}")

    # Try decryption with positional mode
    print("\n--- Decryption attempts ---")
    for mode in ("positional", "reverse"):
        pt = decrypt_with_group_rotation(groups, key, CT, mode)
        score_bd = score_candidate(pt)
        print(f"  {mode:12s}: score={score_bd.crib_score}/24  "
              f"bean={score_bd.bean_passed}  pt={pt[:50]}...")

    print()
    return all_ok


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("COMPASS GROUP-ROTATION CIPHER — BASE RATE TEST")
    print("=" * 70)
    print(f"CT: {CT}")
    print(f"Crib positions: {N_CRIBS}")
    print(f"Testing: how often does a random 4-partition of the alphabet")
    print(f"admit a period-P key (P=4..8) satisfying all {N_CRIBS} crib constraints?")
    print()

    # Phase 0: Verify Kimmo's specific finding
    verify_kimmo()

    # Phase 1: Base rate Monte Carlo
    N_TRIALS = 1_000_000
    n_workers = max(1, cpu_count() - 2)
    trials_per_worker = N_TRIALS // n_workers

    print("=" * 70)
    print(f"PHASE 1: BASE RATE (Monte Carlo, {N_TRIALS:,} random partitions)")
    print(f"  Workers: {n_workers}")
    print(f"  Group sizes: 7,6,7,6 (matching Kimmo)")
    print("=" * 70)

    t0 = time.time()

    args_7676 = [
        (trials_per_worker, 42 + i, "7676")
        for i in range(n_workers)
    ]

    with Pool(n_workers) as pool:
        results_7676 = pool.map(worker_baserate, args_7676)

    # Aggregate
    total_trials = trials_per_worker * n_workers
    totals_7676 = {p: 0 for p in range(4, 9)}
    for r in results_7676:
        for p in range(4, 9):
            totals_7676[p] += r[p]

    elapsed = time.time() - t0

    print(f"\nCompleted in {elapsed:.1f}s")
    print(f"\n{'Period':>8s} {'Valid':>10s} {'Rate':>12s} {'Expected if random':>20s}")
    print("-" * 55)
    for p in range(4, 9):
        count = totals_7676[p]
        rate = count / total_trials
        print(f"{p:>8d} {count:>10,d} {rate:>12.6f} ({rate*100:.4f}%)")

    # Phase 1b: Any group sizes
    print()
    print("=" * 70)
    print(f"PHASE 1b: BASE RATE (any group sizes, min 4 per group)")
    print("=" * 70)

    t0 = time.time()

    args_any = [
        (trials_per_worker, 1000 + i, "any")
        for i in range(n_workers)
    ]

    with Pool(n_workers) as pool:
        results_any = pool.map(worker_baserate, args_any)

    totals_any = {p: 0 for p in range(4, 9)}
    for r in results_any:
        for p in range(4, 9):
            totals_any[p] += r[p]

    elapsed = time.time() - t0

    print(f"\nCompleted in {elapsed:.1f}s")
    print(f"\n{'Period':>8s} {'Valid':>10s} {'Rate':>12s}")
    print("-" * 35)
    for p in range(4, 9):
        count = totals_any[p]
        rate = count / total_trials
        print(f"{p:>8d} {count:>10,d} {rate:>12.6f} ({rate*100:.4f}%)")

    # Phase 2: Score valid partitions with full decryption
    print()
    print("=" * 70)
    print("PHASE 2: DECRYPTION SCORING (valid partitions only)")
    print("  Testing 'positional' and 'reverse' within-group selection")
    print("=" * 70)

    t0 = time.time()

    # Use fewer trials since we're doing more work per trial
    N_DECRYPT = 500_000
    decrypt_per_worker = N_DECRYPT // n_workers

    args_decrypt = [
        (decrypt_per_worker, 2000 + i)
        for i in range(n_workers)
    ]

    with Pool(n_workers) as pool:
        decrypt_results = pool.map(worker_decrypt, args_decrypt)

    # Collect all interesting results
    all_interesting = []
    for r in decrypt_results:
        all_interesting.extend(r)

    elapsed = time.time() - t0

    print(f"\nCompleted in {elapsed:.1f}s")
    print(f"Interesting results (score >= 10): {len(all_interesting)}")

    if all_interesting:
        all_interesting.sort(key=lambda x: -x["score"])
        print(f"\nTop results:")
        for r in all_interesting[:20]:
            print(f"  score={r['score']}/24 period={r['period']} "
                  f"mode={r['mode']} bean={r['bean']} "
                  f"pt={r['pt_snippet']}...")

    # Phase 3: Analytical constraint count
    print()
    print("=" * 70)
    print("PHASE 3: CONSTRAINT ANALYSIS")
    print("=" * 70)

    for period in range(4, 9):
        residues = crib_by_residue(period)
        n_constrained = 0
        n_unconstrained = 0
        constraints_per_residue = {}

        for r in range(period):
            if r in residues:
                n_constrained += 1
                constraints_per_residue[r] = len(residues[r])
            else:
                n_unconstrained += 1
                constraints_per_residue[r] = 0

        # For each constrained residue with k crib positions:
        # All k positions must agree on group shift.
        # Prob of agreement for one pair: 1/4 (random group assignment).
        # For k positions: first is free, each subsequent has 1/4 chance.
        # Total prob per residue with k constraints: (1/4)^(k-1)
        # Total prob across all constrained residues: product of (1/4)^(k-1)

        total_excess = sum(max(0, v - 1) for v in constraints_per_residue.values())
        analytical_prob = (1/4) ** total_excess

        print(f"\n  Period {period}:")
        print(f"    Constrained residues: {n_constrained}/{period}")
        print(f"    Constraints per residue: {constraints_per_residue}")
        print(f"    Excess constraints (must agree): {total_excess}")
        print(f"    Analytical probability: (1/4)^{total_excess} = {analytical_prob:.2e}")

    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print("If the base rate for period 6 is high (>0.1%), Kimmo's finding is")
    print("expected by chance and NOT significant.")
    print("If the base rate is very low (<0.01%), the finding warrants")
    print("investigation of within-group selection mechanisms.")


if __name__ == "__main__":
    main()
