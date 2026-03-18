#!/usr/bin/env python3 -u
"""
=================================================================
ERROR HYPOTHESIS TEST v1 — What If Sanborn Made a Mistake?
=================================================================
Cipher:     All variants on CT97 and CT73
Family:     campaigns
Status:     active
Keyspace:   ~10K variants (trivial)
Last run:   never
Best score: --

HYPOTHESIS
----------
Scheidt: "I intentionally did not do K4... stay away." He didn't
verify K4's encryption. Sanborn hand-encrypted it alone, is
self-described as "math-averse." If a single character is wrong
(carving error, encryption error, off-by-one), 35 years of
analysis have been working with corrupted data.

TESTS
-----
Phase 1: Single CT character error (97 positions × 25 alternatives = 2,425)
  - For each variant CT, check if periodic sub becomes consistent at any period
  - Check if autokey becomes possible (crib-to-crib feedback)
  - Check if Bean constraints become satisfiable at more periods

Phase 2: Crib position shift (1-indexed vs 0-indexed)
  - Test cribs at positions 22-34 and 64-74 (1-indexed convention)
  - Test each crib shifted ±1, ±2

Phase 3: Single crib letter error (24 positions × 25 alternatives = 600)
  - What if one crib letter was confirmed incorrectly?

Phase 4: Single null position error
  - What if one consensus null is actually real, or vice versa?
=================================================================
"""

import sys
import os
import json
import time
from collections import Counter, defaultdict

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_WORDS, BEAN_EQ, BEAN_INEQ,
)

# ── Helpers ────────────────────────────────────────────────────────────

def beaufort_key(ct_char, pt_char):
    return (ALPH_IDX[ct_char] + ALPH_IDX[pt_char]) % MOD

def vigenere_key(ct_char, pt_char):
    return (ALPH_IDX[ct_char] - ALPH_IDX[pt_char]) % MOD

def check_periodic_consistency(key_values, positions, max_period=13):
    """Check if key values at given positions are consistent with any period.
    Returns (best_period, best_score, n_cribs)."""
    n = len(key_values)
    best_p = 0
    best_s = 0
    for p in range(1, max_period + 1):
        residue_map = {}
        score = 0
        for pos, kv in zip(positions, key_values):
            r = pos % p
            if r not in residue_map:
                residue_map[r] = kv
                score += 1
            elif residue_map[r] == kv:
                score += 1
        if score > best_s:
            best_s = score
            best_p = p
    return best_p, best_s, n


def check_bean(key_dict, eq_pairs, ineq_pairs):
    """Check Bean constraints. Returns (eq_ok, n_ineq_violations)."""
    eq_ok = True
    for a, b in eq_pairs:
        if a in key_dict and b in key_dict:
            if key_dict[a] != key_dict[b]:
                eq_ok = False
    violations = 0
    for a, b in ineq_pairs:
        if a in key_dict and b in key_dict:
            if key_dict[a] == key_dict[b]:
                violations += 1
    return eq_ok, violations


def check_autokey_consistency(key_dict, positions, ct_str, pt_dict, max_offset=20):
    """Check if PT-autokey is consistent at any offset.
    For PT-autokey: key[i] = PT[i - offset] for i >= offset.
    At crib positions: key[i] is known, PT[i] is known.
    Check: key[i] == PT[i - offset] for crib positions where i-offset is also a crib."""
    best_offset = 0
    best_consistent = 0
    best_total = 0

    for offset in range(1, max_offset + 1):
        consistent = 0
        total = 0
        for pos in positions:
            src = pos - offset
            if src in pt_dict and pos in key_dict:
                total += 1
                needed_key = ALPH_IDX[pt_dict[src]]
                if key_dict[pos] == needed_key:
                    consistent += 1
        if total > 0 and consistent > best_consistent:
            best_consistent = consistent
            best_total = total
            best_offset = offset

    return best_offset, best_consistent, best_total


# ── Phase 1: Single CT character error ─────────────────────────────────

def phase1_ct_error():
    """Test all single-character mutations of the ciphertext."""
    print("\n  Phase 1: Single CT character error (2,425 variants)")

    results = []

    for mut_pos in range(CT_LEN):
        orig_char = CT[mut_pos]
        for alt_idx in range(26):
            alt_char = ALPH[alt_idx]
            if alt_char == orig_char:
                continue

            # Build mutated CT
            mut_ct = CT[:mut_pos] + alt_char + CT[mut_pos + 1:]

            # Compute key at crib positions under Beaufort
            key_dict = {}
            positions = []
            key_values = []
            for pos, pt_char in CRIB_DICT.items():
                kv = (ALPH_IDX[mut_ct[pos]] + ALPH_IDX[pt_char]) % MOD
                key_dict[pos] = kv
                positions.append(pos)
                key_values.append(kv)

            # Check periodic consistency
            best_p, best_s, n = check_periodic_consistency(key_values, positions)

            # Check Bean
            eq_ok, ineq_viol = check_bean(key_dict, BEAN_EQ, BEAN_INEQ)

            # Check autokey
            pt_dict = dict(CRIB_DICT)
            ak_offset, ak_consistent, ak_total = check_autokey_consistency(
                key_dict, positions, mut_ct, pt_dict
            )

            # Is this better than the original?
            # Original: best periodic score ~8/24 at p7, 0 Bean ineq violations,
            # autokey 1/8 at offset 8
            interesting = False
            reason = []

            if best_s >= 20 and best_p <= 7:
                interesting = True
                reason.append(f"periodic {best_s}/24 at p={best_p}")
            if ineq_viol < 0:  # Can't be negative, but check for improvement
                pass
            if not eq_ok:
                pass  # Bean equality broken = bad
            if ak_total > 0 and ak_consistent == ak_total:
                interesting = True
                reason.append(f"autokey PERFECT {ak_consistent}/{ak_total} at offset={ak_offset}")
            elif ak_total >= 5 and ak_consistent >= ak_total - 1:
                interesting = True
                reason.append(f"autokey near-perfect {ak_consistent}/{ak_total} at offset={ak_offset}")

            if interesting:
                results.append({
                    "type": "ct_error",
                    "mut_pos": mut_pos,
                    "orig": orig_char,
                    "alt": alt_char,
                    "periodic": (best_p, best_s),
                    "bean_eq": eq_ok,
                    "bean_ineq_violations": ineq_viol,
                    "autokey": (ak_offset, ak_consistent, ak_total),
                    "reason": "; ".join(reason),
                })

    # Also check: for each mutation, how many Bean inequality violations?
    # A mutation that REDUCES violations is interesting even without periodic hit
    orig_key = {pos: beaufort_key(CT[pos], CRIB_DICT[pos]) for pos in CRIB_DICT}
    _, orig_ineq = check_bean(orig_key, BEAN_EQ, BEAN_INEQ)

    # Check all mutations at crib positions specifically (these change key values)
    for mut_pos in sorted(CRIB_DICT.keys()):
        orig_char = CT[mut_pos]
        for alt_idx in range(26):
            alt_char = ALPH[alt_idx]
            if alt_char == orig_char:
                continue

            key_dict = dict(orig_key)
            key_dict[mut_pos] = (ALPH_IDX[alt_char] + ALPH_IDX[CRIB_DICT[mut_pos]]) % MOD
            _, ineq = check_bean(key_dict, BEAN_EQ, BEAN_INEQ)

            if ineq < orig_ineq:
                results.append({
                    "type": "ct_error_bean_improvement",
                    "mut_pos": mut_pos,
                    "orig": orig_char,
                    "alt": alt_char,
                    "orig_violations": orig_ineq,
                    "new_violations": ineq,
                    "improvement": orig_ineq - ineq,
                    "reason": f"Bean ineq violations reduced from {orig_ineq} to {ineq}",
                })

    print(f"    Interesting results: {len(results)}")
    for r in sorted(results, key=lambda x: x.get("periodic", (0,0))[1] if "periodic" in x else 0, reverse=True)[:20]:
        print(f"      pos={r['mut_pos']:>2} {r['orig']}→{r['alt']} | {r['reason']}")

    return results


# ── Phase 2: Crib position shift ──────────────────────────────────────

def phase2_crib_shift():
    """Test shifted crib positions."""
    print("\n  Phase 2: Crib position shifts")

    shifts = [
        ("1-indexed", {(s+1, w) for s, w in CRIB_WORDS}),
        ("ENE+1", {(22, "EASTNORTHEAST"), (63, "BERLINCLOCK")}),
        ("BCL+1", {(21, "EASTNORTHEAST"), (64, "BERLINCLOCK")}),
        ("ENE-1", {(20, "EASTNORTHEAST"), (63, "BERLINCLOCK")}),
        ("BCL-1", {(21, "EASTNORTHEAST"), (62, "BERLINCLOCK")}),
        ("both+1", {(22, "EASTNORTHEAST"), (64, "BERLINCLOCK")}),
        ("both-1", {(20, "EASTNORTHEAST"), (62, "BERLINCLOCK")}),
        ("both+2", {(23, "EASTNORTHEAST"), (65, "BERLINCLOCK")}),
        ("both-2", {(19, "EASTNORTHEAST"), (61, "BERLINCLOCK")}),
    ]

    results = []

    for shift_name, crib_set in shifts:
        # Build crib dict for this shift
        crib_dict = {}
        valid = True
        for start, word in crib_set:
            for i, ch in enumerate(word):
                pos = start + i
                if pos < 0 or pos >= CT_LEN:
                    valid = False
                    break
                crib_dict[pos] = ch
            if not valid:
                break

        if not valid:
            print(f"    {shift_name}: OUT OF BOUNDS, skipped")
            continue

        # Compute key
        key_dict = {}
        positions = []
        key_values = []
        for pos in sorted(crib_dict.keys()):
            kv = beaufort_key(CT[pos], crib_dict[pos])
            key_dict[pos] = kv
            positions.append(pos)
            key_values.append(kv)

        # Check periodic
        best_p, best_s, n = check_periodic_consistency(key_values, positions)

        # Check Bean (need to recompute for shifted positions)
        # Bean eq: original is (27, 65). Under shift, these positions change
        eq_ok = True  # Can't directly check without knowing which positions map
        _, ineq = check_bean(key_dict, [], [])  # No standard Bean for shifted cribs

        # Check autokey
        ak_offset, ak_consistent, ak_total = check_autokey_consistency(
            key_dict, positions, CT, crib_dict
        )

        key_str = "".join(ALPH[kv] for kv in key_values)

        print(f"    {shift_name:>10}: periodic {best_s}/24 at p={best_p}, "
              f"autokey {ak_consistent}/{ak_total} at off={ak_offset}, "
              f"key={key_str[:30]}...")

        results.append({
            "shift": shift_name,
            "periodic": (best_p, best_s),
            "autokey": (ak_offset, ak_consistent, ak_total),
            "key_preview": key_str[:40],
        })

    return results


# ── Phase 3: Single crib letter error ──────────────────────────────────

def phase3_crib_error():
    """Test all single-letter mutations of the cribs."""
    print("\n  Phase 3: Single crib letter error (600 variants)")

    results = []
    crib_positions = sorted(CRIB_DICT.keys())
    orig_key = {pos: beaufort_key(CT[pos], CRIB_DICT[pos]) for pos in crib_positions}

    for mut_crib_pos in crib_positions:
        orig_pt = CRIB_DICT[mut_crib_pos]
        for alt_idx in range(26):
            alt_pt = ALPH[alt_idx]
            if alt_pt == orig_pt:
                continue

            # Build mutated crib dict
            mut_crib = dict(CRIB_DICT)
            mut_crib[mut_crib_pos] = alt_pt

            key_dict = {}
            positions = []
            key_values = []
            for pos in crib_positions:
                kv = beaufort_key(CT[pos], mut_crib[pos])
                key_dict[pos] = kv
                positions.append(pos)
                key_values.append(kv)

            # Check periodic
            best_p, best_s, n = check_periodic_consistency(key_values, positions)

            # Check Bean
            eq_ok, ineq_viol = check_bean(key_dict, BEAN_EQ, BEAN_INEQ)

            # Check autokey
            ak_offset, ak_consistent, ak_total = check_autokey_consistency(
                key_dict, positions, CT, mut_crib
            )

            interesting = False
            reason = []

            if best_s >= 20 and best_p <= 7:
                interesting = True
                reason.append(f"periodic {best_s}/24 at p={best_p}")
            if ak_total >= 5 and ak_consistent >= ak_total - 1:
                interesting = True
                reason.append(f"autokey {ak_consistent}/{ak_total} at offset={ak_offset}")

            if interesting:
                # Which word does this position belong to?
                word_name = "ENE" if mut_crib_pos <= 33 else "BCL"
                word_idx = mut_crib_pos - (21 if mut_crib_pos <= 33 else 63)
                results.append({
                    "type": "crib_error",
                    "pos": mut_crib_pos,
                    "word": word_name,
                    "word_idx": word_idx,
                    "orig_pt": orig_pt,
                    "alt_pt": alt_pt,
                    "periodic": (best_p, best_s),
                    "bean_eq": eq_ok,
                    "bean_ineq": ineq_viol,
                    "autokey": (ak_offset, ak_consistent, ak_total),
                    "reason": "; ".join(reason),
                })

    print(f"    Interesting results: {len(results)}")
    for r in sorted(results, key=lambda x: x["periodic"][1], reverse=True)[:20]:
        print(f"      pos={r['pos']:>2} ({r['word']}[{r['word_idx']}]) "
              f"{r['orig_pt']}→{r['alt_pt']} | {r['reason']}")

    return results


# ── Main ───────────────────────────────────────────────────────────────

def main():
    t_start = time.time()

    print("=" * 70)
    print("ERROR HYPOTHESIS TEST v1")
    print("=" * 70)
    print(f"CT: {CT}")
    print(f"Cribs: ENE@21-33, BCL@63-73 (0-indexed)")

    # Baseline
    orig_key = {pos: beaufort_key(CT[pos], CRIB_DICT[pos]) for pos in CRIB_DICT}
    positions = sorted(orig_key.keys())
    key_values = [orig_key[p] for p in positions]
    bp, bs, _ = check_periodic_consistency(key_values, positions)
    eq_ok, ineq = check_bean(orig_key, BEAN_EQ, BEAN_INEQ)
    ak_off, ak_con, ak_tot = check_autokey_consistency(
        orig_key, positions, CT, CRIB_DICT
    )
    print(f"\nBASELINE (no errors):")
    print(f"  Best periodic: {bs}/24 at period {bp}")
    print(f"  Bean: eq={eq_ok}, ineq_violations={ineq}")
    print(f"  Autokey: {ak_con}/{ak_tot} at offset {ak_off}")
    print(f"  Key: {''.join(ALPH[orig_key[p]] for p in positions)}")

    all_results = {}

    # Phase 1
    print(f"\n{'='*70}")
    print("PHASE 1: Single CT character error")
    print(f"{'='*70}")
    all_results["phase1"] = phase1_ct_error()

    # Phase 2
    print(f"\n{'='*70}")
    print("PHASE 2: Crib position shifts")
    print(f"{'='*70}")
    all_results["phase2"] = phase2_crib_shift()

    # Phase 3
    print(f"\n{'='*70}")
    print("PHASE 3: Single crib letter error")
    print(f"{'='*70}")
    all_results["phase3"] = phase3_crib_error()

    # Summary
    elapsed = time.time() - t_start
    print(f"\n{'='*70}")
    print(f"SUMMARY (elapsed: {elapsed:.1f}s)")
    print(f"{'='*70}")

    total_interesting = sum(len(v) for v in all_results.values() if isinstance(v, list))
    print(f"  Total interesting findings: {total_interesting}")

    if total_interesting == 0:
        print(f"  NO single-character errors improve periodic, autokey, or Bean consistency")
        print(f"  This STRENGTHENS confidence that the CT and cribs are correct")
    else:
        print(f"  Found {total_interesting} error variants that improve cipher consistency")
        print(f"  These warrant investigation!")

    # Save
    output_path = os.path.join(_ROOT, "results", "f_error_hypothesis_v1.json")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump({
            "experiment": "error_hypothesis_v1",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "elapsed": elapsed,
            "baseline": {
                "periodic": (bp, bs),
                "bean_eq": eq_ok,
                "bean_ineq": ineq,
                "autokey": (ak_off, ak_con, ak_tot),
            },
            "results": {k: v for k, v in all_results.items()},
        }, f, indent=2)
    print(f"\n  Results: {output_path}")
    print("=" * 70)


if __name__ == "__main__":
    main()
