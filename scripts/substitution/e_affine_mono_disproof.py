#!/usr/bin/env python3
"""
Cipher: monoalphabetic substitution
Family: substitution
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-AFFINE-MONO: Monoalphabetic Affine Cipher — Exhaustive Disproof.

Tests ALL 312 valid monoalphabetic affine keys against K4:
  PT[i] = a_inv * (CT[i] - b) mod 26
  where gcd(a, 26) = 1  → 12 valid 'a' values × 26 'b' values = 312 keys

For each key:
  1. Decrypt full K4 ciphertext
  2. Check crib positions: 21-33 = EASTNORTHEAST, 63-73 = BERLINCLOCK
  3. Check Bean equality: PT[27] == PT[65] (should both be 'R')
  4. Score plaintext with English quadgrams

This is a DISPROOF experiment. The bar for elimination is that NO key
achieves crib score > noise (score <= 7 for any period-1 cipher is
expected by random chance since 24 positions in an affine decryption
will either ALL match cribs or NONE will, making 0 or 24 the only
possible crib scores — see reasoning below).

REASONING:
A monoalphabetic affine cipher maps EVERY occurrence of a letter the
same way. Since the crib positions require specific PT letters, the
cipher is falsified if any mismatch occurs. With 24 crib positions
covering 14 distinct PT letters and 14 distinct CT letters, ANY affine
key either satisfies ALL constraints simultaneously or fails. The
probability of all 24 satisfying a random affine key is negligible.

Expected random crib score for period=1 affine cipher:
  - CT positions 21-33 must decode to EASTNORTHEAST
  - CT positions 63-73 must decode to BERLINCLOCK
  - With 312 keys and 24 distinct crib constraints, expected hits ≈ 0

Repro: PYTHONPATH=src python3 -u scripts/e_affine_mono_disproof.py
"""
from __future__ import annotations

import json
import math
import sys
import time
from math import gcd

sys.path.insert(0, "src")

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS, CRIB_POSITIONS,
    BEAN_EQ,
)
from kryptos.kernel.scoring.ngram import get_default_scorer

# ── Pre-computation ───────────────────────────────────────────────────────

CT_IDX = [ALPH_IDX[c] for c in CT]

# Valid 'a' values: gcd(a, 26) == 1
VALID_A = [a for a in range(1, MOD) if gcd(a, MOD) == 1]
# = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
assert len(VALID_A) == 12, f"Expected 12 valid a-values, got {len(VALID_A)}"

# Precompute modular inverses for all valid a values
MOD_INV: dict[int, int] = {}
for a in VALID_A:
    for b in range(1, MOD + 1):
        if (a * b) % MOD == 1:
            MOD_INV[a] = b
            break

# Precompute crib as (position, expected_pt_idx) pairs
CRIB_PAIRS = [(pos, ALPH_IDX[ch]) for pos, ch in sorted(CRIB_DICT.items())]
CRIB_CT_IDX = [(pos, CT_IDX[pos], ALPH_IDX[ch]) for pos, ch in sorted(CRIB_DICT.items())]

# Bean equality pairs
BEAN_POS = [(i, j) for i, j in BEAN_EQ]  # [(27, 65)]


def affine_decrypt(a: int, b: int) -> str:
    """Decrypt K4 ciphertext under affine key (a, b).

    PT[i] = a_inv * (CT[i] - b) mod 26
    """
    a_inv = MOD_INV[a]
    return "".join(ALPH[(a_inv * (c - b)) % MOD] for c in CT_IDX)


def count_cribs(pt_indices: list[int]) -> int:
    """Count how many crib positions match expected PT letters."""
    return sum(
        1
        for pos, ct_val, expected_pt in CRIB_CT_IDX
        if pt_indices[pos] == expected_pt
    )


def check_bean(pt_indices: list[int]) -> bool:
    """Check Bean equality constraint: PT[27] == PT[65]."""
    return all(pt_indices[i] == pt_indices[j] for i, j in BEAN_POS)


def solve_key_from_crib(ct_pos: int, pt_char: str) -> list[tuple[int, int]]:
    """Given CT[ct_pos] and known PT[ct_pos]=pt_char, find all (a,b) pairs.

    For affine: CT = a*PT + b mod 26
    => b = CT - a*PT mod 26
    Valid for all 12 a values.
    """
    ct_val = CT_IDX[ct_pos]
    pt_val = ALPH_IDX[pt_char]
    pairs = []
    for a in VALID_A:
        b = (ct_val - a * pt_val) % MOD
        pairs.append((a, b))
    return pairs


def main() -> None:
    print("=" * 70)
    print("E-AFFINE-MONO: Monoalphabetic Affine Cipher — Exhaustive Disproof")
    print("=" * 70)
    print(f"K4 CT: {CT}")
    print(f"Length: {CT_LEN}")
    print(f"Valid a values ({len(VALID_A)}): {VALID_A}")
    print(f"Total keys: {len(VALID_A)} × 26 = {len(VALID_A) * 26}")
    print(f"Crib positions: {N_CRIBS} chars at pos 21-33 (EASTNORTHEAST) + 63-73 (BERLINCLOCK)")
    print()

    # Load quadgram scorer
    try:
        scorer = get_default_scorer()
        print("Quadgram scorer: LOADED")
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    # ── Phase 0: Algebraic Analysis ───────────────────────────────────
    print("=" * 50)
    print("Phase 0: Algebraic Constraint Analysis")
    print("=" * 50)
    print()
    print("For a monoalphabetic affine cipher CT = a*PT + b mod 26,")
    print("each crib position (CT[pos], PT[pos]) constrains (a, b):")
    print(f"  b = CT[pos] - a * PT[pos]  mod 26")
    print()

    # Show what each crib position implies
    # Collect all (a,b) candidate sets per position
    pos_candidates: dict[int, set[tuple[int, int]]] = {}
    for pos, pt_char in sorted(CRIB_DICT.items()):
        pairs = solve_key_from_crib(pos, pt_char)
        pos_candidates[pos] = set(pairs)
        if pos in (21, 22, 27, 65):  # Show a few
            print(f"  pos {pos:2d}: CT={CT[pos]} PT={pt_char} → "
                  f"valid (a,b) pairs: {pairs[:4]}{'...' if len(pairs)>4 else ''}")

    # Intersect ALL constraints to find consistent (a,b) pairs
    all_consistent = set(pos_candidates[sorted(CRIB_DICT.keys())[0]])
    for pos in sorted(CRIB_DICT.keys())[1:]:
        all_consistent &= pos_candidates[pos]

    print()
    print(f"  Intersection of ALL {N_CRIBS} crib constraints:")
    print(f"  → {len(all_consistent)} globally consistent (a,b) pairs")
    if all_consistent:
        print(f"  → Pairs: {sorted(all_consistent)}")
    else:
        print("  → EMPTY SET: No affine key satisfies all 24 crib constraints simultaneously")
        print("  → This is a DIRECT ALGEBRAIC DISPROOF")

    print()

    # ── Phase 1: Exhaustive Test ───────────────────────────────────────
    print("=" * 50)
    print("Phase 1: Exhaustive Test — All 312 Keys")
    print("=" * 50)
    print()

    t0 = time.time()
    results = []

    for a in VALID_A:
        a_inv = MOD_INV[a]
        for b in range(MOD):
            # Decrypt
            pt_idx = [(a_inv * (c - b)) % MOD for c in CT_IDX]
            pt_str = "".join(ALPH[x] for x in pt_idx)

            # Crib score
            crib_score = sum(
                1 for pos, ct_val, exp_pt in CRIB_CT_IDX
                if pt_idx[pos] == exp_pt
            )

            # Bean check
            bean_ok = check_bean(pt_idx)

            # Quadgram score
            qscore = scorer.score_per_char(pt_str)

            results.append({
                "a": a,
                "b": b,
                "b_char": ALPH[b],
                "crib_score": crib_score,
                "bean_pass": bean_ok,
                "quadgram_per_char": qscore,
                "plaintext": pt_str,
            })

    elapsed = time.time() - t0

    # Sort by crib_score desc, then quadgram desc
    results.sort(key=lambda r: (-r["crib_score"], -r["quadgram_per_char"]))

    print(f"  Tested: {len(results)} keys in {elapsed:.3f}s")
    print()

    # ── Phase 2: Crib Score Distribution ──────────────────────────────
    print("=" * 50)
    print("Phase 2: Crib Score Distribution")
    print("=" * 50)
    score_dist: dict[int, int] = {}
    for r in results:
        s = r["crib_score"]
        score_dist[s] = score_dist.get(s, 0) + 1

    print()
    print(f"  {'Score':>6} | {'Count':>6} | {'Keys (a,b)':}")
    print(f"  {'------':>6}-+-{'------':>6}-+-{'----------':}")
    for sc in sorted(score_dist.keys(), reverse=True):
        keys = [(r["a"], r["b"]) for r in results if r["crib_score"] == sc]
        keys_str = str(keys[:5]) + ("..." if len(keys) > 5 else "")
        print(f"  {sc:6d} | {score_dist[sc]:6d} | {keys_str}")

    max_crib = results[0]["crib_score"]
    print()
    print(f"  Maximum crib score achieved: {max_crib}/24")

    # ── Phase 3: Top Results Table ─────────────────────────────────────
    print()
    print("=" * 50)
    print("Phase 3: Top 20 Results (sorted by crib score, then quadgram)")
    print("=" * 50)
    print()
    print("  Rank |  a |  b (ch) | Cribs | Bean | Quadgram/ch | Plaintext (first 50 chars)")
    print("  -----+----+---------+-------+------+-------------+---------------------------")
    for rank, r in enumerate(results[:20], 1):
        bean_str = "PASS" if r["bean_pass"] else "fail"
        pt_preview = r["plaintext"][:50]
        print(f"  {rank:4d} | {r['a']:2d} | {r['b']:2d} ('{r['b_char']}') | "
              f"{r['crib_score']:5d} | {bean_str:4} | "
              f"{r['quadgram_per_char']:11.4f} | {pt_preview}")

    # ── Phase 4: Bean Analysis ─────────────────────────────────────────
    print()
    print("=" * 50)
    print("Phase 4: Bean Constraint Analysis (PT[27] == PT[65])")
    print("=" * 50)
    print()
    print(f"  CT[27] = '{CT[27]}', CT[65] = '{CT[65]}'")
    print(f"  Expected PT[27] = PT[65] = 'R' (from crib EASTNORTHEAST)")
    print()

    # For Bean: a_inv*(CT[27]-b) ≡ a_inv*(CT[65]-b) mod 26
    # => CT[27] ≡ CT[65] mod 26 (if a_inv ≠ 0)
    # => same CT letter automatically satisfies Bean for ANY (a,b)!
    ct27 = CT_IDX[27]
    ct65 = CT_IDX[65]
    print(f"  CT[27] = {ct27} ('{CT[27]}'), CT[65] = {ct65} ('{CT[65]}')")
    if ct27 == ct65:
        print(f"  → CT[27] == CT[65]: Bean constraint is AUTOMATICALLY SATISFIED")
        print(f"    by ALL 312 affine keys (PT[27]==PT[65] iff CT[27]==CT[65])")
        bean_auto = True
    else:
        print(f"  → CT[27] ≠ CT[65]: Bean constraint is NEVER satisfied by any affine key")
        bean_auto = False

    bean_pass_count = sum(1 for r in results if r["bean_pass"])
    print(f"  Empirical Bean passes: {bean_pass_count}/312 ({'consistent' if bean_auto and bean_pass_count==312 else 'CHECK'})")

    # ── Phase 5: Self-Encryption Check ────────────────────────────────
    print()
    print("=" * 50)
    print("Phase 5: Self-Encryption Positions (pos 32='S', pos 73='K')")
    print("=" * 50)
    print()
    print("  Self-encrypting: PT[pos] = CT[pos]")
    print(f"  pos 32: CT='{CT[32]}' must equal PT='S' => CT must be 'S' = {CT[32]=='S'}")
    print(f"  pos 73: CT='{CT[73]}' must equal PT='K' => CT must be 'K' = {CT[73]=='K'}")
    print()
    print("  For affine CT = a*PT + b: self-encrypt means a*x + b = x mod 26")
    print("  => x*(a-1) = -b mod 26 (has solution iff gcd(a-1,26) | b)")
    print()
    for a in VALID_A:
        for b in range(MOD):
            # Check if x=18 (S) is self-encrypting: a*18 + b ≡ 18 mod 26
            s_self = (a * 18 + b) % MOD == 18
            # Check if x=10 (K) is self-encrypting: a*10 + b ≡ 10 mod 26
            k_self = (a * 10 + b) % MOD == 10
            if s_self and k_self:
                print(f"  (a={a}, b={b}): S self-encrypts AND K self-encrypts — check cribs!")

    # Count keys with both self-encrypting positions correct
    both_self = [(r["a"], r["b"]) for r in results
                 if (r["a"] * 18 + r["b"]) % 26 == 18
                 and (r["a"] * 10 + r["b"]) % 26 == 10]
    print(f"  Keys where both S(pos 32) and K(pos 73) self-encrypt: {len(both_self)}")
    if both_self:
        for a, b in both_self[:5]:
            print(f"    (a={a}, b={b}='{ALPH[b]}')")

    # ── Phase 6: Verdict ───────────────────────────────────────────────
    print()
    print("=" * 70)
    print("VERDICT")
    print("=" * 70)
    print()

    if max_crib == 0:
        verdict = "ELIMINATED — Zero keys achieve any crib match"
        detail = ("The monoalphabetic affine cipher is ALGEBRAICALLY INCOMPATIBLE "
                  "with K4. The crib constraints form an overdetermined system with "
                  "no solution in the 312-key space. This is a hard disproof.")
    elif max_crib <= 4:
        verdict = f"ELIMINATED — Best {max_crib}/24 cribs (noise level)"
        detail = (f"Maximum of {max_crib}/24 crib matches. Expected random floor for "
                  f"monoalphabetic: ~24/26 ≈ 0.9 per position => most positions fail. "
                  f"No key approaches the 24/24 breakthrough threshold.")
    elif max_crib < 24:
        verdict = f"ELIMINATED — Best {max_crib}/24 cribs (below breakthrough threshold)"
        detail = f"No key achieves full crib match. Maximum {max_crib}/24."
    else:
        verdict = f"INVESTIGATE — {max_crib}/24 cribs achieved!"
        detail = "Unexpected result — manual inspection required."

    print(f"  {verdict}")
    print()
    print(f"  Detail: {detail}")
    print()
    print(f"  Maximum crib score: {max_crib}/24")
    print(f"  Keys tested: {len(results)} (all 12 × 26)")
    print(f"  Bean auto-satisfied: {bean_auto}")
    print(f"  Algebraic proof: {len(all_consistent) == 0}")
    print()

    # ── Algebraic Proof Detail ─────────────────────────────────────────
    print("=" * 50)
    print("Algebraic Proof Detail")
    print("=" * 50)
    print()
    print("For monoalphabetic affine CT = a*PT + b mod 26:")
    print("Each (CT[pos], PT[pos]) pair constrains b = CT[pos] - a*PT[pos] mod 26")
    print()
    print("Take two crib positions with known PT:")

    # Show explicit contradiction between two positions
    example_positions = list(sorted(CRIB_DICT.keys()))[:4]
    for i in range(len(example_positions)):
        for j in range(i + 1, len(example_positions)):
            p1 = example_positions[i]
            p2 = example_positions[j]
            ct1, pt1 = CT_IDX[p1], ALPH_IDX[CRIB_DICT[p1]]
            ct2, pt2 = CT_IDX[p2], ALPH_IDX[CRIB_DICT[p2]]
            # b = ct1 - a*pt1 = ct2 - a*pt2 mod 26
            # a*(pt1 - pt2) = ct1 - ct2 mod 26
            lhs_coeff = (pt1 - pt2) % MOD
            rhs = (ct1 - ct2) % MOD
            print(f"  pos {p1:2d} (CT={CT[p1]}, PT={CRIB_DICT[p1]}) & "
                  f"pos {p2:2d} (CT={CT[p2]}, PT={CRIB_DICT[p2]}):")
            print(f"    a * ({pt1} - {pt2}) ≡ ({ct1} - {ct2}) mod 26")
            print(f"    a * {lhs_coeff} ≡ {rhs} mod 26")
            # Find a values consistent with this pair
            consistent_a = [a for a in VALID_A if (a * lhs_coeff) % MOD == rhs]
            print(f"    → Consistent a values: {consistent_a if consistent_a else 'NONE'}")
            print()

    # ── Save Artifact ──────────────────────────────────────────────────
    artifact = {
        "experiment": "E-AFFINE-MONO",
        "description": "Monoalphabetic affine cipher exhaustive disproof",
        "ct": CT,
        "ct_len": CT_LEN,
        "keys_tested": len(results),
        "valid_a_values": VALID_A,
        "max_crib_score": max_crib,
        "algebraic_consistent_pairs": sorted(all_consistent),
        "bean_auto_satisfied": bean_auto,
        "verdict": verdict,
        "elapsed_seconds": elapsed,
        "crib_score_distribution": {str(k): v for k, v in sorted(score_dist.items())},
        "top_20": [
            {
                "rank": rank,
                "a": r["a"],
                "b": r["b"],
                "b_char": r["b_char"],
                "crib_score": r["crib_score"],
                "bean_pass": r["bean_pass"],
                "quadgram_per_char": r["quadgram_per_char"],
                "plaintext": r["plaintext"],
            }
            for rank, r in enumerate(results[:20], 1)
        ],
    }

    out_path = "results/e_affine_mono_disproof.json"
    with open(out_path, "w") as f:
        json.dump(artifact, f, indent=2)

    print(f"  Artifact: {out_path}")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_affine_mono_disproof.py")


if __name__ == "__main__":
    main()
