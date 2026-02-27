"""E-AUDIT-05: 2x2 Hill cipher using Extra L + YAR superscript anomalies.

Hypothesis: The physical anomalies on the Kryptos sculpture — the Extra L
and the YAR superscript — encode a 2x2 Hill cipher key matrix.

Tests all 24 permutations of placing {L, Y, A, R} into a 2x2 matrix,
using both standard (A=0) and KA (K=0) alphabets, with two padding
strategies for the odd-length (97 char) ciphertext.

Hill decryption: PT_pair = M_inv * CT_pair (mod 26)
"""
from __future__ import annotations

import itertools
import json
import os
import sys
from math import gcd
from typing import Dict, List, Optional, Tuple

from kryptos.kernel.constants import (
    ALPH,
    ALPH_IDX,
    CT,
    CT_LEN,
    CRIB_DICT,
    KRYPTOS_ALPHABET,
    MOD,
    N_CRIBS,
    BEAN_EQ,
    BEAN_INEQ,
)

# ── Alphabet mappings ─────────────────────────────────────────────────────

KA_IDX: Dict[str, int] = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}

ALPHABETS = {
    "AZ": (ALPH, ALPH_IDX),
    "KA": (KRYPTOS_ALPHABET, KA_IDX),
}

# ── Letters from the anomalies ────────────────────────────────────────────

ANOMALY_LETTERS = ["L", "Y", "A", "R"]

# ── Matrix math mod 26 ───────────────────────────────────────────────────


def det_2x2(m: List[List[int]]) -> int:
    """Determinant of 2x2 matrix mod 26."""
    return (m[0][0] * m[1][1] - m[0][1] * m[1][0]) % MOD


def mod_inverse(a: int, mod: int) -> Optional[int]:
    """Modular multiplicative inverse using extended Euclidean algorithm."""
    a = a % mod
    if gcd(a, mod) != 1:
        return None
    # Extended Euclidean
    g, x, _ = _extended_gcd(a, mod)
    if g != 1:
        return None
    return x % mod


def _extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def invert_2x2(m: List[List[int]]) -> Optional[List[List[int]]]:
    """Compute inverse of 2x2 matrix mod 26, or None if singular."""
    d = det_2x2(m)
    d_inv = mod_inverse(d, MOD)
    if d_inv is None:
        return None
    # Adjugate of [[a,b],[c,d]] = [[d,-b],[-c,a]]
    inv = [
        [(d_inv * m[1][1]) % MOD, (d_inv * (-m[0][1])) % MOD],
        [(d_inv * (-m[1][0])) % MOD, (d_inv * m[0][0]) % MOD],
    ]
    return inv


def hill_decrypt(ct_nums: List[int], m_inv: List[List[int]]) -> List[int]:
    """Decrypt using 2x2 Hill cipher. ct_nums must have even length."""
    pt = []
    for i in range(0, len(ct_nums), 2):
        c1, c2 = ct_nums[i], ct_nums[i + 1]
        p1 = (m_inv[0][0] * c1 + m_inv[0][1] * c2) % MOD
        p2 = (m_inv[1][0] * c1 + m_inv[1][1] * c2) % MOD
        pt.append(p1)
        pt.append(p2)
    return pt


# ── Scoring ───────────────────────────────────────────────────────────────


def count_crib_matches(pt_text: str, offset: int = 0) -> Tuple[int, List[str]]:
    """Count how many crib positions match in the plaintext.

    offset: if we prepended a padding char, the real CT positions
    are shifted by +1 in pt_text.
    """
    matches = 0
    details = []
    for pos, expected_ch in CRIB_DICT.items():
        adjusted = pos + offset
        if 0 <= adjusted < len(pt_text):
            actual = pt_text[adjusted]
            if actual == expected_ch:
                matches += 1
                details.append(f"  pos {pos}: {expected_ch} = {actual} MATCH")
    return matches, details


def check_bean(pt_text: str, ct_text: str, alph_idx: Dict[str, int], offset: int = 0) -> Tuple[bool, bool, str]:
    """Check Bean equality and inequality constraints.

    Under Vigenere: k[i] = (CT[i] - PT[i]) mod 26
    Bean EQ: k[27] == k[65]
    Bean INEQ: k[a] != k[b] for each pair
    """
    def keyval(pos: int) -> Optional[int]:
        adj = pos + offset
        if 0 <= adj < len(pt_text) and 0 <= pos < len(ct_text):
            ct_val = alph_idx.get(ct_text[pos])
            pt_val = alph_idx.get(pt_text[adj])
            if ct_val is not None and pt_val is not None:
                return (ct_val - pt_val) % MOD
        return None

    # Equality check
    eq_pass = True
    eq_detail = ""
    for a, b in BEAN_EQ:
        ka, kb = keyval(a), keyval(b)
        if ka is not None and kb is not None:
            if ka != kb:
                eq_pass = False
                eq_detail = f"k[{a}]={ka} != k[{b}]={kb}"
            else:
                eq_detail = f"k[{a}]=k[{b}]={ka}"

    # Inequality check
    ineq_pass = True
    ineq_fails = []
    for a, b in BEAN_INEQ:
        ka, kb = keyval(a), keyval(b)
        if ka is not None and kb is not None:
            if ka == kb:
                ineq_pass = False
                ineq_fails.append(f"k[{a}]=k[{b}]={ka}")

    detail = f"EQ: {eq_detail} | INEQ fails: {len(ineq_fails)}"
    return eq_pass, ineq_pass, detail


# ── Main experiment ───────────────────────────────────────────────────────


def run_experiment():
    print("=" * 78)
    print("E-AUDIT-05: 2x2 Hill Cipher — Extra L + YAR Anomalies")
    print("=" * 78)
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"Anomaly letters: {ANOMALY_LETTERS}")
    print(f"Cribs: {N_CRIBS} positions")
    print()

    # All 24 permutations of [L, Y, A, R]
    perms = list(itertools.permutations(ANOMALY_LETTERS))
    print(f"Testing {len(perms)} permutations x 2 alphabets x 2 padding = "
          f"{len(perms) * 2 * 2} configurations")
    print()

    results = []
    tested = 0
    skipped_singular = 0

    for alph_name, (alph_str, alph_idx) in ALPHABETS.items():
        # Convert CT to numbers in this alphabet
        ct_nums = [alph_idx[c] for c in CT]

        for perm in perms:
            # Build 2x2 matrix from permutation: [[perm[0], perm[1]], [perm[2], perm[3]]]
            m = [
                [alph_idx[perm[0]], alph_idx[perm[1]]],
                [alph_idx[perm[2]], alph_idx[perm[3]]],
            ]
            matrix_label = f"[[{perm[0]},{perm[1]}],[{perm[2]},{perm[3]}]]"
            matrix_vals = f"[[{m[0][0]},{m[0][1]}],[{m[1][0]},{m[1][1]}]]"

            d = det_2x2(m)
            if gcd(d, MOD) != 1:
                skipped_singular += 1
                continue

            m_inv = invert_2x2(m)
            if m_inv is None:
                skipped_singular += 1
                continue

            # Strategy A: drop last char (decrypt 96 chars = 48 pairs)
            ct_a = ct_nums[:96]
            pt_a_nums = hill_decrypt(ct_a, m_inv)
            pt_a_text = "".join(alph_str[n] for n in pt_a_nums)
            crib_a, details_a = count_crib_matches(pt_a_text, offset=0)
            bean_eq_a, bean_ineq_a, bean_detail_a = check_bean(
                pt_a_text, CT, alph_idx, offset=0
            )

            results.append({
                "alphabet": alph_name,
                "matrix_letters": matrix_label,
                "matrix_values": matrix_vals,
                "det": d,
                "padding": "drop_last",
                "crib_matches": crib_a,
                "bean_eq": bean_eq_a,
                "bean_ineq": bean_ineq_a,
                "bean_detail": bean_detail_a,
                "pt_snippet_21_40": pt_a_text[21:40] if len(pt_a_text) > 40 else pt_a_text[21:],
                "pt_snippet_60_77": pt_a_text[60:77] if len(pt_a_text) > 77 else pt_a_text[60:],
                "pt_full": pt_a_text,
            })
            tested += 1

            # Strategy B: prepend padding 'X' (= 98 chars = 49 pairs), offset=+1
            # Try all 26 possible padding chars
            for pad_ch in alph_str:
                ct_b = [alph_idx[pad_ch]] + ct_nums  # 98 chars
                pt_b_nums = hill_decrypt(ct_b, m_inv)
                pt_b_text = "".join(alph_str[n] for n in pt_b_nums)
                crib_b, details_b = count_crib_matches(pt_b_text, offset=1)
                bean_eq_b, bean_ineq_b, bean_detail_b = check_bean(
                    pt_b_text, CT, alph_idx, offset=1
                )

                results.append({
                    "alphabet": alph_name,
                    "matrix_letters": matrix_label,
                    "matrix_values": matrix_vals,
                    "det": d,
                    "padding": f"prepend_{pad_ch}",
                    "crib_matches": crib_b,
                    "bean_eq": bean_eq_b,
                    "bean_ineq": bean_ineq_b,
                    "bean_detail": bean_detail_b,
                    "pt_snippet_21_40": pt_b_text[22:41] if len(pt_b_text) > 41 else "",
                    "pt_snippet_60_77": pt_b_text[61:78] if len(pt_b_text) > 78 else "",
                    "pt_full": pt_b_text,
                })
                tested += 1

            # Strategy C: append padding 'X' (= 98 chars = 49 pairs), no offset
            for pad_ch in alph_str:
                ct_c = ct_nums + [alph_idx[pad_ch]]  # 98 chars
                pt_c_nums = hill_decrypt(ct_c, m_inv)
                pt_c_text = "".join(alph_str[n] for n in pt_c_nums)
                crib_c, details_c = count_crib_matches(pt_c_text, offset=0)
                bean_eq_c, bean_ineq_c, bean_detail_c = check_bean(
                    pt_c_text, CT, alph_idx, offset=0
                )

                results.append({
                    "alphabet": alph_name,
                    "matrix_letters": matrix_label,
                    "matrix_values": matrix_vals,
                    "det": d,
                    "padding": f"append_{pad_ch}",
                    "crib_matches": crib_c,
                    "bean_eq": bean_eq_c,
                    "bean_ineq": bean_ineq_c,
                    "bean_detail": bean_detail_c,
                    "pt_snippet_21_40": pt_c_text[21:40] if len(pt_c_text) > 40 else "",
                    "pt_snippet_60_77": pt_c_text[60:77] if len(pt_c_text) > 77 else "",
                    "pt_full": pt_c_text,
                })
                tested += 1

    # ── Summary ──────────────────────────────────────────────────────────

    print(f"\nTotal configurations tested: {tested}")
    print(f"Skipped (singular matrix, det not coprime to 26): {skipped_singular}")
    print()

    # Sort by crib matches descending
    results.sort(key=lambda r: r["crib_matches"], reverse=True)

    # Expected random crib matches for Hill: each position has 1/26 chance
    # With 24 crib positions: expected = 24/26 ≈ 0.923
    expected_random = N_CRIBS / MOD
    print(f"Expected random crib matches: {expected_random:.2f}")
    print()

    # Distribution of crib match counts
    from collections import Counter
    dist = Counter(r["crib_matches"] for r in results)
    print("Crib match distribution:")
    for k in sorted(dist.keys(), reverse=True):
        bar = "#" * min(dist[k], 60)
        print(f"  {k:2d} matches: {dist[k]:6d} configs  {bar}")
    print()

    # Top results
    print("=" * 78)
    print("TOP 30 RESULTS (by crib matches)")
    print("=" * 78)
    for i, r in enumerate(results[:30]):
        print(f"\n--- Rank {i+1} ---")
        print(f"  Alphabet:    {r['alphabet']}")
        print(f"  Matrix:      {r['matrix_letters']} = {r['matrix_values']}")
        print(f"  Det:         {r['det']}")
        print(f"  Padding:     {r['padding']}")
        print(f"  Crib match:  {r['crib_matches']}/{N_CRIBS}")
        print(f"  Bean EQ:     {'PASS' if r['bean_eq'] else 'FAIL'}")
        print(f"  Bean INEQ:   {'PASS' if r['bean_ineq'] else 'FAIL'}")
        print(f"  Bean detail: {r['bean_detail']}")
        print(f"  PT@21-40:    {r['pt_snippet_21_40']}")
        print(f"  PT@60-77:    {r['pt_snippet_60_77']}")
        # Show first 50 chars of plaintext
        print(f"  PT[0:50]:    {r['pt_full'][:50]}")

    # Check for any result with crib_matches >= 3 (well above random)
    significant = [r for r in results if r["crib_matches"] >= 3]
    print(f"\n{'=' * 78}")
    print(f"Results with >= 3 crib matches: {len(significant)}")
    if significant:
        print("These are worth investigating further:")
        for r in significant:
            print(f"  {r['alphabet']} {r['matrix_letters']} pad={r['padding']} "
                  f"cribs={r['crib_matches']} bean_eq={'P' if r['bean_eq'] else 'F'}")

    # Also check: any result where Bean EQ passes?
    bean_eq_pass = [r for r in results if r["bean_eq"]]
    print(f"\nResults with Bean EQ pass: {len(bean_eq_pass)}")
    if bean_eq_pass:
        # Show top by crib among these
        bean_eq_pass.sort(key=lambda r: r["crib_matches"], reverse=True)
        print("Top 10 Bean EQ passes by crib:")
        for r in bean_eq_pass[:10]:
            print(f"  {r['alphabet']} {r['matrix_letters']} pad={r['padding']} "
                  f"cribs={r['crib_matches']} ineq={'P' if r['bean_ineq'] else 'F'}")

    # Best overall
    best = results[0]
    print(f"\n{'=' * 78}")
    print(f"BEST RESULT: {best['crib_matches']}/{N_CRIBS} crib matches")
    print(f"  Config: {best['alphabet']} {best['matrix_letters']} pad={best['padding']}")
    print(f"  Plaintext: {best['pt_full']}")
    print(f"{'=' * 78}")

    # Verdict
    if best["crib_matches"] >= 18:
        verdict = "SIGNAL — investigate further"
    elif best["crib_matches"] >= 7:
        verdict = "STORE — worth logging but likely noise"
    else:
        verdict = "NOISE — no meaningful signal detected"

    print(f"\nVERDICT: {verdict}")
    print(f"(Expected random: ~{expected_random:.1f} matches. "
          f"Best observed: {best['crib_matches']})")

    # Save results
    os.makedirs("results", exist_ok=True)
    output_path = "results/e_audit_05_hill_2x2_lyar.json"
    summary = {
        "experiment": "E-AUDIT-05",
        "description": "2x2 Hill cipher using Extra L + YAR anomaly letters",
        "total_tested": tested,
        "skipped_singular": skipped_singular,
        "best_crib_matches": best["crib_matches"],
        "best_config": {
            "alphabet": best["alphabet"],
            "matrix": best["matrix_letters"],
            "padding": best["padding"],
        },
        "verdict": verdict,
        "expected_random_cribs": round(expected_random, 2),
        "crib_distribution": {str(k): v for k, v in sorted(dist.items())},
        "top_10": [
            {
                "alphabet": r["alphabet"],
                "matrix": r["matrix_letters"],
                "values": r["matrix_values"],
                "padding": r["padding"],
                "crib_matches": r["crib_matches"],
                "bean_eq": r["bean_eq"],
                "bean_ineq": r["bean_ineq"],
            }
            for r in results[:10]
        ],
    }
    with open(output_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nResults saved to {output_path}")


if __name__ == "__main__":
    run_experiment()
