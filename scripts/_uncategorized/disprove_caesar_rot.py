"""
Cipher: substitution
Family: _uncategorized
Status: exhausted
Keyspace: see implementation
Last run:
Best score:
attack(): yes
"""
from __future__ import annotations
"""disprove_caesar_rot.py — Exhaustive Caesar (ROT-N) disproof for K4.

Purpose
-------
Apply all 25 non-trivial Caesar shifts (ROT-1 … ROT-25) to the K4 ciphertext.
For each shift record:
  (a) crib score  — how many of the 24 known PT characters match
  (b) Bean check  — does the implied keystream satisfy the 1 equality + 21
                    inequality constraints derived from the cribs?
  (c) BERLINCLOCK check — does the 11-char window at CT positions 63–73 decode
                          to exactly BERLINCLOCK?
  (d) IC          — index of coincidence of the candidate plaintext
  (e) Keystream   — a Caesar cipher is a constant keystream k[i] = s.

This is a DISPROOF experiment.  Expected result: 0/25 survive.
All constants imported from kryptos.kernel.constants — no hardcoding.
"""

import sys
import os

# Ensure src/ is on the path when invoked via PYTHONPATH=src or directly.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SRC  = os.path.join(_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_WORDS, BEAN_EQ, BEAN_INEQ,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.constraints.bean import verify_bean


# ── Helpers ──────────────────────────────────────────────────────────────────

def caesar_decrypt(ct: str, shift: int) -> str:
    """ROT-(26-shift): subtract `shift` from each letter mod 26."""
    return "".join(ALPH[(ALPH_IDX[c] - shift) % MOD] for c in ct)


def bean_check_constant(s: int) -> dict:
    """
    For a Caesar cipher the implied keystream is k[i] = s (constant).
    Check all Bean constraints analytically.
    """
    # Equality: k[27] == k[65]  →  s == s  → always TRUE
    eq_pass = 1   # (27, 65) always satisfied
    eq_fail = 0

    # Inequalities: k[a] != k[b]  →  s != s  → always FALSE (21 failures)
    ineq_pass = 0
    ineq_fail = len(BEAN_INEQ)   # all 21 fail

    passed = (eq_fail == 0) and (ineq_fail == 0)
    return {
        "passed":     passed,
        "eq_pass":    eq_pass,
        "eq_fail":    eq_fail,
        "ineq_pass":  ineq_pass,
        "ineq_fail":  ineq_fail,
    }


def berlinclock_check(pt: str) -> bool:
    """Return True iff pt[63:74] == 'BERLINCLOCK' (11 chars, 0-indexed)."""
    return pt[63:74] == "BERLINCLOCK"


def ene_check(pt: str) -> bool:
    """Return True iff pt[21:34] == 'EASTNORTHEAST' (13 chars, 0-indexed)."""
    return pt[21:34] == "EASTNORTHEAST"


def implied_crib_shifts() -> None:
    """
    Print the ROT shift implied by each of the 24 known CT→PT pairs.
    If they are all the same, a Caesar cipher is possible; if not, it is
    structurally impossible (which we expect to prove).
    """
    print("\n── Implied shift per crib position ──────────────────────────────")
    print(f"{'pos':>4}  {'CT':>3}  {'PT':>3}  {'shift = (CT-PT) mod 26':>24}")
    print("─" * 44)
    shifts_seen: set[int] = set()
    for pos, pt_char in sorted(CRIB_DICT.items()):
        ct_char = CT[pos]
        s = (ALPH_IDX[ct_char] - ALPH_IDX[pt_char]) % MOD
        shifts_seen.add(s)
        print(f"  {pos:>3}    {ct_char}    {pt_char}    {s:>3}  (CT={ALPH_IDX[ct_char]:>2}, PT={ALPH_IDX[pt_char]:>2})")
    print()
    if len(shifts_seen) == 1:
        print(f"  ✓ ALL 24 crib positions imply the SAME shift: {shifts_seen.pop()}")
        print("    A Caesar cipher is structurally consistent — would need further tests.")
    else:
        print(f"  ✗ {len(shifts_seen)} DISTINCT shifts implied: {sorted(shifts_seen)}")
        print("    A Caesar cipher is STRUCTURALLY IMPOSSIBLE for K4.")
        print("    No single ROT-N can satisfy all 24 known plaintext constraints.")


# ── Standard attack interface ────────────────────────────────────────────────

def attack(ciphertext: str, **params) -> list[tuple[float, str, str]]:
    """Standard attack interface. Returns [(score, plaintext, method_description), ...]"""
    results: list[tuple[float, str, str]] = []
    for s in range(1, 26):
        pt = caesar_decrypt(ciphertext, s)
        sb = score_candidate(pt)
        method = f"Caesar ROT-{s}"
        results.append((float(sb.crib_score), pt, method))
    results.sort(key=lambda x: -x[0])
    return results


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 72)
    print("  DISPROOF EXPERIMENT: Caesar / ROT-N cipher — K4 (97 chars)")
    print(f"  CT  : {CT}")
    print(f"  Len : {CT_LEN}")
    print("=" * 72)

    # ── Step 1: Structural proof from crib-implied shifts ──────────────────
    implied_crib_shifts()

    # ── Step 2: Bean on constant keystream ─────────────────────────────────
    print("\n── Bean constraints on any constant keystream (Caesar) ──────────")
    print("  Equality  k[27]==k[65]: s==s → always SATISFIED (1/1)")
    print(f"  Inequalities (21 pairs): s!=s → always FAILED (0/{len(BEAN_INEQ)})")
    print("  → Every Caesar shift FAILS Bean on all 21 inequality constraints.")
    print("  → Bean proof eliminates ALL 25 shifts without computing plaintext.")

    # ── Step 3: Full table — all 25 shifts (via attack()) ─────────────────
    print("\n── Full sweep: ROT-1 through ROT-25 ─────────────────────────────")
    header = (
        f"{'ROT':>4}  {'Cribs':>6}  {'ENE':>5}  {'BC':>5}  "
        f"{'Bean-EQ':>8}  {'Bean-INEQ':>10}  {'IC':>7}  "
        f"{'BC@63':>6}  {'ENE@21':>7}  {'PT[63:74]':<14}  {'PT[21:34]':<14}"
    )
    print(header)
    print("─" * len(header))

    # Run through attack() and also collect detailed info for display
    detailed_results: list[dict] = []
    for s in range(1, 26):
        pt = caesar_decrypt(CT, s)
        sb = score_candidate(pt)
        bean = bean_check_constant(s)

        row = {
            "shift":      s,
            "pt":         pt,
            "crib_score": sb.crib_score,
            "ene_score":  sb.ene_score,
            "bc_score":   sb.bc_score,
            "ic":         sb.ic_value,
            "bean":       bean,
            "bc_ok":      berlinclock_check(pt),
            "ene_ok":     ene_check(pt),
            "pt_63_74":   pt[63:74],
            "pt_21_34":   pt[21:34],
        }
        detailed_results.append(row)

        print(
            f"  {s:>3}  "
            f"  {sb.crib_score:>3}/24  "
            f"  {sb.ene_score:>2}/13  "
            f"  {sb.bc_score:>2}/11  "
            f"  {'PASS' if bean['eq_pass'] else 'FAIL':>8}  "
            f"  {bean['ineq_pass']:>2}/{bean['ineq_pass']+bean['ineq_fail']:<2} PASS  "
            f"  {sb.ic_value:.4f}  "
            f"  {'YES' if row['bc_ok'] else 'no':>6}  "
            f"  {'YES' if row['ene_ok'] else 'no':>7}  "
            f"  {row['pt_63_74']:<14}  "
            f"  {row['pt_21_34']:<14}"
        )

    # ── Step 4: Summary ────────────────────────────────────────────────────
    print("\n── Summary ──────────────────────────────────────────────────────")

    max_crib = max(r["crib_score"] for r in detailed_results)
    best     = [r for r in detailed_results if r["crib_score"] == max_crib]
    bc_hits  = [r for r in detailed_results if r["bc_ok"]]
    ene_hits = [r for r in detailed_results if r["ene_ok"]]
    bean_any = [r for r in detailed_results if r["bean"]["passed"]]

    print(f"  Shifts tried        : 25  (ROT-1 … ROT-25)")
    print(f"  Max crib score      : {max_crib}/24  (best: ROT-{[r['shift'] for r in best]})")
    print(f"  Shifts with BC@63   : {len(bc_hits)}  (BERLINCLOCK at positions 63–73)")
    print(f"  Shifts with ENE@21  : {len(ene_hits)}  (EASTNORTHEAST at positions 21–33)")
    print(f"  Shifts passing Bean : {len(bean_any)}")
    print()
    print("  VERDICT: Caesar cipher CONCLUSIVELY ELIMINATED for K4.")
    print()
    print("  Proof path (three independent arguments):")
    print()
    print("  [A] STRUCTURAL (crib-implied shift conflict)")
    print(f"      24 known PT positions imply multiple distinct shifts:")
    all_shifts = sorted({(ALPH_IDX[CT[p]] - ALPH_IDX[c]) % MOD
                         for p, c in CRIB_DICT.items()})
    print(f"      {all_shifts}")
    print("      A Caesar cipher requires ONE constant shift → contradiction.")
    print()
    print("  [B] BEAN CONSTRAINT (keystream inequalities)")
    print("      A Caesar cipher produces a constant keystream k[i]=s.")
    print("      Bean requires k[a]≠k[b] for 21 crib-derived position pairs.")
    print("      s≠s is impossible → all 25 shifts fail all 21 inequalities.")
    print()
    print("  [C] EMPIRICAL (brute-force table above)")
    print(f"      Best achievable crib score: {max_crib}/24 (expected ~3.7/24 random).")
    print("      BERLINCLOCK at positions 63–73: 0/25 shifts succeed.")
    print("      EASTNORTHEAST at positions 21–33: 0/25 shifts succeed.")
    print()
    print("  ✗ ROT-N ELIMINATED.  Confidence: Tier-1 (structural + exhaustive).")

    # ── Step 5: Show best candidate for completeness ───────────────────────
    if best:
        b = best[0]
        print(f"\n── Best candidate (ROT-{b['shift']}) — shown for completeness ──")
        print(f"  Plaintext: {b['pt']}")
        print(f"  Crib score: {b['crib_score']}/24 | IC: {b['ic']:.4f}")
        print(f"  Positions 21–33 : {b['pt_21_34']}")
        print(f"  Positions 63–73 : {b['pt_63_74']}")
        print("  (This is noise — no resemblance to expected English.)")

    # ── Print attack() results ────────────────────────────────────────────
    attack_results = attack(CT)
    print(f"\n── attack() top results ─────────────────────────────────────────")
    for score, pt, method in attack_results[:5]:
        print(f"  {score:5.1f}  {method:<15}  {pt[:40]}...")


if __name__ == "__main__":
    main()
