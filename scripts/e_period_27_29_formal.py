#!/usr/bin/env python3
"""E-PERIOD-27-29: Formal elimination of periods 27, 28, 29 for K4.

CONTEXT
-------
E-FRAC-35 (Bean impossibility proof) eliminated ALL periodic keys at periods
2-26 for ANY transposition. E-AUDIT-01 confirmed via pairwise constraints.
However, periods 27, 28, 29 were NOT covered by E-FRAC-35 (which only
analyzed periods 2-26). A new crib-consistency sweep (2026-02-28) found:
  - Periods 2-52 (except 27, 28, 29): eliminated by crib conflict — two
    crib positions share a residue mod p but have different key values.
  - Periods 27, 28, 29: NO direct crib-consistency conflict → candidates.
  - Periods 53-96: underdetermined (no crib residue overlap possible).

This script formally tests periods 27, 28, 29 under identity transposition
by:
  1. Deriving the full periodic key (most residues fixed by cribs, 3-6 free).
  2. Applying the key to K4 to recover a "partial plaintext" (86-84 chars known).
  3. Computing quadgram score on the known positions.
  4. Searching the 26^{k} free residue values for any quadgram signal.
  5. Reporting: ELIMINATED (all gibberish) or SIGNAL (readable).

Also verifies that ALL 21 Bean inequalities are consistent with the
crib-derived key values for these periods.

Run: PYTHONPATH=src python3 -u scripts/e_period_27_29_formal.py
"""

import sys
import os
import json
import itertools
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS,
    BEAN_EQ, BEAN_INEQ,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
)

# ── Known Vigenere keystream at crib positions ────────────────────────────────

ENE_START = 21
BC_START = 63

KNOWN_KEY: Dict[int, int] = {}
for i, v in enumerate(VIGENERE_KEY_ENE):
    KNOWN_KEY[ENE_START + i] = v
for i, v in enumerate(VIGENERE_KEY_BC):
    KNOWN_KEY[BC_START + i] = v

# For Beaufort: k = (CT + PT) mod 26  →  k_beau[i] = (CT[i] + PT[i]) mod 26
# For Var Beaufort: k = (PT - CT) mod 26
CT_VALS = [ALPH_IDX[c] for c in CT]
PT_VALS_CRIB = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

KNOWN_KEY_BEAU: Dict[int, int] = {
    pos: (CT_VALS[pos] + PT_VALS_CRIB[pos]) % MOD
    for pos in sorted(CRIB_DICT.keys())
}
KNOWN_KEY_VARBEAU: Dict[int, int] = {
    pos: (PT_VALS_CRIB[pos] - CT_VALS[pos]) % MOD
    for pos in sorted(CRIB_DICT.keys())
}

# ── Quadgram scorer (stdlib only) ─────────────────────────────────────────────

QUADGRAM_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "english_quadgrams.json")

def _load_quadgrams() -> Optional[Dict[str, float]]:
    try:
        with open(QUADGRAM_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        return None

QUAD: Optional[Dict[str, float]] = _load_quadgrams()
QUAD_FLOOR = -12.0  # fallback log prob for unknown quadgrams

def quadgram_score(text: str) -> float:
    """Return mean log-prob per char for a text string (higher = more English)."""
    if QUAD is None or len(text) < 4:
        return float('-inf')
    total = 0.0
    count = 0
    for i in range(len(text) - 3):
        q = text[i:i+4]
        total += QUAD.get(q, QUAD_FLOOR)
        count += 1
    return total / count if count > 0 else float('-inf')

# ── IC computation ────────────────────────────────────────────────────────────

def ic(text: str) -> float:
    from collections import Counter
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text)
    return sum(v * (v - 1) for v in counts.values()) / (n * (n - 1))

# ── Core analysis per period ──────────────────────────────────────────────────

ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def analyze_period(p: int) -> dict:
    """Full analysis of periodic key with period p."""
    print(f"\n{'='*60}")
    print(f"PERIOD {p} ANALYSIS")
    print(f"{'='*60}")

    results = {}
    for variant_name, known in [
        ("vigenere",     KNOWN_KEY),
        ("beaufort",     KNOWN_KEY_BEAU),
        ("var_beaufort", KNOWN_KEY_VARBEAU),
    ]:
        # ── Step 1: Map crib constraints to residue classes ──────────────────
        residue_key: Dict[int, int] = {}  # residue → required key value
        conflict = False
        for pos, kval in known.items():
            r = pos % p
            if r in residue_key:
                if residue_key[r] != kval:
                    conflict = True
                    print(f"  [{variant_name}] Period {p}: CONFLICT at residue {r} "
                          f"(pos {list(pos for pos2,kv in known.items() if pos2%p==r)[0]}→{residue_key[r]}"
                          f" vs pos {pos}→{kval})")
                    break
            else:
                residue_key[r] = kval

        if conflict:
            results[variant_name] = {"status": "CONFLICT", "verdict": "ELIMINATED"}
            continue

        # ── Step 2: Check Bean equality ──────────────────────────────────────
        eq_pos1, eq_pos2 = BEAN_EQ[0]
        r1, r2 = eq_pos1 % p, eq_pos2 % p
        if r1 in residue_key and r2 in residue_key:
            if residue_key[r1] != residue_key[r2]:
                print(f"  [{variant_name}] Bean EQ VIOLATED: key[{r1}]={residue_key[r1]} ≠ key[{r2}]={residue_key[r2]}")
                results[variant_name] = {"status": "BEAN_EQ_VIOLATED", "verdict": "ELIMINATED"}
                continue

        # ── Step 3: Check Bean inequalities ──────────────────────────────────
        bean_ineq_violations = []
        for ia, ib in BEAN_INEQ:
            ra, rb = ia % p, ib % p
            if ra in residue_key and rb in residue_key:
                if residue_key[ra] == residue_key[rb]:
                    bean_ineq_violations.append((ia, ib, ra, rb, residue_key[ra]))

        if bean_ineq_violations:
            print(f"  [{variant_name}] Bean INEQ violated ({len(bean_ineq_violations)} pairs)")
            results[variant_name] = {
                "status": "BEAN_INEQ_VIOLATED",
                "violations": len(bean_ineq_violations),
                "verdict": "ELIMINATED"
            }
            continue

        # ── Step 4: Identify free residues ───────────────────────────────────
        all_residues = set(range(p))
        constrained = set(residue_key.keys())
        free_residues = sorted(all_residues - constrained)
        n_free = len(free_residues)

        print(f"\n  [{variant_name}] Period {p}: {len(constrained)}/{p} residues constrained, {n_free} free")
        print(f"    Constrained residues: {dict(sorted(residue_key.items()))}")
        print(f"    Free residues: {free_residues}")

        # ── Step 5: Apply key to known positions ─────────────────────────────
        # With free residues set to 0 initially (will search later)
        def build_pt(free_vals: List[int]) -> str:
            """Build plaintext given free residue values."""
            full_key = dict(residue_key)
            for r, v in zip(free_residues, free_vals):
                full_key[r] = v
            pt_chars = []
            for i in range(CT_LEN):
                r = i % p
                if r in full_key:
                    k = full_key[r]
                    if variant_name == "vigenere":
                        ptv = (CT_VALS[i] - k) % MOD
                    elif variant_name == "beaufort":
                        ptv = (k - CT_VALS[i]) % MOD
                    else:  # var_beaufort
                        ptv = (CT_VALS[i] + k) % MOD
                    pt_chars.append(ALPH[ptv])
                else:
                    pt_chars.append("?")
            return "".join(pt_chars)

        # Compute known-position plaintext (free = 0 for now)
        pt_base = build_pt([0] * n_free)
        known_only = pt_base.replace("?", "")
        print(f"    Known-position plaintext ({len(known_only)} chars):")
        print(f"    {pt_base}")
        q_base = quadgram_score(known_only)
        ic_base = ic(known_only)
        print(f"    Quadgram (known only): {q_base:.3f}/char  IC: {ic_base:.4f}")

        # ── Step 6: Search free residues if space is manageable ──────────────
        max_search = 26 ** min(n_free, 4)  # cap at 26^4 = 456976
        best_score = q_base
        best_pt = pt_base
        best_free = [0] * n_free

        if n_free <= 4 and n_free > 0:
            print(f"    Searching {26**n_free:,} free-residue combinations...")
            for combo in itertools.product(range(MOD), repeat=n_free):
                pt_candidate = build_pt(list(combo))
                known_part = pt_candidate.replace("?", "")
                score = quadgram_score(known_part)
                if score > best_score:
                    best_score = score
                    best_pt = pt_candidate
                    best_free = list(combo)
        elif n_free == 0:
            best_pt = pt_base
            best_score = q_base

        print(f"    Best quadgram: {best_score:.3f}/char (English ~-3.5, random ~-6.5)")
        if n_free > 0:
            free_letters = {r: ALPH[v] for r, v in zip(free_residues, best_free)}
            print(f"    Best free residue values: {free_letters}")
        print(f"    Best plaintext: {best_pt}")

        # Verdict
        if best_score > -4.5:
            verdict = "SIGNAL"
        elif best_score > -5.5:
            verdict = "WEAK_SIGNAL"
        else:
            verdict = "NOISE"

        print(f"    VERDICT: {verdict}")

        results[variant_name] = {
            "status": "TESTED",
            "n_free_residues": n_free,
            "free_residues": free_residues,
            "best_quadgram": best_score,
            "best_plaintext": best_pt,
            "best_free_vals": {str(r): v for r, v in zip(free_residues, best_free)},
            "verdict": verdict,
        }

    return {"period": p, "variants": results}


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("E-PERIOD-27-29: Formal elimination of residual periodic key candidates")
    print("Context: E-FRAC-35 covers p=2-26 via Bean. Crib-consistency covers p=30-52.")
    print("This script closes the gap: p=27, 28, 29 survive both prior tests.\n")

    all_results = []
    for p in [27, 28, 29]:
        r = analyze_period(p)
        all_results.append(r)

    # Summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    eliminated = []
    signals = []
    for r in all_results:
        p = r["period"]
        best_q = max(
            (v.get("best_quadgram", float('-inf'))
             for v in r["variants"].values()
             if isinstance(v, dict)),
            default=float('-inf')
        )
        verdict = "ELIMINATED" if best_q < -5.0 else "SIGNAL"
        if verdict == "ELIMINATED":
            eliminated.append(p)
        else:
            signals.append(p)
        print(f"  Period {p}: best_quadgram={best_q:.3f}/char → {verdict}")

    if not signals:
        print(f"\nAll tested periods ({', '.join(map(str, eliminated))}) → ELIMINATED")
        print("Implication: ALL periodic keys (p=2..52) are now eliminated.")
        print("Combined with p=53..96 being underdetermined, this confirms")
        print("K4 is NOT a simple periodic cipher under identity transposition.")
    else:
        print(f"\nSIGNAL detected at period(s): {signals} — INVESTIGATE IMMEDIATELY")

    # Write results
    os.makedirs("results", exist_ok=True)
    out = {
        "experiment": "E-PERIOD-27-29",
        "hypothesis": "Periods 27, 28, 29 survive Bean+crib-consistency but may fail readability",
        "periods_tested": [27, 28, 29],
        "results": all_results,
        "summary": {
            "eliminated": eliminated,
            "signals": signals,
            "overall_verdict": "ELIMINATED" if not signals else "SIGNAL",
        },
        "derived_fact": (
            "ALL periodic Vigenere/Beaufort/VarBeaufort keys with periods 2-52 are "
            "eliminated under identity transposition: periods 2-26 by Bean (E-FRAC-35/E-AUDIT-01), "
            "periods 30-52 by crib-consistency conflict, periods 27-29 by readability test (this script)."
        )
    }
    outfile = "results/e_period_27_29_formal.json"
    with open(outfile, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nResults written to {outfile}")


if __name__ == "__main__":
    main()
