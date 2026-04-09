"""f_composition_admissibility_v1 — bounded composition admissibility sweep.

Cipher:     additive ∘ columnar transposition  (encryption direction)
Family:     admissibility/composition
Status:     active
Keyspace:   sum_{w=2..10} w! * 8 ≈ 32.3M (width, col_order, period) triples
Last run:
Best score: N/A — campaign produces certificates, not scores

============================================================================
SCOPE — PINNED LITERALLY BELOW AND NOT TO BE EXPANDED IN THIS SCRIPT
============================================================================

This campaign answers ONE question under ONE set of assumptions:

    Does there exist any periodic additive key k (Beaufort variant,
    period in [1, 8]) composed with any columnar transposition
    (widths 2..10, all column orderings, ragged-right incomplete-column
    convention) such that decryption of K4 produces PT with the cribs
    EASTNORTHEAST at 21..33 and BERLINCLOCK at 63..73?

What is intentionally NOT in scope (any of these requires a NEW script,
not a silent expansion of this one):
    - any additive variant other than Beaufort
    - widths outside [2, 10]
    - periods outside [1, 8]
    - keyword-derived column orderings (we enumerate ALL w! orderings)
    - incomplete-column conventions other than ragged-right
    - route / serpentine / rail-fence / spiral transpositions
    - the reverse layer order (transposition ∘ additive)
    - null masks layered on top

============================================================================
CONVENTION & DIRECTION
============================================================================

Encryption direction (pinned):   PT → additive → columnar → CT
    intermediate[j] = beaufort_encrypt(PT[j], k[j % period])
    CT[i]           = intermediate[perm[i]]     (using apply_perm convention)
where perm = columnar_perm(w, col_order, length=97) from
kryptos.kernel.transforms.transposition.

Decryption direction (consequent):  CT → inverse columnar → inverse
additive → PT.  The CSP we actually solve:
    ct_reindexed[j] = CT[invert_perm(perm)[j]]
    periodic_additive(beaufort, period) admissibility on ct_reindexed.

Incomplete-column convention: inherited from columnar_perm() — ragged
right, i.e. columns 0..((97 % w) - 1) have ceil(97/w) positions, the
rest have floor(97/w).

Bean constraints:  INTENTIONALLY DISABLED.  The 242-pair Bean inequality
set was derived from the raw K4 ciphertext.  Under a composition model,
CT values are reindexed through the permutation, and the original Bean
pairs do not translate 1:1.  check_periodic_additive defaults Bean off
when ct_override is supplied.  This produces a CORRECT but WEAKER
admissibility check: every reported UNSAT is still formally valid, but
some SATs may turn out to be infeasible under a re-derived Bean.

============================================================================
WHAT THIS CAMPAIGN DOES AND DOES NOT PROVE
============================================================================

Does prove (for each (w, col_order, period) triple classified UNSAT):
    There is no assignment of a length-`period` Beaufort key that,
    composed with columnar transposition of width w and column order
    col_order (ragged-right), can produce the K4 cribs at their fixed
    positions.

Does NOT prove (survivors / SAT triples):
    That such a key actually decrypts K4 to sensible English.
    SAT here means "admissible under crib-residue collision only";
    it is weaker than "feasible under full Bean + brute force".

This is explicitly a FORMAL UPGRADE of the empirical composition v1
campaigns (which tested ~105K combinations of similar shape with max
score 6/24).  It converts "no empirical signal" into "formal crib-CSP
verdict with witnesses" on a bounded slice.
"""
from __future__ import annotations

import json
import os
import sys
import time
from itertools import permutations
from multiprocessing import Pool, cpu_count
from pathlib import Path
from typing import List, Tuple

# Standalone bootstrap
_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
    if _ROOT == "/":
        raise RuntimeError("Cannot locate repo root")
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.admissibility import (  # noqa: E402
    AdmissibilityCertificate,
    EliminationCertificate,
    check_periodic_additive,
)
from kryptos.kernel.constants import CT, ALPH_IDX  # noqa: E402
from kryptos.kernel.transforms.transposition import (  # noqa: E402
    columnar_perm,
    invert_perm,
)

# ── Pinned scope (DO NOT EDIT WITHOUT FILING A NEW SCRIPT) ─────────────
WIDTHS: Tuple[int, ...] = (2, 3, 4, 5, 6, 7, 8, 9, 10)
PERIODS: Tuple[int, ...] = (1, 2, 3, 4, 5, 6, 7, 8)
VARIANTS: Tuple[str, ...] = ("beaufort",)
ORDER: str = "additive_then_transposition_decrypt"
INCOMPLETE_COLUMN: str = "ragged_right (columnar_perm default)"
BEAN_APPLIED: bool = False    # Hardcoded off for composition — see docstring

# ── Output paths ───────────────────────────────────────────────────────
RESULTS_DIR = Path(_ROOT) / "results" / "composition_admissibility_v1"
CT_INTS: Tuple[int, ...] = tuple(ALPH_IDX[c] for c in CT)

# ── Campaign workers ──────────────────────────────────────────────────

def _sweep_width(args: Tuple[int, str]) -> dict:
    """Worker: enumerate all col_orders for one (width, variant) and
    return aggregate counts + any SAT certificates (bounded by max_keep).
    """
    width, variant = args
    t0 = time.perf_counter()

    n_total = 0
    n_sat = 0
    n_unsat = 0
    reason_counts: dict = {}
    sat_certs: List[dict] = []
    max_keep_sat = 200   # guard against runaway SAT output

    for col_order in permutations(range(width)):
        perm = columnar_perm(width, col_order, length=97)
        inv = invert_perm(perm)
        ct_reindexed = tuple(CT_INTS[inv[j]] for j in range(97))

        for period in PERIODS:
            n_total += 1
            family_name = (
                f"composition_beaufort/w{width}/"
                f"co{''.join(str(c) for c in col_order)}/p{period}"
            )
            cert = check_periodic_additive(
                variant, period,
                use_cp_sat=False,           # pure path for speed
                ct_override=ct_reindexed,
                family_override=family_name,
            )
            if isinstance(cert, EliminationCertificate):
                n_unsat += 1
                r = cert.reason.value
                reason_counts[r] = reason_counts.get(r, 0) + 1
            else:
                n_sat += 1
                if len(sat_certs) < max_keep_sat:
                    sat_certs.append(cert.as_dict())

    return {
        "width": width,
        "variant": variant,
        "n_total": n_total,
        "n_sat": n_sat,
        "n_unsat": n_unsat,
        "reason_counts": reason_counts,
        "sat_certificates_sample": sat_certs,
        "wall_seconds": round(time.perf_counter() - t0, 2),
    }


# ── CP-SAT cross-verification spot check ──────────────────────────────

def _cross_verify_sample() -> List[dict]:
    """Run a small grid (width, col_order, period) under cross_verify=True
    to confirm pure-python and CP-SAT agree on the composition
    formulation.  Disagreement raises RuntimeError from inside
    check_periodic_additive.
    """
    samples = []
    for width in (3, 5, 7):
        for col_order in list(permutations(range(width)))[:3]:
            perm = columnar_perm(width, col_order, length=97)
            inv = invert_perm(perm)
            ct_reindexed = tuple(CT_INTS[inv[j]] for j in range(97))
            for period in (1, 4, 8):
                cert = check_periodic_additive(
                    "beaufort", period,
                    cross_verify=True,
                    ct_override=ct_reindexed,
                    family_override=(
                        f"cross_verify/w{width}/co{col_order}/p{period}"
                    ),
                )
                samples.append({
                    "width": width,
                    "col_order": list(col_order),
                    "period": period,
                    "solver": cert.solver,
                    "kind": (
                        "admissible"
                        if isinstance(cert, AdmissibilityCertificate)
                        else "eliminated"
                    ),
                })
    return samples


# ── Main ──────────────────────────────────────────────────────────────

def main():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    print("=" * 72)
    print("f_composition_admissibility_v1 — bounded composition sweep")
    print("=" * 72)
    print(f"  WIDTHS            = {WIDTHS}")
    print(f"  PERIODS           = {PERIODS}")
    print(f"  VARIANTS          = {VARIANTS}")
    print(f"  ORDER             = {ORDER}")
    print(f"  INCOMPLETE_COLUMN = {INCOMPLETE_COLUMN}")
    print(f"  BEAN_APPLIED      = {BEAN_APPLIED}")
    total_triples = sum(1 for _ in range(1))  # dummy to prime the sum
    total_triples = 0
    for w in WIDTHS:
        fact = 1
        for i in range(1, w + 1):
            fact *= i
        total_triples += fact * len(PERIODS) * len(VARIANTS)
    print(f"  Total (w, col_order, period, variant) triples: {total_triples:,}")
    print()

    # CP-SAT cross-verification sample
    print("Cross-verifying composition formulation (pure_python vs cp_sat)...")
    t_cv = time.perf_counter()
    cv_samples = _cross_verify_sample()
    print(
        f"  Cross-verified {len(cv_samples)} samples in "
        f"{time.perf_counter()-t_cv:.2f}s"
    )

    # Main sweep — parallelised across widths
    workers = min(4, max(1, cpu_count() - 2))
    print(f"\nStarting main sweep with {workers} workers...")
    jobs = [(w, v) for v in VARIANTS for w in WIDTHS]

    t0 = time.perf_counter()
    with Pool(workers) as pool:
        results = []
        for r in pool.imap_unordered(_sweep_width, jobs):
            results.append(r)
            print(
                f"  width={r['width']:2d} variant={r['variant']:9s} "
                f"total={r['n_total']:>10,}  sat={r['n_sat']:>8,}  "
                f"unsat={r['n_unsat']:>10,}  "
                f"wall={r['wall_seconds']:6.1f}s"
            )
    total_wall = time.perf_counter() - t0

    # Aggregate
    aggregate = {
        "scope": {
            "widths": list(WIDTHS),
            "periods": list(PERIODS),
            "variants": list(VARIANTS),
            "order": ORDER,
            "incomplete_column": INCOMPLETE_COLUMN,
            "bean_applied": BEAN_APPLIED,
        },
        "total_triples": total_triples,
        "n_sat_total": sum(r["n_sat"] for r in results),
        "n_unsat_total": sum(r["n_unsat"] for r in results),
        "by_width": sorted(results, key=lambda x: (x["variant"], x["width"])),
        "cross_verify_samples": cv_samples,
        "wall_seconds_total": round(total_wall, 2),
    }

    # Fold reason counts
    reason_totals: dict = {}
    for r in results:
        for k, v in r["reason_counts"].items():
            reason_totals[k] = reason_totals.get(k, 0) + v
    aggregate["reason_counts_total"] = reason_totals

    # Write output
    out_path = RESULTS_DIR / "columnar_beaufort_sweep.json"
    out_path.write_text(json.dumps(aggregate, indent=2, sort_keys=True))
    print(f"\nWrote: {out_path}")

    # Human-readable summary
    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"  Total triples checked:   {total_triples:,}")
    print(f"  UNSAT (formal crib-CSP): {aggregate['n_unsat_total']:,}")
    print(f"  SAT (admissible):        {aggregate['n_sat_total']:,}")
    if total_triples > 0:
        print(
            f"  UNSAT fraction:          "
            f"{100*aggregate['n_unsat_total']/total_triples:.3f}%"
        )
    print(f"  Elimination reasons:")
    for r, n in sorted(reason_totals.items(), key=lambda kv: -kv[1]):
        print(f"    {r:36s} {n:>12,}")
    print(f"\n  Wall time: {total_wall:.1f}s")
    print(f"\n  Note: Bean constraints DISABLED for composition CSP.")
    print(f"  Every UNSAT is a formal crib-residue collision proof.")
    print(f"  SATs are admissible but NOT confirmed feasible.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
