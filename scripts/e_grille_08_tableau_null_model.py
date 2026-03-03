#!/usr/bin/env python3
"""E-GRILLE-08 / E-YAR-05: Tableau-specific null model for Kasiski signals.

CRITICAL TEST: Are the Kasiski IC peaks (periods 5, 7, 10, 14) in the YAR
grille CT genuine signals or artifacts of the KA tableau's own cyclic structure?

The KA tableau is NOT random — it's 26 cyclic shifts of KRYPTOSABCDEFGHIJLMNQUVWXZ.
Characters extracted at arbitrary positions from this structured grid will inherit
periodicity from the cyclic structure.

This script:
1. Builds the exact KA tableau as it appears on the Kryptos sculpture
2. Generates 10,000 random 106-position samples from the tableau
3. Computes IC at periods 5, 7, 10, 14 for each sample
4. Compares observed IC values against this proper null distribution
5. Computes p-values for each period

Usage: PYTHONPATH=src python3 -u scripts/e_grille_08_tableau_null_model.py
"""
from __future__ import annotations

import random
import sys
import math
from collections import Counter
from typing import List, Tuple, Dict

from kryptos.kernel.constants import KRYPTOS_ALPHABET

# ── Constants ────────────────────────────────────────────────────────────────

EXPERIMENT_ID = "E-GRILLE-08"
KA = KRYPTOS_ALPHABET  # "KRYPTOSABCDEFGHIJLMNQUVWXZ"
N_SAMPLES = 10000
SAMPLE_SIZE = 106

GRILLE_CT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"

# Observed IC values at these periods (from the analyst's Kasiski analysis)
OBSERVED_IC = {
    5: 0.0559,
    7: 0.0537,
    10: 0.0612,
    14: 0.0672,
}

# Also test additional periods for completeness
ALL_PERIODS = [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 19, 21, 26, 53]

RANDOM_IC = 1.0 / 26  # ~0.0385
ENGLISH_IC = 0.0667


# ── Tableau construction ─────────────────────────────────────────────────────

def build_tableau() -> List[str]:
    """Build the 28 tableau rows exactly matching the Kryptos sculpture.

    Row 0: header " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD" (31 chars)
    Row 1-26: label + 30 body chars (KA shifted cyclically)
        Row N (index 14) has extra L at end (31 body chars)
    Row 27: footer same as header
    """
    rows = []
    # Header
    rows.append(" ABCDEFGHIJKLMNOPQRSTUVWXYZABCD")

    # 26 body rows (A-Z)
    for i in range(26):
        label = chr(ord("A") + i)
        body = "".join(KA[(j + i) % 26] for j in range(30))
        row = label + body
        if label == "N":
            row += "L"  # Stray L anomaly (B1)
        rows.append(row)

    # Footer
    rows.append(" ABCDEFGHIJKLMNOPQRSTUVWXYZABCD")
    return rows


def build_letter_grid(tableau_rows: List[str]) -> List[Tuple[int, int, str]]:
    """Extract all alphabetic (row, col, letter) positions from the tableau."""
    positions = []
    for r, row in enumerate(tableau_rows):
        for c, ch in enumerate(row):
            if ch.isalpha():
                positions.append((r, c, ch))
    return positions


# ── IC computation ───────────────────────────────────────────────────────────

def compute_ic(text: str) -> float:
    """Index of coincidence."""
    freq = Counter(text)
    n = len(text)
    if n < 2:
        return 0.0
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


def compute_periodic_ic(text: str, period: int) -> float:
    """Average IC across all residue classes modulo period."""
    if period >= len(text):
        return 0.0

    ic_sum = 0.0
    count = 0
    for r in range(period):
        residue = text[r::period]
        if len(residue) >= 2:
            ic_sum += compute_ic(residue)
            count += 1

    return ic_sum / count if count > 0 else 0.0


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    random.seed(42)  # Reproducible

    print(f"{'='*80}")
    print(f"  {EXPERIMENT_ID}: Tableau-Specific Null Model for Kasiski Signals")
    print(f"{'='*80}")
    print(f"  Testing whether Kasiski IC peaks are KA tableau artifacts")
    print(f"  N_SAMPLES = {N_SAMPLES}, SAMPLE_SIZE = {SAMPLE_SIZE}")
    print(f"  Periods to test: {list(OBSERVED_IC.keys())} (primary) + others")
    print()
    sys.stdout.flush()

    # ── Build tableau and extract letter positions ───────────────────────────
    tableau_rows = build_tableau()
    all_positions = build_letter_grid(tableau_rows)

    print(f"Tableau: {len(tableau_rows)} rows")
    print(f"Total alphabetic positions in tableau: {len(all_positions)}")

    # Show letter frequency of the entire tableau
    all_letters = "".join(ch for _, _, ch in all_positions)
    tab_freq = Counter(all_letters)
    print(f"Tableau letter distribution (26 letters):")
    for ch in sorted(tab_freq.keys()):
        print(f"  {ch}: {tab_freq[ch]:4d}", end="")
    print()

    tab_ic = compute_ic(all_letters)
    print(f"Tableau overall IC: {tab_ic:.6f} (random={RANDOM_IC:.4f}, English={ENGLISH_IC:.4f})")
    print()
    sys.stdout.flush()

    # ── Compute observed IC at all periods ───────────────────────────────────
    print(f"Observed IC values from grille CT:")
    observed_all = {}
    for p in ALL_PERIODS:
        ic = compute_periodic_ic(GRILLE_CT, p)
        observed_all[p] = ic
        marker = " ***" if p in OBSERVED_IC else ""
        print(f"  Period {p:2d}: IC = {ic:.6f}{marker}")
    print()
    sys.stdout.flush()

    # ── Generate null distribution ───────────────────────────────────────────
    print(f"Generating {N_SAMPLES} random tableau samples of {SAMPLE_SIZE} positions...")
    sys.stdout.flush()

    # For each period, collect IC values from random samples
    null_ics: Dict[int, List[float]] = {p: [] for p in ALL_PERIODS}

    for sample_idx in range(N_SAMPLES):
        # Randomly select SAMPLE_SIZE positions from the tableau
        selected = random.sample(all_positions, SAMPLE_SIZE)
        sample_text = "".join(ch for _, _, ch in selected)

        # Compute periodic IC at each period
        for p in ALL_PERIODS:
            ic = compute_periodic_ic(sample_text, p)
            null_ics[p].append(ic)

        if (sample_idx + 1) % 2000 == 0:
            print(f"  ... {sample_idx + 1}/{N_SAMPLES} samples complete")
            sys.stdout.flush()

    print(f"  Done.")
    print()

    # ── Compute statistics and p-values ──────────────────────────────────────
    print(f"{'='*80}")
    print(f"RESULTS: Observed vs Tableau Null Distribution")
    print(f"{'='*80}")
    print()

    print(f"{'Period':>6s} {'Observed':>10s} {'Null Mean':>10s} {'Null Std':>10s} "
          f"{'Null 5%':>10s} {'Null 95%':>10s} {'p-value':>10s} {'Verdict':>12s}")
    print(f"{'─'*6} {'─'*10} {'─'*10} {'─'*10} {'─'*10} {'─'*10} {'─'*10} {'─'*12}")

    for p in ALL_PERIODS:
        null_vals = sorted(null_ics[p])
        n = len(null_vals)
        null_mean = sum(null_vals) / n
        null_std = math.sqrt(sum((v - null_mean)**2 for v in null_vals) / n)

        # Percentiles
        p5 = null_vals[int(0.05 * n)]
        p95 = null_vals[int(0.95 * n)]
        p99 = null_vals[int(0.99 * n)]

        # Observed value
        obs = observed_all[p]

        # p-value: fraction of null samples with IC >= observed
        exceeding = sum(1 for v in null_vals if v >= obs)
        p_value = exceeding / n

        # Verdict
        if p_value < 0.01:
            verdict = "SIGNIFICANT"
        elif p_value < 0.05:
            verdict = "MARGINAL"
        else:
            verdict = "NOT SIG"

        marker = " ***" if p in OBSERVED_IC else ""
        print(f"{p:6d} {obs:10.6f} {null_mean:10.6f} {null_std:10.6f} "
              f"{p5:10.6f} {p95:10.6f} {p_value:10.4f} {verdict:>12s}{marker}")

    # ── Detailed analysis of key periods ─────────────────────────────────────
    print(f"\n{'='*80}")
    print(f"DETAILED ANALYSIS OF KEY PERIODS")
    print(f"{'='*80}")

    for p in sorted(OBSERVED_IC.keys()):
        null_vals = sorted(null_ics[p])
        n = len(null_vals)
        null_mean = sum(null_vals) / n
        null_std = math.sqrt(sum((v - null_mean)**2 for v in null_vals) / n)
        obs = observed_all[p]
        exceeding = sum(1 for v in null_vals if v >= obs)
        p_value = exceeding / n

        # Z-score
        z = (obs - null_mean) / null_std if null_std > 0 else 0

        # Percentile of observed in null distribution
        below = sum(1 for v in null_vals if v < obs)
        percentile = below / n * 100

        print(f"\n  Period {p}:")
        print(f"    Observed IC:     {obs:.6f}")
        print(f"    Null mean:       {null_mean:.6f}")
        print(f"    Null std:        {null_std:.6f}")
        print(f"    Z-score:         {z:+.3f}")
        print(f"    Percentile:      {percentile:.1f}%")
        print(f"    p-value (1-tail): {p_value:.4f}")
        print(f"    Null [5%, 95%]:  [{null_vals[int(0.05*n)]:.6f}, {null_vals[int(0.95*n)]:.6f}]")
        print(f"    Null [1%, 99%]:  [{null_vals[int(0.01*n)]:.6f}, {null_vals[int(0.99*n)]:.6f}]")
        print(f"    Null min/max:    [{null_vals[0]:.6f}, {null_vals[-1]:.6f}]")

        if p_value > 0.05:
            print(f"    VERDICT: NOT SIGNIFICANT — IC is within tableau null expectation.")
            print(f"    The period-{p} signal is an ARTIFACT of the KA tableau structure.")
        elif p_value > 0.01:
            print(f"    VERDICT: MARGINAL — borderline significance, likely tableau artifact.")
        else:
            print(f"    VERDICT: SIGNIFICANT — exceeds tableau null at p < 0.01.")
            print(f"    This would indicate genuine periodic structure BEYOND tableau geometry.")

    # ── Also test: uniform random null (for comparison) ──────────────────────
    print(f"\n{'='*80}")
    print(f"COMPARISON: Uniform Random Null (no tableau structure)")
    print(f"{'='*80}")

    uniform_ics: Dict[int, List[float]] = {p: [] for p in OBSERVED_IC.keys()}
    for _ in range(N_SAMPLES):
        sample = "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(SAMPLE_SIZE))
        for p in OBSERVED_IC.keys():
            ic = compute_periodic_ic(sample, p)
            uniform_ics[p].append(ic)

    print(f"\n{'Period':>6s} {'Observed':>10s} {'Tab Mean':>10s} {'Tab p-val':>10s} "
          f"{'Uni Mean':>10s} {'Uni p-val':>10s} {'Conclusion'}")
    print(f"{'─'*6} {'─'*10} {'─'*10} {'─'*10} {'─'*10} {'─'*10} {'─'*30}")

    for p in sorted(OBSERVED_IC.keys()):
        obs = observed_all[p]

        # Tableau null
        tab_vals = null_ics[p]
        tab_mean = sum(tab_vals) / len(tab_vals)
        tab_p = sum(1 for v in tab_vals if v >= obs) / len(tab_vals)

        # Uniform null
        uni_vals = uniform_ics[p]
        uni_mean = sum(uni_vals) / len(uni_vals)
        uni_p = sum(1 for v in uni_vals if v >= obs) / len(uni_vals)

        if tab_p > 0.05 and uni_p < 0.05:
            conclusion = "ARTIFACT (tableau explains signal)"
        elif tab_p > 0.05 and uni_p > 0.05:
            conclusion = "NOT SIGNIFICANT (either model)"
        elif tab_p < 0.05 and uni_p < 0.05:
            conclusion = "GENUINE SIGNAL"
        else:
            conclusion = "ANOMALOUS"

        print(f"{p:6d} {obs:10.6f} {tab_mean:10.6f} {tab_p:10.4f} "
              f"{uni_mean:10.6f} {uni_p:10.4f} {conclusion}")

    # ── Overall verdict ──────────────────────────────────────────────────────
    print(f"\n{'='*80}")
    print(f"OVERALL VERDICT")
    print(f"{'='*80}")

    all_artifact = True
    any_genuine = False
    for p in OBSERVED_IC.keys():
        tab_p = sum(1 for v in null_ics[p] if v >= observed_all[p]) / len(null_ics[p])
        if tab_p < 0.05:
            all_artifact = False
            any_genuine = True

    if all_artifact:
        print(f"""
  ALL Kasiski IC peaks (periods {list(OBSERVED_IC.keys())}) are ARTIFACTS
  of the KA tableau's cyclic structure.

  The KA alphabet KRYPTOSABCDEFGHIJLMNQUVWXZ has inherent periodicity.
  When 106 positions are randomly sampled from this tableau, the resulting
  IC at these periods is ALREADY elevated compared to uniform random text.
  The observed IC values fall comfortably within this tableau-specific
  null distribution.

  CONCLUSION: The grille CT shows NO evidence of an embedded periodic cipher.
  The Kasiski signals that appeared significant against a uniform random
  baseline are fully explained by the tableau structure itself.
""")
    elif any_genuine:
        genuine = [p for p in OBSERVED_IC.keys()
                   if sum(1 for v in null_ics[p] if v >= observed_all[p]) / len(null_ics[p]) < 0.05]
        artifact = [p for p in OBSERVED_IC.keys() if p not in genuine]
        print(f"""
  MIXED RESULT:
  Genuine signals (p < 0.05 vs tableau null): periods {genuine}
  Artifacts (p >= 0.05 vs tableau null): periods {artifact}

  Some IC peaks exceed what the tableau structure alone can explain.
  These warrant further investigation as potential periodic cipher signals.
""")

    print(f"{'='*80}")
    print(f"  {EXPERIMENT_ID} COMPLETE")
    print(f"{'='*80}")


if __name__ == "__main__":
    main()
