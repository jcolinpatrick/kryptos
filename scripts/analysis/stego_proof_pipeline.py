#!/usr/bin/env python3
"""Stego backward propagation pipeline — end-to-end proof chain.

Runs all three layers of the stego proof system:
  Layer 1: Stego layer proof (S2, S4, S5, S6)
  Layer 3: Stego-cipher coupling constraints (CxS-1 through CxS-4)
  Compliance scoring (with --score flag)

Usage:
    PYTHONPATH=src python3 -u scripts/analysis/stego_proof_pipeline.py
    PYTHONPATH=src python3 -u scripts/analysis/stego_proof_pipeline.py --score

# Cipher: Beaufort
# Family: analysis
# Status: active
# Keyspace: N/A (proof pipeline, no search)
# Last run: 2026-03-23
# Best score: N/A
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md

import sys
import os
import argparse

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    ALPH,
    BEAUFORT_KEYSTREAM_AT_CRIBS,
    CT,
    NULL_PALETTE,
)
from kryptos.kernel.constraints.stego import full_stego_proof
from kryptos.kernel.constraints.coupling import propagate_all
from kryptos.kernel.scoring.compliance import (
    MechanismDescription,
    score_mechanism_compliance,
)


DIVIDER = "=" * 72


def print_stego_layer() -> None:
    """Layer 1: Run and display all stego proof properties."""
    print(DIVIDER)
    print("LAYER 1 — STEGO LAYER PROOF")
    print(DIVIDER)
    print()

    properties = full_stego_proof(CT)
    for prop in properties:
        print(f"  [{prop.id}] {prop.name}")
        print(f"       observed : {prop.observed}")
        print(f"       expected : {prop.expected}")
        print(f"       p-value  : {prop.p_value:.6g}")
        print(f"       method   : {prop.method}")
        print(f"       status   : {prop.status}")
        print()

    print(f"  Total properties: {len(properties)}")
    confirmed = sum(1 for p in properties if p.status == "confirmed")
    print(f"  Confirmed: {confirmed}/{len(properties)}")
    print()


def print_coupling_layer() -> None:
    """Layer 3: Run and display all coupling constraints."""
    print(DIVIDER)
    print("LAYER 3 — STEGO-CIPHER COUPLING CONSTRAINTS")
    print(DIVIDER)
    print()

    ks_nums = [ALPH.index(c) for c in BEAUFORT_KEYSTREAM_AT_CRIBS]
    constraints = propagate_all(ks_nums, NULL_PALETTE)
    for con in constraints:
        print(f"  [{con.id}] {con.name}")
        print(f"       description : {con.description}")
        print(f"       evidence    : {con.evidence}")
        print(f"       p-value     : {con.p_value:.6g}")
        print(f"       type        : {con.constraint_type}")
        print()

    print(f"  Total constraints: {len(constraints)}")
    print()


def print_compliance_scoring() -> None:
    """Compliance scoring: evaluate the reference mechanism."""
    print(DIVIDER)
    print("COMPLIANCE SCORING")
    print(DIVIDER)
    print()

    ks_nums = [ALPH.index(c) for c in BEAUFORT_KEYSTREAM_AT_CRIBS]

    mechanism = MechanismDescription(
        name="K4 Beaufort A=0 (reference)",
        uses_ka=True,
        uses_az=True,
        grid_width=5,
        hand_executable=True,
        periodic=False,
        key_source="5-wide KA Polybius grid",
    )

    result = score_mechanism_compliance(ks_nums, mechanism)

    print(f"  Mechanism : {mechanism.name}")
    print(f"  Verdict   : {result.verdict}")
    print()
    print(f"  Hard constraints : {result.hard_pass} PASS / {result.hard_fail} FAIL / {result.hard_unknown} UNKNOWN")
    for hc_id, hc_val in sorted(result.details["hard"].items()):
        print(f"    {hc_id}: {hc_val}")
    print()
    print(f"  Coupling score   : {result.coupling_score:.4f}")
    for cx_id, cx_val in sorted(result.details["coupling"].items()):
        print(f"    {cx_id}: {cx_val:.4f}")
    print()
    print(f"  Bean score       : {result.bean_score:.4f}")
    for sc_id, sc_val in sorted(result.details["bean"].items()):
        print(f"    {sc_id}: {sc_val}")
    print()
    print(f"  Structural score : {result.structural_score:.4f}")
    for xc_id, xc_val in sorted(result.details["structural"].items()):
        print(f"    {xc_id}: {xc_val}")
    print()
    print(f"  Total score      : {result.total:.4f}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Stego backward propagation pipeline"
    )
    parser.add_argument(
        "--score",
        action="store_true",
        help="Include compliance scoring (Tier 0-3 evaluation)",
    )
    args = parser.parse_args()

    print()
    print_stego_layer()
    print_coupling_layer()

    if args.score:
        print_compliance_scoring()

    print(DIVIDER)
    print("PIPELINE COMPLETE")
    print(DIVIDER)


if __name__ == "__main__":
    main()
