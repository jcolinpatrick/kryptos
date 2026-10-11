#!/usr/bin/env bash
# One command for everything on kryptosbot.com/crib-parity/:
#   1. check every Lean proof,
#   2. print the axioms each headline theorem rests on,
#   3. recompute the exact figures that are counts rather than Lean proofs.
# Run from anywhere:  bash formal/k4_parity/reproduce.sh
# Needs elan (https://github.com/leanprover/elan) and Python 3.11+. The first run downloads
# prebuilt Mathlib (lake exe cache get); Mathlib is never built from source.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
cd "$here"
lake exe cache get
lake build
lake env lean AxiomAudit.lean
cd "$repo"
PYTHONPATH=src python3 formal/k4_parity/parity_figures.py
