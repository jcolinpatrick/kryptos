#!/usr/bin/env python3
"""CANCELLED 2026-08-25 by operator decision. Do not re-run; do not restore.

Quagmire IV is PROVABLY UNFILTERABLE by exact linear closure at the evidence
level, and the arithmetic is short enough to state in full:

    Q4 equation:  pi_c(c_i) - pi_p(p_i) - k[r_i] = 0

    At L0 the 24 released cribs touch 14 distinct ciphertext letters and 13
    distinct plaintext letters. Two INDEPENDENT alphabets make those separate
    unknowns: 14 + 13 = 27, minus 2 gauge freedoms (a constant may be added to
    pi_c and to pi_p independently) = 25 effective unknowns BEFORE the key
    contributes P more.

        25 + P unknowns  vs  24 equations   ->  underdetermined at EVERY period.

So linear consistency can never contradict Q4 on the released cribs, at any
period, for any key, for any pair of alphabets. Every cell would report
"consistent" for structural reasons having nothing to do with K4 -- the same
degrees-of-freedom artefact recorded in
scripts/crib_analysis/e_crib_31_filter_power_analysis.py.

Q4 becomes filterable only at crib levels L4/L5 (74 equations, saturating at
P >= 31), and those levels are conditional on an unproven plaintext hypothesis,
so any elimination there would be conditional too.

Contrast Quagmire III, which was allowed to finish: one SHARED alphabet spans
the UNION of 21 letters, giving 20 + P unknowns against 24 equations and
contradicting up to period 3. Narrow, but unconditional and real. Sharing the
alphabet sounds like it should constrain more; it constrains less, because it
recruits more distinct letters into the system.

The original implementation is preserved as
scripts/crib_analysis/e_crib_71_quagmire_iv_exact.py.cancelled
"""
import sys

print(__doc__)
print("CANCELLED: the Quagmire IV sweep will not run. See the docstring above.",
      file=sys.stderr)
sys.exit(3)
