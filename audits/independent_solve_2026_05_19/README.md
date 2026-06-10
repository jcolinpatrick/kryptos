# Independent K4 Solve Attempt — 2026-05-19

Operator: Claude Opus 4.7 (1M context). Authorizing user: Colin Patrick.

This directory is an **audit and frontier-identification** artifact, not
a parallel K4 attack apparatus. It executes the program in the originating
research-lead prompt while honouring the operational doctrine of the
containing repository (see `/home/cpatrick/kryptos/CLAUDE.md` and
`/home/cpatrick/kryptos/MEMORY.md`).

## Quick read

- **Verdict**: `NO VERIFIED SOLVE`.
- **Final report**: `results/final_report.md`.
- **What was independently verified**: data identity vs the kernel, the
  K1/K2 method via the Kryptos-keyed tableau, byte-identical cross-kernel
  parity over 10 Vig/Beau/VarBeau configurations, Bean variant-invariant
  equality `k[27]=k[65]` from the public crib dictionary alone, IC =
  0.036082 and zero repeated trigrams on the 97-character CT.
- **What this attempt explicitly did not do**: re-test items on the
  session briefing's DO NOT TEST list; commit a $25+ compute swing
  without red-team review; touch the sealed coding chart or any
  RR Auction artifacts (`feedback_auction_out_of_scope.md`).

## File layout

```
audits/independent_solve_2026_05_19/
├── execution_contract.md            (binding contract; read before changing anything here)
├── README.md                        (this file)
├── data/                            (audit-local copies of public facts, with provenance)
│   ├── k4.json
│   ├── known_sections.md
│   └── sources.md
├── src/                             (stdlib-only reference impls; NEVER import kryptos.kernel)
│   ├── alphabets.py
│   ├── kryptos_tableau.py
│   ├── scoring.py
│   ├── stats.py
│   ├── constraints.py
│   └── ciphers/
│       ├── vigenere.py
│       ├── beaufort.py
│       ├── autokey.py
│       └── transposition.py
├── tests/                           (cross-checks; kernel imports allowed here as comparator)
│   ├── test_data_integrity.py
│   ├── test_k1_k2_k3.py
│   └── test_cross_kernel.py
├── experiments/
│   ├── e01_baseline_stats.py
│   └── e02_holdout_sanity_sweep.py
└── results/
    ├── baseline_stats.json
    ├── e02_holdout_sweep.json
    ├── experiment_log.md
    ├── negative_results.md
    └── final_report.md
```

## Run order (from scratch)

```bash
# 1. Data identity (uses kernel as comparator)
PYTHONPATH=src python3 audits/independent_solve_2026_05_19/tests/test_data_integrity.py

# 2. Reference reproduces K1 and K2
python3 audits/independent_solve_2026_05_19/tests/test_k1_k2_k3.py

# 3. Cross-kernel parity over 10 configurations
python3 audits/independent_solve_2026_05_19/tests/test_cross_kernel.py

# 4. Independent baseline statistics + Bean re-derivation
python3 audits/independent_solve_2026_05_19/experiments/e01_baseline_stats.py

# 5. Holdout-verified Vig/Beau/VarBeau sanity sweep (138 configs)
python3 audits/independent_solve_2026_05_19/experiments/e02_holdout_sanity_sweep.py
```

All five run in well under a minute on a single core.
