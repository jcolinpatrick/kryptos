# Stehle Significance Audit

## Verdict

- Existence: verified.
- Bean p~1/642: reproduced under the 712-test Bonferroni family; not reproduced as a pre-registered cryptanalytic test.
- Cryptographic role: not proven.
- Recommended use: local anomaly with no current exploit; not a hard constraint.

## Observed Pattern

- 0-indexed positions: [55, 63]
- 1-indexed positions: [56, 64]
- Substring: `DIAWINFBN`
- Lag-4 deltas: [5, 5, 5, 5, 5]

## Statistics

- Fixed start, lag, and specified delta=5: 8.41653e-08
- Fixed start and lag, any constant delta: 2.1883e-06
- Bonferroni factor 712 applied to any-delta raw probability: 0.00155807

The p~1/642 figure is reproduced only as a Bonferroni calculation using raw probability 1/26^4 and a 712-test family. That is a post-hoc descriptive significance calculation, not a cipher predicate.

## Reproduction

```bash
PYTHONPATH=src python3 scripts/audit/audit_stehle_significance.py
```
