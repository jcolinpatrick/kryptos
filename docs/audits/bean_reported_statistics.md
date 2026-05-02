# Bean-Reported Statistics Audit

## Verdict

- Bean/Materna minor-difference statistic is independently reproduced in substance under a K4-multiset permutation null.
- The IID uniform null gives a smaller p-value than Bean's reported p≈1/5520; the K4-multiset permutation null lands near the reported value.
- Repeated-plaintext-letter CT distances are descriptive unless a precise pre-registered statistic and correction family are declared.

## Minor Difference

- Subset: PT letters in KRYPTOS set; n=10
- Observed sum distance: 21
- Exact IID p(sum <= observed): 4.88685e-05 (1/20463.1)
- K4-multiset permutation MC p: 0.000186 (1/5376.3, samples=2000000)

## Repeated Plaintext Letters

- Pair count: 13
- Observed summed CT-distance statistic: 47
- K4-multiset permutation MC p: 0.004276 (1/233.9)

## Caveat

Both statistics are crib-position and H1 dependent. The minor-difference subset is post-hoc: the selected PT-letter set spells KRYPTOS. Neither statistic is a hard constraint or elimination basis without an explicit pre-registered search family correction.

## Reproduction

```bash
PYTHONPATH=src python3 scripts/audit/audit_bean_reported_statistics.py
```
