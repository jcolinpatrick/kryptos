# Stehle Mechanism Audit

## Verdict

- Hard cryptanalytic constraint: False
- Soft ranking feature: True
- Local anomaly with no current exploit: True

## Observed

- Substring: `DIAWINFBN`
- Lag-4 deltas: [5, 5, 5, 5, 5]

## Mechanism Findings

- Additive leakage gives algebraic relations, but no lag-4 pair has both plaintext endpoints known.
- Width 21 explains the five pairs as same-row lag-4 geometry, but not the delta value.
- Single-deletion null scans do not produce a predicate that candidates must satisfy.
- Finite predicate checks falsify geometry-only explanations such as width-21 same-row lag-4 implies delta 5.

## Reproduction

```bash
PYTHONPATH=src python3 scripts/audit/audit_stehle_mechanisms.py
```

