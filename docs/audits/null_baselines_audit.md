# Null Baselines Audit

## Verdict

- Exact Binomial crib-score tail is mathematically correct for the random_text null.
- Empirical nulls cannot justify p-values below their sample floor.
- Stale cache entries found: 0.
- Alert p-value helper refuses stale caches and returns `stale_cache`.
- Alert artifacts record null identity, candidate p-value, family-wise p-value, sample floor, and universe hash.

## Reproduction

```bash
PYTHONPATH=src python3 scripts/audit/audit_null_baselines.py
```

## Key Findings

- Current git commit: `acfe266e624cb882d2ce8a870257a055e04990e9`
- Manifest distributions: 13
- Small random-text calibration mean: 0.9323 (expected 0.9231)
- Exact P(crib_score>=18): 3.654e-21

Search breadth and multiplicity are not solved by the cache itself. A p-value is only candidate-local unless the tested universe and post-hoc search family are explicitly included in the correction.
