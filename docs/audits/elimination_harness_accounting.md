# Elimination Harness Accounting Audit

## Verdict

- All probes passed: True
- A full smoke run must have `coverage.tested == coverage.total == inventory.total_configs`.
- A partial budgeted run must be `INCONCLUSIVE_BUDGET`, not eliminated.
- A resumed run must reach full coverage without dropping completed masks.
- A checkpoint hash mismatch must be refused or explicitly reported.

## Harnesses

### h_624_73_nullmask

- Passed: True
- Full status: ELIMINATED coverage={'tested': 18, 'total': 18, 'coverage_fraction': 1.0}
- Partial status: INCONCLUSIVE_BUDGET coverage={'tested': 24, 'total': 72, 'coverage_fraction': 0.3333333333333333}
- Resume status: ELIMINATED coverage={'tested': 72, 'total': 72, 'coverage_fraction': 1.0}
- Mismatch status: ERROR

### h_pretransposition_layer

- Passed: True
- Full status: ELIMINATED coverage={'tested': 30, 'total': 30, 'coverage_fraction': 1.0}
- Partial status: INCONCLUSIVE_BUDGET coverage={'tested': 12, 'total': 72, 'coverage_fraction': 0.16666666666666666}
- Resume status: ELIMINATED coverage={'tested': 72, 'total': 72, 'coverage_fraction': 1.0}
- Mismatch status: ERROR

### h_624_nonword_key_schedule

- Passed: True
- Full status: ELIMINATED coverage={'tested': 36, 'total': 36, 'coverage_fraction': 1.0}
- Partial status: INCONCLUSIVE_BUDGET coverage={'tested': 24, 'total': 96, 'coverage_fraction': 0.25}
- Resume status: ELIMINATED coverage={'tested': 96, 'total': 96, 'coverage_fraction': 1.0}
- Mismatch status: ERROR

## Reproduction

```bash
PYTHONPATH=src python3 scripts/audit/audit_elimination_harness_accounting.py
```
