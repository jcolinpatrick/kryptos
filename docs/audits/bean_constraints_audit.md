# Bean Constraints Audit

## Verdict

- Existence of k[27] = k[65]: independently reproduced.
- 242 variant-independent inequalities: independently reproduced.
- 101 linear constraints: independently reproduced.
- Exactly 624 crib-position keystream vectors: independently reproduced.
- Scope: H1-conditional only; not a global K4 fact.

## Evidence

- Crib positions audited: [21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73]
- Equality count: 1
- Inequality count: 242
- Linear count: 101
- Valid vector count: 624

## Reproduction

```bash
PYTHONPATH=src python3 scripts/audit/audit_bean_constraints.py
```

## Important Caveat

The 624 count constrains only the 24 modeled crib positions under H1: direct positional crib mapping, canonical CT97, and additive Vigenere/Beaufort/Variant-Beaufort semantics. The other 73 CT positions are not constrained by Bean.

The script did not enumerate 26^24. It solved the linear system modulo 2 and 13, combined 8788 residue-pair candidates by CRT, and applied the inequalities exactly.
