# DSL Dispatcher Semantics Audit

## Verdict

- DSL-valid kinds: 19
- Dispatcher-supported kinds: 18
- Valid without translation: ['key_tape']
- Supported but not DSL-valid: []

The deferred `key_tape` gap is explicit. The dispatcher uses the canonical kernel scoring path, and worker self-reports are overruled by the kernel verifier.

Challenge-mode transposition translators are parameterized by the challenge text length; the audit columnar fixture emits a valid 35-position permutation and executes 1 candidate for the one-point search universe.

The spiral route translator now preserves an explicit `start_corner=top_right` parameter, emits a valid 15-position permutation, and solves the external top-right spiral route fixture.

A two-layer Caesar plus Vigenere challenge enumerates 6 candidate bindings and reports the same `total_tested`, proving this small composed search is accounted for exactly.

## Reproduction

```bash
PYTHONPATH=src python3 scripts/audit/audit_dsl_dispatcher_semantics.py
```
