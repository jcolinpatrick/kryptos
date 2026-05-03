# Known-Answer Battery Audit

## Verdict

The repo has a useful K1/K2/K3 dry-run self-test, but that is not yet a general hand-cipher solver proof. It proves selected known public keys are reachable in scripted strategy schedules.

## Existing Self-Test

- Command exit code: 0
- k1: discovered=True cycles=15 peak=20/20
- k2: discovered=True cycles=17 peak=20/20
- k3: discovered=True cycles=9345 peak=20/20

## Synthetic Fixtures Added To Audit Artifact

- Fixture count: 8
- Families include Caesar, affine, Vigenere, Beaufort, Variant Beaufort, columnar, route, and a two-layer composite.

## Dispatcher Challenge Path

A separate pytest battery now runs independent known-answer challenges through `job_dispatcher.execute(..., challenge_ciphertext=..., challenge_crib_dict=...)` at both K4 length and non-97 lengths for identity, Caesar, Vigenere, Beaufort, Variant Beaufort, Atbash, columnar, rail fence, route, Myszkowski, Bifid, Quagmire, grille, reverse blocks, skip route, boustrophedon, row reversal, and a procedural identity recipe. It also includes a wrong-variant negative control, wrong-crib scoring check, wrong-column-order control, randomized-ciphertext controls, wrong-parameter controls, non-A-Z input rejection, exact cardinality checks, and confirms `key_tape` remains explicitly deferred.

## Static Known-Answer Corpus

- Corpus path: `tests/audit/known_answer_corpus.json`
- Corpus fixture count: 18
- Families include: atbash, beaufort, caesar, columnar, grille, identity, key_tape, myszkowski, polybius, quagmire, rail_fence, reverse_blocks, route, route_boustrophedon, row_reverse, skip_route, variant_beaufort, vigenere.

## External Known-Answer Corpus

- Corpus path: `tests/audit/external_known_answer_corpus.json`
- External fixture count: 11
- Families include: atbash, beaufort, caesar, columnar, myszkowski, polybius, quagmire, rail_fence, route, vigenere.
- Source count: 11.
- These fixtures are still known-key semantic checks, not autonomous solving benchmarks.

## External Composite Corpus

- Corpus path: `tests/audit/external_known_answer_composites.json`
- External composite fixture count: 1
- Families exercised in external composites: columnar.
- Source count: 1.
- Includes a layer-order negative control for the published double-columnar example.

## Static Composite Corpus

- Corpus path: `tests/audit/known_answer_composites.json`
- Composite fixture count: 3
- Families exercised in composites: beaufort, caesar, columnar, reverse_blocks, row_reverse, vigenere.
- Includes a layer-order negative control and a six-point enumerated composite universe check.

## Remaining Gap

The challenge path now supports arbitrary A-Z lengths and has local, external, and composite known-answer corpora. The external corpus covers several live families and one published double-columnar composite, but it is still a known-key semantic battery rather than a proof of autonomous solving power. The next step is broader external coverage for grille/procedural families and larger pre-registered multi-layer searches.

## Reproduction

```bash
PYTHONPATH=src python3 scripts/audit/audit_known_answer_battery.py
PYTHONPATH=src python3 -m pytest tests/audit/test_dispatcher_known_answer_challenges.py -q
```
