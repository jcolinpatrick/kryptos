# Phase R3-0.5-3 — Polybius translator

**Date:** 2026-04-21
**Brief:** `CLAUDE_CODE_BRIEF_round3_0_5_dsl_completion.md` §4
**Phase result:** Complete. 21 new tests, 2 pre-existing tests migrated, all green. Self-test unchanged.

---

## 1. Thinnest phase as anticipated

Pre-flight §2.3 mapped the existing polybius kernel:
- `src/kryptos/kernel/transforms/polybius.py` — `make_polybius_5x5`, `polybius_encode/decode`, `bifid_encrypt/decrypt`
- `src/kryptos/kernel/transforms/compose.py::TransformType.BIFID` already registered with dispatcher
- `polybius` already in `_VALID_CIPHER_KINDS`

R3-0.5-3's implementation is the thinnest of the three phases: a single `_translate_layer` case in `kryptosbot/job_dispatcher.py` that wires the theorist's DSL params to the existing `TransformType.BIFID` step. No new kernel code. No new `TransformType`. No DSL schema changes.

---

## 2. What landed

### 2.1 `polybius` in `_SUPPORTED_KINDS`

`kryptosbot/job_dispatcher.py::_SUPPORTED_KINDS` grows to **9 entries**. This hits the brief's exit target.

### 2.2 `_translate_layer` case for `kind == "polybius"`

Parameters accepted from the binding dict:

| Param | Type | Required | Default | Semantics |
|---|---|---|---|---|
| `square_keyword` | str | **yes** | — | Prefix for the 5×5 grid; `""` gives canonical A–Z |
| `merge` | str (2 chars) | no | `"IJ"` | Which pair shares a cell; `"IJ"`, `"CK"`, `"VW"` |
| `variant` | str | no | `"bifid"` | Only `"bifid"` accepted in R3-0.5-3 |
| `direction` | str | no | `"decrypt"` | `"encrypt"` or `"decrypt"` |
| `period` | int ≥ 0 | no | `0` | Bifid period; 0 means full-length classical |

Produces step dict `{"type": "bifid", "params": {keyword, merge, period, direction}}` — matching the existing `TransformType.BIFID` interface in `compose.py:178`.

### 2.3 Explicit rejection of straight polybius

`variant="polybius"` (straight, length-doubling letter→coord-pair encoding) raises `DispatcherError` with a deferral message pointing the caller at a later brief. Rationale: straight polybius produces 2×-length output from its input, breaking the dispatcher's length-preserving assumption downstream of `score_candidate` (which expects a 97-char plaintext). Wiring it cleanly requires a new `TransformType` AND a scoring-workflow change — neither fits within R3-0.5-3's "thin wrapper" scope.

Bifid (length-preserving fractionation) is the canonical length-preserving variant and covers the multi-layer composition use case the brief §4.1 out-of-scope clause calls out.

### 2.4 Two pre-existing tests migrated

`kryptosbot/tests/test_job_dispatcher.py` had two tests exercising the "unsupported kind" path using `polybius` as the exemplar:

- `test_unsupported_kind_rejected_with_pointer`
- `test_admissibility_rejection_short_circuits`

Both now use `"rail_fence"` instead (still in `_VALID_CIPHER_KINDS`, still lacking a translator). Comments in each test document the migration so future developers understand why the exemplar changed.

---

## 3. Tests (21 new + 2 migrated)

**Kind registration (3):**
- `test_polybius_in_dispatcher_supported_kinds`
- `test_polybius_in_dsl_valid_cipher_kinds`
- `test_bifid_transformtype_already_registered`

**Kernel roundtrip sanity (3):**
- `test_bifid_kernel_roundtrip_identity` — 10-letter PT, KRYPTOS grid, period 5
- `test_make_polybius_5x5_empty_keyword_is_canonical_alphabet`
- `test_make_polybius_5x5_keyword_prefixes_alphabet`

**Translator adversarial (9):**
- `test_translate_polybius_missing_square_keyword_raises`
- `test_translate_polybius_non_string_keyword_raises`
- `test_translate_polybius_straight_variant_raises_with_deferral_note`
- `test_translate_polybius_unknown_variant_raises`
- `test_translate_polybius_bad_merge_length_raises`
- `test_translate_polybius_bad_direction_raises`
- `test_translate_polybius_negative_period_raises`
- `test_translate_polybius_non_int_period_raises`
- `test_translate_polybius_bool_period_rejected` (Python quirk: `True == 1`; explicit bool rejection)

**Translator happy path (3):**
- `test_translate_polybius_minimal_binding_produces_bifid_step`
- `test_translate_polybius_empty_keyword_accepted`
- `test_translate_polybius_all_params_plumbed_through`

**End-to-end dispatch (3):**
- `test_execute_polybius_dispatches_on_k4_ct` (noise expected per 26-letter gotcha; dispatch must run cleanly)
- `test_execute_polybius_sweeps_multiple_keywords`
- `test_execute_polybius_kernel_overrule_preserved`

Test file: `kryptosbot/tests/test_r3_0_5_polybius_translator.py` (21 tests, ~240 lines).

Brief's minimum was 8. This phase delivers 21 — adversarial coverage of the 9 distinct error modes in the translator plus 3 happy paths plus 3 end-to-end. Every translator parameter has at least one negative test.

---

## 4. Non-regression verification

| Check | Expected | Actual | Match |
|---|---|---|---|
| Core test suite | 1529 passed | 1529 passed | ✓ |
| Kryptosbot test suite | 704 + 21 = 725 | 725 passed | ✓ |
| Pre-existing test_job_dispatcher tests | 2 migrated | 2 pass with rail_fence | ✓ |
| Self-test K1 | 15 cycles | 15 cycles | ✓ |
| Self-test K2 | 17 cycles | 17 cycles | ✓ |
| Self-test K3 | 9345 cycles | 9345 cycles | ✓ |
| `polybius` in `_SUPPORTED_KINDS` | yes | yes | ✓ |
| `_SUPPORTED_KINDS` size | 9 | 9 | ✓ |

---

## 5. Code footprint

```
 kryptosbot/job_dispatcher.py                         |  66 +
 kryptosbot/tests/test_job_dispatcher.py              |  20 (migration)
 kryptosbot/tests/test_r3_0_5_polybius_translator.py  | 246 ++
 3 files changed, ~330 insertions
```

Well under the brief's 300-line soft cap excluding tests. The 66 lines added to `job_dispatcher.py` are ~half docstring explaining the K4 applicability and the straight-polybius deferral; the translator body is ~30 lines.

Zero new kernel code. Zero new `TransformType`. Zero DSL schema changes.

---

## 6. What this phase did NOT change

- No new kernel module.
- No changes to `make_polybius_5x5`, `bifid_encrypt`, `bifid_decrypt`.
- No new `TransformType`. Specifically, **`TransformType.POLYBIUS` (straight) was NOT added** — deferred to a later brief.
- No theorist prompt changes.
- No critic changes.
- No legacy worker path changes.
- No `HypothesisSpec` schema changes.
- No changes to `_VALID_CIPHER_KINDS` (polybius was already there).

---

## 7. Handoff to R3-0.5-4

`_SUPPORTED_KINDS` now has **exactly 9 entries** matching the brief's exit target:

```
{atbash, beaufort, columnar, grille, identity, polybius, procedural,
 variant_beaufort, vigenere}
```

R3-0.5-4's job:
- Run all four consistency checks from brief §5.1 (suite green, 9 kinds, self-test matches, smoke test all three new kinds).
- Update `DSL_CUTOVER_CONTRACT.md` §1.2 (already runtime-authoritative; confirm landed state is correct) and §1.3 Example C (revise to use a still-untranslatable kind like `rail_fence` now that `procedural` is translatable).
- Add MEMORY.md pointer for R3-0.5 completion.
- Write `phase_R3_05_04_report.md` with final summary.
- Final commit: `maturation round 3.5 complete: DSL completion for procedural, grille, polybius`.

*End of R3-0.5-3 phase report.*
