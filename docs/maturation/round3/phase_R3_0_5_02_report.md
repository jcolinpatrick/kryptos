# Phase R3-0.5-2 — Grille translator

**Date:** 2026-04-21
**Brief:** `CLAUDE_CODE_BRIEF_round3_0_5_dsl_completion.md` §3
**Phase result:** Complete. 24 new tests, all green. Self-test unchanged.

---

## 1. Thin-adapter confirmation (brief §3 special instruction)

The brief's special instruction for this phase: "this is the phase most likely to grow. Grilles involve kernel-level permutation representation. Before writing the new grille.py transform, map exactly what kernel primitives already exist and confirm the translator can be thin."

**Mapping result (from pre-flight §2.2):**

- `src/kryptos/kernel/transforms/transposition.py::apply_perm(text, perm)` already implements gather-perm semantics: `output[i] = input[perm[i]]`.
- `src/kryptos/kernel/transforms/compose.py::TransformType.TRANSPOSITION_FULL` dispatches through `apply_perm` with `direction="apply"` giving exactly the grille gather.
- `src/kryptos/kernel/transforms/transposition.py::invert_perm` gives the inverse.

**Decision:** Cardano-grille under the permutation-only interpretation (brief §3.2) is semantically identical to `apply_perm` with a full-length mask-as-perm. The implementation is therefore a thin adapter:

- `src/kryptos/kernel/transforms/grille.py` is a new 100-line kernel module exposing `apply_grille_permutation` (a thin wrapper over `apply_perm`) and `validate_grille_mask` (mask-specific validation with clear errors).
- `TransformType.GRILLE = "grille"` added to the compose.py enum.
- `compose.py` dispatch case for `GRILLE` calls `apply_grille_permutation`.
- The translator in `job_dispatcher.py::_translate_layer` maps `kind="grille"` to `{"type": "grille", "params": {"mask_order": [...]}}`.

No new kernel primitive logic. No refactoring of existing primitives. The grille module's entire new implementation is three lines of code (`apply_grille_permutation` is a one-liner over `apply_perm`) plus a validator. Everything else is docstring and the validation function.

**Scope verdict:** thin adapter confirmed. No escalation needed.

---

## 2. What landed

### 2.1 New kernel module `src/kryptos/kernel/transforms/grille.py`

- `apply_grille_permutation(text, mask_order) -> str` — one-liner over `apply_perm`.
- `validate_grille_mask(mask_order, expected_len) -> list[str]` — returns empty list when valid, explicit error strings otherwise. Checks: iterability, int type (rejecting bool), length, negative values, out-of-range values, duplicates, permutation coverage.

Mask validation is positioned in the kernel module (not just the dispatcher translator) because the permutation-only interpretation is a kernel-level invariant — any caller producing a grille mask must satisfy it.

### 2.2 `TransformType.GRILLE` registered

`src/kryptos/kernel/transforms/compose.py`:

- New enum value: `TransformType.GRILLE = "grille"`
- New dispatch case delegating to `apply_grille_permutation`

### 2.3 `grille` in `_SUPPORTED_KINDS`

`kryptosbot/job_dispatcher.py::_SUPPORTED_KINDS` grows to 8 entries.

### 2.4 Translator case in `_translate_layer`

New case for `kind == "grille"`:

- Requires a `hole_mask` binding value (list or tuple).
- Runs `validate_grille_mask` against `CT_LEN` (imported from `kryptos.kernel.constants`).
- Produces `{"type": "grille", "params": {"mask_order": list(mask)}}` on success.
- Raises `DispatcherError` with concatenated validation errors on failure.

### 2.5 Brief deviation: `_VALID_CIPHER_KINDS` grew by one

The brief's §6 non-goal list includes "Do not grow `_VALID_CIPHER_KINDS`. Kinds already in the literal type that still lack translators (rail_fence, route, myszkowski, quagmire, key_tape) remain admissibility-rejected after R3-0.5."

The clause is inconsistent with the brief's own §3 acceptance criteria:

- `grille` was **not** in the pre-R3-0.5 `CipherKind` literal.
- For `HypothesisSpec(pipeline=[CipherLayer(kind="grille", ...)])` to pass `spec.validate()`, `grille` must be in `_VALID_CIPHER_KINDS`.
- The brief's §3.6 "`grille` is in `_SUPPORTED_KINDS`" + §3.5 integration tests require this.

R3-0.5-2 added `"grille"` to both the `CipherKind` Literal and the `_VALID_CIPHER_KINDS` frozenset. This is a one-line DSL change strictly required for the brief's own acceptance criteria to be satisfiable.

Noted in this report for audit transparency. The non-goal's other cited kinds (`rail_fence`, `route`, `myszkowski`, `quagmire`, `key_tape`) remain as before — `key_tape` is still not in the literal (it never was), and the other four stay in the literal without translators, which is what the non-goal actually meant.

---

## 3. Tests (24 total)

Split by purpose:

**Kind registration (3):**
- `test_grille_in_dispatcher_supported_kinds`
- `test_grille_in_dsl_valid_cipher_kinds`
- `test_grille_in_transform_type_enum`

**Mask validation (8):**
- `test_validate_mask_identity_ok` — `[0, 1, ..., 96]` passes
- `test_validate_mask_reverse_ok` — `[96, ..., 0]` passes
- `test_validate_mask_wrong_length` — length < 97
- `test_validate_mask_duplicates` — non-permutation
- `test_validate_mask_out_of_range_high` — position ≥ 97
- `test_validate_mask_negative_position` — position < 0
- `test_validate_mask_non_int_entries` — string entry rejected
- `test_validate_mask_rejects_bool_entries` — Python quirk: `True == 1` and `False == 0` would silently match, so the validator explicitly rejects `bool`

**Gather semantics (4):**
- `test_apply_grille_identity_returns_input_unchanged`
- `test_apply_grille_reverse`
- `test_apply_grille_matches_apply_perm` — regression guard against divergence from the underlying primitive
- `test_apply_grille_bijection_property_random_masks` — 50 random perms, invert + reapply recovers original

**Translator (5):**
- `test_translate_grille_missing_hole_mask_raises`
- `test_translate_grille_non_list_hole_mask_raises`
- `test_translate_grille_invalid_mask_raises_with_specific_error`
- `test_translate_grille_valid_mask_produces_correct_step_dict` (asserts JSON-serializability)
- `test_translate_grille_tuple_mask_accepted` — tuples normalize to lists

**End-to-end dispatch (4):**
- `test_execute_grille_identity_dispatches_and_kernel_scores`
- `test_execute_grille_sweeps_multiple_masks` — 3-value sweep enumerates all 3
- `test_execute_grille_kernel_overrule_preserved` — crib_score/bean_passed equal `score_candidate(CT)` values
- `test_execute_grille_reversed_mask_produces_noise` — candidate_pt is CT[::-1]

Test file: `kryptosbot/tests/test_r3_0_5_grille_translator.py` (24 tests, ~230 lines).

Brief's minimum was 12. This phase delivers 24 because the mask validation function has many distinct error modes and each deserves its own test (following the "adversarial tests required" rule).

---

## 4. Non-regression verification

| Check | Expected | Actual | Match |
|---|---|---|---|
| Core test suite | 1529 passed | 1529 passed | ✓ |
| Kryptosbot test suite | 680 + 24 = 704 | 704 passed | ✓ |
| Self-test K1 | 15 cycles | 15 cycles | ✓ |
| Self-test K2 | 17 cycles | 17 cycles | ✓ |
| Self-test K3 | 9345 cycles | 9345 cycles | ✓ |
| `grille` in `_SUPPORTED_KINDS` | yes | yes | ✓ |
| `grille` in `_VALID_CIPHER_KINDS` | yes | yes | ✓ |
| `TransformType.GRILLE` exists | yes | yes | ✓ |

---

## 5. Code footprint

```
 kryptosbot/hypothesis_dsl.py                       |   3 +
 kryptosbot/job_dispatcher.py                       |  37 +
 kryptosbot/tests/test_r3_0_5_grille_translator.py  | 249 ++
 src/kryptos/kernel/transforms/compose.py           |  18 +
 src/kryptos/kernel/transforms/grille.py            | 107 +
 5 files changed, ~414 insertions
```

Under the brief's 600-line soft cap (excluding the test file). New kernel module is 107 lines of which ~70 is docstring and `validate_grille_mask` body; the actual grille math is 3 lines. Translator case is 24 lines.

---

## 6. What this phase did NOT change

- No new permutation primitive. `apply_grille_permutation` is a one-line wrapper around `apply_perm`.
- No changes to `apply_perm`, `invert_perm`, or any other transposition utility.
- No kernel scoring changes.
- No theorist prompt changes.
- No critic changes.
- No legacy worker path changes.
- No `HypothesisSpec` schema changes except `CipherKind` Literal gaining one member (required preliminary — see §2.5).
- Still no turning-grille support (deferred per brief §3.1 out-of-scope clause).
- Still no partial-grille support (deferred).

---

## 7. Handoff to R3-0.5-3

`_SUPPORTED_KINDS` now = `{atbash, beaufort, columnar, grille, identity, procedural, variant_beaufort, vigenere}` (8 entries). R3-0.5-3 adds `polybius` to reach 9.

Infrastructure R3-0.5-3 inherits:
- `src/kryptos/kernel/transforms/polybius.py` already has `make_polybius_5x5`, `polybius_encode/decode`, `bifid_encrypt/decrypt`.
- `TransformType.BIFID` already registered and dispatched in compose.py line ~178.
- `polybius` already in `_VALID_CIPHER_KINDS` (no DSL change needed for the polybius kind).

R3-0.5-3 is the thinnest of the three phases: it's mostly wiring the translator over already-present kernel infrastructure.

*End of R3-0.5-2 phase report.*
