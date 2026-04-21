# Phase R3-0.5-1 — Procedural translator

**Date:** 2026-04-21
**Brief:** `CLAUDE_CODE_BRIEF_round3_0_5_dsl_completion.md` §2
**Phase result:** Complete. 22 new tests, all green. Self-test unchanged.

---

## 1. What landed

### 1.1 `NON_DSL_FAMILIES` constant

`kryptosbot/critic.py` now exports:

```python
NON_DSL_FAMILIES: frozenset[str] = frozenset({
    "geometry", "k2_coords", "geodetic", "antipodes",
    "archive_evidence", "crib_analysis", "k3_continuity",
})
```

Placed alongside `TIER_1_FAMILIES` and `TIER_2_FAMILIES` with a docstring pointing at R3-1 Option γ and R3-2 as the consumer. A regression test asserts the set is disjoint from both elimination tiers so R3-2 classification is unambiguous.

### 1.2 `_SUPPORTED_KINDS` grew to 7

Added `"procedural"` to the frozenset. The expansion comment at the definition explains that procedural layers are resolved before `_translate_layer` sees them.

### 1.3 `_load_recipes_by_id` helper

Thin wrapper returning `{recipe_id: ProceduralRecipe}` so the dispatcher can O(1)-look up recipes. Accepts an optional custom catalogue `path` for fixture-driven tests.

### 1.4 `_expand_procedural_layers(spec)` — the core change

Replaces every `kind="procedural"` layer with its recipe template's `pipeline` layers via `procedural_enumerator.recipe_to_spec(recipe)`. Identity short-circuits for specs without procedural layers (returns the same object, preserving identity semantics). Raises `DispatcherError` on:

- missing / empty `recipe_id`
- unknown `recipe_id` (with a list of available ids in the message so callers can self-correct)
- `physical_only` recipes
- malformed `dsl_template` (`recipe_to_spec` returns `None`)

All top-level spec fields (hypothesis_id, scoring, null_baseline, compute budgets, assumption_bundle, override fields) are preserved on the expanded spec; only the `pipeline` is rewritten.

### 1.5 `execute()` wiring

Expansion runs **before** admissibility. Rationale: the expanded pipeline's cardinality reflects the real parameter universe. A procedural layer with an empty outer `params` list has cardinality 1 by itself, but its template (e.g., P-F1-1 with 5 keyword values) contributes 5 configs; the admissibility budget check must see the real number.

If expansion raises, the error becomes an admissibility rejection with the `DispatcherError` message preserved in `admissibility_reasons`. No exception escapes `execute()`.

### 1.6 Defensive guard in `_translate_layer`

A procedural layer that reaches `_translate_layer` is a bug — expansion was skipped. The guard raises with a clear pointer at the bug rather than silently limping. This is the brief's "fail-closed at every new boundary" rule made concrete.

---

## 2. Design decision: spec-level expansion instead of layer-level translation

The brief sketch in §2.4 assumed a per-layer `_translate_layer("procedural", binding)` returning a single step dict:

```python
return realize_recipe_as_pipeline(recipe, binding)
```

R3-0.5-1's implementation is instead spec-level: `_expand_procedural_layers(spec)` rewrites the pipeline as a whole, upstream of enumeration.

Reason: each procedural recipe's `dsl_template` declares its own `ParamRange` values (e.g., P-F1-1 enumerates 5 keyword candidates). `_translate_layer` is called once per `(layer, binding)` pair and receives one value per param. For a per-layer approach to work, the outer spec's `_enumerate_bindings` would need to know the inner template's params — which means expanding the procedural layer anyway, just later and with more plumbing.

Spec-level expansion collapses both steps: expand once, then the standard enumeration / translation path applies uniformly. The brief's flexibility clause ("choose whichever is simpler given the existing code") allows this.

Consequence: the `_translate_layer("procedural", ...)` case is a defensive guard, not a translation case. This is explicitly documented at the guard itself and in the pre-flight report.

---

## 3. Tests (22 total)

Split by purpose:

**NON_DSL_FAMILIES (2):**
- `test_non_dsl_families_constant_present_and_frozen` — exact membership check
- `test_non_dsl_families_does_not_overlap_with_tier1_or_tier2` — classification disjointness

**_SUPPORTED_KINDS (1):**
- `test_procedural_in_supported_kinds`

**Recipe lookup (2):**
- `test_load_recipes_by_id_returns_dict_keyed_by_recipe_id`
- `test_load_recipes_by_id_custom_path` — fixture path override, verifies caller test hook

**Expansion happy path (6):**
- `test_expansion_identity_shortcircuit_returns_same_spec` — identity semantics
- `test_expansion_single_layer_baseline_identity` — P-BASELINE-1 → identity
- `test_expansion_single_layer_with_params` — P-F1-1 cardinality 1 → 5 post-expansion
- `test_expansion_preserves_non_procedural_layers_in_order` — mixed pipeline
- `test_expansion_preserves_toplevel_fields` — scoring, null_baseline, budgets, overrides
- `test_expansion_produces_valid_spec_that_passes_kernel_roundtrip` — spec.validate() clean

**Expansion adversarial (6):**
- `test_expansion_missing_recipe_id_raises` — `recipe_id=None`
- `test_expansion_empty_recipe_id_raises` — `recipe_id=""`
- `test_expansion_unknown_recipe_id_raises_with_suggestion` — asserts "available:" list in error message
- `test_expansion_physical_only_recipe_raises` — picks any physical recipe from the live catalogue
- `test_expansion_recipe_id_strict_no_whitespace_normalization` — `"P-F1-1 "` with trailing space rejected (no silent normalization)
- `test_expansion_with_injected_malformed_recipe_raises` — fake recipe fixture with `dsl_template=None`

**Defensive guard (1):**
- `test_translate_layer_procedural_raises_defensive_error`

**End-to-end (4):**
- `test_execute_procedural_baseline_runs_kernel_scoring` — P-BASELINE-1 dispatches, kernel fields populated
- `test_execute_procedural_with_param_sweep_enumerates_all_configs` — P-F1-1 tests exactly 5 configs
- `test_execute_procedural_bad_recipe_id_surfaces_in_admissibility_reasons` — error propagation into admissibility verdict
- `test_execute_kernel_overrule_preserved_on_procedural_path` — crib_score and bean_passed equal `score_candidate(CT)` values when identity template dispatches on CT

Test file: `kryptosbot/tests/test_r3_0_5_procedural_translator.py` (22 tests, ~300 lines).

---

## 4. Non-regression verification

| Check | Expected | Actual | Match |
|---|---|---|---|
| Core test suite | 1529 passed | 1529 passed | ✓ |
| Kryptosbot test suite | 658 + 22 = 680 | 680 passed | ✓ |
| Self-test K1 | 15 cycles | 15 cycles | ✓ |
| Self-test K2 | 17 cycles | 17 cycles | ✓ |
| Self-test K3 | 9345 cycles | 9345 cycles | ✓ |
| Procedural in `_SUPPORTED_KINDS` | yes | yes | ✓ |
| `NON_DSL_FAMILIES` exists | yes | yes | ✓ |

---

## 5. Code footprint

```
 kryptosbot/critic.py                                |  15 +
 kryptosbot/job_dispatcher.py                        | 128 ++++++
 kryptosbot/tests/test_r3_0_5_procedural_translator.py | 305 ++
 3 files changed, ~450 insertions
```

Well under the brief's 400-line soft cap for R3-0.5-1 (excluding the test file, which is always additive). The translator itself is 128 lines in `job_dispatcher.py` — mostly the docstring + error messages — and 15 lines in `critic.py` for the constant + docstring.

---

## 6. What this phase did NOT change

- No kernel code.
- No theorist prompt changes (brief §6 non-goal).
- No legacy worker path changes.
- No modification of `kryptos/` core.
- No change to `_translate_layer` cases for the other 6 kinds.
- No new `HypothesisSpec` fields.
- No changes to `procedural_enumerator.py` itself (the enumerator's own catalogue, `recipe_to_spec`, etc. were used as-is).

---

## 7. Handoff to R3-0.5-2

`_SUPPORTED_KINDS` now = `{atbash, beaufort, columnar, identity, procedural, variant_beaufort, vigenere}` (7 entries). R3-0.5-2 adds `grille` to reach 8.

Infrastructure for R3-0.5-2 to inspect at its pre-flight:
- `src/kryptos/kernel/transforms/transposition.py::columnar_perm` — gather-perm semantics
- `src/kryptos/kernel/transforms/compose.py` line 141: `TRANSPOSITION_FULL` transform type
- R3-0.5-0 pre-flight §2.2 noted that permutation-only grille may reuse `TRANSPOSITION_FULL` without needing a new `TransformType.GRILLE`

*End of R3-0.5-1 phase report.*
