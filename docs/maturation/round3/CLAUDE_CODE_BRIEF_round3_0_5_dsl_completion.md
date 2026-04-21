# KryptosBot — Round 3.5 Brief: DSL Completion (pre-R3-2)

**Intent:** close the three highest-priority translator gaps in `kryptosbot.job_dispatcher._SUPPORTED_KINDS` — `procedural`, `grille`, `polybius` — so the R3 cutover's FB-1 fallback policy actually matches the theorist paradigm rather than rejecting it. R3-1's audit documented that only `{identity, vigenere, beaufort, variant_beaufort, columnar, atbash}` have translators today, which covers <5% of historical theorist output. R3-0.5 raises coverage to the point where R3-2's integration test can reach its 80% spec-production floor.

**Target agent:** Claude Code Opus 4.7, same doctrine as Rounds 1-3 (`CLAUDE.md`, `AGENTS.md`, `MEMORY.md`, `docs/README_current_state.md`, `docs/maturation/SUMMARY.md`, `docs/maturation/round2/SUMMARY.md`, plus `docs/maturation/round3/CURRENT_WORKER_PATH.md` and `docs/maturation/round3/DSL_CUTOVER_CONTRACT.md`).

**Author posture:** this round is narrower than a full maturation cycle and larger than a hygiene pass. It implements exactly three translators and exactly one new `NON_DSL_FAMILIES` classification, and hands back to the R3-2 executor with the DSL_CUTOVER_CONTRACT unchanged in shape. If R3-0.5 needs more than the four phases enumerated below, the brief is wrong — stop and escalate rather than extending.

**[POLICY] Scope discipline (inherited verbatim from R3).** This brief does exactly four things: adds three translators in the stated priority order, wires the hybrid fallback policy that R3-1 §3.5 Option γ defines, lets the deferred `key_tape` kind remain untranslated with a clear "not in R3-0.5" error, and runs the self-test + live-controller readiness checks that prove the expanded DSL is consistent. It does not grow `_VALID_CIPHER_KINDS`. It does not change the DSL schema. It does not add new `HypothesisSpec` fields. Any feature creep discovered mid-phase is deferred to a later brief.

---

## 0. Meta

1. Read this entire brief before touching any file.
2. Read `docs/maturation/round3/phase_R3_01_report.md` — it explains why R3-0.5 exists. Read `docs/maturation/round3/DSL_CUTOVER_CONTRACT.md` — the updated hybrid fallback is defined there and R3-0.5 must land consistent with it. If those two documents disagree with this brief's framing, stop and flag it.
3. Same rules as Rounds 1-3: every phase is a reviewable commit, every phase leaves the repo green, every phase produces a report under `docs/maturation/round3/phase_R3_05_NN_report.md` (`NN` = 1..4).
4. All Round 1-3 policies apply verbatim — truth taxonomy, fail-closed boundaries, kernel-overrule, no hardcoded constants, adversarial-first testing.
5. **Falsification targets for this round:**
   - After R3-0.5 completes, `_SUPPORTED_KINDS` MUST include `procedural`, `grille`, `polybius` in addition to the R3-entry six.
   - After R3-0.5 completes, `_SUPPORTED_KINDS` MUST still exclude `key_tape`, `rail_fence`, `route`, `myszkowski`, `quagmire`. An accidental inclusion of any of these is a defect.
   - After R3-0.5 completes, the existing R2-5 self-test (K1 dry-run, K2 dry-run, K3 discovery at `--cycles 20000`) MUST still pass unchanged: K1/15, K2/17, K3/9345. The R2-5 real-API K1 test must still pass. R3-0.5 adds capabilities; it does not regress anything.
   - After R3-0.5 completes, the DSL dispatcher's translation of a minimal `procedural/grille/polybius` spec MUST produce a valid `JobResult` on K4 CT — even if the result's score is noise-level, the dispatcher must not raise `DispatcherError` or leave un-kernel-verified fields.
6. **Non-falsification targets (do NOT spend time on these):**
   - Making any of the three new translators actually solve K4. A translator's correctness means "produces kernel-verified scoring on CT without crashing," not "produces a breakthrough score."
   - Extending translator coverage beyond procedural/grille/polybius. The remaining kinds (rail_fence, route, myszkowski, quagmire, key_tape) wait for a later brief.
   - Refactoring existing translators (vigenere, beaufort, etc.). The R3-1 audit established they work correctly.

---

## 1. Pre-flight

```bash
# 1. Confirm R3-1 baseline intact.
PYTHONPATH=src python3 -m kryptos doctor
PYTHONPATH=src pytest tests/ -q
PYTHONPATH=src pytest kryptosbot/tests/ -q

# 2. Confirm self-test baseline is unchanged from R3-1 exit.
PYTHONPATH=src python3 -u kryptosbot/self_test.py \
    --panel all --mode dry-run --cycles 20000 \
    --report-path results/self_test/r3_05_baseline.json
# Expected: k1/15 k2/17 k3/9345. Any drift blocks R3-0.5-1.

# 3. Git baseline.
git log -1 --format='%h %s'
git status --short

# 4. Confirm the three target kinds are currently absent from _SUPPORTED_KINDS.
PYTHONPATH=src python3 -c "
from kryptosbot.job_dispatcher import _SUPPORTED_KINDS
for k in ('procedural', 'grille', 'polybius'):
    assert k not in _SUPPORTED_KINDS, f'kind {k} already translated; R3-0.5 pre-flight expects absence'
print('pre-flight ok:', sorted(_SUPPORTED_KINDS))
"

# 5. Confirm the hybrid fallback's NON_DSL_FAMILIES constant exists (added
#    at R3-1 commit 70b3495 in DSL_CUTOVER_CONTRACT.md §2; R3-2 wires it
#    into critic.py, but R3-0.5 also references it for test scaffolding).
#    If the constant is not yet in a source module, R3-0.5-1's first
#    action is to land it in kryptosbot/critic.py.
grep -n NON_DSL_FAMILIES kryptosbot/critic.py || echo "NOT YET LANDED — R3-0.5-1 adds it"

# 6. Read the existing infrastructure that R3-0.5 extends.
head -60 kryptosbot/procedural_enumerator.py
head -30 src/kryptos/kernel/transforms/polybius.py
grep -n "polybius\|bifid" src/kryptos/kernel/transforms/compose.py | head -10

# 7. Check whether any grille implementation already exists.
grep -rn "grille_" src/kryptos/kernel/transforms/ 2>/dev/null || echo "no kernel grille transform exists — R3-0.5-2 creates it"
ls docs/cardan_grille.md docs/*grille*.md 2>&1 | head -5

mkdir -p docs/maturation/round3
```

**Expected state:** all tests green, self-test at R2 numbers, current `_SUPPORTED_KINDS` has exactly six entries, procedural_enumerator.py exists, polybius kernel transform exists, no grille kernel transform. Record exactly in `docs/maturation/round3/phase_R3_05_00_preflight.md`.

If any of these deviate from expected state, stop and investigate before starting R3-0.5-1.

---

## 2. Phase R3-0.5-1 — Procedural translator (highest priority)

**Goal:** translate `CipherLayer(kind="procedural", recipe_id="P-XXX")` into a runnable pipeline via the existing `kryptosbot.procedural_enumerator` infrastructure. Also land the `NON_DSL_FAMILIES` constant that the hybrid fallback depends on.

### 2.1 Why procedural is priority 1

The procedural paradigm is a durable project memory (`MEMORY.md: procedural_paradigm_shift.md`) and the theorist prompt (`kryptosbot/controller.py:1474–1491`) actively steers toward procedural output. R3-1 surfaced that without procedural translation, theorists are being told to propose what R3's FB-1 then rejects. Unblocking this is the single highest-value translator addition.

### 2.2 Scope

**In scope:**

- `_translate_layer` case for `kind == "procedural"`.
- Mapping `recipe_id` → `PipelineConfig` via the existing enumerator machinery.
- Validation: missing `recipe_id` is a `DispatcherError` with a clear message.
- Admissibility integration: a procedural recipe that references an unknown or retired recipe_id is admissibility-rejected, not dispatched.
- Fail-closed on recipes the enumerator cannot realize (e.g., physical-only recipes that have no DSL realization — these are already filtered by the enumerator; the translator surfaces the filter rejection as a `DispatcherError`).

**Out of scope:**

- Adding new recipes to `docs/procedural_recipes.json`. R3-0.5 wires what the enumerator already knows.
- Modifying `kryptosbot/procedural_enumerator.py` except to call it from the translator.
- Supporting multi-recipe composition in a single layer. A procedural layer carries exactly one `recipe_id`.

### 2.3 `NON_DSL_FAMILIES` landing

Define as a frozenset in a single module (recommended: `kryptosbot/critic.py` near the top, exported via `__all__`):

```python
# Families that are methodological/investigative rather than cipher-computational.
# Theories in these families bypass the DSL cipher check and route to the
# legacy SDK-worker path via _run_worker_legacy, with worker_role tagged as
# "agent_sdk_non_dsl_category" so downstream analysis can distinguish them
# from DSL-path contracts. Defined by R3-1 §3.5 Option γ.
NON_DSL_FAMILIES: frozenset[str] = frozenset({
    "geometry",
    "k2_coords",
    "geodetic",
    "antipodes",
    "archive_evidence",
    "crib_analysis",
    "k3_continuity",
})
```

Rationale for each inclusion: all seven families describe methodological, investigative, or spatial-reasoning work that does not correspond to a cipher computation. Theorists using these families are doing research that produces evidence (coordinates, photograph annotations, text relationships) rather than decrypt candidates. Forcing them through the DSL is a category error.

R3-0.5-1 lands `NON_DSL_FAMILIES` in `kryptosbot/critic.py` but does NOT yet wire it into the dispatch fan-out — that's R3-2's job. R3-0.5-1 just makes the constant exist so R3-2 can import it.

### 2.4 Translator implementation

Touch points:

- `kryptosbot/job_dispatcher.py::_SUPPORTED_KINDS` — add `"procedural"`.
- `kryptosbot/job_dispatcher.py::_translate_layer` — new case for `kind == "procedural"`.
- `kryptosbot/job_dispatcher.py::_kind_has_translation` — automatic; derives from `_SUPPORTED_KINDS`.

The translator calls into `procedural_enumerator` to resolve `recipe_id` → a realizable `PipelineConfig`. Sketch:

```python
if kind == "procedural":
    recipe_id = layer.recipe_id
    if not recipe_id:
        raise DispatcherError(
            "procedural layer requires recipe_id"
        )
    from .procedural_enumerator import load_recipes, realize_recipe_as_pipeline
    recipes = load_recipes()
    if recipe_id not in recipes:
        raise DispatcherError(
            f"recipe_id {recipe_id!r} not in procedural_recipes.json; "
            f"available: {sorted(recipes)[:10]}{'...' if len(recipes) > 10 else ''}"
        )
    recipe = recipes[recipe_id]
    if recipe.physical_only:
        raise DispatcherError(
            f"recipe {recipe_id} is marked physical_only — no DSL realization"
        )
    return realize_recipe_as_pipeline(recipe, binding)
```

**`realize_recipe_as_pipeline` is new — R3-0.5-1 authors it inside `procedural_enumerator.py`.** It takes a `ProceduralRecipe` and a binding dict, produces a single dict compatible with `PipelineConfig.steps[i]` (i.e., a `{"type": ..., "params": ...}` dict the `build_pipeline` path can consume). If a recipe's realization spans multiple sub-steps, return the first step here and document that Phase 2 would decompose into a multi-layer spec. Defer decomposition to a later brief.

If the existing enumerator already produces a full `HypothesisSpec` per recipe (that's what `enumerate_all_procedural` does), the implementation can instead call that, then extract the single layer's step. Both paths are acceptable; choose whichever is simpler given the existing code. Document the choice.

### 2.5 Fitness test

New test file `kryptosbot/tests/test_r3_05_procedural_translator.py`:

1. `load_recipes()` returns a non-empty dict.
2. For at least 5 recipes that are NOT `physical_only`, the translator produces a valid `{"type", "params"}` dict.
3. Missing `recipe_id` raises `DispatcherError` with expected message.
4. Unknown `recipe_id` raises `DispatcherError` with expected message.
5. Physical-only recipe raises `DispatcherError` with "no DSL realization" message.
6. End-to-end: dispatch a `HypothesisSpec` containing a procedural layer through `execute()`. Result must be a valid `JobResult` — admissibility ok, `total_tested >= 1`, no raised exceptions.
7. Kernel overrule: the `JobResult`'s best_candidate, if any, must round-trip through `_verify_against_kernel` without field mutation (it's the kernel's own scoring).

Minimum 10 tests. Cover both "procedural realizes to single cipher layer" and "procedural realizes to identity" (a recipe that's a pure transposition composed with identity).

### 2.6 Acceptance criteria for R3-0.5-1

- `procedural` is in `_SUPPORTED_KINDS`.
- `_translate_layer("procedural", ...)` returns a valid step dict for at least 5 recipes.
- `NON_DSL_FAMILIES` is exported from `kryptosbot/critic.py`.
- 10+ new tests, all green.
- Full suite green.
- Self-test unchanged: K1/15, K2/17, K3/9345 on `--cycles 20000`.
- `docs/maturation/round3/phase_R3_05_01_report.md` records: (a) which recipes were tested, (b) any recipes skipped with reason, (c) the choice between `realize_recipe_as_pipeline` vs calling `enumerate_all_procedural` and extracting, (d) `NON_DSL_FAMILIES` landing location.

**Stop condition:** if the enumerator's existing recipe catalogue is too sparse (fewer than 5 realizable recipes), halt and escalate — the translator has no useful target. R3-0.5-1 does NOT populate `procedural_recipes.json`; that is a research-content task, not a wiring task.

---

## 3. Phase R3-0.5-2 — Grille translator

**Goal:** implement a Cardano-grille kernel transform and wire its translator. This is the heaviest of the three phases because no kernel implementation exists today.

### 3.1 Scope

**In scope:**

- New file `src/kryptos/kernel/transforms/grille.py` with:
  - `apply_grille(ct: str, mask: frozenset[int]) -> str` — read positions `i` of `ct` where `i in mask`, concatenate in position order, return the extracted plaintext candidate.
  - `validate_mask(mask: frozenset[int], ct_len: int, expected_output_len: int) -> list[str]` — returns validation errors.
- Registration in `src/kryptos/kernel/transforms/compose.py` as a new `TransformType.GRILLE`.
- `_translate_layer` case for `kind == "grille"`.
- Parameters for the grille layer:
  - `hole_mask: list[int]` — the set of 0-indexed positions to extract. Enumeration over a `ParamRange` whose `values` each contain a `list[int]`.
  - Optionally `rotation: int` for rotating turning grilles (defer if complex — see §3.4).

**Out of scope:**

- Turning-grille rotations (the full 4× rotation case where the mask rotates between reads). Support a single-rotation (static) grille in R3-0.5-2. A later brief handles rotation composition.
- Grille construction from anomaly hints (e.g., deriving a mask from sculpture anomalies). R3-0.5-2 assumes the mask is supplied by the spec; discovery of masks is a research task, not a wiring task.
- Variable-length output. R3-0.5-2 assumes `len(mask) == ct_len` (extraction-over-full-CT) OR that the caller specifies `expected_output_len` explicitly. Any mask that violates the length constraint raises `DispatcherError`.

### 3.2 Kernel transform design

The transform is a permutation-like primitive but selection, not rearrangement:

- Input: full CT of length `CT_LEN=97`.
- Output: plaintext candidate of length `len(mask)`.
- Operation: `output[i] = ct[sorted(mask)[i]]`.

For the dispatcher to use `score_candidate` (which expects a 97-char plaintext), either:

1. **Require `len(mask) == 97`** — the grille covers every position, reducing to a permutation. This is the permutation interpretation.
2. **Pad extracted output** — fill non-mask positions with a fixed sentinel that `score_candidate` scores as noise.
3. **Bypass score_candidate entirely** — use a specialized scorer. Out of R3-0.5 scope.

Choose option 1. Masks that don't cover 97 positions either must be rejected or must also declare the permutation of non-mask positions. This keeps the translator clean while leaving partial-extraction grilles to a later brief.

### 3.3 Translator case

```python
if kind == "grille":
    mask_raw = binding.get("hole_mask")
    if not isinstance(mask_raw, (list, tuple)):
        raise DispatcherError(
            f"grille layer requires 'hole_mask' (list[int]); got {type(mask_raw).__name__}"
        )
    mask = frozenset(mask_raw)
    if len(mask) != len(mask_raw):
        raise DispatcherError("grille hole_mask contains duplicates")
    from kryptos.kernel.constants import CT_LEN
    # R3-0.5-2 permutation-only interpretation.
    if len(mask) != CT_LEN:
        raise DispatcherError(
            f"grille hole_mask must cover all {CT_LEN} positions in R3-0.5 "
            f"(got {len(mask)}); partial extraction deferred to a later brief"
        )
    if not all(0 <= i < CT_LEN for i in mask):
        raise DispatcherError(
            f"grille hole_mask contains out-of-range positions (valid: 0..{CT_LEN-1})"
        )
    return {
        "type": "grille",
        "params": {
            "mask_order": list(mask_raw),  # preserves read order
            "direction": "undo",
        },
    }
```

Under the permutation-only interpretation, `mask_raw` itself (as a list) encodes both the selection AND the order. The kernel transform reads ciphertext in mask order and emits the 97-char permuted string.

### 3.4 Compose.py registration

Add to `src/kryptos/kernel/transforms/compose.py`:

```python
class TransformType(str, Enum):
    ...existing...
    GRILLE = "grille"
```

And in the dispatcher switch (around `compose.py:179` next to polybius):

```python
elif t == TransformType.GRILLE:
    from kryptos.kernel.transforms.grille import apply_grille_permutation
    mask_order = p["mask_order"]
    def _grille_step(text: str) -> str:
        return apply_grille_permutation(text, mask_order)
    steps.append(_grille_step)
```

### 3.5 Fitness test

New test file `kryptosbot/tests/test_r3_05_grille_translator.py`:

1. Identity mask `[0, 1, 2, ..., 96]` returns the input unchanged.
2. Reversed mask `[96, 95, ..., 0]` returns the reversed CT.
3. Even-then-odd mask `[0, 2, 4, ..., 96, 1, 3, ..., 95]` returns the expected reordering.
4. Duplicate in mask raises `DispatcherError`.
5. Mask length != 97 raises `DispatcherError`.
6. Out-of-range index raises `DispatcherError`.
7. Missing `hole_mask` raises `DispatcherError`.
8. End-to-end: dispatch a `HypothesisSpec` with grille layer via `execute()`. `JobResult.total_tested == 1` (one mask enumerated). Result kernel-verified.
9. Bijection check: `apply_grille_permutation` is invertible via `apply_grille_permutation(output, inverse_mask_order)` — a property test over 50 random permutations.
10. Kernel score on an identity-grille'd CT equals the kernel score on raw CT.

Minimum 12 tests.

### 3.6 Acceptance criteria for R3-0.5-2

- `grille` is in `_SUPPORTED_KINDS`.
- `src/kryptos/kernel/transforms/grille.py` exists with `apply_grille_permutation` and `validate_mask`.
- `TransformType.GRILLE` registered in `compose.py`.
- `_translate_layer("grille", ...)` produces valid steps for permutation masks.
- 12+ new tests, all green.
- Full suite green.
- Self-test unchanged.
- `docs/maturation/round3/phase_R3_05_02_report.md` records: (a) the permutation-only interpretation decision, (b) which alternative interpretations were considered and deferred, (c) any unit tests that exercised the bijection property on random masks.

**Stop condition:** if the compose.py registration surfaces a tight coupling to transposition semantics that would require refactoring the `TransformType` enum or the pipeline executor, halt and escalate. The translator is a selection primitive, not a transposition — it should slot in alongside existing transforms, not force them.

---

## 4. Phase R3-0.5-3 — Polybius translator

**Goal:** wire the existing kernel polybius transforms into the dispatcher. This is the shortest phase because most of the implementation already exists — the work is in the translator wrapping.

### 4.1 Scope

**In scope:**

- `_translate_layer` case for `kind == "polybius"`.
- Parameters:
  - `square_keyword: str` — determines the 5×5 alphabet ordering.
  - `merge: str` — default `"IJ"` (the standard convention). Also support `"CK"` etc. via the existing `make_polybius_5x5` parameter.
  - `mode: str` — `"encode"` returns a coordinate-pair string (2× length), `"decode"` is the inverse. Default `"decode"` (unwrap coordinate-pair encoded text). Multi-layer hypotheses typically use `encode` on the plaintext path, but in the K4 dispatch context we're decrypting CT → PT so `decode` is primary.
  - `variant: str` — `"polybius"` (straight) or `"bifid"` (fractionation + reassembly) per the existing kernel enum.

**Out of scope:**

- Inventing new polybius variants. The existing kernel supports the canonical Polybius and Bifid; R3-0.5-3 exposes both.
- Polybius-as-single-layer on K4. Per CLAUDE.md §Gotchas: "Bifid 5×5 impossible for K4 because all 26 letters appear in the ciphertext." The translator must still support the kind (for use as a LAYER in multi-layer specs whose input has been reduced to 25 letters by a prior layer), but dispatches with `crib_alignment="direct_positional"` on raw CT will score as noise. Document this in the phase report.

### 4.2 Translator case

```python
if kind == "polybius":
    keyword = binding.get("square_keyword")
    if keyword is None or not isinstance(keyword, str):
        raise DispatcherError(
            "polybius layer requires 'square_keyword' (str; may be empty for A-Z order)"
        )
    merge = binding.get("merge", "IJ")
    if not isinstance(merge, str) or len(merge) != 2:
        raise DispatcherError(
            f"polybius merge {merge!r} must be a 2-char string (default 'IJ')"
        )
    variant = binding.get("variant", "bifid")  # or "polybius" for straight
    if variant not in ("polybius", "bifid"):
        raise DispatcherError(
            f"polybius variant {variant!r} must be 'polybius' or 'bifid'"
        )
    direction = binding.get("direction", "decode")
    if direction not in ("encode", "decode"):
        raise DispatcherError(
            f"polybius direction {direction!r} must be 'encode' or 'decode'"
        )
    return {
        "type": variant,  # 'polybius' or 'bifid' — compose.py already dispatches
        "params": {
            "keyword": keyword,
            "merge": merge,
            "direction": direction,
        },
    }
```

The `compose.py` transform registry already handles `polybius` and `bifid` types at line ~179. The translator just wires `HypothesisSpec` params to that existing step spec.

### 4.3 Fitness test

New test file `kryptosbot/tests/test_r3_05_polybius_translator.py`:

1. Kernel roundtrip: `make_polybius_5x5("KRYPTOS").polybius_encode(...).polybius_decode(...)` recovers the original on a 25-letter input.
2. Translator: basic polybius spec produces `{"type": "polybius", "params": {...}}`.
3. Missing `square_keyword` raises `DispatcherError`.
4. Invalid `merge` (not 2 chars) raises.
5. Invalid `variant` raises.
6. End-to-end: dispatch a bifid spec on K4 CT. Runs without error; `JobResult.total_tested >= 1`; best_score is noise-level (expected per CLAUDE.md §Gotchas — all 26 letters present).
7. Kernel overrule: a polybius-layer `WorkerContract` passes `_verify_against_kernel` without mutation (kernel is the scorer).
8. Edge: empty-keyword polybius produces the plain A-Z ordering (with I/J merged).

Minimum 8 tests.

### 4.4 Acceptance criteria for R3-0.5-3

- `polybius` is in `_SUPPORTED_KINDS`.
- `_translate_layer("polybius", ...)` produces valid steps.
- Both `polybius` and `bifid` variants reachable via the `variant` parameter.
- 8+ new tests, all green.
- Full suite green.
- Self-test unchanged.
- `docs/maturation/round3/phase_R3_05_03_report.md` records: (a) I/J merge convention chosen, (b) relationship to existing `compose.py` polybius dispatch, (c) reminder that single-layer polybius on raw K4 is impossible per the 26-letter gotcha.

**Stop condition:** if the existing kernel polybius interface (`make_polybius_5x5` et al) surfaces an API incompatibility that requires kernel refactoring, halt and escalate. R3-0.5-3 is a wrapper; deep changes belong in a kernel brief.

---

## 5. Phase R3-0.5-4 — Exit handoff to R3-2

**Goal:** verify R3-0.5's additions are internally consistent, update the final documentation, and hand back to the R3-2 executor with a green baseline.

### 5.1 Consistency checks

All four of these must pass before R3-0.5-4 closes:

```bash
# 1. Full test suite green
PYTHONPATH=src pytest tests/ -q
PYTHONPATH=src pytest kryptosbot/tests/ -q

# 2. _SUPPORTED_KINDS has exactly nine entries now:
PYTHONPATH=src python3 -c "
from kryptosbot.job_dispatcher import _SUPPORTED_KINDS
expected = {'identity', 'vigenere', 'beaufort', 'variant_beaufort', 'columnar', 'atbash', 'procedural', 'grille', 'polybius'}
assert _SUPPORTED_KINDS == expected, f'drift: {_SUPPORTED_KINDS ^ expected}'
print('ok:', sorted(_SUPPORTED_KINDS))
"

# 3. Self-test baseline unchanged
PYTHONPATH=src python3 -u kryptosbot/self_test.py --panel all --mode dry-run \
    --cycles 20000 --report-path results/self_test/r3_05_exit.json
# Expected: k1/15 k2/17 k3/9345

# 4. Dispatcher smoke test: one minimal spec for each new kind runs cleanly.
PYTHONPATH=src python3 -c "
from kryptosbot.hypothesis_dsl import HypothesisSpec, CipherLayer, ParamRange
from kryptosbot.job_dispatcher import execute

# procedural — requires a real recipe_id from the catalogue; pick any first non-physical one at runtime
from kryptosbot.procedural_enumerator import load_recipes
recipes = load_recipes()
non_physical = [rid for rid, r in recipes.items() if not getattr(r, 'physical_only', False)]
assert non_physical, 'no non-physical recipes to smoke-test'
spec_proc = HypothesisSpec(
    hypothesis_id='smoke-proc',
    pipeline=[CipherLayer(kind='procedural', recipe_id=non_physical[0])],
    compute_budget_cpu_minutes=1,
)
print('procedural:', execute(spec_proc, parallel=False).admissibility_verdict)

# grille
spec_grille = HypothesisSpec(
    hypothesis_id='smoke-grille',
    pipeline=[CipherLayer(
        kind='grille',
        params=[ParamRange(name='hole_mask', values=[list(range(97))])],
    )],
    compute_budget_cpu_minutes=1,
)
print('grille:', execute(spec_grille, parallel=False).admissibility_verdict)

# polybius
spec_poly = HypothesisSpec(
    hypothesis_id='smoke-poly',
    pipeline=[CipherLayer(
        kind='polybius',
        params=[ParamRange(name='square_keyword', values=['KRYPTOS'])],
    )],
    compute_budget_cpu_minutes=1,
)
print('polybius:', execute(spec_poly, parallel=False).admissibility_verdict)
"
```

All four checks must report green. Any failure blocks R3-0.5 closure.

### 5.2 Updates to `DSL_CUTOVER_CONTRACT.md`

R3-0.5 landing updates the contract's §1.2 (supported cipher kinds). Replace the pre-R3-0.5 six-kind list with the nine-kind list:

```
identity, vigenere, beaufort, variant_beaufort, columnar, atbash,
procedural, grille, polybius
```

And the "currently NOT translatable" list becomes:

```
rail_fence, route, myszkowski, quagmire, key_tape
```

The hybrid fallback logic (§2, §2bis) is unchanged by R3-0.5 — R3-0.5 just broadens the cipher-family side of the FB-1 check.

Also update the three worked examples in DSL_CUTOVER_CONTRACT §1.3 if any of them implicitly assumed pre-R3-0.5 coverage. (Example C should now be revised — a procedural theory is no longer automatically untranslatable; Example C needs a new "genuinely untranslatable" hypothesis, e.g., one using `key_tape` or `rail_fence`.)

### 5.3 MEMORY.md pointer

Add a project memory entry:

```
- [R3-0.5 DSL completion landed](project_r3_05_dsl_completion.md) -- 2026-04-2X: added procedural, grille, polybius translators. _SUPPORTED_KINDS grew from 6 to 9. R3-2 cutover unblocked with ≥80% spec-production floor reachable.
```

Write the companion file `~/.claude/projects/-home-cpatrick-kryptos/memory/project_r3_05_dsl_completion.md` with:

- Summary of what landed (translators added).
- What `NON_DSL_FAMILIES` covers.
- What's still deferred (key_tape explicitly, plus rail_fence/route/myszkowski/quagmire).
- Commit hash of R3-0.5 closure.
- Acceptance criteria satisfied (self-test, smoke test).

### 5.4 SUMMARY document

Write `docs/maturation/round3/phase_R3_05_04_report.md` with:

- Phase-by-phase summary (R3-0.5-1, R3-0.5-2, R3-0.5-3).
- Test counts added.
- Self-test baselines before and after (should be identical).
- Commit hashes.
- "What R3-0.5 proved": the DSL now covers the three biggest missing kinds from the historical theorist distribution.
- "What R3-0.5 did NOT prove": it did not test the new translators on novel K4 hypotheses (noise-floor smoke only). It did not add recipes. It did not change the hybrid fallback policy.
- "Handoff note": R3-2 can proceed against the updated DSL_CUTOVER_CONTRACT with higher confidence that its R3-3 spec-production test will pass.

### 5.5 Acceptance criteria for R3-0.5-4

- All four consistency checks green.
- DSL_CUTOVER_CONTRACT.md updated with new supported kinds and revised Example C.
- MEMORY.md entry added.
- `phase_R3_05_04_report.md` written.
- Final commit message: `maturation round 3.5 complete: procedural, grille, polybius translators (R3-2 unblocked)`.

---

## 6. Non-goals (reiterated for emphasis)

1. **Do not add new recipes to `procedural_recipes.json`.** R3-0.5-1 wires the enumerator, not the research content.
2. **Do not implement turning grilles.** R3-0.5-2 is permutation-interpretation-only; rotation composition waits.
3. **Do not chase solve K4 with the new translators.** The smoke tests verify the pipeline runs; they do not test that the output is meaningful. Noise-floor scores are expected.
4. **Do not grow `_VALID_CIPHER_KINDS`.** Kinds already in the literal type that still lack translators (rail_fence, route, myszkowski, quagmire, key_tape) remain admissibility-rejected after R3-0.5.
5. **Do not touch R3-1's audit documents** (`CURRENT_WORKER_PATH.md`, `phase_R3_00_preflight.md`, `phase_R3_01_report.md`). They remain valid as historical records — their mortality analysis still describes the K4 2026-04-21 state correctly.
6. **Do not extend `_translate_layer` to procedural kinds requiring multi-step decomposition** (e.g., "reverse then Vigenère" as one procedural layer). Multi-step procedural recipes decompose into multiple `CipherLayer` entries in the spec's `pipeline` list; one layer = one step.
7. **Do not change `NON_DSL_FAMILIES` membership.** The seven families listed in §2.3 are the canonical set. Additions need a separate brief.

---

## 7. Rank by importance

1. **R3-0.5-1 (procedural)** — highest research value per MEMORY.md and theorist prompt. Unblocks the largest class of proposals.
2. **R3-0.5-4 (exit handoff)** — without the final consistency checks, downstream (R3-2) can silently inherit a broken baseline.
3. **R3-0.5-3 (polybius)** — cheap wiring, reasonable completeness.
4. **R3-0.5-2 (grille)** — most implementation work. Medium value (grille anomalies are part of the active anomaly surface but not as active as procedural recipes).

Execute in numerical order (R3-0.5-1 → R3-0.5-4). Dependency chain: 4 depends on 1-3 being landed.

---

## 8. Handoff contract

When R3-0.5-4 finishes:

1. All tests green (core + kryptosbot + the ~30 new tests from this round).
2. `_SUPPORTED_KINDS` has exactly the nine expected entries.
3. Self-test K1/15 K2/17 K3/9345 unchanged.
4. Smoke tests for all three new kinds produce admissible `JobResult`s.
5. `DSL_CUTOVER_CONTRACT.md` updated per §5.2.
6. MEMORY.md pointer added.
7. `phase_R3_05_04_report.md` written.
8. **STOP.** R3-2 is operator-commissioned as a separate instruction. Do NOT start R3-2 as part of R3-0.5 completion.

---

## 9. Confidence note

R3-0.5 should land in 1-2 sessions of focused work. Procedural and polybius are mostly wiring — the hard work already exists (`procedural_enumerator.py` and `kryptos.kernel.transforms.polybius` respectively). Grille is the real implementation (new kernel transform), but scoped tightly to permutation-only keeps it bounded.

If R3-0.5-1 grows past 400 lines of changed code (excluding tests), something is wrong — the translator should be a thin dispatch layer over the existing enumerator. If R3-0.5-2 grows past 600 lines (including the new kernel file and compose.py registration), stop and reassess. If R3-0.5-3 grows past 300 lines, stop — the existing kernel implementation is doing the work.

The shape of this round should feel like: one module of translator wiring (procedural), one new kernel primitive plus wiring (grille), one thin wrapper (polybius), all tied together by a final consistency check. That's it.

---

*End of brief. Four phases. Wire three translators. Preserve baselines. Hand back to R3-2.*
