# Phase R3-0.5-0 — Pre-flight Report

**Date:** 2026-04-21
**Brief:** `CLAUDE_CODE_BRIEF_round3_0_5_dsl_completion.md`
**Goal of this phase:** capture a clean green baseline for R3-0.5, verify the infrastructure each of the three translators will extend, and record commit HEAD before any implementation begins.

---

## 1. Baseline state

### 1.1 `kryptos doctor`

```
PYTHONPATH=src python3 -m kryptos doctor
```

**All 20 checks PASS.** No FAIL rows.

### 1.2 Core test suite

```
PYTHONPATH=src pytest tests/ -q
```

**1529 passed in 106.75s.** 6 deprecation warnings (all pre-existing palette-retirement notices; unrelated to R3-0.5).

### 1.3 Kryptosbot test suite

```
PYTHONPATH=src pytest kryptosbot/tests/ -q
```

**658 passed in 19.12s.**

### 1.4 Self-test dry-run at R2 exit settings

```
PYTHONPATH=src python3 -u kryptosbot/self_test.py --panel all --mode dry-run --cycles 20000 \
    --report-path results/self_test/r3_0_5_baseline.json
```

| Panel | discovered_via    | cycles_to_discovery | peak_score |
|---|---|---|---|
| k1 | quagmire_iii    | **15**   | 20/20 |
| k2 | quagmire_iii    | **17**   | 20/20 |
| k3 | columnar_double | **9345** | 20/20 |

**Matches R3-1 exit baseline exactly.** K1/15, K2/17, K3/9345.

### 1.5 Git baseline

```
HEAD = 74db2c5 maturation round 3: R3-0.5 brief authored, DSL_CUTOVER_CONTRACT revised for hybrid fallback
```

Untracked files unchanged since R3-1 exit (`docs/maturation/round2/K4_RUN_POSTMORTEM.md`, `f0aac050-...png`, `scripts/_infra/k4_run_postmortem.py`, `tests/test_k4_run_dashboard.py`). `null_baselines/manifest.json` modified-but-unstaged (metadata-only refresh from earlier session; not part of R3-0.5).

### 1.6 Target kinds currently absent from `_SUPPORTED_KINDS`

```
PYTHONPATH=src python3 -c "
from kryptosbot.job_dispatcher import _SUPPORTED_KINDS
print(sorted(_SUPPORTED_KINDS))
"
# => ['atbash', 'beaufort', 'columnar', 'identity', 'variant_beaufort', 'vigenere']
```

Expected 6-kind set. `procedural`, `grille`, `polybius` all absent as the brief anticipated. R3-0.5 will grow this to 9 entries.

### 1.7 `NON_DSL_FAMILIES` constant status

```
grep -n NON_DSL_FAMILIES kryptosbot/critic.py → no match
```

Not yet landed. R3-0.5-1 adds it.

---

## 2. Infrastructure inspection

### 2.1 Procedural recipes (R3-0.5-1 target)

**`docs/procedural_recipes.json` exists** with 17 recipes. `kryptosbot/procedural_enumerator.py::load_recipes()` returns a `list[ProceduralRecipe]` (not a dict, as the brief's pseudo-code assumed). A recipe-ID lookup helper is needed.

`ProceduralRecipe` fields: `recipe_id, title, anomaly_id, physical_only, procedure, dsl_template, known_eliminations, tested_status, priority`.

Breakdown:
- **12 non-physical** recipes (usable): `P-BASELINE-1`, `P-BASELINE-2`, `P-F1-1`, `P-F1-2`, `P-F1-4`, `P-A5-4`, `P-A5-4b`, `P-E0e-1a`, `P-E0e-1b`, `P-KRYPTOS-KW`, `P-SANBORN-VOCAB`, `P-BC-KW`.
- **5 physical_only**: `P-A1-3`, `P-B1-3`, `P-D1-3`, `P-A5-2`, `P-B2-2` — the dispatcher rejects these.

**Critical finding: `dsl_template` is already a full `HypothesisSpec`-shaped dict.** Each non-physical recipe's `dsl_template` contains a `pipeline` list of one or more `CipherLayer`-shaped dicts. Example:

```json
{
  "pipeline": [
    {"kind": "vigenere", "alphabet": "AZ",
     "params": [{"name": "keyword", "values": ["KFGWW", "GFKWW", ...]}]}
  ],
  "assumption_bundle": [...],
  "compute_budget_cpu_minutes": 1,
  "scoring": "composite"
}
```

**Additional finding: `procedural_enumerator.recipe_to_spec(recipe)` already exists at line 162.** It converts a `ProceduralRecipe` to a full `HypothesisSpec`. This makes R3-0.5-1's translator a spec-level expansion, not a layer-level translation:

- Expand procedural layers in `execute()` BEFORE `_enumerate_bindings` runs.
- `_translate_layer("procedural", ...)` becomes a defensive guard (procedural layers should never reach it post-expansion).

**This is a cleaner design than the brief's `realize_recipe_as_pipeline()` sketch** — the brief anticipated a per-binding step-dict returner, but the existing code naturally wants spec-level replacement because each procedural layer has its own parameter enumeration that doesn't compose with the outer spec's `_enumerate_bindings` machinery. The brief allows this choice ("Both paths are acceptable; choose whichever is simpler given the existing code").

### 2.2 Grille infrastructure (R3-0.5-2 target)

```
grep -rn "grille\|Grille" src/kryptos/kernel/
→ no matches
```

**No kernel grille transform exists.** R3-0.5-2 creates `src/kryptos/kernel/transforms/grille.py` from scratch.

Existing adjacent infrastructure in `src/kryptos/kernel/transforms/transposition.py`:
- `columnar_perm(width, col_order, length) -> tuple[int, ...]`
- `TRANSPOSITION_FULL` transform type in `compose.py` line 141 consumes `perm: list[int]` and does `output[i] = input[perm[i]]`.

**Thin-adapter feasibility confirmed.** A grille is just a permutation: given a 97-position mask (each position 0–96 appearing exactly once in the mask's read order), `apply_grille_permutation(ct, mask)` is exactly `ct[mask[0]] + ct[mask[1]] + ... + ct[mask[96]]` — identical shape to `TRANSPOSITION_FULL`'s gather semantics. R3-0.5-2 may be able to dispatch grille through the existing `TRANSPOSITION_FULL` step type with a mask-derived perm, avoiding a new `TransformType.GRILLE` entirely.

Decision for R3-0.5-2: explore whether grille can reuse `TRANSPOSITION_FULL`. If yes, the phase is mostly translator wiring + permutation construction — very thin. If not (e.g., the mask→perm mapping is non-trivial for rotations or partial grilles), create `grille.py` as the brief specifies.

Brief's §3.1 already commits to permutation-only interpretation for R3-0.5. Under that interpretation, reusing `TRANSPOSITION_FULL` is exactly right.

### 2.3 Polybius infrastructure (R3-0.5-3 target)

`src/kryptos/kernel/transforms/polybius.py` (124 lines):
- `make_polybius_5x5(keyword="", merge="IJ")` — builds the 5×5 grid
- `polybius_encode(text, grid) -> list[tuple[int,int]]` — letter→(row,col)
- `polybius_decode(coords, grid) -> str` — (row,col)→letter
- `bifid_encrypt(plaintext, grid, period=0) -> str`
- `bifid_decrypt(ciphertext, grid, period=0) -> str`

`src/kryptos/kernel/transforms/compose.py` at lines 23, 178–186:
- `TransformType.BIFID = "bifid"` already registered
- Dispatcher builds grid, dispatches `bifid_encrypt`/`bifid_decrypt` based on `direction` param

**No straight-polybius `TransformType` exists** — only BIFID. Straight polybius (encode letters to coord-pair string without fractionation) is used in some multi-layer compositions but is not registered.

Decision for R3-0.5-3: the translator exposes **bifid** as the primary polybius mode (the general case; polybius coords alone aren't reinjected as a cipher but as an intermediate). R3-0.5-3's `_translate_layer("polybius", ...)` case produces a `{"type": "bifid", "params": {...}}` step. Straight polybius (without fractionation) is out of scope per brief §4.1.

This matches brief §4.1: "the translator exposes both [polybius and bifid] via the `variant` parameter." Given only bifid is registered in compose.py, R3-0.5-3 will ship bifid-only support, document the limitation, and leave adding straight polybius to a later brief. If the brief's "both variants" requirement is binding, R3-0.5-3 may need to also register `TransformType.POLYBIUS` in compose.py — roughly 10 extra lines. That's thin enough to include.

### 2.4 `stego.py` status

`src/kryptos/kernel/constraints/stego.py` header banner: "RETIRED 2026-04-14" — the palette-enrichment math remains importable but the claim is retired. No grille or Cardano-grille machinery here; the file is about null mask statistics, not physical masks.

---

## 3. Pre-flight expectation vs actual

Per brief §1 expected state:

| Check | Expected | Actual | Match |
|---|---|---|---|
| doctor | 20/0 | 20/0 | ✓ |
| core tests | 1529 passed | 1529 passed | ✓ |
| kryptosbot tests | 658 passed | 658 passed | ✓ |
| self-test K1 | 15 cycles | 15 cycles | ✓ |
| self-test K2 | 17 cycles | 17 cycles | ✓ |
| self-test K3 | 9345 cycles | 9345 cycles | ✓ |
| HEAD | `74db2c5` | `74db2c5` | ✓ |
| `procedural`/`grille`/`polybius` absent | yes | yes | ✓ |

All pre-flight expectations satisfied. **Safe to proceed to R3-0.5-1.**

---

## 4. Design adjustments noted during inspection

Two brief-vs-reality deltas recorded for implementation:

1. **Procedural translator design (R3-0.5-1):** `load_recipes()` returns a list and `recipe_to_spec()` already exists. The translator is spec-level expansion rather than per-layer step-dict production. Brief explicitly allows this choice.

2. **Grille translator design (R3-0.5-2):** Existing `TRANSPOSITION_FULL` transform type already implements gather-perm semantics identical to what permutation-only grille needs. R3-0.5-2 will attempt to dispatch grille through `TRANSPOSITION_FULL` with a derived perm list. If that works, no new `TransformType.GRILLE` is needed — the translator becomes a thin adapter over an existing primitive. Brief anticipated a new kernel file; reality may need only a translator and one test file.

Both deltas reduce scope (translator becomes thinner than the brief assumed). Neither adds scope. Both are within the brief's explicit "choose whichever is simpler given the existing code" / "thin adapter" mandate.

---

## 5. Ready to proceed

Starting R3-0.5-1 (procedural translator) at commit `74db2c5`.

Order of operations:

1. Land `NON_DSL_FAMILIES` in `kryptosbot/critic.py` (per brief §2.3).
2. Implement `_expand_procedural_layers(spec)` in `kryptosbot/job_dispatcher.py`.
3. Modify `execute()` to call expansion after admissibility.
4. Enhance `check_admissibility` to validate recipe_ids proactively.
5. Add defensive guard in `_translate_layer` for procedural (should never be reached post-expansion).
6. Add `procedural` to `_SUPPORTED_KINDS`.
7. Write ≥10 tests covering happy path, unknown recipe, physical-only rejection, no-template recipe, dispatch integration, kernel-overrule invariance, cardinality propagation from template, admissibility rejection path.

*End of R3-0.5-0 pre-flight report. Phase R3-0.5-1 starts now.*
