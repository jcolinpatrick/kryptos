# Open-Frontier Map + Historical-Feasibility Prior — Design

**Date:** 2026-05-26
**Status:** DESIGN — pending user review, then writing-plans.
**Scope:** Two advisory generation-layer priors for the kryptosbot controller. Both steer the theorist and add a *soft* critic signal; neither hard-gates dispatch.

---

## 1. Motivation

The honest-evaluation finding (this session): the controller is a strong *disproof* instrument but a weak *discovery* one. Its theorist recombines already-tested families (live cycles showed serpentine-route, Myszkowski∘Vigenere-KA, Gronsfeld variants — all family-adjacent, all flagged by red-team as sitting in heavily-swept space). Two specific gaps drive this:

1. **No positive frontier model.** The controller has a *negative* redirect (yield-feedback `escape_candidates`: "avoid dead families") but nothing that says "here is the structurally *unexplored* direction — aim here." The single most valuable unexplored direction is dropping the direct-carving assumption (the `alignment_model` axis), which almost no historical work touched.
2. **No historical-feasibility prior.** Generation is unconstrained by what Sanborn (a non-cryptographer artist) and Scheidt (a CIA cryptographer) could plausibly hand-execute in 1988–90. The `archivist-historian` agent has this knowledge but only as a manual, on-demand capability — it is not a standing prior on generation.

Both are **advisory + soft critic signal** (locked decision): they shape the prompt and contribute a ranking/concern note to the critic, but never reject a theory or auto-dispatch. This matches the project's standing stance: KB-injection is prompt-context-only, novelty authority stays with the critic's mechanism-signature, lead pursuit stays passive, and the posture is "pursue any non-zero-probability path."

## 2. Goals / Non-goals

**Goals**
- Make the unexplored `family × alignment_model` cells visible to the theorist as a positive target.
- Make a source-cited 1988–90 hand-execution feasibility prior available to the theorist and critic.
- Surface the frontier map to the human operator via `session_briefing.py`.
- Zero change to dispatch admissibility, kernel scoring, or the matched-null gate.

**Non-goals**
- No hard critic gate; no auto-dispatch; no change to `job_dispatcher` admissibility.
- No new cipher kinds or kernel transforms.
- Not a claim that any open cell or feasible mechanism is *more likely to be K4* — only that it is *less explored* / *more historically plausible*. These are search-prioritization signals, not truth claims.

## 3. Shared architecture

One pattern, applied twice (mirrors the yield-feedback loop):

```
structured prior artifact ──render──▶ new optional block in _build_theorist_prompt   (steer generation)
                          ──signal──▶ soft annotation on the critic's per-theory note  (rank/concern, never reject)
```

Both new blocks join the existing conditional-join composition in `controller.py::_build_theorist_prompt` (~L3950), alongside `family_yield_block` / `escape_candidates_block`. Both are attached to the `landscape` dict in the landscape-assembly path (~L2296) the same way `escape_candidates` is.

## 4. Component A — Open-Frontier Map

### 4.1 Cells

The grid is **cipher-family × alignment_model**:
- **Rows (families):** the canonical family universe from `kryptosbot.registries.KNOWN_FAMILIES` unioned with historical ledger families via `kryptosbot.kb_family_map.valid_ledger_family_universe()`.
- **Columns (alignment models):** the 6 keys `direct_ct_pt`, `fixed_len_97`, `ct73_null_extracted`, `arbitrary_null_mask`, `non_direct_alignment`, `joint_mask_mechanism`. These move to a single canonical source `src/kryptos/alignment_models.py` (see §6); `frontier_map.py` imports them there rather than duplicating.

### 4.2 Status taxonomy

| status | meaning | derivation |
|---|---|---|
| `eliminated` | a clean disproof covers this cell | exhaustion_log entry with exhausted status + claims-registry retired/disputed claim tagged with this alignment_model |
| `explored_deep` | substantial tested configs, best score in noise | ledger contracts in this family with N_tested above a threshold and max crib_score < SIGNAL |
| `explored_shallow` | touched but thin | ledger contracts present but below the deep threshold |
| `open` | no evidence yet | no exhaustion/ledger/claims evidence maps to this cell |

**The asymmetry is the deliverable:** because nearly all historical work assumed `direct_ct_pt` + `fixed_len_97`, the four non-direct alignment columns will be overwhelmingly `open`. The map renders those open cells as the priority frontier.

### 4.3 Population — hybrid (approved approach A)

- **Curated grid skeleton:** the row×column cell set is materialized from the two authoritative taxonomies above (not hand-listed — generated from the imports, so it can't drift from the registries).
- **Evidence-computed status:** each cell's status is computed at build time from `exhaustion_log.json`, the theory ledger, `docs/claims_registry.json` (`alignment_model` tags), and `docs/elimination_tiers.md`. Cells with no mapped evidence default to `open`.
- **Family→cell mapping:** reuse `kb_family_map` normalization for family resolution. Alignment resolution: ledger/claims entries that carry an `alignment_model` tag map directly; untagged historical work is treated as `direct_ct_pt` + `fixed_len_97` (its implicit assumption), which is the honest default and keeps non-direct cells `open`.

### 4.4 Module

`kryptosbot/frontier_map.py`:
- `@dataclass FrontierCell{ family: str; alignment_model: str; status: str; n_tested: int; best_crib: int; evidence_refs: tuple[str,...] }`
- `@dataclass FrontierMap{ cells: tuple[FrontierCell,...]; built_at: str; sources: dict }`
- `build_frontier_map(*, project_root, ledger_db_path) -> FrontierMap` — deterministic given inputs.
- `open_cells(map) -> list[FrontierCell]` — status==open, sorted (non-direct alignment columns first).
- `render_open_frontier(map, *, limit) -> str` — the theorist prompt block: top open cells with a one-line "reachable because…" hint (e.g. "arbitrary_null_mask × vigenere: null-mask kernel exists but unsearched").
- `frontier_cell_for_theory(theory) -> FrontierCell | None` — classify a proposed theory into its cell (family from theory.family, alignment from dsl_spec shape / theory metadata; default direct_ct_pt+fixed_len_97).

### 4.5 Critic soft signal

In the critic's per-theory assessment, annotate the resolved cell status: an `open`-cell theory gets a positive note ("targets unexplored frontier cell X"); an `explored_deep` / `eliminated`-cell theory gets a concern note ("cell X already explored_deep / eliminated"). Advisory only — never changes the verdict to reject.

### 4.6 Human surface

`session_briefing.py` gains an OPEN FRONTIER section rendering `open_cells` (it already imports the alignment taxonomy and scans exhaustion/results). Read-only.

## 5. Component B — Historical-Feasibility Prior

### 5.1 Data model

`kryptosbot/data/historical_feasibility.json` — a committed, source-cited table:

```json
{
  "context": "Hand-execution feasibility for Sanborn (artist, non-cryptographer) + Scheidt (CIA cryptographer), 1988-1990 design window.",
  "schema_version": "historical_feasibility.v1",
  "mechanisms": [
    {
      "mechanism_class": "vigenere",
      "tier": "plausible",
      "rationale": "Standard tableau cipher; Scheidt's documented toolkit; used in K1-K3.",
      "primary_source": "reference/FM24-18(87).pdf; Scheidt dossier"
    }
  ]
}
```

- `tier ∈ {plausible, marginal, implausible}` for 1988–90 hand execution.
- Every entry requires `rationale` + `primary_source` (auditable, not vibes).
- Covers the cipher-family universe (one entry per mechanism_class; classes map to families via `kb_family_map`).

### 5.2 Source + verification (approved flow)

1. I draft the table from `reference/` primary sources — chiefly the 1987 **FM 24-18** (the era's actual hand-cipher field manual), plus NSA cryptanalytics (1977), Kubark, Bean 2021, the Scheidt dossier, and the Sanborn handwriting/notes profiles.
2. Dispatch the **archivist-historian** agent to verify/correct each tier against primary sources and flag any unsupported assignment.
3. Commit only after the historian pass; record the verification in the artifact (`verified_by`, `verified_at`).

### 5.3 Module

`kryptosbot/historical_feasibility.py`:
- `load_feasibility() -> FeasibilityTable` (schema-validated; fail-closed on malformed → empty table + WARNING, so generation degrades to unconstrained, never crashes).
- `render_feasibility_prior() -> str` — prompt block: "prefer mechanisms hand-executable in 1988–90; `implausible`-tier mechanisms are low-prior unless strongly motivated."
- `feasibility_tier_for_theory(theory) -> str` — resolve a theory's mechanism class to its tier.

### 5.4 Critic soft signal

`implausible`-tier theories get a downrank/concern note ("historically implausible for 1988-90 hand execution: <rationale>"). Never a reject — a Gronsfeld-in-1989 theory is discouraged, not forbidden (preserves "pursue any non-zero path").

## 6. Integration points (exact)

- **`src/kryptos/alignment_models.py`** (new): the canonical `ALIGNMENT_MODELS` 6-tuple, single source of truth, importable by both `scripts/` and `kryptosbot/` via `PYTHONPATH=src`. A regression test asserts the keys are exactly the 6 listed.
- **`scripts/_infra/session_briefing.py`**: import `ALIGNMENT_MODELS` from the new canonical module (replacing its local definition; behavior unchanged); add the OPEN FRONTIER render section.
- **`controller.py::_build_theorist_prompt`** (~L3500 body, ~L3950 join): two new optional blocks (`frontier_block`, `feasibility_block`) using the existing conditional-join idiom.
- **`controller.py` landscape assembly** (~L2296): attach `frontier_map` + `feasibility` to the landscape dict.
- **`critic.py`**: add the two advisory annotations on the per-theory assessment; assert they cannot flip a verdict to reject (tested invariant).
- **Both cycle loops** (`controller.run` + `run_controller.do_run`): per the dup-loop trap, any prompt/landscape touch patches BOTH; equivalence pinned by the existing cycle-loop characterization test.

## 7. Testing (TDD)

**Frontier map**
- Grid completeness: every (family ∈ universe) × (6 alignment models) cell exists exactly once.
- Status derivation from synthetic exhaustion/ledger/claims fixtures (eliminated / deep / shallow / open).
- Open-asymmetry invariant: with only `direct_ct_pt`+`fixed_len_97` evidence, all four non-direct columns are `open`.
- `render_open_frontier` determinism + cap; `frontier_cell_for_theory` classification.

**Historical feasibility**
- Schema/loader; every entry has tier+rationale+primary_source; fail-closed on malformed.
- `feasibility_tier_for_theory` tiering; render determinism.

**Critic invariants**
- Both annotations are advisory: a theory that would otherwise be APPROVED is never flipped to a reject verdict by either signal (parametrized over open/explored/eliminated and plausible/marginal/implausible).

**Regression**
- K1/K2/K3 self-test unchanged (K1/15, K2/17, K3/9345).
- Theorist prompt still parses with both blocks present; both cycle loops equivalent.

## 8. Scope / sequencing

One design doc, two components, two sequential implementation plans:
1. **Frontier map** first — pure computation, no external dependency.
2. **Historical-feasibility prior** second — gated on the archivist-historian verification step.

Both advisory-only, so neither can break dispatch. Each plan: TDD, kryptosbot + core suites green, self-test unchanged.

## 9. Risks / caveats

- **Frontier staleness:** the map is recomputed each build from live sources, so it tracks the ledger. The curated *grid skeleton* is generated from registries (can't drift); only the status derivation depends on evidence quality.
- **Alignment-dimension sparsity:** most historical work is untagged and defaulted to direct-carving. This is intentional (keeps non-direct cells open) but means `explored_deep` on non-direct cells will only appear once alignment-tagged work accumulates. Acceptable: the map is meant to *open* those directions.
- **Historical-prior subjectivity:** mitigated by mandatory per-entry primary-source citations + the archivist-historian verification pass. Tiers are search priors, not truth claims (§2 non-goal).
- **Advisory-only by design:** these cannot force exploration of an open cell or block a dead one. That is deliberate — they bias generation without entrenching the ledger's blind spots or overriding the critic.
