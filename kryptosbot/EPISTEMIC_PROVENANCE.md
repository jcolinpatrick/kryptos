# Epistemic Provenance Layer

This document describes the provenance / epistemic-status layer for the
KryptosBot research controller. It is operational doctrine for the live
system — new claims and new consumers MUST conform to it.

## Why this exists

A red-team review of the controller showed that H1-conditional claims,
Bean-reported (but not project-rerun) statistics, physical anomaly
interpretations, and assumption-specific eliminations were all leaking into
outputs without their scope hedges. Hand-written hedges in prose are unsafe:
authors forget them, prompts drift, and "Bean reports p≈1/5520" gets cited
as a fact the theory must explain. The provenance layer makes hedges
**structural** rather than **remembered**.

## What is H1?

H1 is the controller shorthand for three load-bearing assumptions that many
project results implicitly inherit:

1. **Direct positional crib mapping** — PT[i] corresponds 1:1 to CT[i] on
   the carved 97-char text. Any outer rearrangement, mask, or selector
   breaks this.
2. **Canonical 97-char transcription** — the CT is exactly as carved, no
   filtering / deletion / reordering before analysis.
3. **Additive cipher family** — the analyzed step is Vigenère, Beaufort,
   or Variant Beaufort. Bean's constraints are variant-independent only
   *within* this family.

Any result that depends on these assumptions is an **H1_CONDITIONAL_DERIVATION**
and is blocked from hard-constraint use outside an explicit H1 workflow.

## File map

- `provenance.py` — enums + `ScopeConditions` + `ProvenanceClaim` dataclass.
- `claims_registry.py` — `CANONICAL_CLAIMS`, the single source of truth.
- `claim_rendering.py` — `render_claim`, `render_claim_inline`, `render_inventory`.
- `claim_policy.py` — `can_use_as_hard_constraint`, `can_use_as_elimination_basis`,
  `can_use_as_ranking_feature`, `can_use_in_prompt`, `can_promote_to_must_explain`.
- `theory_ledger.py` — `claims` table + CRUD.
- `registries.py` — `bootstrap_claims` called from `bootstrap_all`.
- `critic.py` — routes claim-based contradictions through `claim_policy`.
- `controller.py` — prompts inject anomaly-backed claims via `render_claim_inline`.
- `run_controller.py` — `--inventory` CLI flag.

## The 14 epistemic classes

| Class | One-line definition |
|-------|---------------------|
| `PUBLIC_FACT` | Verified by reputable public reporting or the physical sculpture. |
| `PRIMARY_SOURCE_FACT` | Documented by a primary source (Sanborn, Gillogly, etc.). |
| `PROJECT_CONVENTION` | Operating rule used inside this project (e.g. index convention). |
| `H1_CONDITIONAL_DERIVATION` | True only under H1 (direct positional / canonical / additive). |
| `PROJECT_REVERIFIED_STATISTICAL_ANOMALY` | Statistical pattern independently rerun in project. |
| `BEAN_REPORTED_NOT_RERUN` | External statistic cited from Bean 2021, NOT independently re-derived. |
| `PHYSICAL_FACT` | Physical property of the sculpture (existence only). |
| `INTERPRETIVE_PHYSICAL_OBSERVATION` | A cryptographic interpretation of a physical fact. |
| `CONDITIONAL_ELIMINATION` | An elimination that depends on explicit scope conditions. |
| `STRUCTURAL_ELIMINATION` | An elimination that survives transposition / preprocessing. |
| `INTERNAL_RESULT` | Empirical result from this repo. |
| `RETIRED_CLAIM` | Previously-held hypothesis now on the do-not-revive list. |
| `HYPOTHESIS` | Plausible but untested. |
| `DISPROVED_HYPOTHESIS` | Tested and refuted. |

## How `allowed_downstream_uses` works

Every claim carries a list of `AllowedUse` enum values: `SUMMARY`,
`HARD_CONSTRAINT`, `RANKING_FEATURE`, `NULL_BASELINE`, `ELIMINATION_BASIS`,
`PROMPT_CONTEXT`. The policy gates check BOTH the epistemic_class rule
(some classes can never be hard constraints, regardless) AND the per-claim
whitelist. This is intentional: the class rule is the floor, the per-claim
whitelist is the ceiling.

**Example:** a `H1_CONDITIONAL_DERIVATION` with `ELIMINATION_BASIS` in its
`allowed_downstream_uses` can be an elimination basis *only* when
`h1_context=True` is passed to the policy gate. Without H1 context, it is
blocked regardless of the per-claim whitelist.

## Adding a new claim

1. Pick the right `EpistemicClass`. If the claim is a rerun of a
   Bean-reported statistic, you must actually rerun it to qualify for
   `PROJECT_REVERIFIED_STATISTICAL_ANOMALY`; otherwise it is
   `BEAN_REPORTED_NOT_RERUN`.
2. Fill `ScopeConditions` with explicit `True`/`False` for every field
   where you know the answer. Leaving a field at `None` is "unknown" —
   it does NOT imply `True`.
3. Set `verification_status` honestly. `PROJECT_VERIFIED` means *this
   project* ran the verification, not that the result is "confirmed" in
   the community.
4. Set `allowed_downstream_uses` conservatively. Start with `SUMMARY` +
   `PROMPT_CONTEXT`. Add `RANKING_FEATURE` if it is a soft signal. Add
   `ELIMINATION_BASIS` only if you are prepared for the policy gate to let
   it kill theories.
5. Add a `dependency_chain` listing the `claim_id`s it derives from.
   Derived claims must not outrank their dependencies.
6. Run `pytest kryptosbot/tests/test_provenance.py` — the registry
   integrity test catches enum typos and broken roundtrips.
7. Regenerate the inventory: `python3 kryptosbot/run_controller.py --inventory`.

## Project-rerun vs external-author-reported

A claim is `PROJECT_VERIFIED` only if:

- A script in this repo computes the result from scratch, OR
- A test in `tests/` asserts the result against primary inputs.

If you are citing a number from Bean 2021, Hannon 2010, or any other
external author and have not independently recomputed it, the claim MUST
be `BEAN_REPORTED_NOT_RERUN` (or equivalent), with
`verification_status=EXTERNAL_AUTHOR_REPORTED` and
`depends_on_external_author_statistic=True`. The renderer will
auto-append "Bean-reported, not independently re-derived in project".

## Common pitfalls

- **Do not hardcode hedges in prose.** If you find yourself writing
  "(note: this is H1-conditional)" in a prompt string, you are bypassing
  the renderer. Pass the claim through `render_claim_inline()` instead.
- **Do not bypass policy gates.** Every critic elimination must go through
  `can_use_as_elimination_basis`. Every "must explain" framing must go
  through `can_promote_to_must_explain`.
- **Do not promote `PHYSICAL_FACT` to `HARD_CONSTRAINT`.** Physical
  existence is not a cryptographic constraint. Create a separate
  interpretive claim (e.g. `*_cryptographic_interpretation`) if you need
  to reason about what the physical fact means.
- **Do not treat `BEAN_REPORTED_NOT_RERUN` as a filter.** These claims
  are ranking features only. The policy gate blocks them from elimination
  use.
- **Do not add new hedges to `claim_text`.** Hedges live in the renderer.
  The claim_text should be the neutral factual statement.

## CLI

```bash
# Print the full inventory (auto-hedged, grouped by class)
python3 kryptosbot/run_controller.py --inventory

# Same, against a specific ledger DB (falls back to in-process registry if empty)
python3 kryptosbot/run_controller.py --inventory --db db/theory_ledger.sqlite
```

The inventory output is machine-generated and is the only sanctioned
"what we believe" document. Any hand-maintained ledger that disagrees
with it should be retired.
