# Real-K4 Pseudo-Clue Pack Fixtures

This directory contains hand-built fixture pseudo-clue packs for the
real-K4 LLM↔HCC bridge audit. Each `*.json` file is one pack.

**These are not solutions.** Each pack is a structured hypothesis
about how the existing public K4 evidence (cribs, registry tiers,
sculpture context) might map to hand-cipher roles. The bridge audit
compiles each pack into a deterministic spec catalog, dispatches the
specs through the kernel, scores against the public cribs, and runs
a null-baseline calibration. No real-K4 progress is claimed unless
the null gate fires (p ≤ 0.001).

## Pack inventory (bootstrap)

- `01_berlin_clock_columnar.json` — BERLIN/CLOCK as substitution +
  columnar role pair (LESSON-010 i3 family).
- `02_berlin_clock_rail_fence.json` — BERLIN/CLOCK + rail-fence
  three-role composition (LESSON-022 family).
- `03_kryptos_palimpsest_substitution.json` — K1/K2 legacy keys as
  substitution candidates (Vig+col).
- `04_northeast_route_diagonal.json` — NORTHEAST as directional
  hint + route_diagonal layer (speculative).

## Adding a new pack

1. Create a new `*.json` file with a unique `pack_id`.
2. Cite EVERY role's source via `source_ids` referencing
   `provenance_items[*].source_id`.
3. Set `evidence_tier` to the WEAKEST tier of any cited
   provenance.
4. Bound the pack: prefer `max_specs <= 500`. The bridge audit's
   global cap (default 2000) limits the merged spec count
   regardless.
5. Validate locally:
   ```python
   from kryptosbot.real_k4_pseudo_clue_pack import load_pack
   p = load_pack("path/to/pack.json"); print(p.validate())
   ```

## Hard contract

- No K4Bench challenge data may enter a pack.
- No sealed-answer text may enter a pack.
- Every role MUST cite at least one provenance item declared in the
  same pack.
- Empty packs (no roles) are rejected by the compiler.
- Packs declare per-pack bounds; the bridge audit enforces a global
  cap on top of those bounds.
- The bridge audit's run-level classification is
  `interpretive_pipeline_test` by default and only promotes to
  `candidate_pending_external_evaluator` if the null baseline gate
  fires (p ≤ 0.001 against the analytical Binomial null over the
  number of candidates dispatched).
