# K4Bench Curriculum Status

Concise per-challenge status tracker for the K4Bench synthetic
calibration suite. Records which generalized solver capabilities
each bench surfaced and whether the bench remains unsolved by the
current HCC catalogue. NOT a real-K4 progress tracker.

Update rule: only edit when a bench either surfaces a new
generalized lesson, gets solved, or is formally deferred after
exhausting the current capability set.

---

## K4B-009 — Mason diagonal stones

- **Status:** DEFERRED (unsolved after LESSON-016/017/018/019/020/021)
- **Best result:** crib_score 14/24
- **HCC catalogue (final):** 11002 specs dispatched
  (K4B-009.sqlite), 500 attempts retained in latest artifact
  `K4B-009_lesson021_v2_attempt.json`
- **Signal/Promising/Breakthrough:** 0 / 0 / 0
- **Top crib_score=14/24 cluster:** 6 candidates total — 3 from
  `caesar_route_diagonal_columnar` (LESSON-019/020 explicit-axis)
  and 3 from `caesar_route_diagonal_canonical_columnar`
  (LESSON-021 canonical) — all shift=17, MASON columnar keyword,
  width=10 phrase-bound, three layer orders. The two route surfaces
  produce the same permutation here because the canonical
  convention is exactly the (axis="anti", order="forward",
  start_edge="top_then_right", cell_order="forward") combination
  the explicit emitter already enumerates.
- **Lessons surfaced and accepted as generalized capabilities:**
  - LESSON-016 — diagonal grid-route enumeration
  - LESSON-017 — stratified HCC bench-fast family quotas
  - LESSON-018 — numeric clue → Caesar/ROT trigger semantics
  - LESSON-019 — numeric + route + columnar three-layer
    composition
  - LESSON-020 — diagonal cell-order variants (forward / reverse /
    alternate)
  - LESSON-021 — canonical width-only diagonal route alias
- **Lesson progression on K4B-009 max_crib:**
  - pre-LESSON-019: 5/24
  - post-LESSON-019: 14/24 (+9, role-complete composition closed)
  - post-LESSON-020 (cell-order variants): 14/24 (no further gain)
  - post-LESSON-021 (canonical alias): 14/24 (no further gain)
- **Why deferred:** the lesson trajectory on K4B-009 plateaued at
  14/24. Two successive generalized capabilities (LESSON-020
  reverse cell-order, LESSON-021 canonical width-only alias) failed
  to move the score. Continuing to add primitives or cross-products
  solely to chase K4B-009 from 14/24 to 24/24 risks benchmark-
  specific overfitting and is explicitly out-of-scope per the
  closure directive. Defer pending a later benchmark that
  independently motivates additional capabilities.
- **No LESSON-022 from K4B-009.**
- **No K4B-009 solve claimed.**
- **No K4B-009-specific patch was made.**
- **No real-K4 progress claimed.**
- **Next bench in line:** K4B-011.

---

## K4B-010 — Needle group reversal

- **Status:** SOLVED PENDING SEALED EXTERNAL CONFIRMATION
- **Top candidate crib_score:** 24/24 (BREAKTHROUGH band)
- **Top candidate hypothesis_id:** `hcc-k4b-010-reverse_blocks_variant_beaufort-variant_beaufort_reverse_blocks-variant_beaufort=needle-block_size=7-block_mode=reverse_partial-alpha=ka-src=kryptos_alphabet`
- **Top candidate coverage vector:**
  - layer_family: `reverse_blocks_variant_beaufort`
  - layer_order: `["variant_beaufort", "reverse_blocks"]`
  - keyword: `NEEDLE` (variant_beaufort role)
  - alphabet: `KA` (source `kryptos_alphabet`)
  - block_size: 7
  - block_mode: `reverse_partial`
  - operation_source: `phrase_bound_block_size`
  - scheduling_pass: `quota`
  - family_quota: 80
- **Run summary (db/k4bench/K4B-010.sqlite):**
  - theories=8697, experiments=8697
  - status: 1 promising, 1 completed, 8695 eliminated
- **Solved by existing capability surface:** `reverse_blocks` +
  Variant Beaufort + KA alphabet + phrase-bound block_size +
  LESSON-017 stratified scheduler. **No new lesson required.**
- **No K4B-010-specific patch was made.**
- **Sealed evaluator (`tools/evaluate_k4bench_records.py`)
  not run on this VM; sealed answers are off-limits to controller-
  reachable paths. Pending external confirmation.**
- **No real-K4 progress claimed.**

---

## K4B-011 — Observe garden fence

- **Status:** CANDIDATE SOLVED PENDING SEALED EXTERNAL EVALUATOR
  CONFIRMATION
- **Top candidate crib_score:** 24/24 (BREAKTHROUGH band)
- **Top candidate hypothesis_id:**
  `hcc-k4b-011-i3_columnar_vigenere_rail_fence-rail_fence_columnar_vigenere-vigenere=observe-columnar=garden-rail_fence=3-substitution_keyword=observe-columnar_keyword=garden-columnar_width=6-columnar_col_order=(3, 0, 5, 1, 2, 4)-rail_fence_depth=3`
- **Top candidate coverage vector:**
  - layer_family: `i3_columnar_vigenere_rail_fence`
  - layer_order: `[rail_fence, columnar, vigenere]`
  - substitution_keyword: `OBSERVE` (vigenere role)
  - transposition_keyword: `GARDEN` (columnar role; col_order =
    `(3, 0, 5, 1, 2, 4)` from keyword stable rank)
  - rail_fence_depth: `3`
  - role_assignment_mode:
    `independent_two_keyword_rail_fence_three_role`
  - operation_source: `independent_keyword_rail_fence_composition`
- **Run summary (db/k4bench/K4B-011.sqlite + post-LESSON-022 rerun):**
  - theories=10046, experiments=10046
  - status: 1 promising, 10045 eliminated
- **Initial run (pre-LESSON-022) result:** max_crib 5/24, 0
  promising, 0 BREAKTHROUGH. The composition gap was opened by a
  read-only audit confirming the role detectors and independent
  two-keyword assignment were correct, but the three-layer
  combination [sub_clue_kw_a, columnar_clue_kw_b, rail_fence] was
  structurally absent (zero specs even at uncapped emission).
- **Lesson extracted: LESSON-022 — independent two-keyword rail-
  fence three-role composition.**
  - New family generators
    `i3_columnar_<sub>_rail_fence` (3 sub kinds).
  - Trigger: ≥ 2 distinct usable clue keywords (length ≥ 2) AND
    ≥ 1 phrase-bound rail-fence depth.
  - 36 specs emitted on K4B-011; 18 OBSERVE→GARDEN + 18 reverse
    orientation; quota=40 three_layer_sandwich.
  - Of those 36, exactly 1 hit crib=24/24.
- **No new cipher primitive added.**
- **No K4B-011-specific patch was made.**
- **Sealed evaluator (`tools/evaluate_k4bench_records.py`) not
  run on this VM; sealed answers are off-limits to controller-
  reachable paths. Pending external confirmation.**
- **No real-K4 progress claimed.**
- **Next bench in line:** K4B-012.

---

## Other K4Bench challenges

Not yet tracked here; add entries only on lesson-surface, solve, or
formal deferral events.
