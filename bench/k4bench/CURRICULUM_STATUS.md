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

- **Status:** DEFERRED (unsolved after LESSON-016/017/018)
- **Best result:** crib_score 5/24
- **HCC catalogue:** 10010 specs dispatched (K4B-009.sqlite),
  500 attempts retained in attempts artifact
- **Signal/Promising:** 0/0
- **Crib histogram:** 0:3697  1:3835  2:1800  3:555  4:105  5:18
- **Lessons surfaced and accepted as generalized capabilities:**
  - LESSON-016 — diagonal grid-route enumeration
  - LESSON-017 — stratified HCC bench-fast family quotas
  - LESSON-018 — numeric clue → Caesar/ROT trigger semantics
- **Coverage observed in retained sample:**
  - route_diagonal seeds: 112
  - row_reverse seeds: 86
  - numeric Caesar seeds: 6 (shift=17 + complement shift=9 both
    present)
- **Why deferred:** The obvious generalized lessons exposed by
  K4B-009 have been learned and applied. Continuing to add
  primitives or cross-products solely to solve K4B-009 risks
  benchmark-specific overfitting. Defer pending a later benchmark
  that independently motivates additional capabilities.
- **No K4B-009 solve claimed.**
- **No real-K4 progress claimed.**

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

## Other K4Bench challenges

Not yet tracked here; add entries only on lesson-surface, solve, or
formal deferral events.
