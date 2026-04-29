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

## Other K4Bench challenges

Not yet tracked here; add entries only on lesson-surface, solve, or
formal deferral events.
