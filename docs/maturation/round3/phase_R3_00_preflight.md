# Phase R3-00 — Pre-flight Report

**Date:** 2026-04-21
**Brief:** Round 3 Maturation — "Wire the Live Controller Through the DSL"
**Goal of this phase:** Establish a clean, fully-green baseline before starting R3-1, with an explicit audit trail of any pre-flight fixes applied.

---

## 1. Baseline state captured

### 1.1 `kryptos doctor`

Command:

```bash
PYTHONPATH=src python3 -m kryptos doctor
```

Result: **All 20 checks passed.** No FAIL rows. (The stale `bean_count` note in CLAUDE.md is out of date — the check now reports `[PASS] bean_ineq_count (n=242)` correctly.)

### 1.2 Core test suite

Command:

```bash
PYTHONPATH=src pytest tests/ -q
```

**Before pre-flight fix:** 1 failed, 1528 passed in 104.50s
**After pre-flight fix:** 0 failed, **1529 passed** in 109.84s (6 deprecation warnings, all pre-existing palette-retirement notices unrelated to R3).

### 1.3 Kryptosbot test suite

Command:

```bash
PYTHONPATH=src pytest kryptosbot/tests/ -q
```

Result: **658 passed** in 8.89s. Unchanged before/after the pre-flight fix.

### 1.4 Self-test dry-run (default `--cycles 500`)

Command:

```bash
PYTHONPATH=src python3 -u kryptosbot/self_test.py \
    --panel all --mode dry-run \
    --report-path results/self_test/r3_baseline_dryrun.json
```

| Panel | discovered | cycles_to_discovery | total_tested | peak_score |
|---|---|---|---|---|
| k1 | True  | 15 | 15 | 20/20 |
| k2 | True  | 17 | 17 | 20/20 |
| k3 | False | —  | 500 (cap hit) | 4/20 |

Matches R2 `r2_baseline_dryrun.json` on k1/k2 exactly. K3 tested count differs slightly (R2=406, R3=500) — K3 strategy space has grown by at least 94 configurations since R2 baseline was recorded, indicating strategies were added to the generator but K3 still is not discoverable at the 500-cycle cap. Peak score is identical (4/20) — no behavioral drift in discrimination.

### 1.5 Self-test dry-run at R2-exit settings (`--cycles 20000`)

Command:

```bash
PYTHONPATH=src python3 -u kryptosbot/self_test.py \
    --panel all --mode dry-run --cycles 20000 \
    --report-path results/self_test/r3_entry_cycles20000.json
```

| Panel | discovered_via | cycles_to_discovery | peak_score |
|---|---|---|---|
| k1 | quagmire_iii      | **15**   | 20/20 |
| k2 | quagmire_iii      | **17**   | 20/20 |
| k3 | columnar_double   | **9345** | 20/20 |

**Exactly reproduces R2 exit state (K1/15, K2/17, K3/9345).** R3 inherits the Round 2 certified fitness surface without drift.

### 1.6 Git baseline

```
0426e8d K4_RUN_PROTOCOL: operator-review amendments before first K4 run   (R2 exit HEAD)
e2fbdcc pre-R3 hygiene: import CT constant in dashboard script per CLAUDE.md   (current HEAD after pre-flight fix)
```

Untracked files carried over from R2 (not touched in pre-flight):

- `docs/maturation/round2/K4_RUN_POSTMORTEM.md`
- `f0aac050-0944-40df-a3bb-16628000f6d6.png`
- `scripts/_infra/k4_run_postmortem.py`
- `tests/test_k4_run_dashboard.py`

Modified but unstaged:

- `null_baselines/manifest.json` — metadata-only refresh (kernel_commit pointer updated to HEAD). No statistical fields changed. Not part of R3; left alone.

---

## 2. Postmortem finding reproduced in code

**Required per brief §1 step 5:** confirm the architectural gap named in `docs/maturation/round2/K4_RUN_POSTMORTEM.md` §6.1.6 is still present in the controller's worker path.

### 2.1 What the postmortem claims

> The controller's worker dispatch path does not route `HypothesisSpec` objects through `job_dispatcher.execute()` — workers run freeform Python in `results/worker_scratch/` and emit `WorkerContract` JSONs.

### 2.2 What the code actually shows

`kryptosbot/controller.py::_run_worker` (lines 1698–1900) confirmed as the worker dispatch path. Key evidence:

| Line | What it shows |
|---|---|
| 24 | `from claude_agent_sdk import ClaudeAgentOptions` — SDK is the dispatch mechanism |
| 70 | `from .sdk_wrapper import safe_query, classify_error` — SDK subprocess wrapper |
| 1707 | `worker_role="agent_sdk"` — hardcoded to SDK path |
| 1718 | `scratch_dir = self._worker_scratch_dir(theory)` — writes to `results/worker_scratch/` |
| 1722 | `prompt = self._build_worker_prompt(theory)` — freeform prompt, not a spec |
| 1803 | `options = ClaudeAgentOptions(**options_kwargs)` — SDK options constructed |
| 1844 | `async for message in safe_query(prompt=prompt, options=options):` — SDK call |

Searching the full controller for `job_dispatcher` / `HypothesisSpec`:

```
1561: OPTIONAL: "dsl_spec" may contain a kryptosbot.hypothesis_dsl.HypothesisSpec
1563: theory. When populated, the dispatcher in kryptosbot.job_dispatcher can
2256: kryptosbot.hypothesis_dsl.HypothesisSpec via submit_hypothesis_spec, then poll_job.
2271: 4. Call submit_hypothesis_spec with the full HypothesisSpec JSON.
```

**All four occurrences are inside theorist/worker prompt string literals — none are Python calls.** The DSL is mentioned in text the theorist reads, but the controller never executes `job_dispatcher.execute()` itself. Postmortem finding confirmed reproducible.

### 2.3 Downstream consumers also observed

Identified for R3-1 audit (the R3-2 rewrite must keep these green):

| Method | Line | Role |
|---|---|---|
| `_dispatch_theories`   | 1638 | Task fan-out, `asyncio.gather` over `_run_worker` |
| `_run_worker`          | 1698 | **Target of cutover** |
| `_build_worker_prompt` | 2219 | Freeform prompt builder (contract update needed for R3-2) |
| `_absorb_outcomes`     | 2353 | Persist `WorkerContract` to ledger |
| `_run_alerts`          | 2518 | Alert gate — needs matched-family null routing (R2-4) |
| `_stat_audit_filter`   | 2615 | Stat-audit sibling call |
| `_run_lead_pursuit`    | 2790 | Day 6 lead-pursuit evaluator |
| `_run_synthesis`       | 2947 | Day 5 synthesis |

`_build_theorist_prompt` is also in scope for R3-2 (theorist must emit valid DSL specs); exact line to be enumerated in R3-1.

---

## 3. Pre-flight fixes applied

### 3.1 Hygiene fix: `scripts/_infra/k4_run_dashboard.py`

**What failed:** `tests/test_constants.py::TestConstantsIntegrity::test_hardcoded_ct_matches_canonical` — the dashboard hardcoded the K4 CT as two concatenated string literals. The test's regex only matched the first (66-char) literal, which does not equal the 97-char canonical `CT`, flagging a mismatch.

**What I changed:** lines 147–153 of `scripts/_infra/k4_run_dashboard.py`:

**Before:**
```python
# ─── K4 reference ───────────────────────────────────────────────────────────

_K4_CT = (
    "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVT"
    "TMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
)
assert len(_K4_CT) == 97
_CRIB_POSITIONS = set(range(21, 34)) | set(range(63, 74))
_SELF_ENCRYPTING_POSITIONS = {31, 73}
```

**After:**
```python
# ─── K4 reference ───────────────────────────────────────────────────────────
# Imported from canonical kernel constants. Per CLAUDE.md "Always import
# constants, never hardcode": CT and crib positions live in one place.

from kryptos.kernel.constants import (
    CT as _K4_CT,
    CRIB_POSITIONS as _CRIB_POSITIONS,
    SELF_ENCRYPTING as _SELF_ENCRYPTING,
)

_SELF_ENCRYPTING_POSITIONS = frozenset(_SELF_ENCRYPTING.keys())
assert len(_K4_CT) == 97
```

**Why CLAUDE.md-mandated:** "Always import constants, never hardcode" (CLAUDE.md §Gotchas). The hardcode was introduced during R2's K4 run work and slipped past commit because the dashboard file was left untracked.

**Side-effect bug fix:** the hardcoded `_SELF_ENCRYPTING_POSITIONS = {31, 73}` was **wrong**. Position 31 has `CT[31]='K'` and `CRIB_DICT[31]='A'` — not self-encrypting. Position 32 has `CT[32]=PT[32]='S'` (the S in EA**S**T) and is one of the two self-encrypting positions, alongside `73` (the K in BERLINCLOC**K**). Canonical `SELF_ENCRYPTING = {32: 'S', 73: 'K'}`.

Imported frozenset now has keys `{32, 73}` as confirmed by the post-fix check:

```
CT ok: True
cribs ok: True
self-enc: {32, 73}
```

Result: the dashboard now highlights position 32 correctly as self-encrypting. This is a latent display correctness improvement in the dashboard's `_K4_CT[pos]` tile-rendering code (lines 787–790).

**Commit:** `e2fbdcc pre-R3 hygiene: import CT constant in dashboard script per CLAUDE.md`

**Scope discipline note:** the dashboard file itself was previously untracked. The hygiene commit is a first-commit-with-the-fix rather than an amendment to an existing tracked file. The 1962-line diff is dominated by the file's initial introduction, not the 10-line hygiene edit; the hygiene-relevant portion is lines 145–157 in the committed file.

### 3.2 Nothing else changed

No other files modified, added, or deleted during pre-flight. `null_baselines/manifest.json` metadata-refresh left unstaged (not part of R3). The four other untracked R2 artifacts (postmortem doc, PNG, postmortem generator script, dashboard test) left unchanged.

---

## 4. Expected-state comparison

Per brief §1 final paragraph:

> **Expected state:** K1/15, K2/17, K3/9345 on dry-run. All tests green. The controller's `_run_worker` uses `safe_query` with `ClaudeAgentOptions`, not `job_dispatcher.execute`.

| Check | Expected | Actual | Match |
|---|---|---|---|
| K1 dry-run cycles | 15 | 15 | ✓ |
| K2 dry-run cycles | 17 | 17 | ✓ |
| K3 dry-run cycles (@ 20000) | 9345 | 9345 | ✓ |
| Core tests green | yes | 1529 passed, 0 failed | ✓ (after hygiene fix) |
| Kryptosbot tests green | yes | 658 passed, 0 failed | ✓ |
| `_run_worker` uses `safe_query` | yes | line 1844 confirmed | ✓ |
| `_run_worker` uses `ClaudeAgentOptions` | yes | line 1803 confirmed | ✓ |
| `_run_worker` bypasses `job_dispatcher.execute` | yes | no Python reference in file | ✓ |

All eight pre-flight expectations satisfied. **Safe to proceed to R3-1.**

---

## 5. What R3 does not inherit

Items flagged for R3-1's audit:

1. **K3 strategy-space drift (§1.4).** The 406 → 500+ candidate-space growth between R2 baseline and R3 baseline is benign (K3 peak_score unchanged, K3/9345 discovery still works) but should be noted if the synthetic-theory integration test in R3-3 depends on exact R2 strategy counts.
2. **`_worker_scratch_dir` convention (line 1718).** R3-2 eliminates writes here on the DSL path. R3-3 must assert scratch dir empty after a DSL cycle.
3. **`worker_role="agent_sdk"` hardcode (line 1707).** R3-2 introduces a second role value (likely `"dsl_dispatch"`) or removes the field's constancy.
4. **Theorist prompt at `_build_theorist_prompt`.** The prompt already mentions DSL specs (lines 1561–1563, etc.), but the current contract treats them as optional — R3-2 makes them required with a fallback policy.

---

## 6. Decisions recorded

- **Pre-flight fix applied silently:** no. Fully documented in §3 with diff and rationale, and committed separately (commit `e2fbdcc`) from R3-1.
- **K3 strategy space drift:** noted, not fixed. Not in R3 scope; the brief's §policy says feature creep is deferred.
- **Other untracked R2 artifacts:** left untracked. Not in R3 scope.
- **R2 exit fitness (K1/15, K2/17, K3/9345):** carried forward as R3's non-regression target, per brief §0.5 falsification targets.

---

## 7. Ready to proceed

Starting R3-1 (audit + cutover contract) at commit `e2fbdcc`. No code changes expected in R3-1 — only two design documents:

- `docs/maturation/round3/CURRENT_WORKER_PATH.md`
- `docs/maturation/round3/DSL_CUTOVER_CONTRACT.md`

*End of R3-00 pre-flight report.*
