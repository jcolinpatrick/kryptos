# Phase R2-3 — Exhaustion-overlap override

**Date:** 2026-04-21
**Round:** Maturation Round 2
**Author:** Claude Code Opus 4.7
**Status:** complete — override mechanism live, 4 Phase-8 rejected specs now run, critic guards against laundering

## Summary

| Metric | Before R2-3 | After R2-3 |
|---|---|---|
| `HypothesisSpec.override_exhaustion` | not present | **bool field, default False** |
| `HypothesisSpec.override_justification` | not present | **str field, default empty** |
| `TheoryRecord.override_justification` | not present | **str field, SQLite-backed, additive migration** |
| `JobResult.override_justification` + `.override_exhaustion_overlap` | not present | **recorded when override fired** |
| Phase-8 rejected procedural specs (4) | could not run (admissibility reject) | **all 4 run to completion under override** |
| Critic guard against duplicate justification | not present | **TheoryCritic._check_override_duplicate (Jaccard ≥ 0.7)** |
| Test count (kryptosbot) | 603 | **617** (+14 new R2-3 tests) |
| Test count (core) | 1525 | 1525 (unchanged) |

**K3 discovery status: YES** (§0.5 policy — R2-3 is admissibility / critic-level work, no effect on self-test. Verified: cycle 9345 unchanged.)

## 1. Design (brief §4)

### Fields on `HypothesisSpec`

Two new fields, both default-off:

```python
override_exhaustion: bool = False
override_justification: str = ""
```

Validation rules (in `HypothesisSpec.validate()`):

- `override_exhaustion=True` + empty/whitespace justification → validation error.
- `override_exhaustion=False` + non-empty justification → benign (rationale preserved for audit).
- `override_exhaustion=True` + non-empty justification → valid.

Both fields round-trip through `to_dict` / `from_dict`.

### Dispatcher behavior

In `check_admissibility`, the exhaustion-overlap check is now:

- No overlap → unchanged.
- Overlap + `override_exhaustion=False` → rejected, with an operator-visible hint advertising the override.
- Overlap + `override_exhaustion=True` (+ valid justification, guaranteed by spec validation) → `logger.info` records the overridden entries and the justification; admissibility passes.

### JobResult propagation

When `execute()` runs a spec, the result records:

- `override_justification` — the exact string the spec claimed (empty when no override).
- `override_exhaustion_overlap` — list of exhaustion-log `script_id` values the override defeated (empty when no override or no overlap).

This preserves **why** an override-run took place, so the ledger can later audit the rationale even if the theory's downstream outcome is forgotten.

### Critic guard

`TheoryCritic._check_override_duplicate` (new method in `kryptosbot/critic.py`) — runs only when the theory carries `override_justification`. Returns `(prior_id, prior_justification)` if any `COMPLETED` or `ELIMINATED` prior theory's justification (first 100 chars, tokenized) has Jaccard similarity `≥ SIMILARITY_THRESHOLD = 0.7`. The main `evaluate()` path treats that as `REJECT_DUPLICATE` with 0.9 confidence.

Flow illustrated:

```
Theory proposes override with justification "Phase 8 ..."
  → evaluate() reaches the duplicate section
    → _check_override_duplicate walks ELIMINATED + COMPLETED ledger rows
      → if ≥0.7 Jaccard on first 100 chars → REJECT_DUPLICATE
      → else → proceed to other checks
```

### Ledger schema

`TheoryRecord.override_justification: str = ""` persisted via:

- New column on `theories` table (`override_justification TEXT NOT NULL DEFAULT ''`).
- Additive migration: `ALTER TABLE theories ADD COLUMN override_justification ...` when the column is missing (pattern reused from Day-5 `estimated_compute_minutes` migration).
- Updated `_theory_to_row` / `_row_to_theory`.

Backward-compatible: existing DBs work unchanged; new column defaults to empty string.

### Theorist prompt

The `_build_theorist_prompt` function in `kryptosbot/controller.py` gains a new `EXHAUSTION-OVERLAP OVERRIDE` section that:

- Names the override fields exactly.
- Specifies legitimate use cases (multi-layer compositions where prior elimination was single-layer; different assumption bundle; different scoring path).
- Warns against reusing the override to relaunch dead ideas.
- Documents the critic's automatic Jaccard-duplicate rejection.

## 2. Phase 8 retrospective rerun (brief §4.4)

Executed the 4 previously-rejected procedural specs with:

```python
spec.override_exhaustion = True
spec.override_justification = (
    "Phase 8 rejection was advisory exhaustion-overlap on substring "
    "match; these are multi-layer or procedural compositions, not "
    "covered by single-layer exhaustion entries."
)
```

Result summary (artifact: `results/procedural_sweep/r2_3_retrospective/summary.json`):

| Spec | Admissibility | Configs tested | Best score | Overrode |
|---|---|---|---|---|
| `PROC-P-A5-4` | ok | 5 | 3.0 | 1 entry |
| `PROC-P-E0e-1a` | ok | 2 | 1.0 | 10 entries |
| `PROC-P-E0e-1b` | ok | 2 | 2.0 | 10 entries |
| `PROC-P-F1-2` | ok | 4 | 2.0 | 1 entry |

All 4 run to completion. None produce signal (all best scores < 4 against the 6-char noise floor, well below SIGNAL=18). **No new claims are made from these results** — the point of the retrospective is to confirm the override unblocks legitimate work, not to find K4.

## 3. Test delta

New file: `kryptosbot/tests/test_r2_3_exhaustion_override.py` — 14 tests in 3 classes.

| Class | Tests | Guards |
|---|---|---|
| `TestHypothesisSpecOverrideFields` | 6 | Defaults, validation (override without justification, whitespace-only justification), happy path, benign justification-only case, round-trip |
| `TestAdmissibilityHonorsOverride` | 4 | Rejection when no override; pass-through with override; JobResult carries justification + overlap; JobResult empty when no override |
| `TestCriticOverrideDuplicateGuard` | 4 | No-override skip, distinct justification passes, verbatim collision rejected, full `evaluate()` surfaces REJECT_DUPLICATE |

**Full test counts:**
```
tests/ (core):     1525 passed (unchanged)
kryptosbot/tests/: 617 passed (was 603 after R2-2, +14 new R2-3 tests)
Total:             2142 passed, 6 deprecation warnings (pre-existing), 0 failures
```

## 4. Brief acceptance criteria (§4.5) — self-audit

| Criterion | Status |
|---|---|
| `HypothesisSpec` carries `override_exhaustion` + `override_justification` with validation | ✅ 6 tests |
| Critic rejects override-duplicate justifications via Jaccard | ✅ 4 tests; `_check_override_duplicate` implemented |
| Four Phase-8 rejected specs run to completion | ✅ retrospective summary locked in `results/procedural_sweep/r2_3_retrospective/summary.json` |
| ≥ 5 new tests | ✅ 14 (6 validation + 4 admissibility + 4 critic) |
| Phase report includes retrospective results | ✅ §2 |

## 5. Self-test at phase exit

K1 cycle 15; K2 cycle 17; K3 cycle 9345. No drift. Artifact: `results/self_test/r2_3_final.json`.

## 6. Architectural notes

- **Additive everywhere.** No existing caller changes: spec, ledger, dispatcher, critic all accept the new fields through defaults. This keeps R2-1 + R2-2 uncoupled from R2-3, which is a Round 2 design target (§0.1 — each phase a reviewable commit).
- **Override is not a get-out-of-jail card.** The critic-level Jaccard guard means repeatedly invoking the override with minor wording tweaks gets caught. The 100-char prefix + tokenized Jaccard is deliberately forgiving (0.7 threshold, not 1.0) — small rephrasings are still flagged.
- **Operator ergonomics.** When the dispatcher rejects a spec for overlap, the rejection message now explicitly names the override mechanism. The theorist prompt documents it with guidance. No silent surprise.
