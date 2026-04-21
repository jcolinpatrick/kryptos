# Framework Maturation Round 2 — R2-1 through R2-6 Summary

**Period:** 2026-04-21 (single session, 6 phases)
**Brief:** Round 2 maturation brief delivered in session (this document's parent conversation)
**Predecessor:** Round 1 (`docs/maturation/SUMMARY.md`) — 9 phases, complete 2026-04-21
**Status:** **COMPLETE.** Pre-K4 readiness certified subject to operator review of `K4_RUN_PROTOCOL.md`.

This document is the Round 2 handoff. Every phase, every artifact, every test delta, every behavior change.

---

## 1. One-paragraph summary

Round 2 closed the five fitness gaps the Round 1 self-test surfaced: **K3's double columnar**, **KA alphabet in the dispatcher**, **exhaustion-overlap override**, **matched nulls for columnar and extended variant families**, and **real-API K1 self-test**. The most load-bearing result: the framework's full DSL + dispatcher + kernel execution chain was exercised end-to-end via Claude Opus 4.7 against K1 and discovered the correct decryption on the first API call for **$0.0282**. R2-6 concludes with `K4_RUN_PROTOCOL.md` — the operator-facing document that names duration caps, active filters, halt conditions, alert-handling runbook, and post-run analysis. The K4 run itself is the operator's decision; Round 2 delivers the instrument, not the experiment.

---

## 2. Headline numbers

| Metric | Round 1 exit | Round 2 exit | Delta |
|---|---|---|---|
| `tests/` passing | 1525 | 1525 | 0 |
| `kryptosbot/tests/` passing | 570 | **658** | **+88** |
| K1 dry-run discovery cycle | 15 | 15 | unchanged |
| K2 dry-run discovery cycle | 17 | 17 | unchanged |
| K3 dry-run discovery cycle | MISS (peak 4/20 at 406 candidates) | **9,345** (peak 20/20) | **GAP CLOSED** |
| K1 real-API discovery | not attempted | **PASS in 1 call, $0.0282** | ⭐ |
| False-positive BREAKTHROUGHs | 0 | 0 | unchanged |
| Dispatcher alphabets supported (substitution) | AZ | **AZ, KA, keyword_mixed** | +2 |
| Null-baseline distributions | 5 | **11** | +6 |
| New modules under `kryptosbot/` | — | 2 (`panel_cribs`, `token_accountant`) | +2 |
| New runner scripts | — | 2 (`self_test_real_api.py`, `calibrate_null_baselines_r2_4.py`) | +2 |
| Phase-specific maturation commits | 9 (Round 1) | 6 (Round 2) | — |

---

## 3. Phase-by-phase

### R2-00 — Pre-flight baseline verification

- Doctor + full test suites + Phase-7 self-test all matched Round 1 end state.
- Tagged Phase 5 auto-commit `e1afbff` as `maturation-phase-05` (Option A, no history rewrite).
- **Side finding:** K3 panel CT in self_test.py was 281 chars vs canonical 336 — masked by K3 never discovering in Phase 7. Deferred repair to R2-1.
- **Side finding:** K3 double-columnar decomposes as `(width=14, reversed) ∘ (width=42, reversed)` — widths lie outside brief's 4-12 range; R2-1 documented the schedule deviation.
- Artifact: `phase_R2_00_preflight.md`.

### R2-1 — K3 double columnar gap

- Repaired K3 panel CT to canonical 336 chars.
- Replaced `verify_known_answer_contained` K3 stub with actual kernel-sanity via `columnar(w=14, reversed) ∘ columnar(w=42, reversed)`.
- Added `_columnar_double_candidates` strategy with **recipe-pair priority iteration**: motivated × motivated (identity / reversed / reversed-halves) tier-0, swap tiers 1-2, random tiers 3-5. Widths 4-50 on both layers (extended beyond brief's 4-12 with documented rationale).
- K3 discovers at cycle **9,345** (peak 20/20, wall 0.86s). K1 cycle 15, K2 cycle 17 preserved.
- Verified DSL dispatcher (Phase 4 Path A) can execute a two-layer columnar spec under `ct_override(K3)` — kernel-recovered K3 PT exactly.
- +13 tests (4 classes) in `test_r2_1_columnar_double.py`. Updated one obsolete Phase-7 stub test (`test_k3_reports_not_single_call` → `test_k3_kernel_decrypt_matches_known_plaintext`).
- Artifact: `phase_R2_01_report.md`, `results/self_test/r2_1_final.json`, commit `ca3ac72`.

### R2-2 — KA alphabet in dispatcher

- Extended `kryptos.kernel.transforms.vigenere.{encrypt_text, decrypt_text}` with optional `alphabet: Alphabet = None` param. AZ default unchanged (backward-compatible).
- Extended `compose.py`'s VIGENERE/BEAUFORT/VAR_BEAUFORT build to propagate `alphabet_sequence` + `alphabet_label` params.
- New dispatcher helper `_resolve_alphabet_sequence(alphabet, binding)` handles AZ / KA / keyword_mixed.
- `_keyword_to_key_ints` now accepts `alphabet_sequence=None` for non-AZ indexing.
- **Deviation from brief:** R2-2 §3.2 claimed "kernel already supports all three" — actually required the minimal kernel extension above. Documented in phase report §1.
- **Payoff:** K1's Quagmire III decrypts through the DSL as one-layer Vigenère-on-KA with keyword PALIMPSEST. Locked by `test_k1_reduces_to_vigenere_on_ka`.
- +20 tests (5 classes). Updated one Phase-4 KA-rejection test to positive contract.
- Polybius / Quagmire dispatcher translation **remains deferred** per brief §3.2.
- Artifact: `phase_R2_02_report.md`, commit `8ca7551`.

### R2-3 — Exhaustion-overlap override

- `HypothesisSpec.override_exhaustion: bool` + `override_justification: str` fields (default off). Validation: override=True with empty justification is an error.
- `check_admissibility()` demotes exhaustion overlap from rejection to logged warning when override is active.
- `JobResult` gains `override_justification` + `override_exhaustion_overlap` fields — ledger preserves WHY.
- `TheoryRecord.override_justification` persisted via additive SQLite migration.
- `TheoryCritic._check_override_duplicate` — rejects theories whose justification (first 100 chars, Jaccard ≥ 0.7) duplicates a prior tested theory's justification. Prevents laundering.
- Theorist prompt gains `EXHAUSTION-OVERLAP OVERRIDE` section with legitimate-use-case guidance + auto-rejection warning.
- **Phase 8 retrospective:** the 4 previously-rejected procedural specs (PROC-P-A5-4, PROC-P-E0e-1a, PROC-P-E0e-1b, PROC-P-F1-2) now run to completion under the override. None reach SIGNAL (best 3.0/24). No new claims made; mechanism validated.
- +14 tests (3 classes). Artifact: `phase_R2_03_report.md`, commit `3a5ef59`.

### R2-4 — Matched nulls for columnar and extended variant families

- `NullDistribution` gains optional `family: str = ""` field; `cache_key` + filename + manifest entry include family suffix for non-empty families. Legacy Phase 6 empty-family cache unchanged.
- `_sample_one_matched_family` dispatches on family name — additive families decrypt K4 CT with a random keyword; transposition families decrypt with random (width, col_order).
- Brief §5.2 semantic correction: "apply random family member as decryption to K4 CT" (brief was ambiguously worded; R2-4 resolves to the operationally meaningful form).
- Calibrated **6 new distributions** at 50K samples each: `crib_score × {beaufort, variant_beaufort, columnar_single, columnar_double}`, `ngram_score × {columnar_single, columnar_double}`.
- Total wall-clock: 14.1s (well under brief's 5-min budget). Empirical tail floor 1/N = 2 × 10⁻⁵ documented.
- K3 plaintext under the `ngram_score × columnar_double` null: ~40 stdevs above mean — confirms the null is properly distinguishing English from random permutations.
- +18 tests (5 classes). New calibration script `scripts/_infra/calibrate_null_baselines_r2_4.py`.
- Artifact: `phase_R2_04_report.md`, commit `035e8eb`.

### R2-5 — Real-API K1 self-test

**The load-bearing result of Round 2.**

Three infrastructure pieces built:

- **`kryptosbot/panel_cribs.py`** — PanelCribs registry for K1/K2/K3 with 10+10 prefix/suffix pseudo-cribs and Bean equality/inequality derivation. `load_panel_cribs("k4")` raises — no K4 fallback.
- **`kryptosbot/token_accountant.py`** — thread-safe USD ledger, hard ceiling, 50%/80% warnings, per-family pricing table, env-override pricing.
- **ControllerConfig** gains `self_test_mode`, `self_test_max_cycles`, `self_test_max_usd`. Default off.

Runner: **`kryptosbot/self_test_real_api.py`** — a minimal "loop-lite" agent loop. One API call, dispatched via existing DSL, scored via PanelCribs. Explicitly NOT the full persona-controller chain; the phase report documents the scope honestly.

**Live run result:**

```
Panel: K1
Model: claude-opus-4-7
API round-trips: 1
Claude's proposal: family=vigenere, alphabet=KA, keyword=PALIMPSEST
Dispatcher: spec valid, pipeline built, kernel-decrypted
Recovered PT prefix: BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUS
pseudo_crib_score: 20/20
discovered: True
Cost: $0.0282 (0.56% of $5.00 cap)
Wall time: 6.16 seconds
```

**Honest nuance documented:** Claude's reasoning identifies K1 as a known public cipher. Theorist step was **recognition**, not **derivation**. K4 does not have this shortcut. R2-5 validates the **execution chain** (DSL → dispatcher → kernel → scoring), not the theorist's cryptanalytic capacity.

- +23 tests (4 classes). Artifact: `phase_R2_05_report.md`, `results/self_test/r2_5_real_k1.json`, commit `f3d8f23`.

### R2-6 — Pre-K4 readiness review

- `K4_RUN_PROTOCOL.md` authored with 6 required sections: fitness summary, coverage gaps, run protocol, alert handling, halt conditions, post-run analysis.
- This `SUMMARY.md` authored.
- `MEMORY.md` pointer added (pending — single-line index entry).
- **No code changes in R2-6.** The phase is a handoff contract, not an engineering phase.

---

## 4. Test delta summary

| Suite | Round 1 exit | R2-1 | R2-2 | R2-3 | R2-4 | R2-5 | R2-6 |
|---|---|---|---|---|---|---|---|
| `tests/` (core) | 1525 | 1525 | 1525 | 1525 | 1525 | 1525 | 1525 |
| `kryptosbot/tests/` | 570 | 583 | 603 | 617 | 635 | 658 | 658 |
| Total | 2095 | 2108 | 2128 | 2142 | 2160 | 2183 | 2183 |

**+88 kryptosbot tests in Round 2.** Zero regressions across all 6 phases. One Phase-7 K3 stub test updated to positive contract (R2-1). One Phase-4 KA-rejection test updated to positive contract (R2-2). All other test changes are additive.

## 5. Self-test delta summary

| Panel | Round 1 exit | Round 2 exit | Notes |
|---|---|---|---|
| K1 dry-run | discovered cycle 15 | discovered cycle 15 | unchanged |
| K2 dry-run | discovered cycle 17 | discovered cycle 17 | unchanged |
| K3 dry-run | MISS (peak 4/20, tested 406) | **discovered cycle 9345, peak 20/20** | R2-1 closed the gap |
| K1 real-API | not exercised | **discovered 20/20 in one call, $0.0282** | R2-5 new capability |

## 6. Non-goals — affirmed

Per brief §8, Round 2 did **NOT**:

- ✅ Solve K4 (correctly — that's the next experiment, operator-commissioned).
- ✅ Expand retired-claims list (no retirements were added or reversed).
- ✅ Add new procedural recipes (only used the override mechanism to unblock existing ones for R2-3's retrospective test).
- ✅ Rewrite CLAUDE.md / MEMORY.md / AGENTS.md / ORIENT.md (surgical touches only — MEMORY.md pointer in R2-6).
- ✅ Run K2 or K3 real-API (deferred with rationale in R2-5 and K4_RUN_PROTOCOL §2.2).
- ✅ Skip R2-5 and proceed to R2-6 on grounds of expense (R2-5 ran; cost $0.0282).

## 7. Residuals handed to the operator

Three items explicitly named for operator awareness in `K4_RUN_PROTOCOL.md`:

1. **Full controller wiring for panel mode deferred.** R2-5 shipped loop-lite. The full persona + red-team + stat-audit + synthesis chain has not been exercised against a known-answer panel. `K4_RUN_PROTOCOL.md §2.1` and §2.3 document this; first K4 crib≥18 alert exercises the stack.
2. **Theorist recognition vs derivation.** R2-5's K1 success was theorist recognition of a known public cipher. K4 has no known plaintext; the theorist must derive, not recall. Expected K4 performance should be framed accordingly.
3. **K2 / K3 real-API runs remain uncommissioned.** K2 is same family as K1 (trivially succeeds); K3 is kernel-verified via dry-run. Operator can commission at ~$0.10 additional spend if desired.

## 8. Handoff contract

Per brief §10:

1. ✅ All tests green (2183 passing).
2. ✅ `K4_RUN_PROTOCOL.md` exists and is operator-approvable (6 sections, all concrete).
3. ✅ Single commit labeled per the sign-off contract will be produced after this SUMMARY is staged.
4. **STOP.** The K4 run is the operator's commission.

---

## 9. Commit history

```
$ git log --format='%h %s' maturation-phase-05..HEAD | head -20
# Round 1 (Phases 5-9) already present; Round 2 adds:
ca3ac72 maturation round 2 phase R2-1: K3 double columnar gap closed
8ca7551 maturation round 2 phase R2-2: KA + keyword_mixed alphabets in dispatcher
3a5ef59 maturation round 2 phase R2-3: exhaustion-overlap override + critic guard
035e8eb maturation round 2 phase R2-4: matched nulls for columnar + extended variant families
f3d8f23 maturation round 2 phase R2-5: real-API K1 self-test PASSED
<to be filled after R2-6 commit>
```

---

## 10. File inventory

### New files (Round 2)

```
docs/maturation/round2/
  K4_RUN_PROTOCOL.md
  SUMMARY.md
  phase_R2_00_preflight.md
  phase_R2_01_report.md
  phase_R2_02_report.md
  phase_R2_03_report.md
  phase_R2_04_report.md
  phase_R2_05_report.md
kryptosbot/
  panel_cribs.py
  self_test_real_api.py
  token_accountant.py
kryptosbot/tests/
  test_r2_1_columnar_double.py
  test_r2_2_ka_alphabet.py
  test_r2_3_exhaustion_override.py
  test_r2_4_matched_nulls.py
  test_r2_5_self_test_infra.py
scripts/_infra/
  calibrate_null_baselines_r2_4.py
null_baselines/
  manifest.json  (7 new distribution entries)
```

### Modified files (Round 2)

```
kryptosbot/controller.py       (R2-3 override prompt block; R2-5 self_test fields)
kryptosbot/critic.py           (R2-3 _check_override_duplicate)
kryptosbot/hypothesis_dsl.py   (R2-3 override fields + validation)
kryptosbot/job_dispatcher.py   (R2-2 KA path; R2-3 override admissibility)
kryptosbot/models.py           (R2-3 TheoryRecord.override_justification)
kryptosbot/null_baselines.py   (R2-4 family field + new sampling paths)
kryptosbot/self_test.py        (R2-1 K3 repair + double-columnar strategy)
kryptosbot/theory_ledger.py    (R2-3 override_justification column + migration)
kryptosbot/tests/test_job_dispatcher.py        (R2-2 KA positive contract)
kryptosbot/tests/test_self_test.py             (R2-1 K3 positive contract)
src/kryptos/kernel/transforms/compose.py       (R2-2 alphabet_sequence propagation)
src/kryptos/kernel/transforms/vigenere.py      (R2-2 optional alphabet param)
```

---

*Round 2 complete. Pre-K4 readiness certified subject to operator review of K4_RUN_PROTOCOL.md.*
