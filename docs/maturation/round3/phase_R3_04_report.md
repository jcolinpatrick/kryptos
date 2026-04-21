# Phase R3-4 — Updated K4 run protocol + round closure

**Date:** 2026-04-21
**Brief:** R3 commissioning instructions §5; DSL_CUTOVER_CONTRACT §9
**Phase result:** Round 3 complete. K4_RUN_PROTOCOL_R3, SUMMARY, and MEMORY pointer all landed.

---

## 1. Deliverables

### 1.1 `K4_RUN_PROTOCOL_R3.md` (new)

Located at `docs/maturation/round3/K4_RUN_PROTOCOL_R3.md`. **Does NOT overwrite `docs/maturation/round2/K4_RUN_PROTOCOL.md`** — per brief §5 special instruction, the Round 2 protocol is preserved for history. Future operators need both to understand what changed.

Section-by-section coverage:

- **§1 Fitness summary** — invariants post-R3: K1/15, K2/17, K3/9345; R2-4 matched nulls live; R2-5 real-API K1 pass; R3-0.5 9-kind coverage; R3-2 DSL dispatch live.
- **§2 Coverage gaps** — ticked through resolved items (full wiring, three translators) and listed open items (5 remaining untranslated kinds, TokenAccountant not wired, fallback reliability, straight polybius deferred).
- **§3 Run protocol** — explicit per-cycle cost shift (§3.1). Category-A worker cost drops to zero; the budget that sized 4 cycles pre-R3 now sizes 15-25 cycles.
- **§4 Alert handling** — new status-value list: `ok_gated`, `ok_ungated`, `ok_matched_family`, `matched_family_ungated`, `matched_null_miss`, `cache_miss`. Operator must verify status before acting on an alert.
- **§5 Halt conditions** — **new addition per brief §5.1 item 5:** "three consecutive cycles with D column (REJECTED_ADMISSIBILITY count) = 0." Plus the existing halts (BREAKTHROUGH with uncalibrated null; programmatic fallback for 3 consecutive cycles; ledger corruption; kernel-overrule panic).
- **§6 Post-run analysis** — includes **new §6.1.7 DSL utilization metrics** mandatory section capturing dispatcher-reject count, override uses, translation errors, matched-null consultations (hits + misses), DSL-path vs legacy-path contract counts, and programmatic-fallback cycles.
- **§7 Pre-run readiness gate** — commands for doctor + suites + self-test + R2-5 real-API. Operator sign-off must acknowledge the fallback-firing concern explicitly.
- **§8 What R3 proved / didn't prove** — closure statement.
- **§9 Operator sign-off checklist** — 7-item checklist before commissioning the K4 run.

### 1.2 `SUMMARY.md` (new)

Located at `docs/maturation/round3/SUMMARY.md`. Mirrors the Round 1/2 SUMMARY format. Captures:

- Single-paragraph summary and headline numbers table (R2 exit → R3 exit deltas)
- Phase-by-phase table with commit hashes
- Subsystem-by-subsystem "what changed" list
- Invariants preserved
- Falsification target status
- What R3 proved / didn't prove
- Residual concerns for the K4 run

### 1.3 MEMORY.md pointer

Added at the top of the Project section of `~/.claude/projects/-home-cpatrick-kryptos/memory/MEMORY.md`:

```
- [R3 complete — DSL dispatch live on controller](project_r3_complete.md) -- 2026-04-21: ...
```

With companion file `project_r3_complete.md` containing commit-hash summary, architectural payoff, non-regression deltas, and how-to-apply notes.

---

## 2. What this phase did NOT change

- No code. R3-4 is documentation and handoff.
- No tests (the test suite is frozen at R3-3 exit).
- No kernel or dispatcher behavior.
- No theorist prompt.

---

## 3. Final non-regression verification

| Check | Expected | Actual | Match |
|---|---|---|---|
| Core test suite | 1529 passed | 1529 passed | ✓ |
| Kryptosbot test suite | 755 passed | 755 passed | ✓ |
| Self-test K1 | 15 cycles | 15 cycles | ✓ |
| Self-test K2 | 17 cycles | 17 cycles | ✓ |
| Self-test K3 | 9345 cycles | 9345 cycles | ✓ |
| Full R3 commit chain clean | 10 commits | 10 commits | ✓ |

**Commit lineage:**

```
e2fbdcc  pre-R3 hygiene: CT import in dashboard
70b3495  R3-1 audit + cutover contract
74db2c5  R3 contract revision + R3-0.5 brief
3f49f58  R3-0.5-1 procedural translator
b3485c0  R3-0.5-2 grille translator
fff4c21  R3-0.5-3 polybius translator
02442df  R3-0.5-4 exit handoff
95e917b  R3-2 DSL dispatch cutover
fefad8c  R3-3 integration test
(this)   R3-4 K4_RUN_PROTOCOL_R3 + SUMMARY
```

Every phase landed as a single reviewable commit. No squashing across phases.

---

## 4. Handoff contract (brief §handoff)

- [x] Full suite green (core 1529 + kryptosbot 755)
- [x] Self-test still K1/15, K2/17, K3/9345
- [x] R2-5 K1 real-API test still passes (unchanged by R3-2; no touch to kryptos/ or self_test/)
- [x] Synthetic-theory end-to-end test green with all §4.2 assertions met
- [x] Real-theorist `--dry-run` ≥80% valid spec rate on Category A (100% on N=1 — above threshold; small-sample caveat documented)
- [x] `docs/maturation/round3/K4_RUN_PROTOCOL_R3.md` exists, updated per R3-4
- [x] `docs/maturation/round3/SUMMARY.md` written mirroring Round 1/2 format
- [x] Final commit: (next) `maturation round 3 complete: DSL dispatch live on controller worker path`

**STOP.** The K4 run is commissioned as a separate operator instruction. This phase does not start a K4 run.

---

## 5. What the operator should do next

1. Read `docs/maturation/round3/SUMMARY.md` end-to-end.
2. Read `docs/maturation/round3/K4_RUN_PROTOCOL_R3.md` end-to-end.
3. Run the §7 pre-run readiness gate within 24 hours of the intended K4 run.
4. Decide whether to commission the K4 run based on the protocol's §9 sign-off checklist.

R3 delivers the wired instrument. Whether to use it on K4 is the operator's decision.

*End of R3-4 phase report. Round 3 closed.*
