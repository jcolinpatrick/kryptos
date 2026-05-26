# Real-K4 Bounded Instrument Campaign — Postmortem

**Date:** 2026-05-26
**Preregistration:** `docs/campaigns/real_k4_bounded_campaign_2026_05_26_prereg.md` (§4/§6 locked pre-launch; red-teamed; blocker fixed).
**Run protocol:** `docs/maturation/round3/K4_RUN_PROTOCOL_R3.md`.
**Code at launch:** `cf4ec36` (matched-null transposition families landed; null manifest fresh-pinned to `cf4ec36` at launch).
**Cycles:** 568–582 (15 cycles), `--theories 5`, `--db db/theory_ledger.sqlite`, `--verify-transport`, foreground-tracked.
**Wall window:** 2026-05-26 ~21:30–23:28 UTC (~2h).
**Headline result:** **0 non-artifact graded signal. Clean null. No K4 claim. Instrument integrity confirmed.**

---

## 1. PRIMARY outcome (prereg §4)

**Non-artifact graded signal: 0.**

- All 15 cycles: `0 signal` in the per-cycle OUTCOME line; `STAT-AUDIT skipped — no contracts >= 18` every cycle.
- Max kernel-verified crib_score across the run: **4 / 24** (best disproved at crib 4). Lower than the prior A/B campaigns' max of 8.
- 13–23 crib tail: **empty** (nothing above 4).
- `24 review`: 0 this run. The three `crib_score 24` rows visible in the monitor were pre-existing landscape artifacts (468h/476h/624h old), all `ELIMINATED` via kernel-overrule (algebraic-identity "structurally-guaranteed BREAKTHROUGH" cases: `XXXX…EASTNORTHEAST…BERLINCLOCK…XXXX`), not this run's products.

The §4 locked definition was never approached, so the strict `ok_matched_family` requirement was not exercised on a real candidate (see §5 and §7).

## 2. Per-run census (ledger, created_at ≥ 21:28 UTC)

| metric | value |
|---|---|
| theories proposed (run) | 71 (cumulative ledger 2284 → 2355) |
| max best_score (crib) | 4.0 |
| status: criticized | 38 |
| status: eliminated | 19 |
| status: completed | 12 |
| status: error | 2 |
| promising | 0 |

Dispatched (sum of OUTCOME lines): 33; disproved: 19; rejected on admissibility: 20.

Families proposed this run: `key_tape` 16, `novel` 16, `double_columnar` 10, `multi_layer` 6, `polyalphabetic` 6, `transposition` 5, `archive_evidence` 4, `mirror_ka` 4, `fractionation` 2, `antipodes` 1, `nihilist` 1.

## 3. SECONDARY outcomes (prereg §5)

- **Dead-family avoidance (mechanism check, not judgment):** The steering pathway functioned — `reject_empirically_dead` fired once, and red-team blocked several theories citing prior comprehensive sweeps (Quagmire III/IV via `f_quagmire_iii_indicator_sweep`; Myszkowski width-8 via `e_frac_47`; two-layer trans+sub via the columnar+sub / H1/H2 null campaigns). **But the more honest reading is the generation finding:** the theorist repeatedly *proposed* family-adjacent theories in heavily-swept space, and the critic/red-team caught them. The gates did the work; generation kept aiming at near-dead families. This is the "recombines tested families" limitation from the honest evaluation, observed live.
- **13–23 crib tail:** empty (§1).
- **Lead pursuit:** never triggered — `LEAD PURSUIT skipped — no contracts in [6, 17]` all 15 cycles.
- **Matched-null consultations:** **0** (see §7 — stale cache + no contract reached the alert threshold).
- **Max single-cycle crib_score:** 4 (A/B were 8).

## 4. R3 §6.1.7 DSL-utilization metrics

| metric | value |
|---|---|
| total_admissibility_rejections | 20 |
| total_override_exhaustion_uses | 0 |
| total_translation_errors | 0 |
| matched_null_consultations (`ok_matched_family`) | 0 |
| matched_null stale-refusals | 17 |
| programmatic_fallback_cycles | 0 |
| path mix | DSL-dispatcher-dominated (Category-A: columnar/polyalph/transposition/key_tape) |

`total_admissibility_rejections = 20` confirms the D column is non-zero (no architectural regression). `programmatic_fallback_cycles = 0` confirms the theorist agent produced parseable output every cycle (no §6 halt #2 risk). `total_translation_errors = 0`.

## 5. Proposal-mortality table (R3 §6.1.2)

| stage | this run |
|---|---|
| A. Theorist never proposed | n/a (generation active, 71 proposed) |
| B. Critic rejected | included in 38 `criticized` (underconstrained/contradicted/empirically_dead/low_information) |
| B′. `dsl_untranslatable` | 0 |
| C. Red-team killed | ≥2 pre-dispatch blocks (Quagmire, Myszkowski) + concerns dispatched clean |
| D. Dispatcher rejected (admissibility) | 20 |
| E. Scored (dispatched) | 33 dispatched → 19 disproved + 12 completed (all noise, max crib 4) |
| F. Error / infra | 2 (red-team SDK errors, see §7) |

## 6. Halt conditions (prereg §6 / R3 §5)

**None fired. Normal stop at 15 cycles.**

1. ≥18 alert with `matched_null_miss`/`cache_miss`: not triggered (no contract ≥18). ✓
2. 3 consecutive `_programmatic_fallback` cycles: 0 fallback. ✓
3. 3 consecutive D-zero cycles: 20 admissibility rejections distributed across cycles; run completed all 15. ✓
4. Ledger corruption: none. ✓
5. `_verify_against_kernel` panic: none. ✓
6. Normal stop (15 cycles): **this is how it ended.** ✓

## 7. Reliability findings (NEW — bear on decision-grade unattended runs)

### 7.1 Auto-commit staled the null calibration mid-run (significant)

A background `[auto] Update doc(s)` commit moved HEAD `cf4ec36 → f26f374` at ~18:01 local (and my subsequent spec commits moved it further), re-staling the commit-pinned null manifest (pinned `cf4ec36`). For the remainder of the run the alert path logged **17 stale-refusal events**: `Null baseline cache … is stale … refusing to consume stale calibration.`

- **Fail-safe held:** the framework *refused* to consume stale calibration rather than silently using it. Correct behavior.
- **But:** matched-null gating (including the rail_fence/myszkowski/route nulls built for this campaign) was **unavailable for the whole run**. `matched_null_consultations = 0`.
- **Consequence for the prereg:** **RQ-3 (calibration machinery exercised on live matched families) is UNANSWERED**, per the prereg §5 honesty rule — not "passed." Had a ≥18 contract appeared after 18:01, it would have read `matched_null_miss` and triggered §6 halt #1 (calibrate, then re-evaluate). It was moot only because the run produced 0 signal (max crib 4).
- **Root cause:** an unguarded race between the commit-pinned calibration-freshness contract and a background auto-commit daemon. The campaign's own catch ("no silent run") worked; the environment is not yet hardened for unattended decision-grade runs.

### 7.2 Two red-team SDK errors (handled as inconclusive)

Two `redteam pre-check SDK error … Fatal error in message reader: Command failed with exit code 1` events. Handled correctly: the affected theories were counted `error` (the 2 `error`-status theories in §2), red-team treated as **inconclusive** (not a disproof), and dispatch continued for the non-errored theories (`3/4 survived red-team`). Consistent with the timeout/error = inconclusive doctrine. A transport-reliability data point, not a result-corrupter.

## 8. Research-question answers (prereg §1)

- **RQ-1 (non-artifact graded signal?):** No. Clean null, max crib 4. Expected.
- **RQ-2 (avoid dead families?):** Pathway functioned (red-team + `reject_empirically_dead` blocked family-adjacent proposals), but generation *kept proposing* near-dead families — the gates carried the load, not the theorist's judgment. Confirms the generation-quality limitation.
- **RQ-3 (calibration machinery exercised?):** **UNANSWERED for matched families** — stale cache (§7.1) + no contract reached the alert threshold. Kernel-overrule, admissibility, red-team, and the empirically-dead gate WERE exercised and functioned.

## 9. Instrument-integrity verdict

The controller ran a bounded real-K4 campaign and behaved exactly as a trustworthy disproof instrument should: it produced **no false positive**, kept kernel-overrule / admissibility / red-team / yield gates functioning, caught its own staled calibration rather than consuming it, and degraded gracefully on transient SDK errors. The result is a **decision-grade clean null**: there is no graded real-K4 signal in this 15-cycle window, and we know precisely why each proposal died.

This is the answer the end-state was built for. It also reproduces, with full telemetry, the two structural limits from the honest evaluation: (a) generation recombines tested families rather than originating novel structure, and (b) the substrate is direct-carving, so the search never left the space 35 years of work has mostly eliminated.

## 10. Follow-ups

1. **Recalibrate null baselines at current HEAD** (un-stale; one-line) before any further alert-gated work.
2. **Fix the calibration-freshness race (§7.1):** either gate the `[auto]` commit daemon during a campaign, decouple null-cache freshness from git HEAD (content hash rather than commit pin), or rebuild-and-pin as a launch step inside `run_controller`. This is the top operational hardening item for unattended decision-grade runs.
3. **The generation finding (§3, RQ-2) is the case for the in-flight work:** the open-frontier map + historical-feasibility prior (`docs/specs/2026-05-26-frontier-map-and-historical-prior-design.md`) directly target "theorist keeps proposing family-adjacent / near-dead mechanisms." This run is the empirical motivation for that design.
4. **No further real-K4 campaign** until (2) lands and a matched-null consultation is actually exercised on a synthetic ≥18 plant (to answer RQ-3 cleanly).

---

*Outcome: clean decision-grade null. The instrument works on the disproof half; the discovery half remains gated on generation quality and substrate expansion, exactly as the honest evaluation projected.*
