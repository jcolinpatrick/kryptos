# K4 Run Protocol — Round 3 (post-DSL-wiring)

**Status:** Operator-facing readiness document.
**Supersedes:** `docs/maturation/round2/K4_RUN_PROTOCOL.md` for all post-R3 operational decisions. The Round 2 version is preserved for historical continuity; do NOT delete or overwrite.
**Commissioned by:** R3-4 (2026-04-21).
**Preconditions for use:** R3 exit (this commit) + the pre-run readiness gate in §7 passing within 24 hours of the intended run.

---

## 1. Fitness summary (post-R3)

The framework carries the following invariants into the K4 run:

- **K1 rediscovered at cycle 15** — quagmire_iii/PALIMPSEST (self-test dry-run, `--cycles 20000`).
- **K2 rediscovered at cycle 17** — quagmire_iii/ABSCISSA.
- **K3 rediscovered at cycle 9345** — columnar_double (R2-1).
- **R2-4 matched-family nulls** — calibrated for `{beaufort, variant_beaufort, columnar_single, columnar_double}`. Consulted automatically on live cycles when `contract.raw_artifacts["dsl_pipeline_kinds"]` resolves to a matched family (see DSL_CUTOVER_CONTRACT §7.2).
- **R2-5 real-API K1 pass** — verified 2026-04-21 in `kryptosbot/self_test_real_api.py`.
- **R3-0.5 DSL coverage** — 9 supported kinds: `{identity, vigenere, beaufort, variant_beaufort, columnar, atbash, procedural, grille, polybius}`.
- **R3-2 DSL dispatch live** — controller's `_run_worker` routes Category-A (cipher-family) theories via `job_dispatcher.execute()` with kernel-overrule preserved. Workers on the Category-A path no longer call Claude.
- **R3-3 integration test** — all brief §4.2 invariants verified under synthetic conditions.

**[DERIVED FACT]** Self-test dry-run state is reproduced at every R3 commit; any deviation blocks the K4 run.

---

## 2. Coverage gaps (carried into the K4 run)

Resolved since Round 2's protocol:

- ✓ Full controller wiring (postmortem §6.1.6 gap) — closed by R3-2.
- ✓ Three additional DSL translators (procedural, grille, polybius) — closed by R3-0.5.

Open after R3:

1. **Five cipher kinds still lack translators:** `rail_fence, route, myszkowski, quagmire, key_tape`. Theorist-proposed theories using any of these get `dsl_untranslatable` rejection at the critic. Operator should expect a non-zero rate of such rejections in the mortality table; they are the framework honestly reporting "this cipher family can't be tested yet," not errors.

2. **`TokenAccountant` not wired into the controller.** The R2-5 infrastructure is still standalone. Token telemetry for a live K4 run is still recovered post-hoc from Claude Code session transcripts, same as the 2026-04-21 postmortem §6.1.5 did. A later brief wires it.

3. **Agent output reliability** — observed during R3-3 real-theorist measurement. The theorist's dry-run agent occasionally fails to produce parseable JSON output, causing `_propose_theories` to fall through to `_programmatic_fallback`. The fallback emits "Explore X family" template stubs which then get critic-approved in some Category-B families. Operator must monitor this rate during the K4 run (see §6.1.7 below); sustained fallback rate > 30% is an operator intervention signal.

4. **Straight polybius (length-doubling variant) not supported.** Polybius translator accepts `variant="bifid"` only. Multi-layer hypotheses needing straight polybius as an intermediate step must wait for a later brief.

---

## 3. Run protocol (R3 cost profile)

### 3.1 Per-cycle Claude spend

**Pre-R3 per-cycle cost (from postmortem §6.1.5):**

```
5 workers/cycle × worker_subscription_cost (~300K–500K tokens each) +
1 theorist call +
N sibling calls (red-team, stat-audit, pursuit, synthesis)
```

**Post-R3 per-cycle cost for Category-A theories:**

```
0 worker subscription tokens (DSL path is pure Python compute) +
1 theorist call +
N sibling calls
```

**Post-R3 per-cycle cost for Category-B theories:**

```
~subscription cost per Category-B theory (legacy path unchanged) +
1 theorist call shared with Category A +
N sibling calls per Category-B contract
```

### 3.2 Budget planning

The operator's K4 budget gate should key on:

- **Theorist input/output tokens** — rough cycle average 50K–150K tokens (prompt is large; output is per-N-theories).
- **Sibling calls** — red-team ~1 per approved theory, stat-audit ≤1 per signal contract, pursuit ≤1 per sub-signal contract, synthesis 1 per cycle.
- **Category-A workers** — zero tokens (Python compute on 28-core pool).
- **Category-B workers** — ~300K–500K tokens each (legacy SDK subprocess).

**Implication:** the budget that previously sized 4 cycles of K4 now sizes roughly 15–25 cycles under typical Category-A:Category-B ratios (estimated 3:1 or better per theorist distribution), before the sibling calls dominate.

### 3.3 Run duration cap

Operator sets `--cycles N` on invocation. R3-2's architecture makes `N = 15` (the previous protocol cap) generously affordable. **Recommended starting config for the first R3-era K4 run: `--cycles 15 --theories 5`.**

Reduce to `--theories 3` if fallback rate starts dominating early cycles.

---

## 4. Alert handling

### 4.1 Pre-run

Standard pre-run checks:

- Doctor 20/0 pass
- Full suite green
- Self-test K1/15 K2/17 K3/9345
- Pre-run readiness gate (see §7)

### 4.2 During the run

When the controller emits a SIGNAL or BREAKTHROUGH alert:

1. Check the alert event's `contradiction_note` and p-value status. The status fields surfaced by R3-2 are:
   - `"ok_gated"` / `"ok_ungated"` — random_text null consulted (legacy Phase 6 behaviour).
   - `"ok_matched_family"` / `"matched_family_ungated"` — **R2-4 matched null consulted** (the R3-target alert quality).
   - `"matched_null_miss"` — matched-family null cache missing for this family; fell back to random_text with WARNING. Treat as reduced-confidence alert; consider calibrating the missing null before acting.
   - `"cache_miss"` — no null cache at all; alert is uncalibrated (legacy fail-open).

2. **Before acting on an alert, verify the status is `ok_matched_family` or `ok_gated`.** If `matched_null_miss` or `cache_miss`, rerun `scripts/_infra/calibrate_null_baselines.py` and re-evaluate.

3. Kernel-overrule is preserved on all paths. Trust `contract.crib_score` and `contract.bean_passed`; ignore worker-reported values (they're zeroed by `_verify_against_kernel`).

4. Category-B alerts can fire too (the legacy path still runs and the contract is still kernel-verified). Their matched-null fallback is random_text; consider promoting a Category-B alert with a warning.

---

## 5. Halt conditions

Operator halts the run if any of the following:

1. A BREAKTHROUGH alert fires with `matched_null_miss` or `cache_miss` status (ambiguous null) — calibrate first, then re-evaluate.
2. Three consecutive cycles with `_programmatic_fallback` firing (fallback rate > 100% for 3 consecutive cycles) — theorist agent is broken; investigate before continuing.
3. **(R3-4 addition)** Three consecutive cycles with `D column (REJECTED_ADMISSIBILITY count) = 0`. Per brief §5.1 item 5: under R3's architecture, a clean D=0 column sustained across cycles means theorists are proposing only trivially-admissible or only Category-B theories — either the prompt is pulling them away from novel cipher proposals or the anomaly surface has saturated. Operator intervention warranted (prompt review or anomaly rotation).
4. Ledger corruption detected (schema mismatch, missing dsl_spec column on expected rows).
5. Any panic-level error from `_verify_against_kernel` — this is never expected in normal operation.

---

## 6. Post-run analysis

### 6.1 Mandatory sections in the postmortem

All Round 2 protocol sections retained. New under R3:

#### 6.1.1 Cycle-by-cycle telemetry (unchanged from Round 2)

#### 6.1.2 Proposal-mortality table (unchanged structure, new row)

Under R3, the mortality table's categories are:

| Stage | Sub-reason | Category |
|---|---|---|
| A. Theorist never proposed | families/keywords/recipes absent | — |
| B. Critic rejected | reject_underconstrained, reject_contradicted, etc. | — |
| B'. (R3 addition) Critic rejected with `dsl_untranslatable` | Category C: cipher family + missing/malformed/untranslatable spec | split from B |
| C. Red-team killed | — | — |
| D. Dispatcher rejected | admissibility (translation gap, cardinality, exhaustion overlap) | Category A only |
| E. Scoring outcomes (dispatched) | Category A via DSL or Category B via legacy | split by `worker_role` |
| F. Error / infra | — | — |

#### 6.1.3 Negative-space finding (unchanged from Round 2)

#### 6.1.4 Failure-mode classification (unchanged from Round 2)

#### 6.1.5 Subscription accounting

Category-A theories contribute ZERO worker-side subscription tokens. Recompute the postmortem token total over:

- Theorist calls per cycle (≈ 1)
- Sibling calls per cycle (red-team, stat-audit, pursuit, synthesis)
- Category-B worker subprocess tokens (legacy path)

#### 6.1.6 Architectural finding (R3 closure)

Postmortem must confirm that D column is non-zero at least once per ≥5 dispatched cycles. Absence of any D column entries is an architectural regression — either admissibility isn't firing or all theorist-proposed specs are trivially admissible. Both are concerning and warrant investigation.

#### 6.1.7 DSL utilization metrics (R3-4 addition)

New mandatory section. Capture the following counters for every run:

- `total_admissibility_rejections` — count of WorkerContract with status=REJECTED_ADMISSIBILITY.
- `total_override_exhaustion_uses` — theories whose `dsl_spec.override_exhaustion=True` passed admissibility (see `JobResult.override_justification` non-empty).
- `total_translation_errors` — REJECTED_ADMISSIBILITY contracts whose reasons mention "translation error".
- `matched_null_consultations` — count of alerts whose p-value status was `ok_matched_family` or `matched_family_ungated`.
- `matched_null_cache_misses` — count of alerts with status `matched_null_miss`.
- `dsl_path_contracts` — count of contracts with `worker_role="dsl_dispatcher"`.
- `legacy_path_contracts` — count with `worker_role="agent_sdk_non_dsl_category"` (R3-2) or `"agent_sdk"` (pre-R3 / unflagged).
- `programmatic_fallback_cycles` — count of cycles where `_programmatic_fallback` produced theories (detected by "Explore X family" title pattern).

These metrics prove R3's wiring actually runs during the K4 run. Missing any of these (e.g., zero matched-null consultations) on a non-trivial cycle count means the wiring has a silent regression.

---

## 7. Pre-run readiness gate

Before invoking `kryptosbot/solve.py` or `kryptosbot/run_controller.py` for a K4 run, the operator runs:

```bash
# 1. Doctor + full suites
PYTHONPATH=src python3 -m kryptos doctor
PYTHONPATH=src pytest tests/ -q
PYTHONPATH=src pytest kryptosbot/tests/ -q

# 2. Self-test fitness (K3 cap sized for full strategy search)
PYTHONPATH=src python3 -u kryptosbot/self_test.py \
    --panel all --mode dry-run --cycles 20000 \
    --report-path results/self_test/pre_run_<date>.json

# 3. Null cache freshness (optional; auto-rebuilds on miss)
ls -la null_baselines/manifest.json

# 4. R2-5 real-API K1 test (ensures the full dispatch path actually runs end-to-end)
PYTHONPATH=src python3 -u kryptosbot/self_test_real_api.py

# 5. Transport verification (strongly recommended; added 2026-04-24
#    after Campaign C attempt 1 silently hung for 3h on an
#    unverified subscription throttle). Either run the two probes
#    manually, or use --verify-transport as a launch-time gate:
PYTHONPATH=src python3 -u kryptosbot/run_controller.py \
    --verify-transport --status
# (or pass --verify-transport to any launch command; the run halts
#  before touching the ledger if either probe fails)
```

**Expected:**

- Doctor 20/0 PASS.
- Core test suite: expected count passed (check phase-exit report for latest).
- Kryptosbot test suite: expected count passed.
- Self-test: K1 cycles=15, K2 cycles=17, K3 cycles=9345 all discovered at peak 20/20.
- Manifest exists with `kernel_commit_at_latest_write` matching current HEAD.
- R2-5 real-API: K1 discovered via live agent loop.
- Transport probes (if run): direct-api PROCEED, subscription-sdk PROCEED. See `kryptosbot/transport_preflight.py`.

**Any deviation halts the run until resolved.** Commit hash of the green readiness pass is recorded in the K4 run's session header.

**`--verify-transport` policy (2026-04-24).** Currently optional but strongly recommended. Skipping it after a heavy-usage day risks the silent-throttle failure mode that caused Campaign C attempt 1. Whether to make the flag mandatory is a separate operator decision; this protocol does not pre-empt it.

**Operator sign-off:** the R3-3 phase report (§3) and R3-4 this document (§2) flag the fallback-firing reliability concern. Operator must explicitly acknowledge before initiating the K4 run that the fallback trigger is understood and will be monitored via §6.1.7's `programmatic_fallback_cycles` counter.

---

## 8. What R3 proved and what it didn't

### 8.1 Proved

- The live controller dispatches cipher-family theories through `job_dispatcher.execute()` (the postmortem §6.1.6 closure).
- Category-B theories route to the legacy path with explicit tags, preserving the theorist paradigm while still closing the DSL gap for cipher work.
- Kernel overrule is preserved on the DSL path — `job_result_to_worker_contract` calls `_verify_against_kernel`.
- Matched-family nulls from R2-4 are actually consulted on live alerts when the pipeline metadata resolves to a calibrated family.
- The synthetic-theory integration test exercises every code surface R3-2 introduced; the mortality fingerprint asserts exact expected counts.
- `_SUPPORTED_KINDS` = 9 kinds. R3-0.5's broadening is live.

### 8.2 Did not prove

- **K4 solvability.** R3 is architecture and plumbing. The K4 commissioning is a separate operator instruction.
- **Theorist cryptanalytic depth.** The DSL's 9-kind coverage is plumbing, not intelligence. Whether the theorist proposes truly novel hypotheses inside that space is a prompt-quality concern, not an R3 deliverable.
- **Real-theorist spec-production rate above a statistically strong N.** R3-3's measurement observed 100% on N=1 — satisfies the 80% floor but thin evidence. The K4 run's 15-cycle window will produce the first real statistical sample.
- **End-to-end alert gate under realistic conditions.** R3-3 verified the matched-null keying under synthetic conditions; the live gate will be exercised for real the first time during the K4 run.
- **Subscription billing reduction.** The post-R3 per-cycle cost shift (§3.1) is algebraically derivable from the architecture but will only be empirically confirmed on the first live run.

---

## 9. Operator sign-off checklist

Before commissioning the K4 run:

- [ ] Read this document end-to-end.
- [ ] Read the R3 round SUMMARY (`docs/maturation/round3/SUMMARY.md`).
- [ ] Read `docs/maturation/round2/K4_RUN_POSTMORTEM.md` §6.1.6 (what R3 was designed to fix).
- [ ] Run §7 pre-run readiness gate within 24 hours of the intended run.
- [ ] Record the commit hash of the green readiness pass.
- [ ] Acknowledge the §2 open concerns (especially fallback-firing reliability).
- [ ] Commit to checking §6.1.7 DSL utilization metrics at run closure.

**R3 exit commit:** (recorded after final commit lands).

*End of K4_RUN_PROTOCOL_R3.md. Operator-commissioned K4 runs begin here.*
