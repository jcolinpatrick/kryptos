# Real-K4 Bounded Instrument Campaign — Preregistration

**Commissioned:** 2026-05-26
**Status:** PREREGISTERED DRAFT — red-teamed 2026-05-26 (1 blocker + 3 should-fixes + 2 minors applied; see §11). Pending operator sign-off. Do NOT edit success criteria after launch.
**Run protocol:** governed by `docs/maturation/round3/K4_RUN_PROTOCOL_R3.md` (R3 supersedes R2). This document adds the campaign-specific research question, gates, and locked outcome definitions on top of R3.
**Predecessor context:** Campaigns A/B/C (`docs/maturation/round3/K4_CAMPAIGN_{A,B,C}_*`) were prompt-content evaluations that explicitly disclaimed being K4-solve attempts. This is the first bounded real-K4 attempt run **after** the synthetic recovery gate (Gate 1) went green.

---

## 0. Why now (entry precondition)

Gate 1 — the synthetic recovery gate built by PR1–PR4 — is green as of 2026-05-26 (HEAD `795a2d7`):

```
T1_SERPENTINE_QUAGMIRE   -> satisfied, best_score 24   (db/synthetic_profiles/)
T1_BERLINCLOCK_COLUMNAR  -> satisfied, best_score 24   (db/synthetic_profiles/)
T1_SERPENTINE_ROUTE      -> satisfied, best_score 24   (db/synthetic_profiles/)
T1_TAPE_K3PT             -> honestly blocked            (refuses vigenere-fallback conflation)
real ledger              -> untouched during all smokes
full kryptosbot suite    -> 2481 passed, 1 skipped, 0 failures
```

The machine recovers known-recoverable synthetic K4-shaped mechanisms end-to-end while honestly leaving a genuinely-unimplemented one blocked.

**Precise scope of what Gate 1 licenses (do not over-read):** the synthetic profiles recover their *own injected* plaintext from synthetic CT — i.e. Gate 1 proves **recovery-when-the-key-is-in-the-search-distribution**. It does NOT prove **search-adequacy-when-the-key-is-absent**, which is the real-K4 condition (by the 35-year base rate, K4's mechanism is most likely outside the controller's current DSL distribution). Gate 1 therefore licenses an *instrument-integrity test on real K4*, not an expectation of solve. The "next question" below is scoped accordingly.

Per the agreed end-state logic, that earns the right to ask the **next** question — which is NOT "did it solve K4" but:

> **Is this controller a cryptanalytic instrument, or an expensive story generator?**

This campaign is designed to answer that with evidence, under a fixed budget, with the real ledger protected by gates rather than by abstention.

## 1. Research question

Under a bounded, preregistered budget on the real K4 ciphertext, does the controller:

1. produce any **non-artifact graded signal** (precise definition in §4), and
2. successfully *steer away* from already-dead / exhausted mechanisms via its ledger landscape (a mechanism check on the landscape→theorist pathway — NOT a claim of independent cryptanalytic judgment; see §5 and the §7 circularity caveat), and
3. exercise its calibration machinery (matched-null gates, kernel-overrule, crib-paste filter) as designed on live cycles?

This is an **instrument-integrity** evaluation. A zero-signal outcome is an expected and acceptable result; the campaign's value is the falsifiable telemetry, not a solve.

**[HYPOTHESIS]** Prior on a true graded signal surviving all gates in 15 cycles is very low (35-year base rate; every prior internal campaign produced max crib_score ≤ 8 on the real CT). The headline metric is recorded precisely *because* its expected value is zero — a non-zero result is the rare, high-value event the gates exist to make trustworthy.

## 2. Launch configuration (LOCKED)

```bash
PYTHONPATH=src python3 -u kryptosbot/run_controller.py \
    --cycles 15 --theories 5 \
    --db db/theory_ledger.sqlite \
    --coverage-report results/coverage_reports/ \
    --verify-transport
```

**Fixed parameters (no edits after launch):**

| Parameter | Value | Rationale |
|---|---|---|
| Cycle budget | `--cycles 15` | R3 §3.3 recommended first-R3-era config; affordable under Category-A zero-token dispatch. |
| Theory budget | `--theories 5` | R3 §3.3. Reduce to 3 ONLY if the §6 fallback halt trips; reduction is a halt-and-restart, not a mid-run edit. |
| Ledger | `db/theory_ledger.sqlite` (real, default) | Gives the controller its accumulated landscape so it can *avoid known-dead families* — that avoidance is part of the research question. Landscape-carryover confound accepted (§7). |
| Coverage archiving | `results/coverage_reports/` | Every cycle's coverage artifact archived (no silent runs). |
| Transport preflight | `--verify-transport` | MANDATORY here. Campaign C attempt 1 silently hung 3h on an unverified subscription throttle (R3 §7). Run halts before touching the ledger if either probe fails. |
| Background | none | Foreground only. No `&`, no nohup, no detached run. Operator watches it. |

**Mode confirmation:** no `--bench-challenge` and no `--synthetic-profile` flag is present, so this is a real-K4 run (real CT from `kryptos.kernel.constants`, real cribs from disclosure). `KRYPTOS_CT_OVERRIDE` / `KRYPTOS_CRIB_DICT_OVERRIDE` MUST be unset (they are K4Bench-only; setting them for real work is a correctness violation).

## 3. Gates active (auto-enforced — verified present, not newly added)

All of these are standing framework behavior; the prereg asserts they are ON, it does not introduce them:

- **Kernel overrule** — `job_result_to_worker_contract` → `_verify_against_kernel`. Worker-reported scores are zeroed; only `contract.crib_score` / `contract.bean_passed` are trusted (R3 §4.2.3).
- **Crib-paste / artifact detector** — fail-closed inside `_verify_against_kernel`. A plaintext that merely reproduces pasted crib text is rejected, not graded.
- **Matched-family null gate** — R2-4 nulls consulted automatically when the dispatched pipeline resolves to `{beaufort, variant_beaufort, columnar_single, columnar_double}`. Alert `p_value_status` must read `ok_matched_family` / `ok_gated` to be actionable.
- **Phase 6 p-value gate** — alerts gate on `p_value_vs_null <= 1e-6` in addition to crib_score.
- **Null baseline freshness** — rebuilt at HEAD `795a2d7` immediately before this campaign (`null_baselines/manifest.json` re-pinned; left uncommitted per repo convention).

## 4. PRIMARY outcome — "non-artifact graded signal" (LOCKED DEFINITION)

> **This is the single design choice most worth operator scrutiny before sign-off.** Locking it loosely makes the whole campaign un-decision-grade.

A result counts as a **non-artifact graded signal** if and only if ALL of the following hold for a single dispatched, kernel-verified candidate:

1. **Graded ≥ SIGNAL:** `contract.crib_score >= 18` (kernel-verified value, never worker-reported).
2. **Not a paste artifact:** passed the fail-closed crib-paste detector (`_verify_against_kernel` did not flag it).
3. **Null-survived against the RIGHT null:** alert `p_value_status == ok_matched_family` AND `p_value_vs_null <= 1e-6`. **`ok_gated` does NOT count** — it means only the strawman `random_text` null was available (verified: that null's max crib_score is 7 over 100k samples, so any structured-but-wrong transposition output can clear it). `matched_null_miss` and `cache_miss` likewise disqualify. **Only the calibrated families `{vigenere, beaufort, variant_beaufort, columnar_single, columnar_double}` can produce `ok_matched_family`** (verified against `null_baselines/manifest.json`). A graded candidate in any *uncalibrated* family — `route, myszkowski, grille, polybius, quagmire, rail_fence`, etc., which `alerts.py` routes to the random_text fallback — is recorded as **"uncalibrated — pending matched-null build,"** never as a non-artifact signal, until a matched-family null for that family is calibrated and the candidate re-evaluated. (This closes the artifact-masquerade path the red-team found: an unmatched-family artifact beating the strawman null and being stamped `ok_gated`.)
4. **Not a period/width-inflation false positive:** the candidate is NOT in a known underdetermined regime on the raw 97-char carving. This covers (a) **substitution:** periodic substitution at period ≥ 8 on the direct carving (the `period_consistency` trap — scores ~17–19/24 by construction, null-expected); AND (b) **transposition:** the same many-residues-few-constraints analogue in large-width columnar / route / myszkowski (e.g. columnar width ≥ 13), and any candidate whose admissibility passed *only* via `override_exhaustion`. Hits in these regimes are recorded but classified **artifact**, not signal.
5. **Live family, not dead:** the dispatched family is not on the briefing's TIER 1 / DO-NOT-TEST list or the exhaustion log's eliminated set. (Columnar disqualification under this clause must NOT lean on the AUDIT-1-disputed "source-independence" wording, which is an open audit — cite the bounded-universe elimination, not the disputed Tier-1 phrasing.)

**Pre-committed interpretation:**
- **Zero non-artifact graded signals (expected):** campaign concludes the instrument ran correctly and produced no signal — a clean, informative null. No K4 claim. Proceed to the §0-style go/no-go for Path B (capability work).
- **≥1 non-artifact graded signal (rare):** HALT the campaign at cycle end. Do NOT claim a solve. Escalate the single candidate to a focused validation pass — `red-team-disprover` + `statistical-auditor` — under the disproof protocol before any promotion or public statement. A graded signal is an *input to validation, not an output* (CLAUDE.md doctrine).

## 5. SECONDARY outcomes (recorded, do NOT gate the conclusion)

Per the agreed campaign-usefulness questions:

- **Dead-family avoidance (mechanism check, NOT judgment):** count of dispatched contracts whose family appears on the exhaustion/DO-NOT-TEST set. Target: low. **Interpretation is bounded:** because this runs on the shared ledger, "avoidance" measures whether the ledger's accumulated memory successfully steers the theorist — it is a check on the landscape→theorist→critic pathway functioning, NOT a measure of independent cryptanalytic judgment (the ledger *supplies* the avoidance signal, so a low count cannot be credited to the controller "knowing better" on its own). A high count is the informative direction: it means the steering pathway is broken.
- **Calibration-machinery exercised (RQ-3):** if `matched_null_consultations == 0` across all 15 cycles (e.g. every graded candidate landed in an uncalibrated family), RQ-3 is **UNANSWERED for matched families**, not passed — the postmortem must say so explicitly rather than report "gates worked."
- **13–23 crib-score tail:** distribution of kernel-verified crib scores in `[13, 23]`. A populated tail (without §4 disqualifiers) is the texture worth pursuing next; an empty tail with everything ≤ 8 reproduces the prior base rate.
- **Lead-pursuit value:** did any pursued lead (soft `skip_variants` lead) improve a downstream crib score vs. its parent? (passive surfacing only — pursuit never auto-dispatches; locked 2026-04-14.)
- **DSL utilization (R3 §6.1.7):** `total_admissibility_rejections`, `total_translation_errors`, `dsl_path_contracts`, `legacy_path_contracts`, `matched_null_consultations`, `matched_null_cache_misses`, `programmatic_fallback_cycles`, `total_override_exhaustion_uses`. These prove the R3 wiring actually ran (zero matched-null consultations on a non-trivial cycle count = silent regression).
- **Proposal mortality table (R3 §6.1.2):** stages A–F including the `dsl_untranslatable` Category-C split.
- **Max single-cycle crib_score:** descriptive. Prior campaigns A/B = 8.

## 6. Halt conditions (R3 §5, restated and locked)

Operator halts immediately if any of:

1. A `crib_score >= 18` alert fires with `p_value_status ∈ {matched_null_miss, cache_miss}` (ambiguous null) — calibrate the missing null, then re-evaluate; do not act on the raw alert.
2. `_programmatic_fallback` fires for **3 consecutive cycles** (theorist agent broken — investigate before continuing).
3. `D` column (`REJECTED_ADMISSIBILITY` count) = 0 for **3 consecutive dispatched cycles** (theorists proposing only trivially-admissible / Category-B; prompt review or anomaly rotation warranted).
4. Ledger corruption (schema mismatch / missing `dsl_spec` column on expected rows).
5. Any panic-level error from `_verify_against_kernel`.
6. **Normal stop:** 15 cycles complete.

Plus the §4 rule: **any non-artifact graded signal halts at cycle end for focused validation.**

## 7. Confound accounting (accepted)

- **Landscape carryover:** the real ledger carries ~all prior real-K4 proposals. The controller's anomaly counts, pursuit leads, and recent-outcome window reflect that history. This is *intended* (it is what enables dead-family avoidance) but means this campaign is not a fresh-state baseline. The postmortem records the launch-time landscape snapshot.
- **Theorist reliability:** R3 §2.3 flags occasional unparseable theorist output falling through to `_programmatic_fallback` (template stubs). Monitored via §5 halt #2 and the §6.1.7 counter.
- **Untranslatable kinds:** `rail_fence, route, myszkowski, quagmire` lacked Category-A translators at R3 exit (key_tape since landed). Theories in those families may take `dsl_untranslatable` rejection — that is honest "can't test yet," not error, and is recorded in the Category-C mortality split.
- **N is small:** 15 cycles is too few for significance testing on mix fractions. Secondary metrics are directional, not inferential.

## 8. What this campaign does NOT test / claim

- **K4 solvability.** Expected null. A non-artifact graded signal, if it occurs, triggers validation — it is not itself a solve claim.
- **Generation quality / cryptanalytic depth.** Whether the theorist proposes *good* hypotheses inside the DSL space is a prompt-quality question this campaign only weakly informs (small N).
- **Any non-direct-carving alignment.** This campaign runs the controller's current substrate, which assumes direct positional CT[i]→PT[i] on the fixed 97-char carving. The known load-bearing structural risk (nulls / non-direct alignment / physical key) is OUT of scope here and is the subject of separate Path-B substrate work, not this run.

## 9. Pre-run readiness gate (R3 §7 — run within 24h of launch, after sign-off)

```bash
PYTHONPATH=src python3 -m kryptos doctor                      # expect 20/0 PASS
PYTHONPATH=src pytest tests/ -q                               # core suite green
PYTHONPATH=src /home/cpatrick/kryptos/venv/bin/python -m pytest kryptosbot/tests/ -q -n 26   # kryptosbot green (2481p/1s as of 795a2d7)
PYTHONPATH=src python3 -u kryptosbot/self_test.py --panel all --mode dry-run --cycles 20000 \
    --report-path results/self_test/pre_run_2026_05_26.json   # K1/15 K2/17 K3/9345
PYTHONPATH=src python3 -u kryptosbot/self_test_real_api.py    # R2-5 real-API K1 pass
ls -la null_baselines/manifest.json                           # manifest at HEAD
```

Any deviation halts the run until resolved. The commit hash of the green readiness pass is recorded in the run's session header.

## 10. Operator sign-off

Before launch:

- [ ] Red-team-disprover has reviewed THIS preregistration's design (per `feedback_red_team_before_swings`; campaign is real compute).
- [ ] §4 locked definition of "non-artifact graded signal" reviewed and accepted by operator.
- [ ] §9 readiness gate run green within 24h; commit hash recorded.
- [ ] Launch command (§2) recorded in run log with timestamp.
- [ ] Operator acknowledges R3 §2 open concerns (fallback reliability) and commits to checking §6.1.7 metrics at closure.
- [ ] Postmortem (R3 §6 + §4/§5 outcomes here) committed after the run.

## 11. Red-team dispositions (2026-05-26, pre-sign-off)

`red-team-disprover` reviewed this design before any compute. Dispositions:

| # | Finding | Severity | Disposition |
|---|---|---|---|
| 1 | §4.3 admitted `ok_gated` (random_text null) as "null-survived" for families with no calibrated matched null — exactly the families (route/myszkowski/grille/polybius/quagmire) most likely to be dispatched. Strawman null (max crib 7) lets an artifact masquerade as signal. | **BLOCKER** | **FIXED.** §4.3 rewritten: only `ok_matched_family` counts; uncalibrated families recorded "pending matched-null build." Both facts (manifest family set; `alerts.py:203,430` random_text fallback) verified independently before editing. |
| 2 | §4.4 period carve-out covered substitution only, not the large-width transposition analogue. | should-fix | **FIXED.** §4.4 now covers transposition width-inflation + `override_exhaustion`-only admissibility. |
| 3 | §0 "earns the right" over-claimed — Gate 1 proves recovery-when-present, not search-adequacy-when-absent. | should-fix | **FIXED.** §0 precise-scope paragraph added. |
| 4 | Dead-family avoidance on shared ledger is circular (measures ledger memory, not judgment). | should-fix | **FIXED.** §1.2 + §5 reframed as a pathway mechanism-check, not judgment. |
| 5 | N=15/5 mostly reproduces known "max crib 8, zero signal" prior; positive learning thin. | minor | **ACCEPTED.** §1 already frames expected-zero; §8 disclaims. The value is the integrity telemetry + the now-tightened §4 gate, not new signal. |
| 6 | §6 had no halt for `matched_null_consultations == 0` across the run. | minor | **ADDRESSED** as a postmortem-honesty rule (§5 RQ-3 bullet) rather than a hard halt — an all-transposition cycle set can legitimately produce zero matched consultations; the honest move is to mark RQ-3 unanswered, not to halt. |
| 7 | §4.5 live-family check could lean on AUDIT-1-disputed columnar wording. | minor | **FIXED.** §4.5 caveat added. |

The red-team agent (`a274371f80d53722c`) remains resumable if further design pressure is wanted.

---

*This preregistration locks §4 (primary outcome) and §6 (halt conditions). Any post-hoc weakening of the §4 definition invalidates the instrument-integrity reading. §4.3 in particular was the red-team blocker fix — do not relax `ok_matched_family`-only back to admitting `ok_gated`.*
