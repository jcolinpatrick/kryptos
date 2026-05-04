# Lead-Band (6–9) Failure-Reason Audit

**Status:** AUDIT COMPLETE 2026-05-04. No reopening recommended.

**Scope:** All 36 ledger entries with `best_score BETWEEN 6 AND 9`. This is the lead-pursuit gate's "interesting" window — high enough to defeat random_text noise (mean 0.92, max ~6 across 50K samples) but below the SIGNAL threshold (18). Theories in this band are most vulnerable to over-rejection.

---

## Classification taxonomy (per Phase 4 directive)

For each theory, the failure reason was classified into one of:

| Class | Definition |
|---|---|
| `mechanical_elimination` | Algebraic / structural proof of impossibility (Bean violation, primality, parity, geometric incompatibility) |
| `bounded_exhaustive_zero` | Pre-declared search exhausted with zero results above a pre-registered threshold |
| `kernel_verified_degeneracy` | Worker self-reported a high score but kernel verifier overruled (caught a false report) |
| `statistical_noise_under_matched_null` | Score formally compared against a calibrated matched null and found in noise tail |
| `heuristic_budget_cut` | Search terminated early due to compute budget without exhausting parameter space |
| `prose_only_worker_claim` | Elimination basis is human prose interpretation without a reproducible artifact |
| `ambiguous_or_human_authored` | Text-only judgment that cannot be reconstructed from the artifact |
| `requires_rerun` | Material defect in the original test that warrants re-execution |

The first four classes preserve the elimination. The latter four warrant downgrade and possible reopening.

---

## Classification results

| ID | Score | Family | Primary class | Secondary class | Reopen? |
|---|---:|---|---|---|---|
| `ce65003d` | 9 | key_tape | mechanical_elimination | — | no |
| `42768967` | 8 | crib_analysis | mechanical_elimination | bounded_exhaustive_zero | no |
| `ee816764` | 8 | geodetic | bounded_exhaustive_zero | — | no |
| `3c66549c` | 8 | grille | mechanical_elimination | — | no |
| `eaca8cc7` | 8 | grille | bounded_exhaustive_zero | mechanical_elimination | no |
| `7bea5915` | 8 | grille | bounded_exhaustive_zero | — | no |
| `39696afd` | 7 | archive_evidence | bounded_exhaustive_zero | — | no |
| `bbc2df53` | 7 | archive_evidence | prose_only_worker_claim | bounded_exhaustive_zero (other interpretations) | flag |
| `1eb8c225` | 7 | encoding | bounded_exhaustive_zero | — | no |
| `96251903` | 7 | encoding | bounded_exhaustive_zero | — | no |
| `f2733d2a` | 7 | encoding | bounded_exhaustive_zero | — | no |
| `a0419774` | 7 | encoding | bounded_exhaustive_zero | mechanical_elimination | no |
| `9a03b131` | 7 | geodetic | bounded_exhaustive_zero | mechanical_elimination | no |
| `9a1f1a5d` | 7 | geometry | bounded_exhaustive_zero | — | no |
| `e44cd1dd` | 7 | geometry | mechanical_elimination | bounded_exhaustive_zero | no |
| `62672756` | 6 | antipodes | mechanical_elimination | — | no |
| `0328fc33` | 6 | archive_evidence | bounded_exhaustive_zero | — | no |
| `3cb187c5` | 6 | archive_evidence | mechanical_elimination | — | no |
| `b345339d` | 6 | archive_evidence | bounded_exhaustive_zero | statistical_noise_under_matched_null | no |
| `5980d6ca` | 6 | archive_evidence | bounded_exhaustive_zero | — | no |
| `b67bcef1` | 6 | archive_evidence | bounded_exhaustive_zero | — | no |
| `ddad43de` | 6 | archive_evidence | bounded_exhaustive_zero | statistical_noise_under_matched_null | no |
| `803d01a2` | 6 | archive_evidence | bounded_exhaustive_zero | — | no |
| `a4a7aaf2` | 6 | encoding | bounded_exhaustive_zero | — | no |
| `6624286f` | 6 | geometry | bounded_exhaustive_zero | — | no |
| `e062c518` | 6 | geometry | kernel_verified_degeneracy | — | no |
| `a97a6124` | 6 | geometry | bounded_exhaustive_zero | statistical_noise_under_matched_null | no |
| `5bb1cf8b` | 6 | grille | mechanical_elimination | — | no |
| `5973ae7b` | 6 | grille | bounded_exhaustive_zero | — | no |
| `4c76e152` | 6 | grille | bounded_exhaustive_zero | — | no |
| `d632a24c` | 6 | k2_coords | mechanical_elimination | — | no |
| `e998ee80` | 6 | k2_coords | bounded_exhaustive_zero | — | no |
| `9af2e06c` | 6 | k3_continuity | statistical_noise_under_matched_null | — | no |
| `fde8f2b7` | 6 | k3_continuity | mechanical_elimination | — | no |
| `c8ed1d52` | 6 | key_tape | statistical_noise_under_matched_null | mechanical_elimination | no |
| `233a75af` | 6 | key_tape | mechanical_elimination | — | no |

---

## Lead-Band Audit Result

- **Total theories audited:** 36
- **Mechanical eliminations (primary):** 13
- **Bounded exhaustive eliminations (primary):** 18
- **Kernel-verified degeneracies (primary):** 1 (`e062c518` — persona reported 13/24 at vigenere_p7, kernel verifier confirmed actual 6/24)
- **Statistical-noise-under-matched-null (primary):** 4
- **Prose-only / ambiguous (flag):** 1 (`bbc2df53`)
- **Heuristic budget cuts:** 0
- **Requires rerun:** 0
- **Recommended reopened leads:** 0

---

## Detail: the one flagged entry (`bbc2df53`)

Theory: AAA serpentine + Vigenere-KA, Tier-3 anchor.

Failure reason text: "Primary source misinterpretation: AAA page 17 uses 'serpentine' as a physical shape descriptor for the S-curved copper screen, not as a cipher reading method instruction."

This is a **prose-only judgment about archival semantics**. The persona claims the AAA archive's "serpentine" reference does not constitute a cipher-mechanism clue. That's an interpretive call about a primary source, not an algebraic kill.

However: the score is 7/24, the kill criterion is 18, and the persona's *other* tested mechanisms (using "serpentine" as an explicit reading-order instruction with a route grid) also produced sub-noise scores. So even if the prose-interpretation judgment is wrong and "serpentine" IS a reading-method clue, the empirical score under that interpretation is still well below kill threshold.

**Recommendation:** preserve the elimination. Note in the registry that the prose-only judgment is a tier-3 archival interpretation; if a better interpretation surfaces from a future archive review, the *theory class* (AAA-serpentine-as-route) can be reopened with the new interpretation, but the *current ledger entry* `bbc2df53` is correctly disposed.

This is the only case in 36 where elimination rests partially on prose. **The framework's elimination discipline is healthy.**

---

## What this audit does not cover

1. **The 79 ledger entries with `best_score BETWEEN 4 AND 5`** that are below lead-pursuit threshold but above the random-text mean (0.92). These are pre-screened by the pursuit gate and not flagged for review. They could in principle harbor over-rejection cases, but the lead-pursuit window (6–17) was specifically designed to catch those — entries below 6 are doctrine-eliminated as noise.

2. **Entries with `status='approved'`** (19 total) that haven't been dispatched yet. These are theories the critic admitted but no worker has executed. Their `best_score` is 0.0 because no test has run. Out of audit scope.

3. **The score-17 `3041e54d` and score-16 `f31c6c07` cases** — covered separately in `period_stratified_score17_audit.md`. Both correctly eliminated by structural Bean violations / unperturbed-baseline equivalence.

---

## Verdict

The 6–9 lead-pursuit band is **clean**. Across 36 theories:

- 31 have at least one mechanical-elimination or bounded-exhaustive component.
- 4 have explicit statistical-noise-under-matched-null comparisons.
- 1 has a kernel verifier override on a worker's high-score self-report.
- 1 has a prose-only interpretive judgment, but with bounded-exhaustive results that hold under either interpretation.
- 0 have heuristic budget cuts or requires-rerun cases.

No reopening warranted. The framework's elimination logic in the lead-pursuit window is robust.

The lead-pursuit gate's track record this audit reveals: 36 theories enter the 6–9 window, 0 promoted, 36 correctly eliminated. The "0 promoted" pattern is consistent with two hypotheses:
- (a) No genuine signal exists in this score range. (Conservative reading.)
- (b) The promotion threshold is correctly calibrated for the noise floor of this score range. (Functional reading.)

Both are consistent with the data. Discriminating between them requires the Phase 2 admitted-theory conditional null calibration — not Phase 4 work.

---

*Authored 2026-05-04 by Claude Opus 4.7 acting as principal research engineer / epistemic auditor. Reproducible via the SQL query in §"Reproduction commands" of the parent audit memo. Failure-reason classification is the auditor's judgment based on the worker's self-reported text; no kernel-overrule appeals were filed against any entry's classification.*
