# Current Signal Inventory

Current operational finding: no audited active K4 lead is supported by the existing campaign outputs.

This is a triage conclusion, not a proof of absence. The missing piece is a calibrated conditional null for theories that pass critic/red-team/admissibility gates.

---

## Reproduction context

**Date:** 2026-05-04
**Git HEAD:** `eac95e70cd90716f0295412b13b62709b28e0571`
**Kernel commit (per null_baselines manifest):** `7105ac297264deaed2d29a8dc6aab497dcbc264e`
(Today's commits `bbca74e`, `05b3613`, `eac95e7` did not touch kernel files; manifest stays valid.)
**Ledger DB:** `db/theory_ledger.sqlite` (14 MB)
**Pre-flight:** `python3 -m kryptos doctor` → all PASS; `session_briefing.py` → clean.

---

## Score distribution (879 tested theories)

`status NOT IN ('proposed', 'criticized')`:

| Score bin | N | % |
|---|---:|---:|
| 0 | 559 | 63.6% |
| 1–3 | 194 | 22.1% |
| 4–6 | 103 | 11.7% |
| 7–9 | 15 | 1.7% |
| 10–17 | 2 | 0.2% |
| 18–23 (SIGNAL) | 0 | 0.0% |
| 24 (BREAKTHROUGH, all eliminated) | 6 | 0.7% |

The 6 score-24 entries are all `eliminated` with documented algebraic/structural failure reasons (Bean-invariance under non-crib edits, period-impossibility, primality of 433, exhaustive-zero bounded search, exhaustive-zero wordlist primer search). The framework's safety gates correctly caught each.

The 2 entries in the 10–17 range are score-17 (`3041e54d`, key_tape) and score-16 (`f31c6c07`, geometry). Both eliminated; details in §"Top scorers" below.

The 15 entries in the 7–9 range (lead-pursuit window) all carry `eliminated` status. Full audit deferred to Phase 4.

---

## Per-family means (10 families with N >= 10)

| Family | N | Mean | Max | Δ vs random null (0.92) |
|---|---:|---:|---:|---:|
| geodetic | 11 | 2.458 | 8 | +1.54 |
| k3_continuity | 34 | 2.135 | 24 | +1.21 |
| k2_coords | 36 | 2.032 | 6 | +1.11 |
| archive_evidence | 95 | 1.824 | 24 | +0.90 |
| antipodes | 17 | 1.713 | 6 | +0.79 |
| key_tape | 89 | 1.574 | 24 | +0.65 |
| geometry | 90 | 1.236 | 16 | +0.32 |
| encoding | 291 | 1.139 | 7 | +0.22 |
| grille | 118 | 0.878 | 24 | -0.04 |
| crib_analysis | 56 | 0.782 | 24 | -0.14 |

**These elevations are not interpretable as cryptographic signal.** The random_text null has mean 0.92 over uniform random plaintexts. Theories that survive critic/red-team/admissibility gates are conditioned on "mechanism explicitly targets crib positions," which inflates expected scores. Without a calibrated **admitted-theory conditional null**, the per-family deltas confound admissibility-bias with cryptographic content.

This is the central missing measurement. See `admitted_theory_conditional_null_design.md` (Phase 2 of the K4 Evidence Calibration Plan).

---

## Top scorers (best_score >= 16) and failure-reason classifications

All eight are `eliminated`:

| ID | Score | Family | Failure-reason class (heuristic; subject to Phase 4 audit) |
|---|---:|---|---|
| `4ae72d4d` | 24 | archive_evidence | algebraic degeneracy (Bean is crib-position-only; non-crib edits invariant under all 1.64M perturbations) |
| `c682ed26` | 24 | crib_analysis | bounded keyword pool exhaustively zero (no preregistered keyword satisfied joint Bean+self-encrypt) |
| `e1cfceed` | 24 | grille | period-impossibility (12 distinct keystream values require ≥12 residue classes) + 1M Monte Carlo zero |
| `46caf41f` | 24 | k3_continuity | grid factorization impossible (K3+K4 = 433 prime; no rectangular grid extends cleanly) |
| `795fde3e` | 24 | key_tape | bounded search exhausted (720 configs, zero non-degenerate survivors) |
| `a2f896e5` | 24 | key_tape | exhaustive primer search zero (980,785 wordlist entries; no period-1..24 primer matches known tape values) |
| `3041e54d` | 17 | key_tape | period-consistency-underdetermined regime (all periods {2, 19, 38, 46} hit max 17/24; CLAUDE.md documents random expectation ~17.3/24 at p=17). Kill criteria 1+2 met. |
| `f31c6c07` | 16 | geometry | unperturbed Beaufort baseline (mathematical equivalence proved perturbation didn't help) |

The score-17 case is **the highest-priority follow-up**. Under the random_text null `Binomial(24, 1/26)`, P(X >= 17) ≈ 6e-21 per individual test, Bonferroni-adjusted across 879 tests → ~5e-18 — overwhelming "signal." But the period-aware null shifts the expectation upward, and CLAUDE.md says random configs at period 17 score ~17.3/24. **A period-stratified null calibrated specifically for the configurations actually tested by `3041e54d` is required to declare this case truly noise.** See `period_stratified_score17_audit.md` (Phase 3).

---

## What would change this conclusion

1. **Conditional admitted-theory null** showing the per-family elevations are *expected* (would confirm "no cryptographic signal beyond admissibility-gating bias") OR significantly weaker than observed (would suggest admitted-theory mechanisms are encoding partial signal worth investigating).
2. **Period-stratified score-17 audit** producing an empirical p-value < 0.05 after multiplicity correction at the matched periods/alignments — would justify reopening `3041e54d`'s mechanism.
3. **Lead-band failure-reason audit** (Phase 4) identifying any 6–9 band entry whose failure_reason is heuristic-budget-cut or prose-only (rather than algebraic/exhaustive-zero/kernel-verified) — would justify bounded retesting.
4. **Multi-layer / post-transposition** restatement of any single-layer eliminated family — Tier-2 doctrine preserves these as untested at the multi-layer scope. None currently ranked in the top score range, but the search burden has not been calibrated for these compositions either.

---

## Reproduction commands

```bash
# Score distribution
sqlite3 db/theory_ledger.sqlite "
SELECT CASE WHEN best_score=0 THEN '0' WHEN best_score<=3 THEN '1-3'
            WHEN best_score<=6 THEN '4-6' WHEN best_score<=9 THEN '7-9'
            WHEN best_score<=17 THEN '10-17' ELSE 'high' END AS bin,
       COUNT(*)
FROM theories WHERE status NOT IN ('proposed', 'criticized') GROUP BY 1"

# Per-family
sqlite3 db/theory_ledger.sqlite "
SELECT family, COUNT(*), AVG(best_score), MAX(best_score)
FROM theories WHERE status NOT IN ('proposed', 'criticized')
GROUP BY family ORDER BY AVG(best_score) DESC"

# Top scorers
sqlite3 db/theory_ledger.sqlite "
SELECT hypothesis_id, best_score, family, status, failure_reason
FROM theories WHERE best_score >= 16 ORDER BY best_score DESC"

# 6-9 band (Phase 4 input)
sqlite3 db/theory_ledger.sqlite "
SELECT hypothesis_id, best_score, family, failure_reason
FROM theories WHERE best_score BETWEEN 6 AND 9 ORDER BY best_score DESC"
```

---

## Disclaimer on language

This memo deliberately does **not** claim:
- "K4 has no signal."
- "All high scores are artifacts."
- "Family X is globally eliminated."
- "Search has been exhausted."

What it claims, with reproducibility:
- After 879 tested theories, no entry is currently in the SIGNAL (score 18–23) range.
- Every entry at score >= 16 has a documented elimination reason.
- Per-family score elevations are real but cannot be interpreted as cryptographic content until the admitted-theory conditional null is calibrated.
- The framework's safety gates have been working correctly — no false promotion of a noisy result has occurred in the audit-visible record.

---

*Authored 2026-05-04 by Claude Opus 4.7 acting as principal research engineer / epistemic auditor for the K4 Evidence Calibration and Reopening Plan, Phase 1. Source data is the live ledger at the timestamp above; reproductions of these queries against future ledgers will produce different counts as new theories accumulate.*
