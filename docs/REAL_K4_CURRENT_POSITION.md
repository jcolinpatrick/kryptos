# Real-K4 Current Research Position

**Date:** 2026-04-30. Authoritative status report on the real Kryptos
K4 research position at this commit. This document is the entry
point if you want one short, rigorous read on what the project can
do, what it cannot, what it has shown, and why broader search is
not a rational next step.

Companion documents:
- [`docs/REAL_K4_EVIDENCE_GAP_REGISTER.md`](REAL_K4_EVIDENCE_GAP_REGISTER.md) — open evidence gaps
- [`docs/REAL_K4_EVIDENCE_ACQUISITION_PLAN.md`](REAL_K4_EVIDENCE_ACQUISITION_PLAN.md) — what to do next, in priority order
- [`docs/REAL_K4_PSEUDO_CLUE_PACK_ADMISSION.md`](REAL_K4_PSEUDO_CLUE_PACK_ADMISSION.md) — admission standard for any future bridge pack
- [`docs/claims_registry.json`](claims_registry.json) — structured claims (`C-BRIDGE-01`, `C-BRIDGE-02`, `C-BRIDGE-03`, `C-SANBORN-01`, `C-SANBORN-02`)

---

## 1. Executive summary

KryptosBot has matured into a **deterministic hypothesis-testing
platform**, not a magic K4 solver. It compiles bounded structured
hypotheses into hand-cipher specs, dispatches them reproducibly,
and reports null-calibrated outcomes. It does not infer missing
operational clues, search arbitrary source texts meaningfully, or
convert vague public commentary into a cipher mechanism.

The project's empirical record is consistent: every real-K4 audit
and every bridge campaign run on currently-available public
evidence has closed at **null_level**. The bridge pipeline is
validated; the **evidence pool the bridge can compile against is
exhausted at this commit**.

**No K4 solution is claimed. No real-K4 progress is claimed at this
date. K4 is NOT proven impossible — it is judged underdetermined
from public evidence as currently held by this project.**

Future progress requires new admissible evidence — measurement,
provenance, or mechanism specificity — closing at least one row in
the evidence gap register. Adding more pseudo-clue packs without
new evidence is anti-productive: the maximum-of-N null threshold
grows with search breadth, so more packs of the same shape raise
the bar without raising the evidence quality.

---

## 2. Current capability surface

### 2.1 Hand-Cipher Core (HCC) and DSL

A typed hypothesis specification language (`kryptosbot/hypothesis_dsl.py`)
plus a deterministic catalog generator (`kryptosbot/hand_cipher_core.py`)
produce a finite, reproducible spec catalog from each registered
mechanism family. The DSL covers nine kinds at this commit:
`vigenere`, `beaufort`, `variant_beaufort`, `caesar`, `columnar`,
`rail_fence`, `route_boustrophedon`, `route_diagonal`,
`route_diagonal_canonical`, `row_reverse`, `reverse_blocks`,
`skip_route`, plus procedural / grille / polybius translators added
in maturation R3.5.

### 2.2 Job dispatcher

`kryptosbot/job_dispatcher.py` executes specs through the kernel,
applies admissibility and exhaustion gating with explicit override
justification, and surfaces structured `JobResult` objects with
audit-grade verdicts. Workers do not run free-form Claude calls in
the post-R3 control flow — all dispatches go through the dispatcher.

### 2.3 K4Bench curriculum

`bench/k4bench/` is a synthetic calibration suite with 25 K4-shaped
challenges. Lessons through LESSON-022 (independent-keyword
rail-fence three-role) built and validated capabilities for layered
substitution + transposition composition, route variants, block
reversal, numeric Caesar promotion, and stratified scheduling. All
lessons are validated against synthetic challenges with sealed
answers; sealed-answer text never reaches controller paths
(`kryptosbot/bench_loader.py` rejects answer-keyed JSON at load).

### 2.4 Real-K4 interpretive bridge

`kryptosbot/real_k4_*.py` implements the LLM↔HCC bridge:

- `real_k4_pseudo_clue_pack.py` — schema for structured pseudo-clue
  packs with provenance, role hints, numeric roles, operation
  hints, composition templates, bounds, and caveats.
- `real_k4_pseudo_clue_compiler.py` — deterministic compilation of
  packs into HCC specs, with template routing to the existing
  family generators.
- `real_k4_bridge_audit.py` — orchestrator: load packs, compile,
  dispatch, score against public cribs, run null calibration, emit
  audit artifact with full provenance.
- `real_k4_clue_registry.py` — project-safe v2 clue registry across
  five evidence tiers (core public cribs / K1-K3 legacy /
  sculpture context / geodetic / procedural).

### 2.5 Null calibration

`real_k4_audit.compute_null_baseline` builds an analytical Binomial
null over candidate count, classifies each campaign as
`null_level` / `interesting` / `breakthrough` against three
thresholds (`null_level_p_min=0.05`, `interesting_p_max=0.05`,
`breakthrough_p_max=0.001`), and stamps the run with an explicit
non-claim banner. The non-claim banner is mandatory; promotion to
`candidate_pending_external_evaluator` requires the gate to fire
(`p ≤ 0.001`).

### 2.6 Evidence and claims registries

- `kryptosbot/real_k4_clue_registry.py` — keywords with provenance.
- `docs/claims_registry.json` — structured project claims; current
  count 15, including the bridge campaign records and Sanborn
  doctrine.
- `docs/REAL_K4_EVIDENCE_GAP_REGISTER.md` — ten open evidence gaps
  with admission-grade closure conditions.
- `docs/REAL_K4_PSEUDO_CLUE_PACK_ADMISSION.md` — eleven-rule
  admission standard, validator at
  `scripts/_infra/validate_pseudo_clue_pack_admission.py`.

---

## 3. What KryptosBot can do

- **Compile bounded mechanisms.** Given a structured pack with
  provenance-cited keywords, numeric roles, operation hints, and
  composition templates, the bridge produces a deterministic finite
  spec catalog — typically tens to hundreds of specs per pack.
- **Dispatch reproducibly.** Every spec runs through the same
  dispatcher with the same exhaustion override, the same scoring
  surface, and the same provenance stamping. Two runs produce
  identical artifacts.
- **Test crib alignment.** Each candidate plaintext is scored
  against the disclosed cribs (`crib_score` 0 — 24) with explicit
  Bean-equality and Bean-inequality tracking
  (`bean_passed=True / False`).
- **Preserve provenance.** Every emitted spec carries the source
  pack's `pack_id` and `evidence_tier` in its coverage extras.
  Audit artifacts include per-pack rollups and top-N candidate
  detail with mechanism, layer order, role assignment, and
  plaintext prefix.
- **Quantify null-level results.** The analytical Binomial null
  produces a `p_value_for_observed_max` against an explicit model
  whose assumptions are documented in the artifact. Null-level
  campaigns are marked as such in both the artifact and the
  registry.
- **Reject weak hypotheses.** The admission standard's mechanical
  validator rejects packs that lack provenance specificity,
  side-effect predictions, coverage statements, or predeclared
  success criteria. Schema-valid but admission-failing packs are
  blocked at authoring time.
- **Quickly test new evidence if it becomes admissible.**
  Authoring a new pack from a closed gap row is a two- to
  five-file edit; running the bridge audit takes seconds.

---

## 4. What KryptosBot cannot do

- **Infer missing operational clues.** The bridge does not invent
  cipher mechanisms; it tests structured hypotheses an author
  composed from cited evidence. If the evidence does not specify
  the mechanism, the bridge cannot "guess" it.
- **Search arbitrary source texts meaningfully.** Running-key and
  book-cipher hypotheses without specific source-text identification
  collapse to arbitrary keys, which the admission standard
  forbids (rule R5).
- **Convert vague public comments into mechanism.** Per
  `C-SANBORN-01` and `C-SANBORN-02`, non-crib public statements
  are Tier-3 contextual hearsay and may not directly trigger HCC
  roles, keywords, numeric parameters, or composition templates
  without independent measurable evidence and a predeclared
  side-effect prediction.
- **Prove global impossibility.** No null result, however clean,
  proves a cipher family or evidence family is impossible. Null
  results reject specific encodings at specific search breadths.
  This is operational language, not metaphysical.
- **Bypass underdetermination.** When public evidence does not
  fix a mechanism, no amount of search engineering can recover
  that mechanism from public data alone. The right response is
  evidence acquisition, not search expansion.

---

## 5. Summary of empirical results

### 5.1 K4Bench — capability validation

K4Bench challenges through LESSON-022 are individually solved or
formally deferred with documented post-mortems
(`bench/k4bench/CURRICULUM_STATUS.md`). The most recent solve
recorded in project memory is K4B-010 (Needle group reversal,
crib_score 24/24 with `reverse_blocks_variant_beaufort`,
`project_k4b010_solved_by_existing_capability_2026_04_29.md`).
**This validates the platform's capability on synthetic K4-shaped
challenges; it is NOT real-K4 progress.**

### 5.2 Real-K4 HCC audit (bootstrap fixture run)

`results/real_k4_hcc_bridge_audit/audit_001.json` (regenerable):
the four bootstrap fixture packs produced 282 specs, max_crib=5/24,
expected null max=4.47, p(max≥5)=0.421. Null-level. Validated the
bridge end-to-end against real-K4 cribs.

### 5.3 Bridge campaign 001 — broad Team-of-Rivals (`C-BRIDGE-01`)

31 packs across 7 hypothesis families (public crib geometry;
Sanborn/Scheidt two-systems; Stehle anomaly; BCL Beaufort;
width-21 vertical bigrams; NDYAHR/YAR shifts; K2/K3 analogy).
1,730 candidates compiled, dispatched, and scored in 9.6 seconds.
**max_crib = 5 / 24, expected null max = 5.35, p(max ≥ 5) = 0.965,
classification = null_level**. No top-20 candidate passed Bean or
had ngram > 0. Closure note:
[`data/real_k4_pseudo_clue_packs/campaign_001_team_of_rivals/CLOSURE.md`](../data/real_k4_pseudo_clue_packs/campaign_001_team_of_rivals/CLOSURE.md).

### 5.4 Bridge campaign 002 — admission-gated micro (`C-BRIDGE-02`)

3 packs, each `tightened` from a campaign-001 family (Stehle F3-31,
width-21 F5-51, BCL Variant Beaufort F4-43), each with a
predeclared side-effect prediction at `crib_score ≥ 12`. 30
candidates compiled, dispatched, and scored in 0.2 seconds.
**max_crib = 1 / 24, expected null max = 3.24, p(max ≥ 1) ≈ 1.0,
classification = null_level**. Histogram is degenerate at scores
{0:15, 1:15} — no candidate reached crib_score 2. All three
side-effect predictions are **unfired** (no candidate reached the
activation threshold). Closure note:
[`data/real_k4_pseudo_clue_packs/campaign_002_admission_gated_micro/CLOSURE.md`](../data/real_k4_pseudo_clue_packs/campaign_002_admission_gated_micro/CLOSURE.md).

### 5.5 No signal, no progress claim

Every real-K4 campaign run by this project is null. The bridge
pipeline is validated; the current evidence pool the bridge can
compile against is **exhausted at the bridge campaign level**.
**`C-BRIDGE-03`** records this as a live internal research status:
the campaign line is paused pending new admissible evidence. The
pause is not a project-wide policy; it is a research observation
about what the bridge can usefully do RIGHT NOW given the current
evidence pool.

---

## 6. Why public-data-only K4 is underdetermined

K4 is 97 ciphertext characters. The disclosed cribs cover 24 of
those positions (EAST 21 — 24, NORTHEAST 25 — 33, BERLIN 64 — 69,
CLOCK 70 — 74, with compounds EASTNORTHEAST 21 — 33 and
BERLINCLOCK 63 — 73). The remaining 73 positions are unknown
plaintext. From a public-evidence standpoint, the underdetermination
is structural:

1. **97 characters is short**. Statistical signatures (IC,
   Kasiski, periodicity tests) on 97 chars are noisy. K4's IC ≈
   0.0361 is below random (0.0385), but the FRAC agent showed the
   deviation is **not statistically significant** at length 97
   ([`docs/research_questions.md`](research_questions.md), E-FRAC-04).
   Many otherwise-discriminating tests are underpowered at this
   length.
2. **24 of 97 positions are partial constraints, not the
   mechanism.** Bean's 1 equality + 242 inequalities + 101 linear
   constraints derived from the cribs are **necessary** for
   structural cipher correctness but not **sufficient** — 624
   distinct Bean-valid 24-vectors exist; only 3 are crib-valid
   under the disclosed plaintext (one per Vig / Beau / VarBeau
   variant). The cribs **verify** a candidate; they do not
   **identify** the cipher.
3. **Many degrees of freedom remain.** Possible nulls / stego
   masks, possible source texts (running-key candidates), possible
   composition layers (single, two-layer, three-layer), possible
   alphabet keywords, possible widths, depths, periods, and
   shifts. Each axis is bounded by the admission standard, but the
   product of axes is large enough that random configurations
   produce coincidental crib hits with non-trivial probability —
   exactly what the null calibration measures.
4. **Coincidental crib matches are common.** The Binomial null
   over 1,730 candidates predicts an expected max crib score of
   5.35; campaign 001 observed 5. With 30 candidates the expected
   max drops to 3.24; campaign 002 observed 1. Coincidental match
   probability rises with search breadth, which is precisely why
   the admission standard demands corroborating side-effects.
5. **Public comments lack operational specificity.** Sanborn /
   Scheidt non-crib commentary ("two systems", "masked English",
   "stego", and similar) is Tier-3 hearsay. The phrases admit
   multiple mutually-incompatible structural interpretations
   (see GAP-06 in the gap register); without a specific structural
   commitment plus independent corroboration, the bridge cannot
   convert them into a non-arbitrary pack. Campaign 001 family F2
   (5 packs, 630 specs) tested several such interpretations and
   was null.
6. **Cribs verify the mechanism, they do not identify it.** This
   is the core asymmetry: structural correctness IMPLIES crib
   hits; crib hits do NOT imply structural correctness. The
   admission standard's rule R7 (predicted side-effect beyond
   crib score) is the operational response to this asymmetry.

These six properties combined mean that **public-data-only K4 is
underdetermined**. This is a property of the available evidence,
not a property of K4 itself, and not a claim that K4 is impossible.

---

## 7. Research doctrine going forward

- **No more broad pseudo-clue campaigns.** Campaign 001 was the
  broad campaign. It closed null. Campaign 002 was the
  disciplined campaign. It also closed null. The next move is not
  another search.
- **No bridge campaign without a GAP row transitioning via new
  evidence.** Per `C-BRIDGE-03`, the campaign line is paused. A
  GAP-* row in the evidence gap register must move out of `open`
  status by new admissible evidence before a new campaign opens.
- **No arbitrary keys / source texts.** Admission rules R4 and R5
  are absolute. Each keyword and each source-tape segment requires
  specific provenance. "Common English words" and "thematic
  keywords" pools are forbidden.
- **No progress claim from `max_crib` alone.** Without
  `bean_passed=True` and / or non-trivial ngram support, a high
  crib_score is a coincidental decoding of the disclosed
  positions. The non-claim banner is mandatory.
- **Side-effect prediction required.** Admission rule R7 demands a
  predicted observable beyond crib score (Bean constraint
  behavior, anomaly alignment, ngram floor improvement, position
  consistency, null-mask / route geometry prediction, or
  independent observable in the anomaly registry). A pack without
  a side-effect prediction is not admissible.
- **Sanborn doctrine.** Per `C-SANBORN-01` and `C-SANBORN-02`,
  non-crib public comments are contextual provenance only. They
  may supply weak contextual priors but must not directly trigger
  HCC roles without independent measurable evidence and a
  predeclared side-effect prediction. Confirmed crib disclosures
  remain admissible as PUBLIC FACT.

---

## 8. Evidence required to reopen testing

From the evidence gap register, ranked by tractability and value
(see [`docs/REAL_K4_EVIDENCE_ACQUISITION_PLAN.md`](REAL_K4_EVIDENCE_ACQUISITION_PLAN.md)
for the priority ordering and recommended first action):

- **GAP-03 — BCL E0b side-effect operationalization (HIGH, first
  action).** Define a quantitative extended-position E0b distance
  statistic and calibrate its null distribution. Acquisition is
  purely analytical, requires no new primary source, and validates
  by reproducing Bean's measured `p ≈ 1/5,520` on the disclosed
  cribs.
- **GAP-09 — null-mask / stego evidence (HIGH).** Identify or
  measure an independent-of-score null-mask construct. Three
  admissible evidence pathways: physical-geometry-derived,
  independent-statistical-signal-derived, or
  creator-statement-derived (admission rule 11 only). At most
  three free parameters with physical or structural justification.
- **GAP-10 — crib-bound positional mechanism (HIGH).** Compute
  Bean linear residue-class structure for periods 2 — 26 with
  multiple-testing correction; gap-region IC permutation null;
  cross-boundary statistical change tests. Crib-fitting risk is
  high; gap-regions (positions 0 — 20, 34 — 62, 74 — 96) are the
  corroboration surface.
- **GAP-04 — NDYAHR / YAR spatial measurement (LOW).** Quantitative
  spatial data on the YAR / DYARO superscript: precise vertical
  displacement, panel-relative coordinates, presence on Antipodes.
- **GAP-05 — physical sculpture geometry (LOW).** Measured
  physical geometry that predicts a SPECIFIC cipher parameter and
  ties that parameter to a compilable mechanism.
- **GAP-07 — archival source-text provenance (MEDIUM).** A
  specific repo-cited source-text candidate with bounded segment
  and bounded offset hypothesis. Project-safe candidate pool is
  `reference/` (Carter, Sanborn correspondence, NSA, Scheidt
  dossier).

The remaining gaps (GAP-01 Stehle measurement, GAP-02 width-21
vs CT73 contradiction, GAP-06 Sanborn public-comment provenance,
GAP-08 K2/K3 analogy limits) are open but lower priority. See
[`docs/REAL_K4_EVIDENCE_GAP_REGISTER.md`](REAL_K4_EVIDENCE_GAP_REGISTER.md)
for full table.

---

## 9. Recommended next actions

1. **Freeze solver development except bug fixes.** The HCC,
   dispatcher, bridge, and admission standard are validated.
   Adding new cipher primitives or HCC families now would expand
   the search surface without raising evidence quality — exactly
   the failure mode the campaign pause is meant to prevent. Bug
   fixes (with tests) remain in scope; new family work does not.
2. **Maintain K4Bench as a regression suite.** K4Bench lessons
   through LESSON-022 are validated; new lessons should be added
   only when a real-K4 evidence gap motivates them (`feedback_hcc_only_seeds_not_degraded_fallback.md`).
   Treat K4Bench as the standing fitness check that protects the
   platform's correctness.
3. **Focus on evidence acquisition.** Begin GAP-03 per the
   acquisition plan: author the extended-position E0b statistic,
   calibrate its null, validate against Bean's measurement, and
   commit the calibration artifact under `null_baselines/`. Steps
   are purely analytical; no bridge audit is required.
4. **Produce external-facing methodology / report.** This document
   is one such artifact; the public site
   ([kryptosbot.com](https://kryptosbot.com)) and the GitHub
   README should reflect the same posture: KryptosBot is a
   hypothesis-testing platform, current public evidence is
   insufficient for a credible K4 solve, and the project is
   actively documenting what would change that.
5. **Only reopen the bridge when admissibility criteria are met.**
   When a GAP row transitions out of `open` by new admissible
   evidence, author one or two pseudo-clue packs that satisfy
   admission rules 1 — 11. Run the bridge audit. Record the
   outcome under `C-BRIDGE-NN`. Do not reopen on weaker grounds.

---

## 10. Non-claim statement

- **No K4 solution is claimed by this project at this commit.**
- **No real-K4 progress is claimed at this date.** Both bridge
  campaigns closed at `null_level`; no top candidate carried Bean
  or ngram corroboration; the run-level classification on every
  audit remained `interpretive_pipeline_test`.
- **K4 is NOT proven mathematically impossible.** Null results
  reject specific encodings at specific search breadths; they do
  not foreclose mechanism families that have not been tested or
  evidence that has not been acquired.
- **Public-data-only K4 is currently judged underdetermined and
  not practically feasible to solve from this evidence pool
  alone.** This is a research-posture observation about the
  available evidence — it is not a claim about K4 itself, not a
  claim that solution is hopeless, and not a permanent project
  state. It changes when the evidence changes.

---

*Authored 2026-04-30 by Claude Opus 4.7 + Colin Patrick.
Authoritative status report at this commit. Update when a GAP row
closes or a new bridge campaign opens.*
