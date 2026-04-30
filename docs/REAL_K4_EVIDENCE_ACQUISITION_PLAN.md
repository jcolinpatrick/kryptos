# Real-K4 Evidence Acquisition Plan

**Created:** 2026-04-30. Companion to
[`docs/REAL_K4_EVIDENCE_GAP_REGISTER.md`](REAL_K4_EVIDENCE_GAP_REGISTER.md)
and [`docs/REAL_K4_PSEUDO_CLUE_PACK_ADMISSION.md`](REAL_K4_PSEUDO_CLUE_PACK_ADMISSION.md).
Names the concrete evidence actions that would close the three
high-priority open gaps and unblock a future admission-gated bridge
campaign.

This is a **plan**, not an action. No bridge audit is run, no
pseudo-clue pack is authored, and no solver code is changed by this
document.

---

## Current research state summary

- **Bridge pipeline:** validated end-to-end across two closed null
  campaigns (`C-BRIDGE-01` broad / `C-BRIDGE-02` admission-gated).
- **Bridge campaign line:** paused per `C-BRIDGE-03` (live internal
  research status, not policy). The pause closes automatically when
  any GAP-* row in the gap register transitions out of `open`.
- **No signal exists** under either tested encoding regime. Every
  top candidate from both campaigns scored at or below the null
  expected_max for the search size and carried `bean_passed=False`
  and `ngram_score=0.0`.
- **No real-K4 progress is claimed** by any document in the bridge
  line.

## Why further bridge campaigns are paused

Two closed campaigns established the same finding: the current
evidence pool the bridge can compile against has been **exhausted at
the bridge campaign level**. Adding more packs of campaign-001 or
campaign-002 shape is anti-productive — the maximum-of-N null
threshold grows with search breadth, so additional breadth would
**raise** the bar without raising the evidence quality. A new
campaign needs new evidence first.

## Priority ordering for the three high-priority gaps

| rank | gap | first-action class | tractability | false-positive risk | corroboration potential |
|---|---|---|---|---|---|
| 1 | GAP-03 (BCL E0b operationalization) | analytical / cryptanalytic on existing data | high | low (E0b has a well-characterized null) | high |
| 2 | GAP-10 (crib-bound positional mechanism) | analytical / cryptanalytic on existing data | high | high (cribs ARE the score signal — crib-fitting risk dominates) | medium-high |
| 3 | GAP-09 (null-mask / stego evidence) | requires NEW independent observable | medium | medium (depends on rigor of the independence claim) | high |

**Recommendation:** start with GAP-03. It is the strongest currently
in-project quantified signal not yet exploited at the bridge campaign
level, the acquisition is purely analytical (no site visit, no
archival research), and the false-positive risk is the lowest of the
three. If GAP-03 closes, GAP-10 should be next; GAP-09 should be
deferred until at least one of the analytical gaps closes, because
GAP-09 alone cannot reopen bridge testing without simultaneous
analytical corroboration.

---

## GAP-03 — BCL E0b side-effect operationalization

### What "operationalization" needs to mean

Anomaly E0b (Materna 2020 / Bean 2021 §2.4) is a measured statistic
on the disclosed cribs: at the 10 of 24 disclosed-plaintext positions
where PT ∈ {K, R, Y, P, T, O, S}, the standard-alphabet distance
between PT and CT is small (mean Δ = 2.1, sum Δ = 21,
Monte Carlo p ≈ 1/5,520). Bean argues this strongly implies one-to-one
substitution with a keyword-mixed alphabet near KRYPTOS.

The bridge cannot use E0b as a side-effect predicate today because
"matches the cribs" is a tautology (E0b is **measured ON** the cribs).
To turn E0b into a side-effect predicate, we need a quantitative
statement of the form:

> "If the K4 cipher uses a keyword-mixed alphabet near KRYPTOS, then
> the candidate's recovered plaintext at the 73 NON-crib positions
> should produce a related distance statistic that has property X
> with probability at most p₀ under null Y."

The X / p₀ / Y triple is what is missing today.

### Candidate measurable side-effects beyond crib score

1. **Extended-position distance distribution.** For a candidate
   plaintext, identify all positions (across the full 97) where
   PT ∈ {K, R, Y, P, T, O, S}. Compute the standard-alphabet distance
   distribution at those positions (not just the 10 disclosed ones).
   A keyword-mixed alphabet near KRYPTOS predicts this distribution
   continues to cluster near zero. A coincidental crib match
   predicts the distribution at the 73 non-crib positions is
   indistinguishable from random.

2. **Bean equality + linear constraint behavior.** Bean's 1
   equality + 242 inequalities + 101 linear constraints are
   **variant-independent and crib-position-bound** (verified by
   `kryptos doctor`). A candidate that decrypts the cribs to the
   correct letters AND comes from a structurally correct cipher
   class must satisfy `bean_passed=True`. A coincidental decryption
   can match cribs without satisfying Bean, because Bean depends on
   the keystream values at crib positions (not just the plaintext
   letters). Bean satisfaction is therefore an INDEPENDENT
   corroboration of cipher-class correctness — non-trivially so —
   and is precisely the mechanism the bridge already supports
   (`crib_score` and `bean_passed` are separate fields).

3. **Reversed-KA mod-5 pattern (E0d adjacency).** E0d notes that
   under the **reversed Kryptos alphabet**, 13 of 24 known
   (PT − CT) mod 26 values are multiples of 5 (p ≈ 1/1,470). A
   candidate from a keyword-mixed-near-KRYPTOS hypothesis should
   either (a) preserve this mod-5 property at recovered positions,
   or (b) explicitly explain why the property is window-localized.
   Either way the prediction is testable on a candidate plaintext.

4. **Repeated-PT-letter cipher distance (E0c adjacency).** E0c notes
   that for repeated PT letters in the cribs, CT distances cluster
   small (p ≈ 1/240 — 1/310). A candidate plaintext can be measured
   on the same statistic across all 97 positions; under the
   keyword-mixed substitution hypothesis, the property should
   extend.

### Bean as corroboration

Yes — Bean equality + inequality + linear behavior is the cleanest
in-project corroboration available. The 624 Bean-valid 24-vectors
form a necessary-condition superset; only 3 (one per Vig / Beau /
VarBeau variant) are crib-valid under the disclosed plaintext
([`memory/`](../memory/) keystream forensics notes). A candidate
that achieves `crib_score >= 12` AND `bean_passed=True` is therefore
a structurally valid cipher candidate, not just a coincidental
crib match. Campaigns 001/002 both produced 0 such candidates in
the top-20.

The asymmetry the admission standard installs is exactly this:
crib_score alone is information about WHERE the cipher decrypts
correctly; `bean_passed=True` is information about WHAT cipher
class produces that decryption.

### Statistical baseline required

To use any of the candidate side-effects in 1 / 3 / 4 above, the
bridge needs a calibrated null distribution. The recommended
construction:

- **Null model:** for each candidate plaintext, replace it with
  Monte Carlo draws from a distribution that PRESERVES crib values
  exactly (i.e., the random plaintexts share the disclosed cribs
  but are otherwise random English letters). This pins the
  crib-position contribution and isolates the off-crib contribution
  to the side-effect statistic.
- **Sample size:** at least 100,000 Monte Carlo draws per side-effect
  statistic; the existing null baseline cache infrastructure
  (`scripts/_infra/calibrate_null_baselines.py`) already builds
  comparable baselines in ~18 seconds.
- **Threshold:** the project's standing p-value gate for SIGNAL
  promotion is `1e-6` ([`CLAUDE.md`](../CLAUDE.md) §"Phase 6
  p-value gate"). E0b's raw p≈1/5,520 ≈ 1.8 × 10⁻⁴ is **not** a
  free pass to the gate — the operationalized side-effect must
  reach the project's 1e-6 standard under the constructed null.

### What evidence would justify a new BCL pseudo-clue pack

A new BCL pack is admissible when:

1. The side-effect predicate is fully specified (the X / p₀ / Y
   triple above).
2. A null distribution is calibrated and committed to a
   reproducible artifact under `null_baselines/`.
3. The pack predeclares a success criterion of the form
   `crib_score >= 18 AND bean_passed=True AND <E0b-extension-statistic>
   reaches p <= 1e-6 under the calibrated null`.
4. The pack states `campaign_001_coverage: new_provenance`
   (justified by the new operationalization, not the underlying
   E0b which is already cited).

### What is **insufficient**

- A pack that re-asserts E0b as evidence without the
  operationalization triple. (Already tested in campaign 001 F4
  and campaign 002 002-03; both null.)
- A pack that uses the retired BCL palette `{B, G, I, K, O, W, Z}`.
- A pack that proposes "score better on cribs" as a side-effect
  (tautology).

---

## GAP-09 — Null-mask / stego evidence

### Admissible forms of evidence

Three evidence pathways can produce an admissible null-mask
construct:

1. **Physical-geometry-derived mask.** A null mask whose positions
   are dictated by a measured property of the sculpture (panel
   dimensions, line breaks, spacing pattern, lodestone alignment,
   etc.). The construction must be writable as a deterministic
   function of physically measured quantities, with NO step that
   uses K4's score signal as input. Strongest evidence form because
   it is genuinely independent.

2. **Independent-statistical-signal-derived mask.** A null mask
   whose positions are dictated by a statistical property of K4's
   ciphertext that is computed WITHOUT reference to crib scores or
   plaintext-shape scores. Examples: positions of repeated letters,
   positions of specific transition counts, positions matching a
   Polybius / Bifid coordinate pattern. Construction must be
   pre-registered (the rule is fixed BEFORE the score is computed).

3. **Creator-statement-derived mask.** A null mask whose positions
   are dictated by an explicit creator statement (Sanborn / Scheidt)
   that names a specific position class. Project policy treats
   creator statements as Tier-3 hearsay (`C-SANBORN-01`), so this
   pathway is admissible **only with corroborating physical or
   statistical evidence**.

### What is currently too weak

- **Score-conditioned masks.** Any mask derived by SA / IC-greedy /
  brute-force optimization on K4's score signal. The retired BCL
  palette mask was retired exactly because it failed the
  score-conditioned-null check
  (`memory/retired/bcl_palette_keystream.md`,
  `docs/a1_score_conditioned_null_report.md`).
- **Pure-letter-set masks.** A construction that selects positions
  by "letters in this set" without an independent generative
  mechanism. The `{B, G, I, K, O, W, Z}` palette was a 7-letter
  selection out of 26; the construction is mathematically
  underdetermined.
- **K4-bigram-derived masks.** The width-21 bigram anomaly (E0e)
  is a STATISTIC on K4 itself, not an independent observable. Using
  it to fix a null mask risks circularity.

### How to avoid arbitrary null-mask fitting

Three discipline rules borrowed from the admission standard:

1. **Pre-register the rule, then measure.** Write the position
   selection function FIRST, in code, with no K4 input beyond the
   ciphertext text itself (no score). Then apply.
2. **Cap free parameters at 3.** A null mask is a binary vector over
   97 positions; in principle it has 2⁹⁷ possible shapes. Any
   admissible construction must reduce this to at most 3 free
   parameters with physical or structural justification (e.g., a
   width and a row-selection rule + 1 offset).
3. **Demand independent observable.** The mask must align with at
   least one independent observable (a registered anomaly position,
   a sculpture feature, an IC drop in a specific window). The
   alignment must be tested statistically against a permutation
   null.

### Required side-effect predictions

A null mask hypothesis must predict at least one of:

- **Bean reduction at non-null positions.** Removing the predicted
  null positions and re-running Bean checks should produce a
  measurable structural change (Bean residue should hold on the
  reduced 97 − N character text, or fail in a structurally
  consistent way).
- **N-gram floor on extracted plaintext.** The extracted (97 − N)
  -character plaintext, when decrypted under the candidate cipher,
  should score `ngram_score >= -8` (project noise floor).
- **Anomaly co-location.** The null positions should align with
  at least one registered anomaly position in
  [`docs/anomaly_registry.md`](anomaly_registry.md) (e.g., YAR
  letters, the `?` marks, the panel line breaks). Alignment
  measured by a permutation null.

### Acceptable degrees of freedom

| construction class | acceptable DoF | reason |
|---|---|---|
| fully predicted from independent rule | 0 | strongest — no fitting possible |
| 1-parameter family | 1 | acceptable if parameter has an external anchor (e.g., a single sculpture dimension) |
| 2-3-parameter family | 2-3 | acceptable only with a multiple-testing correction in the side-effect null |
| 4+ parameter family | 0 (rejected) | overfitting territory |

### Why GAP-09 is NOT the first action

Closing GAP-09 requires a new independent observable, which means
either physical site work, archival measurement, or a fresh
statistical signal computed without reference to scoring. None of
those is purely analytical, and none of them is on the immediate
critical path for closing the bridge campaign pause. Defer until
GAP-03 closes; the GAP-03 work may generate the structural insight
needed to constrain GAP-09's solution space.

---

## GAP-10 — Crib-bound positional mechanism evidence

### Known crib spans and positional constraints

- **EAST** at 21 — 24 (4 letters)
- **NORTHEAST** at 25 — 33 (9 letters), compounding to **EASTNORTHEAST**
  at 21 — 33 (13 letters)
- **BERLIN** at 64 — 69 (6 letters)
- **CLOCK** at 70 — 74 (5 letters), compounding to **BERLINCLOCK**
  at 63 — 73 (11 letters; note the 1-position overlap into 63 with
  some readings)
- 24 known plaintext positions, 73 unknown.
- **Gap region:** positions 34 — 62 (29 unknown chars between cribs)
  and 74 — 96 (23 unknown chars after cribs), plus 0 — 20 (21
  unknown chars before cribs).

### Possible position-derived mechanisms

1. **Residue-class substitution.** If the cipher is a periodic
   polyalphabetic with period P, the cribs' positions modulo P
   determine which alphabet ROWS are constrained. The Bean linear
   constraint set already encodes the variant-independent
   relationships; a new analytical extension would test whether
   any specific period produces residue-class structure that
   matches the crib pattern.

2. **Gap-region IC analysis.** Compute IC on the 73 unknown
   positions and on each gap segment (0—20, 34—62, 74—96). If a
   specific period emerges in the IC signal, that period
   constrains the cipher class. The IC signal must clear a
   permutation null because IC on a 97-character text has wide
   variance.

3. **Cross-boundary structural change.** Compute window statistics
   (IC, repeated bigrams, letter-class distribution) sliding
   across the crib boundaries. A sudden change at the crib edges
   would suggest a positional mechanism (e.g., a key change or a
   layer boundary).

4. **Bean residue-class refinement.** The Bean linear constraint
   set has 101 entries; some may impose residue-class structure
   that constrains the period of any periodic cipher. Analytical
   work could derive new bounds (e.g., "if period P, residue-class
   r is over-determined") that refine which periods are admissible.

### Why crib hits alone are insufficient

The cribs are the score signal. A coincidental decryption that
matches cribs by chance can score `crib_score = 24` while still
being structurally invalid as a cipher (Bean fails, ngram fails,
the off-crib plaintext is junk). Campaign 001 produced
`crib_score = 5` with `bean_passed = False, ngram_score = 0` —
the simplest case of the failure mode.

The asymmetry: structural correctness IMPLIES crib hits;
crib hits do NOT imply structural correctness. So crib hits cannot
be the only evidence the bridge tests against — they have to be
paired with a side-effect that has independent constructional logic.

### Required side-effect predictions

A crib-bound positional mechanism pack must predict at least one of:

- **Bean equality + linear satisfaction.** Beyond simple
  `bean_passed=True`, predict a specific Bean linear constraint
  whose **residual** (numerical satisfaction tightness) improves
  measurably under the hypothesis. E.g., "constraint #42 is
  satisfied with margin >= 0.8 under hypothesis H, vs <=0.3 under
  random."
- **Gap-region ngram floor.** The 73 non-crib positions, when
  decrypted, should score above the random-English noise floor
  (`ngram_score >= -8` or a similar well-defined threshold).
- **Position-resolved residue match.** If the hypothesis is
  period-P substitution, predict that the disclosed cribs' Bean
  values match a specific residue-class pattern; corroboration is
  the off-crib positions' decryptions matching the same pattern.

### How to avoid crib-fitting

Same discipline rules as GAP-09 plus one specific to GAP-10:

- **Pre-declare the period / mechanism BEFORE inspecting the cribs'
  Bean values.** If the period or mechanism is selected by looking
  at which value "best fits" the cribs, the test is circular.
- **Use the gap regions as the corroboration surface.** The gap
  regions are unknown, so any structural prediction tested there
  is independent of the score.
- **Apply multiple-testing correction.** If the analysis sweeps
  periods 2 — 26, the per-period p-value must be Bonferroni-corrected
  by 25.

### Should GAP-10 be the first gap attacked?

**No.** GAP-10 should be SECOND. Its tractability is comparable to
GAP-03's, but its false-positive risk is materially higher because
the cribs are simultaneously the only score signal AND the only
source of evidence for the position-derived mechanism. Closing
GAP-03 first establishes a working pattern for evidence
operationalization on the same data, and any cross-cutting
techniques (extended-position MC nulls, side-effect statistic
calibration) carry over to GAP-10.

---

## Decision table

| gap_id | next evidence action | required artifact | sufficient-to-reopen condition | likely bridge pack count | priority | est. false-positive risk |
|---|---|---|---|---|---|---|
| GAP-03 | Define and calibrate an extended-position E0b distance side-effect statistic; compute the null distribution under the crib-pinned random-plaintext model | a reproducible script under `scripts/_infra/` (or `scripts/statistical/`) that takes a candidate plaintext and returns (statistic, p-value); a calibration JSON committed under `null_baselines/` | the side-effect statistic clears the project's 1e-6 SIGNAL gate on at least one published candidate plaintext family AND `bean_passed=True` is co-required by the pack's predeclared success criterion | 1 — 2 packs | **1 (highest, recommended first action)** | low |
| GAP-10 | Compute Bean linear residue-class structure for periods 2 — 26 with multiple-testing correction; compute gap-region IC permutation null; compute cross-boundary statistical change tests | a reproducible analysis under `scripts/analysis/` or `scripts/statistical/` producing per-period p-values and a chosen period (or "no admissible period") | one period clears the Bonferroni-corrected gate AND a derived side-effect predicate (Bean residue or gap-region ngram) is testable in the bridge | 1 — 3 packs | 2 | high |
| GAP-09 | Identify or measure an independent-of-score null-mask construct; pre-register the position-selection function; test alignment against a permutation null | a written construction (in code, ≤3 parameters), an alignment test result, and a side-effect prediction for Bean reduction or anomaly co-location | the alignment test reaches p <= 1e-6 against an appropriate permutation null AND the construction itself uses zero K4-score input | 1 — 2 packs | 3 (defer until GAP-03 closes) | medium |

---

## Recommended first action

Begin GAP-03 work. Specifically:

1. Author a **statistical analysis script** (NOT a pseudo-clue
   pack, NOT a bridge audit) under `scripts/statistical/` or
   `scripts/_infra/` that:
   - takes a candidate 97-character plaintext as input
   - identifies positions where PT ∈ {K, R, Y, P, T, O, S}
   - computes the standard-alphabet distance to the carved CT at
     those positions
   - returns (mean_distance, sum_distance, count, p_value_under_null)
2. Author a **null calibration** that produces the null
   distribution under the crib-pinned random-plaintext model
   (preserve crib values exactly, randomize off-crib).
3. Validate the calibration on the disclosed cribs themselves
   (the script should reproduce Bean's measured p ≈ 1/5,520).
4. Persist the calibration under `null_baselines/` with a manifest
   entry.
5. Update the gap register: `GAP-03` status → `partially_closed`
   with a back-reference to the analysis script.
6. Only THEN consider authoring the next bridge pack against the
   newly-operationalized side-effect.

Steps 1 — 4 are purely analytical, take perhaps an hour of focused
work, and produce a reproducible artifact. The bridge pack work
(step 6) is gated on the calibration completing successfully.

---

## Risks of false positives

- **GAP-03 risk:** the extended-position statistic could itself be
  underpowered if the off-crib KRYPTOS-set positions are too few
  to discriminate. The first action's step 3 (calibration on the
  disclosed cribs) is the test that catches this.
- **GAP-10 risk:** highest of the three. The cribs are
  simultaneously the score signal and the evidence basis. Any
  technique that derives a "promising" period from the cribs and
  then tests at the cribs is circular. The mitigation
  (gap-regions as corroboration surface) is mandatory, not optional.
- **GAP-09 risk:** medium. The hardest discipline is verifying that
  "independent of K4 score" actually holds — the construction must
  be writable as a function of physical or pre-registered
  statistical inputs only. If the construction implicitly conditions
  on the bigram anomaly or any other K4-derived statistic, it is
  not independent.

---

## Do not do

- **No broad pseudo-clue campaign.** Campaign 001 was the broad
  campaign; it closed null. Campaign 002 was the disciplined
  campaign; it also closed null. The next action is evidence
  acquisition, not pack authoring.
- **No arbitrary keys.** Every keyword in any future pack must
  cite specific provenance (admission rule R4).
- **No arbitrary source texts.** Running-key / book-cipher
  hypotheses without a specific repo-cited source-text identification
  remain inadmissible (admission rule R5).
- **No pack without a side-effect prediction.** Every future pack
  must predict at least one observable beyond crib score
  (admission rule R7). The acquisition plan above defines the
  operationalization for the side-effect, not its absence.
- **No null-result recycling.** A pack whose only justification is
  "campaign 001/002 didn't try this exact combination" is not
  admissible. The justification must be **new evidence**, not
  **un-tried encoding**.
- **No K4Bench lesson extraction unless a real-K4 evidence gap
  motivates it.** K4Bench is a synthetic calibration suite. Lessons
  extracted from K4Bench are validated for the synthetic challenge
  family they came from. They do not transfer to real K4 unless a
  real-K4 evidence gap explicitly maps onto the lesson's mechanism
  AND the admission standard is satisfied separately.

---

## Update procedure

When a gap closes (or partially closes) by acquisition action, the
gap register
[`docs/REAL_K4_EVIDENCE_GAP_REGISTER.md`](REAL_K4_EVIDENCE_GAP_REGISTER.md)
should be updated FIRST (status field on the row), and this plan
should be updated to record the closing action and back-reference
the artifact. The bridge campaign pause `C-BRIDGE-03` in
`docs/claims_registry.json` automatically closes when any GAP row
transitions out of `open`.
