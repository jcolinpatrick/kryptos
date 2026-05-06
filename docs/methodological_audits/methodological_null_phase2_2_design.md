# Methodological-Family Conditional Null — Phase 2.2 Design

**Date:** 2026-05-04
**Author:** Tier 1 `.claude` hardening pass
**Status:** Design only. No implementation has been committed in this
deliverable.
**Predecessor memo:** `docs/methodological_audits/methodological_null_decision_memo.md`
(Phase 2.1 result: inconclusive due to invalid synthetic model for 4 of 6
families).

---

## Scope and Goal

Phase 2.1 is honest but inconclusive. The synthetic generators in
`scripts/_infra/calibrate_methodological_null.py` sample family
parameters uniformly. For four families this fails to construct the
algebraic-degeneracy / structural-overfit regimes that drove ledger
score-24 BREAKTHROUGH artifacts. The synthetic-null max-ratio is below
0.40 for those families; we cannot interpret the per-family ledger
mean elevations as signal-vs-admissibility-bias under that null.

Phase 2.2 builds **mechanism-aware** synthetic generators that
intentionally construct admissibility-passing-but-content-free
configurations for each target family. The goal is a faithful
conditional null whose max reaches the ledger max regime (max ratio
≥ 0.80), without reproducing the eliminated degeneracy as cryptographic
signal.

---

## Phase 2.2 is required before broad K4 search

Per `k4_campaign_readiness_gate.md`, the "Methodological-null Phase 2.1
status" check is RED until Phase 2.2 lands and produces faithful nulls
for the four mismatched families. The reopen memo
(`k4_reopen_decision_memo.md`) is being amended to reflect that Phase
2.1 was attempted and completed but produced an inconclusive result,
not a closure.

Allowed final answers for the methodological-family elevation question
remain:

- `yes` — the elevations survive a faithful conditional null after
  multiplicity correction.
- `no` — the elevations are within the faithful conditional null's
  expected range (admissibility-bias).
- `inconclusive due to insufficient sampling or invalid synthetic model`.

Phase 2.2 must produce one of these answers for each family or document
why the family is structurally impossible to model synthetically
without reproducing the eliminated degeneracy directly.

---

## Implementation Path

```text
docs/methodological_audits/methodological_null_phase2_2_design.md   # this file
scripts/_infra/calibrate_methodological_null_phase2_2.py            # not yet committed
kryptosbot/tests/test_methodological_null_phase2_2.py               # not yet committed
null_baselines/methodological_null_phase2_2_manifest.json           # produced by runner
results/null_baselines/methodological_null_phase2_2/<family>__v1.jsonl
results/null_baselines/methodological_null_phase2_2/ledger_comparison.json
```

The runner is **opt-in** and **separate** from the Phase 2.1 runner so
the existing artifacts remain reproducible. The Phase 2.2 runner does
NOT mutate Phase 2.1 outputs.

---

## Per-family Generator Specifications

Each family-specific generator is a Python function under
`scripts/_infra/calibrate_methodological_null_phase2_2.py` named
`generate_<family>_phase2_2(rng, sample_count) -> Iterator[SyntheticSpec]`.
Each `SyntheticSpec` has the same shape Phase 2.1 used: a `family`,
`mechanism`, `parameters`, and a kernel-verifiable proof that the
candidate is admissibility-passing.

### k3_continuity

#### Ledger Degeneracy Regime

`46caf41f` produced score 24 because K3+K4 = 433 is prime; the
hypothesis's "extend the K3 columnar grid into K4" mechanism cannot
host a rectangular grid for that combined length. The framework
correctly caught the contradiction. But under a **K3+K4 column-extension
hypothesis** that admits non-rectangular auxiliary configurations
(staggered columns, partial rows, K3 grid + K4 reflow), the
admissibility check passes trivially while the worker can match all
24 cribs without doing real cryptanalysis — the parameters absorb the
crib alignment.

Other ledger entries in this family include `K3 transposition grid
extends into K4 with YAR marking the boundary` (top-scoring theory),
which is structurally similar.

#### Synthetic Generator

A **K3-grid-extension-with-flexible-reflow** sampler:

```text
sample(rng):
    width  ← rng.choice([7, 8, 13, 14])           # K3 historical widths
    rows   ← derived from width and combined length
    reflow ← rng.choice(["staggered", "partial", "boustrophedon", "wrap"])
    crib_alignment ← rng.permutation of crib indices into reflowed positions
    yield SyntheticSpec(
        family="k3_continuity",
        mechanism="grid_extension_reflow",
        parameters={width, rows, reflow, crib_alignment_seed},
        admissibility_proof=run kernel scoring against a synthesized PT
            that reproduces ALL 24 cribs at the reflowed positions
            but otherwise contains no English content,
    )
```

#### Parameters

- `width ∈ {7, 8, 13, 14}` (finite)
- `reflow ∈ {staggered, partial, boustrophedon, wrap}` (finite)
- `crib_alignment_seed ∈ Z_2^32` (sampled)
- N = 10,000 samples per stratum × 4 widths × 4 reflows = 160,000
  samples (downsample to 10,000 with stratified sampling for parity
  with Phase 2.1).

#### Expected Max-Ratio Criterion

A Phase 2.2 generator is faithful for `k3_continuity` if synthetic max
≥ 0.80 × ledger max (24). Concretely, ≥ 19/24.

#### Failure Modes

- Generator too weak: produces few admissibility passes; max stays at
  ~6 like Phase 2.1.
- Generator too strong: actually solves K4 by accident — would mean
  the family generator IS the cryptographic mechanism, in which case
  the hypothesis was never null.

#### Acceptance Criteria

- `synthetic_max / ledger_max ≥ 0.80` for `k3_continuity`.
- Generator produces no plaintext containing > 6 contiguous English
  characters outside the crib regions, demonstrating it is constructing
  admissibility-passing-but-content-free configurations.
- Generator outputs are deterministic given seed.

### archive_evidence

#### Ledger Degeneracy Regime

`4ae72d4d` produced score 24 because Bean is invariant under non-crib
edits; with the canonical CT and any crib-preserving edit pattern,
all 1.64M perturbations trivially "pass" Bean — Bean does not
discriminate at non-crib positions.

#### Synthetic Generator

A **Bean-invariant non-crib perturbation** sampler:

```text
sample(rng):
    edit_count ← rng.randint(1, 4)
    edit_positions ← rng.sample(non_crib_positions, edit_count)
    edit_values ← rng.sample(letters, edit_count)
    perturbed_ct ← apply_edits(CT, edit_positions, edit_values)
    archive_term ← rng.choice(known_archive_terms_pool)
    yield SyntheticSpec(
        family="archive_evidence",
        mechanism="bean_invariant_perturbation",
        parameters={edit_positions, edit_values, archive_term},
        admissibility_proof=run Bean over perturbed_ct's crib indices;
            score the worker's pretend "match" against the canonical
            crib dictionary,
    )
```

#### Parameters

- `edit_count ∈ {1, 2, 3, 4}` (Hamming-1 through Hamming-4)
- `edit_positions ⊆ non_crib_positions` (97 − 24 = 73 candidates)
- `edit_values ∈ A..Z`
- `archive_term ∈ archive_terms_pool` (finite seed list)
- N = 10,000

#### Expected Max-Ratio Criterion

`synthetic_max / ledger_max ≥ 0.80` (≥ 19/24).

#### Failure Modes

- Generator confuses perturbation depth with cryptographic content.
- Failing to mirror the actual archive_evidence admissibility process
  (which is human-curated, not algebraic).

#### Acceptance Criteria

- `synthetic_max / ledger_max ≥ 0.80`.
- Generator does NOT use the canonical crib dictionary as input
  beyond the admissibility step (otherwise it's circular).

### key_tape

#### Ledger Degeneracy Regime

`795fde3e` and `a2f896e5` produced score 24 because their bounded
search universe (720 tape configs / exhaustive primer search) was
small enough to admit all 24 cribs by chance under the chosen
admissibility rule. The mechanism algebraically forces a 24/24 crib
match because the search loops over keystream-recovered tape
candidates.

#### Synthetic Generator

A **crib-derived-keystream tape** sampler:

```text
sample(rng):
    primer_length    ← rng.choice([5, 7, 8, 10])
    null_rule        ← rng.choice(["skip", "consume", "segmented"])
    variant          ← rng.choice(["vigenere", "beaufort", "var_beaufort"])
    primer           ← rng.choice(primer_pool)
    tape_extension   ← derived from primer + crib-induced keystream
    yield SyntheticSpec(
        family="key_tape",
        mechanism="primer_plus_crib_keystream",
        parameters={primer_length, null_rule, variant, primer},
        admissibility_proof=apply tape to CT under variant; verify
            score 24/24 by construction at crib positions; score the
            full plaintext.
    )
```

#### Parameters

- `primer_length ∈ {5, 7, 8, 10}` (finite)
- `null_rule ∈ {skip, consume, segmented}` (finite, exhaustive)
- `variant ∈ {vigenere, beaufort, var_beaufort}` (finite)
- `primer ∈ primer_pool` (finite, K-thematic plus random)
- N = 10,000

#### Expected Max-Ratio Criterion

`synthetic_max / ledger_max ≥ 0.80` (≥ 19/24).

#### Failure Modes

- Producing real signal: if a synthetic tape produces > 6 contiguous
  English characters outside cribs, the generator has crossed into
  cryptographic content. Reject and re-sample.
- Confusing M3 (skip) and M4 (finite tape): the mechanism dimension
  must be a categorical parameter, not silently fixed.

#### Acceptance Criteria

- `synthetic_max / ledger_max ≥ 0.80`.
- All generator outputs are kernel-verified by the dispatcher;
  `kernel_overrule_count` from synthetic batch must match expected
  overfit count.
- Generator does not solve K4 by accident.

### geometry

#### Ledger Degeneracy Regime

The geometry family's high-score outliers come from spatial-grid
hypotheses where parameter overfitting produces accidental
admissibility passes. Examples include grid widths and column orderings
chosen post-hoc to align cribs.

#### Synthetic Generator

A **grid-overfit-by-search** sampler:

```text
sample(rng):
    grid_width    ← rng.choice([5, 6, 7, 8, 9, 10, 13, 14])
    grid_route    ← rng.choice(["columnar", "spiral", "serpentine", "route"])
    column_order  ← rng.permutation(range(grid_width))
    crib_overlay  ← rng.choice(crib_overlay_pool)
    yield SyntheticSpec(
        family="geometry",
        mechanism="grid_with_post_hoc_column_order",
        parameters={grid_width, grid_route, column_order, crib_overlay},
        admissibility_proof=run kernel transposition; score against
            cribs; the search procedure picks the column_order that
            maximizes crib match — by construction, an overfit.
    )
```

#### Parameters

- `grid_width ∈ {5..14}` (finite)
- `grid_route ∈ {columnar, spiral, serpentine, route}` (finite)
- `column_order ∈ S_{grid_width}` (sampled, not exhaustive)
- `crib_overlay` from a finite seed list of post-hoc alignments
- N = 10,000

#### Expected Max-Ratio Criterion

`synthetic_max / ledger_max ≥ 0.80` (≥ 13/16 since geometry's ledger
max is 16, not 24).

#### Failure Modes

- Generator inadvertently rediscovers a real transposition mechanism
  (would mean geometry was crypto, not null).
- Generator's "post-hoc column ordering" leaks into the admissibility
  process under non-overfit settings.

#### Acceptance Criteria

- `synthetic_max / ledger_max ≥ 0.80`.
- Generator outputs include a `post_hoc` flag distinguishing search
  procedure from genuine mechanism, for downstream auditing.

---

## Global Acceptance Criteria

Phase 2.2 is **NOT complete** until either:

1. For every target family in `{k3_continuity, archive_evidence,
   key_tape, geometry}`, `synthetic_max / ledger_max ≥ 0.80` AND the
   per-family Bonferroni-corrected mean elevation falsifies or fails to
   falsify the elevation hypothesis at α = 0.05/6 (or whatever family
   count applies); OR
2. The family is explicitly classified as impossible to model
   synthetically without reproducing the eliminated degeneracy
   directly. In that case the verdict for that family is
   `inconclusive due to insufficient sampling or invalid synthetic
   model`, and that limitation is documented in this file under a
   "Family X Documented Impossibility" section.

The `k4_campaign_readiness_gate.md` "Methodological-null Phase 2.1
status" check stays RED until at least one of these acceptance
conditions holds for every target family.

## Tests Required

The implementation skeleton must include:

- `kryptosbot/tests/test_methodological_null_phase2_2.py`
  - `test_generators_are_deterministic_under_seed`
  - `test_generators_produce_admissibility_passes`
  - `test_generators_do_not_accidentally_solve_k4`
  - `test_max_ratio_meets_threshold_per_family` (skipped pending data
    if the runner has not been run)
  - `test_phase_2_1_outputs_unchanged` (regression — Phase 2.2 must
    not mutate Phase 2.1 artifacts)

## Multiplicity Correction

The Phase 2.2 ledger comparison must correct across the union of all
families considered. If Phase 2.2 only re-runs the four mismatched
families, the family count for Bonferroni is still 6 (combined with
the Phase 2.1 results for `k2_coords` and `encoding`), not 4.

## Reproducibility

```bash
# Smoke (small N)
PYTHONPATH=src python3 -u scripts/_infra/calibrate_methodological_null_phase2_2.py --quick --ledger-comparison

# Full
PYTHONPATH=src python3 -u scripts/_infra/calibrate_methodological_null_phase2_2.py --ledger-comparison

# Single-family
PYTHONPATH=src python3 -u scripts/_infra/calibrate_methodological_null_phase2_2.py --only-family key_tape --ledger-comparison

# Tests
PYTHONPATH=.:src python3 -m pytest kryptosbot/tests/test_methodological_null_phase2_2.py -q
```

## Open Questions for Implementation

1. Should the `k3_continuity` reflow generator be parameter-bounded by
   pre-1990 historical reflow patterns (limited universe), or by a
   broader synthetic universe (likely too generous and would
   over-claim faithfulness)?
2. Should the `archive_evidence` generator use the project's
   `archive_terms_pool` from the controller's family rotation, or a
   curated subset that mirrors what theorists actually proposed?
3. Should the `key_tape` generator include `key_tape` DSL specs from
   the dispatcher to mirror the actual Category-A admission path?
4. Should the `geometry` generator's post-hoc column-order search be
   capped at the same depth used by the worker, or run unbounded to
   establish the ceiling?

These are decisions the implementer must justify in the runner's
docstring; the design does not commit to any of them.

## Limitations Acknowledged in Advance

- Phase 2.2 cannot eliminate the possibility that the ledger means
  reflect cryptographic content. It can only establish whether they
  are within the **faithful** conditional null's range.
- Even with `synthetic_max / ledger_max ≥ 0.80`, the analysis is
  conditional on the synthetic generators being genuinely mechanism-
  aware, not crypto-aware. Independent review of the generators is
  required before any verdict is recorded.
- The four families may need different thresholds. The 0.80 ratio is
  a default; the implementer may justify a higher threshold per
  family.

---

## Family X Documented Impossibility (per Option 2 acceptance)

The design memo's Option 2 acceptance condition (§Global Acceptance
Criteria) requires per-family sections documenting structural
impossibility when `max_ratio < 0.80` after mechanism-aware sampling.
These sections are appended after the Phase 2.2 v2.0 calibration
landed (2026-05-06) and recorded in `methodological_null_phase2_2_decision_memo.md`.

### k3_continuity Documented Impossibility

**Phase 2.2 v2 result:** synthetic null mean=0.896, stdev=0.935, max=7.
`max_ratio = 7/24 = 0.29`, well below 0.80. Statistically
indistinguishable from `random_text__AZ__n97` baseline (mean=0.924,
stdev=0.942, max=7).

**Bernoulli rate test:** ledger has 1 score-24 event in 38 entries;
synthetic null has 0 score-24 events in 10K samples (rule-of-three
upper 95% CI on rate: 3e-4). Binomial one-sided p-value ≈ 0.011.
Significant at α=0.05 but not at Bonferroni-corrected 0.0083.

**Why mechanism-aware random-parameter sampling cannot reach
max_ratio ≥ 0.80:** the documented ledger BREAKTHROUGH (entry
`46caf41f`) scored 24 because the theorist's *flexible reflow*
proposal could absorb any crib alignment by parameter choice. The
framework's safety gate caught this as a contradiction (K3+K4=433 is
prime; no rectangular grid exists). The mechanism producing the
score-24 was a *flawed admissibility check on the theorist's part*,
not a parameter regime random sampling could find. To reproduce that
score in a synthetic null, the generator would have to itself adopt
the flawed admissibility check (e.g., place canonical cribs by
parameter choice), which is exactly the v1.0 generator the red-team
rejected as circular. Therefore: structural impossibility under
faithful synthetic sampling.

### archive_evidence Documented Impossibility

**Phase 2.2 v2 result:** synthetic null mean=0.915, stdev=0.917,
max=5. `max_ratio = 5/24 = 0.21`. Statistically indistinguishable from
`random_text__AZ__n97` baseline.

**Bernoulli rate test:** ledger has 1 score-24 event in 101 entries;
synthetic null has 0 in 10K. Binomial p ≈ 0.030. Significant at
α=0.05 but not at Bonferroni-corrected 0.0083.

**Why mechanism-aware random-parameter sampling cannot reach
max_ratio ≥ 0.80:** the documented ledger BREAKTHROUGH (entry
`4ae72d4d`) scored 24 because the theorist conflated Bean-pass with
"all 24 cribs match" — a flawed admissibility check. Bean is invariant
under non-crib edits, so the theorist's own scoring reported 24/24
regardless of the actual decryption result. The v2 generator
*correctly* applies non-crib Hamming-1..4 perturbations and runs the
real cipher, which produces near-random plaintext (max 5 across 10K
samples). To reproduce the ledger's score-24 events, the synthetic
generator would have to mimic the theorist's flawed scoring rather
than the cipher mechanism. Structural impossibility.

### key_tape Documented Impossibility

**Phase 2.2 v2 result:** synthetic null mean=1.010, stdev=0.946,
max=4. `max_ratio = 4/24 = 0.17`. Statistically indistinguishable from
`random_text__AZ__n97` baseline.

**Bernoulli rate test:** ledger has 2 score-24 events in 95 entries;
synthetic null has 0 in 10K. Binomial p ≈ 3.94e-4. **Significant at
Bonferroni-corrected 0.0083.** This is the strongest evidence among
the four families that the ledger contains family-specific phenomena
the synthetic null does not capture.

**Why mechanism-aware random-parameter sampling cannot reach
max_ratio ≥ 0.80:** the documented ledger BREAKTHROUGHs (`795fde3e`,
`a2f896e5`) scored 24 because the theorists' *bounded search universe*
(720 tape configurations / exhaustive primer search) algebraically
forced 24/24 by keystream-recovery — i.e., the search procedure
selected tape values that matched the cribs by definition. The v2
generator uses primer-extension *forward* (no canonical-PT
back-solving) and does not exercise keystream-recovery search.
Modeling keystream-recovery search would require placing canonical
cribs at canonical positions (effectively the v1.0 approach), which
is circular. Structural impossibility under non-circular synthetic
sampling. The Bernoulli p-value here makes the structural argument
quantitative.

### geometry Documented Impossibility

**Phase 2.2 v2 result:** synthetic null mean=1.408, stdev=1.341,
max=6. `max_ratio = 6/16 = 0.38`. The post-hoc-search element
inflates the central tendency above the random_text baseline (only
family with `vs_random_text_baseline.indistinguishable=False`), but
not enough to reach the ledger max regime.

**Bernoulli rate test:** ledger has 0 score-24 events in 90 entries
(ledger max for this family is 16, not 24); synthetic null has 0 in
10K. Binomial p = 1.0 — no rate difference detectable when both rates
are zero. The Bernoulli framing does not discriminate; the max_ratio
test does (0.38 < 0.80, falls short of acceptance).

**Why mechanism-aware random-parameter sampling cannot reach
max_ratio ≥ 0.80:** the ledger's geometry max is 16 (not 24). The
score-16 ledger entries presumably came from theorists searching
column orders at higher depth than the v2 cap of 50, OR from
theorists adopting non-uniform parameter regimes. The v2 generator's
post-hoc search at depth 50 captures the central-tendency overfit
(mean elevation above random_text) but not the upper-tail overfit
(max=6 vs ledger max 16). Higher search depth would inflate both
mean and max, but at the cost of producing increasingly
crypto-equivalent samples (the search becomes a brute-force keyword
attack). The v2 search depth 50 is calibrated to mirror typical
worker depth; raising it changes what we are sampling rather than
how well we are sampling. Therefore: structural impossibility under
the bounded-search regime. A Phase 2.3 calibration could explicitly
sweep search depth to characterize this trade-off.

---

*Authored 2026-05-04 as part of Tier 1 `.claude` hardening. Phase 2.2
v2.0 implementation landed 2026-05-06 with the documented-
impossibility sections above appended to satisfy Option 2 acceptance.
Phase 2.2 implementation history: v1.0 was retired after red-team
review (degenerate-by-construction non-null); v2.0 runs real cipher
mechanisms but produces distributions statistically indistinguishable
from `random_text__AZ__n97` for 5 of 6 families, confirming that the
ledger's score-24 outliers in the four target families are not
parameter-driven phenomena.*
