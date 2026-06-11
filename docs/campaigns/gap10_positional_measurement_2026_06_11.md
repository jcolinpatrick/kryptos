# Pre-registration: GAP-10 crib-bound positional mechanism measurement (2026-06-11)

**Campaign ID:** `e_gap10_01_positional_measurement`
**Runner:** `scripts/statistical/e_gap10_01_positional_measurement.py`
(pure statistics in `scripts/statistical/gap10_lib.py`, TDD-tested in
`tests/test_gap10_measurement.py`)
**Author:** autonomous session 2026-06-11 (Claude), on Colin's instruction to
start the GAP-10 measurement program.
**Status at registration:** decision thresholds and null models frozen BEFORE
any null draw was generated. **Declared:** the OBSERVED statistics for
component 1 (the real C(p) profile and the all-periods-unsatisfiable fact)
were computed once during design for ground-truthing; the thresholds below are
generic (two-sided, Holm, alpha 0.01) and were not tuned to those values. No
observed value for components 2-3 had been computed at freeze time.

---

## 1. What GAP-10 asks (scope and boundaries)

Per `docs/REAL_K4_EVIDENCE_GAP_REGISTER.md` (GAP-10) and
`docs/REAL_K4_CURRENT_POSITION.md` §8: measure whether the disclosed cribs'
POSITIONAL relationship to the cipher mechanism carries structure — (1) Bean
residue-class structure for periods 2-26 with multiple-testing correction,
(2) gap-region IC under a permutation null, (3) cross-boundary statistical
change tests. Gap regions (0-20, 34-62, 74-96) are the corroboration surface;
crib-fitting risk is declared high.

**Boundary with GAP-03:** the global Bean anchor statistics (the single
equality at (27,65), Bean's p ≈ 1/5,520, E0b distances) belong to GAP-03 and
are NOT re-measured here. This program measures PER-PERIOD residue structure
and REGIONAL/BOUNDARY position statistics only.

**Alignment model:** all three components are measurements on the carved CT
under `fixed_len_97` geometry with disclosed crib positions (0-indexed 21-33,
63-73). Component 1 is additionally H1-flavored (Bean derivation assumes
direct positional crib mapping); its conclusions are H1-conditional and do not
transfer to non-direct models.

**Affine-orbit trap (cited per the 2026-05-29 lemma):** any equality-pattern
statistic over the 624 Bean-valid keystreams is constant on each of the 2
affine orbits, so a within-624 null floors at tail 1/2. Component 1 therefore
uses NO within-624 null: its randomness is over COUNTERFACTUAL CONSTRAINT
SYSTEMS (re-derived from resampled CT letters at crib positions via
`kryptos.kernel.constraints.derive.derive_bean_constraints`).

## 2. Component 1 — Bean residue-class structure, periods 2-26

- **Fixed:** the 24 crib positions; the disclosed PT crib letters; the residue
  geometry N(p) = #{(i,j) crib pairs : i ≡ j mod p}.
- **Random (null):** the CT letters at the 24 crib positions.
  - **N1a (primary):** uniform random permutation of the REAL multiset of 24
    CT crib letters across the 24 positions (composition-preserving).
  - **N1b (secondary, declared):** IID uniform A-Z letters at the 24 positions.
- **Statistic (primary):** C(p) = #{(i,j) in the re-derived Bean inequality
  set : i ≡ j (mod p)}, for p = 2..26 — the count of first-order obstructions
  to a period-p key at crib positions.
- **Statistic (secondary, descriptive):** F0 = #{p in 2..26 : C(p) = 0}
  (first-order survivor count; observed real value is 0).
- **Evaluation:** per-period two-sided empirical tail with add-one correction
  ((#{null ≥ obs}+1)/(M+1) and ≤ side; two-sided = 2·min, capped at 1), Holm
  over the 25 periods. Joint max-statistic: the observed min per-period
  two-sided tail compared against the distribution of each null draw's own
  min tail (rank-based, same reference set; small optimism bias noted).
- **M = 10,000** draws per null family, seed 20260611, parallel across
  cpu_count-2 workers.

## 3. Component 2 — gap-region IC under a permutation null

- **Fixed:** the full 97-char CT letter multiset.
- **Random (null):** uniform random position-subsets of the same cardinality
  (the permutation/composition-conditional null: "is this REGION's letter
  composition unusual GIVEN the CT's overall composition?").
- **Statistics:** IC(R) = sum_a c_a(c_a-1) / (n(n-1)) for
  R1 = 0-20 (n=21), R2 = 34-62 (n=29), R3 = 74-96 (n=23),
  R4 = union of gaps (n=73, the unknown positions).
- **Evaluation:** two-sided empirical tails, Holm over the 4 regions.
  Effect sizes reported as observed IC vs null mean ± sd.
- **M = 100,000** subsets per region, seed 20260611.
- **Distinctness from E-FRAC-19:** that experiment calibrated region IC
  against IID random and English text (a-priori calibration; 0-20 anomaly
  died at Bonferroni p = 1.0). This null is composition-conditional and
  covers all three gap regions plus the union uniformly. E-FRAC-19's verdict
  is not re-litigated.

## 4. Component 3 — cross-boundary statistical change tests

- **Boundaries:** b in {21, 34, 63, 74} (starts of ENE, post-ENE gap, BC,
  post-BC; 0-indexed).
- **Statistic:** D_w(x) = total-variation distance between the unigram
  distributions of CT[x-w : x] and CT[x : x+w], for valid centers
  x in [w, 97-w]. Primary window w = 10; secondary (declared exploratory)
  w in {7, 14}.
- **Evaluation:** per-boundary one-sided (high) empirical tail = rank of
  D_w(b) among all valid centers. Joint: mean rank of the 4 boundaries vs
  M = 100,000 random 4-position subsets of valid centers (placebo
  discipline — same statistic family at non-boundary positions).
- **Power note (declared):** w = 10 unigram windows are low-power; a null
  result means "no detectable unigram change at this scale", NOT "no
  mechanism change at boundaries".

## 5. Decision rules (FROZEN)

- **Evidence candidate:** any PRIMARY statistic with Holm-corrected two-sided
  (component 3: one-sided) p ≤ 0.01 within its component → investigate-first
  protocol: fresh-interpreter reproduction, red-team + statistical-auditor
  review, convention-bundle audit, and a check against the affine-orbit and
  adjacency-null traps BEFORE any claim. No auto-promotion; a candidate is an
  input to validation.
- **MEASURED_NULL:** all primary tails above threshold → the component closes
  as "measured, no positional-mechanism signal at these statistics"; GAP-10's
  register row is updated from "unowned" to "measured (this program), open"
  with artifact pointers. GAP-10 itself stays open either way (these are
  specific statistics, not the universe of positional structure).
- **Program-level multiplicity (declared):** 25 + 4 + 4 primary tests across
  3 components; any HEADLINE cross-component claim additionally carries a
  factor-3 Bonferroni on the component-level minima.
- Secondary/exploratory results (N1b, F0, w in {7,14}) are reported but
  cannot create an evidence candidate on their own.
- No statistic, region, window, or period may be added after null generation
  begins.

## 6. Compute plan

Component 1: 2 x 10,000 derive+count draws, parallelized (~26 workers);
estimated minutes. Components 2-3: closed-form counting over 100,000 draws
each; seconds. Artifacts: `results/gap10_measurement_2026_06_11/summary.json`
+ per-component distributions. Seeds fixed at 20260611 (+ component offsets).
