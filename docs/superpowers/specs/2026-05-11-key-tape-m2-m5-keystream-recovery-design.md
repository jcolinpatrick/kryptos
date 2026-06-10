---
status: design (pending implementation plan)
type: campaign_design
date: 2026-05-11
classification: [INTERNAL RESULT] design only; no K4 progress claim
runner_codename: Swing K-1
campaign_id_planned: C-KEYTAPE-M2M5-01
---

> **LIVE-EVIDENCE BANNER (added 2026-06-09):** This file post-dates the
> 2026-04-09 `docs/superpowers/` namespace demotion (see
> `docs/superpowers/README.md`) and is NOT palette-dependent. It is cited as
> live evidence by `docs/claims_registry.json` claim `C-KEYTAPE-M2M5-01`
> (repro_reference). Per the AUDIT-2 closure residue rule in
> `docs/methodological_audits.md`, a file under this namespace promoted back
> toward live status carries its own banner. The directory-level HISTORICAL
> banner does not apply to this file.

# Swing K-1 -- Key-Tape M2..M5 Keystream Recovery

## 1. Purpose

For each finite-tape model M2, M3, M4, M5 -- as defined in
`src/kryptos/kernel/transforms/key_tape.py` and the
`otp-null-keystream-forensics` skill (SKILL.md, lines 62-66) -- define a
bounded, preregistered universe of
`(variant, alphabet, null_mask, null_rule, tape-length/segmentation)`
configurations. For each configuration, derive the 24-position
constrained keystream from the disclosed cribs, filter by Bean
constraints (1 equality, 242 inequalities, 101 linear), and run a
structural-identification suite on every admitted keystream.

**Output is not plaintext.** The output is one of:

- **(a) An identified keystream source / generator,** which triggers
  full validation per `CLAUDE.md` "Validation gates" and red-team
  review before any promotion. OR
- **(b) A clean null verdict over a hashed universe,** registered as
  `C-KEYTAPE-M2M5-01` in `docs/claims_registry.json` with explicit
  scope language: "within the analyzed model class, under the stated
  assumptions, the universe is null at promotion threshold p <= 1e-6".

**Non-claim banner:** This spec describes an experimental campaign.
No K4 solution is claimed. No real-K4 progress is claimed at this
date. K4 is NOT proven impossible by this design or by a null
outcome.

## 2. Why this swing has non-zero EV

[POLICY] Every prior K4 attack tested *plaintext search* under an
assumed cipher: sweep keys, look for English at non-crib positions.
This swing tests *cipher identification* under a *recovered*
keystream: derive the 24-symbol keystream from cribs, then ask
whether that derived keystream is a known sequence.

[DERIVED FACT] Models M2..M5 are the only classes the Tier 1
elimination list (`docs/elimination_tiers.md`,
`scripts/_infra/session_briefing.py` Tier 1 section) does not cover.
Periodic polyalphabetic, autokey, fractionation, columnar, Gromark,
Hill, and many composition templates are eliminated under
positional-homogeneity + no-null assumptions. M2..M5 explicitly drop
those assumptions.

[DERIVED FACT] The 24-position keystream is fully determined by
`(model, variant, alphabet, mask, rule)` once disclosed cribs are
fixed. There is no degrees-of-freedom inflation: each config yields
exactly one 24-vector, and Bean either admits or rejects it. Bean
admission rate over `26^24` is `624 / 26^24` ~ `1.7e-32`, so a
random config has effectively zero chance of admitting; Bean is a
hard structural test.

[HYPOTHESIS] The novel epistemic risk is the **null-mask hypothesis
space**. The retired palette claim (`C-PALETTE-01`) lived in that
corner. So mask enumeration MUST be parametric with low DOF and
preregistered. Tier 2 (geometry-derived) masks are excluded from
this swing.

## 3. What already exists vs. what this swing builds

### 3.1 Existing primitive (do not re-implement)

The kernel function
`src/kryptos/kernel/transforms/key_tape.py::apply_key_tape` (line 24)
implements the per-spec transform with:

- `tape` parameter (tuple of int 0..25, length L)
- `variant` parameter (CipherVariant: VIGENERE, BEAUFORT, VAR_BEAUFORT)
- `direction` parameter (decrypt / encrypt)
- `null_positions` (frozenset of CT-indexed null positions)
- `null_rule` ("skip" -- M4 / M3 / M5 default; "consume" -- M2 default)
- `alphabet` (AZ or KA)

The dispatcher path through `kryptosbot/job_dispatcher.py:1447` is
fully wired. `_SUPPORTED_KINDS` includes `key_tape` (verified
2026-05-11; GAPS is empty).

### 3.2 What this swing builds (the standalone runner)

What does NOT exist and what this design specifies:

1. A **search-universe enumerator** that emits the
   `(model, variant, alphabet, mask, rule, tape-length/segmentation)`
   product as a sorted, hashable manifest.
2. A **keystream-recovery routine** that, given a config, derives
   the 24-position keystream from disclosed cribs *under the model's
   position-projection rule* (M3 projects to CT73 after null
   extraction; M2 / M4 / M5 stay in CT97).
3. A **Bean filter** wrapper using the existing
   `kryptos.kernel.constraints.bean.verify_bean()`.
4. A **structural-identification suite** with four channels:
   source-text scan, keyword-expansion match, generator match, and
   ngram score (ngram score is ranking only, never a promotion gate
   -- per `feedback_bean_pass_not_promising.md`).
5. A **shuffled-CT null calibration harness** sized for ~86K configs.
6. An **artifact emitter** writing to
   `analysis_runs/key_tape_m2_m5_2026_05_11/`.

### 3.3 Architecture posture (locked)

**Standalone runner. Not dispatcher integration.** The runner uses
`kernel.transforms.key_tape.apply_key_tape` directly for the inner
loop (avoiding `JobResult` overhead at 86K configs). Dispatcher
integration (Phase B) is **explicitly out of scope** for this design
and requires both a Phase A signal AND a separate design doc.

## 4. Search universe

### 4.1 Axes

| Axis | Values | Per-model usage |
|------|--------|-----------------|
| Model | M2, M3, M4, M5 | all configs |
| Variant | vigenere, beaufort, var_beaufort | x3 every model |
| Alphabet | AZ, KA | x2 every model |
| Null rule | skip, consume | M2 fixes to consume; M3 fixes to skip; M4 / M5 fix to skip in Phase A |
| Tape length L (M4) | {24, 30, 36, 49, 60, 73} | x6 for M4 only |
| Segmentation (M5) | boundary sets at {21}, {34}, {63}, {21,34}, {21,63}, {34,63}, {21,34,63} | x7 for M5 only |

Notes:

- The null_rule axis lists both values but each model pins one in
  Phase A. M4 / M5 testing the alternative null_rule (consume) is
  deferred; if Phase A is null and a follow-up is authorized, those
  variants are the natural first extension and would land under a
  new universe hash.
- M1 (no nulls, length 97) is included **only as a control arm**
  for instrumentation calibration. M1 configs are tagged
  `control_arm=True` in artifacts and are **ineligible for
  promotion**, per user direction.

### 4.2 Mask enumeration (Tier 1 only this swing)

[POLICY] Tier 1 masks only. Tier 2 geometry-derived masks are
deferred to a future run.

**Tier 1 mask class A: mod-N parametric.**

- `i mod N in S` for `N in {2..13}`, `S` subset of `{0..N-1}`.
- Constraint: total null count `|nulls| in {17, 20, 24, 28}` -- the
  realistic stego null-count bracket.
- Estimated count after bracket filter: ~150 masks.

**Tier 1 mask class B: boundary-region parametric.**

- Nulls confined to gap regions only:
  `[0..20] union [34..62] union [74..96]`.
- Fixed bracket sizes `{17, 20, 24, 28}`, contiguous-block patterns,
  evenly-spaced patterns.
- Estimated count: ~75 masks.

**Exclusions (hard, by construction):**

- No data-driven masks (no mask inferred from CT statistics).
- No score-conditioned mask selection.
- No reference to `CONSENSUS_NULL_POSITIONS` or any palette-derived
  artifact (retired claim `C-PALETTE-01`).

**Total mask count target:** ~225. Final count fixed by universe
hash at run start.

### 4.3 Total config count (estimated)

For each `(model, variant, alphabet, mask)` combo:

- M2: 1 rule x 6 mask-applicable subset = 1 * 225 = 225 per
  (variant, alphabet).
- M3: 1 rule x 225 masks = 225 per (variant, alphabet).
- M4: 6 lengths x 225 masks = 1350 per (variant, alphabet).
- M5: 7 segmentation sets x 225 masks = 1575 per (variant, alphabet).

Per (variant, alphabet): `225 + 225 + 1350 + 1575 = 3375`.

Total across 3 variants x 2 alphabets: `3375 * 6 = 20250` configs.

Plus M1 control arm: `1 * 1 * 3 * 2 = 6` configs (one mask=empty
config per variant-alphabet).

**Universe size target:** ~20,256 configs. Final count fixed by
universe hash. Updated downward from the earlier ~86K estimate
because tier 2 is excluded and segmentation cardinality is held
tight.

### 4.4 Universe hash

Emitted at run start. SHA-256 over the sorted JSON serialization of
the canonical config enumeration. Recorded in `manifest.json`. Any
config not in the hashed universe is excluded from the result;
re-running with a different hash produces a separate verdict.

## 5. Filter chain

### 5.1 Keystream derivation (per config)

For each config:

1. Apply null mask to CT to obtain CT' (the "active" ciphertext under
   the model's position-projection rule):

   - M2 (consume): CT' = CT97; nulls are positions where tape
     advances but plaintext is `?`.
   - M3 (skip): CT' = CT73 = CT97 with null positions removed.
   - M4: CT' = CT97; null behavior per `null_rule`.
   - M5: CT' = CT97; segments delimited by boundary set.

2. Identify crib positions in CT' coordinates:

   - M2 / M4 / M5: cribs remain at CT97 positions {21..33} and
     {63..73}.
   - M3: cribs re-project. ENE at CT97 [21..33] maps to CT73 indices
     `[21 - n_lt_21 .. 33 - n_lt_or_eq_33]` where `n_lt_21` is the
     count of null positions strictly less than 21 and `n_lt_or_eq_33`
     is the count of null positions in [0..33]. BCL at CT97 [63..73]
     maps similarly using `n_lt_63` and `n_lt_or_eq_73`. Crib
     positions that coincide with null positions are dropped from
     the keystream-recovery set (they yield no constraint).

     Worked example. Mask = {2, 11, 27, 40, 55, 68, 80} (7 nulls).
     - n_lt_21 = 2 (positions 2 and 11 are below 21).
     - n_lt_or_eq_33 = 3 (add position 27).
     - ENE CT97 [21..33] -> CT73 [21-2 .. 33-3] = [19..30].
     - Position 27 in CT97 is dropped (it is a null), so the ENE
       crib contributes 12 of its 13 positions to keystream
       recovery.
     - n_lt_63 = 5, n_lt_or_eq_73 = 6.
     - BCL CT97 [63..73] -> CT73 [63-5 .. 73-6] = [58..67]. No null
       position in [63..73], so all 11 BCL positions contribute.

   The runner MUST compute this mapping deterministically from the
   mask and assert via test (see section 8.3).

3. Derive keystream `k[0..23]` at the (re-projected) crib positions
   using the variant arithmetic:

   - vigenere: `k[i] = (CT[i] - PT[i]) mod 26`
   - beaufort: `k[i] = (CT[i] + PT[i]) mod 26`
   - var_beaufort: `k[i] = (PT[i] - CT[i]) mod 26`

   Where `CT[i]` and `PT[i]` are interpreted in the alphabet's index
   table (AZ vs KA both produce identical k under the disclosed
   cribs because cribs are over English letters, but the *use* of k
   for non-crib positions differs by alphabet -- this matters in
   stage 5.3 channels).

### 5.2 Bean filter

Apply `kryptos.kernel.constraints.bean.verify_bean_from_implied(implied_keys)`
from `src/kryptos/kernel/constraints/bean.py:283`. Pass a dict
`{position: keystream_value}` over the (re-projected) crib positions
only. The kernel function is variant-independent (per CLAUDE.md
gotcha "Bean constraint is variant-independent"). It returns
`bool`, checking only the constraints that have all required
positions populated. The Phase A runner wraps the call in
`bean_filter_wrapper(implied: dict) -> BeanVerdict` where
`BeanVerdict` is a small dataclass with fields `passed: bool`,
`eq_checked: int`, `ineq_checked: int`, `linear_checked: int`,
`failures: list[str]` -- per-constraint detail computed by the
wrapper, not by the kernel function. Admit if `passed == True`.
Persist all configs (admitted and rejected) to `configs.jsonl` so
the rejection rate is part of the artifact.

Expected admit rate per config: 624 admissible 24-vectors over the
`26^24` random space, so a uniformly-random 24-position keystream
has admit probability `624 / 26^24` ~ `1.7e-32`. Real admit rate
under structured (mask, model, variant) constraints will be
dominated by the keystream-derivation step and is itself diagnostic.

### 5.3 Structural-identification suite (admitted configs only)

Four channels. Each channel emits a structured verdict. The runner
must record all four for every admitted keystream.

**Channel S1: source-text scan (Tier A corpus only for promotion).**

- Slide-search the 24-symbol keystream against the canonical Tier A
  source corpus (section 6).
- Match definition: exact 24-symbol substring equality (under the
  variant arithmetic applied to the candidate source text + cribs).
- Output: `s1_match: bool`, `s1_source: str?`, `s1_offset: int?`,
  `s1_match_len: int` (always 24 for a hit; partial matches at
  lengths 12..23 are recorded but not promotion-eligible).
- Tier B (exploratory) corpus runs the same scan with results
  emitted to a separate file `tier_b_hits.jsonl`. Tier B hits MUST
  re-validate against Tier A before any promotion claim.

**Channel S2: keyword-expansion match.**

- For each keyword in the vetted pool (KRYPTOS, ABSCISSA, BERLIN,
  CLOCK, NORTHEAST, EAST, SCHEIDT, plus the contents of
  `wordlists/thematic_keywords.txt` restricted to <= 12 char public-art
  thematic terms), compute the canonical keystream-expansion under
  the variant's keyword-mixed-alphabet rule.
- Test whether the 24-symbol keystream is a prefix, substring, or
  consistent extension of any expansion.
- Output: `s2_match: bool`, `s2_keyword: str?`, `s2_match_len: int`.
- Self-referential keywords (SCULPTOR, ARTIST) are excluded per
  `feedback_k4_keywords_must_fit_public_art_context.md`.

**Channel S3: generator match.**

- Test whether the 24-symbol keystream is consistent with one of:
  - Fibonacci mod 26 (over all 2-value seeds `26 * 26 = 676`).
  - Gromark / Vimark as a *keystream generator*. The Tier 1
    elimination of Gromark applies to its use as the K4 CT cipher.
    Asking whether the recovered 24-symbol keystream is itself a
    Gromark sequence is a structurally different claim and is in
    scope.
  - Autokey from a primer of length 4..12 (primer enumerated as the
    first `primer_len` keystream symbols, then test consistency).
  - Gronsfeld 0..9 (k_i in {0..9} for all i? trivially testable).
- Output: `s3_match: bool`, `s3_generator: str?`, `s3_seed: tuple?`,
  `s3_match_strength: float` (consistency score).

**Channel S4: ngram score (RANKING ONLY, NOT A PROMOTION GATE).**

- English-letter ngram score of the 24-symbol keystream under the
  random-letter null. Used only to rank admitted configs in the
  artifact for human review.
- Output: `s4_ngram_score: float`.

### 5.4 Promotion gate

A config is **promotion-eligible** if and only if ALL of:

1. Bean passes (`bean_passed == True`).
2. At least one of `s1_match`, `s2_match`, `s3_match` is True at the
   preregistered match length (S1: 24, S2: 8, S3: consistency-strength
   `>= 0.95` over 24 positions).
3. Under shuffled-CT null calibration (section 7), the joint event
   `{bean_pass AND structure_match}` has empirical
   `p <= 1e-6`.
4. Red-team-disprover review of the config artifact returns a
   non-fatal verdict per
   `feedback_red_team_before_swings.md`.

[POLICY] Bean PASS alone is not signal. ngram score alone is not
signal. Tier B source-corpus hits alone are not signal.

## 6. Source-text corpus (Tier A and Tier B, hashed)

[POLICY] The corpus manifest is frozen and hashed at run start.
Adding a source after the universe hash is fixed invalidates the
verdict.

### 6.1 Tier A (frozen, promotion-eligible)

- `reference/` contents: Carter Vol 1, Sanborn correspondence, NSA
  documents, Scheidt dossier, KUBARK, CIA 1996 memo, Kahn
  Codebreakers (subject to provenance manifest at
  `reference/provenance.json`).
- K1, K2, K3 disclosed plaintexts.
- Project Gutenberg curated subset: a preregistered, hashed
  selection of public-domain texts contemporary with or relevant to
  the Kryptos design period (1988-1990). Final list pinned at
  `data/source_text_corpus/tier_a_manifest.json` with per-file
  SHA-256.

### 6.2 Tier B (exploratory, non-claim-bearing)

- Expanded Gutenberg subset (~5000 books).
- Cicada Liber Primus (despite the 2026-05-11 finite-tape-related
  disproof on value-conditional skip; this swing tests M2..M5
  separately).
- Anything else flagged by user during run.

Tier B hits MUST revalidate against Tier A before any promotion
claim is made. Tier B is a hypothesis-generator only.

## 7. Null calibration

[POLICY] Calibration is shuffled-CT primary, random-text secondary
sanity check. Per `feedback_statistical_audit_posture.md`,
adversarial posture applies.

### 7.1 Shuffled-CT null (primary)

- Stage 1, baseline: generate 10,000 shuffled-CT instances by
  permuting the 97-character K4 ciphertext (preserves length and
  letter frequency).
- Run the full filter chain on each shuffled CT under a fixed,
  modest config sample (preregistered: 100 configs sampled
  deterministically from the universe).
- Empirical distribution of `{bean_pass AND structure_match}` count
  per shuffled CT defines the null.
- The 10K baseline gives an empirical p-floor of `1 / 10001` ~
  `1e-4`. That is enough to *reject* a candidate that fails the
  baseline. It is NOT enough to *promote* a candidate at the
  required `p <= 1e-6`.
- Stage 2, escalation (triggered only if a candidate survives
  baseline): Monte Carlo escalation to 1e6 trials on the specific
  candidate config OR analytical Binomial extension via
  `kryptosbot/real_k4_audit.py::compute_null_baseline` when the
  per-config trial structure supports a closed-form bound.
  Escalation cost is bounded because it runs only on the rare
  surviving candidate, not on the full universe.
- Stage-2 method choice is recorded in `null_calibration.json`.

### 7.2 Random-text null (secondary)

- Generate 10,000 random 97-letter texts (uniform over A..Z).
- Same filter pass.
- Used only as a sanity check; primary verdict is shuffled-CT.

### 7.3 Calibration artifact

`null_calibration.json` records:

- Method (empirical / analytical Binomial).
- Empirical tail counts.
- Trial counts per method.
- Threshold and verdict.

## 8. Artifacts and schema

Output root: `analysis_runs/key_tape_m2_m5_2026_05_11/`

### 8.1 Files

| File | Content |
|------|---------|
| `manifest.json` | universe_hash, kernel_commit, assumption_bundle, prereg_thresholds, mask_catalog_path, corpus_manifest_path, total_config_count |
| `mask_catalog.json` | every mask: id, model_class (A or B), null_positions, null_count |
| `corpus_manifest.json` | tier_a list with per-file SHA-256, tier_b list separately |
| `configs.jsonl` | one row per config: spec_hash, model_variant, variant, alphabet, null_rule, null_consumption_mode, mask_id, tape_length_or_segments, control_arm flag |
| `admitted_keystreams.jsonl` | one row per Bean-pass config: keystream (24 ints), bean_detail, all 4 structure channel verdicts |
| `promotions.jsonl` | one row per promotion-eligible config: full audit trail including red-team verdict |
| `tier_b_hits.jsonl` | Tier B exploratory hits, separately for hypothesis-generation review |
| `null_calibration.json` | section 7.3 |
| `verdict.md` | run-level summary using `docs/elimination_tiers.md` vocabulary |

### 8.2 Required artifact fields (locked)

- `null_consumption_mode`: literal "skip" or "consume". Per user
  direction, this is a first-class field, never inferred.
- `model_variant`: literal "M1", "M2", "M3", "M4", "M5". Per user
  direction.
- `spec_hash`: SHA-256 over the canonical spec JSON.
- `crib_positions_used`: the actual position list used for keystream
  derivation (CT97 or CT73 indices), so audit can verify M3
  projection.

### 8.3 Required tests (must land before run)

- `test_runner_skip_vs_consume_indexing`: same mask, same variant,
  alphabet, tape -- verify the keystream alignment differs between
  SKIP and CONSUME at the expected positions.
- `test_runner_m3_ct73_projection`: under a known null mask,
  verify the ENE / BCL crib positions in CT73 coordinates match the
  expected re-projection.
- `test_runner_m4_finite_tape_short`: tape length L < 24 with
  position-only nulls -- verify the kernel raises or pads
  consistently with documented semantics.
- `test_runner_m5_segment_boundary`: segments with explicit boundary
  set -- verify each segment uses an independent tape index.
- `test_runner_bean_filter_admission_rate`: random tape with random
  mask -- verify the Bean admit rate matches expected.
- `test_runner_universe_hash_stable`: two runs of the enumerator
  produce identical hash.

## 9. Stop criteria and verdict definitions

### 9.1 Stop criteria

- **Universe exhausted, zero promotions:** emit `verdict.md`
  classification = NULL_LEVEL; register `C-KEYTAPE-M2M5-01` as
  `status: live, evidence: null_at_p_le_1e-6, scope: tier_1_masks_only`.
- **First promotion-eligible config:** pause runner, dispatch
  red-team-disprover, await verdict before resuming. If red-team
  PASSES, escalate to manual triage and full validation gate.
- **Any Tier B hit at S1 24-symbol match:** log, flag as exploratory,
  do NOT promote. Schedule a follow-up Tier A revalidation.
- **Operational failure (e.g., per-task timeout):** treat as
  inconclusive, not as null. Per `feedback_pool_worker_no_per_task_timeout.md`
  use `apply_async + per-future timeout` pattern, default 60s per
  config.

### 9.2 What this swing does NOT decide

- Does not prove M2..M5 impossible at non-tier-1 mask classes.
- Does not address running-key cipher families beyond what the
  generator-match channel S3 tests.
- Does not address PT length other than 73 (M3) and 97 (M1, M2, M4,
  M5). Other PT-length hypotheses are out of scope per
  `feedback_pt_length_open_question.md`.

## 10. Phase B (out of scope, conditional)

If and only if Phase A produces a promotion-eligible config that
survives red-team-disprover review, then Phase B opens:

- Migrate the runner's per-spec logic into a dispatcher-native
  workflow path (the `key_tape` translator already exists, but the
  search orchestration would move into the controller's hypothesis
  loop).
- Extend HCC + admissibility for the specific source/generator
  identified.
- Re-run with broader mask classes (Tier 2 geometry-derived) under
  a new universe hash.

Phase B requires its own design doc. This document does not
authorize it.

## 11. References

- Kernel implementation: `src/kryptos/kernel/transforms/key_tape.py`
- Dispatcher translator: `kryptosbot/job_dispatcher.py:1447`
- DSL validator: `kryptosbot/hypothesis_dsl.py:743`
- Bean constraints: `kryptosbot/../src/kryptos/kernel/constraints/bean.py`
- M1..M5 nomenclature: `.claude/skills/otp-null-keystream-forensics/SKILL.md:62-66`
- Null calibration pattern: `kryptosbot/real_k4_audit.py`
- Real-K4 current position: `docs/REAL_K4_CURRENT_POSITION.md`
- Admission standard: `docs/REAL_K4_PSEUDO_CLUE_PACK_ADMISSION.md`
- Two-tier preregistration policy: `feedback_two_tier_preregistration.md`
- Pool-worker timeout: `feedback_pool_worker_no_per_task_timeout.md`
- Bean-pass not signal: `feedback_bean_pass_not_promising.md`

## 12. Non-claim banner (repeat)

This design specifies an experimental campaign. No K4 solution is
claimed. No real-K4 progress is claimed at this date. A null verdict
is the most likely outcome by base rate. The value of this swing is:

1. Closing the M2..M5 tier-1 mask class at preregistered scope, or
2. Surfacing a structurally identified keystream that triggers full
   validation.

Either outcome advances the project. Both outcomes leave K4 NOT
proven impossible.

---

*Authored 2026-05-11 by Claude Opus 4.7 + Colin Patrick. Sits at
design status pending Colin review and implementation plan via
`writing-plans`.*
