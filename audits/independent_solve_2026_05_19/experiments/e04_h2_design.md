---
status: preregistered
locked_at: 2026-05-19
locked_by: Claude Opus 4.7 (1M context), at user direction "run H2"
contract: ../execution_contract.md
parent_hypothesis: results/final_report.md §5 H2 (revised post-H1)
predecessor: e03_h1_design.md (single-non-columnar-middle, clean null)
---

# E04 — H2 Pre-registration: Non-columnar × non-columnar composed Ts under TABP

## 1. Hypothesis (revised after reading tabp_series_summary.md)

The TABP v2b/v2c campaigns exhausted **columnar × columnar** composed
two-layer transpositions (252,840 unique perms × AZ/KA × Vig/Beau/VarBeau
× periods 1–26) and reported clean null (best ngram_per_char = −6.046
on a 73-char scoring window, well within the random envelope).

What v2b/v2c did NOT cover is **non-columnar × non-columnar** composed
two-layer transpositions under the same TABP shape. H1 (`e03`) tested
**single** non-columnar middle layer (no composition) and reported clean
null at 112,320 configs.

H2 tests the **natural extension**: T_inner ∈ non-columnar perms AND
T_outer ∈ non-columnar perms, both drawn from H1's 312-perm catalogue,
under the same TABP encryption shape `CT = SUB(T_outer(T_inner(PT)))`,
with both AZ and KA inner alphabets.

## 2. Encryption / decryption model

**Encryption (TABP shape)**:
- PT --[T_inner]--> x1 --[T_outer]--> x2 --[SUB]--> CT
- where T_inner and T_outer are both *non-columnar* permutations of [0..96].

**Decryption** (what we apply):
- CT --[SUB^-1]--> intermediate (length 97)
       --[T_outer^-1]--> stage
       --[T_inner^-1]--> PT
- Equivalently: PT = apply_perm(SUB^-1(CT), composed_dec_perm) where
  composed_dec_perm = T_inner^-1 ∘ T_outer^-1.

Note: Model-A-style reversal (PT → SUB → T_in → T_out → CT) is partially
covered by H1 (single-layer non-columnar trans applied after substitution)
and is NOT re-tested here. H2 is strictly TABP-shape.

## 3. Search universe (locked)

### Non-columnar permutation catalogue (312 perms; identical to H1)

- **Myszkowski**: 30 K4-context keywords × widths {5..13} = 270.
- **Rail-fence**: depths {2..15} = 14.
- **Route-spiral**: 7 rectangles × 4 directions = 28.
- **Total**: 312.

`KEYWORD_POOL_K4` (30 keywords) is identical to e03_h1_design.md §3.

### T_inner × T_outer cross product

- |perms| × |perms| = 312 × 312 = 97,344 distinct ordered pairs.
- Note: identity is NOT included; both perms are non-columnar, so
  (mysz_a, mysz_a) etc. are permitted (composes to a different
  permutation than mysz_a alone).

### Substitution layer (SUB)

- variant ∈ {Vigenere, Beaufort, Variant_Beaufort} = 3
- alphabet ∈ {AZ, KA} = 2
- keyword ∈ KEYWORD_POOL_K4 = 30
- period = len(keyword)

|SUB configs| = 3 × 2 × 30 = 180.

### Total config count

97,344 × 180 = **17,521,920** configurations.

### Universe hash

SHA-256 of normalized JSON descriptor:
- model = "TABP_PT_to_TI_to_TO_to_SUB_to_CT"
- t_inner_catalogue = sorted (kind, label) pairs over the 312 perms
- t_outer_catalogue = same 312
- sub_variants = ["vigenere", "beaufort", "var_beaufort"]
- sub_alphabets = ["AZ", "KA"]
- sub_keywords = sorted KEYWORD_POOL_K4
- expected_total = 17521920

Computed at run start; stored in `results/e04_h2_summary.json`.

## 4. Pre-registered thresholds (locked; identical structure to H1)

### Tier 1 — exploratory storage

- `crib_score >= 10` (NOISE_FLOOR per kernel `STORE_THRESHOLD`).
- Action: append to `results/candidates.jsonl`.
- Note: random-extreme-value bound on max(crib_score) over 17.5M trials
  under H0 (random plaintext at crib positions) is approximately
  binomial(24, 1/26) max ≈ 12–13. Tier 1 hits are *expected* under H0.

### Tier 2 — interesting

- Tier 1 AND **at least one** of:
  - `east_hits_holdout >= 8/13`
  - `bcl_hits_holdout >= 6/11`
- Action: log to `results/e04_h2_tier2.jsonl`.

### Tier 3 — pre-registered "promising" PASS

A candidate passes the pre-registered H2 threshold iff all of:

1. `crib_score >= 18`;
2. `holdout_EAST_hits >= 9/13`;
3. `holdout_BCL_hits >= 7/11`;
4. Kernel-side `score_candidate` verification: `bean_passed == True` AND
   `ngram_score / len(pt) >= -5.5` (tighter than v2c's best −6.046).

Tier 3 PASS triggers the contract §3 verification gates (Tier 4); it
does NOT itself constitute a solve.

## 5. Holdout protocol

Per H1: withhold each crib in turn; pass requires exact prediction of
the withheld characters from the candidate's decrypted plaintext alone,
without using those characters to constrain the key.

In H2 the search is exhaustive enumeration (not key recovery), so
"holdout" reduces to: for any candidate with `crib_score >= 10`,
separately verify that no single crib accounts for the entire score.
Tier 3 requires BOTH halves of the holdout to clear independently.

## 6. False-positive defenses

- Self-encrypting positions {32, 73}: candidates with PT[32] != 'S' or
  PT[73] != 'K' are *not auto-rejected* in this run but are flagged in
  the output rows as `self_encrypting_preserved=False`. A Tier 3 PASS
  with self-encrypting violation is treated as an immediate red flag
  for the verification stage.
- The 17.5M-config breadth means Tier 1 hits are expected by chance;
  the Tier 3 gate combines `crib_score >= 18` with **both** holdouts
  individually clearing thresholds well above their random extreme
  values for this search breadth.
- Kernel-side verification at Tier 3 ensures ngram_floor and Bean
  constraints are independently re-checked against the official scoring
  pipeline.

## 7. Compute budget

- Estimated: 4–7 minutes single-core with composed-perm precomputation
  and bytes-level perm-apply. No paid API calls. No token cost. No
  multiprocessing required.
- Well under the $25 swing threshold
  (`feedback_red_team_before_swings.md`); no red-team review needed for
  local CPU compute of this size.

## 8. Stop conditions

- 0 candidates clear Tier 3 → clean null; update
  `results/final_report.md` §10 with H2 result; pivot the "next
  experiment worth human time" recommendation accordingly.
- ≥ 1 candidate clears Tier 3 → halt enumeration; do NOT advance to
  contract §3 Tier 4 without explicit user authorization and red-team
  review of the surviving candidate (`red-team-disprover`).
- A kernel verification failure (e.g. `score_candidate` raises) is
  treated as a halt condition; do not silently skip.

## 9. Reporting

- Append E08 to `results/experiment_log.md`.
- Update `results/final_report.md` §10 (H2 disposition).
- Update `results/negative_results.md` if clean null.
- Save a project memory note under
  `~/.claude/projects/-home-cpatrick-kryptos/memory/` named
  `project_h2_noncolumnar_composed_trans_<verdict>_2026_05_19.md`.

— locked —
