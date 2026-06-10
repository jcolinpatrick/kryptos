# Pre-registration: free-alignment classical sweep (2026-06-10)

**Campaign ID:** `f_free_alignment_classical_2026_06_10`
**Runner:** `scripts/campaigns/f_free_alignment_classical_2026_06_10.py`
**Author:** autonomous session 2026-06-10 (Claude), per Colin's standing
real-K4 directive (`feedback_real_k4_unpaused_2026_05_01`).
**Status at registration:** thresholds frozen BEFORE any campaign config
was executed. Written after G-1 (free-matched null baselines, commit
`ceb8e02`) and the suite-assurance boundary fixes (B-1/B-2/B-3, commit
`f213b4d`) landed and both suites were green.

---

## 1. Hypothesis and why this is genuinely untested

**[HYPOTHESIS]** A single-layer classical decrypt of the carved 97-char
K4 CT yields a plaintext that contains the disclosed cribs
(EASTNORTHEAST, BERLINCLOCK) at NON-canonical offsets — because the true
CT→PT correspondence is shifted by an outer mechanism (reordering,
null-displacement, or offset) that preserves a length-97 stream.

**Alignment model:** `non_direct_alignment` (R1), probed at the
*detection* level via `crib_alignment="free"` (cribs matched anywhere in
the candidate PT). ALIGN-CAUSE: transposition-induced or mask-induced —
the free matcher is agnostic between them; it detects crib *presence*,
not the displacing mechanism.

**Convention bundle (Step 0 freeze):**
- ALPHABET: AZ (A=0) and KA (`KRYPTOSABCDEFGHIJLMNQUVWXZ`, A=0), declared per arm.
- VARIANT: vigenere K=(CT−PT), beaufort K=(CT+PT), var_beaufort K=(PT−CT), A=0.
- POSITIONS: 0-indexed; canonical cribs at 21–33 / 63–73 are NOT assumed.
- ALIGNMENT: `non_direct_alignment`; DSL field `crib_alignment="free"`.
- NULL RULE: no_null_mask at the pipeline level (length-97 preserved);
  displacement-by-mask is only *detected*, not modeled.
- SCOPE: GLOBAL over the 97-char candidate PT.
- BEAN APPLIES?: **No.** Bean depends on fixed positions; under free
  alignment it is N/A by construction (dispatcher reports
  `bean_passed=False`, `scoring_mode="free"`). No Bean-based elimination
  binds here, and none is cited.

**Why untested:** every historical single-layer sweep scored ANCHORED
(crib positions 21–33/63–73 fixed). A decrypt that put EASTNORTHEAST at
offset 30 would have scored ≈ noise and been discarded. The dispatcher
free path became real-K4-capable only on 2026-05-31 (Lever B1), genuine
free finds were silently zeroed at the contract boundary until B-1
(2026-06-10), and free results had no calibrated null until G-1
(2026-06-10). `exhaustion_log.json` contains ZERO free-alignment
campaign entries (checked 2026-06-10); the 2026-06-09 route×QIII and
tableau-axis closures explicitly list "free alignment" as NOT closed.

## 2. Frozen universe

All keyword lists are materialized and SHA-256-hashed by the runner
BEFORE execution; the hashes are recorded in the campaign summary.

**Arm A1 — additive single-layer, motivated keyword population (Tier 1, primary):**
- kinds: `vigenere`, `beaufort`, `variant_beaufort` (3)
- layer alphabet: `AZ`, `KA` (2)
- keyword: tokens parsed from `wordlists/thematic_keywords.txt`
  (uppercase A–Z only, length 3–12, deduplicated, sorted)
- cardinality: 3 × 2 × |W_thematic|

**Arm A2 — Quagmire III diagonal tableau, motivated population (Tier 1, primary):**
- kind: `quagmire`, variant `quagmire_iii`, layer alphabet `AZ`
- tableau_keyword: {KRYPTOS, PALIMPSEST, ABSCISSA, LATITUDE, MAGNETIC, COMPASS} (6)
- period_keyword: the precedented 27 (h12 ∪ h3, verbatim from
  `f_route_outer_quagmire_iii_posttrans_2026_06_09.py`)
- indicator: {K, A, R} (3)
- cardinality: 6 × 27 × 3 = 486

**Arm A3 — additive single-layer, breadth population (Tier 2, exploratory):**
- kinds: `vigenere`, `beaufort`, `variant_beaufort` (3)
- layer alphabet: `AZ`, `KA` (2)
- keyword: `wordlists/english.txt` filtered (uppercase A–Z only,
  length 4–11, deduplicated, sorted) — ~742,705 words
- cardinality: ≈ 4,456,230
- sharding: per (kind × alphabet) pair, the sorted keyword list is split
  into deterministic contiguous chunks of ≤ 10,000; each chunk is one
  HypothesisSpec. Sharding is an artifact-size measure only; the
  arm-level universe is the union and is hashed over the full list.
  (Amended from ≤ 20,000 before any config executed: the DSL ParamRange
  per-axis cardinality cap is 10,000 — purely mechanical.)

Two-tier separation per `feedback_two_tier_preregistration`: A1/A2 are
the motivated, primary evidentiary tier; A3 is declared exploratory
breadth and any A3 hit is corrected over the FULL A3 cardinality. A1/A2
hits are corrected over their own arm cardinalities.

## 3. Scoring and dispatch path

- Real dispatcher only: `kryptosbot.job_dispatcher.execute()` per spec;
  kernel-verified scores only (`score_candidate_free` via
  `_score_real_k4_candidate`, `scoring_mode="free"`). No ad-hoc scoring.
- Free crib score support is {0, 11, 13, 24} (BC anywhere / ENE anywhere
  / both). Free scores are NEVER compared to anchored scores or anchored
  nulls (G-1).
- p-values: G-1 free-matched nulls (`null_baselines/manifest.json`,
  `__free` entries, kernel commit `ceb8e02` rebuild), free-matched
  family per arm: additive arms → matched `vigenere`/`beaufort`/
  `variant_beaufort` free nulls; A2 → free `random_text` null (no
  quagmire family null exists; declared as a conservative analytic
  stand-in, see §5 caveat).

## 4. Controls (run BEFORE the arms; campaign aborts if any fails)

- **C1 (kernel):** `score_candidate_free` on a constructed 97-char PT
  with EASTNORTHEAST at offset 5 and BERLINCLOCK at offset 60 returns
  crib_score 24 with `canonical_positions=False`.
- **C2 (worker path):** `job_dispatcher._evaluate_one` on a synthetic
  CT = vigenere_encrypt(crib-bearing displaced PT, keyword=PALIMPSEST,
  AZ) with a work item of the same shape as arm A1
  (`crib_alignment="free"`, challenge_ciphertext=synthetic) returns
  kernel-verified crib_score 24, `scoring_mode="free"`. This is the
  same per-config function the pool executes.
- **C3 (standing):** the committed synthetic-zoo fixture F9
  (`kryptosbot/tests/test_synthetic_benchmark_zoo.py`) pins the full
  `execute()` end-to-end free solve; suite green at HEAD `ceb8e02`.

## 5. Null model and decision rules (FROZEN)

Per-config chance rates under the free-matched nulls (G-1, 50k samples
each + analytic `free_crib_substring` tail; manifest committed):
- additive families (uniform model): P(≥11) ≈ 2.4e-14, P(≥13) ≈ 3.4e-17,
  P(24) ≈ 8.1e-31 per config.
- Campaign-wide expectation under the null across ALL arms
  (≈ 4.46M configs): ≈ 1.1e-7 expected hits ≥ 11. The expected outcome
  under H0 is ZERO free hits anywhere.

**Why no M=200 empirical max-null replicate arm:** the free score
support is degenerate ({0,11,13,24}) and P(any hit) per replicate
universe is ≈ 1e-7; every replicate max would be 0 and the comparison
carries no information beyond the analytic tail. The empirical content
of the null is already carried by the G-1 50k-sample free calibrations
(committed); pipeline validity (the "could it even score a hit" risk
that max-null replicates also guard) is covered by controls C1–C3.
**Caveat (declared):** the analytic additive free null assumes
~uniform output letters; a periodic key can in principle place a crib
with probability far above the iid value for specific (window, length)
geometries. The decision rules below therefore treat ANY hit as
*investigate-first* (rule S), never as auto-signal, and the
verification step recomputes the hit's probability under a key-matched
empirical null before any claim.

**Decision rules:**
- **DETECT-24:** any config with kernel-verified free crib_score == 24 →
  solve-candidate protocol: (1) `canonical_positions` recorded; (2)
  per-char quadgram floor ≥ −4.5 on the full PT; (3) fresh-interpreter
  reproduction; (4) family-wise p vs free-matched null (Bonferroni over
  the arm cardinality); (5) red-team review. BREAKTHROUGH remains an
  INPUT to validation (AUDIT-3), not an announcement.
- **SIGNAL (rule S):** any config with free crib_score ∈ {11, 13} →
  investigate: recompute under a key-length-matched empirical null
  (50k random keys of the SAME length, same kind/alphabet, free-scored)
  before claiming anything; report family-wise corrected p over the arm.
- **CLEAN_NULL:** zero configs ≥ 11 in an arm → the arm closes as a
  bounded clean null over its hashed universe.
- No universe expansion after seeing results. Shard boundaries and
  budgets are fixed by this document plus the runner constants.

## 6. Scope statement (what a clean null does and does NOT close)

CLOSES (per arm, exactly): "single-layer {kinds} × {alphabets} ×
{hashed keyword list} decrypts of the carved 97-char K4 CT contain
neither disclosed crib as a contiguous substring anywhere in the
output." Detection-level closure for crib-bearing length-97 PTs under
those decrypts.

DOES NOT CLOSE: PT length ≠ 97 (null extraction / variable-length —
`feedback_pt_length_open_question`); multi-layer pipelines; keywords
outside the hashed lists; non-keyword (random/numeric) keys; quagmire_iv
or non-diagonal tableaus; KA-layer quagmire; key_tape / running-key
inners; fragment-level crib presence (<11 full-crib threshold);
mechanisms that disperse cribs non-contiguously (e.g., a transposition
APPLIED AFTER the substitution would scatter crib letters — this sweep
detects only contiguous presence in single-layer decrypt output).

## 6b. Arm A4 addendum (registered 2026-06-10 BEFORE A4 executed)

**Arm A4 — route-undo × additive, motivated keywords (Tier 1):**
- outer: `grille` layer, `hole_mask` = the canonical hash-locked 52-route
  reordering universe (SHA-256 `7a9ac673...`, loaded verbatim from
  `f_non_direct_alignment_tape_inner_2026_05_29.build_reordering_universe`,
  fail-closed on hash mismatch)
- inner: `vigenere`/`beaufort`/`variant_beaufort` × {AZ, KA} ×
  thematic keywords (same hashed list as A1)
- `crib_alignment="free"`; cardinality 52 × 3 × 2 × 339 = 105,768.

Distinctness: the 2026-05-28 crib-forcing closure covered route ×
periodic-additive with cribs FORCED at canonical positions after undo
(anchored). A4 detects the complementary event: a route+key decrypt
whose cribs surface at NON-canonical offsets (displacement surviving
the undo). Same frozen decision rules (§5); A4 hits corrected over
105,768. A4 clean null closes only this detection-level cell over the
hashed universes; everything in §6 "does not close" still applies.

## 6c. Arms A5/A6 addendum (registered 2026-06-10 BEFORE either executed)

**Arm A5 — two-layer columnar × additive, motivated keywords, both peel
orders (Tier 1):**
- layer 1 / layer 2 in BOTH orders (per `docs/search_policy.md`:
  test both peel orders): `columnar` (keyword-derived width+order,
  keyword = thematic list) and additive kind × {AZ, KA} × thematic.
- `crib_alignment="free"`; 3 kinds × 2 alphabets × 2 orders ×
  339 × 339 = 1,378,808 configs across 12 specs.
- Distinctness: anchored columnar×periodic sweeps are Bean-killed or
  sampled-closed under DIRECT alignment only; the free lens detects
  displaced-crib survivors of either peel order. Same frozen rules (§5);
  hits corrected over 1,378,808.

**Arm A6 — route × Quagmire III diagonal, free re-lens (Tier 1):**
- the exact 25,272-config universe of
  `f_route_outer_quagmire_iii_posttrans_2026_06_09` (52 hash-locked
  routes × 6 tableaus × 27 periods × {K,A,R}), re-scored with
  `crib_alignment="free"` instead of anchored post_transposition.
- Distinctness: the 2026-06-09 closure proves no config lands cribs AT
  canonical positions after route undo; A6 detects cribs surfacing
  ELSEWHERE in the undone stream. Same frozen rules; hits corrected
  over 25,272.

## 7. Compute plan

28-vCPU VM; dispatcher pool default (cpu_count − 2). A1+A2: minutes.
A3: 228 shard specs × 20k configs; throughput measured on the first
shard and recorded; total expected ≤ a few hours. Checkpointing =
per-shard artifacts under `results/free_alignment_classical/`;
`compute_budget_cpu_minutes=10` per spec (cap 2M ≫ 20k). Artifacts: one
JSON per shard (~8 MB), ~2 GB total; disk checked before launch.
