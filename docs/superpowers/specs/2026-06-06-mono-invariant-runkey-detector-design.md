# Design Spec — Mono-Invariant Running-Key Detector (BIN-D / E-FRAC-54)

**Date:** 2026-06-06
**Status:** approved design, pending implementation plan
**Cell addressed:** BIN-D D1 — `Mono + Trans + Running-key`, the single three-layer
case flagged UNDERDETERMINED (not eliminated) by E-FRAC-54: "13 mono DOF saturate
fragment discrimination." The audit's prescribed fix (docs/exhaustion_audit_2026_04_08.md
D1): *"A detector that exploits positional information Mono can't swallow — e.g.,
word-level crib consistency across multiple cribs in a way that mono cannot arbitrage."*

## 1. Problem and core insight

A monoalphabetic substitution applies one bijection σ to every position, so any
quadgram/fragment scorer can be tuned by σ's 13 effective DOF to make recovered
running-key fragments look English — fragment scoring saturates (E-FRAC-54,
C-EFRAC54-01: provably non-discriminating at >13 mono DOF on n=97).

**The invariant σ cannot touch:** for two crib positions sharing the same letter,
the running-key *difference* between their images is fixed by the ciphertext and the
transposition alone, independent of σ. These **mono-invariant forced differences**
are also **running-key-source-invariant** (they are tested against generic English
lag-difference statistics, not a specific text). The detector therefore collapses
both the 13 mono DOF and the source-text DOF, leaving only the transposition to
enumerate over a bounded universe.

A prior attempt (`scripts/analysis/e_mono_runkey_discriminator_01.py`) implemented
this idea but on the **retired** CT73 null-extracted basis (imports
`CONSENSUS_NULL_POSITIONS`, `NULL_PALETTE`). This spec rebuilds it on the valid
CT97 / canonical-24-crib basis.

## 2. Models covered (both natural orderings; Trans is the middle layer)

Let `enc` be the encryption transposition (bijection PT-index → CT-index) drawn from
the declared universe (§5). Variants ∈ {vigenere, beaufort, var_beaufort}.

**Model 1 — mono-inner, runkey-outer:** `PT → σ → enc → +K → CT`.
At crib position p: `K[enc(p)] = additive_key(CT[enc(p)], σ(PT[p]))`. For a
same-PT-letter crib pair (p1,p2), σ(PT[p1])=σ(PT[p2]), so the forced difference
`Δ = K[enc(p1)] − K[enc(p2)] = ±(CT[enc(p1)] − CT[enc(p2)]) (mod 26)` (sign per
variant), at running-key lag `|enc(p1) − enc(p2)|` (running key is CT-indexed).
Constraints always exist (same-PT-letter pairs); lags depend on `enc`.
Independent constraints from K4 cribs: E→2, T→2, A,S,N,O,R,L,C→1 each = **11**.

**Model 2 — runkey-inner, mono-outer:** `PT → +K → enc → σ → CT`.
At crib position p: `M_{CT[enc(p)]} := σ⁻¹(CT[enc(p)]) = additive_pre(PT[p], K[p])`.
For two crib positions p1,p2 whose CT-images collide (`CT[enc(p1)] = CT[enc(p2)]`),
the forced difference `Δ = K[p1] − K[p2] = ±(PT[p1] − PT[p2]) (mod 26)` (value KNOWN
and fixed from cribs), at running-key lag `|p1 − p2|` (running key is PT-indexed).
Constraints exist only for image-colliding crib pairs (count depends on `enc`).

Both forced-difference sets are σ-invariant by construction. Convention bundle
(0-indexed; Vig K=CT−PT, Beau K=CT+PT A=0, VarBeau K=PT−CT) is imported from the
kernel; the sign of each Δ is derived from the variant, never hand-typed twice.

## 3. Statistical detector (Approach A — chosen)

**Lag-conditioned English model.** From a declared public English corpus, build
`P_Eng(δ | lag)` = empirical probability that two English letters at distance `lag`
differ by `δ (mod 26)`, for `lag ∈ 1..L_MAX` (default L_MAX=12; beyond that the
distribution is empirically ~uniform and contributes ≈0 LLR). Lag-1 is the
bigram-difference distribution (sharply non-uniform); large lags → uniform.

**Per-config score.** For a (model, variant, transposition) config with forced
differences `{(Δ_i, lag_i)}`:
`LLR = Σ_i log[ P_Eng(Δ_i | min(lag_i, L_MAX)) / (1/26) ]`.
A real running-key solution yields a high LLR (its forced differences match English);
a wrong transposition yields LLR ≈ 0 (differences ≈ uniform). σ and the source text
do not enter.

**Matched null + p-value.** The "is any transposition signal?" question has a
look-elsewhere burden over the whole transposition universe. Null: recompute the
**max-LLR over the identical transposition universe** on `N_NULL` independent
**letter-distribution-preserving shuffles of the full CT** (the SAME null for both
models — a CT shuffle changes Model 1's Δ values and changes Model 2's crib-image
collision structure). `p = (1 + #{null max-LLR ≥ real max-LLR}) / (1 + N_NULL)`.
This is the order-stat-correct matched null (cf. route_null doctrine): max-of-universe
real vs max-of-universe null.

Rejected alternatives: **B** (lag-1-only bigram test) discards lag>1 info and yields
no constraints for some transpositions; **C** (reconstruct + corpus-search the key) is
the known-failure E-FRAC-51/54 baseline — not σ-invariant, saturates.

## 4. Synthetic-recovery go/no-go (first-class gate)

Before any K4 verdict is trusted, validate the detector's own premise:

1. Build a synthetic K4-shaped CT: take the public K1/K2/K3 plaintext-style English
   PT of length 97 (or any declared English PT) with the canonical 24 crib LETTERS
   planted at canonical positions; encrypt with a REAL contiguous English running key
   `K*` (from a declared corpus, offset declared), a KNOWN transposition `enc*` from
   the universe, a KNOWN σ*, under each model/variant.
2. Run the detector. **PASS** iff `enc*` is recovered at LLR rank within the top-k
   AND its matched-null p-value < 0.05 (planted transposition stands above the null).
3. Sweep planting parameters (several `enc*`, several `K*` offsets, both models, 3
   variants) and record the **detection rate** and the **discrimination ceiling**
   (best separation of planted-vs-null LLR).

Outcome branches:
- **Detector has power** (detection rate above a pre-registered floor, e.g. ≥0.8 for
  Model 1) → trust the K4 verdict; run on real K4.
- **Detector underpowered** (cannot recover even planted solutions) → emit
  `DETECTOR_UNDERPOWERED` with the measured ceiling. This is a STRONGER, cleaner
  closure than E-FRAC-54: it proves the mono-invariant positional statistic — the
  best available — still cannot discriminate this family. The family stays
  underdetermined but the question "could a positional detector help?" is answered NO,
  with a number.

## 5. Transposition universe (declared elimination scope)

- **Columnar, all column-orderings, widths 6/8/9** (exactly E-FRAC-54's underdetermined
  set; ~720 + 40,320 + 362,880 ≈ 403,920 orderings) via `kernel.transforms.transposition.columnar_perm`.
- **52-route grid universe** {identity, reverse, colLR, colRL, serpRow, antidiag,
  spiralCW × widths 4,5,6,7,8,11,13,14,21,24} via `kernel.masking.route_null`.
- Hash-lock the enumerated universe; record its sha256 in the result.
- Detector cost per config is O(#cribs²) tiny, so the full universe is seconds–minutes.

## 6. Architecture (small, independently testable units)

```
src/kryptos/detectors/mono_invariant_runkey/
  __init__.py
  english_lag_stats.py     # build/cache P_Eng(δ|lag) from a declared corpus
  forced_differences.py    # (model, variant, enc) -> [(Δ, lag)]; Model 1 & 2
  llr_detector.py          # LLR over forced differences; given P_Eng
  transposition_universe.py# enumerate columnar w6/8/9 + 52-route grid; hash
  null_calibration.py      # shuffled-CT matched null, p-value
scripts/campaigns/f_mono_trans_runkey_detector_2026_06_06.py   # runner + synthetic gate + K4 sweep
docs/campaigns/mono_trans_runkey_detector_2026_06_06.md         # pre-registration
tests/test_mono_invariant_runkey_detector.py                    # unit + integration
```

Stdlib + kernel only for the detector modules (core kryptos is stdlib-only); the
runner may use the venv (numpy) for the shuffle null and corpus stats if helpful.
Each module answers: what it does / how to call it / what it depends on.

## 7. Verdict logic (two-sided, pre-registered)

Computed once; reported symmetrically:
- `DETECTOR_UNDERPOWERED` — synthetic recovery rate < pre-registered floor.
- `CANDIDATE_ESCALATE` — synthetic gate PASSED and real-K4 max-LLR p < 0.05 → name the
  (model, variant, transposition) config(s) for adversarial review (red-team +
  statistical-auditor) before any further compute.
- `CLEAN_NULL → ELIMINATED_UNDER_BOUNDED_MONO_TRANS_RUNKEY_UNIVERSE` (move D1 to bin B)
  — synthetic gate PASSED and real-K4 max-LLR within the matched null (p ≥ 0.05).
  Scope: this transposition universe × both models × 3 variants × declared English
  lag-stats; does NOT generalize to non-English keys (D2), non-enumerated
  transpositions, or non-additive inners.

## 8. Pre-registered thresholds (locked before real-K4 run)

- `L_MAX = 12`; `N_NULL = 2000` shuffles; corpus = declared public English (record
  source_id + sha256). Synthetic detection-rate floor: **Model 1 ≥ 0.80**, Model 2
  reported (collision-gated, expected lower). Real-K4 escalation gate: matched-null
  `p < 0.05` AND LLR per-constraint mean above the synthetic noise band. Stop rule:
  single bounded pass; no universe expansion after seeing real-K4 results.

## 9. Testing (TDD — write tests first)

- **Unit:** `forced_differences` Model 1 & 2 on a hand-constructed toy CT+enc where the
  Δ/lag values are computed by hand; assert exact match and σ-invariance (randomize σ,
  Δ unchanged). `english_lag_stats`: each `P_Eng(·|lag)` sums to 1; lag-1 entropy <
  log2(26) (non-uniform); large-lag entropy ≈ log2(26). `llr_detector`: LLR=0 on a
  uniform stub; LLR>0 when fed English-consistent differences.
- **Integration:** synthetic recovery — a planted (enc*, K*, σ*, model, variant)
  scores `enc*` strictly above all matched-null configs (Model 1). Shuffle control — a
  random CT yields max-LLR within the null band (no false escalation).
- All tests under `tests/`, run with `PYTHONPATH=src pytest`. Kernel self-test
  (`kryptos doctor`) unaffected (no kernel mutation). Known-answer readiness gate already
  GREEN this session.

## 10. Honesty / scope

This is a DETECTOR for a DETECTION limit, not a solver. The likely outcome is either a
clean `ELIMINATED` (moving D1 to bin B) or a quantified `DETECTOR_UNDERPOWERED` — both
durable. It is a narrow bounded test under a matched null, NOT a broad campaign (the
broad-campaign readiness verdict remains BLOCKED). K4 is not expected to be solved by
this build; a `CANDIDATE_ESCALATE` would be a lead requiring full adversarial review,
never a solution claim.
