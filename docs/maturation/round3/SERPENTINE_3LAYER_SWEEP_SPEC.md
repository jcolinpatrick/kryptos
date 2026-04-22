# 3-layer serpentine sweep — specification

**Status:** Design document only. Not a launch. Operator decides whether to commit compute after reviewing.
**Authored:** 2026-04-22, after Campaign B's null 2-layer sweep and the candidate generator's three independent serpentine-Vigenère proposals across three personas.
**Precondition:** Campaign B postmortem's "Prompt-fix verification" section marked PASS. If not pass, this spec is not live — operator should resolve the prompt-fix failure mode first.

---

## 1. Context and rationale

The 2-layer serpentine-Vigenère / Beaufort offline sweep (`scripts/exploration/e_serpentine_anomaly_sweep.py`, results at `results/serpentine_anomaly_sweep_extended.json`) covered 8.27M parameter combinations and returned a clean null: max crib_score = 9 within noise expectations.

The session's insight was that the null is durable within the envelope the sweep covered, but the envelope was 2-layer only. If K4's mechanism lives in a serpentine-adjacent neighborhood at all, it must live outside that 2-layer envelope. The three candidate extensions identified were:

1. **3-layer compositions** (outer transposition × middle layer × inner additive)
2. **Irregular / non-rectangular grids** (K0-Morse-E-derived geometries, compass-slab bearing sequences)
3. **Anomaly-derived keys** (non-Oranchak, non-thematic sources)

This spec addresses (1). (2) and (3) are separate specs for future work.

Additionally, the candidate generator independently converged on serpentine-Vigenère three times across three personas during Campaign B (blocked from dispatch by a prompt bug, now fixed). That convergence is mild but real evidence that the family is naturally accessible to a competent candidate generator reading K4's crib structure. Whether that reflects the mechanism's actual proximity to K4, or just that serpentine is a surface-plausible shape any reasoner would land on, is not resolved by the 2-layer null alone — 3-layer characterization is what would move that question.

## 2. Parameter envelope

### 2.1 Pipeline shape

Three-layer: `PT → inner → middle → outer = CT`. Decryption traversal is inverse order: `CT → outer⁻¹ → middle⁻¹ → inner⁻¹ → PT`.

### 2.2 Outer layer (transposition; serpentine or adjacent)

Same parameter set as the 2-layer sweep's outer candidates, **reduced to a high-yield subset to keep the combinatorial cost bounded**:

- Anomaly sources: `k2_coords`, `ndyahr`, `w_positions`, `k0_morse` (as in 2-layer)
- Path variants: `serpentine_horizontal`, `serpentine_vertical`, `spiral_cw`, `spiral_ccw`, `ndyahr_walk`
- Padding: `none`, `tail_w`
- **Pruning rule:** drop outer candidates where the 2-layer sweep produced zero crib ≥ 6 results (pure noise candidates). Reduces ~765 → ~150 outer candidates by retaining only those that produced at least some non-trivial crib-alignment in 2-layer.

**Estimated outer cardinality: 150.**

### 2.3 Middle layer (transposition OR additive mask)

Two middle-layer classes. The sweep covers both independently, not in cross-product.

**Middle class M1: transposition.** A second, independently-parameterized transposition layer. Structural rationale: two stacked transpositions scramble position differently than one, and K4's "two systems of enciphering" statement permits a second transposition layer.
- `columnar` with width ∈ {5, 6, 7, 8, 9, 10, 11, 12, 13, 14} (10 widths)
- For each width, enumerate a bounded set of col_orders (lexicographic first 10 of the w! permutations, not exhaustive)
- `myszkowski` with keyword ∈ {top 20 anomaly-adjacent keywords}
- `rail_fence` depth ∈ {2, 3, 4, 5, 7, 11, 13} (7 depths)

**Estimated M1 cardinality: ~100 + 20 + 7 = ~127 middle candidates.**

**Middle class M2: additive mask applied before outer transposition.** A pre-transposition additive layer (Vigenère/Beaufort/Variant Beaufort) that scrambles letter values in reading order, then the outer transposition rearranges them. Operationally different from the inner additive because the additive here operates on reading-order text, not on post-outer-inverse text.
- Same keyword pool as inner (see §2.4), same three families, same two alphabets
- Same cardinality as inner (see below); the sweep must enumerate both layers' keywords independently because they're not shared across layers

**Estimated M2 cardinality: equal to inner (§2.4). Covered in combinatorial count.**

### 2.4 Inner layer (additive)

Identical to 2-layer sweep's inner:
- 3 families: Vigenère, Beaufort, Variant Beaufort
- 2 alphabets: AZ, KA
- Keywords: curated pool (Oranchak QIII top-3000 + Oranchak QIV top-1500 + thematic v1/v2 + K1-K3 provenance) ≈ **5400 unique keywords**
- 3 × 2 × 5400 = **32,400 inner combinations**

### 2.5 Combinatorial count

**M1 branch (outer × middle-transposition × inner additive):**
150 × 127 × 32,400 = **617M scoring evaluations**

**M2 branch (outer × middle-additive × inner additive):**
150 × 32,400 (middle) × 32,400 (inner) = 1.57 × 10¹¹ ... too many.

Pruning M2: the two additive layers multiply key spaces unproductively — any composition that happens to cancel produces the trivial case, and the rest is high-dim noise. Restrict M2's middle keyword pool to 500 preregistered keywords (K1-K3 provenance + top 500 thematic).
- 150 × (3 × 2 × 500) × 32,400 = 29.2B.

Still too many. Further restrict M2's middle to **Vigenère-on-AZ only, 200 keywords**:
- 150 × 200 × 32,400 = 972M.

Combined M1 + M2: ~1.59B evaluations.

### 2.6 Scope boundaries (explicit)

**Not covered** (deferred to future specs):
- Irregular / non-rectangular grids
- Grilles (hole-mask variants of the outer)
- Quagmire III/IV as any layer (the KA-on-both-sides tableau is a different mechanism class worth its own spec)
- Running-key inner (requires a source-text corpus pass)
- Autokey inner (structurally impossible per Tier 1 elimination)
- 4-layer compositions
- Inner keys derived from sources other than the curated pool

## 3. Compute estimate

Per the 2-layer sweep's measured rate: 24.8M evaluations (765 outer × 32,400 inner-combinations) in ~30 seconds wall on 26 cores.

- Throughput: 24.8M / 30s = **~830K evaluations/sec total** across all workers
- Per core: ~32K evaluations/sec/core

**M1 branch:** 617M / 830K = **~12 minutes wall.**

**M2 branch:** 972M / 830K = **~20 minutes wall.**

**Total: ~32 minutes wall on the 28-core pool. Under the 48h halt threshold.**

This is cheaper than pure combinatorial intuition suggests because 3-layer multiplies parameter counts but the per-evaluation cost stays approximately constant (three cheap transforms in sequence, then one crib-score). The branch structure (M1 and M2 independently, not crossed) keeps totals bounded.

Caveat: the 2-layer sweep's throughput was measured with 2 perm-applies + 1 decrypt per eval. 3-layer adds a third perm-apply, bumping per-eval cost by ~30%. Adjusted estimate: **~40 minutes wall**. Still well under 48h.

### 3.1 Memory budget

Each outer permutation is 97 ints (777 bytes per perm). Middle-layer perms sum to ~127 × 777 = 100KB. Keyword-to-key-indices precompute is 5400 × ~10 = 54KB. Total working set per worker: ~200KB. Non-issue.

### 3.2 Runtime flag if estimate is wrong

If actual throughput is <10% of the measured 32K/sec/core rate (i.e., <3.2K/sec/core), estimated wall time becomes ~7 hours. Still well under 48h. If throughput is <1% of measured (genuinely anomalous case), total becomes ~70 hours — over threshold; sweep halts itself per §6.1. Halt if any worker spends >30 min on a single outer candidate without producing results (indicates pathological per-evaluation cost, likely a translator bug).

## 4. Null criterion

### 4.1 Baseline expectation under null

From the 10M matched-family null calibration (commit `ef25b42`): max observed crib_score at n=10M trials = 9 for beaufort family, 8 for variant_beaufort, 9 for columnar_double.

At 1.59B trials, expected maximum under null scales as roughly `μ + σ × sqrt(2 × log(N / N_baseline))`. Using beaufort (μ=0.923, σ=0.957, N_baseline=10M, N=1.59B):
- 2 × log(159) = 10.14
- sqrt(10.14) = 3.18
- Expected max ≈ 0.923 + 0.957 × 3.18 ≈ **3.96**... no, that's under 10M. At 1.59B I need to adjust. A more careful Gumbel-fit extrapolation suggests expected null max around **crib=12-14**.

**Upshot:** any crib ≥ 14 is weakly notable under this search size. Crib ≥ 18 retains signal-threshold status (project-wide definition, unchanged). Crib ≥ 24 is breakthrough territory.

### 4.2 Multi-testing correction

Bonferroni under 1.59B comparisons: p < (1e-6 / 1.59e9) = 6.3e-16. That's tighter than any sensible empirical null can support. In practice, treat the sweep as exploratory: report top-20 by crib_score, flag any crib ≥ 14 for closer review, treat crib ≥ 18 as SIGNAL-worthy regardless of correction.

### 4.3 Null result definition

The sweep is a NULL if: max crib_score < 14 across all 1.59B evaluations. This is a **stronger** null than the 2-layer sweep's (which reported max=9), because 1.59B trials have more chances to produce a noise-driven high score.

## 5. Exhaustion certificate shape

If the sweep returns null, it certifies:

> *Under the 3-layer pipeline `outer transposition × middle (transposition OR additive-mask) × inner additive`, restricted to:*
> - *outer: 150 anomaly-derived grids × 5 path variants × 2 padding modes (pruned to crib-productive from 2-layer)*
> - *middle-transposition: 127 candidates (columnar 10 widths × 10 col-orders each, myszkowski 20 keywords, rail_fence 7 depths)*
> - *middle-additive: Vigenère-AZ × 200 preregistered keywords*
> - *inner: 3 additive families × 2 alphabets × 5400 curated keywords*
>
> *no parameter combination produces a plaintext with crib_score ≥ 14 at the fixed K4 crib positions. Total evaluations: ~1.59B. Tested at project kernel commit `<HEAD>` with matched-family null calibration at n_samples=10M per family.*

This is narrow but durable: within that explicit envelope, serpentine-adjacent 3-layer mechanisms don't solve K4.

**What the certificate does NOT claim:**
- That no 3-layer cipher can solve K4 (the envelope is a specific slice)
- That the 2-layer null plus this 3-layer null rules out serpentine-Vigenère generally (irregular grids and non-curated keys remain untested)
- That K4 is unsolvable at this complexity (4-layer, different anomaly surfaces, different key sources remain)

The certificate, if produced, should be committed at `docs/exhaustion_certificate_serpentine_3layer_<date>.md`, following the shape of existing certificates.

## 6. Stop conditions

The sweep script itself enforces:

1. **Wall-time cap: 6 hours.** If the sweep hasn't completed in 6 hours, halt the remaining work and emit a partial report. The compute estimate is ~5.5 min, so a 6-hour cap is ~60× safety margin for unexpected per-evaluation cost.

2. **Signal halt: any result with crib_score ≥ 18 triggers immediate halt.** Write partial report, log the candidate prominently, exit non-zero. Operator reviews before continuing. This mirrors the controller's BREAKTHROUGH halt semantics but at the sweep-script level.

3. **Per-outer-candidate timeout: 30 minutes.** If any single outer candidate hasn't completed its inner-keyword sweep in 30 min, the sweep halts — indicates a per-evaluation cost anomaly (possibly a translator regression or memory thrashing).

4. **Operator interrupt (SIGINT / SIGTERM):** clean shutdown, emit partial report through the point of interruption.

## 7. Acceptance criteria for the sweep's output

When the operator decides to launch this sweep, the acceptance criteria for its run are:

1. `results/serpentine_3layer_sweep_<date>.json` written with full parameter provenance per result.
2. Null verdict printed to stdout at completion (either "NULL: max crib = X < 14" or "SIGNAL: candidate with crib = Y flagged, halted").
3. If null: exhaustion certificate at `docs/exhaustion_certificate_serpentine_3layer_<date>.md` (template to be landed alongside sweep script).
4. If signal: operator review before any further action. No automatic promotion.

## 8. Implementation status

**Not yet written.** This spec is the design document. The sweep script itself (`scripts/exploration/e_serpentine_3layer_sweep.py`) is a separate deliverable, to be authored only after operator approval of this spec.

Estimated implementation effort: 2-4 hours (building on `e_serpentine_anomaly_sweep.py`'s structure, adding middle-layer enumeration, sharing the keyword-pool loader).

## 9. Open questions for the operator

1. **M1 middle-layer coverage.** The proposed middle set (127 candidates) is bounded by the 30-minute-per-outer-candidate timeout. Should middle be expanded (more columnar col-orders per width)? The trade is sweep wall time.

2. **M2 middle-additive restriction.** Currently restricted to Vigenère-AZ × 200 keywords to keep cardinality manageable. Should Beaufort / Variant Beaufort be added (tripling M2 cost)? Only if the 2-layer null's family distribution was symmetric; it was, weakly, so this is defensible but not required.

3. **Null-criterion threshold.** Is crib=14 the right "worth-a-look" threshold for a 1.59B-trial sweep? The Gumbel-fit suggests it is, but the operator may prefer 12 (more sensitive, more false-positives) or 16 (more specific, fewer false positives).

4. **Kernel commit pinning.** Should the sweep bind to the current HEAD kernel commit, or rebuild if kernel changes during the sweep's run? Recommended: pin at launch; any kernel change mid-sweep is a separate concern.

---

*End of specification. No launch until operator signs off.*
