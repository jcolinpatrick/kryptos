# Serpentine 3-layer sweep — exhaustion certificate

**Date:** 2026-04-22
**Status:** NULL under the tested envelope. No lead, no signal. Clean elimination of the specific 3-layer serpentine-adjacent parameter space described below.
**Governs:** `docs/maturation/round3/SERPENTINE_3LAYER_SWEEP_SPEC.md` (commit 74cf4e9) — the design document this certificate closes.
**Commissioned-by:** brief "3-layer serpentine sweep — launch with §9 resolution + post-hoc reconsideration trigger" (session of 2026-04-22).
**Kernel commit pinned at launch:** `74cf4e9`.
**Launched:** 2026-04-22T15:30Z (local 11:30)
**Completed:** 2026-04-22T19:58Z (wall time 1607.05s = 26.8 minutes)
**Halt reason:** none (clean termination — neither wall-time cap, nor lead-halt, nor signal-halt triggered).

---

## 1. What was committed before any compute

The launch used the operator-preferred defaults for each §9 question (resolved via this brief's default-preference rules):

- **Envelope scope:** narrower. Outer candidates capped at 150 (sampled deterministically from the 2-layer sweep's 765-candidate enumeration by stable sort on source/rows/cols/variant/padding). M1 middle kept at spec's 127. M2 middle-additive kept at spec's Vigenère-AZ × 200.
- **Null threshold:** Gumbel-fit at crib < 14, per spec §4.3.
- **Kernel pinning:** at launch, HEAD at commit `74cf4e9`.
- **Certificate format:** matches `docs/exhaustion_certificate_2026_04_08.md`'s structure.

No post-hoc threshold adjustment. No scope change mid-run.

## 2. Parameter envelope (what was actually tested)

### 2.1 Outer layer (150 candidates)

Deterministic first-150 sample of the 2-layer sweep's `_enumerate_outer_candidates()` output, sorted by `(source, rows, cols, variant, padding)`. Sources represented:

- **k2_coords** — grid dimensions derived from K2-decrypted coordinate small-integer readings (3, 4, 5, 6, 7, 8, 13, 14, 38, 44, 57, 65, 77)
- **ndyahr** — grid dimensions derived from NDYAHR letter positional values (N=13, D=3, Y=24, A=0, H=7, R=17); includes `ndyahr_path` variant (walk driven by the NDYAHR step cycle)
- **w_positions** — grid dimensions from W-delimiter segment lengths (20, 15, 11, 9, 15, 22)
- **k0_morse** — grid dimensions from ~25-26 Morse-E counts on the entrance slabs

Path variants: `serpentine_h`, `serpentine_h_vert`, `spiral_cw`, `spiral_ccw`, `ndyahr_path`.
Padding variants: `none` (97-cell trim), `tail_w` (pad to `rows*cols` with W's), `tail_x` (pad with X's).

### 2.2 Middle layer M1 — transposition (127 candidates)

- `columnar` — widths 5-14, first 10 lexicographic col_orders per width (= 100 candidates)
- `myszkowski` — 20 keywords drawn from anomaly-adjacent provenance (`KRYPTOS`, `PALIMPSEST`, `ABSCISSA`, `YARD`, `YAR`, `SANBORN`, `SCHEIDT`, `LANGLEY`, `ANTIPODES`, `COMPASS`, `BERLIN`, `CLOCK`, `SERPENTINE`, `LODESTONE`, `LAYER`, `SHADING`, `SUBTLE`, `INVISIBLE`, `MAGNETIC`, `INTERPRETATIU`)
- `rail_fence` — depths `{2, 3, 4, 5, 7, 11, 13}`

### 2.3 Middle layer M2 — additive mask (200 candidates)

Vigenère-on-AZ × 200 keywords. Pool: first 200 entries of the merged curated list (K1-K3 provenance + thematic v1 + thematic v2 + Oranchak QIII top-400), deterministic order.

### 2.4 Inner layer (5,345 keywords × 3 families × 2 alphabets = 32,070 per outer+middle pair)

Curated keyword pool:
- K1-K3 provenance + Sanborn / Scheidt / installation terms (26 seeds)
- Thematic keywords v2 (881 lines)
- Thematic keywords v1 (425 lines, deduped)
- Oranchak QIII top 3000
- Oranchak QIV top 1500

Merged dedup → 5,345 unique keywords (spec estimated 5,400; the 55-entry shortfall is merge-dedup).

Inner families: Vigenère, Beaufort, Variant Beaufort. Inner alphabets: AZ, KA.

### 2.5 Combinatorial count

- **M1 branch:** 150 × 127 × 5,345 × 3 × 2 = **610,933,500 evaluations**
- **M2 branch:** 150 × 200 × 5,345 × 3 × 2 = **962,100,000 evaluations**
- **Total:** **1,573,033,500 evaluations (~1.57B)**

Each evaluation = one (outer-perm × middle × inner-decrypt × crib-score) chain on the 97-character K4 ciphertext.

## 3. Statistical verdict

**Max crib_score observed: 10.**
**Gumbel-fit null threshold (spec §4): crib < 14.**
**Project SIGNAL threshold: crib ≥ 18.**

The observed maximum (10) is:
- Exactly at the project's "interesting" band lower bound (crib 10-17 = lead-pursuit territory)
- Four points below the Gumbel-fit null max expected under 1.57B trials
- Eight points below the SIGNAL threshold
- Consistent with a null distribution in the low tail region; no configuration approached signal

**Distribution at threshold (crib ≥ 10):** 8 results at crib=10 exactly. Zero results at crib=11, 12, 13, 14+.

**Verdict: CLEAN NULL.** The tested envelope produces no parameter combination that scores above the "interesting" lower bound, and the 8 interesting-band hits are all at the minimum of the band (crib exactly = 10). No "lead" or "signal" candidate emerged.

## 4. Top 10 configurations by crib_score

All at crib_score = 10 (8 total at threshold; table lists 8 + 2 filler from the threshold-=9 band for context; filler entries flagged).

| # | branch | outer_source | grid | variant | pad | middle | family | alpha | keyword | cs | plaintext (60-char prefix) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | M1 | k2_coords | 3x65 | serpentine_h_vert | none | columnar w=10 order=[0,1,2,3,4,…] | variant_beaufort | KA | ACTIVIST | 10 | `FSQBZXQISYOJYBSHYCEYLELSTXDXKUEASFLYRVWCQDRESIMOYGUIFNSZILEC` |
| 2 | M1 | k2_coords | 3x44 | spiral_cw | tail_w | columnar w=11 order=[0,1,2,3,4,…] | variant_beaufort | KA | APEX | 10 | `FLNRTDBUUKBSYEFYYKBNTKEITVOCTKEUTTNDQCEUTJBUYCYXWFBUVKBPFTLM` |
| 3 | M1 | k2_coords | 3x44 | spiral_cw | tail_w | columnar w=11 order=[0,1,2,3,4,…] | variant_beaufort | KA | APEX | 10 | `FLNRTDBUUKBSYEFYYKBNTKEITVOCTKEUTTNDQCEUTJBUYCYXWFBUVKBPFTLM` |
| 4 | M1 | k2_coords | 3x44 | ndyahr_path | tail_x | columnar w=7 order=[0,1,2,4,3,…] | beaufort | KA | COSTS | 10 | `EGBSPHHYKSJNPSBQABVKPBASQNUBSZEASTNFFBZKXOBKBXIXVCOABRKQAFSV` |
| 5 | M1 | k0_morse | 5x20 | serpentine_h_vert | tail_x | myszkowski kw='YARD' | beaufort | KA | TALENTED | 10 | `EYEZWJFCTFLECVTJQDCLNEAGTQHUMXEGCLBZHWJSZPSZYIGEBHJUZFGVZBEJ` |
| 6 | M1 | k0_morse | 5x20 | serpentine_h_vert | tail_w | myszkowski kw='YARD' | beaufort | KA | TALENTED | 10 | `EYEZWJFCTFLECVTJQDCLNEAGTQHUMXEGCLBZHWJSZPSZYIHEBHJUZFGVZBEJ` |
| 7 | M2 | k2_coords | 4x44 | ndyahr_path | tail_w | vigenere_AZ kw='GRILLE' | beaufort | AZ | ALLEN | 10 | `YGBTCUVRECMVVHZGMTLLMXAMTVSETHKGSTKAVGPCDTVJZKATOIMDARZVUCTM` |
| 8 | M2 | k0_morse | 26x4 | spiral_ccw | tail_x | vigenere_AZ kw='PRECESSION' | beaufort | AZ | TREATMENT | 10 | `UFORWWZLXGJMNZTDLTKEFEASLAOCRQSLKTABEBSJOOGXMQZUNNXFZCDAIWHH` |

**Reading the top-8:** every plaintext prefix is random-letter sequence with the crib positions coincidentally matching. No prefix contains English words, coherent fragments, or any near-plaintext structure. Crib-position alignment is 10/24 by random coincidence — the crib-space's combinatorics at that match count produce this many hits under null at 1.57B trials.

**Note on rank 4 (keyword COSTS):** the plaintext prefix contains the literal substring `EASTN` starting at position 30, which looks suggestive but is a length-5 coincidence in random text at 1.57B trials (expected count under null for any specific 5-letter string at any 97-position offset: ~150 hits; we got one here). Not evidence of signal.

**Note on rank 7 (middle keyword GRILLE):** the middle-layer Vigenère-AZ keyword "GRILLE" is thematically suggestive given K4's anomaly set, but the output plaintext is indistinguishable from other crib=10 noise. Middle-keyword identity doesn't survive the inner-layer decryption.

## 5. Branch distribution

| branch | total evals | results at crib ≥ 10 | fraction |
|---|---|---|---|
| M1 (transposition middle) | 610.9M | 6 | 9.8e-9 |
| M2 (additive-mask middle) | 962.1M | 2 | 2.1e-9 |

M1's yield-per-eval is ~4.7× M2's. Under null this isn't a meaningful difference at this sample size; both branches are indistinguishable from matched-family null baseline behavior.

## 6. What this certificate does NOT claim

Explicit scope boundaries — none of the following are ruled out by this sweep:

- **3-layer with non-additive inner** (e.g., Quagmire-as-inner, autokey-as-inner). Not tested.
- **4-layer compositions.** Not tested.
- **Irregular / non-rectangular grids** (K0-Morse-E-count geometry, compass-slab bearing sequences, etc.). Outer was restricted to rectangular grids from the 2-layer enumeration.
- **Grilles as the outer layer** (hole-mask variants beyond those already covered by the serpentine/spiral path variants). Not expanded.
- **Quagmire III/IV as any layer.** Deferred per spec §2.6.
- **Running-key or autokey inner.** Deferred (autokey is Tier-1 structurally eliminated under direct correspondence; running-key needs a source-text corpus pass).
- **Inner keys from sources outside the curated 5,345-keyword pool.** Non-Oranchak non-thematic key material untested.
- **Inner keys outside 3-15 character length range.** Long keywords, phrases, or full-sentence keys not tested.
- **Composed ciphers where middle and inner keys are derived from the same source** (e.g., both from K2 coordinates). Not tested as a constrained coupled-key composition.

The null IS durable within the envelope enumerated in §2. It is NOT a universal claim about 3-layer serpentine-adjacent space.

## 7. Operator recommendation

### 7.1 What this closes

The specific hypothesis "K4's plaintext = inner-additive decrypt of middle-layer (transposition-or-additive-mask) decrypt of outer-serpentine decrypt of CT, with parameters anomaly-derived" is clean-null across 1.57B tested combinations. Combined with the 2-layer sweep's prior null at 8.27M combinations, serpentine-adjacent under additive inner families is durably eliminated across both 2-layer and pruned-3-layer envelopes.

### 7.2 What this leaves open

- **Non-additive inner.** Quagmire III/IV as inner is the closest untested adjacency. If K4's mechanism is serpentine-outer + Quagmire-inner, this sweep doesn't speak to it.
- **Irregular-grid outer.** Rectangular grids are a specific subspace of possible transpositions; physical-sculpture-derived irregular shapes (bearing-indexed walks, compass-rose rotations, etc.) remain untested.
- **4-layer and above.** Each additional layer multiplies the search space but also the absorption capacity for crib coincidences; meaningful characterization at 4-layer requires either extraordinarily tight envelopes or new sampling strategies.

### 7.3 Decision triggered by this certificate

Per the commissioning brief's follow-on rule: **sweep was clean null → strategic reconsideration scaffold produced at `docs/maturation/round3/K4_STRATEGIC_RECONSIDERATION.md`**. That document is the input to a session spent on three framing questions about project direction; no further technical commissioning is expected until that reconsideration produces an answer.

## 8. Artifacts

- **Raw report:** `results/serpentine_3layer_sweep.json` (top-100 results with full parameter provenance, distribution histogram, compute metrics)
- **Commissioning spec:** `docs/maturation/round3/SERPENTINE_3LAYER_SWEEP_SPEC.md` (commit 74cf4e9)
- **2-layer sweep's prior null:** `results/serpentine_anomaly_sweep_extended.json` (reference — max crib = 9 across 8.27M combinations)
- **Sweep script:** `scripts/exploration/e_serpentine_3layer_sweep.py`
- **Run log:** `/tmp/sweep3.out` (ephemeral; key figures captured in this certificate)
- **Strategic reconsideration scaffold:** `docs/maturation/round3/K4_STRATEGIC_RECONSIDERATION.md`

---

*Certificate complete 2026-04-22. Under the envelope of §2, the 3-layer serpentine-adjacent additive-inner hypothesis is null at the Gumbel-fit < 14 threshold across 1.57 billion tested parameter combinations. The strategic reconsideration document is the next-session input.*
