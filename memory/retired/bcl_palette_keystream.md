---
status: RETIRED
retired_on: 2026-04-01
retired_reason: post-hoc selection artifact; SA produces 11 distinct letters on K4 indistinguishable from shuffled controls (p=0.30)
superseded_by: docs/a1_score_conditioned_null_report.md
epistemic_class: retired_claim (was descriptive Level-C anomaly)
notes: Do NOT cite as evidence. Do NOT build new hypotheses on top. See memory/retired/README.md.
---

> # RETIRED DOCUMENT — NOT AUTHORITATIVE
>
> This file is preserved for historical traceability only. The palette {B,G,I,K,O,W,Z}
> construct it depends on was **retired on 2026-04-01** as a post-hoc selection artifact.
> See `docs/a1_score_conditioned_null_report.md` for the score-conditioned null result
> that invalidated the 7-distinct-letter signal. Do not treat any claim in this file as
> a live finding. Do not use it to justify new compute.

# BCL Palette Keystream Deep Investigation — 2026-03-15 (Updated 2026-04-01)

> **Audit note (2026-04-01):** This document describes a Level C descriptive anomaly
> (see `docs/claims_ladder.md`). The Beaufort keystream values at crib positions are
> deterministic given CT and cribs, but interpreting them as "keystream" is specific
> to the Beaufort A=0 convention. The term "model-independent" used in earlier versions
> has been corrected to "ciphertext-intrinsic under Beaufort A=0." The raw p-values
> are uncorrected for the search breadth that led to this investigation.

## Context

The Beaufort keystream at BERLINCLOCK positions 63-70 is {O,C,G,G,B,G,O,K}: 7/8 are palette letters {B,G,I,K,O,W,Z}. P(>=7/8) = 0.000627 (1 in 1595). This investigation dissects the anomaly across all variants, indexings, autokey models, and null masks.

## Key Results

### 1. VARIANT SPECIFICITY [DERIVED FACT]

Only Beaufort A=0 achieves 7/8 palette at BCL first 8 positions.

| Variant | Indexing | BCL first 8 keystream | Palette count | P-value |
|---------|----------|----------------------|---------------|---------|
| Beaufort | A=0 | OCGGBGOK | **7/8** | **0.000627** |
| Vigenere | A=0 | MUYKLGKO | 4/8 | 0.142 |
| Vigenere | A=1 | MUYKLGKO | 4/8 | 0.142 |
| Beaufort | A=1 | QEIIDIQM | 3/8 | 0.370 |
| VarBeau | A=0 | OGCQPUQM | 2/8 | 0.679 |
| VarBeau | A=1 | OGCQPUQM | 2/8 | 0.679 |

A=0 vs A=1 matters for Beaufort (additive). Vigenere/VarBeau are difference-based, so indexing doesn't change the keystream letters.

### 2. ENE vs BCL ENRICHMENT [DERIVED FACT]

Beaufort A=0 keystream at all 24 crib positions:
- ENE (positions 21-33): JLJODEGKUKKKL = **6/13 palette** (P=0.109, NOT significant alone)
- BCL (positions 63-73): OCGGBGOKTRU = **7/11 palette** (P=0.012)
  - First 8: 7/8 palette (P=0.000627)
  - Last 3 (pos 71-73): 0/3 palette — T, R, U
- Combined: **13/24 palette** (expected 6.5, P=0.004)

The enrichment is concentrated at BCL, specifically the first 8 BCL positions (63-70). ENE is mildly enriched but not individually significant.

### 3. BCL KEYSTREAM VALUES ARE CIPHERTEXT-INTRINSIC UNDER BEAUFORT A=0 [DERIVED FACT]

The quantity k[i] = (CT[i] + PT[i]) mod 26 at crib positions is determined entirely by
the ciphertext and the known plaintext. It does not depend on any keyword or autokey chain.
However, this quantity is only interpretable as a "keystream" under the Beaufort convention
(C = K - P mod 26, so K = C + P mod 26). Under Vigenère (K = C - P), the keystream values
are different letters and the palette enrichment disappears (4/8, p=0.142 — see §1 table).
The 7/8 enrichment is therefore specific to the Beaufort A=0 convention, not model-invariant.

### 4. AUTOKEY BACKWARD CHAIN: PT[55-62] = OCGGBGOK [DERIVED FACT, MODEL-DEPENDENT]

Under DEFECTOR:AZ_beau autokey (period 8, PT-feedback), the autokey key at position p (for p >= 8) equals PT[p-8]. Therefore the keystream values at BCL equal the plaintext 8 positions earlier:

| BCL pos | CT | PT (crib) | Beau keystream | = PT[pos-8] | Palette? |
|---------|-----|-----------|----------------|-------------|----------|
| 63 | N | B | O(14) | PT[55]=O | YES |
| 64 | Y | E | C(2) | PT[56]=C | no |
| 65 | P | R | G(6) | PT[57]=G | YES |
| 66 | V | L | G(6) | PT[58]=G | YES |
| 67 | T | I | B(1) | PT[59]=B | YES |
| 68 | T | N | G(6) | PT[60]=G | YES |
| 69 | M | C | O(14) | PT[61]=O | YES |
| 70 | Z | L | K(10) | PT[62]=K | YES |

**NOTE**: The "PT[55-62] = OCGGBGOK" interpretation is ONLY valid if DEFECTOR:AZ_beau autokey is the correct cipher model applied to raw 97 characters with cribs at stated positions. Under the null-mask model, the autokey chain operates on the 73-char extracted text and the position mappings differ.

Positions 58, 59 are consensus nulls. Under this model, PT[58]=G and PT[59]=B, both palette letters.

### 5. RAW-97 AUTOKEY DOES NOT MATCH CRIBS [DERIVED FACT]

DEFECTOR:AZ_beau autokey applied directly to all 97 chars: ENE=0/13, BCL=0/11 crib matches. This is EXPECTED under the two-system model. The raw-97 autokey PT (Section 5 in script) is the "would-need-to-be" PT assuming cribs are correct AND keyword is DEFECTOR AND autokey operates on raw positions — these constraints propagate through the chain but produce internally inconsistent results (see Section 15: PT[63]=B is palette but key[71]=(CT[71]+PT[71])=T, not B; the autokey "key" and "keystream" are different quantities).

### 6. NULL-MASK AUTOKEY (73-CHAR) ALSO FAILS [DERIVED FACT]

All 6 known 15/24 masks + DEFECTOR:AZ_beau autokey on the extracted 73-char text: ENE=1/13, BCL=0/11. Total 1-2/24. The BCL keystream palette enrichment in 73-char space: 4-6/11 (weaker than raw-97's 7/11). Only 3/73 positions match between raw-97 and mask-0 autokey PTs.

### 7. PALETTE PT AT NULL POSITIONS: 0/17 [DERIVED FACT, RAW-97 MODEL]

Under the raw-97 autokey model, the implied PT at all 17 consensus null positions is: P, D, V, F, J, H, D, L, X, J, T, P, P, C, M, C, M. **ZERO** palette letters. This strongly ANTI-correlates: expected 4.6/17, got 0 (P=0.043).

The keystream at null positions: 3/17 palette (positions 12, 75, 84 have palette keystream I, I, K). This is below expected (4.6).

### 8. OVERALL PALETTE IN RAW-97 AUTOKEY PT [DERIVED FACT]

21/97 (21.6%) of the full implied PT are palette letters, vs expected 26.9%. BELOW baseline. The model does NOT propagate palette letters to null positions; instead it AVOIDS them at nulls.

### 9. THE CRITICAL CLARIFICATION [ANALYTICAL]

The Beaufort "keystream" k = (CT + PT) mod 26 and the autokey "operational key" are DIFFERENT quantities:
- Keystream: what you observe from knowing CT and PT (model-independent at crib positions)
- Autokey key: the value used to encrypt/decrypt (model-dependent, = PT[i-8] under autokey)

Under Beaufort autokey: PT[i] = (key[i] - CT[i]) mod 26, where key[i] = PT[i-8].
The "keystream" at position i is (CT[i] + PT[i]) mod 26 = CT[i] + (key[i] - CT[i]) = key[i] (mod 26).

Wait — these ARE equal! Under Beaufort: CT = key - PT, so CT + PT = key. The keystream IS the key.

Correction: Under standard Beaufort (CT = key - PT mod 26):
- key[i] = CT[i] + PT[i] mod 26 (recovering the key from known CT and PT)
- This IS the autokey key value when autokey is the model

So the 7/8 palette enrichment at BCL means: the OPERATIONAL KEY at positions 63-70 is almost entirely palette. Under autokey: key[63-70] = PT[55-62]. So PT[55-62] is mostly palette.

But the KEY is NOT the same as the AUTOKEY FEEDER for all models:
- Under periodic key: key is fixed by keyword, independent of PT
- Under PT-autokey: key[i] = PT[i-period]
- Under CT-autokey: key[i] = CT[i-period]

The fact remains: (CT[i] + PT[i]) mod 26 at BCL = 7/8 palette regardless of model.

## Implications

1. **Beaufort A=0 is uniquely palette-enriched** at BCL. This supports Beaufort as the cipher variant.

2. **The enrichment is a CIPHERTEXT PROPERTY**, not model-dependent. It means the encipherer chose CT at positions 63-70 such that CT[i] + BERLINCLOCK[i] mod 26 is almost always a palette letter. Under Beaufort, this means the key is palette; under other models, it means CT was crafted.

3. **The break at position 71**: key[71] = T (not palette). Under autokey, this would be PT[63] = B, which IS palette. But (CT[71] + PT[71]) = (5+14) = 19 = T. So even though B is palette, the sum CT+PT at position 71 is NOT palette. This is because the keystream depends on BOTH CT and PT, not just the key.

4. **No palette propagation to nulls**: The raw-97 autokey model does NOT create palette PT at null positions. The palette-null connection is in the CIPHERTEXT layer (CT letters at null positions), not the plaintext layer.

5. **Lowest uncorrected p-value**: The BCL first-8 keystream palette enrichment (uncorrected P=0.000627 under binomial null with p=7/26) has one of the lowest individual p-values among tested anomalies, alongside the palette diversity (uncorrected P ≈ 2.4 × 10⁻⁵ under positional null) and KA mod 5 (P=0.000502). These p-values are NOT corrected for the search breadth (~1000 experiments, hundreds of sub-hypotheses) that led to their discovery.

## Scripts and Results
- Script: `scripts/campaigns/e_bcl_palette_keystream_v1.py`
- Results: `results/bcl_palette_keystream.json`
