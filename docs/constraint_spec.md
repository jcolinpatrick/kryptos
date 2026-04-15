# K4 Constraint Specification — Retired Coupling Draft

**RETIREMENT NOTICE (2026-04-15): This is a historical coupling draft, not
a live constraint checklist. Do not use this document to eliminate or promote
candidate K4 mechanisms.**

The palette/null-mask foundation used by this draft (`NULL_PALETTE` =
`{B,G,I,K,O,W,Z}` and `CONSENSUS_NULL_POSITIONS`) was retired on
2026-04-14 as `null_palette_retired` / `C-PALETTE-01` after matched
controls showed the palette family was not specific. The numerical
computations below may still be useful as historical regression fixtures,
but CxS-1/CxS-3 and S2/S4/S5/S6 are not live evidence and are not mandatory
constraints for proposed K4 solutions. Current kernel behavior reflects
this retirement: `kryptos.kernel.constraints.stego` returns
`status="retired"`, and `kryptos.kernel.scoring.compliance` requires an
explicit palette parameter before computing palette-dependent terms.

Live hard constraints remain those independently derived from the canonical
CT, known crib assumptions, and Bean/admissibility math. See
`memory/project_consensus_nulls_epistemic_status_2026_04_14.md`,
`docs/a1_score_conditioned_null_report.md`, and `docs/claims_registry.json`.

**Authors:** Colin Patrick + Claude (KryptosBot)
**Date:** 2026-03-23 (revised: keyword-independence audit)
**Pipeline:** `PYTHONPATH=src python3 -u scripts/analysis/stego_proof_pipeline.py --score`

---

## Overview

This historical draft formalized constraints that were believed to follow
from two sources: (1) Bean's 2021 cryptodiagnostic analysis of the
ciphertext and known plaintext, and (2) project-internal stego-layer
properties that were then treated as confirmed. Source (2) is now retired.
The coupling constraints below therefore record a superseded hypothesis
family, not requirements that any K4 decipherment mechanism must satisfy.

**Retired framing:** Earlier versions called C×S-1/C×S-3
"alphabet-independent constraints" and "the real signal." That language is
no longer valid. Those checks are palette-conditioned descriptive
observations over a retired palette/null-mask construct.

The sections below are retained to preserve historical context and test
reproducibility, but only the Bean/crib-derived hard-constraint material
should be treated as active.

---

## Tier 0 — Bean/Crib-Derived Constraints (active only under stated assumptions)

| ID | Constraint | Value | Source |
|----|-----------|-------|--------|
| HC-1 | Beaufort A=0 keystream at 24 crib positions | `JLJODEGKUKKKLOCGGBGOKTRU` (numeric: 9,11,9,14,3,4,6,10,20,10,10,10,11,14,2,6,6,1,6,14,10,19,17,20) | Derived from CT + known PT under Beaufort C=(K-P)%26, A=0 |
| HC-2 | Bean equality: k[27] = k[65] | Both = G(6) under Beaufort A=0. Variant-independent: equality holds under all three cipher variants. | Bean 2021, mathematical |
| HC-3 | 242 Bean inequalities | All satisfied. Variant-independent (hold under Vigenere, Beaufort, and Variant Beaufort simultaneously). | Bean 2021, mathematical |
| HC-4 | Non-periodic keystream | Historical wording claimed all periods 1-∞; use current admissibility certificates / harness assumption bundles before citing any period elimination. | Mathematical proof / project rerun as applicable |

**How to check:** Given a proposed keystream of 24 values at crib positions
(0-indexed: 21-33 for EASTNORTHEAST, 63-73 for BERLINCLOCK), verify exact
match against HC-1 within the candidate's declared cipher variant,
coordinate system, and assumption bundle. Do not convert a failed check into
a global K4 elimination.

---

## Tier 1 — Coupling Constraints (RETIRED — historical only)

These derived from the intersection of retired stego properties and cipher
layer properties. They must not be used as live gates.

### C×S-1: Keystream palette enrichment [ALPHABET-INDEPENDENT]

- **Observation:** 13/24 keystream values are palette letters {B,G,I,K,O,W,Z}
- **Expected under random:** 6.46 (24 × 7/26)
- **p-value:** 0.0043 (binomial tail)
- **Joint significance with palette restriction:** p = 1.4e-7 (MC 50M, proper joint simulation)
- **Alphabet-independent:** This is a property of the ciphertext at crib positions under Beaufort A=0. It holds regardless of which keyed alphabet (if any) is used for the Polybius grid. No keyword assumption required.
- **Retired interpretation:** Earlier versions inferred that the key
  generator preferentially produced values from the 7-letter null palette.
  That inference is no longer load-bearing because the palette family is
  retired.

### C×S-2: Column concentration [ALPHABET-DEPENDENT — NOT INDEPENDENTLY SIGNIFICANT]

- **Observation:** Under the KRYPTOS-keyed alphabet (KA), 14/24 keystream values have KA_index mod 5 ∈ {0, 3}
- **Expected given C×S-1:** ~15.3 (13 palette letters guaranteed in palette columns + ~2.3 non-palette expected by chance). KRYPTOS at 14/24 is BELOW this expectation.
- **p-value (conditional on C×S-1):** not significant — the column coupling is entirely explained by palette membership.
- **Keyword sweep:** 6,309 of 980K English keywords also place the palette in ≤2 columns (0.64%). KRYPTOS is not statistically special among these. The best-performing keywords (DELPHI, KLIP, etc.) achieve 19/24 column coupling, but this is because they happen to place frequent non-palette keystream letters {L,U,D,R} in the palette columns — a structural coincidence, not a cipher signal.
- **Bean's mod-5 finding:** Bean (2021) reported mod-5 structure in the reversed-KA keystream (13/24, p≈1/1,470). This is EXPLAINED by C×S-1 (palette membership), not by the specific KRYPTOS keyword. Any keyword that concentrates the palette in 2 columns of a 5-wide grid would produce the same mod-5 signal.
- **Status:** Demoted from independent constraint to "explained by C×S-1." Retained for documentation but NOT scored in compliance evaluation.

### C×S-3: Arithmetic progression contained in palette [ALPHABET-INDEPENDENT]

- **Observation:** The values G(6), K(10), O(14) form a step-4 arithmetic progression in the standard (A=0) alphabet. All three are palette letters. These appear at 12/24 keystream positions (50%).
- **Expected under random:** 2.77 (24 × 3/26)
- **p-value:** 3.9e-6 (binomial tail)
- **Alphabet-independent:** The AP exists in the standard alphabet and the palette membership is a ciphertext property. Neither depends on any keyword choice.
- **Dual-alphabet observation:** The AP is arithmetic in AZ (step 4) but NOT arithmetic in the KA alphabet (gaps 5, 8). However, this observation depends on KA specifically. Under a different keyed alphabet, the AP gaps in that alphabet's ordering would differ. The AZ regularity is alphabet-independent; the KA irregularity is KA-specific.

### C×S-4: Stego-cipher structural coupling [ALPHABET-INDEPENDENT]

- **Observation:** The cipher keystream is enriched with the SAME 7 letters that form the stego null palette. This is not a coincidence (joint p = 1.4e-7). The two systems share structural parameters.
- **Retired interpretation:** Earlier versions inferred a common source for
  null mask and keystream generation. That inference is no longer
  load-bearing.
- **What this does NOT tell us:** Which specific keyed alphabet, keyword, or grid layout is used. The coupling is between the LETTER SETS, not between specific grid coordinates.

---

## Tier 2 — Bean Statistical Constraints (supporting evidence)

| ID | Constraint | K4 Value | Threshold | Source |
|----|-----------|----------|-----------|--------|
| SC-4 | Minor differences sum (KRYPTOS-set PT letters) | 20 | ≤ 21 | Bean 2021 Table 2, p=1/5,520 |
| SC-5 | Same-PT clustering mean distance | 3.615 | ≤ 3.7 | Bean 2021 Table 3, p=1/240 |

**SC-4 computation:** For each plaintext letter in {K,R,Y,P,T,O,S} that appears at multiple crib positions, find the corresponding ciphertext letters and compute the shortest circular distance between each pair in the standard alphabet. Sum all distances.

**SC-5 computation:** For ALL repeated plaintext letters (not just the KRYPTOS set), compute shortest circular distances between all pairs of corresponding ciphertext letters. Take the mean.

**Interpretation (Bean 2021):** These properties strongly indicate one-to-one letter substitution without transposition. The ciphertext letters for repeated plaintext letters are unusually close in the alphabet, consistent with a cipher alphabet that is "near" the standard alphabet (e.g., keyword-mixed).

---

## Tier 3 — Structural Constraints (qualitative)

| ID | Constraint | Inference Type | Notes |
|----|-----------|---------------|-------|
| XC-1 | Step-4 arithmetic regularity in AZ alphabet | Deductive (from C×S-3) | Alphabet-independent |
| XC-2 | Key generation has a component producing palette-biased output | Deductive (from C×S-1) | Alphabet-independent |
| XC-3 | Mechanism is hand-executable with graph paper | Historical (Sanborn's self-described capabilities) | |
| XC-4 | Key derived from a grid structure | **Abductive** (one explanation for palette bias, not the only one) | Grid width and keyword are unknown |

---

## Stego Layer Proof (RETIRED Foundation)

The coupling constraints rested on four properties that are now retired:

| ID | Property | Observed | p-value | Method |
|----|----------|----------|---------|--------|
| S2 | Null palette restricted to {B,G,I,K,O,W,Z} | 7 distinct letters at 17 consensus null positions | 6.0e-5 | MC 100K trials |
| S4 | (pos%7, pos%5) classifies 35/35 palette positions | 35 correct (null vs real) | post-hoc, 0 DOF | Structural |
| S5 | Palette generated by KRYPTOS×SEVEN on 5-wide grid | One of ~6,300 keywords that work; thematically motivated but not unique | 0.0032 (for any keyword pair) | MC 50K trials |
| S6 | Zero nulls in crib ranges [21-33] and [63-73] | 0 overlap (17 nulls, 24 crib positions) | 0.0047 | Hypergeometric exact |

**Current status:** These rows are historical regression targets only. They
do not confirm a stego layer and do not make Bean constraints valid
"regardless of the stego model." Bean constraints are valid only under the
assumption bundle actually used by a given harness or proof.

**S5 keyword-independence note (retired):** KRYPTOS is thematically
resonant, but many keywords produce the same column-concentration property.
The palette itself is not confirmed as live evidence.

---

## Keyword-Independence Analysis (2026-03-23)

A sweep of 980,332 English keywords tested which keyed alphabets place the palette {B,G,I,K,O,W,Z} in ≤2 columns of a 5-wide Polybius grid:

| Column pair | Keywords | Best KS coupling | Example keywords |
|-------------|----------|-------------------|-----------------|
| (0, 2) | 5,192 | 19/24 | DELPHI, KLIP, BALDRICK, LAKESIDE |
| (0, 3) | 1,039 | 19/24 | KRYPTOS (14/24), UNDESTRUCTIVELY |
| (1, 3) | 44 | — | — |
| (0, 1) | 18 | 19/24 | WINEMONGERS |
| Other | 17 | — | — |

**Key finding:** KRYPTOS achieves 14/24 keystream-in-palette-columns — BELOW the expected ~15.3 given that 13/24 are already palette letters. The "extra" column coupling for top-performing keywords (19/24) arises because they place frequent non-palette keystream letters {J,L,D,E,U,C,T,R} in the palette columns by construction. This is a structural coincidence of keyword choice, not a cipher signal.

**Current conclusion:** This analysis is superseded by the 2026-04-14
retirement. C×S-1 and C×S-3 are palette-conditioned historical
observations, not live signals.

---

## Historical Mechanism Compliance Checklist

This checklist is retained for historical context only. Use current kernel
APIs and current claim policy when evaluating proposed K4 solutions.

### Step 1: Bean/Crib Checks (scope-limited)
- [ ] Does the mechanism produce keystream `JLJODEGKUKKKLOCGGBGOKTRU` at the 24 crib positions under Beaufort A=0?
- [ ] Does k[27] = k[65]?
- [ ] Do all 242 Bean inequality pairs have distinct key values?
- [ ] Is the mechanism non-periodic?

### Step 2: Coupling Properties (retired; do not use as live scoring)
- [ ] Do ≥13/24 keystream values fall in {B,G,I,K,O,W,Z}? (palette enrichment)
- [ ] Do ≥12/24 keystream values fall in {G,K,O}? (step-4 AP containment)
- [ ] Does the mechanism explain WHY keystream values are palette-biased? (structural coupling)

### Step 3: Supporting Evidence (advisory)
- [ ] Is the minor differences sum ≤ 21? (Bean)
- [ ] Is the same-PT clustering mean ≤ 3.7? (Bean)
- [ ] Is the mechanism hand-executable?
- [ ] Does the key come from a shared source with the null mask?

### Scoring
- Any Step 1 failure → potentially **ELIMINATED**, but only within the
  exact assumption bundle being checked.
- Step 2 must not promote a candidate to **COMPLIANT** unless a caller
  explicitly opts into a palette-conditioned historical/regression
  calculation and labels it that way.

---

## Reproduction

All computations are reproducible:

```bash
# Run the full pipeline
PYTHONPATH=src python3 -u scripts/analysis/stego_proof_pipeline.py --score

# Run unit tests
PYTHONPATH=src pytest tests/test_stego.py tests/test_coupling.py tests/test_compliance.py -v
```

**Source modules:**
- `src/kryptos/kernel/constraints/stego.py` — Stego layer proof
- `src/kryptos/kernel/constraints/coupling.py` — Coupling constraint derivation
- `src/kryptos/kernel/scoring/compliance.py` — Compliance scorer

---

## References

- Bean, R. (2021). "Cryptodiagnosis of Kryptos K4." HistoCrypt 2021. [https://ecp.ep.liu.se/index.php/histocrypt/article/view/153]
- Patrick, C. & Claude (2026). KryptosBot computational analysis. [github.com/jcolinpatrick/kryptos]

---

*Generated: 2026-03-23. Revised: keyword-independence audit (C×S-2 demoted, 980K keyword sweep). Pipeline version: stego_proof_pipeline.py v1.0*
