# K4 Constraint Specification

**Derived from stego-cipher coupling analysis. Any proposed K4 solution must satisfy these constraints.**

**Authors:** Colin Patrick + Claude (KryptosBot)
**Date:** 2026-03-23 (revised: keyword-independence audit)
**Pipeline:** `PYTHONPATH=src python3 -u scripts/analysis/stego_proof_pipeline.py --score`

---

## Overview

This document formalizes the constraints that any K4 decipherment mechanism must satisfy, derived from two independent sources: (1) Bean's 2021 cryptodiagnostic analysis of the ciphertext and known plaintext, and (2) our confirmed stego layer properties. The novel contribution is the **coupling constraints** — properties where the stego and cipher layers share structure.

**Important: Keyword-independence.** The strongest coupling constraints (C×S-1, C×S-3) are properties of the ciphertext and known plaintext. They do NOT depend on which keyed alphabet is used for the Polybius grid. A sweep of 980K English keywords found 6,309 that concentrate the palette in ≤2 grid columns — KRYPTOS is one, but not statistically distinguishable from the others. The alphabet-independent constraints are the real signal.

These constraints are organized into four tiers, from strongest to weakest.

---

## Tier 0 — Hard Constraints (violation = mechanism eliminated)

| ID | Constraint | Value | Source |
|----|-----------|-------|--------|
| HC-1 | Beaufort A=0 keystream at 24 crib positions | `JLJODEGKUKKKLOCGGBGOKTRU` (numeric: 9,11,9,14,3,4,6,10,20,10,10,10,11,14,2,6,6,1,6,14,10,19,17,20) | Derived from CT + known PT under Beaufort C=(K-P)%26, A=0 |
| HC-2 | Bean equality: k[27] = k[65] | Both = G(6) under Beaufort A=0. Variant-independent: equality holds under all three cipher variants. | Bean 2021, mathematical |
| HC-3 | 242 Bean inequalities | All satisfied. Variant-independent (hold under Vigenere, Beaufort, and Variant Beaufort simultaneously). | Bean 2021, mathematical |
| HC-4 | Non-periodic keystream | Proven for all periods 1-∞ on CT97 via Bean inequalities. | Mathematical proof |

**How to check:** Given a proposed keystream of 24 values at crib positions (0-indexed: 21-33 for EASTNORTHEAST, 63-73 for BERLINCLOCK), verify exact match against HC-1. If the mechanism claims periodicity, it is eliminated by HC-4.

---

## Tier 1 — Coupling Constraints (PRIMARY — novel contribution)

These derive from the intersection of confirmed stego properties and cipher layer properties.

### C×S-1: Keystream palette enrichment [ALPHABET-INDEPENDENT]

- **Observation:** 13/24 keystream values are palette letters {B,G,I,K,O,W,Z}
- **Expected under random:** 6.46 (24 × 7/26)
- **p-value:** 0.0043 (binomial tail)
- **Joint significance with palette restriction:** p = 1.4e-7 (MC 50M, proper joint simulation)
- **Alphabet-independent:** This is a property of the ciphertext at crib positions under Beaufort A=0. It holds regardless of which keyed alphabet (if any) is used for the Polybius grid. No keyword assumption required.
- **Implication:** The key generator preferentially produces values from the 7-letter null palette. The stego and cipher layers share a structural connection — the same set of letters is significant in both.

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
- **Implication:** Whatever process generates the null mask and whatever process generates the keystream draw on a common source — likely the same physical artifact (encoding chart). This is the "two systems, one grid" model.
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

## Stego Layer Proof (Foundation)

The coupling constraints rest on four confirmed stego properties:

| ID | Property | Observed | p-value | Method |
|----|----------|----------|---------|--------|
| S2 | Null palette restricted to {B,G,I,K,O,W,Z} | 7 distinct letters at 17 consensus null positions | 6.0e-5 | MC 100K trials |
| S4 | (pos%7, pos%5) classifies 35/35 palette positions | 35 correct (null vs real) | post-hoc, 0 DOF | Structural |
| S5 | Palette generated by KRYPTOS×SEVEN on 5-wide grid | One of ~6,300 keywords that work; thematically motivated but not unique | 0.0032 (for any keyword pair) | MC 50K trials |
| S6 | Zero nulls in crib ranges [21-33] and [63-73] | 0 overlap (17 nulls, 24 crib positions) | 0.0047 | Hypergeometric exact |

**S6 is the critical bridge:** Because no null positions overlap with crib positions, Bean constraints (which assume direct CT↔PT correspondence at crib positions) remain valid regardless of the stego model.

**S5 keyword-independence note:** KRYPTOS is the most thematically resonant keyword (it's the sculpture's name), but 6,309 other keywords produce the same column-concentration property. The palette itself {B,G,I,K,O,W,Z} is confirmed (S2); the specific keyword that generates it is not uniquely determined.

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

**Conclusion:** The real signal is C×S-1 (palette membership, p=0.0043) and C×S-3 (AP containment, p=3.9e-6). Column placement adds no independent information. The specific keyed alphabet remains unknown.

---

## Mechanism Compliance Checklist

Use this to evaluate any proposed K4 solution:

### Step 1: Hard Gates (all must pass)
- [ ] Does the mechanism produce keystream `JLJODEGKUKKKLOCGGBGOKTRU` at the 24 crib positions under Beaufort A=0?
- [ ] Does k[27] = k[65]?
- [ ] Do all 242 Bean inequality pairs have distinct key values?
- [ ] Is the mechanism non-periodic?

### Step 2: Coupling Properties (primary scoring — alphabet-independent)
- [ ] Do ≥13/24 keystream values fall in {B,G,I,K,O,W,Z}? (palette enrichment)
- [ ] Do ≥12/24 keystream values fall in {G,K,O}? (step-4 AP containment)
- [ ] Does the mechanism explain WHY keystream values are palette-biased? (structural coupling)

### Step 3: Supporting Evidence
- [ ] Is the minor differences sum ≤ 21? (Bean)
- [ ] Is the same-PT clustering mean ≤ 3.7? (Bean)
- [ ] Is the mechanism hand-executable?
- [ ] Does the key come from a shared source with the null mask?

### Scoring
- Any Step 1 failure → **ELIMINATED**
- Step 1 all pass + all Step 2 checks → **COMPLIANT**
- Step 1 all pass + some Step 2 checks → **PARTIAL** (investigate further)

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
