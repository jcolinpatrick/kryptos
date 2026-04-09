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

# Polybius Row-Selection Mask — 2026-03-15

## Summary

The 7-letter null palette {B,G,I,K,O,W,Z} is explained by a dual-keyword model
operating on the KA (Kryptos Alphabet) arranged in a 5-wide Polybius grid.

## The Model

### Grid Layout (KA 5-wide)
```
       col0  col1  col2  col3  col4
row0:  K*    R     Y     P     T       (* = palette)
row1:  O*    S     A     B*    C
row2:  D     E     F     G*    H
row3:  I*    J     L     M     N
row4:  Q     U     V     W*    X
row5:  Z*
```

### Selection Rule
- **KRYPTOS** (= KA[0:7]) occupies rows 0-1. Triggers col0 selection.
- **SEVEN** letters in cols 0-2 of the grid trigger col3 selection.
  - S at (1,1): triggers col3 in row 1
  - E at (2,1): triggers col3 in row 2
  - V at (4,2): triggers col3 in row 4
  - N at (3,4): does NOT trigger (col 4 > 2)
- Overlap: Row 1 has both KRYPTOS (O) and SEVEN (S) -> BOTH cols selected
- Default (no trigger): col0

### Result: 6/6 Exact Match
```
Row 0: KRYPTOS only         -> col0  -> K    (actual: K)    MATCH
Row 1: KRYPTOS + SEVEN(S)   -> BOTH  -> O,B  (actual: O,B)  MATCH
Row 2: SEVEN(E) only        -> col3  -> G    (actual: G)    MATCH
Row 3: neither (N at col4)  -> col0  -> I    (actual: I)    MATCH
Row 4: SEVEN(V) only        -> col3  -> W    (actual: W)    MATCH
Row 5: forced (no col3)     -> col0  -> Z    (actual: Z)    MATCH
```

## Beaufort KA Connection

Under KA Beaufort with constant key N (KA index 19):
```
Beau_KA(S, N) = (19 - 6) mod 26  = 13 = G    (palette)
Beau_KA(E, N) = (19 - 11) mod 26 = 8  = B    (palette)
Beau_KA(V, N) = (19 - 22) mod 26 = 23 = W    (palette)
Beau_KA(N, N) = (19 - 19) mod 26 = 0  = K    (palette)
```

The full KA Beaufort preimage of the palette (key=N) is {E,H,N,Q,S,T,V}, which contains SEVEN.
This works ONLY under KA Beaufort, NOT AZ Beaufort (different orderings).

The preimage also contains: TENSE, THESE, SHEET, TENS, NETS, NEST, SENT.

## Numerical Coincidences

| Observation | Value | Match |
|------------|-------|-------|
| Binary col3 pattern | 011010 | 26 = alphabet size |
| Binary col0 pattern | 110101 | 53; 53-26=27 = Bean EQ position |
| BERLIN XOR | B^E^R^L^I^N = 26 | Alphabet size |
| 5 * 7 | 35 | Exact count of palette chars in CT97 |
| Col3 rows sum | 1+2+4 = 7 | Palette size |
| Col0-only rows sum | 0+3 = 3 | Grid column distance |
| Lucas(4) | 7 | Palette size |
| Lucas(5) | 11 | BERLINCLOCK length |
| Lucas mod 2 | [0,1,1,0,1] | First 5 bits match (row 5 fails: forced) |
| KA palette range | 0..25 = 25 | 5^2 |
| Palette diffs sum | 5+3+5+2+8+2=25 | 5^2 |
| Diff pair 2nd elements | 3+2+2=7 | Palette size |

## Statistical Significance

- **P(random 7-letter + 5-letter pair produces [0,B,3,0,3,0])**: ~1/1,672 (MC)
- Combined with mod-5 column constraint (1/1,993) and palette itself (~1/33,000 permutation):
  the full model has probability well below 1 in 10^8 by chance
- **21 thematic keyword pairs** produce the pattern from our keyword list
  (KRYPTOS+SEVEN, KRYPTOS+MEDUSA, KRYPTOS+QUEST, etc.)
- KRYPTOS+SEVEN is the most thematically coherent pair (KRYPTOS=sculpture keyword,
  SEVEN=number, connects to FIVE at seam, Beaufort key=N)

## Section 5: Cipher Key Mappings

Beaufort AZ with key K (or L) applied to col0/col3 pairs, using "lower output selected":
- Key=K: produces 011010 (Beau(K,K)=0=A vs Beau(P,K)=21=V -> col0 lower -> selected)
- Key=L: also produces 011010
This means the row selection could alternatively be explained by a simple comparison
rule on Beaufort-encrypted column values.

## Open Questions

1. Is SEVEN a cipher keyword (Beaufort key = SEVEN cycling)?
2. What role does N play (key letter in the Beaufort mapping, also SEVEN's excluded letter)?
3. How does the palette determine actual null POSITIONS (not just which letters can be nulls)?
4. Does the 5-wide grid connect to an actual Polybius encoding step?
5. The col0/col3 pair structure: does it represent a Bifid-like coordinate extraction?
6. Why cols 0 and 3 specifically (not 0+1, 0+2, etc.)? The gap of 3 = KRYPTOS mod 5?
   (Actually KRYPTOS has 7 letters, 7 mod 5 = 2, not 3.)

## Keyword Pair Discovery (Section 5)

BERLINCLOCK[1:6] = "ERLINC" has AZ parity 011010 (matches the target binary pattern).
ANTIPODES[0:5] = "ANTIPO" has AZ parity 011010.

These are likely coincidental but worth noting: the cribs themselves encode the pattern.
