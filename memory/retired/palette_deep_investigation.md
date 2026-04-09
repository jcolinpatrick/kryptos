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

# Palette {B,G,I,K,O,W,Z} Deep Investigation — 2026-03-15 (Updated 2026-04-01)

> **Audit note (2026-04-01):** This documents Level C descriptive anomalies. All findings
> are post-hoc (discovered from the data, not predicted). P-values are uncorrected for the
> search breadth of ~1000 experiments. The palette was identified by SA optimization (data-
> discovered), not pre-specified. See `docs/claims_ladder.md` for evidence classification.

## Context

The 17 consensus null characters in K4 use ONLY 7 distinct letters. Three p-values exist
depending on the null model used:
- **Positional null** (draw 17 positions from K4's actual letter distribution): p ≈ 2.4 × 10⁻⁵ (~1/42K) — MC verified, 2M trials
- **Permutation test** (10M trials, uniform draws): p ≈ 3.0 × 10⁻⁵ (~1/33K)
- **Stirling analytical** (uniform alphabet, exact): p = 7.78 × 10⁻⁵ (~1/12.9K)

The positional null (first value) is the most appropriate because it accounts for K4's
non-uniform letter distribution. All values are uncorrected for search breadth.

This file documents a comprehensive 18-test investigation into the generating rule.

## Three Major Discoveries

### 1. KA Mod 5 Structure (P = 1/1993)

All 7 palette letters have KA (Kryptos Alphabet) index congruent to 0 or 3 mod 5.

The KA alphabet arranged in a 5-wide grid:

```
     col0  col1  col2  col3  col4
row0:  K*    R     Y     P     T       (* = palette member)
row1:  O*    S     A     B*    C
row2:  D     E     F     G*    H
row3:  I*    J     L     M     N
row4:  Q     U     V     W*    X
row5:  Z*    [end of alphabet]
```

Palette occupies ONLY columns 0 and 3 of this grid. The 11-letter superset
(all letters in columns 0 and 3) is {B,D,G,I,K,M,O,P,Q,W,Z}. The palette
is 7 of these 11, excluding {D,M,P,Q}.

The 4 excluded letters follow an alternating pattern within the grid:
- Row 0: col 0 selected (K), col 3 excluded (P)
- Row 1: BOTH selected (O at col 0, B at col 3)
- Row 2: col 3 selected (G), col 0 excluded (D)
- Row 3: col 0 selected (I), col 3 excluded (M)
- Row 4: col 3 selected (W), col 0 excluded (Q)
- Row 5: col 0 selected (Z), no col 3 entry

For rows 0,2,3,4, the selection alternates: col0, col3, col0, col3.

Probability of 7 random letters all falling in 11-letter superset: C(11,7)/C(26,7) = 0.000502.

### 2. Beaufort KA Key=N Maps {E,H,N,Q,S,T,V} to Palette

Under Beaufort encryption on the KA alphabet with constant key N (KA index 19):
- E -> B, H -> O, N -> K, Q -> Z, S -> G, T -> I, V -> W

The source set {E,H,N,Q,S,T,V} contains the word SEVEN.

Key=N is the ONLY key (of all 26) whose KA-Beaufort preimage of the palette
contains any meaningful English word from a tested list of 18 common words.

### 3. Beaufort BC Keystream 7/8 Palette (P = 1/1595)

The Beaufort keystream at BERLINCLOCK crib positions is:
```
pos 63: O  PALETTE
pos 64: C
pos 65: G  PALETTE
pos 66: G  PALETTE
pos 67: B  PALETTE
pos 68: G  PALETTE
pos 69: O  PALETTE
pos 70: K  PALETTE
pos 71: T
pos 72: R
pos 73: U
```

First 8 positions: 7/8 palette (87.5%). P(>=7/8 at baseline 7/26) = 0.000627.
Last 3 positions: 0/3 palette (includes self-encrypting position 73 where key=U).

This supports Beaufort as the cipher variant and suggests the key itself is
structured around the palette letters.

## Negative Results

All of these were tested and found to NOT explain the palette:

| Test | Result |
|------|--------|
| Affine map KRYPTOS -> palette | NO (both AZ and KA) |
| Quadratic map 0..6 -> palette KA | NO |
| Position formula char = f(pos) | Best 4/17 (linear), 8/17 (permutation cycling) |
| Caesar/Vig/Beau of any keyword | NO subset matches |
| Mod 49 null/nonnull separator | TRIVIAL (2 collisions, 25% prob) |
| Beaufort autokey DEFECTOR identity | Trivial: Beau(X,X)=A for all X |
| AZ->KA cycle structure | P=1/13, not significant |
| Varying mask palette enrichment | P=0.50, not significant |
| Row/col/diagonal pattern in grids | None found |
| Frequency ranking | Palette != bottom-7 letters |
| Odd/even CT counts | Palette != odd-count or even-count set |
| Crib letter overlap | Palette = {G,W,Z} outside cribs, {B,I,K,O} overlap |
| Complement = meaningful keyword | No (complement = ACDEFHJLMNPQRSTUVXY) |

## Grid Coordinate Discrimination (Null vs Non-null Palette Positions)

17 null palette positions vs 18 non-null palette positions share the SAME
KA mod 5 property (both are all in columns 0,3 of the 5-wide grid). The
discriminator between null and non-null is NOT a simple modular condition
on the position. No single modulus or pair of moduli perfectly separates them
(mod 49 works but is trivial due to low collision count).

The null/non-null distinction must come from a position-dependent rule
EXTERNAL to the letter identity (e.g., grid position, distance from cribs,
or interaction with the cipher layer).

## Implications

1. The palette is likely generated by a 5-wide grid structure on KA,
   which is Polybius-adjacent (5x5 is standard Polybius dimension).
   Scheidt's background includes Polybius-based ciphers.

2. The Beaufort KA key=N -> SEVEN connection is tantalizing but could be
   coincidental. N is the 14th letter of AZ (13 in 0-index). SEVEN has
   appeared in Kryptos analysis before (FIVE at grid seam, cylinder 5).

3. The BC keystream enrichment under Beaufort A=0 (7/8 palette, uncorrected p=0.000627)
   is consistent with Beaufort as the cipher variant. The first 8 key letters at BCL
   are almost all palette letters. [HYPOTHESIS] The key generation process and the
   null-insertion process may share common structure — this is a hypothesis, not a
   demonstrated mechanism.

4. The 4 excluded letters {D,M,P,Q} from the superset need further
   investigation. Their exclusion follows an alternating col0/col3 pattern
   across rows, which could be a checkerboard-type selection rule.
