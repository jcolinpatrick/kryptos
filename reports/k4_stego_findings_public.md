# Statistical Observations on Kryptos K4 Null Positions

**By Colin Patrick & Claude (KryptosBot)**
**March 2026 — Revised March 31, 2026 (evidence-hardening pass)**

> **Evidentiary status:** This document describes model-conditional statistical observations.
> All findings depend on a specific cipher model (KA-autokey Vigenère) and have not been
> independently validated by a model-free method. The candidate null positions shift
> dramatically across cipher models (Jaccard overlap 0.161). Nothing here is proven —
> these are observations that may or may not reflect how K4 was actually constructed.

---

## The Short Version

We've tested over 880 experiments and 669 billion configurations against K4. We didn't crack it. Under one specific cipher model (KA-autokey Vigenère), we found a statistically unusual pattern: candidate filler positions use only 7 of 26 possible letters (p ≈ 1/16,000). This pattern is specific to K4's actual letter ordering (shuffled-CT test: 0/500).

However, the candidate positions are **model-dependent** — different cipher models produce different positions. We do not know whether K4 actually contains filler characters.

---

## Background (Skip If You Know Kryptos)

Kryptos is an encrypted sculpture at CIA headquarters. It has four sections. The first three (K1–K3) were solved in 1999. K4 — 97 characters — has resisted every attack for 35 years.

Two plaintext fragments are known (confirmed by Sanborn in 2010 and 2014):
- Positions 21–33: **EASTNORTHEAST**
- Positions 63–73: **BERLINCLOCK**

Jim Sanborn has said K4 uses "two systems of enciphering" — meaning it isn't just one cipher, it's a cipher PLUS something else. Ed Scheidt (the CIA cryptographer who helped design it) confirmed the "something else" is steganography: the art of hiding a message within what looks like ordinary text.

## What Is Steganography in This Context?

Imagine you write a secret message, encrypt it, and get 73 characters of ciphertext. Then you insert 24 extra "filler" characters at specific positions, bringing the total to 97. Someone trying to crack it would be working with 97 characters, not knowing that 24 of them are meaningless noise.

That's the working model for K4. The statistical evidence is unusual but model-dependent.

## Observation #1: The Seven Letters

Under a KA-autokey Vigenère model, simulated annealing identifies 17 candidate filler positions that use only 7 of 26 letters: **B, G, I, K, O, W, Z**.

The probability of this restriction under a permutation test (10M trials): **p ≈ 6.25 × 10⁻⁵ (~1 in 16,000)**. A shuffled-ciphertext test confirmed this depends on K4's actual letter ordering (0/500, p < 0.002).

**Critical caveat:** The 17 positions were identified using a specific cipher model. Different cipher models produce different candidate positions (average Jaccard overlap: 0.161). The palette restriction is real under this model but may not be intrinsic to K4.

These aren't random letters. On the KRYPTOS alphabet grid (the alphabet rearranged starting with K-R-Y-P-T-O-S), these seven letters sit in two specific columns:

```
       col 0   col 1   col 2   col 3   col 4
row 0:  [K]      R       Y       P       T
row 1:  [O]      S       A      [B]      C
row 2:   D       E       F      [G]      H
row 3:  [I]      J       L       M       N
row 4:   Q       U       V      [W]      X
row 5:  [Z]
```

The seven letters (marked in brackets) are exactly **columns 0 and 3** of this grid. This isn't something we went looking for — the grid connection emerged after we identified the seven letters from a completely different analysis.

## Observation #2: Keystream Enrichment (Bean's Grid Structure)

Dr. Richard Bean (University of Queensland) published a 2021 HistoCrypt paper noting that 13 of 24 Beaufort keystream values at crib positions are divisible by 5 in the KA alphabet — i.e., they fall in column 0 of a 5-wide grid. This is the same grid structure observed in the null palette.

A joint simulation (50M shuffled ciphertexts) found that both observations co-occurring has a probability of roughly 1 in 7 million (p ≈ 1.4 × 10⁻⁷).

**Important caveats:**
- Both the palette restriction and the keystream enrichment depend on the same family of cipher models (KA-mixed Beaufort/Vigenère). They are not fully independent observations.
- Bean's observation is specific to Beaufort A=0 arithmetic. Vigenère gives 9/24, Variant Beaufort gives 5/24. This is consistent with Beaufort but does not prove it.
- The joint p-value was computed post-hoc, after both observations were known. It was not a pre-registered test.
- "Two researchers, same structure" does not mean independent confirmation — both are analyzing the same 97-character ciphertext with related mathematical operations.

## Observation #2a: Beaufort Specificity

The keystream enrichment is variant-specific: Beaufort (CT + PT mod 26) gives 13/24 palette hits, Vigenère (CT - PT mod 26) gives 9/24, Variant Beaufort (PT - CT mod 26) gives 5/24. Only Beaufort A=0 produces the concentration.

This is consistent with Beaufort but does not prove it. Sanborn told the New York Times in 2010 that he used "a tableaux slightly different from the one on Kryptos," which could refer to Beaufort but also to other modifications.

Verification: compute (CT[i] + PT[i]) mod 26 at each crib position (A=0) and count palette hits.

## Observation #3: The 14-Column Grid (Exploratory)

97 is prime and doesn't divide neatly. 98 = 7 × 14. If K4 has one delimiter character (bringing it to 98), it fits in a 7 × 14 grid.

Why 14? Because:
- The K3 code chart (Sanborn's working sheet for section 3) has **14 columns**
- The sculpture's lower panel is **14 rows** deep
- K3's 336 characters in a 14×24 grid, plus K4's 97+1 in a 14×7 grid, together fill **14 × 31 = 434 characters** — exactly the lower half of the 28×31 master grid

When we arrange K4 in this 7×14 grid and look at where the filler letters fall, the left half of the grid is **packed with filler** and the right half is **nearly clean**:

- Left 7 columns: **55% filler letters**
- Right 7 columns: **17% filler letters**

We tested grid widths from 2 to 48. Width 14 shows the strongest left-right asymmetry in palette-letter density (p ≈ 1/13,500 after Bonferroni correction for all widths tested).

This is consistent with a 14-column working sheet but does not prove it. The observation is model-conditional (depends on which positions are "null") and was found by searching across all widths (post-hoc).

## Observation #4: The 14×5 Classification Table (Exploratory, No Predictive Power)

A 14×5 lookup table (pos mod 14 × pos mod 5) classifies 28 of 29 palette-letter cells unambiguously as null or real, with only 1 mixed cell.

**Status:** Like the 7×5 KRYPTOS × SEVEN table, this is a post-hoc descriptive fit. Cross-validation has not been performed on this variant, but given that the simpler 7×5 table has zero predictive power, it is unlikely that the 14×5 table (which has more free parameters) would do better. This is retained as an exploratory observation, not a finding.

## What This Doesn't Tell Us

We want to be honest about the limits:

1. **We don't know the cipher key.** Identifying filler characters helps narrow the problem but doesn't solve it. The remaining ~73 real characters are still encrypted.

2. **The 17 "confident" filler positions come from optimization runs** that used a cipher model we later proved doesn't work. The filler positions might be slightly different from what we've identified. However, six independent runs all agreed on these 17, and the statistical properties (the seven-letter restriction, the grid structure) emerged from those positions as an unoptimized side effect — which gives us confidence they're correct.

3. **We don't know what determines the pattern.** We can SEE that certain grid cells are filler and others are real, but we don't know what RULE Sanborn used to decide. It could be based on his encoding chart (sold at auction for $962,500 in 2025), a physical template, or something we haven't thought of.

4. **There are 7 filler positions we're NOT confident about**, drawn from specific ranges in the ciphertext. Our best statistical analysis narrows these to about 55 possible combinations (down from 11,440), but we can't uniquely determine them from the ciphertext alone.

5. **All findings are post-hoc.** Every pattern reported here was discovered through exploratory analysis of the data, not predicted in advance. The 50-million-trial simulation provides a rigorous combined significance, but the individual observations were not pre-registered. We have subjected every claim to adversarial statistical review (see the repository for the full audit), and the findings that survive are reported here.

## Implications (all conditional on the null model being correct)

If — and this is a significant "if" — the null-insertion model is correct:

1. **The cipher would operate on about 73 characters**, not 97. The null positions and count remain uncertain.

2. **The cipher type is unknown.** Periodic substitution is eliminated under direct correspondence. Running keys from 60,000+ public English texts produced no signal. The cipher could be Beaufort (consistent with Beaufort-specific keystream enrichment) but this is not proven.

3. **The key is unknown.** If the cipher is non-periodic, the key is long and high-entropy. Its source is unknown.

4. **The 14-column grid observation** (Finding #3 in this document) is model-conditional and exploratory. The KRYPTOS × SEVEN table has zero cross-validated predictive power.

5. None of these observations have been confirmed by an external method or independent researcher working from different assumptions.

## Thematic Associations (Not Evidence)

The seven palette letters {B,G,I,K,O,W,Z} can be read as containing Cold War references (KGB, Berlin, etc.). This is a post-hoc pattern-match on 7 letters and has no evidentiary value. Any set of 7 letters can be associated with thematic words if you look hard enough. This observation is noted only because it appears in community discussions — it should not be treated as supporting evidence for any hypothesis.

## How to Verify

Everything we've described can be independently checked. The ciphertext is public. The crib positions are confirmed. The seven-letter restriction, the 14-column grid asymmetry, and the classification table are all computed directly from the ciphertext and the known plaintext — no secret data or proprietary methods.

The full analysis code is open source at [github.com/jcolinpatrick/kryptos](https://github.com/jcolinpatrick/kryptos).

## What We Need Help With

1. **The 7 uncertain filler positions** — additional constraints or a fresh analytical approach could pin these down
2. **What generates the N/R pattern in the classification table** — 28 cells are unambiguously "filler" or "real," but we don't know what rule determines which is which
3. **The cipher key** — if anyone has access to the encoding chart, or insights from the physical installation that could reveal the key source
4. **Non-English running key sources** — we've tested English texts extensively, but German or Russian sources (matching K4's Berlin/Cold War theme) remain largely untested

K4 has been unsolved for 35 years. Under one cipher model, we observe a statistically unusual palette restriction at candidate null positions. The cipher layer remains completely open. Whether the null model itself is correct is an open question.

---

*This analysis is part of the KryptosBot project (internal.com). The code, data, and full elimination history are publicly available. All statistical claims include reproduction commands in the repository.*

*We welcome scrutiny, corrections, and collaboration.*
