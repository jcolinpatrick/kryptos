# Elimination Confidence Tiers

**CRITICAL FRAMING:** Every exhaustive-search elimination in this project was conducted under the assumption of **direct positional correspondence** — meaning CT position N maps to PT position N with no transposition. The primary hypothesis (H1) is that a transposition layer exists, which means **the substitution families below have NOT been tested in their correct context as one layer of a multi-layer system.** Multi-layer testing was completed across 250+ experiments (see `reports/final_synthesis.md`).

**FRAC AGENT STATUS (2026-02-21, FINAL):** The FRAC agent has completed 55 experiments (E-FRAC-01 through E-FRAC-55). Mandate COMPLETE + running key gap closure + English key detection + three-layer model + mono inner layer + mono running key underdetermination + Bean-surviving period gap closed. Key results that affect this document:
- ALL fractionation families structurally eliminated (E-FRAC-21) — proofs hold WITH OR WITHOUT transposition
- **Columnar widths 5-15 + periodic substitution: ALL ELIMINATED at discriminating periods**
  - Width-5, Width-7: Bean-ELIMINATED (ZERO orderings pass Bean equality, E-FRAC-26/27)
  - Width-6: exhaustive, best 13/24, corrected p=0.485 = NOISE (E-FRAC-29)
  - Width-8: exhaustive, best 13/24, UNDERPERFORMS random (expected ≥14, E-FRAC-29)
  - Width-9: exhaustive, best 14/24, UNDERPERFORMS random (expected ≥15, E-FRAC-12)
  - Widths 10-15: sampled (100K each), all max 14/24, all underperform random (E-FRAC-30)
- **Simple transposition families ALL ELIMINATED at discriminating periods** (E-FRAC-32):
  - Cyclic shifts (96), reverse (1), affine (9,215), block reversal (47), rail fence (19), single swaps (4,656): ALL NOISE
  - Best score 13/24 from 14,035 permutations — BELOW random baseline (14/24)
- Bean constraint NOT informative for transposition identification (E-FRAC-31)
- SA key optimization on Bean-passing orderings: underdetermination artifact at period 12-13 (E-FRAC-28)
- "Bimodal fingerprint" pre-filter is likely a statistical artifact (E-FRAC-11) — agents should NOT rely on it
- K4's IC, lag-7 autocorrelation, and DFT k=9 peak are NOT statistically significant (E-FRAC-13/14)
- Beaufort key entropy signal RETRACTED — was a selection effect (E-FRAC-16→23→24→25)
- Crib positions validated as correct (E-FRAC-18)
- Multi-objective oracle for JTS: quadgram gap of 0.93/char between false positives and English (E-FRAC-34)
- Recommended JTS thresholds: crib=24 + Bean + quadgram > -5.0 + IC > 0.055 + word ≥6 chars
- **Bean impossibility proof (E-FRAC-35):** ALL periods 2-12, 14, 15, 17, 18, 21, 22, 25 eliminated for ANY transposition + periodic key. Only 8 of 25 periods (2-26) survive: {8, 13, 16, 19, 20, 23, 24, 26}. This is a UNIVERSAL PROOF holding for all 97! permutations.
- **Bean-surviving period validation (E-FRAC-36):** Hill-climbing at periods 8 and 13 (first two Bean-surviving periods) with Bean as HARD constraint. 175 false 24/24+Bean solutions found; ALL have quadgram < -5.0/char (best: -6.171). Multi-objective oracle discriminates at Bean-surviving periods too.
- **Autokey structural elimination (E-FRAC-37):** Autokey (PT/CT × Vig/Beau) + arbitrary transposition CANNOT reach 24/24. PT-autokey max=16/24, CT-autokey max=21/24. Autokey is MORE constrained than periodic keying. This is a structural elimination, not just noise.
- **Comprehensive key model Bean analysis (E-FRAC-38):** Progressive key BEAN-ELIMINATED (δ∈{0,13} only). Quadratic key BEAN-ELIMINATED (0/676 survive full Bean). Fibonacci key BEAN-ELIMINATED (0/676 survive). Running key is the ONLY structured model surviving Bean constraints.
- **Running key + structured columnar: ELIMINATED for known reference texts** (E-FRAC-49)
  - Widths 6, 8, 9 exhaustive: 16,597 Bean-passing configs × 7 texts × 3 variants, 8.4B checks, ZERO matches
- **Running key + ALL structured families: ELIMINATED for known reference texts** (E-FRAC-50)
  - Identity, cyclic, affine, rail fence, block reversal, double columnar: 17,306 Bean-passing configs × 7 texts × 3 variants, 8.8B checks, ZERO matches
  - Reverse and rail fence: Bean-INCOMPATIBLE (zero passes)
  - Combined with E-FRAC-12/29/30 (periodic keys): ALL structured transposition families eliminated with BOTH periodic and running key models from known texts
- **Running key from unknown English text + columnar: ELIMINATED** (E-FRAC-51)
  - 16,597 Bean-passing columnar configs × 3 variants scored for English-like key fragments
  - Best quadgram: -4.151/char, English 5th percentile: -3.551/char, gap: 0.6/char
  - ZERO configs produce English-like key fragments (0/16,597)
  - Extends E-FRAC-49/50 from 7 specific texts to ANY unknown English running key
- **Three-layer model Sub+Trans+Sub: ELIMINATED for columnar widths 6,8,9 + periods 1-12** (E-FRAC-52)
  - Model: CT=Enc₂(σ(Enc₁(PT,K1)),K2) with effective key K_eff[j]=K1[j%p1]+K2[inv(j)%p2] (non-periodic)
  - Bypasses E-FRAC-35's Bean impossibility proof (which only covers single periodic keys)
  - 17,124 Bean-eq configs × 143 period pairs × 2 c-types = 1.53M consistency checks
  - ZERO candidates at p1*p2 ≤ 50; 74 candidates only at p1*p2 ≥ 132, all gibberish (best Q=-5.87/char)
  - p1=1 (key-after-transposition) and p2=1 (single-key): both zero candidates
- **Mono+Trans+Periodic: ELIMINATED for columnar widths 6,8,9 + periods 3-12** (E-FRAC-53)
  - Monoalphabetic inner layer auto-satisfies 9 of 21 Bean-ineq pairs (different-letter)
  - Makes periods 3-7 potentially Bean-viable (bypasses E-FRAC-35's proof!)
  - But ZERO candidates at periods 3-7: bipartite consistency (13 letters + p residues, 24 eqns) too stringent
  - 34 candidates only at period 12 (underdetermined), all gibberish (best Q=-6.33)
- **Mono+Trans+Running key: UNDERDETERMINED** (E-FRAC-54)
  - 13 mono DOF (one shift per known PT letter) provide ~2.5/char quadgram improvement
  - ALL columnar configs AND random perms produce English-range key fragments when mono-optimized
  - E-FRAC-51's elimination (no mono) does NOT extend to the mono case
  - Fragment analysis CANNOT distinguish real English running keys from gibberish when mono present
- Full meta-analysis: `reports/frac_statistical_meta_analysis.md`

Read these tiers carefully before deciding what is and isn't worth testing.

---

## Tier 1: Mathematical Proofs (confidence: ~99.9%)

These are algebraic proofs, not search results. They are permanently valid unless the crib positions or ciphertext transcription are wrong. **Do not re-test these under their stated conditions.**

| Proof | What It Actually Eliminates | Conditions |
|-------|----------------------------|------------|
| Multi-layer proof (CT has 2 E's, PT needs 3) | All pure transposition-only ciphers (no substitution) | Requires CT and crib letters to be correct |
| Periodic polyalphabetic impossibility | All periodic substitution ciphers (period ≤26) under Vigenère, Beaufort, or Variant Beaufort with direct positional correspondence | Requires CT, cribs, AND direct correspondence |
| Hill 2×2 / 3×3 impossibility | Hill cipher with direct positional correspondence | Requires CT, cribs, AND direct correspondence |
| Vimark p=5 algebraic incompatibility | Vimark p=5 with direct positional correspondence | Requires CT, cribs, AND direct correspondence |
| Columnar width-5 Bean impossibility | Width-5 columnar transposition + any periodic substitution (all 120 orderings × all variants: ZERO Bean passes) | Requires Bean constraint (k[27]=k[65]) and CT correctness |
| Columnar width-7 Bean impossibility | Width-7 columnar transposition + any periodic substitution (all 5,040 orderings × all variants: ZERO Bean passes) | Requires Bean constraint (k[27]=k[65]) and CT correctness |
| Columnar width-6 exhaustive crib scoring | Width-6 columnar + periodic sub: exhaustive 720 orderings, max 13/24, corrected p=0.485 (NOISE) | Requires cribs and CT correctness (E-FRAC-29) |
| Columnar width-8 exhaustive crib scoring | Width-8 columnar + periodic sub: exhaustive 40,320 orderings, max 13/24, UNDERPERFORMS random (expected ≥14) | Requires cribs and CT correctness (E-FRAC-29) |
| Columnar width-9 exhaustive crib scoring | Width-9 columnar + periodic sub: exhaustive 362,880 orderings, max 14/24, UNDERPERFORMS random (expected ≥15) | Requires cribs and CT correctness (E-FRAC-12) |
| Columnar widths 10-15 sampled crib scoring | Widths 10-15 columnar + periodic sub: 100K samples each, all max 14/24, ALL underperform random (expected 15+) | Requires cribs and CT correctness (E-FRAC-30) |
| Simple transposition families | Cyclic shifts, reverse, affine, block reversal, rail fence, single swaps + periodic sub: 14,035 perms, max 13/24, BELOW random (14/24) | Requires cribs and CT correctness (E-FRAC-32) |
| **Double columnar (Bean-compatible widths)** | **9 width pairs (w6×w6, w6×w8, w8×w6, w6×w9, w9×w6, w8×w8, w8×w9, w9×w8, w9×w9) + periodic sub: 2,958,400 compositions, max 15/24, matches random. Prior test w9×w7 was flawed (w7 Bean-incompatible).** | **Requires cribs and CT correctness (E-FRAC-46)** |
| **Myszkowski transposition (widths 5-13)** | **226,390 unique permutations (exhaustive at w5-7, sampled at w8-13) + periodic sub: max 15/24, matches random. Tie structure provides no advantage over standard columnar.** | **Requires cribs and CT correctness (E-FRAC-47)** |
| **AMSCO/Nihilist/Swapped columnar (widths 8-13)** | **361,280 permutations (w8 exhaustive, w9-13 sampled 10K each × 4 variants): max 14/24, matches random. ZERO Bean passes (0.0%) — structurally Bean-incompatible. Combined with E-S-22 (widths 5-8): ALL widths 5-13 ELIMINATED.** | **Requires cribs and CT correctness (E-FRAC-48)** |
| **ANY transposition + periodic key (p=2-12,14,15,17,18,21,22,25)** | **PROOF: Bean inequalities structurally violated at these periods for ALL 97! permutations. Type 1: same-residue inequality. Type 2: Bean equality-inequality conflict.** | **Requires Bean constraint correctness (E-FRAC-35)** |
| **Columnar (w6/8/9) + periodic key at Bean-surviving periods (p=8,13,16)** | **17,124 Bean-eq configs × 3 periods × 3 variants = 154K checks. Period 8: max=14/24 = random. Periods 13/16: max=18/20 (underdetermination, random mean 13.4/16.3). ZERO 24/24 matches. Bean-surviving period gap CLOSED.** | **Requires cribs and CT correctness (E-FRAC-55)** |
| **Progressive key (k[i]=k[0]+iδ) + ANY transposition** | **BEAN-ELIMINATED: 38δ ≡ 0 (mod 26) → δ ∈ {0,13}. δ=0 is mono (trivial). δ=13 ≈ period-2 (Bean-eliminated by E-FRAC-35).** | **Requires Bean constraint (E-FRAC-38)** |
| **Quadratic key (k[i]=ai²+bi+c) + ANY transposition** | **BEAN-ELIMINATED: 0/676 (a,b) pairs survive full Bean inequalities.** | **Requires Bean constraint (E-FRAC-38)** |
| **Fibonacci key + ANY transposition** | **BEAN-ELIMINATED: 0/676 seeds survive full Bean inequalities.** | **Requires Bean constraint (E-FRAC-38)** |
| **Autokey (PT/CT) + arbitrary transposition** | **STRUCTURAL: Cannot reach 24/24 cribs. PT-autokey max=16/24, CT-autokey max=21/24. More constrained than periodic.** | **Requires cribs (E-FRAC-37)** |
| **Three-layer Sub+Trans+Sub (columnar w6/8/9, periods 1-12)** | **Non-periodic effective key K_eff[j]=K1[j%p1]+K2[inv(j)%p2] bypasses E-FRAC-35 but: ZERO candidates at p1*p2≤50, 74 candidates only at p1*p2≥132 all gibberish (best Q=-5.87/char). p1=1 and p2=1 also zero candidates. Analytically extends: (a) non-columnar families have ≤448 Bean-passing configs vs 17K columnar, so FP count remains 0 at small products; (b) periods 13+ produce underdetermined gibberish (same as p1*p2≥132 result).** | **Requires cribs, Bean, CT correctness (E-FRAC-52)** |
| **Mono+Trans+Periodic (columnar w6/8/9, periods 3-12)** | **Monoalphabetic inner layer auto-satisfies 9/21 Bean-ineq pairs (different-letter pairs), making periods 3-7 potentially Bean-viable (bypasses E-FRAC-35). But ZERO candidates at periods 3-7 (bipartite consistency too stringent: 5-9 redundant constraints). 34 candidates only at period 12, all gibberish (best Q=-6.33). Analytically extends: periods 13+ have 0 redundant constraints → underdetermined, producing gibberish candidates filtered by quadgram threshold.** | **Requires cribs, Bean, CT correctness (E-FRAC-53)** |

**What could invalidate Tier 1:** Only if the 24 crib positions are wrong (off-by-one, wrong character mapping) or the CT transcription has an error. The wave1 report already caught one VKB error (position 74 was listed as K→K self-encryption; actual CT[74]=W). If one error existed, others could too. The cribs themselves come from Sanborn's public announcements and are highly trustworthy, but the exact 0-indexed position mapping has been a source of bugs.

---

## Tier 2: Exhaustive Search Under Direct Correspondence (confidence: ~95% for what they claim; ~0% for the multi-layer question)

These eliminations are solid FOR THEIR SPECIFIC MODEL: "Is K4 cipher family X applied directly to positions 0–96?" The answer is definitively no. But they tell us NOTHING about whether K4 is "transposition σ applied to cipher family X." That question is wide open.

**Do not re-test these as single-layer, direct-correspondence ciphers. DO test them as the substitution layer after candidate transpositions.**

| Family | Configs Tested | Max Score | Status as Single-Layer | Status After Transposition |
|--------|---------------|-----------|----------------------|--------------------------|
| Vigenère (periodic, all variants) | ~3 billion | 14/24 | ELIMINATED | **ELIMINATED — periodic key at ALL transpositions: p2-7 Bean-impossible (E-FRAC-35 proof), p8+ noise/underdetermined (E-FRAC-55). ALL structured transposition families exhaustively tested (FRAC/TRANS/JTS: columnar w5-15, simple families, double columnar, Myszkowski, AMSCO, strip, grid reads). OPEN only for running key model (non-periodic).** |
| Beaufort / Variant Beaufort | ~500 million | 14/24 | ELIMINATED | **ELIMINATED — same as Vigenère (E-FRAC-35 proof is variant-independent). OPEN only for running key model.** |
| Gromark / Vimark (p=4–7) | ~12 million | 14/24 | ELIMINATED | **ELIMINATED — Vimark is periodic/linear recurrence. E-FRAC-35 covers periods 2-7. JTS linear algebra (E-JTS-08/11) proves ZERO consistent Vimark primers for columnar AND strip transpositions at ALL periods 2-13. E-FRAC-38 eliminates Fibonacci/progressive/quadratic recurrence keys via Bean.** |
| Quagmire I/II/III/IV | ~2 million | 17/24 (artifact) | ELIMINATED | **ELIMINATED — Quagmire uses periodic keyed-alphabet lookup. E-FRAC-35 covers periodic keying at p2-7 for ANY polyalphabetic cipher. E-TABLEAU-21 tested KA/PAL/ABS keyed alphabets + columnar + running key: ZERO in English range. JTS E-JTS-13 tested Quagmire variants + structured transpositions.** |
| Bifid / Playfair / Four-Square / Two-Square | ~4.9 billion | 11/24 | ELIMINATED | **STRUCTURALLY ELIMINATED** (E-FRAC-21: parity + alphabet proofs hold with or without transposition) |
| Nihilist | ~4.9 billion | 11/24 | ELIMINATED | **ELIMINATED — Nihilist substitution is periodic polyalphabetic. E-FRAC-35 covers p2-7 for ANY transposition. Nihilist transposition tested at w8-13: 0% Bean pass rate, structurally incompatible (E-FRAC-48).** |
| Autokey (PT and CT) | ~50,000 | 6/24 | ELIMINATED | **STRUCTURALLY ELIMINATED** (E-FRAC-37: cannot reach 24/24 even with arbitrary transposition; PT max=16/24, CT max=21/24) |
| Running Key (K1–K3 as keystream) | ~45,000 | 7/24 | ELIMINATED | **ELIMINATED for known texts + structured transpositions** (E-FRAC-49/50: columnar w6/8/9, affine, cyclic, double columnar × 7 reference texts × 3 variants = 0 matches out of 17B checks). **ELIMINATED for unknown English text + columnar** (E-FRAC-51: 0/16,597 in English range). **ELIMINATED for K1/K2/K3 as key** (E-JTS-12: 0 matches). **ELIMINATED for KA/PAL/ABS alphabets** (E-TABLEAU-21). OPEN only for unknown non-English source texts or bespoke transpositions. |
| Grid Rotation (K3-style) | ~14,000 | 7/24 | ELIMINATED | N/A (is itself a transposition) |
| Columnar + Vigenère (no bimodal pre-filter) | ~4 million | 12/15 | ELIMINATED (widths 5–10) | **ELIMINATED by FRAC — widths 5-15 comprehensively tested (E-FRAC-12/29/30), ALL noise. E-FRAC-35 proof covers ALL transpositions at p2-7. Extended to double columnar (E-FRAC-46), Myszkowski (E-FRAC-47), AMSCO/Nihilist/Swapped (E-FRAC-48), simple families (E-FRAC-32), grid reading orders (E-FRAC-45), strip transpositions (E-JTS-09/10/11). Bean-surviving periods closed (E-FRAC-55). Periodic key + ANY transposition = ELIMINATED at ALL periods.** |
| Weltzeituhr permutations | ~295 million | 14/24 | ELIMINATED | **ELIMINATED as transposition source — E-FRAC-35 proof covers ALL 97! permutations (including Weltzeituhr-derived) + periodic key. Running key + Weltzeituhr: covered by E-FRAC-50 (identity + simple families) but specific Weltzeituhr permutations not individually tested with running key.** |
| Additive mask + Vimark p=5 | ~3.375 billion | 16/24 | ELIMINATED (0 Bean passes) | **ELIMINATED — Vimark at p=5 is Bean-impossible (E-FRAC-35). JTS linear algebra (E-JTS-08/11) proves 0 consistent Vimark primers at p=5 for columnar and strip transpositions. Additive mask doesn't change periodicity.** |
| VIC-family / Chain Addition | ~2 million | noise floor | ELIMINATED | **VIC contains straddling checkerboard → STRUCTURALLY ELIMINATED** (E-FRAC-21) |

---

## Tier 3: Partial or Statistical Eliminations (confidence: 40–70%)

These were either incompletely tested or used statistical sampling of a space too large to exhaust. They warrant re-testing even under direct correspondence.

| Family | Concern | Confidence | Recommendation |
|--------|---------|------------|---------------|
| ~~ADFGVX~~ | ~~Status report acknowledges "without proper fractionation recovery"~~ | **99.9%** | **STRUCTURALLY ELIMINATED** (E-FRAC-21: parity impossible — output length always 2×N (even), K4=97 (odd). Proof holds with or without transposition.) |
| ~~Turning grille 10×10 (150K Monte Carlo)~~ | ~~Statistical sample of a space with ~2^50 possibilities; 150K samples provides negligible coverage~~ | **99.9%** | **ELIMINATED by universal proofs: E-FRAC-35 (ALL transpositions + periodic key at periods 2-7 violate Bean), E-FRAC-38 (only running key survives Bean), E-FRAC-44 (4^25 ≈ 2^50 options, expected FP = 0). Prior MC tests (E-S-18/70/72/104) superseded.** |
| ~~Straddling checkerboard~~ | ~~"Partially tested" per status report~~ | **99.9%** | **STRUCTURALLY ELIMINATED** (E-FRAC-21: produces digits 0-9, K4 has 26 letters. Proof holds with or without transposition.) |
| Foreign language keywords (~500K) | Only tested under already-eliminated cipher models, not independently | **~50%** | **Keywords themselves are not eliminated** — carry forward into TRANS/JTS searches |

---

## Tier 4: Never Properly Tested (confidence: 0%)

These hypothesis classes appear in the status report's "What We Have NOT Tested" section and remain fully open.

| Hypothesis | Why Untested | Assigned Agent |
|-----------|-------------|----------------|
| ~~Polyalphabetic consistency AFTER transposition~~ | **DONE — ALL FRAC experiments (E-FRAC-01 through E-FRAC-48) test polyalphabetic (periodic) key consistency after undoing candidate transpositions. Tested across: single columnar w5-15 (E-FRAC-12/29/30), simple families (E-FRAC-32), grid reading orders (E-FRAC-45), double columnar (E-FRAC-46), Myszkowski (E-FRAC-47), AMSCO/Nihilist/Swapped (E-FRAC-48). ALL at discriminating periods 2-7. ZERO signal above random.** | ~~TRANS/JTS~~ COMPLETE |
| ~~Double columnar transposition~~ | **DONE — 9 Bean-compatible width pairs, 2.96M compositions, max 15/24 = noise (E-FRAC-46)** | ~~TRANS~~ COMPLETE |
| ~~Myszkowski transposition~~ | **DONE — Widths 5-13, 226K unique patterns, max 15/24 = noise (E-FRAC-47)** | ~~TRANS~~ COMPLETE |
| ~~Turning grille (systematic, with constraints)~~ | **COVERED BY UNIVERSAL PROOFS — Turning grille permutations are a subset of S_97. E-FRAC-35 proves ALL 97! permutations + periodic key violate Bean at discriminating periods (2-7). E-FRAC-38 shows only running key survives Bean. E-FRAC-39 shows running key + ANY transposition is underdetermined. Prior Monte Carlo tests (E-S-18/70/72/104) with negligible coverage (10^-8 of 4^25 space) are superseded by universal proofs. Information-theoretic analysis (E-FRAC-44): 4^25 ≈ 2^50 options → expected FP = 0, so oracle is sufficient for this family, but periodic keying is already Bean-eliminated.** | ~~TRANS~~ COVERED |
| ~~Strip transposition + periodic/running key~~ | **DONE — JTS tested strip transposition at widths 7-13 + periodic Vig/Beau at periods 2-8, 13 (E-JTS-09). Also strip + running key from 7 texts (E-JTS-10): ZERO matches. Strip + Vimark linear algebra (E-JTS-11): ZERO consistent primers. ALL ELIMINATED.** | ~~JTS~~ COMPLETE |
| ~~Vimark/Gromark + transposition (linear algebra)~~ | **DONE — JTS linear algebra approach (E-JTS-08/11): Vimark recurrence is linear mod 26. 24×P system from crib constraints is overdetermined with P(consistent) ≈ 0. ZERO consistent primers for columnar w6-9 AND strip w7-13 at ALL periods 2-13. ELIMINATED.** | ~~JTS~~ COMPLETE |
| ~~K1/K2/K3 as running key for K4~~ | **DONE — JTS E-JTS-12: PALIMPSEST hypothesis. K1/K2/K3 PT, CT, concatenated, grid column order — ALL tested with 694K transpositions (columnar w6/8/9 exhaustive + strip w8-13). ZERO 24/24 matches. ELIMINATED.** | ~~JTS~~ COMPLETE |
| ~~Hill 2×2/3×3 + transposition~~ | **DONE — BESPOKE E-BESPOKE-42: Hill cipher after columnar transposition. Exhaustive at w6/8/9. ELIMINATED.** | ~~BESPOKE~~ COMPLETE |
| ~~Multi-objective SA over arbitrary permutations~~ | **DONE — BESPOKE E-BESPOKE-52: SA at periods 5, 7, 8, 13. At discriminating periods (5,7): cannot reach 24/24. At period 13: trivially reaches 24/24+Bean but all gibberish. Confirms FRAC underdetermination findings (E-FRAC-33/34/44).** | ~~BESPOKE~~ COMPLETE |
| ~~Non-standard cipher models (Polybius, affine, column/row-specific keys)~~ | **DONE — BESPOKE E-BESPOKE-50: Polybius coordinate, affine (12 multipliers), column-specific, row-specific, diagonal keys + columnar. Max 19/24 (row-specific at w6 = underdetermined). No viable candidates. ELIMINATED.** | ~~BESPOKE~~ COMPLETE |
| Bespoke physical transposition (S-curve, strip manipulation) | Cannot be enumerated without creative hypothesis | BESPOKE |
| ~~Non-standard tableau usage~~ | **DONE — 20 experiments (E-TABLEAU-01 to 20). Column reads, rotations, paths, physical keys, misspelling keywords, Hill 2×2, autokey, affine, cross-alphabet Quagmire, K3-method thematic keywords at Bean-surviving periods: ALL ELIMINATED. Tableau is for substitution, not key generation.** | ~~TABLEAU~~ COMPLETE |
| ~~Position-dependent alphabets~~ | **DONE — Equivalent to running key model. Tested via TABLEAU (non-standard key generation) and FRAC (running key + transposition underdetermined, E-FRAC-39). No structured position-dependent model survives Bean + crib constraints except running key from unknown text. K3-method keywords at Bean-surviving periods 8 and 13: ELIMINATED (E-TABLEAU-20).** | ~~TABLEAU~~ COMPLETE |
| ~~Fractionation with proper recovery (ADFGVX, straddling checkerboard)~~ | **DONE — ALL 10 fractionation families structurally eliminated** (E-FRAC-21). Proofs hold with or without transposition. | ~~FRAC~~ COMPLETE |

---

## The Meta-Risk: What If the Ceiling Is a Crib Error?

[HYPOTHESIS — not established fact]

The persistent 14–17/24 ceiling across all families has been interpreted as evidence of a transposition layer. There is an alternative explanation: if any crib positions are wrong, the true ceiling for the correct cipher would be <24/24, and every sweep would show a cap. The bimodal fingerprint (positions 22–30 match well, 64–74 don't) could reflect which cribs are correct rather than which positions are transposed.

**Mitigation:** The cribs come from Sanborn's own public announcements (2010, 2014, 2020) and are highly authoritative. But the wave1 report already caught one error in the project's "verified" knowledge base. The `constants.py` self-verification gate is our primary defense.

**FRAC agent test (E-FRAC-18):** Crib position sensitivity analysis COMPLETED. Result: no shift at any discriminating period (2-7) produces improvement above baseline. Self-encrypting positions confirmed (pos 32 S→S, pos 73 K→K). The published positions (21-33 for ENE, 63-73 for BC) are validated. The crib error hypothesis is effectively ruled out.

**FRAC agent finding (E-FRAC-11):** The bimodal fingerprint is likely a statistical artifact, NOT evidence of transposition structure. The ENE/BC asymmetry is caused by crib ordering in the scoring algorithm (ENE comes first → higher match rate). The bimodal pre-filter in AGENT_PROMPT.md is too restrictive (0/500K random permutations pass) and should not be relied upon.

**Refer to:** `docs/invariants.md` for the full elimination record with artifact pointers.

## FRAC Agent Statistical Meta-Findings (E-FRAC-13/14)

[DERIVED FACT — reproducible via scripts listed below]

**K4's statistical properties are consistent with random text of length 97.** None of the previously cited "anomalies" survive proper multiple-testing correction:

| Claimed Signal | Raw Stat | Corrected Result | Reference |
|---|---|---|---|
| Below-random IC (0.036) | z=-0.84 | 21.5th percentile of random (NOT significant) | E-FRAC-13 |
| Lag-7 autocorrelation | p=0.0077 | Fails Bonferroni (48 lags, needs p<0.001) | E-FRAC-14 |
| DFT peak at k=9 | mag=162 | Below 95th pctile of random max (192) | E-FRAC-14 |
| "English-like" pre-ENE IC | 97.6th pctile | Bonferroni p=1.0 (13 segments have IC ≥ 0.067) | E-FRAC-19 |
| Beaufort key low entropy | p=0.003 | Selection effect — Vigenère key at 16.27th pctile (unremarkable) | E-FRAC-16→25 |
| **Periodic key + ANY transposition** | periods 2-12 | **PROOF: Bean inequalities structurally violated. Only {8,13,16,19,20,23,24,26} survive.** | E-FRAC-35 |
| **Bean-surviving periods (8, 13)** | 175 false 24/24 | **ALL have quadgram < -5.0/char (best: -6.171). Multi-objective oracle discriminates.** | E-FRAC-36 |

**Implication:** There is no statistical evidence favoring any specific transposition width, periodicity, or cipher variant. Prior claims about DFT peaks, lag-7, and Beaufort preference should be retracted. The Bean impossibility proof (E-FRAC-35) eliminates periodic keying at all discriminating periods under ANY transposition. At Bean-surviving periods, hill-climbing trivially reaches 24/24+Bean but produces only false positives discriminated by quadgram score (E-FRAC-36).

**Repro:** See `reports/frac_statistical_meta_analysis.md` for full analysis with all 55 experiments.

---

*Updated 2026-02-21 by agent_frac (FINAL — 55 experiments, mandate complete + ALL gaps closed: running key gap closure + English key detection + three-layer model + mono inner layer + mono running key underdetermination + Bean-surviving period gap closed). See also: `docs/invariants.md` (verified computational invariants), `docs/research_questions.md` (prioritized unknowns).*
