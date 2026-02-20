# Elimination Confidence Tiers

**CRITICAL FRAMING:** Every exhaustive-search elimination in this project was conducted under the assumption of **direct positional correspondence** — meaning CT position N maps to PT position N with no transposition. The primary hypothesis (H1) is that a transposition layer exists, which means **the substitution families below have NOT been tested in their correct context as one layer of a multi-layer system.** The TRANS, JTS, and FRAC agents are doing that work now.

**FRAC AGENT STATUS (2026-02-20):** The FRAC agent has completed 34 experiments (E-FRAC-01 through E-FRAC-34). Key results that affect this document:
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

**What could invalidate Tier 1:** Only if the 24 crib positions are wrong (off-by-one, wrong character mapping) or the CT transcription has an error. The wave1 report already caught one VKB error (position 74 was listed as K→K self-encryption; actual CT[74]=W). If one error existed, others could too. The cribs themselves come from Sanborn's public announcements and are highly trustworthy, but the exact 0-indexed position mapping has been a source of bugs.

---

## Tier 2: Exhaustive Search Under Direct Correspondence (confidence: ~95% for what they claim; ~0% for the multi-layer question)

These eliminations are solid FOR THEIR SPECIFIC MODEL: "Is K4 cipher family X applied directly to positions 0–96?" The answer is definitively no. But they tell us NOTHING about whether K4 is "transposition σ applied to cipher family X." That question is wide open.

**Do not re-test these as single-layer, direct-correspondence ciphers. DO test them as the substitution layer after candidate transpositions.**

| Family | Configs Tested | Max Score | Status as Single-Layer | Status After Transposition |
|--------|---------------|-----------|----------------------|--------------------------|
| Vigenère (periodic, all variants) | ~3 billion | 14/24 | ELIMINATED | **OPEN — primary target for TRANS/JTS** |
| Beaufort / Variant Beaufort | ~500 million | 14/24 | ELIMINATED | **OPEN — primary target for TRANS/JTS** |
| Gromark / Vimark (p=4–7) | ~12 million | 14/24 | ELIMINATED | **OPEN** |
| Quagmire I/II/III/IV | ~2 million | 17/24 (artifact) | ELIMINATED | **OPEN** |
| Bifid / Playfair / Four-Square / Two-Square | ~4.9 billion | 11/24 | ELIMINATED | **STRUCTURALLY ELIMINATED** (E-FRAC-21: parity + alphabet proofs hold with or without transposition) |
| Nihilist | ~4.9 billion | 11/24 | ELIMINATED | **OPEN** |
| Autokey (PT and CT) | ~50,000 | 6/24 | ELIMINATED | **OPEN — target for JTS agent** |
| Running Key (K1–K3 as keystream) | ~45,000 | 7/24 | ELIMINATED | **OPEN** |
| Grid Rotation (K3-style) | ~14,000 | 7/24 | ELIMINATED | N/A (is itself a transposition) |
| Columnar + Vigenère (no bimodal pre-filter) | ~4 million | 12/15 | ELIMINATED (widths 5–10) | **OPEN — needs re-test WITH bimodal filter and polyalphabetic check** |
| Weltzeituhr permutations | ~295 million | 14/24 | ELIMINATED | **OPEN (as transposition source)** |
| Additive mask + Vimark p=5 | ~3.375 billion | 16/24 | ELIMINATED (0 Bean passes) | **OPEN** |
| VIC-family / Chain Addition | ~2 million | noise floor | ELIMINATED | **VIC contains straddling checkerboard → STRUCTURALLY ELIMINATED** (E-FRAC-21) |

---

## Tier 3: Partial or Statistical Eliminations (confidence: 40–70%)

These were either incompletely tested or used statistical sampling of a space too large to exhaust. They warrant re-testing even under direct correspondence.

| Family | Concern | Confidence | Recommendation |
|--------|---------|------------|---------------|
| ~~ADFGVX~~ | ~~Status report acknowledges "without proper fractionation recovery"~~ | **99.9%** | **STRUCTURALLY ELIMINATED** (E-FRAC-21: parity impossible — output length always 2×N (even), K4=97 (odd). Proof holds with or without transposition.) |
| Turning grille 10×10 (150K Monte Carlo) | Statistical sample of a space with ~2^50 possibilities; 150K samples provides negligible coverage | **~40%** | **TRANS agent: test systematically. NOTE: bimodal pre-filter is unreliable (E-FRAC-11).** |
| ~~Straddling checkerboard~~ | ~~"Partially tested" per status report~~ | **99.9%** | **STRUCTURALLY ELIMINATED** (E-FRAC-21: produces digits 0-9, K4 has 26 letters. Proof holds with or without transposition.) |
| Foreign language keywords (~500K) | Only tested under already-eliminated cipher models, not independently | **~50%** | **Keywords themselves are not eliminated** — carry forward into TRANS/JTS searches |

---

## Tier 4: Never Properly Tested (confidence: 0%)

These hypothesis classes appear in the status report's "What We Have NOT Tested" section and remain fully open.

| Hypothesis | Why Untested | Assigned Agent |
|-----------|-------------|----------------|
| Polyalphabetic consistency AFTER transposition | Prior columnar+Vigenère tests checked monoalphabetic consistency only | TRANS, JTS |
| Double columnar transposition | Combinatorial explosion; needs keyword-pair pruning | TRANS |
| Myszkowski transposition | Not in any prior sweep | TRANS |
| Turning grille (systematic, with constraints) | Prior test was Monte Carlo only | TRANS |
| Bespoke physical transposition (S-curve, strip manipulation) | Cannot be enumerated without creative hypothesis | BESPOKE |
| Non-standard tableau usage | Structural analysis, not a sweep | TABLEAU |
| Position-dependent alphabets | "Change the language base" (Scheidt) — untested at scale | TABLEAU, JTS |
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

**Implication:** There is no statistical evidence favoring any specific transposition width, periodicity, or cipher variant. Prior claims about DFT peaks, lag-7, and Beaufort preference should be retracted.

**Repro:** See `reports/frac_statistical_meta_analysis.md` for full analysis with all 25 experiments.

---

*Updated 2026-02-20 by agent_frac. See also: `docs/invariants.md` (verified computational invariants), `docs/research_questions.md` (prioritized unknowns).*
