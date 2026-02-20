# Elimination Confidence Tiers

**CRITICAL FRAMING:** Every exhaustive-search elimination in this project was conducted under the assumption of **direct positional correspondence** — meaning CT position N maps to PT position N with no transposition. The primary hypothesis (H1) is that a transposition layer exists, which means **the substitution families below have NOT been tested in their correct context as one layer of a multi-layer system.** The TRANS, JTS, and FRAC agents are doing that work now.

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
| Bifid / Playfair / Four-Square / Two-Square | ~4.9 billion | 11/24 | ELIMINATED | **OPEN — target for FRAC agent** |
| Nihilist | ~4.9 billion | 11/24 | ELIMINATED | **OPEN** |
| Autokey (PT and CT) | ~50,000 | 6/24 | ELIMINATED | **OPEN — target for JTS agent** |
| Running Key (K1–K3 as keystream) | ~45,000 | 7/24 | ELIMINATED | **OPEN** |
| Grid Rotation (K3-style) | ~14,000 | 7/24 | ELIMINATED | N/A (is itself a transposition) |
| Columnar + Vigenère (no bimodal pre-filter) | ~4 million | 12/15 | ELIMINATED (widths 5–10) | **OPEN — needs re-test WITH bimodal filter and polyalphabetic check** |
| Weltzeituhr permutations | ~295 million | 14/24 | ELIMINATED | **OPEN (as transposition source)** |
| Additive mask + Vimark p=5 | ~3.375 billion | 16/24 | ELIMINATED (0 Bean passes) | **OPEN** |
| VIC-family / Chain Addition | ~2 million | noise floor | ELIMINATED | **OPEN — target for FRAC agent** |

---

## Tier 3: Partial or Statistical Eliminations (confidence: 40–70%)

These were either incompletely tested or used statistical sampling of a space too large to exhaust. They warrant re-testing even under direct correspondence.

| Family | Concern | Confidence | Recommendation |
|--------|---------|------------|---------------|
| ADFGVX (~100K configs) | Status report acknowledges "without proper fractionation recovery" — the undo procedure may have been incorrect | **~60%** | **FRAC agent: re-test with correct recovery** |
| Turning grille 10×10 (150K Monte Carlo) | Statistical sample of a space with ~2^50 possibilities; 150K samples provides negligible coverage | **~40%** | **TRANS agent: test systematically with bimodal constraint to prune** |
| Straddling checkerboard | "Partially tested" per status report; no config count given | **~30%** | **FRAC agent: needs proper exhaustive test** |
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
| Fractionation with proper recovery (ADFGVX, straddling checkerboard) | Prior tests acknowledged as incomplete | FRAC |

---

## The Meta-Risk: What If the Ceiling Is a Crib Error?

[HYPOTHESIS — not established fact]

The persistent 14–17/24 ceiling across all families has been interpreted as evidence of a transposition layer. There is an alternative explanation: if any crib positions are wrong, the true ceiling for the correct cipher would be <24/24, and every sweep would show a cap. The bimodal fingerprint (positions 22–30 match well, 64–74 don't) could reflect which cribs are correct rather than which positions are transposed.

**Mitigation:** The cribs come from Sanborn's own public announcements (2010, 2014, 2020) and are highly authoritative. But the wave1 report already caught one error in the project's "verified" knowledge base. The `constants.py` self-verification gate is our primary defense.

**Test plan:** If the TRANS agent completes its full priority matrix without finding signal, the QA agent should run a systematic crib-perturbation experiment: for each of the 24 crib positions, try shifting it ±1 and re-run the best-performing cipher configurations. If shifting a specific position dramatically improves scores, that position may be mis-indexed.

**Refer to:** `docs/invariants.md` for the full elimination record with artifact pointers.

---

*Extracted from CLAUDE.md on 2026-02-18. See also: `docs/invariants.md` (verified computational invariants), `docs/research_questions.md` (prioritized unknowns).*
