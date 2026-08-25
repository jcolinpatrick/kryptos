# The "Two Systems" Landscape for Kryptos K4

**Status:** Synthesis document. Cross-references existing eliminations.
**Last updated:** 2026-04-12
**Provenance:** Internal synthesis. Not Sanborn-confirmed beyond his original "two systems" remark.

---

## What this document is

Sanborn's 1990 dedication remark stated K4 uses "two systems of enciphering," distinct from the Vigenère used for K1-K3. This document maps where the project's accumulated elimination work stands across the **full landscape** of two-system architectures, not just one slice.

**This document exists because individual elimination artifacts can be misread as covering more than they actually do.** The two-layer cartesian campaign (frozen 2026-04-12) tested *one specific* architectural slice (mask/projection outer + near-identity inner). This document situates that artifact in the broader catalog.

## What this document is NOT

- It is **NOT** a claim that "two systems" means any specific architecture. Sanborn never elaborated. We treat it as a hypothesis class.
- It is **NOT** a proof that K4 is two layers. Single-layer hypotheses remain technically open under non-additive ciphers and procedural mechanisms.
- It is **NOT** a closed taxonomy. Cells marked "untested" are honestly untested; cells marked "open" may include subtle interactions not yet enumerated.
- It is **NOT** a substitute for the underlying elimination artifacts. Cite those, not this synthesis.

## Provenance discipline (for any quotation from this doc)

Every entry below is one of:

- **STRUCTURAL** — algebraic proof, holds independent of search
- **EMPIRICAL** — exhaustive or near-exhaustive sweep with documented null
- **PARTIAL** — tested under specific assumptions/parameters; gaps remain
- **OPEN** — not eliminated; may or may not be testable
- **STRUCTURALLY-OPEN** — framework cannot currently express this class
- **UNDERDETERMINED** — tested but the scoring path cannot distinguish signal from noise

All eliminations carry the **H1 caveat** unless explicitly noted otherwise:

> H1 = direct positional crib mapping on the carved 97-char CT under an additive cipher class (Vigenère, Beaufort, or Variant Beaufort). H1 is a *modeling assumption*, not a proven fact about K4. Mechanisms that break H1 (outer transposition before the analyzed step, position-dependent selectors, physical-overlay remaps, non-additive ciphers) are NOT eliminated by Bean-based proofs.

---

## The matrix: outer layer × inner layer

For each (outer, inner) cell: status, evidence pointer, scope.

### Row: OUTER = (none / single layer)

This is the "K4 is one layer" baseline. Most of the project's mass is here.

| Inner | Status | Evidence | Scope |
|---|---|---|---|
| Periodic Vigenère/Beaufort/VarBeau (any period 1-26) | **STRUCTURAL** | E-FRAC-35 Bean impossibility proof | Direct positional alignment + additive class |
| Hill 2×2 / 3×3 | **STRUCTURAL** | algebraic | Direct positional alignment |
| Bifid / trifid / ADFGVX / Polybius | **STRUCTURAL** | E-FRAC-21 (parity, alphabet, digit constraints) | Holds with or without transposition |
| Autokey (PT or CT, Vig/Beau) | **STRUCTURAL, primer ≤ 25** | E-FRAC-37 rescoped by e_crib_35 (2026-08-25): CT-autokey max 7/24; PT-autokey max 23/24 at primer 25, 24/24 at primer 26 (underdetermined) | Standard autokey rules; non-standard variants not covered; original figure 16/24 was wrong |
| Quagmire I/II/III/IV | **EMPIRICAL** | ~2M configs, eliminated | Periodic keying class; non-periodic Quagmire untested |
| Running-key from K1/K2/K3 plaintext | **EMPIRICAL** | E-JTS-12, ZERO matches across 694K transpositions | Identity + structured transpositions only |
| Running-key from Carter / Kahn / 73 Gutenberg books | **EMPIRICAL** | E-FRAC-49: 8.4B checks, ZERO matches | Specific corpora |
| Running-key from unknown English (any source) | **EMPIRICAL** | E-FRAC-51: 0 of 16,597 Bean-passing configs produce English fragments | English fragment scorer; H1; non-mono inner |
| Vimark / Gromark (orders 1-8) | **STRUCTURAL** | E-JTS-08/11: linear algebra proves zero consistent primers | Bean + recurrence linearity |
| Hill 4+ | **OPEN** | not tested | larger Hill spaces |
| Non-additive cipher classes | **STRUCTURALLY-OPEN** | not in framework | requires bespoke testing |
| Procedural / physical mechanisms | **STRUCTURALLY-OPEN** | not in framework | requires non-algebraic testing |

### Row: OUTER = transposition (columnar / route / segmentation)

These compositions test "transposition first, then substitution".

| Inner | Status | Evidence | Scope |
|---|---|---|---|
| Periodic poly + columnar w5 | **STRUCTURAL** | E-FRAC-26: 0 orderings pass Bean equality | Bean + width 5 |
| Periodic poly + columnar w7 | **STRUCTURAL** | E-FRAC-27: 0 of 5,040 orderings pass Bean | Bean + width 7 |
| Periodic poly + columnar w6/8/9 | **EMPIRICAL** | E-FRAC-29: 720/40,320/362,880 orderings, max 13-14/24, NOISE | Cribs |
| Periodic poly + columnar widths 10-15 | **EMPIRICAL** | E-FRAC-30: 100K samples each, all underperform random | Cribs |
| Periodic poly + ANY transposition (periods 2-12, 14-25 except a few) | **STRUCTURAL** | E-FRAC-35: Bean impossibility proof for ALL 97! permutations | Bean variant-independent |
| Periodic poly + columnar w6/8/9 at Bean-surviving periods (8, 13, 16) | **EMPIRICAL** | E-FRAC-55: 154K checks, ZERO 24/24 matches | Cribs |
| Periodic poly + double columnar (Bean-compatible widths) | **EMPIRICAL** | E-FRAC-46: 2.96M compositions, max 15/24 | Cribs + Bean-compatible widths only |
| Periodic poly + Myszkowski w5-13 | **EMPIRICAL** | E-FRAC-47: 226K unique perms, max 15/24 | Cribs |
| Periodic poly + AMSCO/Nihilist/Swapped w5-13 | **EMPIRICAL** | E-FRAC-48: 361K perms, 0% Bean-pass rate | Structurally Bean-incompatible |
| Periodic poly + simple transposition families | **EMPIRICAL** | E-FRAC-32: 14,035 perms, max 13/24 (below random) | Cribs |
| Additive (Vig/Beau/VarBeau) + columnar w4/6/8/9 | **EMPIRICAL** | E-BEAN-01: full 242-inequality, ZERO of 1,211,832 (ordering, variant) pairs admit Bean-consistent keystream | Running-key-source-independent within additive class |
| Mono + columnar w6/8/9 + periodic key | **EMPIRICAL** | E-FRAC-53: ZERO at periods 3-7, 34 gibberish at period 12 | Cribs + Bean |
| **Mono + columnar + running-key** | **UNDERDETERMINED** | E-FRAC-54: 13 mono DOF saturate fragment discrimination | Scoring-limited, NOT eliminated |
| Periodic poly + grid reading orders (73-char extract) | **EMPIRICAL** | E-COLMASK-NATIVE-GRID-READING: 2,262 configs, max 22/24 = underdetermined | Column mask + shifted crib positions |
| Periodic poly + strip transposition w7-13 | **EMPIRICAL** | E-JTS-09: 0 matches | Cribs + Bean |
| Periodic poly + Wheatstone clock | **EMPIRICAL** | 327M configs, noise | Bespoke parameter space |
| Periodic poly + Weltzeituhr permutations | **EMPIRICAL** | E-FRAC-35 covers all permutations + periodic key | Bean-eliminated as part of universal proof |

### Row: OUTER = mask / null / selection

This is the slice the **2026-04-12 full-cartesian campaign** tested. Excludes substitution outer.

| Inner | Status | Evidence | Scope |
|---|---|---|---|
| Mask/projection outer + near-identity additive inner | **EMPIRICAL** | f_two_layer_stego_cipher_v1, full-cartesian 206,448 profiles, ZERO joint anomaly successes | Bounded parameterized space, blind evaluation, multiplicity-corrected |
| Mask/projection outer + STRONGLY-mixing inner | **OPEN** | NOT tested by the two-layer campaign (excluded by `test_no_strongly_mixing_inner_layers`) | Architectural gap |
| Null mask (any 24 positions) + periodic sub p=1-23 | **STRUCTURAL** | E-NULLMASK-PERIODIC: algebraic proof over (n1,n2,n3) crib-segment null counts | Cribs |
| Null mask + periodic Beaufort (sliding window p=1-8) | **STRUCTURAL** | E-NULLMASK-BEAUFORT-ADMISSIBILITY: formal UNSAT, 44,400 CSPs | Cribs + sliding window |
| Retired palette {B,G,I,K,O,W,Z} as null set + any inner | **RETIRED** | docs/a1_score_conditioned_null_report.md | Do-not-revive |
| W-delimiter (W as null/delimiter) + additive inner | **NARROW_RESIDUAL** | f_w_delimiter_null_v1: 633 grammatical candidates joint-tail, none clear multiplicity bar; AT+NEAR specifically not signal | Constrained slot pair only; segments 0/2/3/5 untested |

### Row: OUTER = substitution

Substitution-first compositions. **The 2026-04-12 campaign does NOT test this row.**

| Inner | Status | Evidence | Scope |
|---|---|---|---|
| Substitution outer + columnar inner | **OPEN** | not enumerated as a campaign | The framework's two-layer composition does not parameterize substitution-as-outer |
| Substitution outer + transposition inner | **OPEN** | partial via TABP series | 5 campaigns covered transposition-first; substitution-first as outer was not the TABP target |
| Two periodic substitutions (different keywords) | **OPEN** | not enumerated | Algebraically equivalent to a single composite key but with different period structure |
| Quagmire-as-outer + transposition inner | **OPEN** | not tested | Quagmire single-layer is empirically eliminated; composition-as-outer untested |
| Hill outer + substitution inner | **OPEN** | not tested | Hill single-layer is structurally eliminated for n=2,3; n=4+ as outer untested |
| K1-style Vigenère outer + K3-style transposition inner | **OPEN** | not tested as a focused composition | The "K4 = K1+K3 again" hypothesis is not enumerated |

### Row: OUTER = three-layer compositions

| Inner stack | Status | Evidence | Scope |
|---|---|---|---|
| Sub + Trans + Sub (columnar w6/8/9, p1*p2 ≤ 50) | **EMPIRICAL** | E-FRAC-52: 1.53M consistency checks, ZERO viable candidates at p1*p2 ≤ 50 | Bean + columnar widths 6/8/9 |
| Mono + Trans + Periodic (columnar w6/8/9, periods 3-12) | **EMPIRICAL** | E-FRAC-53: ZERO at periods 3-7, 34 gibberish at period 12 | Bean + columnar widths |
| **Mono + Trans + Running-key** | **UNDERDETERMINED** | E-FRAC-54: scoring-limited, NOT eliminated | Open under current detection apparatus |
| Three-layer with route / Myszkowski / rail-fence as middle | **OPEN** | not enumerated | Architectural gap (would require composition framework v4) |
| Three-layer with non-columnar middle | **OPEN** | not enumerated | Same gap |

### Row: OUTER = procedural / physical / extra-framework

| Inner | Status | Evidence | Scope |
|---|---|---|---|
| Cardan grille + any inner | **STRUCTURALLY-OPEN** | informally tested, no proper enumeration | Requires defined grille parameter space |
| Physical tableau overlay + any inner | **STRUCTURALLY-OPEN** | informally tested | Requires physical model |
| Misaligned tableau (extra L offset) + any inner | **STRUCTURALLY-OPEN** | docs/procedural_anomaly_recipes.md P-B1-3 | Recipe defined, not yet enumerated as campaign |
| YAR / DESPARATLY / Morse-26E procedural extraction + any inner | **STRUCTURALLY-OPEN** | docs/procedural_anomaly_recipes.md | Various recipes; none yet at campaign-grade enumeration |
| Bespoke chart-based system (Sanborn's coding charts) | **STRUCTURALLY-OPEN** | requires `CipherProcedureLicense` schema | Untestable until schema exists or chart is public |

---

## What this matrix actually says

### Strongly eliminated (universal proofs that need no further testing)

- Pure transposition (any permutation): letter count mismatch (CT has 2 E's, cribs need 3)
- Periodic poly + ANY transposition at discriminating periods: E-FRAC-35
- Hill 2×2/3×3 single-layer or composed under H1: algebraic
- All fractionation families (bifid, trifid, ADFGVX, checkerboard): structural (parity, alphabet, digit)
- Standard autokey + any transposition: E-FRAC-37
- Progressive / quadratic / Fibonacci structured keys + any transposition: E-FRAC-38
- Null mask + periodic sub at all small periods: E-NULLMASK-PERIODIC

### Empirically saturated (huge sweeps, noise everywhere)

- Composition framework v1+v2+v3 (105K branches at the base parameterizations)
- TABP series (5 campaigns, transposition-first additive-periodic class)
- The 2026-04-12 full-cartesian two-layer campaign (206,448 profiles, mask/projection outer × near-identity inner)
- Running-key from any allowlisted corpus + structured transposition

### Genuine open frontier

1. **Mono + Trans + Running-key** (E-FRAC-54). The single multi-layer case with no clean negative. The scoring path cannot distinguish a real English running key from gibberish when a monoalphabetic preprocessing layer is present.

2. **Substitution OUTER + transposition INNER**. The reverse of the TABP direction. Not enumerated by any campaign.

3. **Two-layer compositions where BOTH layers are strongly mixing**. The 2026-04-12 campaign explicitly excluded strongly-mixing inner layers (`test_no_strongly_mixing_inner_layers` enforces this). A v2 campaign with the constraint inverted would close this gap.

4. **Three-layer compositions where the middle layer is NOT columnar**. E-FRAC-52 and E-FRAC-53 only enumerated columnar middle layers.

5. **Procedural / physical mechanisms**. The framework cannot express these. Recipes exist in `docs/procedural_anomaly_recipes.md` but none have been enumerated to campaign-grade.

6. **Cipher classes that break H1**. Anything that rearranges or filters the carved CT *before* the analyzed cipher step invalidates Bean-based eliminations. Most of the strongest negatives in this matrix are H1-conditional.

### What the 2026-04-12 freeze actually covers

The full-cartesian artifact at `results/null_reports/two_layer_full_cartesian_20260412_*.json` covers:

- 552 outer parameterized instances × 374 inner parameterized instances = 206,448 profiles
- Outer family classes: mask-everynth, mask-periodic, projection, segmentation
- Inner family classes: periodic-additive-short, drift, near-identity perturbation, local-Caesar
- All inner classes are NEAR_IDENTITY or WEAKLY_MIXING by design
- Joint anomaly success criterion: cribs ≥18, Bean compatible (or H1 legitimately disabled), width-21 z ≥3 with no cherry-pick, Stehle local pattern present, weak identity preservation ≥0.4, English likeness above noise floor, zero overfit flags

It does NOT cover:

- Strongly-mixing inner ciphers (excluded by test invariant)
- Substitution as the outer layer
- Compositions with 3+ layers
- Procedural / physical outer mechanisms
- Non-additive inner classes (Hill, fractionation, lookup-table)
- Outer layers that operate on something other than positional structure
- The unconstrained K4 segments 0, 2, 3, 5 under the W-delimiter interpretation
- Cipher classes that break H1 direct positional alignment

---

## Recommended language for any external claim

**Acceptable** (scope-bounded, defensible):

> "Within the parameterized two-layer search space tested by f_two_layer_stego_cipher_v1 (mask/projection outer × near-identity additive inner, 206,448 profiles, blind evaluation), no candidate met the joint anomaly success criterion. This is a bounded negative within a bounded search space, not a proof that K4 cannot be two layers."

> "Across the project's accumulated elimination work, most simple two-layer compositions are dead under H1 modeling assumptions. The genuine open frontier includes: mono+trans+running-key (E-FRAC-54), substitution-as-outer compositions, three-layer compositions with non-columnar middle layers, procedural mechanisms not expressible in the algebraic framework, and any cipher class that breaks direct positional crib mapping."

> "The 2026-04-12 full-cartesian campaign tested ONE plausible interpretation of Sanborn's 'two systems' remark — the stego/projection outer with weak inner interpretation. Other interpretations remain genuinely open and are documented in `docs/two_systems_landscape.md`."

**NOT acceptable** (overclaim, would draw fair criticism):

- "K4 is not two layers" — false; only one slice is tested
- "Two-system hypothesis is dead" — false; the matrix has explicit open cells
- "We have eliminated the strongest negative for the parameterized space" — vague
- "Bean impossibility proves..." — Bean is H1-conditional; do not drop the conditional

---

## Soft-prior helper: K4 grammar tool

A separate tool at `src/kryptos/language/` and `scripts/tools/k4_grammar_probe.py`
provides a constrained grammar / register prior for short phrase candidates around
the known anchor cribs (EASTNORTHEAST, BERLINCLOCK). It is **NOT** in this matrix
and **does NOT change any cell above**.

What it is: a hand-curated POS-tagged inventory + 4 register models (directive,
status_report, telegraphic, hybrid) + 9 phrase templates + a transparent linear
score with per-component breakdown. Useful for ranking candidate slot fills by
grammatical plausibility before any cryptanalytic test.

What it is NOT:
- not a decoder
- not a theory generator
- not evidence
- not a basis for promoting any candidate to crib status
- not a hard filter
- soft prior only

Example use: when proposing a slot-fill hypothesis, query the tool first to see
what the grammar prior thinks the most plausible candidates are. Then test those
candidates with the cryptanalytic framework. The grammar prior must never replace
the cryptanalytic test, only inform candidate selection.

**Initial findings** (for reference, not as evidence):
- Most plausible 2-letter PREP before BERLINCLOCK: AT (0.907) > TO (0.871)
- Most plausible 4-letter before BERLINCLOCK: MEET (0.931) > FIND/SEEK (0.907) > NEAR (0.895)
- Most plausible 2-letter after EASTNORTHEAST: TO (0.807) dominates
- "GO EASTNORTHEAST" (0.950) clearly beats "AT EASTNORTHEAST" (0.757)
- "ASSET COMPROMISED" scores higher under status_report register (0.864) than
  directive (0.743)

These are SOFT PRIORS. The W-delimiter null framework (NARROW_RESIDUAL verdict)
already evaluated 100K dictionary candidates per variant; the grammar prior
helps explain WHY certain candidates rank higher under English plausibility but
does not change the underlying cryptanalytic conclusion.

See `src/kryptos/language/README.md` for full documentation.

---

## Cross-references

- Frozen artifact: `results/null_reports/two_layer_full_cartesian_20260412_1ada68c_dirty.{json,md}`
- W-delimiter null: `results/f_w_delimiter_null_v1.{json,md}`
- Master elimination tiers: `docs/elimination_tiers.md`
- E-FRAC series notes: search `docs/` and `memory/` for `E-FRAC-`
- E-BEAN-01: `docs/exhaustion_certificate_2026_04_08.md` §4-5
- TABP series summary: `results/tabp_series_summary.md`
- Procedural recipes (recipes-format hypotheses): `docs/procedural_anomaly_recipes.md`
- Grammar prior tool (soft prior, not evidence): `src/kryptos/language/README.md` and `scripts/tools/k4_grammar_probe.py`
- The retired palette: `memory/retired/` and `docs/a1_score_conditioned_null_report.md`

---

## Maintenance

This document should be updated when:

- A new campaign closes one of the OPEN cells above
- A new framework gap is discovered (a previously-unenumerated cell)
- An elimination is upgraded from PARTIAL to STRUCTURAL
- A previously eliminated cell is unblocked by a new test

This is a synthesis document. The underlying elimination artifacts are the source of truth. **If this document and an artifact disagree, trust the artifact.**

---

*This document exists to prevent overclaiming. Use it as the scope reference for any external "what does the project know about K4 as two layers" claim.*
