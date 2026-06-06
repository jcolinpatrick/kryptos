# Kryptos K4 Exhaustion Audit — Team of Rivals

**Date:** 2026-04-08
**Scope:** Whether the K4 search frontier is still meaningfully open, or whether we have reached the end of what is honestly testable under current public clues, current repo capabilities, and current methodological constraints.
**Methodology:** Adversarial audit. Six rival lenses. A/B/C/D/E classification. No phased execution. No premature closure. No false openness.

This document is the board's single coherent finding. It supersedes the "running-key is #1" framing in MEMORY.md on the points where they conflict.

---

## 1. Repo-Grounded Landscape Inventory

### 1.1 What has been tested, formally

The repo's elimination infrastructure is now in three tiers (`docs/elimination_tiers.md`, `docs/admissibility_architecture.md`):

- **Tier 1 — Mathematical proofs.** Level-A under explicit assumptions. Proven algebraically, not empirically. Includes the Bean impossibility proof (E-FRAC-35: periods 2-12, 14, 15, 17, 18, 21, 22, 25 all structurally eliminated for ANY transposition + periodic key), the autokey structural impossibility (E-FRAC-37: PT-max 16/24, CT-max 21/24, all four variants + arbitrary transposition), fractionation parity/alphabet proofs (E-FRAC-21), progressive/quadratic/Fibonacci key Bean-elimination (E-FRAC-38), null-mask + periodic sub algebraic elimination (E-NULLMASK-PERIODIC), columnar-w5 and columnar-w7 Bean impossibilities, columnar × period-13 structural impossibility, three-layer Sub+Trans+Sub at p1×p2≤50, Mono+Trans+Periodic at p3-12. These are permanent.

- **Tier 2 — Empirical saturation under direct correspondence.** Vigenère (~3B), Beaufort (~500M), Gromark/Vimark p4-7, Quagmire I/II/III/IV, Hill 2×2/3×3, columnar widths 5-15 exhaustive or 100K-sampled (E-FRAC-12/29/30), double columnar (E-FRAC-46), Myszkowski widths 5-13 (E-FRAC-47), AMSCO/Nihilist/Swapped w8-13 (E-FRAC-48), simple transposition families (E-FRAC-32: 14,035 perms), strip transposition (E-JTS-09/10/11), grid reading orders, Wheatstone clock (327M), full VIC pipeline (52M+), RS44 grid-mask (905.6M), interrupted-key Vigenère (14.7M), ITA-2/Baudot/Wilson/sawtooth, Ubchi, Soviet three-step, Sanborn matrix, 72+1 delimiter, Operation Final Vector (22 tasks, 15+ scripts).

- **Tier 3 — Admissibility layer (new, 2026-04-08).** `src/kryptos/admissibility/` introduces formal `EliminationCertificate` / `AdmissibilityCertificate` with a closed reason taxonomy and a 5-entry `CORPUS_ALLOWLIST` that hard-gates running-key sources: `k1_plaintext`, `k2_plaintext`, `k3_plaintext`, `carter_tomb_vol1`, `kahn_codebreakers`. Initial campaign (`f_admissibility_elimination_v1`) formally eliminates 78/78 periodic-additive (variant, period) pairs via `crib_position_contradiction` — the cribs force incompatible residue values before Bean even activates. Running-key policy sweep: 2 accepted / 9 corpus-policy-violation / 16 assumption-unmet. The gate currently applies only to hypotheses routed through `triage_running_key`; direct script execution is ungated and audited post-hoc.

- **Composition framework (2-layer).** `src/kryptos/composition/`, 105,692 branches across 52 distinct family+peel campaigns, 99.6% tested, 0.4% pruned, max score 6/24, **zero Bean passes** across the entire corpus (verified directly against `db/composition_ledger.sqlite`). Score distribution matches `binomial(24, 1/26)` — statistically indistinguishable from random. v1 (additive × transposition, 55K), v2 (transposition × periodic inner on 97 and 80-char extract, 45K), v3 (6 stateful families, 5.2K).

- **Three-layer.** E-FRAC-52 (Sub+Trans+Sub, columnar w6/8/9 × p1-12, p1×p2≤50) and E-FRAC-53 (Mono+Trans+Periodic, columnar w6/8/9 × p3-12) — both found zero candidates at their core targets and only underdetermined gibberish at larger products. E-FRAC-54 (Mono+Trans+Running-key) is the single three-layer case flagged as **UNDERDETERMINED** rather than eliminated: the 13 monoalphabetic DOF saturate quadgram discrimination, so fragment analysis cannot distinguish real English running keys from gibberish when a mono layer is present.

### 1.2 What "running-key is #1" actually means in the repo

Grep found no phrase "running-key is #1" in the repo. The closest sources are:

- `MEMORY.md` lines 31-37 "What Remains Open" — running-key listed first in a five-item enumeration.
- Session briefing script (`scripts/_infra/session_briefing.py`) "OPEN ATTACK SURFACE" block — running-key listed first.
- `docs/elimination_tiers.md` Tier 1/2 headers — "OPEN only for running key model" appears in every Tier-2 cipher-family row as the uneliminated residual.

**The claim's actual basis.** Running-key is the residual of three negative proofs, not a positive finding:

1. E-FRAC-38 Bean analysis eliminated progressive, quadratic, and Fibonacci keys. Of the classical *structured* non-periodic key models, only "unstructured running key" survives Bean under additive-key assumptions.
2. E-FRAC-35 Bean proof eliminated *periodic* keys at all discriminating periods under any transposition.
3. E-FRAC-54 showed that the single combined model (Mono+Trans+Running-key) that could defeat fragment detection *cannot be eliminated* by fragment-scoring analysis — 13 DOF saturate the signal.

So "running-key is #1" is literally "running-key is the last classical additive-key model that Bean does not kill, AND the one realistic three-layer variant of it is not falsifiable by our current detection apparatus." That is a statement about our search, not about K4.

This is a weaker position than it has been represented to have.

### 1.3 Families that remain open only because they have not yet been encoded

Audit of `src/kryptos/composition/registry.py` vs hand-executable classical cipher families yields a confirmed list of families that are **plausible**, **hand-executable**, and **not in the framework**:

- Homophonic (n-to-1 letter→digit-or-symbol mapping) + transposition
- Grille (Cardan / turning) + substitution, as a *physical overlay* composition rather than just a permutation
- Bifid / Four-square + transposition (digraphic substitution as outer layer of a composition where the inner layer is transposition — tested as single-layer, NOT as composition outer)
- Route + autokey (blocked by non-periodic state; E-FRAC-37 rules out autokey-under-transposition structurally, so this is formally dead, listed here for completeness)
- Nomenclator + transposition (blocked by K4's 26-letter alphabet; structurally dead)

Bifid/Four-square as a composition *outer* is the only entry on this list that survives structural objections. Single-layer bifid is formally dead (E-FRAC-21: parity/alphabet), but composition-outer with a non-identity inner has not been tested. See Section 3 entry **C-BIFID-COMP** for treatment.

### 1.4 Recent April 2026 audit context

The April 2026 palette retirement (`docs/a1_score_conditioned_null_report.md`) invalidated seven previously load-bearing findings: BCL enrichment, mod-5 column structure, mod-35 KRYPTOS×SEVEN table, AP {G,K,O} enrichment, 14-col grid asymmetry, SA palette provenance, and the "7 letters at 17 positions" positional null itself. The December 2025–March 2026 "promising anomalies" corpus is now **zero verified signals**. The April 2026 audit reclassified a further 19 of 22 post-retirement "interesting" results as eliminated. After today's audit, the `Eliminated/Interesting` split in the briefing is 44/3.

Three "INTERESTING" items survive: `e_berlin_clock_route` (thematic geometric; 2-letter fragment), `e_carter_transposition_optimized_01` (Carter running-key + columnar, 11/24), `e_model_b_running_key_sa` (Model B running-key SA baseline). None are above SIGNAL.

---

## 2. Team of Rivals Critique

### 2.1 Exhaustion Auditor

**Finding.** The bounded-family squeeze is over. Every classical family with a clear definition, bounded parameter space, and well-defined null model has been either proven dead (Tier 1), exhausted (Tier 2), or admissibility-gated (Tier 3). The composition framework has tested 105K+ two-layer combinations with zero Bean passes. The score distribution is textbook random.

**Strongest affirmation of the feeling.** The `binomial(24, 1/26)` match of the composition score distribution is the single most damning piece of evidence in the entire project: it says that over 105,000 systematically enumerated two-layer hypotheses with thematic keywords produced a score histogram indistinguishable from 105,000 random PT strings. If K4 were a two-layer classical composition with a recognizable classical keyword, at least one of those branches should have pulled clearly away from the distribution. None did.

**Strongest objection.** The framework is 2-layer only. E-FRAC-52/53 covered a thin slice of 3-layer (Sub+Trans+Sub and Mono+Trans+Periodic, columnar w6/8/9 only). That leaves the vast majority of 3-layer space *architecturally untested* — not because it was searched and failed, but because no enumeration exists. "No signal in 2-layer" does not eliminate 3-layer.

**Honest verdict.** The bounded families where a well-defined null is possible are empirically saturated. The unbounded remainders are unbounded specifically because they escape a well-defined null.

### 2.2 Testability Prosecutor

**Finding.** Three of the six "OPEN" items in the session briefing fail testability in the strict sense of this audit:

1. **Bespoke chart-based system.** Has no parameterization, no stop condition, no admissibility basis beyond "Sanborn's archive mentions charts." The AAA finding "actual coding charts" is provenance evidence for a *class* of artifact, not a *function* that maps a chart to a decryption procedure. No `CorpusLicense` analog exists for cipher *procedures*. Fails strict testability.

2. **Model-free null mask search.** "Score CT73 by intermediate statistics, not cipher-model cribs" has no defined statistic, no null model, no stopping condition, and the palette retirement explicitly killed the closest operational version. Fails strict testability.

3. **External evidence (K5, charts, circled letters).** By construction, not testable *within this repo* — requires primary sources not on disk. If those sources arrive, they become testable; until then, this is a data-dependent placeholder, not an open family.

**Strongest objection.** The Prosecutor is too harsh on "bespoke chart-based." Sanborn's public statements about charts and physical procedures do constrain the hypothesis space *if* we admit that admissibility can be established for cipher procedures the same way it is established for corpora. Today we have no schema for that; we could build one (a `CipherProcedureLicense` analog of `CorpusLicense`), which would turn this from untestable into weakly-testable.

**Honest verdict.** The three items above are not "open" — they are *aspirational*. Treating them as open is a category error that inflates the remaining search space and masks how narrow the actually-testable remainder is.

### 2.3 Practical Cryptanalyst

**Finding.** Sanborn's signal about K4 says: "two encryption systems," "not even a math solution," the 2010/2014/2020/2025 cribs, "what's the point?", the 1986 Egypt trip and 1989 Berlin Wall connection, the Carter/Scheidt references. Taking the clue surface at face value:

- "Two encryption systems" is consistent with composition. 105K composition branches → noise. This is a legitimate blow to the composition hypothesis *as classically defined*.
- "Not even a math solution" was originally interpreted as excluding pure algebra and favoring physical/procedural systems. This is the strongest public argument for chart-based / physical / procedural cipher mechanisms — the exact class the Testability Prosecutor just ruled untestable.
- The Egypt / Berlin references give Carter and Berlin Clock as the two *documented* thematic hooks; BERLINCLOCK is already a crib, Carter is already on the corpus allowlist. Neither yields a decrypt.

**Strongest affirmation of residual hope.** Sanborn-style fairness demands that the solution be recoverable without insider knowledge. Every chart-based / physical / procedural hypothesis conflicts with Sanborn-fairness *unless* the procedure is publicly retrievable from the clue surface. That is a much smaller space than "any procedure Sanborn could have invented." The Testability Prosecutor is right that we can't currently bound it; the Practical Cryptanalyst adds that Sanborn-fairness may bound it more than it appears.

**Strongest objection.** "Not a math solution" is a 1990s-era statement from a non-cryptographer artist who may not distinguish "math" from "algorithm." It is weak evidence against math, strong evidence only against formal number theory.

**Honest verdict.** The clue surface points toward a procedure we cannot presently formalize. That does not mean the procedure is wrong; it means the gap is in *our admissibility schema*, not necessarily in K4. Worth exactly as much as we trust Sanborn's self-description.

### 2.4 Search-Economics Analyst

**Finding.** Expected value of the next 30-60 days of compute/engineering:

| Candidate next campaign | Est. compute | Est. effort | Prior prob. of signal | EV signal |
|---|---|---|---|---|
| Carter Vol 1 + columnar w6/8/9 × 3 variants (admissibility-gated) | ~150K configs, minutes | ~1 day framing | ~0.005 (Kahn-like prior) | very low |
| Kahn full + columnar sweep under gate (not identity) | ~150K, minutes | ~1 day | ~0.002 (Kahn already tested at identity, noise) | very low |
| Stateful v4: non-columnar three-layer enumeration | ~1-10M, hours-days | ~5-10 days | ~0.01 (architectural gap) | low-moderate |
| Composition registry extension (bifid-outer, homophonic-outer, grille-outer, four-square-outer) | ~500K-2M per family | ~3-5 days per family | ~0.005 per family | low |
| Admissibility schema for cipher *procedures* | no compute; pure engineering | ~5-10 days | depends on Sanborn-fairness prior | unknown |
| Three-layer non-columnar enumeration (not just E-FRAC-52/53) | ~10-100M | ~5-15 days | ~0.01-0.02 | low-moderate |
| Running-key from new allowlisted Egyptological corpus (e.g., Breasted *Ancient Records of Egypt*) | requires new CorpusLicense + ~5M configs | ~3-5 days + manual provenance | ~0.003 | low |

No candidate has a prior probability above ~2%. The only candidate with reasonable compute-per-unit-info is **composition-registry extension to bifid/four-square/homophonic outer layers**, because it closes a confirmed architectural gap (see 1.3). The highest-leverage item is **non-compute work**: building a `CipherProcedureLicense` analog so bespoke chart-based procedures can be admitted or rejected under a real schema.

**Strongest affirmation.** Continuing to run large sweeps under the current paradigm has diminishing returns approaching zero. The project has already passed the point where "more compute" is a reasonable answer.

**Strongest objection.** Low probability is not zero probability. Each of the above has enough EV to justify a single disciplined pass — *if and only if* the pass is scoped to reject confounds (e.g., non-palette-dependent null models, pre-registered thresholds, no post-hoc reclassification). The issue is not "is the EV positive" but "is the project capable of running these sweeps without accumulating more zombies like the 19 we just killed this morning."

**Honest verdict.** There is a tight set of roughly 3-5 remaining campaigns with non-trivial EV. Beyond that set, compute has negative expected value because it manufactures false positives faster than it eliminates hypotheses.

### 2.5 Repo Realist

**Finding.** What can Kryptosbot actually execute *today* without new research or external data?

- **It can run** the composition framework (45-parameter `PipelineConfig`, exhaustive 2-layer enumeration, constraint propagation, full scoring, checkpointing). It cannot run 3-layer without new enumeration code.
- **It can run** any script in `scripts/running_key/` that declares an allowlisted `source_id` — currently `carter_tomb_vol1` is only literally cited by 2 scripts; the other 16 need manual provenance review before they can be run under policy. Kahn is allowlisted but scripts haven't been updated to declare it.
- **It can run** the periodic-additive admissibility sweep (`f_admissibility_elimination_v1`), which has already formally eliminated 78/78 (variant, period) pairs and is done.
- **It cannot run** any hypothesis requiring external text sources beyond the 5-entry allowlist without either (a) a new CorpusLicense with public justification, (b) manual provenance review for the 16 ASSUMPTION_UNMET scripts, or (c) explicit scoping violation.
- **It cannot run** anything that requires image analysis of the sculpture, the `IMG_1223-1235` circled letters, K5 ciphertext, or physical chart reproductions — this is data-dependent, not code-dependent.
- **It cannot run** "bespoke chart-based systems" in any form, because no `CipherProcedureLicense` schema exists.

**Strongest affirmation.** The repo is in an unusual state: it has a vastly more powerful elimination engine than it has remaining *targets* to point it at. The infrastructure is ready; the hypotheses are not.

**Strongest objection.** The 16 ASSUMPTION_UNMET scripts represent a concrete testable backlog that has not been processed. Manual provenance review is a finite task, not an open research question. That backlog is the repo's single largest actionable item.

**Honest verdict.** The repo can productively spend ~1-2 weeks clearing the admissibility backlog, extending the composition registry with 3-4 missing families, and running 2-3 bounded sweeps. After that, it will be capability-limited on what remains without new data.

### 2.6 Running-Key Skeptic

**Finding.** The "running-key is #1" framing dissolves under scrutiny:

1. **Running-key with a reference text is dead.** E-CFM-09 tested 73 Gutenberg books (47.4M English chars, identity) → 0 full matches. Foreign corpora (cumulative 73.7M chars across 7 languages) → 0 full matches. E-FRAC-49/50 tested running-key + every structured transposition family from 7 reference texts → 0 matches in 17B checks.
2. **Running-key with unknown English text + columnar is dead.** E-FRAC-51: 0/16,597 Bean-passing configs produce English-like key fragments. This bound is real for English keys under columnar transposition.
3. **Running-key with unknown non-English text is unbounded.** Not because of positive evidence, but because the fragment-scoring test was English-specific.
4. **Running-key with mono + any transposition is underdetermined.** E-FRAC-54: 13 mono DOF saturate the discrimination statistic. This is a *detection* limit, not a *testing* limit.
5. **Running-key from Kahn Codebreakers (2.5M chars, CREATOR_STATEMENT source)** has been tested at identity at all offsets × 3 variants → 8/24 = noise (commit `56c56fe`). Not yet tested *with columnar* under the admissibility gate.
6. **Running-key from Carter Tomb Vol 1 (ARTIST_STATEMENT source)** has been allowlisted but no comprehensive campaign result exists under the new gate; the `e_carter_transposition_optimized_01` result of 11/24 is the best we have and is barely above noise.

The honest remaining running-key subclass after all this:

- **Admissible sources:** Carter Vol 1, Kahn Codebreakers, K1/K2/K3 PT (already tested under identity with 0 matches).
- **Admissible transposition:** identity (tested); columnar w6/8/9 (not tested under gate for Carter/Kahn); other structured families (eliminated by E-FRAC-50).
- **Stop condition:** exhaust all offsets × 3 variants × 3 columnar widths for each allowlisted source = ~150K configs per source. Defined. Finite. Minutes of compute.
- **Falsifiability:** Yes for English fragments, no for mono-wrapped cases.

**Strongest objection to "running-key is #1".** After removing everything that's dead, everything that's been tested at identity, and everything that's underdetermined by E-FRAC-54, running-key reduces to: "Carter Vol 1 + columnar w6/8/9, Kahn + columnar w6/8/9, ~300K configs total, ~2% Kahn-like prior, falsifiable only for English-like fragments." That is a 20-minute computation. It is not "the #1 open family." It is a **checklist item** that has not been crossed off.

**Strongest affirmation of running-key's ongoing role.** Even as a residual, running-key is the only family that survives *Bean* under classical additive-key assumptions. It is the correct default null for any new hypothesis. But "the correct default null" is not "the current leading hypothesis."

**Honest verdict.** Running-key is best understood as a **residual admissible family** — specifically, a finite checklist with ~300K configs of actual testing remaining. It is **not** a leading hypothesis. It should be downgraded from "#1 open family" to "finish the checklist, then stop." After Carter and Kahn are columnar-swept under the gate, running-key as an open family is *empirically saturated* and belongs in bin B, not bin C.

---

## 3. Final A/B/C/D/E Ledger

### Bin A — Formally Dead

| ID | Family / subfamily | Why | Proof |
|---|---|---|---|
| A1 | Pure transposition | CT has 2 E's, PT needs 3 (structural count mismatch) | Tier 1 |
| A2 | ALL periodic polyalphabetic, periods 1-26, direct correspondence | Bean algebraic impossibility | E-FRAC-35 |
| A3 | ALL autokey variants (PT/CT × Vig/Beau) + arbitrary transposition | Cannot reach 24/24; PT-max 16/24, CT-max 21/24 | E-FRAC-37 |
| A4 | ALL fractionation families (bifid5×5, trifid, ADFGVX, straddling checkerboard, Polybius digits) as single-layer | Parity / alphabet / digit-count impossibilities | E-FRAC-21 |
| A5 | Hill 2×2, 3×3 | Algebraic impossibility | Tier 1 |
| A6 | Progressive, quadratic, Fibonacci key + arbitrary transposition | Bean equality forces δ∈{0,13}; 0/676 for quadratic and Fibonacci | E-FRAC-38 |
| A7 | Columnar widths 5, 7 + periodic sub, all orderings | ZERO Bean passes, full enumeration | Tier 1 |
| A8 | Columnar × period-13 substitution | Structural impossibility proof | E-D13-COLUMNAR-ALL |
| A9 | Null mask (any 24 positions) + periodic sub, periods 1-23 | Algebraic proof over all (n1,n2,n3) crib-segment null counts | E-NULLMASK-PERIODIC |
| A10 | Three-layer Sub+Trans+Sub, columnar w6/8/9, p1×p2 ≤ 50 | ZERO candidates; empty solution set proven | E-FRAC-52 |
| A11 | Mono+Trans+Periodic, columnar w6/8/9, periods 3-12 | ZERO candidates; bipartite consistency too stringent | E-FRAC-53 |
| A12 | Running-key + columnar w6/8/9 + 7 reference texts (known) | ZERO matches in 8.4B checks | E-FRAC-49 |
| A13 | Running-key + ALL structured transposition families + 7 reference texts | ZERO matches in 8.8B checks; Reverse and rail fence Bean-incompatible | E-FRAC-50 |
| A14 | Running-key from unknown **English** text + columnar w6/8/9 | 0/16,597 Bean-passing configs with English-like fragments | E-FRAC-51 |
| A15 | Vimark/Gromark orders 1-8 + arbitrary transposition | JTS linear algebra; 0 consistent primers | E-JTS-08/11 |
| A16 | K1/K2/K3 PT/CT as running key for K4 | Exhaustive across 694K transpositions | E-JTS-12 |
| A17 | Columnar w5-13 Myszkowski / AMSCO / Nihilist / Swapped | 226K + 361K permutations, 0% Bean pass for AMSCO family | E-FRAC-47/48 |
| A18 | Double columnar 9 Bean-compatible width pairs | 2.96M compositions, max 15/24 | E-FRAC-46 |
| A19 | Bean-surviving periods (8, 13, 16) on columnar w6/8/9 | 154K checks, 0 matches at 24/24 | E-FRAC-55 |
| A20 | Autokey on 73-char column mask extract | 46K configs, max 6/24 | E-COLMASK-AUTOKEY |
| A21 | Full VIC pipeline, Wheatstone, RS44, ITA-2/Baudot, Ubchi, Soviet three-step | Total ~1.3B configs, noise | TICOM/Novel 2026-03-28 |
| A22 | Periodic-additive admissibility, 78/78 (variant, period) pairs | `crib_position_contradiction` | `f_admissibility_elimination_v1` |

**Total bin A:** 22 families/subfamilies. All permanent under stated assumptions.

### Bin B — Empirically Saturated

| ID | Family / subfamily | Coverage | Max score | Worth more work? |
|---|---|---|---|---|
| B1 | Composition framework 2-layer (additive × transposition, transposition × periodic, stateful v3) | 105,692 branches, 52 family+peel campaigns, 0 Bean passes | 6/24 | No — distribution is textbook binomial |
| B2 | Running-key from English Gutenberg, 73 books, identity | 47.4M chars, 462 EAST matches, 19 Bean-EQ, 0 full | — | No |
| B3 | Running-key from foreign corpora (German/French/Latin/Egyptian/Italian/Spanish), identity | 73.7M chars cumulative, 604 partial matches, 0 full | — | No (under identity) |
| B4 | Running-key from Kahn Codebreakers, identity, all offsets × 3 variants | 7.6M configs (commit `56c56fe`) | 8/24 | No under identity |
| B5 | Foreign language keywords (DRUSILLA/Webster family etc.) | ~500K keywords | noise | No |
| B6 | K2 numbers as key, DEFECTOR/PALIMPSEST as key | Exhaustively confirmed 15/24 ceiling | 15/24 | No (DO NOT TEST) |
| B7 | Interrupted-key Vigenère | 14.7M configs | noise | No |
| B8 | NDYAHR, OBKOGBOWWKWIWGZIG, K1-K3 literals as keys | Exhaustive | noise | No |
| B9 | Null-palette-conditioned analyses | Retired 2026-04; 7 findings collapsed | — | No (palette retired) |
| B10 | Operation Final Vector artifact-derived keys, physical transpositions, book-cipher extraction, grille/aperture, clock-procedural, 2025 clue phrases | ~98K configs | 7/24 max | No |
| B11 | E-CFM (10 experiments): homophonic direct, pure nomenclator, null/skip, K3 rotational, running-key from 4M-char tested corpora | Exhaustive within scope | 5-6/24 | No |
| B12 | Mono SA substitution, affine mono, Playfair single-layer | — | DISPROVED | No |

**Total bin B:** 12 categories, all of which have received disproportionate search effort relative to their current EV. Explicitly: no more compute on these.

### Bin C — Testable Now

| ID | Family / subfamily | Bounded how? | Next action | What result would change belief | Worth it? |
|---|---|---|---|---|---|
| **C1** | Running-key: Carter Vol 1 + columnar w6/8/9 × 3 variants, under admissibility gate | ~150K configs, finite offsets × widths × variants | Build `f_running_key_carter_columnar` campaign using `triage_running_key` path (so gate is enforced), run it, publish certificate | A Bean-passing score ≥18/24 with a coherent English fragment in the decrypt | Yes — finite, falsifiable, closes a checklist item |
| **C2** | Running-key: Kahn Codebreakers + columnar w6/8/9 × 3 variants, under admissibility gate | ~150K configs | Same as C1 but Kahn source | Same as C1 | Yes — same rationale as C1 |
| **C3** | Composition framework: bifid-outer + transposition-inner (bifid as composition *outer*, a mode NOT previously tested because single-layer bifid is dead) | ~500K-2M configs depending on keyword set; bifid5×5 requires alphabet decision for the 26th letter | Add `bifid` family to `src/kryptos/composition/registry.py`, author roundtrip tests, sweep via composition campaign | A Bean-passing score ≥18/24 with bifid-outer; or a score distribution that shifts meaningfully from binomial | Moderate — closes an architectural gap in registry |
| **C4** | Composition framework: four-square-outer + transposition-inner | ~1-5M configs | Add `four_square` family to registry | Same as C3 | Moderate — closes gap |
| **C5** | Composition framework: homophonic-outer + transposition-inner | ~500K-5M depending on homophone table enumeration | Add homophonic family with Cardano-style mapping enumeration | A score ≥18/24 + Bean pass | Moderate — homophonic direct is structurally impossible (E-CFM-04) but as composition outer it is not tested |
| **C6** | Non-columnar three-layer: route / Myszkowski / rail-fence as middle layer, with Sub and Periodic or Sub and Running-Key on either side | ~10-100M depending on keyspace | Extend `enumerate_stacks()` in composition orchestrator to 3-layer with explicit family subset; start with depth-3 containing exactly one transposition layer and bounded outer/inner parameter sets | A score ≥18/24 + Bean pass in any 3-layer stack | Moderate — fills a real architectural gap, but noise floor is high at 3-layer |
| **C7** | Admissibility-backlog: 16 running-key scripts currently flagged `ASSUMPTION_UNMET` | Finite: 16 scripts, each either declares allowlisted source, gets archived, or accompanies a new CorpusLicense with evidence | Manual provenance review pass; the backlog is enumerated in `results/admissibility_elimination_v1/running_key_policy.json` | Some scripts unlock previously ungated searches; most will be rejected or archived | Yes — one engineering day, high information value |
| **C8** | Stateful-family seed space expansion (progressive_key: 15 seeds → full short-seed space; compass_offset: 5 → full) | ~50K-500K configs | Extend seed enumeration in `src/kryptos/kernel/transforms/stateful.py` and re-run v3-style campaigns | Same as others: score ≥18 + Bean pass | Moderate — v3 critically underdetermined on seed space |

**Total bin C:** 8 concrete, bounded campaigns. Combined compute: ~100K-200M configs. Combined engineering: ~2-4 weeks. Combined EV: low per-item, moderate in aggregate *only if* the project pre-registers thresholds and refuses to manufacture more zombies.

### Bin D — Weakly Testable

| ID | Family / subfamily | Why weak | What would make it stronger |
|---|---|---|---|
| D1 | Mono + Trans + Running-key (any source, any transposition) | E-FRAC-54: 13 mono DOF saturate fragment discrimination. Not detection-capable with current scorer. | A detector that exploits positional information Mono can't swallow — e.g., word-level crib consistency across multiple cribs in a way that mono cannot arbitrage |
| D2 | Running-key from unknown **non-English** text + any transposition | E-FRAC-51 bound is English-specific. Non-English key fragments pass the filter. Unbounded without a pre-declared language. | Language pre-declaration + an allowlisted non-English source with public justification (e.g., a specific 1980s Egyptological text identified by the archive) |
| D3 | Geometric/route ciphers on sculpture physical dimensions (spiral, S-curve, diagonal at non-rectangular readings) | Operation Final Vector tested 14,320 permutations + 50K Cardan apertures. Noise. But the parameter space of "physical operations on the sculpture" is not finite without a physical model. | A concrete physical model derived from photogrammetry of the sculpture (blocked without new data) |
| D4 | Berlin Clock + Weltzeituhr as routing permutations (clock-time-dependent) | 327M configs tested. Noise. Clock-time dependence is underdetermined because the "starting time" is unknown. | A specific dedication-date or anniversary-time argument to fix the clock state |
| D5 | Thematic keyword extensions beyond the existing ~500K set | Keywords themselves are not eliminated; they propagate into trans/JTS searches. But the thematic frontier is diffuse. | A new archive find that constrains keyword space to a tight set (the AAA findings helped but did not close) |
| D6 | Pre-ENE (positions 0-20) as separate sub-cipher | E-FRAC-19: IC "anomaly" is Bonferroni p=1.0. But the possibility that 0-20 has its own cipher is not formally dead. | A crib or constraint at positions 0-20 — which we don't have |
| D7 | Admissibility-gated running-key from new Egyptological or Berlin sources not yet allowlisted | Requires each new source to acquire a CorpusLicense with public justification. The list of "plausible" sources exceeds the list of "publicly justified." | Archive evidence linking a specific text to Sanborn/Scheidt working papers |
| D8 | Archive-derived cipher hints (ABSCISSA, ATBASH, "4, 8, 10, 26 = Col", "3 words most") | Confirmed as Sanborn research terms (AAA 2026-03-27). Not operationalized into parametric hypotheses. | An operational mapping from the archive term to a specific cipher family or parameter (e.g., ABSCISSA as a column-reading rule with a defined semantics) |

**Total bin D:** 8 weakly testable families. None deserve compute as their primary deliverable. Most deserve *engineering* work to build admissibility or detection machinery that would upgrade them to bin C.

> **[UPDATE 2026-06-06 — D1 detection engineering attempted and characterized]** The
> prescribed "detector that exploits positional information Mono can't swallow" was
> built: a mono- AND source-invariant **forced-difference detector** (same-letter crib
> pairs impose running-key differences fixed by CT+transposition, independent of σ),
> scored by lag-conditioned LLR against English letter-difference statistics with a
> matched CT-shuffle null over columnar w6/8/9 + the 52-route universe. Modules:
> `src/kryptos/detectors/mono_invariant_runkey/`; result:
> `results/mono_trans_runkey_detector_2026_06_06.json` (verdict
> **DETECTOR_UNDERPOWERED**). The machinery is round-trip verified correct, but the
> synthetic go/no-go gate gives **Model-1 detection rate 0.00** (it cannot recover even
> a planted Mono+Trans+Running-key solution): ~11–16 forced-difference constraints,
> mostly at large (uniform-regime) lags, are drowned by the ~404K-transposition
> look-elsewhere burden. Real-K4 max-LLR (3.38) sits mid shuffle-null band (descriptive
> p≈0.22, NON-CONCLUSIVE). **This does NOT eliminate D1** — it sharpens E-FRAC-54 from
> "fragment scoring saturates" to "the strongest mono-invariant positional statistic
> has zero recovery power at K4's parameters." D1 stays bin-D, now characterized as
> undetectable by positional means. A separate, distinct prior detector
> (`src/kryptos/detectors/efrac54_joint.py`, two-sided PT+K English scoring) was NOT
> evaluated by this build and remains a separate question.
>
> **[UPDATE 2026-06-06b — two-sided detector also saturates; D1 closure now airtight]**
> The two-sided joint detector was then validated through the same go/no-go gate,
> including a STRONG cold-start joint search built for the purpose
> (`src/kryptos/detectors/efrac54_joint_search.py`: SA over σ + the 73 free plaintext
> letters with an incremental two-sided scorer validated `== score_joint`; it recovers
> planted solutions to within 1 nat of the oracle, `real_reached_oracle_rate=1.00`, so
> it is NOT search-limited). Result
> (`results/efrac54_joint_coldstart_gonogo_2026_06_06.json`): **detection rate 0.00**.
> The strong search reaches equal/higher joint `t` on SHUFFLED CT as on the real planted
> CT — with **73 free plaintext letters + 26 σ DOF**, both the plaintext and the implied
> keystream can be made English on ANY ciphertext, including noise. The two-sided
> statistic SATURATES at full search strength; an earlier favorable test (true plaintext
> fixed) gave a misleading 0.75 only because fixing the plaintext removed 73 DOF.
> **CONCLUSION: D1 is GENUINELY UNDERDETERMINED. No detector — fragment (E-FRAC-54),
> mono-invariant forced-difference (rate 0.00), or two-sided joint (detection 0.00 under
> a provably strong search) — can discriminate it, because the free plaintext supplies
> enough DOF to fit any English criterion on any CT.** D1 stays bin-D as a matter of
> mathematical underdetermination, not missing engineering.

### Bin E — Untestable Under Current Clues

| ID | Family / subfamily | Why untestable | What clue would reopen it |
|---|---|---|---|
| E1 | Bespoke chart-based cipher (Sanborn's "Code Breaker" overlay, "actual coding charts") | No parameterization, no stop condition, no `CipherProcedureLicense` schema analog | A public reproduction of the chart, OR a public procedure description, OR a `CipherProcedureLicense` schema + an archive finding that fits it |
| E2 | Model-free null mask search on CT73 | No defined statistic, no null model, no threshold; palette version retired | A new null-mask discovery procedure with a pre-registered statistic and a blind-holdout validation protocol. The retired palette should NOT be revived. |
| E3 | K5 ciphertext cross-constraint | K5 is public as a 97-char length claim but the ciphertext is not published | Sanborn publishing K5 CT, or a verified primary-source leak |
| E4 | Circled letters on IMG_1223-1235 archive photos | Letters identified visually but no systematic extraction | A forensic extraction pass of the archive photos into a machine-readable list + a cipher-model hypothesis that consumes it |
| E5 | Physical installation / photogrammetric measurements (curvature, compass, lodestone, water feature) | Not present in repo data; requires primary-source photography and measurement | New photogrammetric or physical-metrology data |
| E6 | Sanborn's private "coding system" (archive evidence) | Known to exist; not public | Public release |
| E7 | Homophonic direct correspondence | E-CFM-04 proves structural impossibility under direct correspondence | Nothing — it is formally dead under direct correspondence |
| E8 | Nomenclator direct | E-CFM-05 proves identical-word → different-CT contradiction | Nothing — formally dead |

**Total bin E:** 8 categories, of which 2 (E7, E8) are formally dead and should actually be in bin A. The remaining 6 are genuinely untestable without new evidence. **They are not a research frontier; they are a waiting list.**

### Ledger totals

| Bin | Count | Spend compute? | Spend engineering? |
|---|---|---|---|
| A (formally dead) | 22 | no | no |
| B (empirically saturated) | 12 | no | no |
| **C (testable now)** | **8** | **yes, bounded** | **yes** |
| D (weakly testable) | 8 | no | sometimes (to upgrade to C) |
| E (untestable) | 6 (+2 misclassified to A) | no | no |

The honestly-open frontier is **8 items in bin C**, of which **2 (C1, C2) are finish-the-checklist** for running-key, **3 (C3, C4, C5) are architectural gaps in the composition registry**, **1 (C6) is the three-layer enumeration gap**, **1 (C7) is a manual provenance backlog**, and **1 (C8) is stateful-family seed-space expansion**.

---

## 4. Running-Key Verdict

**What running-key is.** Running-key is a **residual admissible family** — specifically, a ~300K-config finite checklist (Carter + Kahn × columnar w6/8/9 × 3 variants) that has not yet been executed under the admissibility gate. Nothing more.

**Exact admissible subclass(es).** Under the current allowlist (`k1_plaintext`, `k2_plaintext`, `k3_plaintext`, `carter_tomb_vol1`, `kahn_codebreakers`):
- K1/K2/K3 PT × identity — tested in E-JTS-12, 0 matches.
- K1/K2/K3 PT × structured transposition — tested in E-JTS-12 with 694K transpositions, 0 matches.
- Carter Vol 1 × identity — partial coverage; no single comprehensive result.
- Carter Vol 1 × columnar w6/8/9 — **NOT TESTED under gate**.
- Kahn Codebreakers × identity — tested at all offsets × 3 variants (commit `56c56fe`), 8/24 = noise.
- Kahn Codebreakers × columnar w6/8/9 — **NOT TESTED under gate**.
- Any running-key + mono layer — underdetermined by E-FRAC-54, not falsifiable by current scoring.

**Exact stop condition.** Exhaust the 2 untested (source, columnar width, variant) products above. ~300K configs. Stopping condition: all enumerated or first 24/24 + Bean pass with coherent English fragment.

**Is it leading, residual, or a methodological sink?** **Residual admissible family.** It is *not* leading: no positive evidence, no anomaly points at it, no crib structure prefers it. It is *not* a methodological sink *yet* — the remaining 300K configs are finite and bounded. It **becomes** a methodological sink if, after C1+C2 complete with no signal, the repo responds by expanding the allowlist to include unjustified sources, adding a mono layer, switching to non-English language priors, or otherwise widening the hypothesis to preserve openness.

**Should it keep its #1 slot in "What Remains Open"?** No. It should be:
1. Executed as a checklist (C1, C2) during the next work session.
2. Moved from the "What Remains Open" section of MEMORY.md to a "Final checklist" section with explicit completion criteria.
3. After completion, moved to bin B (empirically saturated).

The current "#1 open family" framing overstates running-key by treating "uneliminated" as "leading."

---

## 5. Final Verdict

### "Have we reached the end of what is honestly testable?"

**Answer:** **Almost yes; only these weak or narrow things remain.**

**Defense.**

The honestly-open frontier is not zero. It is 8 items in bin C. But:

- **2 items (C1, C2)** are finite checklist work, ~300K configs, minutes of compute, ~1 day of framing. Not a research frontier — finish-and-forget.
- **1 item (C7)** is a manual-review backlog of 16 scripts. Not a research frontier — engineering work with a clear definition of done.
- **1 item (C8)** is seed-space expansion for 6 stateful families whose initial v3 coverage was thin. Bounded, low prior, defensible.
- **3 items (C3, C4, C5)** are composition-registry extensions for bifid / four-square / homophonic as composition outer layers. These are plausible, bounded, and close a documented architectural gap. Their prior probability of signal is low.
- **1 item (C6)** is the three-layer non-columnar enumeration gap — the single item in bin C with a real argument for non-trivial EV, because it is the only place where a genuinely under-tested subspace exists at scale.

Aggregate this and the picture is: **the honestly testable remainder is roughly 2-4 weeks of bounded, non-compute-dominated work**. After that work, the project will be limited by one of:

- A new CorpusLicense requiring primary-source evidence (data-dependent, not engineering-dependent).
- A new CipherProcedureLicense schema to admit bespoke chart-based procedures (engineering + evidence).
- New data about K5, the archive charts, the circled letters, or photogrammetric properties of the sculpture (data-dependent).

None of these is a testable hypothesis. They are prerequisites for being able to test anything new. That is the distinction the "open" column in MEMORY.md is presently eliding.

**Why not "No, these specific things remain testable now"?** Because bin C totals 8 items, of which 6 have priors ≤ 0.01 and only 2 (C6, C3) have a non-trivial architectural argument. The rivals agree: more compute under the current paradigm has EV approaching zero after those 8 items are handled.

**Why not "Yes, under current public clues the remaining open space is not honestly testable"?** Because bin C is not empty, and the 8 items are genuinely testable today with no new data. Declaring them closed without running them would be premature. Specifically: not running C6 before giving up would be intellectually dishonest — it is the only remaining place where a meaningful search-space gap has been formally identified.

**The right frame is "almost yes."** We are in the *final* honest search window, not the early or middle one. After it closes, the project's answer becomes "we need new evidence" rather than "we need more compute." That transition should be made *explicit*, not deferred.

---

## 6. Recommendation

### 6.1 Minimal next-campaign set (roughly ordered by value-per-effort)

1. **Clear the admissibility backlog (C7).** One engineering day. Manual-review the 16 ASSUMPTION_UNMET running-key scripts. For each: declare an allowlisted source_id, attach a new CorpusLicense with public evidence, or archive. Output: a smaller, cleaner running-key inventory where every surviving script is gate-compatible.

2. **Execute C1 + C2 (Carter + Kahn × columnar × 3 variants under gate).** ~300K configs, finite, falsifiable for English fragments. One script each. Pre-register the threshold: 24/24 + Bean pass + coherent English fragment → investigate further; anything else → move running-key to bin B and stop.

3. **Execute C6 (non-columnar three-layer enumeration).** Extend `enumerate_stacks()` in `src/kryptos/composition/orchestrator.py` to depth 3 with a bounded registry: {additive, periodic sub, mono} × {route, Myszkowski, rail fence, block} × {additive, periodic sub}. Limit parameter space aggressively. This is the only bin-C item with a real architectural argument. Pre-register thresholds.

4. **Execute C3 + C4 (bifid / four-square as composition outer).** Adds 2 families to `registry.py`, including roundtrip tests. Run under existing framework. Document that single-layer bifid is dead but composition-outer bifid is not tested.

5. **Defer C5 (homophonic).** Lower priority than C3/C4 because homophonic needs a non-trivial enumeration of homophone tables; the other composition gaps are cheaper. Do it only if C3/C4 signal anything above noise.

6. **Defer C8 (stateful seed expansion).** Lowest EV of bin C. Do it only if the composition extensions (C3/C4/C6) all come up empty and before declaring the frontier closed.

After C1-C4 + C6 + C7 complete, publish an *exhaustion certificate* declaring what the project has and has not done. This becomes the formal hand-off document for the "awaiting new evidence" phase.

### 6.2 Explicit deprioritizations and stops

- **STOP** treating running-key as "the #1 open family." Downgrade to "residual checklist item" in MEMORY.md. After C1+C2 complete, move to bin B.
- **STOP** running any new script that declares a running-key source not on the allowlist without first getting a CorpusLicense entry.
- **STOP** manufacturing new "interesting" results without pre-registering a null model and a threshold. The April 2026 audit just eliminated 19 of 22 such items manufactured during the previous 6 months. This is a process failure, not a luck failure.
- **STOP** compute spend on any bin-B family. Bin B is closed.
- **STOP** treating the six "OPEN" items in the session briefing as equivalently open. Three of them (bespoke charts, model-free null mask, external evidence) are bin D or bin E and should be labeled as such.
- **STOP** SA / hill-climbing campaigns on anything without a pre-registered Bean-hard-constraint and an external English-discrimination threshold. E-FRAC-36 proved that hill-climbing at Bean-surviving periods trivially reaches 24/24 + Bean with quadgram < -5.0/char. Every future SA run must report both the crib score AND a separate English fragment quality score below a pre-registered threshold.

### 6.3 What class of new evidence would reopen the space

The bin-E items above directly imply the classes of new evidence that would matter:

1. **A public release of the charts / coding procedures Sanborn used.** Turns E1 into a bin-C campaign immediately. Requires cooperation from Sanborn or an archive researcher with legal access to the private working papers.

2. **K5 ciphertext release.** Turns E3 into a cross-constraint on K4 — potentially decisive given K5 is known to share positional words with K4.

3. **A systematic forensic pass over IMG_1223-1235 producing a machine-readable list of circled letters.** Turns E4 into a bin-C or bin-D hypothesis depending on whether the letters line up with a pre-existing cipher model.

4. **Photogrammetric data on the sculpture.** Turns D3 into a bin-C parameterization if the measurements fix a physical model.

5. **An archive find identifying a specific 1980s running-key source** (Egyptological, Berlin-related, or other Sanborn research subject) with enough public justification to get a CorpusLicense entry. Turns D7 into a finite bin-C campaign per source.

6. **A `CipherProcedureLicense` schema** — pure engineering, no new data required, but requires policy decisions about what counts as public justification for a cipher *procedure* (as distinct from a cipher *source*). If built, would upgrade E1 from untestable to weakly testable.

None of the above items requires more compute. All require either new data or new *schema* — the two things the project has been underinvesting in relative to enumeration capacity.

### 6.4 The single most important recommendation

**Publish the "final checklist" state explicitly.** The project is in an unusual position: infrastructure is ahead of hypotheses. Instead of pretending there is a rich research frontier, publish (in MEMORY.md, on kryptosbot.com, wherever it matters) a precise statement of what bin-C work remains, an EV-ordered completion plan, and an explicit transition-to-waiting-list criterion. This turns the current "feeling of exhaustion" into a measurable program with a defined end state.

The alternative — continuing to run sweeps under a paradigm where the EV has collapsed and the false-positive rate is manufacturing zombies faster than the audit process kills them — is exactly how the April 2026 palette retirement happened and how the 19-item zombie cleanup was necessitated this morning. That pattern will repeat unless the project formally acknowledges the transition to the final phase.

---

*Audit authored by the Team of Rivals board, 2026-04-08. Supersedes the "running-key is #1" framing. Findings owned by the board, not by any individual rival lens.*
