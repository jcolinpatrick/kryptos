# Real-K4 Evidence Gap Register

**Created:** 2026-04-30. Owner: this document. Companion to
[`docs/REAL_K4_PSEUDO_CLUE_PACK_ADMISSION.md`](REAL_K4_PSEUDO_CLUE_PACK_ADMISSION.md)
and [`docs/REAL_K4_EVIDENCE_ACQUISITION_PLAN.md`](REAL_K4_EVIDENCE_ACQUISITION_PLAN.md)
(the acquisition plan names the concrete actions that would close the
high-priority gaps GAP-03 / GAP-09 / GAP-10).
Tracks the gaps the bridge campaigns CANNOT close until new evidence
arrives.

## Purpose

Two real-K4 interpretive bridge campaigns have closed null at this
project. The gating bottleneck is no longer solver architecture or
search breadth — it is the quality and mechanism-specificity of the
evidence pool the campaigns draw from. This register names those
evidence gaps, explains why current evidence is insufficient, and
states what would have to change before a future campaign could
admit a pack against any given gap.

## Current status

- Real-K4 LLM↔HCC interpretive bridge: **validated end-to-end**.
  Schema, compiler, dispatcher, scoring, null calibration, and
  non-claim banner all verified across two closed campaigns.
- Bridge campaign 001 (Team-of-Rivals, 31 packs, 1,730 specs):
  **CLOSED — null_level**. max_crib=5/24, expected null max=5.35,
  p(max ≥ 5)=0.965, no Bean/ngram support in top hits. Closure note:
  [`data/real_k4_pseudo_clue_packs/campaign_001_team_of_rivals/CLOSURE.md`](../data/real_k4_pseudo_clue_packs/campaign_001_team_of_rivals/CLOSURE.md).
  Registry entry: `C-BRIDGE-01`.
- Bridge campaign 002 (admission-gated micro, 3 packs, 30 specs):
  **CLOSED — null_level (side-effect predictions unfired)**.
  max_crib=1/24, expected null max=3.24, p≈1.0. All three predicted
  side-effects activate at `crib_score ≥ 12`; no candidate reached
  the activation threshold. Closure note:
  [`data/real_k4_pseudo_clue_packs/campaign_002_admission_gated_micro/CLOSURE.md`](../data/real_k4_pseudo_clue_packs/campaign_002_admission_gated_micro/CLOSURE.md).
  Registry entry: `C-BRIDGE-02`.

## No-current-signal statement

As of this register's creation date (2026-04-30) the real-K4 bridge
has produced **no signal** of any kind. Every top candidate from both
campaigns scored at or below the null expected_max for the search
size and carried `bean_passed=False` and `ngram_score=0.0`. No
real-K4 progress is claimed by either campaign and none is implied by
this register.

## Bridge-campaign pause rule

**No new bridge campaign should be opened against any of the gaps
below until at least one of them is closed by new admissible
evidence.** "Admissible" is defined by
[`docs/REAL_K4_PSEUDO_CLUE_PACK_ADMISSION.md`](REAL_K4_PSEUDO_CLUE_PACK_ADMISSION.md);
the campaign-admission gate at the bottom of this document repeats
the criteria for convenience. Adding more packs of campaign-001 or
campaign-002 shape is **anti-productive**: the maximum-of-N null
threshold grows with search breadth, and the corroboration discipline
the admission standard installs is undermined by re-using the same
exhausted evidence pool.

## Sanborn public-comment doctrine

Jim Sanborn has historically been extremely careful not to release
operational K4 mechanism clues. The confirmed useful disclosures are
**crib / plaintext anchors** — `EAST` (21 — 24), `NORTHEAST` (25 — 33)
compounding to `EASTNORTHEAST` (21 — 33), `BERLIN` (64 — 69), `CLOCK`
(70 — 74) compounding to `BERLINCLOCK` (63 — 73). These are
disclosed plaintext spans, treated as **PUBLIC FACT** by the project,
and are the only Sanborn material the bridge admits as direct
operational evidence.

Broader public statements and contextual remarks — "two systems",
"masked English", "stego", "I have to be on this earth to verify
solutions", and similar — are **not** operational clues. They may
supply weak contextual priors only. They **must not** directly
trigger HCC roles, keywords, numeric parameters, or composition
templates **unless** paired with independent measurable evidence
**and** a predeclared side-effect prediction. (Per project policy:
[`feedback_sanborn_epistemic_weight.md`](../memory/) and registry
claim `C-SANBORN-01`, Sanborn statements are Tier-3 community
hearsay, NOT [PUBLIC FACT].)

This doctrine is the operational version of `C-SANBORN-01` for the
bridge campaign line; it is enforced by admission rule 11 in
[`docs/REAL_K4_PSEUDO_CLUE_PACK_ADMISSION.md`](REAL_K4_PSEUDO_CLUE_PACK_ADMISSION.md)
and recorded as the live internal_result `C-SANBORN-02` in
`docs/claims_registry.json`.

## Evidence-gap table

| gap_id | evidence area | current state | why insufficient | what would make it admissible | likely HCC mechanisms if admissible | required side-effect prediction | priority | owner / next action | status |
|---|---|---|---|---|---|---|---|---|---|
| GAP-01 | Stehle interval-4 +5 anomaly (E0a) | Single 9-letter window DIAWINFBN at carved 55-63; published 2000 (Stehle), measured 2021 (Bean); not extended beyond that window. | Anomaly is local. Extrapolation to a global Caesar shift / period role is structurally aggressive, as campaign 001 F3 and campaign 002 002-01 demonstrated (both null). No measurement of whether the property persists, weakens, or reverses outside positions 55-63. | Independent measurement of (a) the property's behavior at every other 9-letter window in the carved CT, and (b) a quantified test of whether the property survives any candidate transposition the cipher might apply. The anomaly should be cast as a constrained MEASUREMENT on the full 97-char text, not an isolated window observation. | Caesar shift role with windowed activation, OR period-N substitution with N tied to interval-4 directly, OR a route layer that aligns the window with another anomaly. | Window-localized Bean residue OR position-consistency check that the +5 property is preserved in the candidate plaintext at the original window. | medium | unowned (needs cryptanalytic measurement, NOT cipher search) | open |
| GAP-02 | Width-21 vertical bigram anomaly (E0e) | 11/76 repeated bigrams at width 21, p ~ 1/6750 on raw 97 char (Bean 2021 §2.1). Project memory `memory/width21_bigram_73char.md` shows the anomaly DISAPPEARS after null extraction; widths 10 (p=0.006) and 17 (p=0.008) become high-significance on CT73. | Two contradictory readings co-exist with no resolution: (1) the width-21 anomaly is real and points at a width-21 layer on raw CT (campaign 001 F5-51 / 002-02 — both null); (2) the anomaly is a stego artifact that disappears under correct null extraction, in which case widths 10/17 carry the real route signal. The bridge can only test one reading at a time and has no way to discriminate. | A null-mask hypothesis with INDEPENDENT support that resolves which reading is correct. Either (a) a stego rule that predicts which positions are nulls without depending on the bigram signal, or (b) a non-bigram measurement that re-detects width-21 structure (ngram, IC, period scan) at a comparable significance. | Route_boustrophedon / route_diagonal at the resolved width; columnar at the resolved width; potentially combined with a stego layer if reading (b) wins. | width-NN bigram-count REDUCTION in the candidate plaintext (the cipher has been "undone"), AND/OR an ngram floor improvement at the resolved width. | medium | unowned (needs stego-layer resolution) | open |
| GAP-03 | BCL Beaufort enrichment (E0b adjacent) | Anomaly E0b (Materna 2020 / Bean 2021 §2.4): for 10 of 24 disclosed-plaintext positions where PT in {K,R,Y,P,T,O,S}, CT distances cluster near identity (mean Δ=2.1, p ~ 1/5520). The original BCL palette {B,G,I,K,O,W,Z} construct was retired 2026-04-01 as a post-hoc selection artifact (`memory/retired/bcl_palette_keystream.md`). | The surviving evidence (E0b) supports a keyword-mixed substitution alphabet near KRYPTOS but does NOT specify a mechanism for how the 7/8 BCL keystream coincidence at positions 63-70 should manifest in a bridge-compilable pack. Campaign 002 002-03 made the strongest current attempt and produced no signal. | A FRESH side-effect prediction tied to E0b directly: a quantified statement of what cipher-distance clustering should look like in a candidate's plaintext, BEYOND simply matching cribs. Without that, every BCL pack collapses to "Beaufort + KRYPTOS keyword" which has been tested. | Keyword-mixed alphabet (Quagmire III shape), Beaufort or Variant Beaufort substitution, KRYPTOS as alphabet keyword. | KRYPTOS-set distance preservation in candidate plaintext at the 10 positions, OR Bean constraint behavior. | high | unowned (needs E0b-specific side-effect operationalization) | open |
| GAP-04 | NDYAHR / YAR shifted-letter anomaly (A5) | 3-letter superscript YAR on cipher-side line 15 (Elonka 2002 rubbings); Sanborn undiscussed; "DYARO" extension (5 letters) is community speculation. Tier-2 in the anomaly registry after the 2026-04-03 audit (50 scripts, zero cipher signal). | Spatial measurement is qualitative ("raised several centimeters") with no quantification of whether YAR vs DYARO is the correct reading, no 2-D position data, and no cross-check against the panel-side or Antipodes copy. Campaign 001 F6 packs all null. | Quantitative spatial data: precise vertical displacement per character, panel-relative coordinates, presence/absence on Antipodes. With those, YAR/DYARO can be cast as a positional ANCHOR (mark this position) instead of a numeric shift cue. | Position-anchor numeric role, OR row/column hint for a route grid. | Anomaly co-location: candidate plaintext at the anomaly window must align with another known anomaly position, OR null mask predicts the window. | low | unowned (needs physical re-measurement; project policy says auction sources are out of scope) | open |
| GAP-05 | Physical sculpture geometry / route-width evidence | Lodestone deflection (D1) points to ENE matching the EAST-NORTHEAST crib; K2 coordinates (D2) point ~150-174 ft SE; pool / light effects (D3-D4) classified as artistic. No quantitative geometry data ties any of these to a specific cipher width / depth / period. | The "compass-points-at-the-answer" reading consumes the EAST-NORTHEAST crib evidence narratively without producing a cipher mechanism: it explains WHY the crib is there, not HOW the cipher works. Same for K2 coordinates. | A measured physical geometry that predicts a SPECIFIC numeric parameter (a width, a depth, a period) AND ties that parameter to a cipher mechanism the bridge can compile. | Route width tied to a measured panel dimension; columnar key length tied to a panel feature; rail-fence depth tied to a sculpture facet count. | Independent observable in `docs/anomaly_registry.md` (a different anomaly's state changes under the hypothesis). | low | unowned (needs site-visit measurement and cross-check with Elonka data) | open |
| GAP-06 | Sanborn / Scheidt public-comment provenance (NON-CRIB) | "Two systems", "masked English", "stego", and similar public commentary. Per the Sanborn public-comment doctrine above, these are **contextual provenance only** — Tier-3 community hearsay (`feedback_sanborn_epistemic_weight.md`, `C-SANBORN-01`, `C-SANBORN-02`), not operational mechanism clues. **DISTINCT from confirmed Sanborn crib disclosures** (EAST, NORTHEAST, BERLIN, CLOCK and their compounds), which are PUBLIC FACT and remain admissible. Campaign 001 F2 (5 packs, 630 specs) treated non-crib comments as composition-template triggers and was null. | Sanborn has historically been extremely careful not to release operational K4 mechanism clues. Non-crib comments do not specify what "two systems" or "masked English" means structurally; they cannot disambiguate sub+trans / sub+sub / stego+cipher / two-phase / etc. Without a structural disambiguation **AND** independent measurable evidence, the bridge cannot produce a non-arbitrary pack from these sources. | A non-crib Sanborn comment can supply admission-grade evidence ONLY if (a) a future creator-attested mechanism statement carries a specific structural commitment AND (b) an INDEPENDENT measurable observable (statistical, physical, or archival) corroborates the commitment AND (c) admission rule 11 is satisfied. Public comments alone — no matter how suggestive — cannot reopen a bridge campaign. | Two-layer or three-layer compositions; LESSON-022; LESSON-019. | None admissible without independent corroboration — public comments alone cannot drive an admissible side-effect prediction. Once paired with corroborating evidence, the side-effect inherits from whichever evidence supplies the structural commitment. | low | unowned (this gap stays open until BOTH a new operational creator statement appears AND independent corroboration lands; downgrade to "permanently insufficient on its own" is the more likely outcome) | open — likely permanent |
| GAP-07 | Archival source-text / running-key provenance | No identified candidate source text. Various community guesses (literature, primary documents) without provenance. Per the admission standard rule R5, running-key / book-cipher hypotheses are not admissible without a specific repo-cited source-text identification. | Open-ended source-text searches collapse to arbitrary keys, which is forbidden. The bridge has no way to bound the search without a cited source-tape segment. | A specific, repo-cited source text candidate with (a) a citation that identifies the document by name/date/author, (b) a bounded segment, (c) a bounded offset hypothesis. Archival material from `reference/` (Carter book, Sanborn correspondence, NSA docs, Scheidt dossier) is the only project-safe candidate pool. | Running-key Vigenère / Beaufort with the cited text; constrained offset sweep. | Independent observable: matching N-gram statistics in the recovered keystream against the proposed source text (tighter than crib_score). | medium | unowned (requires evidence-scout work, not cipher search) | open |
| GAP-08 | K2/K3 provenance analogy limits | K1=PALIMPSEST, K2=ABSCISSA, K3=route+columnar with documented widths around 8 / 14. Sanborn's two-systems disclosure means K1-K3 keys are NOT guaranteed to apply to K4. Campaign 001 F7 (4 packs, 90 specs) max_crib=5 (search-wide ceiling) but no Bean/ngram support. | The K1-K3 analogy was already the strongest single contributor in campaign 001. Repeating it without new evidence will only re-hit the same null-level coincidental crib match. The analogy itself is not new evidence; it is a tested hypothesis class. | A provenance source that tightens the K1-K3 → K4 analogy: a documented design pattern (e.g., "Sanborn always uses the prior part's plaintext word as the next part's key") with corroborating evidence in K1→K2 or K2→K3. Without that, the analogy is structurally exhausted at this evidence pool. | Vigenère / Beaufort with K1-K3 derived keywords; columnar at K3-derived widths. | Bean constraint behavior; ngram floor. | medium | unowned (analogy refinement is a primary-source research task) | open |
| GAP-09 | Null-mask / stego evidence | The retired BCL palette construct ({B,G,I,K,O,W,Z}, 17 consensus null positions) was retired 2026-04-01 (`memory/retired/bcl_palette_keystream.md`). Project memory `feedback_pt_length_open_question.md` keeps the K4 plaintext length open — nulls remain possible, count and positions unknown. | Without an admissible null-mask construct the bridge cannot test stego-mediated cipher hypotheses. The retired palette cannot be revived without a methodological audit (per the retired claim's policy). The width-21 vs CT73 contradiction (GAP-02) is downstream of this gap. | A new stego construct with INDEPENDENT support (not derived from a score-conditioned search). The construct must specify (a) which positions are nulls, (b) how the construct was derived without using K4's score signal, (c) a side-effect prediction beyond crib score. | Stego layer composed with any cipher family; null-mask-aware Bean check. | Bean reduction at non-null positions; null-mask alignment with a registered anomaly position; ngram floor on the extracted plaintext. | high | unowned (this gap blocks GAP-02 and blocks any stego-bearing campaign) | open |
| GAP-10 | Crib-bound positional mechanism evidence | The disclosed cribs (EAST-NORTHEAST 21-33, BERLIN-CLOCK 63-73) give 24 of 97 plaintext positions. Bean constraints derive from those cribs and are variant-independent. The cribs are PUBLIC FACT but their POSITIONAL relationship to the cipher mechanism is not. | Multiple campaign-001 packs treated crib boundary positions (21, 24, 25, 33, 64, 69, 70, 73) as numeric width / depth roles (F1-14 alt). All null. The boundary positions carry no structural cipher hint beyond their existence. The cribs WORK as constraints; they do not WORK as cipher parameters. | A non-trivial structural property of the cribs that ties to a specific cipher parameter — for example, a Bean-derived constraint that specifies a residue-class structure, OR an analytical derivation that the gap between cribs (positions 34-62) carries a measurable feature (period, IC anomaly, etc.). | Positional residue-class substitution; gap-region targeted route. | Bean constraint refinement; gap-region ngram floor. | high | unowned (cryptanalytic measurement on the unknown 73 positions) | open |

## Campaign admission gate

A future bridge campaign may be opened **only if at least one gap
above is closed** by new evidence that meets all of the following
criteria (these mirror
[`docs/REAL_K4_PSEUDO_CLUE_PACK_ADMISSION.md`](REAL_K4_PSEUDO_CLUE_PACK_ADMISSION.md)):

1. **New or newly quantified evidence** — a fresh measurement, a
   newly cited primary source, or a re-quantification under a more
   defensible null model. Re-stating an existing anomaly does not
   count.
2. **Specific provenance** — the evidence must point at a checkable
   source (registry key, document section, memory note, or anomaly
   id). Bare creator-statement labels do not qualify.
3. **Explicit mechanism mapping** — the evidence must imply a
   specific role inside a hand-cipher (substitution / columnar /
   alphabet / route / shift / width / depth / period). "Maybe it's a
   key" does not qualify.
4. **Bounded parameter extraction** — the evidence must constrain a
   small parameter pool (≤ 8 entries per parameter) with each
   entry citation-traceable. Open-ended sweeps do not qualify.
5. **Predicted side-effect beyond crib score** — at least one of:
   Bean constraint behavior, anomaly alignment, ngram floor
   improvement, position consistency, null-mask / route geometry
   prediction, or independent observable in the anomaly registry.
6. **campaign_001 / campaign_002 coverage comparison** — the
   evidence must be either (a) `not_covered` (strictly new
   hypothesis class), (b) `tightened` (removes a degree of freedom
   from a tested encoding), or (c) `new_provenance` (cites a source
   not used by any earlier pack). `covered` is rejected.
7. **Predeclared success criteria** — a written threshold for what
   "winning" looks like (typical form: `crib_score >= 18 AND
   <side-effect-marker>`). Post-hoc threshold shifting is not
   permitted.

Even with all criteria met, the new campaign must clear the
admission validator
([`scripts/_infra/validate_pseudo_clue_pack_admission.py`](../scripts/_infra/validate_pseudo_clue_pack_admission.py))
before any bridge audit is run.

## Do not do

- **Do not add packs only because an idea is interesting.** The
  bridge has produced no signal; interestingness is not evidence.
- **Do not expand breadth to chase a higher max_crib.** The null
  expected_max grows with search breadth. Adding packs of the same
  shape raises the bar without raising the evidence quality.
- **Do not use arbitrary keys or arbitrary source texts.** Both are
  forbidden by rules R4 and R5 of the admission standard. Each
  keyword and each source-tape segment requires specific provenance.
- **Do not treat null results as silence.** The null is information.
  It tightens the prior on every closed encoding and on every
  evidence pool that remains exhausted under bridge testing.
- **Do not claim progress from max_crib alone.** Without Bean and/or
  ngram corroboration, a high crib match is a coincidental decoding
  of the disclosed positions. The side-effect rule (R7) exists
  exactly because campaign 001 hit max_crib=5 with zero corroboration
  and that was unmistakably noise.

## Update procedure

This document is the single source of truth for which evidence pools
are exhausted at the bridge campaign level. When a gap is closed
(either by new evidence or by formal demotion), update its row's
`status` field. When a new bridge campaign is opened, add a
back-reference to the campaign that closed (or partially closed)
the gap. Do not delete closed rows — keep the row with status
`closed` or `partially_closed` for traceability.
