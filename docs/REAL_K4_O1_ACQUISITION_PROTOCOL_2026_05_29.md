# O1 Acquisition Protocol — carved K4 line-breaks → admissible T2 observable

**Companion to** `docs/REAL_K4_GAP09_ACQUISITION_SPEC_2026_05_29.md` (which defines
*what* O1 is and *why* it closes GAP-09). This document is the operational
*how*: capture → transcription → registration → admissibility → push-button
closure. It is written so that the moment a usable photograph exists, O1 is
derivable and the T2 verdict is one pre-registered call.

**Status:** PROTOCOL (no observable acquired). Acquisition is an out-of-repo,
physical-access task. Everything downstream of "a usable photo exists" is
specified here and the closure code already exists and is tested.

---

## 0. The one reframing that makes this tractable

O1 is an **ordinal / topological** observable, NOT a metric one. We need exactly:

> for each physical carved row, the K4 character index (0–96, into the public
> stream `OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR`)
> of the **first glyph on that row**.

We do **not** need a metrically rectified, flattened image of the doubly-curved
copper. We need three things only:

1. every K4 glyph **legible**,
2. each glyph's **row membership** unambiguous (which physical row it sits on),
3. the **reading order within each row** unambiguous.

The carved text **is** the known ciphertext (transcription is [PUBLIC FACT],
Elonka Dunin), so once glyphs are read in physical order the glyph→index map is
deterministic by counting — no metric measurement required. Curvature matters
only where it destroys legibility or row-membership, which is worst at the
**row edges** (the left/right margins where the S-curve turns away from the
camera) — exactly the glyphs that define a line break. The capture plan below is
organized around making those edge glyphs legible.

---

## 1. Capture tiers (pick by access channel; Tier A is sufficient for O1)

The K4 panel (and the Antipodes K4 region) is an **S-curved copper screen**;
single-shot full-panel orthographic capture is not achievable and is not
required. Capture in **vertical bands**, each shot roughly square-on to its
*local* surface tangent, with generous overlap so no glyph is lost at a seam.

**Tier A — minimum viable (ordinal O1).** Re-shoot the three K4-region framings
that already exist in-repo as 160×120 thumbnails
(`reference/Pictures/.../cipherlower{left,middle,right}.jpg` — proof that the
per-region frontal approach is feasible) at field grade:
- **Resolution:** glyph cap-height ≥ 50 px (≥ 12 MP per band typical).
- **Geometry:** optical axis ⟂ to the local surface tangent at each band center;
  step the camera laterally (or arc it) so each band is near-frontal where shot.
- **Overlap:** ≥ 30% between adjacent bands; every glyph appears, fully legible,
  in at least one band's near-frontal zone (not only at a band's foreshortened edge).
- **Lighting:** **raking light** (low oblique, ~15–30° from the surface) to throw
  the incised strokes into shadow relief; copper is specular, so cross-polarize
  or shoot multiple light azimuths to kill glare and recover edge glyphs.
- **Scale bar + color target** in frame (documentation/I4, not needed for ordinal O1).

**Tier B — robust edge recovery (recommended).** Add **RTI (Reflectance
Transformation Imaging)** per band: fixed camera, ≥ 24 light positions on a dome/
hemisphere, synthesized normal map. RTI is the epigraphy standard for reading
incised/worn inscriptions and is the right tool for the foreshortened row-edge
glyphs that decide line breaks. Resolves I1/I4 legibility ambiguity that flat
photography leaves open.

**Tier C — metric (only if you want the O5 geometry unlock, not for ordinal O1).**
**Photogrammetry / structure-from-motion**: 40–80 overlapping frames → textured
3D mesh of the panel. Enables (a) geodesic tracing of carved rows on the true
surface, and (b) **metric** comparison of row-break positions to the W-positions
[20, 36, 48, 58, 74] for the O1⇒O5 unlock (§5). Overkill for the ordinal O1 closure.

**Independence note (I4) applies to ALL tiers:** O1 must reproduce across **≥ 2
INDEPENDENT capture sessions** — different day / lighting / operator / provenance
(O4 archival corroboration is confirmed absent, so I4 must come from two photo
sessions). A row-break seen in only one session is provisional and excluded.

---

## 2. Transcription → registration (photo → O1), blinded for I1

Run by a transcriber (or a deterministic procedure) with **NO access to K4
decryption attempts, candidate plaintexts, scores, or the mask(s) under test**
(I1). Pre-register this procedure before reading.

1. **Read** each carved glyph in physical reading order, recording
   `(row_index, position_in_row, glyph, confidence, source_image_ids)`. Use the
   band overlaps to cross-check edge glyphs; require a glyph to be legible in its
   near-frontal band, not only at a foreshortened seam.
2. **Concatenate** rows in physical top-to-bottom, left-to-right order → carved
   sequence `S`.
3. **Anchor check (identity, not derivation):** assert `S == K4_CT` (the public
   97-char stream). A mismatch is a **misread to fix**, not a discovery — the
   ciphertext is known. This is the only use of letter values, and it is identity
   verification, so it does not violate I2.
4. **Derive O1** = `{ i : glyph i is the first glyph of physical row r, r ≥ 2 }`,
   0-based indices into `S`. (Row 1's first glyph is index 0; record it separately
   if you also want row-*ends*.) Optionally also emit row-end indices as a sister
   observable.
5. **Section boundary discipline:** index strictly from K4's first glyph (`O` = 0).
   Do NOT let a captured K3/K4 boundary glyph or the K3-trailing `?` shift the
   indices — the disposed Antipodes counterfactual {0,3,37,72} was wrong precisely
   because a boundary interpunct was included. K4 is `OBKR…UEKCAR`, nothing before.
6. **Output** under `analysis_runs/o1_acquisition_<date>/` with a manifest:
   per-position confidence, source image IDs, the two-session reconciliation, and
   a **SHA-256 of the final O1 index set** (I3 freeze, see §4).

---

## 3. Admissibility checklist (I1–I4) — gate before any closure call

| ID | Requirement | How O1 meets it (or fails) |
|---|---|---|
| **I1** Score-blind | Derived from photo + public CT + counting only; transcriber blind to masks/scores. | PASS iff the §2 blinding is honored and pre-registered. |
| **I2** Not a CT statistic | Row breaks are a physical fabrication/layout property; letter *values* used only for the identity anchor. | PASS iff break decisions use physical position only (never "which break would help a mask"). |
| **I3** Frozen before test | O1, δ, mask M, and null family hashed (SHA-256) before any `gap09_t2…` call. | PASS via §4 pre-registration. |
| **I4** Cross-source persistence | O1 identical across ≥ 2 independent capture sessions (or photo + independent archival layout — none known). | PASS iff two sessions agree on every break; disagreements excluded as provisional. |

A failure of **any** criterion makes the closure circular/artifactual — the exact
failure mode that retired the BCL palette and that the Antipodes.xlsx provenance
check (2026-05-29) just disposed of (an owner-authored 36-col reflow whose wrap
width is contradicted by the same workbook's 30-col KRYPTOS sheet → fails I1/I2).

---

## 4. Pre-registration template (fill in BEFORE running the test)

```
O1 CLOSURE PRE-REGISTRATION  —  date: __________  registrant: __________
- O1 (row-start indices, 0-based into OBKR…UEKCAR): { __________ }
- O1 SHA-256: __________      sessions reconciled: #1 __________  #2 __________
- tolerance δ (justify; default 0): __________
- score-free mask family M under test (declare the generator, NOT post-hoc):
    e.g. "every-N residue rule, N in {7,14}", "Polybius coordinate band", "vowel-class"
    mask generator + params: __________      M SHA-256: __________
- null family (MATCHED — see §5; for a periodic M use periodic_rule_masks):
    __________
- multiplicity: number of (mask, N/phase, δ) combinations to be tested: __________
    correction: Bonferroni / pre-registered family (state): __________
- gate: ADMIT iff  p ≤ 1e-6  AND  side-effect predicate holds (below)
- side-effect predicate (mandatory, beyond co-location): __________
    (Bean reduction at non-null positions, OR n-gram floor pass on null-extracted PT)
- pre-declared outcomes: see §6 decision tree
```

Freeze this (commit the filled template + the M/O1 hashes) before computing
co-location. **No tuning of O1, δ, or M after seeing overlap** (I3).

---

## 5. Push-button closure (the code already exists and is tested)

Use the **periodicity-matched null** — NOT the uniform hypergeometric. Carved
line-breaks are quasi-periodic and the dominant score-free mask family
("every-Nth") is periodic; the uniform null is **misspecified** for that pairing
(it fires p = 6.66e-08 on a period-14 mask vs period-14 breaks with zero stego
content — reproduced and fixed 2026-05-29; see the spec §2 caveat). The matched
null returns p ≈ 0.13 on that same confound — correctly not significant.

```python
from kryptos.admissibility.gap09_colocation import (
    gap09_t2_colocation_p_matched, periodic_rule_masks,
)
from kryptos.kernel.constants import CRIB_POSITIONS

O1   = {...}                       # frozen row-start indices (I3)
M    = {...}                       # the declared score-free mask (its OWN family below)
N    = 14                          # the mask's period (for a periodic rule)
family = periodic_rule_masks(N, n=97, crib_positions=CRIB_POSITIONS)  # MATCHED null

p = gap09_t2_colocation_p_matched(
        mask=M, observable=O1, null_masks=family,
        n=97, crib_positions=CRIB_POSITIONS, delta=0)
# ADMIT the mask construct iff:  p <= 1e-6  AND  side_effect_predicate(M) is True
```

For a non-periodic / bespoke mask family, pass that family's members as
`null_masks` instead (the function is null-agnostic; declare the family in the
pre-registration). The uniform `gap09_t2_colocation_p` is reserved for a
genuinely uniform-random mask only.

**O1 ⇒ O5 sub-test (run alongside):** check whether O1 (row-starts) coincides
with the W-positions **[20, 36, 48, 58, 74]** (within the declared δ). If it does,
that is *geometry* evidence for the W-as-row-delimiter reading — establishing O5's
independence **without assuming it**, and promoting O5 from inadmissible to
admissible. Tier C (photogrammetry) strengthens this from ordinal to metric
coincidence.

---

## 6. Decision tree (pre-declared)

- **p ≤ 1e-6 AND side-effect holds** → GAP-09's first independent anchor. Do NOT
  declare solve; escalate to full validation (kernel verification, matched
  multiplicity audit, red-team) per project doctrine. A 24/24 here is an INPUT to
  validation (AUDIT-3), not an output.
- **p > 1e-6** → documented NEGATIVE: the leading layout observable does not anchor
  that mask. Record it; GAP-09 stays open pending O2 (carved non-letter marks),
  O3 (carving anomalies), O4 (archival layout — currently confirmed absent).
- **O1 coincides with W-positions** → O5 promoted to admissible (a separate, real
  result even if the mask test is negative).
- **Sessions disagree on a break / glyph illegible at an edge** → that break is
  provisional; exclude it and re-shoot that band (Tier B RTI) before freezing.

---

## 7. Traps (do NOT do these)

- **Any reflow as O1.** `cylinder_viewer` 28×31 grid (CT reflow + retired palette),
  `cipher cylinder_5.jpg` (tabletop paper model), and **`Antipodes.xlsx` / its
  `Antipodes_Cipher_Chart.jpg` render** (owner-authored 36-col reflow, wrap width
  contradicted by the same workbook's 30-col KRYPTOS sheet — disposed 2026-05-29)
  are NOT carved-line-break measurements. A grid whose row width changes with a
  spreadsheet column setting carries zero physical information.
- **Single-source breaks** (fails I4). Edge glyphs are where curvature lies; one
  oblique frame will invent or hide breaks. Two independent sessions, or RTI.
- **Smuggling score info into row-reading** (fails I1). Read physical position
  only; never decide a break by "which break would help a mask."
- **Uniform null on a periodic mask** (the misspecification fixed this session).
  Use `gap09_t2_colocation_p_matched`.
- **Tuning O1/δ/M after seeing overlap** (fails I3). Freeze first, hash, then test.
- **Sanborn "97 vs 98 letters" / hidden adjacent `?`** — Tier-3 hearsay,
  contradicted by the carved fact (K4 has zero `?`). Not an O1 input.
- **ct_perturbation / transcription-error anchors** — symmetric (rescue any failed
  decrypt); inadmissible without a pre-registered budget.

---

## 8. Acquisition channels (realistic routes to the photo)

Ordered by independence-from-the-researcher (higher = stronger I1):
1. **Professional/curatorial capture** (CIA OPA, the artist's studio, or a
   conservation/epigraphy team) — strongest I1 (third-party, score-blind operator),
   and the natural route to Tier B/C. A documented request specifying the band +
   RTI plan above is the deliverable.
2. **Direct on-site capture** by an authorized visitor with the §1 Tier-A/B kit —
   feasible if site access is obtainable; two independent sessions satisfy I4.
3. **High-resolution existing photography** from independent photographers/news/
   archival sources (≥ 2 independent provenances) — cheapest, but must clear I4 and
   legibility; the in-repo corpus has been swept (AAA HEIC + non-AAA + Antipodes,
   2026-05-29) and contains nothing metrology-grade, so this means *new* external
   sources.

**Minimum viable, restated:** a high-resolution, near-frontal, raking-light
re-shoot of the three `cipherlower{left,middle,right}` K4-region bands, from **two
independent sessions**, with every glyph legible — sufficient to read which K4
character begins each carved row. Everything downstream is specified above and
the closure code is in `kryptos.admissibility.gap09_colocation` (12 tests green).

---

*Created 2026-05-29 (session 2). Companion to the GAP-09 acquisition spec.
GAP-09 remains evidence-gated: no in-repo analysis can manufacture O1.*
