# Real-K4 Acquisition Specifications

**Created:** 2026-06-11. Companion to
[`docs/REAL_K4_EVIDENCE_GAP_REGISTER.md`](REAL_K4_EVIDENCE_GAP_REGISTER.md),
[`docs/REAL_K4_EVIDENCE_ACQUISITION_PLAN.md`](REAL_K4_EVIDENCE_ACQUISITION_PLAN.md),
and [`docs/REAL_K4_PSEUDO_CLUE_PACK_ADMISSION.md`](REAL_K4_PSEUDO_CLUE_PACK_ADMISSION.md).

This document converts the acquisition-gated gaps into **ready-to-execute
specifications**: exactly what data closes (or advances) each gap, at what
quality, from which admissible channels, with the measurement protocol
pre-registered so the evidence cannot be tainted by post-hoc fitting. It
exists so that when an acquisition opportunity arises (site visit, archive
access, community contact, records request), the ask is already precise.

**This is a specification, not an action.** No acquisition is performed, no
compute is run, and the bridge-campaign pause (`C-BRIDGE-03`) is unaffected
by this document.

**Source policy (applies to every spec):** only publicly documented,
independently obtainable, or institutionally archived sources are
admissible. Private-transaction material is categorically out of scope per
standing project policy. Creator statements are Tier-3 hearsay unless
independently corroborated; packs built on them must satisfy admission
rule 11.

**Cross-cutting provenance requirements (every spec):**

1. **Chain of custody:** original files (no recompression), capture date,
   operator, device, and SHA-256 of originals recorded before any analysis.
2. **Independence:** a source is independent only if it is a different
   capture event AND different operator from material already in
   `reference/` (the GAP-04 stills are all frame-grabs of ONE video — a
   second grab of the same video is NOT independent).
3. **Blind annotation:** anyone transcribing, measuring, or flagging
   features must not be shown the hypotheses under test or any K4 scoring
   output.
4. **Preregistration before scoring:** acquired data feeds a written
   analysis protocol (statistic, null, thresholds) BEFORE anything touches
   crib scoring; mandatory rule-7 side-effect for any pack derived from it.

---

## SPEC-A — GAP-04: square-on photography of the K3/K4 boundary anomaly (YAR)

**Objective.** Confirm or refute the vertical-raise reading of the `YAR`
superscript (Elonka 2002 tactile rubbing) with quantitative, independently
sourced imagery. The 2026-05-29 pixel measurement
(`analysis_runs/ndyahr_displacement_forensic_2026_05_29/`) CONTRADICTED the
6-letter directional `NDYAHR` reading (perspective on the S-curve) and
found R sits slightly LOW (+0.6 sigma downward, no raise), but Y and A were
unmeasurable in every frame (frame-left margin/shadow) and all 30 stills
are single-source. The rubbing remains the only first-hand evidence.

**Data product.**
- One or more photo sets of the lower-left cipher-side panel region with
  the full `ENDYAHR` run in frame PLUS at least two full text rows above
  and below it (control baseline for the hand-cut jitter floor).
- **Geometry:** fronto-parallel to the local panel surface at the anomaly;
  incidence within ~10 degrees on both axes (the perspective artifact that
  killed the directional reading appears in oblique frames — squareness is
  the load-bearing requirement). A short bracket of angles around square-on
  is valuable for verifying angle-independence of any offset.
- **Resolution:** at least ~50 pixels of height per carved glyph in the
  anomaly row (the 2026-05-29 frames resolved a 28 px RMS jitter floor ~
  1.4-1.8 cm; resolving a claimed "several centimeter" raise against that
  floor needs comfortably finer sampling).
- **Lighting:** two variants if possible — diffuse (flat) and raking
  (side-light; a true relief offset casts asymmetric shadow), glare-free
  on Y and A specifically.
- **Scale/reference:** any in-plane object of known size, a stereo pair,
  or overlapping frames sufficient for photogrammetric scale.
- **Secondary target (same visit/source):** the corresponding region on
  Antipodes — presence/absence of the superscript there is a register-named
  cross-check.

**Admissible channels.** New site photography (CIA public affairs /
press / educational access routes); full-resolution originals from
community researchers' own visits (Elonka and others — the ask is
"originals, not web re-encodes"); Smithsonian/AAA holdings; public-records
photo requests. NOT admissible: re-grabs of the existing video source.

**Pre-registered measurement protocol (on arrival).**
Re-run the existing forensic pipeline (same statistics, new data):
1. Control baseline: per-row residual RMS from unambiguous letters in the
   two flanking rows (the jitter floor, in px and cm).
2. Per-character vertical offset of Y, A, R relative to their row baseline,
   in jitter-floor sigma units, per frame.
3. **Decision rules (frozen now):** CONFIRMED iff at least two of {Y, A, R}
   show >= +2 sigma upward offset in at least two independent frames AND
   the offset is angle-stable across the bracket. REFUTED iff all three
   show |offset| < 1 sigma in square-on frames. Otherwise UNRESOLVED
   (report measured bounds; no narrative).
4. Antipodes cross-check reported descriptively (secondary).

**Downstream if CONFIRMED:** YAR is cast as a positional ANCHOR (register
language: "mark this position"), never a numeric shift cue (50-script
numeric exhaustion stands, do-not-revive). An anchor pack must satisfy
admission rules 1-3, 7 (anomaly co-location menu item), 9, 10.
**Downstream if REFUTED:** anomaly A5 closes as carving jitter; GAP-04
moves to closed-negative; the rubbing is annotated as uncorroborated.

---

## SPEC-B — GAP-09: K4-panel physical micro-position dataset

**Objective.** Produce the missing K4-relative independent observable.
Pathway-2 (2026-05-27, `docs/campaigns/gap09_null_mask_pathway2_2026_05_27_results.md`)
proved the closure test is UNRUNNABLE today: every candidate independent
observable is either K3-internal (YAR) or unmeasured (separator marks,
line breaks, spacing). A score-independent null-mask construct needs
physical per-character data for K4 itself.

**Data product.** For each of the 97 carved K4 characters, plus the
section-separator marks and all line breaks as carved:
1. **Layout:** row assignment and within-row index exactly as carved
   (cross-checked against the authoritative Elonka transcription; any
   discrepancy is itself a finding).
2. **Coordinates:** glyph-centroid position in a panel-relative frame
   (defined by panel edges/seams), target relative accuracy ~2 mm — an
   order of magnitude under the measured ~1.4-1.8 cm hand-cut jitter
   floor, so spacing outliers are resolvable above carving noise.
3. **Glyph metrics:** height, width, inter-letter gap to both neighbors,
   and (if capture is 3D) stroke depth.
4. **Anomaly flags:** tool-mark / depth / kerning outliers, flagged blind
   (annotator sees glyphs, not hypotheses).

**Capture modes (either suffices).** (a) Metric photogrammetry from an
overlapping photo sweep of the K4 rows (same access requirements as
SPEC-A; the two specs share a visit), or (b) an existing laser/structured
-light scan obtained from institutional records (GSA/CIA facility records,
Sanborn studio records via AAA, any academic scanning project). Two
independent 2D captures can substitute for one metric capture if scale
references are present.

**Pre-registered analysis discipline (frozen now).**
- Candidate null-masks may be derived ONLY from physical-feature
  thresholds fixed before any scoring (e.g., inter-letter gap > mean + 2
  sigma; depth outlier set), with **at most 3 free parameters** (register
  requirement), each with physical justification.
- Every construct must state (a) which positions are nulls, (b) the
  score-independent derivation, (c) a rule-7 side-effect prediction beyond
  crib score (Bean reduction at non-null positions / anomaly co-location /
  ngram floor on extracted text).
- Evaluation order: the pathway-2 score-independent harness FIRST; only a
  construct that survives it may enter an admission-gated pack. The
  retired BCL palette stays retired regardless (its revival path is a
  methodological audit, not new data).

**Why this is the highest-value acquisition:** GAP-09 blocks GAP-02
(width-21 vs CT73 contradiction) and every stego-mediated cipher
hypothesis; `feedback_pt_length_open_question` keeps PT length open, so
the null-mask question is load-bearing for the entire fixed-97 assumption
boundary.

---

## SPEC-C — GAP-05: panel geometry that predicts a numeric parameter

**Objective.** A measured physical geometry that predicts a SPECIFIC
cipher parameter (width / depth / period / count) tied to a compilable
mechanism — the register's bar for GAP-05. Narrative geometry ("the
compass points at the answer") is explicitly insufficient.

**Data product.** Dimensioned model of the cipher-side panel: overall
dimensions, per-row character counts as carved, seam/edge positions,
S-curve arc geometry (radius/arc-length per text row), facet counts of
adjacent sculpture elements. Centimeter absolute / millimeter relative
precision. **Shared capture:** the SPEC-B photogrammetric sweep covers
this; no separate acquisition needed if SPEC-B executes.

**Pre-registered discipline:** one parameter per pack; the parameter and
its mechanism mapping (admission rule 2) must be written down from the
measurement BEFORE any decrypt is scored; bounded extraction per rule 3;
rule-7 side-effect mandatory. Any geometry-derived width/period that was
already swept under direct alignment does not get re-run (exhaustion
gate); the novel content must be the PARAMETER'S provenance, which makes
a previously-arbitrary cell admissible rather than re-runnable.

---

## SPEC-D — bespoke chart / cipher-procedure description

**Objective.** Obtain a public, citable description of the chart-based
procedure Scheidt provided for K4 sufficient to compile a mechanism. The
session-briefing Bin E names this cell untestable without "the public
chart OR a CipherProcedureLicense schema".

**Sufficiency bar (what a description must pin to be compilable):**
character set; chart/tableau structure (dimensions, fill rule); keying
procedure (state, advance rule, key consumption); input-output mapping
direction; null/padding policy; and at least one worked plaintext-
ciphertext example usable as a known-answer test. A description missing
items goes to the schema route below with each unknown declared as a
bounded `ParamRange`, not guessed.

**Admissible channels.** Published Scheidt interviews/papers and public
statements (rule-11 doctrine applies: Tier-3 unless corroborated;
11a-11d bounded extraction); FOIA/declassification requests for training
materials describing the procedure class; museum/archive holdings (AAA);
academic crypto-history publications (e.g., Cryptologia). The
`cipher_discovery` subsystem's KB should be queried for procedure-class
matches before any new acquisition (desk check, zero cost).

**Engineering alternative (desk item, not acquisition):** draft the
`CipherProcedureLicense` schema — a declared format for partially-known
procedures with bounded unknowns — so that a future partial description
becomes dispatchable without a complete chart. This is a separate
engineering task; this spec only records that the alternative exists.

---

## SPEC-E — in-repo extraction (no external acquisition): circled tableau letters

**Objective.** The AAA archive already holds IMG_1223-1235: Sanborn's
handwritten Vigenère tableau with some letters CIRCLED (row N carries the
documented extra L). The circled-letter set has never been blind-extracted
(`docs/archive_aaa_doctrine.md` item 11; ~380-image AAA backlog note).

**Protocol (desk, queued for a corpus-forensics session):** HEIC-to-JPG
preconversion; blind transcription of circled positions by an annotator
shown ONLY the tableau images (no K4 context); two independent passes,
discrepancies adjudicated on pixels (the AAA index has produced two
PUBLIC-FACT phantoms — primary images only, never index summaries);
output = (row, column, letter) set with confidence per mark. Only after
the set is frozen does any K4-related analysis get preregistered.

---

## Status summary

| spec | gap | external acquisition needed | shares capture with | desk-executable today |
|---|---|---|---|---|
| A | GAP-04 | yes (independent photo) | B/C (same visit) | no (protocol pre-registered) |
| B | GAP-09 | yes (photogrammetry or scan) | A/C | no (analysis discipline frozen) |
| C | GAP-05 | covered by B's capture | A/B | no |
| D | bespoke chart | yes (records/publications) | — | KB query + schema draft only |
| E | circled letters | no (in-repo images) | — | yes (queued, blind protocol) |
