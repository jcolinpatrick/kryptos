# GAP-09 Evidence-Acquisition Spec — independent K4-indexed observables for the T2 closure test

**Date:** 2026-05-29
**Status:** acquisition specification (actionable; no in-session compute closes GAP-09)
**Owner doc:** `docs/REAL_K4_EVIDENCE_GAP_REGISTER.md` (GAP-09), `docs/REAL_K4_EVIDENCE_ACQUISITION_PLAN.md`
**Supersedes for GAP-09:** the acquisition plan's "requires NEW independent observable (deferred)" placeholder — this document specifies *what* observable, *how* to acquire it, and *how* it closes T2.

---

## 1. Why this spec exists

[INTERNAL RESULT] GAP-09 (null-mask / stego evidence) cannot be closed by any
analytical pathway. Pathway-2 (`docs/campaigns/gap09_null_mask_pathway2_2026_05_27_results.md`)
ran 64 score-free mask rules under full anti-circularity discipline and found the
**closure test T2 structurally unrunnable**: GAP-09 closes only via an
independent-observable alignment at p≤1e-6, and **no K4-character-indexed
independent observable positions are documented** (YAR is K3-internal; the carved
`?`-marks and panel line-breaks have no K4-indexed positions recorded; the Stehle
window and width-21 bigram are K4-internal CT statistics, not independent).

Therefore GAP-09 is **evidence-gated, not compute-gated**. The blocking input is a
physical/archival measurement, and this spec defines it precisely so it can be
acquired by a party with sculpture/archival access (Colin: TS/SCI, potential AAA
and site access). The honest framing: GAP-09 is the highest real-solve-probability
lever precisely because it injects information that pure cryptanalysis cannot.

---

## 2. The closure test T2 (precise statistical procedure)

An independent observable unblocks T2 as follows. All objects frozen + SHA-256
hashed **before** the test (pre-registration; no post-hoc tuning).

**Inputs**
- A **score-free null mask** `M ⊆ {0..96}`, `|M| = m`, derived from a frozen rule
  using ONLY public structure (alphabet, geometry) — never K4 CT statistics or any
  crib/score signal (the pathway-2 proposer≠tester≠auditor discipline). `M` must
  not intersect the 24 crib positions (cribs cannot be nulls).
- An **independent observable position set** `O ⊆ {0..96}`, `|O| = k`, acquired per
  §4, satisfying the §3 independence criteria, with a documented provenance chain.

**Statistic** — co-location count
`c = |{ i ∈ M : ∃ j ∈ O with |i − j| ≤ δ }|`, with tolerance `δ` (default `δ = 0`;
any `δ > 0` declared and justified before the test).

**Null distribution** — same-size random masks, computed EXACTLY (no Monte Carlo)
The co-location count is the intersection of a random `m`-subset of the free pool
`F = {0..96} \ {crib positions}` with the FIXED target set `T` (the observable
expanded by ±`δ`, intersected with `F`). That count is therefore exactly
**Hypergeometric**(population `|F|`, successes `|T|`, draws `m`), so
`p = P(X ≥ c)` is an exact hypergeometric survival value — resolving p≤1e-6 with
no sampling floor. This is the same-size-random-mask null the pathway-2 audit
identified as correct (it removes the mask-size confound that made T1
non-discriminating), now in closed form.

> **⚠ NULL-MODEL CAVEAT (verified 2026-05-29).** The uniform-random
> hypergeometric null is **MISSPECIFIED when the mask is drawn from a STRUCTURED
> generative family** (e.g. a periodic "every Nth position" rule — which is the
> dominant family in the §2 rule grammar) **and the observable is itself
> structured** (carved line-breaks are quasi-periodic). Shared period+phase then
> inflates co-location with ZERO stego content: a period-14 mask vs period-14
> line-breaks fires at `p = 6.66e-08` — falsely clearing the 1e-6 gate — purely
> by alignment (reproduced; `tests/test_gap09_colocation.py`). For any structured
> mask family the closure MUST use the **periodicity-matched null**
> `gap09_t2_colocation_p_matched(mask, observable, null_masks=<family>, …)`,
> whose null family is drawn from the SAME grammar (`periodic_rule_masks` builds
> the periodic family). The matched null returns `p = 0.13` on that same
> confound — correctly not significant. The uniform hypergeometric is reserved
> for genuinely uniform-random masks only.

**Executable.** Implemented and tested
(`tests/test_gap09_colocation.py`, 12 green incl. the crib-cannot-be-null guard,
the periodic-mask misspecification reproduction, and a matched-null positive
control):
- `kryptos.admissibility.gap09_colocation.gap09_t2_colocation_p(mask, observable,
  n=97, crib_positions=CRIB_POSITIONS, delta=0)` — exact uniform-random null,
  **uniform masks only**.
- `gap09_t2_colocation_p_matched(mask, observable, null_masks=<family>, n=97,
  crib_positions=CRIB_POSITIONS, delta=0)` — periodicity/family-matched null,
  **required for structured (periodic) masks**; build the family with
  `periodic_rule_masks(period, n=97, crib_positions=CRIB_POSITIONS)`.

The moment an observable `O` is acquired per §4, the closure verdict is one call —
choosing the matched null whenever the mask family is structured.

**Side-effect requirement** (GAP-09 acquisition criterion (c), mandatory)
The mask must additionally carry a prediction **beyond crib score** that verifies
— e.g. Bean reduction at non-null positions, or an n-gram floor pass on the
null-extracted plaintext. Co-location alone is necessary, not sufficient.

**Decision**
GAP-09 admits the mask construct iff `p ≤ 1e-6` **AND** the side-effect predicate
holds. Otherwise the observable is recorded as tested-negative for that mask and
the gap stays open. Multiplicity across rules/masks/observables/δ is declared and
corrected (Bonferroni or pre-registered family); the 1e-6 gate absorbs modest
multiplicity but the count must be stated.

---

## 3. Independence criteria (the anti-circularity bar)

An observable `O` is **ADMISSIBLE** for T2 only if ALL hold:

- **(I1) Score-blind derivability.** `O`'s positions are derivable by a party with
  NO access to K4 decryption attempts, scores, cipher statistics, or candidate
  plaintexts — from the physical sculpture or an archival document alone. The
  measurement protocol must not reference any K4 PT/keystream/score.
- **(I2) Not a K4-internal CT statistic.** `O` is a property of the
  carving/layout/fabrication or an independent archival document — NOT derived from
  K4's ciphertext (this excludes the Stehle window, width-21 bigram, IC, autocorr,
  and every score-conditioned construct, including the retired BCL palette).
- **(I3) Frozen before the test.** `O` and `δ` are fixed and hashed before any
  co-location computation. No tuning `O`, `δ`, or the mask after seeing overlap.
- **(I4) Cross-source persistence.** `O` reproduces across ≥2 INDEPENDENT primary
  sources (e.g. two orthographic photographs from different provenance, or a photo
  plus an archival layout). A line-break or carving anomaly visible in a single
  scan is provisional until corroborated — guards against scan/lighting/JPEG
  artifacts (kryptos-corpus-forensics doctrine).

A failure of any criterion makes the "closure" circular or artifactual — exactly
the failure mode that retired the BCL palette and that the pathway-2 audit was
built to prevent.

---

## 4. Measurement protocols (how to acquire each observable)

General pipeline (forensic-photo-analysis / kryptos-corpus-forensics workflows):
1. Acquire high-resolution, perspective-corrected **orthographic** imagery of the
   K4 panel region; ≥2 independent shots/angles for (I4).
2. Register each carved glyph to its index in the public 97-char K4 stream
   (`OBKR…UEKCAR`; transcription is [PUBLIC FACT], Elonka Dunin). The glyph→index
   map is deterministic letter-by-letter counting.
3. Record observable positions as **K4 character indices 0–96** with per-position
   confidence and the source image IDs. Output under `analysis_runs/` with a
   manifest (repo-relative paths).

Per-observable capture rules are in §6 (populated from the primary-source inventory).

---

## 5. Priority order and minimum-viable acquisition

Acquire in this order (highest information-per-effort first):

1. **Line-break structure (O1)** — *minimum viable acquisition.* The actual carved
   per-character line breaks are **UNDOCUMENTED in any primary source** (the in-repo
   `cylinder_viewer` 28×31 grid is a CT reflow carrying the retired palette — NOT a
   measurement; see §6 Traps). Acquisition needs one good **orthographic** photo of
   the K4 panel + glyph counting; positions are then deterministic. Doubly valuable:
   (a) if the line-break indices co-locate with a score-free mask at p≤1e-6 with a
   verifying side-effect, GAP-09 gets its first independent anchor; (b) the **O1⇒O5
   unlock** (§6) — if breaks coincide with the W-positions [20,36,48,58,74], that
   adjudicates the W-as-delimiter independence dispute *from geometry*, promoting
   O5 to an admissible observable. This single measurement is the project's
   highest-leverage acquisition.
2. **Carved non-letter marks (O2)** — if any fall within/adjacent to the K4 stream;
   deterministic positions, strong independence (layout/artistic).
3. **Carving anomalies (O3)** — requires the multi-image persistence pass
   (kryptos-corpus-forensics over the deferred AAA batch + site photos); subjective,
   so (I4) is load-bearing.
4. **Archival layout document (O4)** — AAA working papers; strongest provenance if
   it exists, but acquisition is research-heavy and may not exist.

If O1 alone is acquired and yields p>1e-6 against the strongest score-free masks,
that is a real (if narrow) negative: it says the leading layout observable does not
anchor a stego mask, and GAP-09 stays open pending O2–O4.

---

## 6. Inventory of candidate observables (primary-source-grounded)

Primary-source pass by the archivist-historian (2026-05-29; agent-memory
`.claude/agent-memory/archivist-historian/k4_physical_layout_observables.md`).
**Headline:** no primary source anywhere documents K4's actual carved
per-character line-break structure. Every in-repo "layout" is a reflow of the
linear CT, a plaintext-draft note, or physically outside K4. The bottleneck is
therefore localized precisely: the missing datum is a **measured K4 panel line/
carving observable**, not an analytical construct.

| ID | Observable | Documented K4 position(s) | Provenance / class | Independence (I1–I2) | Acquisition status |
|---|---|---|---|---|---|
| **O1** | Carved LINE BREAKS (chars per physical row on the copper) | **UNDOCUMENTED** — no primary source records per-character carved line positions for K4 | physical fabrication; Sanborn manuscript (`reference/smithsonian_archive.md`) confirms a scribed row structure existed but gives **no K4 row width/count** | **STRONG if measured** — line-wrap on the S-curved screen is a geometry/letter-width decision, plausibly cipher-independent | **REQUIRES MEASUREMENT** (orthographic photo + glyph count). **Highest-value target.** |
| O2 | Carved `?` / non-letter marks in/adjacent to K4 | **NONE** — 4 total `?` (3 in K2, 1 at end of K3); K1 & K4 have zero | [PUBLIC FACT] canonical CT + AAA stencil photo (`registries.py` `aaa_question_mark_j_stencil`) | n/a (no K4 observable) | **No observable exists.** Do not manufacture one (see Traps). |
| O3 | Carving anomalies / spacing / depth / corrections at K4 chars | **NONE documented inside K4** (YAR is K3-internal; extra-L is on the tableau panel) | forensic doctrine; never applied to K4 | **STRONG if found** (fabrication artifact, cipher-independent) | **REQUIRES forensic K4-specific photo survey**, ≥2 independent images for (I4). 2nd-highest target. |
| O4 | AAA working-paper carved-CT K4 layout with marked positions | **NONE found**; the "3 Lines 93" / "10.8″ 4 rows" yellow-pad notes are **K4 PLAINTEXT-DRAFT** layout, not carved CT (numbers don't reconcile: 8×12≈96≠97) | AAA photos, Sanborn's hand (`reference/kryptosfan_findings.md`) | would be strong if carved-CT, but none is | REQUIRES review of the ~380 unreviewed AAA images (`reference/Pictures/aaa_image_index.md`); may not exist |
| **O5** | The 5 W-positions **[20, 36, 48, 58, 74]** | **DOCUMENTED** [DERIVED FACT], computable from CT | derived from K4 CT | **DISPUTED** — W-as-row-delimiter (independent → valid) vs W-as-ciphertext (correlated → invalid). **Cannot be assumed independent** (W-anchor family heavily worked, largely null: `project_w_anchor_hypothesis_eliminated_2026_04_29`) | available **now** but **INADMISSIBLE by default** — fails (I2) unless independence is established by SEPARATE evidence |

### The O1 ⇒ O5 unlock (sharp, actionable)

O5 (the W-positions) is the only observable with confirmed K4 indices, but using
it presumes the very independence T2 must establish. **Acquiring O1 resolves
this:** if the measured carved line breaks independently coincide with the W
positions, that geometry evidence establishes the W-as-row-delimiter reading
*without* assuming it — promoting O5 from inadmissible to admissible. So the
single measurement (O1) can both supply an anchor and adjudicate O5. This is the
highest-leverage acquisition in the project.

### Traps / inadmissible "observables" (do NOT use)

- **The `cylinder_viewer.html` 28×31 grid** *looks* like a layout fact (it even
  hard-codes "K4 starts row 24 col 27") but is a **mathematical reflow of the
  linear CT** (`Source: …FULL_CORRECTED_CT`), not a transcription of physical line
  breaks, **and it carries the retired NULL_PALETTE {B,G,I,K,O,W,Z}**. Treating its
  row-ends as carved line breaks is a self-inflicted false observable. **Excluded.**
- **Sanborn "look at K4 as 97 and 98 letters" / a hidden `?` adjacent to K4**
  (kryptosfan 2014) — **Tier-3 hearsay** that contradicts the carved fact (K4 has
  zero `?`); Sanborn has a documented misdirection record. **Excluded.**
- **The "4,8,10,26 = Col" AAA notation** — RETRACTED OCR phantom
  (`feedback_archive_col_notation_is_ocr_phantom`). **Excluded.**
- **IMG_1212 26×26 Cyrillic grid X-marks** — a Quagmire-tableau working sheet; the
  X-marks have **no demonstrated mapping to K4 positions** (HYPOTHESIS only).
  **Excluded** until a mapping is independently established.
- **ct_perturbation / transcription-error anchors** — symmetric (can rescue any
  failed decrypt), so inadmissible as a T2 anchor without a pre-registered budget.

---

## 8. Acquisition attempts log

- **2026-05-29 — AAA HEIC corpus forensic pass (in-session).** Swept all 532 AAA
  HEIC images (`reference/Pictures/Arichives of American Art/`) for O4 (a carved-CT
  K4 layout sheet) and O1 (measurable K4 panel imagery). Deliverables under
  `analysis_runs/aaa_gap09_carved_ct_sweep_2026_05_29/`.
  - **O4: CONFIRMED ABSENT** (high confidence). OCR (tesseract) over 263 text-pool
    images matched against 12 diagnostic K4 substrings + all 93 distinct K4 5-grams
    → **zero** K4 transcription/grid in any document; corroborated by visual
    inspection of every high-doc-score page. No carved-CT K4 worksheet exists in
    this corpus. The retracted "4,8,10,26=Col" notation was NOT revived; the
    1223–1235 grid is the KRYPTOS Vigenère tableau (not a K4 mask/layout).
  - **O1: TENTATIVE, NOT metrology-grade.** IMG_1095 (corroborated by IMG_1098 /
    IMG_1135) shows genuine carved K4 (`OBKR`@0, `FBBWFLR…QPRNGKSSO`@17–34, the
    K3/K4 boundary `?` visible) with visible line structure — verified by eye
    against `kernel.constants`. But it is an oblique, foreshortened, halftone
    reproduction of the S-curved screen; per-character horizontal positions are
    nonlinearly distorted and line-break char-indices are NOT cleanly extractable.
    Treated as a reference image, NOT an admissible observable (fails I4 / clean
    positions). Does NOT unblock T2.
  - **Net:** GAP-09 stays blocked on a **flat, frontal, orthographic,
    high-resolution K4 panel photograph** (none in this corpus).
- **2026-05-29 — non-AAA `reference/Pictures/` root check (in-session, visual).**
  Examined the systematic carved-panel region close-ups and high-res cylinder
  shots that the AAA pass did not cover.
  - `cipherlower{left,middle,right}.jpg` — the K4 (lower) panel region, roughly
    frontal per-region framing, BUT only **160×120 px** (thumbnail-grade): line
    structure faintly visible, individual characters illegible. Not metrology-grade.
  - `cipher cylinder_5.jpg` (1742×1418) — a **paper-model grid wrapped on a
    cylinder** (researcher reconstruction on a tabletop), NOT the carved sculpture.
    TRAP CLASS (same as the `cylinder_viewer` grid): its row layout encodes the
    model-builder's assumptions, fails (I1/I2). **Excluded.**
  - **Net:** confirmed across both corpora — no orthographic, high-resolution
    carved-K4 image exists in-repo. BUT the existing thumbnail framings
    (`cipherlower{left,middle,right}`) prove the per-region orthographic approach
    is feasible. **Minimal viable acquisition (refined): a high-resolution
    re-shoot of those exact three K4-region framings** (or a rectified composite),
    sufficient to count which K4 char begins each carved row.
- **2026-05-29 — `antipodes/` subfolder check (in-session, visual).** Antipodes
  (Sanborn's other sculpture, same K4 text) was hypothesized to have FLAT panels
  (no foreshortening). **Falsified:** Antipodes is also a CURVED copper scroll
  (`Antipodes_1.jpg` and the 26-frame set are all curved/oblique) — same metrology
  problem. **However**, `Antipodes_Cipher_Chart.jpg` (rendered from
  `antipodes/Antipodes.xlsx`) is a structured **36-column grid transcription with
  explicit K3/K4/K2 row labels and TOP/BOTTOM-PARTIAL annotations** — the closest
  thing in the repo to a carved-CT layout. **STATUS: candidate pending provenance,
  NOT admissible as-is.** It is a researcher spreadsheet (Tier-4); its 36-wide row
  structure could be a faithful transcription of the physical Antipodes carved rows
  OR a convenient reflow (trap class, same risk as `cylinder_viewer`). **Actionable
  lead (cheaper than a site visit):** establish `Antipodes.xlsx` provenance — does
  its row layout transcribe the physical Antipodes panel rows? If verified faithful,
  its K4 rows yield a line-break observable (an Antipodes-relative O1; note the
  Antipodes line layout may differ from the main Kryptos sculpture, so it is a
  related/corroborating observable, not necessarily the canonical one). Route to
  archivist-historian. `Smithsonian/` (18 AAA scans) and `Lingua/` not yet swept.

## 7. What this spec does NOT claim

- It does not close GAP-09 (no observable acquired here).
- It does not revive the BCL palette or any score-conditioned mask.
- It does not assert any specific line-break or `?`-mark K4 position as fact — §6
  records only what primary sources document; undocumented positions are flagged
  as requiring physical measurement, which is itself the actionable finding.
- It does not weaken the p≤1e-6 gate or the side-effect requirement.
