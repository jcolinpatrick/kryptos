# Archive Photo Evidence Inventory — IMG_1200-1240 Cluster

Date: 2026-03-28
Source: Archives of American Art, Smithsonian Institution
Collection: Jim Sanborn papers, circa 1950-2023

## Critical Evidence Summary

The IMG_1211-1240 range contains Sanborn's working cipher materials for Kryptos.
This is a first-pass forensic inventory. Photos read via pillow-heif from HEIC originals.

## Evidence Items

### IMG_1211 — Cyrillic grid on graph paper
- **Content:** Russian/Cyrillic text in a grid format. Top row reads approximately "АКРШТИНИЕЕАЕЯТЕЛЬНОСТИ" (possibly "ДЕЯТЕЛЬНОСТИ" = "of activity")
- **Second row:** Repeating Cyrillic symbols: Ф, Ч, Ш, Ж, И, Ф, Ч, Ш, Ж, И, Ф, Ч, Ш...
- **Format:** Handwritten on graph paper, partially filled
- **Significance:** The repeating Cyrillic pattern may be a cipher key or encoding scheme. The regularity suggests a substitution table row.

### IMG_1212 — "Kryptos" Sculpture (26²) tableau [HIGHEST PRIORITY]
- **Content:** 26×26 grid filled with handwritten Cyrillic characters, X marks, and circled letters
- **Header:** "Kryptos" Sculpture (26²)
- **X marks:** Scattered throughout the grid, forming a pattern — possibly marking null/blocked positions
- **Circled letters:** Multiple visible — possibly marking positions used in encryption
- **Bottom-left:** Small Cyrillic alphabet grid (А, Б, В...) and red annotation "...room... Russian Ma..."
- **Significance:** This is the ACTUAL working tableau for Kryptos. The X marks may constitute the Cardan grille / null mask pattern. If the X positions can be mapped to the 97-char K4 ciphertext, they could identify null positions directly.
- **Action needed:** Full manual transcription of the 676-cell grid to catalog all X marks and circled letters and determine if they encode the null mask.

### IMG_1213 — Sparse grid on graph paper
- **Content:** Another grid with sparse handwritten entries. Partially filled.
- **Significance:** May be a working draft of IMG_1212 or a different encoding stage.

### IMG_1214 — Mixed Latin/Cyrillic grid
- **Content:** Grid containing Cyrillic characters and some Latin letters. "КАСК" visible.
- **Significance:** Mixed-alphabet working document. May show intermediate encoding steps.

### IMG_1218 — Russian text in grid format
- **Content:** Cyrillic text laid out in a multi-row grid. Dense content across full page.
- **Header annotation (red ink):** "Round room (3) converted Russian Mail" (partially legible)
- **Significance:** Russian source text structured in grid format — possibly the text being encoded or a reference document for cipher construction.

### IMG_1219 — Stencil job order + Phillips Collection text on transparency
- **Content:** Multiple overlapping materials:
  - Job order: "JOB 55741-0001-01 JIM SANBORN" — "misc type for Jim Sanborn stencil type"
  - Text on transparent sheet: Phillips Collection description (running-key candidate)
  - Small printed KA tableau visible in corner
- **Significance:** The stencil job order confirms physical stencil production. The Phillips Collection text on transparency is a direct running-key candidate (tested: 4/24 max = noise for direct use, but viable as source for mono+trans+running-key model).

### IMG_1220 — Phillips Collection museum text
- **Content:** Printed text about the Phillips Collection ("GLORIOUS IMPRESSIONIST PAINTINGS THAT...")
- **Significance:** Additional running-key candidate text.

### IMG_1221 — Transparent overlay with grid patterns [HIGH PRIORITY]
- **Content:** Golden/amber transparent sheet with grid/mesh patterns overlaid on other materials
- **Format:** Physical overlay — possible Cardan grille or "Kryptos Decoding Filter"
- **Significance:** This may be the physical manifestation of the null mask / selection grille. Cannot be digitally analyzed at this resolution.

### IMG_1222 — Russian text block
- **Content:** Dense Russian text paragraph. Appears to be printed reference material.
- **Significance:** Russian source material in Sanborn's working files.

### IMG_1223-1235 — KA Vigenère Tableau (13 photos, multiple angles)
- **Content:** Complete 26×26 Vigenère tableau using KRYPTOS-keyed alphabet (KA)
- **Circled H:** At approximately Row 11 (E), Col 3 (P) — meaning Enc(P, E) = H in KA
- **Circled T:** In the lower portion, exact position requires row identification from context
- **Sheet labeled "#2"** (IMG_1225) — confirms multiple copies exist
- **Significance:** This is the K1-K3 encryption tableau (Quagmire III). The circled letters may mark specific lookup operations performed during K4 encryption.

### IMG_1236 — Sanborn's handwritten encryption concept [CRITICAL]
- **Content:** Sketch of Kryptos sculpture with handwritten note:
  > "encrypted message is included within set of modern day font characters. Could be done to shade an area"
- **Significance:** DIRECT STATEMENT of the steganographic principle. Confirms:
  1. The encrypted message is HIDDEN WITHIN a larger character set (null masking)
  2. A physical overlay ("shade an area") reveals which characters matter
  3. This is exactly the Cardan grille / null mask model

### IMG_1237 — Transparent overlay photo (different angle)
- **Content:** Golden/amber transparency with grid patterns, different angle from IMG_1221
- **Significance:** Additional view of the physical overlay/grille.

### IMG_1238 — Stencil production job order
- **Content:** "JOB 55741-0001-01 JIM SANBORN REV:11-10 EXP:11-10 MW SIZ: 21.06"
  - "misc type for Jim Sanborn stencil type jennifer row... 7x88 on a side aps 55741"
- **Significance:** Confirms stencil production. "7x88" dimension is notable — could this be 7 rows × 88 columns? (K4 has 97 chars; a 7-row grid would have ~14 columns for 97 chars.)

### IMG_1239 — Email: "Proposal for a new encrypted sculpture" (2005)
- **Content:** Email discussing Runes, Viking-era encoding, the Havamal (Norse poem about Odin), Howard Carter
- **Bottom label:** "Sanborn papers, circa 1950-2023"
- **Significance:** Context for K5 development; confirms Sanborn's ongoing interest in historical encryption systems.

### IMG_1240 — "DO NOT SCAN"
- **Content:** Sheet marked "DO NOT SCAN"
- **Significance:** Some archive materials were restricted by Sanborn.

## Bounded Testable Hypotheses

1. **Phillips Collection text as running-key source:** Already tested (4/24 direct, noise). Could be tested under mono+trans model but this is open-ended.

2. **IMG_1212 X-mark pattern as null mask:** If the X marks in the 26² Cyrillic grid can be mapped to K4 positions, they could define the null mask. Requires full manual transcription of the 676-cell grid.

3. **"7x88" stencil dimension as grid parameter:** A 7-column or 7-row grid for K4 (97 chars → 7×14=98, close to 97). Col-7 transposition is already a known K4 feature.

4. **Transparent overlay as physical Cardan grille:** The overlay in IMG_1221/1237 may define the grille pattern. Cannot be digitally extracted without higher-resolution imaging or physical access.

## Status
- Photos converted from HEIC via pillow-heif
- First-pass visual analysis complete
- Full grid transcription of IMG_1212 NOT yet performed (requires careful manual work)
- Running-key test of Phillips Collection text: DONE (noise for direct use)
