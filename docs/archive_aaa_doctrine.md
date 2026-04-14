# Archives of American Art — Doctrine Memo

Source: 532 photos from Jim Sanborn papers, Archives of American Art, Smithsonian Institution (2026-03-27).
Classification per project truth taxonomy.

---

## [PUBLIC FACT] — Primary source confirmed

1. **ABSCISSA is a Sanborn research term.** "★⑩ Definition of ABSCISSA" appears as a starred to-do item in Sanborn's handwritten notes (IMG_1340). Combined with "Bottom chart reading" on the same page. ABSCISSA = x-axis of a coordinate system (or of a Vigenère tableau).

2. **Beaufort cipher is in Sanborn's cipher types list** (IMG_1569-1570). Handwritten list also includes: Compass cipher, Morse code, Alphabet code, Overlay, Normandy.

3. **"I wrote the Plain Text to be [deliberately] enigmatic"** (IMG_1405-1411). K4 plaintext is intentionally cryptic when correctly decrypted.

4. **"He lied"** — Deliberate K2 coordinate change from 38° to 37° (IMG_1381-1389). One degree south.

5. **Physical overlay "Code Breaker" concept** sketched (IMG_1555). Overlay placed ON TOP of code.

6. ~~**"4, 8, 10, 26 = Col"** on the ABSCISSA to-do page (IMG_1340). Possibly column widths.~~ **[RETRACTED 2026-04-14]** Colin re-examined the primary source: "4, 8, 10, 26" are the positions of the four question marks Sanborn drew to indicate those positions are NOT enciphered (i.e. literal unknowns in his working copy), and "Col" is an OCR misread of something else. This is bookkeeping, not a cipher hint. Do not cite this finding. Do not generate theories from it. See `memory/feedback_archive_col_notation_is_ocr_phantom.md`. The prior `f_archive_col_notation_v1` campaign that tested the columnar-widths interpretation returned EMPTY and is preserved for its cipher-family closure value (w4/w6/w7/w8/w9 Bean-impossibility, w10 four-survivor enumeration) but the *archival justification* for running it is retracted.

7. **"3 words most"** (IMG_1568). Context: "A choice of 3 words most typified the way of life." Could refer to 3 keywords.

8. **ATBASH** mentioned on same page as ABSCISSA (IMG_1340). Bottom of page reads "ATBA[SH]" or similar.

9. **Sanborn knew about frequency analysis**: "Frequency Tables forming" on his tradecraft glossary page (IMG_1571).

10. **"Avoid the pitfall of the obvious"** (IMG_1560).

11. **Handwritten Kryptos Vigenère tableau** with some letters CIRCLED (IMG_1223-1235). Row N has the documented extra L.

---

## [HYPOTHESIS] — Archive-supported but not proven

H-AAA-1: ABSCISSA refers to the column-addressing scheme of a Beaufort/Vigenère tableau. A keyword-mixed alphabet (using ABSCISSA or PALIMPSEST) serves as the column header of the cipher chart, changing the CT-to-PT lookup. This is structurally distinct from using the word as a periodic key.

H-AAA-2: "3 words most" = 3 keywords controlling distinct structural parameters. Candidates: KRYPTOS (tableau body), PALIMPSEST (period key or CT alphabet), ABSCISSA (column headers / PT alphabet). This maps to Quagmire IV with two keyword-mixed alphabets.

H-AAA-3: "Bottom chart seeding" = reversed row order in the tableau. Row A maps to the BOTTOM of the chart, row Z to the top. Combined with ABSCISSA column addressing.

H-AAA-4: Overlay/grille mechanism interacts with the cipher layer — not merely a null mask but a structural transformation (reordering, selection).

H-AAA-5: ATBASH applied as a pre- or post-processing step in combination with a Beaufort tableau. Trivially eliminated as standalone; open as one layer.

H-AAA-6: The circled letters on the handwritten tableau encode additional information (indicator positions, key material, or a secondary message).

~~H-AAA-7: "4, 8, 10, 26 = Col" are column widths for a transposition grid applied before or after substitution.~~ **[RETRACTED 2026-04-14]** The underlying notation is OCR-misread bookkeeping (question-mark positions), not a cipher instruction. See finding #6 above and `memory/feedback_archive_col_notation_is_ocr_phantom.md`. Do not generate hypotheses that cite this as archival support.

---

## [NEXT TEST] — Prioritized by structural novelty

### T1: Keyword-mixed tableau alphabet sweep (PRIMARY)
**What:** Test Beaufort/Vigenère/Variant Beaufort decryption where the TABLEAU ALPHABET is keyword-mixed using archive-sourced terms (ABSCISSA, PALIMPSEST, ECLIPSE, NORMANDY), with a SEPARATE keyword as the periodic key. This is Quagmire II/III/IV — structurally distinct from prior tests which used only AZ or KA as the tableau base.
**Why:** ABSCISSA = x-axis of chart. If Sanborn needed the word defined, he was using it as a chart-construction parameter, not just a key word. Bean constraints that eliminated periodic on AZ/KA may not apply to ABSCISSA-mixed alphabets.
**Binding priors:** ABSCISSA as chart term [PUBLIC FACT], Beaufort in cipher list [PUBLIC FACT]
**Soft priors:** "3 words most" suggesting multi-keyword system [HYPOTHESIS]

### T2: Bottom-chart orientation variants (SECONDARY)
**What:** Test reversed-row and reversed-column tableau orientations combined with keyword-mixed alphabets.
**Why:** "Bottom chart reading" on same page as ABSCISSA [PUBLIC FACT]. Reversal changes all key values.

### T3: Atbash as pre/post layer (TERTIARY)
**What:** Apply Atbash before or after T1's best-performing structural variants.
**Why:** ATBASH on same page as ABSCISSA [PUBLIC FACT]. Already tested with standard alphabets [NO SIGNAL]. Open with non-standard tableaux.

---

## What this does NOT change

- Single-layer periodic polyalphabetic on AZ/KA remains ELIMINATED.
- Autokey remains STRUCTURALLY IMPOSSIBLE regardless of tableau.
- Running-key + columnar on English sources remains eliminated.
- The null-mask provenance gap remains partially open.

---

Created: 2026-03-27
