# The K1/K2 Encoding Chart: Physical Layout, Tape, Margins, and Row Breaks

**Date:** 2026-09-19
**Status:** Observational note with a completed digital forensic pass (local enhancement, ink separation, grid metrology, 744-cell transcription check, mark inventory). Full measured report and re-runnable scripts are local-only under `analysis_runs/nyt_coding_chart_forensics_20260919/`; the measured results are summarised in §9.
**Subject image:** the K1/K2 handwritten encoding chart published by The New York Times (John Schwartz, "Original Decoding Charts for 'Kryptos'," 20/21 Nov 2010), analysed here from a 1150 x 1346 px JPEG copy.

This note records what is physically visible on the chart, what the layout is consistent with, and how the chart relates to the carved copper. It deliberately separates observation from inference. It makes no claim about the K4 method.

---

## 1. Why this chart matters

[PUBLIC FACT] On NPR *All Things Considered*, 22 Nov 2010 (host Mary Louise Kelly), two days after the NYT published the charts, Sanborn said:

> "I also divulged, or gave images, of my original decoding charts, the ones that I, well, actually, for me they were encoding charts. And I think once the Krypto-philes study it in a forensic manner, there might be revelations in there. So in a way, I gave more than just Berlin."

He named no examination type (paper, handwriting, corrections, erasures, marginalia). Every specific target in the community's later discussion is elaboration, not his. The remark refers to the K1/K2 charts only: the K3 chart was first shown in 2013 and the K4 material was not public until 2025.

[Tier-4, unrecorded] An attendee's blog summary of the 2013 American Cryptogram Association dinner reports Sanborn urging study of the released charts "particularly regarding misspelled words."

---

## 2. What the chart is

[DERIVED FACT, verified against `kryptos.kernel` constants via `kryptosbot/panel_cribs.py`]

Two pieces of green-grid quadrille paper, photographed separately (white background between them). Each cipher row occupies a four-line block: plaintext, keyword, ciphertext, blank. Rows are numbered 1 to 8 in the left margin. Rows are 31 cells wide.

| Chart row | Section | Plaintext cells | Notes |
|---|---|---|---|
| 1 | K1 | 31 | header line above reads `PALIMPCEST` (sic), partial |
| 2 | K1 | 31 | 63rd K1 character overflows to a vertical N / L / D stack in column 0 below the block |
| 3 | K2 | 31 | header `ABSCISSA` in the unruled top margin |
| 4 | K2 | 30 + `?` | the `?` occupies a cell and is carried through all three lines; the keystream does not advance on it |
| 5 | K2 | **32** | `CFIELDXTHEINFORMATIONWASGATHERED`; the leading C, its key S and its ciphertext I sit in a hand-drawn box in the **left margin**, outside the grid |
| 6 | K2 | 31 | ciphertext line written in an **unruled band** between rows 6 and 7, not in cells (see §3) |
| 7 | K2 | 31 | |
| 8 | K2 | 30 + `?` | image ends here; K2 continues on sheets not shown |

Concatenating the chart's K1 ciphertext rows (including the overflow D) reproduces the 63-character K1 ciphertext exactly. Concatenating rows 3 to 8 reproduces the first 185 letters of K2 ciphertext (a full transcription pass with enhanced crops is pending; two letters in row 6 were ambiguous at screen resolution, R/E and D/O).

Repro:
```bash
PYTHONPATH=src:kryptosbot python3 -c "import panel_cribs as pc; P=pc._K2_PT; print(len(P[61:93]), P[61:93])"
# 32 CFIELDXTHEINFORMATIONWASGATHERED
```

---

## 3. Observations at the seams and margins

Made from 3x enlarged, auto-contrasted crops of the original image. These are visual observations, not measurements.

1. **The two pieces are separated.** There is a white background gap between the K1 piece and the K2 piece. They were not joined when photographed.
2. **Tape residue is at the ends, not across the middle.** The bottom edge of the K1 piece carries a tape tab at the left (the overflow D is written on or under it) and a small tab at the right. The top edge of the K2 piece carries matching tabs, left and right. This is the pattern left when two short corner tabs are severed, not the pattern left by cutting a full-width strip in half.
3. **An unruled band separates rows 6 and 7.** It spans the full width, has no grid lines, and the row 6 ciphertext (`GZLECGY...`) is written in it without cells. Tape is present on or beside this band.
4. **Three lines of writing sit in unruled edge bands:** the overflow D (bottom of the K1 piece), the `ABSCISSA` header (top of the K2 piece), and the row 6 ciphertext (§3.3). All three coincide with tape.
5. **Row 5 overflows to the left.** The 32nd character of the row is placed to the left of column 0 in a hand-drawn box, whereas the K1 overflow after row 2 was placed below the block in column 0. Same problem, two different placements.
6. **Left-margin marks:** row numbers 1 to 8; a right-pointing arrow beside the row 1 ciphertext line; a left-pointing arrow or triangle beside the row 2 ciphertext line; a bracket beside the row 8 ciphertext H. Small tick marks appear under some row 2 ciphertext letters.
7. **Three tape patches on the rows 6/7 join,** not one strip: left, centre and right, under the row 6 ciphertext. They stand out as saturation-excess components in the original and as solid dark blocks in a hard global-levels rendering of the same JPEG.
8. **Two pale blue-grey rectangles in the left margin,** each about one cell wide and one and a half cells tall, beside the key and ciphertext lines of row 3 and again of row 7. Both sit at the head of a pad piece (row 3 heads the K2 piece, row 7 heads the segment below the rows 6/7 join). Soft-edged and slightly darker than the paper; visible in the original at 6x. What they are cannot be settled from one image: reverse-side adhesive or a label seen through the paper, or a translucent patch, are equally consistent.
9. **A thin yellow-brown line runs the full width along the top of the row 4 ciphertext cells.** The letters beneath are not degraded. Consistent with a fold crease that collected grime.

---

## 4. Inference: what the layout is consistent with

Computation pads have unruled margins at the top and bottom of each page. The simplest account of §3 is:

- Where a three-line block ran off the ruled area of a page, the third line was written in the unruled margin rather than restarting the block on the next page. This keeps plaintext, key and ciphertext vertically aligned, which is the point of the worksheet.
- The next page was then hinged on underneath with two short tape tabs at the corners. Two tabs, rather than a full-width strip, make a hinge that folds.
- The result was a long, hinged, foldable scroll of pad pages carrying the whole encipherment in one continuous keystream. The 2026-03 Smithsonian photo notes recorded accordion folds on the charts, which fits.
- The scroll was later cut back apart at the tabs, plausibly for framing, photography or sale.

None of this requires a cryptographic explanation. The blank fourth line is the ordinary separator of a Vigenère hand worksheet.

**Why not simply write on a larger sheet?** Because the 31-cell width is the panel width and the pad width, and the pad's page height is what ran out. Tape is how a pad becomes a scroll.

---

## 5. The chart is not the carving template

[DERIVED FACT] The chart breaks every row at exactly 31 cells (with the two overflow devices above). The carved copper does not. Left-panel line lengths, from the standard transcription, are:

| Carved line | Length | Chart row | Chart length |
|---|---|---|---|
| 1 | 32 | 1 | 31 |
| 2 | 31 | 2 | 31 + overflow D |
| 3 | 31 | 3 | 31 |
| 4 | 30 | 4 | 31 (incl. `?`) |
| 5 | 31 | 5 | 32 |
| 6 | 32 | 6 | 31 |
| 7 | 31 | 7 | 31 |
| 8 | 31 | 8 | 31 (incl. `?`) |

Concretely: the J that ends carved line 1 is the first cell of chart row 2; the T that begins carved line 5 is the last cell of chart row 4; the D that ends carved line 2 is the chart's column-0 overflow. The carved text is the same letter sequence reflowed into different line lengths.

[PUBLIC FACT, same NPR interview] Sanborn: "there were several ways I could manipulate the lines of text so I would end up with a panel that's square on the sides... I did leave an X out."

Reading: the chart is the encipherment draft at a fixed 31-per-row rhythm. Line lengths on the copper were adjusted afterward for the panel's visual edge, either on a separate layout drawing or during letter placement. Anyone using the chart's row breaks as evidence about the copper layout, or vice versa, should note they differ.

This also bounds what "worksheet correct, copper wrong" can mean: the chart spells ILLUSION and UNDERGROUND correctly, so IQLUSION follows from the keyword being written PALIMPCEST on the chart, while UNDERGRUUND entered at the carving stage (see `docs/anomaly_registry.md`, entries on IQLUSION and UNDERGRUUND).

---

## 6. Relation to the 2025 "strips" report

[Tier-3, held locally only as paraphrase] In September 2025 Jarett Kobek and Richard Byrne located K4 plaintext material at the Smithsonian Archives of American Art, described in reporting as scrambled plaintext on strips; Sanborn stated they found it but do not have the key or the method. That material is sealed.

[HYPOTHESIS] If the K4 plaintext existed as physically cut and rearranged strips, that is a working method built on paper manipulation. The K1/K2 chart shows the same habit at the worksheet level: cut pad pages, hinge them with tape, write in margins, box an overflow cell. This is consistent with the project's procedural-over-algebraic posture. It is not evidence about the K4 method: the chart is a Vigenère worksheet for a different section, and the strips are a different artifact.

---

## 7. Confidence and limitations

- **High:** the row-break mismatch between chart and copper (§5); the row 5 32-cell overflow; the K1 concatenation check; the measured results in §9.
- **Medium:** the corner-tab reading of the main-seam tape residue (§3.2) and the three-patch reading of the rows 6/7 join, from a ~1.5 MP web JPEG. Higher-resolution imagery or the physical object could overturn either.
- **Medium:** the two blue-grey margin rectangles and the row 4 crease line are present; their nature is open.
- The image passed through the photographer, NYT prepress and web export. Pixel-level steganalysis (LSB, chi-square) is non-probative on it and contributed to no conclusion here.
- Global levels adjustments of the same JPEG add no information. They can still be a useful visualisation: a hard saturation push isolates the yellowed adhesive and the blue-grey rectangles far more legibly than the original. The speckle they produce in blank cells is amplified paper grain and JPEG chroma noise, not bleed-through (§9.5).

---

## 8. What would require physical access or archive imagery

1. Raking-light photography, to separate pressure indentation from surface graphite. The tonal null in §9.3 says nothing about impressions with no tonal signature.
2. Transmitted or backlit photography: reverse-side content, what the tape patches cover, and what the two blue-grey margin rectangles are.
3. Physical measurement in millimetres plus watermark, to settle whether the K1 piece, the K2 rows 3 to 6 piece and the rows 7 to 8 piece are from the same pad.
4. The remaining K2 sheets, which the NYT image does not include.

---

## 9. Measured results of the digital forensic pass

All items below are [INTERNAL RESULT] with scripts and derived images under `analysis_runs/nyt_coding_chart_forensics_20260919/` (local-only path; the directory is not in the public repo).

### 9.1 File provenance
The JPEG carries the Photoshop CS5 "Save for Web" marker set (APP12 Ducky quality 93, XMP, Adobe APP14), no chroma subsampling, and an XMP document identifier whose timestamp decodes to 2010-11-10. At least two compression generations. Prepared for the NYT's November 2010 coverage.

### 9.2 Grid metrology
Thirty-two vertical rules, so 31 columns, on both pieces. Cell pitch 34.3 px on the K2 piece and 34.6 by 34.8 px on the K1 piece. The K1 piece is reproduced 0.9 percent wider and 1.7 percent taller than the K2 piece, an anisotropic mismatch that indicates independent placement and resizing of two captures during page assembly. Consequence: this image is not dimensionally reliable for overlay or scale-matching tests. Any argument that depends on measuring the chart against the sculpture from this file is unsupported.

The rows 7 to 8 grid is offset by about 2 px from the rows 5 to 6 grid at identical pitch, and the vertical rules drop to zero contrast through the rows 6/7 band. Together with the tape patches, the darker and more chromatic ink of the row 6 ciphertext (matching the ABSCISSA header, which also sits on tape), and the freehand placement of that line, this makes the rows 6/7 band a second physical join. The prior project note had recorded it only as a fold crease.

### 9.3 Hidden or faint content
A letter-sized matched filter over every blank region (header band, blank rows, inter-row gaps, margins, both seams, the area below row 8) returns a noise floor of 2 to 3 grey levels. The faintest genuine pencil glyph on the page returns 12.4 and the median glyph 31.4. Anything about four times fainter than the faintest real glyph would have been detected. Every maximum in the blank regions is a catalogued mark or filter leakage from an adjacent line. No indentation ghost, reverse-side bleed-through or erased text is recoverable from this image. Top-hat and black-hat stroke isolation at five kernel sizes agree.

### 9.4 Ink classes
Pixels separate into printed green rule and low-chroma graphite; 381 pixels in the whole image (0.03 percent) fall in neither. No writing line is in a different ink class from its neighbours. The two chroma outliers (row 6 ciphertext, ABSCISSA header) are the two lines written on tape, so a substrate effect. There is no evidence of a second pen or a second writing session, and the row 5 margin box is in the same class as the grid letters.

### 9.5 The apparent bleed-through in extreme levels renderings
In blank cells the paper-grain residual has a standard deviation of about 6.5 grey levels and each ruled cell has a slightly different mean tone. A 10-level global window amplifies that grain roughly 25 times and clips each cell differently, and the 4:4:4 chroma at quality 93 saturates to multicoloured speckle. The blocky, multicoloured texture in blank cells of the extreme renderings is therefore an artefact of the source encoding, not content.

### 9.6 Cell-by-cell transcription
All 744 cells were read at 3x to 9x against the canonical K1/K2 layout built from the kernel constants, with an independent template matcher as a second reader. Exactly two cells disagree with the canonical text, and both were already known to the community:

| Chart cell | Line | Canonical | Chart | Kernel check |
|---|---|---|---|---|
| Row 2, column 25 (K1 index 56) | key | S | **C** | enc(L, C) = K, the carved letter |
| Row 6, column 21 (K2 letter 114) | plaintext | U | **O** | enc(O, S) = E |
| Row 6, column 21 | ciphertext | R | **E** | carved letter is R |

The two divergences have different mechanisms, and the chart proves it. For IQLUSION the plaintext is spelled ILLUSION correctly and the keyword is written PALIMPCEST; the ciphertext Sanborn computed is the ciphertext that was carved, so the error is a worksheet keystream error that the sculpture faithfully reproduces. For UNDERGRUUND the worksheet is entirely correct, plaintext UNDERGROUND, key ABSCISSA, ciphertext E; the copper carries R, so the error entered after the worksheet. Both conclusions were already in `docs/two_ground_truths.md` and `docs/anomaly_registry.md` on community authority. What is new is pixel verification at pinned cell coordinates with the cipher arithmetic reproduced against the repo kernel.

Consequence for any hypothesis keyed on "Sanborn's deliberate misspellings": at least one of the two K1/K2 misspellings was not visible as a decision at encipherment time, because at that moment the plaintext was spelled correctly.

### 9.7 Mark inventory
Thirty-one non-letter marks catalogued with coordinates (arrows, a check-mark, ticks, corner brackets, isolated dots, a heavily traced S and Y, an underline stroke, a struck H, lower-case letters inside BURIED, the pass-through question-mark cells, the tape patches, and the items in §3.7 to §3.9). None has more than one indicator pointing beyond place-keeping while working across several hundred cells by hand. The row 7 letters are not underlined; they sit slightly high in their cells above the printed rule.

### 9.8 What the chart does and does not carry
Every physical feature of the chart resolves to production mechanics: pad width sets 31 columns, overflow characters go into hand-drawn margin cells or unruled edge bands, tape joins pad pages, marks are place-keeping. Beyond the published text, the only substantive information recoverable from this image is the asymmetry in §9.6, and that was already on record. The remark that forensic study "might" reveal something remains open with respect to the physical object, which this image cannot stand in for.

---

## Sources held locally (private `reference/` tree, not in the public repo)

- NPR transcript compilation, 22 Nov 2010 segment (quote at 02:47 to 03:16 per the LEMMiNO reference list).
- Standard left-panel transcription with line breaks (matches `kryptos.kernel` K1/K2 constants on concatenation).
- Prior Smithsonian photo notes on paper stock and folds (2026-03).
