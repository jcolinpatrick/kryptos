# The K3 Encoding Chart: Provenance, Layout, and the Route It Encodes

**Date:** 2026-09-19
**Status:** Complete. Provenance and route in §1 to §3; the digital forensic pass (blind 336-cell transcription, grid metrology, mark inventory, faint-content test) in §7. Measured report and scripts are local-only under `analysis_runs/k3_chart_forensics_20260919/`.
**Subject image:** a 656 x 1152 px JPEG screen capture of a slide from Jim Sanborn's Big Techday 6 talk (2013), showing his K3 working chart. Held locally under the private `reference/` tree; lineage and generation of the capture are unrecorded.

Companion to `docs/nyt_k1k2_chart_physical_layout_2026_09_19.md`. Same rules: observation, inference and speculation are separated; nothing here is a claim about K4.

---

## 1. Provenance

[PUBLIC FACT, Tier 3 for the description] The chart was first shown in Sanborn's talk "Techno Art: Kryptos, On the Fusion of Art and Science" at Big Techday 6 (TNG Technology Consulting), recorded 14 June 2013, slide numbered 1371220840, described in the community record as a previously unreleased image of the encoding chart used to create the K3 ciphertext. Kryptos-Beyond K4 (kryptosfan) posted it on 29 October 2013. The LEMMiNO documentary calls the image "very low resolution."

[INTERNAL RESULT] Our copy entered the repository on 2026-03-19 with no recorded upstream URL. Nobody local is recorded as the person who captured the slide.

**Correction to the project's prior note.** `reference/kryptosfan_findings.md` §9d says this chart "shows P (plaintext) and C (ciphertext) column labels." It does not. Our image is a bare ruled grid of letters with no marginal labels. The P/C labels belong to a different document, the K3 notes shown in the NOVA programme (1 August 2013), which we do not hold. Sections 9d and 9e of that note were conflated, and master clue #12 there ("K3 chart shows P/C labels on pure transposition") should be re-scoped to the NOVA sheet.

**Sanborn's "forensic manner" remark does not apply here.** That remark (NPR, 22 November 2010) was about the K1/K2 charts published that week. The K3 chart was not public until 2013.

---

## 2. What the image shows

- A hand-written grid of capital letters, **14 columns by 24 rows** = 336 cells = the length of K3.
- The word **END** written at the top right, rotated 90 degrees.
- A **25th, near-empty ruled row** at the bottom holding an "L" (in the same hand as the chart's other L's) in cell 1 and a thin slash in cell 3. This is outside the 336-cell payload and is where the community's "arrow in the lower left-hand corner" was reported. There is no arrow on this image; the L and the slash are what is there.
- A dark bar along the bottom edge, consistent with the slide frame or the capture, not with the paper.
- **No question mark anywhere on the chart.** The copper ends K3 with a literal "?" after the Q of ANYTHINGQ. The chart carries the 336 letters and nothing after them. Sanborn has repeatedly declined to say whether that "?" closes K3 or opens K4, while confirming it is only a question mark.

---

## 3. The route the chart encodes

[DERIVED FACT] Reproducible from the kernel's K3 constants in `kryptosbot/panel_cribs.py`:

1. Write the 336-letter K3 plaintext in **8 rows of 42**.
2. Read it out **column by column, each column bottom to top, columns left to right**. Call the result the intermediate text.
3. Write the intermediate text in **24 rows of 14**. **That is the chart**, row for row: row 1 reads `ILNTAYESTATHCW`, row 24 reads `EDNRWEQWFIGEAD`.
4. Read the chart **column by column, bottom to top, columns left to right**. The result is the K3 ciphertext exactly: column 1 read upward gives `ENDYAHROHNLSRHEOCPTEOIBI`, the first 24 carved letters.

So the chart is the "second gridding": the plaintext went into one grid and was read out on a rotated route, then into this grid and read out on the same route again. This matches the community's rotational description of K3 (kryptosfan "K3 Solution #3", 2009; The Kryptos Project "K3 Method", 2013; the every-192nd-letter decrypt).

The last plaintext letter, the Q of ANYTHINGQ, lands at chart row 24, column 7. The carved "?" has no cell because it was never part of the 336.

Repro:
```bash
PYTHONPATH=src:kryptosbot python3 - <<'EOF'
import panel_cribs as pc
PT, CT = pc._K3_PT, pc._K3_CT
g = [PT[i:i+42] for i in range(0, 336, 42)]
inter = ''.join(''.join(r[c] for r in g)[::-1] for c in range(42))
chart = [inter[i:i+14] for i in range(0, 336, 14)]
assert chart[0] == "ILNTAYESTATHCW" and chart[-1] == "EDNRWEQWFIGEAD"
assert ''.join(''.join(row[c] for row in chart)[::-1] for c in range(14)) == CT
print("chart reproduces K3 CT")
EOF
```

Expected grid (24 rows of 14), for anyone checking the image cell by cell:

```
ILNTAYESTATHCW
BLHMHEHAROIEEH
ISIWNTHONRSLEO
OLTETYMFTEHMHD
ELAAEOAERIILUV
TSGCRIPEEPEKET
PDNADESTEWCRFR
CLRIUARBAELTMT
OUPIEHBLMTIIFT
EYTPNNTRRSHRGS
HEELEEFEAMDOMS
RRNBTWIEOTDLHL
SNMECIEYTTTDON
LTXLHTRGOHCYEH
NHWEADCEEAERNE
HCRNREYTAAADPM
OAMNNSAAUIBDDI
RISLELTMTNESRE
HAOSEOCAEDFOAF
ANNETFNTUDWAHP
YHSPITEATEEEDI
DSHRDEENOSIOTR
NYOANOHEIBRGGM
EDNRWEQWFIGEAD
```

The repository already carried a transcription of the chart in `scripts/k3_continuity/e_k3_jefferson_vertical_01.py` marked "verified". It agrees with the derived grid in all 336 cells. Whether that transcription was read from the pixels or built from the known method is not recorded, which is why the blind read in §7 matters.

---

## 4. What "END" and the extra row are consistent with

[INFERENCE] The ciphertext is read off this chart starting at the bottom of column 1 and finishing at the top of column 14. "END" sits at the top right, rotated so that it reads along the direction of the last column. That is where a read-out along the route finishes. The L-shaped glyph and slash in the extra bottom-left row sit where the read-out begins. Read together they look like start and finish marks for the read-out, which is ordinary bookkeeping for a route worked by hand. This is an inference from position and orientation; the marks are too small at this resolution to resolve their form.

---

## 5. The companion file "K3 code chart hand solve"

[INTERNAL RESULT] A second local image (1188 x 1534 px, ingested ten minutes after the chart on 2026-03-19) is **not** the Big Techday chart and not the NOVA sheet. It is a worked hand-solve of K3 on a modern printout: the K3 ciphertext printed in 7 columns of 48 (column 1, top to bottom, is the first 48 carved letters `ENDYAHROHN...`), over-marked with pink and cyan highlighter bands and pen strikes tracing a read-out path, circled column numbers at top and bottom, four numbered arrows, a drawn question mark above the fourth column, and the recovered plaintext hand-written at the right ("SLOWLY DESPARALY SLOWLY ... CAN YOU SEE ANYTHING Q"). The page has a horizontal fold crease. No local record names its author; the file name suggests it is the project owner's own worksheet. It is not a Sanborn artifact: it displays the recovered plaintext, which an encipherment worksheet would not need, and its handwritten plaintext carries two slips of its own (DESPARALY for DESPARATLY, and WITHIN omitted). See §7.6 for its structure.

---

## 6. Confidence and limitations

- **High:** the route derivation (§3) and the expected grid; the identification of the companion file as a modern hand-solve; the correction to the P/C-labels claim.
- **Medium:** the reading of "END" and the bottom-left marks as read-out start and finish marks; consistent with position and orientation, unresolvable in form at 656 px.
- The image is a low-resolution capture of a projected or printed slide through an unknown chain. Pixel-level steganalysis is non-probative on it. Grid straightness, ink separation and faint-content tests are limited by the ~44 px cell pitch.

---

## 7. Digital forensic pass

All items [INTERNAL RESULT]; scripts, data, 28 enhancements and 45 crops under `analysis_runs/k3_chart_forensics_20260919/` (local only), report at `REPORT.md` there.

### 7.1 The file
Baseline JPEG at standard quality 94, 4:2:0, 96 dpi, an Exif block holding only Orientation, no XMP, no thumbnail. A different pipeline from the NYT K1/K2 file. The image is effectively greyscale: 99.45 percent of pixels have equal red, green and blue. Consequence: no ink-class or colour separation is possible on this file, which is a capability limit rather than a null result. Effective resolution is about 26 px per cell. The crop is tight to the grid on all four sides, so anything in the sheet's own margins, including any P/C labels, is outside the frame. The dark bar at the bottom is two pixel rows of some object cut by the crop.

### 7.2 Grid metrology
15 vertical and 26 horizontal rules: 14 columns by 25 rows, the 25th being the near-empty extra row. Pitch 42.9 by 43.2 px, straight to under 1 px, skew 0.2 degrees. The horizontal rules are about twice as dark as the vertical rules at the same line width. Two indicators (the depth asymmetry, and the vertical rules being the less regular set) favour printed horizontally-ruled stock with vertical column divisions added by hand, but a two-weight printed form would look the same in greyscale. Medium confidence.

### 7.3 Blind transcription and route
All 336 cells were read blind at 6x to 14x on the background-flattened image before the expected grid was consulted. Blind accuracy was 320 of 336. A route battery of 96 readings (8 grid symmetries by 12 read-outs) scored against both K3 texts found exactly one family: columns read bottom to top, left to right, at Hamming distance 0 from the carved ciphertext, with nothing else close (next best 158; random baseline 323). The construction in §3 is unique among the 80 griddings tested.

The 16 blind misreads were adjudicated with a template matcher built only from the 320 doubly-attested cells. It ranks the canonical letter first at 15 of the 16 and second at the last (row 23 column 7, an H whose crossbar is drawn slanted, as the same hand does at two control cells). Confusion classes were E/B/P, D/O, H/N/W. **No chart cell diverges from the canonical K3 text.** This is the opposite of the K1/K2 chart, which carries two divergences.

The DESPARATLY misspelling is present, spread across ten cells by the route, all read and confirmed. No cell holds a question mark; the terminal Q is at row 24, column 7.

### 7.4 Marks
Five marks in total, all outside the 336 letters: "END" rotated 90 degrees above the last cell of the read-out and written in the read-out direction; the "L" and the slash in the extra row; the cut-off dark bar; one diffuse edgeless smudge at the right end of the extra row with no stroke structure. No arrows, ticks, dots, corrections, overwrites, erasures, margin numbers or P/C labels anywhere. The hand writes lower-case m, barred I, Q as a circle with a descender, G as a C with a bar, and H with a frequently slanted crossbar, consistently.

### 7.5 Faint content
A letter-sized matched filter over every blank region gives 3-sigma floors of 1.8 to 7.9 grey levels depending on region; the faintest real glyph scores 6.7. In the quietest margins the margin is about 3.7 times; in the extra row's blank cells the floor is above the faintest real glyph, so a mark that faint could hide there. Only two maxima cross their local floor and both fail the second-indicator test (the smudge, and a crop-edge vignette). Top-hat and black-hat at five kernel sizes show no erased or ghosted character. No faint content is recoverable from this image.

### 7.6 The companion worksheet
Same encoder signature as the chart file but full colour, so the two were saved by the same tool in the same session; they do not register to each other. It is a 7 by 48 column-major table of the K3 ciphertext, over-marked with a highlight scheme whose cell state is a function of (row + column) mod 4 in about 90 percent of cells, and with four circled plaintext letters at indices 0, 84, 168 and 252, which is the same four-way partition seen from the plaintext side. Two transcription slips in the handwritten plaintext (DESPARALY, and WITHIN omitted) are the solver's, not Sanborn's.

### 7.7 What is new against the prior note
P/C labels: unsupported for this image, and the crop means they cannot be refuted from it either. "END" confirmed and pinned in position and direction; no arrow. The missing question mark confirmed at pixel level, with the terminal Q located. New: the unique route, a full blind transcription with zero divergences, the grid metrology and rule-weight asymmetry, the mark inventory, and the characterisation of the companion file.

### 7.8 What the chart does and does not carry
The K3 chart is a clean intermediate worksheet of a two-stage route transposition. It contains the 336 letters, one terminus label, and two small marks where the read-out starts. It carries no error, no correction and no hidden content within the limits stated. The only open physical questions are what the extra-row marks and the cut-off dark object are, and whether the uncropped slide shows labels in the margins.
