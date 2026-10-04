# E-PADGRILLE-01: pad-letter removal from the full cipher panel + overlay as a key generator: pre-registration

**Status:** COMPLETE (clean negative, 2026-10-04). Frozen at 50ac7e7c before the real-K4 statistic was computed. Calibration (matched null, power) used only
null worlds and planted synthetic K4s.
**Runner:** `scripts/grille/e_padgrille_01_pad_removal_overlay.py`
**Universe hash:** `e00d78252176586cf4f7166f3225f8610811cc4640dc9df078268c48bf309c2b` (PREREG dict + the 104 layout names)
**Promotion means "hand to red-team", never "solved".**

## 1. Hypothesis

[HYPOTHESIS] (Colin, 2026-10-04.) K1-K3 contain padding that is not needed: the X separators in K2,
the X and the final Q in K3, and the carved `?` marks, one of which looks squeezed. Perhaps these "buffer"
letters are stego holes. Remove them (or remove every Q, or every X) from the whole K1-K4 cipher panel,
lay the reflowed panel over the tableau (or over another part of the sculpture), and read K4's
running key or repeating keyword through the overlay.

## 2. Delta vs prior work (re-verified, not trusted)

No script in `scripts/`, `docs/` or `memory/` deletes buffer letters from the full panel and re-overlays it
(grep for Q/X removal and pad-letter wording; `run_attack.py --list` over grille/tableau/overlay).
The nearest prior scripts were read, not trusted:

| prior script | what it actually did | defect / scope gap |
|---|---|---|
| `scripts/tableau/e_tableau_overlay.py` (deprecated) | unshifted panel-on-tableau overlay | embedded K3 CT is fabricated after ~120 letters (`...FOLDESLHAHAHRTEW...`); did not test the real panel |
| `scripts/grille/grille_cipher_eq_tableau.py` (deprecated) | cipher==tableau cells as K4 NULLS, no shift | hybrid reflow with the UNDERGRUUND correction applied and the third `?` missing; matches used as nulls, not as a key |
| `scripts/overlay/copper_paper_overlay.py` (deprecated) | K4 vs the horizontally flipped tableau, no shift | one point of this universe (`FOOT|*|none|keep|TAB_FOLD`) |
| `scripts/archive/c7_rejected/e_antipodes_04_sculpture_running_key.py` | "tableau" running key at all offsets | used a bare 26x26 KA square (no labels, header, footer, extra L), AZ cells only: a different object |
| `scripts/campaigns/tableau_running_key.py` (deprecated) | tableau / K1-K3 as running key at offsets | integrity guard flags its embedded K2/K3 literals as divergent |
| `scripts/grille/e_w_removal_hypothesis_01.py` | delete K4's W's, then periodic keys | K4-internal only; no overlay |

Prior-art hook (`.claude/hooks/prior_art_check.py`) output on creating the runner, recorded per process:
tokens `padgrille, removal, overlay`; hits = `e_antipodes_12_combined_leads` (Antipodes keyword letter
removal/insertion), `e_w_removal_hypothesis_01` (W-removal in K4), `copper_paper_overlay` (unshifted
flipped overlay), elimination_tiers wording, reference files. Justification: none deletes buffer letters
from the full panel and re-overlays; the two unshifted overlays appear here only as re-covered points.

## 3. Exact universe

### 3.1 Fixed inputs (each verified by the runner's selftest before any scoring)

- K1-K3 CT/PT: `kryptosbot/panel_cribs.py`. K1 keystream under KA-vig = PALIMPSEST repeated; K2 = ABSCISSA
  repeated; K3 PT[i] = CT[(191 + 192 i) mod 337]. K4 = `kryptos.kernel.constants.CT`; cribs = `CRIB_DICT`
  (24 positions, 21-33 and 63-73, direct positional).
- Panel stream: 865 letters + 4 `?` = 869 tokens. `?` precede K2 letters 37, 162, 223 (anchors `GGWHKK?`,
  `HHDDDUVH?`, `FLGGTEZ?`) and follow K3 (`VDOHW?`): stream indices 100, 226, 288, 771.
- Tableau: 28 rows; header/footer = blank + `ABCDEFGHIJKLMNOPQRSTUVWXYZABCD`; rows A-Z = label + 30 letters
  of KA shifted by the row; extra L at the end of row N (32 cells).
- PTPAD = CT cells that encrypt a plaintext pad: the 6 K2 X separators (Vigenere is positional, so PT and
  CT share the index) + K3's X (MISTX) and final Q (ANYTHINGQ), located through the K3 transposition
  (which keeps letters, so they are the only X and Q in K3 CT).

### 3.2 Grid models for the cipher panel (7)

| grid | cells |
|---|---|
| NYT31-Q4 | strict 31-cell rows, continuous reflow (the NYT K1/K2 chart grid), all 4 `?` take a cell (869 -> last token row 28 col 0) |
| NYT31-Q0 | same, no `?` takes a cell (865) |
| NYT31-SQ1..SQ4 | same, exactly one `?` squeezed (no cell) -> 868 = 28 x 31 |
| COPPER | the 28 carved lines (32/31/31/30/31/32/31/31/...); a deletion shifts the rest of ITS line left; other lines fixed |

### 3.3 Deletions (8 letter sets x 2 `?` modes, deduped to 104 distinct layouts)

Letter sets: `none`, `Q_pre` (Q in K1-K3: 30), `Q_all` (+ K4's 4 Q's), `X_pre` (10), `X_all` (+ K4's X at 6, 79),
`QX_pre`, `QX_all`, `PTPAD` (8). `?` mode: `keep` or `drop` (delete every `?` that has a cell).

[DERIVED FACT] K4's own Q's cannot be pads under the public clue: Sanborn's 2010 clue maps `FLRVQQPRNGKSS`
to `EASTNORTHEAST` letter for letter, so CT[25] = CT[26] = Q encrypt N and O. `Q_all`/`QX_all` are run for
completeness; their ceiling is 22/24.

### 3.4 Overlay targets (4) and hole rules (4 + sweep)

Targets: `TAB` (same row/col), `TAB_FOLD` (col c over tableau col 30-c: the left panel folded onto the right),
`TAB_LFLOW` (tableau stream incl. the extra L reflowed at 31, so rows after N shift by one), `PANEL`
(the unmodified panel under the same grid model).

| rule | key |
|---|---|
| FOOT | running key: target letter under each K4 letter's NEW cell (deleted K4 letters get no key) |
| REMOVED | holes = ORIGINAL cells of deleted letters, reading order; key seq = target letters seen through them |
| SLID | holes = ORIGINAL cells of deleted letters; key seq = panel letters that slid into them after reflow |
| MATCH | holes = K1-K3 cells whose shifted panel letter equals the target letter; key seq = those letters |
| SWEEP | every offset (with wrap) of 4 streams as a running key: TAB (869, blanks = no key), TAB letters (867), PANEL (869, `?` = no key), PANEL letters (865). Covers ANY uniform shift, i.e. any deletion set that leaves K4 intact |

REMOVED/SLID/MATCH sequences are periodic keys at every phase, indexed ADV (every K4 position advances the
key) and, where the layout deletes K4 letters, SKIP (deleted K4 letters do not advance it: the NYT chart's
`?` convention).

### 3.5 Tableau cells (7, identical to E-W31RK-01)

AZ-vig, AZ-beau, AZ-varb, KA-vig (K1/K2), KA-beau, KA-varb, sculpture (A-Z header/labels, KRYPTOS body).

### 3.6 Count

273,196 scored configs per null world (the count is world-dependent through MATCH sequence lengths; the
real count is reported with the result).

## 4. Statistic

Crib matches S (0-24) per config: key letter == the key letter forced by (CT[i], crib[i]) in that cell.
Family statistic = max S over all configs (also reported per rule family).

## 5. Calibration (pre-run; the real K4 statistic was not computed)

Run `calibrate_2026_10_04` (28 workers, before the 22-worker operator cap; 1000 null worlds in 24.8 s,
500 plants in 25.4 s). Artifact: `results/e_padgrille_01/calibrate_2026_10_04/calibration.json`.

Null family max (ALL), 1000 worlds: 6: 219, 7: 665, 8: 107, 9: 8, 10: 1.

| family | null max distribution |
|---|---|
| FOOT | 3: 6, 4: 469, 5: 447, 6: 70, 7: 8 |
| REMOVED | 6: 492, 7: 448, 8: 54, 9: 5, 10: 1 |
| SLID | 5: 228, 6: 609, 7: 149, 8: 13, 9: 1 |
| MATCH | 5: 7, 6: 641, 7: 319, 8: 32, 9: 1 |
| SWEEP | 5: 125, 6: 699, 7: 165, 8: 10, 9: 1 |

Power (exact-model detection: planted config scores 24/24 AND is the family max): **500/500 = 1.00**
(FOOT 84/84, REMOVED 108/108, MATCH 146/146, SLID 64/64, SWEEP 98/98; 0 unstable plants). Plants use
K4-independent deletions only (`none`, `Q_pre`, `X_pre`, `QX_pre`, `PTPAD`) and are redrawn if the key reads
K4's own letters.

## 6. Matched null

Each null world replaces: the tableau body alphabet with a random permutation (labels, header, footer and the
extra L kept); the PANEL target copy with a letter shuffle (`?` fixed); the K1-K3 letters of the laid-over
panel with a shuffle that keeps every Q, X and `?` in place. K4 CT, cribs and every deletion position are
unchanged, so the null replicates the whole search (all 7 grids, 104 layouts, 4 targets, 5 rule families,
all phases/offsets, 7 cells). Seeds 0-999.

## 7. Pre-registered decision rule

- **PROMOTED** (red-team): any config with S >= 18.
- **NOMINATED** (look closer, not evidence of a solve): family-wise p = (1 + #null worlds with ALL max >= observed) / 1001
  <= 0.01, i.e. observed ALL max >= 9 (p(9) = 10/1001 = 0.0100; p(10) = 2/1001).
- Otherwise CLEAN NEGATIVE for this universe.
- A solve claim additionally needs S = 24 and readable non-crib plaintext, and goes through the repo's gates.

## 8. Stop rule

One real run. No re-runs with altered grids, sets, targets or rules under this id; any change is E-PADGRILLE-02
with its own pre-registration.

## 9. What a negative would and would not mean

Would close (direct positional cribs, additive key, the 7 cells): deleting Q, X, Q+X, plaintext pads and/or `?`
from the full panel in the NYT 31-grid or the copper lines, overlaid on the tableau (straight, folded,
L-reflowed) or on the panel itself, with the key read as K4's footprint, through the deleted cells, from the
letters that slid into them, or from letter matches; plus every uniform offset of the tableau and panel
streams as a running key.

Would NOT close: other hole rules or reading orders (columns, boustrophedon, spirals, diagonals); the
sectioned NYT layout (K1 overflow letter, K2 starting a new row, displaced letters boxed in the margin);
Antipodes' layout; overlays offset by anything other than the deletions; vertical flips or the cylinder;
deleting other letters (W, misspellings, IQLUSION's Q); non-additive keys; a keyword used as a keyed alphabet
rather than a key; any null-bearing or transposed K4 (non-direct crib alignment).

## 10. Known weaknesses

- COPPER line breaks in the K3 region come from a transcription (letters verified, breaks not photo-checked).
- NYT31 extends the K1/K2 chart's 31-cell rule to K3/K4, an assumption.
- FOOT and SWEEP overlap (FOOT with no K4 deletion is a SWEEP offset); harmless double counting.
- p resolution is 0.001 (1000 worlds).
- The runner carries an inert `user_hole_rule()` extension point (returns None, adds no configs). Implementing
  it is a new campaign (E-PADGRILLE-02).

## 11. Cost and parallelism

Stdlib pure Python, CPU-bound; ProcessPoolExecutor over null/power worlds. Benchmark (56 worlds): 14 workers
23.7 worlds/s, 20: 24.4, 28: 31.3; pinning 14 workers 21.7 (no gain, so unpinned). Operator cap from
2026-10-04: 22 workers max (enforced in the runner). The real run is one world (< 1 s).

## 12. Controls (filled before the real-K4 run)

Selftest (18 checks) PASS: cipher round trips; K1/K2 keystreams; K3 permutation; panel letters and `?`
positions; copper rows; tableau rows; PTPAD; K4 Q at crib positions; layout spot checks; 5 planted controls
(MATCH, MATCH, SLID, FOOT, REMOVED) each found at 24/24.

## 13. Result (2026-10-04)

Run `full_prereg_2026_10_04` at frozen commit 50ac7e7c (universe e00d7825...; artifact
`results/e_padgrille_01/full_prereg_2026_10_04/real.json`). Selftest 18/18 PASS before scoring.
Repro: `PYTHONPATH=src python3 -u scripts/grille/e_padgrille_01_pad_removal_overlay.py --mode real --workers 22 --run-id <id>`.

[INTERNAL RESULT] **CLEAN NEGATIVE. 0 promoted, 0 nominated.**

| family | K4 max | family-wise p vs matched null |
|---|---|---|
| ALL | 7/24 | 782/1001 = 0.78 |
| FOOT | 4 | 0.99 |
| REMOVED | 6 | 1.00 |
| SLID | 6 | 0.77 |
| MATCH | 7 | 0.35 |
| SWEEP | 6 | 0.87 |

416,087 configs scored; histogram 0: 181,279, 1: 148,615, 2: 63,826, 3: 17,917, 4: 3,766, 5: 597, 6: 84, 7: 3
(mean 0.92 = 24/26, the random-key expectation). The three 7s are one config under X-deletion aliases
(`MATCH|COPPER|X_pre/X_all|drop|TAB_FOLD|*|25-26|KA-beau`); plaintext is gibberish
(`KVRPNCJFTFLZVBLWWBEOHZBS...`). Exact-model power 1.00 (500/500 planted).

**Deviation disclosed.** The real run scored 416,087 configs vs 273,196 per null world: on the real panel,
`MATCH` against the unshifted `PANEL` target matches every cell (panel over itself), producing K1-K3 CT as a
768-letter periodic key; the shuffled null target cannot reproduce that identity. This gives the REAL run
more chances, biasing its max upward, so it cannot manufacture a negative; it would matter only for a
borderline positive.

What this closes and does not close: section 9.
