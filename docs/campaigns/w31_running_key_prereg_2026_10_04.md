# E-W31RK-01: an English running key with a width-31 grid turn: pre-registration

**Campaign id:** `E-W31RK-01`
**Status:** COMPLETE (2026-10-04, §13): 0 promoted, 0 nominated. Frozen before the real-K4 run at commit `37f20408`,
approved by Colin ("approved, freeze it and run it").
**Date authored:** 2026-10-04
**Authorized by:** Colin, 2026-10-04 ("run the width 31 check", then "draft the running key prereg").
**Calibration code (local, private):** `analysis_runs/k4_width31_turn_ceiling_20261004/w31rk_calibration.py`,
`w31rk_calibration_tier2.py`, building on `w31_ceiling.py` in the same directory.
**Campaign code:** `scripts/transposition/e_w31rk_01_running_key_turn.py` (frozen constants in its `PREREG` block).
**Tests:** `tests/test_w31rk_running_key_turn.py` (9 passed, 2026-10-04). Self-test (`--self-test`): PASS.
**Universe hash:** `f8134f51edf93be731d033aa2a7f7cbf10ff9471610c1844255e8acd97ba56cc` (`--plan`; it covers the PREREG block and every configuration id with its permutation).

---

## 1. Hypothesis

[HYPOTHESIS] H-W31RK. K4 was enciphered with two layers taken from Sanborn's own demonstrated working methods:

1. a **running key**: a stretch of ordinary English text used letter by letter as the key, with no repetition; and
2. a **grid turn** at width 31: write the letters into rows of 31 and copy them off by columns.

The layers can come in either order:

- **Order A (Tier 1):** `PT -> running key, indexed by plaintext position -> X -> width-31 turn -> CT`.
- **Order B (Tier 2a):** `PT -> width-31 turn -> Y -> running key, indexed by ciphertext position -> CT`.

Why these two layers, in this geometry:

- [DERIVED FACT] The K1/K2 encoding chart uses rows of exactly 31 cells, the pad width
  (`docs/nyt_k1k2_chart_physical_layout_2026_09_19.md` §2, §9.2).
- [DERIVED FACT] K3 is reproduced exactly by "fill rows left to right, read columns bottom to top" at width 42 and
  then width 14. This campaign's turn code passes that check (§12).
- [INTERNAL RESULT 2026-10-04] A **periodic** key cannot satisfy even 23 of the 24 cribs over any width-31 turn
  below key period 25. Over any turn at widths 2-96 it cannot satisfy all 24 below period 22. The two near-fits
  (23 of 24 at width 37, period 20; 24 of 24 at width 60, period 22) decrypt to gibberish.
  (`analysis_runs/k4_width31_turn_ceiling_20261004/RESULTS.md`)
- [POLICY] Colin's working position (2026-10-04) is that K4 has more than one layer and that plaintext letter i is
  not carved letter i. A running key is the main key family the periodic results leave open.
- [DERIVED FACT] A rearrangement alone cannot be the whole method. The carved text has 2 E's and the cribs need 3,
  so a substitution layer exists.

## 2. Delta vs prior work

Per Colin (2026-10-04), closures by earlier LLM sessions are treated as unverified claims. This campaign does not
depend on any of them. They are listed only to show what is new.

- **E-KEYSTREAM-ENGLISH-01** (`scripts/statistical/e_keystream_english_likelihood_01.py`): the same idea of scoring
  forced key letters as English, on the identity and columnar widths 6, 8 and 9, in AZ Beaufort only.
- **Running-key bijection Phase 2** (exhaustion log): transposition widths 1-10, keyword-mixed tableau modes.
- **Carter and other named-source tape campaigns**: these test specific texts. This campaign needs no source text,
  because it asks only whether the forced key letters look like English.
- **E-FRAC-49 / E-FRAC-50** (running key with structured transpositions): log status active, scope not verified here.
- **E-KTR-01** and the 2026-10-04 ceiling re-check: periodic keys only.

New here:

- width 31 and its 16 distinct turn orderings;
- seven tableau conventions, including the K1/K2 KRYPTOS tableau and the tableau as carved on the sculpture;
- both layer orders;
- a statistic calibrated for power and family-wise false alarms before the real run.

## 3. Exact universe

### 3.1 Orderings

97 letters in rows of 31 gives 4 rows (31, 31, 31, 4). Each ordering is defined by:

- the fill: row by row from any of the 4 corners;
- the read: column by column from any of the 4 corners;
- where the blanks fall: at the end (natural writing) or at the start, as on the copper, where OBKR sits at the right
  end of line 25;
- the permutation or its inverse.

That gives 64 labels, which collapse to **16 distinct permutations** after removing identical ones. Every label is
kept in the output, mapped to its distinct permutation.

Tier 2b repeats the construction at every width from 2 to 96, which gives **1,492 distinct permutations**.

### 3.2 Tableau cells (7)

The key letter at a crib is forced by the ciphertext letter c and the plaintext letter p:

| cell | key index | key letter named in |
|---|---|---|
| AZ-vig | AZ(c) - AZ(p) | AZ |
| AZ-beau | AZ(c) + AZ(p) | AZ |
| AZ-varb | AZ(p) - AZ(c) | AZ |
| KA-vig (K1/K2 tableau) | KA(c) - KA(p) | KA |
| KA-beau | KA(c) + KA(p) | KA |
| KA-varb | KA(p) - KA(c) | KA |
| sculpture (A-Z header and labels, KRYPTOS body) | KA(c) - AZ(p) | AZ |

All arithmetic is mod 26. KA = `KRYPTOSABCDEFGHIJLMNQUVWXZ`.

### 3.3 Fixed inputs

- CT: canonical CT97 (`kryptos.kernel.constants.CT`). The `?` before OBKR is excluded; it is K3's.
- Cribs: canonical `CRIB_DICT`, 0-indexed plaintext positions 21-33 (EASTNORTHEAST) and 63-73 (BERLINCLOCK).
  These are plaintext positions, as in Sanborn's 2025 image. The turn decides which carved letters encode them.
- Key: English text of at least 97 letters, at an unknown offset, letters only. It is aligned to plaintext
  positions in order A and to ciphertext positions in order B.

### 3.4 Counts

| tier | layer order | widths | configurations |
|---|---|---|---|
| 1 | A | 31 | 16 x 7 = 112 |
| 2a | B | 31 | 16 x 7 = 112 |
| 2b | A | 2-96 | 1,492 x 7 = 10,444 |

## 4. Statistics

- **S_A** (orders A, Tiers 1 and 2b): in order A the forced key letters at plaintext positions 21-33 and 63-73 are
  two contiguous fragments of the key text, 13 and 11 letters long. S_A is their mean quadgram log10 over all 18
  quadgrams, using the kernel default scorer (`get_default_scorer()`, `data/english_quadgrams.json`).
- **S_B** (order B, Tier 2a): in order B the forced key letters sit every 3rd or 4th letter of the key text, so no
  contiguous fragment exists. S_B is the mean English unigram log10 of the 24 forced key letters, with the unigram
  table taken from the calibration corpus.

## 5. Calibration (pre-run; the real K4 statistic was not computed)

[INTERNAL RESULT 2026-10-04] Reproduce with `PYTHONPATH=src python3 -u analysis_runs/k4_width31_turn_ceiling_20261004/w31rk_calibration.py`,
then `w31rk_calibration_tier2.py`.

**Corpus** (letters only, uppercase; sha256 of the raw file, first 16 hex):

| file | letters | sha256[:16] |
|---|---|---|
| reference/carter_gutenberg.txt | 117,509 | 5edf7326bec21317 |
| reference/running_key_texts/kahn_codebreakers_1967.txt | 2,547,671 | 8ecbf6a0944c9d7a |
| reference/running_key_texts/nsa_act_1947.txt | 70,153 | a96466af3849d2ea |
| reference/running_key_texts/reagan_berlin.txt | 12,699 | 1c1fc07020e25dcb |
| reference/running_key_texts/cia_charter.txt | 9,235 | 17f7da62085bd13d |
| reference/running_key_texts/udhr.txt | 8,676 | 305445ac2e6bd0f9 |
| reference/running_key_texts/jfk_berlin.txt | 2,825 | 14c3336b237422cd |

**Tier 1 (order A, width 31):**

- **Genuine English key fragments** (20,000 random windows, letters 21-33 and 63-73):
  - mean S_A -4.380;
  - 5th percentile **tau = -4.924**;
  - 1st percentile -5.408.
- **Random letters, single draw:** mean -6.425; 99th percentile -5.850.
- **Matched null** (2,000 letter-preserving shuffles of CT97, maximum over all 112 configurations):
  - median -5.778, q95 -5.480, q99 -5.306;
  - **0 of 2,000** reached tau.
- **Positive control** (500 synthetic order-A messages):
  - setup: English plaintext with the two cribs spliced in at 21 and 63; an English key from a different text than
    the plaintext; a random ordering and cell;
  - result: the true configuration reached tau in **98.8%**, and it was the family maximum in **100%**.

**Tier 2a (order B, width 31, S_B):**

- Matched null q99 = **-1.272** (2,000 shuffles).
- Power at a 1% family-wise false-alarm rate: **0.687** (1,000 synthetic order-B messages).

**Tier 2b (order A, widths 2-96, S_A):**

- Matched null q99 = **-4.941** (1,000 shuffles, 10,444 configurations each).
- Power at a 1% family-wise false-alarm rate: **0.984** (1,000 synthetic messages).

## 6. Matched null

- [POLICY] Each tier uses letter-preserving shuffles of CT97 (seeded: 0-1,999 for Tiers 1 and 2a; 0-999 for
  Tier 2b). Every null sample runs the full search: same orderings, same cells, same statistic, family maximum.
  The null therefore replicates the search, not one configuration.
- [POLICY] The real-K4 run recomputes the nulls with the frozen seeds. The frozen bars in §7 stay as calibrated here.
  If the recomputed q99 differs, both values are reported, and the frozen bar governs.

## 7. Pre-registered promotion rule

- **Tier 1:**
  - A configuration is **PROMOTED** iff its S_A >= **bar_1 = max(tau, null q99) = -4.924**, and the run has no
    PREREG deviation.
  - The family-wise p is also reported: the fraction of null family maxima at or above the real K4 family maximum.
- **Tier 2a:** a configuration is **NOMINATED** iff S_B >= **-1.272**. Tier 2a cannot promote. A nomination
  needs its own pre-registration (for example, a joint decode of plaintext and key).
- **Tier 2b:** a configuration is **NOMINATED** iff S_A >= **-4.941**. Tier 2b cannot promote. Breadth is never used
  to strengthen a Tier 1 result.
- Every configuration's statistic is written out, promoted or not, together with the forced key letters.
- **PROMOTED means "hand to red-team", never "solved".**
  - A promoted configuration gets its full key-text search: candidate sources, plus a decode of the non-crib
    letters. That search runs under a new campaign id.

## 8. Stop rule

- The campaign is complete when all real-K4 configurations of all three tiers and all null samples are computed and
  written under the universe hash.
- No adaptive widening. No width, ordering family, cell, statistic or threshold is added or changed in response to a
  result. Any change needs a new campaign id.
- All randomness is seeded and recorded.

## 9. What a negative would and would not mean

- **A Tier 1 negative:**
  - The scope: under order A, with an English running key at any offset, none of the 16 width-31 turn orderings,
    under any of the 7 tableau cells, forces key fragments that look like English at the pre-registered bar.
  - The strength: calibrated power is about 0.99 per configuration.
  - That is a rejection of H-W31RK in order A, within scope.
- **Conditional on:**
  - canonical CT97;
  - the cribs at their published plaintext positions;
  - a key text whose statistics resemble the calibration corpus;
  - no null letters;
  - additive arithmetic on the AZ or KA alphabet.
- **Not covered:**
  - order B at full strength (power about 0.69);
  - keys that are not English text: numbers, ciphertext, other languages, keyword-mixed alphabets;
  - column orders set by a keyword rather than straight read-outs;
  - two or more turns;
  - widths other than 31 at Tier 1 strength (Tier 2b only);
  - null letters or a plaintext length other than 97;
  - non-additive substitutions.

## 10. Known weaknesses (to red-team before freezing)

- S_A sees only 24 key letters. A key text with unusual statistics (lists, names, numbers spelled out, archaic
  spelling) scores lower than the calibration corpus, so the true power for such a source is below 0.99.
- The calibration plaintexts have the cribs spliced in. That affects only the plaintext, not the key fragments S_A
  scores, so it should not bias tau.
- In order A with a Vigenere-type cell, plaintext and key play symmetric roles. A promoted configuration whose key
  fragments are English is therefore also consistent with the two texts swapped. Red-team must consider both.
- Tier 2a's unigram statistic is weak by design. Its role is to flag, not to decide.

## 11. Cost and parallelism

- Tier 1 and Tier 2a real runs: 112 configurations each, under a second.
- Nulls: seconds to a few minutes on 26 workers. Tier 2b's null (1,000 x 10,444) dominates.
- The campaign script exposes `--workers`, `--batch-size`, `--affinity {auto,none,pin}` and `--benchmark`, per the
  org policy. It uses process-based parallelism over seed ranges, with no threads.

## 12. Controls (filled before the real-K4 run)

- [x] The turn code reproduces K3 from its plaintext (w42 then w14): PASS (2026-10-04).
- [x] A synthetic width-31 turn with a period-8 KA key scores 24/24 at period 8 in the ceiling code: PASS.
- [x] The KA tableau convention reproduces Sanborn's worked example (B with P gives E). The same subtraction recovers
  PALIMPSEST from K1 and ABSCISSA from K2: PASS.
- [x] Tier 1 positive control: 98.8% of true configurations reach tau, and 100% are the family maximum (§5).
- [x] Campaign-script unit tests: orderings, dedupe, both layer orders, statistic, universe hash: 9 passed.
- [x] Re-run the §5 calibration with the frozen campaign script: every value reproduced exactly with the frozen seeds
  (`results/e_w31rk_01/full_prereg_2026_10_04/calibrate.json`).

## 13. Result (2026-10-04)

[INTERNAL RESULT] Run `full_prereg_2026_10_04`, universe `f8134f51...`, no PREREG deviation. Artifacts:
`results/e_w31rk_01/full_prereg_2026_10_04/{calibrate,run}.json` (local; `results/` is gitignored). Repro:
`PYTHONPATH=src python3 -u scripts/transposition/e_w31rk_01_running_key_turn.py --run --run-id <id>`.
Elapsed 12 s on 26 workers.

| tier | configurations | K4 best | bar | family-wise p | passed | verdict |
|---|---|---|---|---|---|---|
| 1 (key by PT position, width 31) | 112 | -5.823 | -4.924 | 0.624 | 0 | 0 promoted |
| 2a (key by CT position, width 31) | 112 | -1.374 | -1.272 | 0.396 | 0 | 0 nominated |
| 2b (key by PT position, widths 2-96) | 10,444 | -5.357 | -4.941 | 0.649 | 0 | 0 nominated |

- K4's best Tier 1 configuration (KA Beaufort, fill rows left to right, read columns bottom-up and right to left,
  inverse) forces the key stretches `XYANDVETKQWPQ | QRIJUSREDGT`. That is random-level: genuine English averages
  -4.38.
- Recomputed nulls matched the frozen calibration exactly (q99: -5.306, -1.272, -4.941).
- **Verdict within scope (§9):** with an English running key applied by plaintext position and any of the 16 width-31
  turn orderings under any of the 7 tableau cells, the forced key stretches are not English. Calibrated power is 0.988.
  The same holds at every width from 2 to 96 at Tier 2 strength (power 0.984). With the key applied after the turn,
  nothing was nominated, at power 0.687.
- **Still open:** the §9 "not covered" list, notably non-English keys, keyword-ordered columns, two or more turns, and
  a full-strength test of key-after-turn (a joint plaintext and key decode).
