# 20 — Cipher Catalog

A concise technical catalog of cipher families relevant to pencil-and-paper cryptography, written for agents investigating K4. Each entry provides mechanism, hand-execution procedure, diagnostic signatures, and a K4-specific plausibility rubric.

---

## How to Read This Catalog

### Rubric Scale

| Rating | Meaning |
|--------|---------|
| 1 | Very low / incompatible |
| 2 | Low / unlikely |
| 3 | Moderate / possible |
| 4 | High / likely |
| 5 | Very high / confirmed compatible |

### K4 Constraint Shorthand

| Code | Constraint | Source |
|------|-----------|--------|
| ALPHA-26 | All 26 letters present in K4 CT; eliminates 5x5 Polybius (I/J merge) | `kryptos.kernel.constants` |
| BEAN-EQ | k[27]=k[65] must hold | `docs/invariants.md` |
| BEAN-INEQ | 21 inequality constraints on keystream values | `docs/invariants.md` |
| CRIB-24 | 24 known PT positions (0-indexed: 21-33=EASTNORTHEAST, 63-73=BERLINCLOCK) | `kryptos.kernel.constants` |
| IC-LOW | IC approximately 0.0361 (below random 0.0385, not significant at n=97) | `docs/invariants.md` |
| LEN-97 | Length 97 (prime) — frustrates fixed-width grid methods | `kryptos.kernel.constants` |
| PEN-PAPER | Must be executable by hand without machine assistance | [HYPOTHESIS] |
| NON-PERIODIC | Key is provably non-periodic under additive model | `docs/elimination_tiers.md` |

### Elimination Status Legend

- **ELIMINATED** — Exhaustively tested and ruled out. Reference provided.
- **STRUCTURALLY ELIMINATED** — Mathematical proof rules out the entire family regardless of key or transposition.
- **OPEN** — Not eliminated; viable hypothesis (possibly as one layer of a multi-layer system).

---

## Diagnostic Tool: Index of Coincidence (IC)

**Inventor:** William F. Friedman, c. 1920 [PUBLIC FACT] — introduced in *The Index of Coincidence and its Applications in Cryptanalysis* (classified until 1961). The first systematic statistical tool for distinguishing cipher types.

**Formula:** IC = sum(f_i * (f_i - 1)) / (N * (N - 1)), where f_i = count of letter i in text of length N.

| Text Type | Expected IC |
|-----------|-------------|
| Random (uniform 26) | 0.0385 (1/26) |
| English | 0.0667 |
| K4 ciphertext | 0.0361 (see `docs/invariants.md`) |
| Monoalphabetic | ~0.0667 (preserves distribution) |
| Vigenere period p | ~0.0385 + 0.0282/p |

**Usage:** (1) IC near 0.0667 suggests monoalphabetic or short period. IC near 0.0385 suggests long-period polyalphabetic or layered cipher. (2) For period detection: split into p columns; columns with English-like IC confirm period. (3) Kasiski examination (repeated n-gram spacing GCDs) complements IC.

**K4 Relevance:** [INTERNAL RESULT] K4's IC of 0.0361 is NOT statistically significant for n=97 (z=-0.84, 21.5th percentile of random; E-FRAC-04, E-FRAC-13). IC alone cannot discriminate cipher type at this length.

---

## SUB-MONO: Monoalphabetic Substitution

### SUB-MONO-1: Caesar, Atbash, Keyword Mixed (antiquity onward)

**Classification:** SUB-MONO | **Era:** Antiquity onward [PUBLIC FACT]

#### Mechanism
Each PT letter maps to exactly one CT letter via fixed table. [PUBLIC FACT] Caesar (shift by k), Atbash (mirror), and keyword-mixed alphabets (e.g., KA: `KRYPTOSABCDEFGHIJLMNQUVWXZ`) are all instances.

#### Hand Execution
**Encrypt:** Look up PT letter in substitution table. **Decrypt:** Reverse lookup.
**Key:** Shift integer, or keyword string. **Pitfalls:** Deduplicate keyword; encrypt vs decrypt direction.

#### Diagnostics
IC identical to plaintext (~0.0667). Period 1. Trivially broken by frequency analysis.

#### K4 Plausibility Rubric

| Dimension | Rating | Notes |
|-----------|--------|-------|
| Pen-and-paper complexity | 5 | Trivial |
| Training required | 5 | Minimal |
| Cold War plausibility | 2 | Too weak alone; KA present on sculpture |
| Multi-stage friendliness | 5 | Natural inner layer |
| K4 constraint compatibility | 2 | IC-LOW rules out mono alone; viable as layer |

**Elimination status:** ELIMINATED as single layer (Tier 2). OPEN as inner layer (E-FRAC-53, E-FRAC-54).
**Quick K4 test:** Frequency analysis rules out any monoalphabetic alone.

---

## SUB-POLY: Polyalphabetic Substitution

### SUB-POLY-1: Tabula Recta / Trithemius (composed 1508, published 1518)

**Classification:** SUB-POLY | **Era:** 1508 onward [PUBLIC FACT]

#### Mechanism
A 26x26 grid; row i = alphabet shifted by i positions. [PUBLIC FACT] Composed by Trithemius in 1508, published posthumously as *Polygraphiae* (1518) — the first printed cryptography book. Trithemius cipher uses progressive key (shift 0,1,2,...) — equivalent to Vigenere with key ABCDEFG..., trivially breakable. The tabula recta's importance is as the foundation for ALL tableau-based ciphers. The Kryptos sculpture physically contains a KA-alphabet tabula recta.

#### Hand Execution
**Encrypt:** Row=key letter, column=PT letter; intersection=CT. **Decrypt:** Find CT in key row; column header=PT.
**Key:** Progressive (Trithemius) or keyword. **Pitfalls:** Row/column confusion; Kryptos uses KA ordering, not AZ.

#### Diagnostics
IC depends on key model. Progressive key: IC near random, period 26.

#### K4 Plausibility Rubric

| Dimension | Rating | Notes |
|-----------|--------|-------|
| Pen-and-paper complexity | 5 | Core skill |
| Training required | 4 | Minimal once understood |
| Cold War plausibility | 3 | Tableau physically present on Kryptos |
| Multi-stage friendliness | 5 | Foundation for all polyalphabetic work |
| K4 constraint compatibility | 3 | Tableau present; key generation is the unknown |

**Elimination status:** Progressive key ELIMINATED (periodic). General tableau: depends on key model.
**Quick K4 test:** Apply Trithemius key and check CRIB-24.

---

### SUB-POLY-2: Vigenere / Beaufort / Variant Beaufort (1553/1857)

**Classification:** SUB-POLY | **Era:** 1553 onward [PUBLIC FACT]

#### Mechanism
All three use a repeating keyword with the tabula recta. [PUBLIC FACT] For key k, plaintext p:
- **Vigenere:** c = (p + k) mod 26
- **Beaufort:** c = (k - p) mod 26 (self-reciprocal)
- **Variant Beaufort:** c = (p - k) mod 26

[DERIVED FACT] Bean constraint k[27]=k[65] holds for all three variants because CT[27]=CT[65] and PT[27]=PT[65].

#### Hand Execution
**Encrypt (Vig):** Write key repeated beneath PT; look up intersection in tabula recta. **Decrypt:** Find CT in key row; read column header.
**Key:** Repeating word/phrase. **Pitfalls:** Confusing Vig/Beau/VBeau sign conventions is the #1 bug source in this project (see `CLAUDE.md`).

#### Diagnostics
IC ~ 0.0385 + 0.0282/p. Kasiski detects period via repeated n-gram GCDs. Each period column is monoalphabetic.

#### K4 Plausibility Rubric

| Dimension | Rating | Notes |
|-----------|--------|-------|
| Pen-and-paper complexity | 5 | Standard tableau |
| Training required | 4 | Basic |
| Cold War plausibility | 5 | K1-K3 used Vigenere with KA |
| Multi-stage friendliness | 5 | Natural substitution layer |
| K4 constraint compatibility | 2 | Periodic key eliminated (NON-PERIODIC); running key OPEN |

**Elimination status:** ELIMINATED for all periodic keys at all periods 2-26 under any transposition (Tier 1: E-FRAC-35, E-FRAC-55). OPEN only as running key variant (SUB-POLY-RUN).
**Quick K4 test:** Periodic keys eliminated. Test running key candidates instead.

---

### SUB-POLY-3: Alberti Cipher Disk (~1466)

**Classification:** SUB-POLY | **Era:** ~1466; conceptual through 19th century [PUBLIC FACT]

#### Mechanism
Two concentric alphabet disks; rotating the inner disk changes the substitution alphabet mid-message. [PUBLIC FACT] Described in Alberti's *De componendis cifris* (~1466) — the first polyalphabetic cipher in the Western tradition. Indicator letters in CT signal rotation points.

#### Hand Execution
**Encrypt:** Set disk alignment; encipher; at chosen intervals rotate and insert indicator letter. **Decrypt:** Read indicators; reverse each alignment.
**Key:** Initial alignment + rotation schedule. **Pitfalls:** Missing indicator insertion/reading.

#### Diagnostics
IC depends on rotation frequency. Indicator letters visible as out-of-place characters at semi-regular intervals.

#### K4 Plausibility Rubric

| Dimension | Rating | Notes |
|-----------|--------|-------|
| Pen-and-paper complexity | 4 | Simple with physical disk |
| Training required | 4 | Modest |
| Cold War plausibility | 3 | Historical precursor |
| Multi-stage friendliness | 3 | Indicators complicate layering |
| K4 constraint compatibility | 2 | No obvious indicators in K4 CT |

**Elimination status:** Periodic rotation: ELIMINATED (E-FRAC-35). Aperiodic rotation: subsumes into running-key models (OPEN).
**Quick K4 test:** Search for indicator patterns; test as segmented monoalphabetic.

---

### SUB-POLY-4: Quagmire I-IV (19th century)

**Classification:** SUB-POLY | **Era:** 19th century [PUBLIC FACT]

#### Mechanism
Four variants of keyword-alphabet polyalphabetic cipher. [PUBLIC FACT] Each uses one or two keyword-mixed alphabets with the tabula recta, differing in which alphabets (PT, CT, key) are mixed. All are periodic polyalphabetic ciphers with the complication of mixed alphabet(s).

#### Hand Execution
**Encrypt:** Build modified tabula recta from keyword-mixed alphabet(s); encipher as Vigenere using modified tableau.
**Key:** Keyword(s) for mixing + key phrase for period. **Pitfalls:** Confusing which variant uses which mixed alphabet(s).

#### Diagnostics
Same IC/Kasiski behavior as standard Vigenere. Mixed alphabets alter within-period frequency peaks but not the periodic structure.

#### K4 Plausibility Rubric

| Dimension | Rating | Notes |
|-----------|--------|-------|
| Pen-and-paper complexity | 4 | Tableau construction required |
| Training required | 3 | Must manage mixed alphabets |
| Cold War plausibility | 4 | KA alphabet present; Quagmire III/IV with KA are natural |
| Multi-stage friendliness | 4 | Good substitution layer |
| K4 constraint compatibility | 2 | Periodic key eliminated; keyed alphabets + running key tested (E-TABLEAU-21) |

**Elimination status:** ELIMINATED for periodic keys (E-FRAC-35). KA alphabets + running key + columnar: ELIMINATED (E-TABLEAU-21, E-JTS-13).
**Quick K4 test:** Only novel non-periodic key models with KA tableau remain testable.

---

## SUB-POLY-AUTO: Autokey Cipher (1553/1586)

**Classification:** SUB-POLY-AUTO | **Era:** 16th century onward [PUBLIC FACT]

#### Mechanism
A short primer key is extended by the plaintext itself (PT-autokey) or ciphertext (CT-autokey). [PUBLIC FACT] Key = primer || PT[0], PT[1], ... (PT-autokey). This produces a non-periodic key, which was the original motivation. Standard break: guess a word at position i, read the key at position (i-p), check if it forms a word ("slide" attack).

#### Hand Execution
**Encrypt (PT-autokey Vig):** Decrypt first p positions using primer; each recovered PT letter becomes key for position (i+p).
**Key:** Short primer. **Pitfalls:** PT-autokey vs CT-autokey confusion; errors propagate.

#### Diagnostics
IC near random. Non-periodic; Kasiski fails.

#### K4 Plausibility Rubric

| Dimension | Rating | Notes |
|-----------|--------|-------|
| Pen-and-paper complexity | 5 | Same as Vigenere |
| Training required | 4 | Slightly more than Vigenere |
| Cold War plausibility | 4 | Non-periodic; historically appealing |
| Multi-stage friendliness | 3 | Self-referential key complicates layering |
| K4 constraint compatibility | 1 | Cannot reach 24/24 cribs (E-FRAC-37) |

**Elimination status:** STRUCTURALLY ELIMINATED — PT-autokey max 16/24, CT-autokey max 21/24, even with arbitrary transposition (Tier 1, E-FRAC-37).
**Quick K4 test:** Already proven impossible; do not re-test.

---

## SUB-POLY-RUN: Running Key (18th century onward)

**Classification:** SUB-POLY-RUN | **Era:** 18th century onward [PUBLIC FACT]

#### Mechanism
Uses the text of an external document as the key, producing a non-periodic polyalphabetic cipher. [PUBLIC FACT] C = (P + K) mod 26, where K[i] is the i-th letter of the reference text from an agreed starting position. Strength: English-frequency key defeats IC/Kasiski. Weakness: both PT and key are natural language, enabling "probable word" attacks.

#### Hand Execution
**Encrypt:** Both parties agree on text + starting position. Write key text under PT. Encipher letter-by-letter.
**Key:** Document reference + offset. **Pitfalls:** Edition/version disagreements; handling spaces/punctuation in key text.

#### Diagnostics
IC near random. Non-periodic; Kasiski fails. Probable word attacks exploit key being English.

#### K4 Plausibility Rubric

| Dimension | Rating | Notes |
|-----------|--------|-------|
| Pen-and-paper complexity | 5 | Same as Vigenere |
| Training required | 4 | Requires agreed text source |
| Cold War plausibility | 5 | Historically common; Scheidt-era compatible |
| Multi-stage friendliness | 5 | Natural substitution layer after transposition |
| K4 constraint compatibility | 4 | Only surviving structured key model (NON-PERIODIC, BEAN-EQ satisfiable) |

**Elimination status:** ELIMINATED for 15+ known reference texts + structured transpositions (E-FRAC-49/50, E-JTS-12). ELIMINATED for unknown English + columnar (E-FRAC-51). **OPEN** for unknown source texts + bespoke transpositions. **UNDERDETERMINED** with monoalphabetic inner layer (E-FRAC-54).
**Quick K4 test:** Select candidate text; apply at every offset; check CRIB-24 after reversing candidate transpositions.

---

## SUB-POLY-PROG: Gromark / Vimark (20th century)

**Classification:** SUB-POLY-PROG | **Era:** 20th century military [PUBLIC FACT]

#### Mechanism
Key sequence generated by linear recurrence (e.g., k[i] = (k[i-1] + k[i-2]) mod 26). [PUBLIC FACT] Short memorizable primer generates long pseudo-random key. Gromark uses mod 10 on digits; Vimark uses mod 26 on letters.

#### Hand Execution
**Encrypt:** Choose primer; generate key by recurrence; encipher via Vigenere.
**Key:** Short primer (2-8 values) + recurrence rule. **Pitfalls:** Modular arithmetic errors; Gromark mod 10 vs Vimark mod 26.

#### Diagnostics
IC near random. Linear algebra attack: crib-derived key values can solve recurrence coefficients.

#### K4 Plausibility Rubric

| Dimension | Rating | Notes |
|-----------|--------|-------|
| Pen-and-paper complexity | 4 | Simple recurrence |
| Training required | 3 | Must understand recurrence |
| Cold War plausibility | 4 | Documented military usage |
| Multi-stage friendliness | 3 | Structured key generation |
| K4 constraint compatibility | 1 | Bean-eliminated (E-FRAC-38) |

**Elimination status:** ELIMINATED — Progressive, Fibonacci, quadratic keys all Bean-eliminated (E-FRAC-38). Vimark: 0 consistent primers via linear algebra (E-JTS-08/11). Tier 1.
**Quick K4 test:** Already proven impossible; do not re-test.

---

## SUB-DIGRAPH: Digraphic Substitution

### SUB-DIGRAPH-1: Porta Cipher (1563)

**Classification:** SUB-DIGRAPH | **Era:** 1563 onward [PUBLIC FACT]

#### Mechanism
Uses 13 self-reciprocal alphabets (not 26). [PUBLIC FACT] Key letter selects alphabet (A/B=alphabet 1, C/D=alphabet 2, etc.). Letters A-M swap with N-Z within each alphabet. Described in della Porta's *De Furtivis Literarum Notis* (1563). Self-reciprocal: encrypting twice returns plaintext.

#### Hand Execution
**Encrypt:** Key letter determines alphabet; look up PT in that alphabet. **Decrypt:** Identical (self-reciprocal).
**Key:** Repeating keyword. **Pitfalls:** Only 13 alphabets; key letters grouped in pairs.

#### Diagnostics
Same Kasiski/IC behavior as Vigenere (periodic).

#### K4 Plausibility Rubric

| Dimension | Rating | Notes |
|-----------|--------|-------|
| Pen-and-paper complexity | 4 | 13 alphabets |
| Training required | 3 | Must learn system |
| Cold War plausibility | 2 | Archaic for 1989 |
| Multi-stage friendliness | 3 | Viable layer |
| K4 constraint compatibility | 2 | Periodic key eliminated; 13-alphabet limitation |

**Elimination status:** Periodic Porta subsumed by E-FRAC-35. Not independently tested with non-periodic key.
**Quick K4 test:** Only novel with non-periodic key source.

---

### SUB-DIGRAPH-2: Playfair (1854, Wheatstone)

**Classification:** SUB-DIGRAPH | **Era:** 1854-WWII [PUBLIC FACT]

#### Mechanism
PT split into digraphs; each pair enciphered via 5x5 grid rules (same row: shift right; same column: shift down; rectangle: swap columns). [PUBLIC FACT] 25-letter grid requires I/J merge. Used by British in Boer War and WWI.

#### Hand Execution
**Encrypt:** Build 5x5 grid from keyword; split PT into digraphs (pad doubles with X); apply three rules.
**Key:** Keyword for 5x5 grid. **Pitfalls:** I/J merge; double-letter handling; rectangle direction.

#### Diagnostics
IC near English. No letter encrypts to itself within a digraph. Reversed digraphs produce reversed CT digraphs.

#### K4 Plausibility Rubric

| Dimension | Rating | Notes |
|-----------|--------|-------|
| Pen-and-paper complexity | 4 | Three rules |
| Training required | 3 | Moderate drill |
| Cold War plausibility | 4 | Widely known through WWII |
| Multi-stage friendliness | 3 | Digraphic structure is awkward |
| K4 constraint compatibility | 1 | ALPHA-26 eliminates standard 5x5 |

**Elimination status:** STRUCTURALLY ELIMINATED — ALPHA-26 (all 26 letters in K4 CT, but Playfair needs 25 with I/J merge). Also E-FRAC-21.
**Quick K4 test:** Already proven impossible; do not re-test.

---

## SUB-FRAC: Fractionation Ciphers

### SUB-FRAC-1: Bifid / Trifid (1901, Delastelle)

**Classification:** SUB-FRAC | **Era:** 1901 onward [PUBLIC FACT]

#### Mechanism
**Bifid:** Each letter maps to (row, col) in 5x5 Polybius square. In blocks of period p, all rows then all columns are written, then read as pairs to reconstruct letters. [PUBLIC FACT] **Trifid:** 3x3x3 cube; three coordinates per letter. Fractionation diffuses each PT letter across multiple CT letters.

#### Hand Execution
**Encrypt (Bifid):** Grid from keyword; convert PT to coordinates; interleave in blocks; read pairs.
**Key:** Keyword for grid + period p. **Pitfalls:** I/J merge; block boundary handling.

#### Diagnostics
IC flattened (near random). Block period detectable via column IC.

#### K4 Plausibility Rubric

| Dimension | Rating | Notes |
|-----------|--------|-------|
| Pen-and-paper complexity | 3 | Coordinate tracking |
| Training required | 3 | Polybius + interleaving |
| Cold War plausibility | 3 | Known to cryptographers |
| Multi-stage friendliness | 2 | Already multi-step internally |
| K4 constraint compatibility | 1 | ALPHA-26 eliminates 5x5 Bifid; Trifid parity fails |

**Elimination status:** STRUCTURALLY ELIMINATED — Bifid: ALPHA-26. Trifid: parity impossibility. E-FRAC-21 proofs hold with/without transposition. Tier 1.
**Quick K4 test:** Already proven impossible; do not re-test.

---

### SUB-FRAC-2: ADFGVX / ADFGX (1918, Nebel)

**Classification:** SUB-FRAC | **Era:** WWI German Army [PUBLIC FACT]

#### Mechanism
ADFGX: 5x5 Polybius with coordinates labeled A,D,F,G,X (distinct in Morse). [PUBLIC FACT] Each letter becomes a two-letter pair, doubling message length. Pairs then undergo columnar transposition. ADFGVX extends to 6x6 (includes digits). Canonical fractionation+transposition system. Broken by Painvin in 1918.

#### Hand Execution
**Encrypt:** Grid -> coordinate pairs -> columnar transposition by keyword. **Decrypt:** Reverse.
**Key:** Grid keyword + transposition keyword. **Pitfalls:** Column-length calculation; confusing the two keywords.

#### Diagnostics
IC very flat. Output is always even length.

#### K4 Plausibility Rubric

| Dimension | Rating | Notes |
|-----------|--------|-------|
| Pen-and-paper complexity | 3 | Two-step process |
| Training required | 3 | Both components |
| Cold War plausibility | 3 | Well-known historically |
| Multi-stage friendliness | 2 | Already multi-stage internally |
| K4 constraint compatibility | 1 | Output always even; K4=97 (odd) = impossible |

**Elimination status:** STRUCTURALLY ELIMINATED — Output length 2N (even), K4=97 (odd). Parity proof holds unconditionally. E-FRAC-21. Tier 1.
**Quick K4 test:** Already proven impossible; do not re-test.

---

## TRANS-COL: Columnar Transposition

### TRANS-COL-1: Simple / Double / Myszkowski (19th century)

**Classification:** TRANS-COL | **Era:** 19th century onward; heavy WWI/WWII use [PUBLIC FACT]

#### Mechanism
**Simple:** Write PT into rows under keyword; read columns in keyword-alphabetical order. [PUBLIC FACT] **Double:** Apply twice with two keywords. **Myszkowski:** Duplicate keyword letters read left-to-right simultaneously across their columns.

#### Hand Execution
**Encrypt:** Keyword across top; PT in rows; number columns by keyword order; read columns top-to-bottom in order.
**Decrypt:** Compute column lengths; fill columns in keyword order; read rows.
**Key:** Keyword (= grid width). **Pitfalls:** Column-length for incomplete final rows; Myszkowski tie-breaking.

#### Diagnostics
IC same as plaintext (transposition preserves frequencies). Anagramming attack: guess width, look for English bigrams between adjacent columns.

#### K4 Plausibility Rubric

| Dimension | Rating | Notes |
|-----------|--------|-------|
| Pen-and-paper complexity | 5 | Simple grid work |
| Training required | 5 | Minimal |
| Cold War plausibility | 5 | Standard field cipher |
| Multi-stage friendliness | 5 | Classic transposition layer |
| K4 constraint compatibility | 3 | LEN-97 limits grids; viable as layer |

**Elimination status:** All widths 5-15 + periodic sub: ELIMINATED (E-FRAC-12/29/30/55). Double columnar: ELIMINATED (E-FRAC-46). Myszkowski 5-13: ELIMINATED (E-FRAC-47). AMSCO/Nihilist/Swapped 5-13: ELIMINATED (E-FRAC-48). + Running key from known texts: ELIMINATED (E-FRAC-49). + Unknown English running key: ELIMINATED (E-FRAC-51). **OPEN** only for unknown non-English text or bespoke orderings.
**Quick K4 test:** Subsumed by existing eliminations for standard models.

---

## TRANS-ROUTE: Route Ciphers (ancient; formalized 19th century)

**Classification:** TRANS-ROUTE | **Era:** Ancient; American Civil War onward [PUBLIC FACT]

#### Mechanism
Write PT into rectangular grid; read out following a route (spiral, serpentine, diagonal, custom). [PUBLIC FACT] Union Army used route ciphers extensively with codebook-defined paths.

#### Hand Execution
**Encrypt:** Choose grid dimensions; write PT in rows; read following route. **Decrypt:** Fill grid following route; read rows.
**Key:** Grid dimensions + route description. **Pitfalls:** Starting position; direction ambiguity; grid fill when text doesn't fit.

#### Diagnostics
IC same as plaintext. Short-range contacts disrupted; English bigrams appear between grid-adjacent cells.

#### K4 Plausibility Rubric

| Dimension | Rating | Notes |
|-----------|--------|-------|
| Pen-and-paper complexity | 5 | Simple grid work |
| Training required | 4 | Must know the route |
| Cold War plausibility | 3 | More historical than Cold War |
| Multi-stage friendliness | 5 | Natural transposition layer |
| K4 constraint compatibility | 3 | LEN-97 limits rectangular grids (prime); route is unknown |

**Elimination status:** Grid reading orders + periodic sub: ELIMINATED (E-FRAC-45). OPEN as layer with running key.
**Quick K4 test:** 97 is prime (only 1x97 or 97x1 without nulls); test routes with running key candidates.

---

## TRANS-GRILLE: Cardano / Turning Grille / Fleissner (1550/1881)

**Classification:** TRANS-GRILLE | **Era:** Cardano 1550; Fleissner 1881 [PUBLIC FACT]

#### Mechanism
**Cardano grille:** Mask with holes placed over surface; message written through holes; remaining spaces filled with cover text (steganographic). [PUBLIC FACT] **Turning grille (Fleissner):** NxN grid (N even); holes at 0/90/180/270 degrees cover every cell exactly once. Write PT through holes at each rotation; read grid row-by-row.

#### Hand Execution
**Encrypt (turning):** Place grille; write through holes; rotate 90; repeat 4x; read grid row-by-row.
**Key:** Grille pattern. **Pitfalls:** Rotation direction; ensuring each cell covered exactly once; N must be even.

#### Diagnostics
IC same as plaintext. Block period N^2. LEN-97 not divisible by standard grille sizes (requires padding).

#### K4 Plausibility Rubric

| Dimension | Rating | Notes |
|-----------|--------|-------|
| Pen-and-paper complexity | 4 | Physical grille needed |
| Training required | 3 | Grille construction |
| Cold War plausibility | 3 | Historical but known to Scheidt |
| Multi-stage friendliness | 4 | Viable transposition layer |
| K4 constraint compatibility | 2 | LEN-97 requires padding or non-standard size |

**Elimination status:** E-FRAC-35 covers ALL 97! permutations + periodic key. E-FRAC-44: 4^25 options, expected FP=0. ELIMINATED with periodic key. OPEN with running key (search space ~2^50).
**Quick K4 test:** Enumerate 10x10 grille configs (padded to 100) + running key; check CRIB-24.

---

## TRANS-RAIL: Rail Fence (ancient)

**Classification:** TRANS-RAIL | **Era:** Ancient to recreational [PUBLIC FACT]

#### Mechanism
Write PT in zigzag across r rails; read each rail left-to-right. [PUBLIC FACT] Period = 2(r-1). Very small key space (r from 2 to n/2).

#### Hand Execution
**Encrypt:** Zigzag across r rows; read rows. **Decrypt:** Compute chars per rail; fill; read zigzag.
**Key:** Number of rails r. **Pitfalls:** Fence-post errors at turning points.

#### Diagnostics
IC same as plaintext. Period 2(r-1). Trivially brute-forced.

#### K4 Plausibility Rubric

| Dimension | Rating | Notes |
|-----------|--------|-------|
| Pen-and-paper complexity | 5 | Trivial |
| Training required | 5 | Minimal |
| Cold War plausibility | 2 | Too simple |
| Multi-stage friendliness | 4 | Easy to compose |
| K4 constraint compatibility | 1 | Bean-incompatible (E-FRAC-32) |

**Elimination status:** ELIMINATED — 19 rail counts, zero Bean passes. Structurally Bean-incompatible. Tier 1.
**Quick K4 test:** Already proven impossible; do not re-test.

---

## MULTI: Substitution + Transposition Compositions

**Classification:** MULTI | **Era:** 20th century military standard [PUBLIC FACT]

#### Mechanism
Apply substitution and transposition in sequence (sub-then-trans, trans-then-sub, or interleaved). [PUBLIC FACT] Defeats both frequency analysis and anagramming. Sanborn stated K4 uses "two separate systems," consistent with this class. [PUBLIC FACT — Sanborn's statement]

#### Hand Execution
**Encrypt (sub-then-trans):** Apply substitution; then transpose result. **Decrypt:** Reverse transposition; reverse substitution.
**Key:** Two independent keys. **Pitfalls:** Layer order (encrypt vs decrypt); assuming transposition operates on PT directly.

#### Diagnostics
IC reflects substitution IC (transposition preserves IC). Kasiski fails on transposed polyalphabetic text. Standard attack: guess transposition, undo it, attack substitution.

#### K4 Plausibility Rubric

| Dimension | Rating | Notes |
|-----------|--------|-------|
| Pen-and-paper complexity | 4 | Two individually simple steps |
| Training required | 3 | Both methods |
| Cold War plausibility | 5 | Standard military crypto; Sanborn's "two systems" |
| Multi-stage friendliness | 5 | This IS multi-stage |
| K4 constraint compatibility | 4 | Primary surviving hypothesis class |

**Elimination status:** 250+ experiments, 669B+ configs. All MULTI with periodic sub: ELIMINATED (E-FRAC-35 + exhaustive structured transposition). Running key + known texts + structured trans: ELIMINATED (E-FRAC-49/50). Three-layer Sub+Trans+Sub: ELIMINATED for tested ranges (E-FRAC-52). **OPEN** for: (a) running key from unknown text + bespoke transposition, (b) mono+trans+running key (underdetermined, E-FRAC-54).
**Quick K4 test:** Select transposition + key source; undo transposition; check CRIB-24 and BEAN-EQ.

---

## Reference Text as Key Source: The Dictionnaire Egyptien Concept

**Classification:** Methodology (not a cipher) | **Era:** Conceptual [PUBLIC FACT]

#### Concept

Using a published reference text as key material has deep historical roots. [PUBLIC FACT] Champollion's *Dictionnaire Egyptien en Ecriture Hieroglyphique* (1841) exemplifies a systematic mapping between symbol systems. In running-key cryptography, the insight is: any publicly available text of sufficient length serves as a non-periodic key.

#### How Reference Texts Serve as Keys

(1) Both parties agree on a specific edition of a text. (2) They agree on a starting offset. (3) Letters extracted sequentially (skipping punctuation/spaces). (4) Applied as Vigenere/Beaufort/VBeau key.

#### K4 Key Source Criteria

[HYPOTHESIS] If K4 uses a running key, the source text likely: is publicly available pre-1990; is known to Sanborn/Scheidt or referenced in sculpture themes; has 97+ letters from start point; is identifiable from contextual clues. Sanborn stated "kryptos is available to all" [PUBLIC FACT]. The 2025 clues reference his 1986 Egypt trip and 1989 Berlin Wall fall — both connecting to published texts (Carter's tomb account tested and eliminated; Berlin-related texts remain open). The Weltzeituhr identification for BERLINCLOCK may point to German-language sources.

**Elimination status:** 15+ specific texts eliminated (E-FRAC-49/50, E-JTS-12). Unknown source texts: OPEN.

---

## Cross-Reference: Eliminated vs Open

| Family | Single-Layer | As Multi-Layer Component |
|--------|-------------|------------------------|
| SUB-MONO | ELIMINATED | OPEN as inner layer (E-FRAC-54) |
| SUB-POLY (periodic) | ELIMINATED | ELIMINATED at all periods + any transposition (E-FRAC-35) |
| SUB-POLY-AUTO | ELIMINATED | STRUCTURALLY ELIMINATED (E-FRAC-37) |
| SUB-POLY-RUN | ELIMINATED (known texts) | **OPEN** for unknown texts + bespoke transposition |
| SUB-POLY-PROG | ELIMINATED | ELIMINATED via Bean (E-FRAC-38) |
| SUB-DIGRAPH | ELIMINATED | STRUCTURALLY ELIMINATED (ALPHA-26/parity) |
| SUB-FRAC | ELIMINATED | STRUCTURALLY ELIMINATED (E-FRAC-21) |
| TRANS-COL | ELIM w/ periodic sub | OPEN as layer with running key |
| TRANS-ROUTE | ELIM w/ periodic sub | OPEN as layer with running key |
| TRANS-GRILLE | ELIM w/ periodic sub | OPEN as layer with running key |
| TRANS-RAIL | ELIMINATED | ELIMINATED (Bean-incompatible) |
| MULTI (sub+trans) | N/A | **PRIMARY OPEN HYPOTHESIS** |

---

## Summary: What Remains

[DERIVED FACT] After 250+ experiments and 669B+ configurations:

1. **Running key from unknown text + transposition** — only surviving structured substitution model. All standard transposition families tested; bespoke transposition is the gap.
2. **Mono + transposition + running key** — underdetermined (E-FRAC-54); cannot be confirmed or eliminated by scoring.
3. **Bespoke physical/procedural method** — consistent with Sanborn's "not a math solution" and the $962,500 coding charts. Untestable without external information.

For full elimination details: `docs/elimination_tiers.md` and `reports/final_synthesis.md`.

---

*Cipher Catalog v1.0 — 2026-02-27*
*Part of the Crypto Field Manual series (`docs/crypto_field_manual/`)*
*References: `docs/elimination_tiers.md`, `docs/invariants.md`, `kryptos.kernel.constants`*
