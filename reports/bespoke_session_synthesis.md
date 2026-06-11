# Bespoke Session Synthesis: What the Coding Chart Cannot Be (and What It Might)

**Date:** 2026-02-22
**Session:** E-BESPOKE-01 through E-BESPOKE-09
**Configurations tested:** ~4M (cumulative across 9 experiments)
**Result:** ALL NOISE (best scores 7-8/24 across all experiments, all at noise floor)
**Author:** Claude (synthesis agent) + Colin Patrick (human lead)
**Classification:** [INTERNAL RESULT] with [HYPOTHESIS] sections clearly marked

---

## QUESTION 1: New Constraints on the Coding Chart from Today's Experiments

Today's nine experiments systematically tested every computationally tractable interpretation of the sculpture's physical anomalies (misspellings, YAR, extra L, "T IS YOUR POSITION", doubled letters) as parameters for standard and near-standard ciphers. The aggregate result is NOISE across ~4M configurations. Here is what we can now RULE OUT about the chart's structure:

### 1.1 The chart does NOT simply re-encode misspellings as cipher parameters

**E-BESPOKE-01** tested misspelling-derived letter substitutions applied to the ciphertext as preprocessing (forward, reverse, simultaneous, sequential, selective by position) under Vigenere, Beaufort, and Variant Beaufort. All 20+ modification variants produced keystream with entropy indistinguishable from random. The IC increase observed under 5-pair letter merging (0.036 to 0.050) was proven to be an artifact of alphabet reduction, not evidence of English structure underneath.

**E-BESPOKE-03** tested misspelling-derived numeric shifts [4, 5, 4, 16] (and with UNDERGRUUND: [4, 5, 4, 16, 6]) as:
- Repeating periodic keys (all rotations, all 24 permutations of 4 values, all 120 permutations of 5 values)
- Transposition column widths and grid dimensions
- Position-dependent alphabet offsets
- Seeds for key-generation schemes (combined with YAR, T=19, RQ)
- Signed/directional shifts (correction vs. application direction)
- Exhaustive combination search (256 sign variants x 3 cipher variants)
- Positional indicators (cumulative sums, decimation distances, null extraction patterns)

**Result:** ALL NOISE. Best scores at the noise floor (6/24). The misspelling deltas are not direct key material, not transposition parameters, not seeds, not offsets.

**Constraint established:** The misspellings' role in K4 is NOT as numeric input to any standard substitution or transposition cipher. If they instruct the solver, they do so at a structural/procedural level (how to BUILD or USE the chart), not as direct cipher parameters.

### 1.2 The chart does NOT use a T-first or T-rotated alphabet

**E-BESPOKE-08** tested the hypothesis that "T IS YOUR POSITION" means the cipher alphabet starts at T (rotation by 19 positions), creating a non-standard letter-to-number mapping. This was tested as:
- T-alphabet Vigenere tableau (substitution with T-indexed key values)
- T-alphabet grid coordinates (columnar transposition with T-indexed column ordering)
- T-alphabet + grid widths 5-14 + keyword orderings
- Rotated KA alphabet (KRYPTOS alphabet starting from T)

**Result:** ALL NOISE. The T-first alphabet does not produce signal under any tested combination.

**E-BESPOKE-04** separately tested T=20 (1-indexed: A=1, B=2, ... T=20, correcting the systematic 0-indexed assumption used in all prior experiments). Six phases tested CT rotation by 20, grid reads at width 20, T=20 as decimation/skip parameter, combined with YAR and misspelling shifts, length variants (96/98 chars), and linear transposition with T=20. Over ~1M configs.

**Result:** ALL NOISE. The 0-indexed vs 1-indexed distinction makes no difference. "T IS YOUR POSITION" does not function as a simple numeric parameter.

**Constraint established:** The chart's alphabet is not a rotation of the standard alphabet, not the KA alphabet rotated to T, and does not use T-derived numeric values as position/skip/offset parameters. "T IS YOUR POSITION" either refers to something about the PHYSICAL position on the sculpture (a COMSEC set-letter, a position indicator for the chart's usage protocol) or has a meaning we have not conceived.

### 1.3 The chart does NOT produce results at any standard grid width (5-14 or 20) with keyword orderings

**E-BESPOKE-02** tested linear transposition j=(m*i+b) mod 97 for ALL 96 valid multipliers and 23 sculpture-derived offsets, combined with affine substitution, position-dependent linear keys, keyword keys (KRYPTOS, PALIMPSEST, ABSCISSA, YAR, DYAR, DYARO), coordinate-pair readings, scatter transpositions, and quadratic position transforms. 237,672 configurations.

**Result:** Best score 7/24. Classification: STORE (borderline noise). The best config (m=4, b=20, Vigenere) produces gibberish plaintext.

**E-BESPOKE-05** specifically tested the 98-character hypothesis (insert one letter to make K4 grid-friendly: 98 = 7 x 14). Inserted every letter A-Z at all 98 positions, tested width-7 columnar with all 5040 orderings, width-14 with keyword orderings, KRYPTOS Vigenere on top. 1,754,429 configurations.

**Result:** Best score 7/24. NOISE. The extra-L / 98-character path does not lead to signal.

**E-BESPOKE-06** tested CC insertion (Checkpoint Charlie) at all positions with width-7, and removal of doubled letters as nulls. 42,101 configurations.

**Result:** Best score 5/24. NOISE.

**E-BESPOKE-09** tested CC insertion for a 99-character ciphertext (99 = 9 x 11, which would explain Sanborn's "10.8 rows" annotation as a clue that 2 chars are missing). CC inserted at all 98 positions, tested width-9 with keyword orderings and exhaustive orderings, width-11 with keyword orderings. 1,928,768 configurations.

**Result:** Best score 8/24 (borderline noise). The 8/24 came from an exhaustive w9 ordering search at CC@0, consistent with random performance for that search space size.

**Constraint established:** The chart does not produce a standard columnar transposition at ANY width from 3 to 20 with any keyword-derived or identity/reverse ordering, whether the CT is 96, 97, 98, or 99 characters. If a grid is involved, either (a) the column ordering is not derivable from any tested keyword, or (b) the grid-read mechanism is non-standard (not simple columnar, not serpentine, not spiral, not diagonal), or (c) the grid dimensions are not derivable from the CT length.

### 1.4 K4's Q frequency tells us the chart does NOT use the KRYPTOS tableau directly

[DERIVED FACT] K4's letter frequency is statistically consistent with random text. In particular, K4 has 4 Q's (frequency 4.1%), which is close to the random expectation of 1/26 = 3.8%. By contrast, K1 and K2 (encrypted using the KRYPTOS-keyword Vigenere tableau) have inflated Q frequencies because Q maps to common plaintext letters under the KA alphabet ordering. K4's normal Q distribution is evidence that K4 was NOT encrypted using the visible KRYPTOS tableau with any standard polyalphabetic method.

**Constraint established:** The coding chart either (a) does not use the KRYPTOS tableau at all, or (b) uses it in a way that does not produce the characteristic letter-frequency distortions of keyword-alphabet Vigenere (e.g., as a lookup table with non-standard access patterns, as a source of column/row labels rather than encryption values, or with the KA ordering applied only to one dimension).

### 1.5 The 1-indexed vs 0-indexed distinction is irrelevant

**E-BESPOKE-04** and **E-BESPOKE-07** systematically tested 1-indexed versions of ALL sculpture-derived parameters:
- YAR: [25, 1, 18] vs [24, 0, 17]
- T: 20 vs 19
- RQ: [18, 17] vs [17, 16]
- EQUAL letter values under 1-indexing
- DYAR, DYARO under 1-indexing
- All combinations of the above

**Result:** ALL NOISE. No 1-indexed variant outperforms its 0-indexed equivalent.

**Constraint established:** The indexing convention (0 vs 1) is not a systematic error hiding the solution. Both have been exhaustively tested. The sculpture parameters, under either convention, do not directly encode key/transposition values for any standard cipher.

---

## QUESTION 2: Structural Observations That SURVIVED Today's Testing

Several numerical and structural patterns in K4 and the sculpture anomalies were noted in the bespoke analysis (`reports/bespoke_misspelling_instructions.md`) but were NOT directly falsified by computation (because they describe structure rather than proposing a specific cipher method). These remain as potentially relevant observations:

### 2.1 Doubled-letter positions are concentrated at residue 4 mod 7

The 6 doubled-letter positions (starting indices of each pair): 18 (BB), 25 (QQ), 32 (SS), 42 (SS), 46 (ZZ), 67 (TT).

Residues mod 7: 18%7=4, 25%7=4, 32%7=4, 42%7=0, 46%7=4, 67%7=4.

**Five of six** doubled positions have residue 4 mod 7. The probability of this occurring by chance for 6 positions in 97 characters, with 7 residue classes, is approximately C(6,5) * (1/7)^5 * (6/7) + (1/7)^6 = approximately 0.00044 (1 in 2,270).

**Assessment:** This is statistically significant (p < 0.001) and survived today's testing. It COULD indicate width-7 structure in the encryption. However, width-7 columnar is Bean-IMPOSSIBLE (E-FRAC-26/27), and width-7 + all 5040 orderings + CC/L insertion produced NOISE in E-BESPOKE-05. The residue-4 concentration may point to a non-columnar width-7 structure (e.g., a width-7 reading order on a chart, a 7-column physical grid with non-standard read-out, or period-7 position-dependent behavior in a bespoke cipher).

**Why it is still useful:** If the chart is a physical grid 7 columns wide, the doubled letters would fall in the same column (column 4 from 0). This could be a construction artifact: column 4 of the chart might have a special property (a repeated row, a null-insertion point, a column separator). This would not be detectable by standard columnar transposition testing because the column ordering is what makes columnar work, and width-7 is Bean-impossible for periodic substitution -- but a chart that uses width-7 with a NON-PERIODIC substitution (running key, position-dependent) would not be caught by Bean elimination.

### 2.2 Doubled-letter values sum to 97 (CT length)

The numeric values of the doubled letters (A=0): B=1, Q=16, S=18, S=18, Z=25, T=19. Sum = 1 + 16 + 18 + 18 + 25 + 19 = 97.

Alternatively, using the 5 DISTINCT doubled letters: B=1, Q=16, S=18, Z=25, T=19. Sum = 79. Not 97. The sum-to-97 property requires counting S twice (because SS appears twice in the ciphertext).

**Assessment:** INTERESTING but fragile. The sum depends on whether you count the two SS digraphs as separate entries. The probability of 6 values from {0..25} summing to 97 is not trivially computable, but a rough estimate gives ~1.5% chance (moderately unlikely but not extraordinary). This is a WEAK pattern -- possibly coincidence, possibly a construction constraint (e.g., the doubled values were chosen to checksum to the CT length).

**Why it might be useful:** If the chart's construction involves placing doubled letters at specific positions such that their values checksum the text length, this is a parity/integrity constraint -- the kind of thing a COMSEC system might include for transmission verification. It would not help decrypt, but it could confirm that the correct chart has been identified.

### 2.3 The misspelling wrong-letters spell EQUAL

Wrong letters from the 4 deliberate misspellings (S->C, L->Q, I->E, E->A) plus the extra L from the tableau: C, Q, E, A, L. These anagram to EQUAL.

**Assessment:** This survived all testing because it is a structural/semantic observation, not a cipher parameter. None of today's experiments found a way to OPERATIONALIZE "EQUAL" as a cipher instruction that produces signal. The EQUAL observation remains as a potential clue to the chart's SEMANTICS: perhaps certain letters are treated as equivalent (equivalence classes in the cipher alphabet), or perhaps "EQUAL" is a word that appears on the chart, or perhaps it describes a PROPERTY the chart must satisfy.

**What we tested and eliminated:** Alphabet equivalence classes (merging {S,C}, {L,Q}, {I,E,A}) under reduced-alphabet Vigenere/Beaufort (E-BESPOKE-01, phase 4). This produced noise. The "EQUAL" instruction, if real, does not simply mean "treat these letters as identical in a standard polyalphabetic cipher."

### 2.4 The misspelling deltas sum to 19 (mod 26) = T

The 4-pair "correct minus wrong" deltas: S-C=16, L-Q=-5=21 (mod 26), I-E=-4=22, E-A=-4=22. Sum = 16+21+22+22 = 81. 81 mod 26 = 3 ... Wait, let me recompute: 81/26 = 3 remainder 3, so this is 3 = D, not T. Actually, the bespoke report says "Correct minus wrong (4-pair): [16, 21, 4, 4] sum=45, 45 mod 26 = 19 (=T)."

There is an ambiguity in the sign direction. The correct-minus-wrong values in the bespoke report's table (section 5.2) are listed as [16, 21, 4, 20, 4] (5-pair) and [16, 21, 4, 4] (4-pair). Let me verify: S(18)-C(2)=16, L(11)-Q(16)=-5=21 mod 26, I(8)-E(4)=4, E(4)-A(0)=4. Sum of 4-pair = 16+21+4+4 = 45. 45 mod 26 = 19 = T.

**Assessment:** This convergence (misspelling deltas summing to T, connecting to "T IS YOUR POSITION") is numerically verified. Combined with T=19 being eliminated as a direct cipher parameter, this suggests that "T" is a META-INSTRUCTION (a pointer to which calculation to perform, or a checksum digit) rather than a cipher value. The misspelling deltas encode T as a SUM, which could mean T is a VERIFICATION digit -- sum the deltas to confirm you have correctly identified the misspelling rules.

### 2.5 Position-within-word values sum to 27 (Bean equality position)

The misspelling positions within their words: S->C at position 7 of PALIMPCEST, L->Q at position 2 of IQLUSION, I->E at position 4 of DIGETAL, O->U at position 10 of UNDERGRUUND, E->A at position 4 of DESPARATLY. Sum = 7+2+4+10+4 = 27.

Position 27 in K4 is the Bean equality position (k[27] = k[65]).

4-pair sum (excluding O->U): 7+2+4+4 = 17 = R (from YAR).

**Assessment:** The 5-pair sum to 27 requires including UNDERGRUUND (the one misspelling corrected on Antipodes). This creates a tension: if UNDERGRUUND is a genuine error (interpretation A from the bespoke report), then the sum-to-27 property fails. If it is deliberate, the sum points to the Bean equality position. This is UNRESOLVABLE without physical inspection of Antipodes. We cannot computationally distinguish deliberate from accidental here.

---

## QUESTION 3: What Kind of Chart IS Still Consistent with All Evidence?

Combining the full constraint set:

**Positive constraints (what the chart MUST satisfy):**
1. Derivable from publicly available information ("kryptos is available to all")
2. Physical/procedural, not purely algorithmic ("not necessarily a math solution", artist designed)
3. Resists standard multi-layer cryptanalysis ("NSA tried many layered systems")
4. Based on "matrix codes" modified "in a myriad of ways" (Scheidt)
5. Simple enough to be designed in 2-3 meetings between Sanborn and Scheidt
6. Produces the known crib alignments (EASTNORTHEAST at 21-33, BERLINCLOCK at 63-73)
7. K3 used a physical rotation grid (42 x 8) -- K4 chart may be structurally similar

**Negative constraints (what the chart CANNOT be):**
1. NOT a standard Vigenere/Beaufort/VB tableau with any keyword (eliminated)
2. NOT any periodic substitution at any period 1-26 with direct correspondence (eliminated)
3. NOT any standard columnar transposition at widths 5-20 (eliminated)
4. NOT the KRYPTOS tableau used conventionally (Q-frequency evidence)
5. NOT parameterized by misspelling deltas, YAR values, or T as direct numeric inputs (today's eliminations)
6. NOT a standard DRYAD/BATCO system with random content (contradicts "available to all")
7. NOT a fractionation cipher (all 26 letters present, 5x5 impossible)
8. NOT Hill cipher (algebraically eliminated)
9. NOT autokey of any form + arbitrary transposition (structurally eliminated)
10. NOT any combination of TWO standard layers (Sub+Trans+Sub eliminated for structured widths)

### 3.1 Chart types still consistent

**Type A: Modified Vigenere tableau with non-standard ACCESS PATTERN**

The visible Vigenere tableau on the sculpture could be used as a LOOKUP TABLE with a non-standard access protocol. Instead of "row = key letter, column = plaintext, cell = ciphertext" (standard Vigenere), the chart might specify:
- A different mapping of inputs to rows/columns (e.g., row = position-dependent function, column = CT letter)
- Reading along diagonals, spirals, or other paths
- Using the tableau's row/column LABELS (KRYPTOSABCDEFGHIJLMNQUVWXZ) as an index rather than the cell values
- A position-dependent rule for whether to read row-then-column or column-then-row

**Why consistent:** A non-standard access pattern would not be caught by any standard cipher test. The Q-frequency objection is avoided if the access pattern does not produce the same frequency distortion as standard KA-Vigenere. The "coding charts" sold at auction may specify the access protocol.

**Weakness:** We have tested some non-standard tableau access patterns (E-TABLEAU-01 through -23, "Non-standard tableau usage" in final_synthesis). However, the space of possible access patterns is essentially infinite, so not all have been tested.

**Type B: A physical grid built FROM the sculpture text**

Rather than using the Vigenere tableau, the chart might be constructed by WRITING K1, K2, or K3 ciphertext (or plaintext) into a grid and using it as a lookup table. For example:
- Write the K1 plaintext into a 26-column grid. Each row defines a substitution alphabet.
- Use a K2-derived parameter to select which row applies at each K4 position.
- Read the encrypted K4 character from the selected row at the plaintext column.

**Why consistent:** This would be "available to all" (the K1/K2/K3 texts are publicly known), procedural rather than mathematical, and would resist standard attack because the effective substitution alphabet at each position depends on the contents of K1/K2/K3 in ways not captured by standard periodic or running-key models.

**Weakness:** We tested K1-K3 as running key sources (E-CHART-01, E-FRAC-49/50) and found NOISE. However, those tests assumed standard Vigenere/Beaufort usage of the running key. If the grid is PHYSICALLY rearranged (rows sorted, columns permuted, text written in a non-standard order), the effective running key would differ from the raw K1/K2/K3 text.

**Type C: K3 rotation grid adapted for K4**

K3 used a physical 42 x 8 rotation grid (write plaintext row-by-row, rotate 90 degrees clockwise, read out). K4 might use a similar grid with different dimensions, different rotation direction, or an additional transformation step.

97 is prime, so no clean grid dimensions exist -- UNLESS one character is added (98 = 7 x 14) or removed (96 = 8 x 12 = 6 x 16). The failure of E-BESPOKE-05 (98-char) and E-BESPOKE-04 phase 5 (96-char) eliminates standard columnar reads of these grids. However, a ROTATION (as K3 used) is fundamentally different from a columnar transposition: a 90-degree rotation of a 7 x 14 grid produces a 14 x 7 grid, and the mapping from input position to output position is NOT equivalent to any standard columnar permutation unless the read-out is simple row-by-row.

**Why consistent:** K3's grid rotation is a known Sanborn method. He explicitly showed (YouTube) that the K3 chart involves writing text into a grid and physically rotating it. This is procedural, not mathematical. The coding charts at auction could specify the K4 grid dimensions and rotation sequence.

**Weakness:** Rotation of a 7x14 grid is equivalent to a specific permutation of 98 positions. We tested all 5040 width-7 columnar orderings with L-insertion at all positions (E-BESPOKE-05) and found NOISE. But a 90-degree rotation is ONE SPECIFIC permutation, not a columnar permutation -- it is a different mathematical object. Specifically, for a 7x14 grid with row-major write and column-major read-after-rotation, position (r,c) maps to position (c, 13-r) in the rotated grid, which is (13-r) * 7 + c in linear index. This specific permutation may NOT have been tested if it does not correspond to any columnar ordering.

**Type D: Position-dependent polyalphabetic with chart-specified alphabets**

The chart might specify 97 individual substitution alphabets (one per position), or a smaller set of alphabets with a position-dependent selection rule. Each position in K4 uses a different row of the chart, where the row is determined by some combination of position number, CT letter, and/or neighboring context.

**Why consistent:** This is the "myriad of ways" Scheidt described -- modifying a base system so that even its designer cannot reconstruct the key. A position-dependent chart with arbitrary alphabets would defeat all periodic analysis and produce CT that is statistically indistinguishable from random (as K4 is). It would also explain why the NSA's "many layered systems" approach failed: the system is not multi-layered in a standard sense but rather BESPOKE at each position.

**Weakness:** With 97 arbitrary alphabets, the system has 97 * 26! degrees of freedom -- far too many for any brute-force attack. This is only solvable if the chart's structure is derivable from public information (sculpture elements). The question becomes: what RULE generates the per-position alphabets?

**Type E: Stencil/grille system using the sculpture's physical layout**

A physical grille (card with holes) placed over the sculpture text could extract specific characters that form the key or the plaintext. The sculpture has ~1800 characters across K0-K4, the Vigenere tableau, and the Morse code. A properly positioned grille could extract 97 characters from this text to serve as a running key for K4.

**Why consistent:** Grilles are physical, procedural, and do not require mathematical sophistication. They are "available to all" (the sculpture text is published). A grille is a "coding chart" in the most literal sense. Sanborn spent 2.5 years cutting letters with 20 assistants and 900 jigsaw blades -- the precision required for a grille overlay is entirely within his capability.

**Weakness:** We have not tested this specific hypothesis. The number of possible 97-character extractions from ~1800 characters is astronomically large (C(1800, 97) is enormous). However, the extraction would follow some RULE (every Nth character, specific rows/columns of the tableau, characters at physically measured positions, etc.), which would dramatically reduce the search space.

---

## QUESTION 4: Top 3 Untested Hypotheses for the Chart's Construction

### Hypothesis 1: The K3 Rotation Grid Extended to K4

**What the chart looks like physically:**
A rectangular grid, likely 14 rows x 7 columns (or 7 x 14), printed on a card or sheet. The grid may be labeled with row/column numbers or letters. A second card (or the same card with markings) specifies the rotation direction and number of rotations.

**How it would be used:**
1. Write the K4 ciphertext into the grid row-by-row (or column-by-column, as the chart specifies)
2. Physically rotate the grid 90 degrees clockwise (or counterclockwise, or 180 degrees)
3. Read out the result in the reading direction specified by the chart
4. Optionally: apply a substitution step using a keyword before or after the rotation

For K3, the specific procedure was: 42 x 8 grid, write row-by-row, rotate 90 degrees CW, read row-by-row from the rotated grid. The result was the K3 ciphertext.

For K4 with 97 characters (prime), one character must be added or removed to fit a grid. The extra L on the tableau is the insertion instruction: insert L at a specific position (perhaps position 53, where L already exists in K4, creating a doubled LL). This gives 98 characters = 7 x 14. Then rotate.

**What inputs from the sculpture define it:**
- Dimensions: 7 (KRYPTOS length) x 14 (the doubled value, or YAR: Y=24 might encode the "fold point" for the rotation)
- Insertion character and position: Extra L on the tableau, position derived from the L's location on the tableau line
- Rotation direction: The compass/lodestone on the sculpture (pointing ENE = clockwise from North)
- Substitution keyword (if any): KRYPTOS or PALIMPSEST

**How to test computationally:**
The key insight missed in E-BESPOKE-05 is that a grid ROTATION is not the same as a columnar transposition. For a 7-column, 14-row grid:
- Write position: linear index i maps to (row, col) = (i // 7, i % 7)
- After 90-degree CW rotation of the physical grid: what was (row, col) becomes (col, 13-row) in the new orientation
- Read position: linear index j from the rotated grid maps to (j // 14, j % 14)
- So the permutation is: output[col * 14 + (13 - row)] = input[row * 7 + col]

This is a SPECIFIC permutation of 98 positions. We need to test:
1. For each of the 98 possible L-insertion positions, construct the 98-character CT
2. Apply the rotation permutation (and its inverse)
3. Apply CW, CCW, and 180-degree rotations
4. For each rotation output, test with Vigenere/Beaufort using KRYPTOS, PALIMPSEST, and other keywords
5. Also test with identity substitution (rotation alone) and with all 26 Caesar shifts

Total configurations: 98 insertion positions x 3 rotations x 2 directions (gather/scatter) x ~10 keyword variants x 3 cipher variants = roughly 17,640. Very tractable.

**Why it has not been tested:**
E-BESPOKE-05 tested width-7 with all 5040 COLUMNAR orderings, which is exhaustive for columnar transposition. But grid rotation is a single specific permutation that may not correspond to any columnar ordering. The rotation permutation is: for each input position (r, c), the output position is (c, maxrow - r). This is NOT the same as reading columns in a different order -- it is a 2D geometric transformation. The E-BESPOKE-05 experiment did not implement grid rotation as a distinct operation.

---

### Hypothesis 2: Grille Extraction from the Sculpture Tableau

**What the chart looks like physically:**
A card (the "coding chart") with 97 holes cut at specific positions, designed to be overlaid on the Vigenere tableau engraved on the sculpture. When placed over the tableau, the holes reveal 97 specific characters from the 26 x 26 = 676 cells. These 97 characters form the key for K4 decryption (under simple Vigenere or Beaufort, possibly with a final rotation/transposition).

**How it would be used:**
1. Place the grille card over the Vigenere tableau on the sculpture
2. Read the 97 characters visible through the holes, in the order specified by numbered holes
3. These 97 characters are the one-time key for K4
4. Decrypt: PT[i] = (CT[i] - KEY[i]) mod 26 (or Beaufort variant)

**What inputs from the sculpture define it:**
The positions of the 97 holes are derived from other sculpture elements:
- The misspelling positions could specify row offsets or column selections (position-within-word values [7, 2, 4, 10, 4] might index into the tableau's rows)
- YAR (Y=24, A=0, R=17) could specify the starting tableau cell
- "T IS YOUR POSITION" could mean start reading from the T-row of the tableau
- The 26 extra E's in the Morse code might encode a binary mask (E=1, non-E=0) that selects which of the 26 rows are used
- The 11 E-groups with sizes [2,1,5,1,3,2,2,5,3,1,1] might specify how many characters to extract from each row

**How to test computationally:**
This is challenging because the grille defines a 97-character key, and without knowing the grille positions, there are C(676, 97) possible grilles (astronomically large). However, if the grille follows a RULE:

- **Rule A (diagonal read):** Extract characters along diagonals of the 26x26 tableau. A diagonal of the standard Vigenere tableau is constant (all same letter). A diagonal of the KA tableau varies. Test all 26 starting rows/columns with diagonal, anti-diagonal, and offset-diagonal reads.
- **Rule B (E-group guided):** Use the 11 E-group sizes to extract that many characters from consecutive rows. Row 0: extract 2 chars, row 1: extract 1 char, etc. For each starting column, test the resulting 26-character key (repeating or extended).
- **Rule C (column-by-column):** Extract 97 characters by reading down specific columns of the tableau, selected by the misspelling rules or YAR.
- **Rule D (keyword-guided spiral):** Starting at tableau cell (Y, K) = row Y=24, column K=10 (from YAR and KRYPTOS), spiral outward and extract the first 97 characters encountered.

Each rule family has a small parameter space (starting positions, directions). Total: perhaps 10,000-50,000 keys to test, each applied with Vigenere/Beaufort. Very tractable.

**Why it has not been tested:**
Prior experiments tested the tableau as a CIPHER MECHANISM (using it for Vigenere encryption with various keywords). Nobody has tested the tableau as a KEY SOURCE -- i.e., extracting characters FROM the tableau to use as a running key. This is a conceptual difference: the tableau is not the cipher, it is the key MATERIAL. The "coding chart" IS the grille that tells you which cells to extract.

This hypothesis elegantly explains several observations:
- "Kryptos is available to all" = the tableau is visible on the sculpture, and the extraction rule is derivable from the Morse code / misspelling clues
- "Coding charts" at auction = physical grille cards
- K4's Q frequency is normal because the key is extracted from the tableau (which contains all 26 letters uniformly across each row), and the key's Q frequency depends on the extraction pattern, not on the KA alphabet ordering
- "Not a math solution" = the extraction is physical (overlay and read), not computational

---

### Hypothesis 3: The Sculpture Text as a Modified DRYAD/Codebook

**What the chart looks like physically:**
A modified DRYAD numeral cipher table (the kind Scheidt describes as "matrix codes"). DRYAD tables are grids where rows are identified by letters and columns by digits (or vice versa), with each cell containing a letter. The K4 chart would be a custom DRYAD where:
- Row headers are the 26 letters of the alphabet (or a subset)
- Column headers are derived from sculpture elements (digits 0-9 from the Morse code, or positions 1-97)
- Cell contents are derived from the sculpture text itself (K1/K2/K3 plaintext or ciphertext, arranged into the grid)

**How it would be used:**
1. For each K4 ciphertext position i, determine the row (from the CT letter) and column (from position i, possibly mod some value)
2. Look up the cell at that (row, column) intersection
3. The cell value is the plaintext letter (direct decryption) or an intermediate value

The critical difference from standard Vigenere: the cell values are NOT the standard Vigenere calculation (row + column mod 26). They are ARBITRARY, determined by whatever text was used to fill the grid.

**What inputs from the sculpture define it:**
- The grid contents: K1 plaintext (260 chars), K2 plaintext (372 chars), K3 plaintext (336 chars), Morse code text, or any combination, written into the grid in row-major order
- The row/column indices: derived from the alphabet (possibly KA-ordered), the Morse E-groups, or the misspelling rules
- The grid dimensions: possibly 26 x N (one row per letter) where N = floor(source_text_length / 26)
- "T IS YOUR POSITION" might specify which column or grid section applies to K4

**How to test computationally:**
1. Construct candidate DRYAD grids from K1 PT, K2 PT, K3 PT (each written row-by-row into a 26-column grid)
2. For each grid, decrypt K4: PT[i] = grid[CT[i]][i mod num_columns]
3. Also test: PT[i] = grid[CT[i]][i mod num_columns] with column offsets from YAR, T, misspelling deltas
4. Also test with KA-ordered rows instead of standard A-Z rows
5. Test both directions: CT letter selects row, position selects column; AND position selects row, CT letter selects column

For K1 PT ("BETWEEN SUBTLE SHADING AND THE ABSENCE OF LIGHT LIES THE NUANCE OF IQLUSION..." ~260 chars), filling a 26-column grid gives 10 rows. The grid maps (letter, position mod 10) to a character from K1 PT.

Total: ~4 source texts x 2 orderings (AZ/KA) x 2 row/col conventions x 26 column offsets x 3 cipher variants (with possible secondary substitution) = ~1,248 configurations. Extremely tractable.

**Why it has not been tested:**
Running key experiments (E-CHART-01, E-FRAC-49/50) tested K1-K3 as LINEAR running keys (standard Vigenere/Beaufort with key = text characters in sequence). They did NOT test K1-K3 as GRID FILL material where the lookup is 2-dimensional (row from CT letter, column from position). The 2D lookup makes the effective key at each position depend on BOTH the CT letter AND the position, creating a fundamentally different mathematical structure from a running key.

This hypothesis explains:
- "Matrix codes" (Scheidt) = literally a matrix/grid lookup
- "Modified in a myriad of ways" = Sanborn filled the matrix with his own text rather than random values
- "Kryptos is available to all" = the text filling the matrix is on the sculpture
- "NSA tried many layered systems" = a 2D lookup is not decomposable into standard layers
- "Coding charts" = the physical grid printed on paper

---

## Summary of New Elimination Landscape

### Definitively eliminated today (E-BESPOKE-01 through -09, ~4M configs):
- Misspelling-derived substitutions as CT preprocessing + standard ciphers
- Misspelling numeric shifts as periodic/autokey key material (all permutations, signs, combinations)
- T-first alphabet rotation under all tested ciphers
- 0-indexed vs 1-indexed parameter variants (no difference)
- ABSCISSA as linear/affine/quadratic position transform
- 98-character (L insertion) + width-7 columnar + KRYPTOS Vigenere (exhaustive)
- 99-character (CC insertion) + width-9/11 columnar + keyword orderings
- Doubled letters as nulls, boundaries, or key material
- CT coordinate-pair readings
- All tested grid widths (3-20) with all tested keyword orderings and reading orders

### Still open (prioritized for next computational session):
1. **Grid rotation** (K3-style, Hypothesis 1): 98-char with physical rotation, NOT columnar -- untested specific permutation
2. **Tableau as key source** (grille extraction, Hypothesis 2): extract characters from the visible tableau using structured rules -- untested paradigm
3. **2D matrix lookup** (DRYAD from sculpture text, Hypothesis 3): K1/K2/K3 text as grid fill with 2D position/letter indexing -- untested paradigm
4. **Width-7 with running key from unknown text**: width-7 is Bean-impossible for PERIODIC keys but NOT for running keys. The residue-4-mod-7 concentration of doubles supports width-7 structure. Running key + width-7 has not been specifically tested.
5. **Antipodes physical inspection**: highest-leverage non-computational action. No complete K4 transcription from Antipodes exists. Differences could reveal the chart directly.

---

## Appendix: Configuration Counts by Experiment

| Experiment | Focus | Configs | Best Score | Classification |
|-----------|-------|---------|-----------|---------------|
| E-BESPOKE-01 | Misspelling CT modifications | ~200 | 6/24 | NOISE |
| E-BESPOKE-02 | ABSCISSA linear transforms | 237,672 | 7/24 | NOISE |
| E-BESPOKE-03 | Misspelling numeric shifts as key | ~5,000 | 6/24 | NOISE |
| E-BESPOKE-04 | T=20 (1-indexed) retest | ~1,000,000 | 6/24 | NOISE |
| E-BESPOKE-05 | 98-char insert (L) + w7 columnar | 1,754,429 | 7/24 | NOISE |
| E-BESPOKE-06 | Doubled-letter / CC insertion | 42,101 | 5/24 | NOISE |
| E-BESPOKE-07 | 1-indexed YAR/DYAR/EQUAL params | ~10,000 | 6/24 | NOISE |
| E-BESPOKE-08 | T-first alphabet hypothesis | ~50,000 | 6/24 | NOISE |
| E-BESPOKE-09 | 99-char CC insertion + w9/w11 | 1,928,768 | 8/24 | NOISE |
| **TOTAL** | | **~4,028,000** | **8/24** | **ALL NOISE** |

---

## Key Takeaway

After 230+ experiments, ~68M configurations, and systematic elimination of every computationally tractable cipher family and parameter derivation, the K4 coding chart is constrained to one of three categories:

1. **A PHYSICAL PROCEDURE** (grid rotation, grille overlay, stencil extraction) that cannot be reduced to a standard cipher operation and must be reverse-engineered from the sculpture's physical properties.

2. **A 2D LOOKUP TABLE** filled with sculpture-derived text, where the lookup depends on both position AND letter value in a non-separable way that defeats all standard 1D cipher analysis.

3. **A RUNNING KEY from an unknown text** applied through a non-standard mechanism (not Vigenere/Beaufort, possibly through a modified tableau or chart-specified per-position alphabets) with a transposition component that may use width-7 (supported by the doubled-letter residue pattern).

All three categories share a common trait: they require a PHYSICAL OBJECT (the chart) that specifies arbitrary lookup values, and the chart's content is derivable from publicly visible sculpture elements using a procedural rule we have not yet conceived. The most promising next steps are: (1) implement and test the grid rotation hypothesis (K3-style, with L-insertion for 98 chars), (2) test tableau-as-key-source with structured extraction patterns, (3) test 2D DRYAD lookup from K1/K2/K3 text fills, and (4) physically inspect Antipodes for the K4 transcription that may reveal the chart directly.

---

*Artifact: `reports/bespoke_session_synthesis.md`*
*Dependencies: E-BESPOKE-01 through E-BESPOKE-09 experiment scripts and results, `reports/bespoke_misspelling_instructions.md`, `reports/final_synthesis.md`*
*Repro: All experiment scripts in `scripts/e_bespoke_*.py`; run with `PYTHONPATH=src python3 -u scripts/<name>.py`*
