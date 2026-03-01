# "Two Separate Systems" -- Exhaustive Analysis of Untested Interpretations

**Date**: 2026-03-01
**Status**: [HYPOTHESIS] -- reasoning analysis, no code executed
**Context**: 395+ experiments, 700B+ configs, ALL NOISE

---

## The Canonical Quote

Sanborn, oral history (~Nov 3, 1990 dedication):

> "There are two systems of enciphering the bottom text. No one really asked me if there are two systems to encipher the bottom text until today at sort of the eleventh hour, and yes, there are **two separate systems** and that is **a major clue in itself**, apparently."

Key phrase: "that is a major clue in itself." The FACT of two-ness is itself informative -- not just a description of difficulty.

---

## What Has Been Tested Under the "Two Systems" Banner

All prior work interprets "two systems" as **composition of two cipher layers** applied sequentially:

1. Transposition + Vigenere (K3-style, all structured families + all periods): ELIMINATED
2. Vigenere + Transposition (reverse order): ELIMINATED
3. Sub+Trans+Sub (three-layer, effective non-periodic key): ELIMINATED for columnar w6/8/9
4. Mono+Trans+Periodic: ELIMINATED at discriminating periods
5. Mono+Trans+Running key: UNDERDETERMINED (too many DOF)
6. Double substitution (Vig+Vig, Beau+Beau, etc.): algebraically = single layer
7. Mask (affine, additive, multiplicative) + encryption: reduces to already-tested forms
8. Two-keyword combination (CKM key-split): 51K configs, ALL NOISE
9. All autokey variants + transposition: structural impossibility (max 21/24)
10. All fractionation: structural impossibility (parity/alphabet proofs)

**Critical observation**: ALL tests assume "two systems" = "two mathematical transformations applied to a single character stream in sequence." This assumption has been the foundation of every experiment. If it is wrong, we have tested the wrong search space entirely.

---

## INTERPRETATION A: Cipher + Separate Key-Generation Method

### Definition
"Two systems" means: (1) a KEY-GENERATION SYSTEM that procedurally produces a keystream from a seed or physical source, and (2) a CIPHER SYSTEM that applies that keystream. The "invention" is not the cipher itself (which could be standard Vigenere) but the KEY-GENERATION method.

### Why Current Tests Don't Cover It
All experiments test either:
- Periodic keys (keyword-derived) -- exhaustively eliminated
- Running keys from known texts -- eliminated for tested corpora
- Algebraic key functions (polynomial, recurrence, progressive) -- Bean-eliminated
- Random/arbitrary keys -- underdetermined by information theory

None test **procedural key derivation** where the key is generated through a multi-step physical or logical process: e.g., reading characters from the tableau in a specific order, using the sculpture's physical layout to derive a path, or performing arithmetic on coordinates/dates to produce a 97-character key.

### Specific Test Proposal
**Test A1: Tableau-derived keystream.** Read the KA tableau (32x33 grid) along specific paths -- diagonals, spirals, serpentine, column-read at specific offsets, or paths determined by a keyword -- extracting a 97-character keystream. Apply as Vigenere key.

Expected result: If this interpretation is correct, one specific path + keyword combination will produce 24/24 cribs with English plaintext. The search space is ~26 keyword chars x ~100 path types x ~100 starting positions = ~260K configs.

**Test A2: Coordinate-derived key.** Use the LOOMIS/BOWEN geodetic marker coordinates (38 57 06.22 N, 077 08 48.14 W), K2 coordinates, or Weltzeituhr zone numbers to seed a key-generation algorithm. E.g., chain addition starting from coordinate digits, or sequential tableau lookups indexed by coordinate values.

**Test A3: Sculpture-text-derived key.** Use K1/K2/K3 ciphertext or plaintext, not as a running key (already tested), but as INPUT to a key-generation algorithm -- e.g., take every Nth character, apply a modular transformation, use as index into the tableau.

### Plausibility: 7/10
**For**: Scheidt's CKM patents are entirely about key generation/splitting. "Systems that didn't depend on mathematics" + "code circles/rings with keyword access" = procedural key generation from a physical device. Sanborn had the tableau physically present. The tableau IS a key-generation system.

**Against**: We've tested many keyword+tableau combinations. The keystream at crib positions (BLZCDCYYGCKAZ, MUYKLGKORNA) shows no obvious pattern that would point to a specific generation rule. Running the KA tableau as a running key (its rows/columns) was already tested in several TABLEAU experiments.

---

## INTERPRETATION B: One System for First Half, One for Second Half

### Definition
"Two systems" means K4's 97 characters are SPLIT into segments, each encrypted with a different method. The split might be:
- Positions 0-48 / 49-96 (midpoint)
- Positions 0-62 / 63-96 (before/after BERLINCLOCK)
- Positions 0-33 / 34-96 (after EASTNORTHEAST)
- Some other structural boundary

### Why Current Tests Don't Cover It
Every experiment treats K4 as a SINGLE 97-character stream encrypted uniformly. If positions 0-33 use Vigenere and positions 34-96 use a transposition (or vice versa), no single-method sweep would detect this. The crib constraints would be split across two different cipher instances, each with fewer constraints and therefore harder to detect.

### Specific Test Proposal
**Test B1: Split at position 34 (after ENE).** Test each half independently:
- Positions 0-33 (34 chars, 13 crib positions from ENE): test all periodic Vig/Beau at periods 2-17
- Positions 34-96 (63 chars, 11 crib positions from BC): test independently

Note: Bean constraint applies across the split (k[27] in half 1, k[65] in half 2), which only constrains if both halves share parameters.

**Test B2: Split at position 63 (before BC).** Similar approach but with a different division:
- Positions 0-62 (63 chars, includes ENE but not BC)
- Positions 63-96 (34 chars, includes BC)

**Test B3: Interleaved split.** Even positions use system A, odd positions use system B. Or every-3rd, every-7th, etc. This would explain the low IC (mixing two independent cipher outputs).

### Plausibility: 5/10
**For**: "Two systems" most literally means two distinct methods. Sanborn said "the whole piece is designed to unveil itself, as if you were to pull up one layer, then you can come to the next" -- suggesting sequential layers or sequential segments. The yellow pad shows "8 Lines 73" -- if 73 chars are encrypted one way and 24 chars (the cribs) another way, this could explain the notation.

**Against**: Bean constraint k[27]=k[65] bridges positions 27 and 65, which would span any plausible split point. If the two halves use completely independent methods, Bean would be a coincidence rather than a structural feature. Also, Scheidt's "I masked the English language" suggests a UNIFORM masking process, not a segmented one. Sanborn's "two systems" + "a major clue in itself" suggests the two systems INTERACT, not that they're applied to separate text.

---

## INTERPRETATION C: Non-Algebraic Physical Rearrangement + Encryption

### Definition
"Two systems" means: (1) a PHYSICAL MANIPULATION of the text on the copper sheet (rearranging strips, folding, overlaying, reading in a non-standard order determined by the S-curve) that produces a different character sequence, and then (2) a STANDARD ENCRYPTION of that rearranged text.

The physical rearrangement is NOT a mathematical transposition in the standard sense -- it is determined by the sculpture's three-dimensional geometry and cannot be derived without access to (or precise measurements of) the physical object.

### Why Current Tests Don't Cover It
All transposition tests assume the 97-character string OBKR...CAR is read left-to-right, top-to-bottom from the copper sheet, and then mathematically transposed. If the S-curve of the sculpture means certain characters are physically adjacent to characters from different rows, or if the curvature creates a non-planar reading order, then the true "input" to the cipher is a different permutation of those 97 characters than any standard grid reading provides.

Specifically:
- Standard column reads were tested (widths 5-15)
- Serpentine/spiral/diagonal reads were tested at width 9
- Grid route ciphers were tested (52K configs)
- But ALL assumed a FLAT rectangular grid

The copper sheet is S-CURVED. Characters at the edges of one row are physically closer to characters in non-adjacent rows on the back side of the curve. A reading order that follows the physical surface (like tracing a finger along the S) would produce a permutation not captured by any flat-grid model.

### Specific Test Proposal
**Test C1: S-curve physical permutation model.** Using photographs and known physical dimensions:
1. Map each of the 97 K4 characters to (x,y,z) coordinates on the curved surface
2. Define candidate reading orders: follow the S-curve continuously, read by proximity on the 3D surface, trace the petrified tree's line of sight through the perforations
3. Apply each reading-order permutation, then test standard ciphers (Vig/Beau at Bean-surviving periods + running key)

This requires physical measurements or very precise photographs -- it is currently UNTESTABLE without sculpture access or the Antipodes replica.

**Test C2: Strip manipulation.** Sanborn worked with copper strips. If the four copper sheets can be rearranged (swapped, reversed, interleaved), the resulting text is a physical permutation. Test: enumerate all 4! x 2^4 = 384 arrangements of 4 sheets (original, reversed) and test each.

### Plausibility: 8/10
**For**: This is the strongest remaining interpretation. Sanborn is a SCULPTOR, not a mathematician. His medium is physical objects. "Systems that didn't depend on mathematics" + "matrix codes that could be modified in myriad ways" + the physical S-curve + "coding charts" sold at auction all point to a procedure that involves physically manipulating the copper. The coding charts may literally show which strip goes where. Fold theory (OFLNUXZ emerging from folding) provides evidence of meaningful physical manipulation. "IDBYROWS may not be a mistake" could be a literal instruction about reading the physical strips by rows.

**Against**: Antipodes has the same text with ZERO mismatches, suggesting the reading order is standard (no physical manipulation changes the text). But Antipodes is FLAT, not S-curved -- so the S-curve reading-order hypothesis would only apply to the CIA sculpture. Also, "Kryptos is available to all" (Sanborn, Feb 2026) suggests no physical access is needed.

---

## INTERPRETATION D: The Tableau AND the Physical S-curve Layout

### Definition
"Two systems" means: (1) the Vigenere TABLEAU on the left side of the sculpture, and (2) the CIPHER TEXT on the right side. They function as two interlocking systems -- the tableau is not just a tool for decryption but an active component of the encryption. Reading both sides together (e.g., matching positions on cipher side to positions on tableau side via the S-curve alignment) produces the plaintext.

### Why Current Tests Don't Cover It
All experiments use the tableau as a standard Vigenere lookup table: given a key letter and either PT or CT, look up the other. Nobody has tested the hypothesis that the tableau's PHYSICAL POSITION relative to the cipher text matters -- i.e., that specific cells of the tableau correspond to specific ciphertext positions based on how they align when the sculpture is viewed/folded/rotated.

### Specific Test Proposal
**Test D1: Positional alignment.** Map each K4 cipher character to the tableau cell that occupies the same physical height on the sculpture. If K4 character at position i aligns with tableau row r, column c, then PT[i] = f(CT[i], r, c) for some function f. This requires physical measurements.

**Test D2: Fold alignment.** When the S-curved copper sheet is mentally "flattened" or "folded," cipher characters overlay specific tableau characters. The fold theory already identified OFLNUXZ from this process. Test: use the known fold geometry to map each CT position to a tableau position, extract the aligned tableau characters as a keystream, and apply Vigenere/Beaufort decryption.

**Test D3: Row-matched encryption.** The K4 ciphertext, when laid out in rows matching the sculpture, may index into specific ROWS of the tableau. "8 Lines 73" could mean K4 is arranged in 8 rows. Each row of K4 is encrypted using the corresponding row of the tableau (a different alphabet for each row). This is essentially a Quagmire variant but with rows determined by physical layout rather than period.

### Plausibility: 6/10
**For**: The 1989 letter says "partly deciphered by using the table" -- "using the table" may mean physically, not abstractly. The S-curve puts tableau and cipher on the same physical sheet, visible from different sides. "Code circles/rings fixed in place" maps to a tableau physically fixed to the sculpture. The fold theory's OFLNUXZ finding suggests meaningful alignment.

**Against**: Quagmire variants were tested and produced ZERO consistent configs. K1/K2 use the tableau in the standard way -- departing from that for K4 requires the "intentional change in methodology," which is plausible but makes the method harder to discover. Physical-alignment tests require measurements we don't have.

---

## INTERPRETATION E: Substitution Applied WITHIN a Transposition Grid

### Definition
Instead of Trans(Sub(PT)) or Sub(Trans(PT)), the cipher operates as follows:
1. Write PT into a grid (e.g., 8 rows x ~12 columns, matching "8 Lines")
2. Apply SUBSTITUTION within the grid, where the key depends on the ROW AND COLUMN position (not just the sequential position)
3. Read off the grid in a different order (column-first, diagonal, etc.)

This is a fundamentally different composition than sequential application. The substitution key at position (r,c) is f(r,c), not f(i) where i is the linear position. This means the key is TWO-DIMENSIONAL.

### Why Current Tests Don't Cover It
All tests model the key as a function of linear position: k[i] for i=0..96. A 2D key model k[r][c] has different periodicity structure. For example, a key that repeats with the row (period = number of columns) AND shifts with the column (progressive across rows) would produce a non-periodic linear keystream that doesn't match any standard periodic or running-key model.

Specifically: if K4 is an 8x13 grid (8 rows, 12-13 columns, with one short row), and the key is determined by BOTH coordinates:
- k[r][c] = row_key[r] + col_key[c] (mod 26)

This produces a key that appears non-periodic when read linearly but is structured in 2D. The crib analysis would see key values that change with BOTH row and column, creating a pattern that standard period-detection would not identify.

### Specific Test Proposal
**Test E1: 2D Vigenere grid.** For grid dimensions (8x13, 8x12+1, 10x10, 7x14):
1. Write K4 CT into the grid row-by-row
2. Model key as k[r][c] = A[r] + B[c] (mod 26) where A is an 8-letter row key and B is a 13-letter column key
3. Given 24 known PT positions, solve for A and B (overdetermined system of 24 equations in 8+13=21 unknowns)
4. Check if the solution produces valid English for the remaining 73 positions

This is computationally cheap: for each grid dimension, it's a single linear system solve. The key space is 26^8 x 26^13 but the crib constraints immediately determine most of it.

**Test E2: "8 Lines 73" literal model.** Write K4 into 8 rows. The "73" might mean the key source is 73 characters long. Apply a 73-character running key to the grid, where key assignment follows COLUMN ORDER (not row order). This means position (r,c) gets key character at index (c*8 + r) or (c*nrows + r) instead of (r*ncols + c).

**Test E3: IDBYROWS instruction.** "ID BY ROWS" = "identify by rows." The grid reading produces one cipher, but the ROWS individually encode something. Test: write K4 into rows of width 8,10,12,13; decrypt each row independently with a different key; check if row-by-row decryption produces coherent text.

### Plausibility: 8/10
**For**: This is the strongest algebraically untested interpretation. "Matrix codes" (Scheidt taught Sanborn) literally means operations on a grid/matrix. "IDBYROWS" is a direct instruction about rows. "8 Lines 73" on the yellow pad describes a grid. "Shifting matrices" = a Vigenere-like operation on a 2D structure. A 2D key (row_key + col_key) is exactly a "key split combiner" in its simplest form: two independent components combined to produce a position-dependent key. This is hand-executable (fill in a grid, apply two short keys). It is "known cryptographic solutions" (Vigenere + transposition/grid) assembled in "a way that has never appeared in cryptographic literature" (2D keying within a grid). It produces non-periodic linear keystream (explaining Bean survival). And the existence of TWO keys (row + column) makes "two separate systems" literally true.

**Against**: The linear system from 24 crib equations in ~21 unknowns is overdetermined. If this model were correct, it would be solvable in seconds from the cribs alone. The fact that nobody has tried this specific formulation is surprising -- it may have been implicitly tested as part of Quagmire or position-dependent alphabet experiments. Also, 2D keying is not truly novel -- it appears in ADFGX/ADFGVX and some Japanese army ciphers. Scheidt would know these.

However: the "implicitly tested" objection needs scrutiny. Quagmire tests used PERIODIC keys in LINEAR position. 2D keying in a GRID is algebraically distinct. And ADFGX/ADFGVX involves fractionation (eliminated), not direct 2D substitution. The Japanese army PURPLE machine is mechanical, not manual. So this may genuinely be untested.

---

## INTERPRETATION F: One System for Generating the Key, One for Applying It

### Definition
"Two systems" means there is a KEY GENERATION SYSTEM and an ENCRYPTION SYSTEM, and Sanborn considers these as two separate named methods. The key generation system is itself a cipher or cipher-like process -- e.g., encrypting a keyword with a second cipher to produce the actual key used for K4 encryption.

This overlaps with Interpretation A but is more specific: the key generation is itself a recognized cipher operation, not just a procedural derivation.

### Why Current Tests Don't Cover It
The CKM key-split tests (E-SPLIT-00, 51K configs) tested combinations of known key sources, but tested a LIMITED set of combination methods (XOR, addition, concatenation, interleaving). They did not test:
- Using one cipher to ENCRYPT the output of another cipher's key
- Applying Vigenere with key=KRYPTOS to produce a SECONDARY key, then using that secondary key to encrypt K4
- Using the tableau as a key-transformation device (input a seed, read the output from a different row/column)

### Specific Test Proposal
**Test F1: Double-keyed Vigenere.** Encrypt keyword A with keyword B using the KA tableau, producing keystream C. Use C to encrypt K4 plaintext. Test all pairs (A,B) from {KRYPTOS, PALIMPSEST, ABSCISSA, BERLINCLOCK, EASTNORTHEAST} and single-word keys up to length 13 from the wordlist.

**Test F2: Tableau as key generator.** Given a seed keyword K:
1. Look up K[0] in the KA tableau to get row R0
2. Read column C0 from R0, producing the next key character
3. Use the previous output to determine the next lookup
4. Iterate to produce a 97-character keystream

This is an autokey-like process but using the TABLEAU as the feedback mechanism rather than the plaintext or ciphertext. It has not been tested because standard autokey was modeled algebraically, not as tableau lookups in the KA alphabet.

**Test F3: Chain addition from keyword.** Standard chain addition (k[i] = k[i-1] + k[i-2] mod 26) was eliminated algebraically. But chain addition in the KA ALPHABET (where the modular arithmetic follows KA ordering, not standard A-Z) has not been tested. KA ordering changes the modular structure: K=0, R=1, Y=2, P=3, ... This could produce different keystreams than standard mod-26.

### Plausibility: 6/10
**For**: Scheidt's CKM patents describe exactly this: generating keys from multiple components through a defined process. "Two systems" = key-generation system + encryption system is the most natural reading from a cryptographic engineer's perspective. Scheidt DESIGNED the method; Sanborn CHOSE the parameters (keywords). Two keywords into a key-combiner is exactly CKM.

**Against**: The CKM key-split campaign tested 51K configs and found nothing. Chain addition in KA alphabet is algebraically equivalent to chain addition in AZ alphabet with a permuted lookup (it's an isomorphism -- the group structure is the same). The key point is that KA alphabet ordering doesn't change the underlying mod-26 arithmetic for addition. However, it DOES change tableau lookups, so Test F2 remains genuinely untested.

---

## INTERPRETATION G: Steganographic Encoding + Conventional Cipher

### Definition
"Two systems" means: (1) a STEGANOGRAPHIC system that embeds data in the arrangement, spacing, font, or visual properties of the text, and (2) a CONVENTIONAL cipher applied to the letter content. The steganographic layer carries information invisible in transcription.

### Why Current Tests Don't Cover It
All experiments work from the 97-character ASCII transcription OBKR...CAR. If information is encoded in:
- Letter size variations on the copper (slightly larger/smaller cuts)
- Spacing between letters (irregular gaps carrying binary data)
- Position of letters relative to row boundaries
- Whether letters are perfectly aligned or slightly offset
- The physical gap between K3 and K4

...then this information is LOST in transcription and no computational test can recover it.

### Specific Test Proposal
**Test G1: High-resolution photographic analysis.** Obtain the highest available resolution photographs of the K4 section. Measure:
- Relative letter heights (is any letter systematically larger/smaller?)
- Inter-letter spacing (is there a pattern -- tight/loose encoding binary?)
- Row-to-row alignment (do letters in adjacent rows align perfectly?)
- Any marks, dots, scratches, or intentional imperfections

**Test G2: Morse code layer.** The entrance panel uses Morse code. Could K4 letters also encode Morse through a secondary channel? E.g., letter SHAPES (letters with only straight lines vs. curves) encoding dots and dashes. Count: AEFHIKLMNTVWXYZ = straight-line-only (approx), BCDGJOPQRSU = curved. Map to binary and check for structure.

**Test G3: Null cipher extraction.** Take every Nth character, first letters of each row at various widths, acrostic patterns. These were tested in E-CFM-03 and Operation Final Vector but only under specific extraction rules. A steganographic system might use a more complex extraction pattern determined by the sculpture's geometry.

### Plausibility: 4/10
**For**: Sanborn is a visual artist who has explicitly created steganographic works (Cyrillic Projector, MEDUSA). "Individualistic visual encoding systems" (WIRED 2005). The kryptosfan blog notes "I think you just have to be there to see it. No picture will let us passively guess." This strongly suggests a visual/physical component.

**Against**: "Kryptos is available to all" (Sanborn, Feb 2026) contradicts the need for physical access. Also, K5 shares "coded words at the same positions" as K4 -- if K4 had a steganographic layer embedded in the physical copper, K5 couldn't share that structure as a separate 97-character message. The 24 known plaintext positions (from Sanborn's own clues) were given as LETTER positions, not visual positions, suggesting the cipher operates on letters.

---

## INTERPRETATION H: K4 Encodes Two Messages Simultaneously

### Definition
"Two systems" means K4 decrypts to TWO DIFFERENT plaintexts depending on which key/method you use. One plaintext is the "surface" message (possibly the Carter tomb narrative). The other is the "real" message (involving EASTNORTHEAST and BERLINCLOCK). This is a DURESS CIPHER or polysemic encryption.

### Why Current Tests Don't Cover It
All experiments search for ONE plaintext that matches the known cribs. If K4 is designed so that:
- Method A + Key A produces plaintext X (containing EASTNORTHEAST and BERLINCLOCK)
- Method B + Key B produces plaintext Y (the Carter tomb narrative or something else entirely)

...then the search needs to find a PAIR of methods/keys that both produce valid English, not just one.

Gillogly explicitly raised this possibility: "K4 might incorporate duress cipher principles -- allowing multiple valid decryptions yielding credible plaintext."

### Specific Test Proposal
**Test H1: Dual-plaintext Vigenere.** Given the 24 known positions of plaintext X (EASTNORTHEAST + BERLINCLOCK), find all Vigenere keys K such that applying K to K4 CT produces English at the remaining 73 positions. Then for each such K, compute what K' would need to be to produce the Carter tomb text at those same positions. Check if K' has any structure (periodicity, English text, keyword-derivable).

This is computationally infeasible as stated (73 free positions = 26^73 possible keys). But if we assume both keys are SHORT (e.g., period 8-13), we can test: for each period p, enumerate K1 values that satisfy the ENE/BC cribs, compute the implied K2 for a Carter-derived alternate plaintext, and check if K2 is also periodic.

**Test H2: XOR-dual encoding.** If K4 = PT1 XOR PT2 (in some modular sense), then knowing PT1 at crib positions gives PT2 at those same positions. Check if the CT values at crib positions, combined with the known PT, could also encode a second meaningful text.

### Plausibility: 3/10
**For**: Gillogly raised it. Scheidt's background in "duress indicators" and "receiver identity protection" supports multi-message encoding. The misspelling pattern (different in each section) could be a duress indicator. "Who says it is even a math solution?" could mean the REAL solution is the second plaintext, not the first.

**Against**: Dual-plaintext encryption for a 97-character text with 24 known positions is mathematically nearly impossible under any structured cipher. The constraints from 24 known positions heavily restrict the key space; producing TWO valid English outputs would require extraordinary luck or a very specific construction. Also, Sanborn said "two systems of enciphering," not "two decipherments" -- the emphasis is on the ENCODING process, not the decoding result.

---

## INTERPRETATION I: One System Readable from Sculpture, One Requiring Transcription

### Definition
"Two systems" means the physical sculpture encodes information in TWO WAYS:
1. Something readable directly from the copper (visual pattern, letter arrangement, fold/overlay)
2. Something that requires transcribing the letters and applying a cipher

The first system is PHYSICAL (you have to be at Langley or see photos). The second is MATHEMATICAL (anyone with the transcription can attempt it).

### Why Current Tests Don't Cover It
All experiments work from the transcription (system 2). System 1 is inaccessible without physical access or precise photographs showing features not captured in the standard transcription.

### Specific Test Proposal
**Test I1: Shadow/projection analysis.** At specific times of day, the perforated copper casts letter-shaped shadows. These shadows overlap on the ground/pool/stone, potentially spelling words. This is consistent with Sanborn's other works (Cyrillic Projector). Test requires: solar angle calculations for Langley coordinates + sculpture orientation + letter positions.

**Test I2: Through-the-copper reading.** The letters are CUT THROUGH the copper. From the back (tableau side), they appear MIRRORED. Read K4 backwards: RACKEUAUHUKG... and test as a separate cipher instance or overlay.

**Test I3: Superimposition.** When viewed from specific angles, letters from different rows might overlap visually, creating new letter combinations. The S-curve means different rows are at different depths. Parallax from a specific viewpoint could align particular letters.

### Plausibility: 5/10
**For**: "I think you just have to be there to see it" (kryptosfan). Sanborn's Cyrillic Projector literally works by projecting text through perforations. The sculpture IS a physical installation, not a text file. "Two systems" = one physical, one textual is elegant. "A major clue in itself" = knowing there's a physical component redirects the solver's attention.

**Against**: "Kryptos is available to all." K5 shares structure with K4 as a 97-character text, implying the cipher operates on text, not physical properties. Sanborn has given purely textual clues (EASTNORTHEAST, BERLINCLOCK) that work within the transcription. The Antipodes replica is FLAT (no S-curve) but reproduces the text identically, suggesting the physical shape is not cryptographically relevant.

---

## INTERPRETATION J: Sanborn's System (PT Choice/Masking) + Scheidt's System (Encryption)

### Definition
"Two systems" means: (1) SANBORN'S system -- the way he prepared the plaintext (choosing words, inserting the Carter narrative, incorporating EASTNORTHEAST and BERLINCLOCK, possibly masking/encoding the English before giving it to Scheidt's method), and (2) SCHEIDT'S system -- the actual cryptographic transformation.

The "mask" is not a mathematical function but a LITERARY/EDITORIAL choice: Sanborn deliberately wrote the plaintext so that, even after decryption, it requires interpretation. "Solve the technique first, then the puzzle" -- the TECHNIQUE is the cipher, the PUZZLE is understanding what the plaintext means.

### Why Current Tests Don't Cover It
If Sanborn's "masking" is editorial (e.g., the plaintext is deliberately obscure, uses abbreviations, or is written in a compressed/coded style), then standard English-language statistics (quadgram scores, IC, word detection) would FAIL on the correctly-decrypted plaintext. Our oracle requires quadgram > -4.84 and IC > 0.055 and non-crib words >= 3. If the plaintext reads like "XSLWDSPRTSLYTHEREMNSOF..." (Slowly Desperately with vowels removed), the oracle would reject it as noise.

More specifically: if the "mask" is vowel removal, the plaintext has no vowels and quadgram analysis fails. If it's phonetic respelling (e.g., KAT for CAT), English word detection fails. If it's abbreviation (ESTNRTHEST instead of EASTNORTHEAST), crib matching at known positions still works but the rest of the plaintext looks like gibberish.

### Specific Test Proposal
**Test J1: Vowel-removed plaintext.** Assume the plaintext (except at known crib positions, which somehow include vowels) has had all vowels replaced by a fixed letter or removed entirely. Test: for each standard cipher, check if the NON-CRIB positions produce consonant-only text with high consonant-cluster frequency. This changes the scoring oracle.

**Test J2: Abbreviation/compression.** The yellow pad shows "8 Lines 73" -- if the PLAINTEXT is 73 characters (compressed from the Carter narrative), and then 24 additional characters were added (the cribs?), totaling 97, the oracle needs to test for compressed English.

**Test J3: Two-language mask.** The cribs are in English (EASTNORTHEAST, BERLINCLOCK). But the rest of the plaintext might be in German (BERLINCLOCK is German in origin) or Latin (ABSCISSA is Latin, PALIMPSEST is Greek-Latin). Test running-key analysis against German texts for non-crib positions.

### Plausibility: 7/10
**For**: This interpretation makes "two systems" literal and NATURAL. Scheidt: "I masked the English language... solve the technique first then the puzzle." This is exactly "technique = Scheidt's cipher, puzzle = Sanborn's masked text." The yellow pad shows Sanborn DRAFTING the plaintext -- he's an active participant in the encoding, not just providing text. "A major clue in itself" = the two-party nature of the encryption (artist + cryptographer) is structurally important. This also explains why NSA failed: they would test cipher methods, but if the plaintext itself is non-standard, no amount of cipher-breaking produces recognizable English.

**Against**: The known cribs (EASTNORTHEAST, BERLINCLOCK) are standard English words. If the masking destroyed English characteristics, why are the cribs intact? Possible answer: the cribs were inserted AFTER masking (Sanborn planted recognizable words at specific positions to provide toeholds). This is consistent with the yellow pad draft NOT containing EASTNORTHEAST or BERLINCLOCK -- they were added later, into a masked text.

---

## INTERPRETATION K: "IDBYROWS" as Literal Instruction

### Definition
"IDBYROWS" (the physical sculpture reading of what Sanborn calls XLAYERTWO) is a DELIBERATE instruction: "ID BY ROWS" = "identify by rows." This means:
1. Arrange K4 in a grid
2. Process it ROW BY ROW (not column-by-column or by any other reading order)
3. Each row is independently encrypted or encodes independent information

Scheidt (ACA 2013): "IDBYROWS may not be a mistake. In spycraft you deliberately do these things."

### Why Current Tests Don't Cover It
Columnar transposition tests read by COLUMNS. Grid route ciphers test various reading patterns. But "ID BY ROWS" specifically means the ROWS are the unit of analysis. This could mean:
- Each row of K4 is encrypted with a different key
- The rows are scrambled (row-level transposition, not character-level)
- Reading ROW-BY-ROW reveals something that column-by-column doesn't
- The row boundaries are the structural unit, and "8 Lines" on the yellow pad gives the number of rows

Row-level operations have NOT been systematically tested as a primary cipher mechanism (only as part of grid reading orders, which treat rows as a secondary feature of column-width selection).

### Specific Test Proposal
**Test K1: Row-independent Vigenere.** Arrange K4 in 8 rows of 12-13 characters. Apply a DIFFERENT Vigenere key to each row. With 8 rows and 24 known plaintext positions, some rows have 3-4 known positions. For each row, enumerate short keys (length 1-6) that satisfy the known positions in that row.

This is computationally feasible: 8 rows x ~26^6 max keys per row = ~8 x 3x10^8 = 2.4 billion, reducible by crib constraints to a much smaller set.

**Test K2: Row scramble + column-read.** Write K4 into 8 rows of 12-13 chars. Scramble the ROW ORDER (8! = 40,320 possibilities). Read COLUMN-BY-COLUMN. Test each resulting 97-char string against standard ciphers.

**Test K3: Row-by-row strip manipulation.** Cut the 8 rows into independent strips. Shift each strip left or right by a different amount (26 positions each). Then read column-by-column. This is a Vigenere-like transposition: 26^8 = ~2x10^11 configs, reducible by crib constraints.

**Test K4: "8 Lines 73" as instruction.** 8 rows of 73/8 ~ 9.125 characters -- doesn't divide evenly. But 8x9=72, 8x10=80. Try: 8 rows of varying length, total 73 characters, with the remaining 24 characters (the crib positions) treated separately. Or: the grid is 8 rows of 9 chars = 72, plus one extra position. The "73" might be the KEY LENGTH, not the grid size.

### Plausibility: 9/10
**For**: This is the single most compelling untested interpretation. It combines multiple independent lines of evidence:
1. Scheidt's direct statement that IDBYROWS "may not be a mistake"
2. "8 Lines 73" on the yellow pad -- 8 rows, 73 unknown chars
3. "Matrix codes" and "shifting matrices" in Scheidt's curriculum
4. "Code circles/rings fixed in place with keyword access" -- a grid with fixed rows and keyword-shifted columns
5. "Two systems" = row-level operation + column-level operation, naturally producing a 2D key
6. "A major clue in itself" = knowing to look at rows instead of columns redirects the attack
7. Hand-executable: write text in rows, apply row shifts, read by columns
8. K3 working chart showed P/C labels -- grid-based processing
9. A 2D key (row_key + col_key) is a primitive CKM key-split: two components combined positionally
10. "ID BY ROWS" on the PHYSICAL SCULPTURE while "X LAYER TWO" was the STATED intent -- if Scheidt says the physical reading matters, the cipher literally tells you to process by rows

**Against**: This is essentially a specific case of Interpretation E (substitution within a grid). The main risk is that somebody HAS tried this implicitly through Quagmire or position-dependent alphabet experiments. However, reviewing the elimination record: Quagmire was tested with PERIODIC keys in LINEAR position, not row-independent keys. Position-dependent alphabets were noted as equivalent to running key, which doesn't capture the 2D structure. The specific model of "independent row keys" has NOT been explicitly tested.

---

## COMBINED INTERPRETATION: E + K (The "Matrix Code" Hypothesis)

The strongest untested hypothesis combines Interpretations E and K into a single coherent model:

### The Model

1. **Write** the 97-character plaintext into a grid of 8 rows ("8 Lines")
   - Row widths: either uniform (12-13 chars) or variable (as determined by "73")
   - The first ~73 chars are the "masked" plaintext; the remaining 24 are crib insertions

2. **Apply** a 2D key: each cell at position (row r, column c) gets key value:
   - k[r][c] = ROW_KEY[r] + COL_KEY[c] (mod 26)
   - ROW_KEY is derived from one keyword (e.g., KRYPTOS = 8 unique characters? No, 7. But K=0,R=1,Y=2,P=3,T=4,O=5,S=6,A=7 in KA order gives 8 values.)
   - COL_KEY is derived from a second keyword

3. **Read** the encrypted grid by ROWS (IDBYROWS) to produce the 97-character ciphertext

This is:
- "Two systems" = row encryption + column encryption (two keywords, two axes)
- "Matrix codes" = 2D grid operation
- "Shifting matrices" = each row/column shift differs
- "Code circles/rings with keyword access" = the row/column keys cycle (like a code wheel for each axis)
- "An invention... never appeared in cryptographic literature" = 2D Vigenere is not in standard textbooks
- Hand-executable = fill grid, look up each cell in tableau using row+column key
- "ID BY ROWS" = literal instruction for reading order
- "8 Lines 73" = 8 rows, 73 characters of masked content (+ 24 crib chars = 97)
- "A major clue in itself" = the 2D structure is the clue
- CKM key-split = two independent key components combined at each position

### Why This Has Not Been Tested

The 2D Vigenere model k[r][c] = A[r] + B[c] with an 8-row grid has:
- 8 row-key values + W column-key values (where W = 12 or 13)
- Total: 8 + 13 = 21 unknowns
- 24 crib constraints (equations)
- System is OVERDETERMINED (24 > 21): solvable if consistent

This means the model is IMMEDIATELY TESTABLE. For each candidate grid width (12, 13, or variable):
1. Set up the 24 linear equations from known PT/CT positions
2. Solve the overdetermined system (mod 26) for the 21 unknowns
3. If a consistent solution exists, decrypt the remaining 73 positions
4. Check if the result is English (or masked English)

This takes SECONDS to compute. The fact that it hasn't been tried is likely because nobody formalized the 2D model in this way. All existing experiments either test periodic keys (1D) or treat the transposition and substitution as separate sequential steps.

### Critical Subtlety

The grid width matters. "8 Lines 73" could mean:
- 8 rows of 9 chars = 72 positions (one short of 73)
- 8 rows of varying length: rows 1-5 have 13 chars, rows 6-8 have 10 chars (5x13 + 3x10 = 95, still not 97)
- The "73" is separate from "8 Lines" -- perhaps 73 is the column key length, or the number of non-crib positions

For exhaustive testing: try all grid widths W from 9 to 16 (giving 7-11 rows with remainder), solve the linear system for each, check consistency.

### Plausibility: 9/10

This is the most plausible untested interpretation because:
1. It is the simplest model consistent with ALL known clues
2. It is immediately testable (algebraic solve, seconds of compute)
3. It has genuinely never been tested (verified against elimination record)
4. It unifies the most evidence from the most independent sources
5. It explains why standard attacks fail (non-periodic linear keystream)
6. It is hand-executable and pre-1989
7. It uses the KA tableau in a natural way (2D lookup)

---

## PRIORITY RANKING

| Rank | Interpretation | Plausibility | Testability | Priority |
|------|---------------|-------------|-------------|----------|
| 1 | **E+K: 2D Matrix Code (IDBYROWS)** | 9/10 | Immediate (algebraic) | **CRITICAL** |
| 2 | **E: Substitution within grid** | 8/10 | Hours (linear systems) | HIGH |
| 3 | **K: IDBYROWS as literal instruction** | 9/10 | Hours (enumeration) | HIGH |
| 4 | **C: Physical rearrangement + encryption** | 8/10 | Blocked (needs measurements) | HIGH but BLOCKED |
| 5 | **A: Cipher + procedural key generation** | 7/10 | Days (path enumeration) | MEDIUM-HIGH |
| 6 | **J: Sanborn's masking + Scheidt's cipher** | 7/10 | Days (oracle modification) | MEDIUM-HIGH |
| 7 | **D: Tableau + S-curve positional alignment** | 6/10 | Blocked (needs measurements) | MEDIUM but BLOCKED |
| 8 | **F: Key-generation system + encryption system** | 6/10 | Days (tableau path search) | MEDIUM |
| 9 | **B: Split encryption (first half / second half)** | 5/10 | Hours (half-text sweeps) | MEDIUM |
| 10 | **I: Physical + transcription systems** | 5/10 | Blocked (needs access) | LOW (blocked) |
| 11 | **G: Steganographic + conventional** | 4/10 | Blocked (needs photos) | LOW (blocked) |
| 12 | **H: Dual-message encoding** | 3/10 | Days (dual-key search) | LOW |

---

## RECOMMENDED NEXT ACTIONS

### Immediate (can be done in minutes):
1. **Test the 2D Vigenere model (E+K combined).** For grid widths 9-16, set up the linear system from 24 crib positions, solve mod 26, check consistency. If ANY width produces a consistent solution, decrypt and evaluate.

### Short-term (hours):
2. **Test row-independent encryption (K1).** 8 rows with independent short keys, constrained by cribs.
3. **Test row scramble + Vigenere (K2).** 40,320 row orderings x standard ciphers.
4. **Test split-text encryption (B1/B2).** Each segment independently against standard methods.

### Medium-term (days):
5. **Modify the scoring oracle for masked plaintext (J1).** Allow consonant-heavy or abbreviated text as valid output.
6. **Test tableau-path key generation (A1/F2).** Enumerate paths through the KA tableau as keystreams.

### Blocked (needs external data):
7. **Physical S-curve permutation (C1).** Requires sculpture measurements.
8. **Shadow/projection analysis (I1).** Requires solar angles + precise sculpture geometry.
9. **High-resolution photographic analysis (G1).** Requires access or detailed photographs.

---

## META-OBSERVATION

The most striking finding of this analysis is that the simplest, most evidence-supported interpretation -- a 2D grid cipher with row and column keys, directly instructed by "IDBYROWS" on the physical sculpture -- has apparently never been formally tested despite 395 experiments and 700 billion configurations. This is likely because the project's architecture is built around 1D sequential composition (transposition + substitution as separate steps), and the 2D model doesn't fit that framework.

The 2D model also elegantly resolves the "two systems" question: the two systems are the ROW encryption and the COLUMN encryption. They are "separate" (independent keys) and their existence as two systems is "a major clue" because it tells the solver to look for a 2D key structure rather than a 1D one.

If the 2D model test (Action 1) fails -- that is, if no grid width produces a consistent solution to the overdetermined linear system -- then the model is DEFINITIVELY ELIMINATED, and we can move to the next interpretation. That kind of clean falsifiability is rare in this project and should be exploited immediately.

---

*Analysis by Claude Opus 4.6, 2026-03-01. Reasoning only -- no code executed.*
