# Bespoke Cipher Design Analysis: What Survives the Elimination Framework?

**Date**: 2026-03-01
**Author**: Reasoning analysis (no code execution)
**Purpose**: Identify the class of cipher a CIA cryptographic chief would design for hand execution in 1989, given that ALL standard and non-standard classical ciphers have been eliminated by 395+ experiments across 700B+ configurations.

---

## Foundational Constraints

Before enumerating candidates, we must state what any surviving method MUST satisfy:

### Hard constraints (violation = impossible)
1. **Hand-executable by a sculptor** -- Sanborn performed this with a chisel and a yellow legal pad. No computers, no machines, no electronic devices.
2. **Uses all 26 letters** -- K4 CT contains all 26 letters. No alphabet reduction (eliminates 5x5 Polybius, I/J merge).
3. **97 characters output** -- The CT is exactly 97 characters.
4. **Consistent with known cribs** -- EASTNORTHEAST at positions 21-33, BERLINCLOCK at positions 63-73 (0-indexed), under whatever cipher model is proposed.
5. **Bean constraint** -- k[27]=k[65] (equality) and 21 inequalities hold under the cipher model.
6. **Non-periodic key** -- Proven: no periodic key (any period 2-26) works with ANY of the 97! possible transpositions (Bean impossibility proof, E-FRAC-35).
7. **Not any single standard cipher** -- ALL classical families exhaustively eliminated (Vigenere, Beaufort, Hill, Playfair, Bifid, ADFGVX, autokey, Gromark, Quagmire I-IV, etc.).
8. **Not any standard multi-layer composition of standard ciphers** -- NSA tried "many layered systems" and failed. Three-layer Sub+Trans+Sub eliminated (E-FRAC-52). Mono+Trans+Periodic eliminated (E-FRAC-53).
9. **Destroys English frequency** -- Scheidt: "I masked the English language." IC = 0.0361 (below random). Frequency analysis and "competence with the English language" will not help.
10. **Pre-1989 knowledge base** -- "Known cryptographic solutions (at the time)." Scheidt retired December 1989.

### Soft constraints (strong evidence but not mathematical proof)
11. **"Two separate systems"** -- Sanborn's oral history, referring to "the bottom text" (K3+K4 area).
12. **"Never appeared in cryptographic literature"** -- Gillogly's characterization. A bespoke combination of known primitives, not a published algorithm.
13. **Two keywords expected** -- One is KRYPTOS. The other is unknown.
14. **Position-dependent, not state-dependent** -- Inferred from K5 sharing coded words at same positions (hypothesis, not proven).
15. **Receiver identity protection "built into the process"** -- Scheidt ACA 2013.
16. **"Solve the technique first, then the puzzle"** -- The masking/method must be identified before the message can be read.

---

## What "Systems Not Dependent on Mathematics" Actually Means

This phrase from Scheidt (Smithsonian oral history) is the most important single clue about K4's nature. In context, Scheidt taught Sanborn:
- Substitution (mathematical: mod-26 arithmetic)
- Transposition (mathematical: permutation groups)
- "Matrix codes" (mathematical: grid operations)
- **"Systems that didn't necessarily depend on mathematics"** (something else entirely)

For a man who spent 26 years at the CIA Cryptographic Center, "not dependent on mathematics" does NOT mean "no numbers involved." It means: **the security does not derive from the mathematical difficulty of inverting an algebraic function.** This is a critical distinction.

All the ciphers we have eliminated share a common trait: they can be expressed as algebraic operations over Z_26 or permutation groups. Their security properties are analyzable mathematically. Scheidt is pointing toward a different paradigm entirely.

What paradigms are "not dependent on mathematics"?

1. **Lookup-table ciphers** -- Security derives from the secrecy of an arbitrary table, not from mathematical structure. Example: codebooks, nomenclators with arbitrary assignments, one-time pads generated from a physical source.

2. **Procedural ciphers** -- Security derives from the secrecy of a multi-step PROCEDURE that involves human judgment or physical actions. Example: "read every third word from page N of book X, then use those letters as..."

3. **Physical ciphers** -- Security derives from information encoded in the physical arrangement of objects. Example: Cardan grilles, where the key is a physical mask you lay over text.

4. **Key-split ciphers** -- Security derives from combining independently meaningless fragments into a working key. No single mathematical operation defines the cipher; instead, a PROCESS of assembly does.

The common thread: **the cipher is defined by a PROCEDURE, not a FUNCTION.** You cannot write f(x) = ... for it. You can only write a sequence of steps, some of which involve arbitrary choices recorded in tables or physical objects.

---

## Candidate Method 1: Tabula Recta With Non-Standard Lookup Path (Scheidt's "Code Circle")

### Description
The Vigenere tableau is physically present on the Kryptos sculpture. Scheidt talked about medieval guild "code circles/rings fixed in place" with keyword access. The standard use of a tableau is: find the key letter's row, find the plaintext letter's column, read the intersection. But what if the lookup path is non-standard?

### Step-by-step procedure
1. Write the plaintext on the yellow pad.
2. Choose a keyword (KRYPTOS) to select starting positions on the tableau.
3. For each plaintext letter, navigate the tableau not by row/column intersection but by a **path**: move right K positions along the row, then down N positions along the column, then diagonally M positions -- where K, N, M are derived from the keyword cycle and possibly from previously encrypted letters.
4. The letter you land on after the path navigation is the ciphertext letter.
5. The "masking" step: before encryption, apply a second keyword to offset each position's starting point on the tableau, so that the effective substitution alphabet is doubly parameterized.

### Why it survives elimination
- It is NOT algebraically equivalent to Vigenere, Beaufort, or any standard polyalphabetic cipher because the lookup is path-dependent, not intersection-based.
- Path navigation on the physical tableau creates a non-linear, non-periodic mapping that cannot be expressed as k[i] = f(i) mod 26.
- It does not correspond to any published cipher family (satisfying Gillogly's "never in literature" claim).

### How to test
- Enumerate small families of "path rules" on the KA-keyed tableau: (right-N, down-M) for each keyword letter, checking if derived keys at crib positions are consistent.
- The tableau is 26x26 = 676 cells. Path rules with bounded step sizes (say, 1-5 in each direction) give ~25 * 25 = 625 rules per keyword letter.
- With 2 keyword letters cycling, this is ~625^2 = ~390K configurations per transposition assumption.

### Plausibility: 5/10
The physical tableau is right there on the sculpture, and Scheidt's "code circles fixed in place" comment directly evokes this. However, path-based lookup is unusual even for historical ciphers, and it is not clear how this specifically "masks English" as a pre-processing step. The two-system requirement is partially satisfied (the path rule is "system 1" and the keyword selection is "system 2"), but this feels like a stretch of one system rather than genuinely two separate systems.

---

## Candidate Method 2: The Key-Split Combiner (Scheidt's Professional Specialty)

### Description
This is the strongest candidate based on Scheidt's post-CIA career. The core CKM principle: a single encryption key is NEVER stored or transmitted whole. It is SPLIT into independent components from different sources, combined at encryption time, and reconstructed from the splits at decryption time. Each split by itself is meaningless.

Applied to K4: the effective key at each position is the sum (mod 26) of TWO OR MORE independently generated key streams, each derived from a different source. No single source reveals the key.

### Step-by-step procedure
1. **Source A**: The keyword KRYPTOS, cycled to length 97. This gives a periodic key stream: K=10, R=17, Y=24, P=15, T=19, O=14, S=18, K=10, R=17, ...
2. **Source B**: A second key stream derived from a DIFFERENT source -- possibly:
   - A running key from a specific text (Carter's book, a specific page)
   - A sequence derived from physical properties (coordinates, compass bearing 67.5 degrees for ENE)
   - A non-periodic sequence generated from the Kryptos tableau itself (reading specific paths through it)
   - A date-derived sequence (1986 Egypt trip, November 9 1989 Berlin Wall)
3. **Combination**: For each position i, the effective key K_eff[i] = Source_A[i] + Source_B[i] (mod 26).
4. **Encryption**: Standard Vigenere/Beaufort encryption using K_eff as the key stream.

### The masking effect
Under this model, even if you know Source A (KRYPTOS), you still see a residual key stream that looks random because Source B is unknown. Frequency analysis on (CT - Source_A) does not reveal English because you are looking at (PT + Source_B), which is still encrypted. You must identify BOTH sources to decrypt. This is precisely "I masked the English language" -- the masking IS Source B (or equivalently, Source A masks what Source B reveals).

### Why it survives elimination
- We tested KRYPTOS as a periodic key (period 7): eliminated. But that tested KRYPTOS ALONE, not KRYPTOS + another source.
- The combined key K_eff = periodic + non-periodic is itself NON-PERIODIC. Our Bean impossibility proof (E-FRAC-35) eliminates periodic keys at ALL transpositions, but a key-split key is not periodic.
- We tested running keys from specific texts under identity transposition and structured transpositions. But we never tested running key + KRYPTOS-offset, because the combination collapses to just a different running key (shifted). HOWEVER: the combination matters if the two sources use DIFFERENT alphabets (AZ vs KA) or different cipher variants (one Vigenere, one Beaufort), because then the combination is NOT a simple mod-26 sum of two streams.

### Critical insight: Cross-variant key splitting
If Source A uses Vigenere (K_A = CT - PT mod 26) and Source B uses Beaufort (K_B = CT + PT mod 26), then the combined system is:
- CT = (PT + K_A - K_B) mod 26, which is NOT equivalent to a simple running key.
- More importantly, if one source uses the KA alphabet and the other uses AZ, the combination produces a non-linear substitution that cannot be expressed as simple mod-26 arithmetic on letter indices.

### How to test
- For each candidate Source B (running key text at offset j), compute K_eff[i] = KRYPTOS_cycled[i] + B[j+i] mod 26. Check crib consistency at the 24 known positions.
- Test with KRYPTOS as Source A against all previously tested running key corpora (73.7M chars cumulative). This is essentially re-running the running key tests with a periodic offset.
- More ambitiously: test KRYPTOS + B where B is derived from the Kryptos tableau itself (e.g., read column 1, then column 2, etc.).
- Cross-variant: test with Source A under Beaufort and Source B under Vigenere (and all permutations of {Vig, Beau, VarBeau} x {AZ, KA}).

### Plausibility: 7/10
This is Scheidt's PROFESSIONAL SPECIALTY. He built an entire company (TecSec) and filed 36 patents around this exact concept. It is hand-executable: you cycle through the keyword, add the running key letter, look up the result on the tableau. It uses "two separate systems" (two key sources). It "masks English" (neither source alone decrypts). It is "not dependent on mathematics" in the sense that the security derives from the secrecy of the second source, not from mathematical complexity. The "invention that has never appeared in cryptographic literature" could be this specific two-source, two-alphabet, two-variant combination protocol.

The weakness: algebraically, under single-alphabet single-variant assumptions, this DOES collapse to a single running key (just shifted by the KRYPTOS offsets). Our existing running key tests WOULD have caught this for any text in our corpus. It only escapes detection if the cross-variant or cross-alphabet property creates genuine non-linearity, or if the second source is a text we have never tested.

---

## Candidate Method 3: The Masking Table (Arbitrary Pre-Substitution)

### Description
Scheidt explicitly stated: "I masked the English language... solve the technique first then go for the puzzle." What if the "masking" is a completely arbitrary substitution table -- not derived from any keyword or algorithm, but hand-crafted by Scheidt/Sanborn to destroy English frequency characteristics?

### Step-by-step procedure
1. **Step 1 (Masking)**: Apply an arbitrary monoalphabetic substitution to the plaintext. This substitution is recorded on the "coding charts" that were part of the $962.5K auction lot. It is designed to equalize letter frequencies (e.g., map common English letters E, T, A to uncommon ones like Z, X, Q and vice versa).
2. **Step 2 (Encryption)**: Apply a standard Vigenere/transposition cipher to the masked text using the Kryptos tableau and keyword(s).

The coding charts ARE the key to step 1. Without them, you cannot undo the mask. This is the "two systems" -- the mask and the cipher.

### Why it survives elimination
- Mono+Trans+Periodic was tested (E-FRAC-53) and ZERO candidates at discriminating periods. BUT: Mono+Trans+Running key was found to be UNDERDETERMINED (E-FRAC-54). The 13 mono degrees of freedom (one shift per known PT letter) overwhelm the key fragment analysis.
- If the mono substitution is completely arbitrary (not a simple shift by a fixed amount per letter, but a hand-crafted permutation of the alphabet), then there are 26! ~ 4 x 10^26 possible masking tables. Combined with even a simple cipher in step 2, this is an enormous space.
- The masking table is explicitly Scheidt's concept. He TOLD us about it.

### The key insight about testability
An arbitrary monoalphabetic substitution before encryption has a devastating property: it makes the cipher underdetermined even with 24 known crib positions. Here is why:

We know PT and CT at 24 positions. Under the model CT = Encrypt(Mask(PT), key):
- We need to determine Mask (26! possibilities) AND key.
- At 24 positions, we see 24 (PT, CT) pairs. The Mask converts each PT letter to a Mask letter. The key then converts each Mask letter to a CT letter.
- The 24 crib positions contain 13 distinct PT letters. For each of 13 distinct PT letters, the Mask assigns it to one of 26 possible letters. That is 26^13 ~ 2.4 x 10^18 possible partial masks.
- For EACH partial mask, the effective key at crib positions changes. The Bean constraint and other consistency checks narrow this, but with 13 degrees of freedom from the mask, the constraint system is hopelessly underdetermined.

This is EXACTLY what E-FRAC-54 found: "ALL columnar configs AND random perms produce English-range key fragments when mono-optimized."

### How to test
This is the hardest candidate to test computationally. Approaches:
- **Assume the mask is frequency-equalizing**: enumerate masks that map {E,T,A,O,I,N,S,R,H,L} to {Z,X,Q,J,V,K,W,F,B,G} (or similar low-frequency targets). This constrains the space to ~10! x 16! ~ 7.5 x 10^19 -- still huge but potentially amenable to constraint-based pruning with the 24 cribs.
- **Assume the mask is recorded on the coding charts**: then this method is fundamentally untestable without the charts. The auction buyer is anonymous.
- **Assume the mask is derivable from the sculpture**: if the Vigenere tableau itself encodes the masking table (e.g., reading a specific row/column gives the permutation), then we can enumerate all 26 rows and 26 columns as candidate masks -- only 52 options.

### Plausibility: 8/10
This is the candidate most directly supported by Scheidt's own words. "I masked the English language" is not metaphorical -- he LITERALLY applied a pre-processing step that destroys English characteristics. The "coding charts" in the auction lot are almost certainly this masking table. The method is:
- Hand-executable (look up each letter in a table)
- "Two systems" (mask + cipher)
- "Not dependent on mathematics" (an arbitrary table, not an algorithm)
- "Never in literature" (pre-masking before Vigenere is known, but using an arbitrary frequency-equalizing mask rather than a keyword-derived one is genuinely novel)
- Destroys frequency analysis (by design)
- Solvable "eventually" (if you figure out the mask exists, you can try to determine it from the 24 cribs and English language constraints)

The weakness: it may be computationally intractable without the coding charts. This would explain why it has survived 35+ years. But Sanborn says "Kryptos is available to all" and "it's solvable," so either (a) the mask is derivable from the sculpture itself, or (b) there is some other constraint that makes the mask discoverable.

---

## Candidate Method 4: Strip Cipher / Sliding Strip With Keyword-Positioned Reads

### Description
Scheidt's museum artifacts include strip cipher devices. The KL-7 ADONIS machine (a rotor/strip cipher) was the workhorse of Cold War military encryption during Scheidt's career. A strip cipher writes plaintext across a set of strips (each containing a scrambled alphabet), then reads off ciphertext from a different row.

What makes this different from a standard polyalphabetic cipher: the "strips" can be PHYSICALLY REARRANGED based on a keyword. The order in which strips are placed, and the row from which ciphertext is read, constitute two independent keys.

### Step-by-step procedure
1. Prepare 97 alphabet strips (or a smaller set recycled), each containing a scrambled alphabet. The scrambling could be the Kryptos tableau rows (26 distinct rows of the KA-keyed Vigenere tableau, recycled as needed).
2. Select strip ORDER using keyword KRYPTOS: the first strip is the K-th row of the tableau, the second is the R-th row, etc.
3. Align each strip so the plaintext letter is at the top.
4. Read ciphertext from row N (the "generatrix"), where N is determined by the second keyword.
5. The "masking" step: before step 3, apply a positional offset to each strip based on a running key, so the effective read position varies per character.

### Why it survives elimination
- A strip cipher with non-standard strip ordering and a running-key offset per position creates a key stream that is neither periodic nor expressible as a simple function.
- Standard Vigenere/Beaufort testing assumes a fixed alphabet per key letter. A strip cipher with position-dependent strip selection does NOT reduce to this.
- The "8 Lines 73" note on Sanborn's yellow pad could describe the strip layout: 8 strips of width ~12, or 8 rows and 73 columns (73 visible characters before padding to 97).

### How to test
- Use the 26 rows of the Kryptos tableau as the strip alphabets.
- Enumerate strip ordering keywords (try KRYPTOS, PALIMPSEST, ABSCISSA, and other Kryptos-associated keywords).
- For each strip ordering, try all 26 generatrix rows.
- With the ordering and generatrix fixed, check the 24 crib positions for consistency.
- Total configurations per keyword: 26 generatrix rows = 26 checks (extremely fast).
- Expand to: running-key offset per position using tested corpora.

### Plausibility: 6/10
Strip ciphers are firmly in Scheidt's professional world (KL-7, M-209). They are hand-executable (the physical device IS the algorithm). "8 Lines 73" on the yellow pad supports a grid/strip structure. However, strip ciphers are well-studied in cryptographic literature, and Gillogly's statement that the method "never appeared in cryptographic literature" argues against a standard strip cipher. It would need to be a MODIFIED strip cipher with a novel twist -- perhaps the strip selection rule is non-standard, or the generatrix selection is position-dependent.

---

## Candidate Method 5: Procedural Route Cipher Through the Physical Sculpture

### Description
The ciphertext is not read left-to-right, top-to-bottom. Instead, a PROCEDURE defines the reading order based on physical properties of the S-curved copper plate. The "cipher" is the reading order itself.

### Step-by-step procedure
1. Write the plaintext on a grid of specific dimensions (perhaps 8 rows x ~12 columns, matching "8 Lines 73").
2. Apply a standard Vigenere cipher using keyword KRYPTOS and the KA tableau.
3. Transcribe the encrypted text onto the physical copper plate in standard reading order.
4. The RECIPIENT reads the text following the S-curve of the physical plate: starting at one edge, following the curve, reversing at each bend. This physically-derived reading order IS the transposition.
5. The "masking" is the combination of the reading order and the encryption: neither alone reveals the plaintext.

### Why it survives elimination
- We have tested many structured transpositions (columnar, route, spiral, diagonal, serpentine) but all were MATHEMATICAL IDEALIZATIONS of physical reading orders. None used the ACTUAL physical geometry of the Kryptos sculpture.
- The S-curve is a continuously varying surface. The exact mapping from physical position to character index depends on the curvature radius at each point, which requires physical measurements of the actual sculpture.
- Sanborn: "I think you just have to be there to see it. No picture will let us passively guess."
- This is fundamentally untestable without precise geometric measurements of the sculpture.

### How to test
- Obtain precise geometric measurements of the Kryptos sculpture's S-curve (when the Hirshhorn reopens for Antipodes inspection, or from architectural drawings).
- Map each character position to its physical (x, y) coordinates on the curved surface.
- Generate candidate reading orders based on: constant-height paths, constant-arc-length paths, geodesic paths, fold-based reading.
- Apply inverse reading order, then test for Vigenere decryption with known keywords.

### Plausibility: 4/10
Sanborn designed the entire courtyard and the copper plate's curvature. Physical reading orders are within his artistic conception. However, this theory has a fatal problem: the USGS marker and the "two systems" clue suggest the cipher has well-defined discrete steps, not a continuous physical mapping. Also, the yellow pad shows Sanborn working with GRIDS (rows and columns), not curves. A curve-based reading order would be extremely difficult to execute precisely by hand, and errors would be unrecoverable. CIA cryptographers design systems that are ROBUST to small errors in execution; a physically-dependent transposition is the opposite.

---

## Candidate Method 6: The Coding Chart / Arbitrary Lookup System

### Description
The $962.5K auction lot contained "coding charts" that Sanborn used to encrypt K4. What if these charts are not a Vigenere tableau or any standard construct, but an ARBITRARY, HAND-DRAWN lookup system? Specifically: a set of custom tables where each table maps a position range to a specific substitution, and the tables themselves define a non-repeating, non-algorithmic cipher.

This is the "guild code ring" model: a PHYSICAL DEVICE (the charts) that you USE to encrypt/decrypt, and without the device, you cannot recover the plaintext. The security is in the OBJECT, not in mathematics.

### Step-by-step procedure
1. Sanborn has N coding charts (perhaps 8, matching "8 Lines").
2. Each chart maps a block of plaintext positions (e.g., positions 0-12, 13-24, 25-36, ...) to ciphertext via an ARBITRARY substitution table.
3. Each chart's substitution table is different, hand-crafted by Scheidt/Sanborn to destroy frequency patterns.
4. Within each block, the substitution may additionally depend on position (a different arbitrary mapping for each position within the block).
5. The "masking" is inherent: because the tables are arbitrary, no algebraic relationship exists between input and output.

### Why it survives elimination
- An arbitrary position-dependent substitution (a different random permutation at each of 97 positions) has 97 x 26! degrees of freedom -- a space so large that NO amount of crib information (24 positions) can meaningfully constrain it.
- All our elimination work assumes the cipher has STRUCTURE (periodicity, algebraic relationships, keyword derivation). An arbitrary lookup has NO structure.
- This is "not dependent on mathematics" in the most literal sense: the security is the physical secrecy of the charts.

### How to test
- This method is UNTESTABLE without the coding charts.
- The only approach: determine if the charts are derivable from the sculpture itself (e.g., reading the tableau in a specific way generates the coding charts).
- If the charts are truly arbitrary, K4 is a one-time pad with partial reuse (the same chart used for a block), and is mathematically unsolvable without the charts.

### Plausibility: 3/10
While this perfectly matches "not dependent on mathematics" and "coding charts," it violates a fundamental constraint: Sanborn says "Kryptos is available to all" and "it's solvable." A cipher secured by an arbitrary, secret, physical object is NOT solvable by the public. The coding charts must be DERIVABLE from publicly available information (the sculpture, the tableau, the known plaintext, Sanborn's clues) -- otherwise the cipher is unfair. Scheidt, as a professional, would design a system that is HARD but SOLVABLE, not one that requires possession of a secret object.

However, a WEAKER version of this theory is more plausible: the coding charts implement a SYSTEMATIC (not arbitrary) transformation that could be independently derived by someone who understands the method. In that case, the charts are a CONVENIENCE, not a necessity. This weaker version is essentially Candidate 3 (masking table) or Candidate 2 (key-split combiner).

---

## Candidate Method 7: Keyed Null Insertion + Substitution (The "73" Theory)

### Description
Sanborn's yellow pad says "8 Lines 73." If the PLAINTEXT is 73 characters and the CIPHERTEXT is 97, then 24 characters have been INSERTED. This insertion of nulls (decoy characters) is the "masking" step.

### Step-by-step procedure
1. Write the 73-character plaintext.
2. Apply a standard Vigenere cipher using keyword KRYPTOS and the KA tableau, producing 73 characters of ciphertext.
3. INSERT 24 additional characters at specific positions determined by a rule (every 4th position, at positions derived from the second keyword, etc.), producing 97 characters.
4. The 24 inserted characters are chosen to destroy frequency patterns (selected to equalize the overall distribution).

### Why it survives elimination
- All our testing assumes a 1-to-1 correspondence between CT positions and PT positions (possibly permuted). Null insertion breaks this: 24 CT positions have NO corresponding PT position.
- Bean constraint and crib scoring assume every CT position encodes a PT character. If some positions are nulls, the constraint structure changes completely.
- We proved null insertion + periodic key is "algebraically impossible" -- but that proof assumed the nulls are at KNOWN positions. If the null positions are UNKNOWN, the problem is different.
- 24 is a suspiciously significant number: it equals the number of known crib positions, the number of Weltzeituhr facets, and the number of hours in a day.

### The critical constraint
EASTNORTHEAST (13 chars) and BERLINCLOCK (11 chars) are known to be at specific positions in the PLAINTEXT. If null insertion shifted these positions, Sanborn would have had to account for the nulls when announcing crib positions. The question is: did Sanborn announce positions in the CIPHERTEXT (including nulls) or in the PLAINTEXT (excluding nulls)?

If the crib positions refer to the ciphertext-with-nulls (the physical sculpture), then the nulls are at OTHER positions and do not affect the crib alignment. There are C(73, 24) = 6.5 x 10^18 ways to distribute 24 nulls among 97 positions, but the 24 crib positions must NOT be null positions, leaving C(73, 24) ways to place nulls in the remaining 73 positions. Wait -- if 24 of 97 positions are nulls, and 24 positions are known cribs, and nulls cannot be at crib positions, then 24 nulls must be distributed among the remaining 73 positions, but only 73 - (97 - 24) = 73 - 73 = 0 non-crib non-null positions... This arithmetic does not work. Let me reconsider.

97 total positions. 24 are nulls (no PT letter). 73 are real (carry PT letters). The 24 crib positions (21-33 and 63-73) must be among the 73 real positions. So the 24 nulls are distributed among the remaining 97 - 24 = 73 positions, of which 73 - 24 = 49 are unknown PT and 24 are crib. Wait: 24 crib positions are real, so 73 - 24 = 49 additional real positions carry unknown PT. The 24 nulls are in the remaining 97 - 73 = 24 positions. These 24 null positions must be among the 97 - 24 (crib) = 73 non-crib positions, and 49 of those 73 non-crib positions are real, so 73 - 49 = 24 are null. This is consistent: exactly 24 non-crib positions are nulls, and 49 non-crib positions are real.

So the model is: C(73, 24) ~ 6.5 x 10^18 ways to choose which 24 of the 73 non-crib positions are nulls. This is large but testable with constraints: the remaining 49 + 24 = 73 real positions, when decrypted with a keyword, must produce English.

### How to test
- For each candidate null pattern (24 positions chosen from the 73 non-crib positions):
  - Remove the null characters, leaving 73 CT characters.
  - Apply Vigenere decryption with KRYPTOS (period 7) to the 73 characters.
  - Check for English characteristics (IC, quadgrams).
- The space is too large for brute force. Use constraint propagation:
  - If period-7 Vigenere is the underlying cipher, then the 73 real positions must have consistent key values at positions mapping to the same residue mod 7.
  - This means: for each residue class r (0-6), all real positions with index mod 7 = r must decrypt with the same key letter.
  - This is a STRONG constraint that prunes most null patterns.
- Alternatively: if the null positions form a pattern (every 4th, every prime, Fibonacci indices, etc.), enumerate structured null patterns.

### Plausibility: 6/10
The "8 Lines 73" note is strong evidence for a 73-character plaintext. The number 24 appearing as both null count and crib count is suspicious. Null insertion is a genuine masking technique that Scheidt would know (military message formats routinely include padding). However:
- We tested null insertion + periodic key and found it "algebraically impossible." This needs to be re-examined for the case where null POSITIONS are unknown.
- Sanborn would have had to carefully manage the null positions when announcing crib locations. This is doable but adds complexity.
- 73 characters of plaintext is SHORT for the Carter/Berlin narrative. The yellow pad drafts are longer.

---

## Candidate Method 8: The Two-Grid System (Matrix Transposition + Substitution With Separate Parameters)

### Description
"Two separate systems" interpreted literally: the plaintext is processed through TWO INDEPENDENT grids, each with its own keyword and dimensions. The first grid performs a transposition (write in rows, read in columns in keyword order). The second grid performs a substitution (the Vigenere tableau with a second keyword).

The innovation: the two grids have DIFFERENT dimensions. The transposition grid might be 8 x 13 (= 104, padding 97 to 104 with 7 nulls), and the substitution grid might be 7 x 14 (= 98, using 97 + question mark). The mismatch in dimensions means the effective cipher is NOT equivalent to a simple transposition + substitution, because characters that are in the same column of one grid are in DIFFERENT columns of the other.

### Step-by-step procedure
1. **System 1 (Transposition)**: Write PT into an 8 x 13 grid (row-wise, with 7 padding characters). Read columns in order determined by keyword 1 (e.g., KRYPTOS sorted: K=1, P=3, R=2, S=5, T=6, O=4, Y=7, giving column order 1,3,2,5,6,4,7). This produces an intermediate text.
2. **System 2 (Substitution)**: Apply Vigenere encryption to the intermediate text using keyword 2 and the KA tableau.
3. The "masking" effect: the transposition disrupts letter positions so that frequency analysis on the final CT does not reveal English, because the substitution key is applied to TRANSPOSED letters, not to the original positional sequence.

### Why it survives elimination
- We tested columnar transposition + periodic Vigenere exhaustively. But we tested specific columnar widths (5-15) with ALL column orderings. Width 13 with a 7-letter keyword (KRYPTOS) would have been tested.
- HOWEVER: if the transposition grid has PADDING (7 null characters at the end), the effective transposition is different from a standard width-13 columnar. The nulls change which positions fall in which columns.
- More importantly: if the two systems use DIFFERENT grid dimensions (e.g., transposition on an 8x13 grid, substitution indexed on a different cycle), the combined effect is non-standard.
- Width 13: at period 7 Vigenere, the BERLINCLOCK crib misses columns 9 and 10 (from CLAUDE.md: "Width 13: misses cols 9,10"). This means not all columns are constrained, leaving room for undetected solutions.

### How to test
- Re-run columnar width 13 + Vigenere period 7, specifically with KRYPTOS-ordered columns and NULL padding at the end.
- Test both the 97-char and 98-char (with question mark) variants.
- Extend to: width-13 transposition with nulls at BEGINNING (or other positions) rather than end.

### Plausibility: 5/10
"Two separate systems" is literally what this is: a transposition and a substitution, each with its own keyword. The grid dimensions could be related to "8 Lines" (8 rows in the transposition grid) and "73" (73 = number of characters in certain configurations). However, this is quite close to standard columnar + Vigenere, which we have tested extensively. The null padding adds a twist, but it is not clear that Gillogly would call this "never appeared in cryptographic literature" -- columnar transposition + Vigenere is classical.

---

## Candidate Method 9: Keyword-Derived Arbitrary Permutation (The "Shifting Matrices" Model)

### Description
Scheidt taught Sanborn "shifting matrices." What if this is not a standard transposition but a method of generating an ARBITRARY (non-columnar) permutation from a keyword? Specifically: use the keyword to seed a deterministic but non-obvious permutation generation algorithm.

### Step-by-step procedure
1. Take keyword KRYPTOS (numeric values: 10, 17, 24, 15, 19, 14, 18).
2. Use a specific algorithm to generate a length-97 permutation from these seed values. For example:
   - Start with identity permutation [0, 1, 2, ..., 96].
   - For each keyword letter K[i], swap positions (i) and (i + K[i] mod 97) in the permutation.
   - Cycle through the keyword repeatedly for multiple rounds.
3. Apply this permutation as a transposition to the plaintext.
4. Then apply Vigenere encryption with a second keyword.

### Why it survives elimination
- We tested structured transpositions (columnar, rail fence, etc.) and simple families (cyclic, affine, single swaps). But we never tested KEYWORD-DERIVED arbitrary permutations generated by a specific algorithm.
- A keyword-seeded permutation is deterministic but non-structured: it does not correspond to any classical transposition family.
- With a 7-letter keyword, the permutation is one of a relatively small number (bounded by the algorithm's structure), but the algorithm itself is unknown.

### How to test
- Enumerate keyword-to-permutation algorithms:
  - Fisher-Yates shuffle seeded by keyword values
  - Iterated swaps based on keyword cycle
  - Lagged Fibonacci index generation
  - Knuth shuffle with keyword-derived random seed
- For each algorithm and keyword (KRYPTOS, PALIMPSEST, ABSCISSA, etc.), generate the permutation, apply it, then test for Vigenere/Beaufort consistency at crib positions.
- The space is bounded by: (number of algorithms) x (number of keywords) x (number of cipher variants) = perhaps a few thousand configurations.

### Plausibility: 4/10
"Shifting matrices" could be a term for this kind of algorithmic permutation generation. It is hand-executable (a sculptor can follow swap instructions on a legal pad). However, there is no specific evidence pointing to any particular permutation generation algorithm, and "never appeared in cryptographic literature" does not obviously apply to keyword-seeded shuffles, which are a standard concept. This feels like it is trying to fit a standard idea into the "bespoke" category.

---

## Candidate Method 10: The Masking Substitution Is the Vigenere Tableau Read Differently

### Description
This is a synthesis of Candidates 1, 3, and 6. The Vigenere tableau on the sculpture IS the coding chart. But instead of using it in the standard way (row/column intersection), Scheidt invented a novel way to READ the tableau that produces the masking substitution.

### Step-by-step procedure
1. **Deriving the mask from the tableau**: Read the tableau in a non-standard way. For example:
   - Read the DIAGONAL of the tableau (positions (0,0), (1,1), ..., (25,25)) to get a 26-letter sequence. Use this as a monoalphabetic substitution.
   - Read a SPIRAL path through the tableau.
   - Read the tableau COLUMN-FIRST instead of ROW-FIRST, using a specific keyword to select which column(s) to read.
   - Use the keyword to select a STAIRCASE PATH through the tableau: start at row K, column R, move down-right for Y steps, etc.
2. **The derived sequence defines a substitution table**: Each letter A-Z maps to the letter found at a specific tableau position determined by the reading rule.
3. **Apply the derived substitution to the plaintext** (this is the masking step).
4. **Then apply standard Vigenere encryption** with the second keyword.

### Why it survives elimination
- We tested "non-standard tableau usage" (E-TABLEAU-01 to 20: column reads, rotations, paths, etc.) but all tests assumed the tableau was being used DIRECTLY as the encryption mechanism, not as a SOURCE for deriving a masking substitution applied BEFORE a second standard encryption.
- The distinction matters: using the tableau to derive a mask, then using the tableau AGAIN for standard encryption, creates a two-step process where neither step alone is standard.
- This is "the technique you need to solve first" -- the non-standard tableau reading is the technique. Once you identify it, you undo the mask and then solve the standard Vigenere.

### How to test
- Enumerate non-standard tableau reads that produce 26-letter sequences (or 26-letter permutations):
  - All 26 diagonals (main + offsets)
  - All 26 columns (already tested as direct substitution, but NOT as pre-masking)
  - Keyword-parameterized paths (KRYPTOS trace through the tableau)
  - Spiral, zigzag, and other structured reads
- For each derived mask + Vigenere decryption with KRYPTOS (or other keywords), check crib consistency.
- Total configurations: ~100 reading rules x ~10 keywords x ~3 cipher variants = ~3000. Extremely fast.

### Plausibility: 7/10
This elegantly satisfies multiple constraints:
- "Two separate systems": mask (derived from tableau reading) + cipher (standard Vigenere using same tableau)
- "Solve the technique first": identify the non-standard tableau reading
- "Never in literature": using a Vigenere tableau as a source for deriving a pre-masking substitution is genuinely novel
- "Not dependent on mathematics": the tableau reading is a PROCEDURE, not an equation
- Hand-executable: look up each letter in the derived mask, then look up the result in the standard tableau
- "Coding charts": the yellow pad charts show the DERIVED mask and possibly the reading rule
- Uses the physical sculpture: the tableau IS on the sculpture, and the reading rule may involve the physical arrangement (the S-curve might determine the reading path)
- Consistent with "IDBYROWS may not be a mistake": "ID BY ROWS" could be an instruction for HOW to read the tableau to derive the mask

The weakness: we do not know WHICH non-standard reading Scheidt used. But the space of reasonable readings is small enough to enumerate.

---

## Synthesis: Ranked Candidates

| Rank | Method | Plausibility | Testable? | Key Evidence |
|------|--------|-------------|-----------|--------------|
| 1 | **Masking Table (Candidate 3)** | 8/10 | Partially (need mask derivation rule or charts) | Scheidt's explicit "I masked the English language"; coding charts at auction; E-FRAC-54 underdetermination |
| 2 | **Tableau-Derived Mask + Vigenere (Candidate 10)** | 7/10 | Yes (~3K configs) | "Two systems"; "solve technique first"; "IDBYROWS"; tableau physically present; novel but hand-executable |
| 3 | **Key-Split Combiner (Candidate 2)** | 7/10 | Yes (re-run corpora with KRYPTOS offset) | 36 CKM patents; Scheidt's professional specialty; "two systems"; cross-variant non-linearity |
| 4 | **Null Insertion + Substitution (Candidate 7)** | 6/10 | Yes (constrained null patterns) | "8 Lines 73" = 73-char PT; 24 nulls = 24 cribs; military padding tradition |
| 5 | **Strip Cipher (Candidate 4)** | 6/10 | Yes (tableau rows as strips) | KL-7/M-209 in Scheidt's career; "8 Lines" = strip dimensions; "shifting matrices" |
| 6 | **Two-Grid System (Candidate 8)** | 5/10 | Yes (width 13 + nulls + period 7) | "Two separate systems"; "8 Lines"; grid dimensions mismatch |
| 7 | **Tableau Path Lookup (Candidate 1)** | 5/10 | Yes (~390K configs per keyword) | "Code circles fixed in place"; physical tableau; "guild" model |
| 8 | **Keyword Permutation (Candidate 9)** | 4/10 | Yes (~few thousand configs) | "Shifting matrices"; deterministic but non-standard |
| 9 | **Physical Route Cipher (Candidate 5)** | 4/10 | Blocked (need measurements) | S-curve; "be there to see it"; courtyard design |
| 10 | **Arbitrary Coding Chart (Candidate 6)** | 3/10 | No (need charts) | Auction lot; "not math"; guild model. But violates "solvable" constraint |

---

## The Most Likely Composite Theory

Based on the full evidence, the most probable K4 design is a combination of elements from the top three candidates:

**Step 1 (The Mask -- "System 1")**:
Derive a monoalphabetic substitution from the Kryptos Vigenere tableau by reading it in a non-standard way specified by the keyword KRYPTOS. This could be as simple as: for each letter L, find L in the first column of the tableau, then read across that row to the column indexed by the corresponding KRYPTOS keyword letter. This produces a non-trivial substitution that is NOT equivalent to standard Vigenere. Apply this substitution to the entire plaintext. This destroys English frequency.

**Step 2 (The Cipher -- "System 2")**:
Apply standard Vigenere encryption (or Beaufort, per the variant) using a SECOND keyword and the KA tableau, producing the final ciphertext.

**Why this works**:
- It is "two separate systems" -- the mask and the cipher.
- "Solve the technique first" -- you must discover the non-standard tableau reading to undo the mask.
- "I masked the English language" -- the mono substitution destroys frequency.
- "Not dependent on mathematics" -- the security is in the SECRET of which tableau reading produces the mask, not in mathematical complexity.
- "Never in cryptographic literature" -- using a Vigenere tableau as a codebook for deriving a pre-masking substitution is genuinely novel.
- Hand-executable -- two table lookups per character.
- "Coding charts" -- the charts in the auction lot record the derived mask for convenience.
- Solvable -- with 24 known crib positions and the constraint that the mask is a permutation (bijective), the system has enough structure to be broken by someone who realizes the mask exists and knows the underlying method is Vigenere.
- "IDBYROWS" -- literally: identify [the mask] by rows [of the tableau].

**Bean constraint satisfaction**: Under this model, the effective key at position i is Mask(PT[i]) mapped through the Vigenere key. The Bean equality k[27]=k[65] constrains the relationship between Mask(R) (since PT[27]=PT[65]=R) and the Vigenere key at those positions. Since both positions map the same PT letter (R) through the same mask, the masked letter is the same at both positions, so Bean equality depends only on the Vigenere key at positions 27 and 65. If the Vigenere key is periodic, standard Bean analysis applies to the KEY, not the masked text. This means: our existing Bean impossibility proofs for periodic keys STILL HOLD, because the mask does not change the key periodicity -- it only changes the "plaintext" that the key operates on. The mask is transparent to Bean.

**Implication**: This composite model is ONLY viable with a NON-PERIODIC key in Step 2 (e.g., a running key from an unknown text, or a key derived from the second keyword via a non-standard algorithm). With periodic key, Bean eliminates it just as it eliminates standard Vigenere.

This further constrains the model: Step 2 must use EITHER:
- A running key (from an untested text source)
- A non-periodic key derived from a short keyword via an algorithm (e.g., autokey, but autokey is eliminated by E-FRAC-37)
- A key-split combination of two sources (Candidate 2)

The most likely complete model:
1. Mask plaintext using tableau-derived monoalphabetic substitution
2. Encrypt masked text using Vigenere with a running key from a specific, as-yet-untested text

This is the intersection of Candidates 2, 3, and 10. It matches all constraints, is hand-executable, uses "two systems," masks English, is "not dependent on mathematics" (the security is in identifying the mask source and the running key text), and has "never appeared in cryptographic literature."

---

## Recommended Next Actions (Reasoning Only -- No Code)

1. **Enumerate tableau-derived monoalphabetic substitutions**: Read the KA tableau in ~100 non-standard ways (diagonals, spirals, keyword traces, "IDBYROWS" literal interpretation). For each, compute the derived 26-letter permutation.

2. **For each derived mask, test running key from all previously tested corpora**: Apply the mask to the known crib plaintext, then check if the resulting "masked cribs" match any running key offset from the 73.7M-character corpus.

3. **Test the key-split model**: For each tableau-derived mask and the KRYPTOS periodic offset, check if (CT - KRYPTOS_offset) at crib positions, when un-masked, produces consistent running key fragments.

4. **Test the null insertion model**: Enumerate structured null patterns (every 4th non-crib position, Fibonacci indices, etc.) that reduce 97 CT chars to 73 PT chars. For each, test Vigenere with KRYPTOS.

5. **Pursue the "IDBYROWS" interpretation**: If IDBYROWS means "identify by rows," test reading each of the 26 tableau rows as a monoalphabetic substitution key. This is only 26 tests.

6. **Wait for Antipodes physical measurements**: The fold theory and physical reading orders cannot be tested without sculpture geometry.

---

*This analysis is REASONING ONLY. All candidate methods require computational verification against the K4 ciphertext before any can be confirmed or eliminated.*

*Generated 2026-03-01 by cryptanalytic reasoning over the full 395+ experiment elimination landscape.*
