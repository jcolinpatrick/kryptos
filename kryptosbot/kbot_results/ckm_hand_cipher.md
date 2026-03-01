# CKM-to-Hand-Cipher Translation Analysis

**Date:** 2026-03-01
**Author:** Claude Opus 4.6 (reasoning-only analysis, no code)
**Context:** 395+ experiments, 700B+ configs, ALL NOISE. This analysis asks: what non-algebraically-reducible key derivation procedures, inspired by Scheidt's CKM patents, could produce a hand cipher that survives the elimination landscape?

---

## 0. The Reducibility Problem

The fundamental obstacle is algebraic collapse. Two periodic key sources combined additively produce a periodic key with period lcm(p_A, p_B). This is already eliminated for all periods 2-26 under ANY transposition (E-FRAC-35). Multiplication mod 26 is affine — tested and zero consistent solutions (Operation Final Vector). XOR over a 26-letter alphabet is isomorphic to addition mod 26 when letters are mapped to integers. Concatenation and interleaving of periodic sources produce periodic keys. In short: any STATIC, POSITION-INDEPENDENT, LINEAR combination of periodic sources collapses to a periodic key, which is eliminated.

To escape this, the combination function must have at least one of:
1. **State dependence** — the combination at position i depends on results from positions < i
2. **Nonlinear mixing** — the combination is not reducible to (a*x + b*y + c) mod 26
3. **Data-dependent routing** — which source contributes to which position depends on intermediate values
4. **Non-periodic source material** — at least one source is a running key or position-dependent function that is not periodic

The question is which of these Scheidt could have designed, Sanborn could have executed by hand, and would be consistent with "known cryptographic solutions at the time" assembled in "a way that has never appeared in cryptographic literature."

---

## 1. Tableau Lookup Combiner (Progressive Keyed Tableau)

### Description
Two independent keyword sources generate two key letters at each position. Instead of adding them mod 26, one selects a ROW in the Vigenere/KA tableau and the other selects a COLUMN. The intersection gives the output key character. This is conceptually a "code circle/ring" — one keyword rotates the inner ring (row selection), another rotates the outer ring (column selection).

### Step-by-step procedure
1. Keyword A = "KRYPTOS" (length 7), Keyword B = "LOOMIS" (length 6)
2. At position i: row = A[i mod 7], column = B[i mod 6]
3. Look up row A[i mod 7], column B[i mod 6] in the Vigenere tableau
4. The tableau entry is the key character K[i]
5. Use K[i] to encrypt: CT[i] = (PT[i] + K[i]) mod 26

### Algebraic reduction
In a standard Vigenere tableau, T[r][c] = (r + c) mod 26. So K[i] = A[i mod 7] + B[i mod 6] mod 26. This IS reducible to additive combination with period lcm(7,6) = 42. **ELIMINATED** — falls within periodic substitution at period 42.

### Escape: Non-standard tableau
If the tableau is NOT the standard Vigenere (i.e., not simple addition), but rather an arbitrary 26x26 Latin square (as the KA tableau on the sculpture potentially represents), then T[r][c] is an arbitrary bijection for each row. The composition is NOT reducible to addition.

The KA tableau on Kryptos uses the keyword-shifted alphabet KRYPTOSABCDEFGHIJLMNQUVWXZ. Each row is a cyclic shift of this sequence. This means T_KA[r][c] = KA[(KA_inv[r] + KA_inv[c]) mod 26], which IS still group addition (isomorphic to Z_26 via the KA permutation). So the KA tableau AS BUILT does not escape the reducibility problem.

However, if Scheidt designed a non-cyclic Latin square (a quasigroup that is not a group), then T[r][c] cannot be expressed as r + c in any re-labeling, and the resulting key is NOT periodic even when both inputs are periodic.

### Parameter space
If the tableau is known (KA): period = lcm(|A|, |B|), already eliminated.
If the tableau is unknown (arbitrary Latin square): 26! x (26!)^25 possible Latin squares — computationally intractable but ALSO not hand-constructable without a reference table.

### Plausibility: 4/10
The KA tableau on the sculpture IS a cyclic group, so this reduces to addition. An arbitrary non-cyclic Latin square would need to be written down somewhere (the coding charts?), making this hypothesis dependent on external information. Scheidt's "code circles" analogy suggests rotation (cyclic = group = reducible). However, the coding charts sold at auction could contain exactly this kind of non-standard lookup table.

---

## 2. Cascaded Keyed Permutation (Key-Dependent Transposition)

### Description
One key source determines a SUBSTITUTION key, and another key source determines a TRANSPOSITION permutation. But crucially: the transposition permutation is DERIVED from the second key source in a position-dependent way, not a static columnar ordering.

### Step-by-step procedure
1. Keyword A = "KRYPTOS" generates a repeating substitution key
2. Keyword B = "LOOMIS" generates a columnar transposition ordering
3. BUT: after substitution, the transposition is applied to BLOCKS whose boundaries or orderings depend on the substitution result
4. Alternatively: the substitution key at each position is modified by the column number the position falls into after transposition

### Why this is NOT reducible
Standard encrypt-then-transpose (or transpose-then-encrypt) with independent keys IS testable: you search over all transpositions and check for periodic key consistency in the re-ordered positions. This is exactly what FRAC/JTS did — and it was eliminated.

But if the transposition ORDER depends on the substitution KEY (or vice versa), the operations are entangled. The effective transformation is not decomposable into "fixed substitution composed with fixed transposition." Each different substitution key produces a different effective transposition, and vice versa.

### Concrete mechanism: Column-key addition
1. Write CT into a grid of width w (from keyword B)
2. Read off columns in keyword order: this gives a permuted sequence
3. At each position j in the permuted sequence, the substitution key is K_sub[j] = A[j mod |A|] + COLUMN_NUMBER(j) mod 26
4. The column number depends on the transposition, so the effective key is k[i] = A[sigma(i) mod |A|] + col(sigma(i)) where sigma is the transposition permutation

This effective key is NOT periodic in i because sigma scrambles the position-to-residue mapping. However, it is still deterministic given (A, B, w), so it has a manageable parameter space.

### What was tested and what was NOT
E-FRAC-52 tested three-layer Sub+Trans+Sub where the effective key is K1[j%p1] + K2[inv(j)%p2]. This IS a specific form of entangled key. Result: ZERO candidates at small period products. But E-FRAC-52 assumed BOTH substitution layers are periodic. If one layer uses a running key or a key derived from the transposition structure itself (e.g., column number), this was NOT tested.

E-BESPOKE-50 tested column-specific and row-specific keys with columnar transposition. Result: max 19/24 at width 6 (underdetermined). This is the closest prior test to this hypothesis.

### Parameter space
Keywords A and B (26^7 x 26^6 ~ 10^9 for these specific lengths), width w (5-15), column-key interaction function (add, multiply, lookup). Total: ~10^10 for a fixed interaction model.

### Plausibility: 6/10
This matches "two separate systems" (sub + trans), matches "shifting matrices" (columnar grid), and the key entanglement is the "novel combination" that makes it bespoke. Sanborn could execute it by hand: write into grid, read columns, apply shifted key. The obstacle is that column-specific keys at small widths were partially tested (E-BESPOKE-50) and showed underdetermination, not signal.

---

## 3. Chained Key Derivation (State Machine / Running Combiner)

### Description
The key at position i is derived from the key at position i-1 AND a keyword, creating a state machine that produces a non-periodic key sequence from periodic inputs. This is the most directly CKM-inspired model: in CKM patents, a "randomizer" introduces entropy that chains through subsequent key splits.

### Step-by-step procedure
1. Seed: K[0] = keyword_A[0]
2. Recurrence: K[i] = f(K[i-1], keyword_A[i mod |A|], keyword_B[i mod |B|])
3. Where f is a non-linear function, e.g.:
   - K[i] = (K[i-1] + A[i mod |A|]) mod 26, then look up in a tableau indexed by B[i mod |B|]
   - K[i] = T[K[i-1]][A[i mod |A|]] + B[i mod |B|] mod 26
   - K[i] = (K[i-1] * A[i mod |A|] + B[i mod |B|]) mod 26

### Why this is NOT reducible
Any recurrence of the form K[i] = g(K[i-1], i) with period-dependent input produces a sequence that is NOT periodic unless g happens to be linear and the modular arithmetic creates a cycle. Non-linear g (especially tableau lookups or multiplicative terms) generates pseudo-random sequences from short seeds.

### What was already eliminated
- E-FRAC-37: Autokey (K[i] depends on PT[i-1] or CT[i-1]) — ELIMINATED, cannot reach 24/24.
- E-FRAC-38: Progressive key (K[i] = K[0] + i*delta) — BEAN-ELIMINATED. Quadratic, Fibonacci — BEAN-ELIMINATED.
- Gromark/Vimark (linear recurrence) — ELIMINATED via linear algebra (E-JTS-08/11).

### What was NOT eliminated
The tested recurrences are all LINEAR (additive, affine, linear recurrence mod 26). A NON-LINEAR recurrence — specifically one involving a tableau lookup where the row depends on K[i-1] and the column depends on a periodic keyword — was NOT tested. This is because non-linear recurrences over Z_26 are not amenable to the algebraic proofs used in E-FRAC-35/37/38 or the linear algebra in E-JTS-08/11.

### Concern: K5 position-dependence hypothesis
If K5 shares coded words at the same positions as K4, a state-dependent cipher requires identical preceding plaintext in both messages to produce identical coded words — which is extremely unlikely for different messages. This would eliminate all state machines. However, this is classified as [HYPOTHESIS], not proven fact. If K5's "shared coded words at same positions" means shared KEY values at those positions (which a key-only state machine would produce regardless of plaintext), this objection vanishes.

### Parameter space
Seed (26 options) x keyword_A (26^k for length k) x keyword_B (26^m for length m) x function family. For keywords of length 5-8 and ~10 candidate functions: ~26^15 x 10 ~ 10^22. This is large but can be constrained: the 24 known key values at crib positions impose 24 constraints on the recurrence. For a recurrence with 2 parameters per step (keyword values), 24 constraints on 97 positions is significantly constraining.

### Plausibility: 7/10
This is the strongest CKM parallel. CKM literally chains key splits through a state machine with a randomizer. Scheidt's expertise in SIGINT (exploiting Soviet cipher machines that ARE state machines) makes this natural. The "guild code circle" analogy works: the circle rotates at each step (state update), and the keyword determines how much (periodic input). Sanborn could execute it with a tableau and two keywords. The K5 objection is real but conditional on an unproven hypothesis.

**Critical distinction from eliminated recurrences:** The linear recurrences (Gromark, progressive, quadratic, Fibonacci) were eliminated because the Bean constraints and crib algebra are solvable for linear systems. A non-linear recurrence (involving modular multiplication, tableau lookup, or conditional branching) does not yield to these algebraic methods. The key insight is that Scheidt would have known the difference between a linear and non-linear keystream generator from his SIGINT work.

---

## 4. Key-from-Ciphertext Feedback (Cipher Feedback / Output Feedback)

### Description
The key at position i depends on the ciphertext produced at position i-1 (CFB mode) or the key output at position i-1 (OFB mode). This creates a data-dependent keystream where the key cannot be precomputed without knowing the ciphertext.

### Step-by-step procedure (CFB-like)
1. Initial key K[0] from keyword[0]
2. K[i] = T[CT[i-1]][keyword[i mod |keyword|]]
   where T is the KA tableau and CT[i-1] is the ciphertext character just produced
3. CT[i] = (PT[i] + K[i]) mod 26

### Why this is NOT reducible
The keystream is a function of the ciphertext, which is a function of the plaintext AND all preceding keystream values. This creates a nonlinear system of 97 equations in 97 unknowns (the plaintext characters) parameterized by the keyword. It cannot be decomposed into a periodic key or a transposition.

### What was already eliminated
- CT-autokey (K[i] = CT[i-1]) — tested in E-FRAC-37, max 21/24. But this is LINEAR autokey with no keyword mixing.
- PT-autokey — max 16/24.

### What was NOT eliminated
Autokey with a NON-LINEAR mixing function (tableau lookup of CT[i-1] against a keyword character) was NOT the model tested in E-FRAC-37. E-FRAC-37 tested K[i] = CT[i-1] (direct) and K[i] = PT[i-1] (direct), both under additive Vigenere. A model where K[i] = T[CT[i-1]][keyword[i mod p]] is a DIFFERENT cipher — it is neither pure autokey nor pure periodic substitution. The tableau T introduces a non-linear mixing that changes the constraint algebra.

### K5 compatibility
This model IS problematic for K5. If K5 has different plaintext but shares coded words at the same positions, the ciphertext feedback would diverge after any position where the plaintexts differ. Unless the shared coded words are specifically at positions where the preceding ciphertext is also identical (which would require careful construction), this is unlikely.

However: if the feedback uses OUTPUT key values (OFB mode) rather than ciphertext, the keystream is deterministic from the seed + keyword alone. This preserves K5 compatibility while retaining the non-linear state evolution.

### Parameter space
Keyword (26^k for length k, say k=5-8) x seed (26) x tableau choice (KA or other) x feedback mode (CFB, OFB, or variant). For keyword lengths 5-8: ~26^9 x 4 ~ 10^13. Constrainable by crib equations.

### Plausibility: 5/10
CFB/OFB modes are standard in modern cryptography but were NOT standard in classical hand ciphers as of 1989. However, Scheidt's CIA background includes electronic cipher machines that DO use feedback modes (KL-7 ADONIS, for example). The translation to a hand cipher is awkward — the encipherer must look up each ciphertext/key output in a tableau before proceeding to the next character, making the process inherently sequential and slow. Sanborn described working from a yellow pad, which is consistent with sequential computation. But the K5 issue (under CFB) and the departure from "known cryptographic solutions" (this IS in the literature) reduce plausibility.

---

## 5. Split-Key Tableau Selection (Polyalphabetic with Key-Dependent Alphabet Selection)

### Description
Instead of one Vigenere tableau, there are N different substitution alphabets (e.g., N=2 or N=4). One key source selects WHICH alphabet to use at each position. Another key source selects the shift within that alphabet. The effective cipher is polyalphabetic, but the alphabet itself changes in a pattern determined by a second keyword.

### Step-by-step procedure
1. Keyword A = "KRYPTOS" determines the shift (standard Vigenere key)
2. Keyword B = "BERLIN" determines the alphabet: if B[i mod 6] is in {A-M}, use KA alphabet; if in {N-Z}, use AZ alphabet
3. CT[i] = alphabet_select(B[i mod 6])[shift(A[i mod 7], PT[i])]

### Why this is NOT reducible
Under a standard Vigenere with one alphabet, CT = (PT + K) mod 26 regardless of the alphabet used (because the KA alphabet is still a cyclic group). But if the alphabets are NOT cyclic permutations of each other — e.g., one is KA and the other is an arbitrary derangement — then the two-alphabet cipher is NOT equivalent to any single polyalphabetic cipher.

Concretely: if alphabet 1 is KRYPTOSABCDEFGHIJLMNQUVWXZ and alphabet 2 is some other ordering where the same shift value maps letters differently, then the effective substitution at each position depends on BOTH keywords in a way that cannot be compressed to a single periodic key.

### What was already eliminated
E-TABLEAU-21 tested KA, PALIMPSEST, and ABSCISSA keyed alphabets with columnar transposition and running key. All eliminated. But this tested ONE alphabet at a time, not alternation between multiple alphabets.

Quagmire I-IV were tested (uses keyword-mixed alphabets with periodic keying). These are specific instantiations of the split-key-tableau idea, but they use a FIXED mapping from key letter to alphabet row. The novel element here is that a SECOND keyword controls which alphabet FAMILY is active.

### Parameter space
Number of alphabets N (2-4) x alphabet definitions (26! each) x keyword A (26^k) x keyword B (26^m) x selection rule. With known alphabets (KA, AZ, reverse): N=2-3, keywords 5-8 chars, ~10^12 configs. With unknown alphabets: intractable.

### Plausibility: 5/10
Matches "shifting matrices" (multiple tableaux), matches "coding systems that could be modified in myriad ways" (parameterized by two keywords and alphabet choice), matches "two separate systems" (two independent key sources controlling different aspects of the cipher). But the KA and AZ alphabets are both cyclic groups over Z_26, so alternating between them IS reducible to a single key schedule (just two different additive constants). The model only escapes reducibility with genuinely non-cyclic alphabets, which would need to be written down — again pointing to the coding charts.

---

## 6. Masking Layer + Simple Cipher (Pre-Processing Combiner)

### Description
This is the most literally faithful reading of Scheidt's statements. The plaintext is PRE-PROCESSED (masked) before a simple cipher is applied. The masking layer destroys English frequency characteristics. The cipher layer may be something already eliminated AS A STANDALONE CIPHER — but after masking, the intermediate text looks like random letters, so frequency-based discrimination fails.

The critical insight: if the mask is a substitution (e.g., a simple monoalphabetic cipher or a keyed permutation of the alphabet), then MASK + VIGENERE = VIGENERE (with a different key). This is the algebraic collapse problem. The mask must be something OTHER than a letter-by-letter substitution to avoid collapse.

### Non-collapsing mask candidates

**6a. Null insertion / character expansion**
Insert null characters at deterministic positions (derived from a keyword) before encrypting. The 97 CT characters do NOT map 1-to-1 to 97 PT characters; some CT positions are nulls whose PT is meaningless. The real plaintext may be only 70-80 characters, with 17-27 nulls inserted at keyword-determined positions.

- **Non-reducible?** YES. No prior test accounts for nulls. All tests assume 97 PT characters. If, say, every 5th position is a null, the real cipher operates on ~78 characters with a different positional alignment.
- **Testable?** The null positions would need to be guessed. With 97 choose k null positions (k = 10-20), the space is ~10^14 to 10^20. But the cribs constrain this heavily: positions 21-33 and 63-73 are known plaintext, so no nulls can be at those positions. This leaves ~73 candidate positions for nulls.
- **Hand-executable?** Yes — Sanborn inserts random letters at marked positions before encrypting.
- **K5 compatible?** Yes — same null pattern, different message.
- **Parameter space:** ~2^73 null patterns (reduced by constraints to maybe 2^50) x keyword x cipher variant.
- **Plausibility: 7/10.** Matches "I masked the English language" literally. Matches "solve the technique first [identify nulls] then the puzzle [decrypt]." Matches non-mathematical ("systems not dependent on math" — inserting nulls is procedural). DOES NOT match the Bean constraint analysis, which assumes K4 has 97 meaningful characters. If some are nulls, Bean's constraints on positions 27 and 65 may involve null positions, invalidating the entire elimination framework. THIS IS THE MOST DANGEROUS HYPOTHESIS because it undermines the foundational assumption of all 395+ experiments.

**6b. Phonetic respelling / abbreviation**
Before encrypting, rewrite the English plaintext in a coded shorthand: drop vowels, use phonetic abbreviations (TH → T, ING → G), military brevity codes. The "masked" intermediate text has non-English letter frequencies.

- **Non-reducible?** Yes — the intermediate text is a different LENGTH and different letter distribution than English.
- **Testable?** Extremely difficult. The respelling rules are arbitrary and not enumerable.
- **Hand-executable?** Yes — this is literally how military message traffic was prepared.
- **Plausibility: 4/10.** The known plaintext includes full English words (EASTNORTHEAST, BERLINCLOCK), not abbreviations. This suggests the plaintext IS standard English, making phonetic masking unlikely. However, it's possible the crib words are spelled out while non-crib words are abbreviated.

**6c. Columnar rearrangement of plaintext before substitution**
The plaintext is written into a grid and read off in a different order BEFORE the substitution cipher is applied. This IS a transposition + substitution composition — exactly what has been tested extensively. However, there is a subtle distinction: in all prior tests, the transposition was applied to the CIPHERTEXT (or equivalently, the inverse transposition was applied to the plaintext). If the process is:
1. Transpose plaintext (using keyword B to determine reading order)
2. Substitute the transposed text (using keyword A for Vigenere)
3. Output the result AS-IS (no further transposition)

Then the search needs to check if TRANS(PT) + periodic_key = CT, which is equivalent to PT = INV_TRANS(CT - periodic_key). This IS what FRAC tested. So this model is ALREADY ELIMINATED for structured transpositions + periodic keys. The only open case is: structured transposition + running key (E-FRAC-54: UNDERDETERMINED for mono + trans + running key).

### Plausibility summary for Section 6
The null insertion hypothesis (6a) is the most concerning because it invalidates the positional assumptions underlying ALL prior work. If even 5-10 positions are nulls, the crib positions shift, Bean constraints change, and the entire elimination edifice crumbles.

---

## 7. Physical Coordinate Key Derivation

### Description
One key source is a keyword. The other is a measurement taken from the physical sculpture itself — distance along the S-curve, row number in the tableau, angular position of a letter on the curved surface. The physical measurement is inherently non-periodic and non-algebraic.

### Step-by-step procedure
1. Keyword A = "KRYPTOS" provides a periodic substitution key
2. For each character position i, measure the physical distance d(i) from some reference point on the S-curve (e.g., in centimeters, or in number of character cells)
3. K[i] = (A[i mod 7] + f(d(i))) mod 26, where f maps physical distance to a value 0-25

### Why this is NOT reducible
The physical distances d(i) are determined by the sculpture's geometry. The S-curve is NOT periodic — it bends, and character spacing may vary. So f(d(i)) is a running key derived from geometry, and the combined key is non-periodic.

### What was already tested
Operation Final Vector tested "physical transpositions" (spiral, serpentine, column-first, block reverse, diagonal, skip, rail fence) — all NOISE. But these tested physical READING ORDERS as transpositions, not physical MEASUREMENTS as key sources.

### What was NOT tested
No experiment has used the actual physical dimensions of the Kryptos sculpture to generate key values. This is because precise measurements are not publicly available. The S-curve shape is known approximately from photographs, but centimeter-level measurements would be needed.

### Parameter space
Keyword A (26^k) x reference point (97 options) x distance metric (arc length, straight line, angular) x mapping function f (linear, modular, lookup). If physical measurements were available: ~10^8 configs.

### Plausibility: 3/10
Scheidt's "systems not dependent on mathematics" could mean physically-derived keys. But this requires Sanborn to have measured the sculpture precisely and used those measurements as key values — an extraordinarily tedious process for 97 characters. More importantly, how would a SOLVER reproduce the measurements? Sanborn has said "Kryptos is available to all" — implying the method can be verified without physical access. This largely rules out measurement-dependent methods. (However, the Hirshhorn Antipodes replica suggests physical inspection IS part of the intended solving process.)

---

## 8. Straddling Substitution with Alphabet Recombination

### Description
Inspired by the straddling checkerboard (used in VIC cipher), but adapted to produce 26 letters instead of digits. Two key sources define a two-phase substitution: first, map each plaintext letter to a pair of coordinates using one key. Then, recombine the coordinates using a second key to produce a single ciphertext letter.

### Step-by-step procedure
1. Key source A defines a Polybius-like grid: 26 letters arranged in a 2-row structure (e.g., 8 frequent letters in row 0, 18 others in rows 1-2, as in a straddling checkerboard)
2. Each PT letter maps to either 1 coordinate (frequent) or 2 coordinates (infrequent)
3. The coordinate stream is then re-parsed into letters using Key source B's mapping
4. The output length MAY DIFFER from input length (variable-length encoding)

### Why this is NOT reducible
The variable-length encoding means position i in the ciphertext does NOT correspond to position i in the plaintext. This breaks the fundamental assumption of all prior work (direct positional correspondence for substitution, or permuted positional correspondence for transposition).

### Already eliminated?
E-FRAC-21 structurally eliminated ALL fractionation families, including straddling checkerboard. The proof: K4 uses all 26 letters (straddling checkerboard produces digits 0-9, not letters). Also, straddling checkerboard produces VARIABLE LENGTH output (97 PT chars would produce more or fewer than 97 CT chars).

BUT: If the straddling step is followed by a RECOMBINATION that maps digit pairs back to letters, and if the variable-length intermediate is padded or truncated to exactly 97 characters, the structural argument breaks. This is a "modified straddling" that Scheidt could have invented — it uses the PRINCIPLE of straddling (two-phase substitution with variable-length intermediary) but produces a fixed-length, all-alphabetic output.

### Parameter space
Grid layout (26! / symmetries ~ 10^20) x recombination table (10^2 → 26 mapping ~ 26^100, but constrained) x padding rule. Effectively intractable without significant constraints.

### Plausibility: 3/10
The VIC cipher (which uses straddling checkerboard) was developed by Soviet intelligence in the 1950s and would have been known to Scheidt from his SIGINT career. But the structural arguments from E-FRAC-21 are strong: any fractionation system that expands then compresses must lose information, which is incompatible with a deterministic cipher. The padding/truncation issue also makes hand execution error-prone. Low plausibility.

---

## 9. Key-Split with Transposition-Dependent Lookup (The "Shifting Matrix" Model)

### Description
This is the model I consider most consistent with ALL of Scheidt's statements. It combines the CKM split-key concept with "shifting matrices" and "systems not dependent on mathematics."

### The core idea
The encryption is performed using a PHYSICAL GRID (matrix) that contains substitution mappings. The grid is keyed by one keyword (which determines the alphabet arrangement). The grid is SHIFTED (rotated, offset) at each position by a value derived from a second keyword. The shift may be horizontal (column offset) or vertical (row offset) or both.

### Step-by-step procedure
1. Construct a tableau: 26 rows x 26 columns, keyed by keyword A ("KRYPTOS"). This is the KA tableau on the sculpture.
2. For each position i:
   a. Compute row from plaintext letter PT[i] (look up in left column of tableau)
   b. Compute column from keyword B letter B[i mod |B|] ("BERLIN", say)
   c. But BEFORE looking up: SHIFT the tableau by an amount derived from a third source:
      - The shift could be: position number i itself (progressive)
      - The shift could be: keyword C[i mod |C|]
      - The shift could be: the previous ciphertext character CT[i-1]
   d. The shifted tableau produces a different output than the unshifted tableau
   e. CT[i] = shifted_tableau[row][column]

### Why this is NOT reducible
If the shift amount is derived from position number: this is a progressive key ADDED to the Vigenere key. Progressive key is Bean-eliminated (E-FRAC-38). REDUCIBLE.

If the shift amount is derived from a third periodic keyword: this is three periodic keys added. Still periodic. REDUCIBLE.

If the shift amount is derived from CT[i-1] (feedback): this is the CFB model from Section 4. Non-linear if the shift is a tableau lookup rather than addition. POTENTIALLY NON-REDUCIBLE — depends on the shift mechanism.

If the shift amount is derived from a NON-STANDARD function of position (e.g., the position's coordinates when the text is written into a grid of width w): this is position-dependent keying after transposition. Tested for standard functions (periodic, progressive, quadratic, Fibonacci) but NOT for grid-coordinate-dependent shifts.

### The most promising variant: Row-Column Cross-Keying
1. Write plaintext into a grid of width w (keyword B determines width and column order)
2. For each cell at grid position (row r, column c):
   - Substitution key = A[c mod |A|] + r (the row number added to the keyword value)
   - CT_cell = (PT_cell + key) mod 26
3. Read the grid off in standard order to produce ciphertext

In this model, the effective key at flat position i is:
- K[i] = A[sigma(i) mod |A|] + floor(sigma(i) / w)
where sigma is the transposition permutation induced by the columnar writing/reading.

This is NOT periodic because floor(sigma(i)/w) depends on the transposition in a non-periodic way. It is NOT a standard transposition + periodic substitution (which E-FRAC tested) because the row number introduces an additive shift that varies across the grid.

### What was already tested
E-BESPOKE-50 tested "row-specific keys" — where each row of a grid has a different additive shift. Result: max 19/24 at width 6 (underdetermined). This IS the closest test to this model. But E-BESPOKE-50 used independently optimized row shifts, not row shifts derived from a simple rule (shift = row number). The parameter space of "shift = c * row_number mod 26 for c in 0-25" with width w and keyword A is much smaller and may not have been tested.

### Parameter space
Keyword A (26^k for k=5-8) x width w (5-15) x keyword B (26^m for m=5-8) x row-shift multiplier c (0-25) x variant (Vig/Beau/VarBeau). Total: ~26^15 x 11 x 26 x 3 ~ 10^22. But the 24 crib constraints are very restrictive on this model: given w and the column ordering, the crib positions map to specific (row, column) coordinates, and the key values at those positions are determined by A and c. This should reduce the effective search to ~10^8 or less per width.

### Plausibility: 8/10
This is my highest-rated model. Here is why:
- **"Shifting matrices"**: The matrix (tableau) shifts by the row number. Literally a shifting matrix.
- **"Two separate systems"**: The columnar transposition IS one system; the row-shifted Vigenere IS the other.
- **"Systems not dependent on mathematics"**: The row number is a PHYSICAL property of the grid layout, not an algebraic formula. You read it off the pad.
- **"Masking"**: The row-dependent shift destroys the periodic structure that frequency analysis exploits.
- **"Code circles fixed in place"**: The tableau is fixed; the row offset rotates it.
- **"Known cryptographic solutions assembled in a new way"**: Columnar transposition and Vigenere are both "known." Using the row number as an additive key component is the "invention."
- **"Receiver identity protection"**: The width w and column ordering could encode the recipient's identity.
- **Hand-executable**: Write into grid, encrypt each cell with keyword + row offset, read off. Yellow pad.
- **CKM parallel**: Key = keyword_value + row_number. Two independent sources combined additively, but the row number is NOT periodic in the flat reading order because the transposition scrambles which row each position came from.
- **Not tested**: The specific model "columnar transposition + Vigenere key + row*c shift" was not systematically swept.
- **K5 compatible**: Same grid width, same keyword, same row-shift rule. Different plaintext produces different ciphertext but the KEY at any given grid cell is identical.

---

## 10. Summary Ranking

| # | Model | Reducible? | Already Eliminated? | Hand-Executable? | Matches Scheidt Statements? | Plausibility |
|---|-------|-----------|--------------------|-----------------|-----------------------------|-------------|
| 1 | Tableau Lookup (standard) | YES (cyclic group) | YES | Yes | Partially | 4/10 |
| 2 | Cascaded Keyed Permutation | Partially | Partially (E-BESPOKE-50) | Yes | Yes | 6/10 |
| 3 | Chained Key Derivation (non-linear) | NO | NO (only linear tested) | Somewhat | Yes (CKM core) | 7/10 |
| 4 | CF/OF Feedback | NO | NO (only linear autokey) | Awkward | Partially | 5/10 |
| 5 | Split-Key Tableau Selection | Depends on alphabets | NO | Yes | Yes | 5/10 |
| 6a | Null Insertion Mask | NO | NO (breaks all assumptions) | Yes | Yes ("masking") | 7/10 |
| 6b | Phonetic Respelling | NO | NO | Yes | Contradicted by cribs | 4/10 |
| 6c | Trans-then-Sub | YES | YES (FRAC) | Yes | Yes | 3/10 |
| 7 | Physical Coordinate Key | NO | NO (no data) | Tedious | "Not math" | 3/10 |
| 8 | Straddling Recombination | NO | Mostly (E-FRAC-21) | Error-prone | Partially | 3/10 |
| 9 | Row-Column Cross-Keying ("Shifting Matrix") | NO | NO (closest: E-BESPOKE-50, partial) | YES | YES (strongest match) | **8/10** |

---

## 11. Recommended Next Steps

### Priority 1: Row-Column Cross-Keying Sweep (Model 9)
Systematically test: for each columnar width w in {5-15}, for each column ordering (exhaustive for w<=9, sampled for w>9), for each keyword A of length 5-8, for each row-shift multiplier c in {1-25}, compute the effective key at the 24 crib positions and check for consistency with the keyword + row*c model. This is a constrained algebraic test, not a brute-force sweep. The 24 crib equations should admit at most a few solutions per (w, ordering), making this computationally cheap.

**Key algebraic structure:** At crib position p, the effective key is:
```
k[p] = A[col(sigma(p)) mod |A|] + c * row(sigma(p))  (mod 26)
```
where sigma is the columnar transposition permutation, col() and row() give the column and row of the position in the grid, and A is the repeating keyword. Given 24 known k[p] values (from the cribs), this is a system of 24 equations in (|A| + 1) unknowns (the keyword characters + the multiplier c). For |A| = 7, that's 8 unknowns and 24 equations — heavily overdetermined. Most (w, ordering) pairs should produce ZERO solutions, making this a fast filter.

### Priority 2: Non-Linear Chained Key (Model 3)
Test recurrences of the form K[i] = T[K[i-1]][A[i mod p]] where T is the KA tableau. For each keyword A of length 5-8 and each seed K[0] in {0-25}, generate the full 97-character keystream and check against the 24 known key values. This is ~26^9 ~ 10^13 configs, which requires intelligent pruning (early termination when k[21] fails).

### Priority 3: Null Insertion (Model 6a)
This requires careful thought, not brute force. If nulls exist, the crib positions in the PLAINTEXT are different from the crib positions in the CIPHERTEXT. Test: for each number of nulls n in {5, 10, 15, 20}, enumerate null patterns that place no nulls at positions 21-33 or 63-73, compute the adjusted plaintext positions, and re-run the standard cipher tests with the adjusted alignment.

### Priority 4: Non-Linear Feedback (Model 4, OFB variant)
Test OFB mode: K[i] = T[K[i-1]][A[i mod p]], CT[i] = (PT[i] + K[i]) mod 26. This is identical to Model 3 (the keystream is independent of plaintext), so Model 3 testing covers both.

---

## 12. The Meta-Observation

The CKM concept at its core is: **the key is not stored; it is COMPUTED from independent sources at the moment of use.** The "novel invention" attributed to Scheidt is not a new cipher — it is a new KEY DERIVATION PROCEDURE applied to a known cipher primitive.

Every prior experiment tested known key derivation procedures (periodic, progressive, recurrence, autokey, running key) applied to known cipher primitives (Vigenere, Beaufort, transposition). What was NOT tested is a key derivation procedure where the key at each position depends on STRUCTURAL properties of the encipherment process itself — specifically, the position's location within a physical grid (row number, column number, distance from a corner).

The "shifting matrix" model (Model 9) is the most natural hand-cipher translation of this CKM concept. The key is COMPUTED at each position from:
- Source 1: the keyword letter for that column (periodic within the grid)
- Source 2: the row number (a structural property of the grid layout)

Neither source alone determines the key. Both are needed — the defining property of a key split. The combination is additive, but the resulting flat keystream is NOT periodic because the transposition scrambles the row-column assignments. This is the algebraic non-reducibility that survives the elimination landscape.

Scheidt's CKM patents describe exactly this architecture: independent generators whose outputs are combined. His "code circle" analogy describes exactly this operation: a fixed device (the tableau) that produces different outputs depending on two independent inputs (keyword position and physical row). And Sanborn's execution on a yellow pad matches perfectly: write the plaintext into a grid, encrypt each cell using the keyword letter for that column PLUS the row number, then read off the result.

This is, to the best of my analysis, the most plausible CKM-to-hand-cipher translation that survives the elimination landscape.

---

*Classification: [HYPOTHESIS] — All models presented are untested hypotheses. None has been validated against the K4 ciphertext. The recommended experiments in Section 11 would either confirm or eliminate each model.*
