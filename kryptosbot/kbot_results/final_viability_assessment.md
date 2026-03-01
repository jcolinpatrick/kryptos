# Final Viability Assessment: Remaining Computationally Testable Hypotheses for K4

**Date**: 2026-03-01
**Author**: Cryptanalytic reasoning agent (Claude Opus 4.6)
**Context**: 375+ experiments, 669B+ configurations, ALL NOISE. Complete review of elimination_tiers.md, final_synthesis.md, audit_matrix.md, research_questions.md, all experiment scripts, KryptosBot reasoning outputs, Scheidt/Sanborn primary sources.

---

## Executive Summary

After exhaustive review of the elimination landscape, I identify **7 computationally testable hypotheses** that have genuinely NOT been covered. I also identify **4 hypotheses that appear untested but are actually eliminated by existing proofs** (common misconceptions). Finally, I conclude with an honest assessment of what remains blocked.

The uncomfortable truth: the computationally testable gap is narrow. Most remaining hypotheses are either (a) blocked on external information, or (b) underdetermined -- meaning they cannot be distinguished from noise even with unlimited compute. The strongest testable hypotheses cluster around a single theme: **tableau-derived pre-masking substitution combined with a non-periodic key**, which is the only model simultaneously consistent with Scheidt's statements, the elimination landscape, and the constraint structure.

---

## SECTION A: Genuinely Untested and Computationally Testable

### Hypothesis 1: Tableau-Derived Monoalphabetic Mask + Running Key (Two-Step Decryption)

**Exact model**: PT_original -> Mono_mask(PT) -> Vigenere/Beaufort(masked_PT, running_key) -> CT.
The monoalphabetic mask is derived from the KA Vigenere tableau by a non-standard reading rule. The running key comes from an unknown text. The cribs (EASTNORTHEAST, BERLINCLOCK) appear in the intermediate "masked PT" layer, NOT in the original English.

**Why not already eliminated**:
- E-FRAC-54 proved Mono+Trans+Running key is UNDERDETERMINED when the mono mask is a free variable. But E-FRAC-54 tested this with ARBITRARY mono masks (13 DOF). It did NOT test masks specifically derived from the physical Kryptos tableau.
- E-TABLEAU-01 to 20 tested non-standard tableau reads as DIRECT encryption mechanisms. They did NOT test tableau reads as sources for a PRE-MASKING substitution applied BEFORE a separate encryption step.
- The distinction is critical: "tableau as cipher" was eliminated; "tableau as mask source + separate cipher" was NOT tested.
- Under this model, the 26 rows of the KA tableau each define a monoalphabetic substitution. Only 26 possible masks exist from row reads (or ~100 from diagonals, spirals, etc.). Combined with the running key constraint, this is a small enough space to enumerate.

**Specific test**:
1. For each of 26 tableau rows (and ~50 other structured reads: diagonals, reverse diagonals, column reads, keyword-traced paths), derive a 26-letter substitution.
2. Apply the inverse mask to the known cribs: masked_crib[i] = Mask_inverse(PT[i]) for each crib position.
3. Compute the implied running key: rk[i] = (CT[i] - masked_crib[i]) mod 26 (Vigenere) or (CT[i] + masked_crib[i]) mod 26 (Beaufort).
4. Check: does the running key at the 24 crib positions satisfy Bean EQ and all 21 Bean INEQs? (The mask is transparent to Bean when it is a fixed permutation, because Bean depends on key equality/inequality, and the mask applies the same function to both PT[27] and PT[65] since PT[27]=PT[65]=R.)
5. For masks that survive Bean: compute the EAST constraint diffs on the running key fragment and scan the full 73.7M tested corpus for matches.
6. Also test against untested text sources: additional Howard Carter editions, specific le Carre passages.

**Parameter space**: ~100 mask derivations x 3 variants x 73.7M corpus offsets = ~22B checks (parallelize trivially). The EAST filter (P(false positive) ~ 8.4e-8 per position) reduces this to ~1.8 positions expected per mask, which is near-zero.

**Feasibility**: Hours on a single machine. The EAST constraint filter is extremely powerful.

**Plausibility**: 7/10. This is the ONLY model that simultaneously satisfies:
- "I masked the English language" (Scheidt, WIRED 2005) -- the mask IS the masking step.
- "Solve the technique first then the puzzle" -- identify the tableau reading rule first.
- "Two separate systems" (Sanborn) -- mask + cipher.
- "IDBYROWS may not be a mistake" (Scheidt) -- literal instruction: identify [the mask] by [reading] rows [of the tableau].
- The tableau is physically present on the sculpture and accessible to all.
- Bean impossibility proof still holds for periodic keys even with the mask (the mask is transparent to Bean).
- Running key is the only structured non-periodic model surviving Bean (E-FRAC-38).

**Why it might fail**: The running key text may not be in our corpus. The mask derivation rule may be more complex than simple row/diagonal reads.

---

### Hypothesis 2: Null Insertion at Structured Positions + Period-7 Vigenere (The "73" Theory)

**Exact model**: The original plaintext is 73 characters. 24 null characters are inserted at structured positions (not crib positions), producing 97 CT characters. The 73 real characters are encrypted with Vigenere using keyword KRYPTOS (period 7). The nulls are chosen to equalize overall letter frequency.

**Why not already eliminated**:
- E-SOLVE-09 explored this hypothesis and E-SOLVE-10 proved that null insertion does NOT rescue periodic keys WITHIN the crib blocks (because ENE and BC are contiguous, so within-block spacing is invariant).
- HOWEVER: E-SOLVE-10 proved within-crib periodicity is preserved, but it did NOT test all null patterns for CROSS-BLOCK consistency. The key question is: can the 24 nulls be distributed such that the reduced positions of ENE and BC are BOTH internally consistent AND mutually consistent at period 7?
- Specifically: the ENE block has 13 consecutive positions (21-33), all non-null. The BC block has 11 consecutive positions (63-73), all non-null. Between them (positions 34-62), some positions are null. The number of nulls in this gap determines the reduced position offset between ENE and BC. For period 7, we need: (reduced_pos(63) - reduced_pos(21)) mod 7 to produce consistency.
- E-SOLVE-10's proof holds for within-block constraints but the script does not appear to have enumerated ALL valid null-placement patterns that satisfy cross-block period-7 consistency.

**Specific test**:
1. Let N_before = number of nulls in positions 0-20 (range: 0 to 20).
2. Let N_between = number of nulls in positions 34-62 (range: 0 to 29, but total nulls = 24).
3. Let N_after = number of nulls in positions 74-96 (range: 0 to 23).
4. Constraint: N_before + N_between + N_after = 24.
5. reduced_pos(21) = 21 - N_before. reduced_pos(63) = 63 - N_before - N_between.
6. For period 7: reduced_pos(21) mod 7 and reduced_pos(63) mod 7 determine the residue classes.
7. Within ENE (13 consecutive reduced positions starting at reduced_pos(21)): the Vigenere key must be consistent at positions with the same residue mod 7. We know the key values from the cribs. Check: for each pair of ENE positions i,j where (reduced_pos(21)+i) mod 7 = (reduced_pos(21)+j) mod 7, does k_vig[21+i] = k_vig[21+j]?
8. Same check within BC.
9. Cross-block: for each ENE position i and BC position j with (reduced_pos(21)+i) mod 7 = (reduced_pos(63)+j) mod 7, does k_vig[21+i] = k_vig[63+j]?
10. Also check Bean EQ and all 21 Bean INEQs under the reduced positions.
11. Enumerate all (N_before, N_between, N_after) triples summing to 24, with N_before in [0,20], N_between in [0,29], N_after in [0,23]. This is at most ~20*29 = 580 combinations (actually fewer due to sum constraint). For each, check steps 7-10.
12. For surviving patterns: enumerate which specific positions within each range are nulls (combinatorial, but heavily pruned by the Vigenere consistency constraint at period 7 -- each residue class has at most 26 possible key values, and within each block the key values are KNOWN).

**Parameter space**: ~580 macro-patterns. For each surviving macro-pattern, the specific null placement within the gap region is combinatorial but the Vigenere constraint (all positions in the same reduced residue class must have the same key) aggressively prunes. This should be tractable.

**Feasibility**: Minutes. The algebraic constraint propagation is fast.

**Plausibility**: 5/10. "8 Lines 73" on the yellow pad is suggestive. 24 nulls = 24 cribs = 24 Weltzeituhr facets is numerologically interesting. However:
- E-SOLVE-10 likely already rules this out for most periods (the within-block constraints are very tight).
- Sanborn would need to have announced crib positions in the CT-with-nulls coordinate system, which is plausible but adds a layer of complexity.
- The period-7 Vigenere with keyword KRYPTOS is an extremely specific model.
- Null insertion is a known technique, not "never in cryptographic literature."

---

### Hypothesis 3: Keyword-Seeded Permutation Generation (Deterministic Non-Columnar Transposition)

**Exact model**: A keyword (KRYPTOS or other) seeds a deterministic algorithm that generates a length-97 permutation. This permutation is used as the transposition layer. The substitution layer uses a running key from an unknown text. The algorithm is a simple, hand-executable procedure -- e.g., iterated position swaps, or a Fisher-Yates-like shuffle driven by keyword digits.

**Why not already eliminated**:
- All tested transpositions are STRUCTURED (columnar, rail fence, double columnar, Myszkowski, AMSCO, affine, cyclic, etc.). Keyword-seeded pseudo-random permutations are a distinct class.
- E-FRAC-35 proves periodic key + ANY transposition is Bean-impossible at periods 2-7. This eliminates keyword-seeded transposition + periodic key.
- BUT: keyword-seeded transposition + RUNNING KEY is NOT covered by E-FRAC-35 (running key is non-periodic, the only model surviving Bean per E-FRAC-38).
- E-FRAC-50 tested running key + structured transpositions. E-FRAC-51 tested running key from unknown English + columnar. Neither tested running key + keyword-seeded pseudo-random permutations.
- The information-theoretic analysis (E-FRAC-44) shows that 2^138 arbitrary permutations satisfy all constraints. But a keyword-seeded permutation is NOT arbitrary -- it comes from a small family (one permutation per keyword). If we enumerate plausible keywords, we are testing ~10^4 permutations, well within the "structured family" regime where E-FRAC-44 predicts zero false positives.

**Specific test**:
1. Implement 5-10 simple, hand-executable permutation generation algorithms:
   a. Iterated swaps: for i=0..96, swap positions i and (i + keyword[i % klen]) mod 97.
   b. Fisher-Yates with keyword-derived sequence.
   c. Knuth shuffle with keyword values as random source.
   d. Iterated transposition: apply a columnar transposition k times (k = keyword length or keyword sum).
   e. "Shifting matrix": generate a 97-element permutation by cycling through keyword values as row/column indices in a matrix.
2. For each algorithm, generate permutations from keywords: KRYPTOS, PALIMPSEST, ABSCISSA, KRYPTOSABCDEFGHIJLMNQUVWXZ (full KA), BERLINCLOCK, EASTNORTHEAST, and ~50 other thematically relevant keywords.
3. For each permutation, check: do the crib positions map to a set of reduced positions where the Vigenere/Beaufort key at those positions satisfies Bean EQ and all 21 Bean INEQs?
4. For surviving candidates: compute EAST constraint diffs and scan running key corpus.

**Parameter space**: ~10 algorithms x ~50 keywords = ~500 permutations. For each, Bean check is O(1). Running key corpus scan for survivors is ~73.7M per survivor. Total: negligible.

**Feasibility**: Minutes.

**Plausibility**: 4/10. "Shifting matrices" (Brother Martin magazine) could refer to this. The procedure is hand-executable. But:
- Keyword-seeded shuffles are a known concept (not "never in cryptographic literature").
- The specific algorithm is unknown, creating a specification problem.
- Sanborn would need to execute the shuffle correctly by hand for 97 positions -- error-prone.
- There is no specific evidence pointing to any particular algorithm.

---

### Hypothesis 4: Position-Dependent Cipher Variant Selection (Mixed Vig/Beau/VarBeau by Position Rule)

**Exact model**: At each position i, the cipher variant (Vigenere, Beaufort, or Variant Beaufort) is selected by a position-dependent rule. The key itself may be from a running key or a keyword-derived source. The variant selection rule could be: based on keyword letter (e.g., if keyword[i%p] is a vowel, use Beaufort; if consonant, use Vigenere), or based on parity, or based on a second keyword cycling independently.

**Why not already eliminated**:
- E-SOLVE-21 tested mixed-variant PERIODIC models and found ZERO consistent periods. But this was for periodic key models only.
- The combination of mixed-variant selection + running key has NOT been tested.
- Under a running key, the key is non-periodic. The variant selection introduces an additional degree of freedom that could allow solutions where pure Vigenere or pure Beaufort fails.
- Algebraically: if the variant at position i is v[i] in {Vig, Beau, VarBeau}, then the three sign conventions are:
  - Vig: k[i] = (CT[i] - PT[i]) mod 26
  - Beau: k[i] = (CT[i] + PT[i]) mod 26
  - VarBeau: k[i] = (PT[i] - CT[i]) mod 26
- At each of the 24 crib positions, three possible key values exist. For a running key from English text, we need the key fragment to look like English. The question is: does ANY variant assignment at the 24 positions produce a key fragment that matches English text?

**Specific test**:
1. At each of 24 crib positions, compute three possible key values (Vig, Beau, VarBeau).
2. Enumerate all 3^24 ~ 2.8 x 10^11 variant assignments... This is too large.
3. INSTEAD: use constraint propagation. Bean EQ requires k[27] = k[65]. Under mixed variants, k[27] can be Vig(27), Beau(27), or VarBeau(27), and k[65] likewise. Only 3x3=9 combinations; check which pairs give k[27]=k[65]. This prunes the 27/65 pair.
4. Similarly, each Bean INEQ pair constrains two positions to have DIFFERENT keys. Enumerate valid variant-pair assignments at each Bean-constrained pair.
5. After Bean pruning, the surviving variant assignments are a MUCH smaller set. For each, compute the implied key at all 24 positions and check for EAST constraint diffs [1,25,1,23] (variant-independent).
6. For surviving assignments: scan 73.7M corpus for running key matches.

But wait -- EAST diffs [1,25,1,23] are computed as CT[21]-CT[22]-..., which are VARIANT-INDEPENDENT for the gap pattern. Actually, they ARE variant-dependent: under Vig, diff = k[22]-k[21] = (CT[22]-PT[22]) - (CT[21]-PT[21]). Under Beau, diff = k[22]-k[21] = (CT[22]+PT[22]) - (CT[21]+PT[21]). Since the PT letters are known at crib positions, these diffs are constants for each variant assignment at positions 21-24.

**Revised test**: For the 4 positions involved in EAST (positions 21-24), there are 3^4 = 81 variant assignments. For each, compute the effective EAST diffs. Filter against the [1,25,1,23] pattern... but wait, the EAST diffs are only useful under a SINGLE variant assumption. Under mixed variants, the EAST diffs change.

Actually, let me reconsider. The key insight: if you use Beaufort at position 21 and Vigenere at position 22, the "key" values are computed with different formulas. The running key at these positions would need to be consistent with a single running key text under those different formulas. This is a genuine constraint but much weaker than the single-variant case.

**Revised feasibility**: The 3^24 space is too large for brute force, but constraint propagation from Bean (1 EQ + 21 INEQ) reduces it substantially. A SAT/CSP solver could handle this in seconds.

**Parameter space**: After Bean pruning, likely ~10^6 to 10^9 surviving assignments. For each, check corpus. Feasible with optimized filtering.

**Feasibility**: Hours to days, depending on pruning effectiveness.

**Plausibility**: 3/10. Mixed-variant selection is an unusual concept. There is no evidence Scheidt taught this. It adds complexity without clear motivation. However, it is genuinely untested and the constraint structure is weaker than single-variant models.

---

### Hypothesis 5: Non-Standard Keystream Recurrence at Periods 14+ (E-SOLVE-18 Gap)

**Exact model**: k[i] = f(k[i-1], keyword[i%p]) where f is a non-linear function (affine, quadratic, multiplicative, mixed). E-SOLVE-18 tested these at periods 2-13. Periods 14+ were NOT tested.

**Why not already eliminated**:
- E-SOLVE-18 explicitly states it tested periods 2-13 only.
- E-FRAC-35 eliminates ALL periods 2-7 for periodic keys under ANY transposition. But non-linear recurrence keys are NOT periodic -- k[i] depends on k[i-1], making it state-dependent.
- The question is whether non-linear recurrence keys escape the Bean impossibility proof. They do, because Bean constraints are derived from the PERIODIC key assumption (same residue mod p => same key). A state-dependent key does NOT have this property.
- HOWEVER: E-FRAC-37 proved that autokey (a specific state-dependent model) cannot reach 24/24 even with arbitrary transposition. The question is whether non-linear recurrences OTHER than autokey can reach 24/24.
- The affine recurrence k[i] = (a*k[i-1] + w[i%p]) mod 26 is NOT autokey. It is a deterministic recurrence from a seed value. With periods 14+, the ENE block (13 consecutive positions) spans at most one full period, providing at most 13 constraints on the p keyword values. At period 14, a 13-position block constrains at most 13 of 14 keyword values (one residue class unconstrained). This could allow solutions.

**Specific test**:
1. Extend E-SOLVE-18 to periods 14-26 for all four recurrence types (affine, quadratic, multiplicative, mixed).
2. For each (type, period, a-parameter if applicable):
   a. Derive keyword values from ENE block transitions.
   b. Check consistency with BC block.
   c. If consistent, forward-propagate from all 26 seeds.
   d. Check Bean EQ/INEQ.
   e. Score against all 24 cribs.
3. At periods 14+, some underdetermination is expected (not all keyword residues constrained by ENE alone). Use BC to provide additional constraints.

**Parameter space**: 4 types x 13 periods x 24 a-values (for affine) x 26 seeds = ~32K evaluations. Trivial.

**Feasibility**: Seconds.

**Plausibility**: 3/10. Non-linear recurrences at high periods are highly underdetermined (this is the same issue as periodic keys at high periods). Any "hits" will likely be false positives filtered by the multi-objective oracle. But the test is so cheap that it should be done for completeness.

**Critical caveat**: At periods 14+, E-FRAC-35 eliminates periodic keys. Non-linear recurrences are non-periodic, so they escape this proof. But E-FRAC-36 showed that even at Bean-surviving periods, hill-climbing trivially finds 24/24+Bean solutions that are all gibberish. Non-linear recurrences at high periods will likely show the same underdetermination.

---

### Hypothesis 6: Digraphic Cipher on 98 Characters (49 Pairs)

**Exact model**: K4 has 98 characters (97 letters + question mark, or 97 letters + an implied 98th character). The cipher operates on PAIRS of letters (digraphs), producing 49 ciphertext digraphs. The digraphic operation is NOT Playfair (eliminated) or standard Bifid (eliminated), but a bespoke 26x26 lookup table where each pair (A,B) maps to a different pair (C,D).

**Why not already eliminated**:
- E-FRAC-21 eliminated all FRACTIONATION families (Playfair, Bifid, Two-Square, Four-Square) via structural proofs. But these proofs rely on specific properties of those cipher families (parity constraints, alphabet reduction, etc.).
- A BESPOKE digraphic lookup (an arbitrary 676-to-676 mapping) is NOT covered by E-FRAC-21. It does not fractionate; it directly maps letter pairs.
- Sanborn said "try both 97 and 98." If 98 characters, there are exactly 49 pairs.
- E-SOLVE-11 tested "digraphic pair operations" as H31, but from the code it appears to test keyword-modulated autokey and tableau walk models, not arbitrary digraphic substitution.

**Specific test**:
1. Assume the cipher operates on consecutive pairs: (CT[0],CT[1]), (CT[2],CT[3]), ..., (CT[96],?), where ? is the 98th character (try A-Z).
2. At crib positions, we know both the CT pair and the PT pair. From the 24 known PT positions (12 complete pairs + 0 half-pairs... actually the crib positions are 21-33 and 63-73, which are NOT necessarily aligned with pair boundaries).
3. If pairs start at even positions: positions 21-33 span pairs (20,21), (22,23), ..., (32,33). But position 20 is unknown PT. We know PT at 21-33 (13 chars), giving 6 complete pairs: (22,23), (24,25), (26,27), (28,29), (30,31), (32,33) and one half-pair at (20,21).
4. For each pair, we know the PT digraph and CT digraph, constraining the 676-to-676 mapping. With ~12 known pairs, we have 12 entries of the mapping. The full mapping has 676 entries, so we know 12/676 = 1.8%.
5. Check: do any two known pairs with the same CT digraph map to different PT digraphs? (This would be a contradiction, proving the model wrong.) Do any two known pairs with the same PT digraph map to different CT digraphs?
6. Also try pair alignment starting at position 1 (odd pairs): (CT[1],CT[2]), (CT[3],CT[4]), etc.

**Parameter space**: This is a consistency check, not a search. Just verify whether the crib data is consistent with any digraphic substitution.

**Feasibility**: Seconds. Just check the known pairs for contradictions.

**Plausibility**: 2/10. Digraphic ciphers are known in literature (Playfair, Hill 2x2), so this would not be "never in cryptographic literature" unless the specific lookup table is novel. The pair alignment problem (cribs may not align with pair boundaries) makes this awkward. And 98 characters is not confirmed (Sanborn said "try both 97 and 98," which is ambiguous).

---

### Hypothesis 7: K3 Method Applied to K4 With Different Parameters (Variable-Length Key Vigenere + Columnar)

**Exact model**: K3 uses a double-length Vigenere key (KRYPTOS repeated to 336 chars) + columnar transposition. What if K4 uses the SAME architecture but with a different keyword (not KRYPTOS) and different columnar width? The "two systems" = (1) Vigenere with keyword X, and (2) columnar transposition with keyword Y.

**Why not already eliminated**:
- Columnar w5-15 + periodic Vigenere at ALL periods is eliminated (E-FRAC-12/29/30/55).
- BUT: the K3 method uses a key that is the KEYWORD REPEATED TO THE FULL TEXT LENGTH, not a cycling period. Under standard Vigenere, this IS periodic with period = keyword length. So this IS covered by the existing eliminations.
- HOWEVER: the K3 transposition grid has specific padding behavior. If K4 uses a keyword-length that is NOT among the tested widths (e.g., width 16-20 were only sampled at 100K each, not exhaustive), there could be a gap.
- More specifically: widths 10-15 were tested with 100K samples each (E-FRAC-30). The exhaustive coverage stops at width 9. If the K4 keyword determines a columnar width of 10-15, and the correct column ordering was not among the 100K sampled, the solution could have been missed.
- E-FRAC-55 closed the Bean-surviving period gap for widths 6/8/9. But it did NOT test widths 10-15 at Bean-surviving periods exhaustively.

**Specific test**:
1. For widths 10-15, compute total number of column orderings (10! to 15!). These range from 3.6M to 1.3T.
2. Width 10: 10! = 3,628,800. Exhaustive enumeration is feasible.
3. Width 11: 11! = 39,916,800. Feasible with parallelization.
4. Width 12: 12! = 479,001,600. Feasible in hours.
5. Width 13: 13! = 6,227,020,800. Feasible in days.
6. Widths 14-15: 14! and 15! are 87B and 1.3T -- infeasible without pruning.
7. For each width and ordering, test Vigenere/Beaufort with keyword-derived period (period = width) at ALL 3 variants.
8. Apply Bean EQ + INEQ as immediate filter.
9. Score remaining candidates against all 24 cribs.

WAIT -- this is exactly what was sampled in E-FRAC-30 (100K each for widths 10-15). The key question is: did the 100K sample provide sufficient statistical power to detect a signal? At width 10, 100K/3.6M = 2.8% coverage. At width 12, 100K/479M = 0.02% coverage. At width 13, 100K/6.2B = 0.002% coverage.

If the correct solution exists at width 12+ with a specific column ordering, 100K samples have negligible probability of finding it. This is a genuine gap.

HOWEVER: E-FRAC-35 proves periodic key + ANY transposition violates Bean at periods 2-7, 9-12, 14, 15, 17, 18, 21, 22, 25. The only surviving periods are {8, 13, 16, 19, 20, 23, 24, 26}. A keyword of length 10-15 gives periods 10-15, which are ALL Bean-eliminated by E-FRAC-35. So this hypothesis IS eliminated for widths 10-15 under periodic Vigenere.

The only exception: if the keyword length does NOT equal the columnar width (e.g., width 13 with a period-8 key). But this was tested in E-FRAC-55 for widths 6/8/9 and in E-HYBRID-01 for widths 5-9 + period 8. Width 10-15 + period 8 or 13 is NOT tested exhaustively.

**Revised test**: Width 10-13 columnar, exhaustive orderings, combined with period 8 or period 13 Vigenere. Period 8 is a Bean-surviving period. Width 10 has 10! = 3.6M orderings; at period 8, with 3 variants = 10.8M checks. Width 11: 120M. Width 12: 1.4B. Width 13: 18.7B.

**Feasibility**: Width 10-11 exhaustive: hours. Width 12: days. Width 13: weeks (but could be pruned by Bean at ordering level).

**Plausibility**: 2/10. The K3 method + different parameters is a natural hypothesis, but:
- Period 8 at widths 10-13 is highly underdetermined (expected random score ~14-17/24).
- Any "hits" will be false positives unless they also pass the multi-objective oracle.
- The sampling at 100K (E-FRAC-30) would have detected statistical anomalies (average score above random) even if it missed the specific solution. The fact that the average was AT or BELOW random strongly suggests no solution exists.
- This is "more of the same" -- standard columnar + periodic Vig at different parameters, not the "invention never in literature" that Gillogly described.

---

## SECTION B: Hypotheses That APPEAR Untested But Are Actually Eliminated

### B1: "What about non-additive cipher models (e.g., multiplicative, affine A!=1)?"

**Status**: ELIMINATED. Under any invertible mod-26 function f (not just addition), the Bean constraints still apply because they derive from the CRIB POSITIONS, not from the algebraic form. If CT[27] -> PT[27] via some function f(CT[27], k[27]) = PT[27], and CT[65] -> PT[65] via f(CT[65], k[65]) = PT[65], and CT[27]=CT[65]=P, PT[27]=PT[65]=R, then k[27] must equal k[65] (since f is the same function with the same inputs producing the same output). The Bean equality is function-independent.

The Bean INEQUALITIES similarly hold for any deterministic function: if CT[a] != CT[b] or PT[a] != PT[b], then k[a] may or may not equal k[b] depending on the specific values. The published inequalities were derived specifically for the additive model (Vigenere/Beaufort/VarBeau), but the EQUALITY k[27]=k[65] is universal for ANY cipher where the key is the only free variable at each position.

For periodic keys under non-additive models: the within-crib constraints are even MORE restrictive (an affine function k[i]=a*x+b with a != 1 has fewer solutions mod 26 than additive). E-BESPOKE-50 tested affine keys + columnar and found max 19/24 (underdetermined at width 6).

### B2: "What about a cipher where the key depends on the POSITION INDEX, not periodically?"

**Status**: This IS the running key model. Any position-dependent key k[i] = g(i) for some function g is equivalent to a running key where the "text" is g(0), g(1), ..., g(96). The running key + transposition model is UNDERDETERMINED (E-FRAC-39), not eliminated. But it cannot be computationally attacked without knowing the key source.

### B3: "What about applying the transposition to the KEY instead of the plaintext?"

**Status**: ELIMINATED. E-SOLVE-12 tested keystream transposition (generate periodic key, transpose it, use transposed key for Vigenere). The transposed keystream is a permutation of periodic values, so the KEY at crib positions must have values drawn from a set of size p (the period). With 24 crib positions and 24 distinct key values needed, this requires p >= 24. At p >= 24, the model is underdetermined (same as any large-period model). At small p, the constraint that all keys come from p distinct values is testable. E-SOLVE-12 tested this for periods 2-13 and widths 3-12. All NOISE.

### B4: "What about a completely different crib alignment (positions shifted by 1 or 2)?"

**Status**: ELIMINATED by E-FRAC-18 (crib position sensitivity analysis). No shift at any discriminating period (2-7) produces improvement above baseline. The published positions are validated.

---

## SECTION C: Hypotheses That Are Blocked (Not Computationally Testable Without External Information)

### C1: Arbitrary Masking Table (Coding Charts)
The $962.5K auction "coding charts" may contain an arbitrary monoalphabetic or polyalphabetic masking table that is not derivable from any public information. With 26! ~ 4 x 10^26 possible mono masks, or 26^97 ~ 10^137 position-dependent masks, this is computationally intractable without the charts. **BLOCKED on auction buyer / chart content.**

### C2: Running Key From Unknown, Untested Text
Running key + arbitrary transposition is UNDERDETERMINED (E-FRAC-39/44). Running key + structured transposition is eliminated for 73.7M tested characters. But the running key text may be a book, letter, or document we have never tested. Without knowing which text, we cannot attack this. **BLOCKED on text identification.** Partially testable under Hypothesis 1 (if combined with a tableau-derived mask).

### C3: Physical S-Curve / Fold Geometry
The Kryptos sculpture's physical curvature may define a transposition or reading order not capturable by any mathematical idealization. Fold theory (OFLNUXZ, ILM under YAR) produced interesting observations but all 39 computational approaches were NOISE. **BLOCKED on physical measurements** (Hirshhorn renovation).

### C4: K5 as Joint Constraint
K5 is 97 characters and shares coded words at the same positions as K4. If K5 ciphertext were known, it would provide additional constraints that could break the underdetermination. **BLOCKED on K5 ciphertext release.**

### C5: Smithsonian Archives
The K4 plaintext was reportedly found in Smithsonian archival materials but is sealed until 2075. **BLOCKED by archival policy.**

---

## SECTION D: The Underdetermination Problem

The deepest result of this project is E-FRAC-44's information-theoretic analysis:
- 505 bits needed to specify 1 of 97! permutations.
- 367 bits available from cribs (113) + Bean (6) + English (248).
- **138-bit deficit** means ~2^138 permutations are consistent with ALL constraints.

This means: **for any cipher model involving an arbitrary transposition + any substitution model, the problem is computationally underdetermined.** You can always find permutations that make ANY key look good. The only escape is:
1. The transposition comes from a SMALL, STRUCTURED family (columnar, etc.) -- but all such families have been tested.
2. External information narrows the transposition (physical measurements, K5, coding charts).
3. The substitution model is so constrained that the key is uniquely determined by the cribs -- but running key + mono mask has enough DOF to absorb the constraints (E-FRAC-54).

**Implication**: Without external information or a novel insight into the cipher's structure, the problem may be computationally unsolvable from ciphertext + cribs alone.

---

## SECTION E: Honest Assessment

### What is worth doing (cost-benefit ranking):

| Rank | Hypothesis | Compute Cost | Expected Value | Recommendation |
|------|-----------|-------------|----------------|----------------|
| 1 | H1: Tableau-derived mask + running key | Hours | MODERATE -- only viable model matching all Scheidt constraints | **DO THIS FIRST** |
| 2 | H2: Null insertion + period-7 (algebraic check) | Minutes | LOW -- likely already killed by E-SOLVE-10, but worth confirming | Do as quick verification |
| 3 | H5: Non-linear recurrence at periods 14+ | Seconds | VERY LOW -- underdetermined | Do for completeness |
| 4 | H6: Digraphic consistency check | Seconds | VERY LOW -- likely consistent (too few constraints) | Do for completeness |
| 5 | H3: Keyword-seeded permutations | Minutes | LOW -- specification problem | Do if H1 fails |
| 6 | H4: Mixed-variant + running key | Hours-days | LOW -- no evidence for this model | Do if everything else fails |
| 7 | H7: Width 10-13 + period 8/13 (exhaustive) | Days-weeks | VERY LOW -- underdetermined at these parameters | Skip unless resources are free |

### What is NOT worth doing:

- More periodic key testing at any width or period (ALL eliminated by E-FRAC-35 + E-FRAC-55).
- More single-layer cipher testing (ALL 110+ families eliminated).
- More SA/hill-climbing on arbitrary permutations (produces only false positives per E-FRAC-36/44).
- More running key testing from KNOWN corpora under IDENTITY transposition (73.7M chars, all noise).
- Any fractionation, Playfair, Bifid, etc. (structurally impossible per E-FRAC-21).

### What would actually solve this:

1. **The $962.5K coding charts** -- if they contain the masking table, the problem reduces to standard Vigenere.
2. **K5 ciphertext** -- additional constraints from a second message encrypted with the same method.
3. **Physical measurements of the sculpture** -- enables testing geometric transpositions.
4. **A genuine new insight** -- someone realizes what "two separate systems" and "code circles fixed in place" means in a way that produces a specific, testable cipher model.
5. **Sanborn or Scheidt provides another clue** -- one more word of plaintext, or a description of the method class, would break the underdetermination.

### The bottom line:

The computationally testable hypothesis space is nearly exhausted. Hypothesis 1 (tableau-derived mask + running key) is the last high-plausibility, computationally tractable model. If it fails, the remaining open hypotheses are either blocked on external information or computationally underdetermined.

This is consistent with the project's trajectory: 375 experiments testing progressively more exotic models, all producing noise. The cipher was designed by a professional cryptographer (Scheidt) to resist exactly this kind of systematic computational attack. Its security likely derives from information that is not present in the ciphertext alone -- the "coding charts," the physical sculpture, or knowledge that has not been publicly released.

K4 will likely be solved by one of:
- A human insight that correctly identifies the bespoke method from Scheidt/Sanborn's clues
- The release of the $962.5K auction materials
- Physical access to the Antipodes sculpture at the Hirshhorn
- The 2075 unsealing of the Smithsonian archives
- Sanborn providing additional information before then

The era of productive computational brute-force on K4 is over.

---

*Assessment based on complete review of: CLAUDE.md, MEMORY.md, elimination_tiers.md, final_synthesis.md, audit_matrix.md, research_questions.md, invariants.md, kryptos_ground_truth.md, ed_scheidt_dossier.md, kryptosfan_findings.md, bespoke_cipher_design.md, and ~50 experiment scripts. All file paths, experiment IDs, and proof references verified against the repository.*
