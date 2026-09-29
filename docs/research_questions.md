# Research Questions — Ordered by Search Space Reduction Potential

**Purpose**: Guide the novelty engine's hypothesis prioritization. Questions are ordered by
how much resolving them would shrink the remaining search space.

---

## Tier 1: Maximum Leverage (resolving any one of these would transform the problem)

### RQ-1: What is the cipher TYPE?

**Current state**: (updated 2026-09-29) Unknown. In the standard letter-for-letter reading, no repeating key of any length from 1 to 26 fits the known letters, with either the standard alphabet or the KRYPTOS alphabet, and the key is not produced by any of the simple step-by-step formulas we tested (linear recurrences of order 1 to 8) on those alphabets. With one keyword-scrambled alphabet used on both sides (the way K1 and K2 used theirs), repeating keys of length 1 to 22, 24 and 25 are also ruled out, whatever that alphabet is; lengths 23 and 26 are not. Versions that use two different scrambled alphabets, or a Gromark cipher with keyed alphabets, are not yet ruled out in our published record. The 2026 program extended the negatives beyond the letter-for-letter reading: campaigns that first undo a rearrangement, or let the known words land anywhere (millions of configurations, each campaign checked against a chance baseline built the same way), found nothing. For the simple substitution + rearrangement + running-key family, the strongest detector we built could not tell real text from shuffled text at 97 letters (0 of 6 planted test cases detected), so that family stays open as a limit on what can be detected. [HYPOTHESIS] It may be position-dependent (not state-dependent) based on the K5 shared-positions inference, but this inference is unproven. (see `docs/kryptos_ground_truth.md` C5)

**What's been eliminated**:
- Standard Vigenere with periodic key
- Beaufort with periodic key
- Gromark / Vimark with fixed AZ/KA alphabets (linear recurrence keystream, orders 1-8). PARTIAL per AUDIT-6: ACA-standard Gromark is impossible for key values 0..10; Gromark with keyed alphabets on both sides is open in the repo record
- Chaocipher as a single layer (142,129 keyword pairs tested, best 7/24 = noise). Enigma as a single layer: its reflector means it never enciphers a letter to itself, but in the letter-for-letter reading K4 has two such positions (S at 32, K at 73). (An older note said K5 rules out all state-dependent ciphers; that inference is unproven and not used, see `docs/kryptos_ground_truth.md` C5.)
- Polynomial position function k[i]=f(i), degrees 1-20
- Compound columnar + periodic Vigenere/Beaufort (widths 4-9, all column orders, periods 1-24, standard A-Z alphabet; Bean-free re-run f_columnar_periodic_rederived_v1, 2026-08-24). This replaces the older "widths 5-10, periods 1-22" entry: widths 5 and 7 had 0 orderings actually tested before that re-run, and width 10 is covered only by a 2026-09-29 re-check that is not yet archived

**What remains viable**:
- Running key from an unknown text (key = plaintext of another document)
- Non-linear key generation (lookup tables, non-algebraic rules)
- Fractionation ciphers: standard forms are ruled out as the final layer, with or without a transposition (E-FRAC-21, scoped 2026-08-24: ADFGVX and ADFGX fail on parity; 5x5 Bifid, Playfair, Two-Square and Four-Square on their 25-letter output; standard straddling checkerboard and VIC output digits). 6x6 Bifid and Trifid remain OPEN: the old IC argument against 6x6 Bifid used a faulty simulator, and no complete Trifid proof over all periods survives in the current record
- Manual/procedural cipher (Sanborn, 2009 Smithsonian oral history: Scheidt gave him ideas for "systems that didn't necessarily depend on mathematics"; the often-repeated wording "not even a math solution" has not been traced to a source)
- Multi-layer cipher with a non-standard composition
- Modified Quagmire with artifact-derived parameters
- Something entirely novel that doesn't fit classical categories

**If resolved**: Entire attack methodology changes. This is the single most valuable question.

**Novelty engine priority**: HIGHEST — generate hypotheses across ALL remaining cipher types.

---

### RQ-2: What is the key source / generation method?

**Current state**: In the letter-for-letter reading, the key letters at the 24 known positions follow directly from the clues. Under Vigenere with the standard alphabet they are `BLZCDCYYGCKAZ` (positions 21-33) and `MUYKLGKORNA` (positions 63-73). They are not readable English, show no simple pattern, and do not follow a linear recurrence of order 1 to 8.

**Key constraint**: Bean equality k[27] = k[65] = Y (Vigenere) / G (Beaufort), in the letter-for-letter reading only; it does not carry over across a transposition except for repeating keys whose period divides 38
- Positions 27 and 65 are 38 apart — NOT a simple period

**Observations**:
- Pre-ENE (positions 0-20) has IC = 0.0667, but that is not unusual for a 21-letter stretch of K4 (E-FRAC-19, see RQ-7), so it is not evidence of a different cipher or key
- In the letter-for-letter reading the key does not repeat with any period from 1 to 26 (standard or KRYPTOS alphabet). That it is position-dependent is a hypothesis (K5 inference), not established

**If resolved**: Directly produces the plaintext.

**FRAC findings (E-FRAC-38/39/49/50/51/52/53/54):**
- Running key is the only structured non-periodic key model surviving Bean constraints under additive-key assumptions, in the letter-for-letter reading on the standard alphabet (E-FRAC-38, Level A). Its "+ ANY transposition" extension applied the frozen Bean sets across a transposition and does not stand (2026-08-24 banner in `docs/elimination_tiers.md`)
- Running key + structured transposition families (columnar w6/8/9, identity, cyclic, affine, rail fence, block reversal, double columnar) produced ZERO matches from 7 known reference texts (E-FRAC-49/50), but only the configurations that passed a frozen Bean filter were scanned, and that filter does not hold across a transposition (2026-08-24 banner; C-BEAN-01 disputed). Not exhaustive except for the identity (no transposition) case
- Running key from UNKNOWN English text + columnar: ZERO of the scanned configs produce English-like key fragments (E-FRAC-51), with the same Bean-filter limitation, so not exhaustive
- Running key + arbitrary transposition is massively underdetermined (~700-2000 feasible offsets per text, E-FRAC-39)
- Carter is NOT special — SA optimization produces same quadgram quality with random keys (E-FRAC-40)
- Three-layer Sub+Trans+Sub (E-FRAC-52): DISPUTED 2026-08-24; only 1.32% of its declared model space was evaluated, so "only gibberish" is not an elimination
- Mono+Trans+Periodic (E-FRAC-53): ZERO candidates at periods 3-7 for columnar widths 6, 8, 9 (re-confirmed over all 403,920 column orders without Bean filtering); the periods 10-12 part was retracted (943 genuine solutions had been recorded as zero)
- **Mono+Trans+Running key: UNDERDETERMINED** — 13 mono DOF saturate key fragment analysis, making English detection impossible when mono layer present (E-FRAC-54)

**Novelty engine priority**: HIGHEST — focus on:
- Running key from texts not yet tested, English or not (E-FRAC-51's English running key + columnar result scanned only Bean-filtered configurations, so it is not exhaustive)
- Running key from other Sanborn-associated texts not yet tested
- Artifact-derived key sequences (clock readings, coordinates, dates)
- Non-linear key generation from a short seed
- Models that don't fit standard transposition+substitution paradigm

---

### RQ-3: Is there a transposition layer, and what type?

**Current state**: (updated 2026-09-29) Rearrangements based on two Berlin clocks (480 from the Mengenlehreuhr set-theory clock, plus orderings from the Weltzeituhr world clock) were tested with thematic keyword alphabets and found nothing. In 2026 we scored candidates after undoing 52 route rearrangements, including routes combined with a Vigenere-style cipher using six keyword alphabets (KRYPTOS among them) and 27 thematic keywords (25,272 configurations, 2026-06-10), and found nothing. In August 2026 an older proof that ruled out repeating keys at most key lengths under any rearrangement was withdrawn, and the searches that relied on it were reopened. Columnar rearrangements were then re-run without the faulty check: for every grid width from 4 to 9 and every column order (substitution first, then rearrangement), no repeating key of length 1 to 24 on the standard alphabet fits the known letters. If a rearrangement layer exists, it is not one of the families whose searches still stand, at the depths tested.

**Tested and eliminated**:
- Columnar transposition (widths 4-9, all column orders) + periodic Vigenere/Beaufort, periods 1-24, standard A-Z alphabet (Bean-free re-run f_columnar_periodic_rederived_v1, 2026-08-24; width 10 is covered only by a 2026-09-29 re-check that is not yet archived)
- Mengenlehreuhr + Weltzeituhr clock-face permutations + standard alphabets

**Not tested**:
- Full 97-position transposition (97! is astronomical, but constrained by cribs)
- Transposition that operates on the full text (not blocks)
- Route ciphers on grids with dimensions related to the sculpture
- Spiral, diagonal, or S-curve reading of the sculpture text
- Transposition followed by UNKNOWN (not Vigenere) substitution
- No transposition at all (pure substitution with complex key)

**FRAC agent eliminations (E-FRAC-01 to 50):**
- Columnar widths 5-15 + periodic sub: widths 6 and 8 exhaustive (E-FRAC-29) and 10-15 sampled (E-FRAC-30), all noise at discriminating periods. The width-9 re-evaluation (E-FRAC-12) and the width 5/7 "ZERO Bean passes" results (E-FRAC-26/27) were retracted or disputed on 2026-08-24; widths 4-9 are now covered by the Bean-free re-run listed above
- Width-9 non-columnar reads (serpentine, spiral, diagonal): eliminated (E-FRAC-03/45)
- Width-9 × width-7 compound: NOT covered. The early test (E-FRAC-04) was flawed, and E-FRAC-46 re-ran only width pairs from 6, 8 and 9 (it skipped width 7 on a Bean ruling now disputed)
- Simple families (cyclic, affine, rail fence, swap, reversal): ALL eliminated (E-FRAC-32)
- Width-9 + running key, progressive, autokey: recorded as eliminated (E-FRAC-02). No E-FRAC-02 script remains in the repo (only the deprecated E-FRAC-02b baseline, which tests whether E-FRAC-02's 20/24 scores were artifacts of too many free key values), so this cannot be re-checked. The autokey part does not extend to other rearrangements: self-keying with an unrestricted rearrangement is not ruled out
- Width-9 + mixed alphabets: recorded as eliminated (E-FRAC-05), but that script is marked deprecated ("do not cite results as current") and the exhaustion log does not list it as exhausted. It also required Bean equality after undoing the transposition, a check the 2026-08-24 audit found invalid across a transposition
- Double columnar, 9 width pairs from widths 6, 8, 9, + periodic sub: max 15/24 = random (E-FRAC-46, standing). Pairs using widths 5 or 7 were skipped on a Bean ruling now disputed
- Myszkowski (widths 5-13): eliminated (E-FRAC-47)
- AMSCO/Nihilist/Swapped (widths 8-13; w8 exhaustive, w9-13 sampled) + periodic sub: eliminated on the attainable-crib ceiling (at most 16/24 at periods 8-10, 23/24 at period 24; 24/24 only at periods 25-26, which are underdetermined) (E-FRAC-48). The old "0% Bean pass" wording is retired
- Running key + columnar (w6,8,9) from 7 texts: ZERO matches among the Bean-filtered configurations scanned (E-FRAC-49; not exhaustive, since the frozen Bean filter does not hold across a transposition)
- Running key + structured families from 7 texts: ZERO matches among the Bean-filtered configurations scanned (E-FRAC-50; same limitation, except the identity case)
- Running key from unknown English text + columnar: ZERO English-like keys among the Bean-filtered configurations scanned (E-FRAC-51; same limitation)
- ~~Universal proof: ALL 97! perms + periodic key at p2-7 violate Bean (E-FRAC-35)~~ RETRACTED 2026-08-24: falsified by a constructive counterexample (with the transposition free, period 2 admits 267 valid key pairs). A transposition plus a repeating key is NOT proven impossible in general
- ~~Bean-surviving periods: columnar w6/8/9 at p8/13/16 (E-FRAC-55)~~ DISPUTED 2026-08-24: its first-phase Bean gate discarded 95.8% of orderings, and the "Bean-surviving periods" list fell with E-FRAC-35
- **Information-theoretic proof:** 138-bit deficit, arbitrary search underdetermined (E-FRAC-44)
- **Three-layer Sub+Trans+Sub (E-FRAC-52):** DISPUTED 2026-08-24; only 1.32% of its declared model space was evaluated
- **Mono+Trans+Periodic (E-FRAC-53):** ZERO candidates at periods 3-7 for columnar widths 6, 8, 9 (standing); periods 10-12 retracted

**If resolved**: Reduces problem from "find transposition AND substitution" to "find substitution."

**Novelty engine priority**: HIGH, but constrained by crib positions. Many structured transposition families have been searched with repeating keys, but several of those eliminations were retracted or disputed on 2026-08-24 (see the banner in `docs/elimination_tiers.md`), and self-keying or running keys combined with a rearrangement are not ruled out.

---

## Tier 2: High Leverage (significant constraint on remaining space)

### RQ-4: What is the role of "the point"?

**Sanborn's clue**: "What's the point?" is deliberately embedded.

**Hypotheses**:
- A. Physical point on the sculpture (compass, lodestone, coordinates)
- B. A specific position in the ciphertext that acts as a key parameter
- C. A decimal point or period that changes number interpretation
- D. A "point" in the geometric sense (intersection, reference point)
- E. The word POINT or its position in the plaintext
- F. Starting point for a reading order / route cipher

**If resolved**: May reveal a key parameter or structural element.

**Novelty engine priority**: HIGH — generate testable hypotheses for each interpretation.

---

### RQ-5: How do Sanborn's 1986 Egypt trip and the 1989 fall of the Berlin Wall figure in the solution?

**Sanborn's clue**: Two events are embedded in the solution.

**Implications**:
- The plaintext likely references these events
- Dates/coordinates may be key parameters: 1986, 1989, Nov 9 1989
- Carter's Tomb of Tutankhamun connects to Egypt
- BERLINCLOCK connects to Berlin Wall
- The key or plaintext may encode a narrative about these events

**If resolved**: Constrains plaintext content, may reveal key parameters.

**Novelty engine priority**: MEDIUM-HIGH — test date-derived keys, Carter text as running key.

---

### RQ-6: What does "delivering a message" mean?

**Sanborn**: Codes are about "delivering a message."

**Hypotheses**:
- A. The encryption models a real intelligence message delivery
- B. The plaintext IS a message (narrative, instructions, coordinates)
- C. The encryption method itself involves "delivery" (routing, forwarding)
- D. Meta-commentary on the sculpture's purpose

**If resolved**: Constrains the expected plaintext format.

**Novelty engine priority**: MEDIUM — constrains plaintext expectations but not the method directly.

---

### RQ-7: What do the first 21 letters (positions 0-20, before EASTNORTHEAST) encode?

**Observation**: IC = 0.0667 at positions 0-20. **FRAC finding (E-FRAC-19): This IC is NOT unusual.** It ranks #10 out of 77 contiguous 21-char segments of K4 (13 segments have IC ≥ 0.067). Bonferroni-corrected p=1.0. The "English-like" claim is unfounded — the high IC is just letter repetition (4 O's, 4 B's) in a short sample. Pre-ENE letter frequencies have near-zero correlation with English (r=0.018).

**Hypotheses** (all weakened by E-FRAC-19 finding):
- A. Different cipher for first 21 characters (simpler, possibly key indicator) — IC not significant
- B. Same cipher but the key happens to produce English-like IC
- C. Transposition has moved English text into these positions
- D. Null cipher or plaintext header — eliminated by E-FRAC-22

**If resolved**: May reveal a "key indicator group" or separate cipher for the header.

**Novelty engine priority**: HIGH — relatively small space, high information density.

---

## Tier 3: Moderate Leverage

### RQ-8: Is the "change in methodology" from K3→K4 a specific technique?

**Scheidt**: Intentional change, difficulty 9/10.

**K3 method**: A pure transposition with no substitution: an unkeyed double rotation (write the plaintext in 8 rows of 42 and read the columns bottom to top; repeat with 24 rows of 14). Equivalently PT[i] = CT[(191 + 192*i) mod 337]. [DERIVED FACT: K3 CT is an exact anagram of K3 PT and the rotation reproduces it 336/336; checked by `scripts/audit/audit_kryptos_text_integrity.py`.] *Erratum 2026-09-29: this line previously read "Double-length key Vigenere + columnar transposition", which is wrong.*

**What changed?**:
- Different substitution type?
- Different key generation?
- Added layers?
- Fundamentally different approach?

**Novelty engine priority**: MEDIUM — test K3 method variants with modifications.

---

### RQ-9: What is K5 and how does it relate to K4?

**Reported** (2025 reporting attributed to Sanborn; his August 2025 open letter says K4's riddle "will persist as K5"): K5 is 97 characters and shares some coded words at the same positions as K4.
[HYPOTHESIS] This may suggest a position-dependent cipher, but it does not prove one, and it cannot be used to eliminate state-dependent ciphers (`docs/kryptos_ground_truth.md` C5).

**Unknown**: What are K5's coded words? What is K5's plaintext?

**If resolved**: Additional cribs, constraints on the cipher.

**Novelty engine priority**: LOW (we lack K5 ciphertext to test against).

---

### RQ-10: Is there a connection to the sculpture's physical properties?

**Known**: Sculpture includes compass, lodestone, quartz, Morse code panel, coordinates,
water feature, curved surfaces.

**Hypotheses**:
- K2 coordinates (38°57'6.5"N, 77°8'44"W, which is 38.9518, -77.1456 in decimal degrees) as key parameters
- Compass bearings as key values
- Petrified wood / geological references
- Physical measurements as key values

**Novelty engine priority**: MEDIUM — generate artifact-derived parameter hypotheses.

---

## Tier 4: Background / Long-term

### RQ-11: Is there meaningful structure in the known keystream?

The Vigenere keystream `BLZCDCYYGCKAZ...MUYKLGKORNA` — is there a pattern we're missing?

**Tests to run**:
- Autocorrelation analysis
- Difference sequences
- Modular arithmetic patterns
- Key as positions in a known alphabet
- Cross-referencing with K1-K3 plaintext as running key

**Novelty engine coverage**: 8 hypotheses (alphabet mapping, difference analysis, modular
analysis at 5 moduli, K1-K3 plaintext as running key)

---

### RQ-12: Could the cipher use a non-standard alphabet (keyword-mixed, reversed, etc.)?

**Hypotheses**:
- IJ-merged 25-letter alphabet with standard Vigenere
- Bifid cipher with KRYPTOS-keyed 5x5 Polybius square
- Trifid cipher with 27-symbol alphabet
- Reversed KRYPTOS-keyed alphabet

Mostly tested but not exhaustively for all cipher types. ~~Fractionation ciphers
(bifid, trifid) are particularly interesting because they produce very low IC
values, matching K4's 0.0361.~~ **FRAC finding (E-FRAC-13/21): ALL fractionation families structurally eliminated. Bifid 6×6 is IC-INCOMPATIBLE (IC 0.059-0.069, K4 at 0th percentile). Bifid 5×5 requires 25-letter alphabet but K4 uses all 26.**

**Novelty engine coverage**: 5 hypotheses (IJ merge, bifid, trifid, reversed alphabet,
Quagmire III cross-listed from RQ-8)

---

### RQ-13: Is the reading direction standard (left-to-right, top-to-bottom)?

Sculpture text is arranged in a specific physical layout. Alternative reading orders
could produce a different ciphertext.

**Hypotheses**:
- Full reverse (R→O)
- Boustrophedon (serpentine) at various line widths
- Spiral reading on rectangular grids
- Diagonal reading on rectangular grids

**Novelty engine coverage**: 16 hypotheses (1 reverse, 7 boustrophedon widths,
4 spiral grids, 4 diagonal grids)

---

## Priority Matrix for Novelty Engine

| Research Question | Priority | Cheap Triage? | Hypotheses | Eliminated | Triaged |
|------------------|----------|--------------|------------|------------|---------|
| RQ-1 (cipher type) | CRITICAL | Yes (IC, crib) | 20 | 6 | 14 |
| RQ-2 (key source) | CRITICAL | Yes (crib match) | 81 | 66 | 15 |
| RQ-3 (transposition) | HIGH | Yes (crib align) | 29 | 0 | 29 |
| RQ-4 ("the point") | HIGH | Partial | 22 | 2 | 20 |
| RQ-5 (Egypt/Berlin) | MEDIUM-HIGH | Yes (date keys) | 64 | 59 | 5 |
| RQ-6 (delivering msg) | MEDIUM | Partial | 3 | 0 | 3 |
| RQ-7 (pre-ENE) | HIGH | Yes (IC, freq) | 5 | 0 | 5 |
| RQ-8 (K3 change) | MEDIUM | Yes | 5 | 0 | 5 |
| RQ-9 (K5) | LOW | No (no data) | 0 | 0 | 0 |
| RQ-10 (physical) | MEDIUM | Partial | 15 | 1 | 14 |
| RQ-11 (keystream) | LOW | Yes | 8 | 0 | 8 |
| RQ-12 (alphabets) | LOW | Yes | 5 | 1 | 4 |
| RQ-13 (reading dir) | LOW | Yes | 16 | 0 | 16 |

*Table counts last updated 2026-02-21. Several FRAC findings it drew on (E-FRAC-12, 21, 26/27, 35, 49-51, 52, 53 p10-12, 55) were later retracted, disputed, rescoped or reopened, so "all gaps closed" no longer holds; see `docs/elimination_tiers.md`.*

---

## Novelty Engine Wiring

The novelty engine is implemented in `src/kryptos/novelty/` and wired as follows:

1. **Tag every hypothesis** with the RQ(s) it addresses → `hypothesis.research_questions`
2. **Prioritize** by: `priority_score = sum(RQ_weights) * triage_score / (1 + log(compute_cost))`
3. **Reject** hypotheses that address only eliminated space → triage eliminates at noise floor
4. **Boost** hypotheses that address multiple RQs simultaneously → sum of RQ weights
5. **Track** which RQs have been most/least explored → `ledger.get_underexplored_rqs()`

### RQ Tier Weights (in `hypothesis.py:RQ_WEIGHTS`):
- Tier 1 (RQ-1, RQ-2, RQ-3): weight = 10
- Tier 2 (RQ-4, RQ-5, RQ-6, RQ-7): weight = 5
- Tier 3 (RQ-8, RQ-10): weight = 2
- Tier 4 (RQ-9, RQ-11, RQ-12, RQ-13): weight = 1

### Under-explored RQs (< 10 hypotheses):
RQ-6, RQ-7, RQ-8, RQ-9, RQ-11, RQ-12

### Coverage Tracking:
The ledger tracks hypotheses-per-RQ to identify under-explored questions.
Run `python -m kryptos novelty status` to see current coverage.

### Commands:
```bash
python -m kryptos novelty generate   # Generate and record hypotheses
python -m kryptos novelty triage     # Run cheap tests on proposed hypotheses
python -m kryptos novelty status     # Show coverage + under-explored RQs
```
