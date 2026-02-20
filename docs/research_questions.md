# Research Questions — Ordered by Search Space Reduction Potential

**Purpose**: Guide the novelty engine's hypothesis prioritization. Questions are ordered by
how much resolving them would shrink the remaining search space.

---

## Tier 1: Maximum Leverage (resolving any one of these would transform the problem)

### RQ-1: What is the cipher TYPE?

**Current state**: Unknown. We know it's position-dependent (not state-dependent), non-periodic,
and NOT a simple linear recurrence keystream (orders 1-8 eliminated).

**What's been eliminated**:
- Standard Vigenere with periodic key
- Beaufort with periodic key
- Gromark / Vimark (linear recurrence keystream, orders 1-8)
- Chaocipher, Enigma (state-dependent, eliminated by K5 constraint)
- Polynomial position function k[i]=f(i), degrees 1-20
- Compound columnar + periodic Vigenere (widths 5-10, periods 1-22)

**What remains viable**:
- Running key from an unknown text (key = plaintext of another document)
- Non-linear key generation (lookup tables, non-algebraic rules)
- ~~Fractionation ciphers (Polybius, bifid, trifid)~~ **ALL 10 families structurally eliminated** (E-FRAC-21: parity, alphabet, IC proofs hold with or without transposition)
- Manual/procedural cipher (Sanborn: "not even a math solution")
- Multi-layer cipher with a non-standard composition
- Modified Quagmire with artifact-derived parameters
- Something entirely novel that doesn't fit classical categories

**If resolved**: Entire attack methodology changes. This is the single most valuable question.

**Novelty engine priority**: HIGHEST — generate hypotheses across ALL remaining cipher types.

---

### RQ-2: What is the key source / generation method?

**Current state**: The known keystream at crib positions is:
- Vigenere: `BLZCDCYYGCKAZ` (pos 21-33), `MUYKLGKORNA` (pos 63-73)
- These are NOT readable English, NOT a simple pattern, NOT linear recurrence

**Key constraint**: Bean equality k[27] = k[65] = Y (Vigenere) / G (Beaufort)
- Positions 27 and 65 are 38 apart — NOT a simple period

**Observations**:
- Pre-ENE (positions 0-20) has IC = 0.0667 (English-like), possibly different cipher/key
- The key is position-dependent but not periodic

**If resolved**: Directly produces the plaintext.

**FRAC findings (E-FRAC-38/39/49/50/51/52/53/54):**
- Running key is the ONLY structured non-periodic key model surviving Bean constraints (E-FRAC-38)
- Running key + ALL structured transposition families (columnar w6/8/9, identity, cyclic, affine, rail fence, block reversal, double columnar) produce ZERO matches from 7 known reference texts (E-FRAC-49/50)
- Running key from UNKNOWN English text + columnar: ZERO configs produce English-like key fragments (E-FRAC-51)
- Running key + arbitrary transposition is massively underdetermined (~700-2000 feasible offsets per text, E-FRAC-39)
- Carter is NOT special — SA optimization produces same quadgram quality with random keys (E-FRAC-40)
- Three-layer Sub+Trans+Sub: non-periodic effective key bypasses Bean proof but produces only gibberish (E-FRAC-52)
- Mono+Trans+Periodic: bypasses 9/21 Bean-ineq but ZERO candidates at discriminating periods (E-FRAC-53)
- **Mono+Trans+Running key: UNDERDETERMINED** — 13 mono DOF saturate key fragment analysis, making English detection impossible when mono layer present (E-FRAC-54)

**Novelty engine priority**: HIGHEST — focus on:
- Running key from UNKNOWN NON-ENGLISH texts (English running key + columnar eliminated by E-FRAC-51)
- Running key from other Sanborn-associated texts not yet tested
- Artifact-derived key sequences (clock readings, coordinates, dates)
- Non-linear key generation from a short seed
- Models that don't fit standard transposition+substitution paradigm

---

### RQ-3: Is there a transposition layer, and what type?

**Current state**: k4suite has tested Mengenlehreuhr (480 perms) and Weltzeituhr permutations
with all thematic keyword alphabets. No breakthrough.

**Tested and eliminated**:
- Columnar transposition (widths 5-10) + periodic Vigenere
- Mengenlehreuhr + Weltzeituhr clock-face permutations + standard alphabets

**Not tested**:
- Full 97-position transposition (97! is astronomical, but constrained by cribs)
- Transposition that operates on the full text (not blocks)
- Route ciphers on grids with dimensions related to the sculpture
- Spiral, diagonal, or S-curve reading of the sculpture text
- Transposition followed by UNKNOWN (not Vigenere) substitution
- No transposition at all (pure substitution with complex key)

**FRAC agent eliminations (E-FRAC-01 to 50):**
- Columnar widths 5-15 + periodic sub: ALL eliminated at discriminating periods
- Width-9 non-columnar reads (serpentine, spiral, diagonal): eliminated (E-FRAC-03/45)
- Width-9 × width-7 compound: eliminated (E-FRAC-04/46)
- Simple families (cyclic, affine, rail fence, swap, reversal): ALL eliminated (E-FRAC-32)
- Width-9 + running key, progressive, autokey: eliminated (E-FRAC-02)
- Width-9 + mixed alphabets: eliminated (E-FRAC-05)
- Double columnar (9 Bean-compatible width pairs): eliminated (E-FRAC-46)
- Myszkowski (widths 5-13): eliminated (E-FRAC-47)
- AMSCO/Nihilist/Swapped (widths 8-13): eliminated, 0% Bean pass (E-FRAC-48)
- **Running key + columnar (w6,8,9) from 7 texts: ZERO matches** (E-FRAC-49)
- **Running key + ALL structured families from 7 texts: ZERO matches** (E-FRAC-50)
- **Running key from unknown English text + columnar: ZERO configs with English-like keys** (E-FRAC-51)
- **Universal proof:** ALL 97! perms + periodic key at p2-7 violate Bean (E-FRAC-35)
- **Information-theoretic proof:** 138-bit deficit, arbitrary search underdetermined (E-FRAC-44)
- **Three-layer Sub+Trans+Sub:** non-periodic effective key, ZERO viable candidates (E-FRAC-52)
- **Mono+Trans+Periodic:** bypasses 9/21 Bean-ineq, ZERO at discriminating periods (E-FRAC-53)

**If resolved**: Reduces problem from "find transposition AND substitution" to "find substitution."

**Novelty engine priority**: HIGH — but constrained by crib positions. ALL standard structured transposition families + ALL standard key models now eliminated.

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

**If resolved**: Likely reveals a key parameter or structural element.

**Novelty engine priority**: HIGH — generate testable hypotheses for each interpretation.

---

### RQ-5: How do the 1986 Egypt trip and 1989 Berlin Wall connect?

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

### RQ-7: What does the pre-ENE segment (positions 0-20) encode?

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

**K3 method**: Double-length key Vigenere + columnar transposition.

**What changed?**:
- Different substitution type?
- Different key generation?
- Added layers?
- Fundamentally different approach?

**Novelty engine priority**: MEDIUM — test K3 method variants with modifications.

---

### RQ-9: What is K5 and how does it relate to K4?

**Known**: K5 is 97 characters. Shares coded words at same positions as K4.
This proves position-dependent cipher.

**Unknown**: What are K5's coded words? What is K5's plaintext?

**If resolved**: Additional cribs, constraints on the cipher.

**Novelty engine priority**: LOW (we lack K5 ciphertext to test against).

---

### RQ-10: Is there a connection to the sculpture's physical properties?

**Known**: Sculpture includes compass, lodestone, quartz, Morse code panel, coordinates,
water feature, curved surfaces.

**Hypotheses**:
- Coordinates (38.9517, -77.1467) as key parameters
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

### RQ-12: Could the cipher use a non-standard alphabet (IJ merge, etc.)?

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

*Updated 2026-02-20 — includes FRAC agent findings (E-FRAC-01 to 53, ALL gaps closed)*

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
