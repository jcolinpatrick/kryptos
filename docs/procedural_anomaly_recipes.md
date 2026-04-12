# Procedural Anomaly Recipes — K4 as an Escape Room

**Date:** 2026-04-11
**Author:** Colin Patrick + Claude (Opus 4.6)
**Status:** Live operational document
**Truth Tag:** [POLICY] for the reframe; individual recipes are [HYPOTHESIS]

---

## 0. Why This Document Exists

The exhaustion audit (2026-04-08) concluded that the bounded-family cipher search
is effectively saturated: 50+ cipher families eliminated, 105K+ composition branches
at noise floor, the only algebraic survivor is running-key residual. Yet K4 remains
unsolved.

**The missing paradigm:** Sanborn is a sculptor, not a cryptographer. He sat with
Scheidt for 2-3 meetings, learned "systems that didn't necessarily depend on
mathematics" and "coding systems he could modify in myriad ways," then built
something with a chisel. Gillogly confirmed: "K4 employs an invention by Ed
Scheidt that has never appeared in cryptographic literature."

The framework tests cipher **families** — named mathematical objects with bounded
parameter spaces. But Sanborn didn't pick from a taxonomy. He followed a
**procedure** — a sequence of physical/manual steps that may combine known
primitives in a way no catalog describes.

**This document reframes the open attack surface.** Instead of organizing by
cipher family, it organizes by **physical anomaly** and asks: what concrete
procedure does this anomaly suggest, and has that procedure been tested?

### The escape-room paradigm

An escape room gives you:
1. An environment with objects in it
2. Some objects have anomalies (things "wrong" or "out of place")
3. The anomalies, combined correctly, reveal a procedure
4. The procedure, executed on the right material, yields the answer

Kryptos maps directly:

| Escape-room element | Kryptos analog |
|---|---|
| The locked box | K4 ciphertext (97 chars) |
| Clue objects in the room | Anomalies (YAR, extra L, compass, misspellings, etc.) |
| The combination / key | A physical procedure derived from the anomalies |
| The "aha" moment | Realizing anomalies are *instructions*, not decoration |

### What goes in "underexplored"

The filter is NOT "can we parameterize it and sweep it computationally?" The
filter IS: **has this anomaly been operationalized as a concrete physical
procedure and actually executed on the 97 characters?**

Most anomalies have been catalogued and speculated about. Few have been turned
into a recipe that someone actually performs step-by-step on the ciphertext.
The framework has tested many of these anomaly values as *algebraic parameters*
(e.g., YAR numeric values as key material), but not as *procedural instructions*
(e.g., "start at Y, offset by A, rotate R").

---

## 1. Anomaly Inventory with Procedural Status

Each anomaly from `docs/anomaly_registry.md` is assessed: what procedure does
it suggest, and has that specific procedure been tested?

### Legend

- **TESTED-AS-ALGEBRA**: Values were fed into parameterized cipher sweeps
- **TESTED-AS-PROCEDURE**: A specific step-by-step physical operation was
  implemented and tested
- **UNTESTED-PROCEDURE**: The anomaly suggests a procedure that has never been
  executed on K4
- **PARTIALLY-TESTED**: Some procedural interpretations tested, others not

---

### A1. "LAYER TWO" (K2 plaintext ending)

**Anomaly:** K2 decrypts to "X LAYER TWO" (corrected 2006). An operational
instruction embedded in the plaintext of K2.

**Algebraic interpretation (TESTED):** Two-layer composition of cipher families.
105K+ branches tested in composition framework. Max 6/24. Dead as algebra.

**Procedural interpretations (UNTESTED or PARTIAL):**

| Recipe ID | Procedure | Tested? | Script |
|---|---|---|---|
| P-A1-1 | Write K4 on a transparency. Physically overlay on K1 or K2 ciphertext region of the sculpture. Read the result. | PARTIAL — `e_k3k4_overlay_k1k2.py` tested grid overlay, but as a cipher operation, not as physical position-mapping with the sculpture's actual line breaks | `scripts/team/e_k3k4_overlay_k1k2.py` (DEPRECATED) |
| P-A1-2 | "Layer two" = the second pass. Decrypt K4 with one method, then decrypt the result with a second method. Try: (a) decrypt with tableau keyword, then (b) read result via a physical operation (grille, route). | TESTED-AS-ALGEBRA via composition framework. NOT tested with anomaly-derived parameters for each layer. | — |
| P-A1-3 | "Layer two" = literally the second *layer* of copper. The sculpture has two sides. Read something from behind the cipher panel through the cutout letters. | UNTESTED-PROCEDURE | — |
| P-A1-4 | K3 plaintext ends "CAN YOU SEE ANYTHING Q" — answer to Howard Carter finding Tutankhamun's tomb. K2 says "LAYER TWO." K3 asks the question. K4 is the answer. The "layer" is archaeological: the next stratum down. Procedure: strip the top layer (some operation) to reveal the layer beneath. | CONCEPTUAL — no concrete procedure defined | — |

**Priority:** LOW-MEDIUM. "Layer two" has been heavily explored algebraically.
The untested angles (P-A1-3, P-A1-4) need physical data or a more concrete
procedure definition.

---

### A5. YAR Superscript (physically raised letters)

**Anomaly:** Letters Y, A, R (possibly DYARO) are physically raised several
centimeters above baseline on the cipher panel, near the K3/K4 boundary.
Confirmed by Elonka Dunin with physical rubbings (Oct 2002).

**Algebraic interpretations (TESTED):**
- Y=24, A=0, R=17 as key material: tested in periodic, progressive, and
  primer-value sweeps. Noise.
- YAR as Vimark primer seeds: tested in E-JTS-08/11. Zero consistent primers.
- 50+ YAR-themed scripts: zero cipher signal (see `reports/yar_anomaly_audit_2026_04_03.md`).

**Procedural interpretations:**

| Recipe ID | Procedure | Tested? | Script |
|---|---|---|---|
| P-A5-1 | YAR marks the boundary. Start reading K4 from the first character AFTER the YAR position on the sculpture. The "superscript" means "skip these." | UNTESTED-PROCEDURE — position-dependent reading order not tested | — |
| P-A5-2 | YAR reversed = RAY. "Between subtle shading and the absence of light" — shine a light (RAY) through the sculpture cutouts at the YAR position. The light pattern on the wall behind reveals the reading order. | UNTESTED — requires physical access | — |
| P-A5-3 | Y, A, R as a signature/authentication trigraph (like a radio callsign). They don't encrypt anything — they identify the sender/receiver. Skip them entirely when decrypting K4. (Consistent with Scheidt's "receiver identity built into the process.") | PARTIALLY TESTED — K4 with 3 chars removed has been tested as CT94, but not specifically with YAR identified as the removed characters at their sculpture positions | — |
| P-A5-4 | DYARO (5 chars) as a Beaufort primer. D=3, Y=24, A=0, R=17, O=14. These are the first 5 values of the keystream. Then the keystream extends by some rule (autokey, Fibonacci, running). | TESTED-AS-ALGEBRA — Vimark/Gromark primers exhaustively swept. Fibonacci eliminated (E-FRAC-38). But DYARO specifically as a non-recurrence primer + bespoke extension hasn't been tested. | — |

**Priority:** LOW. Extensively tested as algebra. Procedural angles mostly
require physical access or produce interpretations that have been covered by
algebraic equivalents. The authentication-trigraph interpretation (P-A5-3) is
the most interesting untested angle.

---

### A6 + C5. "?" Between K3/K4 + "T IS YOUR POSITION"

**Anomaly:** A question mark sits between K3 and K4. The Morse code reads
"T IS YOUR POSITION" (or "WHAT IS YOUR POSITION"). Combined: QTH = standard
Morse prosign for "What is your position?"

**Algebraic interpretations (TESTED):**
- T=19 as starting position in various sweeps. Tested.
- Position 19 as offset for reading order. Tested in route/columnar.

**Procedural interpretations:**

| Recipe ID | Procedure | Tested? |
|---|---|---|
| P-C5-1 | Literal COMSEC instruction: Go to column T (the 20th column, 0-indexed 19) of the Vigenère tableau. Read down that column. The sequence of letters is your keystream. Apply to K4. | TESTED — `blitz_t_position.py`, `blitz_t_position_v2.py`, `blitz_t_position_extended.py`. The T-column of the standard and KA tableaux were tested as keystreams. Noise. |
| P-C5-2 | "T is your position" = T is a position MARKER in K4. Find all T's in K4 CT (positions 35, 37, 50, 67, 68, 80 — six T's). These mark segment boundaries. Read K4 in 7 segments defined by the T positions. | PARTIALLY TESTED — T-position segmentation tested in `blitz_t_position_v2.py` approach C, but only as landmarks for grid overlay, not as segment boundaries for independent decryption |
| P-C5-3 | Numbers station protocol: "T is your position" means use the T-row of your one-time pad (= the tableau). Procedure: (1) Find row T in the tableau, (2) use that row as the substitution alphabet for K4. This is just Caesar shift by T=19. | TESTED — Caesar/ROT-N exhaustively eliminated |
| P-C5-4 | "Your position" = the compass bearing. The lodestone deflects the compass to point ENE (~67.5°). T = 19. 19 × 360/26 ≈ 26.3° — not ENE. But if A=0 and T=19 in KA ordering: T is at KA position 5. 5 × 360/26 ≈ 69.2° ≈ ENE. Procedure: the KA-indexed value of T gives the compass bearing, confirming KA is operative. | CONCEPTUAL — this is a cross-validation, not a decryption procedure |
| P-C5-5 | DRYAD interpretation: In military COMSEC, a DRYAD is a 26-row × 26-col random substitution table, pre-distributed on a numbered card. "T is your position" = use DRYAD row T. The tableau IS a DRYAD table. Row T of the KA-keyed tableau gives a specific substitution. | TESTED — Quagmire variants with KA-keyed tableau exhaustively tested and eliminated |
| P-C5-6 | "What is your position?" is the question. K4's plaintext IS the answer — a position report. The decrypted K4 gives coordinates, a grid reference, or a location description. This constrains what the plaintext looks like, not the decryption method. | OBSERVATIONAL — consistent with BERLINCLOCK crib |

**Priority:** LOW. Heavily tested. The most interesting untested angle is
whether T-positions in K4 serve as segment boundaries for independent
sub-ciphers (P-C5-2 as a segmentation mechanism, not just landmarks).

---

### B1. Extra "L" on Tableau → HILL

**Anomaly:** Row N of the tableau has an extra L, making HILL readable down the
right edge. Same line as YAR superscript on the cipher side.

**Algebraic interpretations (TESTED):**
- Hill cipher 2×2, 3×3, 4×4: eliminated (Tier 1 + E-BESPOKE-42).

**Procedural interpretations:**

| Recipe ID | Procedure | Tested? |
|---|---|---|
| P-B1-1 | The extra L is a POINTER. It extends row N one character past the grid boundary. On the cipher side, the corresponding position is near YAR. The extra L says "look HERE" — it marks a specific position on the cipher panel. | UNTESTED-PROCEDURE — the positional correspondence between the extra L and specific cipher-panel characters hasn't been exploited as a starting-point marker |
| P-B1-2 | HILL is not the cipher name — it's a **person's name**. Lester S. Hill published his cipher in 1929. But more relevantly, in the escape-room paradigm: "hill" = elevated terrain. YAR is physically elevated (superscript). The extra L + YAR together say "the raised letters matter." | CONCEPTUAL |
| P-B1-3 | The extra L changes the character count of row N from 26 to 27. If you use the tableau as a grid overlay, row N is offset by 1 character relative to all other rows. This misalignment could be the grille mechanism: place the tableau on the cipher panel, and the shifted row N reads different characters than a clean overlay. | UNTESTED-PROCEDURE — misaligned-row overlay never tested |

**Priority:** MEDIUM. P-B1-3 (misaligned overlay) is a genuinely untested
physical procedure. It's concrete enough to implement.

---

### D1. Compass Rose Deflected by Lodestone → ENE

**Anomaly:** The lodestone physically deflects a compass to point approximately
ENE. EASTNORTHEAST is the first K4 crib.

**Algebraic interpretations (TESTED):**
- ENE as compass bearing → numeric value → key material. Tested.
- ENE direction as reading direction on grids. Tested in route/spiral scripts.

**Procedural interpretations:**

| Recipe ID | Procedure | Tested? |
|---|---|---|
| P-D1-1 | The compass is a CALIBRATION TOOL. Place a compass on the sculpture. The lodestone makes it point to a specific character on the cipher panel. That character is where you start reading. | UNTESTED — requires physical measurement to determine exact character |
| P-D1-2 | ENE = 67.5°. On a 360° compass rose with 26 positions (one per letter), 67.5° points to letter index floor(67.5 × 26/360) = 4 → E (A=0). "E is your position" = start at the first E in K4? | TESTED — various E-position starting points tried |
| P-D1-3 | The compass doesn't point to a letter — it points to the **pool**. The pool is between the viewer and the sculpture. You must go AROUND or THROUGH the pool to reach the sculpture. The pool's circular water motion defines a rotational reading direction. | CONCEPTUAL — requires physical visit |

**Priority:** LOW. The compass→ENE link is already confirmed by the cribs.
Further exploitation requires physical access.

---

### C1 + C2. Extra E's (26 total) + DIGETAL Misspelling

**Anomaly:** 26 extra E's in the Morse code (exact alphabet size). DIGETAL
misspelling adds one E.

**Procedural interpretations:**

| Recipe ID | Procedure | Tested? |
|---|---|---|
| P-C1-1 | 26 E's = 26 binary markers. Each E marks a position. Map E positions in the Morse code to corresponding positions on the cipher panel (by line alignment). The marked positions form a grille mask. Read K4 through that mask. | UNTESTED-PROCEDURE — E positions haven't been mapped to cipher-panel positions as a mask |
| P-C1-2 | E in Morse = single dit (.). The E's are PADDING to align the Morse text to a specific width or rhythm. Strip the E's and re-parse. The remaining text may contain additional hidden messages. | PARTIALLY TESTED — Morse analysis exists but not with E-stripping + re-parsing |
| P-C1-3 | 26 E's = alphabet mapping. The E's appear in a specific sequence of positions. Each E position maps to a letter A-Z (1st E → A, 2nd → B, ..., 26th → Z). This gives a monoalphabetic substitution key. | UNTESTED-PROCEDURE |

**Priority:** MEDIUM. P-C1-1 (E-positions as grille mask) is concrete and
testable without physical access if the Morse-to-cipher-panel positional
correspondence is established.

---

### A3. UNDERGRUUND (transcription-phase error)

**Anomaly:** The coding chart says UNDERGROUND correctly. The sculpture has
UNDERGRUUND. The error is in the TRANSCRIPTION onto copper — E became R in the
ciphertext. This is the only confirmed transcription-phase modification.

**Procedural interpretation:**

| Recipe ID | Procedure | Tested? |
|---|---|---|
| P-A3-1 | The sculpture IS the message, errors and all. The physical copper is the authoritative text, not the coding charts. Any procedure must use what's ON THE COPPER, including all "errors." K4's CT is exactly what's carved — no corrections needed. | OPERATIONAL ASSUMPTION — this is how we already operate |
| P-A3-2 | Conversely: if Sanborn deliberately changed letters during transcription, he may have done the same to K4. The "true" K4 CT may differ from the carved CT at 1-3 positions. Search: for each 1-3 position substitution of K4 CT, test against the known cribs. | PARTIALLY TESTED — some perturbation analysis exists but not systematic single-char substitution sweep of all 97 positions × 25 alternatives |

**Priority:** LOW-MEDIUM. P-A3-2 (CT perturbation) is a large but bounded
search (97 × 25 = 2,425 single-char variants, combinatorially larger for
multi-char). Worth a cheap sweep if framed correctly.

---

### A4. DESPARATLY (Sanborn refused to answer)

**Anomaly:** DESPERATELY → DESPARATLY. Changed positions: E→A at word position
5, E deleted at word position 8. Sanborn's REFUSAL to answer whether this was
intentional is the loudest signal in the anomaly registry.

**Procedural interpretations:**

| Recipe ID | Procedure | Tested? |
|---|---|---|
| P-A4-1 | The numbers 5 and 8 are step/stride parameters. Write K4 into a grid of width 5, read every 8th character. Or: skip 5, read 8, skip 5, read 8... | PARTIALLY TESTED — width-5 columnar is Bean-eliminated, but stride-8 reading or skip-5-read-8 pattern is NOT a standard columnar and has not been tested |
| P-A4-2 | DESPARATLY has 10 letters. DESPERATELY has 11. 11 - 10 = 1. The missing letter count per anomaly: PALIMPCEST (1 changed), IQLUSION (1 changed), UNDERGRUUND (1 changed), DESPARATLY (1 changed + 1 missing = 2), DIGETAL (1 changed). Total alterations: 6. Total missing: 1. This may be a count clue. | CONCEPTUAL |
| P-A4-3 | Positions 5, 8 in K4 CT are B, S. In AZ: B=1, S=18. BS or 1,18 as key fragment? | TESTED-AS-ALGEBRA — individual position values as key seeds tested |
| P-A4-4 | "E→A" = "encrypt E as A" — a substitution hint. Under Beaufort A=0: if PT=E(4) and CT=A(0), key = (0-4) mod 26 = 22 = W. Under Vigenère: key = (0-4) mod 26 = 22 = W. This gives us a key letter: W. Combined with position 5: key position 5 = W? | UNTESTED-PROCEDURE — extracting key values from the misspelling substitutions as a system has not been tested |

**Priority:** MEDIUM. P-A4-1 (skip-5-read-8 pattern) and P-A4-4 (misspellings
as substitution examples) are both genuinely untested procedures.

---

### F1. Collected Misspelling Substitutions (cross-cutting)

**Anomaly:** Five deliberate letter substitutions across the installation:
- PALIMPCEST: S→C (keyword position 7)
- IQLUSION: L→Q
- UNDERGRUUND: O→U (transcription phase — disputed)
- DESPARATLY: E→A, missing E
- DIGETAL: I→E

**Procedural interpretations:**

| Recipe ID | Procedure | Tested? |
|---|---|---|
| P-F1-1 | Each substitution is an example encryption. The wrong letter is the CT, the correct letter is the PT. Extract the implied key value for each: C=(S→C): Vig key = C-S = -16 ≡ 10 = K. Q=(L→Q): Vig key = Q-L = 5 = F. U=(O→U): Vig key = U-O = 6 = G. A=(E→A): Vig key = A-E = -4 ≡ 22 = W. E=(I→E): Vig key = E-I = -4 ≡ 22 = W. Key fragment: K, F, G, W, W. | UNTESTED-PROCEDURE — these key values have never been tested as a keystream fragment or primer |
| P-F1-2 | Same as P-F1-1 but under Beaufort: C=(K-P)%26. S→C: K=(C+S)%26 = (2+18)%26 = 20 = U. L→Q: K=(Q+L)%26 = (16+11)%26 = 1 = B. O→U: K=(U+O)%26 = (20+14)%26 = 8 = I. E→A: K=(A+E)%26 = (0+4)%26 = 4 = E. I→E: K=(E+I)%26 = (4+8)%26 = 12 = M. Key fragment: U, B, I, E, M. | UNTESTED-PROCEDURE |
| P-F1-3 | The substituted letters themselves form a set: {C, Q, U, A, E}. Rearranged: EQUAL (community observation, but disputed because U comes from UNDERGRUUND which may not be intentional). If valid: "EQUAL" as keyword for some operation. | TESTED — EQUAL as keyword tested in sweep. Noise. |
| P-F1-4 | The CORRECT letters that were replaced form a set: {S, L, O, E, I}. Rearranged: SOLEI (French: sun), OILES, OLIES, OSIEL, LOSEI... or as anagram: OLIES, OISLE. No obvious word. As values: S=18, L=11, O=14, E=4, I=8 → 18, 11, 14, 4, 8. | UNTESTED — these five values as key/primer not specifically tested |

**Status (2026-04-11):** TESTED — NOISE. ~4,000 configs across all primers
(full/no-UG × 3 variants × 2 orderings × 17 extension rules × 3 decrypt
variants), plus position-specific placement, reverse PT/CT assignment, and
alternate primers (word positions, word lengths, letter values). Best 5/24,
all fail Bean equality. Primer values show no substring match or structural
overlap with the known keystream at crib positions. Script:
`scripts/analysis/e_misspelling_key_extraction.py`.

**Priority:** LOW (downgraded from HIGH). They treat the misspellings as literal encryption
examples — which is exactly how an escape room works: "here's a worked example,
now apply the same rule to the locked box." If Sanborn was showing the solver
how his cipher works by embedding example encryptions in the surrounding text,
the implied key values could be the actual key (or primer) for K4.

---

### B2. Tableau Flipped (readable from behind)

**Anomaly:** The Vigenère tableau is engraved from the back, readable only from
behind the sculpture.

**Procedural interpretation:**

| Recipe ID | Procedure | Tested? |
|---|---|---|
| P-B2-1 | "Things are reversed." The cipher text should be read backwards (position 96 first). Decrypt the reversed CT. | TESTED — reverse reading tested and eliminated |
| P-B2-2 | The tableau is meant to be used FROM BEHIND. When you stand behind the sculpture, the tableau is on your LEFT and the cipher panel is on your RIGHT. The physical act of looking through the cipher panel cutouts from behind, with the tableau visible through them, IS the decryption procedure. | UNTESTED — requires physical access |
| P-B2-3 | Mirror the tableau (read each row right-to-left). Use the mirrored tableau for decryption instead of the standard one. | PARTIALLY TESTED — reversed/reflected alphabets tested in Quagmire sweeps, but not specifically the mirrored tableau as a lookup table |

**Priority:** LOW. Mostly requires physical access.

---

### E0b. Minor Differences (KRYPTOS-set letters stay close)

**Anomaly:** At the 24 known PT positions, when PT ∈ {K,R,Y,P,T,O,S}, the
corresponding CT letters are very close in the standard alphabet (mean distance
2.1, p ≈ 1/5,520). Bean argues this strongly implies one-to-one substitution.

**Procedural interpretation:**

| Recipe ID | Procedure | Tested? |
|---|---|---|
| P-E0b-1 | The cipher alphabet is "near" the standard alphabet — a small perturbation, not a keyword mixing. Procedure: generate all alphabets that are within Hamming distance 5-8 of ABCDEFGHIJKLMNOPQRSTUVWXYZ and test each as a Beaufort/Vig cipher alphabet. | UNTESTED — "near-AZ" alphabets as cipher alphabets not systematically tested |
| P-E0b-2 | The closeness implies the key values at KRYPTOS-letter positions are small. The key is not random — it's structured to produce small shifts for specific PT letters. This constrains the key generator. | OBSERVATIONAL — feeds into keystream forensics |

**Priority:** MEDIUM. P-E0b-1 is a bounded search (alphabets near AZ) that
hasn't been tried.

---

### E0e. Width-21 Repeated Vertical Bigrams

**Anomaly:** Writing K4 at width 21 gives 11 repeated vertical bigrams out of
76 (p ≈ 1/6,750 for random, but consistent with English at width 21).

**Procedural interpretation:**

| Recipe ID | Procedure | Tested? |
|---|---|---|
| P-E0e-1 | Width 21 is the intended grid width. Write K4 in 21 columns. Read columns in some order (not standard columnar — use an anomaly-derived order). Example: use YAR (Y=24→24%21=3, A=0, R=17) as column-read indices: start at column 3, then column 0, then column 17, then... | PARTIALLY TESTED — columnar w21 tested with standard orderings but not with anomaly-derived column orders |
| P-E0e-2 | Width 21 is related to the Fibonacci sequence (21 = F(8)). The Gromark cipher uses Fibonacci-like key generation. Width 21 could be a Gromark artifact with a 5-digit primer (period 21). Primers exhaustively tested (E-FRAC-38: 0/676 survive Bean). But: what if the Fibonacci addition is mod 21, not mod 26? Or mod 10? | PARTIALLY TESTED — Fibonacci mod 26 eliminated. Non-standard moduli not tested. |

**Priority:** MEDIUM. Width 21 remains the strongest statistical anomaly in K4.
Non-standard-modulus Fibonacci at width 21 is a genuine gap.

---

## 2. Composite Procedural Hypotheses

These combine multiple anomalies into a single multi-step procedure — the
escape-room "solution chain."

### CP-1: The COMSEC Message Procedure

**Chain:** C5 (T IS YOUR POSITION) → D1 (compass → ENE) → A5 (YAR as callsign)

**Procedure:**
1. "T is your position" → find position T in the tableau (row or column T)
2. The compass confirms direction: read ENE (upper-right diagonal on a grid)
3. YAR is the authentication trigraph — strip it before decrypting
4. Remaining text decrypts with the key derived from step 1

**Status:** Steps 1 and 3 individually tested. The COMBINATION as a procedure
has not been tested as a single pipeline.

**Priority:** MEDIUM. The individual components are noise, but they may only
work in combination. Worth wiring up as a single procedure.

---

### CP-2: The Worked-Example Procedure

**Chain:** F1 (misspellings as examples) → A1 (LAYER TWO) → B1 (HILL pointer)

**Procedure:**
1. Extract key values from misspelling substitutions (P-F1-1 or P-F1-2)
2. These give the first 5 key values (primer)
3. Extend the key using a generation rule (Fibonacci, autokey, running)
4. "Layer two" = apply a second operation after decryption
5. The extra L / HILL marker tells you where to start the second operation

**Status:** Step 1 is UNTESTED. Steps 2-5 depend on step 1 producing coherent
output. This is the highest-priority composite hypothesis.

**Priority:** HIGH. If step 1 produces values that, when used as a primer,
decrypt K4 to anything above noise, this immediately becomes the leading
hypothesis.

---

### CP-3: The Grid Reading Procedure

**Chain:** E0e (width 21) → A4 (DESPARATLY: 5, 8) → A6 (? separator)

**Procedure:**
1. Write K4 into a width-21 grid (4 full rows + 1 partial row of 13)
2. The "?" between K3 and K4 is NOT part of K4 — it's a separator
3. Skip every 5th position, read every 8th (from DESPARATLY)
4. The extracted characters form the "real" ciphertext
5. Decrypt the extracted text with a standard method

**Status:** Width-21 grid tested with standard columnar. Skip-5/read-8 pattern
UNTESTED on width-21 grid. This specific combination is genuinely novel.

**Priority:** MEDIUM.

---

### CP-4: The Physical Overlay Procedure

**Chain:** A1 (LAYER TWO) → B1 (extra L offset) → B2 (flipped tableau)

**Procedure:**
1. The tableau is physically layered over the cipher panel (readable from
   behind = it faces the cipher panel when the sculpture is assembled)
2. The extra L on row N creates a 1-character offset on that row
3. Positions where tableau letters align with cipher-panel letters cancel
   or transform (XOR-like)
4. Positions where they DON'T align (due to the offset) reveal the real
   message

**Status:** `e_tableau_overlay.py` exists (DEPRECATED) but tested a simplified
version: remove tableau letters from cipher text. The physical-alignment version
with the row-N offset has NOT been tested.

**Priority:** MEDIUM-HIGH. P-B1-3 (misaligned row overlay) is concrete,
implementable, and genuinely untested.

---

### CP-5: The 26-E Mask Procedure

**Chain:** C1 (26 E's) → A1 (LAYER TWO) → "stego"

**Procedure:**
1. Map the 26 Morse E positions to their physical line positions on the
   entrance slabs
2. Project those positions onto the cipher panel (same line on the facing
   surface)
3. The projected positions form a 26-position mask on the 869-char cipher text
4. Characters at those positions are "nulls" — remove them
5. The remaining characters, or specifically the K4-region subset, form the
   true ciphertext
6. Decrypt the reduced text

**Status:** UNTESTED-PROCEDURE. Requires establishing the physical line
correspondence between Morse slabs and cipher panel.

**Priority:** MEDIUM. Depends on whether the Morse/cipher-panel physical
correspondence can be established without a site visit.

---

## 3. Implementation Priority Queue

Ordered by: (a) genuinely untested, (b) concretely implementable without
physical access, (c) highest escape-room coherence.

| Rank | Recipe | Why |
|---|---|---|
| 1 | **P-F1-1 / P-F1-2** (misspellings as encryption examples → key values) | Highest escape-room coherence. "Here's how the cipher works" embedded in the sculpture. Completely untested. Implementable in 30 minutes. |
| 2 | **P-B1-3** / **CP-4** (misaligned tableau overlay with row-N offset) | Concrete physical procedure. The extra L has a specific mechanical effect on overlay alignment. Untested. |
| 3 | **P-A4-1** (skip-5/read-8 from DESPARATLY) | Non-standard extraction pattern. Not columnar. Testable on K4 directly. |
| 4 | **P-E0b-1** (near-AZ cipher alphabets) | Bean's statistical anomaly directly suggests the cipher alphabet is close to standard AZ. Bounded search. |
| 5 | **CP-2** (worked-example composite: misspelling keys → primer → extend) | Depends on P-F1-1/2 producing coherent output. Natural follow-up. |
| 6 | **P-E0e-2** (non-standard-modulus Fibonacci at width 21) | Strongest statistical anomaly + known gap in Fibonacci modulus testing. |
| 7 | **P-C1-1** (26 Morse E positions → grille mask) | Requires establishing Morse/cipher positional correspondence. Medium difficulty. |
| 8 | **CP-1** (COMSEC composite: T-position + compass + YAR strip) | All components individually noise, but the combination is untested. |

---

## 4. Statistical Anomalies as Procedural Fingerprints

**[POLICY] Strong-to-moderate statistical anomalies are NOT abandoned under the
procedural paradigm — they are CONSTRAINTS on any proposed procedure.**

Whatever hand-executable method Sanborn used, it produced the ciphertext we
have. That ciphertext contains mathematical regularities that are the *shadows*
of the procedure. These shadows are how we detect and validate procedural
hypotheses. A procedure that cannot explain the strongest anomalies is wrong,
even if it's physically plausible.

### Anomalies that any valid procedure MUST explain

| Anomaly | Strength | What it constrains |
|---|---|---|
| **Bean minor-diffs** (p≈1/5520) | STRONG | The cipher alphabet is "near" standard AZ for KRYPTOS-set letters. Rules out any procedure that produces wildly scrambled substitutions at those positions. |
| **Width-21 vertical bigrams** (p≈1/6750) | STRONG | The ciphertext has columnar structure at width 21. Any procedure must either produce this directly or be consistent with it as an artifact. |
| **Stehle delta-5 lag-4** (p≈1/642 corrected) | MODERATE-STRONG | Positions 55-63 have a constant-difference property. This is a local regularity — it constrains what the key generation or substitution rule does in that specific segment. A procedure that uses a structured key (e.g., Fibonacci-like, stepped, or table-based) could produce this. A completely random key cannot. |
| **Bean equality k[27]=k[65]** | HARD CONSTRAINT | Whatever generates the keystream must produce the same value 38 positions apart. This eliminates most periodic structures but is naturally satisfied by running-key or position-dependent lookup procedures. |
| **624 valid keystreams** | HARD CONSTRAINT | The procedure's keystream at the 24 crib positions must be one of exactly 624 survivors of the Bean eq+ineq+linear system. |

### How to use these in recipe testing

When testing a procedural recipe:
1. First check: does the procedure's keystream match one of the 624 valid
   keystreams? If not, the procedure is dead.
2. Second check: does the procedure produce the Stehle delta-5 property at
   positions 55-63? If not, the procedure doesn't explain the strongest local
   regularity.
3. Third check: does the procedure produce near-identity substitutions for
   KRYPTOS-set letters? If not, it contradicts Bean's strongest global signal.
4. Fourth check: does the procedure produce width-21 columnar structure? If
   not, it must explain why the strongest positional anomaly exists.

A procedure that passes all four checks would be an extraordinarily strong
candidate, even before checking the full plaintext.

---

## 5. What This Document Does NOT Claim

- It does NOT claim that the algebraic search was wrong. The eliminations are
  real and permanent.
- It does NOT claim that any specific recipe above will work. Each is
  [HYPOTHESIS] with low prior probability.
- It does NOT claim that Kryptos is "just an escape room." It uses the
  escape-room *paradigm* as a lens for generating testable procedures that the
  algebraic framework missed.
- It does NOT override the Bean constraints. Any procedure that produces a
  candidate plaintext must still pass HC-1 through HC-4 from `constraint_spec.md`.
- It does NOT abandon mathematical analysis. Statistical anomalies are the
  *fingerprints* of the procedure — they are how we constrain, detect, and
  validate procedural hypotheses. The procedural and mathematical paradigms
  are complementary, not competing.

The claim is narrower: **the anomalies have been tested as algebra but not as
procedures, and a sculptor's puzzle is more likely to be procedural than
algebraic. But the procedure, whatever it is, left mathematical traces that
we must use to find it.**

---

## 5. Relationship to Existing Bins

This document proposes recipes that currently fall in **Bin E** ("bespoke
chart-based cipher: no parameterization") or **Bin D** ("weakly testable").
The recipes above ARE the parameterization that the exhaustion audit said was
missing. They turn "bespoke" into concrete, testable, bounded procedures.

If any recipe produces a score ≥18/24 + Bean pass, it should be escalated
through the standard pipeline (`docs/preregistered_thresholds_2026_04_08.md`).

If all recipes produce noise, the document serves as a formal record of what
was tried under the procedural paradigm, analogous to how `elimination_tiers.md`
records what was tried under the algebraic paradigm.

---

*Last updated: 2026-04-11*
*Primary author: Colin Patrick (human lead) + Claude (computational partner)*
