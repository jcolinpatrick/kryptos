# K4 Mapping Matrix

**Purpose:** Map every cipher family to K4-specific observables, elimination status, and actionable experiment outlines. This is the action-oriented bridge between historical cryptographic knowledge (`20_cipher_catalog.md`) and the project's elimination record (`docs/elimination_tiers.md`).

**Rule:** Ciphertext, cribs, and Bean constraints are defined in `kryptos.kernel.constants`. Never hardcode them. Elimination proofs are in `docs/elimination_tiers.md`; this file references them by experiment ID, not re-derives them.

---

## Part 1: Master Matrix

Legend for **Elimination Status**:
- **ELIMINATED-T1**: Tier 1 mathematical proof
- **ELIMINATED-T2**: Tier 2 exhaustive search (single-layer, direct correspondence)
- **PARTIALLY-TESTED**: Some parameters tested, others open
- **UNTESTED**: Never tested in this repo
- **OPEN-MULTI**: Eliminated as single layer, open as one layer of multi-layer
- **STRUCTURALLY-BLOCKED**: Violates ALPHA-26 or other hard constraint

| Cipher Family | Code | Observable Artifacts | K4 Compatibility | Elimination Status | Repo Reference | Priority |
|---|---|---|---|---|---|---|
| **Caesar / simple shift** | SUB-MONO | IC unchanged from PT (~0.065); frequency peaks shifted uniformly | Violates IC-LOW (would preserve English IC); violates CRIB-24 (only 1 of 26 shifts could match any crib position) | ELIMINATED-T2 | E-S series (exhaustive 26 shifts) | CLOSED |
| **Keyword-mixed monoalphabetic** | SUB-MONO | IC unchanged from PT; digraph/trigraph frequencies redistributed but IC preserved | Violates IC-LOW; violates CRIB-24 (fixed substitution cannot satisfy both cribs simultaneously) | ELIMINATED-T2 | E-S series; E-BESPOKE-50 (affine variants) | CLOSED |
| **Affine substitution** | SUB-MONO | IC unchanged; 12 valid multipliers x 26 shifts = 312 options | Violates IC-LOW; same structural issue as mono | ELIMINATED-T2 | E-BESPOKE-50 | CLOSED |
| **Vigenere (periodic key)** | SUB-POLY | IC depends on period; IC-LOW consistent with long period; periodic Kasiski/Friedman signature | Satisfies ALPHA-26. Violates NON-PERIODIC (proven). Violates BEAN-EQ at all periods 2-26 + any transposition (E-FRAC-35 proof for periods outside {8,13,16,19,20,23,24,26}; E-FRAC-55 closes remaining) | ELIMINATED-T1 | E-FRAC-35, E-FRAC-55, E-S series (~3B configs) | CLOSED |
| **Beaufort / Variant Beaufort** | SUB-POLY | Same IC/periodicity profile as Vigenere; Bean constraint is variant-independent | Same as Vigenere: NON-PERIODIC violation, BEAN-EQ proof applies identically | ELIMINATED-T1 | E-FRAC-35 (variant-independent proof) | CLOSED |
| **Quagmire I/II/III/IV** | SUB-POLY | Periodic keyed-alphabet lookup; IC depends on period; same periodicity signature as Vigenere | Satisfies ALPHA-26. Falls under periodic polyalphabetic; E-FRAC-35 covers all periodic keying | ELIMINATED-T1 | E-FRAC-35; E-TABLEAU-21; E-JTS-13 | CLOSED |
| **Gronsfeld** | SUB-POLY | Vigenere restricted to digits (key values 0-9); periodic | Subset of periodic Vigenere; same elimination applies | ELIMINATED-T1 | E-FRAC-35 (subset) | CLOSED |
| **Porta** | SUB-DIGRAPH | Reciprocal pairs; only 13 cipher alphabets; IC typically higher than Vigenere for same period | Violates CRIB-24 under direct correspondence (reciprocal constraint). [DERIVED FACT] Porta's involutory property (E=D) constrains key space further | ELIMINATED-T2 | E-S series | CLOSED |
| **Autokey (PT-autokey, CT-autokey)** | SUB-POLY-AUTO | Non-periodic (key seeded then self-generating); IC approaches English for long messages | Satisfies ALPHA-26, NON-PERIODIC. Violates CRIB-24: structurally cannot reach 24/24 even with arbitrary transposition (PT max=16/24, CT max=21/24) | ELIMINATED-T1 | E-FRAC-37 | CLOSED |
| **Running key** | SUB-POLY-RUN | Non-periodic; IC depends on key text language; key fragments should be readable text | Satisfies ALPHA-26, NON-PERIODIC, BEAN-EQ, BEAN-INEQ. [INTERNAL RESULT] Only structured non-periodic model surviving all Bean constraints (E-FRAC-38). Running key + known texts + structured transpositions: eliminated (E-FRAC-49/50). Unknown English + columnar: eliminated (E-FRAC-51). **Mono+Trans+Running key: UNDERDETERMINED** (E-FRAC-54) | PARTIALLY-TESTED | E-FRAC-38/39/49/50/51/54 | HIGH |
| **Gromark / Vimark** | SUB-POLY-PROG | Linear recurrence keystream; periodic modular structure; IC varies with primer | Violates BEAN-EQ: E-FRAC-38 eliminates Fibonacci/progressive/quadratic recurrence via Bean. E-JTS-08/11 prove zero consistent Vimark primers at all periods 2-13 for columnar and strip transpositions | ELIMINATED-T1 | E-FRAC-38; E-JTS-08/11 | CLOSED |
| **Progressive key (k[i]=k[0]+i*delta)** | SUB-POLY-PROG | Linear key growth; effectively period-2 or constant | BEAN-ELIMINATED: only delta in {0,13} survives; delta=0 is mono, delta=13 is period-2 (Bean-impossible) | ELIMINATED-T1 | E-FRAC-38 | CLOSED |
| **Quadratic / Fibonacci key** | SUB-POLY-PROG | Structured non-linear recurrence | BEAN-ELIMINATED: 0/676 seeds survive full Bean inequalities for both models | ELIMINATED-T1 | E-FRAC-38 | CLOSED |
| **Playfair** | SUB-DIGRAPH | Digraphic; requires 25-letter grid (I/J merge); IC ~0.048-0.055; produces only even-length CT | Violates ALPHA-26 (needs I/J merge but K4 has all 26 letters). Violates LEN-97 (odd length incompatible with strict digraphic) | STRUCTURALLY-BLOCKED | E-FRAC-21 | CLOSED |
| **Two-Square / Four-Square** | SUB-DIGRAPH | Digraphic; 25-letter grids; IC ~0.048-0.055 | Same structural blocks as Playfair: ALPHA-26, LEN-97 (odd) | STRUCTURALLY-BLOCKED | E-FRAC-21 | CLOSED |
| **Bifid (5x5)** | SUB-FRAC | Fractionation into coordinates; 25-letter grid; IC ~0.045-0.055 | Violates ALPHA-26 (5x5 requires I/J merge; K4 uses all 26) | STRUCTURALLY-BLOCKED | E-FRAC-21 | CLOSED |
| **Bifid (6x6)** | SUB-FRAC | 36-symbol grid; IC ~0.059-0.069 | IC-INCOMPATIBLE: K4's IC=0.0361 is at 0th percentile of Bifid 6x6 output. [INTERNAL RESULT] Proven in E-FRAC-21 | STRUCTURALLY-BLOCKED | E-FRAC-21 | CLOSED |
| **Trifid** | SUB-FRAC | 27-symbol cube fractionation; output length = 3x input (mod structure) | CT length parity constraint: Trifid output must be divisible by 3; 97 mod 3 = 1. [INTERNAL RESULT] Structural proof in E-FRAC-21 | STRUCTURALLY-BLOCKED | E-FRAC-21 | CLOSED |
| **ADFGVX / ADFGX** | SUB-FRAC | Fractionation + columnar transposition; output always even-length (ADFGVX) or paired | Output length always 2xN (even); K4=97 (odd). [INTERNAL RESULT] Parity impossibility proof in E-FRAC-21 | STRUCTURALLY-BLOCKED | E-FRAC-21 | CLOSED |
| **Straddling checkerboard** | SUB-FRAC | Variable-length encoding; produces digits 0-9 | K4 contains 26 letters, not digits. [INTERNAL RESULT] Structural proof in E-FRAC-21 | STRUCTURALLY-BLOCKED | E-FRAC-21 | CLOSED |
| **VIC cipher** | SUB-FRAC | Contains straddling checkerboard component | Inherits straddling checkerboard structural block | STRUCTURALLY-BLOCKED | E-FRAC-21 | CLOSED |
| **Enigma / Hebern / rotor machines** | SUB-POLY-MECH | State-dependent (rotor stepping); non-periodic but deterministic from initial state; IC ~0.048-0.055 | Violates K5 position-dependent constraint: K5 shares coded words at same positions, proving cipher is position-dependent NOT state-dependent. [PUBLIC FACT] K5 confirmation from Sanborn 2025 | ELIMINATED-T1 | `docs/invariants.md` section 8 | CLOSED |
| **Kryha / M-325 / KL-7** | SUB-POLY-MECH | Various mechanical polyalphabetic; state-dependent stepping | Same K5 position-dependency violation as Enigma | ELIMINATED-T1 | `docs/invariants.md` section 8 | CLOSED |
| **Hill cipher (2x2, 3x3, 4x4)** | SUB-POLY | Matrix multiplication; polygraphic; IC approaches random for large matrices | n=2,3,4: algebraic impossibility under direct correspondence. n>4: 97 is prime, so no block structure possible. With transposition: tested at w6/8/9, eliminated (E-BESPOKE-42) | ELIMINATED-T1 | E-BESPOKE-42; `docs/invariants.md` | CLOSED |
| **Simple columnar** | TRANS-COL | Rearranges positions within columns; preserves letter frequencies exactly; IC unchanged | Satisfies ALPHA-26, IC-LOW (transposition preserves IC). Tested exhaustively at widths 5-15 + periodic sub. ALL NOISE. Double columnar (9 Bean-compatible pairs): NOISE (E-FRAC-46) | ELIMINATED-T2 | E-FRAC-12/29/30/46; E-S series | OPEN-MULTI |
| **Myszkowski transposition** | TRANS-COL | Variant columnar with repeated-key columns read differently; preserves letter frequencies | Widths 5-13 exhaustively/sampled: max 15/24, matches random | ELIMINATED-T2 | E-FRAC-47 | OPEN-MULTI |
| **AMSCO / Nihilist transposition** | TRANS-COL | Alternating single/double character fills; preserves letter frequencies | Widths 5-13: 0% Bean pass rate. Structurally Bean-incompatible | ELIMINATED-T2 | E-FRAC-48; E-S-22 | CLOSED |
| **Rail fence** | TRANS-RAIL | Zigzag pattern; preserves letter frequencies; simple position formula | Tested all rail counts; Bean-INCOMPATIBLE (reverse and rail fence: zero Bean passes per E-FRAC-50) | ELIMINATED-T2 | E-FRAC-32/50 | CLOSED |
| **Route ciphers (spiral, diagonal, serpentine)** | TRANS-ROUTE | Grid fill + non-standard read-off; preserves letter frequencies; IC unchanged | Width-9 non-columnar reads tested (serpentine, spiral, diagonal): eliminated (E-FRAC-03/45). Other grid dimensions and non-standard routes: NOT exhaustively tested beyond these | PARTIALLY-TESTED | E-FRAC-03/45 | MEDIUM |
| **Turning grille (Fleissner)** | TRANS-GRILLE | 4 rotations of quarter-grille mask; N/4 cells per rotation; requires N divisible by 4 for square grille | LEN-97: no square grid possible (97 is prime). 10x10=100 requires 3 padding chars. [INTERNAL RESULT] Universal proofs supersede: E-FRAC-35 (all transpositions + periodic key at p2-7 violate Bean), E-FRAC-44 (expected FP=0 for 4^25 options). Prior MC tests (E-S-18/70/72/104) had negligible coverage | ELIMINATED-T1 | E-FRAC-35/44; E-S-18/70/72/104 | CLOSED |
| **Cardano grille (aperture mask)** | TRANS-GRILLE | Fixed mask selects plaintext positions from a larger text; not strictly a transposition of the full CT | [INTERNAL RESULT] Tested as aperture extractor in audit (E-AUDIT series): NOISE. But Cardano with a LARGER cover text producing 97-char extract is a different model — essentially a null/selection cipher, not a transposition of K4 CT itself | PARTIALLY-TESTED | E-AUDIT series | LOW |
| **Columnar + periodic Vigenere (combined)** | MULTI | Two-layer: transposition then substitution; IC depends on substitution layer | ALL structured transposition families + ALL periodic substitution: ELIMINATED. [INTERNAL RESULT] Universal proof at discriminating periods (E-FRAC-35); exhaustive at widths 5-15 (E-FRAC-12/29/30/55) | ELIMINATED-T1 | E-FRAC-35/55; full FRAC series | CLOSED |
| **Columnar + running key** | MULTI | Two-layer: transposition then running key; non-periodic; key fragments should be readable | Known texts + columnar w6/8/9: 0/17B matches (E-FRAC-49). Unknown English + columnar: 0/16,597 in English range (E-FRAC-51). ALL structured transposition families + 7 texts: 0 matches (E-FRAC-50) | ELIMINATED-T2 | E-FRAC-49/50/51 | OPEN-MULTI |
| **Mono + transposition + running key** | MULTI | Three-layer: monoalphabetic inner + transposition + running key outer; 13 mono DOF absorb key analysis | [INTERNAL RESULT] UNDERDETERMINED: mono layer's 13 DOF saturate key fragment analysis, making English detection impossible (E-FRAC-54). This is the ONE identified open structured gap | PARTIALLY-TESTED | E-FRAC-54 | **HIGH** |
| **Sub + Trans + Sub (three-layer)** | MULTI | Effective key K_eff[j]=K1[j%p1]+K2[inv(j)%p2] is non-periodic; bypasses E-FRAC-35 | Columnar w6/8/9, periods 1-12: ZERO viable candidates. 74 candidates only at p1*p2>=132, all gibberish (best Q=-5.87/char) | ELIMINATED-T2 | E-FRAC-52 | CLOSED |
| **Mono + Trans + periodic** | MULTI | Mono layer auto-satisfies 9/21 Bean-ineq, potentially opening periods 3-7 | ZERO candidates at discriminating periods 3-7; 34 candidates at period 12, all gibberish | ELIMINATED-T2 | E-FRAC-53 | CLOSED |
| **Nomenclator / code+cipher** | CODE | Hybrid: common words replaced by code groups, rest enciphered; variable output character set | [HYPOTHESIS] Satisfies ALPHA-26 if code groups are letter sequences. Satisfies PEN-PAPER. Untested — no systematic code+cipher model has been explored | UNTESTED | N/A | MEDIUM |
| **Bespoke procedural cipher** | N/A | Arbitrary substitution tables (coding charts); not derivable from keyword or algorithm | [PUBLIC FACT] Sanborn: "Who says it is even a math solution?" Coding charts sold at auction ($962.5K). [HYPOTHESIS] Charts may specify non-algorithmic substitution. Untestable without chart contents | UNTESTED | N/A | HIGH (blocked) |
| **Physical/optical cipher** | N/A | Light through cut copper + reflecting pool; S-curve projection; physical measurement as key | [HYPOTHESIS] Consistent with Sanborn's artistic practice. Untestable without sculpture geometry measurements. Requires Hirshhorn visit | UNTESTED | N/A | HIGH (blocked) |

---

## Part 2: Untested / Open Items -- Experiment Outlines

#### [SUB-POLY-RUN] Running Key from Unknown Text -- Test Plan

**Status:** PARTIALLY-TESTED
**What's untested:** Running key from non-English texts (German, French, Latin, Arabic -- relevant to Egypt/Berlin themes), and from Sanborn-associated texts beyond the 7 already tested. [INTERNAL RESULT] English running key + columnar is eliminated (E-FRAC-51), but non-English key texts and bespoke transpositions remain open.
**Why it matters:** [INTERNAL RESULT] Running key is the ONLY structured non-periodic key model surviving Bean (E-FRAC-38). Sanborn's clues reference Berlin (German) and Egypt (potentially Arabic/French archaeological texts).

**Minimal experiment outline:**
- Script name: `scripts/e_cfm_01_running_key_foreign.py`
- Approach: Test German and French source texts (Berlin Wall speeches, Tutankhamun discovery accounts in original languages) as running keys at all offsets, with Vigenere/Beaufort/VarBeau, against identity + columnar w6/8/9
- Key parameters: Source text (5-10 foreign-language candidates), offset (0 to len(text)-97), cipher variant (3), transposition (identity + Bean-passing columnar configs)
- Expected output: Key fragment quadgram scores against target-language models; anything above -3.5/char in the source language warrants investigation
- Compute estimate: Small-medium (similar to E-FRAC-49: ~10K configs per text)
- Dependencies: `kryptos.kernel.constants`, `kryptos.kernel.scoring.aggregate`, foreign-language quadgram models (would need to be sourced or approximated)

**Success criteria:** Key fragments at any offset form readable foreign-language text (quadgram/char > -3.5 in source language, or human-recognizable phrases).

---

#### [MULTI] Mono + Transposition + Running Key -- Test Plan

**Status:** PARTIALLY-TESTED (UNDERDETERMINED per E-FRAC-54)
**What's untested:** [INTERNAL RESULT] The 13 monoalphabetic DOF absorb key fragment analysis, making automated English detection impossible (E-FRAC-54). No experiment has attempted to constrain the mono layer independently or use external information to reduce the DOF.
**Why it matters:** This is the ONE identified open gap in the structured cipher model space. If K4 uses this architecture, additional constraints are needed to break the underdetermination.

**Minimal experiment outline:**
- Script name: `scripts/e_cfm_02_mono_running_constrain.py`
- Approach: (1) Enumerate mono mappings that preserve known self-encrypting positions (CT[32]=PT[32]=S, CT[73]=PT[73]=K imply mono fixes S and K). (2) For each reduced-DOF mono, test running key detection on Bean-passing columnar configs. (3) Alternatively, use K4's letter frequency distribution as a constraint on the mono mapping (the mono layer must produce a CT frequency distribution consistent with K4's observed frequencies given an English plaintext)
- Key parameters: Mono mapping (11 remaining DOF after fixing S->S, K->K), transposition (Bean-passing columnar w6/8/9), running key scoring
- Expected output: Whether frequency-constrained mono reduces DOF enough for running key detection to work
- Compute estimate: Medium (mono enumeration is 26^11 in theory but heavily constrained by frequency matching -- expect <10K viable mono maps)
- Dependencies: `kryptos.kernel.constants`, `kryptos.kernel.scoring.aggregate`, `kryptos.kernel.constraints`

**Success criteria:** Reduction from 13 DOF to <=5 via frequency/self-encryption constraints, enabling running key fragment analysis to discriminate English from random.

---

#### [TRANS-ROUTE] Route Ciphers with Non-Standard Grids -- Test Plan

**Status:** PARTIALLY-TESTED
**What's untested:** [INTERNAL RESULT] Width-9 routes tested (E-FRAC-03/45) but other grid dimensions and non-standard route patterns are open. Specifically: grids derived from sculpture physical dimensions (e.g., Kryptos has ~86 rows of varying width; Antipodes has 47 rows of 32-36 chars), prime-factorization grids (97 is prime -- only 1x97 or 97x1), and grids with padding/null characters.
**Why it matters:** [PUBLIC FACT] Sanborn is a visual artist who works with physical layouts. Route ciphers follow physical reading paths, consistent with "not even a math solution."

**Minimal experiment outline:**
- Script name: `scripts/e_cfm_03_route_nonstandard.py`
- Approach: Generate route permutations for grids with padding (e.g., 10x10 with 3 nulls, 7x14 with 1 null) using spiral, diagonal, serpentine, and S-curve patterns. Score each against cribs using `score_candidate()`. Also test reading K4 CT off a model of the sculpture's physical row widths
- Key parameters: Grid dimensions (all NxM where N*M in [97..102], accounting for up to 5 padding positions), route type (4-6 patterns), null positions (start, end, distributed)
- Expected output: Crib scores; anything above 18/24 at a discriminating configuration warrants investigation
- Compute estimate: Small (hundreds of grid/route/null combinations)
- Dependencies: `kryptos.kernel.constants`, `kryptos.kernel.scoring.aggregate`

**Success criteria:** Any route permutation scoring above the noise floor (>14/24 at period <=7 or >18/24 with running key) that produces coherent key fragments.

---

#### [CODE] Nomenclator / Code+Cipher Hybrid -- Test Plan

**Status:** UNTESTED
**What's untested:** No code+cipher hybrid model has been systematically explored. [HYPOTHESIS] A nomenclator replaces common words/phrases with fixed code groups while enciphering the rest. If EASTNORTHEAST and BERLINCLOCK are partially code groups (pre-assigned letter sequences) rather than enciphered plaintext, the crib-based elimination framework may not fully apply.
**Why it matters:** [PUBLIC FACT] Nomenclators were the dominant diplomatic cipher from the 15th-19th century and would be familiar to Scheidt (former CIA cryptographer). The "coding charts" sold at auction could literally be a nomenclator table.

**Minimal experiment outline:**
- Script name: `scripts/e_cfm_04_nomenclator_model.py`
- Approach: (1) Test whether cribs could be code groups by checking if CT at crib positions shows any internal structure (repeated bigrams, alphabetical ordering, positional patterns) distinct from the surrounding CT. (2) Model a simple nomenclator where N common English words are replaced by 2-5 letter code groups and the remaining text is enciphered with a simple substitution or Vigenere
- Key parameters: Number of code groups (10-50), code group length (2-5), substitution model for non-code text
- Expected output: Whether the crib regions show structural differences from non-crib regions under nomenclator assumptions
- Compute estimate: Small (structural analysis + limited enumeration)
- Dependencies: `kryptos.kernel.constants`

**Success criteria:** Statistical evidence that crib-region CT behaves differently from non-crib CT under a nomenclator model, OR identification of a code group structure consistent with all 24 crib positions.

---

#### [TRANS-ROUTE] Sculpture-Geometry Transposition -- Test Plan

**Status:** UNTESTED (blocked by physical access)
**What's untested:** [HYPOTHESIS] K4 CT read in an order determined by the sculpture's physical properties -- the S-curve of the copper, the compass rose bearings, the lodestone position, coordinates encoded in the Morse panel. This is distinct from standard route ciphers because the "grid" is the sculpture itself, not a mathematical construct.
**Why it matters:** [PUBLIC FACT] Sanborn: "Who says it is even a math solution?" and "kryptos is available to all." The Antipodes at the public Hirshhorn may contain the necessary geometric information.

**Minimal experiment outline:**
- Script name: `scripts/e_cfm_05_sculpture_geometry.py`
- Approach: Using known sculpture dimensions (main panel: ~6ft x 3ft, ~86 rows, row widths from photographs), define candidate reading orders: (1) follow the S-curve of the copper sheet, (2) read in compass bearing order from a central point, (3) spiral from coordinates 38.9517N 77.1467W mapped onto the grid
- Key parameters: Row widths (from photograph analysis), reading direction variants, starting position
- Expected output: Permutation of positions 0-96; score against cribs and running key models
- Compute estimate: Small (tens of candidate permutations from physical models)
- Dependencies: `kryptos.kernel.constants`, `kryptos.kernel.scoring.aggregate`, sculpture dimension data (partially available in `reference/Pictures/`)

**Success criteria:** Any physically-motivated permutation that scores above noise floor or produces recognizable key fragments. Ideally, also testable against Antipodes layout for cross-validation.

---

## Part 3: Cross-Reference Table

This table maps observable K4 properties to cipher families, enabling diagnostic reasoning: given what we observe, which families are consistent?

| K4 Observable | Cipher Families Consistent | Cipher Families Inconsistent |
|---|---|---|
| **IC = 0.0361 (below random 0.0385)** [DERIVED FACT] Not statistically significant for n=97 (E-FRAC-04/13) | SUB-POLY (long period), SUB-POLY-RUN, SUB-POLY-MECH (if not state-blocked), MULTI (any composition), TRANS-* (preserves IC of underlying PT, which could be English IC ~0.065 masked by substitution) | SUB-MONO (preserves English IC ~0.065), SUB-DIGRAPH/Playfair (IC ~0.048-0.055), SUB-FRAC/Bifid-6x6 (IC ~0.059-0.069). Note: IC alone is a weak discriminator at n=97 |
| **All 26 letters present (ALPHA-26)** [DERIVED FACT] | SUB-POLY, SUB-POLY-RUN, SUB-POLY-AUTO, SUB-POLY-PROG, TRANS-*, MULTI, CODE | SUB-FRAC/Bifid-5x5 (requires I/J merge to 25), SUB-DIGRAPH/Playfair (same 25-letter constraint), SUB-FRAC/straddling checkerboard (produces digits) |
| **Non-periodic key under additive model (NON-PERIODIC)** [DERIVED FACT] Proven from crib constraints | SUB-POLY-RUN, SUB-POLY-AUTO (but separately eliminated by E-FRAC-37), MULTI (compositions can produce non-periodic effective keys), CODE (no periodicity requirement) | SUB-POLY (periodic by definition), SUB-POLY-PROG/Gromark (linear recurrence is quasi-periodic), Gronsfeld (periodic) |
| **Bean equality k[27]=k[65] (BEAN-EQ)** [PUBLIC FACT] | SUB-POLY-RUN (satisfies by construction if key text has matching characters at mapped positions), MULTI with running key component, CODE | SUB-POLY-PROG/progressive (only delta=0 or 13 survive, both eliminated), SUB-POLY-PROG/quadratic (0/676 survive), SUB-POLY-PROG/Fibonacci (0/676 survive). Note: BEAN-EQ is tautological for pure transposition models |
| **97-character length, prime (LEN-97)** [DERIVED FACT] | All ciphers that work on arbitrary-length text: SUB-POLY-RUN, TRANS-COL (with variable-length last column), TRANS-ROUTE (with padding), MULTI | SUB-FRAC/Trifid (needs length divisible by 3), SUB-FRAC/ADFGVX (output always even), SUB-DIGRAPH/Playfair (needs even length), TRANS-GRILLE/turning grille (needs N divisible by 4 for standard square) |
| **"Two separate systems" (Sanborn)** [PUBLIC FACT] | MULTI (by definition -- any two-layer composition), TRANS-COL + SUB-POLY-RUN, TRANS-ROUTE + SUB-*, CODE + substitution overlay | SUB-MONO (single system), single-layer TRANS-* (single system), single-layer SUB-POLY (single system). Note: "two systems" strongly implies MULTI family |
| **Self-encrypting positions: CT[32]=PT[32]=S, CT[73]=PT[73]=K** [DERIVED FACT] | Any cipher where key value can be zero/identity at specific positions: SUB-POLY-RUN (running key letter producing identity shift), MULTI (composition cancellation). Also consistent with transposition models where these positions are fixed points | SUB-MONO (if self-encryption occurs, the mono map fixes those letters -- constrains but doesn't eliminate) |
| **Hand-executable (PEN-PAPER)** [HYPOTHESIS] Based on Scheidt background and 1989 context | SUB-POLY-RUN (tedious but feasible), TRANS-COL (easy), TRANS-ROUTE (easy), TRANS-GRILLE (easy with physical grille), CODE/nomenclator (easy with table), SUB-MONO (trivial), simple MULTI compositions | SUB-POLY-MECH/Enigma (requires machine), advanced matrix ciphers (Hill 4x4+ impractical by hand), any method requiring computation |

---

## Summary of Open Research Vectors

Ordered by priority, referencing research questions from `docs/research_questions.md`:

| Priority | Open Vector | Key Constraint | Addresses RQ |
|---|---|---|---|
| **HIGH** | Mono + transposition + running key (underdetermined gap) | Need external constraints to reduce 13 mono DOF | RQ-1, RQ-2, RQ-3 |
| **HIGH** | Running key from non-English / untested texts | Need foreign-language quadgram models | RQ-2, RQ-5 |
| **HIGH** | Bespoke procedural cipher / coding charts | Blocked: requires auction lot contents or Sanborn disclosure | RQ-1, RQ-8 |
| **HIGH** | Physical/optical cipher (sculpture geometry) | Blocked: requires Hirshhorn visit + measurements | RQ-1, RQ-10 |
| **MEDIUM** | Route ciphers with non-standard grids and padding | Small parameter space, quick to test | RQ-3, RQ-13 |
| **MEDIUM** | Nomenclator / code+cipher hybrid | Novel model class, untested | RQ-1, RQ-6 |
| **LOW** | Cardano grille as selection from larger cover text | Requires hypothetical cover text | RQ-3 |

[POLICY] All experiments must import constants from `kryptos.kernel.constants`, use `score_candidate()` from `kryptos.kernel.scoring.aggregate`, and respect the scoring underdetermination warning: only scores at period <=7 are meaningful discriminators.

---

*Created: 2026-02-27 | Part of the Crypto Field Manual series | Cross-references: `docs/elimination_tiers.md`, `docs/research_questions.md`, `docs/invariants.md`, `reports/final_synthesis.md`*
