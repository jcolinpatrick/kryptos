# Kryptos K4 — Ground Truth & Operating Policies

This file contains domain knowledge, public facts, derived facts, and operating policies
for the Kryptos K4 cryptanalysis project. Extracted from CLAUDE.md to keep the development
guide focused. See also: `docs/invariants.md` for verified computational invariants.

---

## (A) Proven / Public Facts and Derived Facts

### A1) Kryptos K4 ciphertext (canonical)

[PUBLIC FACT] K4 ciphertext:
OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR

[DERIVED FACT] Length = 97
[DERIVED FACT] Starts with `O`, ends with `R`

[DERIVED FACT] Index of Coincidence (IC) on full ciphertext:
- IC(K4) ≈ 0.036082… (recompute via `tools/validate_public_invariants.py` or the snippet in Appendix)

[DERIVED FACT] Uniform-random IC expectation for 26 letters is 1/26 ≈ 0.0384615…

---

### A2) Public cribs (0-indexed positions)

[PUBLIC FACT] Publicly released clues imply these plaintext placements (0-indexed, inclusive):
- Positions **21–33**: `EASTNORTHEAST`
- Positions **63–73**: `BERLINCLOCK`

[DERIVED FACT] The same in 1-indexed human counting:
- 22–34 = EASTNORTHEAST
- 64–74 = BERLINCLOCK

---

### A3) Deterministic consequences of ciphertext + cribs

#### A3.1 Self-equality and non-equality examples

[DERIVED FACT] At position 32: CT[32] = `S` and PT[32] = `S`
[DERIVED FACT] At position 73: CT[73] = `K` and PT[73] = `K`

[DERIVED FACT] Not self-equal examples:
- CT[27] = `P` while PT[27] = `R`
- CT[28] = `R` while PT[28] = `T`

#### A3.2 Implied keystream fragments under AZ Vigenère convention

Definition used here:
- Alphabet: A=0, …, Z=25
- "Implied keystream" at position i is **K[i] = (CT[i] − PT[i]) mod 26**

[DERIVED FACT] For PT `EASTNORTHEAST` at positions 21–33:
- K[21..33] = `BLZCDCYYGCKAZ`
- Numeric = (1,11,25,2,3,2,24,24,6,2,10,0,25)

[DERIVED FACT] For PT `BERLINCLOCK` at positions 63–73:
- K[63..73] = `MUYKLGKORNA`
- Numeric = (12,20,24,10,11,6,10,14,17,13,0)

[DERIVED FACT] Equality implied by the above:
- K[27] = `Y` (24)
- K[65] = `Y` (24)
- Therefore K[27] = K[65] = 24

---

### A4) 2025 public disclosures about K4 and K5 (facts only)

[PUBLIC FACT] K4 plaintext was reportedly found in Smithsonian archival materials and is not publicly released; access is sealed until 2075 (per 2025 reporting).
[PUBLIC FACT] Sanborn-related "coding charts / original coding system" materials were auctioned, and public reporting cites a sale price of $962,500 (per 2025 reporting).
[PUBLIC FACT] Additional 2025 reporting attributes to Sanborn that:
- K4's solution relates to **two historical events** (reported as 1986 Egypt-related and 1989 Berlin Wall-related).
- The theme involves "delivering a message" (phrasing varies by report).
- K5 exists, is **97 characters**, and will share **some coded words at the same positions** as K4.
- K5 is connected conceptually to K2 ("it's buried out there somewhere" phrasing appears in reporting).

**Important:** These are public-report facts about **claims and disclosures**, not proof of any specific cipher mechanism.

### A5) Two Ground Truths — Physical vs Intent

[POLICY] The physical sculpture and Sanborn's stated intent are NOT identical. See `docs/two_ground_truths.md` for the full framework.

[DERIVED FACT] K4 ciphertext is identical across both ground truths (no corrections announced).
[PUBLIC FACT] K2 ending decrypts as IDBYROWS on physical copper (both sculptures). Sanborn verbally corrected to XLAYERTWO in 2006 but never modified the copper.
[PUBLIC FACT] UNDERGRUUND appears on Kryptos; UNDERGROUND (correct) appears on Antipodes. Original coding charts show correct spelling.
[POLICY] Default to Physical Sculpture (Ground Truth A) for primary analysis. Test both when method depends on K2 structure.

---

## (B) Internal Reproducible Results

### B0) Rule: internal results are not "truth" without artifacts

[POLICY] Any repo-generated claim belongs here as **[INTERNAL RESULT]**, and MUST include:
1) **Repro command** (copy/paste runnable)
2) **Artifact pointers**
   - code path(s)
   - run manifest (JSON/YAML/TOML) including parameters
   - output logs
   - DB file + query (if persisted)
   - git commit hash (or equivalent version stamp)
3) **Acceptance criteria** and whether it was met

If any item is missing, it is **not a result**—it is a hypothesis.

### B1) Internal Results Registry

Create/maintain a file (recommended): `docs/internal_results_registry.md` with entries like:

- **IR-0001**
  - Claim: …
  - Repro: `…`
  - Artifacts: Code, Manifest, Logs, DB (plus query), Commit
  - Status: reproduced Y/N, by whom, on what date

[POLICY] Claude must update the registry whenever a result is referenced in analysis or used to eliminate search space.

### B2) Repo "constants" are policies until proven

Examples of things that must NOT be asserted as "constants" unless validated locally:
- exact file paths (e.g., where Bean constraints live)
- counts (number of scripts/tests/DB size)
- "canonical package" claims

---

## (C) Hypotheses and Operating Policies

### C1) Two-lane operating model

[POLICY] Lane A — Verification (hard science)
- strict reproducibility, explicit search spaces, precise acceptance criteria
- no narrative leaps
- code output is not "truth" without validation gates

[POLICY] Lane B — Exploration (creative but disciplined)
- speculation is allowed ONLY when labeled **[HYPOTHESIS]**
- every hypothesis must end with a test plan
- prefer hypotheses that reduce entropy if true (high leverage)

### C2) Code skepticism doctrine

[POLICY] Never assume existing code is correct.

[POLICY] When results look "impossible" or "breakthrough", suspect:
- indexing (0 vs 1)
- permutation direction conventions
- alphabet ordering / merges (IJ, etc.)
- Beaufort/Vigenère sign conventions
- boundary inclusivity of cribs
- unintended mutation/caching/globals

[POLICY] Prefer differential validation:
- write a minimal reference implementation for critical primitives
- compare against main implementation on randomized micro-tests (fixed seed)

### C3) Validation gates (must pass before trusting conclusions)

[POLICY] Gate 1: unit tests pass (fast)
[POLICY] Gate 2: minimal reference implementation reproduces outcome
[POLICY] Gate 3: invariant checks (bijection, reversibility, crib alignment)
[POLICY] Gate 4: reproduce from a clean process (fresh interpreter)

### C4) Creativity doctrine (structured)

[POLICY] Creativity is required, but must remain testable and reproducible.

**Public sentiment (accurate framing):**
- [PUBLIC FACT] Public reporting attributes to Sanborn: "Who says it is even a math solution?" (wording varies by report).
- [PUBLIC FACT] Public reporting attributes to Scheidt: K4 involves multiple stages / masking (details disputed; treat as clue/constraint, not proof).

[POLICY] Acceptable hypothesis classes:
- manual/procedural ciphers (paper rules, clocks, grids)
- orthographic manipulation (misspellings, omissions, punctuation as control)
- language-base changes (alphabet ordering, digraph rules)
- artifact-driven parameters (clock/quartz/lodestone/coordinates mapping to route/offset/primer)
- geometry/layout (reading order, projections, serpentine traversals)
- layering with a human-in-the-loop branching step

[POLICY] Every hypothesis must produce:
1) one-paragraph falsifiable statement
2) mapping to parameters
3) minimal fast test
4) expanded sweep definition + pruning
5) expected outcomes (what increases belief vs kills it)

### C5) K5 relationship to K4 (strictly hypothesis)

[HYPOTHESIS] K5 sharing coded words at the same positions as K4 may constrain how Sanborn reused structure across messages.
**Not allowed as fact:** "therefore K4 is position-dependent" or eliminating stateful ciphers.
**Test plan:** Use only claims supported by public reporting + any internal artifacts you possess; if attempting eliminations, demonstrate them with explicit assumptions and proofs.

---

## Appendix A — Public invariants validator (REQUIRED)

[POLICY] Maintain a runnable validator script that recomputes all **[DERIVED FACTS]** from **[PUBLIC FACTS]**.

Recommended location: `tools/validate_public_invariants.py`

Minimum checks:
- ciphertext length, first/last char
- crib alignment at 21..33 and 63..73
- implied keystream fragments (AZ subtraction)
- IC(full) and IC(0..20) (report both)
- print a one-line "PASS/FAIL" summary
