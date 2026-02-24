# K4 Multi-Agent Campaign — Final Synthesis

**Date:** 2026-02-20
**Scope:** 170+ experiments across 6 agents (FRAC, TRANS, TABLEAU, JTS, BESPOKE, QA), 27 sessions
**Status:** All agent mandates exhausted. Transitioning to official Claude Code agent teams.

---

## 1. What Was Tested

### By the numbers
- **~200 experiments** (55 FRAC + 54 TRANS + 23 TABLEAU + 12 JTS + 55 BESPOKE + QA validation)
- **~65 million cipher configurations** scored against 24 cribs
- **~17 billion running-key offset checks**
- **~12,000 CPU-seconds** of compute
- **110+ classical cipher families** exhaustively tested
- **0 genuine signals** (all scores within noise at discriminating periods)

### Transposition families tested (TRANS + FRAC)
Columnar (widths 5-15), double columnar (9 Bean-compatible width pairs), Myszkowski (widths 5-13), AMSCO/Nihilist/Swapped (widths 5-13), rail fence, cyclic shifts, affine permutations, single swaps, reversals, grid reading orders (serpentine, spiral, diagonal, snake, etc. at widths 5-13), S-curve, boustrophedon, strip manipulation.

### Substitution models tested
Vigenere, Beaufort, Variant Beaufort (all periods 2-26), autokey (PT/CT, all variants), progressive key, quadratic key, Fibonacci key, LCG keystream, polynomial keys (deg 1-6), Hill 2x2-4x4, Quagmire I-IV, Porta, Gronsfeld, affine (a!=1), monoalphabetic, mixed alphabets (keyword and arbitrary), running key (K1-K3, Carter book, 25+ themed texts, 7 reference texts at all offsets).

### Non-standard methods tested (BESPOKE + TABLEAU)
Non-standard tableau access (column reads, rotations, paths), K1-K3 as operational instructions, misspelling-derived keywords (QUAY, EQUAL), cross-alphabet Quagmire, position-dependent alphabets, strip manipulation, physical reading orders from sculpture geometry, text-derived permutations, multi-objective SA, segmented encryption, grid rotation, self-referential keys, reverse layer order.

---

## 2. What Is Eliminated

### Tier 1: Mathematical proofs (certainty ~99.9%)
- Pure transposition (letter frequency mismatch)
- All periodic polyalphabetic (any variant, any period, direct correspondence)
- Periodic key + ANY transposition at periods 2-7, 9-12, 14, 15, 17, 18, 21, 22, 25 (Bean impossibility proof, E-FRAC-35)
- Hill n×n for n=2,3,4 (algebraic) and n>4 (97 is prime)
- All fractionation (Bifid 5×5/6×6, Trifid, ADFGVX/ADFGX, Playfair, Two-Square, Four-Square, straddling checkerboard)
- Autokey (all forms) + arbitrary transposition (cannot reach 24/24)
- Progressive, quadratic, Fibonacci keys + any transposition (Bean-eliminated)
- Turning grille 10×10 (structurally impossible)

### Tier 2: Exhaustive search (certainty ~95%)
- All structured transposition families (columnar w5-15, double columnar, Myszkowski, AMSCO, Nihilist, Swapped, simple families) + all substitution models → NOISE
- Keyword-mixed alphabets + columnar → 0 survivors
- K3-method variants (thematic keywords at Bean-surviving periods) → NOISE
- Non-standard tableau usage → NOISE
- Running key from 7 known reference texts + structured transpositions → 0/17B matches
- All K1-K3 derived keys → NOISE

### Statistical claims debunked
- IC = 0.036 (21.5th percentile of random, not significant)
- Lag-7 autocorrelation (fails Bonferroni correction)
- DFT peak at k=9 (below 95th percentile)
- Bimodal fingerprint (artifact of crib ordering)

---

## 3. What Remains Open

### 3.1 Running key from unknown text
The only structured key model surviving Bean constraints. But running key + transposition is massively underdetermined: ~35% of English text offsets achieve 24/24 bipartite matching under some permutation. After Bean: ~0.6% feasible — still hundreds of offsets in any reference text. No known reference text shows signal above SA-optimized random key.

### 3.2 Bespoke physical/procedural cipher
Sanborn: "Who says it is even a math solution?" The coding charts sold for $962,500 at auction. These may specify arbitrary substitution tables not derivable from any keyword or algorithm. Without the charts, this is untestable.

### 3.3 Non-standard structures not yet conceived
Position-dependent alphabets, non-textbook compositions, methods that don't fit standard cryptographic taxonomy. K4's "intentional change in methodology" (Scheidt) from K3 may be fundamental — a different cipher TYPE, not just different parameters.

### 3.4 External information needed
- **K5 ciphertext** (97 chars, shares coded words at same positions as K4)
- **Smithsonian archives** (plaintext found Sept 2025, sealed until 2075)
- **Decoded coding charts** from the $962.5K auction lot
- **New Sanborn statements** (if any)

---

## 4. Key Theoretical Results

### Information-theoretic underdetermination (E-FRAC-44)
- 505 bits needed to identify 1 of 97! permutations
- 367 bits available from cribs (113) + Bean (6) + English (248)
- **138-bit deficit** → ~2^138 permutations consistent with ALL constraints
- Structured families (columnar: 2^18.5 options) → expected false positives = 0
- Arbitrary permutations (2^505 options) → expected false positives = 2^401

### Multi-objective oracle (E-FRAC-34/40/42)
Any candidate must satisfy ALL of:
1. Crib score = 24/24
2. Bean constraint PASS
3. Quadgram/char > -4.84 (English benchmark; SA gibberish peaks at -4.27)
4. IC > 0.055
5. Non-crib words >= 7 chars: at least 3
6. Semantic coherence (human evaluation — the only reliable discriminator)

### SA produces convincing false positives
SA-optimized transpositions achieve quadgram = -4.27/char with ANY key (random or Carter). They produce real English words (DISTINGUISHED, LABORATORY) but incoherent sentences. No automated metric perfectly separates SA gibberish from real English at 97 chars.

---

## 5. Architectural Lessons

### What worked
- **The scoring oracle** (`score_candidate()`) was fast, reliable, and the foundation for all 170+ experiments
- **Compute separation** (job runner for heavy sweeps, agents for hypothesis generation)
- **Structured elimination** (methodical coverage of hypothesis space, documented with repro commands)
- **Cross-validation** (QA agent caught no bugs in other agents' work — code quality was high)

### What didn't work
- **Git-based coordination** created merge conflicts, branch divergence, and required an 80-line auto-recovery function
- **PROGRESS.md as shared state** grew to 1,210 lines, burning ~15-20K tokens per agent iteration on orientation
- **Rigid role assignments** couldn't adapt when mandates were exhausted
- **No real-time communication** — alerts were write-only, read on next iteration
- **6 agents was too many** — diminishing returns from parallel enumeration of an exhausted hypothesis space

### Recommendation for future work
Use official Claude Code agent teams (3 agents: lead + explorer + validator) with dynamic task assignment. Keep the job runner for compute separation. Focus on creative/physical methods rather than enumeration.

---

## Artifact Index

| Agent | Report | Experiments |
|-------|--------|-------------|
| FRAC | `reports/frac_final_synthesis.md` | E-FRAC-01 to 55 |
| TRANS | `results/trans/SUMMARY.md` | E-TRANS-1 to 6 |
| TABLEAU | `archive/session_reports/tableau_post_frac_synthesis.md` | E-TABLEAU-01 to 23 |
| JTS | `reports/frac_jts_oracle_specification.md` | E-JTS-01 to 12 |
| QA | `archive/session_reports/qa_structural_claims_verification.md` | Cross-verification |
| All | `archive/session_reports/session_27_regression_report.md` | Regression meta-analysis |
| All | `archive/session_reports/progress_archive.md` | Full 1,210-line experiment log |

---

*This document supersedes individual agent synthesis reports for high-level status.*
