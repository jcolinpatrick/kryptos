# MEMORY.md — K4 Decision-Support Index

Slim index for agents working on K4. Full history in topic files (linked below).
For project guidance, see [CLAUDE.md](CLAUDE.md).

---

## Project State

- **286 experiments with results**, 670B+ configurations scored, ~950 scripts tracked
- **0 genuine signals** — all scores within noise at discriminating periods
- Computational work paused pending Antipodes physical inspection
- Transitioned from custom 6-agent harness (170+ experiments) to official Claude Code agent teams

## What Is Eliminated (High Confidence)

- **Gronsfeld** (digit key {0-9}): key values at cribs exceed 9 (E-S-BERLIN-EXTEND)
- **Porta** (half-alphabet key {A-M}): key values at cribs exceed 12 (E-S-BERLIN-EXTEND)
- All periodic polyalphabetic (any variant, any period, direct correspondence)
- All fractionation families (Bifid, Trifid, ADFGVX, Playfair, Two-Square, Four-Square, etc.)
- Hill cipher (n=2,3,4 algebraic; n>4 impossible since 97 is prime)
- Autokey (all forms) + arbitrary transposition — STRUCTURALLY IMPOSSIBLE
- Progressive, quadratic, Fibonacci keys + any transposition (Bean-eliminated)
- All structured transposition families + all substitution models → NOISE
- Running key from 7 known reference texts + structured transpositions → 0/17B matches
- K4 IC=0.036 is NOT statistically significant for 97 chars
- Lag-7 autocorrelation, DFT peak at k=9, bimodal fingerprint — all debunked
- Polybius fractionation + null mask → ELIMINATED (1,126 configs, all noise)
- VIC family (all variants: straddling checkerboard, full pipeline, hybrid) → ELIMINATED
- Gromark/Vimark on 73-char null-extracted → ELIMINATED (8.74B configs, zero hits)
- MCMC quadgram attack on CT73 → NOISE (5-phase attack, all noise)
- K0 Morse text as running key → ELIMINATED (28,140 configs, best 5/24)
- Progressive running key → ELIMINATED (1,059,708 configs, best 8/24)
- Palette letters as cipher key material → DISPROVED (Gromark, columnar, index/mask, all ≤6/24)
- CKM credential-based key construction (K1/K2/K3 PT × keywords, 6 models) → ELIMINATED (173M+ configs, best 10/24)

## DO NOT TEST (Proven Impossible / Exhausted)

- Autokey (PT, CT, Beaufort variants) — structural impossibility proof
- DEFECTOR+PALIMPSEST combined → 15/24 ceiling is inherited, not independent
- K2 number-word keywords as cipher keys → NOISE
- YES WONDERFUL THINGS as K4 PT[0:18] → incompatible with all 64 combos
- Positional keying via (pos%M, pos%N) lookup table → DISPROVED
- CIA cryptonym digraph constraints → ELIMINATED
- Leetspeak visual resemblance (palette as numbers) → DISPROVED
- K2 coordinate key generation → DISPROVED
- 72+1 delimiter hypothesis → ELIMINATED
- NDYAHR as: hidden message, unified block, blind cryptanalysis, directional pointers → all DISPROVED
- INCLINARE stacking null mask → NOISE
- Cold War keywords, Operation Gold, Russian intelligence keywords → all NOISE
- K1-K3 plaintext does NOT encode literal key values
- Mailing list hypotheses: Wheatstone clock, Sawtooth, ITA-2, Morse reinterpretation → all NOISE
- CKM mod-26 key construction from K1/K2/K3 PT + keywords → NOISE (all 6 models, 1000+ keywords)
- Null value sequence OBKOGBOWWKWIWGZIG as cipher key material → NOISE (144 configs, best 3/24)
- {G,K,O} AP concentration as position-dependent key mechanism → NOT ACTIONABLE (AZ indexing artifact)
- CT80 (null-extracted) single-layer keyword attacks, 22 keywords → ELIMINATED (2,010 configs, zero ≥6/24)

## What Remains Open

1. **Running key from unknown text** — only structured non-periodic key model surviving Bean
2. **Bespoke physical/procedural cipher** — Sanborn's coding charts ($962.5K auction), untestable without charts
3. **Non-standard structures not yet conceived** — position-dependent alphabets, non-textbook compositions
4. **External information needed** — K5 ciphertext, Smithsonian archives (sealed until 2075), decoded coding charts
5. **ABSCISSA/beau/KA sigma search** — 2 forced positions + additional V constraints; targeted SA search next

## Bean-Compatible Periods

Only periods {8, 13, 16, 19, 20, 23, 24, 26} are Bean-compatible for transposition + periodic substitution (E-FRAC-07). All others are proven impossible.

## Critical Pitfalls (Quick Reference)

- **0-indexed positions everywhere** — cribs at 21-33 and 63-73
- **KA alphabet**: `KRYPTOSABCDEFGHIJLMNQUVWXZ` (all 26 letters, non-standard order)
- **Vigenere sign**: K = (CT - PT) mod 26; Beaufort: K = (CT + PT) mod 26
- **Scoring underdetermination**: periods >= 17 produce false-positive high scores; only period <= 7 is discriminating
- **constants.py is the single source of truth** — never hardcode CT or cribs

## Key Reference Files

- `docs/kryptos_ground_truth.md` — public facts, internal results policy
- `docs/invariants.md` — verified computational invariants
- `docs/elimination_tiers.md` — full elimination tables (Tier 1-4)
- `docs/research_questions.md` — RQ-1 through RQ-13 with priorities
- `reports/final_synthesis.md` — 170+ experiment synthesis
- `anomaly_registry.md` — physical sculpture anomalies

## Agent Conventions

- Import constants from `kryptos.kernel.constants` — never hardcode
- Use `score_candidate()` from `kryptos.kernel.scoring.aggregate` — never hand-roll
- Multi-objective thresholds: crib=24/24 + Bean PASS + quadgram > -4.84/char + IC > 0.055 + non-crib words >= 7 chars >= 3
- Experiment scripts: `scripts/e_<topic>_<nn>_<short_name>.py`
- Always use `python3 -u` for unbuffered output in background tasks

---

## Active Findings (Confirmed)

### Stehle Delta4=5 Anomaly (2026-03-15)

**Status: LOCAL COINCIDENCE (p~0.0016), FULLY CHARACTERIZED**
- Only constant-difference window in entire CT (pos 55-63, lag 4, delta=5)
- **Anatomy**: cipher output produced Δ4=5 at two consecutive non-null pairs (56→60, 57→61) — one of only 3 such pairs in all of CT97 at lag 4. Null insertion at 58,59 extended this because both forced values (W,I) are palette letters.
- Pos 59 is doubly constrained (D(55)+5=I AND N(63)-5=I). Pos 58 is singly constrained (B(62)-5=W).
- **NOT a generative mechanism**: only 4/17 null positions are arithmetically constrained, count matches random expectation (MC p=0.59). No global constant-difference rule exists (1,248 tests, MC p=0.954).
- Stehle and width-21 bigram anomaly are largely independent; only pos 59 satisfies both.
- Scripts: `scripts/campaigns/e_stehle_delta4_comprehensive.py`, `scripts/analysis/e_null_arithmetic_census.py`, `scripts/analysis/e_global_delta_sweep.py`

### Null Insertion Mathematical Structure (2026-03-15)

**Status: SIGNIFICANT STRUCTURAL DISCOVERY, MECHANISM UNKNOWN**
- 17 consensus nulls are NOT random: IC=0.1103 (2.87x random, p=0.0008), only 7 distinct letters (p=3e-5)
- W absorption: 4/5 W's are nulls (p=0.003); only non-null W at pos 48 = midpoint of crib endpoints
- JKL consecutive AP at position 52: only ascending consecutive triple in CT (expected: 0.14)
- Null chars come from constrained source (short key, repeated word, or deterministic formula)
- **Open question: what rule generates these 17 characters at these positions?**
- Script: `scripts/campaigns/e_null_insertion_structure.py` | Result: `results/null_insertion_structure.json`

### Palette {B,G,I,K,O,W,Z} + Beaufort Enrichment (2026-03-15)

**Status: REAL ANOMALY (p=0.000627), MECHANISM OPEN**
- KA mod 5 structure: all 7 palette letters have KA index ≡ 0 or 3 mod 5 (p=0.000502) — columns 0,3 of 5-wide KA grid
- Beaufort KA key=N maps {E,H,N,Q,S,T,V} → palette exactly; source contains "SEVEN" — **INCOMPATIBLE WITH GKO FINDING (2026-03-25)**: key=N maps zero sources to {G,K,O}; key=N and the GKO crib keystream concentration cannot be the same mechanism
- BCL Beaufort keystream: 7/8 palette at positions 63-70 (p=0.000627) — UNIQUE to Beaufort A=0
- Combined 24 cribs: 13/24 palette (p=0.004)
- Keystream is model-independent at crib positions (CT+PT, no keyword assumption needed)
- Three independent robust signals confirmed (Fisher combined p ~ 1.4e-8): palette diversity, BCL enrichment, DEFECTOR uniqueness
- Interpretive layer (mod 5, SEVEN) is consistent but NOT independently validated
- **(pos%7, pos%5) mod-35 table: OVERFIT** — LOO cross-validation 47.1% accuracy (below 48.6% baseline). Predicts 0/14 candidate positions as null. Descriptive artifact, not a generative rule. Downgraded 2026-03-25.
- Detail: `memory/palette_deep_investigation.md`, `memory/bcl_palette_keystream.md`

### Cardan Grille + Model 2 (2026-03-04)

**Status: PARADIGM MODEL, OPEN SEARCH**
- Paradigm: PT → Cipher(key) → real_CT → SCRAMBLE(σ) → K4_CARVED
- YES WONDERFUL THINGS disproved (incompatible with all 64 combos)
- 21/64 keyword/cipher/alphabet combos feasible; 5 have 2 FORCED sigma values
- ABSCISSA/beau/KA most promising: aligns with period-8 signal
- AZ→KA cycle structure: 17-cycle + 8-cycle + {Z} fixed
- Detail: `.claude/memory/grille_cardan_results.md`

### Mixed-Variant Bean Enumeration (2026-03-21)

**Status: FEASIBLE_BUT_WEAK — informational only**
- 146,577,600 surviving mixed-variant assignments (0.052% of 3^24)
- 5 positions LOCKED to Vigenere (27, 29, 30, 64, 65) in ALL solutions
- Bean constraints provide only ~1927x reduction — operationally weak
- Detail: `scripts/exploration/e_mixed_variant_bean.py`

### E-S-BERLIN-EXTEND Key Derivations (2026-02-28)

- Zero periods 1-26 consistent with 24-position sparse keystream (all 3 variants)
- Gronsfeld + Porta structurally eliminated (key values exceed digit/half-alphabet ranges)
- Beam search "ACTIONATION" is canonical false positive (underdetermination)
- Keystream Jaccard ENE∩BC ≈ 0.33-0.36 (consistent with random)
- Detail: `.claude/memory/elimination_ledger.md`

### Mailing List Mining — Untested Leads (2026-03-24)

5 Tier 2 leads from kryptos.groups.io (25,917 messages):
- Wheatstone cryptograph / clock cipher (physical device at CIA)
- Sanborn's "matrix" method (June 2005 interview reference)
- Double transposition with null insertion (community hypothesis)
- Keyed Caesar + route cipher hybrid
- Base-3/ternary encoding of alphabet
- Detail: `.claude/memory/mbox_mining_results.md`

---

## Elimination History — Full Detail in Topic Files

| Date | Section | Verdict | Topic File |
|------|---------|---------|------------|
| 2026-03-15 | Fleissner 180 + DEFECTOR autokey | CEILING/IMPOSSIBLE | `elimination_ledger.md` |
| 2026-03-15 | Palette-constrained null mask | DISPROVED (3,432 masks) | `stego_null_mask_tests.md` |
| 2026-03-15 | NDYAHR (5 variants) | ALL DISPROVED | `ndyahr_exhaustive.md` |
| 2026-03-15 | Polybius fractionation + null mask | ELIMINATED (1,126 configs) | `elimination_ledger.md` |
| 2026-03-15 | DEFECTOR autokey structural proof | IMPOSSIBLE | `elimination_ledger.md` |
| 2026-03-15 | Cipher model variations | 15/24 CEILING | `elimination_ledger.md` |
| 2026-03-15 | Statistical validation (6 claims) | 3 ROBUST, 3 WEAK | `elimination_ledger.md` |
| 2026-03-15 | Overnight computation (4 tasks) | ALL NOISE | `elimination_ledger.md` |
| 2026-03-15 | Null mask tests (7-remaining, NDYAHR paired) | DISPROVED | `stego_null_mask_tests.md` |
| 2026-03-16 | Leetspeak, K2 coords, keystream AP | ALL DISPROVED | `elimination_ledger.md` |
| 2026-03-16 | Session heavyweight (Cold War, DEFECTOR+PAL) | ALL ELIMINATED | `session_20260316_heavyweight.md` |
| 2026-03-16 | VIC family (6 variants) | ALL ELIMINATED | `vic_family_exhaustive.md` |
| 2026-03-16 | INCLINARE, CIA cryptonym, Period-6, 72+1 | ALL ELIMINATED | `elimination_ledger.md` |
| 2026-03-17 | 396 mask filter, MCMC quadgram | STRUCTURALLY DEAD / NOISE | `stego_null_mask_tests.md` |
| 2026-03-17 | Digraph-anchored, K1-K3 instructions, positional keying | ALL NOISE/DISPROVED | `elimination_ledger.md` |
| 2026-03-21 | Polybius grid walk, process-based ciphers | ALL NOISE | `elimination_ledger.md` |
| 2026-03-22 | K0 Morse running key, progressive running key | ALL ELIMINATED | `elimination_ledger.md` |
| 2026-03-23 | Palette as Gromark/columnar/index key | ALL DISPROVED | `elimination_ledger.md` |
| 2026-03-24 | Mailing list hypotheses (4 tested) | ALL NOISE | `mbox_mining_results.md` |
| 2026-03-25 | CKM credential key (K1/K2/K3 PT × keywords, 6 models, 173M+) | ALL NOISE | `elimination_ledger.md` |

All topic files in `.claude/memory/` unless otherwise noted.

---

## Topic File Index

### Active Research
- `grille_cardan_results.md` — Cardan grille + Model 2 detailed results, cycle structure
- `mbox_mining_results.md` — Mailing list mining results + 5 untested Tier 2 leads

### Stego/Null Layer
- `stego_null_mask_tests.md` — All null mask testing (palette-constrained, separator, position rule, brute force, INCLINARE, 396 filter)
- `memory/palette_deep_investigation.md` (repo) — Palette generation mechanisms
- `memory/bcl_palette_keystream.md` (repo) — BCL Beaufort keystream enrichment
- `memory/palette_mod35_rule.md` (repo) — Mod-35 position rule analysis
- `memory/palette_null_separator.md` (repo) — Null/non-null separator analysis
- `memory/polybius_row_selection.md` (repo) — Polybius row-selection mask

### Keystream Forensics
- `memory/keystream_forensics_v2.md` (repo) — Keystream structure analysis
- `memory/keystream_ap_investigation.md` (repo) — AP enrichment deep dive
- `memory/width10_17_deep_investigation.md` (repo) — Width 10/17 bigram analysis
- `memory/width21_bigram_73char.md` (repo) — Width 21 bigram 73-char

### Historical Elimination (Full Reports)
- `elimination_ledger.md` — Complete experiment reports (2026-02-28 to 2026-03-24)
- `ndyahr_exhaustive.md` — All 5 NDYAHR variant investigations
- `vic_family_exhaustive.md` — VIC family (6 variants)
- `session_20260316_heavyweight.md` — Cold War, Operation Gold, DEFECTOR+PALIMPSEST

### External Research
- `memory/ticom_archive_research.md` (repo) — TICOM archive research notes
- `memory/bruteforce_7remaining.md` (repo) — 7-remaining brute force analysis

---

*Last updated: 2026-03-25. Full history: topic files above. Volatile state maintained here.*

### Wilson Prime 1/p Masking Stream (2026-03-24)

**Status: DISPROVED (5,148 configs, best 0/24)**
- Hypothesis: WW at positions 19-20 signals Wilson primes (5, 13, 563); decimal/binary expansion of 1/p used as keystream
- Models tested: single digits mod 26, digit pairs mod 26, binary 5-bit groups mod 26, combined interleave, combined sum
- All 3 variants (Vigenere, Beaufort, Variant Beaufort) tested at all valid offsets
- 1/5 period=1 (trivial), 1/13 period=6, 1/563 period=281 (binary=562)
- Zero configurations scored >= 10/24 (all noise)
- Script: `scripts/novel/e_wilson_prime_mask_01.py` | Result: `results/wilson_prime_mask_20260324_163542.json`

### ITA-2/Baudot Mod-31 Reflective Encoding (2026-03-24)

**Status: DISPROVED (288 configs, best 4/24 anchored, 0/24 free)**
- Hypothesis (Edward Hannon, kryptos mailing list 2011): 31-char sculpture width maps to ITA-2 5-bit codes (0-31), mod-31 arithmetic for encryption
- 6 models tested: ITA-2 Vigenere mod 31, ITA-2 Beaufort mod 31, standard A=0 mod 31 (vig/beau/add), grid transposition (widths 30/31/32 with keyword column permutations), mod-31 position-dependent key, mixed ITA-2 encode/decode with mod-31 arithmetic
- 9 keywords: KRYPTOS, PALIMPSEST, ABSCISSA, DEFECTOR, SHADOW, BERLIN, SCHEIDT, SANBORN, SCHEIDTQ
- Bonus: grid31 transposition + mod-31 substitution combos (135 configs)
- Zero configurations scored >= 10/24. Best: AZ_vig31|key=SHADOW at 4/24 (noise)
- ITA-2 has 5 unmapped values in mod-31 space (0, 2, 4, 8, 27) causing ~16% of positions to be unmappable -- structural problem for this hypothesis
- Script: `scripts/novel/e_baudot_mod31_01.py` | Result: `results/baudot_mod31_20260324_123652.json`

### W-Delimiter Segment Rearrangement (2026-03-24)

**Status: DISPROVED (45,360 configs, best 0/24)**
- Hypothesis: 5 W's in K4 at positions [20,36,48,58,74] are delimiters; 6 segments should be rearranged before Vigenere/Beaufort decryption
- All 720 permutations of 6 segments tested x 7 keywords x 3 variants (Vig/Beau/VBeau)
- 3 modes: segments with W (97 chars), without W (92 chars), reversed internally
- Named orderings (identity, reverse, crib_v1, crib_v2, interleaved) also checked with IC diagnostics
- Zero non-zero scores across entire search space
- Script: `scripts/grille/e_w_delimiter_01.py`

### Sanborn "Matrix" Method (2026-03-24)

**Status: NOISE (3,108 configs, best 6/24)**
- Hypothesis: Sanborn's mention of a "matrix" in June 2005 interview; 5 models tested:
  1. Custom tableau (keyword-mixed 26x26, periodic key) -- 864 configs, best ~5/24
  2. Keyed Polybius 6x5 read-off + pair transposition -- 72 configs, best ~1/24
  3. Double-substitution matrix (two keyword alphabets + key shift) -- 1,728 configs, best 6/24
  4. Straddling checkerboard (keyword-derived assignments) -- 36 configs, noise
  5. Bifid-like mod 26 (no I/J merge, paired coordinate ops) -- 408 configs, noise
- Keywords: KRYPTOS, PALIMPSEST, ABSCISSA, DEFECTOR, SHADOW, SCHEIDT; periods 7-10
- Best: 6/24 from Model 3 (SHADOW/DEFECTOR alphabets, KRYPTOS key) -- well within noise
- 1,981/3,108 configs scored >= 1/24 but distribution is typical random (score 1: 1099, score 2: 684, ...)
- Script: `scripts/novel/e_sanborn_matrix_method_01.py`

### E-CKM-03b: CKM M1 English Wordlist Expansion (2026-03-25)

**Status: NOISE (1,920,000 configs, best 8/24)**
- Hypothesis: K4 key constructed via M1 model: key[i] = f(section[(i+offset) % Ls], keyword[i % Lk]) mod 26, using common English words as keyword
- Follow-up to E-CKM-03 (33 thematic keywords, zero hits >= 8)
- ~1000 English words (lengths 3-13) evenly sampled from wordlists/english.txt (896K words)
- 3 sections (K1, K2, K3) x 2 alphabets (AZ, KA) x 4 combiners (add, sub_AB, sub_BA, xor) x 20 offsets x 4 CT variants (CT97 + 3 CT73 masks)
- 10 hits at score 8/24 (noise ceiling); zero hits >= 9
- CKM credential-based M1 key construction with English keywords: ELIMINATED
- Script: `scripts/two_system/e_ckm_credential_03b.py` | Result: `results/e_ckm_credential_03b.json`

### E-GLOBAL-DELTA-SWEEP: Phase 2 Global Delta Rule Sweep (2026-03-25)

**Status: NOT SIGNIFICANT (1,248 tests, max |z| = 2.729, MC p = 0.954)**
- Hypothesis: A global constant-difference rule CT[i+d] - CT[i] ≡ v (mod 26) governs null placement
- For each lag d in {1,...,48} and delta v in {0,...,25}: counted pairs by null-involvement category
- Two-proportion z-test for enrichment at null-involved pairs vs non-null pairs
- Zero (lag, delta) pairs significant after Bonferroni correction (k=1,248)
- Highest observed z = 2.729 (lag=47, delta=7) -- well below MC median of 3.076
- MC baseline (100K shuffles of 17 null positions): observed max |z| ranks at 95th percentile FROM THE BOTTOM (p=0.954)
- Null positions show LESS delta structure than random placement, not more
- No global constant-difference rule exists for null value selection
- Script: `scripts/analysis/e_global_delta_sweep.py` | Result: `results/global_delta_rule_sweep.json`

### Phase 3: Stehle delta4=5 and Width-21 Bigram Interaction (2026-03-25)

**Status: WEAK INTERACTION -- no joint optimization detected**
- Hypothesis: Delta4=5 anomaly (pos 55-63, lag 4) and width-21 bigram anomaly share the same null insertion mechanism
- T3.1: 11 repeated width-21 bigrams found; 6 involve at least one null position. Key findings:
  - Positions 36 and 74 (both null, both W) create TWO repeated bigrams (LW at 15/53, WA at 36/74)
  - Position 59 (null, I) creates the IT bigram (matching pos 16)
  - Position 52 (null, K) creates the KK bigram (matching pos 31 and 73)
- T3.2: 12 of 17 null positions have constraints from BOTH delta4 and width-21 systems
  - Position 59: UNIQUE -- delta4 forces I, width-21 also allows I. Overlap = {I}. Actual = I. Both satisfied.
  - Position 58: delta4 allows {W, Z}, width-21 allows {I}. NO overlap. Actual = W (satisfies delta4, not w21).
  - Positions 14 and 75 also have overlap but actual values don't match the overlap set
- T3.3 MC (100K samples): p(W21 >= 11) = 0.015. CDW metric trivially achieved (CDW=4 in 100% of trials at lag=1).
  - NOTE: CDW metric measured max-any-lag chain length, not the Stehle-specific 5-consecutive-positions-at-lag-4 metric. The CDW result is UNINFORMATIVE.
  - Width-21 count alone is modestly significant (p=0.015) confirming prior finding (p=0.00016 on a different metric)
- Position 59 is the ONLY position where both anomalies agree and the actual value satisfies both
- No evidence of joint optimization -- the two anomalies appear to be independent consequences of null insertion
- Script: `scripts/analysis/e_stehle_width21_interaction.py` | Result: `results/stehle_width21_interaction.json`

### E-CT80-CIPHER-ATTACK: CT80 (17-null) Cipher Attacks (2026-03-25)

**Status: NOISE (2,010 configs, zero hits >= 6/24)**
- Hypothesis: K4 has exactly 17 nulls (consensus positions), giving 80-char ciphertext; standard cipher attacks on CT80 with free-position crib search
- CT80: RUXOHULSLIFBBFLRVQQPRNGKSSOTTQSJQSSEKZZWATJLUDIANFBNYPVTTMZFPKDKXTJCDKUHUAUEKCAR
- Phase 1: Periodic Beaufort/Vigenere/VarBeau with 22 keywords x 2 alphabets (AZ, KA) -- 132 configs, zero hits
- Phase 2: All 26 single-letter keys x 3 variants x 2 alphabets -- 156 configs, zero hits
- Phase 3: Columnar untranspose (widths 5,7,8,10,16,20) + 22 keywords x 3 variants x 2 alphabets -- 792 configs, zero hits
- Phase 4: Running key from K1/K2/K3 plaintext x 3 variants x 2 alphabets + col7 variants + offsets -- 930 configs, zero hits
- All scored with score_candidate_free (free-position crib search since positions shift after null removal)
- CT80 single-layer keyword attacks: ELIMINATED for these 22 keywords
- Script: `scripts/analysis/e_ct80_cipher_attack.py` | Result: `results/ct80_cipher_attack.json`

### Phase 1: Null Arithmetic Constraint Census (2026-03-25)

**Status: NOT SIGNIFICANT (4/17 constrained, MC p=0.59)**
- For each of 17 consensus null positions, checked all lags 1-48 for constant-difference chains through non-null neighbors
- 4 positions are arithmetically forced: 36(W, 1 constraint), 52(K, 3 constraints), 59(I, 1 constraint), 74(W, 2 constraints)
- All forced values are palette letters and uniquely determined
- BUT: total constraint count (7) matches random expectation (MC mean=7.30, p=0.59)
- Palette-random baseline is even higher (mean=8.85, p=0.78)
- Local arithmetic is NOT a null-value generation mechanism
- Script: `scripts/analysis/e_null_arithmetic_census.py` | Result: `results/null_arithmetic_constraint_census.json`

### Phase 4: Mod-35 LOO Cross-Validation (2026-03-25)

**Status: OVERFIT (LOO accuracy 47.1%, below 48.6% baseline)**
- Held out each of 17 consensus nulls, rebuilt (pos%7, pos%5) table from remaining 16, predicted held-out
- 8/17 correct (47.1%) — WORSE than naive "always predict NULL" baseline (48.6%)
- 9 of 17 nulls occupy unique cells or cells shared with "real" positions — removing from training collapses prediction
- The mod-35 table predicts ZERO additional nulls among 14 non-crib palette candidates
- **Downgraded from "confirmed finding" to "descriptive artifact with zero predictive power"**

### Phase 5: Width-21 Mask Resolution (2026-03-25)

**Status: TOP MASKS IDENTIFIED, CIPHER ATTACKS NOISE**
- Searched C(14,7) = 3,432 candidate 24-null masks (7 unknowns from 14 non-crib palette positions)
- Width-21 bigram count on CT73 as primary metric; 3 masks achieve max w21=8
- Core 5 positions in ALL top masks: {18(B), 19(B), 56(I), 62(B), 93(K)}
- Ambiguous pair from {45,46,47,48} cluster (KZZW region)
- All top-20 masks pass Bean constraints (242/242 inequalities)
- Cipher attacks on top 3 CT73s: ALL NOISE (0 hits >= 6/24 across 29 keywords x 3 variants x 5 test types)
- Script: `scripts/analysis/e_width21_mask_resolution.py`, `scripts/analysis/e_top3_mask_cipher_attack.py`

### Phase 6: Null Value Sequence Analysis (2026-03-25)

**Status: NO CLEAR PATTERN**
- 17 null values in position order: OBKOGBOWWKWIWGZIG
- All 7 palette letters used (W×4, O×3, G×3, B×2, K×2, I×2, Z×1)
- Word fragments: "BOW" (pos 12,14,20), "ZIG" (pos 78,84,85), "OBK" (pos 0,1,2 = first 3 CT chars)
- No arithmetic progression in AZ or KA indexing; no repeating period 2-8 pattern
- 3/17 have (pos - AZ_val) ≡ 0 mod 26 (pos 1→B, pos 14→O, pos 74→W) — mildly interesting but p≈0.05
- Null values do not obviously encode key material or a readable message

### E-NULL-SEQ-KEY: Null Value Sequence as Key Material (2026-03-25)

**Status: NOISE (144 configs, best 3/24)**
- Hypothesis: The 17-char null value sequence OBKOGBOWWKWIWGZIG serves as key material for K4 decryption
- 6 phases tested:
  1. Direct running key on CT97 (null seq + reversed, AZ + KA, 3 variants) -- 12 configs, best 3/24
  2. Running key on CT73 null-extracted (cycling + partial, AZ + KA) -- 18 configs, best 0/24
  3. Derived keys (cumulative sum mod 26, pairwise differences, AZ + KA) -- 24 configs, best 2/24
  4. Null seq as keyword for mixed alphabet + 7 common keywords -- 42 configs, best 3/24
  5. Null values interleaved as key at null positions + keyword elsewhere -- 42 configs, best 3/24
  6. Self-encryption keystream (2*CT mod 26 at null positions, nearest-neighbor + cycling) -- 6 configs, best 1/24
- Self-key sequence at null positions: CCUCMCCSSUSQSMYQM (no periodic consistency found)
- Zero configurations scored >= 6/24. All noise.
- Null value sequence as cipher key material: ELIMINATED
- Script: `scripts/analysis/e_null_sequence_as_key.py` | Result: `results/null_sequence_as_key.json`

### E-CRIB-KEYSTREAM-TOPOLOGY: Crib Keystream Topology Analysis (2026-03-25)

**Status: MULTIPLE SIGNIFICANT ANOMALIES CONFIRMED**
- 5 statistical tests on the Beaufort A=0 keystream at crib positions (24 values total)
- **T1 — BCL boundary sharpness at pos 71**: 7/8 palette in pos 63-70, 0/3 in pos 71-73. P(this split at any position in 11 draws)=0.00098. P(this exact split: first 8 >=7, last 3 =0)=0.00020. **SIGNIFICANT.**
- **T2 — Key segment length**: BCL strict run from start is only 1 (pos 64=C breaks it), but pos 65-70 has 6 consecutive palette. ENE is strongly back-loaded: last 6 have 4/6 palette (KUKKKL), last 7 have 5/7 (GKUKKKL).
- **T3 — ENE K-repeat**: K appears 4/6 in last 6 ENE positions. P(any palette letter >=4/6)=0.00028. **SIGNIFICANT.**
- **T4 — Symmetric enrichment**: P(any 8-window >=7 palette AND any disjoint 6-window >=4 palette in 24 draws)=0.00118. **SIGNIFICANT.**
- **T5 — Palette letter dominance**: K dominates ENE (4/13), G dominates BCL (3/11). P(both cribs have a dominant palette letter)=0.00040. Run of 3 consecutive identical palette letters (KKK at pos 30-32): P=0.004. Joint/independent ratio=0.96 (consistent with independence). **SIGNIFICANT.**
- **Key structural observation**: BCL enrichment is FRONT-loaded (pos 63-70) with sharp cutoff. ENE enrichment is BACK-loaded (pos 27-33). The enriched regions are at the ends CLOSEST to each other (gap=31 positions), not at the outer extremes.
- **AUDIT NOTE (statistical-auditor)**: Most sub-p-values are UNCONDITIONAL and double-count the prior palette enrichment (13/24, p~3e-5). After conditioning on the known BCL rate (7/11), the boundary at pos 71 has conditional p~0.10 (NOT SIGNIFICANT). The K-repeat has conditional p~0.015 (MARGINAL). Only the overall 13/24 enrichment and KA cols {0,3} remain independently significant.
- Script: `scripts/analysis/e_crib_keystream_topology.py` | Result: `results/crib_keystream_topology.json`

### E-DMPQ-EXCLUSION: {D,M,P,Q} Exclusion Rule Analysis (2026-03-25)

**Status: DESCRIPTIVE — no clean generative rule found**
- Palette pattern is UNIQUE among all C(11,7)=330 subsets of KA mod-5 superset
- 10/330 subsets meet "alternating col0/col3" criterion; palette is one of them
- No simple parity/modular rule cleanly separates 7 from 4 (best: 9/11 accuracy)
- Joint probability (column restriction + alternation + coverage): p=1.52e-5
- BUT column restriction (p=5e-4) is PRIOR; new alternation component is only p=0.030 conditional
- Beaufort KA key=N preimage: source {E,H,N,Q,S,T,V} concentrates in cols 1,4 (complementary to palette cols 0,3) — structural consequence of Beaufort arithmetic, not independent
- {D,M,P,Q} AZ indices {3,12,15,16}: no word, no obvious pattern
- Script: `scripts/analysis/e_dmpq_exclusion_rule.py` | Result: `results/dmpq_exclusion_rule.json`

### E-ENRICHMENT-TOPOLOGY: Joint ENE+BCL Enrichment Topology (2026-03-25)

**Status: NO SPATIAL STRUCTURE BEYOND BASE RATE**
- Autocorrelation at lags 1-12: all p > 0.07 (none significant after Bonferroni)
- Longest consecutive palette run (6, BCL pos 65-70): p=0.077 conditional (not significant)
- No periodic structure survives Bonferroni (k=47 periods tested)
- **{G,K,O} at 12/24 crib positions (subsequently downgraded — see E-GKO-AP-ANALYSIS)** — unconditional p=3.9e-6, but conditional p~0.01 (post-hoc corrected for C(7,3)=35 subset selection). In AZ: G=6, K=10, O=14 form an AP with step 4. Unique to Beaufort AZ indexing; not actionable.
- Spatial arrangement of palette within 24 crib positions carries NO additional information beyond overall 13/24 rate
- Script: `scripts/analysis/e_enrichment_topology.py` | Result: `results/enrichment_topology.json`

### E-GKO-AP-ANALYSIS: {G,K,O} Arithmetic Progression Deep Dive (2026-03-25)

**Status: SIGNIFICANT BUT NOT ACTIONABLE — AZ indexing artifact (downgraded 2026-03-25)**
- 7-test analysis of GKO={6,10,14} (AP with step 4) in Beaufort A=0 crib keystream
- **T1 (AP significance)**: {G,K,O} gets 12/24 hits — RANK 1 of 312 possible 3-element APs. P(max AP >= 12 in random)=0.0009. P(this specific AP >= 12)=0.0000 (0/100K MC trials). **Statistically significant (p<0.001, downgraded to AZ artifact — see status).**
- **T2 (uniqueness)**: Only 1/312 APs achieves >= 12 hits. GKO is the unique maximum.
- **T3 (K dominance)**: K=10 appears 5x (positions 28,30,31,32,70). Self-reinforcement NOT present: 2/12 GKO-ks positions have GKO CT (expected 2.1).
- **T4 (parity)**: 16/24 crib positions have same-parity CT+PT (= even keystream). Binomial p=0.0758 (marginal). Even enrichment is 16/24 vs expected 12; GKO concentration is a SUBSET of this parity enrichment.
- **T5 (Beaufort KA sources)**: Key=N (the "SEVEN" key) maps ZERO PT letters to GKO keystream values — GKO is NOT reachable through Beaufort KA with key=N. Keys S, B, C, D, M, N, U produce zero GKO sources. Key=Q produces 9 GKO sources.
- **T6 (running key under KA Beaufort)**: KA keystream at 12 GKO positions is {T:2, R:2, K:1, O:1, X:1, A:1, F:1, G:1, W:1, J:1} — flat, no dominance pattern. Full 24-position KA keystream: WXAKGZTOAXAFDRGTGNWRJLFK.
- **T7 (consecutive runs)**: KKK at positions 30-32 (length 3). P(max run >= 3)=0.0282. CT diffs at run = [4,8], PT diffs = [-4,18]. Same keystream forces CT_diff = -PT_diff mod 26 — confirmed.
- **Key insight**: GKO concentration is statistically real (p<0.001) but DOWNGRADED after 4-agent follow-up: (1) unique to Beaufort AZ indexing — all other variant/alphabet combos give 2-6/24; (2) English running key impossible under Beaufort AZ (50% GKO needed vs 10.3% in English); (3) no position function generates the pattern; (4) does NOT extend to non-crib positions. The anomaly is a crib-CT interaction artifact of AZ indexing, not a cipher mechanism signal.
- Script: `scripts/analysis/e_gko_ap_analysis.py` | Result: `results/gko_ap_analysis.json`

### E-GKO-KEY-SWEEP: Multi-Variant Multi-Alphabet GKO Key Sweep (2026-03-25)

**Status: BEAUFORT AZ UNIQUELY MAXIMIZES GKO -- variant/alphabet diagnostic completed**
- Computed running key values at all 24 crib positions under 6 variant/alphabet combos
- **Phase 1/3 (6 combos)**: GKO letter counts vary dramatically by model:
  - Beaufort AZ:  12/24 (MAXIMUM -- unique)
  - Beaufort KA:   6/24
  - Vigenere AZ:   6/24
  - Vigenere KA:   4/24
  - VarBeau AZ:    2/24 (MINIMUM)
  - VarBeau KA:    3/24
- The AZ keystream k[i]=(AZ(CT)+AZ(PT))%26 is FIXED at crib positions regardless of cipher model. The 12/24 GKO-valued indices are an invariant. What changes is which LETTERS those indices map to.
- **Phase 2 (Beaufort AZ running key)**: Under Beaufort AZ, key=keystream, so 50% of running key must be G/K/O. English G+K+O frequency = 10.3%. Binomial p = 1.17e-06. A natural English running key under Beaufort AZ is essentially impossible.
- **Phase 4 (7 keyword-mixed alphabets)**: DEFECTOR preserves the AP property (GKO indices {5,9,13}, step=4). Other keywords break it. GKO letter counts under Beaufort:
  - KRYPTOS: 6/24, DEFECTOR: 2/24, PALIMPSEST: 2/24, ABSCISSA: 6/24, SHADOW: 7/24, BERLIN: 2/24, SCHEIDT: 5/24
  - DEFECTOR and SHADOW show notable "best triple" concentration (10/24 for non-GKO triples)
- **Key finding**: Beaufort AZ is the ONLY variant/alphabet combo producing GKO enrichment >= 12/24. This is mathematically guaranteed since Beaufort AZ key = AZ keystream directly. Under any other model, the GKO letter concentration is 2-6/24 (within or near random expectation).
- **Implication**: If the cipher is NOT Beaufort AZ, the GKO concentration is an artifact of AZ indexing rather than a property of the key text. The anomaly's significance depends on assuming Beaufort AZ as the cipher model.
- Script: `scripts/analysis/e_gko_key_sweep.py` | Result: `results/gko_key_sweep.json`

### E-GKO-POSITION-KEY: Position-Dependent Key Functions for GKO Pattern (2026-03-25)

**Status: NO SIMPLE POSITION FUNCTION GENERATES GKO PATTERN**
- 7-test analysis of what function key[i] = f(i) or f(CT[i]) could produce GKO values ({6,10,14}) at exactly the 12 observed positions
- **T1 (Linear key)**: Best class_score=6 (a=16, b=20): 6/12 correct GKO, 0 false positives. Best exact match: 5/24. WEAK -- no better than half the GKO positions.
- **T2 (Quadratic key)**: Best class_score=6, exact_match=6/24 (a=11, b=17, c=4). Full 17,576-config sweep: 86 configs above threshold, none decisive. No improvement over linear.
- **T3 (Modular periods)**: ALL periods 2-13 have conflicts. Period 13 has fewest (8 conflicts, 3 consistent residues: {1,5,11}={G,K,O}). No period produces 0 conflicts; the keystream is NOT purely periodic at crib positions.
- **T4 (Key from CT letter)**: 9 of 9 multi-occurrence CT letters have INCONSISTENT key mappings. Key is NOT a function of CT letter alone. Only 5 single-occurrence CT letters have trivially "clean" mappings.
- **T5 (Parity prediction)**: Even keystream: 16/24 (all 12 GKO + 4 non-GKO). Best parity predictor: mod 13 at 83.3% accuracy (but with many residue classes, this is overfit). Overall even rate 67% sets the baseline; mod-M prediction barely exceeds it.
- **T6 (Difference patterns)**: GKO index sequence = [2,0,1,1,1,1,2,0,0,0,2,1] (O,G,K,K,K,K,O,G,G,G,O,K). All value differences are trivially multiples of 4 (AP step). ENE block is K-dominated (KKKK run), BCL block is G-dominated (GGG run). The two crib regions show MIRROR-like structure: ENE has O-start then K-plateau, BCL has O-start then G-plateau.
- **T7 (GKO index mapping)**: Mod 10 and mod 13 both achieve 11/12 accuracy (91.7%) for mapping position -> GKO index. Best linear (a*pos+b) mod 3: only 8/12 (not compelling). No quadratic mod 3 reaches 9/12. The high mod-10/mod-13 accuracy is an artifact of having 10-13 residue classes for 12 data points (overfit).
- **Key finding**: The GKO pattern at crib positions is NOT generated by any simple position-dependent function (linear, quadratic, periodic, or CT-dependent). The mirror structure between ENE and BCL blocks (K-plateau vs G-plateau) suggests the pattern arises from the interaction of crib content with the encryption mechanism, not from a position formula.
- Script: `scripts/analysis/e_gko_position_key.py` | Result: `results/gko_position_key.json`

### E-GKO-RUNNING-KEY-SEARCH: Running-Key GKO Cluster Analysis (2026-03-25)

**Status: PARTIAL KEY EXTRACTED, KEY FRAGMENTS NOT ENGLISH**
- 5-phase investigation of GKO enrichment implications for running-key models
- **Phase 1 (GKO-dense words)**: 6,015 English words have >=50% GKO density. Longest: MONOGONOPOROUS (14 chars, 50%). No Kryptos-specific words exceed 40% GKO density. CLOCK is highest at 40%.
- **Phase 2 (K1/K2/K3 GKO density)**: K1 max 24-char window = 12.5% GKO (far below 50%). K2 max = 25%. K3 max = 16.7%. No K section window approaches 50% GKO.
- **Phase 3 (K1/K2/K3 as running key)**: ALREADY ELIMINATED — cites E-K123-RUNNING-KEY (48,228 configs, best 6/24 NOISE)
- **Phase 4 (Partial key extraction)**: Under Beaufort A=0 (AZ), key = keystream at crib positions:
  - ENE key (pos 21-33): JLJODEGKUKKKL
  - BCL key (pos 63-73): OCGGBGOKTRU
  - 12/24 GKO positions: {24,27,28,30,31,32,63,65,66,68,69,70}
  - Key[21]=J != Key[63]=O, so key period is NOT a factor of 42
- **Phase 5 (Pattern analysis)**:
  - Letter freq in 24 key chars: K=5, G=4, O=3, J=2, L=2, U=2, then 6 singletons
  - English word fragments in ENE key: JODE (pos 23-26), ODEG (pos 24-27, 94 words), KUKK (pos 28-31, 2 words)
  - English word fragments in BCL key: OKTR (pos 69-72, 1 word), KTRU (pos 70-73, 6 words)
  - Neither 13-char ENE key nor 11-char BCL key appears as substring of any English word
  - 22 matching key-value pairs among 24 crib positions; GCD of all diffs = 1 (no periodic structure)
- **Conclusion**: A natural English running key under Beaufort AZ is essentially impossible (50% GKO required; English has ~10.3%). Key fragments contain marginal word-like substrings (JODE, ODEG) but nothing compelling. The GKO concentration likely reflects cipher mechanism rather than key content.
- Script: `scripts/analysis/e_gko_running_key_search.py` | Result: `results/gko_running_key_search.json`

### E-GKO-REVERSE-PLAINTEXT: Reverse GKO Pattern to Predict Non-Crib PT (2026-03-25)

**Status: GKO EXTENSION CONSISTENT WITH ENGLISH BUT NOT DISCRIMINATING**
- 7-phase analysis: if keystream at non-crib positions were constrained to GKO={6,10,14}, what plaintext results?
- **P1**: For each of 73 non-crib positions, computed 3 candidate PT letters (one per GKO value)
- **P2 (best-case GKO PT)**: Frequency-optimized plaintext achieves 69.1% top-8 letters (English ~70%) but quadgram score -6.935/char (random=-7.5, English=-4.84). Text is letter-frequency plausible but NOT word-structured.
- **P3 (compatibility)**: 51/73 (69.9%) non-crib positions have at least one GKO value producing a top-8 English letter. Expected random (best-of-3 from top 8/26): 66.8%. **NOT significant** -- barely above random expectation for best-of-3 selection.
- **P4 (constant keystream)**: K=10 everywhere produces score_candidate_free=24 (trivially, since cribs are preserved). Plaintext outside cribs is gibberish (WJATQWNW...).
- **P5 (sliding window)**: Non-crib regions (pos 0-20, 87-96) show 67-70% common letter rate under GKO-forced PT, comparable to crib regions. No standout English-looking window outside cribs.
- **P6 (null positions)**: Null positions are MORE GKO-compatible (avg best-rank 4.4) than non-null non-crib positions (avg best-rank 7.6). Diff=-3.3. **CONTRADICTS filler model** -- nulls are easier to extend with GKO, not harder.
- **P7 (English-optimal ks distribution)**: GKO values are English-optimal at 6/56 (10.7%) of non-null non-crib positions. Expected random: 11.5%. GKO top-8 production rate: 29.2% vs all-ks average 30.8%. **GKO is average, not special, for producing English at non-crib positions.**
- **Conclusion**: The GKO concentration at crib positions does NOT extend as a useful predictor to non-crib positions. The ~50% GKO rate at cribs is an anomaly of the crib letters interacting with those specific CT positions, not a global keystream property. Phase 6 finding (nulls MORE GKO-compatible) is interesting but follows from null positions having constrained CT letters (mostly palette={B,G,I,K,O,W,Z}).
- Script: `scripts/analysis/e_gko_reverse_plaintext.py` | Result: `results/gko_reverse_plaintext.json`
