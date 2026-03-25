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

## Active Findings (Confirmed, Actionable)

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
- Beaufort KA key=N maps {E,H,N,Q,S,T,V} → palette exactly; source contains "SEVEN"
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
