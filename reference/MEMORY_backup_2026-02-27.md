# Kryptos K4 — Persistent Memory Index

## Project Status (2026-02-27)
- **267+ experiments, ~669B configs total, ALL NOISE** — `reports/final_synthesis.md`
- **TWO GROUND TRUTHS framework established** — `docs/two_ground_truths.md`
- **Punctuation / X-delimiter structural analysis** (2026-02-27) — see below
- **Kryptos section boundary map (Physical Kryptos)**: K1[0-62] K2[63-434] K3[435-771] K4[772-868] = 869
- **Antipodes begins with K3**, cycling K3→K4→K1→K2, 865 letters per pass
- **Physical vs Intent divergences**: IDBYROWS vs XLAYERTWO, UNDERGRUUND vs UNDERGROUND, 4 vs 5 delimiter X
- **K4 CT is ground-truth-agnostic** — IDENTICAL on both sculptures, no corrections announced
- Antipodes transcription COMPLETE + computationally verified (2026-02-25)
- **Physical/optical hypothesis OPEN**: S-curve projection + pool — untestable without geometry
- **YAR→WLD post-decryption hypothesis OPEN** — YAR in K3 CT maps to WLD in K3 PT (unverified, K3 decryption method not reproducible)
- Next action: Antipodes physical measurements when Hirshhorn reopens, or K5/external info

## Punctuation & X-Delimiter Analysis (2026-02-27, E-AUDIT-08)
**Punctuation is treated INCONSISTENTLY across K1-K3 — this is structural, not accidental.**

### Punctuation hierarchy on Kryptos sculpture
- `?` = LITERAL on copper, NOT enciphered (4 total on cipher side)
- `.` period = NEVER appears on Kryptos (but DOES appear on Antipodes as S.F. dots)
- `'` apostrophe = OMITTED entirely (HOW'S → HOWS)
- `X` as period = ENCIPHERED as a regular cipher letter
- `Q` as `?` = ENCIPHERED (K3 plaintext: CHAMBERQ = CHAMBER?)

### Delimiter X positions
- **K1**: 0 delimiter X (single sentence, no periods)
- **K2 (sculpture, pre-correction)**: 4 delimiter X at positions [67, 137, 198, 250], CT letters = ASTT
- **K2 (corrected)**: 5 delimiter X (adds position 361 = WEST|X|LAYERTWO)
- **K3**: 1 delimiter X (FROM THE MIST|X|CAN YOU SEE ANYTHING) — missed in prior analysis because repo K3 PT is garbled
- **K2 also has 2 content X**: in EXACT (pos 211) and SIX (pos 288)

### K3 plaintext is GARBLED in repo
- Repo K3 PT = 226 chars, K3 CT = 336 chars — **110-char discrepancy**
- Repo has nonsense: "DEBABORETURNST", "SENTALANTSANDHOW"
- Full correct K3 PT (from Antipodes layout) is the Howard Carter / Tutankhamun passage ending "FROM THE MIST X CAN YOU SEE ANYTHING Q"
- **Must fix repo K3 PT** — multiple scripts use the wrong version

### K4 X-as-delimiter hypothesis [HYPOTHESIS]
- K4 CT has X at positions **6 and 79** (both outside crib regions)
- If these are delimiter X in plaintext: K4 has **3 sentences of lengths 6, 72, 17**
- Both cribs (EASTNORTHEAST pos 21-33, BERLINCLOCK pos 63-73) fall in middle segment
- **Self-encrypting X**: PT=X → CT=X requires key=K (KA Vigenère) or key=A (AZ Vigenère)
- **New constraint**: k[6] = k[79] (gap=73), alongside Bean k[27]=k[65] (gap=38)
- Test plan: combine k[6]=k[79] with Bean and crib constraints to narrow key model
- Script: `scripts/e_audit_08_delimiter_x_extraction.py`

### Antipodes Row 22 anomaly [HUMAN CONFIRMED]
- The `?` after LOCATION on row 22 is made **very skinny** — does NOT consume a character space
- This is UNIQUE on the entire Antipodes sculpture (all other ? take full space)
- Same row has **W.W. with dots** (Kryptos has WW without dots)
- Sanborn compressed the ? to fit the dots — dots were MORE IMPORTANT than consistent ? spacing
- Implication: punctuation placement is deliberate and structural

### K2 delimiter gap pattern
- Gaps between K2 delimiters: 70, 61, 52 (decreasing by 9 each)
- If continued: 43, 34, 25, 16, 7... — suggestive but only 3 data points

## Key Constants
- CT: `OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR`
- Length: 97 (prime), IC: 0.0361 (NOT unusual for n=97), all 26 letters present
- Cribs (0-indexed): positions 21-33 = EASTNORTHEAST, positions 63-73 = BERLINCLOCK
- Bean EQ: k[27]=k[65] (variant-independent: CT[27]=CT[65]=P, PT[27]=PT[65]=R)
- Key is provably NON-PERIODIC under additive key model + exact cribs (see Audit below)

## Scoring Rules
- Period <=7 is meaningful (~8.2/24 expected random). **ONLY trust p<=7 scores.**
- Period 13: ~13.5. Period 17: ~17.3. Period 24: ~19.2. All high-period scores are FALSE POSITIVES.

## Multi-Objective Oracle Thresholds
crib=24/24 + Bean PASS + quadgram > -4.84/char + IC > 0.055 + non-crib words >=7 chars >= 3 + semantic coherence (human).

## Sanborn Direct Communication (2026-02, unique primary source)
1. "I generally don't answer method questions, suffice it to say the NSA tried many layered systems on it"
2. "kryptos is available to all" (solution from PUBLIC info only)
3. Berlin Clock is "A reminder"
4. "I hope more people ask to see Antipodes it should be out again"
- Implication: standard multi-layer FAILED at NSA. Publicly available info suffices. Pushes AGAINST random charts, TOWARD visible sculpture elements used unconventionally.

## 2025 Developments (discovered via web search 2026-02-25)
- **Sanborn Aug 2025 open letter + 4 new clues** (Elonka.com, Scientific American):
  1. Two historical events: his 1986 Egypt trip + 1989 Berlin Wall fall
  2. BERLINCLOCK = **Weltzeituhr** (World Clock at Alexanderplatz), NOT Mengenlehreuhr
  3. "The codes within Kryptos are about delivering a message"
  4. K5 connects to K2's "its buried out there somewhere"
- **William H. Webster died August 8, 2025** — CIA Director during Kryptos installation (1987-1991), the "WW" in K2's "ONLY WW THIS IS HIS LAST MESSAGE". Sanborn's open letter was the SAME MONTH. Served 4 years + **97 days** as DCI. See `reference/william_h_webster.md`
- **"Who says it is even a math solution?"** — Sanborn's public quote (Spy Museum, Nov 2025). Counseled "creativity."
- **K4 plaintext DISCOVERED but NOT SOLVED** (Kobek-Byrne, Sept-Oct 2025):
  - Found scrambled plaintext strips in Smithsonian Archives of American Art
  - Sanborn: "They discovered it. They did not decipher it. They do not have the key. They don't have the method."
  - Kobek/Byrne signed no NDA, went public in NYT Oct 16 2025, but did NOT release the plaintext
  - Smithsonian materials now SEALED until 2075
- **$962,500 auction** (RR Auction, Nov 20 2025): Complete K4 archive sold to anonymous buyer. Includes coding charts, copper maquette, Scheidt letter, AND a private session with Sanborn explaining the full methodology. Buyer identity unknown.
- **K5 confirmed**: 97 chars, "similar but not identical" coding to K4, shares some coded words at same positions, will be in a public space, release TBD
- **Sanborn health**: Turned 80 on auction day. "I no longer have the physical, mental or financial resources." Cancer treatment ~2023.
- **No one else has done systematic Antipodes analysis** — our 1,584-letter reconstruction is unique in the community
- Multiple unverified AI/"solutions" appeared (Naughton, Klepp, Genie Engine) — all debunked
- Sources: elonka.com/kryptos, scientificamerican.com, washingtonpost.com, rrauction.com, schneier.com

## Antipodes Sculpture — Analysis (2026-02-25, FINAL)
- **Location**: Hirshhorn Museum (Smithsonian), Washington DC — public access
- **Sequence**: K3 → K4 → K1 → K2 → K3 → K4 → K1 → K2 (truncates mid-K2). NO delimiters between sections except ONE space.
- **ONE SPACE only** — row 13 (K4→K1, pass 1). Row 39 has NO space. [HUMAN CONFIRMED, REVISED]
- **? marks are PROSE CONTENT, not delimiters**: K3/K4 boundary `?` = K3's "CAN YOU SEE ANYTHING?". K2 `?` marks = K2's questions. No delimiters between K1/K2 or K2/K3 supports this.
- **TWO DOTS unique to Antipodes**: Row 22 `W.W.` with dots in K2 plaintext position. Dots do NOT change letter spacing but ? on same row is compressed to compensate. [HUMAN CONFIRMED]
- **1,584 letters, ZERO mismatches** (computational verification against K3+K4+K1K2 × 2 passes, with UNDERGROUND correction)
- **Transposition impossibility**: CT has 2 E's, cribs need 3 E's → pure single-layer transposition is mathematically impossible for K4
- **Row 34 is longest** (36 chars, ends in L). Range: 32–36 chars/row.
- **Full justification** — both margins flush, variable inter-char spacing. Like "justify" in Word. Kryptos is ragged right. [HUMAN CONFIRMED]
- **Truncation**: Ends at K1K2 pass 2 pos 286/432, right before 3rd K2 `?` and dots. 6-foot version may lack final Z.
- **Tableau**: 32×33, perfect KA cyclic shifts, ZERO anomalies, no extra L. [HUMAN VERIFIED]
- **Absent from Antipodes**: YAR superscript, extra L, out-of-alignment letters. [HUMAN CONFIRMED]
- **Extra L = strongest "one clue" candidate** (Sanborn CNN 2005)
- Full reconstruction: `memory/antipodes_reconstruction.md`
- Spreadsheet: `reference/Pictures/antipodes/Antipodes.xlsx` + chart: `Antipodes_Cipher_Chart.jpg`
- **Still need**: Right-side cylinder photos, rows 19+43 edge resolution, Z at end of row 47

## What's ELIMINATED (summary)
Full detail: `memory/eliminations.md` + `docs/elimination_tiers.md`
- ALL periodic substitution, ALL structured transpositions (single columnar w5-12 exhaustive, double columnar w7-9 exhaustive 667B, keyword w13-15, Myszkowski, AMSCO, rail fence, etc.)
- ALL key models except running key (autokey, progressive, polynomial, Fibonacci, LCG, Hill, Quagmire, Porta, Gronsfeld, Gromark/Vimark)
- Hill+transposition (E-ANTIPODES-01), Gromark/Vimark+transposition (E-ANTIPODES-05) — closed open gaps
- ALL fractionation (Bifid, Trifid, ADFGVX/ADFGX, Playfair, Two-Square, Four-Square)
- Running key from 15+ known texts, null/skip ciphers, shared-key models, tableau permutations, sculpture-parameter ciphers, multi-layer cascades, bespoke experiments
- CT is statistically consistent with random text of length 97 (IC, DFT, autocorrelation all non-significant)
- Physical reversal/mirror operations (all orientations, Antipodes widths): ELIMINATED
- Tableau path keys, YAR block cipher, K3→K4 continuity, XLAYERTWO trim, coordinate grid: ALL NOISE

## What Remains Open
1. **Running key from unknown text** — only structured key model surviving Bean
2. **Bespoke physical/procedural cipher** — "not a math solution", coding charts ($962.5K)
3. **Physical S-curve projection hypothesis** — light through cut copper + reflecting pool = physical decryption. Untestable without sculpture geometry measurements. Consistent with Sanborn's artistic practice and "not a math solution."
4. **Non-standard structures not yet conceived** — position-dependent alphabets, non-textbook methods
5. **External information needed**: K5 CT, Smithsonian (2075), decoded coding charts
6. **Antipodes physical inspection** — highest-leverage next action (Hirshhorn under renovation)

## Two Ground Truths (2026-02-27) — `docs/two_ground_truths.md`
**Physical Sculpture (A)** = what the copper says. **Sanborn's Intent (B)** = what he says it should say.
- K4 CT is **identical** across both — no corrections, ground-truth-agnostic
- K2 ending: IDBYROWS (A, both sculptures) vs XLAYERTWO (B, 2006 verbal correction, never on copper)
- K2 UNDERGROUND: UNDERGRUUND on Kryptos (A) vs UNDERGROUND on Antipodes (A) and coding charts (B)
- K2 delimiter X: 4 on physical (A) vs 5 with restored X (B)
- K2 cipher letters: 369 (A) vs 370 (B, with restored X)
- DESPARATLY: Sanborn REFUSED to say if intentional — divergence type unknown
- **Default to Physical (A)** for primary analysis; test both when method depends on K2 structure

## Kryptos vs Antipodes Comparative Analysis (2026-02-26, audited 2026-02-27)
- **Kryptos section lengths**: K1=63, K2=372 (369 cipher + 3 literal ?), K3=337, K4=97, Total=869
- **Antipodes section lengths**: K3=336, K4=97, K1=63, K2=369, per-cycle=865 (4 fewer than Kryptos)
- **Difference**: On Antipodes, ? REPLACES cipher letters (K3 loses 1 final cipher letter, K2 loses 3 Q's enciphering ?)
- **Single CT difference**: pos 177 (R→E), the UNDERGRUUND correction. K4 is character-identical.
- **K2 X-omission on both**: both predate 2006 correction, decrypt to IDBYROWS not XLAYERTWO
- **Antipodes = "original" version**: preserves correct E at UNDERGROUND, pre-correction text
- **Colin's theory**: Antipodes exists to make Kryptos "available to all" (public museum vs CIA HQ)
- **Physical hypothesis**: Sanborn's art = light through copper. Pool = projection surface. "Not a math solution."

## Key Theoretical Results
- **Bean impossibility (E-FRAC-35)**: Only periods {8,13,16,19,20,23,24,26} survive for periodic key + ANY transposition (using 22 Bean constraints)
- **Full pairwise impossibility (E-AUDIT-01)**: ALL periods 2-26 eliminated using all 276 pairwise constraints from 24 crib positions (strictly stronger than Bean-only)
- **Underdetermination is ABSOLUTE**: ~2^138 permutations satisfy ALL constraints. No automated metric separates SA gibberish from real English at 97 chars.
- Bean is TAUTOLOGICALLY SATISFIED by the 24 cribs for transposition models

## First-Principles Audit (2026-02-26)
**Critical finding**: Most eliminations assume fixed crib positions + additive key model.
- **A1 (fixed positions)**: Required by 100% of eliminations. If positions float, scoring logic is invalid.
- **A3 (additive key)**: Required by ~65% of eliminations. Bean constraints only valid for additive models.
- **Bean is family-specific, NOT universal**: Only valid inside additive single-symbol key models.
- **Non-periodicity is conditional**: Robust to 97% of single perturbations, but periods 24-26 can resurrect under positional drift. No period ≤23 ever resurrects.
- **Position-free scorer built**: `score_candidate_free()` in `aggregate.py` + `free_crib.py`
- **Audit experiments** (all noise): strip stagger (20M configs), Weltzeituhr FSM (6K), Cardan aperture, crib robustness
- **IC insight**: Weltzeituhr FSM produces mean IC=0.0373, with 31.6% of samples ≤ K4's 0.0361. Without-replacement scheduling CAN produce sub-random IC.
- Full matrix: `reports/audit_matrix.md`

## kryptosbot.com
- Static site builder: `site_builder/` (Jinja2 + Python, builds to `site/`)
- Design system v2: Inter + JetBrains Mono, 8px grid, semantic tokens, dark/light themes
- Preview: `cd site && python3 -m http.server 8000 --bind 0.0.0.0`
- Network: user on 192.168.1.179, server is 192.168.1.156 (headless Ubuntu, no GUI)

## Columnar Crib Span (2026-02-27)
- Both cribs span ALL columns for grid widths 7-11 (pigeonhole: crib_len >= width)
- Width 12: BERLINCLOCK (11 chars) misses column 2. EASTNORTHEAST still spans all.
- Width 13: BERLINCLOCK misses columns 9,10. EASTNORTHEAST spans all 13.
- Implication: simple columnar can't selectively affect one crib at widths 7-11

## File Index
- `memory/full_ciphertext.md` — Complete Kryptos sculpture ciphertext (K1–K4), section boundaries, notes
- `memory/kryptos_tableau.md` — Kryptos Vigenère tableau (KA alphabet), row anomalies, usage notes
- `memory/antipodes_tableau.md` — Antipodes tableau (human-verified 2026-02-25), comparison with Kryptos, extra L analysis
- `memory/eliminations.md` — Full elimination record with experiment references (380 lines)
- `memory/kryptosbot.md` — kryptosbot.com design document
- `docs/elimination_tiers.md` — Elimination confidence tiers (Tier 1-4)
- `docs/invariants.md` — Verified computational invariants (keystream, Bean, alphabets)
- `docs/two_ground_truths.md` — Physical Sculpture vs Sanborn's Intent framework (2026-02-27)
- `docs/kryptos_ground_truth.md` — Public facts, 2025 disclosures, hypothesis classes
- `docs/research_questions.md` — Prioritized unknowns (RQ-1 through RQ-13)
- `anomaly_registry.md` — Physical anomalies + narrative anomaly allocation
- `reports/final_synthesis.md` — Comprehensive elimination landscape
- `reports/audit_matrix.md` — Formal assumption dependency matrix (2026-02-26)
- `reports/k4_ground_truth_audit_2026-02-27.md` — Four-source ground truth audit (Colin's Antipodes.xlsx verification)
- `archive/` — Legacy harness, session reports, superseded dragnets
