# MEMORY.md — K4 Decision-Support Index

Decision dashboard for agents working on K4.
For durable repo setup, commands, validation rules, and operating doctrine, see `CLAUDE.md`.
For full history, audits, and experiment detail, use the topic files listed below.

---

## Project State

- ~286 experiments with recorded results; 670B+ configurations scored
- No credible decrypt path established as of 2026-03-26
- Positive findings to date are descriptive anomalies, not actionable decrypt levers
- Critical blocker: the consensus 17-position null mask does not yet have a fully documented provenance chain
- Computational work is constrained until null-mask provenance is re-established or replaced by first-principles derivation
- Current environment has transitioned from custom harnessing to Claude Code agent teams

---

## Hard Blockers

1. **Null-mask provenance gap** *(partially resolved 2026-03-27)*
   - Null-mask validation shows IC is non-discriminative within the palette-consistent 24-null family; palette consistency remains the only strong independent evidentiary basis for the consensus 17-set
   - 3,432 palette-consistent 24-null masks exist (consensus 17 + 7 of 14 extras); specific 24-null mask underdetermined by cipher statistics
   - `f_running_key_73char_overnight_v1.py` mask violates palette constraint (0/7 extras are palette letters) — do not use without correction

2. **Short-text underdetermination**
   - K4 is only 97 chars
   - Surface statistics are weak and frequently deceptive

3. **Potential multi-layer ambiguity**
   - Tier 2 single-layer eliminations do **not** eliminate those families as one layer of a multi-layer construction

4. **External-information ceiling**
   - Some plausible avenues may remain inaccessible without physical/chart/archive evidence

---

## What Is Eliminated (High Confidence)

- Gronsfeld
- Porta
- All periodic polyalphabetic, direct-correspondence single-layer models
- Fractionation families previously exhaustively tested
- Hill cipher
- Autokey families
- Progressive/quadratic/Fibonacci periodic key models under tested assumptions
- Structured transposition families + tested substitution models → noise
- Known tested running-key sources → no result
- Polybius fractionation + tested null-mask models → eliminated
- VIC-family tested variants → eliminated
- Gromark/Vimark on tested null-extracted forms → eliminated
- MCMC quadgram attack on CT73 → noise
- K0 Morse as tested running key source → eliminated
- Progressive running key → eliminated
- Palette-derived cipher key material → disproved
- CKM credential-style tested constructions → eliminated
- English running key + columnar transposition on all 3432 palette-consistent 73-char extracts → eliminated (61M configs, 0 English-like fragments; keystream frequencies structurally non-English)
- Periodic polyalphabetic on keyword-mixed tableaux (ABSCISSA, PALIMPSEST, ECLIPSE, NORMANDY ×AZ/KA) → eliminated (14,460 configs, max 6/24; Bean EQ proven alphabet-invariant; zero consistent small periods for all 30 combos)
- Mono + columnar(w1-10) + running-key Beaufort/Vigenère on keyword-mixed tableaux (AZ, KA, ABSCISSA×2, PALIMPSEST ×{std, bottom}) → eliminated via bijection discriminator (~47B checks, 0 survivors across 10 modes × 11 source texts × 1,385 trans configs; injectivity rejection is alphabet-invariant)

See `elimination_ledger.md` and topic files for exact evidence and scope.

---

## DO NOT TEST

Do not re-run without a materially new assumption, proof, corpus, or mechanism:

- Autokey variants already structurally eliminated
- DEFECTOR + PALIMPSEST inherited-ceiling variants
- K2 number-word key theories
- YES WONDERFUL THINGS as fixed opening PT[0:18]
- Positional lookup-table keying
- CIA cryptonym digraph constraints
- Leetspeak / palette-as-number ideas
- K2 coordinate key generation
- 72+1 delimiter theory
- NDYAHR hidden/unified/directional reinterpretations
- INCLINARE stacking null-mask theories
- Cold War keyword families already searched
- K1-K3 plaintext as literal key values
- Mailing-list hypotheses already tested
- CKM mod-26 constructions already searched
- OBKOGBOWWKWIWGZIG as direct key material
- CT80 single-layer keyword attacks already exhausted

If revisiting any of these, state explicitly what new assumption breaks the prior elimination.

---

## What Remains Open

1. ~~Re-derive the null mask from first principles~~ **Reframed:** IC/frequency/autocorrelation cannot discriminate within the palette family; the palette restriction (p≈3×10⁻⁵) IS the provenance. Open question narrows to: which 7 of 14 extra positions complete the 24-null mask?
2. **Mono + trans + running key from UNTESTED sources** — model survives structurally (13 mono DOF defeat fragment analysis) but all tested source texts eliminated via bijection discriminator on all tested tableaux. Next discriminator: word-boundary test on surviving model class; expand source-text corpus with pre-1990 texts Sanborn demonstrably accessed.
3. **Bespoke physical / procedural chart-based system** — the archive's "Code Breaker" overlay sketch and "actual coding charts" suggest mechanisms that do NOT reduce to standard Beaufort/Vigenère arithmetic. This is now the primary live archive branch after keyword-mixed tableau arithmetic was eliminated.
4. **Unknown-source running-key models** — tested corpus (Carter ×3, CIA/intel docs, K2/K3 PT, Sanborn manuscript) is thematically motivated but not exhaustive. Priority acquisitions: Kahn's "The Codebreakers", Schliemann's Troy narrative, additional Egyptological texts.
5. External evidence paths:
   - K5 ciphertext
   - Decoded or recovered coding charts (archive confirms they exist)
   - Circled letters on handwritten tableau (IMG_1223-1235, unexplored)
6. ~~ABSCISSA / Beaufort / KA-sigma style underdetermined constructions~~ **Strongly reduced:** periodic models eliminated on all tested mixed alphabets; running-key bijection eliminated on 10 alphabet modes × 11 sources. Live residual: ABSCISSA as procedural/physical chart clue (not standard arithmetic).
7. Multi-layer hand-executable systems with non-obvious peel order

---

## Immediate Next Actions

1. **Expand source-text corpus** — priority: Kahn's "The Codebreakers" (Scheidt connection), Schliemann Troy narrative (Sanborn manuscript reference), additional Carter/Egyptological variants. Re-run bijection on new sources (~25 min/mode, deterministic).
2. **Word-boundary discriminator on mono+trans+running-key** — the 13 mono DOF defeat frequency analysis but may not defeat dictionary word matching at boundaries.
3. **Investigate bespoke chart mechanisms** — the archive's overlay sketch and "actual coding charts" reference suggest non-standard constructions. This requires either (a) forensic analysis of the handwritten tableau photos for non-obvious structure, or (b) hypothesis generation about hand-executable procedures Scheidt might have taught Sanborn.
4. Treat early statistics as advisory only
5. Test both peel orders for any two-layer hypothesis
6. Preserve multiple structural branches instead of collapsing on IC/period alone

---

## Critical Pitfalls

- Positions are 0-indexed
- Use imported constants only; never hardcode CT, cribs, or null positions
- KA ordering is non-standard and must not be assumed
- Vigenère / Beaufort sign conventions are easy to mix up
- Scores on short texts are highly underdetermined
- Period evidence can be a transposition artifact
- A promising score is not evidence until independently reproduced

---

## Short-Layered-Cipher Doctrine

For short ciphertexts, do not treat IC, Kasiski, autocorrelation, DFT, or hill-climber optima as structural proof.

Mandatory:
- preserve diverse branches
- test both peel orders
- separate structural search from keyword search
- report deceptive signals explicitly when campaigns fail

---

## Session Findings (2026-03-27)

Null-mask validation shows IC is non-discriminative within the palette-consistent 24-null family; palette consistency remains the only strong independent evidentiary basis for the consensus 17-set. A 61M-configuration running-key fragment campaign found no English-like fragments across tested palette-consistent 73-char extracts under columnar-transposition models. The negative result appears structural rather than incidental: crib-derived keystream letter frequencies are profoundly non-English, and transposition cannot repair that. This strongly disfavors ordinary English running-key + columnar-transposition models, leaving mono + trans + running key as the main surviving structured family.

See `results/session_20260326_structural_campaign.md` for full report.

### Archives of American Art — Primary Source Findings (2026-03-27)

532 photos from Jim Sanborn's papers at Smithsonian. KEY FINDINGS [PRIMARY SOURCE]:
- **ABSCISSA** confirmed as Sanborn research term ("★ Definition of ABSCISSA" on to-do list)
- **Beaufort cipher** explicitly listed in Sanborn's handwritten cipher types list, along with Compass cipher, Morse code, Alphabet code, **Overlay**, **Normandy**
- **"3 words most"** — possibly 3 keywords (KRYPTOS, PALIMPSEST, ABSCISSA?)
- **"He lied"** — deliberate K2 coordinate change from 38° to 37° (one degree south)
- **"I wrote the Plain Text to be enigmatic"** — K4 PT is intentionally cryptic
- **Physical overlay "Code Breaker"** sketch — grille/overlay decryption concept
- **ATBASH** mentioned on same page as ABSCISSA
- **"4, 8, 10, 26 = Col"** — possible cipher parameters
- **Junction buoy** study with arrows similar to coding chart
- **CIA cryptonym system** described: "2 letters determine general category or place, followed by letters that form a word with the first two"

Full analysis: `archive_aaa_findings.md` in session memory. Photos at `reference/Pictures/Arichives of American Art/`.

### Archive-Informed Tableau Campaign (2026-03-27)

14,460 configs tested across 10 keyword-mixed tableau alphabets (ABSCISSA, PALIMPSEST, ECLIPSE, NORMANDY × AZ/KA). ALL NOISE (max 6/24). Key findings:
- **Bean EQ is alphabet-invariant** — proven: when CT[i]=CT[j] and PT[i]=PT[j], the key equality holds for ANY alphabet. No "magic alphabet" can bypass Bean.
- **Zero consistent small periods** for all 30 (alphabet, variant) combos — extends periodic elimination to all archive-derived mixed alphabets.
- ABSCISSA as tableau-construction keyword (chart column addressing): ELIMINATED for periodic models.
- Quagmire IV (split alphabets), indicator sweep, Atbash pre/post, reversed rows: ALL ELIMINATED.
- **NOT eliminated:** Running-key Beaufort on non-standard tableaux, physical overlay/chart interaction.

Doctrine memo: `docs/archive_aaa_doctrine.md`. Full report: `results/e_aaa_tableau_struct_06_report.md`.

### Running-Key Bijection on Mixed Tableaux (2026-03-27)

~47B checks across 10 alphabet modes × 1,385 transposition configs × 11 source texts × 2 directions × 2 variants. **ZERO survivors.** 4.8 hours runtime.
- Bijection discriminator's injectivity rejection is alphabet-invariant: switching from AZ to ABSCISSA-mixed/KA/PALIMPSEST-mixed does NOT rescue any source-text offsets.
- **ELIMINATED:** Mono + columnar(w1-10) + running-key Beaufort/Vigenère on tested mixed tableaux from all tested source texts.
- **NOT eliminated:** Running-key from UNKNOWN source texts, non-mono outer substitution layers, physical chart constructions that don't reduce to standard Beaufort/Vigenère arithmetic.

Full report: `results/e_aaa_runkey_bijection_08_report.md`.

---

## Key Reference Files

### Audit & Status
- `statistical_audit_20260326.md`
- `elimination_ledger.md`

### Active Research
- `grille_cardan_results.md`
- `mbox_mining_results.md`

### Stego / Null Layer
- `stego_null_mask_tests.md`
- `memory/palette_deep_investigation.md`
- `memory/bcl_palette_keystream.md`
- `memory/palette_mod35_rule.md`
- `memory/palette_null_separator.md`
- `memory/polybius_row_selection.md`

### Keystream Forensics
- `memory/keystream_forensics_v2.md`
- `memory/keystream_ap_investigation.md`
- `memory/width10_17_deep_investigation.md`
- `memory/width21_bigram_73char.md`

### Historical Elimination
- `vic_family_exhaustive.md`
- `ndyahr_exhaustive.md`
- `session_20260316_heavyweight.md`

### External Research
- `memory/ticom_archive_research.md`
- `memory/bruteforce_7remaining.md`
- `kubark_pdf_reference.md` — CIA KUBARK manual PDF (63pp scanned, needs OCR)

### Archives of American Art (PRIMARY SOURCE)
- `archive_aaa_findings.md` — Full analysis of 532 photos from Sanborn's papers
- `antipodes_archive_absence.md` — Antipodes completely absent from Sanborn's archive despite covering 1950-2023
- `dan_brown_lost_symbol_analysis.md` — Chapter 53 circled by Sanborn, 37/38 match, attorney memo, layered architecture
- `session_20260328_archive_campaigns.md` — Full session: tableau sweep, bijection, one-lie, Brown analysis, buoy sketch

---

Last updated: 2026-03-28