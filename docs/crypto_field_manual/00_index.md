# Crypto Field Manual — Index

**Purpose:** A durable, historically grounded cryptographic knowledge base focused on pencil-and-paper methods, built to raise kryptosbot's baseline competence and translate domain knowledge into falsifiable K4 research hypotheses.

**Audience:** kryptosbot (Claude Code agents working on Kryptos K4) and the human lead.

**Scope:** Methods plausible for a 1988–1990 hand-cipher context. This manual does NOT claim any technique is "the answer" to K4; it equips the research team to generate and evaluate hypotheses rigorously.

---

## File Map

| File | Contents | Use it when… |
|------|----------|--------------|
| `00_index.md` | This file. Master index, glossary, shared taxonomy. | Orienting to the field manual. |
| `10_people_orgs_timeline.md` | Chronological timeline: Alberti (1466) → Trithemius → Porta → Jefferson → Civil War → Friedmans → WWII → Cold War → Kryptos (1990). 23 entries, era summaries. ~2,400 words. | You need historical context for a cipher family, want to know who invented what, or need to assess Cold War plausibility. |
| `20_cipher_catalog.md` | 17 cipher family entries + IC diagnostic tool + Dictionnaire Égyptien concept. Each with mechanism, hand execution, diagnostics, K4 plausibility rubric (5 dimensions, 1–5 scale). Eliminated vs. Open summary table. ~4,500 words. | You need to understand how a cipher works, what artifacts it produces, or how to test it against K4 constraints. |
| `30_k4_mapping_matrix.md` | Master matrix (33 cipher entries × 7 columns), 5 experiment outlines for open items, cross-reference table (8 K4 observables × consistent/inconsistent families). ~3,600 words. | You need to know what's been tested, what hasn't, and what to try next. |
| `40_recommended_additions.md` | 13 additional topics in 3 priority tiers (HIGH/MEDIUM/CONTEXT), each with K4 justification and what it would unlock. Summary table of assumption-breaking potential. ~2,500 words. | Looking for new research directions beyond the mandatory topic list. |

---

## How This Relates to Existing Docs

This field manual is **complementary** to existing repo documentation:

- **`docs/elimination_tiers.md`** — What's eliminated and at what confidence. The field manual REFERENCES this; it does not duplicate elimination proofs.
- **`docs/research_questions.md`** — Prioritized unknowns (RQ-1..RQ-13). The field manual's recommended additions link back to open RQs.
- **`docs/invariants.md`** — Verified computational invariants. The cipher catalog cites these; it does not restate them.
- **`docs/kryptos_ground_truth.md`** — Public facts about Kryptos. The timeline cites this for Sanborn/Scheidt context.
- **`reports/final_synthesis.md`** — 170+ experiment synthesis. The mapping matrix cross-references experiment IDs.

**Rule:** If information already exists in the above files, we cite it with a path reference rather than restating it.

---

## Shared Taxonomy

### Cipher Family Codes

Used consistently across all field manual files for cross-referencing.

| Code | Family | Examples |
|------|--------|----------|
| **SUB-MONO** | Monoalphabetic substitution | Caesar, Atbash, keyword mixed, affine |
| **SUB-POLY** | Polyalphabetic substitution | Vigenère, Beaufort, Gronsfeld, Quagmire I–IV |
| **SUB-POLY-AUTO** | Autokey variants | PT-autokey, CT-autokey |
| **SUB-POLY-RUN** | Running key | Key = text of another document |
| **SUB-DIGRAPH** | Digraphic substitution | Playfair, Two-Square, Four-Square, Porta (digraphic mode) |
| **SUB-FRAC** | Fractionation | Bifid, Trifid, ADFGVX, ADFGX, straddling checkerboard |
| **SUB-POLY-MECH** | Mechanical polyalphabetic | Enigma, Hebern, Kryha, M-325 SIGFOY, KL-7 ADONIS |
| **SUB-POLY-PROG** | Progressive/structured key | Gromark, Vimark, Fibonacci key, polynomial key |
| **TRANS-COL** | Columnar transposition | Simple columnar, double columnar, Myszkowski |
| **TRANS-ROUTE** | Route ciphers | Spiral, diagonal, serpentine, boustrophedon |
| **TRANS-GRILLE** | Grille / mask ciphers | Cardano grille, turning grille, Fleissner |
| **TRANS-RAIL** | Rail fence / zigzag | Rail fence with N rails |
| **MULTI** | Multi-layer compositions | Any combination of the above |
| **CODE** | Code systems | Nomenclators, codebooks, one-part/two-part codes |
| **SIGNAL** | Signaling systems | Wig-wag, Morse, semaphore (encoding, not encryption) |

### K4 Constraint Shorthand

Referenced throughout the field manual when assessing compatibility.

| Tag | Constraint | Detail |
|-----|-----------|--------|
| **ALPHA-26** | Full 26-letter alphabet required | All 26 letters appear in K4 CT; eliminates 5×5 Polybius (I/J merge) |
| **BEAN-EQ** | k[27] = k[65] | CT[27]=CT[65]=P, PT[27]=PT[65]=R; variant-independent |
| **BEAN-INEQ** | 21 inequality constraints | See `docs/invariants.md` |
| **CRIB-24** | 24 known plaintext positions | Pos 21–33 = EASTNORTHEAST, pos 63–73 = BERLINCLOCK (0-indexed) |
| **IC-LOW** | IC ≈ 0.0361 | Below random (0.0385), but NOT statistically significant for n=97 |
| **LEN-97** | Length 97 (prime) | Constrains grid dimensions; no 2-factor grid possible |
| **PEN-PAPER** | Hand-executable | Scheidt background + 1989 technology context |
| **NON-PERIODIC** | Key is provably non-periodic | Under additive key model + exact cribs (see `docs/invariants.md`) |

### Truth Taxonomy Labels

Every nontrivial claim in this manual MUST carry one of:

- **[PUBLIC FACT]** — Verified by reputable public reporting or primary sources
- **[DERIVED FACT]** — Deterministic consequence of PUBLIC FACTS, reproducible
- **[INTERNAL RESULT]** — Empirical result from this repo, with artifact pointer + repro command
- **[HYPOTHESIS]** — Plausible but unproven; must include test plan
- **[POLICY]** — Operating rule for how we work

---

## Quick Reference: K4 Constraints Summary

For convenience, the full constraint set that any K4 hypothesis must satisfy:

1. **Ciphertext**: 97 characters, all 26 letters present (ALPHA-26)
2. **Known plaintext**: 24 characters at fixed positions (CRIB-24)
3. **Bean equality**: k[27] = k[65] (BEAN-EQ)
4. **Bean inequalities**: 21 pairs (BEAN-INEQ)
5. **Non-periodic key**: Under additive model (NON-PERIODIC)
6. **IC**: 0.0361, not statistically significant (IC-LOW)
7. **Length**: 97, prime (LEN-97)
8. **Hand-executable**: Plausible for pen-and-paper (PEN-PAPER)
9. **Multi-layer likely**: Sanborn's "two separate systems" statement; single-layer exhaustively eliminated
10. **Full solution oracle**: crib=24/24 + Bean PASS + quadgram > -4.84/char + IC > 0.055 + non-crib words ≥7 chars ≥3

See `docs/invariants.md` for exact keystream values and Bean constraint details.
See `docs/elimination_tiers.md` for what has been tested and eliminated.

---

## Key Cross-Cutting Findings

Insights that emerged from building the field manual across all four files:

1. **Two assumption-breaking model classes are untested** (`40_recommended_additions.md`):
   - **Homophonic substitution** — breaks the additive-key assumption underlying ~65% of repo eliminations. K4's IC-LOW and ALPHA-26 are both consistent with proportioned homophones.
   - **Null/steganographic extraction** — breaks the "decrypt(CT)=PT" assumption. If K4's message is extracted by selection rule rather than decrypted, the entire elimination framework is inapplicable.

2. **The ONE identified open structured gap** (`30_k4_mapping_matrix.md`, experiment outline #2):
   - Mono + transposition + running key is UNDERDETERMINED (E-FRAC-54). Self-encrypting positions at CT[32]=PT[32]=S and CT[73]=PT[73]=K fix 2 of 13 mono DOF. Frequency constraints may reduce the remaining 11 DOF enough for running key detection.

3. **VIC-like procedural ciphers are a missing model class** (`40_recommended_additions.md`):
   - The VIC cipher demonstrates 4+ hand-operable techniques in one system. No VIC-style multi-step procedural model has been tested against K4. A modified VIC using letter-to-letter substitution (avoiding the eliminated straddling checkerboard) is untestable without a model but plausible.

4. **Historical pattern: multi-layer was standard by 1860** (`10_people_orgs_timeline.md`):
   - Civil War ciphers combined substitution + transposition. By Scheidt's era, multi-layer was default doctrine. This strongly supports Sanborn's "two separate systems."

5. **Running key remains the only surviving structured key model** (`20_cipher_catalog.md`):
   - Every other structured key generation method (periodic, autokey, progressive, Fibonacci, quadratic, Gromark/Vimark) is ELIMINATED. The key is either from an unknown text or from a bespoke non-algorithmic source (coding charts).

---

*Created: 2026-02-27 | Part of the Kryptos K4 research project*
