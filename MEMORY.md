# MEMORY.md — Kryptos K4 Project Memory

Persistent knowledge base for agents working on the Kryptos K4 project.
For full project guidance, see [CLAUDE.md](CLAUDE.md).

---

## Project State

- **320+ experiments complete**, 669B+ configurations scored
- **0 genuine signals** — all scores within noise at discriminating periods
- Computational work paused pending Antipodes physical inspection
- Transitioned from custom 6-agent harness (170+ experiments) to official Claude Code agent teams

## E-S-BERLIN-EXTEND Results (2026-02-28) — `scripts/e_s_berlin_extend.py`

Bidirectional beam-search extension from BERLINCLOCK (pos 63-73) across all 3 variants.

**[DERIVED FACT] Zero periods consistent**: No period 1-26 is consistent with the 24-position sparse keystream (Vigenère, Beaufort, VarBeaufort). Confirms algebraic proof from E-AUDIT-01.

**[DERIVED FACT] Gronsfeld ELIMINATED (direct application)**: Keystream values at crib positions include 11, 25, 24, 20, 17 etc. — all exceed the Gronsfeld digit range {0–9}. Gronsfeld is structurally impossible under direct (no-transposition) application for all 3 variants.

**[DERIVED FACT] Porta ELIMINATED (direct)**: Known keystream values exceed 12 (the Porta half-alphabet upper bound) under Vigenère convention. E.g. K[22]=L(11), K[23]=Z(25)→ Z>12.

**[INTERNAL RESULT] Beam search "ACTIONATION" FALSE POSITIVE**: PT-quality beam search universally converges to "ACTIONATIONATIONATION…" across all regions (74-96, 0-20, 34-62) and all 3 variants (score ≈ -3.07 to -3.12). Implied key is always gibberish (WEKCLKTQUPVGRMTHABWWPAG etc.). This is a canonical example of the underdetermination problem: English-looking PT at the cost of incoherent key.

**[INTERNAL RESULT] Key-quality beam also false positive**: Best key-quality beam forces keystream to spell "TIONATION…" (score ≈ -3.05 to -3.08) but the implied PT is incoherent. The beam exploits TION/ATION being the highest-frequency English quadgrams.

**[INTERNAL RESULT] No candidate phrase at pos 74 produces coherent key**: All tested phrases (ISATFOUR, MIDNIGHT, WALL, CHECKPOINT, etc.) at position 74 score ≤ -5.05, well within noise (floor ≈ -6.63). Best: Beaufort "WALL"→key="SGOV" (-5.05).

**[INTERNAL RESULT] Global sweep short-string artifacts**: Global sweep finds "WALL"@pos6 Beaufort→key="TORS" (-3.66) and "ATFOUR"@pos11 Vigenère→key="LINARR" (-4.18). These are 4–6 character coincidences producing only 1–3 quadgrams. NOT genuine signals.

**[INTERNAL RESULT] Keystream Jaccard ENE∩BC ≈ 0.33–0.36**: The two keystream sets share 4–5 values out of ~13–14 unique. Consistent with random draws from mod-26 uniform distribution.

**Verdict: E-S-BERLIN-EXTEND = NOISE + TOOL (Gronsfeld/Porta eliminations)**

---

## What Is Eliminated (High Confidence)

- **Gronsfeld** (digit key {0–9}): key values at cribs exceed 9, direct elimination (E-S-BERLIN-EXTEND)
- **Porta** (half-alphabet key {A-M}): key values at cribs exceed 12, direct elimination (E-S-BERLIN-EXTEND)
- All periodic polyalphabetic (any variant, any period, direct correspondence)
- All fractionation families (Bifid, Trifid, ADFGVX, Playfair, Two-Square, Four-Square, etc.)
- Hill cipher (n=2,3,4 algebraic; n>4 impossible since 97 is prime)
- Autokey (all forms) + arbitrary transposition
- Progressive, quadratic, Fibonacci keys + any transposition (Bean-eliminated)
- All structured transposition families + all substitution models → NOISE
- Running key from 7 known reference texts + structured transpositions → 0/17B matches
- K4 IC=0.036 is NOT statistically significant for 97 chars
- Lag-7 autocorrelation, DFT peak at k=9, bimodal fingerprint — all debunked

## What Remains Open

1. **Running key from unknown text** — only structured non-periodic key model surviving Bean constraints
2. **Bespoke physical/procedural cipher** — Sanborn's coding charts ($962.5K auction), untestable without charts
3. **Non-standard structures not yet conceived** — position-dependent alphabets, non-textbook compositions
4. **External information needed** — K5 ciphertext, Smithsonian archives (sealed until 2075), decoded coding charts

## Bean-Compatible Periods

Only periods {8, 13, 16, 19, 20, 23, 24, 26} are Bean-compatible for transposition + periodic substitution (E-FRAC-07). All others are proven impossible.

## Critical Pitfalls (Quick Reference)

- **0-indexed positions everywhere** — cribs at 21–33 and 63–73
- **KA alphabet**: `KRYPTOSABCDEFGHIJLMNQUVWXZ` (all 26 letters, non-standard order)
- **Vigenère sign**: K = (CT - PT) mod 26; Beaufort: K = (CT + PT) mod 26
- **Scoring underdetermination**: periods >= 17 produce false-positive high scores; only period <= 7 is discriminating
- **constants.py is the single source of truth** — never hardcode CT or cribs

## Key Reference Files

- `docs/kryptos_ground_truth.md` — public facts, internal results policy
- `docs/invariants.md` — verified computational invariants
- `docs/elimination_tiers.md` — full elimination tables (Tier 1–4)
- `docs/research_questions.md` — RQ-1 through RQ-13 with priorities
- `reports/final_synthesis.md` — 170+ experiment synthesis
- `anomaly_registry.md` — physical sculpture anomalies

## Agent Conventions

- Import constants from `kryptos.kernel.constants` — never hardcode
- Use `score_candidate()` from `kryptos.kernel.scoring.aggregate` — never hand-roll
- Multi-objective thresholds: crib=24/24 + Bean PASS + quadgram > -4.84/char + IC > 0.055 + non-crib words >= 7 chars >= 3
- Experiment scripts: `scripts/e_<topic>_<nn>_<short_name>.py`
- Always use `python3 -u` for unbuffered output in background tasks
- All commands require `PYTHONPATH=src`
