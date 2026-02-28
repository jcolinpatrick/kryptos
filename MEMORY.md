# MEMORY.md — Kryptos K4 Project Memory

Persistent knowledge base for agents working on the Kryptos K4 project.
For full project guidance, see [CLAUDE.md](CLAUDE.md).

---

## Project State

- **320+ experiments complete**, 669B+ configurations scored
- **0 genuine signals** — all scores within noise at discriminating periods
- Computational work paused pending Antipodes physical inspection
- Transitioned from custom 6-agent harness (170+ experiments) to official Claude Code agent teams

## What Is Eliminated (High Confidence)

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
