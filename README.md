<p align="center">
  <img src="ops/site_builder/static/internal.png" alt="KryptosBot" width="180">
</p>

<h1 align="center">KryptosBot</h1>

<p align="center">
  <strong>An open-source computational analysis of Kryptos K4</strong><br>
  671 billion+ configurations evaluated across recorded experiments. 1,000+ experiment scripts. Zero verified breakthroughs.
</p>

<p align="center">
  <a href="https://internal.com">internal.com</a> &middot;
  <a href="https://internal.com/workbench/">Workbench</a> &middot;
  <a href="https://internal.com/submit/">Submit a Theory</a> &middot;
  <a href="https://internal.com/browse/">Browse Eliminations</a>
</p>

---

## What is this?

**Kryptos** is an encrypted sculpture at CIA headquarters in Langley, Virginia. Installed in 1990 by artist Jim Sanborn with cryptographic assistance from Ed Scheidt (retired Chairman of the CIA Cryptographic Center), it contains four encrypted messages. The first three (K1–K3) were solved in 1998–1999. **The fourth, K4, remains unsolved after over 35 years.**

This repository is a systematic attempt to solve K4. At a minimum, it rigorously documents what doesn't work within clearly stated assumptions. **No K4 solution is claimed by this project; no real-K4 progress is currently claimed; K4 is not proven impossible. Public-data-only K4 is judged underdetermined from the current public evidence pool — see [`docs/REAL_K4_CURRENT_POSITION.md`](docs/REAL_K4_CURRENT_POSITION.md) for the authoritative status report.**

### K4 at a glance

| | |
|---|---|
| **Ciphertext** | `OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR` |
| **Length** | 97 characters (prime), all 26 letters present |
| **Known plaintext** | Positions 21-33: `EASTNORTHEAST`, Positions 63-73: `BERLINCLOCK` |
| **IC** | 0.0361 (below random expectation of 0.0385) |

## What's here

```
src/kryptos/          # Core library: cipher transforms, scoring, constraints
  kernel/             #   Pure computation: alphabets, transforms, Bean constraints
    scoring/          #     Crib scoring, n-gram analysis, IC
  pipeline/           #   Candidate evaluation and parallel sweep runner
  novelty/            #   Hypothesis generation and triage
  corpus/             #   Egyptological corpus for running-key testing
  cli/                #   Command-line tools (sweep, reproduce, novelty, report)

scripts/              # 1,000+ experiment scripts organized by cipher family
  substitution/       #   Vigenere, Beaufort, Hill, monoalphabetic, etc.
  transposition/      #   Columnar, rail fence, route, grid-based
  fractionation/      #   Bifid, Trifid, ADFGVX, Playfair
  grille/             #   Cardan grille, turning grille, tableau overlays
  polyalphabetic/     #   Kasiski analysis, period detection
  running_key/        #   Book ciphers, thematic running keys
  encoding/           #   Morse (K0), misspelling analysis, binary tests
  campaigns/          #   Structured multi-stage campaigns (preregistered)
  ...and more

tests/                # 1,500+ unit, QA, and benchmark tests
bench/                # Cipher-solving benchmark framework
ops/site_builder/     # Static site generator for internal.com
ops/api/              # FastAPI backend (theory classifier, submission queue)
ops/publish/          # Publishing workflow (filtered push to GitHub)
```

## Quick start

**Python 3.11+** required. The repo uses a small Python dependency stack for testing, scientific computing, web/API serving, and agent tooling; see [requirements.txt](requirements.txt).

```bash
# Clone
git clone https://github.com/jcolinpatrick/kryptos.git
cd kryptos

# Run tests
PYTHONPATH=src pytest tests/

# Run an experiment
PYTHONPATH=src python3 -u scripts/substitution/e_atbash_01_keyword_decrypt.py

# Try the workbench cipher solver
PYTHONPATH=src python3 -m kryptos sweep <config.toml>

# Check environment health
PYTHONPATH=src python3 -m kryptos doctor
```

## Scoring system

Every candidate decryption is scored against known constraints:

| Score | Classification | Meaning |
|-------|---------------|---------|
| 0-9   | Noise         | Expected random performance |
| 10-17 | Interesting   | Worth logging, likely noise |
| 18-23 | Signal        | Unusual within tested scope; requires follow-up and validation |
| 24    | Breakthrough  | All cribs match; potential solution |

The score is based on crib consistency (do the known plaintext positions produce a valid keystream?), Bean constraints (equality/inequality relationships between key positions), index of coincidence, and n-gram quality.

**After 671 billion+ configurations: no verified solution has emerged within the tested families and parameter ranges.** Many standard bounded classical families have been saturated under direct positional correspondence, but that does not rule out multi-layer, procedural, or differently aligned constructions.

## What's been eliminated

The [internal.com](https://internal.com/browse/) site currently documents 494 formal eliminations across 7 categories:

- **Substitution.** Vigenere, Beaufort, Quagmire, Hill, Caesar, mixed alphabets.
- **Transposition.** Columnar, double-columnar, AMSCO, Myszkowski, rail fence, route, grille.
- **Fractionation.** Bifid, Trifid, ADFGVX, Playfair, four-square (structurally eliminated under direct correspondence).
- **Multi-layer.** Substitution + transposition combinations, null extraction, three-layer cascades.
- **Key models.** Running keys, autokey (structurally eliminated), progressive, Fibonacci, date-derived.
- **Bespoke.** RS44, VIC, Wheatstone, Weltzeituhr, DRYAD charts, NATO/COMSEC.
- **Uncategorized.** Morse-derived, encoding schemes, sculpture-physical hypotheses.

**Important caveat:** These eliminations are always scoped to the assumptions actually tested. Single-layer eliminations do not rule out the same cipher family as one layer of a multi-layer construction.

## Working hypotheses

None of these are proven. They represent live hypothesis surfaces or residual coverage gaps. Status as of April 2026.

1. **Two systems.** Sanborn has publicly stated K4 uses "two systems of enciphering," distinct from the Vigenere used for K1-K3. The project treats this as **Tier-3 contextual hearsay** (per claims-registry entries `C-SANBORN-01` and `C-SANBORN-02`), not as a load-bearing piece of operational evidence. The phrase admits multiple mutually-incompatible structural interpretations and has so far not produced a non-arbitrary cipher mechanism. Any specific mechanistic interpretation remains a hypothesis that must be paired with independent measurable evidence before it gains evidentiary weight. See the [pseudo-clue-pack admission standard](docs/REAL_K4_PSEUDO_CLUE_PACK_ADMISSION.md) rule 11.
2. **CT perturbation.** The currently primary anomaly surface. Evidence from photographed coding charts in Sanborn's archive at the Smithsonian suggests the canonical 97-character ciphertext may include a small number of transcription errors. If real, modest CT corrections could unlock cipher families that currently fail by a small margin. Open and actively explored.
3. **W-delimiter structural hypothesis.** The five carved `W`s at positions 20, 36, 48, 58, and 74 explain the old width-21 vertical-bigram anomaly. As a *single-layer* construction the W-segmentation hypothesis has been saturated (80+ tested, no signal); it remains admissible as one layer within multi-layer constructions. Whether the `W`s are delimiters, nulls, row markers, or something else remains open.
4. **Null insertion or procedural markers.** Some positions in K4 may be filler or marker symbols. The number, placement, and interpretation remain unknown. The older statistical "null palette" family is retired and should not be treated as evidence.
5. **Residual running-key and non-periodic additive models.** Within additive-key assumptions and direct correspondence, running-key style models remain an open residual family. That is a scoped statement, not a global claim about all possible K4 constructions.

See [docs/research_questions.md](docs/research_questions.md) for the full list of open questions.

## Contributing

The whole point of open-sourcing this is to get more eyes on K4.

**Try a theory:** Use the [browser workbench](https://internal.com/workbench/), no install needed. Apply transpositions and substitutions, see crib scores in real time.

**Submit a theory:** Use [internal.com/submit](https://internal.com/submit/) to check if your idea has already been tested. Novel feasible theories are queued for evaluation.

**Write an experiment:** See any script in `scripts/` for the pattern. Import constants from `kryptos.kernel.constants`, implement an `attack()` function, check results against the scoring system.

**Report an error:** If you think an elimination is wrong, [open an issue](https://github.com/jcolinpatrick/kryptos/issues/new).

## Project research-state documents

- [Real-K4 current position](docs/REAL_K4_CURRENT_POSITION.md): authoritative status report — what KryptosBot can and cannot do, why public-data-only K4 is judged underdetermined, and the explicit non-claim statement.
- [Evidence gap register](docs/REAL_K4_EVIDENCE_GAP_REGISTER.md): ten open evidence gaps (GAP-01…GAP-10) with admission-grade closure conditions.
- [Evidence acquisition plan](docs/REAL_K4_EVIDENCE_ACQUISITION_PLAN.md): recommended first action and priority order across the high-priority gaps.
- [Pseudo-clue-pack admission standard](docs/REAL_K4_PSEUDO_CLUE_PACK_ADMISSION.md): eleven-rule admission gate including the Sanborn public-comment doctrine.

## Key external references

- [Bean 2021](https://ecp.ep.liu.se/index.php/histocrypt/article/view/153): "Cryptodiagnosis of Kryptos K4," HistoCrypt 2021.
- [Elonka Dunin's Kryptos page](https://elonka.com/kryptos/): community hub and transcription.
- [Ed Scheidt dossier](reference/ed_scheidt_dossier.md): what the co-creator has revealed.
- [Sanborn's open letter (Aug 2025)](reference/sanborn_open_letter_aug2025.md): AI verification, K5 confirmed.

## Credits

Built by **Colin Patrick** (human lead) and **Claude** (computational partner, Anthropic).

The sculpture *Kryptos* was created by **Jim Sanborn** with cryptographic assistance from **Ed Scheidt** (retired Chairman of the CIA Cryptographic Center).

---

