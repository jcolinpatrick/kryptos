# Architecture Plan

## Overview

The Kryptos K4 research suite has been refactored from an organic collection of scripts
into a structured, testable, reproducible cryptanalysis platform.

## Structure

```
kryptos/
├── src/kryptos/              # Canonical package (pip install -e .)
│   ├── kernel/               # Zero-dependency core primitives
│   │   ├── constants.py      # SINGLE source of truth (CT, cribs, Bean, alphabets)
│   │   ├── alphabet.py       # Alphabet model, validation, keyword mixing
│   │   ├── text.py           # Text normalization and encoding
│   │   ├── config.py         # Dataclass-based configs (SweepConfig, ExperimentConfig)
│   │   ├── transforms/       # Cipher transform implementations
│   │   │   ├── vigenere.py   # Vigenere/Beaufort/Variant families + additive masks
│   │   │   ├── transposition.py  # Full-text + block transpositions (8 families)
│   │   │   ├── polybius.py   # Bifid/trifid fractionation ciphers
│   │   │   └── compose.py    # Composable pipelines with typed configs
│   │   ├── constraints/      # Ground-truth constraint checking
│   │   │   ├── crib.py       # Crib matching, implied keys, periodicity
│   │   │   ├── bean.py       # Bean equality/inequality (with diagnostics)
│   │   │   └── consistency.py # Alphabet bijection, IC, monoalphabetic checks
│   │   ├── scoring/          # Modular, explainable scoring
│   │   │   ├── ic.py         # Index of Coincidence (transposition-invariant)
│   │   │   ├── ngram.py      # Quadgram log-probability scoring
│   │   │   ├── crib_score.py # Crib alignment with classification thresholds
│   │   │   └── aggregate.py  # ScoreBreakdown: THE canonical scoring path
│   │   └── persistence/      # Data storage
│   │       ├── sqlite.py     # SQLite with schema v2, WAL mode
│   │       └── artifacts.py  # JSONL logs, run manifests
│   ├── pipeline/             # Experiment execution
│   │   ├── evaluation.py     # CANONICAL evaluation: evaluate_candidate(), evaluate_pipeline()
│   │   ├── runners.py        # SweepRunner: parallel, checkpointed, resumable
│   │   └── experiments.py    # Worker functions for block/full transposition sweeps
│   ├── novelty/              # Hypothesis engine (creative but falsifiable)
│   │   ├── hypothesis.py     # Hypothesis dataclass, ResearchQuestion enum, priority
│   │   ├── generators.py     # Running key, date-derived, transform recombination
│   │   ├── triage.py         # Cheap tests before expensive sweeps
│   │   └── ledger.py         # Anti-repeat research memory (SQLite)
│   └── cli/                  # Command-line interface
│       ├── main.py           # `python -m kryptos` entry point
│       ├── doctor.py         # 18-check environment verification
│       └── reproduce.py      # Rerun from manifest
├── k4lab.py                  # Legacy standalone library (still functional)
├── k4_wave2_suite.py         # Legacy CLI runner (still functional)
├── k4suite/                  # Legacy production package (still functional)
├── scripts/                  # Standalone experiment scripts (56 files)
├── tests/                    # pytest suite (99 tests)
├── docs/                     # Documentation
│   ├── invariants.md         # Ground-truth invariants registry
│   ├── research_questions.md # Prioritized unknowns + novelty engine wiring
│   └── ARCHITECTURE_PLAN.md  # This file
├── obsolete/                 # Quarantined legacy files (nothing deleted)
│   └── README.md             # Index of moved files with replacements
├── db/                       # SQLite databases (~1.2 GB)
├── results/                  # Experiment output files
├── reference/                # Reference materials (Carter, Sanborn, etc.)
├── wordlists/                # Dictionaries
├── REPORT.md                 # Phase 0 forensics report
├── RUNBOOK.md                # Canonical commands
├── CLAUDE.md                 # Agent instructions
└── pyproject.toml            # Package config
```

## Key Design Decisions

### 1. Single Source of Truth
`src/kryptos/kernel/constants.py` replaces three independent definitions
(k4lab.py, k4_constants.py, k4suite/core/domain.py). All other modules
import from here.

### 2. Canonical Evaluation Path
`src/kryptos/pipeline/evaluation.py` provides `evaluate_candidate()` as
THE scoring function. Returns `ScoreBreakdown` with full diagnostics.

### 3. Novelty Engine Wired to Research Questions
The novelty engine (`src/kryptos/novelty/`) generates hypotheses tagged
with research questions from `docs/research_questions.md`. Priority is
computed from RQ tier weights and triage scores, balanced by coverage
tracking to avoid under-exploring any question.

### 4. Nothing Deleted
All 65 moved files are preserved in `obsolete/` with a mapping index.

### 5. Legacy Compatibility
`k4lab.py`, `k4_wave2_suite.py`, and `k4suite/` all remain functional.
The new `src/kryptos/` package operates alongside them.

## Data Flow

```
Hypothesis (novelty/generators.py)
  → Triage (novelty/triage.py) — cheap tests
  → Promoted candidates → SweepRunner (pipeline/runners.py)
  → Worker function (pipeline/experiments.py)
  → Transform pipeline (kernel/transforms/compose.py)
  → Constraint checking (kernel/constraints/*)
  → Canonical scoring (pipeline/evaluation.py → scoring/aggregate.py)
  → SQLite persistence (kernel/persistence/sqlite.py)
  → Ledger update (novelty/ledger.py)
```
