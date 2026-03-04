# KryptosBot Operational Runbook

**Target environment:** Ubuntu VM accessed via VS Code Remote-SSH.
Project root: `/home/cpatrick/kryptos/`. Python venv at `~/kryptos/venv/`.

**Paradigm (2026-03-04):** The 97 carved K4 characters are SCRAMBLED ciphertext.
`PT → simple substitution → REAL CT → SCRAMBLE → carved text`.
**Primary focus: Construct the Cardan grille from the Kryptos tableau's structural elements.**
The Kryptos tableau (28×31 with key column) overlays the cipher grid (28×31).
Three Kryptos-only elements (absent from Antipodes) are the grille construction clues:
key column (AZ order), header/footer rows (standard alphabet), extra L on row N.
The scrambling layer's exact relationship to the grille is UNKNOWN.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Environment Setup](#2-environment-setup)
3. [Pre-Flight Checks](#3-pre-flight-checks)
4. [Using solve.py](#4-using-solvepy)
5. [Monitoring](#5-monitoring)
6. [Long-Running Operations](#6-long-running-operations)
7. [Troubleshooting](#7-troubleshooting)
8. [Quick Reference](#8-quick-reference)

---

## 1. Architecture Overview

```
~/kryptos/                              ← project root
├── CLAUDE.md                           ← master instructions
├── src/kryptos/                        ← core crypto kernel (stdlib only)
├── scripts/                            ← 430+ experiment scripts
│   └── kbot_harness.py                 ← pre-built test harness for agents
├── data/english_quadgrams.json         ← scoring data
├── venv/                               ← Python venv (numpy, jinja2, SDK)
├── results/                            ← unified output (gitignored)
│   ├── campaigns/YYYYMMDD_HHMMSS/      ← per-campaign agent output
│   └── compute/YYYYMMDD_HHMMSS/        ← per-compute-run output
└── kryptosbot/                         ← campaign runner directory
    ├── solve.py                        ← THE entry point (all commands)
    ├── monitor.py                      ← live dashboard
    ├── RUNBOOK.md                      ← this file
    └── kryptosbot/                     ← Python package (library modules)
        ├── agent_runner.py             ← shared agent session loop
        ├── sdk_wrapper.py              ← SDK safety wrapper
        ├── config.py                   ← K4 constants, HypothesisStatus, KryptosBotConfig
        ├── database.py                 ← SQLite persistence
        ├── compute.py                  ← local multiprocessing engine
        └── strategies.py               ← unified strategy registry (22 strategies)
```

### Library modules

| Module | Purpose |
|--------|---------|
| `strategies.py` | Unified strategy registry: 22 strategies across 3 modes (agent/reasoning/compute). Strategy definitions, prompts, `build_prompt()`, `get_strategies()`. |
| `agent_runner.py` | Shared agent session loop. Unified message handling, verdict extraction, `AgentResult` dataclass, `TokenTracker` for budget monitoring, `crib_event` for cross-agent early termination. |
| `sdk_wrapper.py` | Wraps `claude_agent_sdk.query()` to suppress the known anyio cleanup bug. Classifies errors (rate limit, auth, quota) into actionable messages. Provides `safe_query()` and `preflight_check()`. |
| `config.py` | K4 ciphertext, known cribs, `HypothesisStatus` enum, `KryptosBotConfig` runtime settings. |
| `database.py` | SQLite persistence: hypotheses, evidence, disproof_log, sessions, campaigns. WAL mode. |
| `compute.py` | Local multiprocessing engine: columnar permutations, keyword sweeps, key derivation, quadgram scoring. |

### Pre-deployed test harness

`scripts/kbot_harness.py` provides validated functions that agents can import:

```python
import sys; sys.path.insert(0, 'scripts')
from kbot_harness import test_perm, score_text, K4_CARVED, KEYWORDS
```

---

## 2. Environment Setup

```bash
cd ~/kryptos
source venv/bin/activate

# ANTHROPIC_API_KEY must be set for agent modes
# Either export directly or put in kryptosbot/.env:
echo "ANTHROPIC_API_KEY=sk-ant-api03-your-key" > kryptosbot/.env
```

All commands below assume the venv is activated and you're in `~/kryptos/`.

---

## 3. Pre-Flight Checks

```bash
# 1. Verify core framework (no API key needed)
PYTHONPATH=src python3 -m kryptos doctor

# 2. Verify agent_runner imports
python3 -c "from kryptosbot.kryptosbot.strategies import STRATEGIES; print(f'{len(STRATEGIES)} strategies OK')"

# 3. Test Agent SDK (uses a few hundred tokens)
PYTHONPATH=src python3 kryptosbot/solve.py preflight

# 4. List all strategies
PYTHONPATH=src python3 kryptosbot/solve.py list

# 5. Run existing tests
PYTHONPATH=src pytest tests/ -q
```

---

## 4. Using solve.py

### One entry point, all commands

```bash
# Default: blitz campaign (6 parallel unscramble agents)
python3 kryptosbot/solve.py

# Local compute only (free, no API tokens)
python3 kryptosbot/solve.py compute

# Run specific strategies by name
python3 kryptosbot/solve.py run grille_geometry constraint_solver wildcard

# Reasoning-only agents (bespoke thinking, no code execution)
python3 kryptosbot/solve.py reason

# Single agent, quick test
python3 kryptosbot/solve.py run wildcard --max-turns 5

# Full options
python3 kryptosbot/solve.py --agents 6 --max-turns 25 --budget 50.0

# Utility commands
python3 kryptosbot/solve.py list          # Show all strategies
python3 kryptosbot/solve.py preflight     # SDK/auth health check
python3 kryptosbot/solve.py report        # Show results summary
```

All commands should be prefixed with `PYTHONPATH=src` when run from `~/kryptos/`.

### Strategy modes

| Mode | Cost | What happens |
|------|------|-------------|
| **AGENT** | ~$1-60 | Claude agent with tools (Read, Write, Edit, Bash, Glob, Grep). Writes & runs code. |
| **REASONING** | ~$1-5 | Claude agent without tools. Pure analytical thinking. |
| **COMPUTE** | $0 | Local CPU only. No API tokens. Uses multiprocessing. |

### Cost guide

| Command | Approx. cost |
|---------|-------------|
| `solve.py compute` | $0 |
| `solve.py run wildcard --max-turns 5` | ~$0.50 |
| `solve.py run grille_geometry` | ~$2-5 |
| `solve.py reason` | ~$5-15 |
| `solve.py` (default, 6 agents) | ~$15-60 |
| `solve.py --budget 15` | ≤$15 |

---

## 5. Monitoring

### Live dashboard

Open a second terminal:

```bash
cd ~/kryptos
source venv/bin/activate
python3 kryptosbot/monitor.py --interval 3
python3 kryptosbot/monitor.py --db results/results.db  # explicit DB path
```

### Results summary

```bash
PYTHONPATH=src python3 kryptosbot/solve.py report
```

---

## 6. Long-Running Operations

### tmux (essential for overnight runs)

```bash
# Start a named session
tmux new -s kbot

# Run your campaign
PYTHONPATH=src python3 -u kryptosbot/solve.py --budget 30

# Split pane for monitoring: Ctrl+B then "

# Detach (keeps running after you close VS Code): Ctrl+B then D

# Reconnect later:
tmux attach -t kbot
```

### Recommended workflow

```
1. solve.py compute                  Free baseline (minutes)
2. solve.py report                   Check results
3. solve.py run wildcard --max-turns 5   Quick test (~$0.50)
4. solve.py --budget 15              Full parallel attack
5. Repeat
```

---

## 7. Troubleshooting

### "ModuleNotFoundError: No module named 'claude_agent_sdk'"

```bash
source ~/kryptos/venv/bin/activate
pip install claude-agent-sdk
```

### "ModuleNotFoundError: No module named 'kryptosbot'"

Run from `~/kryptos/`, not from `~/kryptos/kryptosbot/`:
```bash
cd ~/kryptos
PYTHONPATH=src python3 kryptosbot/solve.py preflight
```

### Token budget exceeded

Use `--budget` to cap spending:
```bash
PYTHONPATH=src python3 kryptosbot/solve.py --budget 10.00
```

### Process died when VS Code disconnected

Use tmux (see section 6). Results already written are preserved.

---

## 8. Quick Reference

### Shell setup (every new terminal)

```bash
cd ~/kryptos
source venv/bin/activate
```

### Commands at a glance

```bash
# ── FREE (local compute) ────────────────────────────────────
PYTHONPATH=src python3 kryptosbot/solve.py compute

# ── CHEAP ($0.50-5) ─────────────────────────────────────────
PYTHONPATH=src python3 kryptosbot/solve.py run wildcard --max-turns 5

# ── MODERATE ($5-15) ─────────────────────────────────────────
PYTHONPATH=src python3 kryptosbot/solve.py reason

# ── EXPENSIVE ($15-60) ──────────────────────────────────────
PYTHONPATH=src python3 kryptosbot/solve.py --budget 30

# ── STATUS (free) ───────────────────────────────────────────
PYTHONPATH=src python3 kryptosbot/solve.py list
PYTHONPATH=src python3 kryptosbot/solve.py preflight
PYTHONPATH=src python3 kryptosbot/solve.py report
python3 kryptosbot/monitor.py
```

---

*Last updated: 2026-03-03 — consolidated to solve.py, unified strategy registry*
