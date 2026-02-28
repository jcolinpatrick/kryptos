# KryptosBot Operational Runbook

**Target environment:** Ubuntu VM accessed via VS Code Remote-SSH from Windows workstation.
The kryptos project, all 320+ scripts, and KryptosBot all live on the VM.

---

## Table of Contents

1. [VS Code Remote-SSH Setup](#1-vs-code-remote-ssh-setup)
2. [VM Prerequisites](#2-vm-prerequisites)
3. [Installation](#3-installation)
4. [Environment Configuration](#4-environment-configuration)
5. [Pre-Flight Checks](#5-pre-flight-checks)
6. [Phase 1: Local Compute Baseline (Free)](#6-phase-1-local-compute-baseline)
7. [Phase 2: Bootstrap — Import Existing Knowledge](#7-phase-2-bootstrap)
8. [Phase 3: Agent Analysis](#8-phase-3-agent-analysis)
9. [Phase 4: Disproof Sweep](#9-phase-4-disproof-sweep)
10. [Phase 5: Full Campaign (When Warranted)](#10-phase-5-full-campaign)
11. [Monitoring](#11-monitoring)
12. [Multi-Day Operations](#12-multi-day-operations)
13. [Adding Custom Strategies](#13-adding-custom-strategies)
14. [Troubleshooting](#14-troubleshooting)
15. [Quick Reference](#15-quick-reference)

---

## 1. VS Code Remote-SSH Setup

### On your Windows machine

1. Install the **Remote - SSH** extension in VS Code (Microsoft, `ms-vscode-remote.remote-ssh`)

2. Open the Command Palette (`Ctrl+Shift+P`) → **Remote-SSH: Add New SSH Host**

   ```
   ssh your-username@your-vm-ip-or-hostname
   ```

   Select your SSH config file when prompted (usually `C:\Users\Colin\.ssh\config`).

3. If you don't already have one, your `~/.ssh/config` entry should look like:

   ```
   Host kryptosvm
       HostName 192.168.x.x
       User colin
       IdentityFile ~/.ssh/id_rsa
       ForwardAgent yes
   ```

4. Connect: Command Palette → **Remote-SSH: Connect to Host** → select `kryptosvm`

5. VS Code opens a new window connected to the VM. The bottom-left corner shows
   `SSH: kryptosvm` (green) confirming you're remote.

6. **Open your kryptos project folder:** File → Open Folder → navigate to wherever
   your existing kryptos project lives on the VM (e.g., `/home/colin/kryptos/`)

### What runs where

```
┌─────────────────────────┐          ┌──────────────────────────────────┐
│  Windows Workstation     │   SSH    │  Ubuntu VM                       │
│                          │ ◄──────► │                                  │
│  VS Code UI              │          │  VS Code Server (auto-installed) │
│  Keyboard / display      │          │  Python / pip / node             │
│  SSH client              │          │  Agent SDK                       │
│                          │          │  All 28 CPU cores                │
│                          │          │  /home/colin/kryptos/  ← project │
│                          │          │  /home/colin/kryptos/kryptosbot/ │
└─────────────────────────┘          └──────────────────────────────────┘

Everything executes on the VM. Your Windows machine is just the display.
```

### Extensions to install on the remote side

After connecting, VS Code will prompt you to install extensions on the remote host.
Install these **on the SSH remote** (not locally):

- **Python** (Microsoft)
- **Pylance**

VS Code handles this automatically — click "Install in SSH: kryptosvm" when prompted.

---

## 2. VM Prerequisites

Run these in VS Code's integrated terminal (`` Ctrl+` ``), which is already SSH'd to the VM:

```bash
# Python 3.10+
python3 --version

# Node.js 18+ (needed by Agent SDK runtime)
node --version
# If missing:
# curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
# sudo apt-get install -y nodejs

# Core count
nproc

# Git
git --version

# Verify your kryptos project
ls ~/kryptos/CLAUDE.md
ls ~/kryptos/MEMORY.md
find ~/kryptos -maxdepth 1 -name "*.py" | wc -l
```

---

## 3. Installation

In VS Code's integrated terminal:

```bash
# Navigate to your existing kryptos project
cd ~/kryptos

# Extract KryptosBot INTO the project so agents can see everything
tar xzf /path/to/kryptosbot.tar.gz

# Install the Agent SDK in a venv (recommended)
python3 -m venv ~/kryptos/kryptosbot/.venv
source ~/kryptos/kryptosbot/.venv/bin/activate
pip install claude-agent-sdk
```

### Directory layout after extraction

```
~/kryptos/                         ← your existing project root
├── CLAUDE.md
├── MEMORY.md
├── scripts/                       ← your 320+ scripts
├── data/                          ← quadgram files, wordlists, etc.
├── results/                       ← existing results
└── kryptosbot/                    ← newly extracted
    ├── kryptosbot/                ← Python package
    │   ├── __init__.py
    │   ├── config.py
    │   ├── compute.py             ← local multiprocessing engine
    │   ├── database.py
    │   ├── framework_strategies.py
    │   ├── orchestrator.py
    │   └── worker.py
    ├── .vscode/
    │   └── launch.json
    ├── .venv/                     ← Python virtual environment
    ├── run_kryptosbot.py
    ├── run_lean.py                ← lean mode (recommended)
    ├── run_custom_campaign.py
    ├── monitor.py
    ├── RUNBOOK.md
    ├── .env.template
    └── pyproject.toml
```

### Open the kryptosbot folder in VS Code

File → Open Folder → `~/kryptos/kryptosbot/`

This makes the launch configs in `.vscode/launch.json` work. You can also keep
the parent open and run from terminal — either approach works.

---

## 4. Environment Configuration

### 4a. Create `.env` on the VM

```bash
cd ~/kryptos/kryptosbot
cp .env.template .env
nano .env    # or click .env in VS Code Explorer
```

Contents:

```env
ANTHROPIC_API_KEY=sk-ant-api03-your-key-here

# CRITICAL: Point to your existing framework root (the parent directory)
KBOT_PROJECT_ROOT=/home/colin/kryptos
```

### 4b. Select the Python interpreter in VS Code

Command Palette (`Ctrl+Shift+P`) → **Python: Select Interpreter** →
choose `~/kryptos/kryptosbot/.venv/bin/python3`

### 4c. Verify

```bash
source .venv/bin/activate
export $(grep -v '^#' .env | xargs)

echo $KBOT_PROJECT_ROOT
ls $KBOT_PROJECT_ROOT/CLAUDE.md || ls $KBOT_PROJECT_ROOT/.claude/CLAUDE.md
```

---

## 5. Pre-Flight Checks

```bash
cd ~/kryptos/kryptosbot
source .venv/bin/activate
export $(grep -v '^#' .env | xargs)

# 1. List strategies (no API key needed)
python3 run_kryptosbot.py --strategies

# 2. Test local compute engine (no API key needed)
python3 -c "
from kryptosbot.compute import run_statistical_profile
r = run_statistical_profile('/tmp/test_stats.json')
print('IoC:', r['index_of_coincidence'])
print('Entropy:', r['shannon_entropy'])
print('Conclusions:')
for c in r['conclusions']: print(' ', c)
import os; os.remove('/tmp/test_stats.json')
"

# 3. Test Agent SDK auth (uses a few hundred tokens)
python3 -c "
import asyncio
from claude_agent_sdk import query, ClaudeAgentOptions
async def test():
    async for msg in query(prompt='Say OK', options=ClaudeAgentOptions(allowed_tools=[])):
        if hasattr(msg, 'result'):
            print('Agent SDK:', msg.result)
            return
asyncio.run(test())
"
```

All three pass → you're ready.

---

## 6. Phase 1: Local Compute Baseline (Free)

**Your VM's 28 cores doing real work. Zero tokens. Zero cost.**

```bash
python3 run_lean.py --local --workers 28
```

Or via VS Code: Run & Debug (`Ctrl+Shift+D`) → **Lean: Local Compute Only (FREE)**

**What runs:**

| Attack | What it does | Duration |
|--------|-------------|----------|
| `stats` | IoC, entropy, autocorrelation, chi-squared | Seconds |
| `simple` | Exhaustive Caesar (25) and Affine (312) | Seconds |
| `keywords` | Vigenère + Beaufort with Kryptos wordlist × 2 alphabets | Minutes |
| `columnar` | All permutations for column widths 2-12 | Minutes–hours |

**To run a single attack:**

```bash
python3 run_lean.py --local --attack stats
python3 run_lean.py --local --attack simple
python3 run_lean.py --local --attack keywords --workers 28
python3 run_lean.py --local --attack columnar --workers 28 --col-max 15
```

**Results land in `kbot_results/`:**

```bash
# Quick check for crib matches (the holy grail)
python3 -c "
import json
d = json.load(open('kbot_results/master_summary.json'))
print('Total crib matches:', d['total_crib_matches'])
for k, v in d['per_attack'].items():
    print(f'  {k}: {v}')
"

# Read statistical conclusions
python3 -c "
import json
d = json.load(open('kbot_results/statistical_profile.json'))
for c in d['conclusions']: print(c)
"
```

---

## 7. Phase 2: Bootstrap — Import Existing Knowledge

**One agent session reads your framework and imports prior findings into the DB.**

```bash
python3 run_kryptosbot.py --bootstrap --verbose
```

Token cost: ~$0.30-1.00

Verify:

```bash
python3 run_kryptosbot.py --report
```

---

## 8. Phase 3: Agent Analysis

**One agent reads local compute results + framework knowledge, provides analysis.**

```bash
python3 run_lean.py --agent
```

Token cost: ~$0.60-2.50

Results in `kbot_results/agent_analysis_raw.txt`. The agent may also write new
Python scripts for you to run locally (free) in the next iteration.

**The daily cycle:**

```
Local compute ($0) → Agent analysis (~$1-2) → Run new scripts ($0) → Agent → ...
```

---

## 9. Phase 4: Disproof Sweep

```bash
python3 run_kryptosbot.py --disproofs --verbose
```

Use when disproof requires reasoning (statistical inference, pattern analysis)
rather than brute force (which lean mode handles locally).

---

## 10. Phase 5: Full Campaign (When Warranted)

Use sparingly. Start small:

```bash
python3 run_kryptosbot.py --workers 4 --priority 1 --verbose
```

28 agent workers burns tokens fast. 4-8 is the sweet spot for reasoning tasks.

---

## 11. Monitoring

### Live dashboard — open a second terminal in VS Code

Click the **+** icon in the terminal panel (also SSH'd to the VM):

```bash
cd ~/kryptos/kryptosbot
source .venv/bin/activate
python3 monitor.py
```

### tmux — essential for long/overnight runs

```bash
# Start a named session
tmux new -s kbot

# Run your campaign
python3 run_lean.py --local --workers 28

# Split pane for monitoring: Ctrl+B then "
python3 monitor.py

# Detach (keep running after you close VS Code): Ctrl+B then D

# Reconnect later (even from a different VS Code window):
tmux attach -t kbot
```

**tmux is critical.** Without it, closing your VS Code window or losing your
SSH connection kills the running process. With tmux, the process continues on
the VM regardless of your connection state.

### screen alternative

```bash
screen -S kbot
python3 run_lean.py --local --workers 28
# Detach: Ctrl+A then D
# Reconnect: screen -r kbot
```

---

## 12. Multi-Day Operations

### Recommended daily workflow

```bash
# Morning: start local compute in tmux (free)
tmux new -s kbot-compute
cd ~/kryptos/kryptosbot && source .venv/bin/activate
export $(grep -v '^#' .env | xargs)
python3 run_lean.py --local --workers 28
# Detach: Ctrl+B then D

# When compute finishes: agent analysis (~$1-2)
tmux new -s kbot-agent
cd ~/kryptos/kryptosbot && source .venv/bin/activate
export $(grep -v '^#' .env | xargs)
python3 run_lean.py --agent
# Review kbot_results/agent_analysis_raw.txt
# Run any new scripts locally (free)

# Evening: check status
python3 run_kryptosbot.py --report

# Overnight: extended columnar sweep (free, in tmux)
tmux new -s kbot-night
python3 run_lean.py --local --attack columnar --workers 28 --col-max 18
```

### After VM reboot

```bash
cd ~/kryptos/kryptosbot && source .venv/bin/activate
export $(grep -v '^#' .env | xargs)
python3 run_kryptosbot.py --report     # see what completed
python3 run_lean.py --local --workers 28  # continue
```

### Feeding Claude Code session discoveries back

1. Update CLAUDE.md / MEMORY.md in your framework
2. `python3 run_kryptosbot.py --bootstrap` to re-import
3. Continue the cycle

---

## 13. Adding Custom Strategies

See `run_custom_campaign.py` for the template. For local compute extensions,
add functions to `kryptosbot/compute.py` following the existing pattern.

---

## 14. Troubleshooting

### VS Code Remote-SSH won't connect

```powershell
# From Windows PowerShell, test raw SSH:
ssh colin@your-vm-ip

# Common issues:
# - VM not running → start it
# - Firewall blocking port 22 → sudo ufw allow ssh
# - SSH service down → sudo systemctl start sshd
# - Wrong key → check IdentityFile in ssh config
```

### "ModuleNotFoundError: No module named 'claude_agent_sdk'"

```bash
# Make sure you activated the venv
source ~/kryptos/kryptosbot/.venv/bin/activate
pip install claude-agent-sdk
```

### Agent can't find CLAUDE.md

```bash
echo $KBOT_PROJECT_ROOT
ls -la $KBOT_PROJECT_ROOT/CLAUDE.md
ls -la $KBOT_PROJECT_ROOT/.claude/CLAUDE.md
# Fix the path in .env if wrong
```

### Quadgram file not found

```bash
find ~/kryptos -name "*quadgram*" -o -name "*4gram*" 2>/dev/null
ln -s /actual/path/to/quadgrams.txt ~/kryptos/english_quadgrams.txt
```

### Process died when VS Code disconnected

You forgot tmux. Restart the run — the database preserves all completed work:

```bash
python3 run_kryptosbot.py --report    # see what finished
python3 run_lean.py --local --workers 28  # continue
```

### Database locked errors

Too many simultaneous writers. Reduce agent workers or increase timeout:

```bash
# Edit kryptosbot/database.py, change:
#   conn.execute("PRAGMA busy_timeout=10000")
# to:
#   conn.execute("PRAGMA busy_timeout=30000")
```

---

## 15. Quick Reference

### Shell setup (every new terminal)

```bash
cd ~/kryptos/kryptosbot
source .venv/bin/activate
export $(grep -v '^#' .env | xargs)
```

### Commands

```bash
# ── LOCAL COMPUTE (FREE) ──
python3 run_lean.py --local --workers 28               # All attacks
python3 run_lean.py --local --attack stats              # Stats only
python3 run_lean.py --local --attack columnar --col-max 15  # Columnar only

# ── AGENT INTELLIGENCE (TOKENS) ──
python3 run_lean.py --agent                             # Analyze results (~$1-2)
python3 run_kryptosbot.py --bootstrap                   # Import knowledge (~$0.50)
python3 run_kryptosbot.py --disproofs                   # Disproof sweep
python3 run_kryptosbot.py --single <strategy>           # One strategy
python3 run_kryptosbot.py --workers 4                   # Small parallel campaign

# ── STATUS ──
python3 run_kryptosbot.py --report
python3 run_kryptosbot.py --strategies
python3 monitor.py

# ── LONG RUNS (use tmux) ──
tmux new -s kbot
tmux attach -t kbot
```

### Execution order

```
1.  run_lean.py --local --workers 28        Free compute baseline
2.  Review kbot_results/                    Check local results
3.  run_kryptosbot.py --bootstrap           Import framework knowledge (~$0.50)
4.  run_kryptosbot.py --report              Verify import
5.  run_lean.py --agent                     Agent analysis (~$1-2)
6.  Run agent-written scripts locally       Free
7.  run_lean.py --agent                     Feed back results (~$1-2)
8.  Repeat 6-7 daily
9.  run_kryptosbot.py --disproofs           Periodic disproof sweep
```

### Cost guide

| Operation | Dollar cost (Sonnet) |
|-----------|---------------------|
| Any local compute | $0 |
| Bootstrap | $0.30-1.00 |
| Agent analysis | $0.60-2.50 |
| Single strategy | $0.60-2.50 |
| Disproof sweep | $1-5 |
| Full campaign (4 workers) | $6-25 |
| Full campaign (28 workers) | $30-200+ ← avoid |
