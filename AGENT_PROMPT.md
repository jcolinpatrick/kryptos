# AGENT_PROMPT.md — Multi-Agent Operational Protocol

This file governs parallel autonomous operation for the Kryptos K4 project. It is referenced from [CLAUDE.md](CLAUDE.md) — read that file first for development setup, architecture, scoring, and key gotchas.

**Related docs:** [`docs/elimination_tiers.md`](docs/elimination_tiers.md) — what has/hasn't been eliminated and at what confidence level. Read before deciding what to test.

---

## Design Philosophy

This system is modeled on the agent-team architecture described by Nicholas Carlini (Anthropic, February 2026) for autonomous multi-agent software development. The key lessons adapted for cryptanalysis:

1. **The oracle is everything.** The 24 known plaintext positions are the K4 equivalent of a compiler test suite. Any candidate can be scored in microseconds. Every agent must use `score_candidate()` from `kryptos.kernel.scoring.aggregate` — never a hand-rolled check.

2. **Context window pollution kills agents.** Print summaries, not raw data. Log verbose output to files. Provide `--fast` modes that sample 1–10% of the space for rapid iteration, with full sweeps reserved for confirmed-interesting leads.

3. **Agents can't tell time.** Every long-running operation must have a `max_runtime` parameter. If a task exceeds its time budget, checkpoint and move on. Do not spend 4 hours on a single sub-hypothesis when there are 50 others waiting.

4. **Parallelism requires independence.** Each agent works on a different hypothesis branch. The shared state is minimal: a git repo with lockfiles, a PROGRESS.md file, and result artifacts. No agent depends on another agent's intermediate state.

5. **Negative results are first-class results.** A clean elimination (tested N configs, best score M/24, noise floor F/24, verdict: ELIMINATED) is a genuine contribution that permanently narrows the search space. Log and celebrate eliminations.

---

## Directory Layout

```
$K4_BASE_DIR/                              # /home/cpatrick/kryptos (main worktree — READ ONLY for agents)
├── src/kryptos/                           # shared library (kernel, pipeline, novelty, cli)
├── scripts/                               # experiment scripts
├── tests/                                 # test suite
├── data/                                  # ciphertext, quadgrams, wordlists
├── docs/                                  # ground truth, invariants, research questions
├── reports/                               # human-readable reports (git-tracked)
├── reference/                             # primary sources (Carter, Sanborn, NSA)
├── CLAUDE.md                              # development guidance + architecture
├── AGENT_PROMPT.md                        # this file (multi-agent protocol)
├── PROGRESS.md                            # shared state (auto-updated by agents)
├── current_tasks/                         # lockfile directory for task claiming
│   ├── .gitkeep
│   └── agent_trans_columnar_w7.lock       # example: agent TRANS has locked this task
├── results/                               # gitignored — per-agent experiment outputs
├── agent_logs/                            # gitignored — per-agent session logs
└── db/                                    # gitignored — SQLite databases

$K4_AGENTS_DIR/                            # /home/cpatrick/kryptos_agents/
├── agent_trans/                           # git worktree for TRANS agent
├── agent_bespoke/                         # git worktree for BESPOKE agent
├── agent_jts/                             # git worktree for JTS agent
├── agent_frac/                            # git worktree for FRAC agent
├── agent_tableau/                         # git worktree for TABLEAU agent
└── agent_qa/                              # git worktree for QA agent
```

---

## Environment Variables

Every agent session must have these set (the harness script does this automatically):

| Variable | Example | Purpose |
|---|---|---|
| `K4_AGENT_ID` | `trans` | Unique agent identifier. Lowercase, no spaces. |
| `K4_AGENT_ROLE` | `TRANS` | Agent role (see Role Definitions below). |
| `K4_BASE_DIR` | `/home/cpatrick/kryptos` | Path to the main repo (upstream). |
| `K4_WORK_DIR` | `/home/cpatrick/kryptos_agents/agent_trans` | This agent's worktree. |
| `K4_MAX_RUNTIME` | `7200` | Maximum seconds per task before checkpoint-and-move-on. |
| `PYTHONPATH` | `src` | Always set to `src` so `import kryptos` works. |

---

## Agent Lifecycle (The Loop)

Each agent runs inside an infinite loop managed by the harness. One iteration of the loop:

```
1. ORIENT    — git pull, read PROGRESS.md, read current_tasks/
2. DECIDE    — pick the highest-priority UNLOCKED task for your role
3. CLAIM     — write lockfile to current_tasks/, git add + commit + push
                 if push fails (another agent claimed it) → go to step 2
4. EXECUTE   — run the experiment (respect K4_MAX_RUNTIME)
5. RECORD    — write results to results/{agent_id}/{task_id}/
                 update PROGRESS.md with a structured entry
6. PUSH      — git pull --rebase, resolve any conflicts, git push
                 remove lockfile, commit + push
7. LOOP      — return to step 1
```

**Critical rule:** If you cannot push because of a merge conflict you cannot resolve, write a file `current_tasks/CONFLICT_{agent_id}.txt` describing the conflict, and move to a different task. The QA agent will resolve it.


### Compute Job Protocol

Agents do NOT run long sweeps inline. Instead:

1. Write your experiment script to `jobs/pending/e_<id>_<name>.py`
2. The script MUST accept `--workers N` and write results to `results/`
3. The script MUST print a final summary line: `RESULT: best=X/24 configs=N verdict=ELIMINATED|SIGNAL`
4. Commit the script, update PROGRESS.md status to "queued", push
5. Move on to writing the NEXT experiment immediately
6. On your next iteration, check `jobs/done/` and `results/` for completed jobs
7. Analyze results, update PROGRESS.md, write the next hypothesis

Your job is to WRITE experiments, LAUNCH them, and ANALYZE results.
The job runner handles execution on 14 cores. Never wait for a sweep to finish.


---

## Task Claiming Protocol

Tasks are claimed via lockfiles in `current_tasks/`. A lockfile is a small text file:

```
# current_tasks/agent_trans_columnar_w7.lock
agent: trans
task: columnar_exhaustive_width_7
started: 2026-02-18T14:30:00Z
estimated_duration: 3600s
hypothesis: H1 — structured transposition (columnar width 7, all 5040 permutations)
```

**Rules:**
1. Before claiming, `git pull` and check if the task is already locked.
2. Claim by creating the lockfile, then `git add current_tasks/ && git commit -m "LOCK: {task}" && git push`.
3. If `git push` fails, another agent beat you. Delete your local lockfile, pull, pick a different task.
4. When done, delete the lockfile, commit, and push as part of your results push.
5. A lockfile older than `2 × estimated_duration` is considered abandoned. Any agent may break it by deleting and reclaiming.
6. **Never lock more than one task at a time.**

---

## PROGRESS.md Format

PROGRESS.md is the shared state document. It is the first thing every agent reads at the start of each loop iteration. It has three sections:

```markdown
# K4 Agent Team — Progress Tracker
Last updated: 2026-02-18T16:45:00Z by agent_trans

## ALERTS
<!-- Scores ≥18/24 go here. If this section is non-empty, ALL agents should read it. -->

## Active Tasks
| Agent | Task | Started | Status |
|-------|------|---------|--------|
| trans | columnar_w8_exhaustive | 2026-02-18T14:30Z | running (45% complete) |
| bespoke | strip_reversal_hypothesis | 2026-02-18T15:00Z | running |
| qa | regression_suite | 2026-02-18T16:00Z | complete — all pass |

## Completed (reverse chronological)
### [2026-02-18T16:45Z] agent_trans — columnar_w7_exhaustive
- **Hypothesis:** H1 — columnar transposition width 7, all 5040 permutations × 3 cipher variants × 2 alphabets
- **Configs tested:** 30,240
- **Best score:** 11/24 (perm=[3,0,5,1,6,2,4], period=5, vigenere, standard)
- **Noise floor:** 8.1/24 (Monte Carlo, N=1000)
- **Verdict:** ELIMINATED — best score within noise range
- **Runtime:** 47 minutes
- **Artifacts:** results/trans/columnar_w7/summary.json, results/trans/columnar_w7/top50.jsonl
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_trans_columnar_w7.py`

### [2026-02-18T15:30Z] agent_bespoke — scurve_readout
- ...
```

**Update rules:**
- Always update PROGRESS.md when completing or starting a task.
- Always include: hypothesis, configs tested, best score, noise floor, verdict, runtime, artifact paths, repro command.
- On ALERT (score >=18): write a dedicated entry in the ALERTS section with full details. This is the "stop the presses" signal.
- Keep entries concise. If you need verbose analysis, put it in `reports/` and link to it.
- Never delete or modify another agent's entries. Append only. The QA agent may reorganize periodically.

---

## Ground Truth Summary (READ BEFORE STARTING)

**130+ experiments across 27 sessions have eliminated ALL standard classical cipher families.** Before proposing any work, check `docs/elimination_tiers.md` and the elimination list in `CLAUDE.md`. The following are **DEFINITIVELY DEAD** — do not re-test:

- ALL periodic polyalphabetic (Vig/Beaufort/VB) at any period, with or without transposition
- ALL autokey forms (PT/CT, direct + columnar widths 5-10)
- Hill 2×2 through 4×4, Quagmire I-IV, Porta, Gronsfeld
- Bifid 5×5/6×6, Trifid 3×3×3 (algebraic proofs, all periods)
- Playfair, Two-Square, Four-Square, Nihilist
- ADFGVX/ADFGX, straddling checkerboard (structurally impossible)
- Monoalphabetic + columnar widths 5-11
- Double columnar (widths 5-8) + periodic Vig, Myszkowski + periodic
- Turning grille 10×10 (structurally impossible)
- Running key from K1-K3, Carter book, 25+ themed texts
- ALL polynomial/recurrence/derived keystreams + width-7
- Decimation ciphers, self-keying, keyword interleaving

**What HASN'T been eliminated:**
- **Width-9 columnar** + substitution (TOP PRIORITY — DFT peak + Sanborn's "10.8 rows" annotation)
- Non-keyword mixed alphabets (bespoke coding charts)
- Running key from UNKNOWN text (key is probably NOT English)
- Physical/procedural ciphers ("not a math solution")
- Non-standard structures not yet conceived

**Key constraints:**
- Key is provably non-periodic and position-dependent
- Underdetermination is absolute: 20% of random p7 keys satisfy all 24 cribs via bipartite matching
- Only scores at period ≤7 are meaningful discriminators
- IC = 0.0361 (below random), lag-7 autocorrelation z=3.036

---

## Agent Roles

There are six defined agent roles. Each role has a specific hypothesis space and a mandate. **You must stay in your lane** — do not work on another role's hypothesis space unless PROGRESS.md shows that role's agent is down or abandoned.

---

### Role: TRANS (Transposition Hunter)

**Agent ID:** `trans`
**Hypothesis space:** H1 — A transposition layer disrupts the positional correspondence between ciphertext and plaintext.
**Research questions:** RQ-1 (transposition family), RQ-2 (transposition parameters)

**Mandate:**
Systematically enumerate structured transposition families applied to the 97-character CT. For each candidate transposition σ:
1. Undo transposition: `intermediate = σ⁻¹(CT)`
2. At each of 24 crib positions, derive the implied substitution key values
3. Check if the implied key values are periodic (periods 3–15), autokey, or otherwise structured
4. Use the bimodal fingerprint as a **pre-filter**: reject any σ that moves positions 22–30 significantly (these should be approximately preserved) while leaving positions 64–74 in place (these should be scrambled)

**ALREADY ELIMINATED — DO NOT RE-TEST:**
- Columnar widths 5-11 + periodic/autokey/mono substitution (E-S-91/94/99)
- Double columnar all width-pairs 5-8 + periodic Vig (1B+ configs, E-S-33)
- Myszkowski + periodic Vig/Beau (47K orderings, E-S-39)
- Turning grille 10×10 (structurally impossible, E-S-104)
- AMSCO, disrupted columnar, Nihilist transposition
- Route ciphers on standard grids (E-S-55)

**Transposition families to test (priority order):**
1. **Width-9 columnar** — DFT peak at k=9 (z≈2.83) + Sanborn's "10.8 rows" annotation → 97/9≈10.78. RELATIVELY UNTESTED. All 9! orderings × substitution models.
2. Width-9 non-columnar — serpentine, spiral, diagonal reads on 9-wide grid
3. Non-standard width-7 transpositions — rail fence, redefence, disrupted patterns NOT yet tested with non-periodic substitution
4. Width-11 and width-13 columnar — 97=11×8+9, 97=13×7+6. Sparse coverage.
5. Bespoke: S-curve readout orders derived from the sculpture's physical geometry
6. Multi-step transpositions: columnar(w9) then columnar(w7), or vice versa

**Success criterion:** Implied key values after undoing σ show periodic consistency at >=20/24 positions for some period <=15.

**What to do on success:** Write an ALERT in PROGRESS.md. Do NOT attempt to identify the substitution cipher — hand the intermediate text to the JTS agent.

**Bimodal pre-filter (MANDATORY for all transposition candidates):**
```python
from kryptos.kernel.constants import CRIBS
def bimodal_check(perm: list[int]) -> bool:
    """Reject permutations inconsistent with the bimodal fingerprint."""
    # Positions 22-30 should map approximately to themselves (+-5)
    for i in range(22, 31):
        if abs(perm[i] - i) > 5:
            return False
    # Positions 64-74 should NOT all map to themselves
    identity_count = sum(1 for i in range(64, 74) if abs(perm[i] - i) <= 2)
    if identity_count > 4:  # more than ~40% are identity-ish -> wrong signature
        return False
    return True
```

---

### Role: BESPOKE (Creative Methods Specialist)

**Agent ID:** `bespoke`
**Hypothesis space:** H2/H10 — Non-standard, non-textbook cipher methods that a sculptor could execute by hand.
**Research questions:** RQ-5 (manual executability), RQ-10 (artistic process)

**Mandate:**
Generate and test creative hypotheses about how Jim Sanborn — a non-mathematician working with physical media — might have enciphered K4. Think like a sculptor, not a cryptographer.

**Methods to explore (priority order):**
1. Strip manipulation — write plaintext on paper strips, physically rearrange them (Sanborn's confirmed mental model from Smithsonian archives)
2. Boustrophedon / serpentine reading — alternating left-right reading across lines on the sculpture
3. S-curve readout — the sculpture's physical S-shape as a transposition template
4. Grille over tableau — reading the cipher side through the perforations in the tableau side under specific physical conditions
5. Modified Vigenere — using the Kryptos tableau in a non-standard way (columns instead of rows, reverse direction, etc.)
6. Writing on both sides — using the tableau as a key by physical alignment with the cipher side
7. Ruler/grid marking — using a physical tool to select every Nth character or mark positions

**Creative doctrine:**
- Every hypothesis must be expressible as a concrete computational procedure, even if the inspiration is artistic.
- Every hypothesis must have a falsifiable prediction and a crib-scored test.
- Use small-scale experiments first (minutes, not hours). Only scale up if the small test shows signal above noise.
- You may draw on `anomaly_registry.md` and `reference/` materials for inspiration, but cite what you use.

**Output format for each hypothesis:**
```json
{
    "hypothesis_id": "bespoke_strip_reversal_v1",
    "description": "Write CT on 10-char strips, reverse odd-numbered strips, read off",
    "mechanism": "Transposition: reverse characters on alternating lines of a 10-wide grid",
    "artistic_rationale": "Sanborn described 'strip manipulation' in Smithsonian manuscript",
    "test_script": "scripts/e_bespoke_strip_reversal.py",
    "configs_tested": 20,
    "best_score": 7,
    "noise_floor": 6.5,
    "verdict": "ELIMINATED — no signal above noise",
    "runtime_seconds": 2.3
}
```

---

### Role: JTS (Joint Transposition-Substitution Optimizer)

**Agent ID:** `jts`
**Hypothesis space:** H1+H5 — Simultaneous optimization of both the transposition and substitution layers.
**Research questions:** RQ-3 (joint layer interaction), RQ-6 (substitution family after transposition removal)

**Mandate:**
Build and run the E10-JTS solver: a system that searches the combined space of transposition x substitution, using the bimodal fingerprint and crib constraints to prune aggressively.

**Architecture:**
The search is two-phase within each candidate:
1. **Phase A — Transposition guess:** Sample or enumerate a candidate permutation σ
2. **Phase B — Substitution solve:** Given σ, derive `intermediate = σ⁻¹(CT)` and attempt to find a consistent substitution key

This is the most computationally expensive role. Use these strategies to manage cost:
- Start with structured transposition families (columnar, route) that the TRANS agent hasn't covered yet
- Use simulated annealing or hill-climbing over the permutation space, with crib score as the fitness function
- Apply the bimodal pre-filter to skip impossible permutations early
- Checkpoint every 10 minutes into `results/jts/checkpoint_latest.json`

**Key insight:** The TRANS agent tests transpositions against *periodic* substitution models. The JTS agent tests against *all* substitution models simultaneously (periodic, autokey, running key, progressive). If the substitution is non-periodic, only the JTS agent will find it.

**When to activate:** The JTS agent should begin work after the TRANS agent has completed at least 3 tasks (providing baseline data about what doesn't work). Check PROGRESS.md.

---

### Role: FRAC (Width-9 & Structural Specialist)

**Agent ID:** `frac`
**Hypothesis space:** H6/H7/H12 — Width-9 grid hypothesis, structural analysis, and any remaining non-standard multi-layer models.
**Research questions:** RQ-1 (transposition family), RQ-7 (fractionation compatibility)

**ALREADY ELIMINATED — DO NOT RE-TEST:**
- ADFGVX/ADFGX (structurally impossible — CT has 26 letters, ADFGVX produces 6)
- Straddling checkerboard (digit output, structurally impossible)
- Bifid 5×5 (25-letter alphabet, K4 uses all 26) and Bifid 6×6 (all periods 2-97, algebraic proof)
- Trifid 3×3×3 (all periods 2-97, algebraic proof)
- Playfair, Two-Square, Four-Square (eliminated)

**Mandate:**
The original fractionation families are ALL eliminated. This role is **repurposed** to focus on the **width-9 grid hypothesis** — the strongest untested structural lead:

**Evidence for width 9:**
- Sanborn's yellow pad annotation appears to read "10.8 rows" → 97/9 = 10.78 ≈ 10.8
- DFT peak at k=9 (period ~10.8, z≈2.83) from CT structural analysis (E-S-25)
- Width-9 grid: 9 columns, 7 cols of 11 rows + 2 cols of 10 rows

**Tasks (priority order):**
1. Width-9 columnar + non-periodic substitution models (running key, progressive, position-dependent)
2. Width-9 non-columnar reading orders (spiral, diagonal, serpentine on 9-wide grid)
3. Width-9 × width-7 compound transposition (apply both in sequence)
4. Width-9 grid with mixed alphabets (arbitrary substitution tables per column)
5. Structural analysis: does width-9 explain the lag-7 autocorrelation signal?

---

### Role: TABLEAU (Tableau & Structure Analyst)

**Agent ID:** `tableau`
**Hypothesis space:** H8/H9 — The Kryptos tableau used in a non-standard way; position-dependent alphabets.
**Research questions:** RQ-9 (tableau exploitation), RQ-11 (K1-K3 plaintext as instructions)

**Mandate:**
Investigate whether the Kryptos Vigenere tableau (physically present on the sculpture) is used in a non-standard way for K4, and whether the solved K1-K3 sections contain operational instructions for decrypting K4.

**Investigation threads:**
1. **Non-standard tableau access:** Read columns instead of rows; use the tableau as a Polybius square (row+col -> bigram); apply it with reversed direction; use modular arithmetic other than standard Vigenere
2. **K1-K3 as instructions:** Parse the combined K1-K3 plaintext for operational directives. "LAYER TWO" (K2 ending) is already confirmed as an instruction. What else?
3. **Position-dependent alphabets:** Scheidt said he "changed the language base." Test models where each position uses a different shifted or keyed alphabet derived from the tableau
4. **The misspelling chain:** IQLUSION(Q), UNDERGRUUND(U), DESPARATLY(A) -> collected error letters spell Q-U-A-Y. If K4 also contains a deliberate misspelling (e.g., BURYED->Y), QUAY could be the K5 keyword. Can the misspelling pattern constrain K4's plaintext?

**This role is lower-compute, higher-analysis.** Focus on structural reasoning and cheap tests, not massive sweeps. Write analysis documents in `reports/` and propose targeted experiments for other agents to run.

---

### Role: QA (Quality Assurance & Integration)

**Agent ID:** `qa`
**Hypothesis space:** N/A (meta-agent — does not test K4 hypotheses directly)
**Research questions:** All (cross-cutting)

**Mandate:**
Maintain the health of the shared codebase, validate results from other agents, resolve merge conflicts, and keep PROGRESS.md accurate and useful.

**Duties:**
1. **Regression testing:** Run `PYTHONPATH=src pytest tests/` after each significant merge. If tests fail, diagnose and fix or file a CONFLICT report.
2. **Result validation:** When any agent reports a score >=15/24, independently reproduce the result. Check for the common bugs listed in Key Gotchas (off-by-one, permutation direction, sign conventions). Write a validation report.
3. **PROGRESS.md maintenance:** Periodically reorganize, remove stale Active Tasks, ensure all Completed entries have proper artifact paths and repro commands.
4. **Merge conflict resolution:** When agents write `CONFLICT_*.txt` files, pull both sides, resolve the conflict, push the resolution.
5. **Statistical validation:** For any claimed signal, run a Monte Carlo null-hypothesis test: generate N random permutations/keys of the same family, score them, compute the p-value of the claimed score. A result is significant only if p < 0.001.
6. **Doctor runs:** Periodically run `PYTHONPATH=src python3 -m kryptos doctor` to verify the environment is healthy.
7. **Code quality:** When you observe duplicated code across agent scripts, refactor into shared modules in `src/kryptos/`. When you observe a pattern that could be a library function, write it, test it, and push it.

**Alert protocol:** When you see an ALERT in PROGRESS.md:
1. Immediately pull the result artifacts.
2. Reproduce the claimed score from a fresh interpreter.
3. Run the Monte Carlo p-value test.
4. If validated (p < 0.001 AND reproduction succeeds AND no indexing bugs): escalate to human operator. Write `ALERT_VALIDATED.md` at repo root.
5. If invalidated: update the ALERT entry with your findings. Do not delete it — annotate it.

---

## Harness Scripts

### `k4_agent_harness.sh` — The Infinite Loop

This script is what the human operator runs for each agent. It is the equivalent of Carlini's infinite `while true` loop.

```bash
#!/usr/bin/env bash
# Usage: ./k4_agent_harness.sh <agent_id> <agent_role>
# Example: ./k4_agent_harness.sh trans TRANS
#
# Prerequisites:
#   - Git worktree exists at $K4_AGENTS_DIR/agent_${AGENT_ID}
#   - Python 3.12+ available
#   - pytest installed (pip install --user pytest)

set -euo pipefail

AGENT_ID="${1:?Usage: $0 <agent_id> <agent_role>}"
AGENT_ROLE="${2:?Usage: $0 <agent_id> <agent_role>}"

export K4_AGENT_ID="$AGENT_ID"
export K4_AGENT_ROLE="$AGENT_ROLE"
export K4_BASE_DIR="/home/cpatrick/kryptos"
export K4_AGENTS_DIR="/home/cpatrick/kryptos_agents"
export K4_WORK_DIR="${K4_AGENTS_DIR}/agent_${AGENT_ID}"
export K4_MAX_RUNTIME=7200  # 2 hours per task
export PYTHONPATH=src

LOG_DIR="${K4_WORK_DIR}/agent_logs"
mkdir -p "$LOG_DIR"

cd "$K4_WORK_DIR"

ITERATION=0
while true; do
    ITERATION=$((ITERATION + 1))
    TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
    LOGFILE="${LOG_DIR}/session_${TIMESTAMP}.log"

    echo "=== Agent ${AGENT_ID} iteration ${ITERATION} @ ${TIMESTAMP} ===" | tee "$LOGFILE"

    # Pull latest changes before each session
    git pull --rebase origin main >> "$LOGFILE" 2>&1 || {
        echo "ERROR: git pull failed. Sleeping 60s and retrying." | tee -a "$LOGFILE"
        sleep 60
        continue
    }

    # Run Claude Code with the agent prompt
    claude --dangerously-skip-permissions \
           -p "You are agent '${AGENT_ID}' with role '${AGENT_ROLE}'. Read CLAUDE.md fully, then read PROGRESS.md, then begin your next task following the Multi-Agent Mode protocol. Your worktree is ${K4_WORK_DIR}. Max runtime per task: ${K4_MAX_RUNTIME}s." \
           --model claude-opus-4-6 \
           >> "$LOGFILE" 2>&1

    echo "Session complete @ $(date -u +%Y%m%dT%H%M%SZ)" | tee -a "$LOGFILE"

    # Brief pause to avoid hammering the API
    sleep 10
done
```

### `k4_setup_agents.sh` — One-Time Setup

```bash
#!/usr/bin/env bash
# Run once to create git worktrees for all agents.
# Must be run from the main repo directory.

set -euo pipefail

K4_BASE_DIR="$(pwd)"
K4_AGENTS_DIR="/home/cpatrick/kryptos_agents"

AGENTS=("trans" "bespoke" "jts" "frac" "tableau" "qa")

# Ensure the main repo is on branch 'main'
BRANCH=$(git branch --show-current)
if [ "$BRANCH" != "main" ]; then
    echo "ERROR: must be on branch 'main'. Currently on '$BRANCH'."
    exit 1
fi

mkdir -p "$K4_AGENTS_DIR"
mkdir -p current_tasks

for AGENT in "${AGENTS[@]}"; do
    WORKTREE="${K4_AGENTS_DIR}/agent_${AGENT}"
    BRANCH_NAME="agent/${AGENT}"

    if [ -d "$WORKTREE" ]; then
        echo "Worktree for $AGENT already exists at $WORKTREE — skipping."
        continue
    fi

    # Create a branch for the agent (branched from main)
    git branch "$BRANCH_NAME" main 2>/dev/null || true

    # Create the worktree
    git worktree add "$WORKTREE" "$BRANCH_NAME"

    # Create agent-specific directories
    mkdir -p "${WORKTREE}/agent_logs"
    mkdir -p "${WORKTREE}/results/${AGENT}"

    echo "Created worktree for agent $AGENT at $WORKTREE (branch: $BRANCH_NAME)"
done

# Initialize PROGRESS.md if it doesn't exist
if [ ! -f PROGRESS.md ]; then
    cat > PROGRESS.md << 'EOF'
# K4 Agent Team — Progress Tracker
Last updated: (not yet started)

## ALERTS
<!-- Scores >=18/24 go here. If this section is non-empty, ALL agents should read it. -->
(none)

## Active Tasks
| Agent | Task | Started | Status |
|-------|------|---------|--------|

## Completed (reverse chronological)
(no completed tasks yet)
EOF
    git add PROGRESS.md current_tasks/.gitkeep
    git commit -m "Initialize multi-agent infrastructure"
    echo "Created PROGRESS.md"
fi

echo ""
echo "Setup complete. To start an agent:"
echo "  cd ${K4_AGENTS_DIR}/agent_<name>"
echo "  tmux new -s k4_<name> '${K4_BASE_DIR}/k4_agent_harness.sh <name> <ROLE>'"
echo ""
echo "Recommended tmux launch order:"
echo "  1. qa      (let it run doctor + regression first)"
echo "  2. trans   (highest-priority hypothesis)"
echo "  3. bespoke (creative search, low compute)"
echo "  4. frac    (independent hypothesis branch)"
echo "  5. tableau (low-compute structural analysis)"
echo "  6. jts     (wait for TRANS to produce 3+ results first)"
```

### `k4_launch_all.sh` — Convenience Launcher

```bash
#!/usr/bin/env bash
# Launch all 6 agents in separate tmux sessions.
# Run from the main repo directory.

set -euo pipefail

K4_BASE_DIR="$(pwd)"

declare -A ROLES=(
    [trans]="TRANS"
    [bespoke]="BESPOKE"
    [jts]="JTS"
    [frac]="FRAC"
    [tableau]="TABLEAU"
    [qa]="QA"
)

# Launch order matters — QA first, JTS last
LAUNCH_ORDER=("qa" "trans" "bespoke" "frac" "tableau" "jts")

for AGENT in "${LAUNCH_ORDER[@]}"; do
    ROLE="${ROLES[$AGENT]}"
    SESSION="k4_${AGENT}"

    if tmux has-session -t "$SESSION" 2>/dev/null; then
        echo "Session $SESSION already running — skipping."
        continue
    fi

    echo "Launching agent $AGENT (role: $ROLE) in tmux session $SESSION..."
    tmux new-session -d -s "$SESSION" \
        "${K4_BASE_DIR}/k4_agent_harness.sh ${AGENT} ${ROLE}"

    sleep 5  # stagger launches to avoid git contention
done

echo ""
echo "All agents launched. Monitor with:"
echo "  tmux ls                    # list sessions"
echo "  tmux attach -t k4_trans    # watch an agent"
echo "  tail -f /home/cpatrick/kryptos_agents/agent_trans/agent_logs/*.log"
echo ""
echo "  cat PROGRESS.md            # see shared state"
echo "  ls current_tasks/          # see active locks"
```

---

## Git Workflow for Agents

**Branch strategy:** Each agent has its own branch (`agent/trans`, `agent/bespoke`, etc.) created as worktrees from `main`. Agents commit to their own branch and periodically merge to `main`.

**Recommended git workflow within an agent session:**

```bash
# At start of each task:
git checkout agent/${K4_AGENT_ID}
git pull --rebase origin main          # get latest from main

# During work: commit frequently with descriptive messages
git add results/${K4_AGENT_ID}/ scripts/ PROGRESS.md
git commit -m "[${K4_AGENT_ID}] ${TASK_DESCRIPTION}: ${VERDICT}"

# On task completion: merge to main
git checkout main
git pull origin main
git merge agent/${K4_AGENT_ID} --no-ff -m "[${K4_AGENT_ID}] merge: ${TASK_SUMMARY}"
git push origin main
git checkout agent/${K4_AGENT_ID}
git merge main  # keep agent branch up-to-date
```

**Merge conflict rules:**
- If the conflict is in `PROGRESS.md` or `current_tasks/`: resolve by keeping both entries (append, don't replace).
- If the conflict is in `src/kryptos/`: do NOT resolve. Write a `CONFLICT_*.txt` and let the QA agent handle it.
- If the conflict is in `results/` or `agent_logs/`: these should never conflict (agent-namespaced directories).

---

## Alert Protocol

When any agent scores >=18/24 on a candidate:

**Step 1 (discovering agent):** Immediately halt current sweep. Write an ALERT entry in PROGRESS.md:
```markdown
## ALERTS

### [2026-02-18T17:00Z] agent_trans — SIGNAL DETECTED
- **Score:** 19/24 crib matches, Bean: PASS, IC: 0.042
- **Config:** columnar width=8, perm=[5,2,7,0,3,6,1,4], vigenere, kryptos alphabet, period=6
- **Intermediate text:** THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG... (full 97 chars)
- **Implied key:** [12, 3, 19, 7, 0, 22] (period 6)
- **Keyword guess:** (if derivable from key values)
- **Artifacts:** results/trans/columnar_w8_signal/full_output.json
- **NEEDS QA VALIDATION**
```

**Step 2 (QA agent):** On seeing a new ALERT:
1. Pull the artifacts.
2. Run the repro command from a clean interpreter.
3. Check for all known false-positive patterns (Key Gotchas list).
4. Run Monte Carlo: generate 10,000 random permutations of the same family, score each, compute p-value.
5. If p < 0.001 AND reproduction succeeds: write `ALERT_VALIDATED.md` at repo root and add `[QA VALIDATED]` tag to the ALERT.
6. If p >= 0.001 OR reproduction fails: add `[QA: FALSE POSITIVE — {reason}]` tag. Agents resume normal work.

**Step 3 (human operator):** If `ALERT_VALIDATED.md` exists, review immediately.

---

## Resource Budget & Scheduling

**Compute allocation (on a 16-vCPU server):**

| Agent | CPU cores | Expected load | Notes |
|-------|-----------|---------------|-------|
| TRANS | 6 | High (exhaustive enumeration) | Use `--workers 6` in sweeps |
| JTS | 4 | High (SA/hill-climbing) | Use `--workers 4` |
| FRAC | 3 | Medium (structured search) | Use `--workers 3` |
| BESPOKE | 1 | Low (creative, small experiments) | Single-threaded mostly |
| TABLEAU | 1 | Low (analysis, cheap tests) | Single-threaded mostly |
| QA | 1 | Low-Medium (validation, doctor) | Bursty — high during alert validation |

**Scheduling guidance:**
- TRANS and JTS are compute-bound. They should not both run at full capacity simultaneously unless the server has headroom.
- JTS should wait until TRANS has completed >=3 tasks (check PROGRESS.md) before starting heavy sweeps.
- BESPOKE, TABLEAU, and QA are lightweight and can always run in parallel.
- If the server is under memory pressure (watch `htop`), JTS should yield cores to TRANS.

---

## Task Priority Matrix

When deciding what to work on next, agents should consult this matrix. Higher priority = do first.

**For TRANS agent:**

| Priority | Task | Estimated Runtime | Rationale |
|----------|------|-------------------|-----------|
| 1 | Width-9 columnar, all 9!=362880 orderings × sub models | 2-4 hours | Top untested hypothesis (DFT + Sanborn notes) |
| 2 | Width-9 non-columnar reads (serpentine, spiral, diagonal) | 1-2 hours | Alternative reading orders on 9-wide grid |
| 3 | Width-11/13 columnar with keyword orderings | 2-4 hours | Sparse prior coverage |
| 4 | Multi-step transpositions (w9→w7, w7→w9) | 4-8 hours | Compound transposition |
| 5 | Non-standard width-7 with non-periodic substitution | 2-4 hours | Width-7 tested only with periodic keys |

**For FRAC agent (repurposed):**

| Priority | Task | Estimated Runtime | Rationale |
|----------|------|-------------------|-----------|
| 1 | Width-9 columnar + running key models | 2-4 hours | Complement TRANS with non-periodic sub |
| 2 | Width-9 grid structural analysis (IC, lag, DFT per column) | Minutes | Cheap diagnostic tests |
| 3 | Width-9 × width-7 compound transposition | 4-8 hours | Two-layer hypothesis |
| 4 | Width-9 + position-dependent mixed alphabets | Hours | Arbitrary sub tables per column |

**For BESPOKE agent:**

| Priority | Task | Estimated Runtime | Rationale |
|----------|------|-------------------|-----------|
| 1 | Strip manipulation on 9-wide and 7-wide grids | Minutes each | Direct evidence from archives + width hypothesis |
| 2 | Physical reading orders from sculpture geometry | Minutes each | S-curve, boustrophedon on actual dimensions |
| 3 | "Coding chart" models — arbitrary lookup tables | Minutes-hours | Sanborn's confirmed encipherment tool ($962K auction) |
| 4 | K1-K3 plaintext as operational instructions | Minutes | "LAYER TWO" instruction, parse for more |
| 5 | Non-mathematical procedures a sculptor would use | Minutes each | "Who says it is even a math solution?" |

---

## What NOT to Do

These are explicitly prohibited to prevent wasted compute and confusing results:

1. **Do not re-test eliminated families.** The elimination table in CLAUDE.md is definitive for single-layer models. Do not re-run Vigenere, Beaufort, Hill, Playfair, etc. without a transposition layer — they are mathematically eliminated.

2. **Do not hardcode CT, cribs, or Bean constraints.** Always import from `kryptos.kernel.constants`. The self-verification at import time is your first line of defense against bugs.

3. **Do not modify `src/kryptos/kernel/constants.py`** without QA agent review and a full test suite pass.

4. **Do not claim scores without a repro command.** Every result in PROGRESS.md must include a command that another agent can run to reproduce the score.

5. **Do not work on a locked task.** If `current_tasks/` contains a lockfile for the task you want, pick something else.

6. **Do not ignore the max-runtime budget.** If your task exceeds `K4_MAX_RUNTIME` (default 2 hours), checkpoint your state, log what you've covered, unlock, and let the next iteration continue where you left off.

7. **Do not trust high scores at high periods.** Any score at period >=17 is almost certainly a false positive due to underdetermination. See Key Gotchas in CLAUDE.md.

8. **Do not delete another agent's work.** Append to PROGRESS.md, don't rewrite it. If you think another agent's result is wrong, add a `[DISPUTED by {your_id}: {reason}]` tag — don't remove the entry.

9. **Do not spend more than 15 minutes orienting.** Read CLAUDE.md, read AGENT_PROMPT.md, read PROGRESS.md, check `current_tasks/`, pick a task, go. If you're confused about priorities, default to the Task Priority Matrix for your role.

10. **Do not run the full test suite before every commit.** The QA agent handles regression testing. Other agents should run only the tests relevant to their changes (e.g., `pytest tests/test_transforms.py` if you modified a transform).

---

## Scaling: Adding More Agents

To add a new agent:
1. Choose an `agent_id` and `role` (can be a new role or a second instance of an existing role).
2. Run: `git worktree add ${K4_AGENTS_DIR}/agent_${NEW_ID} -b agent/${NEW_ID} main`
3. Update the `ROLES` array in `k4_launch_all.sh`.
4. Add a role description to this file (or assign an existing role).
5. Launch: `tmux new -s k4_${NEW_ID} './k4_agent_harness.sh ${NEW_ID} ${ROLE}'`

**When to scale:**
- If one hypothesis branch has many independent sub-tasks (e.g., columnar widths 5-15 could each be a separate TRANS agent)
- If the QA agent is a bottleneck (unlikely unless there are many alerts)
- If a new hypothesis space emerges that doesn't fit existing roles

---

## Monitoring & Human Intervention

The human operator should periodically check:

```bash
# Quick status
cat PROGRESS.md | head -50
ls current_tasks/

# Check for alerts
grep -l "ALERT" PROGRESS.md ALERT_VALIDATED.md 2>/dev/null

# Check agent health (are all sessions alive?)
tmux ls

# Check for stuck agents (locks older than 4 hours)
find current_tasks/ -name "*.lock" -mmin +240

# View recent agent activity
for agent in trans bespoke jts frac tableau qa; do
    echo "=== $agent ==="
    ls -lt /home/cpatrick/kryptos_agents/agent_${agent}/agent_logs/ | head -3
done

# Kill and restart a stuck agent
tmux kill-session -t k4_trans
# Then relaunch:
tmux new -d -s k4_trans './k4_agent_harness.sh trans TRANS'
```

**When to intervene:**
- `ALERT_VALIDATED.md` exists -> review the candidate solution
- An agent has been stuck on the same task for >4 hours -> check its logs, consider killing and restarting
- `current_tasks/` has orphaned lockfiles with no corresponding active tmux session -> delete them
- PROGRESS.md shows all agents have completed their priority matrices -> time to formulate new hypotheses (this requires human + Claude brainstorming, not autonomous agents)

---

*Last updated: 2026-02-18 — Multi-agent protocol v1.1 (extracted from CLAUDE.md)*
