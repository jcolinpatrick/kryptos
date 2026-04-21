# Phase 0 — Pre-flight report

**Date:** 2026-04-20
**Git baseline:** `5ad398d wip: pre-maturation baseline (day 5/6/7 pantheon, site-builder tests, self_heal)`
**Prior HEAD:** `24b40ce [auto] Update 2 other file(s)`
**Operator:** Claude Opus 4.7 (1M context), session under `/home/cpatrick/kryptos`

---

## Purpose

Capture the baseline state of the repository before the framework maturation brief
(`docs/maturation/` phase sequence) begins. Establish that:

1. Both test suites are green.
2. `doctor` reports only the known-stale `bean_count` failure.
3. Session briefing, VM capability report, and controller inventory all run.
4. There are no undiagnosed environmental issues.

This document exists per the brief's §1 and §12.1 requirements. It is **read-only reference** — Phase 1+
work does not modify it.

---

## 1. Test suites

| Suite | Collection size | Result | Wall time |
|---|---|---|---|
| `tests/` (core) | 1521 tests | ✅ 1521 passed, 6 warnings | 107.41s |
| `kryptosbot/tests/` | 364 tests | ✅ 364 passed | 6.93s |

**Warnings:** 6 `DeprecationWarning` from `check_coupling_constraints(palette=None)`. These are
intentional warnings installed during the 2026-04-14 palette retirement and do not indicate failure.
They will remain until Phase 2 relocates `NULL_PALETTE` fully and all callers migrate.

**Command:**
```bash
PYTHONPATH=src pytest tests/ -q           # 1521 passed, 6 warnings in 107.41s
PYTHONPATH=src pytest kryptosbot/tests/ -q # 364 passed in 6.93s
```

**Status:** [PUBLIC FACT] Green baseline.

---

## 2. `kryptos doctor`

**Command:** `PYTHONPATH=src python3 -m kryptos doctor`

**Result:** 17 PASS, 1 FAIL.

| Check | Status | Notes |
|---|---|---|
| python_version | PASS | Python 3.12 |
| constants_import | PASS | |
| ct_length | PASS | len=97 |
| ct_boundary | PASS | |
| crib_count | PASS | n=24 |
| **bean_count** | **FAIL** | **Known stale threshold; CLAUDE.md §Key Gotchas.** Check asserts `len(BEAN_INEQ) == 21` but the canonical count is 242 (since the Bean Linear constraint expansion). **Phase 1 §3.4 fixes this.** |
| alphabet_az | PASS | |
| alphabet_ka | PASS | |
| alphabet_ka_construct | PASS | |
| vig_roundtrip | PASS | HELLOWORLD → KLWNTZVCNI → HELLOWORLD |
| vig_key_recovery | PASS | k=3 |
| perm_valid | PASS | len=10 |
| perm_roundtrip | PASS | ABCDEFGHIJ → BGDIAFEJCH → ABCDEFGHIJ |
| bean_check_runs | PASS | |
| scoring_runs | PASS | score=2 |
| database | PASS | |
| quadgrams | PASS | score=-63.5 |
| novelty_engine | PASS | id=a433d1a3b3a4 |

**Status:** [DERIVED FACT] Environmental baseline healthy; the single failure is a known stale-threshold
bug explicitly called out in CLAUDE.md and targeted by Phase 1 §3.4.

---

## 3. Session briefing

**Command:** `PYTHONPATH=src python3 scripts/_infra/session_briefing.py`
**Output:** `docs/maturation/phase_00_briefing.txt` (full capture)

Key state from the briefing:

- **Exhaustion log:** 1023 entries (226 exhausted, 797 active).
- **Results directory:** 417 JSON files + 53 subdirs.
- **Script corpus:** 896 scripts tracked.
- **Constants:** CT length 97, 24 crib positions, Bean = 1 equality + 242 inequalities + 101 linear
  constraints, 624 valid keystreams at crib positions.
- **Disputed / retired claims present:**
  - `C-PALETTE-01` RETIRED (palette + CONSENSUS_NULL_POSITIONS; target of Phase 2 relocation).
  - `C-HIST-01` SUPERSEDED (pre-2026-03-22 synthesis documents).
- **IC:** 0.0361, Bonferroni p=1.0 (not significant at n=97).

No schema drift flagged. Briefing ran in under 5s.

**Status:** [PUBLIC FACT] Live-state tooling operational.

---

## 4. VM capability report

**Command:** `bash scripts/vm_capability_report.sh --json`
**Output:** `results/vm_capability.txt` (90 lines)

| Resource | Value |
|---|---|
| OS | Ubuntu 24.04.4 LTS, kernel 6.8.0-107-generic, x86_64 |
| CPU | 28 vCPUs, 2 sockets × 14 cores/socket, 2.60 GHz, AVX-512 |
| RAM | 11 GiB total, 9.3 GiB available |
| Swap | 8 GB file |
| Disk | 96 GB root, 57 GB free, 393 MB/s I/O |
| Network | IP 192.168.1.156/24, internet + Gutenberg reachable |
| Python | 3.12.3, 64-bit, cpu_count = 28 |
| All-core throughput | 309.0 M ops/sec, ~61% efficiency, ~1.5M DRAGNET candidates/sec |

**Issues:**
- The `--json` flag did not produce `results/vm_capability.json`. Shell script has an unbound-variable
  bug at `scripts/vm_capability_report.sh:198` (`VCPUS: unbound variable`). The `.txt` report completed
  cleanly before the JSON-emission error. **Out of scope for this brief.** Logged for future fix.

**Status:** [PUBLIC FACT] Expected compute capacity confirmed. Default worker pool = 26 (cpu_count - 2).

---

## 5. Controller inventory

**Command:** `PYTHONPATH=src python3 kryptosbot/run_controller.py --inventory`
**Output:** `docs/maturation/phase_00_inventory.txt` (138 lines, 46 provenance entries)

Inventory surfaces the provenance registry (not the MCP tool surface; see §6 for tools). Coverage:

- Public facts: 2 entries
- Primary-source facts: 7 entries
- H1-conditional derivations: 6 entries
- Project-reverified statistical anomalies: 2 entries
- Bean-reported (not independently re-derived): 3 entries
- Physical sculpture facts: 7 entries
- Interpretive physical observations: 6 entries (each tagged "cryptographic role unproven")
- Project internal results: (remainder)

The controller correctly distinguishes `[PUBLIC FACT]` from `[PROJECT-VERIFIED]` from
`[BEAN-REPORTED, NOT REVERIFIED]` at the inventory level, which the brief's truth taxonomy relies on.

**Status:** [PUBLIC FACT] Provenance layer operational.

---

## 6. MCP tool inventory

**Command:** `grep -n '@tool' kryptosbot/k4_tools.py kryptosbot/research_tools.py`

| File | @tool count | Purpose |
|---|---|---|
| `kryptosbot/k4_tools.py` | 7 | K4-specific computational tools (hill_climb, try_keyword_sweep, swap_and_test, …) |
| `kryptosbot/research_tools.py` | 10 | Research-state tools (get_canonical_facts, search_theory_ledger, get_family_status, …) |
| **Total** | **17** | |

**Relevance to later phases:** Phase 5 (MCP surface redesign) will deprecate the three noise tools in
`k4_tools.py` (`hill_climb`, `try_keyword_sweep`, `swap_and_test`) and introduce 8 new DSL-oriented
tools. Current `k4_tools` count of 7 is the pre-deprecation baseline. `research_tools.py` is preserved
unchanged per §7.3.

---

## 7. Working-tree state at phase entry

Pre-brief WIP committed at `5ad398d` (see §Git baseline). Only remaining untracked file:

- `f0aac050-0944-40df-a3bb-16628000f6d6.png` (843 KB, UUID-named, apparent screenshot drop)

Left untracked intentionally; ownership unclear. Does not block any phase.

**Gitignore update:** `site.stale-*/` added to `.gitignore` in the WIP commit to suppress a recurring
stale build artifact (`site.stale-1776599833/`). The directory itself is root-owned and remains on disk;
operator can `sudo rm -rf` at leisure — non-blocking.

---

## 8. Pre-flight verdict

All acceptance criteria for entry to Phase 1 are met:

- [x] Both test suites green.
- [x] `doctor` has zero failures **other than** the known-stale `bean_count` check (CLAUDE.md
      §Key Gotchas explicitly documents this as non-environmental).
- [x] Session briefing runs without error.
- [x] VM capability report runs (JSON mode failure is a shell-script bug unrelated to the brief).
- [x] Controller inventory runs.
- [x] Clean git baseline established.
- [x] `docs/maturation/` directory created.

**Proceeding to Phase 1.**

---

## Appendix A — Artifacts produced by this phase

| Path | Size |
|---|---|
| `docs/maturation/phase_00_preflight.md` | this file |
| `docs/maturation/phase_00_briefing.txt` | full session briefing output |
| `docs/maturation/phase_00_inventory.txt` | 138 lines, 46 provenance entries |
| `results/vm_capability.txt` | 90 lines (pre-existing path; regenerated) |

## Appendix B — Deferred items (NOT Phase 0 scope)

1. `scripts/vm_capability_report.sh:198` has `VCPUS: unbound variable` bug; `--json` mode fails to emit
   `vm_capability.json`. **Out of scope.** File under future hygiene work.
2. Six `DeprecationWarning` from `check_coupling_constraints(palette=None)`. Will be resolved as a
   side-effect of Phase 2 when all live callers migrate off the retired palette path.
3. The 843 KB root PNG `f0aac050-...png` has unclear provenance. Operator should decide retention
   independently of this brief.
