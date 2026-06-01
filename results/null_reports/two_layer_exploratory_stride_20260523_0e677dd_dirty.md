# two_layer_exploratory_stride_20260523_0e677dd_dirty

**FROZEN NULL REPORT — IMMUTABLE PROJECT ARTIFACT**

- Frozen at: 2026-05-23T00:59:58.322814+00:00
- Frozen by: unknown

## Canonical Claim

> EXPLORATORY null over 2,000 stride-sampled profiles. Coverage is approximate; this is NOT a definitive negative result for the two-layer hypothesis class. Use only as a first-look indicator.

## Run Provenance

- Campaign: `f_two_layer_stego_cipher_v1`
- Sampling mode: `exploratory_stride`
- Sampling seed: `0`
- Target evaluations: `2000`
- Pairs evaluated: `2,000`
- Plan complete for mode: `True`
- Workers: `16`
- Started: `2026-05-23T00:48:49.391845+00:00`
- Completed: `2026-05-23T00:48:51.206841+00:00`

## Generator Counts

- Outer parameterized instances: `552`
- Inner parameterized instances: `374`
- Full cartesian: `206,448`

## Coverage Report

- Distinct outer instances touched: `551/552`
- Distinct inner instances touched: `374/374`
- Cross-pair coverage: `16/16`
- Outers seeing all inner families: `48`
- Median inner families per outer: `3.0`
- Low complexity evals: `170`
- Medium complexity evals: `361`
- High complexity evals: `1469`
- Qualifies as family-cover-complete: `False`
- Qualifies as low-complexity-emphasized: `False`
- Qualifies as full-cartesian-complete: `False`

## Joint Anomaly Successes

**Zero candidates** met the joint anomaly success criterion.

## Git Provenance

- Commit: `0e677dd770a9e1224da532ed61deba279a9a9160`
- Branch: `main`
- Subject: scrub: remove agent-architecture references from CLAUDE.md/MEMORY.md
- Commit date: `2026-04-30T08:48:14-04:00`
- Working tree clean: `False`
- Dirty files: `7`
  ```
  M run_attack.py
  ?? dictionary.txt
  ?? e_explorer_01_sanborn_manuscript.py
  ?? exhaustion_log.tmp
  ?? scripts/gpu_attacks/
  ?? solver_cascade.exe
  ?? solver_gpu.exe
  ```

## Kernel Constants

- CT length: `97`
- CT SHA-256: `eea813570c7f1fd3b34674e47b5c3da8948026f5cefee612a0b38ffaa515ceab`
- Crib count: `24`
- Crib dict SHA-256: `5414f2d545473e6515ef8919aa281c0a9cc8cd64957878ae1afa976867a53c99`
- Bean equality SHA-256: `620352e4d094176b5498fc359e0d406cd78555cfaef466dc269542865309de51`
- Bean inequality count: `242`
- Bean inequality SHA-256: `06496a166b98afdbe690de87e35ef74562fc03f7e8eefe07804c5326638dea5e`
- Bean linear constraint count: `101`
- Bean linear SHA-256: `1256f336983f4fdabf507c1464010b6d3fffe8e8f74d2691590bef48b2ef0818`

## Code SHA-256 Hashes

These hashes pin the exact code that produced the result. A future
re-run with different hashes is not a replay; it is a new run.

```
4535f7efc25a96e2  scripts/campaigns/f_two_layer_stego_cipher_v1.py
7c33f040d4fffe56  src/kryptos/campaigns/__init__.py
33d58f59ea19783f  src/kryptos/campaigns/two_layer/__init__.py
8581d9fec901f0f4  src/kryptos/campaigns/two_layer/families.py
ca7591ce4d97c24a  src/kryptos/campaigns/two_layer/outer_layers.py
a1e2d23aa2ecc2ff  src/kryptos/campaigns/two_layer/inner_layers.py
104ba133c2d9bc68  src/kryptos/campaigns/two_layer/evaluation.py
c410a7462eab8493  src/kryptos/campaigns/two_layer/multiplicity.py
5cf2e8b3c8533deb  src/kryptos/campaigns/two_layer/provenance.py
499174463ffd8928  src/kryptos/campaigns/two_layer/sampling.py
0f9953a2a26c73a4  src/kryptos/campaigns/two_layer/coverage.py
519b9f020eac8ae5  src/kryptos/campaigns/two_layer/parallel.py
edfcec54960efcc6  src/kryptos/campaigns/two_layer/checkpoint.py
```

## Replay Instructions

To attempt to reproduce this exact result:

```bash
git checkout 0e677dd770a9e1224da532ed61deba279a9a9160
PYTHONPATH=src python3 scripts/campaigns/f_two_layer_stego_cipher_v1.py \
    --sampling-mode exploratory_stride \
    --seed 0 \
    --target-evals 2000 \
    --workers 16
```

If kernel constants or code hashes have changed, the replay is
not the same experiment.

---

*This file is a frozen project artifact. Do not edit.*