# Phase R2-00 — Pre-flight baseline verification

**Date:** 2026-04-21
**Round:** Maturation Round 2
**Author:** Claude Code Opus 4.7
**Status:** complete

## Pre-flight gate summary

| Check | Result |
|---|---|
| `kryptos doctor` | [PASS] all 20 checks green (including `bean_count` which was stale in CLAUDE.md but has been silently fixed) |
| `pytest tests/` | [PASS] 1525 passed, 6 deprecation warnings (all related to retired null-palette, not regressions) |
| `pytest kryptosbot/tests/` | [PASS] 570 passed |
| Self-test dry-run K1 | [PASS] discovered cycle 15, peak 20/20 — matches Phase 7 baseline |
| Self-test dry-run K2 | [PASS] discovered cycle 17, peak 20/20 — matches Phase 7 baseline |
| Self-test dry-run K3 | [EXPECTED MISS] peak 4/20 after 406 candidates — matches Phase 7 baseline; gap target of R2-1 |
| False-positive breakthroughs | 0 across all panels |
| Phase 5 commit tagged | `maturation-phase-05` on `e1afbff` (Option A per brief §1 — no history rewrite) |

## Baseline self-test JSON

Artifact: `results/self_test/r2_baseline_dryrun.json`

```
k1: discovered=True via='quagmire_iii' cycles=15 peak=20/20 wall=0.00s tested=15
k2: discovered=True via='quagmire_iii' cycles=17 peak=20/20 wall=0.00s tested=17
k3: discovered=False via=None cycles=None peak=4/20 wall=0.03s tested=406
```

All values match the Phase 7 report verbatim. Round 2 starts from a clean baseline.

## Pre-flight side-finding (critical for R2-1)

**[INTERNAL RESULT]** The K3 panel's ciphertext in `kryptosbot/self_test.py` has length **281**, not the canonical **336**. The `known_plaintext` field is correctly 336 chars.

The mismatch has no effect on Phase 7 because:
- The Phase 7 K3 path never succeeded, so no scoring function ever compared a 281-char candidate against a 336-char plaintext.
- The kernel-sanity check for K3 explicitly short-circuits: `"K3 double-columnar transposition not expressible in a single kernel call; manual two-pass required."` It never actually calls a kernel transform against the K3 panel, so the length mismatch was never surfaced.

**[DERIVED FACT]** Repair of the K3 panel CT to the canonical 336 chars is a prerequisite for R2-1. This will be done as the first step of R2-1, not as part of preflight, so the diff lands on the correct phase commit.

## Pre-flight side-finding (K3 decomposition verified)

**[INTERNAL RESULT]** An empirical search over (width, ordering) pairs using the kernel's `columnar_perm` + `apply_perm` primitives confirms:

```
K3_PT = columnar_decrypt(columnar_decrypt(K3_CT, width=42, order=reversed), width=14, order=reversed)
```

Equivalent aliases: (21, reversed) × (28, reversed); (28, reversed) × (21, reversed); (42, reversed) × (14, reversed).

This is the **kernel-overrule ground truth** for K3 and will inform R2-1's self-test schedule. The widths `{14, 21, 28, 42}` lie outside the brief's suggested `4-12` range; R2-1 will document this width-schedule deviation.

The search ran `101,761` configs in 19.4s (single-threaded Python) against motivated orderings (identity, reversed, reversed-halves, single-swap-from-identity). The per-config cost is ~190 µs; scaling out to the full R2-1 schedule is comfortably within budget.

## K3 discovery status after Round 2 phase N (policy check)

Per brief §0.5, every phase reports whether the K3 dry-run self-test discovers K3. For this preflight phase:

**K3 discovered: NO** (peak 4/20). This is the baseline miss; R2-1 will close it.

## Git state at preflight exit

```
$ git log -1 --format='%h %s'
5bc14c8 maturation phase 09: ORIENT.md + architecture + doctrine refresh

$ git tag -l | grep maturation
maturation-phase-05

$ git status --short
?? f0aac050-0944-40df-a3bb-16628000f6d6.png    # untracked user file, not from this session
```

Directory `docs/maturation/round2/` created. Ready to proceed to R2-1.
