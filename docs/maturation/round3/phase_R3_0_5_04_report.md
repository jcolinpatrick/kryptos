# Phase R3-0.5-4 — Exit handoff

**Date:** 2026-04-21
**Brief:** `CLAUDE_CODE_BRIEF_round3_0_5_dsl_completion.md` §5
**Phase result:** Round 3.5 complete. All four consistency checks green. R3-2 unblocked.

---

## 1. Phase-by-phase summary

| Phase | What landed | Tests added | Commit |
|---|---|---|---|
| R3-0.5-0 | Pre-flight baseline + infrastructure inspection (§2.1 procedural, §2.2 grille, §2.3 polybius) | 0 | part of `3f49f58` |
| R3-0.5-1 | Procedural translator (spec-level expansion via `recipe_to_spec`); `NON_DSL_FAMILIES` in critic | 22 | `3f49f58` |
| R3-0.5-2 | Grille translator — new `src/kryptos/kernel/transforms/grille.py`, `TransformType.GRILLE`, `grille` in `_VALID_CIPHER_KINDS` | 24 | `b3485c0` |
| R3-0.5-3 | Polybius translator via existing `TransformType.BIFID` (straight polybius deferred); 2 pre-existing tests migrated from polybius exemplar to rail_fence | 21 | `fff4c21` |
| R3-0.5-4 | Consistency checks, DSL_CUTOVER_CONTRACT §1.2/§1.3 updated, MEMORY.md pointer | 0 | this commit |

**Total new tests:** 67 across R3-0.5 (vs brief's minimum of 30 across the three translator phases).
**Total new source code:** ~335 lines of production code in `kryptosbot/` and `src/kryptos/`, excluding tests.

---

## 2. Consistency checks (§5.1)

### 2.1 Full test suites green

```
PYTHONPATH=src pytest tests/ -q
→ 1529 passed in 105.99s
```

```
PYTHONPATH=src pytest kryptosbot/tests/ -q
→ 725 passed in 18.58s
```

- Core suite unchanged at 1529 throughout R3-0.5 — no regressions in the kernel or kryptos-package code.
- Kryptosbot grew 658 → 680 (R3-0.5-1) → 704 (R3-0.5-2) → 725 (R3-0.5-3). Delta: **+67 tests.**

### 2.2 `_SUPPORTED_KINDS` has exactly 9 entries

```
PYTHONPATH=src python3 -c "
from kryptosbot.job_dispatcher import _SUPPORTED_KINDS
expected = {'identity', 'vigenere', 'beaufort', 'variant_beaufort',
            'columnar', 'atbash', 'procedural', 'grille', 'polybius'}
assert _SUPPORTED_KINDS == expected, f'drift: {_SUPPORTED_KINDS ^ expected}'
print('ok:', sorted(_SUPPORTED_KINDS))
"
→ ok: ['atbash', 'beaufort', 'columnar', 'grille', 'identity', 'polybius',
       'procedural', 'variant_beaufort', 'vigenere']
```

### 2.3 Self-test baseline unchanged

```
PYTHONPATH=src python3 -u kryptosbot/self_test.py --panel all --mode dry-run \
    --cycles 20000 --report-path results/self_test/r3_0_5_exit.json
```

| Panel | discovered_via    | cycles | peak_score |
|---|---|---|---|
| k1 | quagmire_iii    | **15**   | 20/20 |
| k2 | quagmire_iii    | **17**   | 20/20 |
| k3 | columnar_double | **9345** | 20/20 |

**K1/15, K2/17, K3/9345 — identical to R3-1 exit and pre-flight baseline.** Zero regression.

### 2.4 Smoke test: all three new kinds dispatch cleanly

Procedural (P-BASELINE-1), grille (identity mask on 97 positions), polybius (KRYPTOS keyword bifid) each produce `admissibility_verdict == "ok"` when dispatched through `execute()`.

```
procedural: ok
grille: ok
polybius: ok
```

---

## 3. Document updates landed

### 3.1 `docs/maturation/round3/DSL_CUTOVER_CONTRACT.md`

- **§1.2 Supported cipher kinds** — "Post-R3-0.5 state (after ... lands)" replaced with "Current state (R3-0.5 exit, 2026-04-21 — 9 entries)", with an explanatory paragraph documenting how each new kind dispatches. Still auto-authoritative in the sense that the critic reads `_SUPPORTED_KINDS` at runtime.
- **§1.3 Example C** — revised from a procedural P-F1-1 hypothesis (which is now dispatchable post-R3-0.5-1) to a rail-fence hypothesis (which remains untranslatable). The revision note in the example itself explains why.

### 3.2 MEMORY.md

- New pointer entry: `[R3-0.5 DSL completion landed](project_r3_05_dsl_completion.md)` placed at the top of the Project section.
- New memory file at `~/.claude/projects/-home-cpatrick-kryptos/memory/project_r3_05_dsl_completion.md` with full commit-hash summary, covered-vs-deferred kinds list, non-regression numbers, and a how-to-apply note for R3-2.

---

## 4. What R3-0.5 proved

1. **The DSL covers the three biggest missing kinds from the historical theorist distribution.** Combined with the pre-R3-0.5 six, the controller can now dispatch 9 of the 14 kinds in `_VALID_CIPHER_KINDS`. The procedural kind alone unblocks ~12 of the 17 recipes in `docs/procedural_recipes.json`.

2. **Kernel overrule is preserved on all three new paths.** Every end-to-end test in each translator's test file verifies that `best_candidate.crib_score` and `best_candidate.bean_passed` equal the kernel's direct computation via `score_candidate()`. No shim can silently shift scoring on any of the three new kinds.

3. **Self-test fitness is unchanged.** K1/15, K2/17, K3/9345 reproduce identically at entry and at exit. The three new translators do not perturb the strategy search that rediscovers K1/K2/K3.

4. **Thin-adapter path held for all three.** No new kernel primitive logic. Procedural reuses `recipe_to_spec` + spec-level expansion. Grille is a 3-line function over `apply_perm`. Polybius wires the existing `TransformType.BIFID`. Brief's 400/600/300-line soft caps were easily met; the actual production-code footprint is well below them.

---

## 5. What R3-0.5 did NOT prove

1. **It did not test the new translators on novel K4 hypotheses.** Smoke tests verify the pipeline runs; they do not test that the output is meaningful. Noise-floor scores are expected (and observed — procedural P-F1-1 scored max 4/24; grille reverse mask scored 1/24; polybius scored 0/24). This is the correct outcome given CLAUDE.md's 26-letter polybius gotcha and the fact that P-F1-1's candidate keywords are not the real K4 key.

2. **It did not grow the procedural recipe catalogue.** R3-0.5-1 wires the existing 17 recipes through the dispatcher; it does not propose new recipes. Research-content is a separate concern.

3. **It did not implement turning grilles, partial grilles, or straight polybius.** All three remain explicitly deferred to a later brief. Their respective translator cases raise `DispatcherError` with a deferral pointer when invoked.

4. **It did not change the hybrid fallback policy.** `NON_DSL_FAMILIES` landed with the seven operator-specified members; R3-0.5 did not add or remove any.

---

## 6. Handoff note for R3-2

R3-2 can now proceed against the updated DSL_CUTOVER_CONTRACT with higher confidence that its R3-3 spec-production test will pass:

- **Pre-R3-0.5 DSL coverage:** estimated <5% of historical theorist output.
- **Post-R3-0.5 DSL coverage:** the three largest missing kinds are now dispatchable. A reasonable projection (not measured) is that R3-3's Category-A spec-production rate can plausibly reach the brief's 80% floor — though this depends on theorist prompt quality, which R3-2 may iterate.

R3-3 will measure the real rate. If it still falls below 80% after one prompt iteration, a second DSL-completion pass (covering rail_fence, route, myszkowski, quagmire, or key_tape as appropriate) becomes the escalation.

**Outstanding briefs:**
- R3-2 cutover — next to run
- Turning-grille / partial-grille — needed if research surfaces rotation-based hypotheses
- Straight-polybius — needed if multi-layer specs want length-doubling intermediate coord-pair encodings
- key_tape — operator-flagged for its own design cycle

---

## 7. Acceptance criteria

| Brief criterion | Status |
|---|---|
| All four consistency checks green | ✓ (§2) |
| DSL_CUTOVER_CONTRACT.md updated with new supported kinds and revised Example C | ✓ (§3.1) |
| MEMORY.md entry added | ✓ (§3.2) |
| `phase_R3_05_04_report.md` written | ✓ (this file) |
| Final commit message: `maturation round 3.5 complete: ...` | (next commit) |

---

## 8. Commit plan

R3-0.5-4 lands as a single commit containing:

- `docs/maturation/round3/DSL_CUTOVER_CONTRACT.md` — §1.2 and §1.3 updates
- `docs/maturation/round3/phase_R3_0_5_04_report.md` — this file
- `~/.claude/projects/-home-cpatrick-kryptos/memory/MEMORY.md` — pointer entry
- `~/.claude/projects/-home-cpatrick-kryptos/memory/project_r3_05_dsl_completion.md` — new memory file

Note: MEMORY.md lives outside the git repo (user-space memory system) and is not committed via the repo. Only the in-repo doc changes land in the commit.

Commit message: `maturation round 3.5 complete: DSL completion for procedural, grille, polybius`.

---

## 9. R3 status after R3-0.5

- **R3-0** Operator review amendments (pre-R3) — landed earlier
- **R3-1** Audit + cutover contract — landed (`70b3495`)
- **R3-0.5** DSL completion — **landed (this round)**
- **R3-2** Cutover implementation — pending, operator-commissioned
- **R3-3** Integration test — pending, operator-commissioned
- **R3-4** Updated run protocol — pending, operator-commissioned

*End of R3-0.5-4 phase report. Round 3.5 complete. Handing back to operator for R3-2 commissioning.*
