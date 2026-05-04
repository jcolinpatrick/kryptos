# DSL / Dispatcher Coverage Audit

**Status:** AUDIT COMPLETE 2026-05-04. Coverage at 100%; no DSL-valid kinds without dispatcher translation.

**Audit script:** `scripts/audit/audit_dsl_dispatcher_semantics.py` (live; regenerated 2026-05-03)
**Audit dossier:** `docs/audits/dsl_dispatcher_semantics.md` (machine-generated)

---

## Verdict (from live audit)

| | Count |
|---|---:|
| DSL-valid kinds (`_VALID_CIPHER_KINDS`) | 19 |
| Dispatcher-supported kinds (`_SUPPORTED_KINDS`) | 19 |
| **Valid without translation** | **0** |
| Supported but not DSL-valid | 0 |

The two sets agree exactly. There is no kind a theorist can propose that the dispatcher cannot translate.

---

## Coverage matrix

| Kind | DSL-valid | Dispatcher-supported | Kernel transform | Test files referencing |
|---|:-:|:-:|:-:|:-:|
| atbash | ✅ | ✅ | `transforms.atbash` | 12 |
| beaufort | ✅ | ✅ | `transforms.vigenere` (BEAUFORT) | 24 |
| caesar | ✅ | ✅ | `transforms.vigenere` (1-letter) | 12 |
| columnar | ✅ | ✅ | `transforms.transposition.columnar_perm` | 25 |
| grille | ✅ | ✅ | `transforms.transposition.apply_perm` (mask) | 9 |
| identity | ✅ | ✅ | (no-op) | 12 |
| key_tape | ✅ | ✅ | `transforms.key_tape` | 13 |
| myszkowski | ✅ | ✅ | `transforms.transposition.myszkowski_perm` | 7 |
| polybius | ✅ | ✅ | `transforms.bifid` (5×5) | 6 |
| procedural | ✅ | ✅ | dispatcher-procedural-translator | 5 |
| quagmire | ✅ | ✅ | `transforms.quagmire` | 10 |
| rail_fence | ✅ | ✅ | `transforms.transposition.rail_fence_perm` | 18 |
| reverse_blocks | ✅ | ✅ | `transforms.transposition.reverse_blocks_perm` | 4 |
| route | ✅ | ✅ | `transforms.transposition.serpentine_perm` / `spiral_perm` | 14 |
| route_boustrophedon | ✅ | ✅ | `transforms.transposition.serpentine_perm` (vertical) | 7 |
| row_reverse | ✅ | ✅ | `transforms.transposition.row_reverse_perm` | 4 |
| skip_route | ✅ | ✅ | `transforms.transposition.skip_route_perm` | 3 |
| variant_beaufort | ✅ | ✅ | `transforms.vigenere` (VAR_BEAUFORT) | 19 |
| vigenere | ✅ | ✅ | `transforms.vigenere` (VIGENERE) | 41 |

Every DSL-valid kind has both dispatcher support and dedicated kernel transform support. Every kind has at least 3 test files referencing it.

---

## Kinds explicitly deferred or rejected

**None.** As of 2026-05-04 commit `eac95e70`, the dispatcher accepts every kind the DSL allows. The previously-deferred `key_tape` gap was closed 2026-05-03 in commits `419d90d` (translator) and supporting work; the audit dossier was regenerated in `fd02a6b`.

---

## Methodological-family kinds (not DSL kinds)

The DSL covers cipher mechanisms. Methodological families (k2_coords, archive_evidence, antipodes, geodetic, geometry, k3_continuity, crib_analysis, multi_layer, etc.) are dispatched through worker scripts, not the DSL path. Theorists for these families set `dsl_spec: null` in their proposals — the controller's prompt explicitly states this is allowed for non-DSL methodological families.

These are not DSL coverage gaps. They are a separate dispatch path with worker-script execution. Phase 2.1 of the K4 Evidence Calibration Plan (deferred) covers methodological-family conditional null calibration.

---

## Unsupported-kind error handling

**Verified:** when a theorist proposes a kind not in `_VALID_CIPHER_KINDS`, the critic rejects with `dsl_untranslatable: cipher-fam` and the theory does not reach the dispatcher.

When a theorist proposes a kind in `_VALID_CIPHER_KINDS` but not in `_SUPPORTED_KINDS` (currently the empty set — no such kind exists), the dispatcher would raise `dsl_untranslatable` at translation time and the theory would be rejected at admissibility.

Cycle 201 of long_run 2026-05-03 saw a real `dsl_untranslatable` rejection: the theory "Compass-Rose Per-Position Variant Tape: Bearing-Indexed Vigenere/Beaufort/VarBeaufort Selection on Physical Slab Geometry" was rejected because per-position-variant-selection is not a valid kind. The rejection was clean and audit-visible.

**The fail-loud-and-honest contract is satisfied.**

---

## Legacy / deprecated MCP tools

**Audit:** `kryptosbot/_archive/` contains `campaign_v2.py` as an `ImportError` stub (per CLAUDE.md). No live import path delegates to MCP tools that bypass canonical scoring. The `dispatcher_doc_parity` test family (`kryptosbot/tests/test_dispatcher_doc_parity.py`) enforces the parity contract.

The `kernel-overrule` doctrine (per CLAUDE.md and `kryptosbot/ARCHITECTURE.md`) requires that every worker self-report is recomputed by the canonical kernel path. Workers cannot smuggle scores past the verifier; this was demonstrated in cycle 198 (lifetime kernel-overrule count = 6) where six worker self-reports were caught and overruled.

---

## K1/K2/K3 fitness check (Phase 6 dry-run)

Per CLAUDE.md pre-flight rule #10, when modifying kernel scoring or transforms, run:

```bash
PYTHONPATH=src python3 kryptosbot/self_test.py --panel all --mode dry-run
```

**Result (2026-05-04):**

```
=== Summary ===
  solved: 2/3  total_wall=0.05s
```

K1 and K2 both rediscovered cleanly. K3 is `discovered=False` after 500 cycles at peak score 4/20. **This is the documented expected behavior:** K3 in dry-run mode uses `keyed_columnar_double` with `max_cycles=500`, which does not solve K3 in the limited compute budget. K3's solver requires longer cycles + the Pollux-pre-procedural step. The dry-run is calibrated to detect *regressions* in K1/K2 specifically; K3 not solving in 500 cycles is not a regression.

Per `kryptosbot/self_test.py` doctrine, the framework's pre-flight contract is satisfied when K1 and K2 both rediscover. **The DSL/dispatcher pathway is not blocked by avoidable gaps for known-answer recovery.**

---

## Acceptance criteria check

Per the K4 Evidence Calibration Plan Phase 5:

| # | Criterion | Status |
|---|---|---|
| 1 | Every DSL-valid kind genuinely supported by dispatcher OR explicitly marked deferred | ✅ all 19 supported; none deferred |
| 2 | K1/K2/K3 self-test pathway not blocked by DSL gaps | ✅ K1/K2 rediscover; K3 in expected-not-solved state |
| 3 | Unsupported kinds fail loudly and honestly | ✅ verified via cycle 201 example |
| 4 | No legacy/deprecated MCP tool can silently bypass scoring | ✅ kernel-overrule path verified, parity test enforces |

**All acceptance criteria met.** No patches needed.

---

## What this audit does not cover

1. **Dispatcher translator correctness for individual kinds.** This audit verifies every DSL kind reaches the dispatcher; it does not verify each translator produces correct kernel TransformConfigs. That's covered by per-kind unit tests (referenced in the coverage matrix above).

2. **Performance / scaling characteristics.** Coverage is binary; performance is a separate concern.

3. **Methodological-family worker dispatch.** Phase 2.1 work, not Phase 5.

4. **Tier-1/Tier-2 elimination scope.** The DSL accepts kinds that have been single-layer-eliminated (e.g., periodic Vigenere on raw 97-char CT, eliminated for periods 1–26 by full Bean inequality set). This is correct: scope-elimination is about parameter space, not kind admissibility. The dispatcher accepts the proposal; the admissibility gate or kill criteria reject the result. See `docs/elimination_tiers.md`.

---

## Verdict

**DSL/dispatcher coverage is at 100% with no avoidable gaps.** Phase 5 acceptance criteria all met. The framework is ready for Phase 7 decision-memo without DSL-side blockers.

The remaining methodological-family conditional null work (Phase 2.1) is the highest-leverage outstanding item, not a DSL gap.

---

*Authored 2026-05-04 by Claude Opus 4.7 acting as principal research engineer / epistemic auditor. Cross-checks: `audit_dsl_dispatcher_semantics.py` output (committed), `_SUPPORTED_KINDS` and `_VALID_CIPHER_KINDS` from live source, `kryptosbot/self_test.py` dry-run output. Source-of-truth file pointers: `kryptosbot/job_dispatcher.py:_SUPPORTED_KINDS`, `kryptosbot/hypothesis_dsl.py:_VALID_CIPHER_KINDS`.*
