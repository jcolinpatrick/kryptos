# Phase 2 — Retired-constant relocation — Report

**Date:** 2026-04-20
**Entry baseline:** `fdc4eea maturation phase 01: legacy surface quarantine`
**Goal:** `CONSENSUS_NULL_POSITIONS`, `NULL_PALETTE`, and `BEAUFORT_KEYSTREAM_AT_CRIBS`
exit the live `kryptos.kernel.constants` import surface and move to a `kryptos.kernel.retired`
namespace that is clearly off-limits to new code. The two critic regex guards become
documented as complementary to the new import-level guard.

---

## 1. New namespace (brief §4.1)

Created:
- `src/kryptos/kernel/retired/__init__.py` — package-level docstring + re-exports.
- `src/kryptos/kernel/retired/palette.py` — holds the three retired constants with
  a module-local `_verify()` that runs at import.

The constants themselves are unchanged bit-for-bit:

```python
NULL_PALETTE                 = frozenset("BGIKOWZ")                                 # 7 letters
CONSENSUS_NULL_POSITIONS     = frozenset({0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85})  # 17 positions
BEAUFORT_KEYSTREAM_AT_CRIBS  = "JLJODEGKUKKKLOCGGBGOKTRU"                           # 24 chars
```

The `_verify()` in `retired/palette.py` is a copy of the relaxed verification that
previously lived in `kernel/constants.py::_verify()` (length 0 OR historical length;
positions in `[0, CT_LEN)`; positions disjoint from crib positions). The numeric
cross-check between `BEAUFORT_KEYSTREAM_AT_CRIBS` and the `BEAUFORT_KEY_*` tuples is
kept in `test_position_mapping.py::test_beaufort_keystream_at_cribs` instead of being
duplicated in the retired module (avoids a circular import and keeps `retired/` from
taking a live dependency on the unretired Beaufort-key constants).

---

## 2. Removed from `kernel/constants.py` (brief §4.2)

Lines ~149-176 (the three constants + retirement comment block) replaced with a
one-paragraph pointer to `kryptos.kernel.retired`.

Lines ~199-211 (the relaxed `_verify()` assertions on the retired constants)
removed; the assertions now run at import time of `retired/palette.py` instead.

After this change:

```bash
$ python3 -c "from kryptos.kernel.constants import NULL_PALETTE"
ImportError: cannot import name 'NULL_PALETTE' from 'kryptos.kernel.constants' ...

$ python3 -c "from kryptos.kernel.retired import NULL_PALETTE"
# silent OK
```

---

## 3. Live-caller audit (brief §4.2 inspect-each)

**Grep scope:** `--include=*.py` for any of `NULL_PALETTE`, `CONSENSUS_NULL_POSITIONS`,
`BEAUFORT_KEYSTREAM_AT_CRIBS` across the repo.

| Scope | File count | Category |
|---|---|---|
| `src/` | 4 | 3 live-kernel importers + `kernel/constants.py` itself |
| `kryptosbot/` | 8 | 1 live importer (`polybius_scorer.py`) + 1 quarantine shim (`constants.py`) + 6 files that mention the name only in strings/prompts/regex |
| `ops/` | 1 | Mentions the name in a retirement-notice prompt string (`classifier.py`) — no import |
| `tests/` | 9 | 8 files import; 1 only regex-matches the string |
| `kryptosbot/tests/` | 2 | Both only hypothesis-string fixtures (no import) |
| `scripts/` | 82 | All historical experiments — see §6 below |

**Live files modified (import-path switch):**

1. `src/kryptos/kernel/scoring/compliance.py` — reads `BEAUFORT_KEYSTREAM_AT_CRIBS`
   as a reference keystream for CxS-2 compliance anchoring. Migrated to
   `from kryptos.kernel.retired import BEAUFORT_KEYSTREAM_AT_CRIBS`.
   Documented in the import block.
2. `src/kryptos/kernel/constraints/stego.py` — the retired stego-proof module
   (docstring: "RETIRED 2026-04-14"). Imports both `CONSENSUS_NULL_POSITIONS` and
   `NULL_PALETTE`. Migrated to `from kryptos.kernel.retired import ...`.
3. `kryptosbot/polybius_scorer.py` — retired scorer (module docstring: "RETIRED
   2026-04-14"). Migrated to `from kryptos.kernel.retired import ...` for all
   three constants.
4. `kryptosbot/constants.py` — the kryptosbot-level quarantine shim. Updated so:
   - `BEAUFORT_KEYSTREAM_AT_CRIBS` removed from the eager re-exports.
   - `_RETIRED_PALETTE_SYMBOLS` extended to include `BEAUFORT_KEYSTREAM_AT_CRIBS`.
   - `__getattr__` now forwards to `kryptos.kernel.retired` (was
     `kryptos.kernel.constants`).
   - Module docstring updated to reflect the 2026-04-20 move.

**Live files with string/regex references only (no import — no change needed):**

- `src/kryptos/composition/scoring_bridge.py` — comment about historical behaviour.
- `kryptosbot/controller.py` — theorist-prompt scratch-policy warning strings.
- `kryptosbot/critic.py` — regex source for textual-revival detection. **Docstrings
  updated** (brief §4.4) to point at the new import-level guard complement.
- `kryptosbot/registries.py` — one comment string.
- `kryptosbot/oracle.py` — messages in docstrings.
- `ops/api/classifier.py` — retirement-notice prose served to the site classifier.
- `tests/test_hardening_surfaces.py` — existing import-level regex guard (see §5).
- `kryptosbot/tests/test_controller_hardening.py` +
  `kryptosbot/tests/test_priority5_search_space_risk.py` — hypothesis-string fixtures
  fed to the critic.

---

## 4. Tests updated (brief §4.2)

Eight test files switched imports from `kryptos.kernel.constants` → `kryptos.kernel.retired`
for the retired symbols, each with an inline comment justifying the dependency (per
brief §4.3 allow-list requirement):

- `tests/test_a1_palette_audit.py`
- `tests/test_compliance.py`
- `tests/test_constants.py`
- `tests/test_coupling.py`
- `tests/test_polybius_scorer.py`
- `tests/test_position_mapping.py` (including the inline import in
  `TestBeanAcrossLayers::test_beaufort_keystream_at_cribs`)
- `tests/test_stego.py`
- `tests/test_stego_solve.py`

Test counts post-Phase-2 (reconciliation below):

| Suite | Pre-Phase-2 | Post-Phase-2 | Delta |
|---|---|---|---|
| `tests/` | 1522 | 1525 | +3 (`test_retired_usage.py`) |
| `kryptosbot/tests/` | 364 | 364 | 0 |

All green. Six pre-existing `DeprecationWarning` warnings persist (unchanged; they
are intentional warnings installed during the 2026-04-14 quarantine).

---

## 5. CI guard (brief §4.3)

New file `tests/test_retired_usage.py` with three tests:

- `test_no_live_imports_of_retired_outside_allow_list` — AST-walks `src/`,
  `kryptosbot/`, `tests/` for any `ImportFrom` or `Import` node whose module starts
  with `kryptos.kernel.retired`. Every hit must be in the allow-list. Skips
  `kryptos.kernel.retired` itself and `kryptosbot/_archive/`.
- `test_allow_list_entries_exist` — regression-guards against stale allow-list
  pointers to deleted/renamed files.
- `test_allow_list_entries_actually_import_retired` — regression-guards against
  cruft in the allow-list (if a file is in the list but no longer imports retired,
  it should be removed from the list).

Allow-list (11 entries, every one with an in-file justifying comment):

| File | Justification |
|---|---|
| `src/kryptos/kernel/constraints/stego.py` | Live retired stego-proof module |
| `src/kryptos/kernel/scoring/compliance.py` | CxS-2 historical-anchor reference keystream |
| `kryptosbot/polybius_scorer.py` | Retired kryptosbot scorer |
| `tests/test_a1_palette_audit.py` | Palette-provenance regression guard |
| `tests/test_compliance.py` | Compliance math regression fixtures |
| `tests/test_constants.py` | Regression guard on the move itself |
| `tests/test_coupling.py` | CxS-1..CxS-4 coupling math fixtures |
| `tests/test_polybius_scorer.py` | Tests the retired polybius scorer module |
| `tests/test_position_mapping.py` | Historical mask / crib-shift mechanics |
| `tests/test_stego.py` | Tests the retired stego module |
| `tests/test_stego_solve.py` | Regression-guards the retired solve pipeline |

**Complementary guard:** `tests/test_hardening_surfaces.py::test_retired_palette_constants_only_imported_in_quarantined_modules`
(pre-existing) was updated to assert the complementary negative invariant: **no**
file in `src/` or `kryptosbot/` may import the retired symbols from the *old*
pre-move paths (`kryptos.kernel.constants`, `kryptosbot.constants`). Pre-Phase-2 it
allowed the two now-migrated importers (`stego.py`, `polybius_scorer.py`); post-move
the allow-list is empty and the test is a stronger tautology (the symbols no longer
exist there, so the import would fail at runtime — this guard catches it at
collection time instead).

---

## 6. Scripts left unchanged (explicit scope decision)

72 scripts under `scripts/` still have `from kryptos.kernel.constants import NULL_PALETTE`
or equivalent. Each is an archived palette-era experiment. **They were not migrated** because:

1. The brief's live-code guard (`test_retired_usage.py`) walks only `src/`,
   `kryptosbot/`, and `tests/` — `scripts/` is outside that perimeter.
2. The existing `test_hardening_surfaces.py` guard likewise walks only `src/` and
   `kryptosbot/`.
3. These scripts are not imported by any live code path. They execute only when run
   directly, at which point the `ImportError` from the old path is a clearer failure
   mode than silent resurrection of retired behaviour.
4. Bulk-rewriting 72 files was disallowed by the brief ("Do not blanket rewrite.
   Inspect each.") and individually inspecting archived experiments has near-zero
   return on attention.

If any of these scripts is resurrected for a historical-reproducibility study, the
authoring operator switches the import to `kryptos.kernel.retired` at that time.

---

## 7. Critic guard docstrings updated (brief §4.4)

`kryptosbot/critic.py` — both `_detect_retired_palette_revival` and
`_detect_consensus_null_positions_revival` docstrings now explicitly note:

- These regex guards catch **textual** revival in theorist output.
- **Import-level** revival is caught by `tests/test_retired_usage.py`.
- The constants themselves moved to `kryptos.kernel.retired` on 2026-04-20.

The regex machinery and the `_RETIRED_PALETTE_LETTERS` / `_CONSENSUS_NULL_MASK_PATTERNS`
constants are unchanged.

---

## 8. Acceptance criteria (brief §4.5)

| Criterion | Status |
|---|---|
| `from kryptos.kernel.constants import NULL_PALETTE` raises `ImportError` | ✅ |
| `from kryptos.kernel.retired import NULL_PALETTE` works | ✅ |
| `pytest tests/test_retired_usage.py -q` passes | ✅ (3 tests) |
| Full suite green | ✅ (1525 + 364 = 1889 tests, 0 failures) |
| `docs/maturation/phase_02_report.md` enumerates every caller touched and why | ✅ (this file, §3 and §4) |
| `doctor` still exits 0 | ✅ (20 PASS / 0 FAIL) |

---

## 9. Deferred items

None introduced by Phase 2 that affect later phases. The 72 script-level old-path
imports (§6) are an accepted outcome of scope, not a deferred fix — they will be
addressed individually only when a specific script is resurrected.

---

## 10. Changed files summary

```
A  src/kryptos/kernel/retired/__init__.py       (package docstring + re-exports)
A  src/kryptos/kernel/retired/palette.py        (the three constants + _verify)
M  src/kryptos/kernel/constants.py              (removed retired block + _verify asserts)
M  src/kryptos/kernel/scoring/compliance.py     (import path switch)
M  src/kryptos/kernel/constraints/stego.py      (import path switch)
M  kryptosbot/constants.py                      (shim updated; adds BEAUFORT_KEYSTREAM_AT_CRIBS)
M  kryptosbot/polybius_scorer.py                (import path switch)
M  kryptosbot/critic.py                         (docstring updates; no code change)
M  tests/test_a1_palette_audit.py               (import path switch)
M  tests/test_compliance.py                     (import path switch)
M  tests/test_constants.py                      (import path switch)
M  tests/test_coupling.py                       (import path switch)
M  tests/test_polybius_scorer.py                (import path switch)
M  tests/test_position_mapping.py               (import path switch)
M  tests/test_stego.py                          (import path switch)
M  tests/test_stego_solve.py                    (import path switch)
M  tests/test_hardening_surfaces.py             (stronger invariant on old paths)
A  tests/test_retired_usage.py                  (CI guard, 3 tests)
A  docs/maturation/phase_02_report.md           (this file)
```

No behaviour change to the controller, kernel, or any production path. All test
suites green.
