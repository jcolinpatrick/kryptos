# CONSENSUS_NULL_POSITIONS / NULL_PALETTE — Retirement Doctrine

**Status:** retired 2026-04-01 (palette) / 2026-04-14 (code-path quarantine landed)
**Claim ID:** `null_palette_retired` (kryptosbot/claims_registry.py) / `C-PALETTE-01` (docs/claims_registry.json)
**Scope:** entire palette / null-mask descriptive-anomaly family

## TL;DR

`NULL_PALETTE` (`frozenset("BGIKOWZ")`) and `CONSENSUS_NULL_POSITIONS`
(the 17-position frozenset) were derived from a retired hypothesis and
have no independent verification. They remain importable from
`src/kryptos/kernel/constants.py` for historical reproducibility only.
**Do not cite them as live evidence. Do not use them in live scoring,
canonical facts, or worker prompts.**

The 2026-04-14 quarantine closed every live code path that was still
treating them as ground truth. The kernel symbols themselves are
intentionally NOT physically removed — physical removal is out of scope
per Colin's explicit constraint. The retirement is enforced by labels
and gates at every consumer, not by symbol deletion.

## Why retired

- The 7-letter palette `{B,G,I,K,O,W,Z}` was proposed as a stego-layer
  constant based on SA optimization against an English-likeness proxy.
- Matched controls (April 2026) disproved its specificity: among 100
  random 7-letter palettes, `BGIKOWZ` ranked in the 1st percentile for
  cross-model mask agreement, and 76 of 133 single-letter-swap neighbors
  outperformed it. The convergence improvement from palette constraints
  is a generic combinatorial property, not evidence for these letters.
- The 17 consensus null positions are literally "where the palette
  letters live in CT, minus crib overlaps". They are not an independent
  observation — they are a downstream consequence of the retired
  palette hypothesis. "Consensus" was historical weight from repeated
  citation, not epistemic support.
- The earlier `p~3e-5` enrichment claim was post-hoc and traced to
  selection from positions already containing palette letters.

Primary sources:

- `docs/a1_score_conditioned_null_report.md` — original retirement
  analysis with matched-control tables.
- `docs/rival_audit_2026_04_01.md` — Frequentist Auditor objection.
- `docs/claims_registry.json` → `C-PALETTE-01` — structured registry
  entry with scope, red-team status, and quarantine pointer.
- `kryptosbot/claims_registry.py` → `null_palette_retired` — Python
  claim_policy entry that wires into critic / worker routing.
- `ops/site_builder/templates/methodology.html` /
  `ops/site_builder/templates/findings.html` — public-facing kryptosbot.com
  pages, retracted with matched-controls explanation.

## 2026-04-14 quarantine — what landed

Six commits, executed in one session, each green at the commit
boundary. The test suite goes from palette-as-confirmed to
palette-as-retired with no mid-state contradiction:

### Commit 1 — drop from canonical_facts and prompt surfaces

- `kryptosbot/controller.py` `_load_canonical_facts`: removed
  `NULL_PALETTE` and `CONSENSUS_NULL_POSITIONS` from the facts dict.
  Added docstring explaining the quarantine.
- `kryptosbot/controller.py` theorist prompt (~line 1191): removed the
  literal `{B,G,I,K,O,W,Z}` letter set from the "DO NOT propose"
  instruction. The prompt now cites `null_palette_retired` by claim_id
  and explicitly declines to name the letter set to avoid
  re-anchoring.
- `kryptosbot/research_tools.py` `get_canonical_facts` tool
  description: removed "null palette" from the exposed facts list and
  the "These are ground truth" phrasing. New wording explicitly
  excludes retired claims.
- `scripts/_infra/session_briefing.py`: removed the "Null palette / 17
  consensus positions" print from the CRITICAL CONSTANTS block. The
  briefing still surfaces the palette in its retirement section, which
  is the correct place.

### Commit 2 — kill dead `extract_nulls()`

- `src/kryptos/composition/scoring_bridge.py::extract_nulls`: previously
  imported `CONSENSUS_NULL_POSITIONS` lazily and stripped them from the
  ciphertext by default. Zero live callers (confirmed by grep). Body
  replaced with `raise NotImplementedError(...)` pointing at this
  doctrine file. Retained rather than deleted so any future rebased
  branch that expected the function to exist fails loudly with a
  retirement pointer instead of silently producing retired-mask output.

### Commit 3 — relabel stego.py status + atomic test update

- `src/kryptos/kernel/constraints/stego.py`: every `StegoProperty`
  returned by `palette_restriction`, `null_position_classification`,
  `polybius_generation`, and `crib_null_avoidance` now carries
  `status="retired"` unconditionally (was `"confirmed"` /
  `"confirmed" if observed else "failed"`). `artifact` pointer updated
  from `memory/confirmed_findings.md` to this file. Module docstring
  rewritten to explain the retirement.
- `src/kryptos/kernel/constraints/coupling.py`: module docstring
  relabeled. Functions themselves are palette-generic and were not
  touched — they take `palette` as a parameter and are fine.
- `tests/test_stego.py`: all five `test_status_is_confirmed` methods
  renamed to `test_status_is_retired` and their assertions flipped to
  `assert result.status == "retired"`. `test_all_confirmed` renamed to
  `test_all_retired`. Mathematical-invariant tests (p-values, observed
  counts, classification accuracy) were left intact — they still
  compute correct values of the retired statistic and are needed for
  historical reproducibility / regression.

### Commit 4 — gate compliance.py palette terms + kryptosbot shims

- `src/kryptos/kernel/scoring/compliance.py`: `NULL_PALETTE` removed
  from the module-level import. `check_coupling_constraints` now takes
  an explicit `palette` parameter with default `None`. When `palette`
  is `None`, `CxS-1` and `CxS-3` return `0.0` and a `DeprecationWarning`
  fires pointing at this doctrine. `CxS-2` and `CxS-4` are unaffected
  (palette-independent). `score_mechanism_compliance` plumbs `palette`
  through to the coupling checker.
- `tests/test_compliance.py`: tests that exercise palette-specific math
  now import `NULL_PALETTE` explicitly and pass it as
  `palette=NULL_PALETTE`. New regression tests:
  `test_palette_none_gives_zero_cxs1_cxs3_with_warning` and
  `test_real_keystream_no_palette_is_partial_not_compliant` pin the
  gate — any future reintroduction of the implicit default fails them.
- `kryptosbot/constants.py`: `NULL_PALETTE` and
  `CONSENSUS_NULL_POSITIONS` removed from the eager re-export. A
  module-level `__getattr__` now intercepts attribute access to those
  two names, emits a `DeprecationWarning`, and returns the value from
  the kernel on demand. Normal imports (`CT`, `CRIB_DICT`, etc.) are
  unaffected — `__getattr__` is only called on lookup miss.
- `kryptosbot/polybius_scorer.py`: has ZERO live callers per grep.
  Module-level `warnings.warn(...)` added at import time to surface any
  accidental revival. Math untouched for historical use.

### Commit 5 — registry updates, critic retired-revival matcher, API restart

- `docs/claims_registry.json` → `C-PALETTE-01`: scope expanded to
  explicitly include `CONSENSUS_NULL_POSITIONS` and the
  stego S2/S4/S5/S6 properties. `artifact` updated to include this
  doctrine file. `red_team_status` and `notes` document the 2026-04-14
  quarantine with file-level pointers.
- `kryptosbot/critic.py`: new `_detect_retired_palette_revival()`
  helper. Matches within 100-character windows of trigger tokens
  (`null`, `palette`, `mask`, `filler`, `separator`, `stego`,
  `letter set`, `letter subset`) and flags any theory containing >= 5
  of the 7 retired palette letters `{B,G,I,K,O,W,Z}` as single-letter
  tokens. `TheoryCritic.evaluate()` calls this as "Check 2.5" before
  duplicate detection and returns `REJECT_ELIMINATED` with a
  quarantine-specific reason if matched. Sanity tests show 4/4
  positive cases flagged and 4/4 negative cases clean.
- `kryptosbot/audits/day7_output/README.md`: new quarantine note
  marking `queue.json` / `queue.md` as frozen pre-retraction audit
  history; must not be loaded as live theorist context.
- `ops/api/classifier.py`: already hotfixed prior to Commit 1 — the
  `COMMON_ELIMINATIONS` prompt block moved the palette from
  "WHAT REMAINS OPEN" to a new `RETIRED HYPOTHESES` section. **The
  kryptosbot-api systemd service must be restarted for the hotfix to
  take effect in the running process.**

### Commit 6 — relax `_verify()` assertions

- `src/kryptos/kernel/constants.py::_verify`: the `len(NULL_PALETTE) == 7`
  and `len(CONSENSUS_NULL_POSITIONS) == 17` assertions were relaxed to
  `len(...) in (0, 7)` and `len(...) in (0, 17)`. The current state
  still has 7 and 17 (physical removal is out of scope), so this is a
  no-behavior-change commit. It exists as preparation so that any
  future physical-removal step would not crash every import in the
  project. A retirement-aware comment block was added above the
  constants explaining the status.

## What was deliberately NOT changed

- **The kernel constants themselves.** `NULL_PALETTE` and
  `CONSENSUS_NULL_POSITIONS` still hold their historical values.
  Physical removal (Commit 7 in the red-team's proposed sequence) was
  explicitly rejected by Colin. Rationale: renaming or moving symbols
  creates a two-source-of-truth footgun (cf. the
  `exhaustion_log.json` vs `scripts/EXHAUSTION.json` incident), and
  the retirement is adequately enforced at every consumer via labels
  and gates.
- **`kryptosbot/registries.py`** `null_palette_retired` claim_policy
  entry — already correctly placed.
- **`kryptosbot/oracle.py`** `RETIRED_ANOMALY_IDS` list — already
  correctly placed. Note that `oracle.test_stego_placement_rule` still
  compares against `CONSENSUS_NULL_POSITIONS` as an answer key; this
  is a known follow-up item flagged in the red-team report but not in
  scope for the 2026-04-14 quarantine. It is only reachable via
  explicit caller opt-in and does not poison the live pipeline.
- **Archived scripts under `scripts/`** (~80 files) that import the
  retired constants. The `stego.py` label change means any
  `StegoProperty` they produce is now tagged `status="retired"`
  automatically — no per-script edit is needed to prevent them from
  emitting "confirmed" artifacts.
- **`kryptosbot/audits/day7_output/queue.json`** — frozen as audit
  history. The sibling `README.md` flags it as quarantined.

## Test state after the quarantine

Full project test suite: **1478 kernel tests + 261 kryptosbot tests =
1739 tests passing**, zero failures.

Expected warnings:

- 6× `DeprecationWarning` in `tests/test_compliance.py` structural
  tests that deliberately exercise palette-independent invariants
  without passing a palette. This is the gate firing exactly where it
  should; a future regression that silently reintroduces the default
  would make these warnings disappear and the new regression tests
  would fail.

## Open follow-ups (not in quarantine scope)

- **API service restart.** The `ops/api/classifier.py` hotfix is in the
  file on disk but the running `kryptosbot-api.service` process still
  has the pre-hotfix classifier context loaded (service up 5+ days).
  Restart required: `sudo systemctl restart kryptosbot-api.service`.
- **`kryptosbot/oracle.py::test_stego_placement_rule`** still compares
  against `CONSENSUS_NULL_POSITIONS` as an answer key. Safe because
  the function is only callable via explicit opt-in, but worth
  relabeling or gating in a follow-up.
- **Superpowers plans** under `docs/superpowers/plans/` and
  `docs/superpowers/specs/` reference `NULL_PALETTE` /
  `CONSENSUS_NULL_POSITIONS` in code blocks. These are already
  demoted (see `docs/superpowers/README.md` banner) and not
  authoritative, but a future doc-hygiene pass could add an explicit
  retirement warning to each.
- **Physical removal (Commit 7).** Red-team argument for skipping this
  is documented above and in the red-team report. If Colin later
  authorizes it, the preparation work in Commit 6 means the physical
  removal itself is just: (a) empty the frozensets in
  `constants.py`, (b) delete the retirement block after the symbols,
  (c) update `test_constants.py` `== 7` / `== 17` to `== 0`,
  (d) delete `kryptosbot/constants.py` `__getattr__` hook,
  (e) delete `kryptosbot/polybius_scorer.py` and any callers.

## Related memory

- `memory/retired/README.md` — retired research notes index
- `memory/project_day7_spot_audit_complete.md` — Day 7 audit cutover
- `memory/feedback_accept_specific_disproofs.md` — doctrine against
  pivoting when a mechanism is disproved (applies to any future
  attempt to rehabilitate the palette under a new framing)

## Authored

2026-04-14, as the durable in-repo pointer for the quarantine
mechanic. Referenced by docstrings in: `kernel/constants.py`,
`kernel/constraints/stego.py`, `kernel/constraints/coupling.py`,
`kernel/scoring/compliance.py`, `composition/scoring_bridge.py`,
`kryptosbot/controller.py`, `kryptosbot/research_tools.py`,
`kryptosbot/constants.py`, `kryptosbot/polybius_scorer.py`,
`kryptosbot/critic.py`, `tests/test_stego.py`,
`tests/test_compliance.py`, `scripts/_infra/session_briefing.py`,
`kryptosbot/audits/day7_output/README.md`,
`docs/claims_registry.json`.
