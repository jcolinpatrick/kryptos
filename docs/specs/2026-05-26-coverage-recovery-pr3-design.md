# PR3 — Synthetic-CT Real-Recovery Coverage (design)

**Date:** 2026-05-26
**Status:** approved design, pre-implementation
**Builds on:** PR1 (coverage-audit), PR2 (deterministic coverage scheduler — commits `72c1526`..`908fe85`)
**Spec lineage:** `docs/specs/2026-05-25-coverage-scheduler-pr2-design.md`

---

## 1. Problem

PR2's coverage scheduler closes a profile's obligation at the **emitted + admissible**
boundary: it builds the explicit `closing_spec`, runs the dispatcher's pre-kernel
preamble (`_expand_procedural_layers` → `check_admissibility`), and stops before the
kernel. That proves the obligation spec is *generated and accepted*, but not that the
mechanism actually *works* — admissibility only validates DSL shape, translation-path
support, and budget; it never executes the translator or scores anything.

Concretely, PR3's design exploration found that PR2's columnar and route
`closing_spec`s are **admissible but not executable**: the dispatcher's `columnar`
translator needs `width` + `col_order` (not `keyword`), and its `route` translator
needs `variant` (serpentine/spiral/diagonal) + grid (not a keyword at all). A
keyword-only columnar/route spec passes admissibility yet would fail real dispatch.
Only the quagmire `closing_spec` is genuinely executable today.

## 2. Goal

Upgrade the closure for **recovery-target** profiles from "admissible" to
**real recovery**: generate a synthetic ciphertext from the profile's mechanism,
dispatch the `closing_spec` against it, and require the kernel scoring path to
actually recover the known plaintext (crib_score ≥ SIGNAL). This exercises the full
translate + decrypt + score pipeline on a synthetic-but-real ciphertext — catching
translator, crib-alignment, and scoring bugs that admissibility-only misses.

The synthetic ciphertext is generated from a known plaintext via the mechanism; the
real K4 ciphertext is never touched.

## 3. Scope decisions (decided)

1. **Closure = real recovery (scoring)**, not just admissible. Verdict uses PR1's
   existing ladder: `best_score ≥ SIGNAL (18)` → `satisfied`; `< 18` →
   `tested_but_no_signal` (a genuine bug signal for a recovery target).
2. **Synthetic CT is generated** via the kernel's own transform pipeline run in
   ENCRYPT direction, so the same pipeline in decrypt direction provably recovers it
   (guaranteed round-trip). Not hand-authored; not via K4Bench's loader/override
   machinery.
3. **Scoring is the default for recovery-target profiles** under
   `--coverage-scheduler-enabled`. No new flag. `emitted_and_admissible` (PR2) remains
   the verdict for non-recovery-target available profiles (route).
4. **One canonical 97-char plaintext**, shared across profiles, with cribs at the
   standard 24 K4 crib positions (so crib_score is out of 24 and a correct round-trip
   reaches 24 ≥ 18).
5. **Coverage = quagmire + columnar real recovery; route stays emitted+admissible.**
   Route's `keyword=ABSCISSA` obligation has no executable mapping in the dispatcher's
   route model, so it is left at PR2's emitted+admissible with a documented
   limitation (follow-up: redefine the route profile). `T1_TAPE_K3PT` stays blocked.
6. **Per-profile `recovery_target` marker, fail-closed.** A "try-to-score-else-admit"
   fallback would be fail-open: if a recovery target's CT generation broke, it would
   silently downgrade to `emitted_and_admissible` and still pass, masking the bug.
   Instead, recovery targets are marked explicitly; generation/dispatch failure on a
   recovery target is a hard failure, never a downgrade.

## 4. Components

### 4.1 `synthetic_profiles.py` — profile extension

- Add field `recovery_target: bool = False` to `SyntheticProfile`.
  - `T1_SERPENTINE_QUAGMIRE` → `True`.
  - `T1_BERLINCLOCK_COLUMNAR` → `True`.
  - `T1_ABSCISSA_ROUTE` → `False` (stays emitted+admissible).
  - `T1_TAPE_K3PT` → `False` (blocked).
- New `__post_init__` invariant: `recovery_target` implies `status == "available"` and
  a non-empty `closing_spec`. A `blocked` profile must not be a recovery target.
- Enrich the **columnar** `closing_spec` so it is dispatch-executable while still
  satisfying the keyword obligation. The columnar layer params become:
  - `keyword=["BERLINCLOCK"]` (obligation axis — unchanged),
  - `width=[11]`,
  - `col_order=[<keyword_to_order("BERLINCLOCK", 11) as a list>]`.
  The dispatcher reads `width`/`col_order`; the obligation matcher reads `keyword`;
  the extra `keyword` param is ignored by the translator. The `col_order` value is
  computed once from `kryptos.kernel.transforms.transposition.keyword_to_order` and
  written as a literal list in the registry (auditable; not computed at import).
- Quagmire's `closing_spec` is already executable — unchanged.
- Add `recovery_target` to `to_dict`.

### 4.2 `coverage_synthetic.py` — new module (synthetic-CT generator)

- Module constant `CANONICAL_PLAINTEXT`: a fixed 97-letter A–Z plaintext.
- Crib positions: the standard 24 K4 crib positions (0-indexed: 21–33 and 63–73),
  imported from the canonical kernel source `kryptos.kernel.constants.CRIB_POSITIONS`
  rather than re-listed. (Importing the indices does not use the real K4 ciphertext —
  only the integer positions; the synthetic CT and cribs come from
  `CANONICAL_PLAINTEXT`.)
- `generate_synthetic_challenge(closing_spec: dict) -> tuple[str, dict[int, str]]`:
  1. Parse via `HypothesisSpec.from_dict`; expand procedural layers (none expected).
  2. Get the single-config binding via `_enumerate_bindings(spec)` (the closing_spec
     pins each param to one value, so it yields exactly one binding tuple) and call the
     dispatcher's `_build_pipeline_config(spec, bindings, text_length=97)` to get the
     pipeline_dict.
  3. Set each STEP's `params["direction"] = "encrypt"`. NOTE: `build_pipeline` ignores
     `PipelineConfig.direction` — the compose step builders read `direction` from each
     step's own params (transposition: default `"undo"`=decrypt, so any non-`"undo"`
     value encrypts; vigenere/quagmire/bifid: default `"decrypt"`, so any
     non-`"decrypt"` value encrypts). The literal `"encrypt"` selects the encrypt
     branch uniformly across all step types. (The decrypt dispatch via `execute()`
     builds its own pipeline_dict with the default directions, using the SAME
     `_translate_layer` output, so encrypt and decrypt are true inverses.)
  4. Build a `PipelineConfig` from the (direction-patched) steps — mirroring
     `_evaluate_one`'s `TransformConfig`/`PipelineConfig` construction — call
     `kryptos.kernel.transforms.compose.build_pipeline`, and apply to
     `CANONICAL_PLAINTEXT` → synthetic CT (length 97).
  5. `crib_dict = {pos: CANONICAL_PLAINTEXT[pos] for pos in CRIB_POSITIONS}`.
  6. Return `(ct, crib_dict)`.
- Single-layer specs only. If a spec has >1 layer, raise (multi-layer encrypt-order is
  out of scope — the two recovery targets are single-layer).

### 4.3 `coverage_scheduler.py` — scoring path

- `run_coverage_schedule`, for an available profile, branches on `recovery_target`:
  - **`recovery_target == True`:** generate `(ct, cribs)` via
    `coverage_synthetic.generate_synthetic_challenge(closing_spec)`; call
    `job_dispatcher.execute(spec, challenge_ciphertext=ct, challenge_crib_dict=cribs,
    bench_mode=True, parallel=False)`; record `record_emitted_spec` + a
    `record_dispatcher_outcome(admissibility_verdict="ok", admissibility_only=False,
    total_tested=<JobResult.total_tested>, best_score=<JobResult.best_score>)`. PR1's
    ladder yields `satisfied` / `tested_but_no_signal`. **Fail-closed:** if generation
    or `execute` raises, record a hard failure (not an admissibility downgrade) — the
    report `passed` is False with a `forced_fail_reason` naming the failure.
  - **`recovery_target == False` (route):** unchanged PR2 emitted+admissible path.
- A small helper reads `best_score` / `total_tested` from the `JobResult` (use the
  documented `JobResult` fields; the best candidate's `crib_score` is the score).

### 4.4 No `run_controller.py` change required

PR2 already routes `--synthetic-profile --coverage-scheduler-enabled` through
`run_coverage_schedule`; PR3 changes only what that function does internally. The
existing `finally` block still writes the report.

## 5. Safety invariants (asserted in code + tests)

- Never touches the real K4 ciphertext: the synthetic CT is produced from
  `CANONICAL_PLAINTEXT` via the mechanism, and `execute(challenge_ciphertext=...)`
  decrypts that, never the kernel `CT`.
- Never writes the real/default ledger (synthetic ledger only, per PR1/PR2).
- `bench_mode=True` isolates from the real-K4 exhaustion log.
- No LLM/API call; the kernel runs only on the 97-char synthetic CT (1 config).
- Fail-closed for recovery targets (no silent downgrade to admissibility).

## 6. Testing

New `kryptosbot/tests/test_coverage_synthetic.py` + additions to
`test_coverage_scheduler.py` / `test_synthetic_profiles.py`:

1. **Round-trip** — for each recovery target, decrypting `generate_synthetic_challenge`'s
   CT with the closing_spec recovers `CANONICAL_PLAINTEXT`, and `crib_dict` equals the
   canonical PT at the 24 positions.
2. **Recovery-target closing_specs are executable** — `_build_pipeline_config` +
   translation succeed (no `DispatcherError`) for quagmire and columnar.
3. **Scheduler real recovery** — `run_coverage_schedule` for quagmire and for columnar
   yields a report whose obligation cause is `satisfied` (PR1's
   `REJECTION_CAUSE_SATISFIED`) with `passed is True`, best_score == 24.
4. **Route unchanged** — `T1_ABSCISSA_ROUTE` still yields `emitted_and_admissible`,
   `passed is True`; it is NOT a recovery target.
5. **Fail-closed** — a deliberately broken recovery-target spec (e.g. a closing_spec
   whose mechanism can't recover) is reported as failure (`passed is False`,
   `tested_but_no_signal` or a hard generation/dispatch failure), NOT silently
   downgraded to `emitted_and_admissible`.
6. **No real CT on the recovery path** — assert `execute` is called with a non-None
   `challenge_ciphertext` (spy/monkeypatch), so the kernel `CT` is never the input.
7. **Registry invariant** — every `recovery_target` profile is `available` with a
   non-empty `closing_spec`; blocked/route profiles are not recovery targets.
8. **End-to-end smoke** (Task in plan, run by controller): `--synthetic-profile
   T1_SERPENTINE_QUAGMIRE --coverage-scheduler-enabled` writes a `coverage_report.v2`
   whose obligation cause is now `satisfied`; real ledger mtime untouched.

## 7. Explicitly NOT in scope (YAGNI / scope guard)

- Route real recovery — documented limitation; `keyword=ABSCISSA` has no executable
  route mechanism. Follow-up: redefine the route profile (real route variant or
  columnar-keyed) in a later PR.
- Multi-layer encrypt-order (step reversal) — both recovery targets are single-layer.
- Unblocking `T1_TAPE_K3PT` (finite-tape search model).
- No real K4 search; no LLM theorist; no K4Bench loader/override machinery.
- **No K4-solve capability is claimed.** This validates synthetic-mechanism recovery
  against an isolated ledger; it makes no statement about the real K4 plaintext.
