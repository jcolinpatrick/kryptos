# PR4 — Route Profile Redefinition (serpentine, recovery target) (design)

**Date:** 2026-05-26
**Status:** approved design, pre-implementation
**Builds on:** PR1 (coverage-audit), PR2 (scheduler), PR3 (real-recovery — commits up to `db4b031`)
**Closes:** the PR3 documented follow-up — `T1_ABSCISSA_ROUTE`'s `keyword=ABSCISSA` obligation had no executable mapping in the dispatcher's route model, so it was the one available profile left at `emitted_and_admissible`.

---

## 1. Problem

PR3 made quagmire and columnar profiles real-recovery targets but had to leave the
route profile at `emitted_and_admissible`: the dispatcher's `route` translator has no
keyword concept — it requires `variant` ∈ {serpentine, spiral, diagonal,
diagonal_canonical} plus a grid (rows/cols or width). `keyword=ABSCISSA` on a route
layer is meaningless there, so the profile could never dispatch or recover. The
registry therefore ended PR3 non-uniform: two recovery targets + one admissible-only
route + one blocked.

## 2. Goal

Redefine the route profile as a genuine, dispatch-executable **serpentine** route
transposition that recovers a synthetic ciphertext (crib_score ≥ SIGNAL), making it a
PR3-style recovery target. This preserves route-KIND coverage in the registry (route
is a distinct dispatcher kind worth covering) and removes the last admissible-only
gap among available profiles.

## 3. Scope decisions (decided)

1. **Make it a real route profile** (not an ABSCISSA columnar; not both). Route-kind
   coverage is the point; the ABSCISSA label was never a valid route key and is
   dropped.
2. **Variant = serpentine.** The dispatcher itself cites Sanborn's "serpentine copper
   screen ... with Vigenère's Tableaux" as the natural Kryptos serpentine anchor, so
   it is thematically consistent with the other anchor-flavored profiles. It shares
   the word "serpentine" with `T1_SERPENTINE_QUAGMIRE` (different dispatcher kind, no
   functional conflict).
3. **Recovery target.** Flows through PR3's existing recovery-target path (generate
   synthetic CT → dispatch → score → `satisfied`). No generator or scheduler change.

## 4. Components

### 4.1 `synthetic_profiles.py` — redefine the profile

Rename `_T1_ABSCISSA_ROUTE` → `_T1_SERPENTINE_ROUTE`, `profile_id`
`T1_ABSCISSA_ROUTE` → `T1_SERPENTINE_ROUTE`, and the `_REGISTRY` key. New shape:

- **Obligation:** `ParameterObligation(expected_family="transposition_route",
  expected_layer_kind="route", expected_layer_variant=None,
  expected_parameter_axis="variant", expected_parameter_value="serpentine")`.
  (Drops the `keyword=ABSCISSA` obligation. The matcher reads the `variant` param,
  which PR1's `_layer_to_record` exposes from the route layer's `variant` ParamRange.)
- **`closing_spec`:** one `route` layer, `alphabet="AZ"`, params
  `variant=["serpentine"]`, `rows=[10]`, `cols=[10]` (10×10 = 100 ≥ 97 so the grid
  covers every position). `null_baseline` + `compute_budget_cpu_minutes=30` as the
  other profiles. The route translator emits a `transposition_full` perm step; the
  generator's per-step `direction="encrypt"` override produces the forward serpentine
  perm, and the decrypt dispatch inverts it — guaranteed round-trip.
- **`recovery_target=True`.**
- Description + notes rewritten for the serpentine route (cite the Sanborn
  serpentine-screen anchor); remove all ABSCISSA references.

### 4.2 No generator or scheduler change

`coverage_synthetic.generate_synthetic_challenge` and
`coverage_scheduler.run_coverage_schedule` already handle any single-layer recovery
target. The redefined route profile is single-layer and recovery_target, so it uses
the existing path unchanged.

### 4.3 Consequence: the `emitted_and_admissible` branch loses its real-profile user

After this change the available profiles are quagmire, columnar, and serpentine-route
— **all recovery targets**. No real profile exercises the scheduler's non-recovery
(`emitted_and_admissible`) branch. That branch stays in code (it is correct and needed
for any future non-recovery available profile). To keep it tested, the two PR3 tests
that used the route profile for the non-recovery / no-execution path are repointed to
an **inline non-recovery-target available profile fixture** built in the test module
(a minimal `SyntheticProfile(status="available", recovery_target=False, …)` with a
valid columnar `closing_spec` and obligation). This keeps branch coverage independent
of any registry profile being non-recovery.

## 5. Testing

- **Registry IDs:** `test_registry_exposes_pr1_profile_ids` updated — replace
  `T1_ABSCISSA_ROUTE` with `T1_SERPENTINE_ROUTE`; new sorted order is
  `[T1_BERLINCLOCK_COLUMNAR, T1_SERPENTINE_QUAGMIRE, T1_SERPENTINE_ROUTE,
  T1_TAPE_K3PT]`.
- **Recovery targets:** `test_recovery_targets_are_quagmire_and_columnar` becomes a
  three-target assertion `{T1_SERPENTINE_QUAGMIRE, T1_BERLINCLOCK_COLUMNAR,
  T1_SERPENTINE_ROUTE}` (rename the test accordingly).
- **Obligation shape:** a test pins the route obligation
  (`kind=route`, axis=`variant`, value=`serpentine`).
- **Round-trip:** add `T1_SERPENTINE_ROUTE` to the `test_coverage_synthetic`
  round-trip loop — generated CT decrypts via the closing_spec to `best_score == 24`.
- **Scheduler `satisfied`:** add `T1_SERPENTINE_ROUTE` to the recovery-target
  `satisfied` / `best_score == 24` scheduler test.
- **Replace `test_route_stays_emitted_and_admissible`:** a new test
  `test_non_recovery_profile_reaches_emitted_and_admissible` builds an inline
  non-recovery-target available profile and asserts its obligation reaches
  `emitted_and_admissible` (`passed True`).
- **Repoint `test_run_coverage_schedule_never_executes_kernel`:** use the same inline
  non-recovery fixture (assert `execute` is never called on the non-recovery path),
  since the route profile now legitimately executes.

## 6. Safety / scope guards

- No generator/scheduler/run_controller code change — pure profile + test edits.
- `T1_TAPE_K3PT` stays blocked; no real K4 CT; synthetic-ledger isolation unchanged.
- The `emitted_and_admissible` branch remains in code and remains tested (via fixture).
- No K4-solve capability claimed.

## 7. Explicitly NOT in scope

- Re-introducing ABSCISSA as a separate profile (could be a future columnar profile;
  not needed now — YAGNI).
- Other route variants (spiral/diagonal); serpentine is sufficient for route-kind
  coverage.
- Unblocking `T1_TAPE_K3PT`.
