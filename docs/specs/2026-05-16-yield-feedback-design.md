# Design: Empirical-Yield Feedback Loop for the K4 Controller

**Date:** 2026-05-16
**Status:** Draft, awaiting implementation
**Audit basis:** [docs/audits/controller_maturity_audit_2026_05_16.md](../audits/controller_maturity_audit_2026_05_16.md)
**Scope:** Phase 1 of a three-phase plan. Phases 2 (retrieval-gated mechanism injection) and 3 (ledger-driven curated few-shot library) are designed-for but not built here.

## 1. Context

The 2026-05-16 controller maturity audit concluded that `kryptosbot/run_controller.py` is mature enough to run safely and reject false signal, but not mature enough to find a K4 solution under its current hypothesis-generation strategy. Across 528 cycles and 2 007 persisted theories the controller produced zero promising findings and never crossed the moderate-signal band (crib 10 to 17) under a non-paste plaintext. 70 percent of the theory budget went to four families (encoding, key_tape, archive_evidence, k2_coords) whose empirical yield is indistinguishable from noise across 1 400+ trials. The critic has no view of empirical yield, only static Tier 1 / Tier 2 family-elimination registries.

This spec closes the memory-to-prompt feedback loop in one direction: read the ledger's accumulated yield, expose it to the theorist as advisory pressure, and enforce it in the critic with a bypass path that requires structural novelty rather than prose.

## 2. Goal and non-goals

### Goal

When the theorist tries to re-propose a theory in a family that has been demonstrated empirically dead by accumulated ledger evidence, the controller must:

1. Surface the family's yield to the theorist before generation (advisory).
2. Reject the theory at the critic stage unless the proposal carries a structurally novel mechanism signature (enforcement).
3. Record structured escape telemetry so the next cycle's prompt can apply persistent pressure across consecutive blocked cycles.

### Non-goals (Phase 1)

- No new persistence schema beyond additive fields on existing tables.
- No LLM training, fine-tuning, or few-shot library harvesting.
- No retrieval, RAG, or wide-web search.
- No CLI flag for policy override.
- No automatic mechanism suggestion when the critic blocks all candidates. The cycle ends cleanly with escape telemetry; the operator (or Phase 2) supplies alternatives.
- No change to the kernel, the dispatcher, the verifier, or the alert pipeline.

## 3. Authority model

The system has four distinct authorities. None is collapsed into another.

```
authority           surface
------------------  ----------------------------------------
ledger              source of record (theories.* columns)
family_yield.py     source of derived policy truth
                      stats query, FamilyYieldPolicy,
                      classify(), check_bypass_eligibility()
theorist prompt     advisory rendering for proposal shaping
critic              enforcement; REJECT_EMPIRICALLY_DEAD
```

The ledger is authoritative for historical outcomes. `FamilyYieldPolicy` is authoritative for empirical-death classification. The theorist feedback packet is a lossy rendering for proposal shaping; the critic is the enforcement surface. Both consumers call the same classifier on the same snapshot, so divergence is structurally impossible.

## 4. Components

Seven changes, ordered by dependency.

### 4.1 New pure module: `kryptosbot/family_yield.py`

```python
@dataclass(frozen=True)
class FamilyYieldPolicy:
    min_trials: int = 50
    mean_score_below: float = 2.0
    require_zero_promotions: bool = True
    require_best_below_store_threshold: bool = True
    low_yield_trials: int = 50
    low_yield_mean_below: float = 2.0
    shadow_mode: bool = False  # opt-in: log would-reject without rejecting

@dataclass(frozen=True)
class FamilyYieldStats:
    family: str
    trials: int
    mean_score: float
    best_score: float
    promotions: int
    eliminated: int

@dataclass(frozen=True)
class FamilyYieldVerdict:
    family: str
    status: Literal["healthy", "insufficient_data", "low_yield", "empirically_dead"]
    reasons: tuple[str, ...]
    stats: FamilyYieldStats

DEFAULT_POLICY = FamilyYieldPolicy()

def classify_family_yield(
    stats: FamilyYieldStats,
    policy: FamilyYieldPolicy = DEFAULT_POLICY,
) -> FamilyYieldVerdict: ...

def check_bypass_eligibility(
    *,
    family: str,
    subfamily: str,
    mechanism_signature: str,
    prior_subfamilies_in_family: frozenset[str],
    prior_mechanism_signatures_in_family: frozenset[str],
) -> tuple[bool, tuple[str, ...]]:
    """Returns (eligible, reasons). Structural only. No prose parsing."""

def render_packet(
    yield_index: dict[str, FamilyYieldVerdict],
) -> str:
    """Pure renderer: dict -> theorist-prompt text. No side effects."""
```

Stdlib only. No persistence, no I/O. Trivially unit-testable without instantiating a `TheoryCritic`.

Classification rule:

```
n < min_trials                                     -> insufficient_data
n >= min_trials,
  mean < low_yield_mean_below,
  promotions == 0                                  -> low_yield
n >= min_trials,
  mean < mean_score_below,
  promotions == 0,
  best_score < STORE_THRESHOLD                     -> empirically_dead
otherwise                                          -> healthy
```

`STORE_THRESHOLD` is the existing kernel constant
(`kryptos.kernel.scoring.aggregate.STORE_THRESHOLD == 10`) that classifies a
result as worth persisting. Tying the empirical-death floor to it means a
family with even one "interesting" stored result avoids the dead label even
if its mean is low.

`healthy` and `insufficient_data` are non-actionable (no rejection). `low_yield` is advisory only (no rejection). `empirically_dead` is the enforcement target.

### 4.2 Ledger query: `theory_ledger.py::family_yield_stats()`

Single new method. ~30 LOC. No schema change.

```python
def family_yield_stats(self) -> list[FamilyYieldStats]:
    rows = self._db.execute("""
      SELECT family,
             COUNT(*) AS trials,
             AVG(best_score) AS mean_score,
             MAX(best_score) AS best_score,
             SUM(CASE WHEN status = 'promising'  THEN 1 ELSE 0 END) AS promotions,
             SUM(CASE WHEN status = 'eliminated' THEN 1 ELSE 0 END) AS eliminated
      FROM theories
      WHERE family <> ''
      GROUP BY family
    """).fetchall()
    return [FamilyYieldStats(...) for r in rows]
```

Plus two helpers used by the critic:

```python
def subfamily_index(self) -> dict[str, frozenset[str]]: ...
def mechanism_signature_index(self) -> dict[str, frozenset[str]]: ...
```

Each runs one full scan of `theories`. At 2 000 rows this is ~10 ms; at 20 000 rows it is ~100 ms. Once per cycle, dominated by every other phase of the cycle. No cache in Phase 1.

### 4.3 New verdict variant and structured payload

In `kryptosbot/models.py` (or wherever `CriticDecision` lives):

```python
class CriticDecision(Enum):
    ...
    REJECT_EMPIRICALLY_DEAD = "reject_empirically_dead"  # NEW

@dataclass
class EmpiricalDeathRejectionPayload:
    family: str
    verdict: FamilyYieldVerdict
    bypass_failed_reasons: tuple[str, ...]
    # Phase 1: always (). Phase 2: populated by cipher-discovery KB.
    suggested_mechanisms: tuple[str, ...] = ()

@dataclass
class CriticVerdict:
    decision: CriticDecision
    confidence: float
    reasons: list[str]
    # NEW. Phase 2/3 forward-design field. None for every other decision type.
    empirical_death: Optional[EmpiricalDeathRejectionPayload] = None
```

Backward-compat: `Optional` with `None` default; existing constructors keep working. Ledger serializes `critic_verdict` as JSON already; the new key is additive and absent on pre-Phase-1 rows.

### 4.4 Critic gate: `critic.py::_check_family_empirically_dead`

Inserted in `evaluate()` **after the TIER_1 / TIER_2 family checks AND after the duplicate-detection check, but before the contradiction and DSL-translatability checks**.

Specifically, the existing critic order is:

```
1. completeness
2. TIER_1 / TIER_2 family elimination
3. duplicate detection
   <-- NEW: 3.5  empirical-death (this spec)
4. contradiction check
4.5. prompt-surface scope check
5. DSL translatability
6. information gain estimation
```

The placement matters: a theory that is a literal duplicate of a prior trial in a dead family must be rejected as `REJECT_DUPLICATE`, not `REJECT_EMPIRICALLY_DEAD`. Duplicate is the more specific, cheaper, and more accurate verdict. Empirical-death applies only to NEW theories in dead families.

```python
def _check_family_empirically_dead(self, theory, family_lower):
    verdict = self.yield_index.get(family_lower)
    if not verdict or verdict.status != "empirically_dead":
        return None

    eligible, reasons = check_bypass_eligibility(
        family=family_lower,
        subfamily=_normalize_subfamily(theory.subfamily),
        mechanism_signature=_mechanism_signature(theory),
        prior_subfamilies_in_family=self.prior_subfamilies.get(family_lower, frozenset()),
        prior_mechanism_signatures_in_family=self.prior_signatures.get(family_lower, frozenset()),
    )
    if eligible:
        return None  # fall through; downstream checks may still reject

    if self.policy.shadow_mode:
        # Log would-reject, return None so the theory proceeds.
        logger.warning("[shadow] would_reject_empirically_dead: %s", family_lower)
        return None

    return CriticVerdict(
        decision=CriticDecision.REJECT_EMPIRICALLY_DEAD,
        confidence=0.9,
        reasons=[
            f"Family '{theory.family}' empirically dead "
            f"(n={verdict.stats.trials}, mean={verdict.stats.mean_score:.2f}, "
            f"best={verdict.stats.best_score:.1f}, "
            f"promotions={verdict.stats.promotions}); bypass not satisfied",
            *reasons,
        ],
        empirical_death=EmpiricalDeathRejectionPayload(
            family=family_lower,
            verdict=verdict,
            bypass_failed_reasons=reasons,
            suggested_mechanisms=(),  # Phase 2 populates
        ),
    )
```

The critic receives `yield_index`, `prior_subfamilies`, and `prior_signatures` from the controller at batch construction time. O(1) per theory; no SQL during evaluation.

`_normalize_subfamily(s)` is a one-line helper: strip whitespace, lowercase, collapse internal whitespace. Used both at signature-hash time and at index lookup time so superficial typography differences do not generate false bypasses.

**Mechanism signature**. For Category-A (DSL) theories: canonical hash of the DSL spec layers. For Category-B (non-DSL investigative) theories: weak structured hash:

```python
category_b_signature_source = {
    "family": family.lower(),
    "subfamily": normalize(subfamily),
    "mechanism_tokens": normalized_content_tokens(mechanism),
    "anomalies_exploited": sorted(anomalies_exploited),
    "clue_anchors_used": sorted(clue_anchors_used),
    "minimal_test_method": minimal_test_spec.get("method", ""),
}
```

Hash the canonical JSON. `novelty_basis` is preserved on `TheoryRecord` but never enters the hash; it explains novelty, it does not define it.

Category-B is not exempt from the empirical-death gate. Several of the highest-yield-noise families (geometry, k2_coords, archive_evidence) are Category-B today; exempting them would reopen the exact loophole the spec closes. If `physical_overlay` or another family should route as Category-B in the future, that addition belongs in `NON_DSL_FAMILIES` deliberately rather than as a side effect of this spec.

### 4.5 Controller wiring: `controller.py`

`_assess_landscape()` snapshots all three indices once per cycle and stashes them on the controller instance:

```python
def _assess_landscape(self) -> dict[str, Any]:
    ...
    stats = self.ledger.family_yield_stats()
    self._cycle_yield_index = {
        s.family: classify_family_yield(s, self.config.family_yield_policy)
        for s in stats
    }
    self._cycle_prior_subfamilies = self.ledger.subfamily_index()
    self._cycle_prior_signatures = self.ledger.mechanism_signature_index()
    landscape["family_yield"] = render_packet(self._cycle_yield_index)
    landscape["escape_pressure"] = self._render_escape_pressure(
        self.state.escape_needed_streak,
        self.state.last_escape_status,
        self.state.last_escape_families_blocked,
        self.state.last_escape_families_blocked_total,
    )
    ...
```

The critic's batch invocation receives the cached indices and the policy at construction time, so per-theory evaluation never hits the ledger or the policy module again.

### 4.6 Theorist prompt: `pantheon.py`

Two new sections appended to the theorist system message:

```
=== RECENT FAMILY YIELD (advisory) ===

EMPIRICALLY DEAD (the critic will reject new theories in these families
unless you specify a subfamily not previously tried, supply a structured
mechanism signature distinct from prior trials, and document why this is
not a relabeling):
  - encoding         n=826  mean=0.78  best=7   promotions=0
  - key_tape         n=207  mean=0.75  best=24* promotions=0  (*paste)
  - archive_evidence n=196  mean=1.30  best=24* promotions=0
  - k2_coords        n=177  mean=0.61  best=6   promotions=0

LOW YIELD:
  - grille           n=162  mean=0.64  best=24* promotions=0
  - geometry         n=128  mean=0.97  best=16  promotions=0

HEALTHY OR UNDEREXPLORED:
  - multi_layer, fractionation, double_columnar, novel, ...

=== ESCAPE PRESSURE (cross-cycle) ===
[rendered only when last_escape_status indicates pressure]
```

The packet is RENDERED, not enforced. The critic does the enforcement.

### 4.7 Tests

See section 8.

## 5. Data flow

### 5.1 Per-cycle sequence

```
                  CYCLE N START
                       |
                       v
      +-------------------------------------------------+
      | ResearchController._run_cycle_loop              |
      |   self._begin_cycle_phase_state()               |
      |   self._cycle_empirical_dead_rejections = []    |
      +-------------------------+-----------------------+
                                |
                                v
      +-------------------------------------------------+
      | _assess_landscape()                             |
      |   stats   = ledger.family_yield_stats()         |
      |   priors  = ledger.subfamily_index()            |
      |   sigs    = ledger.mechanism_signature_index()  |
      |                                                 |
      |   self._cycle_yield_index   = {classify(...)}   |
      |   self._cycle_prior_subfamilies = priors        |
      |   self._cycle_prior_signatures  = sigs          |
      |                                                 |
      |   landscape["family_yield"] = render_packet(    |
      |     self._cycle_yield_index                     |
      |   )                                             |
      |   landscape["escape_pressure"] = render(        |
      |     self.state.escape_needed_streak,            |
      |     self.state.last_escape_status, ...          |
      |   )                                             |
      +-------------------------+-----------------------+
                                |
                                v
      +-------------------------------------------------+
      | _generate_theories(landscape, ...)              |
      +-------------------------+-----------------------+
                                |
       candidates == []  <------+------>  candidates non-empty
              |                                |
              v                                v
   write_cycle_escape_summary           critic phase
     (status="no_candidates",             critic.yield_index = ...
      streak unchanged)                   critic.prior_subfamilies = ...
              |                            critic.prior_signatures = ...
              v                            for theory in candidates:
        continue                             verdict = critic.evaluate(theory)
                                             if REJECT_EMPIRICALLY_DEAD:
                                               append to
                                                 _cycle_empirical_dead_rejections
                                                 |
                                                 v
                                          approved == [] ?
                                                 |
                                  yes ------> write_cycle_escape_summary
                                              (status = "needed_but_unavailable"
                                                if dead-rejections > 0
                                              else "no_candidates",
                                               increments streak iff
                                                "needed_but_unavailable")
                                              continue
                                                 |
                                  no  ------> dispatch, absorb, alerts,
                                              hardening, lead-pursuit
                                                 |
                                                 v
                                              _run_synthesis(...)
                                                 |
                                                 v
                                  write_cycle_escape_summary(
                                    status =
                                      "partial_empirical_block" if any
                                       dead-rejections else "none",
                                    resets streak
                                  )
                                                 |
                                                 v
                                          persist state + ledger
                                                 |
                                                 v
                                  CYCLE N END
```

### 5.2 Three invariants

1. **Yield indices are snapshotted once per cycle.** They are stale by construction within a cycle (eliminations landing during cycle N do not change cycle N's classifier output). This is correct: without it, the critic and parallel worker absorption race. Cycle N+1's `_assess_landscape` re-snapshots.

2. **The critic never queries the ledger for yield data.** All yield decisions read the cached indices injected by the controller. O(1) per theory.

3. **Theorist packet and critic verdict cannot diverge** because both consume the same `self._cycle_yield_index` dict.

### 5.3 The single escape-telemetry chokepoint

`_write_cycle_escape_summary` is the single function that writes escape telemetry. It is called from every path that ends a cycle: both early-`continue` paths AND the success path's end-of-synthesis. This is the structural fix for the bug that the original Section 3 draft had, where `_run_synthesis` was the only write site and early-exit cycles silently produced no telemetry.

```python
def _write_cycle_escape_summary(
    self,
    *,
    status: EscapeStatus,
    families_blocked: list[str] = (),
) -> None:
    blocked_total = len(families_blocked)
    blocked_top10 = self._truncate_blocked_families(families_blocked)

    if status == "needed_but_unavailable":
        self.state.escape_needed_streak += 1
    else:
        # "none", "no_candidates", "partial_empirical_block",
        # and the Phase-2 "needed_and_satisfied" all reset the streak.
        self.state.escape_needed_streak = 0

    self.state.last_escape_status = status
    self.state.last_escape_families_blocked = blocked_top10
    self.state.last_escape_families_blocked_total = blocked_total
    self.state.last_escape_cycle = self.state.cycle_number

    if status == "partial_empirical_block":
        self.state.last_partial_empirical_block_count = len(families_blocked)

    # The CycleSynthesis path also stores the same on _last_synthesis
    # for in-process transient use by render_packet, but the source of
    # truth is ControllerState (persisted).
```

`_truncate_blocked_families` sorts by (blocked_count desc, trials desc, family_id asc) and keeps the top 10.

### 5.4 Streak semantics

```python
if escape_status == "needed_but_unavailable":
    escape_needed_streak += 1
elif escape_status == "partial_empirical_block":
    escape_needed_streak = 0  # partial = brake redirected, not stranded
elif escape_status == "no_candidates":
    escape_needed_streak = 0  # theorist failure, not empirical-death failure
else:  # "none", "needed_and_satisfied" (Phase 2)
    escape_needed_streak = 0
```

Three rendering levels for cross-cycle pressure:

```
streak == 1:
  PRIOR CYCLE NEEDED ESCAPE - N families blocked.

streak == 2:
  SECOND CONSECUTIVE ESCAPE-NEEDED CYCLE - avoid blocked families
  unless mechanism_signature is new.

streak >= 3:
  REPEATED ESCAPE FAILURE - this cycle MUST prioritize families
  outside the blocked set; reusing blocked families requires a
  structurally new mechanism.
```

Prompt pressure only. Phase 1 does not introduce a halt condition for the streak.

### 5.5 Failure modes

| Condition | Behavior |
| --- | --- |
| `ledger.family_yield_stats()` raises | `_assess_landscape` catches, logs WARNING, sets `self._cycle_yield_index = {}`. Critic sees no `empirically_dead` family, no rejection on this axis. Disables only the empirical-death brake for that cycle; Tier 1 / Tier 2 / duplicate / contradiction / DSL / exhaustion / red-team / kernel verifier all still apply. |
| Cold start (fresh ledger) | All families have `n=0`. All classify as `insufficient_data`. No rejection. |
| Family with `trials < min_trials` | Always `insufficient_data` regardless of mean. Prevents `novel`, `fractionation`, `double_columnar` (n=3 to 7) from being labelled dead. |
| Operator changes policy mid-run | Each cycle re-snapshots with the new policy. No drift. |
| Theorist invents a new subfamily NAME to bypass | `_mechanism_signature` hashes the structured layout (DSL spec or weak Category-B signature), not the subfamily name. Renaming without structural change still fails the signature check. |
| Pre-Phase-1 ControllerState load | New fields default cleanly: `escape_needed_streak=0`, `last_escape_status="none"`, `last_escape_families_blocked=[]`, `last_escape_cycle=0`. |

## 6. Operational concerns

### 6.1 Configuration

Policy thresholds live in `family_yield.py::FamilyYieldPolicy`. No CLI flag in Phase 1. Operators who need to override edit the dataclass in code. Deliberate friction: the audit found that the project's bigger problem is invisible drift, not misconfigured runs.

`shadow_mode: bool = False` is opt-in. Set to `True` in tests and diagnostic runs to exercise the path without rejecting. Merged default is `False`. Phase 1 begins gating immediately at merge time.

### 6.2 Persistence

Four new fields on `ControllerState`:

```python
@dataclass
class ControllerState:
    ...
    escape_needed_streak: int = 0
    last_escape_status: str = "none"
    last_escape_families_blocked: list[str] = field(default_factory=list)
    last_escape_families_blocked_total: int = 0
    last_escape_cycle: int = 0
    last_partial_empirical_block_count: int = 0
```

Serialized via the existing `state` JSON column on `controller_state`. Backward-compat: dataclass defaults handle pre-Phase-1 rows; no migration script needed.

### 6.3 Backward compatibility

| Surface | Change | Compat notes |
| --- | --- | --- |
| `theories` table | none | read-only new query |
| `controller_state` JSON | 6 new keys | dataclass defaults; old rows load cleanly |
| `theories.critic_verdict` JSON | new optional `empirical_death` key | absent on pre-Phase-1 rows; reader treats as None |
| `CriticDecision` enum | adds `REJECT_EMPIRICALLY_DEAD` | additive; every existing `match` / `if` over CriticDecision audited before merge |
| theorist prompt | new appended sections | additive |

### 6.4 Fail-open posture

Phase 1 fails open on yield-stats failure because the empirical-death gate is a search-allocation brake, not a cryptographic constraint. Hard gates (Tier 1, Tier 2, duplicate, contradiction, DSL, exhaustion, red-team, kernel verifier, alert pipeline) are all independent of yield data and continue to apply. The next cycle's landscape renders "FAMILY-YIELD UNAVAILABLE" so the operator knows the brake is off.

### 6.5 Rollout

No feature flag. Mergeable when tests pass. Fresh ledgers behave identically to pre-Phase-1 until 50 trials accumulate per family. The live ledger (n=826 for encoding, etc.) starts gating immediately, which is the intended behavior.

### 6.6 Documentation touchpoints

| File | Change |
| --- | --- |
| `kryptosbot/ARCHITECTURE.md` | new section: Family-yield feedback loop |
| `kryptosbot/ORIENT.md` | new §5.6: "Critic rejected my theory with REJECT_EMPIRICALLY_DEAD" |
| `CLAUDE.md` | none (doctrine unchanged; this is mechanism) |
| `MEMORY.md` | one entry on Phase 1 landing |
| `docs/audits/controller_maturity_audit_2026_05_16.md` | annotate Tier A recommendation #4 as "LANDED Phase 1" once merged |

## 7. Out of scope / forward design

### 7.1 Phase 2 (next, not built here)

When a cycle's escape_status is `needed_but_unavailable`, query the existing `cipher_discovery_subsystem` for mechanisms that:

- match the structural shape required by current cribs and anchors,
- have NOT been tried in the blocked families (signature delta),
- are dispatcher-testable or carry a bounded Category-B test method.

Populate `EmpiricalDeathRejectionPayload.suggested_mechanisms` and surface in the next cycle's theorist prompt as concrete escape candidates. The "needed_and_satisfied" enum value lights up when this path produces at least one critic-approved theory.

The Phase 1 design preserves every hook this needs: a structured rejection payload with `suggested_mechanisms: tuple[str, ...]`, an `escape_status` field that already includes the satisfied variant, and a single chokepoint (`_write_cycle_escape_summary`) where Phase 2 can plug in the suggestion path.

### 7.2 Phase 3 (deferred)

Ledger-driven curated few-shot library. Harvest:

- approved-and-survived theories as "valid novel bounded hypothesis" examples,
- `REJECT_EMPIRICALLY_DEAD` rejections as "dead-family rephrase" examples,
- `REJECT_UNDERCONSTRAINED` rejections as "DSL-shaped but epistemically useless" examples,
- post-execution structured disproofs as "procedural mechanism with a real kill criterion" examples.

Inject as few-shot context in the theorist system prompt. Risk: this can crystallize the project's current local minima if the harvest distribution mirrors the same dead families. Mitigated by Phase 1 already redirecting allocation; Phase 3 lands only after Phase 1 has changed the family distribution.

## 8. Testing

Phase 1 follows the project's existing `superpowers:test-driven-development` posture. Pure module first, integration second, characterization against the existing trace last. Approximately 250 LOC across five new test files plus two updates.

### 8.1 Test layer breakdown

| Layer | File | New / Update | What it proves |
| --- | --- | --- | --- |
| pure module | `tests/test_family_yield.py` | new | every classifier branch, bypass-eligibility branches, boundary cases |
| ledger query | `tests/test_theory_ledger.py` | update | `family_yield_stats()`, `subfamily_index()`, `mechanism_signature_index()` shapes; fresh and populated DBs |
| critic gate | `tests/test_critic_empirical_death.py` | new | dead+no-bypass-reject, dead+bypass-fall-through, healthy-fall-through, tier-1 wins ordering, shadow mode |
| landscape render | `tests/test_landscape_yield_packet.py` | new | packet text matches critic verdict for same family (shared symmetry invariant) |
| escape telemetry | `tests/test_cycle_escape_telemetry.py` | new | early-exit paths write summary, streak increments and resets, truncation, backward-compat on cold load |
| cycle-loop char | `tests/test_cycle_loop_characterization.py` | update | new canonical trace events for early-exit-with-summary case |

### 8.2 Named invariants

```
test_shared_symmetry_invariant
test_streak_only_increments_on_full_block
test_no_candidates_does_not_increment_empirical_streak
test_partial_empirical_block_resets_streak
test_shadow_mode_logs_but_does_not_reject
test_fail_open_when_yield_stats_raises
test_tier_1_wins_over_empirical_death
test_bypass_requires_structural_novelty
test_bypass_grants_pass_on_new_subfamily_AND_new_signature
test_truncation_at_10_by_severity
test_total_count_preserved_when_truncated
test_backward_compat_loads_pre_phase_1_state
test_boundary_min_trials
test_critic_decision_enum_exhaustive_handling
test_category_b_signature_excludes_novelty_basis
test_early_exit_writes_cycle_escape_summary
test_synthesis_path_writes_cycle_escape_summary
```

### 8.3 Coverage target

- `family_yield.py` reaches 100 percent branch coverage (pure ~150 LOC module).
- `_check_family_empirically_dead` reaches 100 percent branch coverage (dead / healthy × bypass / no-bypass × shadow / normal = 8 branches).
- Cycle-loop integration covers all three Phase-1-reachable `escape_status` values: `none`, `no_candidates`, `partial_empirical_block`, `needed_but_unavailable`.

`needed_and_satisfied` is unreachable in Phase 1 and is guarded with `pytest.skip("Phase 2")` so the enum value is not silently unreachable forever.

### 8.4 Existing tests impact

| Test file | Impact |
| --- | --- |
| `test_cycle_loop_characterization.py` (test G) | New canonical event `on_cycle_escape_summary`. Re-baseline once after merge. |
| `test_critic_*.py` (general) | Audit every `CriticVerdict` construction site to confirm it tolerates the new optional `empirical_death` field. None should break; defensive review. |
| `test_theory_ledger.py` controller-state round-trip | One new assertion for the six new ControllerState fields. |

## 9. Files touched

```
NEW:
  kryptosbot/family_yield.py
  kryptosbot/tests/test_family_yield.py
  kryptosbot/tests/test_critic_empirical_death.py
  kryptosbot/tests/test_landscape_yield_packet.py
  kryptosbot/tests/test_cycle_escape_telemetry.py

UPDATE:
  kryptosbot/theory_ledger.py            (new query methods, ControllerState fields)
  kryptosbot/models.py (or contracts.py) (CriticDecision variant, payload dataclass, CriticVerdict optional field)
  kryptosbot/critic.py                   (new gate method, evaluate() insertion)
  kryptosbot/controller.py               (landscape snapshot, _write_cycle_escape_summary, early-exit wiring)
  kryptosbot/pantheon.py                 (theorist prompt template extensions)
  kryptosbot/tests/test_theory_ledger.py (round-trip assertions)
  kryptosbot/tests/test_cycle_loop_characterization.py (re-baseline)
  kryptosbot/ARCHITECTURE.md             (new section)
  kryptosbot/ORIENT.md                   (new §5.6)
  MEMORY.md                              (Phase 1 landing entry, post-merge)
  docs/audits/controller_maturity_audit_2026_05_16.md (annotate as LANDED, post-merge)
```

## 10. Acceptance criteria

This spec is considered satisfied when, on the live ledger as of the audit date:

1. Cycle 529's `_assess_landscape` reports `encoding`, `key_tape`, `archive_evidence`, and `k2_coords` as `empirically_dead` in the theorist prompt packet.
2. A NEW theory (one that does not duplicate any prior trial's DSL spec hash, so duplicate-detection lets it through) proposed in `encoding` family with a subfamily AND mechanism_signature both present in the prior 826 trials is rejected with `REJECT_EMPIRICALLY_DEAD`. (Duplicate theories are rejected as `REJECT_DUPLICATE` by the existing earlier gate, not by this spec.)
3. A theory proposed in `encoding` family with a mechanism_signature that does not appear in the prior 826 trials AND a subfamily not previously seen falls through the empirical-death gate (it may still be rejected by contradiction / DSL / exhaustion).
4. A cycle in which all candidates are rejected by empirical-death writes a `_write_cycle_escape_summary` entry with `status="needed_but_unavailable"`, `escape_needed_streak` incremented, and `last_escape_families_blocked` populated.
5. A cycle in which some but not all candidates are rejected by empirical-death writes `status="partial_empirical_block"`, `escape_needed_streak` reset to 0.
6. The full new test suite passes. Existing tests pass.
7. `MEMORY.md` and `docs/audits/controller_maturity_audit_2026_05_16.md` are annotated.
