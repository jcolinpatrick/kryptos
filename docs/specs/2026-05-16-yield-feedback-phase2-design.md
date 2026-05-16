# Design: Empirical-Yield Feedback Loop, Phase 2 — Crib-Paste Detector + Cipher-Discovery KB Injection

**Date:** 2026-05-16
**Status:** Draft, awaiting implementation
**Audit basis:** [docs/audits/controller_maturity_audit_2026_05_16.md](../audits/controller_maturity_audit_2026_05_16.md), Tier A #1 and Phase 1 §7.1 forward-design.
**Predecessor:** [docs/specs/2026-05-16-yield-feedback-design.md](2026-05-16-yield-feedback-design.md) (Phase 1, landed 2026-05-16).
**Scope:** Phase 2 of a three-phase plan. Phase 3 (ledger-driven curated few-shot library) remains designed-for but not built here.

## 1. Context

Phase 1 of the yield-feedback loop landed on 2026-05-16. It closed the controller's memory-to-prompt feedback gap in one direction: the critic now rejects new theories in empirically-dead families unless a structural-novelty bypass (unseen subfamily AND unseen `mechanism_signature`) is satisfied, and the next cycle's prompt carries cross-cycle escape pressure.

Phase 1 did not close the loop in the *redirect* direction. When the critic blocks an entire cycle's candidates with `REJECT_EMPIRICALLY_DEAD`, the theorist receives prompt pressure ("avoid blocked families unless mechanism_signature is new") but no concrete escape candidates. The `EmpiricalDeathRejectionPayload.suggested_mechanisms: tuple[str, ...] = ()` field exists as a Phase-2 forward-design hook and is always empty under Phase 1.

Phase 1 also did not address the worker-side false-BREAKTHROUGH artifact. The live ledger contains 8 events with `crib_score == 24` whose plaintexts are unambiguous crib-paste artifacts: random or repeated characters bracketing the canonical crib strings (`XXXXX…EASTNORTHEAST…XXXXX`, `LTSCUVVHD…EASTNORTHEAST…WEWAOL`, etc.). The math is legitimate — 624 Bean-valid keystreams admit arbitrary plaintexts at the 24 crib positions — but the result is a false-promotion candidate caught only downstream by the ngram floor and stat-audit gates, at the cost of a full elimination round-trip per event.

Phase 2 closes both gaps:

1. **Crib-paste detector** — guards the worker-result intake (`contracts.py::_verify_against_kernel`). Catches the 8 known events plus future variants before they reach promotion / alert pipelines.
2. **Cipher-discovery KB injection** — populates `EmpiricalDeathRejectionPayload.suggested_mechanism_records` on every empirical-death rejection by querying the existing `cipher_discovery.sqlite` knowledge base under a structural-novelty join. Suggestions surface in the next cycle's theorist prompt, conditional on escape status, with hard caps.

## 2. Goal and non-goals

### Goal

When a worker produces a 24/24 result whose plaintext is a literal crib paste, the controller must reject it as an artifact before promotion. When the critic blocks one or more theories with `REJECT_EMPIRICALLY_DEAD`, the controller must offer the theorist a curated, structurally-novel list of cipher mechanisms from the discovery KB in the next cycle's prompt, with rendering strength matching the severity of the block.

### Non-goals (Phase 2)

- No DSL-stub synthesis for KB records. Suggestions carry a one-line sketch and a `dispatcher_testable` flag; theorist still authors any actual DSL.
- No auto-dispatch of KB candidates. Suggestions are prompt context only.
- No new column on `theory_ledger.sqlite`. Suggestion payloads serialize through the existing `critic_verdict` JSON path; cycle-level aggregates through `ControllerState`.
- No new column on `cipher_discovery.sqlite`. KB signatures are computed at query time and versioned in the emitted payload.
- No partial-paste detection at `crib_score` 18–23. The live ledger has zero events in that band; pre-registering a threshold without empirical examples invites overfit.
- No change to the kernel, the dispatcher, the alert pipeline, the W-emphasis rotation, the lead-pursuit phase, or the stat-audit gate.

## 3. Authority model

Five distinct authorities. None is collapsed into another.

```
authority                         surface
--------------------------------  --------------------------------------------
kernel                            recomputes verified scores
contracts._verify_against_kernel  worker-result truth boundary;
                                    hosts the crib-paste detector
critic                            empirical-death enforcement (Phase 1) +
                                    per-rejection KB query trigger (Phase 2)
kb_injection.py                   KB query, novelty join, signature, ranking
controller / ControllerState      single-writer chokepoint for
                                    escape telemetry and last-cycle suggestions
theorist prompt                   advisory rendering, conditional on
                                    escape_status, with hard caps
```

The ledger snapshot is the authority for prior-trial signatures. `kb_injection.query_suggestions()` is the authority for KB-derived candidates. The critic is the authority for whether a candidate gets recorded in the rejection payload. The controller is the authority for cross-cycle aggregation. The theorist prompt is a lossy rendering, never a source of truth.

## 4. Components

Seven changes, ordered by dependency.

### 4.1 New pure module: `kryptosbot/kb_family_map.py`

Curated, auditable namespace bridge between KB `cipher_family` strings and ledger family identifiers. Stdlib only. No I/O.

```python
# Every value in KB_TO_LEDGER_FAMILY MUST be in valid_ledger_family_universe()
# (KNOWN_FAMILIES.family_id ∪ historical ledger.theories.family). The test
# suite enforces this — a value referencing a non-existent family fails
# test_kb_family_map_values_resolve_to_real_families.

KB_TO_LEDGER_FAMILY: Mapping[str, frozenset[str]] = {
    "columnar":               frozenset({"columnar_single", "double_columnar", "route_cipher"}),
    "polybius transposition": frozenset({"fractionation", "multi_layer"}),
    "positional":             frozenset({"route_cipher", "geometry", "procedural"}),
    "steganographic":         frozenset({"stego_layer", "physical_overlay", "procedural"}),
    "running key":            frozenset({"running_key", "key_tape"}),
    "substitution":           frozenset({"vigenere", "beaufort", "variant_beaufort", "novel"}),
    "polyalphabetic":         frozenset({"vigenere", "beaufort", "variant_beaufort", "polyalphabetic"}),
    "fractionation":          frozenset({"fractionation", "multi_layer"}),
    "route transposition":    frozenset({"route_cipher", "transposition"}),
    "monoalphabetic":         frozenset({"caesar", "atbash", "affine", "novel"}),
    "Delastelle":             frozenset({"four_square", "multi_layer"}),
    "Playfair family":        frozenset({"four_square", "multi_layer"}),
    # Grows by curated audit. Unmapped KB cipher_family strings produce
    # verdict="defer_needs_mapping" — NOT a silent allow.
}

KB_TO_DSL_KIND: Mapping[str, str] = {
    "columnar":               "columnar",
    "polybius transposition": "polybius",
    "route":                  "route",
    "route transposition":    "route",
    "myszkowski":             "myszkowski",
    "rail fence":             "rail_fence",
    "quagmire":               "quagmire",
    "grille":                 "grille",
    "procedural":             "procedural",
}

def map_kb_family_to_ledger_families(kb_family: str) -> Optional[frozenset[str]]:
    """Returns None when unmapped. None → defer_needs_mapping in callers."""
```

### 4.2 New pure module: `kryptosbot/kb_injection.py`

KB query, signature generation, novelty join, ranking. Stdlib + sqlite3 only. Imports from `kb_family_map` and from the existing `cipher_discovery` package only for `CipherRecord` typing; runs against `db/cipher_discovery.sqlite` by default with an injected path for tests.

```python
KB_SIGNATURE_SCHEMA_VERSION = "kb_mechanism_sig_v1"

def kb_mechanism_signature(record: CipherRecord) -> str:
    """sha256[:16] of canonical JSON of:
      - schema: KB_SIGNATURE_SCHEMA_VERSION
      - canonical_name (normalized)
      - cipher_family (normalized)
      - cipher_type (normalized)
      - taxonomy (sorted normalized tokens)
      - mechanics_tokens (sorted normalized tokens drawn from
          canonical_name, cipher_family, cipher_type, operational_mechanics,
          and description)
    Ledger-family mapping is deliberately excluded. The signature describes
    the KB mechanism; the family map is a separate namespace bridge. Mixing
    them would let a mapping-table edit silently invalidate every signature.
    """

def dispatcher_testable(record: CipherRecord) -> bool:
    """KB_TO_DSL_KIND[normalize(record.cipher_family)] ∈ _SUPPORTED_KINDS."""

@dataclass(frozen=True)
class KBCandidateNoveltyVerdict:
    kb_record_id: str
    kb_cipher_family: str
    mapped_ledger_families: tuple[str, ...]
    tested_status_ok: bool          # tested_in_project=0 OR exhaustion_status ∉ {"exhausted"}
    family_blocked: bool            # mapped_ledger_families ∩ blocked_families_in_cycle ≠ ∅
    static_exhaustion_blocked: bool # any mapped family in Tier-1/Tier-2 elimination registries
    mechanism_signature: str
    signature_seen: bool            # ∈ prior_signatures (any of the mapped ledger families)
    dispatcher_testable: bool
    verdict: Literal["allow", "reject", "defer_needs_mapping"]
    reasons: tuple[str, ...]

@dataclass(frozen=True)
class CipherDiscoverySuggestion:
    kb_record_id: str
    canonical_name: str
    kb_cipher_family: str
    mapped_ledger_families: tuple[str, ...]
    mechanism_signature: str
    signature_schema_version: str            # KB_SIGNATURE_SCHEMA_VERSION
    dispatcher_testable: bool
    k4_relevance_score: float
    sketch_class: Literal["dsl_testable", "category_b", "unknown"]
    one_line_sketch: str                     # truncated description or mechanics
    bounded_kill_criterion: str              # rendered prompt guidance
    source_verdict: Literal["allow"]         # only verdict="allow" surfaces

    def to_dict(self) -> dict[str, Any]: ...
    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CipherDiscoverySuggestion": ...

def query_suggestions(
    *,
    blocked_family: str,
    blocked_signature: str,
    prior_signatures: Mapping[str, frozenset[str]],   # per-ledger-family
    blocked_families_in_cycle: frozenset[str],
    static_exhaustion_blocklist: frozenset[str],
    db_path: str | os.PathLike[str] = "db/cipher_discovery.sqlite",
    max_per_call: int = 12,
) -> tuple[CipherDiscoverySuggestion, ...]:
    """Reads KB, applies novelty join, returns ranked allow-list.
    Sort key (deterministic): (dispatcher_testable desc,
    k4_relevance_score desc, canonical_name asc).
    Missing DB → returns (). Caller logs once per cycle.
    Corrupt row → skipped with WARNING; remaining rows continue.
    """
```

### 4.3 Verdict and payload extension (additive)

`CriticDecision.REJECT_EMPIRICALLY_DEAD` already exists (Phase 1). The payload widens:

```python
@dataclass
class EmpiricalDeathRejectionPayload:
    family: str
    verdict: FamilyYieldVerdict
    bypass_failed_reasons: tuple[str, ...]

    # NAME CHANGE: suggested_mechanisms → suggested_mechanism_records
    # to reflect the type widening from tuple[str, ...] to a structured record.
    suggested_mechanism_records: tuple[CipherDiscoverySuggestion, ...] = ()
    suggestion_source: Literal["cipher_discovery_kb", "none"] = "none"
    suggestion_query_scope: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]: ...
    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "EmpiricalDeathRejectionPayload": ...
```

Phase 1's `suggested_mechanisms: tuple[str, ...] = ()` is renamed and re-typed. Phase 1 never populates the field with non-empty values, so the rename is safe; the audit pass over existing dispatch sites (Phase 1 Task 8) is repeated in Phase 2 to cover the new name.

### 4.4 Crib-paste detector inside `contracts.py::_verify_against_kernel`

The detector lives in the existing verifier function, which is already the single chokepoint every worker-result path flows through (worker contract validation, `record_experiment_result`, `job_result_to_worker_contract`).

```python
def _non_crib_ngram_per_char(pt: str, ngram_scorer) -> float:
    """Score the PT with crib positions masked. Returns
    ngram_total / len(non_crib_indices). Uses the existing kernel ngram
    scorer (same instance the kernel verification path uses)."""

def _is_crib_paste_artifact(
    pt: str,
    *,
    verified_crib: int,
    non_crib_ngram_per_char: float,
) -> bool:
    """Pre-registered:
        verified_crib == 24 AND non_crib_ngram_per_char <= -6.2
    Versioned as 'crib_paste_artifact:v1' in verification_error strings."""
```

Integration in `_verify_against_kernel`:

```
  1. snapshot worker self-report
  2. validate PT shape  (Phase 1's non-A-Z guard already here)
  3. recompute kernel crib_score / bean_passed / score
  4. ⟵ NEW: if verified_crib == 24:
            try:
                ngram_pc = _non_crib_ngram_per_char(pt, _scorer)
                paste = _is_crib_paste_artifact(
                    pt,
                    verified_crib=verified_crib,
                    non_crib_ngram_per_char=ngram_pc,
                )
            except Exception as exc:
                logger.warning("crib_paste_detector raised: %s", exc)
                paste = True  # fail-closed: treat as artifact, not signal
                ngram_pc = float("nan")

            if paste:
                contract.raw_artifacts["artifact_class"] = "crib_paste"
                contract.raw_artifacts["kernel_verified_before_artifact_filter"] = {
                    "crib_score": verified_crib,
                    "bean_passed": <verified_bean>,
                    "score": <verified_score>,
                    "bean_variant": <verified_variant>,
                    "non_crib_ngram_per_char": ngram_pc,
                }
                contract.crib_score = 0
                contract.score = 0.0
                contract.bean_passed = False
                contract.bean_variant = None
                contract.verification_error = (
                    "crib_paste_artifact:v1: verified_crib=24, "
                    f"non_crib_ngram_per_char={ngram_pc:.2f} <= -6.2"
                )
                contract.status = WorkerStatus.INCONCLUSIVE
                contract.fields_overwritten = True
  5. return contract
```

Status is forced to `WorkerStatus.INCONCLUSIVE`, *not* `DISPROVED`. The controller maps `DISPROVED → TheoryStatus.ELIMINATED`, which is too strong for an artifact: the paste is not evidence that the hypothesis family is exhausted, only that this candidate is not signal. Selecting INCONCLUSIVE preserves the elimination accounting in the ledger while removing the false-promotion path.

The detector has its own local `try / except`. It does not rely on `_verify_against_kernel`'s outer catch-all. Detector failure means "treat as paste, fail closed" — the same posture the verifier already takes for indeterminate kernel outcomes.

### 4.5 Critic gate: `critic.py::_check_family_empirically_dead`

Phase 1's gate already exists. Phase 2 extends it to populate `suggested_mechanism_records` when the gate fires:

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
        return None
    if self.policy.shadow_mode:
        logger.warning("[shadow] would_reject_empirically_dead: %s", family_lower)
        return None

    # NEW Phase 2 block — KB query.
    cache_key = (family_lower, _mechanism_signature(theory))
    if cache_key in self._kb_cache:
        suggestions = self._kb_cache[cache_key]
    else:
        suggestions = kb_injection.query_suggestions(
            blocked_family=family_lower,
            blocked_signature=_mechanism_signature(theory),
            prior_signatures=self.prior_signatures,
            blocked_families_in_cycle=self.blocked_families_in_cycle,
            static_exhaustion_blocklist=self.static_exhaustion_blocklist,
            db_path=self._kb_db_path,
        )
        self._kb_cache[cache_key] = suggestions

    suggestion_source = "cipher_discovery_kb" if suggestions else "none"
    return CriticVerdict(
        decision=CriticDecision.REJECT_EMPIRICALLY_DEAD,
        confidence=0.9,
        reasons=[...],
        empirical_death=EmpiricalDeathRejectionPayload(
            family=family_lower,
            verdict=verdict,
            bypass_failed_reasons=reasons,
            suggested_mechanism_records=suggestions,
            suggestion_source=suggestion_source,
            suggestion_query_scope={
                "blocked_family": family_lower,
                "blocked_signature_prefix": _mechanism_signature(theory)[:8],
                "blocked_families_in_cycle": sorted(self.blocked_families_in_cycle),
                "max_per_call": 12,
                "kb_signature_schema_version": KB_SIGNATURE_SCHEMA_VERSION,
            },
        ),
    )
```

`self._kb_cache` is a per-cycle dict on the critic instance. Cache key is `(family_lower, blocked_signature)`; KB DB is queried at most once per unique key per cycle. The cache is cleared between cycles by re-instantiating the critic — Phase 1 already re-instantiates the critic at each batch construction, so no separate reset is needed.

The critic receives `blocked_families_in_cycle` and `static_exhaustion_blocklist` from the controller at the same batch construction time as Phase 1's `yield_index`, `prior_subfamilies`, and `prior_signatures`:

- `blocked_families_in_cycle = frozenset(f for f, v in yield_index.items() if v.status == "empirically_dead")` — derived from the snapshotted yield index; no extra ledger query.
- `static_exhaustion_blocklist` — the union of family names appearing in the controller's existing TIER_1 / TIER_2 elimination registries (already consulted by Phase 1's critic earlier in `evaluate()`); snapshotted once per cycle from the same source.

Order in `evaluate()` is unchanged: empirical-death stays at step 3.5, between duplicate-detection and contradiction. KB query cost is paid only when the gate would have fired anyway.

### 4.6 Controller wiring

`_assess_landscape()` (Phase 1) already snapshots yield indices. Phase 2 adds:

```python
def _assess_landscape(self) -> dict[str, Any]:
    # ... existing Phase 1 work (yield indices, escape pressure) ...

    # NEW: render KB-derived escape candidates from the prior cycle.
    landscape["escape_candidates"] = self._render_escape_candidates(
        status=self.state.last_escape_status,
        suggestions=self.state.last_escape_suggestions,
    )
    return landscape
```

`_write_cycle_escape_summary` (Phase 1 chokepoint) gains one input and one output field:

```python
def _write_cycle_escape_summary(
    self,
    *,
    status: EscapeStatus,
    families_blocked: list[str] = (),
    blocked_stats: list[tuple[str, FamilyYieldStats]] = (),
    rejections: list[EmpiricalDeathRejectionPayload] = (),   # NEW
) -> None:
    # ... existing Phase 1 streak / status / families logic ...

    # NEW: aggregate suggestions from this cycle's empirical-death rejections.
    suggestions_by_family: dict[str, list[CipherDiscoverySuggestion]] = {}
    for r in rejections:
        if not r.suggested_mechanism_records:
            continue
        suggestions_by_family.setdefault(r.family, []).extend(
            r.suggested_mechanism_records
        )

    # Cap per family, dedupe by mechanism_signature, sort deterministically.
    aggregated: list[dict[str, Any]] = []
    for fam, recs in sorted(suggestions_by_family.items()):
        seen_sigs = set()
        per_fam: list[CipherDiscoverySuggestion] = []
        for rec in recs:
            if rec.mechanism_signature in seen_sigs:
                continue
            seen_sigs.add(rec.mechanism_signature)
            per_fam.append(rec)
        per_fam.sort(key=lambda s: (
            not s.dispatcher_testable, -s.k4_relevance_score, s.canonical_name,
        ))
        for rec in per_fam[:3]:                  # 3-per-family cap at storage
            aggregated.append({**rec.to_dict(), "blocked_family": fam})

    aggregated.sort(key=lambda d: (
        not d["dispatcher_testable"], -d["k4_relevance_score"], d["canonical_name"],
    ))
    self.state.last_escape_suggestions = aggregated[:24]   # storage hard cap; render caps tighter
```

Storage cap of 24 keeps `ControllerState` JSON bounded; per-status render caps (§4.7) further trim what reaches the prompt.

All calls to `_write_cycle_escape_summary` from critic-exit paths pass `rejections=self._cycle_empirical_dead_rejections`. The Phase 1 chokepoint architecture (`_cycle_empirical_dead_rejections` accumulated during critic evaluation, escape summary written before any worker dispatch or outcome absorption) is preserved verbatim. **No rewiring through `_absorb_outcomes`** — that path handles worker results, not critic rejections, and an all-rejected cycle returns from critic without dispatching anything.

`ControllerState` gains one field:

```python
@dataclass
class ControllerState:
    # ... existing Phase 1 fields ...
    last_escape_suggestions: list[dict[str, Any]] = field(default_factory=list)
```

Stored as a JSON-friendly `list[dict]` rather than `list[CipherDiscoverySuggestion]` to avoid ad-hoc dataclass serialization through every existing `to_dict` path. The dict shape is `CipherDiscoverySuggestion.to_dict()` plus a `"blocked_family"` key. The `from_dict` path is exercised in tests and reused by `_render_escape_candidates` when reading back.

### 4.7 Theorist prompt rendering

`_render_escape_candidates(status, suggestions)` is a pure function. The render is conditional on the prior cycle's escape status, with hard caps:

```
status == "needed_but_unavailable":
  Render an "ESCAPE CANDIDATES" block, framed as required guidance.
  Caps: ≤ 8 total, ≤ 3 per blocked family.
  Ordering: dispatcher_testable first, then by k4_relevance_score desc.

status == "partial_empirical_block":
  Render a short "ADVISORY" block, framed as advisory (not mandate).
  Caps: ≤ 3 total.
  Ordering: same as above.

status ∈ {"none", "no_candidates", "needed_and_satisfied"}:
  Render nothing.

status not recognized:
  Render nothing; log WARNING once.
```

The render is the only place hard caps are *visible* to the theorist. Storage on `ControllerState` is capped at 24 to bound JSON size, but the prompt never sees more than 8.

Output format (illustrative, not normative — text is shaped by `render_escape_candidates`):

```
=== ESCAPE CANDIDATES (cipher-discovery KB, prior cycle blocked) ===

The prior cycle blocked all candidates with REJECT_EMPIRICALLY_DEAD across:
encoding (n=826), k2_coords (n=177).

Candidates from the K4-relevance-ranked discovery KB that have NOT been
tried in those families (mechanism signature unseen, ledger family not
blocked, dispatcher-testable where flagged):

  [dispatcher-testable]
    - Swagman Cipher (columnar; k4_relevance=42.2)
      One-line sketch: <truncated description>
      Bounded kill criterion: <rendered prompt guidance>

    - Tri-Square Cipher (Playfair family; k4_relevance=40.7)
      ...

  [Category-B investigative]
    - Astrolabe Cipher (positional; k4_relevance=67.4)
      ...

A candidate that you propose under one of these families must still
present an unseen mechanism_signature AND unseen subfamily to bypass the
empirical-death gate. The bypass discipline from Phase 1 is unchanged.
```

`needed_and_satisfied` is unreachable in Phase 1 and becomes reachable in Phase 2 only when a KB-suggested mechanism produces at least one critic-approved theory in the *current* cycle. The render path explicitly handles it (no render) so the enum value is never silently dropped.

## 5. Data flow

### 5.1 Worker-result path (crib-paste)

```
worker submits contract
  │
  ▼
contracts.py::_verify_against_kernel
  ├─ snapshot self-report
  ├─ validate PT shape (Phase 1 a-z guard)
  ├─ kernel recomputes crib_score / bean_passed / score
  ├─ ⟵ if verified_crib == 24:
  │      try: paste = _is_crib_paste_artifact(pt,
  │              verified_crib=24, non_crib_ngram_per_char=ngram_pc)
  │      except: paste = True   # fail-closed
  │      if paste:
  │          preserve verified values in raw_artifacts
  │          zero signal fields
  │          status = WorkerStatus.INCONCLUSIVE
  │          verification_error = "crib_paste_artifact:v1: ..."
  └─ return contract
  │
  ▼
_absorb_outcomes → ledger → alerts (Phase 1)
```

### 5.2 Critic + landscape path (KB injection)

```
                    CYCLE N
  ┌─────────────────────────────────────────────────────┐
  │ _begin_cycle_phase_state                            │
  │   self._cycle_empirical_dead_rejections = []        │
  │   self._kb_db_missing_logged_this_cycle = False     │
  │   (critic re-instantiated → fresh self._kb_cache)   │
  └────────────────────────┬────────────────────────────┘
                           │
                           ▼
  ┌─────────────────────────────────────────────────────┐
  │ _assess_landscape                                   │
  │   yield_index   = ...                  (Phase 1)    │
  │   escape_pressure = ...                (Phase 1)    │
  │   escape_candidates = _render_escape_candidates(    │
  │       status   = self.state.last_escape_status,     │
  │       suggestions = self.state.last_escape_suggestions, │
  │   )                                                 │
  └────────────────────────┬────────────────────────────┘
                           │
                           ▼
  ┌─────────────────────────────────────────────────────┐
  │ _generate_theories → critic                         │
  │   for theory in candidates:                         │
  │     verdict = critic.evaluate(theory)               │
  │     if verdict.decision == REJECT_EMPIRICALLY_DEAD: │
  │        kb_injection.query_suggestions(...)          │
  │        cache by (family_lower, blocked_signature)   │
  │        verdict.empirical_death.suggested_*_records  │
  │        append payload to                            │
  │          self._cycle_empirical_dead_rejections      │
  └────────────────────────┬────────────────────────────┘
                           │
              approved == 0│
                           ▼
  ┌─────────────────────────────────────────────────────┐
  │ _write_cycle_escape_summary(                        │
  │   status = "needed_but_unavailable",                │
  │   families_blocked = [...],                         │
  │   rejections = self._cycle_empirical_dead_rejections│
  │ )                                                   │
  │   → aggregate suggestions per family                │
  │   → cap per family, dedupe, sort                    │
  │   → write ControllerState.last_escape_suggestions   │
  │   → increment escape_needed_streak                  │
  └────────────────────────┬────────────────────────────┘
                           │ early-continue
                           ▼
                    CYCLE N+1 START
                    ↑ landscape sees ControllerState.last_escape_suggestions
```

### 5.3 Invariants

1. **KB is generator, not novelty authority.** `query_suggestions` cannot promote a candidate to bypass the empirical-death gate. The critic's existing `prior_mechanism_signatures_in_family` snapshot is the only authority for whether a theory's signature is "unseen."
2. **No suggestion is ever auto-dispatched.** Suggestions are prompt context only. Phase 1's structural-novelty bypass remains the only gate that lets a dead-family theory through.
3. **Unmapped KB family → silent on prompt.** `verdict="defer_needs_mapping"` candidates are logged at WARNING with `kb_record_id` and `kb_cipher_family`, never rendered. Operator path: `grep "defer_needs_mapping" logs/` → curate addition to `KB_TO_LEDGER_FAMILY`.
4. **Storage decoupled from render.** `ControllerState.last_escape_suggestions` capped at 24 for JSON size; render caps at 8 (full block) / 3 (partial / advisory). The two limits are independent — render-cap changes do not require a state rewrite.
5. **Detector fails closed, KB injection fails open.** Crib-paste detector failure → treat as paste (no false promotion). KB query failure → empty suggestion list (theorist falls back to Phase 1 escape pressure).
6. **No cycle-summary writes ever go through `_absorb_outcomes`.** Critic rejections are aggregated during the critic phase; escape summary is written before any worker dispatch on full-block cycles. `_absorb_outcomes` continues to handle worker results only.

### 5.4 Streak semantics (Phase 1, unchanged)

Phase 1's streak rules remain authoritative. Phase 2 changes only what is *attached* to escape summaries, not when they are written:

```
status == "needed_but_unavailable":  streak += 1
status == "partial_empirical_block": streak  = 0   (brake redirected)
status == "no_candidates":           streak  = 0   (theorist failure, not empirical-death)
status == "none":                    streak  = 0
status == "needed_and_satisfied":    streak  = 0   (Phase 2 reachable)
```

## 6. Operational concerns

### 6.1 Configuration

No CLI flag. Crib-paste threshold is hard-coded with `crib_paste_artifact:v1` schema version. KB DB path defaults to `db/cipher_discovery.sqlite`, overridable via constructor injection in tests (`critic._kb_db_path`). Family map and DSL-kind map live in `kb_family_map.py` and grow by curated audit.

### 6.2 Persistence

| Surface | Change | Compat |
|---|---|---|
| `theories` table | none | read-only new query in `kb_injection` |
| `cipher_discovery.sqlite` | none | read-only query |
| `controller_state` JSON | 1 new key: `last_escape_suggestions: list[dict]` | dataclass default `[]`; pre-Phase-2 rows load cleanly |
| `theories.critic_verdict` JSON | renamed/widened key inside `empirical_death`: `suggested_mechanism_records: list[dict]` | absent on pre-Phase-2 rows; reader tolerates missing key |
| `CriticDecision` enum | unchanged | Phase 1 added `REJECT_EMPIRICALLY_DEAD` |

The `suggested_mechanism_records` field carries fully-serialized dicts (not nested dataclasses) to avoid ad-hoc round-trip handling through every existing JSON consumer. `CipherDiscoverySuggestion.to_dict()` and `EmpiricalDeathRejectionPayload.to_dict()` are the canonical serialization paths and are unit-tested directly.

### 6.3 Backward compatibility

- Phase 1's `suggested_mechanisms: tuple[str, ...] = ()` is renamed to `suggested_mechanism_records: tuple[CipherDiscoverySuggestion, ...] = ()`. Phase 1 never populated the field, so the rename is safe. The dispatch-site audit (Phase 1 Task 8) is repeated to confirm no reader relies on the old name.
- Pre-Phase-2 ledger rows that carry `empirical_death.suggested_mechanisms` from a Phase 1 snapshot are tolerated by `EmpiricalDeathRejectionPayload.from_dict`: it reads either name and treats both as empty if not a list of dicts.
- Pre-Phase-2 `ControllerState` JSON without `last_escape_suggestions` loads cleanly via dataclass default.

### 6.4 Fail-open and fail-closed posture

- **Crib-paste detector**: fail-closed. Detector raises → treat as paste, zero signal fields. The only way to false-positive is for the detector itself to misfire on a legitimate 24/24 with non-paste ngram floor; pre-registered threshold of -6.2 is far below the kernel's already-existing ngram floor (-5.5), so legitimate signal candidates remain unaffected.
- **KB injection**: fail-open. Missing DB / corrupt row / unknown cipher_family → empty `suggested_mechanism_records`, `suggestion_source="none"`. The empirical-death gate continues to fire as in Phase 1; only the redirect content is missing. WARNING is logged at most once per cycle, regardless of how many rejections fired.

### 6.5 Logging discipline

| Event | Level | Frequency |
|---|---|---|
| Crib-paste detected | INFO | per event |
| Crib-paste detector raised | WARNING | per event |
| KB DB missing | WARNING | **once per cycle** (controller-level flag, not critic-level) |
| KB DB corrupt row | WARNING | per row |
| KB candidate `defer_needs_mapping` | WARNING | per candidate, with `kb_record_id` and `kb_cipher_family` |
| Suggestions populated | DEBUG | per rejection |

Once-per-cycle KB-missing logging is enforced by a single flag on the controller (`self._kb_db_missing_logged_this_cycle: bool`) that the critic checks before issuing the WARNING. Reset by `_begin_cycle_phase_state`.

### 6.6 Documentation touchpoints

| File | Change |
|---|---|
| `kryptosbot/ARCHITECTURE.md` | extend Family-yield section with Phase 2 KB-injection subsection |
| `kryptosbot/ORIENT.md` | add §5.7: "Critic populated suggested_mechanism_records / Worker contract rejected as crib_paste" |
| `CLAUDE.md` | none |
| `MEMORY.md` | one entry on Phase 2 landing |
| `docs/audits/controller_maturity_audit_2026_05_16.md` | annotate Tier A #1 + Phase 1 §7.1 as LANDED post-merge |

## 7. Out of scope / forward design

### 7.1 Phase 3 (deferred, unchanged from Phase 1 spec §7.2)

Ledger-driven curated few-shot library. Harvests `REJECT_EMPIRICALLY_DEAD` rejections (now carrying Phase 2 KB suggestions), approved-and-survived theories, and structured disproofs into a few-shot example bank for the theorist system prompt. Lands only after Phase 2 has changed the family allocation distribution; the harvest mirrors current bias if it runs too early.

### 7.2 Partial-paste detection at `crib_score` 18–23

Out of scope for Phase 2. The live ledger has zero events in this band; pre-registering a threshold without empirical examples invites overfit. If partial paste appears in a future ledger snapshot, that is a Phase 2.1 hotfix with a new pre-reg and a versioned threshold (`crib_paste_artifact:v2`).

### 7.3 Persisting KB signatures on `cipher_discovery.sqlite`

Out of scope. Per-cycle hash cost over 83 records is negligible. Persisting introduces migration surface before the signature algorithm has been validated; if the schema changes, persisted signatures go stale. `signature_schema_version` is emitted in every suggestion payload for forward-compat.

### 7.4 Curated few-shot rendering of suggestions

Out of scope. Phase 2 ships one-line sketches drawn directly from KB description / mechanics text plus a `bounded_kill_criterion` field. Phase 3 may replace the templated render with curated examples.

## 8. Testing

Phase 2 follows the project's `superpowers:test-driven-development` posture. Pure modules first, integration second, characterization against the existing trace last. Approximately 400 LOC across six new test files plus targeted updates.

### 8.1 Test layer breakdown

| Layer | File | New / Update | What it proves |
|---|---|---|---|
| Pure detector | `tests/test_crib_paste_detector.py` | new | 8 ledger events all detected; benign 24/24 with legitimate PT not detected; non-A-Z handled by Phase 1 guard first; threshold boundary at -6.2 exact; detector exception → fail-closed; `_non_crib_ngram_per_char` masks correct positions |
| Pure KB injection | `tests/test_kb_injection.py` | new | `kb_mechanism_signature` deterministic + key-order-insensitive; `dispatcher_testable` matches `_SUPPORTED_KINDS`; `query_suggestions` returns only `verdict=="allow"`; missing DB → `()` and once-per-cycle log; corrupt row skipped with WARNING; deterministic ranking; cache hit on repeat key |
| Family map | `tests/test_kb_family_map.py` | new | every key resolves; every value is a non-empty frozenset; every value member is in `valid_ledger_family_universe()`; unmapped → `defer_needs_mapping`; DSL-kind values are in `_SUPPORTED_KINDS`; **value-resolution test runs against the union of `KNOWN_FAMILIES.family_id` and historical `ledger.theories.family`, not against a test fixture** |
| Contracts integration | `tests/test_contracts.py` | update | `_verify_against_kernel` integration: 24/24 paste → INCONCLUSIVE + zeroed + artifact_class set; 24/24 non-paste (legitimate signal) → preserved; non-paste 18/24 untouched; detector exception → fail-closed without disturbing rest of verifier |
| Critic + KB integration | `tests/test_critic_empirical_death.py` | update | `REJECT_EMPIRICALLY_DEAD` payload populated with non-empty `suggested_mechanism_records` when seeded fixture KB has candidates; empty + `suggestion_source="none"` when not; cache hit on repeat `(family, signature)` within a cycle |
| Escape summary aggregation | `tests/test_cycle_escape_telemetry.py` | update | `_write_cycle_escape_summary` aggregates rejections by family, dedupes by signature, caps to 3 per family at storage, sorts deterministically, caps to 24 total at storage |
| Cycle-loop characterization | `tests/test_cycle_loop_characterization.py` | re-baseline | new canonical event `on_kb_suggestions_collected`; all-critic-rejected cycle writes escape summary BEFORE early-continue (regression guard against `_absorb_outcomes` mis-wiring); existing trace unchanged otherwise |
| Render | `tests/test_landscape_yield_packet.py` | update | `needed_but_unavailable` → up to 8 rendered, 3-per-family cap; `partial_empirical_block` → advisory up to 3; `none`/`no_candidates`/`needed_and_satisfied` → no KB block; unknown status → no render + WARNING |
| JSON round-trip | `tests/test_kb_serialization.py` | new | `CipherDiscoverySuggestion` `to_dict`/`from_dict` round-trips; `EmpiricalDeathRejectionPayload` with non-empty suggestions round-trips through the existing `critic_verdict` JSON column; `ControllerState.last_escape_suggestions` round-trips through `controller_state` JSON column |
| Acceptance | `tests/test_phase2_acceptance.py` | new | end-to-end with a **fixture-backed `cipher_discovery.sqlite`** (4-5 seeded rows covering dispatcher-testable, Category-B, exhausted, unmapped); crib-paste worker contract → zeroed without promotion; KB-empty cycle → fail-open behavior |
| Smoke | `tests/test_phase2_live_kb_smoke.py` | new (skipped on CI) | live `db/cipher_discovery.sqlite` query returns ≥1 candidate for at least one empirically-dead family; `@pytest.mark.skipif(not Path("db/cipher_discovery.sqlite").exists())` so CI is unaffected |

### 8.2 Named invariants (must each have a test)

```
test_crib_paste_detector_fires_at_threshold
test_crib_paste_detector_does_not_fire_for_legitimate_24_24
test_crib_paste_detector_exception_fails_closed
test_non_crib_ngram_per_char_masks_correct_positions
test_kb_signature_deterministic_under_key_reorder
test_kb_signature_excludes_ledger_family_mapping
test_kb_signature_includes_schema_version
test_kb_query_missing_db_returns_empty_and_logs_once_per_cycle
test_kb_query_corrupt_row_skipped_with_warning
test_kb_query_dispatch_testable_ranks_first
test_kb_family_map_values_resolve_to_real_families
test_kb_family_map_unmapped_returns_defer_needs_mapping
test_critic_populates_suggestions_on_empirically_dead
test_critic_cache_hit_on_repeat_family_signature
test_critic_no_kb_query_when_bypass_satisfied
test_kb_suggestion_round_trips_through_critic_verdict_json
test_controller_state_last_escape_suggestions_round_trips
test_all_critic_rejected_cycle_writes_escape_summary_before_continue
test_escape_summary_aggregates_dedupes_caps_at_3_per_family
test_render_needed_but_unavailable_caps_at_8_total
test_render_partial_empirical_block_caps_at_3_total
test_render_none_emits_no_kb_block
test_render_needed_and_satisfied_emits_no_kb_block
test_kb_db_missing_logged_once_per_cycle_not_per_rejection
test_phase1_to_phase2_payload_compat_old_field_name_tolerated
```

### 8.3 Coverage target

- `kb_injection.py`: 100% branch coverage on `kb_mechanism_signature`, `dispatcher_testable`, novelty-join state machine, `query_suggestions` filter pipeline.
- `kb_family_map.py`: 100% line + every key reached.
- Crib-paste detector: 100% branch on `_is_crib_paste_artifact` + `_non_crib_ngram_per_char`.
- `_write_cycle_escape_summary` aggregation block: 100% branch.

### 8.4 Existing tests impact

| Test file | Impact |
|---|---|
| `test_cycle_loop_characterization.py` (test G) | New canonical event `on_kb_suggestions_collected`. Re-baseline once after merge. |
| `test_critic_*.py` (general) | Audit every `EmpiricalDeathRejectionPayload` construction site to confirm rename `suggested_mechanisms → suggested_mechanism_records` does not break readers. |
| `test_theory_ledger.py` controller-state round-trip | One new assertion for the `last_escape_suggestions` field. |
| `test_landscape_yield_packet.py` (test_shared_symmetry_invariant) | No change; KB rendering is independent of yield-classification symmetry. |

## 9. Files touched

```
NEW:
  kryptosbot/kb_injection.py
  kryptosbot/kb_family_map.py
  kryptosbot/tests/test_kb_injection.py
  kryptosbot/tests/test_kb_family_map.py
  kryptosbot/tests/test_crib_paste_detector.py
  kryptosbot/tests/test_kb_serialization.py
  kryptosbot/tests/test_phase2_acceptance.py
  kryptosbot/tests/test_phase2_live_kb_smoke.py
  kryptosbot/tests/fixtures/cipher_discovery_phase2_fixture.sqlite

UPDATE:
  kryptosbot/contracts.py                       (crib-paste detector inside _verify_against_kernel)
  kryptosbot/models.py (or wherever payload lives)
                                                (rename field, widen type, to_dict/from_dict)
  kryptosbot/critic.py                          (KB query in _check_family_empirically_dead, cache, db_path injection)
  kryptosbot/controller.py                      (escape-summary aggregation, _render_escape_candidates,
                                                 _begin_cycle_phase_state resets _kb_db_missing_logged_this_cycle and re-instantiates critic (fresh _kb_cache),
                                                 ControllerState.last_escape_suggestions)
  kryptosbot/pantheon.py                        (landscape prompt extension for escape_candidates block)
  kryptosbot/tests/test_contracts.py            (24/24 paste + legitimate cases)
  kryptosbot/tests/test_critic_empirical_death.py
                                                (assert suggestions populated + cached)
  kryptosbot/tests/test_cycle_escape_telemetry.py
                                                (aggregation, dedup, caps)
  kryptosbot/tests/test_cycle_loop_characterization.py
                                                (re-baseline + all-rejected-pre-continue regression test)
  kryptosbot/tests/test_landscape_yield_packet.py
                                                (render caps under each status)
  kryptosbot/tests/test_theory_ledger.py        (round-trip assertion for last_escape_suggestions)
  kryptosbot/ARCHITECTURE.md                    (Phase 2 subsection)
  kryptosbot/ORIENT.md                          (§5.7)
  MEMORY.md                                     (Phase 2 landing, post-merge)
  docs/audits/controller_maturity_audit_2026_05_16.md
                                                (Tier A #1 + Phase 1 §7.1 annotated LANDED, post-merge)
```

## 10. Acceptance criteria

This spec is satisfied when, on a clean checkout plus the fixture-backed test KB:

1. A worker contract with `crib_score=24`, `pt[21:34]=="EASTNORTHEAST"`, `pt[63:74]=="BERLINCLOCK"`, and garbage elsewhere (ngram per-char <= -6.2 on the non-crib positions) returns from `_verify_against_kernel` with `crib_score=0`, `bean_passed=False`, `status=WorkerStatus.INCONCLUSIVE`, `raw_artifacts["artifact_class"]=="crib_paste"`, and `raw_artifacts["kernel_verified_before_artifact_filter"]["crib_score"]==24`.
2. A worker contract with `crib_score=24` from a legitimate solution candidate (non-paste PT, non-crib ngram per-char > -5.5) passes through unchanged.
3. A `REJECT_EMPIRICALLY_DEAD` in an `encoding`-family theory, evaluated against the **fixture-backed test KB** that contains at least one record mapped to a non-blocked ledger family with an unseen signature, yields `CriticVerdict.empirical_death.suggested_mechanism_records` with at least one entry having `source_verdict=="allow"` and the expected `mechanism_signature` value. (Live KB is exercised by `test_phase2_live_kb_smoke.py`, skipped on CI.)
4. A cycle that ends with `escape_status="needed_but_unavailable"` writes `ControllerState.last_escape_suggestions` aggregated by blocked family (capped at 3 per family at storage, 24 total at storage); the *next* cycle's theorist prompt renders an "ESCAPE CANDIDATES" block with at most 8 total suggestions and at most 3 per family.
5. A cycle that ends with `escape_status="partial_empirical_block"` renders an advisory block of at most 3 suggestions, framed as advisory.
6. A cycle that ends with `escape_status="none"`, `"no_candidates"`, or `"needed_and_satisfied"` renders no KB block.
7. KB query cache hits on duplicate `(family, blocked_signature)` within a cycle (verified by mock counter).
8. Missing `db/cipher_discovery.sqlite` → `suggestion_source="none"`, `suggested_mechanism_records=()`, exactly one WARNING logged per cycle regardless of rejection count.
9. An all-critic-rejected cycle writes `_write_cycle_escape_summary` with `status="needed_but_unavailable"` and populated `last_escape_suggestions` *before* any early-continue. This is checked by `test_cycle_loop_characterization.py` against the canonical trace, guarding against the wiring failure mode where rejection aggregation drifts into `_absorb_outcomes` (which is unreachable on all-rejected cycles).
10. `EmpiricalDeathRejectionPayload` with non-empty `suggested_mechanism_records` round-trips through the `theories.critic_verdict` JSON column. `ControllerState.last_escape_suggestions` round-trips through the `controller_state` JSON column.
11. Every value in `KB_TO_LEDGER_FAMILY` is in `valid_ledger_family_universe() = KNOWN_FAMILIES.family_id ∪ ledger.theories.family` (snapshot taken at test time). Every value in `KB_TO_DSL_KIND` is in `job_dispatcher._SUPPORTED_KINDS`.
12. The full new test suite passes. Existing Phase 1 tests pass.
13. `MEMORY.md` and `docs/audits/controller_maturity_audit_2026_05_16.md` are annotated post-merge.

---

*Phase 2 closes the redirect direction of the yield-feedback loop and removes the false-promotion artifact path. The critic now answers "this family is dead — and here are the unseen mechanisms from the discovery KB that you could try instead" with structured, JSON-serializable suggestion records, gated by the same structural-novelty discipline Phase 1 introduced. Phase 3 (curated few-shot library) becomes useful only after Phase 2 changes the empirical family distribution.*
