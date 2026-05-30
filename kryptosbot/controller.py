"""
Persistent research controller for KryptosBot.

Long-lived orchestrator that manages the search process, not directly
"solve K4" in one step. Maintains structured campaign state, consults
prior hypotheses and eliminations, generates candidate theories,
runs a critic pass, dispatches survivors to workers, and absorbs outcomes.

The controller never parses free-text for control flow decisions.
All inter-component communication uses typed models from models.py.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from claude_agent_sdk import ClaudeAgentOptions

from .config import KryptosBotConfig, HypothesisStatus as LegacyStatus
from .contracts import (
    ParseResult, validate_worker_contract, validate_theory_proposals,
    TheoryParseReport,
)
from .critic import TheoryCritic
from .models import (
    TheoryRecord, TheoryStatus,
    CriticVerdict, CriticDecision,
    WorkerContract, WorkerStatus,
    ExperimentRecord,
    EvidenceLink, EvidenceType,
    ControllerState,
    PursuitLead, PursuitLeadStatus,
    PURSUIT_SOURCE_PURSUE, PURSUIT_SOURCE_SKIP_VARIANTS,
)
from .pantheon import (
    AgentSpec,
    DEFAULT_AGENTS_DIR,
    load_roster,
    resolve_model_for_phase,
)
from .pantheon_siblings import (
    RedTeamVerdict,
    StatAuditVerdict,
    CycleSynthesis,
    PursuitVerdict,
    run_red_team_precheck,
    run_stat_audit,
    run_results_synthesis,
    run_pursuit_evaluator,
)
from .registries import bootstrap_all
from .research_tools import set_ledger, set_canonical_facts
from .routing import (
    describe_routing_table,
    select_redteam,
    select_results_analyst,
    select_stat_auditor,
    select_theorist,
    select_worker,
    select_pursuit_evaluator,
)
from .sdk_wrapper import safe_query, classify_error, extract_sdk_text_content
from .theory_ledger import TheoryLedger
from .claims_registry import CANONICAL_CLAIMS, CANONICAL_CLAIMS_BY_ID
from .claim_rendering import render_claim_inline
from .claim_policy import can_use_in_prompt
from .family_yield import FamilyYieldStats

# Reverse map anomaly_id -> claim_id (for interpretive claims, which are what
# the controller actually surfaces in prompts). Existence claims are not used
# as ranking/prompt anchors — the interpretive counterpart is.
_ANOMALY_TO_CLAIM_ID: dict[str, str] = {}
for _c in CANONICAL_CLAIMS:
    if _c.related_anomaly_id:
        # Prefer interpretive claims over bare existence claims when both exist.
        existing = _ANOMALY_TO_CLAIM_ID.get(_c.related_anomaly_id)
        if existing is None:
            _ANOMALY_TO_CLAIM_ID[_c.related_anomaly_id] = _c.claim_id
        else:
            prev = CANONICAL_CLAIMS_BY_ID[existing]
            from .provenance import EpistemicClass as _EC
            if (prev.epistemic_class == _EC.PHYSICAL_FACT
                    and _c.epistemic_class != _EC.PHYSICAL_FACT):
                _ANOMALY_TO_CLAIM_ID[_c.related_anomaly_id] = _c.claim_id


def _render_anomaly_line(anomaly_id: str, fallback_title: str) -> str:
    """Render an anomaly for prompt context via the provenance layer.

    Falls back to the raw title if no canonical claim is registered.
    """
    claim_id = _ANOMALY_TO_CLAIM_ID.get(anomaly_id)
    if claim_id:
        claim = CANONICAL_CLAIMS_BY_ID.get(claim_id)
        if claim is not None:
            ok, _ = can_use_in_prompt(claim)
            if ok:
                return f"[{claim.claim_id}] {render_claim_inline(claim)}"
    return fallback_title

logger = logging.getLogger("kryptosbot.controller")


def _extract_message_text(content: Any) -> str:
    """Extract raw text from a ``claude_agent_sdk`` AssistantMessage.content.

    Post-K4-cycle-1 hygiene (2026-04-21). The SDK streams
    AssistantMessage objects whose ``content`` attribute is typically a
    list of ContentBlock dataclasses (TextBlock, ThinkingBlock,
    ToolUseBlock). Calling ``str()`` on such a list returns a Python
    repr like
    ``"[TextBlock(citations=None, text='[\\n  {\"title\":...', type='text')]"``
    which silently breaks downstream JSON extraction — the repr's
    single-quoted string value and escaped newlines confuse
    ``validate_theory_proposals`` / ``validate_worker_contract`` and
    their ``extract_json_block`` helper, causing the theorist or
    worker output to appear empty and the controller to fall through
    to programmatic fallback paths.

    This helper extracts text from each block explicitly:

    - ``TextBlock`` (``.type == "text"``) → ``.text``
    - ``ThinkingBlock`` (``.type == "thinking"``) → skipped (never JSON
      payload; leaking it into the parsed text can pollute JSON scans)
    - Any other block with a ``.text`` attribute → included as a
      best-effort fallback
    - Unknown block types without ``.text`` → skipped silently

    Non-list content (e.g., a plain string from legacy SDK shapes) is
    returned as ``str(content)`` unchanged.

    See ``docs/maturation/round3/K4_RUN_CYCLE1_DIAGNOSTIC.md`` for the
    bug history.
    """
    return extract_sdk_text_content(content)


def _raw_contains_json_like_structure(raw: str) -> bool:
    """Best-effort signal that a payload likely attempted structured output."""
    text = raw or ""
    return (
        "```json" in text
        or bool(re.search(r"\[\s*\{", text))
        or bool(re.search(r"\{\s*\"", text))
    )


def _looks_like_sdk_repr_mangling(raw: str) -> bool:
    """Detect Python repr-shaped SDK content that should have been normalized."""
    text = raw or ""
    return any(
        marker in text for marker in (
            "TextBlock(",
            "ThinkingBlock(",
            "ToolUseBlock(",
            "[FakeTextBlock(",
        )
    )


_RETRACTED_RECENT_OUTCOME_PATTERNS: tuple[str, ...] = (
    "4, 8, 10, 26 = col",
    "sequential four-width columnar transposition",
)


def _is_retracted_recent_outcome(theory: TheoryRecord) -> bool:
    """Hide stale recent-outcome titles that depend on retracted archive OCR.

    Historical ledger records remain intact for auditability. This filter only
    prevents the live landscape panel from surfacing the retracted
    '"4, 8, 10, 26 = Col"' archival justification as if it were an active
    prompting surface.
    """
    blob = f"{theory.title} {theory.core_claim} {theory.notes}".lower()
    return any(pat in blob for pat in _RETRACTED_RECENT_OUTCOME_PATTERNS)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_hcc_seed(theory: TheoryRecord) -> bool:
    """True iff this theory is a deterministic HandCipherCore seed.

    HCC seeds are challenge-local, parameter-enumerated cipher
    pipelines emitted by ``bench_fallback.hand_cipher_core_fallback``;
    they are deterministic in the sense that no LLM call shapes them
    and no adversarial pre-check changes their predicted outcome. The
    durable discriminator is ``minimal_test_spec.method ==
    "bench_hand_cipher_core"`` — more specific than ``origin ==
    "programmatic_fallback"`` (which the real-K4 fallback path also
    uses) and stable across the bench-mode pipeline.

    Used by the K4Bench cost-control gates in ``_red_team_filter``:
    when ``redteam_min_crib_score > 0`` HCC seeds bypass the LLM
    sibling call without affecting LLM-generated theories.
    """
    spec = theory.minimal_test_spec or {}
    return spec.get("method") == "bench_hand_cipher_core"


# ---------------------------------------------------------------------------
# Search-space risk policy (Priority 5)
# ---------------------------------------------------------------------------
#
# Day 5 shipped a lexicon-based classifier (_classify_concern_risk /
# _BUDGET_RISK_TOKENS) that inferred a risk label from red-team reasons
# prose. The Day 6 6x5 verification run falsified the approach: across
# three cycles (65-67), ~80% of the lexicon's "unbounded_search" flags
# were semantic misclassifications of concerns that belonged in
# exhausted_source_material, underconstrained, duplicate_family, or
# residual_caution buckets. See
# feedback_concerned_vs_search_space_risk_separation.md.
#
# Priority 5 replaces the lexicon with a structured field on
# RedTeamVerdict: search_space_risk, emitted directly by the red-team
# agent. The controller reads it off verdict.search_space_risk with
# no inference step. The lexicon and its tests are gone — no fallback.
#
# Only one value triggers the BOUNDED-SEARCH POLICY worker prompt
# injection: "unbounded_search". The other non-none values get their
# own tailored warning blocks or no injection at all. See
# _build_worker_prompt below for the switch.
#
# POLICY UPDATE 2026-04-17: search_space_risk="duplicate_family" no
# longer dispatches clean. The taxonomy defines duplicate_family as
# "the mechanism has been structurally eliminated; re-running under a
# new name would produce the same result" — which is logically a
# rejection. The controller now escalates CONCERNED+duplicate_family
# to REJECT in _red_team_filter, before the worker prompt is built.
# This reverses the original Priority-5 choice; see _red_team_filter
# for the rationale and the run evidence that motivated it.


# ---------------------------------------------------------------------------
# Campaign-A hardening (2026-04-22) — runtime halt thresholds
# ---------------------------------------------------------------------------
#
# Red-team finding: R3 protocol §5 enumerated halt conditions (three
# consecutive programmatic-fallback cycles, three consecutive cycles
# with D-column = 0, matched_null_miss on a BREAKTHROUGH) but none of
# them were wired into either cycle loop. Only should_abort_run (fatal
# agent failure) was live. An overnight run could drift for 15 cycles
# in a silently-degraded state.
#
# These thresholds are module-level so tests can monkeypatch them down
# to 1-2 for fast-failing coverage. The live loops consume them via
# ResearchController._check_cycle_hardening_halts which consolidates
# all three halt checks into one decision point, called after alert
# processing (step 5b). Both controller.run and run_controller.do_run
# must consult the result (feedback_dup_cycle_loop_trap.md).

# Three consecutive cycles where _programmatic_fallback emitted any
# theory with origin="programmatic_fallback" ⇒ halt. The theorist
# agent is broken; investigate before burning more compute.
FALLBACK_HALT_STREAK: int = 3

# Three consecutive dispatched cycles with zero REJECTED_ADMISSIBILITY
# contracts ⇒ halt. D-column=0 for three in a row means either (a)
# theorists are only proposing trivially-admissible specs, or (b) the
# prompt is narrow enough that admissibility has nothing to filter,
# or (c) everything is routing to the legacy path and the DSL is not
# exercised. All three are concerning; the operator should intervene.
# Cycles with zero dispatched contracts do NOT increment the counter
# (they are not "D=0" in a meaningful sense).
D_ZERO_HALT_STREAK: int = 3


# ---------------------------------------------------------------------------
# Controller configuration
# ---------------------------------------------------------------------------

@dataclass
class ControllerConfig:
    """Configuration for the research controller."""
    # Paths
    project_root: Path = Path(".")
    ledger_db_path: Path = Path("db/theory_ledger.sqlite")

    # Cycle control
    max_cycles: int = 10
    theories_per_cycle: int = 5
    max_concurrent_workers: int = 4
    worker_timeout_minutes: int = 30

    # Agent SDK
    allowed_tools: list[str] = field(
        default_factory=lambda: ["Read", "Write", "Edit", "Bash", "Glob", "Grep"]
    )
    permission_mode: str = "bypassPermissions"

    # Theorist model (for hypothesis generation)
    # Bumped from 15 to 40 on 2026-04-12 after the Day 2 Pantheon
    # integration. Pre-Pantheon, the generic theorist was a one-shot and
    # 15 turns was plenty. With Pantheon personas loaded via
    # theorist_system_prompt(), keystream-forensics needed 24 turns for
    # just 2 hypotheses in the _day2_probe_generation.py smoke test;
    # for a full 5-hypothesis cycle it will need ~35-45 turns of
    # extended-thinking budget. 40 gives headroom without being
    # extravagant.
    theorist_max_turns: int = 40

    # Worker model
    # Bumped from 25 to 50 on 2026-04-13 after Day 4 verification run
    # showed cycle 46 theory 919ee772 failing contract validation with
    # "No fenced JSON block found" at 102 stream-content-turns / ~7
    # minutes wall time. The original 25 was calibrated for the
    # pre-Pantheon generic worker that did minimal tool use. Under the
    # Day 4 persona-loaded worker path, workers are expected to
    # (per their Tool Discipline stat) check existing infrastructure,
    # possibly write test scripts, run them, and then emit a fenced
    # JSON result. That sequence needs more turn budget — 50 gives
    # comfortable headroom without being extravagant.
    worker_max_turns: int = 50

    # Behavior
    skip_critic: bool = False
    skip_red_team: bool = False    # bypass the proposal-time red-team-disprover sibling call
    skip_stat_audit: bool = False  # bypass the post-execution statistical-auditor sibling call (Day 5)
    skip_synthesis: bool = False   # bypass the end-of-cycle results-analyst synthesis (Day 5)
    dry_run: bool = False          # generate + critic but don't dispatch

    # Alerting — contradiction detector for the elimination ledger.
    # NOT a victory bell. See alerts.py for the rationale.
    alert_threshold: str = "signal"  # "none" | "signal" | "breakthrough"

    # Day 5 stat-audit threshold. Any contract with kernel-verified
    # crib_score >= this value is sent to statistical-auditor for
    # post-execution review. Default mirrors SIGNAL_THRESHOLD (18) from
    # the kernel scoring layer.
    stat_audit_threshold: int = 18

    # Day 6 lead-pursuit thresholds (inclusive). Any contract with
    # kernel-verified crib_score in [lo, hi] is sent to the pursuit
    # evaluator for follow-up classification. 6-17 covers the
    # "interesting but not signal" band — above noise, below stat-audit.
    lead_pursuit_lo: int = 6
    lead_pursuit_hi: int = 17
    skip_lead_pursuit: bool = False
    # Auto-close stale open leads after N cycles without a downstream
    # theorist reference. 0 disables auto-close.
    lead_pursuit_stale_cycles: int = 3

    # Max soft leads (source_verdict='skip_variants') surfaced per
    # theorist prompt. Intentionally small — soft leads carry weaker
    # provenance (the evaluator rejected the specific lead) so we
    # cap hard to avoid prompt sludge.
    soft_pursuit_leads_prompt_cap: int = 3

    # R2-5 (2026-04-21): self-test mode. When set, the controller
    # routes scoring through kryptosbot.panel_cribs instead of the
    # K4-specific kernel constants, caps cycles and USD spend, and
    # tags ledger entries with panel:<id> so they're segregated from
    # real K4 research. None = normal K4 operation.
    #
    # The brief's §6.1 policy:
    #   - ``self_test_mode`` is the single switch that enables real-
    #     API K1/K2/K3 runs.
    #   - ``self_test_max_cycles`` hard-caps the cycle count.
    #   - ``self_test_max_usd`` hard-caps API spend.
    #   - Whichever trips first halts with an explicit status.
    self_test_mode: Optional[str] = None  # None | "k1" | "k2" | "k3"
    self_test_max_cycles: int = 20
    self_test_max_usd: float = 5.00

    # Day 6 hardening priority #1: bounded-search policy total-
    # configuration cap. When red-team flags a theory as
    # unbounded_search, the worker prompt requires the worker to bound
    # its test envelope below this threshold or return
    # needs_bounded_design. Pulled out of the hardcoded 5000 in
    # _build_worker_prompt so lead pursuit can use a tighter cap for
    # narrower follow-up sweeps.
    bounded_search_max_configurations: int = 5000

    # Campaign-C toggles (2026-04-24): provenance-split gates for the
    # prompt-content blocks originally bundled under the single Oranchak
    # block. Split per K4_CAMPAIGN_C_PREREG.md so the Oranchak community-
    # corpora effect can be isolated from the AAA-archive serpentine-
    # Vigenère anchor effect. Both default True — Campaign-A prompt
    # state is `(True, True)`, identical to pre-split behavior. The
    # `--no-oranchak` CLI shorthand still sets both False
    # (Campaign-A launch reproducibility).
    include_oranchak_corpora: bool = True   # community-derived keyword pools + fills CSV
    include_serpentine_anchor: bool = True  # AAA archive page 17 Sanborn quote

    # K4Bench input mode (2026-04-26): when both fields are non-None
    # the controller is running against one synthetic challenge JSON
    # instead of real K4. The kernel CT/cribs are already overridden
    # via env vars at this point — these fields carry the prompt-side
    # surface (bench_id, suite_id, clue text, solver contract). Set
    # together by run_controller.main when --bench-challenge is given.
    # When None, real-K4 prompt assembly is unchanged.
    bench_challenge_payload: Optional[dict[str, Any]] = None
    bench_challenge_prompt_block: Optional[str] = None

    # HandCipherCore deterministic-seed controls (2026-04-27).
    # Active only in bench mode; in real-K4 mode both fields are
    # ignored because _collect_hcc_seeds returns [] regardless.
    #
    #   hcc_seeds_cap = None  → emit the full HCC catalogue (default,
    #                            currently up to 64 specs from
    #                            generate_layered_specs)
    #   hcc_seeds_cap = 0     → disable HCC seeding entirely
    #                            (set by --no-hcc-seeds)
    #   hcc_seeds_cap = N > 0 → cap emitted seeds at N
    #                            (set by --hcc-seeds N)
    #
    #   hcc_only = True       → skip the LLM theorist call entirely;
    #                            dispatch only HCC seeds. Combined
    #                            with hcc_seeds_cap=0 would dispatch
    #                            nothing — argparse rejects that
    #                            combination at CLI time.
    #
    # CRITICAL: ``theories_per_cycle`` does NOT cap HCC seeds. The
    # cap is governed exclusively by ``hcc_seeds_cap``. This is by
    # design — HCC seeds carry the deterministic-coverage contract
    # and must not be silently dropped because a user lowered
    # ``--theories``.
    hcc_seeds_cap: Optional[int] = None
    hcc_only: bool = False

    # K4Bench cost-control flags (2026-04-28). Active only in bench
    # mode; in real-K4 mode they are inert (HCC seeds are empty, so
    # the HCC-origin gate trivially does nothing). Each flag governs
    # one specific LLM phase that adds cost without information for
    # deterministic HCC seeds:
    #
    #   bench_fast              meta flag. Implies skip_synthesis +
    #                            deterministic_critic + sets
    #                            redteam_min_crib_score>0 so HCC seeds
    #                            bypass red-team pre-dispatch. Used
    #                            for tokens-free HCC-only coverage runs.
    #
    #   deterministic_critic    forces the critic stage to remain
    #                            deterministic. Today the critic is
    #                            ALWAYS deterministic (TheoryCritic is
    #                            a pure-Python class with no LLM call),
    #                            so this flag currently affects only
    #                            the startup-banner mode line. It is
    #                            recorded so a future LLM-backed critic
    #                            path can read it without reshuffling
    #                            CLI semantics.
    #
    #   redteam_min_crib_score  pre-dispatch gate for the red-team
    #                            sibling call. 0 (default) means
    #                            "red-team every approved theory" —
    #                            existing behavior. N>0 means "skip
    #                            red-team for HCC seeds pre-dispatch".
    #                            HCC seeds have no a-priori crib_score
    #                            before workers run, so any positive
    #                            threshold means "deterministic HCC
    #                            seeds bypass red-team" (cost control).
    #                            LLM-generated theories ALWAYS hit the
    #                            red-team filter regardless of N.
    bench_fast: bool = False
    deterministic_critic: bool = False
    redteam_min_crib_score: int = 0

    # Yield-feedback Phase 1: policy used by the critic empirical-death gate
    # and the landscape packet renderer. See spec §6.1.
    family_yield_policy: "FamilyYieldPolicy" = field(
        default_factory=lambda: __import__(
            "kryptosbot.family_yield", fromlist=["DEFAULT_POLICY"]
        ).DEFAULT_POLICY
    )

    # PR 1 (2026-05-17) synthetic profile observability. When non-None,
    # the cycle loop and dispatcher emit record_* events through this
    # collector so a coverage report can be assembled at end-of-run.
    # None (default) preserves pre-PR-1 behavior bit-for-bit.
    #
    # The collector is owned by run_controller.main; the controller does
    # NOT instantiate one of its own. PR 2 (coverage scheduler) will read
    # the same collector to drive deterministic spec emission, but in PR
    # 1 the collector is observability-only.
    coverage_collector: Optional[Any] = None

    # PR 1: parsed-but-inert flag for the coverage scheduler. Recorded
    # on the config so PR 2 can land behind a flag without re-touching
    # CLI plumbing. PR 1 reads this only to surface it on the coverage
    # report's extra_notes for audit; it does NOT alter generation.
    coverage_scheduler_enabled: bool = False

    @property
    def is_bench_mode(self) -> bool:
        """True iff the controller is running a K4Bench challenge.

        Backwards-compatible alias for ``problem.is_bench``. New code
        SHOULD route through ``self.problem`` so the registry / anomaly
        / exhaustion gates are explicit; this property is preserved
        only for legacy call sites that have not yet been migrated.
        """
        return self.bench_challenge_payload is not None

    @property
    def problem(self) -> "ProblemContext":
        """Single funnel for problem-state access.

        Returns a fresh ``ProblemContext`` each call (the object is
        frozen + cheap to construct, and we deliberately do not cache
        on a frozen dataclass to keep the config hashable). All
        controller surfaces — landscape, prompts, critic rules,
        red-team context, synthesis, fallback, display — MUST read
        real-K4 registry / anomaly / exhaustion / family state through
        this object so a K4Bench run cannot accidentally reach into
        the real-K4 corpus.
        """
        from kryptosbot.problem_context import ProblemContext

        if self.bench_challenge_payload is None:
            return ProblemContext.real_k4()
        return ProblemContext.k4bench(
            payload=self.bench_challenge_payload,
            prompt_block=self.bench_challenge_prompt_block or "",
        )

    def __post_init__(self) -> None:
        root = self.project_root.resolve()
        if not self.ledger_db_path.is_absolute():
            self.ledger_db_path = root / self.ledger_db_path


# ---------------------------------------------------------------------------
# Cycle observability callbacks
# ---------------------------------------------------------------------------
#
# Bundle of optional callbacks for the shared cycle-loop body. Both
# ResearchController.run (library mode) and run_controller.do_run (TUI
# mode) call _run_cycle_loop with a CycleCallbacks bundle. Library mode
# leaves every field None — _run_cycle_loop emits no callback events,
# only its existing logger.* calls. TUI mode populates the bundle with
# wrappers around display.print_*, so cycle headers, dispatch banners,
# halt messages and per-phase progress all render via Rich.
#
# This is the seam introduced by the priority-1 cycle-loop collapse
# (feedback_dup_cycle_loop_trap.md). Before this seam, the for-loop body
# was duplicated in controller.run() and run_controller.do_run(), and a
# new phase had to be patched in both. After this seam, the body lives
# in one place and the two entry points only differ in their callback
# bundle.
#
# Adding a new event:
#   1. Add the field to CycleCallbacks (Optional, default None).
#   2. Add a single ``cb.emit("on_<event>", ...)`` line in
#      ``_run_cycle_loop`` at the moment the event is meaningful.
#   3. If TUI rendering is desired, wire the field in
#      ``run_controller._build_display_callbacks``.
#
# Callback contract:
#   - Emits are best-effort. A raising callback is logged and swallowed
#     so the cycle loop never fails because the TUI broke.
#   - Callbacks must not write to the ledger. The ledger is the loop's
#     state machine; observers are read-only.
#   - Callback signatures are documented inline at each field.

@dataclass
class CycleCallbacks:
    """Optional observability hooks invoked by the shared cycle loop.

    Each callback is None by default. The shared loop body emits events
    via ``CycleCallbacks.emit(name, *args)``, which is a no-op when the
    named callback is None. See the comment block above for the full
    rationale and authoring contract.
    """

    # ── Cycle body ────────────────────────────────────────────────────
    # on_cycle_begin(cycle: int, total_max: int) — fired after the
    # cycle counter is incremented but before any phase work.
    on_cycle_begin: Optional[Callable[[int, int], None]] = None
    # on_cycle_error(cycle: int, exc: BaseException) — fired when the
    # cycle body raises. The loop catches and persists state regardless.
    on_cycle_error: Optional[Callable[[int, BaseException], None]] = None
    # on_landscape(landscape: dict) — fired after _assess_landscape returns.
    on_landscape: Optional[Callable[[dict], None]] = None
    # on_no_candidates() — fired when _generate_theories returns []
    # and should_abort_run() is False (the cycle continues to the next).
    on_no_candidates: Optional[Callable[[], None]] = None
    # on_candidates_generated(count: int) — fired with the size of the
    # candidate list returned by _generate_theories.
    on_candidates_generated: Optional[Callable[[int], None]] = None
    # on_dry_run_skip() — fired when config.dry_run is True and
    # dispatch is bypassed.
    on_dry_run_skip: Optional[Callable[[], None]] = None
    # on_run_halt(reason: str) — fired when the cycle loop is breaking
    # because of a halt condition (fatal agent error, hardening halt).
    on_run_halt: Optional[Callable[[str], None]] = None

    # ── Phase: theorist generation ────────────────────────────────────
    # on_theorist_event(event: str, detail: Any) — passed as on_progress
    # to _generate_theories. Forwarded directly into the existing
    # theorist progress callback shape (no signature change).
    on_theorist_event: Optional[Callable[[str, Any], None]] = None

    # ── Phase: critic loop ────────────────────────────────────────────
    on_critic_start: Optional[Callable[[], None]] = None
    # on_critic_result(theory_title: str, decision_value: str,
    #                  confidence: float, reason: str) — fired per theory.
    on_critic_result: Optional[Callable[[str, str, float, str], None]] = None
    # on_critic_summary(approved_count: int, total_count: int)
    on_critic_summary: Optional[Callable[[int, int], None]] = None

    # ── Phase: red-team filter ────────────────────────────────────────
    # on_redteam_progress(event: str, detail: Any) — passed as on_progress
    # to _red_team_filter. See run_controller._build_display_callbacks
    # for the existing event taxonomy ("start", "verdict", "summary",
    # "skipped").
    on_redteam_progress: Optional[Callable[[str, Any], None]] = None

    # ── Phase: dispatch ───────────────────────────────────────────────
    on_dispatch_header: Optional[Callable[[int], None]] = None
    # on_worker_message(hypothesis_id: str, event: str, detail: Any) —
    # passed as on_worker_message to _dispatch_theories.
    on_worker_message: Optional[Callable[[str, str, Any], None]] = None
    on_dispatch_footer: Optional[Callable[[], None]] = None
    # on_outcome_summary(outcomes: list[WorkerContract])
    on_outcome_summary: Optional[Callable[[Any], None]] = None

    # ── Phase: stat audit (Day 5) ─────────────────────────────────────
    on_stat_audit_progress: Optional[Callable[[str, Any], None]] = None

    # ── Phase: lead pursuit (Day 6) ───────────────────────────────────
    on_pursuit_progress: Optional[Callable[[str, Any], None]] = None

    # ── Phase: synthesis (Day 5) ──────────────────────────────────────
    on_synthesis_progress: Optional[Callable[[str, Any], None]] = None

    def emit(self, name: str, *args: Any, **kwargs: Any) -> None:
        """Invoke the named callback if set. Swallow exceptions.

        A raising display callback must never fail the cycle. The
        exception is logged so observability bugs are visible in logs,
        not silent.
        """
        cb = getattr(self, name, None)
        if cb is None:
            return
        try:
            cb(*args, **kwargs)
        except Exception:
            logger.exception(
                "Cycle callback %s raised; loop continues", name,
            )


# ---------------------------------------------------------------------------
# Research Controller
# ---------------------------------------------------------------------------

class ResearchController:
    """
    Persistent, theory-ledger-driven research controller.

    Lifecycle per cycle:
    1. Load state from ledger
    2. Assess landscape (families, anomalies, recent outcomes)
    3. Generate candidate theories
    4. Run critic pass
    5. Dispatch survivors to workers
    6. Absorb outcomes and update ledger
    7. Persist state

    The controller is designed to be run repeatedly (cron, manual, or loop).
    Each cycle is self-contained and picks up where the last one left off.
    """

    def __init__(self, config: ControllerConfig) -> None:
        self.config = config
        self.ledger = TheoryLedger(config.ledger_db_path)
        # K4Bench input mode: in bench mode the critic must not reject
        # cipher-family theories on real-K4 elimination grounds (Tier 1/2,
        # FamilyRecord.elimination_tier, retired-palette / consensus-null
        # revival, K4-anomaly-keyed prompt-surface checks). Spec-shape
        # checks (completeness, duplicate, override-duplicate,
        # dsl_untranslatable) still fire normally. ``getattr`` is
        # defensive against legacy KryptosBotConfig (no is_bench_mode
        # property); those paths default to bench_mode=False.
        self.critic = TheoryCritic(
            self.ledger,
            bench_mode=getattr(config, "is_bench_mode", False),
        )
        self.state = ControllerState()
        self._semaphore = asyncio.Semaphore(config.max_concurrent_workers)

        # Day 5 per-cycle transient state. These dicts are populated by
        # _red_team_filter and _stat_audit_filter during a cycle and read
        # by _run_synthesis at end-of-cycle. Reset by _begin_cycle_phase_state.
        self._cycle_redteam_verdicts: dict[str, RedTeamVerdict] = {}
        self._cycle_stat_audit_verdicts: dict[str, StatAuditVerdict] = {}
        self._cycle_alert_summaries: list[str] = []
        # Campaign-A hardening (2026-04-22): hold the full AlertEvent list
        # so _check_cycle_hardening_halts can inspect level + p_value_status
        # at halt-decision time. The compact summary form in
        # _cycle_alert_summaries loses the p_value_status field.
        self._cycle_alert_events: list[Any] = []
        # Day 6: per-cycle pursuit verdicts, keyed by hypothesis_id.
        # Populated by _run_lead_pursuit for any contract in the 6-17
        # interesting band. Consumed by _run_synthesis for rendering
        # and used by _open_pursuit_leads to write to the ledger.
        self._cycle_pursuit_verdicts: dict[str, PursuitVerdict] = {}
        self._cycle_pursuit_leads_opened: list[str] = []
        self._last_synthesis: Optional[CycleSynthesis] = None
        self._fatal_agent_error: Optional[str] = None

        # Phase 2 yield-feedback (Task 17): per-cycle latch so the
        # KB-missing WARNING fires at most once per cycle, not once per
        # rejected theory. Initialised here in case _begin_cycle_phase_state
        # has not been called yet (cold-start tests).
        self._kb_db_missing_logged_this_cycle: bool = False

        # Phase 2 yield-feedback (Task 19): empirical-dead rejections
        # accumulated within the current cycle. Initialised here for
        # cold-start tests that call ``_write_cycle_escape_summary``
        # directly without entering a cycle loop. Reset by
        # ``_begin_cycle_phase_state`` at every cycle boundary.
        self._cycle_empirical_dead_rejections: list = []

        # 2026-05-17: per-cycle upstream filtering counters. The D-zero
        # halt is re-aimed at total upstream filtering (critic +
        # red-team + dispatcher admissibility) rather than dispatcher
        # alone. Cold-start init is here; per-cycle reset is in
        # ``_begin_cycle_phase_state``.
        self._cycle_critic_reject_count: int = 0
        self._cycle_redteam_reject_count: int = 0

        # Inject ledger into research tools
        set_ledger(self.ledger)
        self._load_canonical_facts()

        # Load the Pantheon roster once per controller instance. Each cycle
        # will route to a specific agent persona via kryptosbot.routing;
        # see _generate_theories. If the roster is unavailable (e.g. the
        # .claude/agents/ directory is missing), the controller falls back
        # to the pre-Pantheon generic theorist path so nothing breaks.
        self._pantheon_roster: dict[str, AgentSpec] = {}
        agents_dir = config.project_root.resolve() / ".claude" / "agents"
        try:
            self._pantheon_roster = load_roster(agents_dir)
            logger.info(
                "Pantheon roster loaded: %d agents from %s",
                len(self._pantheon_roster), agents_dir,
            )
            logger.info("%s", describe_routing_table(self._pantheon_roster))
        except FileNotFoundError as exc:
            logger.warning(
                "Pantheon roster unavailable (%s) — theorist will fall back "
                "to generic system prompt for this session.",
                exc,
            )

    # PR 1 (2026-05-17): synthetic profile coverage collector helper.
    # All call sites that want to feed events to the optional collector
    # go through this single chokepoint. If the collector is None
    # (the default — real-K4 runs, every test that does not opt in),
    # this is a fast no-op. If the collector raises, the exception is
    # swallowed: a synthetic-profile observability bug must NEVER break
    # the cycle. Matches the policy on CycleCallbacks.emit.
    def _coverage_record(self, method_name: str, **kwargs: Any) -> None:
        collector = getattr(self.config, "coverage_collector", None)
        if collector is None:
            return
        method = getattr(collector, method_name, None)
        if method is None:
            return
        try:
            method(**kwargs)
        except Exception:
            logger.exception(
                "coverage collector method %s raised; ignored",
                method_name,
            )

    def _begin_cycle_phase_state(self) -> None:
        """Reset per-cycle Day 5 transient state at the start of a cycle.

        Called from both controller.run() and run_controller.do_run().
        Idempotent — safe to call from either entry point at any cycle
        boundary.
        """
        self._cycle_redteam_verdicts = {}
        self._cycle_stat_audit_verdicts = {}
        self._cycle_alert_summaries = []
        self._cycle_alert_events = []
        self._cycle_pursuit_verdicts = {}
        self._cycle_pursuit_leads_opened = []

        # Phase 2 yield-feedback (Task 19): initialize empirical-dead
        # rejections list here so the no-candidates early-exit path can
        # thread it into ``_write_cycle_escape_summary`` before the
        # critic loop (which is the normal init site at line ~1418)
        # has had a chance to run.
        self._cycle_empirical_dead_rejections = []

        # Phase 2 yield-feedback (Task 17): per-cycle flag so the
        # KB-missing WARNING (raised when ``db/cipher_discovery.sqlite``
        # is absent during the empirical-death KB query) fires at most
        # once per cycle, never once per rejection.
        self._kb_db_missing_logged_this_cycle = False

        # 2026-05-17: D-zero halt re-aimed at total upstream filtering
        # rather than dispatcher admissibility alone. Phase 1 + Phase 2
        # gates (family-yield, structural-novelty, red-team escalation
        # policies) are now sophisticated enough that the dispatcher
        # admissibility check often finds nothing to reject — that's
        # the upstream gates working as designed, not a regression.
        # ``_check_cycle_hardening_halts`` sums these per-cycle counts
        # plus the dispatcher D-count; only when ALL three layers go
        # silent does the halt fire.
        self._cycle_critic_reject_count = 0
        self._cycle_redteam_reject_count = 0

        # Phase 2 yield-feedback (Task 15 review): the controller mutates
        # the critic's per-cycle indices in place each cycle rather than
        # re-instantiating; without an explicit clear, the critic's
        # _kb_cache would leak across cycles. Clear it here at the cycle
        # boundary. The derived ``blocked_families_in_cycle`` is NOT
        # recomputed here — see Task 17a. ``_begin_cycle_phase_state``
        # runs BEFORE ``_assess_landscape`` populates
        # ``self._cycle_yield_index``, so any derivation at this point
        # would read the previous cycle's yield_index. The correct
        # injection site is ``_refresh_critic_cycle_state``, called from
        # ``_run_cycle_loop`` immediately after ``_assess_landscape``.
        critic = getattr(self, "critic", None)
        if critic is not None and hasattr(critic, "_kb_cache"):
            critic._kb_cache.clear()

    def _refresh_critic_cycle_state(self) -> None:
        """Install the freshly-computed per-cycle indices onto the critic.

        Called from ``_run_cycle_loop`` AFTER ``_assess_landscape`` has
        populated ``self._cycle_yield_index`` / ``_cycle_prior_subfamilies``
        / ``_cycle_prior_signatures`` for the current cycle. Deriving
        ``blocked_families_in_cycle`` here (rather than in
        ``_begin_cycle_phase_state``) guarantees the critic's
        KB-novelty join uses the current cycle's empirical-death
        snapshot, not the previous cycle's.

        ``static_exhaustion_blocklist`` is not refreshed here because it
        is loaded once from a static elimination registry and does not
        change between cycles.
        """
        critic = getattr(self, "critic", None)
        if critic is None:
            return
        critic.yield_index = getattr(self, "_cycle_yield_index", {}) or {}
        critic.prior_subfamilies = getattr(self, "_cycle_prior_subfamilies", {}) or {}
        critic.prior_signatures = getattr(self, "_cycle_prior_signatures", {}) or {}
        critic.blocked_families_in_cycle = frozenset(
            f for f, v in (critic.yield_index or {}).items()
            if getattr(v, "status", "") == "empirically_dead"
        )

    def _record_theorist_parse_diagnostics(self, diagnostics: dict[str, Any]) -> None:
        """Persist compact theorist parse telemetry into controller state."""
        self.state.last_theorist_parse_diagnostics = dict(diagnostics)
        outcome = diagnostics.get("parse_outcome")
        if outcome == "success":
            self.state.theorist_parse_successes += 1
        elif outcome == "partial_valid":
            self.state.theorist_parse_partial_successes += 1
        if diagnostics.get("used_fallback"):
            self.state.theorist_fallbacks += 1
            reason = str(diagnostics.get("fallback_reason") or "unknown")
            counts = dict(self.state.theorist_fallback_reasons)
            counts[reason] = counts.get(reason, 0) + 1
            self.state.theorist_fallback_reasons = counts

    def _build_theorist_parse_diagnostics(
        self,
        raw_output: str,
        report: TheoryParseReport,
    ) -> dict[str, Any]:
        """Classify theorist parse results for logs, persistence, and fallback."""
        raw = raw_output or ""
        valid_count = len(report.valid)
        invalid_count = len(report.invalid)
        error_count = len(report.errors)
        suspicious_json_like = _raw_contains_json_like_structure(raw)
        repr_mangling_suspected = _looks_like_sdk_repr_mangling(raw)

        parse_outcome = "success"
        used_fallback = False
        fallback_reason = ""
        if valid_count and invalid_count:
            parse_outcome = "partial_valid"
        elif not valid_count:
            used_fallback = True
            parse_outcome = "fallback"
            if not raw.strip():
                fallback_reason = "model_returned_nothing"
            elif repr_mangling_suspected:
                fallback_reason = "structured_output_mangled_locally"
            elif invalid_count and not error_count:
                fallback_reason = "model_returned_only_invalid_proposals"
            elif suspicious_json_like:
                fallback_reason = "model_returned_json_like_but_unparseable"
            else:
                fallback_reason = "model_returned_unparseable_text"

        return {
            "cycle": self.state.cycle_number,
            "raw_length": len(raw),
            "valid_count": valid_count,
            "invalid_count": invalid_count,
            "error_count": error_count,
            "used_fallback": used_fallback,
            "fallback_reason": fallback_reason,
            "parse_outcome": parse_outcome,
            "suspicious_json_like": suspicious_json_like,
            "repr_mangling_suspected": repr_mangling_suspected,
            "suspicious_fallback": bool(
                used_fallback and (suspicious_json_like or repr_mangling_suspected or invalid_count)
            ),
            "errors": list(report.errors[:5]),
            "invalid_errors": [
                str(item.get("error", "")) for item in report.invalid[:5]
            ],
        }

    def _classify_worker_parse_failure(
        self,
        raw_output: str,
        errors: list[str],
    ) -> dict[str, Any]:
        """Classify legacy worker contract-parse failures for auditability."""
        raw = raw_output or ""
        has_json_like = _raw_contains_json_like_structure(raw)
        repr_mangling_suspected = _looks_like_sdk_repr_mangling(raw)
        reason = "contract_validation_failed"
        if not raw.strip():
            reason = "model_returned_nothing"
        elif any("No fenced JSON block" in err for err in errors):
            if repr_mangling_suspected:
                reason = "structured_output_mangled_locally"
            elif has_json_like:
                reason = "model_returned_json_like_without_fences"
            else:
                reason = "model_returned_unstructured_text"
        elif any("JSON parse error" in err for err in errors):
            reason = (
                "structured_output_mangled_locally"
                if repr_mangling_suspected
                else "model_returned_invalid_json"
            )
        return {
            "parse_failure_reason": reason,
            "repr_mangling_suspected": repr_mangling_suspected,
            "suspicious_json_like": has_json_like,
            "contract_validation_errors": list(errors),
            "raw_output_preview": raw[:5000],
        }

    def should_abort_run(self) -> bool:
        """True when the current controller session hit a fatal agent failure."""
        return self._fatal_agent_error is not None

    @property
    def fatal_agent_error(self) -> Optional[str]:
        """Human-readable explanation for the current fatal agent failure."""
        return self._fatal_agent_error

    # ------------------------------------------------------------------
    # Campaign-A hardening (2026-04-22) — runtime halt conditions
    # ------------------------------------------------------------------

    def _check_cycle_hardening_halts(
        self,
        candidates: list[TheoryRecord],
        outcomes: list[WorkerContract],
        triggered_alerts: list[Any],
    ) -> Optional[str]:
        """Update halt counters and return a halt reason if any trips.

        Consolidates the three R3 §5 halt conditions (programmatic-
        fallback streak, D-column-zero streak, matched_null_miss on
        BREAKTHROUGH) into one decision point. Called from both cycle
        loops after the alert pass.

        Side effects: mutates ``self.state.consecutive_fallback_cycles``,
        ``self.state.consecutive_d_zero_cycles``, and
        ``self.state.halt_reason_hardening``. Resets counters on
        streak-break so a single good cycle clears the running window.

        ``self.state.halt_reason_hardening`` is cleared at function entry
        and re-set only if a check below trips. Without this clear, a
        one-time halt (e.g. cycle 528 D-zero streak) persists in
        ControllerState across runs and causes every subsequent cold
        run to break out of the cycle loop after a single cycle even
        when the underlying counter has reset. Pre-2026-05-17 builds
        had no run-start clear, which made the controller act
        permanently-halted after any historical hardening trip.

        Args:
            candidates: theories generated this cycle (theorist output
                or programmatic fallback). Empty list means no theorist
                activity this cycle; counters are NOT advanced in that
                case because "no candidates" is already covered by
                should_abort_run.
            outcomes: worker contracts returned by _dispatch_theories.
                An empty list means no theory reached dispatch (could be
                dry_run, or all rejected by critic/red-team). We only
                count D=0 when there WERE dispatched contracts.
            triggered_alerts: AlertEvent objects emitted by _run_alerts.
                Used to detect BREAKTHROUGH + matched_null_miss /
                cache_miss (R3 §5 halt condition 1).

        Returns:
            A human-readable halt reason string when a threshold is
            crossed, or None when the cycle is within bounds. When a
            reason is returned, ``self.state.halt_reason_hardening`` is
            also set so the post-loop code can see it.
        """
        # Clear any halt reason carried over from a prior cycle so this
        # cycle's checks own the field. Each check below re-sets the
        # field if its condition still trips. See docstring for the
        # cross-run persistence bug this fixes. Empty string (not None)
        # to preserve the ControllerState.halt_reason_hardening: str
        # type contract.
        self.state.halt_reason_hardening = ""

        # ── Halt 1: BREAKTHROUGH with unreliable null cache ─────────
        # A BREAKTHROUGH alert whose p-value status is matched_null_miss
        # or cache_miss is uncalibrated — the operator must rebuild the
        # null cache before treating this as signal. We halt immediately
        # (no streak required) because the alert has already fired and
        # the next cycle would compound the ambiguity.
        for ev in triggered_alerts:
            level = getattr(ev, "level", "")
            p_status = getattr(ev, "p_value_status", "")
            if level == "breakthrough" and p_status in (
                "matched_null_miss", "cache_miss"
            ):
                reason = (
                    f"BREAKTHROUGH alert fired with p_value_status={p_status!r} "
                    f"— null cache is unreliable for this family; calibrate "
                    f"before proceeding (scripts/_infra/calibrate_null_baselines.py). "
                    f"hypothesis_id={getattr(ev, 'hypothesis_id', '?')}"
                )
                self.state.halt_reason_hardening = reason
                return reason

        # ── Halt 2: programmatic-fallback streak ────────────────────
        # "Fallback fired this cycle" = any candidate carries
        # origin="programmatic_fallback". The _programmatic_fallback
        # method tags every record it emits; real theorist parses leave
        # the default "theorist_agent" in place.
        #
        # Bench-mode HCC-only carve-out (2026-04-29, LESSON-021
        # follow-up): when --hcc-only is set OR every candidate this
        # cycle is a deterministic HCC seed (``_is_hcc_seed`` true),
        # the dispatch is the intended deterministic-coverage path,
        # NOT a degraded theorist. Counting those cycles toward the
        # fallback streak produced spurious cycle-3 halts on bench
        # reruns even though all seeds were correctly dispatched. The
        # durable discriminator is
        # ``minimal_test_spec.method == "bench_hand_cipher_core"``,
        # which the real-K4 _programmatic_fallback path does NOT
        # carry — so this carve-out cannot mask a degraded real-K4
        # theorist.
        all_hcc_seeds = bool(candidates) and all(
            _is_hcc_seed(c) for c in candidates
        )
        if self.config.hcc_only or all_hcc_seeds:
            # Deterministic HCC-only dispatch — does not count as a
            # fallback cycle.
            self.state.consecutive_fallback_cycles = 0
            fallback_fired_this_cycle = False
        else:
            fallback_fired_this_cycle = any(
                getattr(c, "origin", "theorist_agent")
                == "programmatic_fallback"
                for c in candidates
            )
            if fallback_fired_this_cycle:
                self.state.consecutive_fallback_cycles += 1
            else:
                self.state.consecutive_fallback_cycles = 0

        if self.state.consecutive_fallback_cycles >= FALLBACK_HALT_STREAK:
            reason = (
                f"Programmatic fallback fired for "
                f"{self.state.consecutive_fallback_cycles} consecutive cycles "
                f"(threshold={FALLBACK_HALT_STREAK}). The theorist agent is "
                f"not producing parseable output; investigate before "
                f"committing more compute."
            )
            self.state.halt_reason_hardening = reason
            return reason

        # ── Halt 3: upstream-filtering-zero streak ──────────────────
        # Re-aimed 2026-05-17 (was D-column-zero streak).
        #
        # Original signal: count of REJECTED_ADMISSIBILITY worker
        # contracts ("D column"). The halt fired when D=0 for 3
        # consecutive dispatched cycles. The premise was that healthy
        # operation has SOME admissibility rejections, and D=0
        # indicates either trivially-admissible specs or a silenced
        # DSL path.
        #
        # By 2026-05-17 the premise had become wrong. Phase 1's
        # family-yield gate + structural-novelty bypass + red-team's
        # exhausted_source_material / unbounded_search /
        # duplicate_family escalation policies do so much upstream
        # filtering that the dispatcher admissibility check often
        # finds nothing left to reject — that's the upstream gates
        # working as designed, not a regression. Cycles 545/546/547
        # on 2026-05-17 each dispatched 3-6 well-filtered theories,
        # ALL of which translated cleanly and ran in the kernel; the
        # old counter tripped after 3 such cycles and halted the run.
        #
        # New signal: total upstream filtering = critic rejections +
        # red-team rejections (REJECT or ESCALATED→REJECT) + dispatcher
        # admissibility rejections. The halt only fires when ALL three
        # layers go silent simultaneously — that genuinely indicates a
        # filtering-pipeline regression, not just a healthy upstream.
        #
        # State field ``consecutive_d_zero_cycles`` is kept under its
        # old name for schema-load compatibility; its semantic has
        # widened to "consecutive cycles with zero upstream filtering".
        #
        # Bench-mode HCC-only carve-out (2026-04-29): the deterministic
        # HCC seed catalogue is pre-validated and produces zero
        # admissibility rejections by construction. Same carve-out
        # applies to the widened metric.
        dispatched_this_cycle = len(outcomes)
        if self.config.hcc_only or all_hcc_seeds:
            # Deterministic HCC seeds: filtering=0 by design, not a signal.
            self.state.consecutive_d_zero_cycles = 0
        elif dispatched_this_cycle > 0:
            d_count = sum(
                1 for o in outcomes
                if o.status == WorkerStatus.REJECTED_ADMISSIBILITY
            )
            critic_rejects = int(
                getattr(self, "_cycle_critic_reject_count", 0) or 0
            )
            redteam_rejects = int(
                getattr(self, "_cycle_redteam_reject_count", 0) or 0
            )
            upstream_filtering_count = (
                critic_rejects + redteam_rejects + d_count
            )
            if upstream_filtering_count == 0:
                self.state.consecutive_d_zero_cycles += 1
            else:
                self.state.consecutive_d_zero_cycles = 0
        # else: dispatched=0 cycles don't move the counter either way.

        if self.state.consecutive_d_zero_cycles >= D_ZERO_HALT_STREAK:
            reason = (
                f"Upstream filtering (critic rejects + red-team rejects + "
                f"dispatcher admissibility rejects) was zero for "
                f"{self.state.consecutive_d_zero_cycles} consecutive "
                f"dispatched cycles (threshold={D_ZERO_HALT_STREAK}). "
                f"All filtering layers approved every theorist spec, "
                f"which suggests a regression in the filtering pipeline; "
                f"operator review required."
            )
            self.state.halt_reason_hardening = reason
            return reason

        return None

    # ------------------------------------------------------------------
    # Yield-feedback Phase 1: escape telemetry chokepoint.
    # See docs/specs/2026-05-16-yield-feedback-design.md §5.3.
    # ------------------------------------------------------------------
    _ESCAPE_BLOCKED_CAP = 10

    def _truncate_blocked_families(
        self,
        blocked_with_stats: list[tuple[str, "FamilyYieldStats"]],
    ) -> list[str]:
        """Return top-N family names by severity.

        Sort key: (eliminated DESC, trials DESC, family_id ASC).
        Eliminated count is the proxy for "blocked severity" in Phase 1
        because every blocked family has accumulated eliminations.
        """
        ranked = sorted(
            blocked_with_stats,
            key=lambda kv: (-kv[1].eliminated, -kv[1].trials, kv[0]),
        )
        return [name for name, _ in ranked[: self._ESCAPE_BLOCKED_CAP]]

    def _write_cycle_escape_summary(
        self,
        *,
        status: str,
        families_blocked: list[str],
        blocked_stats: Optional[
            list[tuple[str, "FamilyYieldStats"]]
        ] = None,
        rejections: Optional[list] = None,
    ) -> None:
        """Single chokepoint for writing per-cycle escape telemetry.

        Called from every cycle-exit path (no-candidates early-continue,
        all-rejected early-continue, success-path end-of-synthesis) so
        the streak counter is updated from one code path.

        Streak semantics (see spec §5.4):
          - "needed_but_unavailable" increments
          - everything else resets to 0

        Phase 2 Task 18: aggregates ``rejections``' KB suggestions into
        ``self.state.last_escape_suggestions`` for the next cycle's
        prompt. Per-family cap of 3, total storage cap of 24 (render-side
        caps in Task 20 are tighter; the two layers are independent).
        """
        blocked_total = len(families_blocked)
        if blocked_stats:
            blocked_top = self._truncate_blocked_families(blocked_stats)
        else:
            blocked_top = families_blocked[: self._ESCAPE_BLOCKED_CAP]

        if status == "needed_but_unavailable":
            self.state.escape_needed_streak += 1
        else:
            self.state.escape_needed_streak = 0

        self.state.last_escape_status = status
        self.state.last_escape_families_blocked = blocked_top
        self.state.last_escape_families_blocked_total = blocked_total
        self.state.last_escape_cycle = self.state.cycle_number

        if status == "partial_empirical_block":
            self.state.last_partial_empirical_block_count = len(
                families_blocked
            )
        elif status not in ("none",):
            # Leave the partial count untouched so a partial cycle's
            # count survives subsequent non-partial cycles, allowing the
            # operator to see "last cycle that had partial blocking".
            pass

        # ── Phase 2 Task 18: aggregate KB suggestions for the next-cycle prompt.
        # Storage caps (3-per-family, 24-total) are SPEC-MANDATED here;
        # render-side caps live in Task 20's renderer. Empty/missing
        # ``rejections`` simply yields an empty list — non-empirical-death
        # exit paths therefore clear stale suggestions naturally.
        from kryptosbot.kb_injection import CipherDiscoverySuggestion

        suggestions_by_family: dict[str, list[CipherDiscoverySuggestion]] = {}
        for r in rejections or ():
            recs = getattr(r, "suggested_mechanism_records", ()) or ()
            if not recs:
                continue
            suggestions_by_family.setdefault(r.family, []).extend(recs)

        aggregated: list[dict] = []
        for fam in sorted(suggestions_by_family.keys()):
            seen_sigs: set[str] = set()
            per_fam: list[CipherDiscoverySuggestion] = []
            for rec in suggestions_by_family[fam]:
                if rec.mechanism_signature in seen_sigs:
                    continue
                seen_sigs.add(rec.mechanism_signature)
                per_fam.append(rec)
            per_fam.sort(key=lambda s: (
                not s.dispatcher_testable,
                -float(s.k4_relevance_score),
                s.canonical_name.lower(),
            ))
            for rec in per_fam[:3]:                  # 3-per-family cap at storage
                entry = rec.to_dict()
                entry["blocked_family"] = fam
                aggregated.append(entry)

        aggregated.sort(key=lambda d: (
            not bool(d.get("dispatcher_testable")),
            -float(d.get("k4_relevance_score", 0.0)),
            str(d.get("canonical_name", "")).lower(),
        ))
        self.state.last_escape_suggestions = aggregated[:24]   # storage hard cap

    # ------------------------------------------------------------------
    # Yield-feedback Phase 2: next-cycle escape-candidates renderer.
    # See docs/specs/2026-05-16-yield-feedback-design.md §5.4.
    # ------------------------------------------------------------------
    _ESCAPE_RENDER_CAPS = {
        "needed_but_unavailable": (8, 3),   # (total cap, per-family cap)
        "partial_empirical_block": (3, 3),
    }

    def _render_escape_candidates(
        self,
        *,
        status: str,
        suggestions: list,
    ) -> str:
        """Render the next-cycle 'ESCAPE CANDIDATES' / advisory block.

        Conditional on prior cycle's escape_status. Storage caps (set in
        _write_cycle_escape_summary) bound the input; rendering caps further
        trim what the theorist actually sees.
        """
        caps = self._ESCAPE_RENDER_CAPS.get(status)
        if caps is None:
            return ""
        total_cap, per_family_cap = caps
        if not suggestions:
            return ""

        # Bucket by family, sort within each, take up to per_family_cap from each.
        by_family: dict[str, list[dict]] = {}
        for s in suggestions:
            by_family.setdefault(s.get("blocked_family", "?"), []).append(s)
        ordered: list[dict] = []
        for fam in sorted(by_family.keys()):
            recs = by_family[fam]
            recs.sort(key=lambda d: (
                not bool(d.get("dispatcher_testable")),
                -float(d.get("k4_relevance_score", 0.0)),
                str(d.get("canonical_name", "")).lower(),
            ))
            ordered.extend(recs[:per_family_cap])

        ordered.sort(key=lambda d: (
            not bool(d.get("dispatcher_testable")),
            -float(d.get("k4_relevance_score", 0.0)),
            str(d.get("canonical_name", "")).lower(),
        ))
        ordered = ordered[:total_cap]

        lines: list[str] = []
        if status == "needed_but_unavailable":
            lines.append("=== ESCAPE CANDIDATES (cipher-discovery KB) ===")
            lines.append(
                "The prior cycle blocked all candidates with REJECT_EMPIRICALLY_DEAD."
            )
            lines.append(
                "Candidates below are dispatcher-testable or Category-B investigative "
                "options whose mechanism signature is unseen in the blocked ledger families."
            )
            lines.append("")
        else:  # partial_empirical_block
            lines.append("=== KB advisory (some candidates blocked) ===")
            lines.append(
                "The prior cycle partially blocked candidates. The mechanisms below "
                "are advisory only -- your existing approach is still valid."
            )
            lines.append("")

        for d in ordered:
            tag = "dispatcher-testable" if d.get("dispatcher_testable") else "Category-B"
            lines.append(
                f"  - {d['canonical_name']} [{tag}] "
                f"(family={d.get('kb_cipher_family','?')}, "
                f"k4_relevance={d.get('k4_relevance_score',0):.1f}, "
                f"blocked={d.get('blocked_family','?')})"
            )
            sketch = d.get("one_line_sketch") or ""
            if sketch:
                lines.append(f"    Sketch: {sketch}")
            kill = d.get("bounded_kill_criterion") or ""
            if kill:
                lines.append(f"    Kill criterion: {kill}")
            lines.append("")

        lines.append(
            "Proposing a theory under one of these mechanisms must still present "
            "an unseen mechanism_signature AND unseen subfamily to bypass the "
            "empirical-death gate. Phase 1's structural-novelty discipline is unchanged."
        )
        return "\n".join(lines)

    def _render_previous_synthesis(
        self, prev: Optional[dict[str, Any]],
    ) -> str:
        """Render the prior cycle's results-analyst synthesis as theorist context.

        Closes Tier-C #8 from
        docs/audits/controller_maturity_audit_2026_05_16.md: the
        synthesis ``recommended_next_focus`` field was computed and
        persisted, but ``_build_theorist_prompt`` never read it. The
        recommendation surfaced at end-of-cycle for human visibility
        and then dead-ended; consecutive cycles produced the same
        recommendation (w_delimiter_segments / X-Q-Z marker semantics)
        without the theorist ever seeing it.

        Returns ``""`` when there is no prior synthesis (cold-start
        first cycle of a session, or the synthesis pass errored / was
        skipped). Empty string preserves the pre-fix prompt shape.

        Args:
            prev: the ``landscape["previous_synthesis"]`` dict, or None.
                Expected keys: ``headline`` (str), ``recommended_next_focus``
                (str), plus auxiliary fields the renderer ignores.

        Returns:
            A rendered prompt block, or "" when there is nothing to say.
        """
        if not prev:
            return ""
        headline = str(prev.get("headline") or "").strip()
        next_focus = str(prev.get("recommended_next_focus") or "").strip()
        if not headline and not next_focus:
            return ""

        lines: list[str] = ["=== PRIOR CYCLE SYNTHESIS ==="]
        if headline:
            lines.append(f"Last cycle: {headline}")
        if next_focus:
            if headline:
                lines.append("")
            lines.append("Results-analyst recommends for this cycle:")
            lines.append(f"  -> {next_focus}")
            lines.append("")
            lines.append(
                "You may follow this recommendation or override it. If you "
                "override, your novelty_basis must briefly explain why your "
                "direction is more promising than the recommended one."
            )
        return "\n".join(lines)

    def _classify_agent_failure(self, error_text: str) -> tuple[bool, str]:
        """Classify whether an SDK/CLI failure should halt the remaining run.

        Epistemic impact: a hard provider/auth/protocol failure means later cycles
        are not genuine "no candidate" research outcomes. They are infrastructure
        failures and must not be laundered into controller progress.
        """
        label, explanation = classify_error(error_text)
        fatal_labels = {
            "RATE_LIMIT",
            "TOKEN_LIMIT",
            "QUOTA_EXCEEDED",
            "CREDITS_EXHAUSTED",
            "BILLING",
            "ENTITLEMENT",
            "AUTH_FAILURE",
            "AUTH_FORBIDDEN",
            "PROTOCOL_MISMATCH",
            "NESTED_SESSION",
            "SERVICE_UNAVAILABLE",
            "OVERLOADED",
            "TIMEOUT",
            "CONNECTION",
        }
        is_fatal = label in fatal_labels
        if is_fatal:
            return True, f"{label}: {explanation}"
        return False, f"{label}: {explanation}"

    def _load_canonical_facts(self) -> None:
        """Load canonical K4 facts from kernel constants into research tools.

        Under K4Bench input mode the kernel's CT/cribs/Bean derivation
        already point at the synthetic challenge (because
        KRYPTOS_CT_OVERRIDE / KRYPTOS_CRIB_DICT_OVERRIDE were installed
        at process start), so the same import path produces challenge-
        appropriate facts. We additionally enrich the facts dict with
        the bench-side payload (bench_id, suite_id, clue_text, solver
        contract) so workers calling ``get_canonical_facts`` see the
        challenge context the theorist saw.

        QUARANTINE (2026-04-14): NULL_PALETTE and CONSENSUS_NULL_POSITIONS
        were previously injected here and exposed to workers via the
        get_canonical_facts MCP tool as "ground truth". They are now
        retired (see memory/project_consensus_nulls_epistemic_status_2026_04_14.md
        and docs/a1_score_conditioned_null_report.md) and MUST NOT appear
        in this dict. Canonical facts are the project's strongest epistemic
        surface; retired claims must not ride on it.
        """
        try:
            from kryptosbot.constants import (
                CT, CT_LEN, CRIB_WORDS, N_CRIBS,
                BEAN_EQ, BEAN_INEQ,
                NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD,
                BREAKTHROUGH_THRESHOLD,
            )
            facts = {
                "ciphertext": CT,
                "ct_length": CT_LEN,
                "cribs": [(pos, word) for pos, word in CRIB_WORDS],
                "n_crib_chars": N_CRIBS,
                "bean_equality": list(BEAN_EQ),
                "bean_inequality_count": len(BEAN_INEQ),
                "thresholds": {
                    "noise": NOISE_FLOOR,
                    "store": STORE_THRESHOLD,
                    "signal": SIGNAL_THRESHOLD,
                    "breakthrough": BREAKTHROUGH_THRESHOLD,
                },
            }
            if self.config.is_bench_mode and self.config.bench_challenge_payload:
                # Surface bench-side context the theorist was given.
                # Keys do not collide with the K4 facts above.
                facts.update({
                    "bench_mode": True,
                    "bench_id": self.config.bench_challenge_payload.get("bench_id"),
                    "suite_id": self.config.bench_challenge_payload.get("suite_id"),
                    "title": self.config.bench_challenge_payload.get("title"),
                    "clue_text": self.config.bench_challenge_payload.get("clue_text"),
                    "constraint_summary": self.config.bench_challenge_payload.get("constraint_summary"),
                    "solver_required_fields": self.config.bench_challenge_payload.get("solver_required_fields"),
                    "strict_pass_rule": self.config.bench_challenge_payload.get("strict_pass_rule"),
                    "known_crib_score_target": self.config.bench_challenge_payload.get("known_crib_score_target"),
                })
            set_canonical_facts(facts)
        except ImportError:
            logger.warning("Could not import kernel constants for canonical facts")

    # ------------------------------------------------------------------
    # Session baseline (read by _assess_landscape for cycle_delta)
    # ------------------------------------------------------------------

    def _snapshot_session_baseline(self) -> None:
        """Record the ledger's tested/eliminated counts at session start.

        Both ``ResearchController.run`` and ``run_controller.do_run``
        must call this before the cycle loop so that
        ``_assess_landscape``'s ``cycle_delta`` reflects work done in
        this session, not zero. Before this helper existed, the TUI
        (do_run) path skipped baseline initialization and reported
        ``cycle_delta = 0`` permanently.

        The baseline is read only by ``_assess_landscape`` via
        ``getattr(self, '_session_baseline_*', current_value)``, so
        forgetting to call this helper degrades silently to "zero
        delta" rather than crashing. Tests in
        ``test_cycle_loop_characterization.py`` assert that both
        entry points populate the attributes.
        """
        counts = self.ledger.count_by_status()
        self._session_baseline_tested = sum(
            counts.get(s, 0) for s in ["completed", "eliminated", "promising"]
        )
        self._session_baseline_eliminated = counts.get("eliminated", 0)

    # ------------------------------------------------------------------
    # Main run loop
    # ------------------------------------------------------------------

    async def run(
        self, *, callbacks: Optional[CycleCallbacks] = None,
    ) -> ControllerState:
        """
        Execute the controller for up to max_cycles.

        Each cycle: assess → generate → critic → dispatch → absorb → persist.

        ``callbacks`` is an optional ``CycleCallbacks`` bundle of
        observability hooks. Library-mode callers (cron, smoke tests)
        pass nothing and the loop emits only its existing logger.*
        output. ``run_controller.do_run`` populates the bundle with
        ``display.print_*`` wrappers so the same loop body renders via
        Rich for interactive sessions. The two paths now share
        ``_run_cycle_loop``; this is the priority-1 cycle-loop collapse
        (see ``feedback_dup_cycle_loop_trap.md`` and
        ``test_cycle_loop_characterization.py``).
        """
        # Synthetic-mode enforcement (2026-04-26). Refuse a real launch
        # against a synthetic-tainted ledger (or vice versa) BEFORE
        # bootstrap so the launch fails without mutating ledger state.
        # Source of truth for the launching mode is the kernel's
        # KRYPTOS_CT_OVERRIDE flag. See SyntheticModeError for the
        # failure surface and feedback_synthetic_mode_propagation for
        # the rationale.
        from kryptos.kernel.constants import _SYNTHETIC_MODE
        self.ledger.verify_and_pin_synthetic_mode(_SYNTHETIC_MODE)

        # Bootstrap registries — gated via ProblemContext so a bench
        # run never seeds real-K4 family / anomaly / claim / exhaustion
        # rows into the bench-scoped ledger. Bench mode runs only the
        # generic controller-queue-reset bootstrap. See run_controller.do_run
        # for the matching gate on the TUI entry point.
        if self.config.problem.is_real_k4:
            bootstrap_all(self.ledger, self.config.project_root)
        else:
            from .registries import bootstrap_controller_queue_reset
            bootstrap_controller_queue_reset(self.ledger)

        # Load persisted state
        self.state = self.ledger.load_controller_state()

        # Reconcile any theories orphaned in RUNNING from a prior crash
        orphaned = self.ledger.reconcile_orphaned_running()
        if orphaned:
            logger.warning(
                "Reconciled %d orphaned RUNNING theories: %s",
                len(orphaned), orphaned,
            )

        logger.info(
            "Controller starting at cycle %d (theories: %d proposed, %d tested, %d eliminated)",
            self.state.cycle_number,
            self.state.theories_proposed,
            self.state.theories_tested,
            self.state.theories_eliminated,
        )

        # Snapshot baseline for session-local deltas. Extracted to a
        # helper so run_controller.do_run can call it too — without it,
        # the TUI path's cycle_delta values were always 0 because the
        # baseline attributes were never set on the controller.
        self._snapshot_session_baseline()

        await self._run_cycle_loop(callbacks or CycleCallbacks())

        logger.info("Controller completed %d cycles", self.config.max_cycles)
        return self.state

    async def _run_cycle_loop(self, cb: CycleCallbacks) -> None:
        """Shared cycle-loop body for both library and TUI entry points.

        Before this method existed the for-loop body was duplicated in
        ``ResearchController.run`` and ``run_controller.do_run``, which
        meant every new phase had to be patched in two places (see
        ``feedback_dup_cycle_loop_trap.md``). The body now lives only
        here; both entry points dispatch to it with their own
        ``CycleCallbacks`` bundle.

        Pinned by ``test_cycle_loop_characterization.py`` (test G):
        the canonical trace produced by this method is identical
        regardless of which callback bundle is passed.
        """
        total_max = self.state.cycle_number + self.config.max_cycles

        for cycle in range(self.config.max_cycles):
            self.state.cycle_number += 1
            self.state.last_cycle_at = _now_iso()
            logger.info("=== Cycle %d ===", self.state.cycle_number)
            self._begin_cycle_phase_state()  # Day 5: reset per-cycle dicts
            cb.emit("on_cycle_begin", self.state.cycle_number, total_max)

            try:
                # Step 1: Assess landscape
                landscape = self._assess_landscape()
                logger.info("Landscape: %s", json.dumps(landscape, indent=2)[:500])
                cb.emit("on_landscape", landscape)

                # Step 2: Generate candidate theories
                candidates = await self._generate_theories(
                    landscape, on_progress=cb.on_theorist_event,
                )
                logger.info("Generated %d candidate theories", len(candidates))

                # PR 1 (2026-05-17): emit one record_emitted_spec event
                # per generated theory so the coverage collector sees the
                # post-generation spec surface. The dsl_spec dict contains
                # the layer/param structure the obligation matcher reads.
                # No-op when coverage_collector is None.
                for _c in candidates:
                    _layers = (_c.dsl_spec or {}).get("pipeline", []) or []
                    self._coverage_record(
                        "record_emitted_spec",
                        hypothesis_id=_c.hypothesis_id,
                        title=_c.title or "",
                        family=_c.family or "",
                        spec_hash=(_c.dsl_spec or {}).get("spec_hash", ""),
                        layers=_layers,
                        origin=_c.origin or "theorist_agent",
                    )

                if not candidates:
                    if self.should_abort_run():
                        logger.warning(
                            "Aborting remaining cycles after fatal theorist failure: %s",
                            self.fatal_agent_error,
                        )
                        cb.emit(
                            "on_run_halt",
                            self.fatal_agent_error or "fatal agent failure",
                        )
                        break
                    logger.info("No candidates generated, ending cycle")
                    self._write_cycle_escape_summary(
                        status="no_candidates",
                        families_blocked=[],
                        rejections=self._cycle_empirical_dead_rejections,
                    )
                    cb.emit("on_no_candidates")
                    continue

                cb.emit("on_candidates_generated", len(candidates))

                # Step 3: Critic pass
                cb.emit("on_critic_start")
                approved = []
                # Yield-feedback Phase 1 + Task 17a: install the fresh
                # per-cycle yield indices onto the critic so each
                # evaluate() runs O(1) without re-querying the ledger,
                # and re-derive blocked_families_in_cycle from the
                # CURRENT cycle's yield_index (not the previous cycle's,
                # which is what _begin_cycle_phase_state would see).
                self._refresh_critic_cycle_state()
                self.critic.policy = self.config.family_yield_policy
                self._cycle_empirical_dead_rejections = []
                # 2026-05-17: reset upstream filtering counters at the
                # start of every critic pass so the D-zero halt counter
                # sees only THIS cycle's filtering rate.
                self._cycle_critic_reject_count = 0
                self._cycle_redteam_reject_count = 0
                for theory in candidates:
                    if self.config.skip_critic:
                        theory.status = TheoryStatus.APPROVED
                        approved.append(theory)
                        cb.emit(
                            "on_critic_result",
                            theory.title, "approve", 1.0, "",
                        )
                        # PR 1: skip-critic path still records an
                        # "approve" outcome so the coverage collector
                        # sees the spec progressed past the critic gate.
                        self._coverage_record(
                            "record_critic_outcome",
                            hypothesis_id=theory.hypothesis_id,
                            decision="approve",
                            confidence=1.0,
                            reasons=["skip_critic flag set"],
                        )
                    else:
                        verdict = self.critic.evaluate(theory)
                        theory.critic_verdict = verdict
                        # PR 1: record the critic verdict for coverage.
                        self._coverage_record(
                            "record_critic_outcome",
                            hypothesis_id=theory.hypothesis_id,
                            decision=verdict.decision.value,
                            confidence=verdict.confidence,
                            reasons=list(verdict.reasons),
                        )
                        theory.status = (
                            TheoryStatus.APPROVED
                            if verdict.decision == CriticDecision.APPROVE
                            else TheoryStatus.CRITICIZED
                        )
                        self.ledger.upsert_theory(theory)

                        if verdict.decision == CriticDecision.APPROVE:
                            approved.append(theory)
                            logger.info(
                                "  APPROVED: %s (confidence=%.2f)",
                                theory.title, verdict.confidence,
                            )
                        else:
                            # 2026-05-17: count this rejection toward
                            # upstream filtering so the D-zero halt does
                            # not fire when critic is doing the work.
                            self._cycle_critic_reject_count += 1
                            logger.info(
                                "  REJECTED [%s]: %s — %s",
                                verdict.decision.value, theory.title,
                                verdict.reasons[0] if verdict.reasons else "no reason",
                            )
                            if (
                                verdict.decision == CriticDecision.REJECT_EMPIRICALLY_DEAD
                                and verdict.empirical_death is not None
                            ):
                                self._cycle_empirical_dead_rejections.append(
                                    verdict.empirical_death
                                )

                        cb.emit(
                            "on_critic_result",
                            theory.title,
                            verdict.decision.value,
                            verdict.confidence,
                            verdict.reasons[0] if verdict.reasons else "",
                        )

                logger.info(
                    "%d/%d theories approved by critic",
                    len(approved), len(candidates),
                )
                cb.emit("on_critic_summary", len(approved), len(candidates))

                # Day 6: any approved theory tagged "pursuit_lead:<id>"
                # closes the corresponding open lead as PURSUED. Best-
                # effort — never fails the cycle on bookkeeping.
                self._close_referenced_pursuit_leads(approved)

                if not approved:
                    blocked = [
                        r.family for r in self._cycle_empirical_dead_rejections
                    ]
                    blocked_stats = [
                        (r.family, r.verdict.stats)
                        for r in self._cycle_empirical_dead_rejections
                        if r.verdict is not None and r.verdict.stats is not None
                    ]
                    status = (
                        "needed_but_unavailable"
                        if blocked else "no_candidates"
                    )
                    self._write_cycle_escape_summary(
                        status=status,
                        families_blocked=blocked,
                        blocked_stats=blocked_stats,
                        rejections=self._cycle_empirical_dead_rejections,
                    )
                    logger.info(
                        "No theories survived critic, ending cycle (escape=%s)",
                        status,
                    )
                    continue

                # Step 3b: Red-team pre-check (Day 3 Pantheon integration)
                # Sibling call to red-team-disprover for each theory the
                # critic approved. Red-team's adversarial priors filter
                # out theories likely to be noise BEFORE the controller
                # commits worker compute. Replaces the hand-rolled
                # ct_perturbation budget rule from Day 2 (now deleted from
                # critic.py) with a principled adversarial review.
                #
                # Implementation: serial sibling calls (one red-team
                # session per approved theory). Compute is not the
                # constraint — the user explicitly approved this; see
                # feedback_do_not_cap_runtime.md.
                approved = await self._red_team_filter(
                    approved, on_progress=cb.on_redteam_progress,
                )

                if not approved:
                    logger.info("No theories survived red-team, ending cycle")
                    continue

                if self.config.dry_run:
                    # Yield-feedback Phase 1: write escape telemetry even
                    # in dry_run so integration tests for partial_empirical_block
                    # can assert on state without dispatching real workers.
                    if self._cycle_empirical_dead_rejections:
                        _blocked = [
                            r.family for r in self._cycle_empirical_dead_rejections
                        ]
                        _blocked_stats = [
                            (r.family, r.verdict.stats)
                            for r in self._cycle_empirical_dead_rejections
                            if r.verdict is not None and r.verdict.stats is not None
                        ]
                        self._write_cycle_escape_summary(
                            status="partial_empirical_block",
                            families_blocked=_blocked,
                            blocked_stats=_blocked_stats,
                            rejections=self._cycle_empirical_dead_rejections,
                        )
                    else:
                        self._write_cycle_escape_summary(
                            status="none",
                            families_blocked=[],
                            rejections=self._cycle_empirical_dead_rejections,
                        )
                    logger.info("DRY RUN — skipping dispatch")
                    cb.emit("on_dry_run_skip")
                    continue

                # Step 4: Dispatch to workers
                cb.emit("on_dispatch_header", len(approved))
                outcomes = await self._dispatch_theories(
                    approved, on_worker_message=cb.on_worker_message,
                )
                logger.info("Got %d experiment outcomes", len(outcomes))
                cb.emit("on_dispatch_footer")
                cb.emit("on_outcome_summary", outcomes)

                # Step 5: Absorb outcomes
                self._absorb_outcomes(outcomes)

                # Step 5c: Day 5 — statistical-auditor post-execution
                # signal review. Populates self._cycle_stat_audit_verdicts
                # which _run_alerts consumes to gate signal-level alerts.
                # Best-effort: never blocks the cycle.
                try:
                    await self._stat_audit_filter(
                        approved, outcomes,
                        on_progress=cb.on_stat_audit_progress,
                    )
                except Exception as exc:
                    logger.exception("Stat-audit filter raised (continuing)")
                    cb.emit("on_cycle_error", self.state.cycle_number, exc)

                # Step 5b: Run contradiction-detector alerts BEFORE persisting
                # state. Alerting is best-effort and never blocks the loop.
                # Honors stat-audit gate from step 5c.
                self._run_alerts(approved, outcomes)

                # Step 5b'. Campaign-A hardening (2026-04-22): consolidated
                # halt check. Updates state counters; sets
                # self.state.halt_reason_hardening if a threshold trips.
                # Reads the AlertEvent list captured by _run_alerts above
                # so matched_null_miss / cache_miss on BREAKTHROUGH is
                # visible. Called AFTER alerts so p_value_status is
                # populated, BEFORE persist so the halt reason is saved
                # in the ledger.
                hardening_reason = self._check_cycle_hardening_halts(
                    candidates=candidates,
                    outcomes=outcomes,
                    triggered_alerts=self._cycle_alert_events,
                )
                if hardening_reason:
                    logger.warning(
                        "Campaign-A hardening halt: %s", hardening_reason,
                    )

                # Step 5d: Day 6 — lead-pursuit evaluator for sub-signal
                # (6-17) contracts. Populates _cycle_pursuit_verdicts and
                # opens PursuitLead rows in the ledger for any "pursue"
                # verdict. Best-effort: never blocks the cycle.
                try:
                    await self._run_lead_pursuit(
                        approved, outcomes,
                        on_progress=cb.on_pursuit_progress,
                    )
                except Exception as exc:
                    logger.exception("Lead pursuit raised (continuing)")
                    cb.emit("on_cycle_error", self.state.cycle_number, exc)

                # Yield-feedback Phase 1: success-path escape telemetry.
                # If any candidate was rejected by empirical-death but
                # others survived, log partial_empirical_block (streak
                # resets). Otherwise log none.
                if self._cycle_empirical_dead_rejections:
                    blocked = [
                        r.family for r in self._cycle_empirical_dead_rejections
                    ]
                    blocked_stats = [
                        (r.family, r.verdict.stats)
                        for r in self._cycle_empirical_dead_rejections
                        if r.verdict is not None and r.verdict.stats is not None
                    ]
                    self._write_cycle_escape_summary(
                        status="partial_empirical_block",
                        families_blocked=blocked,
                        blocked_stats=blocked_stats,
                        rejections=self._cycle_empirical_dead_rejections,
                    )
                else:
                    self._write_cycle_escape_summary(
                        status="none",
                        families_blocked=[],
                        rejections=self._cycle_empirical_dead_rejections,
                    )

                # Step 6: Persist state.
                # Wrapped in its own try so a transient SQLite I/O glitch
                # (lock contention, WAL checkpoint conflict, etc.) does
                # NOT propagate up and halt the cycle. Live-run audit
                # 2026-04-30 found controller_state.cycle_number stuck
                # at 197 even though the run reached 250, suggesting
                # silent persistence failures somewhere in cycles 198-250.
                # With this guard, persistence failures get logged and
                # the run continues; cycle counts in theories/experiments
                # tables remain authoritative. The final post-loop save
                # below also writes the last-known state.
                self._update_state_counts()
                try:
                    self.ledger.save_controller_state(self.state)
                except Exception as exc:  # noqa: BLE001
                    logger.exception(
                        "save_controller_state failed at cycle %d "
                        "(continuing): %s",
                        self.state.cycle_number, exc,
                    )
                try:
                    self.ledger.refresh_family_stats()
                except Exception as exc:  # noqa: BLE001
                    logger.exception(
                        "refresh_family_stats failed at cycle %d "
                        "(continuing): %s",
                        self.state.cycle_number, exc,
                    )

                # Step 6b: Day 5 — end-of-cycle results synthesis. Produces
                # a structured CycleSynthesis written to self._last_synthesis
                # which the next cycle's _assess_landscape can render.
                try:
                    await self._run_synthesis(
                        approved, outcomes,
                        on_progress=cb.on_synthesis_progress,
                    )
                except Exception as exc:
                    logger.exception("Cycle synthesis raised (continuing)")
                    cb.emit("on_cycle_error", self.state.cycle_number, exc)

            except Exception as exc:
                logger.exception("Error in cycle %d", self.state.cycle_number)
                # Persist state even on error so we don't lose progress.
                # Same swallow-and-log treatment as the success path: a
                # save failure here previously raised and bubbled up.
                try:
                    self.ledger.save_controller_state(self.state)
                except Exception as save_exc:  # noqa: BLE001
                    logger.exception(
                        "save_controller_state failed in error handler "
                        "at cycle %d (continuing): %s",
                        self.state.cycle_number, save_exc,
                    )
                cb.emit("on_cycle_error", self.state.cycle_number, exc)

            # Campaign-A hardening (2026-04-22): break the cycle loop
            # after persist + synthesis have run, so the halt reason is
            # saved and the run closes cleanly. Placed OUTSIDE the try
            # so a cycle that errors mid-body can still break here if a
            # prior cycle set the halt reason.
            if self.state.halt_reason_hardening:
                logger.warning(
                    "Stopping run after cycle %d: %s",
                    self.state.cycle_number,
                    self.state.halt_reason_hardening,
                )
                cb.emit("on_run_halt", self.state.halt_reason_hardening)
                break

        # Final post-loop save. Belt-and-suspenders against the audit
        # 2026-04-30 finding where cycle_number got stuck at 197 with
        # the run reaching 250 — a single persistence write at the end
        # ensures the run-end state always lands in the ledger,
        # regardless of whether mid-cycle saves intermittently failed.
        try:
            self._update_state_counts()
            self.ledger.save_controller_state(self.state)
            logger.info(
                "Final controller_state persisted: cycle_number=%d",
                self.state.cycle_number,
            )
        except Exception as final_exc:  # noqa: BLE001
            logger.exception(
                "Final save_controller_state failed: %s", final_exc,
            )

    # ------------------------------------------------------------------
    # Step 1: Assess landscape
    # ------------------------------------------------------------------

    def _assess_landscape(self) -> dict[str, Any]:
        """Build a structured view of the current research landscape.

        Reads all real-K4 registry / anomaly / family state through
        ``self.config.problem`` so a K4Bench run never reaches into
        the real-K4 corpus. In bench mode this short-circuits to
        ``_assess_landscape_bench`` for a challenge-local landscape;
        in real-K4 mode the ProblemContext accessors return the live
        registries so behavior is unchanged.
        """
        problem = self.config.problem
        if problem.is_bench:
            return self._assess_landscape_bench()

        STANDING_CONSTRAINTS = problem.standing_constraints()
        ADMISSIBLE_PROMPT_ANOMALY_IDS = problem.admissible_prompt_anomaly_ids()

        status_counts = self.ledger.count_by_status()
        family_counts = self.ledger.count_by_family()
        open_anomalies = self.ledger.get_open_anomalies()
        all_open_anomaly_count = len(open_anomalies)
        active_families = self.ledger.get_active_families()
        recent = [
            t for t in self.ledger.recent_outcomes(limit=20)
            if not _is_retracted_recent_outcome(t)
        ]

        # Filter active families to only those relevant to cryptanalysis
        # (exclude infra/meta families that are script categories, not cipher families)
        _META_FAMILIES = frozenset({
            "_infra", "_uncategorized", "analysis", "admissibility",
            "campaigns", "campaigns_final_checklist", "campaigns_tabp",
            "cfm", "team", "blitz", "exploration", "statistical",
        })
        crypto_families = [
            f for f in active_families
            if f.family_id not in _META_FAMILIES
        ]

        # Find genuinely underexplored cipher families.
        #
        # A family is "underexplored" only if ALL of:
        # - it is not meta/infra
        # - the controller's own ledger has tested fewer than 3 theories in it
        # - the family record itself has fewer than 5 total_theories from any
        #   source (this catches families auto-loaded from exhaustion_log.json
        #   that have many scripts but no controller theories)
        # - it is NOT in EXTERNALLY_EVIDENCED_FAMILIES (campaign + kernel work)
        # - its elimination_tier is 4 OR it has zero elimination_evidence text
        #
        # The external-evidence guards prevent the theorist from wasting cycles
        # (and tokens) re-proposing theories for families that have been
        # thoroughly tested elsewhere — by external campaigns (running_key,
        # stego_layer, w_delimiter), by kernel-level proofs (E-FRAC series),
        # or by exhaustion-log script families with significant coverage.
        EXTERNALLY_EVIDENCED_FAMILIES = problem.externally_evidenced_families()

        tested_families = family_counts  # {family: {total, eliminated, promising}}
        underexplored = [
            f for f in crypto_families
            if tested_families.get(f.family_id, {}).get("total", 0) < 3
            and f.total_theories < 5
            and f.family_id not in EXTERNALLY_EVIDENCED_FAMILIES
            and (f.elimination_tier == 4 or not f.elimination_evidence.strip())
        ]

        # Separate standing constraints (permanent facts) from investigable anomalies
        standing_constraint_ids = {c["id"] for c in STANDING_CONSTRAINTS}
        investigable = [
            a for a in open_anomalies
            if a.anomaly_id not in standing_constraint_ids
            and a.anomaly_id in ADMISSIBLE_PROMPT_ANOMALY_IDS
        ]

        # Sort investigable anomalies so under-explored ones surface first.
        #
        # Rotation 2026-04-20: the prior sort hard-pinned w_delimiter_segments
        # to position 0. That emphasis was added 2026-04-17 when W was the
        # live structural lead; it is now saturated (80+ controller theories
        # across cycles 125-133, all eliminated or rejected). Replacing the
        # pin with len(a.theories_exploring) as the primary sort key lets
        # ranking self-tune: depth-mined anomalies demote automatically as
        # counts accumulate, and fresh surfaces bubble up without hand-edits.
        #
        # Priority (from KNOWN_ANOMALIES; lower = more important: Tier
        # S=1, A=2, B=3, C=4) is the tiebreaker, so within an equal
        # exploration bucket the S/A tier anchors still win.
        #
        # Disproof-pivot risk on low-count anomalies (e.g. aaa_coordinate_lie
        # at 15) is handled downstream by the critic and red-team, not here;
        # see feedback_accept_specific_disproofs.md.
        _priority_map = {
            a["anomaly_id"]: a.get("priority", 99)
            for a in problem.known_anomalies()
        }
        investigable.sort(
            key=lambda a: (
                len(a.theories_exploring),
                _priority_map.get(a.anomaly_id, 99),
            )
        )

        # Find anomalies not yet addressed by any theory
        unaddressed_anomalies = [
            a for a in investigable
            if not a.theories_exploring
        ]

        self.state.underexplored_families = [f.family_id for f in underexplored]
        self.state.open_anomalies = [a.anomaly_id for a in investigable]

        # Compute cycle delta: changes since session start
        current_tested = sum(
            status_counts.get(s, 0) for s in ["completed", "eliminated", "promising"]
        )
        current_eliminated = status_counts.get("eliminated", 0)
        delta = {
            "new_tested": current_tested - getattr(
                self, '_session_baseline_tested', current_tested
            ),
            "new_eliminated": current_eliminated - getattr(
                self, '_session_baseline_eliminated', current_eliminated
            ),
        }

        # Yield-feedback Phase 1: snapshot family yield stats once per
        # cycle. Fail-open: if the ledger query raises, leave indices
        # empty so the critic gate becomes a no-op for this cycle while
        # every other gate (Tier-1, Tier-2, duplicate, contradiction,
        # DSL, exhaustion, red-team, kernel verifier) still applies.
        from kryptosbot.family_yield import (
            classify_family_yield,
            render_packet,
            render_escape_pressure,
        )
        try:
            yield_stats_rows = self.ledger.family_yield_stats()
            self._cycle_yield_index = {
                s.family.lower(): classify_family_yield(
                    s, self.config.family_yield_policy,
                )
                for s in yield_stats_rows
            }
            self._cycle_prior_subfamilies = self.ledger.subfamily_index()
            self._cycle_prior_signatures = self.ledger.mechanism_signature_index()
        except Exception:
            logger.warning(
                "family_yield query failed; empirical-death brake disabled for this cycle",
                exc_info=True,
            )
            self._cycle_yield_index = {}
            self._cycle_prior_subfamilies = {}
            self._cycle_prior_signatures = {}

        landscape = {
            "status_counts": status_counts,
            "cycle_delta": delta,
            "theorist_parse_telemetry": {
                "successes": self.state.theorist_parse_successes,
                "partial_successes": self.state.theorist_parse_partial_successes,
                "fallbacks": self.state.theorist_fallbacks,
                "fallback_reasons": dict(self.state.theorist_fallback_reasons),
                "last": dict(self.state.last_theorist_parse_diagnostics),
            },
            "standing_constraints": STANDING_CONSTRAINTS,
            "active_families": [
                {"id": f.family_id, "name": f.name, "theories": f.total_theories,
                 "tested": tested_families.get(f.family_id, {}).get("total", 0)}
                for f in crypto_families[:10]
            ],
            "underexplored_families": [
                {"id": f.family_id, "name": f.name,
                 "tested": tested_families.get(f.family_id, {}).get("total", 0)}
                for f in underexplored[:5]
            ],
            "open_anomalies": [
                {"id": a.anomaly_id, "title": a.title,
                 "claim_id": _ANOMALY_TO_CLAIM_ID.get(a.anomaly_id, ""),
                 "priority": _priority_map.get(a.anomaly_id, 99),
                 "explored_by": len(a.theories_exploring)}
                for a in investigable[:14]
            ],
            "prompt_anomaly_count": len(investigable),
            "registry_open_anomaly_count": all_open_anomaly_count,
            "unaddressed_anomalies": [
                {"id": a.anomaly_id, "title": a.title,
                 "claim_id": _ANOMALY_TO_CLAIM_ID.get(a.anomaly_id, ""),
                 "priority": _priority_map.get(a.anomaly_id, 99)}
                for a in unaddressed_anomalies[:14]
            ],
            "recent_outcomes": [
                {
                    "title": t.title,
                    "family": t.family,
                    "status": t.status.value,
                    "score": t.best_score,
                }
                for t in recent[:5]
            ],
            # Day 5: structured handoff from the previous cycle's
            # results-analyst synthesis. None on the first cycle of a
            # session or if synthesis was skipped/errored.
            "previous_synthesis": (
                {
                    "headline": self._last_synthesis.headline,
                    "recommended_next_focus": self._last_synthesis.recommended_next_focus,
                    "family_movements": list(self._last_synthesis.family_movements),
                    "evidence_added": list(self._last_synthesis.evidence_added),
                    "dispatched_count": self._last_synthesis.dispatched_count,
                    "disproved_count": self._last_synthesis.disproved_count,
                    "signal_count": self._last_synthesis.signal_count,
                    "risk_breakdown": dict(
                        getattr(self._last_synthesis, "risk_breakdown", {}) or {}
                    ),
                }
                if self._last_synthesis is not None
                else None
            ),
            # Day 6: open HARD pursuit leads (source_verdict='pursue')
            # from prior cycles. Surfaced in the theorist prompt as
            # priority context so sub-signal follow-ups no longer
            # depend on persona rotation.
            "pursuit_leads": [
                {
                    "lead_id": lead.lead_id,
                    "source_theory_id": lead.source_theory_id,
                    "source_cycle": lead.source_cycle,
                    "crib_score": lead.crib_score,
                    "rationale": lead.rationale,
                    "suggested_variants": list(lead.suggested_variants),
                }
                for lead in self._safe_get_open_pursuit_leads(
                    source_verdict=PURSUIT_SOURCE_PURSUE,
                )
            ],
            # SOFT pursuit leads (source_verdict='skip_variants'):
            # evaluator rejected the specific lead but left concrete
            # variant directions worth preserving. Capped small to
            # avoid prompt sludge per feedback.
            "soft_pursuit_leads": [
                {
                    "lead_id": lead.lead_id,
                    "source_theory_id": lead.source_theory_id,
                    "source_cycle": lead.source_cycle,
                    "crib_score": lead.crib_score,
                    "rationale": lead.rationale,
                    "suggested_variants": list(lead.suggested_variants),
                }
                for lead in self._safe_get_open_pursuit_leads(
                    limit=self.config.soft_pursuit_leads_prompt_cap,
                    source_verdict=PURSUIT_SOURCE_SKIP_VARIANTS,
                )
            ],
            "family_yield": render_packet(self._cycle_yield_index),
            "escape_pressure": render_escape_pressure(
                streak=self.state.escape_needed_streak,
                last_status=self.state.last_escape_status,
                blocked=self.state.last_escape_families_blocked,
                blocked_total=self.state.last_escape_families_blocked_total,
            ),
        }
        landscape["escape_candidates"] = self._render_escape_candidates(
            status=self.state.last_escape_status,
            suggestions=self.state.last_escape_suggestions,
        )
        try:
            from kryptosbot.frontier_map import build_frontier_map, render_open_frontier
            _fm = build_frontier_map(ledger_db_path=self.config.ledger_db_path)
            landscape["frontier_open"] = render_open_frontier(_fm, limit=12)
        except Exception as exc:
            logger.warning("frontier map unavailable: %s", exc)
            landscape["frontier_open"] = ""  # advisory; never break the landscape
        return landscape

    def _safe_get_open_pursuit_leads(
        self,
        limit: int = 10,
        *,
        source_verdict: Optional[str] = None,
    ) -> list[PursuitLead]:
        """Wrapper around ledger.get_open_pursuit_leads that never raises.

        Called during landscape assessment, which must never fail the
        cycle. If the ledger table is missing or a query raises, return
        an empty list and log the error. The optional `source_verdict`
        filter selects hard vs soft leads.
        """
        try:
            return self.ledger.get_open_pursuit_leads(
                limit=limit, source_verdict=source_verdict,
            )
        except Exception:
            logger.exception("Failed to fetch open pursuit leads (returning [])")
            return []

    def _close_referenced_pursuit_leads(
        self, theories: list[TheoryRecord],
    ) -> None:
        """Close any open pursuit lead whose lead_id is referenced by an
        approved theory via the "pursuit_lead:<id>" tag convention.

        Day 6: this is how the lead-pursuit lane actually closes. When
        a theorist cycle generates a variant that targets an open lead
        and the critic approves it, the lead transitions from OPEN to
        PURSUED. Leads that nobody targets eventually auto-close as
        STALE via _run_lead_pursuit's end-of-phase sweep.

        Best-effort — never blocks the cycle on bookkeeping errors.
        """
        closed: set[str] = set()
        for theory in theories:
            for tag in theory.tags or []:
                if not isinstance(tag, str) or not tag.startswith("pursuit_lead:"):
                    continue
                lead_id = tag.split(":", 1)[1].strip()
                if not lead_id or lead_id in closed:
                    continue
                try:
                    lead = self.ledger.get_pursuit_lead(lead_id)
                except Exception:
                    logger.exception(
                        "pursuit-lead lookup failed for %s (continuing)",
                        lead_id,
                    )
                    continue
                if lead is None or lead.status != PursuitLeadStatus.OPEN:
                    continue
                try:
                    self.ledger.close_pursuit_lead(
                        lead_id,
                        status=PursuitLeadStatus.PURSUED,
                        closed_cycle=self.state.cycle_number,
                    )
                    closed.add(lead_id)
                    logger.info(
                        "  ↪ LEAD PURSUED %s by theory %s (cycle %d)",
                        lead_id, theory.hypothesis_id[:8],
                        self.state.cycle_number,
                    )
                except Exception:
                    logger.exception(
                        "pursuit-lead close failed for %s (continuing)",
                        lead_id,
                    )

    # ------------------------------------------------------------------
    # Step 2: Generate theories
    # ------------------------------------------------------------------

    def _collect_hcc_seeds(self) -> list[TheoryRecord]:
        """Compute the HandCipherCore deterministic coverage seeds for
        the current bench challenge.

        Returns the full role × layer-order × family permutation set
        from ``hand_cipher_core_fallback``. The result is deterministic
        for a given bench payload — same clue pack always produces
        the same seed list, in the same order, with the same
        hypothesis_ids.

        In real-K4 mode this returns ``[]``. The bench-mode call site
        in ``_generate_theories`` is responsible for actually merging
        the seeds into the cycle's candidate list; this function only
        produces the seed material so it can be unit-tested
        independently of the LLM session.

        2026-04-27 patch: this is the deterministic-coverage entry
        point the controller uses BEFORE any LLM call. The contract:
        every seed in this list MUST appear in the cycle's dispatched
        candidate set (subject only to ledger-dedup against prior
        cycles). The LLM may add candidates above these but cannot
        replace or omit them.
        """
        if self.config.problem.is_real_k4:
            return []
        # --no-hcc-seeds: explicit operator opt-out. Returns [] without
        # calling the generator at all — useful for LLM-only diagnostic
        # runs where the operator wants to see what the theorist
        # produces in isolation.
        cap = self.config.hcc_seeds_cap
        if cap is not None and cap == 0:
            return []
        from .bench_fallback import hand_cipher_core_fallback
        payload = self.config.bench_challenge_payload or {}
        # n_target is a floor on the catalogue size, NOT a cap. The
        # function returns the full HCC role × order matrix (up to
        # the generate_layered_specs internal max_specs ceiling).
        # ``theories_per_cycle`` deliberately does NOT cap HCC seeds:
        # the cap is governed by ``hcc_seeds_cap`` only, so a user
        # lowering --theories cannot silently drop coverage seeds.
        seeds = hand_cipher_core_fallback(
            payload,
            n_target=self.config.theories_per_cycle,
        )
        # --hcc-seeds N: explicit cap. Slice from the front so the
        # earliest-emitted families (columnar+vigenere first) are
        # preserved even under aggressive caps.
        if cap is not None and cap > 0:
            seeds = seeds[:cap]
        return seeds

    def _merge_hcc_seeds_into_candidates(
        self,
        seeds: list[TheoryRecord],
        llm_candidates: list[TheoryRecord],
    ) -> list[TheoryRecord]:
        """Combine HCC seeds with LLM-supplied candidates.

        Seeds come first (deterministic-coverage contract); LLM
        candidates that share a hypothesis_id with any seed are
        dropped (the seed already covers them). LLM candidates with
        novel hypothesis_ids are appended in order.

        Also dedupes against the live ledger so a seed that was
        already dispatched on a prior cycle isn't re-dispatched —
        this matches the behaviour of the pre-2026-04-27
        ``_programmatic_fallback`` bench branch and keeps the
        ``ResearchController`` cycle behaviour idempotent across
        restarts.
        """
        seen_ids: set[str] = set()
        out: list[TheoryRecord] = []
        for seed in seeds:
            if seed.hypothesis_id in seen_ids:
                continue
            if self.ledger.exists(seed.hypothesis_id):
                # Already in the ledger from a prior cycle; the
                # ledger row carries its own coverage_vector so the
                # seed has already done its job. Skip to keep the
                # dispatched-set finite.
                continue
            seen_ids.add(seed.hypothesis_id)
            out.append(seed)
        for cand in llm_candidates:
            if cand.hypothesis_id in seen_ids:
                continue
            seen_ids.add(cand.hypothesis_id)
            out.append(cand)
        return out

    async def _generate_theories(
        self, landscape: dict[str, Any],
        on_progress: Any = None,
    ) -> list[TheoryRecord]:
        """
        Generate candidate theories using Agent SDK theorist session.

        The theorist is given the current landscape and must produce
        structured theory records (not free-text). Falls back to
        programmatic generation if the agent fails.

        2026-04-27 patch — HandCipherCore deterministic coverage:
        in BENCH MODE only, this function calls
        ``_collect_hcc_seeds`` BEFORE the LLM theorist runs. The
        seeds are deterministic role × layer-order × family
        permutations from the challenge clue pack. They are
        guaranteed to appear in the returned candidate list
        (subject only to ledger dedup against prior cycles); the
        LLM theorist may add additional candidates, but cannot
        replace or omit any seed. Real-K4 mode is unchanged — the
        seeds list is empty and the function behaves exactly as
        before.

        PANTHEON INTEGRATION (Day 2): instead of a generic system prompt,
        the theorist loads one of the Pantheon operator/interpretive-rival
        personas from .claude/agents/*.md, rotating across cycles. Each
        cycle gets a different frame (cryptanalyst → escape-room →
        stego → archivist → keystream → cipher-discovery → repeat). The
        persona loader, rotation policy, and model routing all live in
        kryptosbot.pantheon and kryptosbot.routing. See
        memory/project_sdk_setting_sources_verified.md for the
        empirical facts the integration relies on.

        Sibling-call discipline: setting_sources=["project"] makes
        .claude/skills/ available via the Skill tool, AND makes
        .claude/agents/ available via the Task/Agent tool. We explicitly
        DISABLE Task/Agent in the theorist session (disallowed_tools)
        so the theorist can use skills freely but cannot inline-delegate
        to other Pantheon agents. All inter-agent orchestration happens
        at the Python controller level as sibling calls — never from
        inside a subagent. See feedback_team_of_rivals_audit.md.

        Args:
            on_progress: Optional callback(event, detail) for live display.
                Events: "start", "turn", "tool_use", "done", "fallback", "error".
        """
        # 2026-04-27: collect HCC seeds BEFORE the LLM call. Empty in
        # real-K4 mode. The seeds are merged into every return path
        # below so a seed cannot be silently omitted by an LLM that
        # produces a few "interesting" candidates of its own.
        hcc_seeds = self._collect_hcc_seeds()
        if hcc_seeds and on_progress:
            on_progress(
                "hcc_seeds",
                f"injected {len(hcc_seeds)} deterministic coverage seeds",
            )

        # --hcc-only: skip the LLM call entirely and dispatch only
        # the HCC seed list. Used for deterministic-coverage runs
        # where the operator wants to validate the seed-only
        # behaviour without paying for an LLM session. When the
        # operator combined --hcc-only with --no-hcc-seeds the CLI
        # already errored out, so the empty-seeds branch here is a
        # defensive boundary for programmatic callers only.
        if self.config.hcc_only:
            if not hcc_seeds:
                logger.warning(
                    "--hcc-only requested but no HCC seeds available "
                    "(real-K4 mode or --no-hcc-seeds set); returning []"
                )
                return []
            if on_progress:
                on_progress(
                    "hcc_only",
                    f"hcc_only=True; skipping LLM, dispatching {len(hcc_seeds)} seeds",
                )
            # Run through the merge helper so ledger-dedup still
            # applies (matches the bench-mode path's idempotency
            # contract across cycle restarts).
            return self._merge_hcc_seeds_into_candidates(hcc_seeds, [])

        prompt = self._build_theorist_prompt(landscape)

        # Select Pantheon persona for this cycle and resolve its model.
        # If the roster is empty (no .claude/agents/ found), fall through
        # to a generic theorist — same behavior as the pre-Pantheon
        # controller.
        persona: AgentSpec | None = None
        if self._pantheon_roster:
            try:
                persona = select_theorist(
                    self.state.cycle_number, self._pantheon_roster
                )
            except Exception as exc:
                logger.warning(
                    "Pantheon routing failed (%s) — falling back to generic theorist",
                    exc,
                )

        if persona is not None:
            # Use theorist_system_prompt() not system_prompt(). The default
            # system_prompt() returns the agent body with its narrative
            # Output Contract intact — correct for audit-mode calls but
            # CONFLICTS with the theorist's JSON-array-generation task.
            # The theorist variant wraps the body with output-format
            # override directives. See pantheon.AgentSpec.theorist_system_prompt
            # for the full rationale. Observed failure mode without this
            # wrapper: 16-minute, 75-turn sessions with 0 JSON output.
            system_prompt = persona.theorist_system_prompt()
            model, fallback_model = resolve_model_for_phase(persona, "theorist")
            persona_name = persona.name
        else:
            system_prompt = (
                "You are a K4 research theorist. Generate novel, testable hypotheses "
                "about the K4 cipher based on the current research landscape. "
                "Output ONLY a JSON array of hypothesis objects. No prose."
            )
            # Pre-Pantheon default: Opus on the theorist for creative reasoning
            model, fallback_model = "claude-opus-4-8", "claude-sonnet-4-6"
            persona_name = "generic"

        # Attribution line — Colin's Day 2 spec requirement. Makes
        # five-cycle audits trivial by logging exactly which persona
        # and model ran at each cycle, and what the safety posture was.
        logger.info(
            "theorist_agent=%s model=%s fallback=%s setting_sources=project "
            "task_tools=disabled cycle=%d",
            persona_name, model, fallback_model, self.state.cycle_number,
        )
        if on_progress:
            on_progress(
                "persona",
                f"{persona_name} ({model})",
            )

        raw_chunks: list[str] = []
        stderr_lines: list[str] = []
        if on_progress:
            on_progress("start", "Theorist agent session starting...")

        def _capture_stderr(line: str) -> None:
            stderr_lines.append(line)

        options = ClaudeAgentOptions(
            allowed_tools=self.config.allowed_tools,
            # Explicitly block inline subagent delegation from the theorist.
            # The Pantheon architecture uses sibling calls from the Python
            # controller, not nested subagent calls from within a session.
            # Task/Agent is the Claude Code harness's subagent-spawning tool.
            disallowed_tools=["Task", "Agent"],
            permission_mode=self.config.permission_mode,
            system_prompt=system_prompt,
            cwd=str(self.config.project_root.resolve()),
            max_turns=self.config.theorist_max_turns,
            # Load .claude/skills/ and .claude/agents/ from the project.
            # Verified 2026-04-12 via Day 1 probe — see
            # memory/project_sdk_setting_sources_verified.md
            setting_sources=["project"],
            model=model,
            fallback_model=fallback_model,
            stderr=_capture_stderr,
        )

        try:
            async for message in safe_query(prompt=prompt, options=options):
                if hasattr(message, "result"):
                    raw_chunks.append(str(message.result))
                    if on_progress:
                        on_progress("result", str(message.result)[:150])
                elif hasattr(message, "content"):
                    # Post-K4-cycle-1 hygiene (2026-04-21): message.content
                    # is typically a list of ContentBlock dataclasses
                    # (TextBlock, ThinkingBlock, ToolUseBlock). Python's
                    # str() on such a list yields a repr like
                    # "[TextBlock(citations=None, text='[\\n  {...', type='text')]"
                    # which extract_json_block cannot parse — it silently
                    # falls through to _programmatic_fallback. Extract
                    # TextBlock text explicitly so the downstream
                    # validator sees raw JSON. See K4_RUN_CYCLE1_DIAGNOSTIC.md.
                    text = _extract_message_text(message.content)
                    raw_chunks.append(text)
                    if on_progress:
                        # Check for tool use in structured content
                        if hasattr(message, "content") and isinstance(message.content, list):
                            for block in message.content:
                                if hasattr(block, "type") and block.type == "tool_use":
                                    tool_name = getattr(block, "name", "?")
                                    on_progress("tool_use", tool_name)
                                    break
                            else:
                                snippet = text.replace("\n", " ")[:120]
                                on_progress("turn", snippet)
                        else:
                            snippet = text.replace("\n", " ")[:120]
                            on_progress("turn", snippet)
        except Exception as exc:
            combined_error = str(exc)
            if stderr_lines:
                combined_error = f"{combined_error}\n" + "\n".join(stderr_lines[-20:])
            is_fatal, classified = self._classify_agent_failure(combined_error)
            if is_fatal:
                self._record_theorist_parse_diagnostics({
                    "cycle": self.state.cycle_number,
                    "parse_outcome": "fatal_agent_failure",
                    "used_fallback": False,
                    "fallback_reason": "",
                    "error": classified,
                    "raw_length": 0,
                    "valid_count": 0,
                    "invalid_count": 0,
                    "error_count": 1,
                })
                self._fatal_agent_error = classified
                logger.warning("Theorist session failed fatally: %s", classified)
                if on_progress:
                    on_progress("error", classified)
                # 2026-04-27: even on fatal LLM failure, bench mode
                # still emits HCC seeds for THIS cycle so the
                # deterministic coverage matrix runs. The
                # fatal_agent_error flag still halts the run after
                # this cycle finishes — see should_abort_run().
                if hcc_seeds:
                    return self._merge_hcc_seeds_into_candidates(hcc_seeds, [])
                return []
            logger.warning("Theorist session failed: %s", combined_error)
            self._record_theorist_parse_diagnostics({
                "cycle": self.state.cycle_number,
                "parse_outcome": "agent_failure_fallback",
                "used_fallback": True,
                "fallback_reason": "agent_failure",
                "error": combined_error[:500],
                "raw_length": 0,
                "valid_count": 0,
                "invalid_count": 0,
                "error_count": 1,
            })
            if on_progress:
                on_progress(
                    "fallback",
                    f"agent_failure: {type(exc).__name__}; using programmatic generation",
                )
            return self._programmatic_fallback(landscape)

        raw_output = "\n".join(raw_chunks)
        # Route validation through ProblemContext so bench runs validate
        # against an empty anomaly registry (any anomalies_exploited
        # reference becomes a contamination signal, not a real-K4 ID
        # check).
        report = validate_theory_proposals(
            raw_output, problem=self.config.problem
        )
        diagnostics = self._build_theorist_parse_diagnostics(raw_output, report)
        self._record_theorist_parse_diagnostics(diagnostics)

        if report.errors:
            for err in report.errors:
                logger.warning("Theorist parse error: %s", err)
        if report.invalid:
            logger.info(
                "Rejected %d invalid theory proposals from theorist",
                len(report.invalid),
            )
            for inv in report.invalid:
                logger.debug(
                    "  Rejected proposal #%s: %s",
                    inv.get("index", "?"), inv.get("error", "unknown"),
                )

        if not report.valid:
            logger.warning(
                "No valid theories parsed from theorist output; using fallback "
                "(reason=%s suspicious=%s valid=%d invalid=%d errors=%d)",
                diagnostics.get("fallback_reason", "unknown"),
                diagnostics.get("suspicious_fallback", False),
                diagnostics["valid_count"],
                diagnostics["invalid_count"],
                diagnostics["error_count"],
            )
            if diagnostics.get("suspicious_fallback"):
                logger.warning(
                    "Suspicious theorist fallback: raw output looked structured "
                    "but produced zero valid proposals (repr_mangling=%s, "
                    "json_like=%s)",
                    diagnostics.get("repr_mangling_suspected", False),
                    diagnostics.get("suspicious_json_like", False),
                )
            if on_progress:
                on_progress(
                    "fallback",
                    f"{diagnostics.get('fallback_reason', 'unknown')} "
                    f"(invalid={diagnostics['invalid_count']} errors={diagnostics['error_count']})",
                )
            # The fallback in bench mode IS the HCC catalogue, so we
            # do NOT additionally prepend hcc_seeds here — that would
            # double-count. In real-K4 mode hcc_seeds is empty, so
            # prepending would be a no-op anyway.
            return self._programmatic_fallback(landscape)

        # 2026-04-27 deterministic-coverage merge: bench-mode runs
        # always include the HCC seeds in the dispatched set. In
        # real-K4 mode hcc_seeds is empty, so this collapses to the
        # historical ``report.valid[:theories_per_cycle]`` behaviour
        # bit-for-bit.
        llm_candidates = report.valid[:self.config.theories_per_cycle]
        if hcc_seeds:
            return self._merge_hcc_seeds_into_candidates(
                hcc_seeds, llm_candidates,
            )
        return llm_candidates

    # ------------------------------------------------------------------
    # Step 3b: Red-team pre-check (Day 3 Pantheon integration)
    # ------------------------------------------------------------------

    async def _red_team_filter(
        self,
        approved: list[TheoryRecord],
        on_progress: Any = None,
    ) -> list[TheoryRecord]:
        """
        Run red-team-disprover as a sibling call against each approved
        theory. Returns the filtered list of theories that survived the
        adversarial pre-check.

        Behavior:
          - skip_red_team config flag → returns input unchanged
          - red-team-disprover not in roster → returns input unchanged
            (logs a warning so the missing agent is visible)
          - SDK error or parse failure for a specific theory → that
            theory passes through (red-team verdict="error" treated as
            "pass" per pantheon_siblings.RedTeamVerdict.should_dispatch)
          - verdict="reject" → theory downgraded to CRITICIZED, removed
            from the dispatch set, and its critic_verdict is annotated
            with the red-team rejection reasons
          - verdict="concerned" → theory passes but logs a warning and
            annotates the critic_verdict
          - verdict="pass" → theory passes through unchanged

        All red-team verdicts are upserted to the ledger via the theory's
        critic_verdict field, so the audit trail is preserved regardless
        of the final dispatch decision.

        Args:
            approved: theories that survived the critic stage
            on_progress: optional callback(event, detail) for the TUI.
                Events:
                  "start"      detail = (agent_name, model, count)
                  "verdict"    detail = RedTeamVerdict + theory title
                  "summary"    detail = (survivors, total, rejected)
                  "skipped"    detail = reason string
        """
        if self.config.skip_red_team:
            logger.info("Red-team pre-check skipped (config.skip_red_team=True)")
            if on_progress:
                on_progress("skipped", "config.skip_red_team=True")
            return approved

        # K4Bench cost-control gate (2026-04-28): when
        # redteam_min_crib_score > 0, skip the red-team sibling call for
        # HCC seeds (deterministic challenge-local coverage). LLM-
        # generated theories ALWAYS hit red-team regardless of N. HCC
        # seeds carry minimal_test_spec.method == "bench_hand_cipher_core"
        # — that's the durable discriminator (more specific than
        # origin="programmatic_fallback", which is shared with the real-
        # K4 fallback path). Pre-dispatch HCC seeds have no crib_score,
        # so any positive threshold collapses to "skip red-team for HCC
        # pre-dispatch"; the field name preserves intent (a future post-
        # dispatch red-team path can re-read it as "redteam if crib >= N").
        min_crib = int(self.config.redteam_min_crib_score or 0)
        if min_crib > 0:
            llm_theories: list[TheoryRecord] = []
            hcc_bypass: list[TheoryRecord] = []
            for t in approved:
                if _is_hcc_seed(t):
                    hcc_bypass.append(t)
                else:
                    llm_theories.append(t)
            if hcc_bypass:
                logger.info(
                    "Red-team gate: bypassing %d HCC seed(s) "
                    "(redteam_min_crib_score=%d, deterministic seeds "
                    "without pre-dispatch crib_score skip pre-check)",
                    len(hcc_bypass), min_crib,
                )
                if on_progress:
                    on_progress(
                        "skipped",
                        f"hcc_bypass={len(hcc_bypass)} "
                        f"min_crib={min_crib}",
                    )
            if not llm_theories:
                # Nothing to red-team; HCC bypass returns the full set
                # unchanged (caller still dispatches them).
                return approved
            approved_for_redteam = llm_theories
        else:
            hcc_bypass = []
            approved_for_redteam = approved

        redteam_spec = select_redteam(self._pantheon_roster)
        if redteam_spec is None:
            logger.warning(
                "Red-team pre-check skipped: red-team-disprover not in "
                "Pantheon roster. Theories will dispatch without "
                "adversarial pre-check."
            )
            if on_progress:
                on_progress("skipped", "red-team-disprover not in roster")
            return approved

        # Attribution line — same format as the theorist line.
        from .pantheon import resolve_model_for_phase
        rt_model, _ = resolve_model_for_phase(redteam_spec, "red_team")
        logger.info(
            "redteam_agent=%s model=%s setting_sources=project "
            "task_tools=disabled cycle=%d count=%d",
            redteam_spec.name, rt_model, self.state.cycle_number,
            len(approved_for_redteam),
        )
        if on_progress:
            on_progress(
                "start",
                (redteam_spec.name, rt_model, len(approved_for_redteam)),
            )

        survivors: list[TheoryRecord] = list(hcc_bypass)
        concerned_count = 0
        error_count = 0
        for theory in approved_for_redteam:
            verdict = await run_red_team_precheck(
                theory,
                redteam_spec=redteam_spec,
                project_root=self.config.project_root.resolve(),
                allowed_tools=self.config.allowed_tools,
                permission_mode=self.config.permission_mode,
                bench_mode=self.config.problem.is_bench,
            )

            # Day 5: capture the verdict in the per-cycle dict so the
            # end-of-cycle synthesis can read it. Set/cleared by
            # _begin_cycle_phase_state.
            self._cycle_redteam_verdicts[theory.hypothesis_id] = verdict

            logger.info(verdict.to_log_line(theory.hypothesis_id))
            if on_progress:
                on_progress("verdict", (theory, verdict))

            # Annotate the theory's critic_verdict so the ledger captures
            # the red-team review for this theory regardless of outcome.
            if theory.critic_verdict is not None:
                theory.critic_verdict.reasons = list(theory.critic_verdict.reasons)
                theory.critic_verdict.reasons.append(
                    f"red-team:{verdict.verdict} (conf={verdict.confidence:.2f})"
                )
                for r in verdict.reasons[:3]:  # keep ledger reasons compact
                    theory.critic_verdict.reasons.append(f"  - {r}")

            # Controller-side escalation (added 2026-04-17): CONCERNED with
            # search_space_risk=duplicate_family auto-escalates to REJECT.
            # Rationale: the Priority-5 taxonomy defines duplicate_family
            # as "the mechanism has been structurally eliminated; re-running
            # under a new name would produce the same result." That is
            # logically a rejection of the theory, not a dispatch decision.
            # Day 8+ evidence (2026-04-17 run cycles 94-102, cycle 102 test
            # run): every CONCERNED+duplicate_family theory dispatched during
            # those cycles burned 3-8 minutes of compute and produced noise
            # exactly as the red-team predicted. Honoring the taxonomy's own
            # semantics closes this waste path. Reverses the original
            # Priority-5 "duplicate_family dispatches clean" choice.
            #
            # NOTE: this is NOT a lexicon rule (which
            # feedback_concerned_vs_search_space_risk_separation.md
            # forbids). It reads the structured search_space_risk value
            # emitted directly by the red-team agent. If the agent tags
            # borderline cases too aggressively, the correct response is
            # for it to use residual_caution for those cases, not for the
            # controller to hedge on duplicate_family.
            # 2026-04-30 extension: same pattern for unbounded_search and
            # exhausted_source_material. Live-run audit (cycles 176-250)
            # found 7-of-8 CONCERNED theories per cycle dispatched anyway
            # with these risk values. The audit memo explicitly named
            # "v7 is the 4th cipher pivot against the same fixed
            # CT-perturbation list — needs a hard stop after this round"
            # and the controller dispatched CT-v7 anyway. The risk
            # taxonomy defines all three of these as logical rejections,
            # not borderline cases, so all three should escalate. This
            # leaves residual_caution as the only CONCERNED-with-risk
            # value that still dispatches, matching the agent's intended
            # semantics for "I looked and found no structural problem."
            HARD_GATE_RISKS = {
                "duplicate_family",
                "unbounded_search",
                "exhausted_source_material",
            }
            risk_value = (verdict.search_space_risk or "none")
            if (
                verdict.verdict == "concerned"
                and risk_value in HARD_GATE_RISKS
            ):
                logger.warning(
                    "  ↑ ESCALATED concerned→reject by %s policy: %s — %s",
                    risk_value,
                    theory.title[:60],
                    verdict.reasons[0] if verdict.reasons else "no reason given",
                )
                theory.status = TheoryStatus.CRITICIZED
                if theory.critic_verdict is not None:
                    theory.critic_verdict.reasons = list(theory.critic_verdict.reasons)
                    theory.critic_verdict.reasons.append(
                        f"controller escalated concerned→reject on "
                        f"search_space_risk={risk_value}"
                    )
                self.ledger.upsert_theory(theory)
                # 2026-05-17: count this rejection toward upstream
                # filtering so the D-zero halt does not fire when
                # red-team is doing the work.
                self._cycle_redteam_reject_count += 1
                continue

            if verdict.verdict == "reject":
                # Downgrade this theory before dispatch
                theory.status = TheoryStatus.CRITICIZED
                self.ledger.upsert_theory(theory)
                logger.info(
                    "  ↓ DOWNGRADED by red-team: %s — %s",
                    theory.title,
                    verdict.reasons[0] if verdict.reasons else "no reason given",
                )
                # 2026-05-17: count this rejection toward upstream filtering.
                self._cycle_redteam_reject_count += 1
                continue

            if verdict.verdict == "concerned":
                concerned_count += 1
                # Priority 5: read search_space_risk directly off the
                # verdict. No lexicon inference. "residual_caution" and
                # "none" mean the red-team looked and found no
                # structural problem — dispatch clean. Any other value
                # gets surfaced in the warning log and fed to
                # _build_worker_prompt for a category-specific block.
                # duplicate_family is handled above via controller-side
                # escalation to REJECT and never reaches this branch.
                risk = verdict.search_space_risk or "none"
                if risk in ("none", "residual_caution"):
                    logger.warning(
                        "  ⚠ Red-team CONCERNED about %s — %s "
                        "(risk=%s, dispatching clean)",
                        theory.title[:60],
                        verdict.reasons[0] if verdict.reasons else "no reason given",
                        risk,
                    )
                else:
                    logger.warning(
                        "  ⚠ Red-team CONCERNED about %s — %s "
                        "(dispatching with risk=%s)",
                        theory.title[:60],
                        verdict.reasons[0] if verdict.reasons else "no reason given",
                        risk,
                    )
            elif verdict.verdict == "error":
                error_count += 1

            # Persist the annotated verdict back to the ledger
            self.ledger.upsert_theory(theory)
            survivors.append(theory)

        rejected = len(approved) - len(survivors)
        # Survivors include both red-teamed survivors AND HCC bypasses.
        # The "clean" tally subtracts the bypass count so the log
        # accurately reports the red-team's adversarial verdict
        # distribution; the bypass count is shown separately so the
        # operator can see how much LLM cost was avoided.
        clean = len(survivors) - len(hcc_bypass) - concerned_count - error_count
        logger.info(
            "Red-team filter: %d/%d theories survived "
            "(%d clean, %d concerned, %d error, %d rejected, %d hcc-bypass)",
            len(survivors), len(approved),
            clean, concerned_count, error_count, rejected, len(hcc_bypass),
        )
        if on_progress:
            on_progress(
                "summary",
                (len(survivors), len(approved), rejected, concerned_count, error_count),
            )
        return survivors

    def _assess_landscape_bench(self) -> dict[str, Any]:
        """Build a challenge-local landscape for K4Bench input mode.

        Hard contract (2026-04-26): in bench mode the landscape MUST
        NOT carry any real-K4 family, anomaly, standing constraint,
        anchor, or recent-outcome string. The only permitted bench
        context is:

          - bench_id / suite_id / title          (from challenge JSON)
          - challenge CT length / crib count     (from challenge JSON)
          - prior attempts for this bench_id     (bench-scoped ledger)
          - synthetic ledger status              (pinned mode marker)
          - cycle telemetry                      (status_counts, delta)
          - previous_synthesis                   (only if produced
                                                  under bench mode in
                                                  this same run)

        This method is the single source of truth for bench-mode
        landscape content. ``_assess_landscape`` short-circuits to it
        when ``is_bench_mode`` so KNOWN_FAMILIES / KNOWN_ANOMALIES /
        STANDING_CONSTRAINTS / EXTERNALLY_EVIDENCED_FAMILIES /
        ADMISSIBLE_PROMPT_ANOMALY_IDS are never read for a bench run.
        Empty arrays are returned for the K4-specific fields so the
        downstream theorist-prompt builder, display, and programmatic
        fallback all see a structurally complete dict but with no
        content to leak.
        """
        status_counts = self.ledger.count_by_status()

        current_tested = sum(
            status_counts.get(s, 0)
            for s in ("completed", "eliminated", "promising")
        )
        current_eliminated = status_counts.get("eliminated", 0)
        delta = {
            "new_tested": current_tested - getattr(
                self, "_session_baseline_tested", current_tested
            ),
            "new_eliminated": current_eliminated - getattr(
                self, "_session_baseline_eliminated", current_eliminated
            ),
        }

        # All bench context is sourced via ProblemContext so the
        # accessor is the single audit point for what's permitted in
        # a bench landscape. The ledger pin is added in by the
        # controller (it lives on the bench-scoped ledger, not on
        # the immutable challenge payload).
        bench_context = self.config.problem.bench_context_dict()
        try:
            bench_context["synthetic_ledger_pin"] = (
                self.ledger.get_pinned_synthetic_mode()
            )
        except Exception:
            bench_context["synthetic_ledger_pin"] = None

        prior_attempts = {
            "total": sum(status_counts.values()),
            "completed": status_counts.get("completed", 0),
            "eliminated": status_counts.get("eliminated", 0),
            "promising": status_counts.get("promising", 0),
            "running": status_counts.get("running", 0),
            "criticized": status_counts.get("criticized", 0),
            "error": status_counts.get("error", 0),
        }

        previous_synthesis = (
            {
                "headline": self._last_synthesis.headline,
                "recommended_next_focus":
                    self._last_synthesis.recommended_next_focus,
                "family_movements": list(
                    self._last_synthesis.family_movements
                ),
                "evidence_added": list(self._last_synthesis.evidence_added),
                "dispatched_count": self._last_synthesis.dispatched_count,
                "disproved_count": self._last_synthesis.disproved_count,
                "signal_count": self._last_synthesis.signal_count,
            }
            if self._last_synthesis is not None
            else None
        )

        return {
            "bench_mode": True,
            "status_counts": status_counts,
            "cycle_delta": delta,
            "theorist_parse_telemetry": {
                "successes": self.state.theorist_parse_successes,
                "partial_successes":
                    self.state.theorist_parse_partial_successes,
                "fallbacks": self.state.theorist_fallbacks,
                "fallback_reasons": dict(
                    self.state.theorist_fallback_reasons
                ),
                "last": dict(self.state.last_theorist_parse_diagnostics),
            },
            "bench_context": bench_context,
            "prior_attempts": prior_attempts,
            "previous_synthesis": previous_synthesis,
            # The following fields are kept in the dict for structural
            # parity with the real-K4 landscape (so display + theorist
            # prompt builder see the same shape) but MUST stay empty
            # under bench mode. Any non-empty value here is a leak.
            "standing_constraints": [],
            "active_families": [],
            "underexplored_families": [],
            "open_anomalies": [],
            "unaddressed_anomalies": [],
            "prompt_anomaly_count": 0,
            "registry_open_anomaly_count": 0,
            "recent_outcomes": [],
            "pursuit_leads": [],
            "soft_pursuit_leads": [],
        }

    def _strip_landscape_for_bench(
        self, landscape: dict[str, Any],
    ) -> dict[str, Any]:
        """Return a bench-safe view of the landscape.

        Defense-in-depth complement to ``_assess_landscape_bench``: even
        if a future change accidentally re-introduces real-K4 fields
        into a bench landscape, this projection drops them before the
        theorist prompt is built.

        Kept fields (bench-safe by construction — counts, counters,
        and bench_context derived from the challenge JSON itself):
          - bench_mode                           sentinel
          - status_counts                        bench-ledger counts
          - cycle_delta                          session delta
          - theorist_parse_telemetry             parse rates
          - bench_context                        bench_id/title/etc.
          - prior_attempts                       bench-scoped summary
          - previous_synthesis                   bench-cycle synthesis
                                                 only (real-K4 mode
                                                 never reaches this
                                                 stripper)
        Dropped: every other field — including any real-K4 anomaly,
        family, anchor, or claim name that could leak into a bench
        prompt.

        The acceptance test for this helper is in
        ``test_bench_mode_pipeline.py::test_bench_prompt_omits_real_k4_anomaly_phrases``:
        a bench-mode theorist prompt must not contain K4-specific
        phrases unless they appear verbatim in the challenge JSON.
        """
        bench_safe_keys = (
            "bench_mode",
            "status_counts",
            "cycle_delta",
            "theorist_parse_telemetry",
            "bench_context",
            "prior_attempts",
            "previous_synthesis",
        )
        return {k: landscape.get(k) for k in bench_safe_keys}

    def _render_landscape_anomaly_claims(self, landscape: dict[str, Any]) -> str:
        """Render the anomaly-backed ProvenanceClaims visible in the landscape
        as auto-hedged lines for injection into prompts.
        """
        lines: list[str] = []
        seen: set[str] = set()
        for bucket in ("open_anomalies", "unaddressed_anomalies"):
            for item in landscape.get(bucket, []):
                cid = item.get("claim_id") or ""
                if not cid or cid in seen:
                    continue
                seen.add(cid)
                claim = CANONICAL_CLAIMS_BY_ID.get(cid)
                if claim is None:
                    continue
                ok, _ = can_use_in_prompt(claim)
                if not ok:
                    continue
                lines.append(f"- [{cid}] {render_claim_inline(claim)}")
        return "\n".join(lines) if lines else "(no anomaly-backed claims in current landscape)"

    def _render_pursuit_leads_for_prompt(
        self,
        pursuit_leads: list[dict[str, Any]],
        soft_pursuit_leads: Optional[list[dict[str, Any]]] = None,
    ) -> str:
        """Render the open pursuit leads as a priority-context block.

        Day 6: this block tells the theorist which sub-signal follow-ups
        the evaluator flagged as worth extending. Leads are NOT a
        dispatch trigger — the theorist still decides whether to generate
        variants. Passive surfacing by design; see
        project_day6_lead_pursuit_plan.md decision 5 and
        feedback_pursuit_stays_passive.md.

        Two sections rendered:
          - PRIORITY PURSUIT LEADS: hard leads (evaluator verdict=pursue).
            Capped at 10. Full rationale + up to 3 variants each.
          - SOFT PURSUIT LEADS: soft leads (evaluator verdict=skip with
            non-empty suggested_variants). Capped small by caller. Shorter
            rationale + up to 2 variants each. Lower priority framing.
        """
        soft_pursuit_leads = soft_pursuit_leads or []
        lines: list[str] = []

        # --- Hard leads section -----------------------------------------
        if not pursuit_leads:
            lines.append(
                "PRIORITY PURSUIT LEADS (recent interesting results "
                "worth following up):\n  (none open)"
            )
        else:
            lines.append(
                "PRIORITY PURSUIT LEADS (recent interesting results "
                "worth following up):"
            )
            for lead in pursuit_leads[:10]:
                hid = str(lead.get("source_theory_id", ""))[:8]
                score = lead.get("crib_score", 0)
                cyc = lead.get("source_cycle", "?")
                rationale = str(lead.get("rationale", ""))[:200]
                lines.append(
                    f"  - lead_id={lead.get('lead_id', '?')} "
                    f"source={hid} score={score}/24 opened_in_cycle={cyc}"
                )
                if rationale:
                    lines.append(f"    rationale: {rationale}")
                variants = lead.get("suggested_variants") or []
                for v in list(variants)[:3]:
                    lines.append(f"    variant: {str(v)[:160]}")

        # --- Soft leads section -----------------------------------------
        if soft_pursuit_leads:
            lines.append("")
            lines.append(
                "SOFT PURSUIT LEADS (evaluator skipped the parent lead but "
                "preserved nearby variant directions — weaker context, "
                "only pursue if it fits the cycle's theme):"
            )
            for lead in soft_pursuit_leads:
                hid = str(lead.get("source_theory_id", ""))[:8]
                score = lead.get("crib_score", 0)
                cyc = lead.get("source_cycle", "?")
                rationale = str(lead.get("rationale", ""))[:120]
                lines.append(
                    f"  ~ lead_id={lead.get('lead_id', '?')} "
                    f"source={hid} score={score}/24 opened_in_cycle={cyc}"
                )
                if rationale:
                    lines.append(f"    rationale: {rationale}")
                variants = lead.get("suggested_variants") or []
                for v in list(variants)[:2]:
                    lines.append(f"    variant: {str(v)[:140]}")

        lines.append(
            "\nIf any of your proposals target or extend these leads, "
            "include the lead's lead_id in your theory's tags field as "
            "\"pursuit_lead:<lead_id>\" so the critic can prioritize them. "
            "Leads are context, NOT mandatory — generate new independent "
            "theories too."
        )
        return "\n".join(lines)

    def _render_oranchak_corpora_for_prompt(self) -> str:
        """Render the mirrored Oranchak community reference corpora as
        a read-only resource block for the theorist.

        Campaign-A hardening addition (2026-04-22). The assets are:

          - ``wordlists/quagmire3_keywords_oranchak.txt`` (10,000 words)
            — community-curated English frequency list used as a
            Quagmire III keyword sweep space.
          - ``wordlists/quagmire4_keywords_oranchak.txt`` (7,092 words)
            — same shape, Quagmire IV pool.
          - ``data/k4_candidate_fills_oranchak.csv`` (19,185 rows) —
            K4-shaped candidate plaintexts (97 chars with EASTNORTHEAST
            at 21-33 and BERLINCLOCK at 63-73). Useful as a fill-
            language reference for scoring decrypted plaintext
            plausibility outside the crib regions.

        Scope constraint: these are REFERENCES, not theories to propose
        directly. The theorist may:
          (a) propose a Quagmire-family theory using the keyword pool
              as its sweep space — after B-DSL-expanded (2026-04-22),
              kind="quagmire" dispatches natively and requires
              variant ∈ {quagmire_iii, quagmire_iv}, period_keyword,
              ct_alphabet_keyword, pt_alphabet_keyword, and indicator.
              For K1/K2-style Quagmire III set both alphabet keywords
              to the same string (e.g., "KRYPTOS") and indicator to
              that keyword's first letter.
          (b) propose a fill-language-scoring refinement where the
              CSV is used as a plausibility reference for non-crib
              positions.
          (c) rank other proposals by whether their predicted
              plaintext resembles candidates in the fills corpus.

        Tier 3 flag on accompanying source (``reference/cia_1996_memo.md``):
        the CIA 1996 memo is NOT in this block. Its OTP claim rests on
        three other wrong cipher diagnoses; it has no evidentiary
        weight. Do not cite it.

        Campaign-C split (2026-04-24): the serpentine-Vigenère anchor
        that used to live inside this renderer has moved to its own
        method (_render_serpentine_anchor_for_prompt) so it can be
        gated independently. This renderer now contains *only*
        community-derived content.
        """
        return (
            "ORANCHAK COMMUNITY REFERENCE CORPORA (mirrored 2026-04-21):\n"
            "  - wordlists/quagmire3_keywords_oranchak.txt: 10,000 English words "
            "ordered by community Reddit-frequency; use as preregistered Quagmire "
            "III keyword sweep space.\n"
            "  - wordlists/quagmire4_keywords_oranchak.txt: 7,092 words, same shape "
            "for Quagmire IV.\n"
            "  - data/k4_candidate_fills_oranchak.csv: 19,185 K4-shaped candidate "
            "plaintexts (97 chars, cribs fixed at 21-33 and 63-73). Use as a "
            "fill-language plausibility reference for non-crib positions.\n"
            "\n"
            "HOW TO USE:\n"
            "  - kind='quagmire' IS NOW DISPATCHABLE (B-DSL-expanded, "
            "2026-04-22). Required fields: variant ∈ {'quagmire_iii', "
            "'quagmire_iv'}, period_keyword (a keyword from the Oranchak "
            "pool is natural), ct_alphabet_keyword, pt_alphabet_keyword, "
            "indicator (single char). For K1/K2-style Quagmire III set "
            "both alphabet keywords to the same string and indicator to "
            "that string's first letter. Missing any alphabet keyword is "
            "the footgun from f_w10 and will be rejected loudly.\n"
            "  - For fill-language scoring, cite the CSV path in your "
            "minimal_test_spec so the worker can load it; do not paste "
            "candidate rows inline.\n"
            "\n"
            "EPISTEMIC CAVEAT: these are community-seeded reference lists, "
            "not preregistered eliminations. A keyword scoring well against "
            "this pool's ordering is a ranking feature, not a signal. "
            "Treat the corpora as CONTEXT that widens the theorist's "
            "accessible search space — not as evidence."
        )

    def _render_serpentine_anchor_for_prompt(self) -> str:
        """Render the archive-derived serpentine-Vigenère hypothesis seed.

        Primary-source material from the Sanborn Archives of American
        Art holdings (UAN AAA-AAA_sanbojim_4129080, page 17): Sanborn
        describes Kryptos as "a serpentine copper screen perforated
        with encoded text and Blaise De Vigenère's Tableaux". The
        pairing of "serpentine" with "Vigenère's Tableaux" in a single
        Sanborn sentence is a candidate hypothesis seed — the ``route``
        kind with variant="serpentine" composed with a single-layer
        Vigenere on KA is the natural dispatch shape for testing it.
        Not confirmed evidence; valid hypothesis seed.

        Campaign-C split (2026-04-24): moved out of
        _render_oranchak_corpora_for_prompt so it can be gated
        independently. The community-Oranchak corpora and this
        archive-derived anchor have different provenance and should
        not be bundled behind a single toggle.
        """
        return (
            "SERPENTINE-VIGENÈRE ANCHOR (Tier 3, primary-source hypothesis seed):\n"
            "  Sanborn's AAA archive page 17 (UAN AAA-AAA_sanbojim_4129080) "
            "describes Kryptos as \"a serpentine copper screen perforated "
            "with encoded text and Blaise De Vigenère's Tableaux\". The "
            "pairing of the two technical terms in one sentence motivates "
            "testing a two-layer spec with kind='route', variant='serpentine' "
            "composed with kind='vigenere' on alphabet='KA'. Not confirmed; "
            "fair game as a hypothesis anchor."
        )

    def _render_manual_focus_for_prompt(self) -> str:
        """Render operator-injected focus areas that should guide generation.

        Re-seed pass 2026-05-07: ~50 cycles (466-515) returned 0 genuine
        signal. Two 24/24 events were crib-paste fabrications caught by
        stat-audit. Theorist proposals concentrated on five anchors that
        are now either eliminated, saturated, or producing only revivals.
        This block freezes those anchors and redirects to lanes the
        proposal stream has not yet exercised.
        """
        return (
            "MANUAL PRIORITY FOCUS (re-seed pass, effective 2026-05-07):\n"
            "\n"
            "FROZEN ANCHORS — do NOT propose theories built on these for "
            "the duration of this re-seed pass:\n"
            "  - w_delimiter_segments: 11 elimination families across "
            "21,570+ configs (project_w_anchor_hypothesis_eliminated_"
            "2026_04_29). Multi-layer rebrandings keep getting flagged "
            "and rejected by red-team. Set aside until a genuinely novel "
            "mechanism class appears that does not depend on W positions, "
            "W-segment lengths, W-derived col_orders, or W-rank as a "
            "permutation source.\n"
            "  - aaa_compass_cipher: e_compass_route_01 (576 configs, "
            "best 4/24), E-ANTIPODES-11 (9588 configs), Kimmo compass-"
            "cipher base-rate sweep, and 8+ controller cycles in the "
            "preceding run all returned noise. Bearing-indexed indicator "
            "schedules, compass-rose grid masks, and lodestone-bearing "
            "route reads are all in the eliminated set. Set aside.\n"
            "  - aaa_coordinate_lie: 5+ specific mechanisms cleanly "
            "disproved in the preceding run alone (true-coord Beaufort, "
            "delta-Beaufort, Gronsfeld delta, Quagmire IV dual-key "
            "seeding, ROUTE reading-order). Per accept-specific-disproofs "
            "doctrine, the next coord-lie proposal must fix the specific "
            "mechanical error of one prior disproof, not pivot to "
            "preserve the coordinate commitment. Default posture: do "
            "not propose new coord-lie theories this pass.\n"
            "  - width21_vertical_bigrams: ranking feature only. Do not "
            "build new theories on it.\n"
            "  - ct_perturbation Stage A (single-character Hamming-1 "
            "archive-agnostic): exhausted by the 2026-05-01 hardened "
            "rerun (10,465,764 configs over 2,425 H1 variants). Do not "
            "propose Stage A revivals under any cipher family. Stage B "
            "(archive-anchored Hamming-2) is the only ct_perturbation "
            "variant still admissible.\n"
            "\n"
            "REDIRECT — propose into these underexplored lanes:\n"
            "  1. Finite-tape keystream models (key_tape DSL kind, "
            "landed 2026-05-03). Models M1-M5 from keystream-forensics "
            "are now first-class dispatcher targets: finite tape with "
            "null-skip vs null-consume rules, segmented tape (split at "
            "self-encrypting positions), tape-with-interrupt. The DSL "
            "supports tape arrays of length <= 97, variants vigenere/"
            "beaufort/var_beaufort, alphabet AZ or KA, and "
            "null_positions with null_rule skip|consume. This lane has "
            "NOT been mined by recent cycles.\n"
            "  2. Obscure / poorly-evidenced ciphers from the cipher-"
            "discovery KB. The KB currently holds 10 untested entries "
            "in 'probable_but_poorly_evidenced' status. Propose tests "
            "of those that are hand-executable by a 1989 sculptor (run "
            "`PYTHONPATH=src python3 -m kryptos.cipher_discovery.cli "
            "query <term>` to look one up before proposing).\n"
            "  3. Multi-layer compositions where neither layer is a "
            "frozen anchor. Specifically: key_tape (inner) X CT-"
            "perturbation Stage B (outer), or cipher-discovery "
            "candidate X Stage B. The intersection of two productive-"
            "but-sparsely-tested lanes is the obvious unswept region.\n"
            "  4. Mechanism classes that do not have a clue-anchor "
            "justification at all (no AAA quote, no sculpture geometry, "
            "no coordinate notebook). The accept-specific-disproofs "
            "doctrine cuts both ways: revivals tied to known anchors "
            "are penalized, but a genuinely novel mechanism with no "
            "anchor justification is admissible if it has a bounded "
            "search and a concrete kill criterion.\n"
            "\n"
            "Hard rules unchanged: preregistered geometry / parameter "
            "envelope, no rescue parameters (optional truncation, "
            "optional wrap, choose-among-plausible-rectangles), no "
            "retired-claim revival (null-palette, 17-position mask, "
            "Sanborn-self-reference keywords like SCULPTOR/ARTIST)."
        )

    def _build_theorist_prompt(self, landscape: dict[str, Any]) -> str:
        """Build the theorist prompt from the current landscape."""
        hedged_claims = self._render_landscape_anomaly_claims(landscape)
        pursuit_leads_block = self._render_pursuit_leads_for_prompt(
            landscape.get("pursuit_leads") or [],
            landscape.get("soft_pursuit_leads") or [],
        )
        manual_focus_block = self._render_manual_focus_for_prompt()
        if self.config.include_oranchak_corpora:
            oranchak_block = self._render_oranchak_corpora_for_prompt()
        else:
            oranchak_block = ""
        if self.config.include_serpentine_anchor:
            serpentine_block = self._render_serpentine_anchor_for_prompt()
        else:
            serpentine_block = ""

        # Yield-feedback loop sections (Phase-1, 2026-05-16).
        # Rendered as standalone sections AFTER the JSON landscape dump so
        # the model sees them as advisory context rather than raw data.
        # All three are skipped when empty, preserving pre-Phase-1 prompt
        # shape for cold-start / no-pressure cycles.
        #
        # Phase-2 (Task 22, 2026-05-16): escape_candidates is the redirect
        # direction of the yield-feedback loop. When a cycle finishes with
        # last_escape_status="needed_but_unavailable", _assess_landscape
        # surfaces cipher-discovery-KB suggestions for the blocked
        # families; this block renders them as advisory context so the
        # next cycle's theorist can propose them. Empty/missing key
        # preserves Phase-1 prompt shape.
        family_yield_block = landscape.get("family_yield") or ""
        escape_pressure_block = landscape.get("escape_pressure") or ""
        escape_candidates_block = landscape.get("escape_candidates") or ""
        frontier_block = landscape.get("frontier_open") or ""

        # Prior-cycle synthesis (2026-05-17). Closes Tier-C #8 from the
        # 2026-05-16 controller-maturity audit: results-analyst
        # produces a recommended_next_focus per cycle and stores it on
        # the landscape, but _build_theorist_prompt previously did not
        # read it. That made the recommendation a phantom signal —
        # printed at end-of-cycle for human visibility but never reaching
        # the theorist's prompt. Rendered before the yield-feedback
        # blocks so the steer arrives ahead of the pressure / candidate
        # signals.
        previous_synthesis_block = self._render_previous_synthesis(
            landscape.get("previous_synthesis")
        )

        # K4Bench input mode replaces the real-K4 anchor prelude with
        # the synthetic-challenge prompt block. The block is fully
        # self-contained (CT, cribs, clue text, solver contract) and
        # the rest of the prompt below clarifies how to treat the
        # historical landscape under bench mode.
        #
        # Critically: the K4 landscape carries open anomalies
        # (aaa_coordinate_lie / "He lied", width21_vertical_bigrams,
        # w_delimiter_segments / W segmentation), K4-specific families
        # (k2_coords, geodetic, antipodes), and the manual-focus /
        # serpentine-anchor / Oranchak-corpora blocks — none of which
        # apply to a synthetic K4Bench challenge. Surfacing them under
        # bench mode primes the theorist to test K4 anomalies on a
        # CT that has no relation to K4. The bench-mode prompt below
        # therefore (a) skips the K4 anchor blocks entirely (they are
        # already gated on include_oranchak_corpora /
        # include_serpentine_anchor / hedged_claims, which
        # run_controller.main forces False / empty in bench mode), and
        # (b) serializes only a STRIPPED landscape view that carries
        # cycle telemetry but no K4 anomaly / family / anchor names.
        problem = self.config.problem
        if problem.is_bench:
            bench_block = problem.bench_prompt()
            bench_landscape = self._strip_landscape_for_bench(landscape)
            bench_intro = (
                "K4BENCH SYNTHETIC CALIBRATION RUN — the controller is "
                "running against one challenge from the K4Bench blind "
                "synthetic suite. The CIPHERTEXT and CRIB SPANS in the "
                "block above are the SOLE source of truth. The landscape "
                "summary below has been STRIPPED to cycle-telemetry "
                "fields only; real-K4 anomalies, families, and anchor "
                "blocks have been intentionally suppressed because they "
                "do not apply to a synthetic calibration challenge.\n\n"
            )
            bench_id_for_skel = (
                (self.config.bench_challenge_payload or {}).get("bench_id")
                or "K4Bench"
            )
            return f"""{bench_block}

{bench_intro}Generate {self.config.theories_per_cycle} novel, testable hypotheses for the
K4Bench challenge above.

CYCLE TELEMETRY (synthetic-challenge run; no real-K4 content):
{json.dumps(bench_landscape, indent=2)}

CONSTRAINTS:
- Each hypothesis must propose a hand-executable classical/procedural
  cipher chain that, when applied to the K4Bench ciphertext, would
  produce a 97-character A-Z plaintext matching the declared cribs.
- Each must have a clear kill criterion (how to disprove it).
- Use the public clue pack as your source of key material and
  procedure hints.
- Avoid overfitting only the 24 crib positions: a plaintext that
  matches the cribs but reads as noise outside them is a crib-overfit.
- Do not import real-K4 elimination history as a hard constraint; the
  K4Bench construction is independent of K4. A family eliminated for
  real K4 may still be the right answer here.

DSL_SPEC CONTRACT (same shape as the real-K4 theorist contract):
Cipher-family theories MUST include a translatable dsl_spec. Supported
cipher kinds:
  identity, vigenere, beaufort, variant_beaufort, columnar, atbash,
  rail_fence, myszkowski, route, quagmire, grille, polybius, procedural

Required parameter shapes (these are the dispatcher's exact parameter
names; mismatches are repaired or rejected before dispatch):
  - rail_fence:        params=[{{"name": "depth", "values": [<int >= 2>]}}]
  - route:             params=[{{"name": "variant",
                                 "values": ["serpentine"|"spiral"]}},
                                {{"name": "rows", "values": [<int>]}},
                                {{"name": "cols", "values": [<int>]}}]
                       (rows*cols must be >= 97)
  - quagmire:          params=[{{"name": "period_keyword",
                                 "values": [<non-empty A-Z str>]}},
                                {{"name": "indicator", "values": [<single A-Z>]}},
                                {{"name": "ct_alphabet_keyword", "values": [<A-Z>]}},
                                {{"name": "pt_alphabet_keyword", "values": [<A-Z>]}}]
                       Use variant="quagmire_iii" or "quagmire_iv" — NOT
                       "III"/"IV" Roman numerals (rejected).
  - polybius:          params=[{{"name": "square_keyword", "values": [<str>]}},
                                {{"name": "variant", "values": ["bifid"]}},
                                {{"name": "merge", "values": ["IJ"|"CK"|"VW"]}}]
  - vigenere/beaufort/variant_beaufort:
                       params=[{{"name": "keyword", "values": [<A-Z str>]}}]
  - columnar:          params=[{{"name": "width", "values": [<int >= 2>]}},
                                {{"name": "col_order",
                                 "values": [[<permutation of 0..width-1>]]}}]
  - grille:            params=[{{"name": "hole_mask",
                                 "values": [[<permutation of 0..96>]]}}]

Other contract fields:
  hypothesis_id MUST be a non-empty string (theorist-supplied slug).
  pipeline[].alphabet ∈ {{AZ, KA, keyword_mixed}}
  crib_alignment ∈ {{direct_positional, post_transposition, free}}
  scoring ∈ {{crib_only, crib_plus_bean, ngram_vs_null, composite}}
  null_baseline.method ∈ {{random_text, shuffled_ct,
                           matched_variant_family, monte_carlo_cached}}

OUTPUT FORMAT (JSON array — literal, not a description):
Emit ONLY a top-level JSON array of objects. Do not wrap it in any
other JSON structure, do not include ```json fences except optionally
around the array itself, and do not emit prose before or after. The
parser is strict: a trailing summary, a leading "Here are my
theories:", or wrapping the array in {{"theories": [...]}} all cause
the entire batch to be rejected.

Each object MUST include the required fields ``core_claim``,
``mechanism``, ``family``; SHOULD include ``title``, ``kill_criteria``,
``expected_signal``, ``compute_cost_estimate``, ``minimal_test_spec``;
and MUST include a translatable ``dsl_spec`` (since every K4Bench
challenge uses a hand-executable cipher chain — there are no
methodological / non-cipher families in bench mode).

Concrete shape (copy this skeleton and fill in fields):
[
  {{
    "title": "Vigenere with CEDAR keyword",
    "core_claim": "K4Bench challenge {bench_id_for_skel} uses a Vigenere cipher keyed CEDAR",
    "mechanism": "Single-layer Vigenere over A-Z with keyword from clue pack",
    "family": "vigenere",
    "kill_criteria": ["Crib score below 10 with CEDAR keyword"],
    "expected_signal": "crib_score >= 18 with Bean PASS",
    "compute_cost_estimate": "low",
    "minimal_test_spec": {{"method": "vigenere_keyword", "parameters": {{"keyword": "CEDAR"}}}},
    "dsl_spec": {{
      "hypothesis_id": "bench-vig-cedar",
      "pipeline": [{{
        "kind": "vigenere", "alphabet": "AZ",
        "params": [{{"name": "keyword", "values": ["CEDAR"]}}]
      }}],
      "crib_alignment": "direct_positional",
      "scoring": "crib_plus_bean",
      "compute_budget_cpu_minutes": 1,
      "assumption_bundle": ["single_layer"]
    }}
  }},
  {{ /* second hypothesis with the same shape */ }}
]

The dispatcher / worker pipeline is identical in bench mode. A spec
that fails ``validate_hypothesis_spec`` is rejected; the Roman-numeral
quagmire variant pitfall and the empty hypothesis_id pitfall are
auto-repaired before validation, but every other shape error is
reported as ``dsl_untranslatable`` rejection.
"""

        return f"""Generate {self.config.theories_per_cycle} novel, testable K4 hypotheses.

CURRENT RESEARCH LANDSCAPE:
{json.dumps(landscape, indent=2)}

{pursuit_leads_block}

{manual_focus_block}

{oranchak_block}

{serpentine_block}

CONSTRAINTS:
- Each hypothesis must target an active or partially explored family
- Each must have a clear kill criterion (how to disprove it)
- Each should target an underexplored family OR investigate an open anomaly
- Standing constraints (Bean equality, 624 keystreams, self-encrypting positions, etc.) are FACTS — use them to constrain your proposals, not as things to "investigate"
- Open anomalies are testable patterns — propose theories that would EXPLAIN or DISPROVE them
- Do NOT propose hypotheses for eliminated families (tier 1/2 single-layer)
- Prioritize hypotheses that would produce high information gain

EXHAUSTION-OVERLAP OVERRIDE (R2-3, available 2026-04-21):
The dispatcher's admissibility check rejects specs whose cipher family
substring-matches a prior exhaustion-log entry. If your proposal genuinely
adds new information beyond that overlap — e.g., a DIFFERENT assumption
bundle, a different scoring path, a multi-layer composition where the old
elimination was single-layer, a Bean-linear-subset approach not previously
run — you may include ``override_exhaustion: true`` and a non-empty
``override_justification`` in your minimal_test_spec. The justification
must be specific to why the overlap doesn't apply; do NOT reuse the
override to rerun previously-eliminated work. The critic rejects overrides
whose justification (first 100 chars, Jaccard ≥ 0.7) duplicates a prior
theory's override_justification, so laundering a dead idea under new
wording is caught automatically.

IMPORTANT — THE PROCEDURAL PARADIGM (philosophy, not DSL shape):
Sanborn is a sculptor, not a cryptographer. He learned "systems that didn't
necessarily depend on mathematics" from Scheidt in 2-3 meetings. Gillogly
confirmed K4 uses "an invention by Ed Scheidt that has never appeared in
cryptographic literature." The algebraic cipher-family search (50+ families,
105K+ composition branches) is effectively saturated at noise floor.

Prefer PROCEDURAL hypotheses — concrete step-by-step physical operations a
sculptor could execute by hand — over algebraic ones. Physical anomalies on
the sculpture (YAR superscript, extra L, misspellings, compass, LAYER TWO)
are likely INSTRUCTIONS, not decorations.

CRITICAL DISAMBIGUATION:

The "procedural paradigm" above is a PHILOSOPHY about mechanism
preference — favor hand-executable over purely algebraic. That
philosophy is SEPARATE from the DSL's literal ``kind="procedural"``,
which is a narrow technical label reserved for pre-registered recipes
with a ``recipe_id`` (e.g., ``P-042``, ``CP-117``). Using
``kind="procedural"`` with an ad-hoc recipe name (``"serpentine_read"``,
``"ragbaby_inverse"``, ``"alberti_disk_w_indicator"``, etc.) will be
rejected as ``dsl_untranslatable`` — the dispatcher cannot synthesize
a new cipher from a string label.

When your procedural-paradigm hypothesis maps to an existing DSL kind,
USE THAT KIND. Examples:

  - Serpentine / zigzag physical read → ``kind="route"``,
    ``variant="serpentine"`` (composed with Vigenere/Beaufort inner
    gives the AAA-archive "serpentine copper screen + Vigenère
    tableaux" anchor directly).
  - W-segment columnar reorder → ``kind="columnar"`` with a
    W-derived ``col_order``.
  - Compass-bearing-indexed tableau rotation → ``kind="quagmire"``
    with ``indicator`` chosen per-bearing.
  - Depth-based zigzag → ``kind="rail_fence"`` with ``depth``.

Only propose ``kind="procedural"`` when the theory literally executes
a recipe listed in ``docs/procedural_recipes.json`` with its ``P-xxx``
or ``CP-xxx`` identifier supplied in the ``recipe_id`` field (NOT the
``params``). Anomalies with recipe IDs in the landscape surface those
identifiers; cite them directly.

The "procedural" FAMILY (theory.family) is a separate classification
from the DSL kind. A theory whose family is "procedural" can still
use any cipher kind in its pipeline — they are orthogonal fields.

STATISTICAL FINGERPRINTS — ADVISORY, NOT MANDATORY:
The following claims are drawn from the canonical provenance registry with
epistemic hedges auto-inserted. They are RANKING FEATURES, not must-explain
constraints. Do NOT treat Bean-reported statistics as hard facts you must
accommodate; treat them as soft signals that MAY narrow the search.

{hedged_claims}

Theories that exploit or explain a signal score higher than theories that
ignore it, but no proposal is rejected merely for failing to explain a
BEAN_REPORTED_NOT_RERUN or PROJECT_REVERIFIED_STATISTICAL_ANOMALY item.

DO NOT propose theories involving the retired null-palette / null-mask
family (claim_id: null_palette_retired). A specific 7-letter subset was
investigated and retired 2026-04-14 after matched controls disproved its
specificity; the letter set is intentionally not named here to avoid
re-anchoring. Do not attempt to infer it. Any theory proposing a fixed
small-alphabet null set at a fixed position mask should be treated as a
revival of this retired claim and withdrawn.

DO NOT invoke CONSENSUS_NULL_POSITIONS or any "17-position null mask"
construct as a foundation for a theory. This mask is pending retraction:
it was derived from the retired palette hypothesis and has no independent
verification. Theories that rest on the 17-position mask are building on
historical weight, not epistemic support, and will be rejected by the
critic. See memory/project_consensus_nulls_epistemic_status_2026_04_14.md.

ACTIVE ANOMALY SURFACE (RE-SEEDED 2026-05-07):
The five-anchor surface (w_delimiter_segments, aaa_compass_cipher,
aaa_coordinate_lie, width21_vertical_bigrams, ct_perturbation) has
returned 0 genuine signal across the most recent ~50 cycles, with
proposal flow concentrating on revivals of already-eliminated
families. This pass FREEZES four of the five anchors and treats only
ct_perturbation Stage B (archive-anchored Hamming-2) as an active
anchor. See MANUAL PRIORITY FOCUS for the redirect lanes
(key_tape DSL finite-tape models, cipher-discovery untested entries,
multi-layer compositions where neither layer is a frozen anchor).

Frozen anchors for this pass: w_delimiter_segments,
aaa_compass_cipher, aaa_coordinate_lie, width21_vertical_bigrams.
Active anchor: ct_perturbation (Stage B only; Stage A exhausted
2026-05-01).

Open-anomaly entries from the landscape JSON above are surfaced for
audit context; treat them as evidence the proposal may NOT build on
unless the entry is the active ct_perturbation anchor. Other
historical anomalies remain in the ledger but are demoted from
active prompting until a future hardening pass restores them with
new finite evidence.

OUTPUT FORMAT (JSON array):
[
  {{
    "title": "Short descriptive title",
    "core_claim": "What this hypothesis claims about K4",
    "mechanism": "The specific cipher/method mechanism proposed",
    "family": "Cipher family (must match an active family_id)",
    "subfamily": "Optional subfamily",
    "tags": ["tag1", "tag2"],
    "clue_anchors_used": ["Which known facts this builds on"],
    "anomalies_exploited": ["Which anomalies this addresses"],
    "novelty_basis": "Why this is genuinely new, not a rehash",
    "kill_criteria": ["Specific conditions that would disprove this"],
    "expected_signal": "What a correct result would look like",
    "compute_cost_estimate": "low/medium/high",
    "minimal_test_spec": {{
      "method": "How to test this hypothesis",
      "parameters": {{}}
    }},
    "dsl_spec": {{ /* REQUIRED for cipher families — see DSL_SPEC CONTRACT below.
                     Copy Example A/B/C shape. Set null ONLY if family is in
                     {{geometry, k2_coords, geodetic, antipodes, archive_evidence,
                      crib_analysis, k3_continuity}}. */ }}
  }}
]

DSL_SPEC CONTRACT (R3-2, 2026-04-21):
Cipher-family theories MUST include a dsl_spec that the dispatcher can
execute. Methodological/investigative theories (family in geometry,
k2_coords, geodetic, antipodes, archive_evidence, crib_analysis,
k3_continuity) may set "dsl_spec": null and will route through the
legacy worker path with a ledger tag.

Supported cipher kinds (translator lives in kryptosbot.job_dispatcher):
  identity, vigenere, beaufort, variant_beaufort, columnar, atbash,
  rail_fence, myszkowski, route, quagmire, grille, polybius, procedural

IMPORTANT — the ``procedural`` DSL kind is NOT the same as the
"procedural paradigm" philosophical section below. ``procedural`` is
reserved for pre-registered recipes with a ``recipe_id`` like
``P-042`` or ``CP-117``. If your theory implements a different
mechanism (serpentine read, ragbaby cipher, Alberti disk, compass-
bearing tableau, W-segment polyalphabetic, etc.), use the appropriate
cipher kind directly:

  - Serpentine / spiral / zigzag read → ``kind="route"``,
    ``variant="serpentine"`` or ``"spiral"`` with ``rows``, ``cols``.
  - Rail-fence (zigzag depth) → ``kind="rail_fence"`` with ``depth``.
  - Myszkowski (columnar with tied columns) → ``kind="myszkowski"``
    with ``keyword``.
  - Quagmire III / IV → ``kind="quagmire"`` with ``period_keyword``,
    ``ct_alphabet_keyword``, ``pt_alphabet_keyword``, ``indicator``.
    The ``variant`` field takes the CANONICAL snake_case form
    ``"quagmire_iii"`` or ``"quagmire_iv"`` — NOT the roman-numeral
    labels ``"III"`` / ``"IV"`` the cipher is commonly called. Correct:
    ``{{"kind": "quagmire", "variant": "quagmire_iii", ...}}``. Wrong
    (rejected as dsl_untranslatable): ``{{"kind": "quagmire",
    "variant": "III", ...}}``.
  - Bifid (length-preserving Polybius fractionation) →
    ``kind="polybius"``, ``variant="bifid"``.
  - Cardan grille (hole_mask permutation) → ``kind="grille"``.

Emitting ``kind="procedural"`` with an ad-hoc recipe name will be
rejected as ``dsl_untranslatable``. The dispatcher cannot synthesize a
new cipher from a string label; only registered recipes with declared
templates dispatch.

Valid enum/value domains for dsl_spec fields:
  pipeline[].alphabet: AZ | KA | keyword_mixed
  crib_alignment: direct_positional | post_transposition | free
  scoring: crib_only | crib_plus_bean | ngram_vs_null | composite
  null_baseline.method: random_text | shuffled_ct |
                        matched_variant_family | monte_carlo_cached

Untranslatable kinds (proposing one triggers CriticDecision.
REJECT_UNDERCONSTRAINED with reason "dsl_untranslatable"):
  none — all DSL-valid kinds now have dispatcher translators as of 2026-05-03.

Family and dsl_spec must describe the SAME mechanism class. Do not use a
pipeline kind that does not match the declared family mechanism. "free_search"
is INVALID; the only free-alignment enum value is "free".

Example A — single-layer Vigenere on KA alphabet:
  "dsl_spec": {{
    "hypothesis_id": "<fill with title-derived slug>",
    "pipeline": [
      {{"kind": "vigenere", "alphabet": "KA",
        "params": [{{"name": "keyword",
                     "values": ["PALIMPSEST", "KRYPTOS"]}}]}}
    ],
    "crib_alignment": "direct_positional",
    "scoring": "crib_plus_bean",
    "compute_budget_cpu_minutes": 1,
    "assumption_bundle": ["single_layer"]
  }}

Example B — two-layer columnar-then-Vigenere:
  "dsl_spec": {{
    "hypothesis_id": "<slug>",
    "pipeline": [
      {{"kind": "columnar", "alphabet": "AZ",
        "params": [{{"name": "width", "values": [7]}},
                   {{"name": "col_order",
                     "values": [[3, 1, 4, 0, 6, 2, 5]]}}]}},
      {{"kind": "vigenere", "alphabet": "AZ",
        "params": [{{"name": "keyword",
                     "values": ["KRYPTOS"]}}]}}
    ],
    "crib_alignment": "post_transposition",
    "scoring": "crib_plus_bean",
    "compute_budget_cpu_minutes": 2,
    "assumption_bundle": ["multilayer", "columnar_first"]
  }}

Example C — honest null (non-cipher theory, no spec required):
  Theory's family is e.g. "geometry" or "k2_coords".
  "dsl_spec": null

If you cannot express your cipher-family theory as a valid spec over the
supported kinds, DO NOT fabricate one. Set "dsl_spec": null and accept
rejection — the framework will later extend the DSL rather than you
launder an untranslatable theory through a fake spec.

{"" if not previous_synthesis_block.strip() else previous_synthesis_block + chr(10) + chr(10)}{"" if not family_yield_block.strip() else family_yield_block + chr(10) + chr(10)}{"" if not frontier_block.strip() else frontier_block + chr(10) + chr(10)}{"" if not escape_pressure_block.strip() else escape_pressure_block + chr(10) + chr(10)}{"" if not escape_candidates_block.strip() else escape_candidates_block + chr(10) + chr(10)}Output ONLY the JSON array. No commentary."""

    def _programmatic_fallback(
        self, landscape: dict[str, Any]
    ) -> list[TheoryRecord]:
        """
        Generate theories programmatically when agent fails.

        Uses underexplored families and unaddressed anomalies to construct
        structured hypotheses without an API call. Skips families/anomalies
        that already have theories in the ledger to avoid re-proposing
        eliminated work.

        K4Bench input mode (2026-04-26 v2): routes to
        ``bench_fallback.hand_cipher_core_fallback``. The earlier
        revision returned ``[]`` in bench mode because the real-K4
        fallback corpus draws from the K4 family / anomaly registries
        that don't apply to a synthetic challenge — but that produced
        Proposed=0 / Tested=0 cycles whenever the theorist hiccupped
        on a K4Bench run. The HandCipherCore fallback is challenge-
        local: it mines keys from ``bench_challenge_payload["clue_text"]``
        and emits validated DSL specs over the supported cipher kinds
        (vigenere, beaufort, variant_beaufort, columnar, rail_fence,
        myszkowski, route, quagmire III, plus two-layer combinations).
        Every emitted spec is validated via
        ``validate_hypothesis_spec`` AND every layer kind is checked
        for dispatcher translation BEFORE the TheoryRecord is built,
        so any returned theory is guaranteed dispatchable.

        Real-K4 mode is unchanged: underexplored_families +
        unaddressed_anomalies as before.
        """
        if not self.config.problem.is_real_k4:
            from .bench_fallback import hand_cipher_core_fallback

            payload = self.config.bench_challenge_payload or {}
            theories = hand_cipher_core_fallback(
                payload,
                n_target=self.config.theories_per_cycle,
            )
            # Drop catalogue entries that already exist in the ledger
            # (deterministic catalogue → stable IDs → second cycle would
            # otherwise propose the same set). This mirrors the real-K4
            # branch's existence check below.
            fresh: list[TheoryRecord] = []
            for theory in theories:
                if not self.ledger.exists(theory.hypothesis_id):
                    fresh.append(theory)
            logger.info(
                "bench_fallback emitted %d theories (%d catalogue, %d "
                "already in ledger) for bench_id=%s",
                len(fresh),
                len(theories),
                len(theories) - len(fresh),
                payload.get("bench_id", "?"),
            )
            # If every catalogue entry is already in the ledger, return
            # the full set so the cycle still has something to dispatch
            # — duplicate-protection lives in the dispatcher / critic.
            return fresh if fresh else theories[: self.config.theories_per_cycle]

        theories = []

        # Generate theories for underexplored families — skip those already tested
        for fam_info in landscape.get("underexplored_families", [])[:5]:
            fam_id = fam_info["id"]
            # Check if we already have a theory for this exact family exploration
            existing = self.ledger.get_theories_by_family(fam_id)
            if existing:
                continue  # already have theories for this family, skip

            theory = TheoryRecord(
                title=f"Explore {fam_info['name']} family",
                core_claim=f"K4 may use a mechanism from the {fam_info['name']} family",
                mechanism=f"Standard {fam_info['name']} with keyword from K1-K3 methods",
                family=fam_id,
                novelty_basis=f"Family has {fam_info.get('tested', 0)} controller-tested theories",
                kill_criteria=[
                    "All reasonable keywords produce crib score < 10",
                    "Bean constraints violated for all parameter combinations",
                ],
                expected_signal="Crib score >= 10 with Bean pass",
                compute_cost_estimate="medium",
                minimal_test_spec={
                    "method": "keyword_sweep",
                    "parameters": {"family": fam_id},
                },
                # Campaign-A hardening (2026-04-22): durable provenance so
                # the mortality table detects silent sustained fallback
                # without relying on title-pattern grep.
                origin="programmatic_fallback",
            )
            if not self.ledger.exists(theory.hypothesis_id):
                theories.append(theory)

        # Generate theories exploiting unaddressed anomalies
        for anom_info in landscape.get("unaddressed_anomalies", [])[:3]:
            theory = TheoryRecord(
                title=f"Investigate anomaly: {anom_info['title']}",
                core_claim=f"The anomaly '{anom_info['title']}' is a structural consequence of the K4 cipher method",
                mechanism="To be determined through investigation",
                family="novel",
                anomalies_exploited=[anom_info["id"]],
                novelty_basis=f"No theory has yet addressed anomaly {anom_info['id']}",
                kill_criteria=["Anomaly is explained by random chance (p > 0.05)"],
                expected_signal="Anomaly is explained by a specific cipher mechanism",
                compute_cost_estimate="low",
                minimal_test_spec={
                    "method": "anomaly_investigation",
                    "parameters": {"anomaly_id": anom_info["id"]},
                },
                origin="programmatic_fallback",
            )
            if not self.ledger.exists(theory.hypothesis_id):
                theories.append(theory)

        return theories[:self.config.theories_per_cycle]

    # ------------------------------------------------------------------
    # Step 4: Dispatch theories to workers
    # ------------------------------------------------------------------

    async def _dispatch_theories(
        self, theories: list[TheoryRecord],
        on_worker_message: Any = None,
    ) -> list[WorkerContract]:
        """Dispatch approved theories to workers and collect outcomes.

        R3-2 (2026-04-21): fan-out per DSL_CUTOVER_CONTRACT §2.5.
        Category-B theories (family ∈ NON_DSL_FAMILIES) route to the
        legacy SDK path with a worker_role tag; all other approved
        theories go through the DSL _run_worker (which dispatches via
        job_dispatcher.execute and does NOT spawn a Claude subprocess).

        Every dispatched theory is guaranteed to reach a terminal state
        in the ledger. If a worker raises an exception, the theory gets
        an ERROR contract with its hypothesis_id preserved.

        Args:
            on_worker_message: Optional callback(hypothesis_id, event, detail)
                called during worker execution for live progress display.
                Events: "start", "turn", "tool_use", "done", "error".
        """
        from .critic import NON_DSL_FAMILIES

        tasks = []
        dispatch_roles: list[str] = []  # align with tasks; ERROR contracts need it
        for theory in theories:
            theory.status = TheoryStatus.RUNNING
            self.ledger.upsert_theory(theory)
            family_lower = (theory.family or "").lower()
            if family_lower in NON_DSL_FAMILIES:
                # Category B — methodological / investigative; legacy path.
                tasks.append(
                    self._run_worker_legacy(
                        theory, on_worker_message,
                        tag="non_dsl_category",
                    )
                )
                dispatch_roles.append("agent_sdk_non_dsl_category")
            else:
                # Category A — cipher-family; DSL dispatch.
                tasks.append(self._run_worker(theory, on_worker_message))
                dispatch_roles.append("dsl_dispatcher")

        outcomes = await asyncio.gather(*tasks, return_exceptions=True)

        results = []
        for theory, outcome, role in zip(theories, outcomes, dispatch_roles):
            if isinstance(outcome, Exception):
                logger.error(
                    "Worker for %s raised exception: %s",
                    theory.hypothesis_id, outcome,
                )
                error_contract = WorkerContract(
                    hypothesis_id=theory.hypothesis_id,
                    worker_role=role,
                    status=WorkerStatus.ERROR,
                    error=f"Worker exception: {type(outcome).__name__}: {outcome}",
                )
                # Record a failed experiment so the audit trail is complete
                exp = ExperimentRecord(
                    experiment_id=f"exp-err-{uuid.uuid4().hex[:8]}",
                    hypothesis_id=theory.hypothesis_id,
                    worker_role=role,
                    completed_at=_now_iso(),
                    result=error_contract,
                )
                self._record_experiment_and_link(exp)
                # Even when the worker raised before _run_worker could clean
                # up, we still scan for any artifacts it left behind.
                try:
                    self._cleanup_worker_artifacts(theory, error_contract)
                except Exception as exc:
                    logger.warning(
                        "Cleanup after gather-exception failed for %s: %s",
                        theory.hypothesis_id, exc,
                    )
                results.append(error_contract)
            else:
                results.append(outcome)

        return results

    async def _run_worker(
        self, theory: TheoryRecord, on_message: Any = None,
    ) -> WorkerContract:
        """Dispatch one Category-A (cipher) theory via the DSL.

        R3-2 (2026-04-21): no Claude call on this path. The theorist
        proposed a HypothesisSpec during the theory-proposal phase; by
        the time we get here the critic has already validated the spec
        and confirmed every layer kind is translatable. This function
        parses the spec, runs admissibility + dispatch through
        job_dispatcher.execute (which uses the 28-core multiprocessing
        pool), and converts the JobResult to a kernel-verified
        WorkerContract via job_result_to_worker_contract.

        Under the hybrid fallback (see DSL_CUTOVER_CONTRACT §2),
        Category-B theories (family ∈ NON_DSL_FAMILIES) route to
        _run_worker_legacy instead and never reach this function.
        """
        from .hypothesis_dsl import HypothesisSpec, repair_spec_shape
        from .job_dispatcher import (
            check_admissibility,
            execute,
            job_result_to_worker_contract,
        )

        async with self._semaphore:
            # ExperimentRecord.config is built AFTER repair so the
            # downstream attempt-replay path (bench_attempts.py) sees
            # the canonical repaired dsl_spec, not the raw theorist-
            # authored form. The wrapper key 'dsl_spec' matches the
            # K4Bench attempt-replay layer-source priority order
            # (raw_artifacts.dispatched_dsl_spec.pipeline ->
            #  experiment.config.dsl_spec.pipeline ->
            #  theory.minimal_test_spec.dsl_spec.pipeline).
            exp = ExperimentRecord(
                experiment_id=f"exp-{uuid.uuid4().hex[:8]}",
                hypothesis_id=theory.hypothesis_id,
                worker_role="dsl_dispatcher",
                config={"dsl_spec": dict(theory.dsl_spec)},
            )
            start_time = datetime.now(timezone.utc)
            if on_message:
                on_message(theory.hypothesis_id, "start", theory.title)

            # Parse the DSL spec. Invariant: the critic already validated
            # it, so this should never fail. If it does, surface as ERROR.
            #
            # K4Bench wiring (2026-04-26): rerun repair_spec_shape on the
            # raw dsl_spec so the dispatcher's translator sees the same
            # canonical form the critic validated. Without this the
            # critic's repair was scoped to validation only and the raw
            # (un-repaired) dsl_spec would reach _translate_layer, which
            # would reject e.g. a quagmire ``variant: "III"`` even though
            # the critic just approved its repaired form.
            try:
                repaired_spec_dict, repair_report = repair_spec_shape(
                    theory.dsl_spec,
                    default_hypothesis_id=theory.hypothesis_id,
                )
                if repair_report.applied():
                    logger.info(
                        "Dispatch repaired dsl_spec for theory %s: %s",
                        theory.hypothesis_id[:8],
                        "; ".join(repair_report.entries)[:300],
                    )
                spec = HypothesisSpec.from_dict(repaired_spec_dict)
                spec_errors = spec.validate()
                if spec_errors:
                    raise ValueError(
                        f"spec revalidation failed (critic missed?): "
                        f"{spec_errors}"
                    )
                # Update experiment.config to the repaired dict so
                # downstream attempt-replay sees the canonical form
                # the dispatcher actually fed into translation.
                exp.config = {"dsl_spec": dict(repaired_spec_dict)}
            except Exception as exc:
                contract = WorkerContract(
                    hypothesis_id=theory.hypothesis_id,
                    worker_role="dsl_dispatcher",
                    status=WorkerStatus.ERROR,
                    error=f"spec parse failure (post-critic): {exc}",
                    duration_seconds=(
                        datetime.now(timezone.utc) - start_time
                    ).total_seconds(),
                )
                exp.completed_at = _now_iso()
                exp.result = contract
                self._record_experiment_and_link(exp)
                return contract

            # Admissibility check — when rejected, return immediately;
            # no compute spent. This is the code path the K4 2026-04-21
            # run never reached (postmortem §6.1.6 "Row D = 0").
            #
            # K4Bench: bench_mode skips the real-K4 exhaustion-log
            # overlap heuristic; spec-shape / translation / cardinality
            # checks still fire so a malformed bench spec is still
            # rejected before compute. ``getattr`` is defensive against
            # legacy test paths that build the controller with the older
            # ``KryptosBotConfig`` (no is_bench_mode property); those
            # paths fall through as not-bench-mode, which is the correct
            # default.
            bench_mode_flag = getattr(self.config, "is_bench_mode", False)
            admissible, reasons = check_admissibility(
                spec, bench_mode=bench_mode_flag,
            )
            if not admissible:
                elapsed = (
                    datetime.now(timezone.utc) - start_time
                ).total_seconds()
                contract = WorkerContract(
                    hypothesis_id=theory.hypothesis_id,
                    worker_role="dsl_dispatcher",
                    status=WorkerStatus.REJECTED_ADMISSIBILITY,
                    disproof_evidence=[
                        f"ADMISSIBILITY: {r}" for r in reasons
                    ],
                    duration_seconds=elapsed,
                    narrative_summary=(
                        "Admissibility check rejected the spec without "
                        f"running compute. {len(reasons)} reason(s)."
                    ),
                    raw_artifacts={
                        "dsl_pipeline_kinds": [
                            layer.kind for layer in spec.pipeline
                        ],
                        "dsl_spec_hash": spec.spec_hash,
                    },
                )
                # PR 1: dispatcher-outcome event for the admissibility-
                # rejected branch. The "exhaustion overlap" detail is
                # in `reasons`; the collector classifies that on its own.
                self._coverage_record(
                    "record_dispatcher_outcome",
                    hypothesis_id=theory.hypothesis_id,
                    spec_hash=spec.spec_hash,
                    admissibility_verdict="rejected",
                    admissibility_reasons=list(reasons),
                )
                if on_message:
                    on_message(
                        theory.hypothesis_id, "done",
                        f"rejected_admissibility: {len(reasons)} reason(s)",
                    )
                exp.completed_at = _now_iso()
                exp.result = contract
                self._record_experiment_and_link(exp)
                return contract

            if on_message:
                on_message(
                    theory.hypothesis_id, "dispatch",
                    f"running {spec.expected_cardinality()} configs",
                )

            # Dispatch via job_dispatcher.execute. asyncio.to_thread so
            # the controller's event loop stays responsive while the
            # multiprocessing pool does the work.
            #
            # K4Bench: pass bench_mode through so the per-spec
            # admissibility re-check inside execute() also bypasses the
            # real-K4 exhaustion log. (execute() validates the spec
            # again before running; without bench_mode the second check
            # would re-impose the K4 overlap.) Reuse the same defensive
            # getattr-resolved flag from the admissibility check above
            # so legacy KryptosBotConfig paths still work.
            try:
                job_result = await asyncio.to_thread(
                    execute, spec, bench_mode=bench_mode_flag,
                )
            except Exception as exc:
                elapsed = (
                    datetime.now(timezone.utc) - start_time
                ).total_seconds()
                contract = WorkerContract(
                    hypothesis_id=theory.hypothesis_id,
                    worker_role="dsl_dispatcher",
                    status=WorkerStatus.ERROR,
                    error=f"dispatch raised: {type(exc).__name__}: {exc}",
                    duration_seconds=elapsed,
                )
                # PR 1: dispatcher raised — record as an admissibility
                # error (the spec never produced a JobResult). Treat
                # equivalently to admissibility-rejected for coverage.
                self._coverage_record(
                    "record_dispatcher_outcome",
                    hypothesis_id=theory.hypothesis_id,
                    spec_hash=spec.spec_hash,
                    admissibility_verdict="error",
                    admissibility_reasons=[
                        f"dispatch raised: {type(exc).__name__}: {exc}"
                    ],
                )
                exp.completed_at = _now_iso()
                exp.result = contract
                self._record_experiment_and_link(exp)
                return contract

            elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()

            # Kernel overrule: job_result_to_worker_contract internally
            # calls _verify_against_kernel, so the returned contract's
            # crib_score / bean_passed / score are kernel-sourced.
            contract = job_result_to_worker_contract(
                job_result, hypothesis_id=theory.hypothesis_id,
            )
            contract.duration_seconds = elapsed
            contract.worker_role = "dsl_dispatcher"

            # PR 1: dispatcher-outcome event for the successful path.
            # Signal/breakthrough booleans are derived from the kernel-
            # verified contract crib_score (the canonical signal source),
            # not the worker self-report.
            _crib = float(getattr(contract, "crib_score", 0.0) or 0.0)
            _bean = bool(getattr(contract, "bean_passed", False))
            self._coverage_record(
                "record_dispatcher_outcome",
                hypothesis_id=theory.hypothesis_id,
                spec_hash=spec.spec_hash,
                admissibility_verdict="ok",
                admissibility_reasons=[],
                total_tested=job_result.total_tested,
                best_score=_crib,
                best_p_value_vs_null=job_result.best_p_value_vs_null,
                universe_hash=job_result.universe_hash,
                signal_alert=(_crib >= 18.0),
                breakthrough_alert=(_crib >= 24.0 and _bean),
            )

            # Preserve pipeline layer kinds in raw_artifacts for the
            # alert gate's matched-family null lookup (DSL_CUTOVER_CONTRACT
            # §7). The JobResult already carries spec_hash via
            # artifact_path; this denormalizes the kinds for quick access.
            contract.raw_artifacts.setdefault("dsl_pipeline_kinds", [
                layer.kind for layer in spec.pipeline
            ])
            contract.raw_artifacts.setdefault(
                "dsl_spec_hash", spec.spec_hash,
            )

            # K4Bench attempt-replay (2026-04-27): backfill the dispatched
            # DSL spec onto theory.minimal_test_spec so the third layer
            # of the bench_attempts source chain has data even when the
            # WorkerContract / ExperimentRecord rows have not yet been
            # picked up by emit_attempt_artifact. This rewrites whatever
            # the theorist authored into ``minimal_test_spec`` because
            # at this point the dispatched form is the authoritative
            # description of what the kernel actually ran.
            if job_result.dispatched_dsl_spec:
                if not isinstance(theory.minimal_test_spec, dict):
                    theory.minimal_test_spec = {}
                theory.minimal_test_spec["dsl_spec"] = dict(
                    job_result.dispatched_dsl_spec
                )
                if job_result.best_config_bindings:
                    theory.minimal_test_spec["best_config_bindings"] = [
                        list(p) for p in job_result.best_config_bindings
                    ]
                self.ledger.upsert_theory(theory)

            if on_message:
                on_message(
                    theory.hypothesis_id, "done",
                    f"{contract.status.value} score={contract.score} "
                    f"in {elapsed:.0f}s",
                )

            exp.completed_at = _now_iso()
            exp.result = contract
            self._record_experiment_and_link(exp)
            # Defensive cleanup (no-op on DSL path since scratch was
            # never created, but protects against accidental writes).
            self._cleanup_worker_artifacts(theory, contract)
            return contract

    async def _run_worker_legacy(
        self,
        theory: TheoryRecord,
        on_message: Any = None,
        *,
        tag: Optional[str] = None,
    ) -> WorkerContract:
        """Pre-R3 SDK-subprocess worker path — live in R3 for Category B.

        R3-2 (2026-04-21): kept live under the hybrid fallback policy
        (DSL_CUTOVER_CONTRACT §6.1). Called by _dispatch_theories for
        theories whose family is in NON_DSL_FAMILIES. No DeprecationWarning
        is emitted — this path is part of the supported dispatch surface.

        Args:
            tag: When "non_dsl_category", the returned WorkerContract
                 carries worker_role="agent_sdk_non_dsl_category".
                 Otherwise defaults to "agent_sdk" (pre-R3 behaviour,
                 preserved for tests and one-off scripts).
        """
        # R3-2: resolve worker_role from tag. "non_dsl_category" marks
        # Category-B dispatches for downstream mortality-table analysis.
        worker_role_value = (
            "agent_sdk_non_dsl_category" if tag == "non_dsl_category"
            else "agent_sdk"
        )
        async with self._semaphore:
            exp_id = f"exp-{uuid.uuid4().hex[:8]}"
            exp = ExperimentRecord(
                experiment_id=exp_id,
                hypothesis_id=theory.hypothesis_id,
                worker_role=worker_role_value,
                config=theory.minimal_test_spec,
            )

            # Create the worker's designated scratch directory BEFORE the
            # worker starts. The directory is under results/worker_scratch/
            # which is gitignored. The worker prompt instructs the worker
            # to write all intermediate files here, NOT into scripts/ or
            # tests/. The cleanup pass after the worker finishes removes
            # both the scratch directory AND any files the worker dropped
            # in scripts/ or tests/ in violation of the policy.
            scratch_dir = self._worker_scratch_dir(theory)
            scratch_dir.mkdir(parents=True, exist_ok=True)

            # Build worker prompt (prompt references scratch_dir path)
            prompt = self._build_worker_prompt(theory)

            # Day 4 Pantheon integration: load a persona for the worker
            # based on the theory's family. Replaces the Day 2/3 generic
            # worker system prompt with cryptanalyst / stego-analyst /
            # keystream-forensics / etc. depending on which family the
            # theory belongs to. The persona body is wrapped with
            # worker_system_prompt() which overrides the agent's native
            # narrative Output Contract with a fenced ```json
            # WorkerContract directive — fixes the Day 2 cycle 36
            # worker contract error where a generic worker ran 21 minutes
            # and emitted output without ```json fences.
            #
            # Fallback: if the roster is empty or routing raises, fall
            # through to the pre-Day-4 generic system prompt. The
            # controller continues working regardless.
            worker_persona: AgentSpec | None = None
            if self._pantheon_roster:
                try:
                    worker_persona = select_worker(
                        theory.family or "", self._pantheon_roster,
                    )
                except Exception as exc:
                    logger.warning(
                        "Day 4 worker routing failed for theory %s "
                        "(family=%s): %s — falling back to generic prompt",
                        theory.hypothesis_id, theory.family, exc,
                    )

            if worker_persona is not None:
                # Persona-driven worker: load body via worker_system_prompt,
                # honor setting_sources so skills load, block Task/Agent
                # per sibling-call discipline.
                worker_system = worker_persona.worker_system_prompt()
                worker_model, worker_fallback = resolve_model_for_phase(
                    worker_persona, "worker",
                )
                worker_persona_name = worker_persona.name
                worker_setting_sources = ["project"]
                worker_disallowed_tools = ["Task", "Agent"]
            else:
                # Pre-Day-4 generic fallback — retained for roster-missing
                # environments and as a safety net if routing raises.
                worker_system = (
                    "You are a K4 research worker. Test the given hypothesis "
                    "and report results in strict JSON format. "
                    "Use the available tools to test the hypothesis."
                )
                # Generic no-persona worker fallback. Kept in lockstep with the
                # persona path's resolve_model_for_phase(worker) routing, which
                # was upgraded to Opus on 2026-05-29 (Opus primary, Sonnet
                # fallback). Do not let the roster-missing safety net silently
                # run a weaker model than the normal worker path.
                worker_model = "claude-opus-4-8"
                worker_fallback = "claude-sonnet-4-6"
                worker_persona_name = "generic"
                worker_setting_sources = None
                worker_disallowed_tools = None

            logger.info(
                "worker_agent=%s model=%s fallback=%s theory=%s family=%s "
                "setting_sources=%s task_tools=disabled cycle=%d",
                worker_persona_name, worker_model, worker_fallback,
                theory.hypothesis_id, theory.family or "(none)",
                "project" if worker_setting_sources else "none",
                self.state.cycle_number,
            )
            if on_message:
                on_message(
                    theory.hypothesis_id, "persona",
                    f"{worker_persona_name} ({worker_model})",
                )

            options_kwargs: dict[str, Any] = dict(
                allowed_tools=self.config.allowed_tools,
                permission_mode=self.config.permission_mode,
                system_prompt=worker_system,
                cwd=str(self.config.project_root.resolve()),
                max_turns=self.config.worker_max_turns,
                model=worker_model,
                fallback_model=worker_fallback,
            )
            if worker_setting_sources is not None:
                options_kwargs["setting_sources"] = worker_setting_sources
            if worker_disallowed_tools is not None:
                options_kwargs["disallowed_tools"] = worker_disallowed_tools
            options = ClaudeAgentOptions(**options_kwargs)

            raw_chunks: list[str] = []
            start_time = datetime.now(timezone.utc)
            # event_count: number of stream messages observed from the
            # SDK with a `content` attribute. This is NOT the same as
            # ClaudeAgentOptions.max_turns: max_turns bounds the
            # assistant *turns* the SDK loop will execute, but each
            # turn can yield multiple stream messages (assistant text +
            # tool_use + tool_result blocks delivered as separate
            # Message objects). It is therefore expected and normal
            # for event_count to exceed worker_max_turns; do not
            # interpret event_count as a turn budget. Renamed from
            # `turn_count` post-Day-5 hardening so the operator is not
            # misled into thinking the SDK turn limit is being violated.
            event_count = 0

            if on_message:
                on_message(theory.hypothesis_id, "start", theory.title)

            # Heartbeat: print elapsed time every 30s so the terminal
            # doesn't look frozen during long worker runs.
            async def _heartbeat():
                interval = 30
                while True:
                    await asyncio.sleep(interval)
                    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                    mins, secs = divmod(int(elapsed), 60)
                    if on_message:
                        on_message(
                            theory.hypothesis_id, "heartbeat",
                            f"still running... {mins}m{secs:02d}s elapsed, {event_count} stream events"
                        )

            heartbeat_task = asyncio.create_task(_heartbeat())

            # Wrap the streaming loop in a coroutine so asyncio.wait_for
            # can enforce a hard timeout — the SDK's own timeout doesn't
            # kill runaway Bash subprocesses.
            async def _stream_worker():
                nonlocal event_count
                async for message in safe_query(prompt=prompt, options=options):
                    if hasattr(message, "result"):
                        raw_chunks.append(str(message.result))
                        if on_message:
                            preview = str(message.result)[:200]
                            on_message(theory.hypothesis_id, "result", preview)
                    elif hasattr(message, "content"):
                        # Same hygiene as the theorist path: list-of-
                        # ContentBlock must be text-extracted rather
                        # than Python-repr-stringified. See
                        # _extract_message_text and
                        # K4_RUN_CYCLE1_DIAGNOSTIC.md.
                        text = _extract_message_text(message.content)
                        raw_chunks.append(text)
                        event_count += 1
                        # Extract tool use info if present
                        if on_message:
                            if hasattr(message, "content") and isinstance(message.content, list):
                                for block in message.content:
                                    if hasattr(block, "type") and block.type == "tool_use":
                                        tool_name = getattr(block, "name", "?")
                                        on_message(theory.hypothesis_id, "tool_use", tool_name)
                            else:
                                # Text turn — show a snippet
                                snippet = text.replace("\n", " ")[:120]
                                on_message(theory.hypothesis_id, "turn", snippet)

            timeout_secs = self.config.worker_timeout_minutes * 60

            try:
                await asyncio.wait_for(_stream_worker(), timeout=timeout_secs)
            except asyncio.TimeoutError:
                heartbeat_task.cancel()
                if on_message:
                    on_message(
                        theory.hypothesis_id, "error",
                        f"TIMEOUT after {self.config.worker_timeout_minutes}m — killed",
                    )
                timeout_contract = WorkerContract(
                    hypothesis_id=theory.hypothesis_id,
                    worker_role=worker_role_value,
                    status=WorkerStatus.TIMEOUT,
                    error=f"Timed out after {self.config.worker_timeout_minutes} minutes",
                )
                # Record the experiment row with completed_at filled in
                # so downstream "active workers" telemetry doesn't see
                # this as still-in-flight, and theory_ledger.upsert_theory
                # doesn't audit-annotate as "no experiment trail".
                # See feedback_silent_failure_hunter doctrine.
                exp.completed_at = _now_iso()
                exp.result = timeout_contract
                self._record_experiment_and_link(exp)
                # Even on timeout, clean up any artifacts the worker dropped
                # before the timer fired.
                self._cleanup_worker_artifacts(theory, timeout_contract)
                return timeout_contract
            except Exception as exc:
                heartbeat_task.cancel()
                exc_contract = WorkerContract(
                    hypothesis_id=theory.hypothesis_id,
                    worker_role=worker_role_value,
                    status=WorkerStatus.ERROR,
                    error=str(exc),
                )
                # Same as the timeout branch: record the experiment so
                # the SDK transport silent-fail path does not leak rows
                # with empty completed_at and does not require the
                # ledger's audit annotation as a fallback.
                exp.completed_at = _now_iso()
                exp.result = exc_contract
                self._record_experiment_and_link(exp)
                # Even on exception, clean up any artifacts the worker
                # dropped before the exception.
                self._cleanup_worker_artifacts(theory, exc_contract)
                return exc_contract

            heartbeat_task.cancel()
            elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
            raw_output = "\n".join(raw_chunks)

            # Parse structured output — fail closed on invalid payloads
            parse_result = validate_worker_contract(raw_output, theory.hypothesis_id)

            if parse_result.is_valid:
                contract = parse_result.value
                contract.duration_seconds = elapsed
                contract.worker_role = worker_role_value
            else:
                # Explicit parse failure — do NOT infer status from prose
                artifacts = self._classify_worker_parse_failure(
                    raw_output, parse_result.errors,
                )
                logger.warning(
                    "Worker output for %s failed contract validation: %s "
                    "(reason=%s suspicious=%s)",
                    theory.hypothesis_id,
                    "; ".join(parse_result.errors),
                    artifacts["parse_failure_reason"],
                    bool(
                        artifacts["repr_mangling_suspected"]
                        or artifacts["suspicious_json_like"]
                    ),
                )
                contract = WorkerContract(
                    hypothesis_id=theory.hypothesis_id,
                    worker_role=worker_role_value,
                    status=WorkerStatus.ERROR,
                    error=(
                        "Contract validation failed: "
                        + "; ".join(parse_result.errors)
                    ),
                    duration_seconds=elapsed,
                    # Raw output preserved for audit only, never parsed
                    raw_artifacts=artifacts,
                )

            if on_message:
                on_message(
                    theory.hypothesis_id, "done",
                    f"{contract.status.value} score={contract.score} in {elapsed:.0f}s",
                )

            # Record experiment
            exp.completed_at = _now_iso()
            exp.result = contract
            self._record_experiment_and_link(exp)

            # Clean up worker artifacts. Two passes:
            # 1. Remove the worker's designated scratch directory entirely
            #    (success path — worker followed the rules).
            # 2. Defensive: scan scripts/ and tests/ for any files matching
            #    the worker's hypothesis_id and delete them. Catches workers
            #    that ignored the scratch instruction.
            self._cleanup_worker_artifacts(theory, contract)

            return contract

    def _record_experiment_and_link(self, exp: ExperimentRecord) -> None:
        """Persist an experiment and mirror its ID onto the parent theory."""
        self.ledger.record_experiment(exp)
        theory = self.ledger.get_theory(exp.hypothesis_id)
        if theory is None:
            return
        if exp.experiment_id not in theory.experiment_ids:
            theory.experiment_ids.append(exp.experiment_id)
            self.ledger.upsert_theory(theory)

    def _cleanup_worker_artifacts(
        self, theory: TheoryRecord, contract: WorkerContract,
    ) -> None:
        """Clean up scratch files left by a worker.

        Two passes:
        1. Remove the entire scratch directory at results/worker_scratch/<id>/
           (intended path — worker followed the rules).
        2. Defensively scan scripts/ and tests/ for files matching the
           worker's hypothesis_id (truncated 12-char hex) and delete them.
           Logs any defensive deletions as a policy violation against
           the worker.

        Best-effort: any failure here is logged but does not affect the
        contract that's already been recorded in the ledger.
        """
        # Pass 1: scratch directory
        try:
            scratch_dir = self._worker_scratch_dir(theory)
            if scratch_dir.exists():
                import shutil
                shutil.rmtree(scratch_dir)
        except Exception as exc:
            logger.warning(
                "Failed to remove scratch dir for %s: %s",
                theory.hypothesis_id, exc,
            )

        # Pass 2: defensive scan for files referencing the hypothesis_id
        # The hypothesis_id is a 12-char hex hash. Workers typically embed
        # it in filenames or docstrings. We look for either pattern.
        try:
            self._defensive_artifact_scan(theory)
        except Exception as exc:
            logger.warning(
                "Defensive artifact scan failed for %s: %s",
                theory.hypothesis_id, exc,
            )

    def _defensive_artifact_scan(self, theory: TheoryRecord) -> None:
        """Scan scripts/ and tests/ for files referencing the worker's
        hypothesis_id and delete them.

        Catches workers that wrote artifacts outside the designated scratch
        directory in violation of the prompt's instructions. Each defensive
        deletion is logged as a policy violation.
        """
        hid = theory.hypothesis_id
        if not hid or len(hid) < 8:
            return

        # The hypothesis_id is a 12-char hex string. Workers typically use
        # the full string OR a 12-char prefix in filenames.
        hid_short = hid[:12]

        scan_roots = [
            self.config.project_root / "scripts",
            self.config.project_root / "tests",
            self.config.project_root / "src",
        ]

        deleted = []
        for root in scan_roots:
            if not root.exists():
                continue
            # Match files where the hypothesis_id appears in the filename
            for path in root.rglob("*.py"):
                # Skip anything in src/ — workers should never write source
                if str(path).startswith(str(self.config.project_root / "src")):
                    # Only flag if the file was created very recently AND
                    # contains the hypothesis_id; src/ files are usually
                    # legitimate. We only delete from src/ if the filename
                    # itself contains the hash (extreme worker violation).
                    if hid_short not in path.name:
                        continue
                # Match by filename containing the hypothesis_id
                if hid_short in path.name:
                    try:
                        path.unlink()
                        deleted.append(str(path.relative_to(self.config.project_root)))
                    except Exception as exc:
                        logger.warning("Failed to delete %s: %s", path, exc)
                    continue
                # Match by file content (file mentions the hypothesis_id
                # AND was modified recently — within the last 30 min)
                try:
                    mtime = path.stat().st_mtime
                    import time
                    if time.time() - mtime < 1800:  # 30 min
                        # Read first 1KB to check for the hash
                        with path.open("rb") as f:
                            head = f.read(1024).decode("utf-8", errors="ignore")
                        if hid_short in head:
                            path.unlink()
                            deleted.append(str(path.relative_to(self.config.project_root)))
                except Exception:
                    continue

        # Clean up empty parent directories that were created by workers.
        #
        # Post-Day-5 hardening: previously the canonical-subdir check
        # was inverted — the comment said "Preserve known canonical
        # subdirs" but the code removed empty dirs ONLY when they
        # matched the canonical set, deleting exactly the dirs that
        # were supposed to be preserved. This loop now correctly
        # preserves canonical subdirs and removes empty non-canonical
        # ones created by worker policy violations.
        canonical = {
            "scripts/hypothesis_tests",
            "scripts/tests",
            "scripts/hypothesis",
        }
        for root in scan_roots:
            if not root.exists():
                continue
            for d in sorted(root.rglob("*"), reverse=True):
                if not d.is_dir():
                    continue
                try:
                    if any(d.iterdir()):
                        continue  # not empty; leave alone
                    relpath = d.relative_to(self.config.project_root)
                    if str(relpath) in canonical:
                        # Preserve canonical subdirs even when empty.
                        continue
                    d.rmdir()
                except Exception:
                    continue

        if deleted:
            logger.warning(
                "POLICY VIOLATION: worker %s wrote %d file(s) outside its "
                "scratch directory; deleted: %s",
                theory.hypothesis_id, len(deleted), deleted,
            )

    def _worker_scratch_dir(self, theory: TheoryRecord) -> Path:
        """Designated scratch directory for one worker's intermediate artifacts.

        Workers are instructed to write any test scripts, intermediate
        results, or other scratch files into this directory instead of
        polluting scripts/ or tests/. The directory is under results/ which
        is gitignored, so artifacts never reach git. The controller cleans
        up the directory after the worker completes (success or failure).
        """
        return (
            self.config.project_root
            / "results"
            / "worker_scratch"
            / theory.hypothesis_id
        )

    def _build_risk_warning_block(
        self,
        risk_value: str,
        rationale: str,
        scratch_dir_rel: Path,
    ) -> str:
        """Select the worker prompt warning block for a search_space_risk value.

        Priority 5. Each category has distinct enforcement semantics per
        project_priority5_search_space_risk_design.md. "none",
        "residual_caution", "duplicate_family", and "other" dispatch
        clean with no injection — the first two because there is no
        structural concern, the second two because the red-team already
        recorded the concern in the ledger via theory.critic_verdict.reasons
        and additional prompt injection would be compute noise.
        """
        if risk_value == "unbounded_search":
            cap = self.config.bounded_search_max_configurations
            return (
                "\n"
                "BOUNDED-SEARCH POLICY (red-team search_space_risk="
                "unbounded_search):\n"
                "The red-team-disprover marked this theory as having an "
                "unconstrained or\nquasi-continuous parameter space. "
                f"Verbatim concern: {rationale}\n"
                "\n"
                "Before evaluating ANY parameter combination, you MUST:\n"
                "  1. Write a finite test envelope to "
                f"{scratch_dir_rel}/test_envelope.json with these fields:\n"
                "     - parameters: list of every free parameter you will sweep\n"
                "     - bounds: explicit min/max/step for each parameter\n"
                "     - total_configurations: integer product of the bounds\n"
                "     - rationale: one sentence per parameter justifying the bound\n"
                f"  2. If total_configurations exceeds {cap}, EITHER tighten the\n"
                "     bounds OR return status='inconclusive' with\n"
                "     next_action='needs_bounded_design' and a disproof_evidence\n"
                "     entry explaining why the search space cannot be bounded.\n"
                "  3. Only after the envelope is written do you proceed to test.\n"
                "\n"
                "If you cannot construct a finite envelope at all, do NOT\n"
                "spend wall-clock on exploratory search. Return:\n"
                "  status: 'inconclusive'\n"
                "  next_action: 'needs_bounded_design'\n"
                "  disproof_evidence: ['unable to bound free parameters: <names>']\n"
                "An honest unbounded-search inconclusive is strictly more\n"
                "valuable than 600 seconds of unguided sweeping that returns 0.\n"
            )

        if risk_value == "exhausted_source_material":
            return (
                "\n"
                "EXHAUSTION-OVERLAP WARNING (red-team search_space_risk="
                "exhausted_source_material):\n"
                "The red-team-disprover flagged this theory as mining a\n"
                "source that has already been exhausted by prior work with\n"
                f"zero signal. Verbatim concern: {rationale}\n"
                "\n"
                "Before committing compute, you MUST explicitly distinguish\n"
                "this test from the prior exhausted work. Either:\n"
                "  (a) In your narrative_summary, cite the specific novelty\n"
                "      that makes this test NOT a rerun — a new mechanism, a\n"
                "      different parameter regime, a constraint the prior\n"
                "      sweep could not express — AND proceed to test; or\n"
                "  (b) Return:\n"
                "        status: 'inconclusive'\n"
                "        next_action: 'duplicate_of_exhausted'\n"
                "        disproof_evidence: ['overlaps exhausted prior work: "
                "<citation>']\n"
                "\n"
                "'It's worth another look' is NOT sufficient novelty. The\n"
                "point of this block is to force an honest choice between\n"
                "genuine extension and redundant compute.\n"
            )

        if risk_value == "underconstrained":
            return (
                "\n"
                "TIGHTEN-KILL-CRITERION WARNING (red-team search_space_risk="
                "underconstrained):\n"
                "The red-team-disprover flagged this theory's kill criterion\n"
                "as too loose to actually disprove the mechanism. Verbatim\n"
                f"concern: {rationale}\n"
                "\n"
                "Before running the test, you MUST pre-register a concrete,\n"
                "numeric threshold in your test_envelope that would\n"
                "unambiguously falsify the hypothesis. Examples:\n"
                "  - 'crib_score >= 18 with bean_passed on at least one\n"
                "     configuration' — not 'found a pattern'\n"
                "  - 'ngram_score > -3.5 on the full plaintext' — not\n"
                "    'looks English-like'\n"
                "  - An explicit Bonferroni / FDR correction for the\n"
                "    number of configurations tested\n"
                "\n"
                "In your final result, report whether the theory crossed\n"
                "your pre-registered threshold — NOT whether you 'felt' a\n"
                "signal. Post-hoc threshold adjustment is the primary\n"
                "failure mode this block exists to prevent.\n"
            )

        # none / residual_caution / duplicate_family / other / unknown:
        # dispatch clean. The red-team verdict is already persisted in
        # theory.critic_verdict.reasons via the ledger upsert, so the
        # concern is visible in the audit trail without polluting the
        # worker prompt.
        return ""

    def _build_worker_prompt(self, theory: TheoryRecord) -> str:
        """Build a worker prompt for testing a specific theory.

        Priority 5: the red-team verdict may carry a structured
        search_space_risk value. The controller switches on that value
        and injects a category-specific warning block. Only
        "unbounded_search" triggers the BOUNDED-SEARCH POLICY block;
        other non-none risks get their own tailored blocks or no
        injection at all.

        K4Bench input mode (2026-04-26): when ``config.is_bench_mode``,
        the prompt prefixes the synthetic-challenge block so the
        worker tests against the K4Bench CT/cribs, not real K4.
        """
        scratch_dir = self._worker_scratch_dir(theory)
        scratch_dir_rel = scratch_dir.relative_to(self.config.project_root)
        verdict = self._cycle_redteam_verdicts.get(theory.hypothesis_id)
        risk_value = (verdict.search_space_risk if verdict else "none") or "none"
        rationale = ""
        if verdict and verdict.reasons:
            rationale = verdict.reasons[0]

        warning_block = self._build_risk_warning_block(
            risk_value, rationale, scratch_dir_rel,
        )

        bench_prefix = ""
        if self.config.is_bench_mode and self.config.bench_challenge_prompt_block:
            bench_prefix = (
                self.config.bench_challenge_prompt_block
                + "\n\nK4BENCH WORKER POLICY:\n"
                "  - The CIPHERTEXT and CRIB SPANS above are the SOLE\n"
                "    source of truth for this run. Do NOT operate on\n"
                "    real-K4 ciphertext.\n"
                "  - The kernel's score_candidate already targets the\n"
                "    K4Bench cribs because KRYPTOS_CT_OVERRIDE and\n"
                "    KRYPTOS_CRIB_DICT_OVERRIDE were installed before\n"
                "    process start. Your scoring path is the same one\n"
                "    you would use for real K4 — no special calls.\n"
                "  - A strict pass requires exact 97-char plaintext PLUS\n"
                "    a reproducible method/layer order (keys, routes,\n"
                "    alphabets). Plaintext-only is partial.\n"
                "  - Avoid crib-overfitting: a plaintext that matches\n"
                "    only the 24 declared positions but reads as noise\n"
                "    outside them is an overfit, not a solve.\n\n"
            )

        return f"""{bench_prefix}Test the following hypothesis and report structured results.
{warning_block}

HYPOTHESIS:
  ID: {theory.hypothesis_id}
  Title: {theory.title}
  Claim: {theory.core_claim}
  Mechanism: {theory.mechanism}
  Family: {theory.family}
  Kill Criteria: {json.dumps(theory.kill_criteria)}
  Expected Signal: {theory.expected_signal}
  Test Spec: {json.dumps(theory.minimal_test_spec, indent=2)}

INSTRUCTIONS:
1. Use the available tools (search_theory_ledger, get_canonical_facts, get_family_status, etc.) to gather context.
2. Prefer the DSL-driven path for cryptanalytic computation: submit the test as a
   kryptosbot.hypothesis_dsl.HypothesisSpec via submit_hypothesis_spec, then poll_job.
3. Evaluate against kill criteria.
4. Report results in the structured JSON format below.

DSL-FIRST EXECUTION (PREFERRED PATH, Phase 5):
The dispatcher has access to kernel infrastructure you do not: the 28-core
multiprocessing pool, the canonical score_candidate scoring path (which
already incorporates the kernel-overrule guarantee on crib_score and
bean_passed), deterministic universe_hash deduplication, and admissibility
checks against the compute budget and exhaustion log.

When your theory has a clean translation into the DSL:
  1. Call enumerate_admissible_transforms to see which cipher kinds are supported.
  2. Call request_compute_budget_estimate to right-size the spec.
  3. Call query_exhaustion to verify you're not re-running eliminated territory.
  4. Call submit_hypothesis_spec with the full HypothesisSpec JSON.
  5. Call poll_job (possibly more than once) until state == "completed".
  6. Read the JobResult, interpret, and report structured results below.

For candidate-level scoring (e.g. to verify a single plaintext outside a
full sweep), use score_candidate_canonical. Never implement your own
crib-scoring or Bean-checking — they will be overruled by the kernel
either way, so doing your own is wasted effort.

If the theory genuinely cannot be translated to the DSL (e.g. a novel
procedural recipe not in the DSL vocabulary yet, or a mechanism that
fundamentally requires agent reasoning inside the loop), fall back to
scratch scripts per the policy below. In your narrative_summary, briefly
explain why the DSL path wasn't viable.

SCRATCH FILES — IMPORTANT:
Phase 5 narrowed policy: scratch is for INTERPRETATION ONLY (plots,
summaries, diff inspections), NOT for running ciphers. The DSL-first
path above handles cipher execution via kernel-verified dispatch.

If you need scratch for interpretation, write ONLY to:

    {scratch_dir_rel}/

This directory is your designated scratch area. It already exists and is
gitignored. The controller will clean it up after you finish.

DO NOT write scratch files to:
- scripts/ (curated experiment tree, polluting it breaks the rigor standard)
- tests/ (project test suite, polluting it can break pytest collection)
- src/ (source code, do not modify)
- Anywhere outside {scratch_dir_rel}/

If you need to RUN a script you wrote, save it to {scratch_dir_rel}/<name>.py
and execute it with: PYTHONPATH=src python3 {scratch_dir_rel}/<name>.py

Files left in scripts/ or tests/ will be cleaned up by the controller, and
the worker will be flagged as having violated the scratch policy in audit.

REQUIRED OUTPUT FORMAT (emit this JSON at the end of your response):
```json
{{
  "hypothesis_id": "{theory.hypothesis_id}",
  "status": "success|disproved|inconclusive|error",
  "score": 0.0,
  "crib_score": 0,
  "bean_passed": false,
  "best_plaintext": "",
  "disproof_evidence": [],
  "supporting_evidence": [],
  "next_action": "",
  "family_generalization": "",
  "narrative_summary": "Brief human-readable summary"
}}
```

You MUST output this JSON block. The controller parses it for control flow.

IMPORTANT — score fields are recomputed by the controller, not trusted from
your output. The controller will:
  1. Take your `best_plaintext` (must be 97 characters in CT97 space, A-Z only)
  2. Recompute `crib_score` via `kryptos.kernel.scoring.crib_score.score_cribs`
  3. Recompute `bean_passed` by deriving the keystream under all three classical
     variants (Vigenere, Beaufort, Variant Beaufort) and running
     `kryptos.kernel.constraints.bean.verify_bean_simple` on each
  4. Set `score` to float(crib_score) (mirror, not an aggregate score)

Your self-reported `crib_score`, `bean_passed`, and `score` will be DISCARDED
and replaced with the kernel's values. There is no benefit to inflating these
fields -- the controller will catch the disagreement and flag your contract as
having fabricated values.

If you cannot produce a 97-character CT97-space `best_plaintext`, leave that
field empty. The controller will record the verification gap and your status
(disproved/inconclusive/error) will still drive the ledger correctly. An honest
"inconclusive with empty plaintext" is strictly more useful than a fabricated
"breakthrough"."""

    # ------------------------------------------------------------------
    # Step 5: Absorb outcomes
    # ------------------------------------------------------------------

    def _absorb_outcomes(self, outcomes: list[WorkerContract]) -> None:
        """Update the ledger based on worker outcomes."""
        for contract in outcomes:
            if not contract.hypothesis_id:
                logger.warning(
                    "Skipping outcome with no hypothesis_id (status=%s, error=%s) "
                    "— this indicates a bug in _dispatch_theories",
                    contract.status.value, contract.error[:200] if contract.error else "",
                )
                continue

            theory = self.ledger.get_theory(contract.hypothesis_id)
            if not theory:
                continue

            # Map worker status to theory status.
            #
            # Post-Day-5 hardening: WorkerStatus.SUCCESS means "the
            # worker process completed without crashing or timing
            # out". It does NOT mean "this hypothesis produced a K4
            # signal worth pursuing". Promotion to TheoryStatus.PROMISING
            # is reserved for results whose KERNEL-VERIFIED crib_score
            # crosses SIGNAL_THRESHOLD (18). Successful runs whose
            # verified score is below that threshold are merely
            # COMPLETED — they ran cleanly but produced no signal.
            #
            # The threshold is read from the controller-loaded
            # canonical facts (set by _load_canonical_facts). We use a
            # local fallback so a missing facts dict cannot silently
            # invert the gate to "always promising".
            try:
                from kryptosbot.constants import SIGNAL_THRESHOLD as _SIGNAL_THRESHOLD
            except ImportError:
                _SIGNAL_THRESHOLD = 18

            if contract.status == WorkerStatus.SUCCESS:
                # crib_score on the contract has already been
                # recomputed by contracts._verify_against_kernel at
                # boundary parse time, so this comparison is against
                # kernel-verified data, not worker self-report.
                if contract.crib_score >= _SIGNAL_THRESHOLD:
                    new_status = TheoryStatus.PROMISING
                else:
                    new_status = TheoryStatus.COMPLETED
                    logger.info(
                        "  · %s ran SUCCESS but verified crib_score=%d < "
                        "SIGNAL=%d — recording as COMPLETED, not PROMISING",
                        contract.hypothesis_id[:8], contract.crib_score,
                        _SIGNAL_THRESHOLD,
                    )
            else:
                status_map = {
                    WorkerStatus.DISPROVED: TheoryStatus.ELIMINATED,
                    WorkerStatus.INCONCLUSIVE: TheoryStatus.COMPLETED,
                    # ERROR / TIMEOUT mean the worker did not produce a
                    # trustworthy result. Mapping these to COMPLETED
                    # historically polluted the score-ranking surface
                    # (see live-run audit 2026-04-30). They now route
                    # to TheoryStatus.ERROR so downstream queries can
                    # exclude un-tested theories from completion stats.
                    WorkerStatus.ERROR: TheoryStatus.ERROR,
                    WorkerStatus.TIMEOUT: TheoryStatus.ERROR,
                }
                new_status = status_map.get(contract.status, TheoryStatus.COMPLETED)

            theory.status = new_status
            theory.best_score = max(theory.best_score, contract.score)
            if contract.best_plaintext:
                theory.best_plaintext = contract.best_plaintext[:500]
            theory.outcome_summary = contract.narrative_summary[:2000]
            if contract.disproof_evidence:
                theory.failure_reason = "; ".join(contract.disproof_evidence[:3])

            self.ledger.upsert_theory(theory)

            # Add evidence links
            if contract.disproof_evidence:
                for evidence_text in contract.disproof_evidence:
                    link = EvidenceLink(
                        evidence_id=f"ev-{uuid.uuid4().hex[:8]}",
                        hypothesis_id=theory.hypothesis_id,
                        evidence_type=EvidenceType.DISPROOF,
                        content=evidence_text[:5000],
                    )
                    self.ledger.add_evidence(link)

            if contract.supporting_evidence:
                for evidence_text in contract.supporting_evidence:
                    link = EvidenceLink(
                        evidence_id=f"ev-{uuid.uuid4().hex[:8]}",
                        hypothesis_id=theory.hypothesis_id,
                        evidence_type=EvidenceType.EXPERIMENT_RESULT,
                        content=evidence_text[:5000],
                    )
                    self.ledger.add_evidence(link)

            # Update anomaly records to reflect this theory explored them
            if theory.anomalies_exploited:
                for anom_id in theory.anomalies_exploited:
                    anom = self.ledger.get_anomaly(anom_id)
                    if anom:
                        if theory.hypothesis_id not in anom.theories_exploring:
                            anom.theories_exploring.append(theory.hypothesis_id)
                        # If theory was eliminated and provided disproof, mark anomaly explained
                        if new_status == TheoryStatus.ELIMINATED and contract.disproof_evidence:
                            if theory.hypothesis_id not in anom.evidence_against:
                                anom.evidence_against.append(theory.hypothesis_id)
                        self.ledger.upsert_anomaly(anom)

            # Log family generalization if provided
            if contract.family_generalization:
                logger.info(
                    "Family generalization for %s: %s",
                    theory.family, contract.family_generalization,
                )

            self.state.recent_outcomes.append({
                "hypothesis_id": theory.hypothesis_id,
                "title": theory.title,
                "family": theory.family,
                "status": new_status.value,
                "score": contract.score,
            })

        # Keep only the last 50 recent outcomes
        self.state.recent_outcomes = self.state.recent_outcomes[-50:]

    # ------------------------------------------------------------------
    # Alerting (contradiction detector)
    # ------------------------------------------------------------------

    def _apply_stat_audit_rejection_downgrades(
        self,
        outcomes: list[WorkerContract],
    ) -> None:
        """Downgrade PROMISING theories rejected by stat-audit.

        This is ledger hygiene, not alert behavior, so it must run even when
        alerting is disabled.
        """
        for c in outcomes:
            sv = self._cycle_stat_audit_verdicts.get(c.hypothesis_id)
            if sv is None or sv.verdict != "rejected":
                continue

            concern = (
                sv.methodology_concerns[0]
                if sv.methodology_concerns else "no concern given"
            )
            theory = self.ledger.get_theory(c.hypothesis_id)
            if theory is not None and theory.status == TheoryStatus.PROMISING:
                theory.status = TheoryStatus.COMPLETED
                downgrade_note = f"stat-audit rejected: {concern[:200]}"
                if theory.failure_reason:
                    theory.failure_reason = (
                        theory.failure_reason + "; " + downgrade_note
                    )
                else:
                    theory.failure_reason = downgrade_note
                theory.updated_at = _now_iso()
                self.ledger.upsert_theory(theory)
                logger.warning(
                    "  ↓ LEDGER DOWNGRADE %s PROMISING → COMPLETED "
                    "(stat-audit rejected)",
                    c.hypothesis_id[:8],
                )
                for outcome in self.state.recent_outcomes:
                    if outcome.get("hypothesis_id") == c.hypothesis_id:
                        outcome["status"] = TheoryStatus.COMPLETED.value
                        break

    def _run_alerts(
        self,
        theories: list[TheoryRecord],
        outcomes: list[WorkerContract],
    ) -> None:
        """Run the contradiction-detector alert pass on this cycle's outcomes.

        Best-effort: any failure here is logged but does not block the
        controller loop. See alerts.py for the design philosophy — this
        is NOT a victory bell, it's a contradiction detector for the
        elimination ledger.
        """
        try:
            from .alerts import AlertLevel, process_alerts
            try:
                threshold = AlertLevel(self.config.alert_threshold)
            except ValueError:
                logger.warning(
                    "Invalid alert_threshold %r; defaulting to 'signal'",
                    self.config.alert_threshold,
                )
                threshold = AlertLevel.SIGNAL

            # Stat-audit rejection is a ledger gate independent of alerts.
            # Apply it before the alert-threshold early return so
            # alert_threshold=none cannot leave a rejected PROMISING theory.
            self._apply_stat_audit_rejection_downgrades(outcomes)

            if threshold == AlertLevel.NONE:
                return

            # Build a hypothesis_id -> theory metadata lookup so the
            # alert event can carry title/family/mechanism.
            theory_lookup = {
                t.hypothesis_id: {
                    "title": t.title,
                    "family": t.family,
                    "mechanism": t.mechanism,
                }
                for t in theories
            }

            # Day 5: honor the stat-audit gate. Any contract whose
            # stat-audit verdict is "rejected" is suppressed from alerting.
            # The verdict is recorded on the contract for audit, and the
            # suppression itself is logged so the gate is observable.
            #
            # Day 6 D6-FU-7: a stat-audit REJECTED verdict must ALSO
            # downgrade the theory's ledger status when _absorb_outcomes
            # promoted it to PROMISING. Alert suppression alone leaves
            # a fabricated PROMISING entry in the ledger forever. The
            # 2026-04-14 cycle-64 verification run exposed this gap —
            # that case was harmless because the worker self-reported
            # DISPROVED, but any future SUCCESS-reporting worker that
            # crib-pastes would slip through without this downgrade.
            gated_outcomes: list[WorkerContract] = []
            for c in outcomes:
                sv = self._cycle_stat_audit_verdicts.get(c.hypothesis_id)
                if sv is not None and sv.verdict == "rejected":
                    concern = (
                        sv.methodology_concerns[0]
                        if sv.methodology_concerns else "no concern given"
                    )
                    logger.info(
                        "  ⊘ Alert SUPPRESSED for %s by stat-audit reject — %s",
                        c.hypothesis_id[:8], concern,
                    )
                    continue
                gated_outcomes.append(c)

            results_dir = self.config.project_root / "results" / "breakthroughs"
            triggered = process_alerts(
                outcomes=gated_outcomes,
                threshold=threshold,
                cycle_number=self.state.cycle_number,
                results_dir=results_dir,
                theory_lookup=theory_lookup,
            )
            # Day 5: capture compact summaries for the end-of-cycle synthesis
            for ev in triggered:
                self._cycle_alert_summaries.append(
                    f"{ev.level} alert: {ev.hypothesis_id[:8]} "
                    f"crib={ev.crib_score} bean={ev.bean_passed} — "
                    f"{(ev.theory_title or '')[:60]}"
                )
            # Campaign-A hardening (2026-04-22): retain the full AlertEvent
            # list so _check_cycle_hardening_halts can read p_value_status
            # on BREAKTHROUGH events.
            self._cycle_alert_events = list(triggered)
            if triggered:
                logger.warning(
                    "%d alert event(s) fired in cycle %d — see %s",
                    len(triggered), self.state.cycle_number, results_dir,
                )
        except Exception:
            logger.exception("Alert processing failed (continuing run)")

    # ------------------------------------------------------------------
    # Day 5: Statistical-auditor post-execution signal audit
    # ------------------------------------------------------------------

    async def _stat_audit_filter(
        self,
        theories: list[TheoryRecord],
        outcomes: list[WorkerContract],
        on_progress: Any = None,
    ) -> None:
        """
        Run statistical-auditor as a sibling call against any contract
        whose kernel-verified crib_score >= self.config.stat_audit_threshold.

        This is the post-execution mirror of _red_team_filter. Where
        red-team gates BEFORE compute is spent, stat-audit gates the
        propagation of results AFTER compute has been spent. Verdicts
        are written to self._cycle_stat_audit_verdicts where _run_alerts
        consumes them to suppress alerts for rejected signals.

        Behavior:
          - skip_stat_audit config flag → no-op
          - statistical-auditor not in roster → no-op (with a warning)
          - no contract meets the threshold → no-op
          - SDK error or parse failure for a specific contract → that
            contract gets a verdict="error" recorded (treated as
            "concerned" by the alert gate, NOT "confirmed", so flaky
            audits don't silently confirm noise)

        Args:
            theories: theories that were dispatched this cycle (for
                title/family/mechanism context to the auditor)
            outcomes: worker contracts to consider for audit
            on_progress: optional TUI callback (start, verdict, summary,
                skipped) — same shape as _red_team_filter
        """
        if self.config.skip_stat_audit:
            logger.info("Stat-audit skipped (config.skip_stat_audit=True)")
            if on_progress:
                on_progress("skipped", "config.skip_stat_audit=True")
            return

        audit_spec = select_stat_auditor(self._pantheon_roster)
        if audit_spec is None:
            logger.warning(
                "Stat-audit skipped: statistical-auditor not in Pantheon roster. "
                "Signal-level alerts will fire without post-execution review."
            )
            if on_progress:
                on_progress("skipped", "statistical-auditor not in roster")
            return

        threshold = int(self.config.stat_audit_threshold)
        candidates = [
            c for c in outcomes
            if int(c.crib_score or 0) >= threshold
        ]
        if not candidates:
            logger.info(
                "Stat-audit: no contracts at or above threshold %d this cycle",
                threshold,
            )
            if on_progress:
                on_progress("skipped", f"no contracts >= {threshold}")
            return

        sa_model, _ = resolve_model_for_phase(audit_spec, "stat_audit")
        logger.info(
            "stat_audit_agent=%s model=%s setting_sources=project "
            "task_tools=disabled cycle=%d count=%d threshold=%d",
            audit_spec.name, sa_model, self.state.cycle_number,
            len(candidates), threshold,
        )
        if on_progress:
            on_progress("start", (audit_spec.name, sa_model, len(candidates)))

        theory_by_id = {t.hypothesis_id: t for t in theories}
        confirmed_n = concerned_n = rejected_n = 0
        for contract in candidates:
            theory = theory_by_id.get(contract.hypothesis_id)
            if theory is None:
                # Theory metadata was lost (shouldn't happen — defensive).
                # Skip this audit so we don't pass a None to the prompt builder.
                logger.warning(
                    "Stat-audit: no theory record for %s — skipping",
                    contract.hypothesis_id[:8],
                )
                continue

            verdict = await run_stat_audit(
                theory,
                contract,
                audit_spec=audit_spec,
                project_root=self.config.project_root.resolve(),
                allowed_tools=self.config.allowed_tools,
                permission_mode=self.config.permission_mode,
            )

            self._cycle_stat_audit_verdicts[contract.hypothesis_id] = verdict
            logger.info(verdict.to_log_line(contract.hypothesis_id))
            if on_progress:
                on_progress("verdict", (theory, contract, verdict))

            if verdict.verdict == "confirmed":
                confirmed_n += 1
            elif verdict.verdict == "rejected":
                rejected_n += 1
                logger.warning(
                    "  ✗ Stat-audit REJECTED %s — %s",
                    contract.hypothesis_id[:8],
                    verdict.methodology_concerns[0]
                    if verdict.methodology_concerns else "no concern given",
                )
            else:  # concerned, error
                concerned_n += 1

        logger.info(
            "Stat-audit filter: %d confirmed, %d concerned, %d rejected of %d signal contracts",
            confirmed_n, concerned_n, rejected_n, len(candidates),
        )
        if on_progress:
            on_progress(
                "summary",
                (confirmed_n, concerned_n, rejected_n, len(candidates)),
            )

    # ------------------------------------------------------------------
    # Day 6: Lead-pursuit phase for sub-signal (6-17) contracts
    # ------------------------------------------------------------------

    def _open_pursuit_lead_from_verdict(
        self,
        *,
        contract: WorkerContract,
        verdict: "PursuitVerdict",
        source_verdict: str,
        lead_id_prefix: str,
    ) -> None:
        """Persist a pursuit lead from an evaluator verdict.

        Shared by the PURSUE path (hard lead, prefix 'pl-') and the
        SKIP-with-variants path (soft lead, prefix 'pls-'). Failures
        are logged but never raised — pursuit bookkeeping must not
        block the cycle.
        """
        lead_id = (
            f"{lead_id_prefix}{contract.hypothesis_id[:8]}-"
            f"c{self.state.cycle_number}"
        )
        lead = PursuitLead(
            lead_id=lead_id,
            source_theory_id=contract.hypothesis_id,
            source_cycle=self.state.cycle_number,
            crib_score=int(contract.crib_score or 0),
            rationale=verdict.rationale[:500],
            suggested_variants=list(verdict.suggested_variants),
            status=PursuitLeadStatus.OPEN,
            source_verdict=source_verdict,
            opened_at=_now_iso(),
        )
        try:
            self.ledger.insert_pursuit_lead(lead)
            self._cycle_pursuit_leads_opened.append(lead_id)
            marker = "↪" if source_verdict == PURSUIT_SOURCE_PURSUE else "~"
            kind = "LEAD OPENED" if source_verdict == PURSUIT_SOURCE_PURSUE else "SOFT LEAD OPENED"
            logger.info(
                "  %s %s %s source=%s cycle=%d score=%d",
                marker, kind, lead_id, contract.hypothesis_id[:8],
                self.state.cycle_number, contract.crib_score,
            )
        except Exception as exc:
            # Duplicate PRIMARY KEY (same cycle re-run) or other
            # constraint violation — log and continue, never block
            # the cycle on pursuit bookkeeping.
            logger.warning(
                "  ~ lead insert failed for %s: %s",
                lead_id, exc,
            )

    async def _run_lead_pursuit(
        self,
        theories: list[TheoryRecord],
        outcomes: list[WorkerContract],
        on_progress: Any = None,
    ) -> None:
        """
        Run the lead-pursuit evaluator as a sibling call against any
        contract whose kernel-verified crib_score is in the
        [lead_pursuit_lo, lead_pursuit_hi] band. For each "pursue"
        verdict, open a structured pursuit lead in the ledger so the
        next cycle's theorist sees it as priority context.

        Positioned post-absorb, post-alerts, adjacent to synthesis.
        This is the Day 6 addition that closes the "rotation chance"
        gap — interesting-but-not-breakthrough results no longer
        depend on persona rotation for follow-up.

        Behavior:
          - skip_lead_pursuit config flag → no-op
          - pursuit evaluator agent not in roster → no-op (with a warning)
          - no contracts in band → no-op
          - SDK/parse error for a specific contract → verdict="error"
            recorded, treated as "skip" (flaky calls cannot flood
            the pursuit queue with ghost leads)
          - verdict="pursue" → PursuitLead row inserted in the ledger

        Stale leads from prior cycles are auto-closed at the end of
        the phase based on self.config.lead_pursuit_stale_cycles.
        """
        if self.config.skip_lead_pursuit:
            logger.info("Lead pursuit skipped (config.skip_lead_pursuit=True)")
            if on_progress:
                on_progress("skipped", "config.skip_lead_pursuit=True")
            return

        pursuit_spec = select_pursuit_evaluator(self._pantheon_roster)
        if pursuit_spec is None:
            logger.warning(
                "Lead pursuit skipped: neither results-analyst nor "
                "research-chancellor is in the Pantheon roster. "
                "Sub-signal results will not be followed up this cycle."
            )
            if on_progress:
                on_progress("skipped", "pursuit evaluator not in roster")
            return

        lo = int(self.config.lead_pursuit_lo)
        hi = int(self.config.lead_pursuit_hi)
        candidates = [
            c for c in outcomes
            if lo <= int(c.crib_score or 0) <= hi
        ]
        if not candidates:
            logger.info(
                "Lead pursuit: no contracts in band [%d, %d] this cycle",
                lo, hi,
            )
            if on_progress:
                on_progress("skipped", f"no contracts in [{lo}, {hi}]")
            return

        pv_model, _ = resolve_model_for_phase(pursuit_spec, "pursuit")
        logger.info(
            "pursuit_agent=%s model=%s setting_sources=project "
            "task_tools=disabled cycle=%d count=%d band=[%d,%d]",
            pursuit_spec.name, pv_model, self.state.cycle_number,
            len(candidates), lo, hi,
        )
        if on_progress:
            on_progress("start", (pursuit_spec.name, pv_model, len(candidates)))

        theory_by_id = {t.hypothesis_id: t for t in theories}
        pursue_n = skip_n = error_n = 0
        for contract in candidates:
            theory = theory_by_id.get(contract.hypothesis_id)
            if theory is None:
                logger.warning(
                    "Lead pursuit: no theory record for %s — skipping",
                    contract.hypothesis_id[:8],
                )
                continue

            verdict = await run_pursuit_evaluator(
                contract,
                theory,
                pursuit_spec=pursuit_spec,
                project_root=self.config.project_root.resolve(),
                allowed_tools=self.config.allowed_tools,
                permission_mode=self.config.permission_mode,
            )

            self._cycle_pursuit_verdicts[contract.hypothesis_id] = verdict
            logger.info(verdict.to_log_line(contract.hypothesis_id))
            if on_progress:
                on_progress("verdict", (theory, contract, verdict))

            if verdict.verdict == "pursue":
                pursue_n += 1
                # Open a HARD pursuit lead. Lead ID is deterministic
                # per source theory + cycle so repeated calls on the
                # same contract don't multiply.
                self._open_pursuit_lead_from_verdict(
                    contract=contract,
                    verdict=verdict,
                    source_verdict=PURSUIT_SOURCE_PURSUE,
                    lead_id_prefix="pl-",
                )
            elif verdict.verdict == "skip":
                skip_n += 1
                # SOFT lead path: the evaluator rejected this specific
                # lead but left behind concrete variant directions. We
                # persist them as a soft lead (source_verdict=skip_variants)
                # so the next theorist sees them as weaker context instead
                # of losing the information at the cycle boundary. See
                # feedback_pursuit_stays_passive.md — these remain passive
                # context, not dispatch triggers.
                if verdict.suggested_variants:
                    self._open_pursuit_lead_from_verdict(
                        contract=contract,
                        verdict=verdict,
                        source_verdict=PURSUIT_SOURCE_SKIP_VARIANTS,
                        lead_id_prefix="pls-",
                    )
            else:  # error
                error_n += 1

        # Auto-close stale leads from prior cycles.
        try:
            closed_stale = self.ledger.auto_close_stale_pursuit_leads(
                current_cycle=self.state.cycle_number,
                stale_after_cycles=int(self.config.lead_pursuit_stale_cycles),
            )
            if closed_stale:
                logger.info(
                    "Lead pursuit: auto-closed %d stale lead(s): %s",
                    len(closed_stale), closed_stale,
                )
        except Exception:
            logger.exception(
                "Lead pursuit: auto-close-stale raised (continuing)"
            )

        logger.info(
            "Lead pursuit filter: %d pursue, %d skip, %d error of %d band contracts",
            pursue_n, skip_n, error_n, len(candidates),
        )
        if on_progress:
            on_progress(
                "summary",
                (pursue_n, skip_n, error_n, len(candidates)),
            )

    # ------------------------------------------------------------------
    # Day 5: End-of-cycle results synthesis
    # ------------------------------------------------------------------

    async def _run_synthesis(
        self,
        theories: list[TheoryRecord],
        outcomes: list[WorkerContract],
        on_progress: Any = None,
    ) -> None:
        """
        Run results-analyst end-of-cycle synthesis as a sibling call.
        Produces a structured CycleSynthesis that gets persisted to
        self._last_synthesis where the next cycle's _assess_landscape
        can render it for the theorist.

        Best-effort: failure here is logged but never blocks the cycle.

        Args:
            theories: dispatched theories from this cycle
            outcomes: worker contracts from this cycle
            on_progress: optional TUI callback (start, result, skipped)
        """
        if self.config.skip_synthesis:
            logger.info("Cycle synthesis skipped (config.skip_synthesis=True)")
            if on_progress:
                on_progress("skipped", "config.skip_synthesis=True")
            return

        synth_spec = select_results_analyst(self._pantheon_roster)
        if synth_spec is None:
            logger.warning(
                "Cycle synthesis skipped: results-analyst not in Pantheon roster."
            )
            if on_progress:
                on_progress("skipped", "results-analyst not in roster")
            return

        sy_model, _ = resolve_model_for_phase(synth_spec, "synthesis")
        logger.info(
            "synthesis_agent=%s model=%s cycle=%d",
            synth_spec.name, sy_model, self.state.cycle_number,
        )
        if on_progress:
            on_progress("start", (synth_spec.name, sy_model))

        # Priority 5: derive the per-dispatch risk map from the red-team
        # verdicts. Only non-"none" risks are passed to synthesis so the
        # downstream formatter can render a compact breakdown.
        risk_by_hid: dict[str, tuple[str, str]] = {}
        for hid, v in self._cycle_redteam_verdicts.items():
            if v.verdict != "concerned":
                continue
            risk_value = v.search_space_risk or "none"
            if risk_value == "none":
                continue
            first_reason = v.reasons[0] if v.reasons else ""
            risk_by_hid[hid] = (risk_value, first_reason)

        try:
            synthesis = await run_results_synthesis(
                cycle_number=self.state.cycle_number,
                theories=theories,
                contracts=outcomes,
                redteam_verdicts=self._cycle_redteam_verdicts,
                stat_audit_verdicts=self._cycle_stat_audit_verdicts,
                alert_summaries=self._cycle_alert_summaries,
                risk_by_hid=risk_by_hid,
                synthesis_spec=synth_spec,
                project_root=self.config.project_root.resolve(),
                allowed_tools=self.config.allowed_tools,
                permission_mode=self.config.permission_mode,
                bench_mode=self.config.problem.is_bench,
            )
        except Exception:
            logger.exception("Synthesis call raised (continuing run)")
            return

        self._last_synthesis = synthesis
        if synthesis.error:
            logger.warning(
                "Synthesis returned degraded result for cycle %d: %s",
                self.state.cycle_number, synthesis.error,
            )
        else:
            logger.info(
                "Synthesis cycle=%d headline=%r dispatched=%d disproved=%d signal=%d",
                self.state.cycle_number,
                synthesis.headline[:80],
                synthesis.dispatched_count,
                synthesis.disproved_count,
                synthesis.signal_count,
            )
        if on_progress:
            on_progress("result", synthesis)

    # ------------------------------------------------------------------
    # State management
    # ------------------------------------------------------------------

    def _update_state_counts_on(self, state: ControllerState) -> None:
        """Refresh theory counts on a state object from the ledger."""
        counts = self.ledger.count_by_status()
        state.theories_proposed = sum(counts.values())
        state.theories_tested = sum(
            counts.get(s, 0) for s in ["completed", "eliminated", "promising"]
        )
        state.theories_eliminated = counts.get("eliminated", 0)
        state.theories_promising = counts.get("promising", 0)

    def _update_state_counts(self) -> None:
        """Refresh controller state counts from ledger."""
        self._update_state_counts_on(self.state)

    def get_status(self) -> dict[str, Any]:
        """Get current controller status from persisted ledger state."""
        state = self.ledger.load_controller_state()
        self._update_state_counts_on(state)
        summary = self.ledger.summary()
        return {
            "controller": state.to_dict(),
            "ledger": summary,
        }
