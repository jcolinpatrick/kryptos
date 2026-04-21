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
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from claude_agent_sdk import ClaudeAgentOptions

from .config import KryptosBotConfig, HypothesisStatus as LegacyStatus
from .contracts import (
    ParseResult, validate_worker_contract, validate_theory_proposals,
    TheoryParseReport,
)
from .critic import TheoryCritic
from .database import ResultsDB
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
from .sdk_wrapper import safe_query, classify_error
from .theory_ledger import TheoryLedger
from .claims_registry import CANONICAL_CLAIMS, CANONICAL_CLAIMS_BY_ID
from .claim_rendering import render_claim_inline
from .claim_policy import can_use_in_prompt

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
# Controller configuration
# ---------------------------------------------------------------------------

@dataclass
class ControllerConfig:
    """Configuration for the research controller."""
    # Paths
    project_root: Path = Path(".")
    ledger_db_path: Path = Path("db/theory_ledger.sqlite")
    legacy_db_path: Path = Path("results/results.db")

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

    def __post_init__(self) -> None:
        root = self.project_root.resolve()
        if not self.ledger_db_path.is_absolute():
            self.ledger_db_path = root / self.ledger_db_path
        if not self.legacy_db_path.is_absolute():
            self.legacy_db_path = root / self.legacy_db_path


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
        self.critic = TheoryCritic(self.ledger)
        self.state = ControllerState()
        self._semaphore = asyncio.Semaphore(config.max_concurrent_workers)

        # Day 5 per-cycle transient state. These dicts are populated by
        # _red_team_filter and _stat_audit_filter during a cycle and read
        # by _run_synthesis at end-of-cycle. Reset by _begin_cycle_phase_state.
        self._cycle_redteam_verdicts: dict[str, RedTeamVerdict] = {}
        self._cycle_stat_audit_verdicts: dict[str, StatAuditVerdict] = {}
        self._cycle_alert_summaries: list[str] = []
        # Day 6: per-cycle pursuit verdicts, keyed by hypothesis_id.
        # Populated by _run_lead_pursuit for any contract in the 6-17
        # interesting band. Consumed by _run_synthesis for rendering
        # and used by _open_pursuit_leads to write to the ledger.
        self._cycle_pursuit_verdicts: dict[str, PursuitVerdict] = {}
        self._cycle_pursuit_leads_opened: list[str] = []
        self._last_synthesis: Optional[CycleSynthesis] = None
        self._fatal_agent_error: Optional[str] = None

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

    def _begin_cycle_phase_state(self) -> None:
        """Reset per-cycle Day 5 transient state at the start of a cycle.

        Called from both controller.run() and run_controller.do_run().
        Idempotent — safe to call from either entry point at any cycle
        boundary.
        """
        self._cycle_redteam_verdicts = {}
        self._cycle_stat_audit_verdicts = {}
        self._cycle_alert_summaries = []
        self._cycle_pursuit_verdicts = {}
        self._cycle_pursuit_leads_opened = []

    def should_abort_run(self) -> bool:
        """True when the current controller session hit a fatal agent failure."""
        return self._fatal_agent_error is not None

    @property
    def fatal_agent_error(self) -> Optional[str]:
        """Human-readable explanation for the current fatal agent failure."""
        return self._fatal_agent_error

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
            set_canonical_facts(facts)
        except ImportError:
            logger.warning("Could not import kernel constants for canonical facts")

    # ------------------------------------------------------------------
    # Main run loop
    # ------------------------------------------------------------------

    async def run(self) -> ControllerState:
        """
        Execute the controller for up to max_cycles.

        Each cycle: assess → generate → critic → dispatch → absorb → persist.
        """
        # Bootstrap registries
        bootstrap_all(self.ledger, self.config.project_root)

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

        # Snapshot baseline for session-local deltas
        counts = self.ledger.count_by_status()
        self._session_baseline_tested = sum(
            counts.get(s, 0) for s in ["completed", "eliminated", "promising"]
        )
        self._session_baseline_eliminated = counts.get("eliminated", 0)

        for cycle in range(self.config.max_cycles):
            self.state.cycle_number += 1
            self.state.last_cycle_at = _now_iso()
            logger.info("=== Cycle %d ===", self.state.cycle_number)
            self._begin_cycle_phase_state()  # Day 5: reset per-cycle dicts

            try:
                # Step 1: Assess landscape
                landscape = self._assess_landscape()
                logger.info("Landscape: %s", json.dumps(landscape, indent=2)[:500])

                # Step 2: Generate candidate theories
                candidates = await self._generate_theories(landscape)
                logger.info("Generated %d candidate theories", len(candidates))

                if not candidates:
                    if self.should_abort_run():
                        logger.warning(
                            "Aborting remaining cycles after fatal theorist failure: %s",
                            self.fatal_agent_error,
                        )
                        break
                    logger.info("No candidates generated, ending cycle")
                    continue

                # Step 3: Critic pass
                approved = []
                for theory in candidates:
                    if self.config.skip_critic:
                        theory.status = TheoryStatus.APPROVED
                        approved.append(theory)
                    else:
                        verdict = self.critic.evaluate(theory)
                        theory.critic_verdict = verdict
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
                            logger.info(
                                "  REJECTED [%s]: %s — %s",
                                verdict.decision.value, theory.title,
                                verdict.reasons[0] if verdict.reasons else "no reason",
                            )

                logger.info(
                    "%d/%d theories approved by critic",
                    len(approved), len(candidates),
                )

                # Day 6: any approved theory tagged "pursuit_lead:<id>"
                # closes the corresponding open lead as PURSUED. Best-
                # effort — never fails the cycle on bookkeeping.
                self._close_referenced_pursuit_leads(approved)

                if not approved:
                    logger.info("No theories survived critic, ending cycle")
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
                approved = await self._red_team_filter(approved)

                if not approved:
                    logger.info("No theories survived red-team, ending cycle")
                    continue

                if self.config.dry_run:
                    logger.info("DRY RUN — skipping dispatch")
                    continue

                # Step 4: Dispatch to workers
                outcomes = await self._dispatch_theories(approved)
                logger.info("Got %d experiment outcomes", len(outcomes))

                # Step 5: Absorb outcomes
                self._absorb_outcomes(outcomes)

                # Step 5c: Day 5 — statistical-auditor post-execution
                # signal review. Populates self._cycle_stat_audit_verdicts
                # which _run_alerts consumes to gate signal-level alerts.
                # Best-effort: never blocks the cycle.
                try:
                    await self._stat_audit_filter(approved, outcomes)
                except Exception:
                    logger.exception("Stat-audit filter raised (continuing)")

                # Step 5b: Run contradiction-detector alerts BEFORE persisting
                # state. Alerting is best-effort and never blocks the loop.
                # Honors stat-audit gate from step 5c.
                self._run_alerts(approved, outcomes)

                # Step 5d: Day 6 — lead-pursuit evaluator for sub-signal
                # (6-17) contracts. Populates _cycle_pursuit_verdicts and
                # opens PursuitLead rows in the ledger for any "pursue"
                # verdict. Best-effort: never blocks the cycle.
                try:
                    await self._run_lead_pursuit(approved, outcomes)
                except Exception:
                    logger.exception("Lead pursuit raised (continuing)")

                # Step 6: Persist state
                self._update_state_counts()
                self.ledger.save_controller_state(self.state)
                self.ledger.refresh_family_stats()

                # Step 6b: Day 5 — end-of-cycle results synthesis. Produces
                # a structured CycleSynthesis written to self._last_synthesis
                # which the next cycle's _assess_landscape can render.
                try:
                    await self._run_synthesis(approved, outcomes)
                except Exception:
                    logger.exception("Cycle synthesis raised (continuing)")

            except Exception:
                logger.exception("Error in cycle %d", self.state.cycle_number)
                # Persist state even on error so we don't lose progress
                self.ledger.save_controller_state(self.state)

        logger.info("Controller completed %d cycles", self.config.max_cycles)
        return self.state

    # ------------------------------------------------------------------
    # Step 1: Assess landscape
    # ------------------------------------------------------------------

    def _assess_landscape(self) -> dict[str, Any]:
        """Build a structured view of the current research landscape."""
        from kryptosbot.registries import (
            STANDING_CONSTRAINTS,
            ADMISSIBLE_PROMPT_ANOMALY_IDS,
        )

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
        from kryptosbot.registries import EXTERNALLY_EVIDENCED_FAMILIES

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
        from kryptosbot.registries import KNOWN_ANOMALIES
        _priority_map = {
            a["anomaly_id"]: a.get("priority", 99)
            for a in KNOWN_ANOMALIES
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

        return {
            "status_counts": status_counts,
            "cycle_delta": delta,
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
        }

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

    async def _generate_theories(
        self, landscape: dict[str, Any],
        on_progress: Any = None,
    ) -> list[TheoryRecord]:
        """
        Generate candidate theories using Agent SDK theorist session.

        The theorist is given the current landscape and must produce
        structured theory records (not free-text). Falls back to
        programmatic generation if the agent fails.

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
            model, fallback_model = "claude-opus-4-7", "claude-sonnet-4-6"
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
                    text = str(message.content)
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
                self._fatal_agent_error = classified
                logger.warning("Theorist session failed fatally: %s", classified)
                if on_progress:
                    on_progress("error", classified)
                return []
            logger.warning("Theorist session failed: %s", combined_error)
            if on_progress:
                on_progress(
                    "fallback",
                    f"Agent failed ({type(exc).__name__}), using programmatic generation",
                )
            return self._programmatic_fallback(landscape)

        raw_output = "\n".join(raw_chunks)
        report = validate_theory_proposals(raw_output)

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
            logger.info("No valid theories parsed from theorist output, using fallback")
            return self._programmatic_fallback(landscape)

        return report.valid[:self.config.theories_per_cycle]

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
            redteam_spec.name, rt_model, self.state.cycle_number, len(approved),
        )
        if on_progress:
            on_progress("start", (redteam_spec.name, rt_model, len(approved)))

        survivors: list[TheoryRecord] = []
        concerned_count = 0
        error_count = 0
        for theory in approved:
            verdict = await run_red_team_precheck(
                theory,
                redteam_spec=redteam_spec,
                project_root=self.config.project_root.resolve(),
                allowed_tools=self.config.allowed_tools,
                permission_mode=self.config.permission_mode,
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
            if (
                verdict.verdict == "concerned"
                and (verdict.search_space_risk or "none") == "duplicate_family"
            ):
                logger.warning(
                    "  ↑ ESCALATED concerned→reject by duplicate_family "
                    "policy: %s — %s",
                    theory.title[:60],
                    verdict.reasons[0] if verdict.reasons else "no reason given",
                )
                theory.status = TheoryStatus.CRITICIZED
                if theory.critic_verdict is not None:
                    theory.critic_verdict.reasons = list(theory.critic_verdict.reasons)
                    theory.critic_verdict.reasons.append(
                        "controller escalated concerned→reject on "
                        "search_space_risk=duplicate_family"
                    )
                self.ledger.upsert_theory(theory)
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
        logger.info(
            "Red-team filter: %d/%d theories survived "
            "(%d clean, %d concerned, %d error, %d rejected)",
            len(survivors), len(approved),
            len(survivors) - concerned_count - error_count,
            concerned_count, error_count, rejected,
        )
        if on_progress:
            on_progress(
                "summary",
                (len(survivors), len(approved), rejected, concerned_count, error_count),
            )
        return survivors

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

    def _render_manual_focus_for_prompt(self) -> str:
        """Render operator-injected focus areas that should guide generation.

        Keep this block narrow and procedural. It exists for cases where the
        project has a credible workflow-level lead that is too weak to promote
        to an anomaly but strong enough to prioritize over generic theorizing.
        """
        return (
            "MANUAL PRIORITY FOCUS:\n"
            "  - Rotate across the under-explored anomaly surface. The "
            "open_anomalies list in the landscape is now ranked by exploration "
            "depth (lowest explored_by count first); take that ranking seriously "
            "and bias generation toward the top of the list.\n"
            "  - ct_perturbation is the currently under-mined, archive-anchored "
            "lead. Published Sanborn coding charts prove specific transcription "
            "errors in the carved K1-K3 plaintexts (IQLUSION, UNDERGRUUND, "
            "DESPARATLY). Strong proposals here test whether analogous "
            "perturbations of K4 CT — a preregistered short variant list derived "
            "from archive evidence, NOT arbitrary single-char sweeps — change "
            "the behavior of already-eliminated cipher families.\n"
            "  - w_delimiter_segments is SATURATED as a single-layer lead "
            "(80+ theories tested, all eliminated). It remains admissible only "
            "as one layer of a multi-layer construction or with a genuinely "
            "novel mechanism that is not a rehash of reset / segment-tape / "
            "digit-key / compass-rotation / strip-permutation / Chaocipher "
            "variants already disproved. Do not propose another single-layer "
            "W variant unless it clears that bar.\n"
            "  - width21_vertical_bigrams is a ranking feature, not a clue "
            "surface. Do not build new theories on it; use it only to rank "
            "candidates that arise from other anchors.\n"
            "  - aaa_coordinate_lie: the archive evidence is real, but "
            "multiple specific mechanisms (true-coord digits, coord-lie delta, "
            "coord-delta Gronsfeld) have been cleanly disproved. Per "
            "accept-specific-disproofs doctrine, new coord-lie mechanisms must "
            "either fix the specific error of a prior disproof or propose a "
            "genuinely different mechanism class — not a pivot that preserves "
            "the coordinate commitment while dodging the last disproof.\n"
            "  - aaa_compass_cipher is mature; new proposals should either "
            "tie to physical-sculpture geometry specifically or be set aside.\n"
            "  - Do NOT use rescue parameters such as optional truncation, "
            "optional wrap, or choose-among-plausible-rectangles geometry. "
            "A valid theory must have one preregistered geometry and one "
            "preregistered parameter envelope."
        )

    def _build_theorist_prompt(self, landscape: dict[str, Any]) -> str:
        """Build the theorist prompt from the current landscape."""
        hedged_claims = self._render_landscape_anomaly_claims(landscape)
        pursuit_leads_block = self._render_pursuit_leads_for_prompt(
            landscape.get("pursuit_leads") or [],
            landscape.get("soft_pursuit_leads") or [],
        )
        manual_focus_block = self._render_manual_focus_for_prompt()
        return f"""Generate {self.config.theories_per_cycle} novel, testable K4 hypotheses.

CURRENT RESEARCH LANDSCAPE:
{json.dumps(landscape, indent=2)}

{pursuit_leads_block}

{manual_focus_block}

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

IMPORTANT — THE PROCEDURAL PARADIGM:
Sanborn is a sculptor, not a cryptographer. He learned "systems that didn't
necessarily depend on mathematics" from Scheidt in 2-3 meetings. Gillogly
confirmed K4 uses "an invention by Ed Scheidt that has never appeared in
cryptographic literature." The algebraic cipher-family search (50+ families,
105K+ composition branches) is effectively saturated at noise floor.

Prefer PROCEDURAL hypotheses — concrete step-by-step physical operations a
sculptor could execute by hand — over algebraic ones. Physical anomalies on
the sculpture (YAR superscript, extra L, misspellings, compass, LAYER TWO)
are likely INSTRUCTIONS, not decorations.

Anomalies with recipe IDs (P-xxx, CP-xxx) reference specific testable procedures
in docs/procedural_anomaly_recipes.md. When an anomaly has a recipe, propose
a theory that EXECUTES that recipe, not one that merely "investigates" the pattern.

The "procedural" family is for hypotheses that derive from physical anomaly
interpretation rather than cipher taxonomy. Use it.

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

ACTIVE ANOMALY SURFACE (RESET 2026-04-15, W EMPHASIS ROTATED OUT 2026-04-20):
Only the following investigable anomalies are admissible as active prompt
anchors for new theories: ct_perturbation, aaa_coordinate_lie,
aaa_compass_cipher, w_delimiter_segments, width21_vertical_bigrams.
Ranking is self-tuning: the open_anomalies list above is sorted by
exploration depth (lowest explored_by count first), so whichever anchor is
currently under-mined surfaces at the top. Follow that ranking.
Treat ct_perturbation as the PRIMARY under-mined anchor: archive-evidence
anchored, bounded (archive-derived preregistered variant list), and least
explored. Treat w_delimiter_segments as SATURATED for single-layer work
(80+ theories tested, all eliminated across cycles 125-133); it remains
admissible as a LAYER in a multi-layer proposal but is not a standalone
primary anchor. Treat width21 as a derived ranking feature largely
explained by W placement, not as an independent clue surface. Other
historical anomalies remain in the ledger for audit but are demoted from
active prompting unless a future hardening pass restores them with new
finite evidence.

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
    "dsl_spec": null
  }}
]

OPTIONAL: "dsl_spec" may contain a kryptosbot.hypothesis_dsl.HypothesisSpec
JSON object describing a bounded, kernel-executable translation of this
theory. When populated, the dispatcher in kryptosbot.job_dispatcher can
run the spec directly on the 28-core compute infrastructure, bypassing
the per-worker scratch-code path. Phase 4 accepts null here; leave null
when no clean DSL translation exists (e.g. novel procedural recipes not
in the DSL vocabulary yet).

Output ONLY the JSON array. No commentary."""

    def _programmatic_fallback(
        self, landscape: dict[str, Any]
    ) -> list[TheoryRecord]:
        """
        Generate theories programmatically when agent fails.

        Uses underexplored families and unaddressed anomalies to construct
        structured hypotheses without an API call. Skips families/anomalies
        that already have theories in the ledger to avoid re-proposing
        eliminated work.
        """
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

        Every dispatched theory is guaranteed to reach a terminal state
        in the ledger. If a worker raises an exception, the theory gets
        an ERROR contract with its hypothesis_id preserved.

        Args:
            on_worker_message: Optional callback(hypothesis_id, event, detail)
                called during worker execution for live progress display.
                Events: "start", "turn", "tool_use", "done", "error".
        """
        tasks = []
        for theory in theories:
            theory.status = TheoryStatus.RUNNING
            self.ledger.upsert_theory(theory)
            tasks.append(self._run_worker(theory, on_worker_message))

        outcomes = await asyncio.gather(*tasks, return_exceptions=True)

        results = []
        for theory, outcome in zip(theories, outcomes):
            if isinstance(outcome, Exception):
                logger.error(
                    "Worker for %s raised exception: %s",
                    theory.hypothesis_id, outcome,
                )
                error_contract = WorkerContract(
                    hypothesis_id=theory.hypothesis_id,
                    worker_role="agent_sdk",
                    status=WorkerStatus.ERROR,
                    error=f"Worker exception: {type(outcome).__name__}: {outcome}",
                )
                # Record a failed experiment so the audit trail is complete
                exp = ExperimentRecord(
                    experiment_id=f"exp-err-{uuid.uuid4().hex[:8]}",
                    hypothesis_id=theory.hypothesis_id,
                    worker_role="agent_sdk",
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
        """Run a single worker for a theory."""
        async with self._semaphore:
            exp_id = f"exp-{uuid.uuid4().hex[:8]}"
            exp = ExperimentRecord(
                experiment_id=exp_id,
                hypothesis_id=theory.hypothesis_id,
                worker_role="agent_sdk",
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
                worker_model = "claude-sonnet-4-6"
                worker_fallback = "claude-haiku-4-5"
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
                        text = str(message.content)
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
                    worker_role="agent_sdk",
                    status=WorkerStatus.TIMEOUT,
                    error=f"Timed out after {self.config.worker_timeout_minutes} minutes",
                )
                # Even on timeout, clean up any artifacts the worker dropped
                # before the timer fired.
                self._cleanup_worker_artifacts(theory, timeout_contract)
                return timeout_contract
            except Exception as exc:
                heartbeat_task.cancel()
                exc_contract = WorkerContract(
                    hypothesis_id=theory.hypothesis_id,
                    worker_role="agent_sdk",
                    status=WorkerStatus.ERROR,
                    error=str(exc),
                )
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
                contract.worker_role = "agent_sdk"
            else:
                # Explicit parse failure — do NOT infer status from prose
                logger.warning(
                    "Worker output for %s failed contract validation: %s",
                    theory.hypothesis_id, "; ".join(parse_result.errors),
                )
                contract = WorkerContract(
                    hypothesis_id=theory.hypothesis_id,
                    worker_role="agent_sdk",
                    status=WorkerStatus.ERROR,
                    error=(
                        "Contract validation failed: "
                        + "; ".join(parse_result.errors)
                    ),
                    duration_seconds=elapsed,
                    # Raw output preserved for audit only, never parsed
                    raw_artifacts={"raw_output_preview": raw_output[:5000]},
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
        return f"""Test the following K4 hypothesis and report structured results.
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
                    WorkerStatus.ERROR: TheoryStatus.COMPLETED,
                    WorkerStatus.TIMEOUT: TheoryStatus.COMPLETED,
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
